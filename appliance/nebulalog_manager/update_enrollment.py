"""Bind initial updater state to measured OCI software and explicit publisher trust.

Installation provenance is not a release signature or a qualification claim. No
signing key is generated here. Publisher trust requires an independently obtained
SPKI SHA256 fingerprint and is immutable through this interface.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid

from .common import Refused, atomic_json, audit, locked, require_linux_root, run
from .firstboot import FirstBoot
from .image_bundle import ApplicationSchema as application_schema, ImageBundleLoader, run_private, strict_json, verify_bundle
from . import publisher_inputs
from .baseline import ContentUpdate

STATE = Path("/var/lib/nebulalog/manager/updates")
PUBLIC_KEY = Path("/etc/nebulalog/release-public.pem")
SHA256 = re.compile(r"[a-f0-9]{64}")
COMPONENT_IMAGES = {"nebulalog": "NEBULALOG_IMAGE", "postgresql": "POSTGRESQL_IMAGE",
                    "clickhouse": "CLICKHOUSE_IMAGE", "keycloak": "KEYCLOAK_FIPS_IMAGE"}
ROOT_UID = 0
FIXED_HOST_FILES = {"appliance/host_boot.py": Path("/usr/libexec/nebulalog/host-boot"),
                    "appliance/factory_host.py": Path("/usr/libexec/nebulalog/factory-host"),
                    "appliance/factory_kernel.py": Path("/usr/libexec/nebulalog/factory-kernel")}
FIXED_HOST_ROOT = Path("/")


def _tree(path: Path):
    """No writable ancestor or symlink may replace a trusted enrollment object."""
    if not path.is_absolute():
        raise Refused("Enrollment paths must be absolute")
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise Refused("Enrollment directory ancestry must be root-owned, nonsymlink and protected")


def _read(path: Path, maximum=1024 * 1024) -> bytes:
    _tree(path.parent)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise Refused("Required enrollment file is unavailable or unsafe") from exc
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1 or info.st_mode & 0o022 or not 0 < info.st_size <= maximum:
        os.close(descriptor)
        raise Refused("Enrollment input must be a bounded, protected root-owned regular file")
    with os.fdopen(descriptor, "rb") as stream:
        value = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if len(value) > maximum or any(getattr(info, key) != getattr(after, key) for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
            raise Refused("Enrollment file changed while being read")
        return value


def _json(path: Path):
    return strict_json(_read(path))


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def application_source_digest(files: dict) -> str:
    """Exact source subset consumed by the production application Containerfile."""
    subset = {path: digest for path, digest in files.items()
              if path.startswith(("cmd/", "internal/", "web/", "migrations/"))
              or path in ("go.mod", "go.sum", "appliance/images/application/Containerfile", "LICENSE")}
    if not subset:
        raise Refused("Captured source manifest has no application source")
    return _hash(json.dumps(subset, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _identity(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError) as exc:
        raise Refused("Enrollment requires a canonical installation identity") from exc
    return value


def _same_or_write(path, value):
    # Parent protection plus the global lock prevents unprivileged/parallel races.
    if path.exists() or path.is_symlink():
        if _json(path) != value:
            raise Refused("Existing enrollment or installed state differs; automatic replacement is refused")
    else:
        atomic_json(path, value)


def _write_key(path, value):
    if path.exists() or path.is_symlink():
        if _read(path, 16384) != value:
            raise Refused("Installed publisher key differs; automatic trust rotation is refused")
        return
    _tree(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".release-public-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # Never replace a key created after our check.
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def _installed_state(state: Path):
    raw = _read(state / "initial-enrollment.json")
    initial, current = strict_json(raw), _json(state / "current.json")
    if (not isinstance(initial, dict) or type(initial.get("schema")) is not int or initial["schema"] != 1
            or initial.get("state") != "enrolled" or not isinstance(initial.get("current"), dict)):
        raise Refused("Initial installed-release identity is malformed")
    _identity(initial.get("installation_id"))
    original = initial["current"]
    for record in (original, current):
        if (not isinstance(record, dict) or type(record.get("sequence")) is not int or not 0 <= record["sequence"] < 2**63
                or not isinstance(record.get("version"), str) or not record["version"]
                or not isinstance(record.get("components"), dict) or not set(COMPONENT_IMAGES) <= set(record["components"])
                or any(not isinstance(item, dict) or not isinstance(item.get("version"), str) or not item["version"]
                       for item in record["components"].values())):
            raise Refused("Installed update version record is incomplete")
    if current["sequence"] < original["sequence"] or current["sequence"] == original["sequence"] and current != original:
        raise Refused("Installed state changed without an accepted release sequence")
    return raw, initial, current


def enrolled_key(state: Path, public_key: Path) -> dict:
    """Every appliance update action pins key bytes to completed enrollment."""
    try:
        receipt = _json(state / "publisher-trust.json")
        initial_raw, initial, _ = _installed_state(state)
    except (OSError, Refused) as exc:
        raise Refused("Updates require completed installed-release and publisher-key enrollment") from exc
    if (not isinstance(receipt, dict) or type(receipt.get("schema")) is not int or receipt["schema"] != 1 or receipt.get("state") != "enrolled"
            or receipt.get("algorithm") != "RSA-PSS-SHA256" or type(receipt.get("rsa_bits")) is not int or not 3072 <= receipt["rsa_bits"] <= 8192
            or receipt.get("public_key") != str(public_key) or not SHA256.fullmatch(str(receipt.get("spki_sha256", "")))
            or receipt.get("initial_enrollment_sha256") != _hash(initial_raw)
            or receipt.get("installation_id") != initial.get("installation_id")
            or receipt.get("pem_sha256") != _hash(_read(public_key, 16384))):
        raise Refused("Publisher trust, installed key or initial update identity changed")
    return receipt


def enrollment_status(state: Path) -> dict:
    """A local file check only; status never starts probes or enrolls trust."""
    result = {"installed_release": "not_enrolled", "publisher_trust": "not_enrolled", "update_ready": False,
              "operator_action": "Complete first-boot installed-release enrollment"}
    try:
        _, initial, _ = _installed_state(state)
        result["installed_release"] = "enrolled"
        mode = initial.get("provenance", {}).get("publisher", {}).get("mode")
        result["operator_action"] = ("Retry first-boot setup to complete packaged factory publisher enrollment" if mode == "factory"
                                     else "Private unsealed candidate: publisher trust is not configured for distribution" if mode == "private-unsealed"
                                     else "nebulalog update enroll-trust --public-key <public.pem> --expected-spki-sha256 <independently-authenticated-hash> --trust-source <reference>")
    except (OSError, Refused, ValueError, TypeError):
        if (state / "initial-enrollment.json").exists() or (state / "initial-enrollment.json").is_symlink():
            result["installed_release"] = "invalid"
        return result
    try:
        receipt = _json(state / "publisher-trust.json")
        enrolled_key(state, Path(receipt["public_key"]))
        result.update(publisher_trust="enrolled", update_ready=True, operator_action=None)
    except (OSError, Refused, ValueError, TypeError, KeyError):
        if (state / "publisher-trust.json").exists() or (state / "publisher-trust.json").is_symlink():
            result["publisher_trust"] = "invalid"
            result["operator_action"] = "Review changed publisher trust or initial installed identity; automatic replacement is refused"
    return result


class UpdateEnrollment:
    def __init__(self, *, data=Path("/var/lib/nebulalog"), etc=Path("/etc/nebulalog"),
                 share=Path("/usr/share/nebulalog"), runner=run, firstboot=None):
        self.data, self.etc, self.share = data, etc, share
        self.state = data / "manager/updates"
        self.temp = data / "tmp"
        self.runner = (lambda argv, **kwargs: run_private(argv, temp=self.temp, **kwargs)) if runner is run else runner
        self.public_runner = runner  # Public build-input probes need no enrolled data mount.
        self.firstboot = firstboot or FirstBoot()

    def _gate(self):
        require_linux_root()
        gate = self.firstboot.gate()  # Actual FIPS/SELinux and encrypted storage identity.
        if gate.get("host_ready") is not True:
            raise Refused("Installed release enrollment requires the measured host/storage gate")
        setup = _json(self.data / "configuration/bootstrap/setup.json")
        identity = _identity(gate.get("installation_id"))
        if not isinstance(setup, dict) or setup.get("installation_id") != identity:
            raise Refused("Installed runtime setup belongs to another appliance")
        _tree(self.data / "manager")
        self.state.mkdir(mode=0o700, exist_ok=True)
        _tree(self.state)
        _tree(self.temp)
        return identity

    def _descriptor(self):
        raw = _read(self.share / "initial-release.json")
        value = strict_json(raw)
        fields = {"schema", "product", "sequence", "schema_revision", "source_commit", "source_dirty",
                  "source_snapshot_sha256", "bundle_manifest_sha256", "qualification_status", "publisher"}
        if (not isinstance(value, dict) or set(value) != fields or type(value.get("schema")) is not int or value["schema"] != 1
                or value.get("product") != "nebulalog" or type(value.get("sequence")) is not int or not 0 <= value["sequence"] < 2**63
                or not isinstance(value.get("schema_revision"), str) or not re.fullmatch(r"[1-9][0-9]{0,8}", value["schema_revision"])
                or not re.fullmatch(r"[a-f0-9]{40}", str(value.get("source_commit", "")))
                or type(value.get("source_dirty")) is not bool or value.get("qualification_status") != "pending"
                or any(not SHA256.fullmatch(str(value.get(key, ""))) for key in ("source_snapshot_sha256", "bundle_manifest_sha256"))):
            raise Refused("Initial release provenance is missing explicit build identity or has unsupported claims")
        source = _read(self.share / "source-manifest.json", 8 * 1024**2)
        manifest = strict_json(source)
        if (_hash(source) != value["source_snapshot_sha256"] or not isinstance(manifest, dict)
                or set(manifest) != {"schema", "files"} or type(manifest["schema"]) is not int or manifest["schema"] != 1
                or not isinstance(manifest["files"], dict) or not manifest["files"]):
            raise Refused("Captured source manifest does not match initial release provenance")
        for path, digest in manifest["files"].items():
            if (not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]+(?:/[A-Za-z0-9_.@-]+)*", path)
                    or any(part in (".", "..", ".local", "node_modules", ".git") for part in path.split("/"))
                    or not isinstance(digest, str) or not SHA256.fullmatch(digest)):
                raise Refused("Unsafe or invalid captured source manifest entry")
        application_schema.bind_source(manifest["files"], value["schema_revision"])
        publisher_inputs.binding(value["publisher"], manifest["files"])
        return value, _hash(raw), application_source_digest(manifest["files"])

    def _publisher(self, descriptor, *, require_factory=False):
        source = _read(self.share / "source-manifest.json", 8 * 1024**2)
        if _hash(source) != descriptor["source_snapshot_sha256"]:
            raise Refused("Source provenance changed during publisher verification")
        paths = (self.share / "publisher-trust.json", self.share / "publisher-public.spki")
        raw = [_read(path, 16384) if path.exists() or path.is_symlink() else None for path in paths]
        return publisher_inputs.validate(descriptor["publisher"], strict_json(source)["files"], *raw,
                                         runner=self.public_runner, require_factory=require_factory)

    def _factory_host(self, descriptor):
        """Verify the image's measured immutable generation and initial selection."""
        from . import host_dispatch, host_payload
        record = _json(self.share / "initial-host.json")
        fields = {"schema", "abi", "host", "initial_release_sha256", "source_snapshot_sha256", "catalog", "catalog_sha256", "fixed_files"}
        if (not isinstance(record, dict) or set(record) != fields or type(record["schema"]) is not int or record["schema"] != 1
                or type(record["abi"]) is not int or record["abi"] != host_payload.ABI
                or record["initial_release_sha256"] != _hash(_read(self.share / "initial-release.json"))
                or record["source_snapshot_sha256"] != descriptor["source_snapshot_sha256"]
                or record["catalog"] != list(host_payload.CATALOG) or record["catalog_sha256"] != host_payload.CATALOG_SHA256
                or not isinstance(record["host"], dict) or set(record["host"]) != {"generation", "version", "host_source_sha256", "abi"}
                or type(record["host"]["abi"]) is not int or not isinstance(record["fixed_files"], dict)
                or set(record["fixed_files"]) != set(FIXED_HOST_FILES)):
            raise Refused("Initial host generation lacks its exact factory ABI and release binding")
        source = _read(self.share / "source-manifest.json", host_payload.MAX_SOURCE_MANIFEST)
        snapshot = host_payload.source_manifest(source)
        if _hash(source) != descriptor["source_snapshot_sha256"] or record["host"]["host_source_sha256"] != host_payload.host_source_hash(snapshot["files"]):
            raise Refused("Initial host source differs from the measured factory source")
        for name, path in FIXED_HOST_FILES.items():
            if record["fixed_files"][name] != snapshot["files"].get(name) or _hash(_read(path, host_payload.MAX_FILE)) != record["fixed_files"][name]:
                raise Refused("Fixed host dispatch code differs from factory source")
        host = host_dispatch.generation_info(record["host"].get("generation"))
        metadata = host_dispatch.protected_json(host_payload.GENERATIONS / host["generation"] / "host-payload.json")
        if host != record["host"] or metadata["source_snapshot_sha256"] != descriptor["source_snapshot_sha256"]:
            raise Refused("Initial generation content differs from factory identity")
        expected = {"schema": 1, "generation": host["generation"], "sequence": descriptor["sequence"]}
        if _json(self.etc / "host-selection.json") != expected:
            raise Refused("Initial selected generation differs from factory release")
        return host

    def verify_initial_host_installation(self):
        """Read-only initial AIDE source mapping and fixed entrypoint acceptance.

        Live policy/configuration/unit acceptance remains the caller's job.
        This is factory-only; it cannot bless a later selected update baseline.
        """
        from . import host_payload
        descriptor, descriptor_sha, _ = self._descriptor()
        host = self._factory_host(descriptor)
        source = strict_json(_read(self.share / "source-manifest.json", host_payload.MAX_SOURCE_MANIFEST))
        mappings = dict(FIXED_HOST_FILES)
        special = {"nebulalog": "usr/local/bin/nebulalog", "nebulalog-setup": "usr/local/sbin/nebulalog-setup",
                   "nebulalog-seal": "usr/local/sbin/nebulalog-seal"}
        for entry in host_payload.CATALOG:
            if entry["path"].startswith("lib/"):
                mappings[entry["source"]] = host_payload.GENERATIONS / host["generation"] / entry["path"]
            elif entry["path"].startswith("bin/"):
                name = Path(entry["path"]).name
                mappings[entry["source"]] = FIXED_HOST_ROOT / special.get(name, "usr/libexec/nebulalog/" + name)
        for name, path in mappings.items():
            if source["files"].get(name) != _hash(_read(path, host_payload.MAX_FILE)):
                raise Refused("Initial fixed entrypoint or generation source differs from captured bytes")
        return {"schema": 1, "verified": True, "host": host,
                "source_snapshot_sha256": descriptor["source_snapshot_sha256"], "initial_release_sha256": descriptor_sha,
                "source_mappings": {name: str(path) for name, path in sorted(mappings.items())}}

    def verify_build_inputs(self, *, require_factory=False, include_host=True):
        """Verify pristine offline build inputs without requiring enrolled storage.

        Shared by the installer and sealer, before any runtime image load. This
        verifies source/image binding only; it never claims guest qualification.
        """
        descriptor, descriptor_sha, application_source = self._descriptor()
        if descriptor["bundle_manifest_sha256"] != _hash(_read(self.share / "images/manifest.json")):
            raise Refused("Initial release provenance does not match the installed offline bundle")
        verified = verify_bundle(self.share / "images", _json(self.etc / "images.json"), root_owned=True)
        if verified["images"]["NEBULALOG_IMAGE"].get("application_source_sha256") != application_source:
            raise Refused("Application image does not match the captured release source")
        publisher = self._publisher(descriptor, require_factory=require_factory)
        host = self._factory_host(descriptor) if include_host else None
        return {"descriptor": descriptor, "descriptor_sha256": descriptor_sha,
                "application_source_sha256": application_source, "bundle": verified,
                "host": host,
                "publisher": {key: value for key, value in publisher.items() if key != "public"}}

    def _container(self, name, expected):
        value = strict_json(self.runner(["podman", "container", "inspect", "nebulalog-" + name], timeout=30))
        if (not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict)
                or not isinstance(value[0].get("State"), dict) or value[0]["State"].get("Running") is not True
                or not SHA256.fullmatch(str(value[0].get("Id", "")))
                or str(value[0].get("Image", "")).removeprefix("sha256:") != expected["config_digest"].removeprefix("sha256:")):
            raise Refused("Running container does not match the verified initial image: " + name)
        return value[0].get("Id")

    def _version(self, component, container=None):
        container = container or component
        commands = {
            "nebulalog": ("10001:10001", ["/usr/local/bin/nebulalog", "version"]),
            "postgresql": ("999:999", ["psql", "-X", "--username=postgres", "--dbname=postgres", "--tuples-only",
                                      "--no-align", "--set=ON_ERROR_STOP=1", "--command", "SELECT split_part(current_setting('server_version'), ' ', 1)"]),
            "clickhouse": ("101:101", ["clickhouse-client", "--config-file=/etc/nebulalog/clickhouse-client.xml",
                                      "--max_execution_time=15", "--query", "SELECT version() FORMAT TSVRaw"]),
            "keycloak": ("1000:1000", ["/opt/keycloak/bin/kc.sh", "--version"]),
        }
        user, command = commands[component]
        output = self.runner(["podman", "exec", "--user", user, "nebulalog-" + container, *command], timeout=120).strip()
        if component == "keycloak":
            # JVM notices may precede the version; require one unambiguous line.
            matches = re.findall(r"(?m)^Keycloak ([0-9][A-Za-z0-9.+_-]{0,127})\s*$", output)
            output = matches[0] if len(matches) == 1 else ""
        if not re.fullmatch(r"[0-9][A-Za-z0-9.+_-]{0,127}", output):
            raise Refused("Runtime version could not be measured unambiguously: " + component)
        return output

    def installed(self):
        result = self._installed()
        factory = self.trust_factory()
        if factory["mode"] == "factory":
            result["publisher_trust"] = "enrolled"
        return {**result, "build_mode": factory["mode"], "update_ready": factory["update_ready"]}

    def _running_host(self, host):
        from .host_payload import GENERATIONS
        expected = GENERATIONS / host["generation"] / "lib/nebulalog_manager/update_enrollment.py"
        if (Path(__file__).resolve() != expected or os.environ.get("NEBULALOG_HOST_GENERATION") != host["generation"]
                or os.environ.get("NEBULALOG_HOST_SOURCE_SHA256") != host["host_source_sha256"]
                or os.environ.get("NEBULALOG_HOST_ABI") != "1"):
            raise Refused("Initial release enrollment must run through the measured fixed host dispatcher")

    def _installed(self):
        identity = self._gate()
        with locked(self.state.parent / "transaction.lock"), locked(self.state / "transaction.lock"):
            if (self.state / "current.json").exists() and not (self.state / "initial-pending.json").exists():
                raise Refused("Existing installed state has no initial enrollment proposal; automatic adoption differs from supported crash recovery")
            descriptor, descriptor_sha, application_source = self._descriptor()
            self._publisher(descriptor)
            host = self._factory_host(descriptor)
            self._running_host(host)
            bundle = self.share / "images"
            if _hash(_read(bundle / "manifest.json")) != descriptor["bundle_manifest_sha256"]:
                raise Refused("Initial release does not match the offline bundle manifest")
            pins = _json(self.etc / "images.json")
            verified = verify_bundle(bundle, pins, root_owned=True)
            if verified["images"]["NEBULALOG_IMAGE"].get("application_source_sha256") != application_source:
                raise Refused("Verified application image source label is missing or differs from the captured application source")
            loaded = _json(self.state.parent / "image-bundle-receipt.json")
            if not isinstance(loaded, dict) or type(loaded.get("schema")) is not int or loaded["schema"] != 1 or loaded.get("status") != "loaded" or loaded.get("network_used") is not False:
                raise Refused("Verified offline image load receipt is required")
            lifecycle = _json(self.data / "configuration/lifecycle.json")
            if not isinstance(lifecycle, dict) or lifecycle.get("schema_revision") != descriptor["schema_revision"]:
                raise Refused("Runtime schema revision differs from the initial release")
            inspector = ImageBundleLoader(data=self.data, runner=self.runner)
            # Runtime enrollment precedes the console's policy-selection action.
            # A later accepted content bridge measures selection independently;
            # it must never rewrite this immutable initial host/OCI identity.
            components, measurements = {"host": host}, {"host": {**host, "generation_files_verified": True}}
            for component, pin in COMPONENT_IMAGES.items():
                item = verified["images"][pin]
                image = inspector._inspect_installed(pins[pin], item)
                if loaded.get("images", {}).get(pin) != image:
                    raise Refused("Installed image differs from its offline load receipt")
                containers = ("api", "ingest") if component == "nebulalog" else (component,)
                observed = {}
                for name in containers:
                    before = self._container(name, item)
                    version = self._version(component, name)
                    if self._container(name, item) != before:
                        raise Refused("Runtime container changed during version measurement")
                    observed[name] = version
                if len(set(observed.values())) != 1:
                    raise Refused("API and ingestion use different application versions")
                components[component] = {"version": next(iter(observed.values())), "image": pins[pin],
                                         "schema_revision": descriptor["schema_revision"]}
                measurements[component] = {**image, "runtime_versions": observed, "archive_sha256": item["archive_sha256"]}
            current = {"sequence": descriptor["sequence"], "version": components["nebulalog"]["version"], "components": components}
            receipt = {"schema": 1, "state": "enrolled", "installation_id": identity, "initial_release_sha256": descriptor_sha,
                       "provenance": descriptor, "application_source_sha256": application_source,
                       "current": current, "measurements": measurements}
            publisher_trust = "not_enrolled"
            if (self.state / "publisher-trust.json").exists() or (self.state / "publisher-trust.json").is_symlink():
                enrolled_key(self.state, self.etc / "release-public.pem")
                publisher_trust = "enrolled"
            for name in ("transaction.json",):
                if (self.state / name).exists():
                    raise Refused("Update transactions already exist; initial enrollment cannot reset installed state")
            # A durable proposal permits exact-only crash recovery, never a reset.
            for name, value in (("initial-pending.json", receipt), ("current.json", current), ("initial-enrollment.json", receipt)):
                if ((self.state / name).exists() or (self.state / name).is_symlink()) and _json(self.state / name) != value:
                    raise Refused("Existing enrollment or installed state differs; automatic replacement is refused")
            _same_or_write(self.state / "initial-pending.json", receipt)
            _same_or_write(self.state / "current.json", current)
            _same_or_write(self.state / "initial-enrollment.json", receipt)
            audit(self.state / "history.jsonl", "update.initial_enrolled", installation_id=identity,
                  sequence=current["sequence"], initial_release_sha256=descriptor_sha)
            return {"schema": 1, "ok": True, "status": "enrolled", "installation_id": identity,
                    "initial_release_sha256": descriptor_sha, "current": current,
                    "publisher_trust": publisher_trust,
                    "qualification_status": "pending"}

    def _content(self, installation_id):
        """Measure selected content; never infer or adopt an installed release label."""
        path = self.data / "configuration/security-policy.json"
        before = _read(path)
        policy = strict_json(before)
        setup = _json(self.data / "configuration/bootstrap/setup.json")
        if (not isinstance(policy, dict) or policy.get("installation_id") != installation_id
                or setup.get("installation_id") != installation_id
                or policy.get("baseline") != setup.get("baseline")):
            raise Refused("Selected compliance content is not bound to this installation and baseline")
        measured = ContentUpdate.measure(path, runner=self.runner)
        if _read(path) != before or measured["policy_sha256"] != _hash(before):
            raise Refused("Selected compliance policy changed during content measurement")
        return measured

    def trust_factory(self):
        """Enroll only public trust carried by the trusted initial appliance image.

        The factory image is the authentication boundary; downloading a key and
        hash together from an untrusted origin is not independent authentication.
        """
        descriptor, descriptor_sha, _ = self._descriptor()
        publisher = self._publisher(descriptor)
        if publisher["mode"] == "private-unsealed":
            return {"mode": "private-unsealed", "status": "not_configured", "update_ready": False}
        _, initial, _ = _installed_state(self.state)
        if initial.get("initial_release_sha256") != descriptor_sha or initial.get("provenance") != descriptor:
            raise Refused("Factory publisher trust is not bound to the enrolled initial appliance image")
        description = publisher["descriptor"]
        trust_source = ("Factory appliance image provenance sha256:" + descriptor_sha + "; repository:"
                        + description["repository"] + "; key_id:" + description["key_id"])
        result = self.trust(self.share / "publisher-public.spki", publisher["spki_sha256"], trust_source,
                            expected_source_sha256=descriptor["publisher"]["public_spki_pem_sha256"])
        return {**result, "mode": "factory", "update_ready": True}

    def factory_status(self):
        """Read-only first-boot acceptance; missing trust never triggers enrollment."""
        descriptor, descriptor_sha, _ = self._descriptor()
        publisher = self._publisher(descriptor)
        if publisher["mode"] == "private-unsealed":
            return {"mode": "private-unsealed", "update_ready": False}
        _, initial, _ = _installed_state(self.state)
        if initial.get("initial_release_sha256") != descriptor_sha or initial.get("provenance") != descriptor:
            raise Refused("Factory trust no longer matches the enrolled appliance image")
        receipt = enrolled_key(self.state, self.etc / "release-public.pem")
        description = publisher["descriptor"]
        expected_source = ("Factory appliance image provenance sha256:" + descriptor_sha + "; repository:"
                           + description["repository"] + "; key_id:" + description["key_id"])
        if receipt.get("spki_sha256") != publisher["spki_sha256"] or receipt.get("trust_source") != expected_source:
            raise Refused("Enrolled publisher differs from packaged factory trust")
        return {"mode": "factory", "update_ready": True, "spki_sha256": publisher["spki_sha256"]}

    def trust(self, source: Path, fingerprint: str, trust_source: str, *, expected_source_sha256=None):
        identity = self._gate()
        if (not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint)
                or not isinstance(trust_source, str) or not 8 <= len(trust_source) <= 512
                or any(ord(char) < 32 or ord(char) == 127 for char in trust_source)):
            raise Refused("Supply an independently authenticated lowercase SPKI SHA256 and a documented trust source")
        with locked(self.state.parent / "transaction.lock"), locked(self.state / "transaction.lock"):
            initial_raw, initial, current = _installed_state(self.state)
            if initial.get("state") != "enrolled" or initial.get("installation_id") != identity:
                raise Refused("Complete installed-release enrollment before enrolling publisher trust")
            if not (self.state / "publisher-trust.json").exists() and current != initial["current"]:
                raise Refused("Installed state changed before initial publisher trust enrollment")
            raw = _read(source, 16384)
            if expected_source_sha256 is not None and _hash(raw) != expected_source_sha256:
                raise Refused("Factory publisher source changed before immutable trust enrollment")
            key = publisher_inputs.public_key(raw, fingerprint, runner=self.runner, temporary_root=self.temp)
            public = key["public"]
            target = self.etc / "release-public.pem"
            receipt = {"schema": 1, "state": "enrolled", "installation_id": identity, "algorithm": "RSA-PSS-SHA256",
                       "rsa_bits": key["rsa_bits"], "spki_sha256": fingerprint, "pem_sha256": _hash(public),
                       "initial_enrollment_sha256": _hash(initial_raw),
                       "public_key": str(target), "trust_source": trust_source}
            # Verify all existing state before any write. Crash after key installation
            # resumes only from the exact durable pending receipt and key bytes.
            for name in ("publisher-pending.json", "publisher-trust.json"):
                if (self.state / name).exists() and _json(self.state / name) != receipt:
                    raise Refused("Publisher trust already differs; automatic rotation is refused")
            if target.exists() or target.is_symlink():
                if _read(target, 16384) != public:
                    raise Refused("Installed publisher key differs; automatic trust rotation is refused")
            _same_or_write(self.state / "publisher-pending.json", receipt)
            _write_key(target, public)
            _same_or_write(self.state / "publisher-trust.json", receipt)
            enrolled_key(self.state, target)
            audit(self.state / "history.jsonl", "update.publisher_enrolled", installation_id=identity, spki_sha256=fingerprint)
            return {"schema": 1, "ok": True, "status": "enrolled", "installation_id": identity,
                    "public_key": str(target), "spki_sha256": fingerprint, "trust_source": trust_source}


def main(argv=None):
    argparse.ArgumentParser(description="Enroll measured installed release; no signer is generated").parse_args(argv)
    try:
        print(json.dumps(UpdateEnrollment().installed(), indent=2, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc) if isinstance(exc, Refused) else "Installed release enrollment failed"}), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
