"""Real same-schema Podman/Quadlet transactions inside the encrypted Rocky appliance.

This module never executes a path or hook obtained from a release manifest. OCI
archives are loaded locally and immutable image references are checked before use.
"""
from datetime import datetime, timezone
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPSHandler, ProxyHandler, Request
import uuid

from nebulalog_manager import aide, kernel_boot, kernel_integrity, kernel_retention, kernel_retention_integration, kernel_updates, os_payload
from nebulalog_manager.backup import _encrypted_staging
from nebulalog_manager.baseline import Baseline, _json as baseline_json, rule_results
from nebulalog_manager.common import CommandFailed, Refused, atomic_json, audit, locked, require_linux_root, trusted_file
from nebulalog_manager.security import status as security_status, scan
from nebulalog_manager.updates import digest_file, REQUIRED_CHECKS
from .auth import LocalHTTPSHandler, local_auth, response_bytes, tls_context
from .commands import Commands
from .host_runtime import HostRuntime

DATA = Path("/var/lib/nebulalog")
CONFIG = DATA / "configuration"
QUADLETS = Path("/etc/containers/systemd")
STATE = DATA / "manager/updates"
NAMES = {
    "nebulalog": ("api", "ingest"),
    "postgresql": ("postgresql",),
    "clickhouse": ("clickhouse",),
    "keycloak": ("keycloak",),
    "edge": ("edge",),
}
ORDER = ("postgresql", "clickhouse", "keycloak", "api", "ingest")
IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[a-zA-Z_][a-zA-Z_0-9]{0,62}")
IDENTITY_GATES = frozenset(("local_password_otp", "ad_ldaps_otp", "saml_okta", "saml_entra", "saml_generic", "oidc_generic"))


def atomic_file(path, body, mode=0o600, owner=None):
    if path.is_symlink():
        raise Refused("Refusing a symlink activation target")
    fd, name = tempfile.mkstemp(prefix=".nebulalog-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            if owner is not None:
                os.fchown(stream.fileno(), *owner)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def inventory(directory):
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise Refused("Configuration and backup inventories refuse links/special files")
        if path.is_file():
            files.append({"path": path.relative_to(directory).as_posix(), "bytes": path.stat().st_size,
                          "sha256": digest_file(path), "mode": path.stat().st_mode & 0o777,
                          "uid": path.stat().st_uid, "gid": path.stat().st_gid})
    return files


def verify_inventory(directory, expected):
    actual = inventory(directory)
    if actual != expected:
        raise Refused("Recovery inventory no longer matches its captured bytes and permissions")


def image_from_quadlet(text):
    matches = re.findall(r"^Image=(.*)$", text, re.MULTILINE)
    if len(matches) != 1 or not IMAGE.fullmatch(matches[0]):
        raise Refused("Existing Quadlet must have one immutable SHA256 image pin")
    return matches[0]


def load_config(path=CONFIG / "lifecycle.json"):
    trusted_file(path)
    if path.stat().st_mode & 0o077:
        raise Refused("Lifecycle credentials must be root-only")
    value = json.loads(path.read_text())
    if value.get("schema") != 1 or value.get("data_root", str(DATA)) != str(DATA):
        raise Refused("Unsupported lifecycle configuration")
    if value.get("quadlet_dir", str(QUADLETS)) != str(QUADLETS) or value.get("manager_state", str(STATE)) != str(STATE):
        raise Refused("Lifecycle paths do not match the installed appliance")
    api = urlsplit(value.get("api_url", ""))
    if api.hostname not in ("127.0.0.1", "::1", "localhost") or api.scheme not in ("http", "https") or api.username:
        raise Refused("Lifecycle API checks must use the local appliance")
    if value.get("edge_service") not in (None, "nebulalog-edge.service"):
        raise Refused("Unsupported edge service")
    if not isinstance(value.get("auth_probe"), dict) or not value.get("issuer", "").startswith("https://"):
        raise Refused("Local password/OTP health identity is not configured")
    return value


class Lifecycle:
    def __init__(self, config, commands=None, *, state=STATE, data=DATA, configuration=CONFIG,
                 quadlets=QUADLETS, guard=require_linux_root):
        self.config = config
        self.cmd = commands or Commands()
        self.state, self.data, self.configuration, self.quadlets = state, data, configuration, quadlets
        self.guard = guard
        self.services = ORDER + (("edge",) if config.get("edge_service") else ())

    def receipt(self, stage, action, **details):
        value = {"ok": True, "action": action, "observed_at": datetime.now(timezone.utc).isoformat(), **details}
        atomic_json(stage / ("adapter-" + action + ".json"), value)
        return value

    def encrypted(self):
        _encrypted_staging(self.data / "manager", self.cmd)
        temporary = self.data / "tmp"
        temporary.mkdir(mode=0o700, exist_ok=True)
        if temporary.is_symlink() or temporary.stat().st_uid != 0 or temporary.stat().st_mode & 0o077:
            raise Refused("Image extraction requires a private root-owned encrypted temporary directory")
        # Canonical configuration/credential files remain on encrypted storage.
        data = json.loads(self.cmd(["findmnt", "--json", "--target", str(self.data)]))["filesystems"]
        config = json.loads(self.cmd(["findmnt", "--json", "--target", str(self.configuration)]))["filesystems"]
        if len(config) != 1 or config[0]["fstype"] != "xfs" or config[0]["source"].split("[")[0] != data[0]["source"].split("[")[0]:
            raise Refused("Runtime secrets/configuration must reside on the encrypted data filesystem")

    def release(self, stage):
        self.guard()
        if stage.is_symlink() or stage.resolve().parent != (self.state / "releases").resolve():
            raise Refused("Adapter release is not a manager-owned staging directory")
        transaction = json.loads(trusted_file(self.state / "transaction.json").read_text())
        manifest = trusted_file(stage / "manifest.json")
        if transaction.get("release") != str(stage) or transaction.get("manifest_sha256") != digest_file(manifest):
            raise Refused("Adapter release does not match the durable verified transaction")
        release = json.loads(manifest.read_text())
        if not set(release["components"]) <= set(NAMES) | {"host"}:
            raise Refused("This runtime adapter accepts OCI application and fixed host components; baseline/SCAP content requires a qualified content adapter")
        for artifact in release["artifacts"]:
            name = artifact["name"]
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}", name):
                raise Refused("Unsafe staged artifact")
            if "host" in release["components"] and transaction.get("state") in {"rolling_back", "rolled_back", "recovery_required"}:
                # Restoring retained prior code/data never needs candidate bytes.
                # Manager rechecks retained signature; backup and old-generation
                # hashes remain mandatory at their respective restore boundaries.
                continue
            source = trusted_file(stage / name)
            if source.stat().st_size != artifact["bytes"] or digest_file(source) != artifact["sha256"]:
                raise Refused("Signed artifact changed after manager verification")
        return release, transaction

    def service(self, action, names):
        for name in names:
            if name not in self.services:
                raise Refused("Unknown appliance service")
            unit = "nebulalog-" + name + ".service"
            self.cmd(["systemctl", action, unit], timeout=180)
            wanted = "active" if action == "start" else "inactive"
            observed = self.cmd(["systemctl", "show", "--property=ActiveState", "--value", unit])
            if observed != wanted:
                raise Refused("Service did not reach its requested state: " + name)
            if action == "stop" and self.cmd(["systemctl", "show", "--property=Result", "--value", unit]) != "success":
                raise Refused("Service did not stop gracefully: " + name)

    def maintenance(self, active, stage):
        private = self.data / "manager/maintenance.json"
        public = Path("/run/nebulalog-public/maintenance.json")
        if active:
            value = {"active": True, "release": str(stage),
                     "observed_at": datetime.now(timezone.utc).isoformat(), "reason": "appliance component maintenance"}
            atomic_json(private, value)
            public.parent.mkdir(mode=0o755, exist_ok=True)
            info = public.parent.lstat()
            if public.parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise Refused("Public maintenance directory is not root-controlled")
            os.chmod(public.parent, 0o755)
            atomic_file(public, (json.dumps(value) + "\n").encode(), 0o644)
            self.cmd(["restorecon", "-RF", str(public.parent)])
        else:
            for marker in (public, private):
                if marker.exists() or marker.is_symlink():
                    trusted_file(marker)
                    marker.unlink()
                    descriptor = os.open(marker.parent, os.O_RDONLY)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)

    def pg(self, args, *, input=None, timeout=120):
        return self.cmd(["podman", "exec", "--user", "999:999", "nebulalog-postgresql", *args], input=input, timeout=timeout)

    def sql(self, query):
        return self.pg(["psql", "-X", "--username=postgres", "--dbname=postgres", "--tuples-only", "--no-align",
                        "--set=ON_ERROR_STOP=1", "--command", query])

    def pg_ready(self, timeout=120):
        deadline = time.monotonic() + timeout
        while True:
            try:
                if self.sql("SELECT 1") == "1":
                    return
            except Exception:
                pass
            if time.monotonic() >= deadline:
                raise Refused("PostgreSQL did not become ready before the recovery deadline")
            time.sleep(2)

    def api_ready(self, timeout=120):
        deadline = time.monotonic() + timeout
        while True:
            try:
                if json.loads(self.get("/api/health")).get("status") == "ok":
                    return
            except Exception:
                pass
            if time.monotonic() >= deadline:
                raise Refused("API/databases did not become ready before the recovery deadline")
            time.sleep(2)

    def ch(self, query, params=()):
        return self.cmd(["podman", "exec", "--user", "101:101", "nebulalog-clickhouse", "clickhouse-client",
                         "--config-file=/etc/nebulalog/clickhouse-client.xml", "--max_execution_time=15",
                         "--query", query, *params], timeout=30)

    def preflight(self, stage):
        release, transaction = self.release(stage)
        self.encrypted()
        if (self.data / "manager/maintenance.json").exists():
            raise Refused("Existing maintenance requires completion before another component update")
        graphroot = Path(self.cmd(["podman", "info", "--format", "{{.Store.GraphRoot}}"])).resolve()
        if not graphroot.is_relative_to(self.data.resolve()):
            raise Refused("Podman image storage must reside on the encrypted data filesystem")
        if not security_status(self.cmd)["host_controls_ok"]:
            raise Refused("Host security controls are unhealthy")
        for name in self.services:
            if self.cmd(["systemctl", "show", "--property=ActiveState", "--value", "nebulalog-" + name + ".service"]) != "active":
                raise Refused("Preflight requires the expected appliance services to be running")
        local_auth(self.config)
        previous = transaction["previous"]["components"]
        for component, change in release["components"].items():
            if component == "host":
                continue
            if change.get("rollback_safe") is not True or not IMAGE.fullmatch(change.get("image", "")):
                raise Refused("Every component needs a reversible release and an immutable OCI image")
            if change.get("database_migration") != "none" or change.get("schema_revision") != self.config["schema_revision"]:
                raise Refused("Automatic component updates require the current schema; controlled migrations are a separate qualification")
            if component not in previous:
                raise Refused("Component is not part of the installed release")
            old = previous[component]["version"]
            new = change["version"]
            if component == "postgresql" and old.split(".")[0] != new.split(".")[0]:
                raise Refused("Automatic PostgreSQL major upgrades are not supported")
            if component == "clickhouse" and (old.split(".")[:2] != new.split(".")[:2] or change.get("family") != ".".join(new.split(".")[:2])):
                raise Refused("ClickHouse changes must stay within the signed supported family")
            if component == "keycloak":
                self.identity_qualification(stage, release, change)
            for name in NAMES[component]:
                source = trusted_file(self.quadlets / ("nebulalog-" + name + ".container"))
                old_image = image_from_quadlet(source.read_text())
                self.cmd(["podman", "image", "inspect", old_image], timeout=30)
        self.sql("SELECT 1")
        self.ch("SELECT 1")
        if shutil.disk_usage(self.data).free < sum(item["bytes"] for item in release["artifacts"]) * 3 + 1024**3:
            raise Refused("Insufficient staged-image and metadata backup reserve")
        host = {"host": HostRuntime(self, stage).preflight()} if "host" in release["components"] else {}
        return self.receipt(stage, "preflight", components=list(release["components"]),
                            schema_revision=self.config["schema_revision"], logs_backup=False, **host)

    @staticmethod
    def identity_qualification(stage, release, change):
        artifacts = {item["name"] for item in release["artifacts"]}
        name = change.get("qualification_artifact")
        if name not in artifacts:
            raise Refused("Keycloak changes require signed candidate-specific browser qualification evidence")
        report = json.loads(trusted_file(stage / name).read_text())
        if (report.get("schema") != 1 or report.get("keycloak_image") != change["image"]
                or not re.fullmatch(r"[0-9a-f]{40,64}", report.get("source_commit", ""))
                or not isinstance(report.get("checks"), dict)):
            raise Refused("Identity browser qualification does not match this candidate")
        for gate in IDENTITY_GATES:
            check = report["checks"].get(gate, {})
            if (check.get("status") != "passed" or check.get("method") != "real_browser"
                    or check.get("evidence_artifact") not in artifacts
                    or check.get("evidence_artifact") == name):
                raise Refused("Required prerelease identity browser evidence is missing: " + gate)
        return {"artifact": name, "checks": sorted(IDENTITY_GATES), "kind": "signed prerelease browser qualification"}

    def backup(self, stage, *, os_backup=False, retain_maintenance=False, maintenance_owner=None):
        release = {}
        if not os_backup:
            release, _ = self.release(stage)
        owner = maintenance_owner or stage
        if retain_maintenance:
            marker = json.loads(trusted_file(self.data / "manager/maintenance.json").read_text())
            if (not os_backup or owner.is_symlink() or owner.resolve().parent != (self.data / "manager/os-updates").resolve()
                    or marker.get("active") is not True or marker.get("release") != str(owner)):
                raise Refused("Recovery backup requires the existing operation-owned maintenance gate")
        elif maintenance_owner is not None:
            raise Refused("Backup maintenance owner requires retained maintenance")
        self.encrypted()
        destination = stage / "recovery"
        destination.mkdir(mode=0o700, exist_ok=False)
        self.maintenance(True, owner)
        try:
            self.service("stop", ("api", "keycloak"))
            owners = json.loads(self.sql("SELECT json_object_agg(datname,pg_get_userbyid(datdba)) FROM pg_database WHERE datname IN ('nebulalog','keycloak')"))
            if set(owners) != {"nebulalog", "keycloak"} or any(not IDENTIFIER.fullmatch(owner) for owner in owners.values()):
                raise Refused("Recovery requires the two known databases and safe observed owner identities")
            role_sql = "SELECT json_object_agg(rolname,rolpassword) FROM pg_authid WHERE rolname IN (" + ",".join("'" + owner + "'" for owner in sorted(set(owners.values()))) + ")"
            roles = json.loads(self.sql(role_sql))
            for database in ("nebulalog", "keycloak"):
                target = destination / (database + ".dump")
                self.cmd.capture(["podman", "exec", "--user", "999:999", "nebulalog-postgresql", "pg_dump",
                                  "--username=postgres", "--dbname=" + database, "--format=custom"], target, timeout=600)
                self.cmd.feed(["podman", "exec", "-i", "--user", "999:999", "nebulalog-postgresql",
                               "pg_restore", "--list"], target, timeout=120)
            # Validate before copy; copy2 alone would follow symlinks.
            configuration_files = inventory(self.configuration)
            shutil.copytree(self.configuration, destination / "configuration")
            directories = []
            for path in [self.configuration, *self.configuration.rglob("*")]:
                target = destination / "configuration" / path.relative_to(self.configuration)
                info = path.stat()
                os.chown(target, info.st_uid, info.st_gid)
                if path.is_dir():
                    directories.append({"path": path.relative_to(self.configuration).as_posix(),
                                        "uid": info.st_uid, "gid": info.st_gid, "mode": info.st_mode & 0o777})
            verify_inventory(destination / "configuration", configuration_files)
            quadlets = destination / "quadlets"
            quadlets.mkdir(mode=0o700)
            # Apache edge is a native service, not a Quadlet container.
            for name in ORDER:
                path = trusted_file(self.quadlets / ("nebulalog-" + name + ".container"))
                image_from_quadlet(path.read_text())
                shutil.copy2(path, quadlets / path.name)
            evidence = {"schema": 1, "owners": owners, "role_hashes": roles, "configuration_directories": directories,
                        "files": inventory(destination), "includes_clickhouse_logs": False}
            atomic_json(stage / "adapter-backup-inventory.json", evidence)
            host = {"host": HostRuntime(self, stage).backup()} if "host" in release.get("components", {}) else {}
            result = self.receipt(stage, "backup", postgresql=True, configuration=True,
                                  inventory_sha256=digest_file(stage / "adapter-backup-inventory.json"),
                                  ingestion="continues receiving; durable data and WAL are not restored from a metadata backup", **host)
            if os_backup:
                self.service("start", ("keycloak", "api"))
                self.api_ready()
                if not retain_maintenance:
                    self.maintenance(False, owner)
            return result
        except BaseException as failure:
            # The manager does not invoke rollback for preflight/backup failures.
            # Preserve active=true if service recovery itself fails.
            try:
                self.service("start", ("keycloak", "api"))
                self.api_ready()
                if not retain_maintenance:
                    self.maintenance(False, owner)
                self.receipt(stage, "backup-recovery", recovered=True, services=["keycloak", "api"], maintenance_retained=retain_maintenance)
            except BaseException as recovery_error:
                self.receipt(stage, "backup-recovery", ok=False, recovered=False,
                             error=type(recovery_error).__name__, original_error=type(failure).__name__)
                raise Refused("Backup failed and writer recovery failed; maintenance remains active") from recovery_error
            raise

    def checked_backup(self, stage):
        receipt = json.loads(trusted_file(stage / "adapter-backup.json").read_text())
        manifest = trusted_file(stage / "adapter-backup-inventory.json")
        if digest_file(manifest) != receipt["inventory_sha256"]:
            raise Refused("Recovery manifest has changed")
        evidence = json.loads(manifest.read_text())
        verify_inventory(stage / "recovery", evidence["files"])
        return evidence

    def prepare(self, stage):
        release, _ = self.release(stage)
        self.checked_backup(stage)
        prepared = stage / "prepared-quadlets"
        prepared.mkdir(mode=0o700, exist_ok=False)
        images = {}
        for component, change in release["components"].items():
            if component == "host":
                continue
            self.cmd(["skopeo", "copy", "--preserve-digests", "oci-archive:" + str(stage / change["artifact"]),
                      "containers-storage:" + change["image"]], timeout=900)
            observed = json.loads(self.cmd(["podman", "image", "inspect", change["image"]], timeout=30))
            if len(observed) != 1 or change["image"] not in observed[0].get("RepoDigests", []):
                raise Refused("Loaded OCI image digest does not match the signed image reference")
            images[component] = change["image"]
            for name in NAMES[component]:
                source = stage / "recovery/quadlets" / ("nebulalog-" + name + ".container")
                text = source.read_text()
                original = image_from_quadlet(text)
                atomic_file(prepared / source.name, text.replace("Image=" + original, "Image=" + change["image"]).encode(), 0o644)
        host = {"host": HostRuntime(self, stage).prepare(prepared)} if "host" in release["components"] else {}
        return self.receipt(stage, "prepare", images=images, files=inventory(prepared), **host)

    def activate(self, stage):
        release, _ = self.release(stage)
        self.checked_backup(stage)
        preparation = json.loads(trusted_file(stage / "adapter-prepare.json").read_text())
        verify_inventory(stage / "prepared-quadlets", preparation["files"])
        self.service("stop", tuple(reversed(self.services)))
        self.cmd(["sync", "-f", str(self.data)], timeout=120)
        # Fixed file set; no Exec/volume/env changes are accepted from downloaded artifacts.
        for item in preparation["files"]:
            name = item["path"]
            if name not in {"nebulalog-" + n + ".container" for n in self.services}:
                raise Refused("Prepared release contains an unexpected Quadlet")
            atomic_file(self.quadlets / name, (stage / "prepared-quadlets" / name).read_bytes(), 0o644)
        host = HostRuntime(self, stage) if "host" in release["components"] else None
        if host:
            host.apply()
        self.cmd(["systemctl", "daemon-reload"])
        self.service("start", self.services)
        return self.receipt(stage, "activate", services=list(self.services), maintenance=True,
                            durable_data_preserved=True, migration="none",
                            **({"host": host.runtime_evidence("update-activate")} if host else {}))

    def rollback(self, stage):
        release, _ = self.release(stage)
        evidence = self.checked_backup(stage)
        finalized = stage / "adapter-finalize.json"
        historical = finalized.exists() and json.loads(trusted_file(finalized).read_text()).get("transaction_state") == "committed"
        self.maintenance(True, stage)
        self.service("stop", tuple(reversed(self.services)))
        host = HostRuntime(self, stage) if "host" in release["components"] else None
        if host:
            host.apply(rollback=True)
        # Restore original image pins and environment/TLS/identity configuration before services start.
        changed_units = {"nebulalog-" + name + ".container" for component in release["components"] if component != "host" for name in NAMES[component]}
        for source in (stage / "recovery/quadlets").iterdir():
            if historical and source.name not in changed_units:
                continue
            body = source.read_bytes()
            if historical:
                # A later operator rollback must preserve post-update root-owned service settings.
                current = trusted_file(self.quadlets / source.name).read_text()
                body = current.replace("Image=" + image_from_quadlet(current),
                                       "Image=" + image_from_quadlet(source.read_text())).encode()
            atomic_file(self.quadlets / source.name, body, source.stat().st_mode & 0o777)
        if historical:
            self.cmd(["systemctl", "daemon-reload"])
            self.service("start", self.services)
            return self.receipt(stage, "rollback", restored_image_pins=True, current_databases_preserved=True,
                                current_configuration_preserved=True, kind="same-schema operator rollback",
                                **({"host": host.runtime_evidence("update-rollback")} if host else {}))
        expected_files = {f["path"] for f in inventory(stage / "recovery/configuration")}
        for existing in self.configuration.rglob("*"):
            if existing.is_symlink():
                raise Refused("Refusing a link in live configuration during rollback")
            if existing.is_file() and existing.relative_to(self.configuration).as_posix() not in expected_files:
                raise Refused("Unexpected new configuration requires manual reconciliation before rollback")
        for item in sorted(evidence["configuration_directories"], key=lambda item: len(Path(item["path"]).parts)):
            directory = self.configuration / item["path"]
            directory.mkdir(parents=True, exist_ok=True, mode=item["mode"])
            os.chown(directory, item["uid"], item["gid"])
            os.chmod(directory, item["mode"])
        for item in inventory(stage / "recovery/configuration"):
            target = self.configuration / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_file(target, (stage / "recovery/configuration" / item["path"]).read_bytes(), item["mode"], (item["uid"], item["gid"]))
        self.cmd(["restorecon", "-RF", str(self.configuration)], timeout=120)
        self.cmd(["systemctl", "daemon-reload"])
        self.service("start", ("postgresql",))
        self.pg_ready()
        owners = evidence["owners"]
        query = "SELECT json_object_agg(rolname,rolpassword) FROM pg_authid WHERE rolname IN (" + ",".join("'" + owner + "'" for owner in sorted(set(owners.values()))) + ")"
        if json.loads(self.sql(query)) != evidence["role_hashes"]:
            raise Refused("Database role credentials changed; automatic restore cannot safely reconcile them")
        for database in ("nebulalog", "keycloak"):
            self.pg(["dropdb", "--username=postgres", "--force", "--if-exists", database])
            self.pg(["createdb", "--username=postgres", "--owner=" + owners[database], database])
            self.cmd.feed(["podman", "exec", "-i", "--user", "999:999", "nebulalog-postgresql", "pg_restore",
                           "--username=postgres", "--exit-on-error", "--single-transaction", "--dbname=" + database],
                          stage / "recovery" / (database + ".dump"), timeout=600)
        self.service("start", tuple(name for name in self.services if name != "postgresql"))
        return self.receipt(stage, "rollback", restored_databases=["nebulalog", "keycloak"],
                            restored_image_pins=True, clickhouse_logs_preserved=True, wal_preserved=True,
                            **({"host": host.runtime_evidence("update-rollback")} if host else {}))

    def get(self, path, token=None):
        headers = {"Authorization": "Bearer " + token} if token else {}
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=tls_context(self.config)))
        with opener.open(Request(self.config["api_url"].rstrip("/") + path, headers=headers), timeout=15) as response:
            return response_bytes(response)

    def web(self):
        issuer = urlsplit(self.config["issuer"])
        opener = build_opener(ProxyHandler({}), LocalHTTPSHandler(context=tls_context(self.config)))
        # Exercise the actual HTTPS edge and its certificate on the local peer.
        with opener.open("https://" + issuer.netloc + "/", timeout=15) as response:
            return response_bytes(response)

    def canary(self):
        marker = "nebulalog-update-health-" + uuid.uuid4().hex
        stamp = datetime.now(timezone.utc).isoformat()
        record = ["1", stamp, "NEBULALOG-HEALTH", "SYSTEM", "general", "0", stamp, "vsys1", "lifecycle-check", "", "", "", "general", "informational", marker, "1", "0x0", "0", "0", "0", "0", "", "nebulalog-health", "0", "", stamp]
        with socket.create_connection(("127.0.0.1", 514), timeout=5) as connection:
            connection.sendall((",".join(record) + "\n").encode())
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            count = self.ch("SELECT count() FROM nebulalog.events WHERE serial='NEBULALOG-HEALTH' AND description={marker:String} AND ingested_at > now()-INTERVAL 5 MINUTE", ["--param_marker=" + marker])
            if int(count) >= 1:
                return {"marker": marker, "transport": "loopback TCP514", "persisted": True}
            time.sleep(1)
        raise Refused("Ingestion health canary did not persist before its deadline")

    def _compliance_context(self):
        policy = self.configuration / "security-policy.json"
        if Path(self.config["compliance_policy"]) != policy:
            raise Refused("Lifecycle assessment requires the selected installation policy")
        setup_path = self.configuration / "bootstrap/setup.json"
        setup = baseline_json(setup_path)
        installation = str(uuid.UUID(setup["installation_id"]))
        images, quadlets = {}, {}
        for name in ORDER:
            image = self.cmd(["podman", "inspect", "--format", "{{.Image}}", "nebulalog-" + name])
            if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", image):
                raise Refused("Running immutable image identity is unavailable")
            images[name] = image.removeprefix("sha256:")
            unit = trusted_file(self.quadlets / ("nebulalog-" + name + ".container"))
            image_from_quadlet(unit.read_text())
            quadlets[name] = digest_file(unit)
        packages = self.cmd(["rpm", "-qa", "--qf", "%{NEVRA}\n"])
        if not packages or len(packages) > 1024 * 1024:
            raise Refused("Installed package inventory is unavailable")
        return {"installation_id": installation, "baseline": setup["baseline"], "boot_id": self.boot_id(),
                "setup_sha256": digest_file(trusted_file(setup_path)),
                "policy_sha256": digest_file(trusted_file(policy)), "images": images, "quadlets": quadlets,
                "packages_sha256": hashlib.sha256("\n".join(sorted(packages.splitlines())).encode()).hexdigest()}

    def compliance(self, stage):
        """Retain one current assessment for explicit review, never reuse an old approval."""
        report = stage / "adapter-compliance.json"
        atomic_json(report, {"status": "checking"})
        try:
            return self._compliance(stage)
        except Exception as exc:
            result = baseline_json(report)
            if result.get("status") == "checking":
                atomic_json(report, {"status": "failed", "error": type(exc).__name__})
            raise

    def _compliance(self, stage):
        context = self._compliance_context()
        binding = hashlib.sha256(json.dumps(context, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        directory = stage / ("compliance-" + binding)
        marker = directory / "lifecycle-binding.json"
        with locked(stage / "compliance.lock"):
            if not directory.exists():
                directory.mkdir(mode=0o700)
                atomic_json(marker, {"schema": 1, "context": context, "scan_complete": False})
                atomic_file(directory / "security-policy.json",
                            trusted_file(self.configuration / "security-policy.json").read_bytes())
            record = baseline_json(marker)
            if record.get("schema") != 1 or record.get("context") != context:
                raise Refused("Lifecycle assessment binding is missing or changed")
            if digest_file(trusted_file(directory / "security-policy.json")) != context["policy_sha256"]:
                raise Refused("Retained assessment policy differs from the installed selection")
            def bounded(argv, **kwargs):
                kwargs["timeout"] = min(kwargs.get("timeout", 120), 900)
                return self.cmd(argv, **kwargs)
            manager = Baseline(directory, runner=bounded)
            scanned = record.get("scan_complete") is not True
            if scanned:
                manager.scan(context["installation_id"], context["baseline"])
                if self._compliance_context() != context:
                    raise Refused("Appliance changed during lifecycle assessment")
                atomic_json(marker, {**record, "scan_complete": True})
            # The existing CLI can review this exact directory. Hold its same
            # lock while validating the attempt, all artifacts and every finding.
            with locked(directory / "baseline.lock"):
                assessment, findings, assessed = manager._validated_assessment(context["installation_id"], context["baseline"])
                if not assessed:
                    raise Refused("Lifecycle assessment contains unusable results")
                automated = bool(assessment["assessments"]) and all(
                    item["automated_assessment_passed"] for item in assessment["assessments"])
                proof = {"configuration": str(directory), "boot_id": context["boot_id"],
                         "assessment_sha256": digest_file(manager.assessment_path),
                         "policy_sha256": context["policy_sha256"], "baseline": context["baseline"],
                         "automated_assessment_passed": automated, "review_complete": False}
                if not automated:
                    try:
                        manager._validate_review(baseline_json(manager.review_path), context["installation_id"],
                                                 context["baseline"], findings)
                    except (Refused, OSError, ValueError, KeyError, TypeError):
                        atomic_json(stage / "adapter-compliance.json", {**proof, "status": "review_required"})
                        raise Refused("Review the exact retained lifecycle assessment before retrying health") from None
                    proof.update(review_complete=True, review_sha256=digest_file(manager.review_path))
                if not scanned:
                    # A same-boot configuration change need not alter RPM or
                    # image identities. Measure every rule again; an old review
                    # can approve only the exact outcomes still observed now.
                    verification = directory / ("verification-" + uuid.uuid4().hex)
                    current = scan(manager.policy_path, verification, bounded)
                    if current.get("host", {}).get("host_controls_ok") is not True:
                        raise Refused("Current host security controls failed during assessment")
                    for item in assessment["assessments"]:
                        if rule_results(verification / (item["kind"] + ".xml"), item["profile"]) != item["rules"]:
                            atomic_json(marker, {**record, "scan_complete": False})
                            atomic_json(stage / "adapter-compliance.json", {**proof, "status": "assessment_changed"})
                            raise Refused("Current rule outcomes changed; a fresh assessment and review are required")
                    proof["verification_report"] = str(verification / "summary.json")
                if self._compliance_context() != context:
                    raise Refused("Appliance changed before lifecycle assessment acceptance")
                current_assessment, current_findings, current_assessed = manager._validated_assessment(
                    context["installation_id"], context["baseline"])
                if not current_assessed or current_assessment != assessment or current_findings != findings:
                    raise Refused("Assessment or current host evidence changed before acceptance")
                if not automated:
                    manager._validate_review(baseline_json(manager.review_path), context["installation_id"],
                                             context["baseline"], findings)
                atomic_json(stage / "adapter-compliance.json", {**proof, "status": "passed"})
                return proof

    def livepatch_health(self, stage):
        self.guard()
        self.encrypted()
        return self.health(stage, livepatch_health=True)

    def health(self, stage, *, os_health=False, livepatch_health=False):
        release = {}
        if os_health and livepatch_health:
            raise Refused("Health operation must have one owner")
        if livepatch_health:
            self.guard()
            if stage.is_symlink() or stage.resolve().parent != (self.state / "livepatch-health").resolve():
                raise Refused("Livepatch health stage is outside protected retained storage")
        elif os_health:
            self.guard()
            if stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve():
                raise Refused("OS health stage is not an operation-owned recovery directory")
        else:
            release, _ = self.release(stage)
        checks = {name: False for name in REQUIRED_CHECKS}
        evidence = {}
        def assess(name, operation):
            try:
                value = operation()
                if value is False:
                    raise Refused("Check did not pass")
                checks[name] = True
                evidence[name] = value
                return value
            except Exception as exc:
                evidence[name] = {"error": type(exc).__name__}
                return None
        # Services can be active while the database/issuer is still starting.
        try:
            self.api_ready()
        except Refused:
            pass
        assess("api", lambda: json.loads(self.get("/api/health")).get("status") == "ok")
        assess("web", lambda: bool(re.search(rb'id=["\']root["\']', self.web())))
        assess("postgresql", lambda: self.sql("SELECT 1") == "1")
        assess("clickhouse", lambda: self.ch("SELECT 1") == "1")
        token = None
        try:
            token, proof = local_auth(self.config)
            checks["local_auth"] = checks["keycloak"] = True
            evidence["local_auth"] = proof
            evidence["keycloak"] = {"issuer": self.config["issuer"], "fresh_session": True}
        except Exception as exc:
            evidence["local_auth"] = {"error": type(exc).__name__}
        host = security_status(self.cmd)
        assess("selinux", lambda: host["selinux"]["value"] == "Enforcing")
        assess("firewall", lambda: host["firewalld"]["value"] == "active")
        def fips():
            if not token or not host["host_controls_ok"]:
                return False
            app = json.loads(self.get("/api/security", token))
            env = json.loads(self.cmd(["podman", "inspect", "--format", "{{json .Config.Env}}", "nebulalog-keycloak"]))
            return app.get("application_crypto_fips_enabled") is True and "KC_FIPS_MODE=strict" in env
        assess("fips", fips)
        assess("luks", lambda: self.encrypted() or True)
        assess("ingestion", self.canary)
        assess("compliance", lambda: self.compliance(stage))
        host = {}
        if "host" in release.get("components", {}):
            checks["host"] = False
            if all(checks.get(key) is True for key in REQUIRED_CHECKS):
                try:
                    host["host"] = HostRuntime(self, stage).runtime_evidence("update-health", accept_integrity=True)
                    checks["host"] = True
                except Exception as exc:
                    evidence["host"] = {"error": type(exc).__name__}
        value = {"ok": all(checks.values()), "checks": checks, "evidence": evidence,
                 "observed_at": datetime.now(timezone.utc).isoformat(), "certification": "not asserted", **host}
        atomic_json(stage / "adapter-health.json", value)
        return value

    def finalize(self, stage):
        release, transaction = self.release(stage)
        if transaction.get("state") not in ("committed", "rolled_back"):
            raise Refused("Maintenance cannot end before a durable completed transaction")
        health = json.loads(trusted_file(stage / "adapter-health.json").read_text())
        if health.get("ok") is not True or not all(health.get("checks", {}).get(key) is True for key in REQUIRED_CHECKS):
            raise Refused("Maintenance cannot end without all runtime acceptance checks")
        host = {}
        if "host" in release["components"]:
            if health.get("checks", {}).get("host") is not True:
                raise Refused("Maintenance cannot end without measured host acceptance")
            host["host"] = HostRuntime(self, stage).runtime_evidence("update-finalize", accept_integrity=True)
        self.maintenance(False, stage)
        if host:
            host["host"]["checks"]["maintenance_released"] = True
        return self.receipt(stage, "finalize", transaction_state=transaction["state"], **host)

    def trusted_repositories(self):
        policy = configparser.ConfigParser(interpolation=None)
        policy.read(trusted_file(Path("/etc/dnf/dnf.conf")))
        if policy.get("main", "gpgcheck", fallback="0") != "1" or policy.get("main", "installonly_limit", fallback="") != "3":
            raise Refused("DNF must verify RPM signatures and retain three kernels")
        key = trusted_file(Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9"))
        if digest_file(key) != self.config.get("rocky_key_sha256"):
            raise Refused("Rocky package verification key does not match enrolled trust")
        permitted = {"baseos", "appstream", "extras"}
        enabled = set()
        for path in Path("/etc/yum.repos.d").glob("*.repo"):
            repository = configparser.ConfigParser(interpolation=None)
            repository.read(trusted_file(path))
            for name in repository.sections():
                if repository.get(name, "enabled", fallback="1") != "1":
                    continue
                if name not in permitted or name in enabled or repository.get(name, "gpgcheck", fallback=policy.get("main", "gpgcheck")) != "1":
                    raise Refused("Unqualified or unsigned enabled package repository")
                if repository.get(name, "gpgkey", fallback="").strip() != "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9":
                    raise Refused("Repository does not use the enrolled Rocky 9 verification key")
                location = repository.get(name, "metalink", fallback=repository.get(name, "mirrorlist", fallback=repository.get(name, "baseurl", fallback="")))
                parsed = urlsplit(location)
                if parsed.scheme != "https" or parsed.hostname not in ("mirrors.rockylinux.org", "download.rockylinux.org", "dl.rockylinux.org"):
                    raise Refused("Repository metadata source is not an allowed Rocky HTTPS endpoint")
                enabled.add(name)
        if not {"baseos", "appstream"} <= enabled:
            raise Refused("Required Rocky repositories are not enabled")
        return sorted(enabled)

    def os_preflight(self):
        self.guard()
        self.encrypted()
        repositories = self.trusted_repositories()
        if not security_status(self.cmd)["host_controls_ok"]:
            raise Refused("OS maintenance requires healthy host security controls")
        if (self.data / "manager/maintenance.json").exists():
            raise Refused("Another maintenance transaction requires completion")
        self.sql("SELECT 1")
        self.ch("SELECT 1")
        local_auth(self.config)
        parent = self.data / "manager/os-updates"
        parent.mkdir(mode=0o700, exist_ok=True)
        stage = parent / uuid.uuid4().hex
        stage.mkdir(mode=0o700)
        result = self.backup(stage, os_backup=True)
        boot_id = self.boot_id()
        atomic_json(self.data / "manager/os-latest.json", {"stage": str(stage), "state": "prepared",
                    "boot_id": boot_id, "observed_at": datetime.now(timezone.utc).isoformat()})
        return {**result, "repositories": repositories, "stage": str(stage), "boot_id": boot_id}

    def os_postcheck(self):
        """Accept the current runtime only against this OS operation's recovery state."""
        self.guard()
        self.encrypted()
        path = self.data / "manager/os-latest.json"
        latest = json.loads(trusted_file(path).read_text())
        transaction = json.loads(trusted_file(self.data / "manager/os-transaction.json").read_text())
        stage = Path(latest["stage"])
        if (stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve()
                or transaction.get("stage") != str(stage) or transaction.get("state") != "postcheck"
                or not latest.get("boot_id") or latest["boot_id"] != transaction.get("boot_id") or latest["boot_id"] != self.boot_id()
                or latest.get("state") not in ("prepared", "postcheck_passed")):
            raise Refused("OS health check is not bound to the active update and recovery directory")
        try:
            self.checked_backup(stage)
            os_payload.accept_integrity(stage, runner=self.cmd)
            result = self.health(stage, os_health=True)
            if result.get("ok") is not True or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
                raise Refused("OS runtime, security or compliance acceptance failed")
        except Exception as exc:
            atomic_json(path, {**latest, "state": "postcheck_failed", "error": type(exc).__name__})
            self.maintenance(True, stage)
            audit(self.data / "manager/audit.jsonl", "os.postcheck_failed", error=type(exc).__name__)
            raise Refused("OS runtime acceptance failed; recovery evidence retained and maintenance remains active") from exc
        atomic_json(path, {**latest, "state": "postcheck_passed"})
        return {**self.receipt(stage, "os-postcheck", checks=result["checks"]), "stage": str(stage)}

    def os_recover(self):
        """Recover retained OS work, including a verified old-kernel recovery boot."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock"), locked(self.data / "manager/updates/transaction.lock"):
            path = self.data / "manager/os-latest.json"
            journal = self.data / "manager/os-transaction.json"
            latest = json.loads(trusted_file(path).read_text())
            transaction = json.loads(trusted_file(journal).read_text())
            stage = Path(latest["stage"])
            current_boot = self.boot_id()
            preparing = transaction.get("state") == "reboot_preparing" or transaction.get("recovery_phase") == "reboot_preparing"
            retry = transaction.get("state") in ("recovery_required", "reboot_preparing") or (
                transaction.get("state") == "complete" and transaction.get("finalization") in ("pending", "failed"))
            if (not retry or not preparing and transaction.get("recovery_phase") not in ("updating", "postcheck")
                    or stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve()
                    or transaction.get("stage") != str(stage)
                    or latest.get("state") not in (("postcheck_passed", "reboot_prepared", "postcheck_failed") if preparing else
                                                  ("prepared", "postcheck_failed", "postcheck_passed"))
                    or preparing and (transaction.get("reboot_pending") is not True or
                                      any(transaction.get("health", {}).get(name) is not True for name in REQUIRED_CHECKS))
                    or not latest.get("boot_id") or latest["boot_id"] != transaction.get("boot_id")
                    or current_boot != latest["boot_id"] and not any(os.path.lexists(stage / name) for name in ("kernel-plan.json", "kernel-deferred.json"))):
                raise Refused("OS recovery requires the exact retained same-boot postcheck transaction")
            marker = self.data / "manager/maintenance.json"
            if marker.exists() and json.loads(trusted_file(marker).read_text()).get("release") != str(stage):
                raise Refused("Another transaction owns appliance maintenance")
            if preparing:
                # The scheduler records reboot_requested BEFORE calling systemd.
                # A retained reboot_preparing operation has not requested a reboot;
                # it may have stopped any subset of services before interruption.
                transaction = {**transaction, "state": "recovery_required", "recovery_phase": "reboot_preparing"}
                atomic_json(journal, transaction)
            self.maintenance(True, stage)
            try:
                self.checked_backup(stage)
                if current_boot != latest["boot_id"]:
                    # Armed boots use their exact GRUB/AIDE reconciliation path.
                    if os.path.lexists(stage / "kernel-boot-current.json"):
                        raise Refused("Owned kernel boot transition requires reboot-complete")
                    if os.path.lexists(stage / "kernel-deferred.json"):
                        _, plan, _, _ = kernel_updates.load_candidate(stage)
                    else:
                        plan, _ = kernel_updates.load_plan(stage)
                    if self.cmd(["/usr/bin/uname", "-r"]) != plan["old_kernel"] or security_status(self.cmd).get("host_controls_ok") is not True:
                        raise Refused("Cross-boot recovery requires the verified old kernel and healthy host controls")
                    kernel_updates.verify_preserved(plan)
                    self.service("start", self.services)
                    latest, transaction, _ = self._os_recovery_backup(stage, latest, transaction)
                    observation = {"recovery_boot_id": current_boot, "recovery_observed_at": datetime.now(timezone.utc).isoformat()}
                    latest = {**latest, **observation}
                    transaction = {**transaction, **observation, "state": "recovery_required"}
                    atomic_json(path, latest)
                    atomic_json(journal, transaction)
                if preparing and self._kernel_candidate(stage) is not None:
                    kernel_boot.abort_candidate(stage, **self._kernel_callbacks())
                os_payload.accept_integrity(stage, runner=self.cmd)
                candidate = self._kernel_candidate(stage)
                if preparing:
                    self.service("start", self.services)
                result = self.health(stage, os_health=True)
                if result.get("ok") is not True or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
                    raise Refused("OS runtime, security or compliance acceptance failed")
                reboot = candidate is not None
                try:
                    self.cmd(["dnf", "needs-restarting", "--reboothint"], timeout=120)
                except CommandFailed as exc:
                    if exc.returncode != 1:
                        raise Refused("Cannot determine whether a reboot is required") from exc
                    reboot = True
            except Exception as exc:
                atomic_json(path, {**latest, "state": "postcheck_failed", "error": type(exc).__name__})
                atomic_json(journal, {**transaction, "state": "recovery_required", "error": type(exc).__name__})
                audit(self.data / "manager/audit.jsonl", "os.recovery_health_failed", error=type(exc).__name__)
                raise Refused("OS recovery acceptance failed; maintenance and recovery evidence remain intact") from exc
            atomic_json(path, {**latest, "state": "postcheck_passed"})
            completed = {**transaction, "state": "complete", "status": "no_updates" if transaction.get("no_updates") is True else "updated", "finalization": "pending",
                         "reboot_pending": reboot, "health": result["checks"], "recovery_phase": "postcheck",
                         "completed_at": datetime.now(timezone.utc).isoformat()}
            atomic_json(journal, completed)
            try:
                self.maintenance(False, stage)
            except Exception as exc:
                atomic_json(journal, {**completed, "finalization": "failed", "finalization_error": type(exc).__name__})
                raise Refused("OS health passed; retry os-recover to release maintenance") from exc
            atomic_json(journal, {**completed, "finalization": "complete"})
            audit(self.data / "manager/audit.jsonl", "os.recovery_verified", reboot_pending=reboot)
            return self.receipt(stage, "os-recover", checks=result["checks"], status=completed["status"], reboot_pending=reboot)

    def _os_recovery_backup(self, stage, latest, transaction):
        """Refresh a stale backup without releasing the owning operation's gate."""
        pointer = stage / "recovery-backup-current.json"
        if os.path.lexists(pointer):
            reference = json.loads(trusted_file(pointer).read_text())
            name = reference.get("filename")
            if set(reference) != {"filename", "sha256"} or not isinstance(name, str) or not re.fullmatch(r"recovery-backup-[0-9a-f]{32}\.json", name):
                raise Refused("Recovery backup reference is invalid")
            intent_path = trusted_file(stage / name)
            intent = json.loads(intent_path.read_text())
            if (digest_file(intent_path) != reference["sha256"]
                    or set(intent) != {"schema", "owner_stage", "boot_id", "previous", "backup", "inventory_sha256"}
                    or intent["schema"] != 1 or intent["owner_stage"] != str(stage)
                    or intent["boot_id"] != transaction.get("boot_id") or latest.get("boot_id") != transaction.get("boot_id")):
                raise Refused("Recovery backup intent no longer matches its operation")
            restored = Path(intent["backup"])
            prior = Path(intent["previous"])
            if (restored.parent != stage.parent or restored.is_symlink() or not re.fullmatch(r"[0-9a-f]{32}", restored.name)
                    or name != "recovery-backup-" + restored.name + ".json"
                    or prior.parent != stage.parent or prior.is_symlink()
                    or any(record.get("recovery_backup_stage", str(stage)) not in (str(prior), str(restored)) for record in (latest, transaction))):
                raise Refused("Recovery backup reference belongs to another operation")
            self.checked_backup(restored)
            receipt = json.loads(trusted_file(restored / "adapter-backup.json").read_text())
            if receipt["inventory_sha256"] != intent["inventory_sha256"]:
                raise Refused("Refreshed recovery backup inventory has changed")
            # The immutable intent makes a crash between these two journal
            # writes resumable without adopting an unrelated recovery backup.
            latest = {**latest, "recovery_backup_stage": str(restored)}
            transaction = {**transaction, "recovery_backup_stage": str(restored)}
            atomic_json(self.data / "manager/os-latest.json", latest)
            atomic_json(self.data / "manager/os-transaction.json", transaction)
        backup_stage = Path(latest.get("recovery_backup_stage", str(stage)))
        if (backup_stage.is_symlink() or backup_stage.parent != stage.parent or not backup_stage.is_dir()
                or latest.get("recovery_backup_stage") != transaction.get("recovery_backup_stage")):
            raise Refused("Recovery backup directory is not bound to the active operation")
        self.checked_backup(backup_stage)
        receipt = json.loads(trusted_file(backup_stage / "adapter-backup.json").read_text())
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(receipt["observed_at"])).total_seconds()
        except (KeyError, TypeError, ValueError):
            raise Refused("Recovery backup timestamp is invalid") from None
        if age < 0:
            raise Refused("Recovery backup timestamp is dated in the future")
        if age > 7200:
            previous = backup_stage
            backup_stage = stage.parent / uuid.uuid4().hex
            backup_stage.mkdir(mode=0o700)
            self.backup(backup_stage, os_backup=True, retain_maintenance=True, maintenance_owner=stage)
            self.checked_backup(backup_stage)
            receipt = json.loads(trusted_file(backup_stage / "adapter-backup.json").read_text())
            intent = {"schema": 1, "owner_stage": str(stage), "boot_id": transaction["boot_id"],
                      "previous": str(previous), "backup": str(backup_stage), "inventory_sha256": receipt["inventory_sha256"]}
            name = "recovery-backup-" + backup_stage.name + ".json"
            kernel_updates.record(stage, name, intent)
            atomic_json(pointer, {"filename": name, "sha256": hashlib.sha256(kernel_updates.encode(intent)).hexdigest()})
            latest = {**latest, "recovery_backup_stage": str(backup_stage)}
            transaction = {**transaction, "recovery_backup_stage": str(backup_stage)}
            atomic_json(self.data / "manager/os-latest.json", latest)
            atomic_json(self.data / "manager/os-transaction.json", transaction)
        return latest, transaction, backup_stage

    def _reboot_binding(self, latest, transaction, *, new_boot=False):
        """Bind a reboot action to its recovery directory and original boot."""
        try:
            stage = Path(latest["stage"])
            original_boot = latest["boot_id"]
            valid_boot = str(uuid.UUID(original_boot)) == original_boot
        except (KeyError, TypeError, ValueError, AttributeError):
            raise Refused("OS reboot is not bound to a valid recovery operation") from None
        parent = self.data / "manager/os-updates"
        if (not valid_boot or not stage.is_absolute() or stage.is_symlink() or not stage.is_dir()
                or stage.parent != parent or stage.resolve().parent != parent.resolve()
                or transaction.get("stage") != str(stage) or transaction.get("boot_id") != original_boot):
            raise Refused("OS reboot is not bound to the exact recovery operation")
        current_boot = self.boot_id()
        if new_boot and current_boot == original_boot:
            raise Refused("Reboot completion requires a different observed boot identity")
        if not new_boot and current_boot != original_boot:
            raise Refused("OS reboot preparation or abort requires the original boot")
        marker = self.data / "manager/maintenance.json"
        if os.path.lexists(marker):
            owner = json.loads(trusted_file(marker).read_text())
            if owner.get("active") is not True or owner.get("release") != str(stage):
                raise Refused("Another transaction owns appliance maintenance")
        return stage, current_boot

    @staticmethod
    def _kernel_candidate(stage):
        # A pending pointer may belong to a prior, explicitly adopted stage.
        # Never discover a candidate merely because a global pointer exists.
        if not any(os.path.lexists(stage / name) for name in ("kernel-plan.json", "kernel-deferred.json", "kernel-completed.json")):
            return None
        return kernel_updates.load_candidate(stage)

    def _kernel_callbacks(self):
        return {"prepare": aide.authorized_update_prepare, "accept": aide.authorized_update_accept, "runner": self.cmd}

    def _kernel_finalize(self, stage, checks):
        if any(checks.get(name) is not True for name in REQUIRED_CHECKS):
            raise Refused("Kernel acceptance requires every runtime check")
        proof = kernel_boot.accepted_transitions(stage, runner=self.cmd)
        if proof["boot_id"] != self.boot_id():
            raise Refused("Kernel acceptance requires the verified current boot")
        if str(uuid.UUID(proof["boot_id"])) != proof["boot_id"]:
            raise Refused("Kernel acceptance boot identity is invalid")
        acceptance = {"schema": 1, **proof, "checks": {name: True for name in REQUIRED_CHECKS}, "finalization": "complete"}
        previous = None
        pointer = stage / "kernel-acceptance-current.json"
        if os.path.lexists(pointer):
            retained, previous, _ = kernel_updates.read_acceptance(stage)
            if retained["boot_id"] == proof["boot_id"]:
                # Older immutable generations predate the optional compound
                # proof. Absence means no authority; preserve their bytes.
                if "retention_integrity_sha256" not in retained and acceptance.get("retention_integrity_sha256") is None:
                    acceptance.pop("retention_integrity_sha256", None)
                if {key: value for key, value in retained.items() if key != "previous_acceptance_sha256"} != acceptance:
                    raise Refused("Current kernel acceptance differs from its retained proof")
                previous = retained["previous_acceptance_sha256"]
        acceptance["previous_acceptance_sha256"] = previous
        name = "kernel-acceptance-" + proof["boot_id"] + ".json"
        kernel_updates.record(stage, name, acceptance)
        atomic_json(pointer, {"boot_id": proof["boot_id"], "sha256": hashlib.sha256(kernel_updates.encode(acceptance)).hexdigest()})
        return kernel_updates.mark_complete(stage, acceptance, runner=self.cmd)

    def _kernel_retention_acceptance(self, stage, backup_stage, directory):
        if directory != stage:
            raise Refused("Kernel retention acceptance belongs to another operation")
        value, checksum, _ = kernel_updates.read_acceptance(stage)
        proof = kernel_boot.accepted_transitions(stage, runner=self.cmd)
        if any(value.get(key) != item for key, item in proof.items()) or value["boot_id"] != self.boot_id():
            raise Refused("Kernel retention requires the exact current accepted boot")
        kernel_integrity.checked_backup(backup_stage)
        health = self.health(stage, os_health=True)
        if health.get("ok") is not True or any(health.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
            raise Refused("Kernel retention requires fresh complete runtime acceptance")
        return {"ok": True, "kernel": value["kernel"], "recovery_kernel": value["recovery_kernel"],
                "boot_id": value["boot_id"], "receipt_sha256": checksum, "install_plan_sha256": value["kernel_plan_sha256"]}

    def _kernel_retain(self, stage, latest, transaction):
        journal = self.data / "manager/os-transaction.json"
        transaction = {**transaction, "kernel_retention": "pending", "finalization": "pending"}
        atomic_json(journal, transaction)
        self.maintenance(True, stage)
        try:
            latest, transaction, backup_stage = self._os_recovery_backup(stage, latest, transaction)
            def accepted(directory):
                return self._kernel_retention_acceptance(stage, backup_stage, directory)
            result = kernel_integrity.retain_three(stage, accepted=accepted, runner=self.cmd)
            if result.get("ok") is not True:
                raise Refused("Kernel retention did not verify its final inventory")
            health = self.health(stage, os_health=True)
            if health.get("ok") is not True or any(health.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
                raise Refused("Kernel retention runtime postcheck failed")
            self.maintenance(False, stage)
        except Exception as exc:
            self.maintenance(True, stage)
            atomic_json(journal, {**transaction, "kernel_retention": "failed", "finalization": "failed", "retention_error": type(exc).__name__})
            raise Refused("Kernel retention requires recovery; maintenance and retained kernels are preserved") from exc
        atomic_json(journal, {**transaction, "kernel_retention": "complete", "finalization": "complete"})
        return result

    def _kernel_retention_resume(self, stage, latest, transaction, current_boot):
        """Reconcile proven erasure after reboot, with no package execution."""
        journal = self.data / "manager/os-transaction.json"
        latest_path = self.data / "manager/os-latest.json"
        transaction = {**transaction, "kernel_retention": "pending", "finalization": "pending"}
        atomic_json(journal, transaction)
        self.maintenance(True, stage)
        try:
            if not os.path.lexists(stage / kernel_retention.INTENT):
                raise Refused("Unattempted retention plan requires a new execution generation")
            latest, transaction, backup_stage = self._os_recovery_backup(stage, latest, transaction)
            original, checksum = kernel_retention.load_historical_plan(stage)
            if original["boot_id"] == current_boot or self.boot_id() != current_boot:
                raise Refused("Retention recovery requires the exact later boot")
            def authorize(directory, plan_sha):
                if directory != stage or plan_sha != checksum or self.boot_id() != current_boot:
                    raise Refused("Retention recovery authorization belongs to another operation")
                return {"ok": True, "stage": str(stage), "boot_id": current_boot,
                        "backup_stage": str(backup_stage), "backup_sha256": kernel_integrity.checked_backup(backup_stage),
                        "operation_sha256": original["operation_sha256"], "retention_plan_sha256": checksum}
            recovered = kernel_retention_integration.recover_later_boot(stage, authorize=authorize, runner=self.cmd)
            if (recovered.get("ok") is not True or recovered.get("status") != "integrity_reconciled"
                    or recovered.get("release_accepted") is not False):
                raise Refused("Retention recovery did not reconcile the exact integrity change")
            health = self.health(stage, os_health=True)
            if health.get("ok") is not True or any(health.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
                raise Refused("Retention recovery requires all current runtime checks")
            self._kernel_finalize(stage, health["checks"])
            result = kernel_retention_integration.finish_later_boot(stage, recovered["compound_ref"],
                accepted=lambda directory: self._kernel_retention_acceptance(stage, backup_stage, directory), runner=self.cmd)
            if result.get("ok") is not True or result.get("status") != "complete":
                raise Refused("Retention recovery completion was not verified")
            postcheck = self.health(stage, os_health=True)
            if postcheck.get("ok") is not True or any(postcheck.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
                raise Refused("Retention recovery runtime postcheck failed")
            latest = {**latest, "state": "reboot_completed", "observed_boot_id": current_boot}
            atomic_json(latest_path, latest)
            transaction = {**transaction, "state": "complete", "kernel_finalization": "complete",
                           "observed_boot_id": current_boot, "reboot_pending": False}
            atomic_json(journal, transaction)
            self.maintenance(False, stage)
        except Exception as exc:
            self.maintenance(True, stage)
            atomic_json(journal, {**transaction, "kernel_retention": "failed", "finalization": "failed",
                                 "retention_error": type(exc).__name__})
            raise Refused("Later-boot kernel retention requires recovery; maintenance remains active") from exc
        atomic_json(journal, {**transaction, "kernel_retention": "complete", "finalization": "complete"})
        return self.receipt(stage, "reboot-complete", boot_id=current_boot, checks=postcheck["checks"],
                            status="complete", reboot_pending=False, retention=result)

    def unlock_readiness(self, candidate_kernel=None):
        if self.config.get("unattended_reboot") is not True:
            raise Refused("Unattended reboot has not been enabled after unlock qualification")
        uuids = set()
        def walk(items):
            return [node for item in items for node in ([item] + walk(item.get("children", [])))]
        for target in ("/", str(self.data)):
            mounts = json.loads(self.cmd(["findmnt", "--json", "--target", target]))["filesystems"]
            tree = json.loads(self.cmd(["lsblk", "--json", "--inverse", "--output", "NAME,TYPE,FSTYPE,UUID", mounts[0]["source"].split("[")[0]]))
            uuids.update(node["uuid"] for node in walk(tree["blockdevices"]) if node.get("fstype") == "crypto_LUKS")
        if not uuids:
            raise Refused("Cannot establish encrypted boot/data ancestry")
        # A candidate may be selected for one boot while the recovery kernel
        # remains the persistent default. Inspect the actual intended initramfs.
        candidate = candidate_kernel if candidate_kernel is not None else self.cmd(["grubby", "--default-kernel"])
        if not isinstance(candidate, str) or not re.fullmatch(r"/boot/vmlinuz-[A-Za-z0-9._+-]+", candidate):
            raise Refused("Unrecognized selected boot kernel")
        trusted_file(Path(candidate))
        initrd = trusted_file(Path(candidate.replace("vmlinuz-", "initramfs-") + ".img"))
        crypttab = self.cmd(["lsinitrd", "--file", "/etc/crypttab", str(initrd)], timeout=120)
        for identity in sorted(uuids):
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", identity) or identity not in crypttab:
                raise Refused("An encrypted boot/data member is missing from the selected initramfs crypttab")
            device = "/dev/disk/by-uuid/" + identity
            metadata = json.loads(self.cmd(["cryptsetup", "luksDump", "--dump-json-metadata", device]))
            tokens = [identifier for identifier, value in metadata.get("tokens", {}).items()
                      if value.get("type") == "systemd-tpm2" and identifier.isdigit()]
            if not tokens:
                raise Refused("Console-only disk unlock cannot satisfy unattended reboot readiness")
            unlocked = False
            for token in tokens:
                try:
                    self.cmd(["cryptsetup", "open", "--test-passphrase", "--token-only", "--token-id", token, device], timeout=30)
                    unlocked = True
                    break
                except Exception:
                    continue
            if not unlocked:
                raise Refused("TPM token could not unlock an encrypted boot/data member")
        return {"candidate_kernel": candidate, "encrypted_members": sorted(uuids), "token_test": True,
                "note": "Current token unlock is tested; new-kernel reboot survival remains an appliance qualification result"}

    def reboot_prepare(self):
        self.guard()
        self.encrypted()
        latest = json.loads(trusted_file(self.data / "manager/os-latest.json").read_text())
        transaction = json.loads(trusted_file(self.data / "manager/os-transaction.json").read_text())
        stage, boot_id = self._reboot_binding(latest, transaction)
        if (latest.get("state") != "postcheck_passed" or transaction.get("state") != "reboot_preparing"
                or transaction.get("reboot_pending") is not True
                or any(transaction.get("health", {}).get(name) is not True for name in REQUIRED_CHECKS)):
            raise Refused("OS reboot preparation requires the accepted pending reboot transaction")
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(latest["observed_at"])).total_seconds()
        except (KeyError, TypeError, ValueError):
            raise Refused("OS recovery backup timestamp is invalid") from None
        if not 0 <= age <= 7200:
            raise Refused("OS recovery backup is stale or dated in the future")
        self.checked_backup(stage)
        candidate = self._kernel_candidate(stage)
        unlock = self.unlock_readiness("/boot/vmlinuz-" + candidate[1]["kernel"]) if candidate is not None else self.unlock_readiness()
        local_auth(self.config)
        self.maintenance(True, stage)
        try:
            self.service("stop", tuple(reversed(self.services)))
            self.cmd(["sync", "-f", str(self.data)], timeout=120)
            if candidate is not None:
                kernel_boot.arm_candidate(stage, **self._kernel_callbacks())
        except BaseException:
            # A successful restart alone is not runtime/security acceptance.
            # Keep the durable gate for os_recover, which checks every required
            # health contract before releasing it.
            try:
                self.service("start", self.services)
            except Exception as exc:
                audit(self.data / "manager/audit.jsonl", "os.reboot_prepare_restart_failed", error=type(exc).__name__)
            raise
        atomic_json(self.data / "manager/os-latest.json", {**latest, "state": "reboot_prepared", "boot_id": boot_id})
        return self.receipt(stage, "reboot-prepare", unlock=unlock, services_stopped=list(self.services), boot_id=boot_id)

    def reboot_abort(self):
        self.guard()
        self.encrypted()
        latest = json.loads(trusted_file(self.data / "manager/os-latest.json").read_text())
        transaction = json.loads(trusted_file(self.data / "manager/os-transaction.json").read_text())
        stage, _ = self._reboot_binding(latest, transaction)
        if latest.get("state") != "reboot_prepared" or transaction.get("state") != "reboot_requested":
            raise Refused("No operation-owned prepared reboot can be aborted")
        self.checked_backup(stage)
        if self._kernel_candidate(stage) is not None:
            kernel_boot.abort_candidate(stage, **self._kernel_callbacks())
        self.service("start", self.services)
        result = self.health(stage, os_health=True)
        if result.get("ok") is not True or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
            raise Refused("Reboot abort runtime acceptance failed; maintenance remains active")
        self.maintenance(False, stage)
        atomic_json(self.data / "manager/os-latest.json", {**latest, "state": "reboot_aborted"})
        return self.receipt(stage, "reboot-abort", services_restarted=list(self.services), recovered=True,
                            health=result["checks"])

    @staticmethod
    def boot_id():
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if not re.fullmatch(r"[0-9a-f-]{36}", value):
            raise Refused("Current boot identity is unavailable")
        return value

    def boot_gate(self):
        """Runs after encrypted mounts and BEFORE the public HTTPS edge starts."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock"):
            private = self.data / "manager/maintenance.json"
            if private.exists():
                marker = json.loads(trusted_file(private).read_text())
                if marker.get("active") is not True:
                    raise Refused("Unrecognized durable maintenance marker")
                self.maintenance(True, Path(marker["release"]))
                return {"ok": True, "maintenance": True, "source": "encrypted marker"}
            for path, owner_key, terminal in ((self.state / "transaction.json", "release", ("committed", "rolled_back", "preflight_failed")),
                                              (self.data / "manager/os-transaction.json", "stage", ("complete", "failed", "reboot_aborted"))):
                if not path.exists():
                    continue
                record = json.loads(trusted_file(path).read_text())
                pending = (record.get("state") not in terminal or record.get("finalization", "complete") != "complete"
                           or record.get("kernel_finalization") in ("pending", "failed")
                           or record.get("kernel_retention") in ("pending", "failed"))
                if pending:
                    self.maintenance(True, Path(record.get(owner_key, str(self.data / "manager"))))
                    return {"ok": True, "maintenance": True, "source": "interrupted transaction"}
            return {"ok": True, "maintenance": False, "source": "no pending transaction"}

    def reboot_complete(self):
        """Reconcile an actual new boot; never clear a gate on same-boot success."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock"), locked(self.data / "manager/updates/transaction.lock"):
            path = self.data / "manager/os-latest.json"
            journal = self.data / "manager/os-transaction.json"
            if not path.exists() or not journal.exists():
                return {"ok": True, "status": "not_pending"}
            latest = json.loads(trusted_file(path).read_text())
            transaction = json.loads(trusted_file(journal).read_text())
            if (transaction.get("state") == "complete" and transaction.get("finalization", "complete") == "complete"
                    and transaction.get("kernel_finalization") not in ("pending", "failed")
                    and transaction.get("kernel_retention") not in ("pending", "failed")):
                return {"ok": True, "status": "not_pending"}
            stage, current_boot = self._reboot_binding(latest, transaction, new_boot=True)
            if (transaction.get("kernel_retention") in ("pending", "failed")
                    and os.path.lexists(stage / "kernel-acceptance-current.json")):
                self.maintenance(True, stage)
                if os.path.lexists(stage / kernel_retention.PLAN):
                    retained_plan, _ = kernel_retention.load_historical_plan(stage)
                    if retained_plan["boot_id"] != current_boot:
                        return self._kernel_retention_resume(stage, latest, transaction, current_boot)
                acceptance, _, _ = kernel_updates.read_acceptance(stage)
                if acceptance["boot_id"] == current_boot and transaction.get("kernel_finalization") == "complete":
                    retained = self._kernel_retain(stage, latest, transaction)
                    return self.receipt(stage, "reboot-complete", boot_id=current_boot, checks=acceptance["checks"],
                                        status="complete", reboot_pending=False, retention=retained)
            transition = os.path.lexists(stage / "kernel-boot-current.json")
            latest_allowed = ("reboot_prepared", "recovery_required", "reboot_completed") + (("postcheck_passed", "postcheck_failed") if transition else ())
            transaction_allowed = ("reboot_requested", "recovery_required", "complete") + (("reboot_preparing",) if transition else ())
            if latest.get("state") not in latest_allowed or transaction.get("state") not in transaction_allowed:
                raise Refused("Interrupted OS work has not reached the verified reboot phase")
            self.maintenance(True, stage)
            candidate = None
            boot_result = None
            try:
                self.checked_backup(stage)
                candidate = self._kernel_candidate(stage)
                if candidate is not None:
                    boot_result = kernel_boot.verify_postboot(stage, **self._kernel_callbacks())
                    if boot_result.get("outcome") not in ("candidate", "recovery"):
                        raise Refused("Kernel reboot outcome was not verified")
                result = self.health(stage, os_health=True)
                if result.get("ok") is not True or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
                    raise Refused("New-boot runtime, security or compliance acceptance failed")
                if boot_result is not None and boot_result["outcome"] == "candidate":
                    kernel_boot.commit_candidate(stage, health={"ok": True, "stage": str(stage), "boot_id": current_boot,
                        "kernel": candidate[1]["kernel"], "checks": result["checks"]}, **self._kernel_callbacks())
            except Exception as exc:
                atomic_json(path, {**latest, "state": "recovery_required", "observed_boot_id": current_boot, "error": type(exc).__name__})
                atomic_json(journal, {**transaction, "state": "recovery_required", "observed_boot_id": current_boot, "error": type(exc).__name__})
                audit(self.data / "manager/audit.jsonl", "os.reboot_health_failed", boot_id=current_boot)
                raise Refused("New-boot recovery or health acceptance failed; maintenance remains active") from exc
            # Record a successfully booted, accepted OS before releasing maintenance.
            atomic_json(path, {**latest, "state": "reboot_completed", "observed_boot_id": current_boot})
            recovered = boot_result is not None and boot_result["outcome"] == "recovery"
            completed = {**transaction, "state": "complete", "finalization": "pending", "reboot_pending": recovered,
                         "observed_boot_id": current_boot, "completed_at": datetime.now(timezone.utc).isoformat()}
            if candidate is not None:
                completed.update(kernel_finalization="recovery_required" if recovered else "pending", kernel_outcome=boot_result["outcome"])
                if recovered:
                    completed.update(kernel_retry="held", kernel_recovery_reason="candidate_not_running_after_reboot")
                else:
                    completed["kernel_retention"] = "pending"
            atomic_json(journal, completed)
            try:
                self.maintenance(False, stage)
            except Exception as exc:
                atomic_json(journal, {**completed, "finalization": "failed", "finalization_error": type(exc).__name__})
                raise Refused("New OS boot passed; retry reboot-complete to release maintenance") from exc
            completed = {**completed, "finalization": "complete"}
            atomic_json(journal, completed)
            if candidate is not None and not recovered:
                try:
                    self._kernel_finalize(stage, result["checks"])
                except Exception as exc:
                    self.maintenance(True, stage)
                    atomic_json(journal, {**completed, "kernel_finalization": "failed", "finalization_error": type(exc).__name__})
                    raise Refused("Kernel boot passed; acceptance finalization requires retry") from exc
                completed = {**completed, "kernel_finalization": "complete"}
                atomic_json(journal, completed)
                self._kernel_retain(stage, {**latest, "state": "reboot_completed", "observed_boot_id": current_boot}, completed)
            audit(self.data / "manager/audit.jsonl", "os.reboot_verified", boot_id=current_boot)
            return self.receipt(stage, "reboot-complete", boot_id=current_boot, checks=result["checks"],
                                status="kernel_recovery_required" if recovered else "complete", reboot_pending=recovered)
