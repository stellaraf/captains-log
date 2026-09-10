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

from nebulalog_manager import os_payload
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

    def backup(self, stage, *, os_backup=False):
        release = {}
        if not os_backup:
            release, _ = self.release(stage)
        self.encrypted()
        destination = stage / "recovery"
        destination.mkdir(mode=0o700, exist_ok=False)
        self.maintenance(True, stage)
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
                self.maintenance(False, stage)
            return result
        except BaseException as failure:
            # The manager does not invoke rollback for preflight/backup failures.
            # Preserve active=true if service recovery itself fails.
            try:
                self.service("start", ("keycloak", "api"))
                self.api_ready()
                self.maintenance(False, stage)
                self.receipt(stage, "backup-recovery", recovered=True, services=["keycloak", "api"])
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

    def health(self, stage, *, os_health=False):
        release = {}
        if os_health:
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
        """Retry same-boot postcheck acceptance, without repeating package changes."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock"), locked(self.data / "manager/updates/transaction.lock"):
            path = self.data / "manager/os-latest.json"
            journal = self.data / "manager/os-transaction.json"
            latest = json.loads(trusted_file(path).read_text())
            transaction = json.loads(trusted_file(journal).read_text())
            stage = Path(latest["stage"])
            retry = transaction.get("state") == "recovery_required" or (
                transaction.get("state") == "complete" and transaction.get("finalization") in ("pending", "failed"))
            if (not retry or transaction.get("recovery_phase") not in ("updating", "postcheck")
                    or stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve()
                    or transaction.get("stage") != str(stage)
                    or latest.get("state") not in ("prepared", "postcheck_failed", "postcheck_passed")
                    or not latest.get("boot_id") or latest["boot_id"] != transaction.get("boot_id") or latest["boot_id"] != self.boot_id()):
                raise Refused("OS recovery requires the exact retained same-boot postcheck transaction")
            marker = self.data / "manager/maintenance.json"
            if marker.exists() and json.loads(trusted_file(marker).read_text()).get("release") != str(stage):
                raise Refused("Another transaction owns appliance maintenance")
            self.maintenance(True, stage)
            try:
                self.checked_backup(stage)
                os_payload.accept_integrity(stage, runner=self.cmd)
                result = self.health(stage, os_health=True)
                if result.get("ok") is not True or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
                    raise Refused("OS runtime, security or compliance acceptance failed")
                reboot = False
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
            completed = {**transaction, "state": "complete", "status": "updated", "finalization": "pending",
                         "reboot_pending": reboot, "health": result["checks"],
                         "completed_at": datetime.now(timezone.utc).isoformat()}
            atomic_json(journal, completed)
            try:
                self.maintenance(False, stage)
            except Exception as exc:
                atomic_json(journal, {**completed, "finalization": "failed", "finalization_error": type(exc).__name__})
                raise Refused("OS health passed; retry os-recover to release maintenance") from exc
            atomic_json(journal, {**completed, "finalization": "complete"})
            audit(self.data / "manager/audit.jsonl", "os.recovery_verified", reboot_pending=reboot)
            return self.receipt(stage, "os-recover", checks=result["checks"], status="updated", reboot_pending=reboot)

    def unlock_readiness(self):
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
        candidate = self.cmd(["grubby", "--default-kernel"])
        if not re.fullmatch(r"/boot/vmlinuz-[A-Za-z0-9._+-]+", candidate):
            raise Refused("Unrecognized default boot kernel")
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
        stage = Path(latest["stage"])
        if stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve():
            raise Refused("OS recovery directory is outside the manager")
        observed = datetime.fromisoformat(latest["observed_at"])
        if (datetime.now(timezone.utc) - observed).total_seconds() > 7200:
            raise Refused("OS recovery backup is stale")
        self.checked_backup(stage)
        unlock = self.unlock_readiness()
        local_auth(self.config)
        boot_id = self.boot_id()
        self.maintenance(True, stage)
        try:
            self.service("stop", tuple(reversed(self.services)))
            self.cmd(["sync", "-f", str(self.data)], timeout=120)
        except BaseException:
            self.service("start", self.services)
            self.api_ready()
            local_auth(self.config)
            self.maintenance(False, stage)
            raise
        atomic_json(self.data / "manager/os-latest.json", {**latest, "state": "reboot_prepared", "boot_id": boot_id})
        return self.receipt(stage, "reboot-prepare", unlock=unlock, services_stopped=list(self.services), boot_id=boot_id)

    def reboot_abort(self):
        self.guard()
        self.encrypted()
        latest = json.loads(trusted_file(self.data / "manager/os-latest.json").read_text())
        stage = Path(latest["stage"])
        if stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve() or latest.get("state") != "reboot_prepared":
            raise Refused("No operation-owned prepared reboot can be aborted")
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
            for path, terminal in ((self.state / "transaction.json", ("committed", "rolled_back", "preflight_failed")),
                                   (self.data / "manager/os-transaction.json", ("complete", "failed", "reboot_aborted"))):
                if not path.exists():
                    continue
                record = json.loads(trusted_file(path).read_text())
                pending = record.get("state") not in terminal or record.get("finalization", "complete") != "complete"
                if pending:
                    self.maintenance(True, Path(record.get("release", str(self.data / "manager"))))
                    return {"ok": True, "maintenance": True, "source": "interrupted transaction"}
            return {"ok": True, "maintenance": False, "source": "no pending transaction"}

    def reboot_complete(self):
        """Reconcile an actual new boot; never clear a gate on same-boot success."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock"):
            path = self.data / "manager/os-latest.json"
            journal = self.data / "manager/os-transaction.json"
            if not path.exists() or not journal.exists():
                return {"ok": True, "status": "not_pending"}
            latest = json.loads(trusted_file(path).read_text())
            transaction = json.loads(trusted_file(journal).read_text())
            if transaction.get("state") == "complete" and transaction.get("finalization", "complete") == "complete":
                return {"ok": True, "status": "not_pending"}
            stage = Path(latest["stage"])
            if stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve():
                raise Refused("Untrusted OS recovery directory")
            if latest.get("state") not in ("reboot_prepared", "recovery_required", "reboot_completed") or transaction.get("state") not in ("reboot_requested", "recovery_required", "complete"):
                raise Refused("Interrupted OS work has not reached the verified reboot phase")
            current_boot = self.boot_id()
            if not latest.get("boot_id") or current_boot == latest["boot_id"]:
                raise Refused("Reboot completion requires a different observed boot identity")
            self.maintenance(True, stage)
            result = self.health(stage, os_health=True)
            if result.get("ok") is not True or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
                atomic_json(path, {**latest, "state": "recovery_required", "observed_boot_id": current_boot})
                atomic_json(journal, {**transaction, "state": "recovery_required", "observed_boot_id": current_boot})
                audit(self.data / "manager/audit.jsonl", "os.reboot_health_failed", boot_id=current_boot)
                raise Refused("New-boot health or local MFA failed; maintenance remains active")
            # Record a successfully booted, accepted OS before releasing maintenance.
            atomic_json(path, {**latest, "state": "reboot_completed", "observed_boot_id": current_boot})
            completed = {**transaction, "state": "complete", "finalization": "pending", "reboot_pending": False,
                         "observed_boot_id": current_boot, "completed_at": datetime.now(timezone.utc).isoformat()}
            atomic_json(journal, completed)
            try:
                self.maintenance(False, stage)
            except Exception as exc:
                atomic_json(journal, {**completed, "finalization": "failed", "finalization_error": type(exc).__name__})
                raise Refused("New OS boot passed; retry reboot-complete to release maintenance") from exc
            atomic_json(journal, {**completed, "finalization": "complete"})
            audit(self.data / "manager/audit.jsonl", "os.reboot_verified", boot_id=current_boot)
            return self.receipt(stage, "reboot-complete", boot_id=current_boot, checks=result["checks"], status="complete")
