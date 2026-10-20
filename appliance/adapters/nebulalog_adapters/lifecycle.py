"""Podman/Quadlet transactions and fixed schema upgrades in the Rocky appliance.

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

from nebulalog_manager import host_dispatch, host_activation, aide, kernel_boot, kernel_integrity, kernel_retention, kernel_retention_integration, kernel_updates, os_payload
from nebulalog_manager.backup import _encrypted_staging
from nebulalog_manager.baseline import Baseline, ContentUpdate, _json as baseline_json, rule_results
from nebulalog_manager.common import CommandFailed, Refused, atomic_json, audit, locked, require_linux_root, trusted_file
from nebulalog_manager.security import status as security_status, scan
from nebulalog_manager.updates import digest_file, REQUIRED_CHECKS
from nebulalog_manager.image_bundle import ApplicationSchema, strict_json
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
STORAGE_LOCK = 4850182995969828167
STORAGE_OWNER_UID = 0
STORAGE_OWNER_GID = 0


def storage_gate_value(value):
    if (not isinstance(value, dict) or set(value) != {"schema", "held", "delivery_held", "operation"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or type(value["held"]) is not bool or type(value["delivery_held"]) is not bool):
        raise Refused("Invalid host storage maintenance evidence")
    if value["held"]:
        if not isinstance(value["operation"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["operation"]):
            raise Refused("Invalid host storage maintenance owner")
    elif value["delivery_held"] or value["operation"] is not None:
        raise Refused("Inconsistent host storage maintenance evidence")
    return value


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


def _initialization_context(revision, operation):
    if (not isinstance(revision, str) or revision not in ApplicationSchema.RETENTION_REVISIONS
            or not isinstance(operation, str) or not re.fullmatch(r"[0-9a-f]{64}", operation)):
        raise Refused("Unsupported fixed initialization catalog observation")
    return {"operation": operation, "owner": "nebulalog"}


def _fixed_catalog_digest(value):
    collections = {"relations", "columns", "constraints", "indexes", "sequences",
                   "triggers", "rules", "policies", "inheritance"}
    counters = {"extra_objects", "functions", "extra_types", "extensions"}
    if (not isinstance(value, dict) or set(value) != collections | counters
            or any(not isinstance(value[key], list) for key in collections)
            or any(type(value[key]) is not int or value[key] != 0 for key in counters)):
        raise Refused("Unrecognized fixed application catalog")
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _observe_fixed_pg_catalog(commands, revision, operation):
    """Private structural readback; the caller owns factory/restore authority.

    Reconstruct the expected catalog in a disposable transactional namespace.
    No application DDL, row normalization, maintenance transition or enrollment
    occurs here. Restored transient rows may still exist at this boundary.
    """
    context = _initialization_context(revision, operation)
    adapter = Lifecycle({}, commands=commands)
    raw = adapter._schema_psql(adapter._schema_query(context, catalog_only=revision, structural_only=True))
    if not isinstance(raw, str) or not 1 <= len(raw.encode()) <= 256 * 1024:
        raise Refused("Invalid fixed application catalog readback")
    observed = strict_json(raw.encode())
    profile = "host-stepup-v2" if revision == "4" else "host-stepup"
    if (not isinstance(observed, dict) or set(observed) != {"revision", "profile", "catalog", "database"}
            or observed["revision"] != revision or observed["profile"] != profile):
        raise Refused("Fixed application catalog profile differs")
    database = observed["database"]
    if (not isinstance(database, dict)
            or set(database) != {"system_identifier", "database_oid", "database", "owner", "server_version"}
            or database["database"] != "nebulalog" or database["owner"] != "nebulalog"
            or not isinstance(database["system_identifier"], str)
            or not re.fullmatch(r"[1-9][0-9]{0,19}", database["system_identifier"])
            or type(database["database_oid"]) is not int or not 1 <= database["database_oid"] < 2**32
            or type(database["server_version"]) is not int or database["server_version"] // 10000 != 17):
        raise Refused("Fixed application database identity differs")
    return {"schema_revision": revision, "schema_sha256": ApplicationSchema.schema_digest(revision),
            "profile": profile, "catalog_sha256": _fixed_catalog_digest(observed["catalog"]),
            "database": database}


def _observe_ready_application_catalog(commands, revision, operation, *, data=DATA, configuration=CONFIG):
    """Private settled readback under the caller's exact retained delivery hold.

    This is not a public authority route. The installed firstboot/restore
    coordinator must bind its journal, immutable inputs and stopped services
    before calling; release/OS-update stage allowlists remain unchanged.
    """
    context = _initialization_context(revision, operation)
    adapter = Lifecycle({}, commands=commands, data=data, configuration=configuration)
    adapter._schema_hold(None, context)
    structure = _observe_fixed_pg_catalog(commands, revision, operation)
    raw = adapter._schema_psql(adapter._schema_query(context, catalog_only=revision))
    if not isinstance(raw, str) or not 1 <= len(raw.encode()) <= 256 * 1024:
        raise Refused("Invalid settled application catalog readback")
    observed = strict_json(raw.encode())
    if (not isinstance(observed, dict) or set(observed) != {"revision", "catalog", "marker", "profile", "markers"}
            or observed["revision"] != revision or observed["profile"] != structure["profile"]
            or observed["marker"] is not None or observed["markers"] != []
            or _fixed_catalog_digest(observed["catalog"]) != structure["catalog_sha256"]):
        raise Refused("Settled application catalog differs from its fixed profile")
    retention = adapter._retention_table_operation(operation)
    adapter._schema_hold(None, context)
    return {**structure, "markers": [], "retention": retention}


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
        if not set(release["components"]) <= set(NAMES) | {"host", "baseline"}:
            raise Refused("Scanner engine changes require a separately qualified vendor RPM recipe")
        if "baseline" in release["components"] and "host" not in release["components"]:
            raise Refused("Compliance content requires the fixed host coordinator and integrity transaction")
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

    def application_schema_current(self):
        """Read actual schema provenance without changing installation settings.

        lifecycle.json belongs to the customer's protected configuration. A
        completed additive migration therefore has a separate retained pointer;
        rolling back an application image does not roll this pointer backward.
        Live catalog verification is still required under the storage barrier.
        """
        initial = self.config.get("schema_revision")
        ApplicationSchema.schema_digest(initial)
        path = self.data / "manager/application-schema.json"
        if not os.path.lexists(path):
            return {"revision": initial, "state": None}
        if initial in ApplicationSchema.RETENTION_REVISIONS:
            raise Refused("Factory retention schema cannot adopt an unqualified migration pointer")
        value = strict_json(trusted_file(path).read_bytes())
        if (not isinstance(value, dict) or set(value) != {"schema", "revision", "stage", "receipt_sha256"}
                or type(value["schema"]) is not int or value["schema"] != 1 or value["revision"] != "2"
                or not isinstance(value["stage"], str)
                or not isinstance(value["receipt_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["receipt_sha256"])):
            raise Refused("Actual application schema provenance is invalid")
        origin = Path(value["stage"])
        receipt = self.application_schema_receipt(origin)
        if (receipt.get("schema_revision") != value["revision"]
                or digest_file(trusted_file(origin / "adapter-application-schema.json")) != value["receipt_sha256"]):
            raise Refused("Actual application schema differs from retained migration proof")
        return {"revision": value["revision"], "state": value}

    def application_schema_accept(self, stage):
        """Publish only a verified, committed schema outcome under a writer hold."""
        receipt = self.application_schema_verify(stage)
        if receipt.get("state") != "complete" or receipt.get("schema_revision") != "2":
            raise Refused("A completed schema migration is required before activation")
        value = {"schema": 1, "revision": "2", "stage": str(stage),
                 "receipt_sha256": digest_file(trusted_file(stage / "adapter-application-schema.json"))}
        previous = self.application_schema_current()
        if previous["state"] is not None and previous["state"] != value:
            raise Refused("Another retained operation owns the actual schema provenance")
        atomic_json(self.data / "manager/application-schema.json", value)
        return value

    def application_schema_check(self, stage, snapshot=None):
        """Verify live catalog against factory or retained migration authority."""
        value = snapshot if snapshot is not None else self.application_schema_current()
        if (not isinstance(value, dict) or set(value) != {"revision", "state"}
                or not isinstance(value["revision"], str) or value["revision"] not in ApplicationSchema.SCHEMAS):
            raise Refused("Invalid retained application schema snapshot")
        if value["state"] is None:
            if value["revision"] != self.config["schema_revision"]:
                raise Refused("Factory schema snapshot differs from the installed authority")
            observed = self.application_schema_catalog(stage, value["revision"])
            if observed.get("markers", []) != []:
                raise Refused("Factory schema contains unowned migration provenance")
            return observed
        state = value["state"]
        if (not isinstance(state, dict) or set(state) != {"schema", "revision", "stage", "receipt_sha256"}
                or type(state["schema"]) is not int or state["schema"] != 1
                or state["revision"] != "2" or value["revision"] != "2"
                or not isinstance(state["stage"], str)):
            raise Refused("Retained schema snapshot has no exact migration authority")
        origin = Path(state["stage"])
        self.application_schema_receipt(origin)
        if digest_file(trusted_file(origin / "adapter-application-schema.json")) != state["receipt_sha256"]:
            raise Refused("Retained schema snapshot receipt changed")
        return self.application_schema_verify(origin, maintenance_stage=stage)

    def application_schema_restore(self, stage, snapshot):
        """Restore provenance only after restoring and checking the database."""
        self.application_schema_check(stage, snapshot)
        current = self.application_schema_current()
        if current["state"] not in (None, snapshot["state"]) and current["state"].get("stage") != str(stage):
            raise Refused("Another schema operation cannot be erased by rollback")
        path = self.data / "manager/application-schema.json"
        if snapshot["state"] is not None:
            atomic_json(path, snapshot["state"])
        elif os.path.lexists(path):
            trusted_file(path).unlink()
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return self.application_schema_current()

    @staticmethod
    def application_schema_transition(change, revision):
        # An operator image rollback retains the additive schema. A subsequent
        # release can declare the same reviewed transition, but cannot replay it.
        if revision == "2" and change.get("database_migration") == ApplicationSchema.ADDITIVE_UPGRADE:
            ApplicationSchema.transition(change, "1")
            return "none"
        return ApplicationSchema.transition(change, revision)

    def storage_gate_aware_ingest(self):
        """Only a bound schema-2/3/4 application can receive during backup."""
        path = self.state / "current.json"
        if not os.path.lexists(path):
            return False
        current = strict_json(trusted_file(path).read_bytes())
        app = current.get("components", {}).get("nebulalog", {})
        revision = app.get("schema_revision")
        if revision not in ("2", *ApplicationSchema.RETENTION_REVISIONS) or app.get("schema_sha256") != ApplicationSchema.schema_digest(revision):
            return False
        image = app.get("image")
        if (not isinstance(image, str) or not IMAGE.fullmatch(image)
                or image_from_quadlet(trusted_file(self.quadlets / "nebulalog-ingest.container").read_text()) != image):
            return False
        try:
            running = self.cmd(["podman", "inspect", "--format", "{{.Image}}", "nebulalog-ingest"])
            pinned = self.cmd(["podman", "image", "inspect", "--format", "{{.Id}}", image])
            environment = strict_json(self.cmd(["podman", "inspect", "--format", "{{json .Config.Env}}", "nebulalog-ingest"]))
            mounts = strict_json(self.cmd(["podman", "inspect", "--format", "{{json .Mounts}}", "nebulalog-ingest"]))
        except (CommandFailed, Refused, ValueError, TypeError):
            return False
        target = "/run/nebulalog-storage-maintenance"
        if (not isinstance(environment, list) or not all(isinstance(item, str) for item in environment)
                or [item for item in environment if item.startswith("STORAGE_MAINTENANCE_PATH=")]
                    != ["STORAGE_MAINTENANCE_PATH=" + target + "/gate.json"]
                or not isinstance(mounts, list) or not all(isinstance(item, dict) for item in mounts)):
            return False
        gate_mounts = [item for item in mounts if item.get("Destination") == target
                       or isinstance(item.get("Destination"), str) and item["Destination"].startswith(target + "/")]
        if (len(gate_mounts) != 1 or gate_mounts[0].get("Destination") != target
                or gate_mounts[0].get("Type") != "bind" or gate_mounts[0].get("RW") is not False
                or gate_mounts[0].get("Source") != str((self.data / "manager/storage-maintenance").resolve())):
            return False
        return bool(re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", running)
                    and re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", pinned)
                    and running.removeprefix("sha256:") == pinned.removeprefix("sha256:"))

    def database_restore_context(self, stage, backup):
        return {"schema": 1, "stage": str(stage),
                "operation": hashlib.sha256(str(stage).encode()).hexdigest(),
                "backup_sha256": digest_file(trusted_file(stage / "adapter-backup-inventory.json")),
                "application_schema": backup["application_schema"],
                "migration_intent_sha256": digest_file(trusted_file(stage / "adapter-application-schema-intent.json"))
                    if os.path.lexists(stage / "adapter-application-schema-intent.json") else None}

    def database_restore_status(self, stage, backup):
        """Authenticate an interrupted restore without relying on DB existence."""
        context = self.database_restore_context(stage, backup)
        intent = stage / "adapter-database-restore-intent.json"
        complete = stage / "adapter-database-restore-complete.json"
        if not os.path.lexists(intent):
            if os.path.lexists(complete):
                raise Refused("Database restore completion has no retained intent")
            return context, False, False
        if strict_json(trusted_file(intent).read_bytes()) != context:
            raise Refused("Database restore intent differs from its verified backup")
        done = os.path.lexists(complete)
        if done and strict_json(trusted_file(complete).read_bytes()) != context:
            raise Refused("Database restore completion differs from its retained intent")
        if not done:
            # This must precede republishing the host fence. No service start or
            # gate release is permitted until this exact restore is complete.
            gate = storage_gate_value(strict_json(trusted_file(self.data / "manager/storage-maintenance/gate.json").read_bytes()))
            expected = {"schema": 1, "held": True, "delivery_held": True, "operation": context["operation"]}
            if gate != expected:
                raise Refused("Interrupted database restore lost its continuous host hold")
            if context["migration_intent_sha256"] is not None:
                schema_context = self._schema_context(stage)
                executor = self._schema_intent(stage, schema_context)["executor"]
                if self.cmd(["podman", "ps", "--all", "--no-trunc", "--filter",
                             "id=" + executor["container_id"], "--format", "{{.ID}}"]):
                    raise Refused("An interrupted restore's migration client is no longer absent")
        return context, True, done

    def storage_maintenance(self, stage, *, held, delivery_held=False, host_only=False):
        """Publish a restore-independent fence, then cross the application lock.

        This primitive does not migrate a schema or release HTTP maintenance.
        Callers must keep it held across backup, activation, health and restore.
        Unknown PostgreSQL outcomes leave the durable host fence in force.
        The caller holds the existing lifecycle transaction lock throughout.
        """
        self.guard()
        log_stage = stage.parent == self.data / "manager/log-backups"
        if log_stage:
            # Only an existing protected native-backup journal extends the
            # fixed operation catalog. Arbitrary manager paths remain refused.
            from nebulalog_manager.log_backup import owned_stage
            owned_stage(stage, self.data)
        if (not stage.is_absolute() or stage.is_symlink()
                or not log_stage and stage.resolve().parent not in ((self.state / "releases").resolve(),
                                                  (self.data / "manager/os-updates").resolve())):
            raise Refused("Storage maintenance needs a protected lifecycle operation")
        if type(held) is not bool or type(delivery_held) is not bool or not held and delivery_held:
            raise Refused("Invalid storage maintenance transition")
        if type(host_only) is not bool or host_only and not (held and delivery_held):
            raise Refused("A host-only fence can only stop delivery and removal")
        operation = hashlib.sha256(str(stage.resolve()).encode()).hexdigest()
        directory = self.data / "manager/storage-maintenance"
        path = directory / "gate.json"
        if directory.is_symlink():
            raise Refused("Storage maintenance directory cannot be a link")
        try:
            directory.mkdir(mode=0o755)
        except FileExistsError:
            pass
        else:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchown(descriptor, STORAGE_OWNER_UID, STORAGE_OWNER_GID)
                os.fchmod(descriptor, 0o755)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        if (directory.stat().st_uid != STORAGE_OWNER_UID or directory.stat().st_gid != STORAGE_OWNER_GID
                or directory.stat().st_mode & 0o7777 != 0o755):
            raise Refused("Storage maintenance directory must remain root-owned with mode 0755")
        previous = None
        if path.exists() or path.is_symlink():
            trusted_file(path)
            if path.stat().st_size > 4096 or path.stat().st_mode & 0o022:
                raise Refused("Unsafe storage maintenance evidence")
            previous = storage_gate_value(strict_json(path.read_bytes()))
            if previous["held"] and previous["operation"] != operation:
                raise Refused("A different operation owns storage maintenance")
        elif self.application_schema_current()["revision"] != "1" or not held:
            raise Refused("Missing host storage maintenance evidence requires recovery")
        desired = {"schema": 1, "held": held, "delivery_held": delivery_held,
                   "operation": operation if held else None}
        if not held and (previous is None or not previous["held"]):
            journal = stage / "adapter-storage-maintenance.json"
            retained = strict_json(trusted_file(journal).read_bytes()) if journal.exists() else {}
            completed = (retained.get("state") == "complete" and retained.get("ok") is True
                         and retained.get("action") == "storage-maintenance" and retained.get("gate") == desired)
            interrupted = retained.get("state") == "intent" and retained.get("desired") == desired
            if retained.get("operation") != operation or not (completed or interrupted):
                raise Refused("Only the operation holding storage maintenance may release it")
            # A prior clear may have committed and published idle before its
            # receipt. Re-arm the host fence and verify the DB under the lock;
            # the retained exact operation intent permits this one retry only.
        conservative = {"schema": 1, "held": True, "delivery_held": True, "operation": operation}
        # This file is not part of the PostgreSQL backup. Readers recheck it
        # under the same DB lock; a pre-fence in-flight writer must settle first.
        atomic_file(path, (json.dumps(conservative) + "\n").encode(), 0o644)
        atomic_json(stage / "adapter-storage-maintenance.json", {
            "state": "intent", "operation": operation, "desired": desired})
        if host_only:
            # Recovery may need to stop a lost migration client before a DB
            # barrier can finish. This receipt is explicitly not DB completion.
            return {"ok": True, "action": "storage-host-fence", "operation": operation,
                    "gate": conservative, "database_barrier": False}
        encoded = json.dumps(desired, separators=(",", ":"))
        revision = self.application_schema_current()["revision"]
        allow_missing = "true" if revision == "1" else "false"
        require_retention = "true" if revision in ApplicationSchema.RETENTION_REVISIONS else "false"
        # Operation is generated hex; desired JSON contains only fixed keys,
        # booleans, null and that hex. No caller SQL, paths or hooks are executed.
        query = f"""
SET LOCAL search_path=public,pg_catalog;
SET LOCAL lock_timeout='60s';
SET LOCAL statement_timeout='90s';
DO $gate$
DECLARE gate jsonb; engine jsonb; n bigint;
BEGIN
 PERFORM pg_advisory_xact_lock({STORAGE_LOCK});
 SELECT value INTO gate FROM public.settings WHERE key='storage_emergency_maintenance' FOR UPDATE;
 IF gate IS NULL THEN
  IF NOT {allow_missing} THEN RAISE EXCEPTION 'Missing storage maintenance evidence'; END IF;
 ELSE
  IF jsonb_typeof(gate) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Invalid storage maintenance evidence'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(gate)) != 4
   OR NOT gate ?& ARRAY['schema','held','delivery_held','operation']
   OR jsonb_typeof(gate->'schema') IS DISTINCT FROM 'number'
   OR gate->>'schema' IS DISTINCT FROM '1'
   OR jsonb_typeof(gate->'held') IS DISTINCT FROM 'boolean'
   OR jsonb_typeof(gate->'delivery_held') IS DISTINCT FROM 'boolean'
   OR (gate->>'held'='false' AND (gate->>'delivery_held'!='false' OR gate->'operation'!='null'::jsonb))
   OR (gate->>'held'='true' AND (jsonb_typeof(gate->'operation') IS DISTINCT FROM 'string' OR gate->>'operation' IS DISTINCT FROM '{operation}'))
   THEN RAISE EXCEPTION 'Foreign or malformed storage maintenance evidence'; END IF;
 END IF;
 IF to_regclass('public.storage_emergency_actions') IS NOT NULL THEN
  SELECT count(*) INTO n FROM public.storage_emergency_actions WHERE completed_at IS NULL;
  IF n != 0 THEN RAISE EXCEPTION 'Pending removal prevents lifecycle metadata changes'; END IF;
 ELSIF NOT {allow_missing} THEN RAISE EXCEPTION 'Missing emergency action evidence'; END IF;
 IF to_regclass('public.storage_emergency_inserts') IS NOT NULL THEN
  SELECT count(*) INTO n FROM public.storage_emergency_inserts;
  IF n != 0 THEN RAISE EXCEPTION 'Unresolved insertion prevents lifecycle metadata changes'; END IF;
 ELSIF NOT {allow_missing} THEN RAISE EXCEPTION 'Missing emergency insertion evidence'; END IF;
 IF to_regclass('public.retention_actions') IS NOT NULL THEN
  SELECT count(*) INTO n FROM public.retention_actions WHERE completed_at IS NULL;
  IF n != 0 THEN RAISE EXCEPTION 'Pending retention removal prevents lifecycle metadata changes'; END IF;
 ELSIF {require_retention} THEN RAISE EXCEPTION 'Missing retention action evidence'; END IF;
 SELECT value INTO engine FROM public.settings WHERE key='retention_engine';
 IF engine IS NOT NULL THEN
  IF jsonb_typeof(engine) IS DISTINCT FROM 'object' OR engine->'schema' IS DISTINCT FROM '1'::jsonb
   OR engine->>'mode' IS NULL OR engine->>'mode' NOT IN ('uninitialized','partition')
  THEN RAISE EXCEPTION 'Unresolved retention engine prevents lifecycle metadata changes'; END IF;
 ELSIF {require_retention} OR to_regclass('public.retention_actions') IS NOT NULL
 THEN RAISE EXCEPTION 'Missing retention engine evidence'; END IF;
 IF {require_retention} AND engine->>'mode' IS DISTINCT FROM 'partition'
 THEN RAISE EXCEPTION 'Retention engine is not initialized'; END IF;
 INSERT INTO public.settings(key,value) VALUES('storage_emergency_maintenance','{encoded}'::jsonb)
 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;
 INSERT INTO public.audit_events(actor,action,target,detail)
 VALUES('host-lifecycle','storage.emergency.maintenance','{operation}','{encoded}'::jsonb);
END $gate$;
SELECT value::text FROM public.settings WHERE key='storage_emergency_maintenance';
"""
        result = self.cmd(["podman", "exec", "-i", "--user", "999:999", "nebulalog-postgresql",
            "psql", "-X", "--username=postgres", "--dbname=nebulalog", "--single-transaction",
            "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1"],
            input=query.encode(), timeout=120)
        if storage_gate_value(strict_json(result.encode())) != desired:
            raise Refused("Storage maintenance readback differs; host hold remains in force")
        retention = self._retention_table(stage) if revision in ApplicationSchema.RETENTION_REVISIONS else None
        atomic_file(path, (json.dumps(desired) + "\n").encode(), 0o644)
        return self.receipt(stage, "storage-maintenance", state="complete", operation=operation, gate=desired,
                            **({"retention": retention} if retention is not None else {}))

    def _retention_table(self, stage):
        """Bind a retention schema to its unchanged TTL-free physical table.

        The host fence remains conservative across both database observations.
        This is a readback only; an uninitialized/migrating engine is never adopted.
        """
        return self._retention_table_operation(hashlib.sha256(str(stage.resolve()).encode()).hexdigest())

    def _retention_table_operation(self, operation):
        # Private firstboot/restore callers establish their own immutable journal
        # and exact service/pin authority; an operation string grants none.
        if not isinstance(operation, str) or not re.fullmatch(r"[0-9a-f]{64}", operation):
            raise Refused("Invalid retention observation owner")
        expected_gate = {"schema": 1, "held": True, "delivery_held": True, "operation": operation}
        path = self.data / "manager/storage-maintenance/gate.json"
        if storage_gate_value(strict_json(trusted_file(path).read_bytes())) != expected_gate:
            raise Refused("Retention table verification requires the exact host delivery fence")
        query = "SELECT value::text FROM public.settings WHERE key='retention_engine';"
        engine = strict_json(self._schema_psql(query).encode())
        identifier = engine.get("table_uuid") if isinstance(engine, dict) else None
        if (not isinstance(engine, dict) or type(engine.get("schema")) is not int or engine["schema"] != 1
                or engine.get("mode") != "partition" or not isinstance(identifier, str)
                or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", identifier)
                or identifier == "00000000-0000-0000-0000-000000000000"):
            raise Refused("Retention engine has no settled physical table identity")
        raw = self.ch("SELECT toString(uuid) AS uuid,engine,partition_key,create_table_query FROM system.tables "
                      "WHERE database='nebulalog' AND name='events' "
                      "SETTINGS show_table_uuid_in_table_create_query_if_not_nil=0 FORMAT JSONEachRow")
        if len(raw.encode()) > 65536:
            raise Refused("Oversized retention table evidence")
        rows = [strict_json(line.encode()) for line in raw.splitlines() if line.strip()]
        if (len(rows) != 1 or not isinstance(rows[0], dict)
                or set(rows[0]) != {"uuid", "engine", "partition_key", "create_table_query"}
                or rows[0]["uuid"] != identifier or rows[0]["engine"] != "MergeTree"
                or rows[0]["partition_key"] != "(log_type, toDate(ingested_at))"
                or not isinstance(rows[0]["create_table_query"], str) or not rows[0]["create_table_query"].strip()
                or re.search(r"\bTTL\b", rows[0]["create_table_query"], flags=re.IGNORECASE)):
            raise Refused("Retention table changed or legacy TTL remains; host hold is retained")
        if (strict_json(self._schema_psql(query).encode()) != engine
                or storage_gate_value(strict_json(trusted_file(path).read_bytes())) != expected_gate):
            raise Refused("Retention ownership changed during physical table verification")
        return {"table_uuid": identifier, "mode": "partition", "ttl": False,
                "ddl_sha256": hashlib.sha256(rows[0]["create_table_query"].encode()).hexdigest()}

    def _schema_read_dependencies(self, stage):
        """Start the selected CH dependency under the existing writer hold."""
        if self.application_schema_current()["revision"] not in ApplicationSchema.RETENTION_REVISIONS:
            return
        expected = {"schema": 1, "held": True, "delivery_held": True,
                    "operation": hashlib.sha256(str(stage.resolve()).encode()).hexdigest()}
        path = self.data / "manager/storage-maintenance/gate.json"
        if storage_gate_value(strict_json(trusted_file(path).read_bytes())) != expected:
            raise Refused("Schema dependency startup requires the exact host delivery fence")
        self.service("start", ("clickhouse",))
        deadline = time.monotonic() + 120
        while True:
            try:
                if self.ch("SELECT 1") == "1":
                    return
            except (CommandFailed, Refused, OSError):
                pass
            if time.monotonic() >= deadline:
                raise Refused("ClickHouse did not become ready for held schema verification")
            time.sleep(1)

    def _schema_stop_dependencies(self):
        if self.application_schema_current()["revision"] in ApplicationSchema.RETENTION_REVISIONS:
            self.service("stop", ("clickhouse",))

    @staticmethod
    def _schema_catalog(namespace):
        """Semantic catalog, including executable/security behavior, not live data."""
        if not IDENTIFIER.fullmatch(namespace):
            raise Refused("Invalid fixed catalog namespace")
        query = r"""SELECT jsonb_build_object(
 'relations', COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,c.relkind,c.relpersistence,
  pg_get_userbyid(c.relowner),c.relrowsecurity,c.relforcerowsecurity,c.reloptions,c.relacl,
  c.relam,c.reltablespace,c.relispartition) ORDER BY c.relname)
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='NAMESPACE'), '[]'::jsonb),
 'columns', COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,a.attnum,a.attname,
  format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,a.attisdropped,
  a.attstorage,a.attcompression,a.attoptions,a.attacl,a.attcollation,
  pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attnum)
  FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
  WHERE n.nspname='NAMESPACE' AND a.attnum>0 AND c.relkind IN ('r','p','v','m','f')), '[]'::jsonb),
 'constraints',COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,k.contype,
  k.convalidated,k.condeferrable,k.condeferred,k.connoinherit,pg_get_constraintdef(k.oid,true))
  ORDER BY c.relname,k.conname) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='NAMESPACE'),'[]'::jsonb),
 'indexes',COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,i.indisvalid,i.indisready,
  i.indislive,i.indisreplident,i.indisclustered,pg_get_indexdef(c.oid)) ORDER BY c.relname)
  FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='NAMESPACE'),'[]'::jsonb),
 'sequences',COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,s.seqtypid,s.seqstart,
  s.seqincrement,s.seqmax,s.seqmin,s.seqcache,s.seqcycle,
  (SELECT jsonb_agg(jsonb_build_array(d.deptype,t.relname,a.attname) ORDER BY d.deptype,t.relname,a.attname)
   FROM pg_depend d JOIN pg_class t ON t.oid=d.refobjid
   JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=d.refobjsubid
   WHERE d.classid='pg_class'::regclass AND d.objid=c.oid AND d.refclassid='pg_class'::regclass))
  ORDER BY c.relname) FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='NAMESPACE'),'[]'::jsonb),
 'triggers',COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,t.tgname,t.tgenabled,
  pg_get_triggerdef(t.oid)) ORDER BY c.relname,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='NAMESPACE' AND NOT t.tgisinternal),'[]'::jsonb),
 'rules',COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,r.rulename,r.ev_enabled,
  pg_get_ruledef(r.oid)) ORDER BY c.relname,r.rulename) FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class
  JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='NAMESPACE'),'[]'::jsonb),
 'policies',COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,p.polname,p.polcmd,p.polpermissive,
  p.polroles,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY c.relname,p.polname)
  FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='NAMESPACE'),'[]'::jsonb),
 'inheritance',COALESCE((SELECT jsonb_agg(jsonb_build_array(c.relname,pn.nspname,p.relname,i.inhseqno)
  ORDER BY c.relname,i.inhseqno) FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_class p ON p.oid=i.inhparent
  JOIN pg_namespace pn ON pn.oid=p.relnamespace WHERE n.nspname='NAMESPACE'),'[]'::jsonb),
 'extra_objects',(SELECT count(*) FROM (
  SELECT oprnamespace AS ns FROM pg_operator UNION ALL SELECT opcnamespace FROM pg_opclass
  UNION ALL SELECT opfnamespace FROM pg_opfamily UNION ALL SELECT collnamespace FROM pg_collation
  UNION ALL SELECT connamespace FROM pg_conversion UNION ALL SELECT cfgnamespace FROM pg_ts_config
  UNION ALL SELECT dictnamespace FROM pg_ts_dict UNION ALL SELECT prsnamespace FROM pg_ts_parser
  UNION ALL SELECT tmplnamespace FROM pg_ts_template) x JOIN pg_namespace n ON n.oid=x.ns WHERE n.nspname='NAMESPACE'),
 'functions',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='NAMESPACE'),
 'extra_types',(SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
  WHERE n.nspname='NAMESPACE' AND t.typrelid=0 AND t.typelem=0),
 'extensions',(SELECT count(*) FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE n.nspname='NAMESPACE'))"""
        # Only the generated schema identifier is normalized. OIDs which encode
        # relation identity are deliberately represented by qualified names above.
        inner = query.replace('NAMESPACE', namespace)
        return "SELECT replace((" + inner + ")::text,'" + namespace + ".','public.')::jsonb"

    @staticmethod
    def _schema_literal(value):
        # Every variable value enters as generated hexadecimal UTF-8, never SQL.
        return "convert_from(decode('" + value.encode().hex() + "','hex'),'UTF8')"

    def _schema_context(self, stage, *, current=True):
        if current:
            release, _ = self.release(stage)
        else:
            self.guard()
            if (not stage.is_absolute() or stage.is_symlink() or stage.resolve() != stage
                    or stage.parent != (self.state / "releases").resolve()):
                raise Refused("Schema provenance is not an owned canonical release stage")
            release = strict_json(trusted_file(stage / "manifest.json").read_bytes())
        backup = self.checked_backup(stage)
        change = release.get("components", {}).get("nebulalog", {})
        if (change.get("schema_revision") != "2" or change.get("schema_sha256") != ApplicationSchema.schema_digest("2")
                or change.get("database_migration") not in ("none", ApplicationSchema.ADDITIVE_UPGRADE)
                or change.get("rollback_safe") is not True):
            raise Refused("Operation is not bound to the reviewed application schema")
        owner = backup.get("owners", {}).get("nebulalog", "")
        if not isinstance(owner, str) or not IDENTIFIER.fullmatch(owner):
            raise Refused("Backup has no valid application database owner")
        legacy, additive, stepup = ApplicationSchema.reviewed_sql()
        return {"schema": 1, "stage": str(stage.resolve()),
                "operation": hashlib.sha256(str(stage.resolve()).encode()).hexdigest(),
                "manifest_sha256": digest_file(trusted_file(stage / "manifest.json")),
                "backup_sha256": digest_file(trusted_file(stage / "adapter-backup-inventory.json")),
                "schema_revision": "2", "schema_sha256": ApplicationSchema.schema_digest("2"),
                "sql_sha256": ApplicationSchema.SCHEMAS["2"]["migrations/postgres.sql"],
                "additive_sha256": hashlib.sha256(additive.encode()).hexdigest(), "owner": owner}

    def _schema_hold(self, stage, context):
        path = self.data / "manager/storage-maintenance/gate.json"
        trusted_file(path)
        if path.stat().st_size > 4096:
            raise Refused("Oversized storage maintenance evidence")
        expected = {"schema": 1, "held": True, "delivery_held": True, "operation": context["operation"]}
        if storage_gate_value(strict_json(path.read_bytes())) != expected:
            raise Refused("Schema work requires the exact operation's host delivery hold")
        for name in ("api", "ingest", "keycloak"):
            if self.cmd(["systemctl", "show", "--property=ActiveState", "--value", "nebulalog-" + name + ".service"]) != "inactive":
                raise Refused("All application writers must be stopped before schema work")
        return expected

    @staticmethod
    def _schema_record(path, value):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if path.exists() or path.is_symlink():
            if trusted_file(path).read_bytes() != raw:
                raise Refused("Immutable schema operation evidence changed")
            return hashlib.sha256(raw).hexdigest()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return hashlib.sha256(raw).hexdigest()

    def _schema_query(self, context, *, migrate=False, gate_operation=None, catalog_only=None, structural_only=False):
        if (catalog_only not in (None, "1", "2", "3", "4") or migrate and catalog_only
                or type(structural_only) is not bool
                or structural_only and (migrate or catalog_only not in ApplicationSchema.RETENTION_REVISIONS)):
            raise Refused("Invalid catalog-only schema request")
        legacy, additive, stepup = ApplicationSchema.reviewed_sql()
        owner = context["owner"]
        operation = context["operation"]
        probe = "captainslog_probe_" + operation[:24]
        marker = self._schema_literal(json.dumps(context, sort_keys=True, separators=(",", ":"))) + "::jsonb"
        gate_operation = gate_operation or operation
        if not re.fullmatch(r"[0-9a-f]{64}", gate_operation):
            raise Refused("Invalid schema maintenance owner")
        gate = self._schema_literal(json.dumps({"schema": 1, "held": True, "delivery_held": True,
                                               "operation": gate_operation}, separators=(",", ":"))) + "::jsonb"
        old_sql = self._schema_literal(legacy)
        new_sql = self._schema_literal(additive)
        step_sql = self._schema_literal(stepup)
        retention_sql = self._schema_literal(ApplicationSchema.reviewed_retention_sql()) if catalog_only in ApplicationSchema.RETENTION_REVISIONS else "NULL"
        challenge_sql = self._schema_literal(ApplicationSchema.reviewed_host_stepup_v2_sql()) if catalog_only == "4" else "NULL"
        expected_query = self._schema_literal(self._schema_catalog(probe))
        actual_query = self._schema_literal(self._schema_catalog("public"))
        # A fresh transaction reconstructs the allowed profiles from fixed SQL.
        # It never uses live catalog output as the expected schema.
        return f"""
SET LOCAL search_path=pg_catalog;
SET LOCAL lock_timeout='30s'; SET LOCAL statement_timeout='120s';
CREATE TEMP TABLE captainslog_schema_result(value jsonb) ON COMMIT DROP;
DO $migration$
DECLARE old_catalog jsonb; new_catalog jsonb; retention_catalog jsonb; challenge_catalog jsonb; engine jsonb; actual jsonb; found jsonb; profile text; revision text; item record;
BEGIN
 PERFORM pg_advisory_xact_lock({STORAGE_LOCK});
 IF current_setting('server_version_num')::integer / 10000 != 17 THEN RAISE EXCEPTION 'Unqualified PostgreSQL major'; END IF;
 IF {str(structural_only).lower()} THEN
  IF current_user<>'postgres' OR current_database()<>'nebulalog'
   OR NOT EXISTS(SELECT FROM pg_roles WHERE rolname='nebulalog' AND rolcanlogin
    AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
   OR EXISTS(SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='nebulalog'))
  THEN RAISE EXCEPTION 'Unexpected fixed application role authority'; END IF;
  IF EXISTS(SELECT FROM pg_prepared_xacts WHERE database=current_database())
   OR EXISTS(SELECT FROM pg_extension WHERE extname<>'plpgsql')
   OR EXISTS(SELECT FROM pg_foreign_server)
   OR EXISTS(SELECT FROM pg_namespace WHERE nspname NOT IN ('public','pg_catalog','information_schema')
    AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%')
  THEN RAISE EXCEPTION 'Unqualified fixed application database objects'; END IF;
 END IF;
 IF (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()) IS DISTINCT FROM '{owner}'
 THEN RAISE EXCEPTION 'Application database owner differs from backup'; END IF;
 IF EXISTS(SELECT FROM pg_event_trigger) OR EXISTS(SELECT FROM pg_default_acl WHERE defaclnamespace IN (0,'public'::regnamespace))
 THEN RAISE EXCEPTION 'Unqualified DDL hooks or default privileges'; END IF;
 IF EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace)
 THEN RAISE EXCEPTION 'Unqualified application functions'; END IF;
 IF (SELECT nspowner FROM pg_namespace WHERE nspname='public') IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname='pg_database_owner')
  OR (SELECT count(*) FROM aclexplode((SELECT nspacl FROM pg_namespace WHERE nspname='public'))) != 3
  OR EXISTS(SELECT FROM aclexplode((SELECT nspacl FROM pg_namespace WHERE nspname='public')) a
    WHERE a.is_grantable OR a.grantor<>(SELECT oid FROM pg_roles WHERE rolname='pg_database_owner')
    OR NOT (a.grantee=(SELECT oid FROM pg_roles WHERE rolname='pg_database_owner') AND a.privilege_type IN ('CREATE','USAGE')
      OR a.grantee=0 AND a.privilege_type='USAGE'))
 THEN RAISE EXCEPTION 'Public namespace privileges differ from the qualified PG17 profile'; END IF;
 IF EXISTS(SELECT FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_class p ON p.oid=i.inhparent
  WHERE c.relnamespace='public'::regnamespace OR p.relnamespace='public'::regnamespace)
 THEN RAISE EXCEPTION 'Application table inheritance is not qualified'; END IF;
 FOR item IN SELECT c.relname FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind='r' ORDER BY c.relname LOOP
  EXECUTE format('LOCK TABLE public.%I IN ACCESS EXCLUSIVE MODE',item.relname);
 END LOOP;
 profile := CASE WHEN to_regclass('public.host_stepup_pending') IS NULL THEN 'base' ELSE 'host-stepup' END;
 IF '{catalog_only or ''}' IN ('3','4') AND profile<>'host-stepup'
 THEN RAISE EXCEPTION 'Retention schema requires the fixed host-stepup profile'; END IF;
 IF '{catalog_only or ''}'='4' THEN
  IF to_regclass('public.host_stepup_pending_v2') IS NULL
  THEN RAISE EXCEPTION 'Schema 4 requires the fixed host-stepup-v2 profile'; END IF;
  profile := 'host-stepup-v2';
 END IF;
 EXECUTE 'CREATE SCHEMA {probe} AUTHORIZATION "{owner}"';
 EXECUTE 'SET LOCAL ROLE "{owner}"';
 EXECUTE 'SET LOCAL search_path={probe},pg_catalog';
 EXECUTE {old_sql};
 IF profile IN ('host-stepup','host-stepup-v2') THEN EXECUTE {step_sql}; END IF;
 EXECUTE 'SET LOCAL search_path=pg_catalog';
 EXECUTE {expected_query} INTO old_catalog;
 EXECUTE 'SET LOCAL search_path={probe},pg_catalog';
 EXECUTE {new_sql};
 EXECUTE 'SET LOCAL search_path=pg_catalog';
 EXECUTE {expected_query} INTO new_catalog;
 IF '{catalog_only or ''}' IN ('3','4') THEN
  EXECUTE 'SET LOCAL search_path={probe},pg_catalog';
  EXECUTE {retention_sql};
  EXECUTE 'SET LOCAL search_path=pg_catalog';
  EXECUTE {expected_query} INTO retention_catalog;
 END IF;
 IF '{catalog_only or ''}'='4' THEN
  EXECUTE 'SET LOCAL search_path={probe},pg_catalog';
  EXECUTE {challenge_sql};
  EXECUTE 'SET LOCAL search_path=pg_catalog';
  EXECUTE {expected_query} INTO challenge_catalog;
 END IF;
 EXECUTE 'DROP SCHEMA {probe} CASCADE';
 EXECUTE {actual_query} INTO actual;
 IF actual IS DISTINCT FROM old_catalog AND actual IS DISTINCT FROM new_catalog AND actual IS DISTINCT FROM retention_catalog AND actual IS DISTINCT FROM challenge_catalog
 THEN RAISE EXCEPTION 'Application catalog differs before reading any application data'; END IF;
 -- Firstboot/restore may verify the exact structure before normalizing any
 -- restored operation rows. This branch never executes application DDL/DML.
 IF {str(structural_only).lower()} THEN
  IF current_database()<>'nebulalog' OR current_user<>'{owner}'
   OR ('{catalog_only or ''}'='3' AND actual IS DISTINCT FROM retention_catalog)
   OR ('{catalog_only or ''}'='4' AND actual IS DISTINCT FROM challenge_catalog)
  THEN RAISE EXCEPTION 'Catalog differs from the requested fixed initialization profile'; END IF;
  IF EXISTS(SELECT FROM public.settings WHERE key LIKE 'application_schema_migration:%')
  THEN RAISE EXCEPTION 'Factory/restored schema contains unowned migration evidence'; END IF;
  RESET ROLE;
  INSERT INTO pg_temp.captainslog_schema_result VALUES(jsonb_build_object(
   'revision','{catalog_only or ''}','catalog',actual,'profile',profile,
   'database',jsonb_build_object('system_identifier',(SELECT system_identifier::text FROM pg_control_system()),
    'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
    'database',current_database(),'owner','{owner}','server_version',current_setting('server_version_num')::integer)));
  RETURN;
 END IF;
 IF (SELECT value FROM public.settings WHERE key='storage_emergency_maintenance') IS DISTINCT FROM {gate}
 THEN RAISE EXCEPTION 'Database delivery hold differs'; END IF;
 SELECT value INTO found FROM public.settings WHERE key='application_schema_migration:{operation}';
 IF {str(migrate).lower()} THEN
  IF actual IS DISTINCT FROM old_catalog OR found IS NOT NULL
   OR EXISTS(SELECT FROM public.settings WHERE key='storage_emergency' OR key LIKE 'application_schema_migration:%')
  THEN RAISE EXCEPTION 'Schema is not the exact unmigrated legacy profile'; END IF;
  EXECUTE 'SET LOCAL search_path=public,pg_catalog';
  EXECUTE {new_sql};
  EXECUTE 'SET LOCAL search_path=pg_catalog';
  EXECUTE {actual_query} INTO actual;
  IF actual IS DISTINCT FROM new_catalog THEN RAISE EXCEPTION 'Target catalog differs from fixed SQL'; END IF;
  INSERT INTO public.settings(key,value) VALUES('application_schema_migration:{operation}',{marker});
  INSERT INTO public.audit_events(actor,action,target,detail)
   VALUES('host-lifecycle','application.schema.migrate','{operation}',{marker});
  found := {marker};
 END IF;
 IF '{catalog_only or ''}' IN ('1','2','3','4') THEN
  IF ('{catalog_only or ''}'='1' AND actual IS DISTINCT FROM old_catalog)
   OR ('{catalog_only or ''}'='2' AND actual IS DISTINCT FROM new_catalog)
   OR ('{catalog_only or ''}'='3' AND actual IS DISTINCT FROM retention_catalog)
   OR ('{catalog_only or ''}'='4' AND actual IS DISTINCT FROM challenge_catalog)
  THEN RAISE EXCEPTION 'Catalog differs from the requested fixed schema'; END IF;
  revision := '{catalog_only or ''}';
 ELSIF actual=new_catalog AND found={marker} THEN
  IF EXISTS(SELECT FROM public.storage_emergency_actions WHERE completed_at IS NULL)
   OR EXISTS(SELECT FROM public.storage_emergency_inserts)
  THEN RAISE EXCEPTION 'Unresolved storage evidence prevents schema recovery'; END IF;
  revision := '2';
 ELSIF actual=old_catalog AND found IS NULL
  AND NOT EXISTS(SELECT FROM public.settings WHERE key='storage_emergency' OR key LIKE 'application_schema_migration:%')
 THEN revision := '1';
 ELSE RAISE EXCEPTION 'Schema outcome is foreign, partial, or unproven'; END IF;
 IF revision='1' AND EXISTS(SELECT FROM public.settings WHERE key='storage_emergency' OR key LIKE 'application_schema_migration:%')
 THEN RAISE EXCEPTION 'Legacy catalog contains foreign or partial migration evidence'; END IF;
 IF revision IN ('2','3','4') THEN
  IF NOT EXISTS(SELECT FROM public.settings WHERE key='storage_emergency')
   OR (SELECT count(*) FROM public.storage_emergency_state) != 1
  THEN RAISE EXCEPTION 'Target schema lacks required emergency policy/state'; END IF;
  IF EXISTS(SELECT FROM public.storage_emergency_actions WHERE completed_at IS NULL)
   OR EXISTS(SELECT FROM public.storage_emergency_inserts)
  THEN RAISE EXCEPTION 'Unresolved storage evidence prevents schema recovery'; END IF;
 END IF;
 IF revision IN ('3','4') THEN
  SELECT value INTO engine FROM public.settings WHERE key='retention_engine';
  IF jsonb_typeof(engine) IS DISTINCT FROM 'object' OR engine->'schema' IS DISTINCT FROM '1'::jsonb
   OR engine->>'mode' IS DISTINCT FROM 'partition'
   OR NOT EXISTS(SELECT FROM public.settings WHERE key='retention_status')
   OR EXISTS(SELECT FROM public.retention_actions WHERE completed_at IS NULL)
  THEN RAISE EXCEPTION 'Unsettled retention evidence prevents schema observation'; END IF;
 END IF;
 IF (SELECT count(*) FROM public.settings WHERE key LIKE 'application_schema_migration:%') > 128
  OR EXISTS(SELECT FROM public.settings WHERE key LIKE 'application_schema_migration:%' AND octet_length(value::text)>8192)
 THEN RAISE EXCEPTION 'Oversized migration marker inventory'; END IF;
 RESET ROLE;
 INSERT INTO pg_temp.captainslog_schema_result VALUES(jsonb_build_object('revision',revision,
  'catalog',actual,'marker',found,'profile',profile) ||
  CASE WHEN '{catalog_only or ''}' IN ('1','2','3','4') THEN jsonb_build_object('markers',
   (SELECT COALESCE(jsonb_agg(jsonb_build_object('key',key,'value',value) ORDER BY key),'[]'::jsonb)
    FROM public.settings WHERE key LIKE 'application_schema_migration:%')) ELSE '{{}}'::jsonb END);
END $migration$;
SELECT value::text FROM pg_temp.captainslog_schema_result;
"""

    def _schema_psql(self, query):
        return self.cmd(["podman", "exec", "-i", "--user", "999:999", "nebulalog-postgresql",
            "psql", "-X", "--username=postgres", "--dbname=nebulalog", "--single-transaction",
            "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1"], input=query.encode(), timeout=150)

    def _schema_intent(self, stage, context):
        path = stage / "adapter-application-schema-intent.json"
        intent = strict_json(trusted_file(path).read_bytes())
        if (not isinstance(intent, dict) or set(intent) != {"context", "executor"}
                or intent["context"] != context):
            raise Refused("Schema intent is not bound to this operation and backup")
        execution = intent["executor"]
        if (not isinstance(execution, dict) or set(execution) != {"container_id", "image", "unit", "application_name"}
                or not re.fullmatch(r"[0-9a-f]{64}", execution.get("container_id", ""))
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", execution.get("image", ""))
                or execution.get("unit") != "nebulalog-schema-" + context["operation"][:32] + ".service"
                or execution.get("application_name") != "captainslog-schema-" + context["operation"][:32]):
            raise Refused("Invalid retained schema executor identity")
        self._schema_record(path, intent)
        return intent

    def application_schema_fence(self, stage):
        """Remove the exact client, then fence orphan PostgreSQL server execution.

        Must precede restore. Stopping a podman CLI alone does not stop its
        container child, and absence from pg_stat_activity alone is not a fence.
        """
        context = self._schema_context(stage)
        self._schema_hold(stage, context)
        intent = self._schema_intent(stage, context)
        executor = intent["executor"]
        unit = executor["unit"]
        load = self.cmd(["systemctl", "show", "--property=LoadState", "--value", unit])
        if load != "not-found":
            self.cmd(["systemctl", "stop", unit], timeout=60)
            if self.cmd(["systemctl", "show", "--property=ActiveState", "--value", unit]) not in ("inactive", "failed"):
                raise Refused("Migration supervisor remains active")
        identity = executor["container_id"]
        listed = self.cmd(["podman", "ps", "--all", "--no-trunc", "--filter", "id=" + identity, "--format", "{{.ID}}"])
        if listed:
            if listed != identity:
                raise Refused("Migration client identity changed")
            self.cmd(["podman", "rm", "--force", "--time", "10", identity], timeout=60)
        if self.cmd(["podman", "ps", "--all", "--no-trunc", "--filter", "id=" + identity, "--format", "{{.ID}}"]):
            raise Refused("Migration client can still execute")
        app = executor["application_name"]
        query = f"""SET LOCAL search_path=pg_catalog; SET LOCAL statement_timeout='30s';
DO $fence$ DECLARE item record; BEGIN
 FOR item IN SELECT pid FROM pg_stat_activity WHERE datid=(SELECT oid FROM pg_database WHERE datname=current_database())
  AND application_name='{app}' AND pid<>pg_backend_pid() LOOP
  IF NOT pg_terminate_backend(item.pid,10000) THEN RAISE EXCEPTION 'Migration executor did not terminate'; END IF;
 END LOOP;
 PERFORM pg_advisory_xact_lock({STORAGE_LOCK});
 PERFORM pg_stat_clear_snapshot();
 IF EXISTS(SELECT FROM pg_stat_activity WHERE datid=(SELECT oid FROM pg_database WHERE datname=current_database())
  AND application_name='{app}' AND pid<>pg_backend_pid()) THEN RAISE EXCEPTION 'Migration backend remains'; END IF;
END $fence$; SELECT 'fenced';"""
        if self._schema_psql(query) != "fenced":
            raise Refused("Migration backend fence was not observed")
        return self.receipt(stage, "application-schema-fence", operation=context["operation"],
                            intent_sha256=digest_file(stage / "adapter-application-schema-intent.json"), executor=executor)

    def _schema_result(self, stage, context, raw, *, recovered):
        observed = strict_json(raw.encode())
        if (not isinstance(observed, dict) or set(observed) != {"revision", "catalog", "marker", "profile"}
                or observed["revision"] not in ("1", "2") or observed["profile"] not in ("base", "host-stepup")):
            raise Refused("Unrecognized schema readback")
        if observed["revision"] != "2" or observed["marker"] != context:
            return self.receipt(stage, "application-schema-recovery", ok=False, state="aborted",
                                operation=context["operation"], schema_revision="1", replay_permitted=False)
        intent = self._schema_intent(stage, context)
        result = {**context, "ok": True, "action": "application-schema", "state": "complete",
                  "intent_sha256": digest_file(stage / "adapter-application-schema-intent.json"),
                  "marker": context, "profile": observed["profile"], "executor": intent["executor"],
                  "catalog_sha256": hashlib.sha256(json.dumps(observed["catalog"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        # Completion is immutable. Recovery does not rewrite a receipt which the
        # manager's actual-schema pointer may already bind by hash.
        self._schema_record(stage / "adapter-application-schema.json", result)
        return result

    def application_schema_recover(self, stage):
        context = self._schema_context(stage)
        self.application_schema_fence(stage)
        self._schema_hold(stage, context)
        return self._schema_result(stage, context, self._schema_psql(self._schema_query(context)), recovered=True)

    def application_schema_receipt(self, stage):
        """Static immutable provenance; does not claim a current database check."""
        context = self._schema_context(stage, current=False)
        intent = self._schema_intent(stage, context)
        path = stage / "adapter-application-schema.json"
        retained = strict_json(trusted_file(path).read_bytes())
        extra = {"ok", "action", "state", "intent_sha256", "marker", "profile", "executor", "catalog_sha256"}
        if (not isinstance(retained, dict) or set(retained) != set(context) | extra
                or any(retained.get(k) != v for k, v in context.items())
                or retained.get("ok") is not True or retained.get("action") != "application-schema"
                or retained.get("state") != "complete" or retained.get("marker") != context
                or retained.get("profile") not in ("base", "host-stepup")
                or retained.get("executor") != intent["executor"]
                or retained.get("intent_sha256") != digest_file(stage / "adapter-application-schema-intent.json")
                or not isinstance(retained.get("catalog_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", retained["catalog_sha256"])):
            raise Refused("Retained schema completion provenance changed")
        self._schema_record(path, retained)
        return retained

    def application_schema_verify(self, stage, *, maintenance_stage=None):
        """Recheck original completion under a current operation's delivery hold."""
        retained = self.application_schema_receipt(stage)
        context = self._schema_context(stage, current=False)
        owner_stage = maintenance_stage or stage
        if (not owner_stage.is_absolute() or owner_stage.is_symlink() or owner_stage.resolve() != owner_stage
                or owner_stage.parent not in ((self.state / "releases").resolve(),
                                               (self.data / "manager/os-updates").resolve())):
            raise Refused("Schema verification needs an owned maintenance stage")
        gate_operation = hashlib.sha256(str(owner_stage).encode()).hexdigest()
        self._schema_hold(owner_stage, {"operation": gate_operation})
        actual = self._schema_result(stage, context,
            self._schema_psql(self._schema_query(context, gate_operation=gate_operation)), recovered=True)
        if actual != retained:
            raise Refused("Retained application schema receipt no longer verifies")
        return actual

    def application_schema_catalog(self, stage, revision):
        """Observe a fixed factory/restored profile; never adopt it as provenance.

        The coordinator must separately bind the requested revision to factory
        source or a checked backup. This method cannot authorize SQL migration.
        """
        self.guard()
        if (not isinstance(revision, str) or revision not in ApplicationSchema.SCHEMAS
                or not stage.is_absolute() or stage.is_symlink() or stage.resolve() != stage
                or stage.parent not in ((self.state / "releases").resolve(),
                                        (self.data / "manager/os-updates").resolve())):
            raise Refused("Invalid schema catalog observation scope")
        owner = "nebulalog"
        if (stage / "adapter-backup.json").exists():
            owner = self.checked_backup(stage).get("owners", {}).get("nebulalog", "")
        if not isinstance(owner, str) or not IDENTIFIER.fullmatch(owner):
            raise Refused("Unknown application database owner")
        context = {"operation": hashlib.sha256(str(stage).encode()).hexdigest(), "owner": owner}
        self._schema_hold(stage, context)
        observed = strict_json(self._schema_psql(self._schema_query(context, catalog_only=revision)).encode())
        profiles = ("host-stepup-v2",) if revision == "4" else ("host-stepup",) if revision == "3" else ("base", "host-stepup")
        if (not isinstance(observed, dict) or set(observed) != {"revision","catalog","marker","profile","markers"}
                or observed["revision"] != revision or observed["profile"] not in profiles
                or not isinstance(observed["markers"], list) or len(observed["markers"]) > 128):
            raise Refused("Unrecognized schema catalog observation")
        markers = []
        for item in observed["markers"]:
            if (not isinstance(item, dict) or set(item) != {"key", "value"}
                    or not isinstance(item["key"], str) or not re.fullmatch(r"application_schema_migration:[0-9a-f]{64}", item["key"])):
                raise Refused("Malformed retained migration marker")
            markers.append({"key": item["key"], "sha256": hashlib.sha256(json.dumps(item["value"], sort_keys=True,
                            separators=(",", ":")).encode()).hexdigest()})
        if revision in ("1", *ApplicationSchema.RETENTION_REVISIONS) and markers:
            raise Refused("Factory schema contains unowned migration completion evidence")
        retention = self._retention_table(stage) if revision in ApplicationSchema.RETENTION_REVISIONS else None
        return {"ok": True, "schema_revision": revision, "schema_sha256": ApplicationSchema.schema_digest(revision),
                "sql_sha256": ApplicationSchema.SCHEMAS[revision]["migrations/postgres.sql"],
                "stage": str(stage), "operation": context["operation"], "owner": owner,
                "profile": observed["profile"], "markers": markers,
                "catalog_sha256": hashlib.sha256(json.dumps(observed["catalog"], sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                **({"retention": retention} if retention is not None else {})}

    def _schema_client_ready(self):
        raw = self._schema_psql("SELECT jsonb_build_object('listen',current_setting('listen_addresses'),'rules',"
            "(SELECT jsonb_agg(jsonb_build_object('type',type,'database',database,'user_name',user_name,"
            "'address',address,'netmask',netmask,'auth_method',auth_method,'options',options,'error',error) ORDER BY rule_number) "
            "FROM pg_hba_file_rules));")
        value = strict_json(raw.encode())
        if (not isinstance(value, dict) or set(value) != {'listen', 'rules'}
                or value['listen'] not in ('*', 'localhost', '127.0.0.1', '127.0.0.1,::1')
                or not isinstance(value['rules'], list) or not 1 <= len(value['rules']) <= 64):
            raise Refused("PostgreSQL loopback client authentication is not qualified")
        loopback = False
        for rule in value['rules']:
            if (not isinstance(rule, dict) or set(rule) != {'type','database','user_name','address','netmask','auth_method','options','error'}
                    or rule['error'] is not None or rule['options'] not in (None, [])):
                raise Refused("PostgreSQL authentication configuration is ambiguous")
            if rule['type'] == 'local' or rule['database'] == ['replication']:
                continue
            if (rule['type'] not in ('host','hostssl','hostnossl') or rule['auth_method'] != 'scram-sha-256'
                    or rule['database'] != ['all'] or rule['user_name'] != ['all']):
                raise Refused("PostgreSQL TCP rules differ from the qualified SCRAM profile")
            if rule['type'] in ('host','hostnossl') and (rule['address'] == 'all'
                    or rule['address'] == '127.0.0.1' and rule['netmask'] == '255.255.255.255'):
                loopback = True
        if not loopback:
            raise Refused("No qualified loopback SCRAM connection is available")

    def application_schema_migrate(self, stage):
        context = self._schema_context(stage)
        self._schema_hold(stage, context)
        if (stage / "adapter-application-schema-intent.json").exists():
            return self.application_schema_recover(stage)
        release, _ = self.release(stage)
        if ApplicationSchema.transition(release["components"]["nebulalog"], self.config["schema_revision"]) != ApplicationSchema.ADDITIVE_UPGRADE:
            raise Refused("No reviewed additive schema migration was authorized")
        # Preflight exact old catalog before creating even a stopped executor.
        before = strict_json(self._schema_psql(self._schema_query(context)).encode())
        if before["revision"] != "1":
            raise Refused("An unowned target schema is not a migration opportunity")
        self._schema_client_ready()
        image = self.cmd(["podman", "inspect", "--format", "{{.Image}}", "nebulalog-postgresql"])
        if re.fullmatch(r"[0-9a-f]{64}", image): image = "sha256:" + image
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise Refused("PostgreSQL client image has no immutable identity")
        pinned = image_from_quadlet(trusted_file(self.quadlets / "nebulalog-postgresql.container").read_text())
        accepted_image = self.cmd(["podman", "image", "inspect", "--format", "{{.Id}}", pinned])
        if re.fullmatch(r"[0-9a-f]{64}", accepted_image): accepted_image = "sha256:" + accepted_image
        if accepted_image != image:
            raise Refused("Running PostgreSQL client image differs from the protected Quadlet pin")
        name = "nebulalog-schema-" + context["operation"][:32]
        # Use the existing root-controlled Podman secret. Secret bytes never
        # enter a host command argument, receipt, or diagnostic output.
        script = 'set -eu; export PGPASSWORD="$(cat /run/secrets/nebulalog-pg-password)"; exec psql -X --host=127.0.0.1 --username=postgres --dbname=nebulalog --single-transaction --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1'
        identity = self.cmd(["podman", "create", "--name", name, "--label", "captainslog.schema.operation=" + context["operation"],
            "--network=container:nebulalog-postgresql", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user=999:999", "--interactive", "--secret=nebulalog-pg-password,uid=999,gid=999,mode=0400",
            "--env", "PGSSLMODE=disable",
            "--env", "PGAPPNAME=captainslog-schema-" + context["operation"][:32],
            "--entrypoint=/bin/sh", image, "-c", script], timeout=60)
        executor = {"container_id": identity, "image": image, "unit": name + ".service",
                    "application_name": "captainslog-schema-" + context["operation"][:32]}
        if not re.fullmatch(r"[0-9a-f]{64}", identity):
            raise Refused("Migration client has no exact container identity")
        self._schema_record(stage / "adapter-application-schema-intent.json", {"context": context, "executor": executor})
        self._schema_hold(stage, context)
        raw = self.cmd(["systemd-run", "--unit=" + executor["unit"], "--wait", "--pipe", "--collect",
            "--property=KillMode=control-group", "--property=RuntimeMaxSec=180", "--",
            "podman", "start", "--attach", "--interactive", identity], input=self._schema_query(context, migrate=True).encode(), timeout=210)
        # A valid stdout does not prove COMMIT (psql emits SELECT before commit).
        # The independent transaction below is authoritative, even on success.
        self.application_schema_fence(stage)
        return self._schema_result(stage, context, self._schema_psql(self._schema_query(context)), recovered=False)

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

    def component_hook(self, name, stage):
        """Publish terminal evidence only after all method effects have ended."""
        if name not in host_dispatch.HOOK_STATES:
            raise Refused("Unknown component hook")
        _, transaction = self.release(stage)
        journal = host_dispatch.HookJournal(stage, transaction)
        with locked(stage / "component-hook-lease.lock") as descriptor:
            ticket = journal.enter(name)
            original = self.cmd
            self._component_ticket = ticket
            if type(original) is Commands:
                self.cmd = Commands(inherited_locks=((descriptor, stage / "component-hook-lease.lock"),),
                    observer=lambda phase, kind, **details: journal.command_event(ticket, phase, kind,
                        scap=getattr(self, "_component_scap", None), **details),
                    failure_observer=lambda kind, **details: journal.command_event(ticket, "failed", kind, **details))
            try:
                result = getattr(self, name.removeprefix("update-"))(stage)
            except BaseException:
                # If any native acknowledgement is missing, finish refuses and
                # leaves the hook unresolved. No timeout/PID inference is used.
                journal.finish(ticket, "failed")
                raise
            else:
                journal.finish(ticket, "success" if result.get("ok") is True else "failed", result=result)
                return result
            finally:
                self.cmd = original
                del self._component_ticket

    def component_operation(self, stage, label, operation):
        """Fence fixed helpers that use their own native-command implementation."""
        if label not in {"host-integrity-prepare", "host-integrity-accept-forward", "host-integrity-accept-rollback"}:
            raise Refused("Unknown compound component operation")
        ticket = getattr(self, "_component_ticket", None)
        if ticket is None:
            if type(self.cmd) is Commands:
                raise Refused("Compound component operation requires an active exact hook")
            return operation()  # Injected native boundary in source fixtures only.
        _, transaction = self.release(stage)
        journal = host_dispatch.HookJournal(stage, transaction)
        command = journal.command_event(ticket, "dispatch", "call", argv=["fixed-compound", label])
        result = operation()
        # The fixed helper must validate its complete acceptance before return.
        journal.command_event(ticket, "complete", "call", ticket=command)
        return result

    def _component_guard(self, stage, transaction):
        return host_dispatch.HookJournal(stage, transaction).assert_settled(
            allow=getattr(self, "_component_ticket", None))

    def preflight(self, stage):
        release, transaction = self.release(stage)
        self._component_guard(stage, transaction)
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
        schema = self.application_schema_current()
        application = release["components"].get("nebulalog")
        migration = self.application_schema_transition(application, schema["revision"]) if application else "none"
        target_schema = application["schema_revision"] if application else schema["revision"]
        for component, change in release["components"].items():
            if component in {"host", "baseline"}:
                continue
            if change.get("rollback_safe") is not True or not IMAGE.fullmatch(change.get("image", "")):
                raise Refused("Every component needs a reversible release and an immutable OCI image")
            if component != "nebulalog":
                if change.get("database_migration") != "none" or change.get("schema_revision") != target_schema:
                    raise Refused("Supporting components must preserve the target application schema")
                ApplicationSchema.transition(change, target_schema)
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
        if release.get("content_enrollment") == "selected-baseline-v1":
            from nebulalog_manager.baseline import ContentUpdate
            if "baseline" in previous:
                raise Refused("Content enrollment cannot replace an existing measured component")
            ContentUpdate.bridge(stage, self.configuration, self.cmd)
            self.content_assessment(stage, trusted_file(self.configuration / "security-policy.json").read_bytes())
        host = {"host": HostRuntime(self, stage).preflight()} if "host" in release["components"] else {}
        # Written before returning to the manager, before backup or preparation
        # can stop writers or authorize candidate effects. An interrupted fixed
        # preflight may be rechecked only while no such effects have started.
        self._schema_record(stage / "adapter-backup-intent.json", self.preactivation_context(stage))
        return self.receipt(stage, "preflight", components=list(release["components"]),
                            schema_revision=schema["revision"], target_schema_revision=target_schema,
                            database_migration=migration, logs_backup=False, **host)

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

    def preactivation_context(self, stage):
        """Bind the unchanged runtime before backup can stop a writer."""
        _, transaction = self.release(stage)
        def snapshot(directory):
            files = inventory(directory)
            for entry in files:
                entry["mode"] = (directory / entry["path"]).stat().st_mode & 0o7777
            directories = []
            for path in [directory, *sorted(directory.rglob("*"))]:
                if path.is_dir():
                    info = path.stat()
                    directories.append({"path": path.relative_to(directory).as_posix(),
                        "uid": info.st_uid, "gid": info.st_gid, "mode": info.st_mode & 0o7777})
            return {"files": files, "directories": directories}
        return {"schema": 1, "stage": str(stage), "manifest_sha256": transaction["manifest_sha256"],
                "previous_sha256": hashlib.sha256(json.dumps(transaction["previous"], sort_keys=True,
                    separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
                "application_schema": self.application_schema_current(),
                "configuration": snapshot(self.configuration), "quadlets": snapshot(self.quadlets)}

    def preactivation_recover(self, stage):
        """Resume only proven unchanged code; never restore an incomplete dump."""
        release, transaction = self.release(stage)
        self._component_guard(stage, transaction)
        if (transaction.get("activation_started") is not False
                or transaction.get("state") not in {"rolling_back", "recovery_required"}):
            raise Refused("Unchanged-runtime recovery requires a durable preactivation transaction")
        for name in ("activate", "application-schema-intent", "application-schema",
                     "database-restore-intent", "database-restore-complete"):
            if os.path.lexists(stage / ("adapter-" + name + ".json")):
                raise Refused("Candidate effects cannot use unchanged-runtime recovery")
        snapshot = strict_json(trusted_file(stage / "adapter-backup-intent.json").read_bytes())
        if snapshot != self.preactivation_context(stage):
            raise Refused("Runtime changed since the preactivation backup intent")
        marker = self.data / "manager/maintenance.json"
        if os.path.lexists(marker):
            owner = strict_json(trusted_file(marker).read_bytes())
            if owner.get("active") is not True or owner.get("release") != str(stage):
                raise Refused("Another operation owns public maintenance")
        self.storage_maintenance(stage, held=True, delivery_held=True, host_only=True)
        self.maintenance(True, stage)
        self.service("stop", tuple(name for name in reversed(self.services) if name != "postgresql"))
        self.service("start", ("postgresql",))
        self.pg_ready()
        # Unknown INSERT/removal outcomes still refuse this barrier. A failed
        # backup is not authority to clear an unsettled storage operation.
        self._schema_read_dependencies(stage)
        self.storage_maintenance(stage, held=True, delivery_held=True)
        self.application_schema_check(stage, snapshot["application_schema"])
        if snapshot != self.preactivation_context(stage):
            raise Refused("Runtime changed while recovering the preactivation hold")
        host = HostRuntime(self, stage) if "host" in release["components"] else None
        if host:
            # Reconstruct only a missing host-file recovery copy after proving
            # each live file still equals the original protected plan. Database
            # dump files and incomplete backup evidence remain untouched.
            host.backup(preactivation_recovery=True)
        self.service("start", tuple(name for name in self.services if name != "postgresql"))
        self.storage_maintenance(stage, held=True, delivery_held=False)
        return self.receipt(stage, "rollback", unchanged_runtime_recovered=True,
                            current_databases_preserved=True, current_configuration_preserved=True,
                            **({"host": host.runtime_evidence("update-rollback")} if host else {}))

    def backup(self, stage, *, os_backup=False, retain_maintenance=False, maintenance_owner=None):
        release = {}
        if not os_backup:
            release, transaction = self.release(stage)
            self._component_guard(stage, transaction)
        owner = maintenance_owner or stage
        if retain_maintenance:
            marker = json.loads(trusted_file(self.data / "manager/maintenance.json").read_text())
            if (not os_backup or owner.is_symlink() or owner.resolve().parent != (self.data / "manager/os-updates").resolve()
                    or marker.get("active") is not True or marker.get("release") != str(owner)):
                raise Refused("Recovery backup requires the existing operation-owned maintenance gate")
        elif maintenance_owner is not None:
            raise Refused("Backup maintenance owner requires retained maintenance")
        self.encrypted()
        schema_snapshot = self.application_schema_current()
        if not os_backup:
            self._schema_record(stage / "adapter-backup-intent.json", self.preactivation_context(stage))
        receiving = self.storage_gate_aware_ingest()
        writers = ("api", "keycloak") + (() if receiving else ("ingest",))
        restart_writers = ("keycloak", "api") + (() if receiving else ("ingest",))
        destination = stage / "recovery"
        destination.mkdir(mode=0o700, exist_ok=False)
        self.maintenance(True, owner)
        storage_held = False
        try:
            self.storage_maintenance(owner, held=True, delivery_held=True)
            storage_held = True
            self.service("stop", writers)
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
                        "application_schema": schema_snapshot,
                        "files": inventory(destination), "includes_clickhouse_logs": False}
            atomic_json(stage / "adapter-backup-inventory.json", evidence)
            host = {"host": HostRuntime(self, stage).backup()} if "host" in release.get("components", {}) else {}
            result = self.receipt(stage, "backup", postgresql=True, configuration=True,
                                  inventory_sha256=digest_file(stage / "adapter-backup-inventory.json"),
                                  ingestion="receiving into durable WAL" if receiving else "legacy receiver stopped for a consistent backup",
                                  schema_revision=schema_snapshot["revision"], storage_maintenance=True, **host)
            if os_backup:
                self.service("start", restart_writers)
                self.storage_maintenance(owner, held=True, delivery_held=False)
                self.api_ready()
                if not retain_maintenance:
                    self.maintenance(False, owner)
            return result
        except BaseException as failure:
            # The manager does not invoke rollback for preflight/backup failures.
            # Preserve active=true if service recovery itself fails.
            try:
                if not storage_held:
                    raise Refused("Storage barrier was not established; its uncertain hold requires recovery")
                self.service("start", restart_writers)
                self.api_ready()
                self.storage_maintenance(owner, held=os_backup or retain_maintenance, delivery_held=False)
                if not retain_maintenance:
                    self.maintenance(False, owner)
                self.receipt(stage, "backup-recovery", recovered=True, services=list(restart_writers),
                             maintenance_retained=retain_maintenance, storage_maintenance_held=os_backup or retain_maintenance)
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
            if component in {"host", "baseline"}:
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
        release, transaction = self.release(stage)
        if transaction.get("activation_started") is False:
            raise Refused("Candidate activation was not durably authorized by the manager")
        backup = self.checked_backup(stage)
        preparation = json.loads(trusted_file(stage / "adapter-prepare.json").read_text())
        verify_inventory(stage / "prepared-quadlets", preparation["files"])
        self.storage_maintenance(stage, held=True, delivery_held=True)
        self.service("stop", tuple(name for name in reversed(self.services) if name != "postgresql"))
        self._schema_read_dependencies(stage)
        self.application_schema_check(stage, backup["application_schema"])
        self._schema_stop_dependencies()
        self.service("stop", ("postgresql",))
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
        self.service("start", ("postgresql",))
        self.pg_ready()
        self._schema_read_dependencies(stage)
        application = release["components"].get("nebulalog")
        migration = self.application_schema_transition(application, backup["application_schema"]["revision"]) if application else "none"
        if migration == ApplicationSchema.ADDITIVE_UPGRADE:
            result = self.application_schema_migrate(stage)
            if result.get("ok") is not True or result.get("state") != "complete":
                raise Refused("Application schema migration did not commit; activation remains held")
            self.application_schema_accept(stage)
        else:
            self.application_schema_check(stage)
        self.service("start", tuple(name for name in self.services if name != "postgresql"))
        # Health can now exercise real INSERT and WAL delivery. Destructive
        # retention remains held until durable commit and final acceptance.
        self.storage_maintenance(stage, held=True, delivery_held=False)
        return self.receipt(stage, "activate", services=list(self.services), maintenance=True,
                            durable_data_preserved=True, migration=migration,
                            schema_revision=self.application_schema_current()["revision"],
                            **({"host": host.runtime_evidence("update-activate")} if host else {}))

    def rollback(self, stage):
        release, transaction = self.release(stage)
        if transaction.get("activation_started") is False:
            return self.preactivation_recover(stage)
        evidence = self.checked_backup(stage)
        finalized = stage / "adapter-finalize.json"
        historical = finalized.exists() and json.loads(trusted_file(finalized).read_text()).get("transaction_state") == "committed"
        restore_context, restoring, restored = (None, False, False) if historical else self.database_restore_status(stage, evidence)
        self.maintenance(True, stage)
        self.storage_maintenance(stage, held=True, delivery_held=True, host_only=True)
        self.service("stop", tuple(name for name in reversed(self.services) if name != "postgresql"))
        self.service("start", ("postgresql",))
        self.pg_ready()
        migration_intent = stage / "adapter-application-schema-intent.json"
        if os.path.lexists(migration_intent) and not (restoring and not restored):
            # Remove the exact retained execution client before waiting on a
            # database lock. An orphan client may still be about to connect.
            self.application_schema_fence(stage)
        if not (restoring and not restored):
            self._schema_read_dependencies(stage)
            self.storage_maintenance(stage, held=True, delivery_held=True)
            if os.path.lexists(migration_intent) and not historical and not restored:
                outcome = self.application_schema_recover(stage)
                if outcome.get("state") not in ("complete", "aborted"):
                    raise Refused("Unproven migration outcome cannot authorize database restore")
            else:
                self.application_schema_check(stage, evidence["application_schema"] if restored else None)
        self._schema_stop_dependencies()
        self.service("stop", ("postgresql",))
        host = HostRuntime(self, stage) if "host" in release["components"] else None
        if host:
            host.apply(rollback=True)
        # Restore original image pins and environment/TLS/identity configuration before services start.
        changed_units = {"nebulalog-" + name + ".container" for component in release["components"] if component in NAMES for name in NAMES[component]}
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
            self.service("start", ("postgresql",))
            self.pg_ready()
            self._schema_read_dependencies(stage)
            self.application_schema_check(stage)
            self.service("start", tuple(name for name in self.services if name != "postgresql"))
            self.storage_maintenance(stage, held=True, delivery_held=False)
            return self.receipt(stage, "rollback", restored_image_pins=True, current_databases_preserved=True,
                                current_configuration_preserved=True, kind="operator image rollback with current schema retained",
                                schema_revision=self.application_schema_current()["revision"],
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
        if not restored:
            # The durable intent follows the verified empty-action/INSERT
            # barrier and executor fence. On restart either DB may be absent;
            # only this exact intent plus a continuous host hold permits retry.
            self._schema_record(stage / "adapter-database-restore-intent.json", restore_context)
            for database in ("nebulalog", "keycloak"):
                self.pg(["dropdb", "--username=postgres", "--force", "--if-exists", database])
                self.pg(["createdb", "--username=postgres", "--owner=" + owners[database], database])
                self.cmd.feed(["podman", "exec", "-i", "--user", "999:999", "nebulalog-postgresql", "pg_restore",
                               "--username=postgres", "--exit-on-error", "--single-transaction", "--dbname=" + database],
                              stage / "recovery" / (database + ".dump"), timeout=600)
        self._schema_read_dependencies(stage)
        self.application_schema_restore(stage, evidence["application_schema"])
        self._schema_record(stage / "adapter-database-restore-complete.json", restore_context)
        self.service("start", tuple(name for name in self.services if name != "postgresql"))
        self.storage_maintenance(stage, held=True, delivery_held=False)
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

    def baseline_runner(self, stage, policy_path):
        """Fixed eval completion, shared by preflight and postactivation scans."""
        def bounded(argv, **kwargs):
            kwargs["timeout"] = min(kwargs.get("timeout", 120), 900)
            ticket = getattr(self, "_component_ticket", None)
            if ticket is None or argv[:3] != ["oscap", "xccdf", "eval"]:
                return self.cmd(argv, **kwargs)
            _, transaction = self.release(stage)
            journal = host_dispatch.HookJournal(stage, transaction)
            self._component_scap = journal.scap_authority(policy_path, argv)
            try:
                return self.cmd(argv, **kwargs)
            except CommandFailed as failure:
                if failure.returncode == 2:
                    journal.acknowledge_scap(ticket, getattr(failure, "execution_ticket", None), argv)
                raise
            finally:
                del self._component_scap
        return bounded

    def content_assessment(self, stage, policy_raw, role="candidate"):
        path = stage / ("content-" + role + "-assessment") / "security-policy.json"
        return ContentUpdate.candidate_assessment(stage, policy_raw, self.baseline_runner(stage, path), role=role)

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
            bounded = self.baseline_runner(stage, directory / "security-policy.json")
            roles = [role for role in ("candidate", "rollback") if os.path.lexists(stage / ("content-" + role + "-assessment.json")) and context["policy_sha256"] == host_dispatch.protected_json(stage / ("content-" + role + "-assessment.json")).get("policy_sha256")]
            if len(roles) > 1:
                raise Refused("Content assessment direction is ambiguous")
            content_assessment = roles[0] if roles else None
            manager = Baseline(directory, runner=bounded, **({"host": ContentUpdate.assessment_host, "full_evidence": True} if content_assessment else {}))
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
                if content_assessment:
                    proof["content_continuation"] = ContentUpdate.finding_continuation(stage, manager, bounded, role=content_assessment, current_locked=True)
                    proof.update(review_complete=not automated, review_sha256=proof["content_continuation"]["review_sha256"])
                elif not automated:
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
                    current = scan(manager.policy_path, verification, bounded, **({"full_evidence": True} if content_assessment else {}))
                    if current.get("host", {}).get("host_controls_ok") is not True:
                        raise Refused("Current host security controls failed during assessment")
                    for item in assessment["assessments"]:
                        if rule_results(verification / (item["kind"] + ".xml"), item["profile"]) != item["rules"]:
                            atomic_json(marker, {**record, "scan_complete": False})
                            atomic_json(stage / "adapter-compliance.json", {**proof, "status": "assessment_changed"})
                            raise Refused("Current rule outcomes changed; a fresh assessment and review are required")
                    if content_assessment:
                        previous_output = directory / "baseline-assessments" / assessment["artifact_directory"]
                        for item in assessment["assessments"]:
                            if ContentUpdate.assessment_evidence(previous_output, item["kind"], item["profile"]) != ContentUpdate.assessment_evidence(verification, item["kind"], item["profile"], source=previous_output / (item["kind"] + "-content.xml")):
                                raise Refused("Current assessment facts changed; candidate approval cannot continue")
                    proof["verification_report"] = str(verification / "summary.json")
                if self._compliance_context() != context:
                    raise Refused("Appliance changed before lifecycle assessment acceptance")
                current_assessment, current_findings, current_assessed = manager._validated_assessment(
                    context["installation_id"], context["baseline"])
                if not current_assessed or current_assessment != assessment or current_findings != findings:
                    raise Refused("Assessment or current host evidence changed before acceptance")
                if content_assessment:
                    if ContentUpdate.finding_continuation(stage, manager, bounded, role=content_assessment, current_locked=True) != proof["content_continuation"]:
                        raise Refused("Content approval changed before lifecycle acceptance")
                elif not automated:
                    manager._validate_review(baseline_json(manager.review_path), context["installation_id"],
                                             context["baseline"], findings)
                atomic_json(stage / "adapter-compliance.json", {**proof, "status": "passed"})
                return proof

    def livepatch_health(self, stage):
        self.guard()
        self.encrypted()
        return self.health(stage, livepatch_health=True)

    def health(self, stage, *, os_health=False, livepatch_health=False, boot_health=False):
        release = {}
        if sum(bool(value) for value in (os_health, livepatch_health, boot_health)) > 1:
            raise Refused("Health operation must have one owner")
        if boot_health:
            self.guard()
            if (not stage.is_absolute() or stage.is_symlink() or stage.resolve() != stage
                    or stage.parent != self.data / "manager/boot-integrity"
                    or not re.fullmatch(r"[a-f0-9]{32}", stage.name)):
                raise Refused("Boot health stage is not an owned integrity generation")
        elif livepatch_health:
            self.guard()
            if stage.is_symlink() or stage.resolve().parent != (self.state / "livepatch-health").resolve():
                raise Refused("Livepatch health stage is outside protected retained storage")
        elif os_health:
            self.guard()
            if stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve():
                raise Refused("OS health stage is not an operation-owned recovery directory")
        else:
            release, _ = self.release(stage)
        if not boot_health and not livepatch_health:
            self.storage_maintenance(stage, held=True, delivery_held=False)
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
        content = {}
        if all(checks.values()) and ("baseline" in release.get("components", {}) or release.get("content_enrollment") == "selected-baseline-v1"):
            from nebulalog_manager.baseline import ContentUpdate
            try:
                _, transaction = self.release(stage)
                if release.get("content_enrollment") == "selected-baseline-v1":
                    measured = ContentUpdate.bridge_health(stage, self.configuration, self.cmd)
                else:
                    measured = ContentUpdate.measure(self.configuration / "security-policy.json", self.cmd)
                    forward = host_activation.selection()["generation"] == HostRuntime(self, stage).candidate["generation"]
                    expected = HostRuntime(self, stage).content()
                    if measured["policy_sha256"] != expected["plan"]["after_policy_sha256" if forward else "before_policy_sha256"]:
                        raise Refused("Content health measured another selected policy")
                    version = release["components"]["baseline"]["version"] if forward else transaction["previous"]["components"]["baseline"]["version"]
                    if measured["version"] != version:
                        raise Refused("Content health version differs from its retained signed authority")
                content["content"] = measured
            except Exception as exc:
                checks["compliance"] = False
                evidence["content"] = {"error": type(exc).__name__}
        value = {"ok": all(checks.values()), "checks": checks, "evidence": evidence,
                 "observed_at": datetime.now(timezone.utc).isoformat(), "certification": "not asserted", **host, **content}
        atomic_json(stage / "adapter-health.json", value)
        return value

    def finalize(self, stage):
        release, transaction = self.release(stage)
        self._component_guard(stage, transaction)
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
        if "baseline" in release["components"] or release.get("content_enrollment") == "selected-baseline-v1":
            current = host_dispatch.protected_json(self.state / "current.json")
            expected = current.get("components", {}).get("baseline")
            if transaction["state"] == "committed" or expected is not None:
                from nebulalog_manager.baseline import ContentUpdate
                measured = ContentUpdate.measure(self.configuration / "security-policy.json", self.cmd)
                if (not isinstance(expected, dict) or health.get("content") != expected
                        or any(expected.get(key) != measured[key] for key in ("generation", "policy_sha256", "engine"))):
                    raise Refused("Content commit inventory differs from current policy and accepted health")
        self.storage_maintenance(stage, held=False)
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
        boot_id = self.boot_id()
        journal = self.data / "manager/os-transaction.json"
        transaction = json.loads(trusted_file(journal).read_text())
        if (transaction.get("state") != "preflight" or transaction.get("stage") is not None
                or transaction.get("payload_started") is not False):
            raise Refused("OS backup requires a new scheduler-owned preflight")
        with self._os_preflight_lease(stage):
            latest = self.data / "manager/os-latest.json"
            proof = {"schema": 1, "stage": str(stage), "boot_id": boot_id,
                     "scheduler": transaction,
                     "previous_latest_sha256": digest_file(trusted_file(latest)) if os.path.lexists(latest) else None,
                     "context": self._os_preflight_context()}
            if proof["context"]["boot_id"] != boot_id:
                raise Refused("OS preflight boot changed while capturing cancellation evidence")
            # Immutable evidence precedes both owner publication and any hold.
            checksum = self._schema_record(stage / "os-preflight-intent.json", proof)
            atomic_json(journal, {**transaction, "stage": str(stage), "boot_id": boot_id,
                                 "preflight_sha256": checksum, "storage_maintenance": "held", "finalization": "pending"})
            latest_value = {"stage": str(stage), "state": "backup_preparing", "boot_id": boot_id,
                            "preflight_sha256": checksum, "observed_at": datetime.now(timezone.utc).isoformat()}
            atomic_json(latest, latest_value)
            result = self.backup(stage, os_backup=True)
            atomic_json(latest, {**latest_value, "state": "prepared"})
        return {**result, "repositories": repositories, "stage": str(stage), "boot_id": boot_id}

    def _os_preflight_lease(self, stage):
        """Keep the hook and any surviving native command behind one fence."""
        import contextlib
        @contextlib.contextmanager
        def lease():
            path = stage / "os-preflight.lock"
            with locked(path) as descriptor:
                self._os_command_records(stage)
                original = self.cmd
                if type(original) is Commands:
                    self.cmd = Commands(inherited_locks=((descriptor, path),),
                        observer=lambda phase, kind, **details: self._os_command_event(stage, phase, kind, **details))
                try:
                    yield descriptor
                finally:
                    self.cmd = original
        return lease()

    def _os_command_records(self, stage):
        """Client exit/FD absence is not acknowledgement of delegated effects."""
        tokens = set()
        for path in stage.glob("os-command-*"):
            match = re.fullmatch(r"os-command-([0-9a-f]{32})-(intent|complete)\.json", path.name)
            if match is None:
                raise Refused("Unknown OS command evidence")
            tokens.add(match[1])
        if len(tokens) > 1024:
            raise Refused("OS command evidence limit reached")
        for token in sorted(tokens):
            intent_path = stage / ("os-command-" + token + "-intent.json")
            raw = trusted_file(intent_path).read_bytes()
            intent = strict_json(raw)
            if (not isinstance(intent, dict) or set(intent) != {"schema", "id", "stage", "boot_id", "kind", "command_sha256"}
                    or type(intent["schema"]) is not int or intent["schema"] != 1
                    or intent["id"] != token or intent["stage"] != str(stage) or intent["boot_id"] != self.boot_id()
                    or intent["kind"] not in {"call", "capture", "feed"}
                    or not isinstance(intent["command_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", intent["command_sha256"])
                    or raw != (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode()):
                raise Refused("OS command intent changed")
            complete = stage / ("os-command-" + token + "-complete.json")
            if not os.path.lexists(complete):
                raise Refused("An OS command has no successful completion acknowledgement; recovery remains held")
            expected = {"schema": 1, "id": token, "intent_sha256": hashlib.sha256(raw).hexdigest(), "success": True}
            if trusted_file(complete).read_bytes() != (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode():
                raise Refused("OS command completion evidence changed")
        return len(tokens)

    def _os_command_event(self, stage, phase, kind, *, argv=None, ticket=None):
        if kind not in {"call", "capture", "feed"}:
            raise Refused("Unknown OS command boundary")
        if phase == "dispatch":
            if self._os_command_records(stage) >= 1024:
                raise Refused("OS command evidence limit reached")
            token = uuid.uuid4().hex
            value = {"schema": 1, "id": token, "stage": str(stage), "boot_id": self.boot_id(), "kind": kind,
                     "command_sha256": hashlib.sha256(json.dumps(argv, separators=(",", ":"), allow_nan=False).encode()).hexdigest()}
            checksum = self._schema_record(stage / ("os-command-" + token + "-intent.json"), value)
            return {"id": token, "intent_sha256": checksum}
        if phase != "complete" or not isinstance(ticket, dict) or set(ticket) != {"id", "intent_sha256"}:
            raise Refused("Unknown OS command acknowledgement")
        token = ticket["id"]
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token):
            raise Refused("Invalid OS command acknowledgement")
        path = trusted_file(stage / ("os-command-" + token + "-intent.json"))
        intent = strict_json(path.read_bytes())
        if (digest_file(path) != ticket["intent_sha256"] or intent.get("stage") != str(stage)
                or intent.get("boot_id") != self.boot_id() or intent.get("kind") != kind):
            raise Refused("OS command acknowledgement belongs to another invocation")
        self._schema_record(stage / ("os-command-" + token + "-complete.json"), {"schema": 1, **ticket, "success": True})

    def _os_preflight_context(self):
        """Measure unchanged-runtime authority without accepting an AIDE change."""
        from nebulalog_manager import aide_updates
        def snapshot(directory):
            files = inventory(directory)
            paths = [directory, *sorted(directory.rglob("*"))]
            details = []
            for path in paths:
                info = path.lstat()
                details.append({"path": path.relative_to(directory).as_posix(),
                    "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid,
                    "inode": info.st_ino, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
                    "metadata": aide_updates._metadata(path)})
            return {"files": files, "details": details}
        manager = aide.Aide()
        if manager.guard().root != self.data:
            raise Refused("OS cancellation integrity belongs to another appliance")
        history = aide_updates.accepted_plan_history(manager=manager)
        xml, _, packages = os_payload.inventory(self.cmd)
        pending = self.data / "manager/kernel-pending.json"
        return {"boot_id": self.boot_id(), "kernel": self.cmd(["/usr/bin/uname", "-r"]),
                "default_kernel": self.cmd(["/usr/sbin/grubby", "--default-kernel"]),
                "grubenv": kernel_updates.describe(Path(kernel_boot.ENV)),
                "rpm_xml_sha256": hashlib.sha256(xml.encode()).hexdigest(), "packages": packages,
                "configuration": snapshot(self.configuration), "quadlets": snapshot(self.quadlets),
                "application_schema": self.application_schema_current(),
                "kernel_pending_sha256": digest_file(trusted_file(pending)) if os.path.lexists(pending) else None,
                "integrity": {"head": history["head"], "database_sha256": history["database_sha256"],
                    "original_enrollment_sha256": hashlib.sha256(json.dumps(history["original_enrollment"],
                        sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()}}

    def _os_cancellation_planning(self, stage):
        """Freeze inert preparation; any execution or deferred owner refuses."""
        allowed = {"kernel-plan.json", "kernel-inventory-before.xml", "rpm-inventory-before.xml"}
        directories = {"kernel-packages", "kernel-keydb"}
        for path in stage.iterdir():
            if path.name.startswith(("kernel-", "rpm-")):
                if path.name in directories and path.is_dir() and not path.is_symlink():
                    inventory(path)  # Private planning trees may contain no links or special files.
                elif path.name not in allowed or path.is_symlink() or not path.is_file():
                    raise Refused("OS cancellation cannot abandon package or kernel execution evidence")
            if path.name.startswith(("adapter-activate", "adapter-reboot", "adapter-database-restore",
                                     "adapter-application-schema-intent")):
                raise Refused("OS cancellation cannot abandon lifecycle effects")
        names = allowed | {"operation.json", "os-payload-plan.json", "os-integrity-plan.json", "os-no-updates.json"}
        return {name: digest_file(trusted_file(stage / name)) for name in sorted(names) if os.path.lexists(stage / name)}

    def _os_cancel_preapply(self, transaction, manager_lock_fd):
        """Cancel only an unchanged original boot, never restore a partial dump."""
        journal = self.data / "manager/os-transaction.json"
        latest_path = self.data / "manager/os-latest.json"
        stage = Path(transaction.get("stage", ""))
        if (not stage.is_absolute() or stage.is_symlink() or stage.resolve() != stage
                or stage.parent != self.data / "manager/os-updates" or not re.fullmatch(r"[0-9a-f]{32}", stage.name)
                or transaction.get("payload_started") is not False
                or transaction.get("storage_maintenance") not in {"held", "release_pending"}
                or any(transaction.get(field) is not None for field in ("kernel_finalization", "kernel_retention", "kernel_rollback", "kernel_retry"))):
            raise Refused("OS cancellation requires exact retained same-boot unattempted preflight ownership")
        with self._os_preflight_lease(stage):
            proof_path = trusted_file(stage / "os-preflight-intent.json")
            raw = proof_path.read_bytes()
            proof = strict_json(raw)
            if (not isinstance(proof, dict)
                    or set(proof) != {"schema", "stage", "boot_id", "scheduler", "previous_latest_sha256", "context"}
                    or type(proof["schema"]) is not int or proof["schema"] != 1
                    or not isinstance(proof["scheduler"], dict) or not isinstance(proof["context"], dict)
                    or proof["stage"] != str(stage) or proof["boot_id"] != transaction.get("boot_id")
                    or self.boot_id() != proof["boot_id"]
                    or hashlib.sha256(raw).hexdigest() != transaction.get("preflight_sha256")
                    or raw != (json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    or proof["scheduler"].get("state") != "preflight"
                    or proof["scheduler"].get("payload_started") is not False
                    or proof["scheduler"].get("reboot_pending") is True
                    or proof["context"].get("kernel_pending_sha256") is not None):
                raise Refused("OS cancellation preflight evidence changed or owns a pending reboot")
            latest = strict_json(trusted_file(latest_path).read_bytes()) if os.path.lexists(latest_path) else None
            if latest is None or latest.get("stage") != str(stage):
                predecessor = digest_file(trusted_file(latest_path)) if latest is not None else None
                if predecessor != proof["previous_latest_sha256"]:
                    raise Refused("OS cancellation latest journal has a foreign owner")
                latest = {"stage": str(stage), "boot_id": proof["boot_id"], "state": "backup_preparing",
                          "preflight_sha256": transaction["preflight_sha256"]}
            if (latest.get("preflight_sha256") != transaction["preflight_sha256"]
                    or latest.get("state") not in {"backup_preparing", "prepared", "preapply_cancel_failed", "postcheck_passed"}):
                raise Refused("OS cancellation latest journal passed the preparation boundary")
            self._reboot_binding(latest, transaction)
            planning = self._os_cancellation_planning(stage)
            if transaction.get("reboot_pending") is True and not (
                    transaction.get("kernel_reboot_required") is True and "kernel-plan.json" in planning):
                raise Refused("OS cancellation cannot abandon an existing reboot obligation")
            if proof["context"] != self._os_preflight_context():
                raise Refused("OS runtime changed since the immutable preflight evidence")
            intent = {"schema": 1, "stage": str(stage), "boot_id": proof["boot_id"],
                      "preflight_sha256": transaction["preflight_sha256"], "planning": planning}
            intent_sha = self._schema_record(stage / "os-cancellation-intent.json", intent)
            transaction = {**transaction, "state": "recovery_required", "recovery_phase": "cancel_preapply",
                           "finalization": "pending", "cancellation_sha256": intent_sha}
            atomic_json(journal, transaction)
            atomic_json(latest_path, latest)
            try:
                self.storage_maintenance(stage, held=True, delivery_held=True, host_only=True)
                self.maintenance(True, stage)
                self.service("stop", tuple(name for name in reversed(self.services) if name != "postgresql"))
                self.service("start", ("postgresql",))
                self.pg_ready()
                self._schema_read_dependencies(stage)
                self.storage_maintenance(stage, held=True, delivery_held=True)
                self.application_schema_check(stage, proof["context"]["application_schema"])
                if proof["context"] != self._os_preflight_context():
                    raise Refused("OS context changed while settling preflight recovery")
                self.service("start", tuple(name for name in self.services if name != "postgresql"))
                integrity = aide.Aide().check_for_transaction(manager_lock_fd)
                if integrity.get("state") != "clean" or integrity.get("exit_code") != 0:
                    raise Refused("Unchanged OS cancellation requires a fresh clean integrity check")
                result = self.health(stage, os_health=True)
                if (result.get("ok") is not True or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS)
                        or proof["context"] != self._os_preflight_context()
                        or planning != self._os_cancellation_planning(stage)):
                    raise Refused("OS cancellation requires unchanged current runtime and complete health")
                completion = {"schema": 1, "stage": str(stage), "boot_id": proof["boot_id"],
                              "intent_sha256": intent_sha, "preflight_sha256": transaction["preflight_sha256"]}
                self._schema_record(stage / "os-cancellation-complete.json", completion)
                atomic_json(latest_path, {**latest, "state": "postcheck_passed"})
                transaction = {**transaction, "state": "complete", "status": "cancelled", "reboot_pending": False,
                               "health": result["checks"], "health_boot_id": proof["boot_id"], "finalization": "pending"}
                atomic_json(journal, transaction)
                completed = self._os_finalize(stage, transaction, result["checks"], proof["boot_id"])
            except Exception as exc:
                retained = strict_json(trusted_file(journal).read_bytes())
                if retained.get("state") != "complete":
                    atomic_json(latest_path, {**latest, "state": "preapply_cancel_failed"})
                    atomic_json(journal, {**retained, "state": "recovery_required", "recovery_phase": "cancel_preapply",
                                         "error": type(exc).__name__})
                raise Refused("OS cancellation remains held; retry exact recovery after resolving the failure") from exc
            audit(self.data / "manager/audit.jsonl", "os.preapply_cancelled", stage=str(stage))
            return self.receipt(stage, "os-recover", checks=result["checks"], status="cancelled", reboot_pending=False,
                                finalized=completed["finalization"] == "complete", storage_released=completed["storage_maintenance"] == "released")

    def _os_finalize(self, stage, transaction, checks, current_boot):
        """Release destructive storage authority only after durable OS acceptance.

        Deferred reboot and fallback success expose the healthy runtime while
        retaining the same operation's destructive hold. The caller supplies
        freshly verified health; a retained healthy journal alone cannot clear it.
        """
        journal = self.data / "manager/os-transaction.json"
        retained = json.loads(trusted_file(journal).read_text())
        latest = json.loads(trusted_file(self.data / "manager/os-latest.json").read_text())
        if (retained != transaction or transaction.get("stage") != str(stage)
                or transaction.get("state") not in {"complete", "reboot_aborted"}
                or transaction.get("finalization") not in {"pending", "failed"}
                or latest.get("stage") != str(stage) or latest.get("boot_id") != transaction.get("boot_id")
                or latest.get("state") not in {"postcheck_passed", "reboot_completed", "reboot_aborted"}
                or transaction.get("health_boot_id") != current_boot or self.boot_id() != current_boot
                or transaction.get("health") != checks
                or any(checks.get(name) is not True for name in REQUIRED_CHECKS)
                or type(transaction.get("reboot_pending")) is not bool):
            raise Refused("OS finalization requires exact durable current-boot acceptance")
        owner, observed = self._reboot_binding(latest, transaction, new_boot=current_boot != transaction["boot_id"])
        if owner != stage or observed != current_boot:
            raise Refused("OS finalization recovery owner changed")
        pending = transaction["reboot_pending"] or any(
            transaction.get(field, "complete") not in (None, "complete")
            for field in ("kernel_finalization", "kernel_retention", "kernel_rollback"))
        transaction = {**transaction, "storage_maintenance": "held" if pending else "release_pending"}
        atomic_json(journal, transaction)
        try:
            self.storage_maintenance(stage, held=pending, delivery_held=False)
            self.maintenance(False, stage)
        except Exception as exc:
            atomic_json(journal, {**transaction, "finalization": "failed", "finalization_error": type(exc).__name__})
            raise Refused("OS acceptance passed; operation-owned storage finalization requires retry") from exc
        transaction = {**transaction, "finalization": "complete", "storage_maintenance": "held" if pending else "released"}
        atomic_json(journal, transaction)
        return transaction

    def os_postcheck(self):
        """Accept the current runtime only against this OS operation's recovery state."""
        self.guard()
        self.encrypted()
        path = self.data / "manager/os-latest.json"
        latest = json.loads(trusted_file(path).read_text())
        transaction = json.loads(trusted_file(self.data / "manager/os-transaction.json").read_text())
        stage = Path(latest["stage"])
        finalizing = transaction.get("state") == "complete" and transaction.get("finalization") in {"pending", "failed"}
        current_boot = self.boot_id()
        if (stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve()
                or transaction.get("stage") != str(stage) or not (transaction.get("state") == "postcheck" or finalizing)
                or not latest.get("boot_id") or latest["boot_id"] != transaction.get("boot_id") or latest["boot_id"] != current_boot
                or latest.get("state") not in ("prepared", "postcheck_passed", "reboot_aborted")):
            raise Refused("OS health check is not bound to the active update and recovery directory")
        try:
            self._reboot_binding(latest, transaction)
            if transaction.get("resuming_deferred") is True:
                latest, transaction, backup_stage = self._os_recovery_backup(stage, latest, transaction)
            else:
                backup_stage = stage
            self.checked_backup(backup_stage)
            os_payload.accept_integrity(stage, runner=self.cmd)
            result = self.health(stage, os_health=True)
            if (result.get("ok") is not True or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS)
                    or self.boot_id() != current_boot):
                raise Refused("OS runtime, security or compliance acceptance failed")
        except Exception as exc:
            atomic_json(path, {**latest, "state": "postcheck_failed", "error": type(exc).__name__})
            self.maintenance(True, stage)
            audit(self.data / "manager/audit.jsonl", "os.postcheck_failed", error=type(exc).__name__)
            raise Refused("OS runtime acceptance failed; recovery evidence retained and maintenance remains active") from exc
        atomic_json(path, {**latest, "state": "postcheck_passed"})
        if finalizing:
            # Recheck the negative hint before releasing a destructive hold;
            # the scheduler's earlier observation is not acceptance authority.
            reboot = self._kernel_candidate(stage) is not None
            try:
                self.cmd(["dnf", "needs-restarting", "--reboothint"], timeout=120)
            except CommandFailed as exc:
                if exc.returncode != 1:
                    raise Refused("Cannot determine whether a reboot is required") from exc
                reboot = True
            transaction = {**transaction, "health": result["checks"], "health_boot_id": current_boot,
                           "reboot_pending": reboot or transaction.get("reboot_pending") is True}
            atomic_json(self.data / "manager/os-transaction.json", transaction)
            transaction = self._os_finalize(stage, transaction, result["checks"], current_boot)
        return {**self.receipt(stage, "os-postcheck", checks=result["checks"], boot_id=current_boot,
                    finalized=finalizing, storage_released=finalizing and transaction.get("storage_maintenance") == "released"),
                "stage": str(stage)}

    def os_recover(self):
        """Recover retained OS work, including a verified old-kernel recovery boot."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock") as manager_lock_fd, locked(self.data / "manager/updates/transaction.lock"):
            path = self.data / "manager/os-latest.json"
            journal = self.data / "manager/os-transaction.json"
            transaction = json.loads(trusted_file(journal).read_text())
            cancelling = (transaction.get("state") in {"preflight", "planning"}
                or transaction.get("state") == "recovery_required" and transaction.get("recovery_phase") in {"preflight", "planning", "cancel_preapply"}
                or transaction.get("state") == "complete" and transaction.get("status") == "cancelled"
                    and transaction.get("finalization") in {"pending", "failed"})
            if cancelling:
                return self._os_cancel_preapply(transaction, manager_lock_fd)
            latest = json.loads(trusted_file(path).read_text())
            stage = Path(latest["stage"])
            current_boot = self.boot_id()
            preparing = transaction.get("state") == "reboot_preparing" or transaction.get("recovery_phase") == "reboot_preparing"
            aborted = latest.get("state") == "reboot_aborted" and (
                transaction.get("state") == "reboot_aborted" and transaction.get("finalization") in {"pending", "failed"}
                or transaction.get("state") == "recovery_required" and transaction.get("recovery_phase") == "reboot_abort")
            retry = transaction.get("state") in ("recovery_required", "reboot_preparing") or (
                transaction.get("state") == "complete" and transaction.get("finalization") in ("pending", "failed")) or aborted
            if (not retry or not preparing and not aborted and transaction.get("recovery_phase") not in ("updating", "postcheck")
                    or stage.is_symlink() or stage.resolve().parent != (self.data / "manager/os-updates").resolve()
                    or transaction.get("stage") != str(stage)
                    or latest.get("state") not in (("reboot_aborted",) if aborted else
                        ("postcheck_passed", "reboot_prepared", "postcheck_failed") if preparing else
                        ("prepared", "postcheck_failed", "postcheck_passed"))
                    or aborted and (transaction.get("reboot_pending") is not True
                        or transaction.get("health_boot_id") != current_boot
                        or any(transaction.get("health", {}).get(name) is not True for name in REQUIRED_CHECKS))
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
                atomic_json(journal, {**transaction, "state": "recovery_required", "error": type(exc).__name__,
                                     "recovery_phase": "postcheck" if aborted else transaction.get("recovery_phase")})
                audit(self.data / "manager/audit.jsonl", "os.recovery_health_failed", error=type(exc).__name__)
                raise Refused("OS recovery acceptance failed; maintenance and recovery evidence remain intact") from exc
            atomic_json(path, {**latest, "state": "postcheck_passed"})
            completed = {**transaction, "state": "complete", "status": "no_updates" if transaction.get("no_updates") is True else "updated", "finalization": "pending",
                         "reboot_pending": reboot, "health": result["checks"], "health_boot_id": current_boot, "recovery_phase": "postcheck",
                         "completed_at": datetime.now(timezone.utc).isoformat()}
            atomic_json(journal, completed)
            try:
                self._os_finalize(stage, completed, result["checks"], current_boot)
            except Exception as exc:
                atomic_json(journal, {**completed, "finalization": "failed", "finalization_error": type(exc).__name__})
                raise Refused("OS health passed; retry os-recover to release maintenance") from exc
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

    def _kernel_recovery_health(self, stage, kernel, boot_id):
        if self.boot_id() != boot_id or self.cmd(["/usr/bin/uname", "-r"]) != kernel:
            raise Refused("Kernel recovery requires the exact current recovery boot")
        result = self.health(stage, os_health=True)
        if (result.get("ok") is not True
                or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS)
                or self.boot_id() != boot_id or self.cmd(["/usr/bin/uname", "-r"]) != kernel):
            raise Refused("Kernel recovery requires all current runtime checks")
        return {name: True for name in REQUIRED_CHECKS}

    def _kernel_recovery_authorization(self, stage, backup_stage):
        observed = self.boot_id()
        running = self.cmd(["/usr/bin/uname", "-r"])
        checks = self._kernel_recovery_health(stage, running, observed)
        checksum = kernel_integrity.checked_backup(backup_stage)
        if self.boot_id() != observed:
            raise Refused("Kernel recovery boot changed during backup verification")
        return {"ok": True, "stage": str(stage), "boot_id": observed, "kernel": running,
                "checks": checks, "backup_stage": str(backup_stage), "backup_sha256": checksum}

    def kernel_retry(self):
        """Explicitly request the single permitted retry of a failed candidate."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock"), locked(self.data / "manager/updates/transaction.lock"):
            latest_path = self.data / "manager/os-latest.json"
            journal = self.data / "manager/os-transaction.json"
            latest = json.loads(trusted_file(latest_path).read_text())
            transaction = json.loads(trusted_file(journal).read_text())
            stage, current_boot = self._reboot_binding(latest, transaction, new_boot=True)
            if (transaction.get("kernel_finalization") != "recovery_required"
                    or transaction.get("kernel_outcome") != "recovery"
                    or os.path.lexists(stage / "kernel-acceptance-current.json")
                    or os.path.lexists(stage / "kernel-rollback-intent.json")):
                raise Refused("Kernel retry requires an unaccepted candidate after verified fallback")
            # A request receipt precedes systemctl. An interrupted request is
            # never silently issued again; rollback can cancel the owned arm.
            if os.path.lexists(stage / "kernel-retry-request.json"):
                raise Refused("A kernel retry was already requested; inspect reboot completion or use kernel-rollback")
            self.maintenance(True, stage)
            transaction = {**transaction, "state": "recovery_required", "finalization": "pending",
                           "kernel_finalization": "recovery_required", "kernel_retry": "preparing"}
            atomic_json(journal, transaction)
            try:
                recovery = kernel_boot.reconcile_recovery(stage, **self._kernel_callbacks())
                if recovery.get("outcome") != "recovery" or recovery.get("boot_id") != current_boot:
                    raise Refused("Kernel retry requires a verified current fallback boot")
                proof = kernel_boot.verified_recovery(stage, runner=self.cmd)
                latest, transaction, backup_stage = self._os_recovery_backup(stage, latest, transaction)
                self._kernel_recovery_health(stage, proof["recovery_kernel"], current_boot)
                unlock = self.unlock_readiness("/boot/vmlinuz-" + proof["kernel"])
                local_auth(self.config)
                def authorize(directory):
                    if directory != stage:
                        raise Refused("Kernel retry authorization belongs to another operation")
                    return self._kernel_recovery_authorization(stage, backup_stage)
                armed = kernel_boot.retry_candidate(stage, authorize=authorize, **self._kernel_callbacks())
                if (armed.get("ok") is not True or armed.get("status") != "retry_armed"
                        or armed.get("attempt") != 2 or armed.get("boot_id") != current_boot
                        or armed.get("release_accepted") is not False):
                    raise Refused("Kernel retry did not return an exact bounded arm receipt")
                transaction = {**transaction, "state": "reboot_preparing", "kernel_retry": "armed",
                               "retry_boot_id": current_boot, "reboot_pending": True}
                atomic_json(journal, transaction)
                self.storage_maintenance(stage, held=True, delivery_held=True)
                self.service("stop", tuple(reversed(self.services)))
                self.cmd(["sync", "-f", str(self.data)], timeout=120)
                if self.boot_id() != current_boot:
                    raise Refused("Kernel retry boot changed before its reboot request")
                request = {"schema": 1, "stage": str(stage), "boot_id": current_boot,
                           "transition_sha256": armed["transition_sha256"], "attempt": 2}
                kernel_updates.record(stage, "kernel-retry-request.json", request)
                atomic_json(latest_path, {**latest, "state": "reboot_prepared", "retry_boot_id": current_boot})
                transaction = {**transaction, "state": "reboot_requested", "kernel_retry": "requested"}
                atomic_json(journal, transaction)
                audit(self.data / "manager/audit.jsonl", "os.kernel_retry_requested", boot_id=current_boot)
                self.cmd(["systemctl", "reboot"], timeout=120)
            except Exception as exc:
                try:
                    state = kernel_boot.candidate_status(stage, runner=self.cmd)
                    if state.get("phase") in {"retry_arm", "postboot", "recovery_resume"}:
                        kernel_boot.abort_candidate(stage, **self._kernel_callbacks())
                    self.service("start", self.services)
                    kernel_boot.reconcile_recovery(stage, **self._kernel_callbacks())
                    proof = kernel_boot.verified_recovery(stage, runner=self.cmd)
                    checks = self._kernel_recovery_health(stage, proof["recovery_kernel"], current_boot)
                    failed = {**transaction, "state": "complete", "finalization": "pending",
                              "kernel_retry": "held", "kernel_finalization": "recovery_required",
                              "kernel_outcome": "recovery", "reboot_pending": True,
                              "kernel_recovery_reason": "retry_request_failed", "error": type(exc).__name__,
                              "health": checks, "health_boot_id": current_boot}
                    atomic_json(latest_path, {**latest, "state": "reboot_completed", "observed_boot_id": current_boot})
                    atomic_json(journal, failed)
                    self._os_finalize(stage, failed, checks, current_boot)
                except Exception as recovery_error:
                    self.maintenance(True, stage)
                    atomic_json(journal, {**transaction, "state": "recovery_required", "finalization": "failed",
                                         "kernel_retry": "held", "error": type(recovery_error).__name__})
                    raise Refused("Kernel retry recovery requires attention; maintenance remains active") from recovery_error
                raise Refused("Kernel retry could not complete; the old kernel and runtime were verified, candidate recovery remains pending") from exc
            return self.receipt(stage, "kernel-retry", status="reboot_requested", boot_id=current_boot,
                                attempt=2, reboot_pending=True, release_accepted=False, unlock=unlock)

    def kernel_rollback(self):
        """Remove only the owned unaccepted candidate after verified fallback."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock"), locked(self.data / "manager/updates/transaction.lock"):
            latest = json.loads(trusted_file(self.data / "manager/os-latest.json").read_text())
            transaction = json.loads(trusted_file(self.data / "manager/os-transaction.json").read_text())
            stage, current_boot = self._reboot_binding(latest, transaction, new_boot=True)
            if (os.path.lexists(stage / "kernel-acceptance-current.json")
                    or not (transaction.get("kernel_finalization") == "recovery_required"
                            and transaction.get("kernel_outcome") == "recovery"
                            or transaction.get("kernel_rollback") in {"pending", "failed", "complete"})):
                raise Refused("Kernel rollback requires the owned unaccepted fallback candidate")
            return self._kernel_rollback(stage, latest, transaction, current_boot)

    def _kernel_rollback(self, stage, latest, transaction, current_boot):
        from nebulalog_manager import kernel_rollback
        latest_path = self.data / "manager/os-latest.json"
        journal = self.data / "manager/os-transaction.json"
        self.maintenance(True, stage)
        transaction = {**transaction, "state": "recovery_required", "finalization": "pending",
                       "kernel_finalization": "recovery_required", "kernel_rollback": "pending"}
        atomic_json(journal, transaction)
        try:
            if not any(os.path.lexists(stage / name) for name in
                       (kernel_rollback.PLAN, kernel_rollback.INTENT, kernel_rollback.COMPLETE)):
                proof = kernel_boot.prepare_rollback_recovery(stage, **self._kernel_callbacks())
                if proof.get("outcome") != "recovery" or proof.get("boot_id") != current_boot:
                    raise Refused("Kernel rollback requires exact current fallback integrity")
            self.service("start", self.services)
            # Existing rollback evidence takes priority: candidate files may
            # already be gone. Its typed recovery validates the retained scope
            # and boot history without repeating RPM or recapturing a baseline.
            latest, transaction, backup_stage = self._os_recovery_backup(stage, latest, transaction)
            def authorize(directory):
                if directory != stage:
                    raise Refused("Kernel rollback authorization belongs to another operation")
                return self._kernel_recovery_authorization(stage, backup_stage)
            result = kernel_rollback.rollback(stage, authorize=authorize, runner=self.cmd)
            if (result.get("ok") is not True or result.get("status") != "rolled_back"
                    or result.get("release_accepted") is not False):
                raise Refused("Kernel rollback did not verify exact removal and integrity")
            checks = self._kernel_recovery_health(stage, result["recovery_kernel"], current_boot)
            completed = kernel_updates.mark_rolled_back(stage, {k: v for k, v in result.items() if k != "ok"},
                {"ok": True, "stage": str(stage), "boot_id": current_boot,
                 "kernel": result["recovery_kernel"], "checks": checks}, runner=self.cmd)
            if completed.get("status") != "rolled_back" or completed.get("release_accepted") is not False:
                raise Refused("Kernel rollback disposition was not durably verified")
            latest = {**latest, "state": "reboot_completed", "observed_boot_id": current_boot}
            transaction = {**transaction, "state": "complete", "finalization": "pending",
                           "kernel_finalization": "complete", "kernel_rollback": "complete",
                           "kernel_outcome": "rolled_back", "kernel_retry": "held", "reboot_pending": False,
                           "observed_boot_id": current_boot, "health": checks, "health_boot_id": current_boot}
            atomic_json(latest_path, latest)
            atomic_json(journal, transaction)
            self._os_finalize(stage, transaction, checks, current_boot)
        except Exception as exc:
            self.maintenance(True, stage)
            atomic_json(journal, {**transaction, "state": "recovery_required", "finalization": "failed",
                                 "kernel_rollback": "failed", "rollback_error": type(exc).__name__})
            raise Refused("Kernel rollback requires recovery; maintenance and exact evidence are retained") from exc
        audit(self.data / "manager/audit.jsonl", "os.kernel_rolled_back", boot_id=current_boot)
        return self.receipt(stage, "kernel-rollback", status="rolled_back", boot_id=current_boot,
                            reboot_pending=False, release_accepted=False, checks=checks, rollback=completed)

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
        current_boot = self.boot_id()
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
            transaction = {**transaction, "state": "complete", "kernel_retention": "complete",
                           "reboot_pending": False, "health": health["checks"], "health_boot_id": current_boot}
            atomic_json(journal, transaction)
            self._os_finalize(stage, transaction, health["checks"], transaction["health_boot_id"])
        except Exception as exc:
            self.maintenance(True, stage)
            atomic_json(journal, {**transaction, "kernel_retention": "failed", "finalization": "failed", "retention_error": type(exc).__name__})
            raise Refused("Kernel retention requires recovery; maintenance and retained kernels are preserved") from exc
        return result

    def _kernel_retention_unattempted(self, stage, latest, transaction, current_boot):
        """Accept the later boot before creating a new, once-only erase plan."""
        journal = self.data / "manager/os-transaction.json"
        latest_path = self.data / "manager/os-latest.json"
        transaction = {**transaction, "kernel_retention": "pending", "finalization": "pending"}
        atomic_json(journal, transaction)
        self.maintenance(True, stage)
        try:
            # An erase intent is global to the operation, across all execution
            # generations. Observed unchanged packages cannot permit replay.
            if os.path.lexists(stage / kernel_retention.INTENT):
                raise Refused("Attempted retention cannot start another execution generation")
            kernel_retention.verify_unattempted(stage, runner=self.cmd)
            original, _ = kernel_retention.load_historical_plan(stage)
            if original["boot_id"] == current_boot or self.boot_id() != current_boot:
                raise Refused("Unattempted retention requires the exact later boot")
            latest, transaction, _ = self._os_recovery_backup(stage, latest, transaction)
            candidate = self._kernel_candidate(stage)
            if candidate is None:
                raise Refused("Unattempted retention has no owned kernel candidate")
            boot = kernel_boot.verify_postboot(stage, **self._kernel_callbacks())
            if (boot.get("outcome") != "candidate" or boot.get("phase") != "resume"
                    or boot.get("boot_id") != current_boot or boot.get("kernel") != candidate[1]["kernel"]
                    or boot.get("release_accepted") is not False):
                raise Refused("Kernel retention requires the accepted candidate to be running")
            health = self.health(stage, os_health=True)
            if health.get("ok") is not True or any(health.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
                raise Refused("Unattempted retention requires all current runtime checks")
            if self.boot_id() != current_boot:
                raise Refused("Retention boot changed before current acceptance")
            kernel_boot.commit_candidate(stage, health={"ok": True, "stage": str(stage), "boot_id": current_boot,
                "kernel": candidate[1]["kernel"], "checks": health["checks"]}, **self._kernel_callbacks())
            self._kernel_finalize(stage, health["checks"])
            latest = {**latest, "state": "reboot_completed", "observed_boot_id": current_boot}
            atomic_json(latest_path, latest)
            transaction = {**transaction, "state": "complete", "kernel_finalization": "complete",
                           "observed_boot_id": current_boot, "reboot_pending": False}
            atomic_json(journal, transaction)
            # Retention now derives a current-boot execution generation from
            # the immutable old plan. Its own fresh health/backup/AIDE checks
            # still precede the single durable erase intent.
            result = self._kernel_retain(stage, latest, transaction)
        except Exception as exc:
            self.maintenance(True, stage)
            atomic_json(journal, {**transaction, "kernel_retention": "failed", "finalization": "failed",
                                 "retention_error": type(exc).__name__})
            raise Refused("Unattempted later-boot retention requires recovery; maintenance remains active") from exc
        return self.receipt(stage, "reboot-complete", boot_id=current_boot, checks=health["checks"],
                            status="complete", reboot_pending=False, retention=result)

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
                           "observed_boot_id": current_boot, "reboot_pending": False,
                           "kernel_retention": "complete", "health": postcheck["checks"], "health_boot_id": current_boot}
            atomic_json(journal, transaction)
            self._os_finalize(stage, transaction, postcheck["checks"], current_boot)
        except Exception as exc:
            self.maintenance(True, stage)
            atomic_json(journal, {**transaction, "kernel_retention": "failed", "finalization": "failed",
                                 "retention_error": type(exc).__name__})
            raise Refused("Later-boot kernel retention requires recovery; maintenance remains active") from exc
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
        backup_stage = Path(latest.get("recovery_backup_stage", str(stage)))
        if (backup_stage.parent != stage.parent or backup_stage.is_symlink()
                or latest.get("recovery_backup_stage") != transaction.get("recovery_backup_stage")):
            raise Refused("Reboot recovery backup belongs to another operation")
        # Refreshed backups retain the original OS stage and hold owner.
        observed_at = (json.loads(trusted_file(backup_stage / "adapter-backup.json").read_text())["observed_at"]
                       if backup_stage != stage else latest.get("observed_at"))
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(observed_at)).total_seconds()
        except (KeyError, TypeError, ValueError):
            raise Refused("OS recovery backup timestamp is invalid") from None
        if not 0 <= age <= 7200:
            raise Refused("OS recovery backup is stale or dated in the future")
        self.checked_backup(backup_stage)
        candidate = self._kernel_candidate(stage)
        unlock = self.unlock_readiness("/boot/vmlinuz-" + candidate[1]["kernel"]) if candidate is not None else self.unlock_readiness()
        local_auth(self.config)
        self.maintenance(True, stage)
        try:
            rearmed = False
            if candidate is not None:
                progress = kernel_boot.candidate_status(stage, runner=self.cmd)
                if progress.get("phase") in {"abort", "rearm"}:
                    # Rearm authorization needs the complete healthy runtime;
                    # it must precede the delivery fence and service stops.
                    result = kernel_boot.rearm_candidate(stage,
                        authorize=lambda directory: self._kernel_recovery_authorization(directory, backup_stage),
                        **self._kernel_callbacks())
                    if result.get("ok") is not True or result.get("status") != "rearmed" or result.get("boot_id") != boot_id:
                        raise Refused("Kernel rearm did not verify its operation-bound receipt")
                    rearmed = True
            self.storage_maintenance(stage, held=True, delivery_held=True)
            self.service("stop", tuple(reversed(self.services)))
            self.cmd(["sync", "-f", str(self.data)], timeout=120)
            if candidate is not None and not rearmed:
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
        stage, current_boot = self._reboot_binding(latest, transaction)
        if latest.get("state") != "reboot_prepared" or transaction.get("state") != "reboot_requested":
            raise Refused("No operation-owned prepared reboot can be aborted")
        self.checked_backup(stage)
        if self._kernel_candidate(stage) is not None:
            kernel_boot.abort_candidate(stage, **self._kernel_callbacks())
        self.service("start", self.services)
        result = self.health(stage, os_health=True)
        if result.get("ok") is not True or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
            raise Refused("Reboot abort runtime acceptance failed; maintenance remains active")
        atomic_json(self.data / "manager/os-latest.json", {**latest, "state": "reboot_aborted"})
        transaction = {**transaction, "state": "reboot_aborted", "finalization": "pending", "reboot_pending": True,
                       "health": result["checks"], "health_boot_id": current_boot, "recovery_phase": "postcheck"}
        atomic_json(self.data / "manager/os-transaction.json", transaction)
        self._os_finalize(stage, transaction, result["checks"], current_boot)
        return self.receipt(stage, "reboot-abort", services_restarted=list(self.services), recovered=True,
                            health=result["checks"], boot_id=current_boot, finalized=True, storage_released=False)

    @staticmethod
    def boot_id():
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if not re.fullmatch(r"[0-9a-f-]{36}", value):
            raise Refused("Current boot identity is unavailable")
        return value

    def _ordinary_boot_stage(self):
        # Initial setup owns its pre-enrollment configuration. An existing
        # enrollment must provide its immutable boot root; legacy facts cannot
        # be silently recaptured from the running machine.
        if not os.path.lexists(self.data / "manager/aide-enrollment.json"):
            return None
        from nebulalog_manager import ordinary_boot
        try:
            return ordinary_boot.pending_stage(self.data, runner=self.cmd)
        except Exception as exc:
            # A periodic verification can fail before it has a valid plan.
            # Record only a failure owner; this provides no baseline or
            # acceptance authority and cannot take another operation's gate.
            hold = ordinary_boot.observation_hold(self.data, boot_id=self.boot_id())
            if hold is None:
                raise Refused("Ordinary boot observation failed without an owned recovery hold") from exc
            self.maintenance(True, hold)
            raise Refused("Ordinary boot observation requires recovery; maintenance remains active") from exc

    def _ordinary_boot_owner(self, stage):
        from nebulalog_manager import ordinary_boot
        marker = self.data / "manager/maintenance.json"
        if os.path.lexists(marker):
            value = json.loads(trusted_file(marker).read_text())
            if (value.get("active") is not True or not isinstance(value.get("release"), str)
                    or not ordinary_boot.owns_maintenance(stage, value["release"])):
                raise Refused("Another operation owns maintenance during ordinary boot verification")

    def _ordinary_boot_complete(self):
        from nebulalog_manager import ordinary_boot
        stage = self._ordinary_boot_stage()
        if stage is None:
            return {"ok": True, "status": "not_pending"}
        self._ordinary_boot_owner(stage)
        self.maintenance(True, stage)
        try:
            observed_boot = self.boot_id()
            integrity = ordinary_boot.reconcile(stage, **self._kernel_callbacks())
            if integrity.get("ok") is not True:
                raise Refused("Ordinary boot integrity reconciliation did not pass")
            health = self.health(stage, boot_health=True)
            if (health.get("ok") is not True
                    or any(health.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS)
                    or self.boot_id() != observed_boot):
                raise Refused("Ordinary boot requires every current runtime check")
            complete = ordinary_boot.finalize(stage, health={"ok": True, "stage": str(stage),
                "boot_id": observed_boot, "checks": health["checks"]}, runner=self.cmd)
            if complete.get("ok") is not True or complete.get("boot_id") != observed_boot:
                raise Refused("Ordinary boot finalization did not verify the current boot")
            self._ordinary_boot_owner(stage)
            self.maintenance(False, stage)
        except Exception as exc:
            self.maintenance(True, stage)
            raise Refused("Ordinary boot verification requires recovery; maintenance remains active") from exc
        return self.receipt(stage, "boot-complete", boot_id=observed_boot, checks=health["checks"],
                            status="complete", integrity=integrity, ordinary_boot=complete)

    def boot_gate(self):
        """Runs after encrypted mounts and BEFORE the public HTTPS edge starts."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock"), locked(self.data / "manager/updates/transaction.lock"):
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
                           or record.get("kernel_finalization") in ("pending", "failed", "recovery_required")
                           or record.get("kernel_retention") in ("pending", "failed")
                           or record.get("storage_maintenance") == "release_pending"
                           or record.get("storage_maintenance") == "held"
                           and self.boot_id() != record.get("health_boot_id", record.get("boot_id")))
                if pending:
                    self.maintenance(True, Path(record.get(owner_key, str(self.data / "manager"))))
                    return {"ok": True, "maintenance": True, "source": "interrupted transaction"}
            ordinary = self._ordinary_boot_stage()
            if ordinary is not None:
                self._ordinary_boot_owner(ordinary)
                self.maintenance(True, ordinary)
                return {"ok": True, "maintenance": True, "source": "ordinary boot integrity"}
            return {"ok": True, "maintenance": False, "source": "no pending transaction"}

    def reboot_complete(self):
        """Reconcile an actual new boot; never clear a gate on same-boot success."""
        self.guard()
        self.encrypted()
        with locked(self.data / "manager/transaction.lock"), locked(self.data / "manager/updates/transaction.lock"):
            path = self.data / "manager/os-latest.json"
            journal = self.data / "manager/os-transaction.json"
            if not path.exists() or not journal.exists():
                return self._ordinary_boot_complete()
            latest = json.loads(trusted_file(path).read_text())
            transaction = json.loads(trusted_file(journal).read_text())
            if (transaction.get("state") == "complete" and transaction.get("finalization", "complete") == "complete"
                    and transaction.get("reboot_pending") is not True
                    and transaction.get("storage_maintenance", "released") == "released"
                    and transaction.get("kernel_finalization", "complete") in (None, "complete")
                    and transaction.get("kernel_retention", "complete") in (None, "complete")
                    and transaction.get("kernel_rollback", "complete") in (None, "complete")):
                return self._ordinary_boot_complete()
            stage, current_boot = self._reboot_binding(latest, transaction, new_boot=True)
            if (transaction.get("kernel_rollback") in {"pending", "failed"}
                    or transaction.get("kernel_rollback") == "complete"
                    and transaction.get("finalization") != "complete"):
                return self._kernel_rollback(stage, latest, transaction, current_boot)
            if (transaction.get("kernel_retention") in ("pending", "failed")
                    and os.path.lexists(stage / "kernel-acceptance-current.json")):
                self.maintenance(True, stage)
                if os.path.lexists(stage / kernel_retention.PLAN):
                    retained_plan, _ = kernel_retention.load_historical_plan(stage)
                    if retained_plan["boot_id"] != current_boot:
                        if not os.path.lexists(stage / kernel_retention.INTENT):
                            return self._kernel_retention_unattempted(stage, latest, transaction, current_boot)
                        return self._kernel_retention_resume(stage, latest, transaction, current_boot)
                acceptance, _, _ = kernel_updates.read_acceptance(stage)
                if acceptance["boot_id"] == current_boot and transaction.get("kernel_finalization") == "complete":
                    retained = self._kernel_retain(stage, latest, transaction)
                    return self.receipt(stage, "reboot-complete", boot_id=current_boot, checks=acceptance["checks"],
                                        status="complete", reboot_pending=False, retention=retained)
            transition = os.path.lexists(stage / "kernel-boot-current.json")
            deferred = transaction.get("storage_maintenance") == "held" and transaction.get("reboot_pending") is True
            latest_allowed = ("reboot_prepared", "recovery_required", "reboot_completed") + (("postcheck_passed", "postcheck_failed") if transition or deferred else ()) + (("reboot_aborted",) if deferred else ())
            transaction_allowed = ("reboot_requested", "recovery_required", "complete") + (("reboot_preparing",) if transition else ()) + (("reboot_aborted",) if deferred else ())
            if latest.get("state") not in latest_allowed or transaction.get("state") not in transaction_allowed:
                raise Refused("Interrupted OS work has not reached the verified reboot phase")
            self.maintenance(True, stage)
            candidate = None
            boot_result = None
            try:
                latest, transaction, backup_stage = self._os_recovery_backup(stage, latest, transaction)
                self.checked_backup(backup_stage)
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
                         "observed_boot_id": current_boot, "completed_at": datetime.now(timezone.utc).isoformat(),
                         "health": result["checks"], "health_boot_id": current_boot}
            if candidate is not None:
                completed.update(kernel_finalization="recovery_required" if recovered else "pending", kernel_outcome=boot_result["outcome"])
                if recovered:
                    completed.update(kernel_retry="held", kernel_recovery_reason="candidate_not_running_after_reboot")
                else:
                    completed["kernel_retention"] = "pending"
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
            else:
                try:
                    self._os_finalize(stage, completed, result["checks"], current_boot)
                except Exception as exc:
                    raise Refused("New OS boot passed; retry reboot-complete to release maintenance") from exc
            audit(self.data / "manager/audit.jsonl", "os.reboot_verified", boot_id=current_boot)
            return self.receipt(stage, "reboot-complete", boot_id=current_boot, checks=result["checks"],
                                status="kernel_recovery_required" if recovered else "complete", reboot_pending=recovered)
