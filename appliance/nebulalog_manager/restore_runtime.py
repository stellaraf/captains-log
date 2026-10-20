"""Runtime half of a fresh-appliance configuration restore.

The coordinator owns archive authentication, database restores and the four host
locks. This module never overwrites an enrolled runtime, imports a realm, resets
an account, or accepts a source appliance's host/integrity/update enrollment.
"""
from __future__ import annotations

import hashlib
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from .backup import _directory, _encrypted_staging, _pg
from .bootstrap import Bootstrap, image_pins
from .common import Refused, atomic_json, require_linux_root, run, trusted_file
from .firstboot import FirstBoot, Locations, RUNTIME_CHECKS, _private_file, _write_bytes
from .host_payload import strict_json

LISTENERS = ("keycloak", "api", "ingest", "edge")
SYSTEMD = Path("/etc/systemd/system")
RESTORE_STAGES = frozenset(("directories", "storage-maintenance", "certificates", "images", "environment",
                          "postgresql", "restored-databases", "identity-rebind", "schema", "lifecycle",
                          "edge", "installed-release"))
TLS_FILES = ("ca.key", "ca.crt", "server.key", "server.crt")
SOURCE_FILES = tuple("configuration/" + name for name in (
    "bootstrap/setup.json", "bootstrap/secrets.json", "bootstrap/runtime-secrets.json",
    "bootstrap/runtime-state.json", "lifecycle.json", *("tls/" + name for name in TLS_FILES)))
PREPARED_STAGES = frozenset(("directories", "storage-maintenance", "certificates", "images", "environment", "postgresql"))


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise Refused("Invalid restore installation/operation identity") from None
    return value


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Refused("Invalid restore evidence digest")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _storage_query_id(operation, phase):
    raw = bytearray(hashlib.sha256(("captains-log/storage-init/" + _sha(operation) + "/" + phase).encode()).digest()[:16])
    raw[6], raw[8] = (raw[6] & 15) | 0x50, (raw[8] & 63) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _json(path):
    return strict_json(_private_file(path, maximum=1024 * 1024))


def _hash(path):
    return hashlib.sha256(_private_file(path, maximum=1024 * 1024)).hexdigest()


def refuse_normal_provision(paths):
    """A restore can only resume through its coordinator, including after reboot."""
    pointer = paths.data / "manager/restore.json"
    if os.path.lexists(pointer):
        # Even a completed restore has its own runtime path. Re-running the fresh
        # realm generator is never an appropriate restore recovery operation.
        _json(pointer)
        raise Refused("A configuration restore owns this runtime; use restore recovery or setup verification")


def valid_restored_state(state, paths, *, pending=False):
    """Read-only proof used by normal console/AIDE gates, not an adoption switch."""
    try:
        context = state["restore"]
        target = _uuid(state["installation_id"])
        operation = _uuid(context["id"])
        stage = Path(context["stage"])
        if (stage != paths.data / "manager/restores" / operation
                or context.get("target_installation_id") != target
                or set(context) != {"id", "stage", "source_installation_id", "target_installation_id", "manifest_sha256"}):
            return False
        _directory(stage, private=True)
        proof = _json(stage / "runtime-activation.json")
        pointer = _json(paths.data / "manager/restore.json")
        transaction = _json(stage / "transaction.json")
        allowed = {"runtime_ready", "verifying"} if pending else {"runtime_ready"}
        if (pointer != {"schema": 2, "id": operation, "stage": str(stage)}
                or transaction.get("state") not in allowed
                or transaction.get("kind") != "configuration-restore"
                or any(transaction.get(key) != value for key, value in context.items())
                or transaction.get("runtime", {}).get("completed") != state.get("completed")
                or transaction.get("runtime", {}).get("active_stage") is not None
                or transaction.get("runtime", {}).get("factory_binding") != state.get("factory_binding")):
            return False
        return (state.get("kind") == "configuration-restore" and state.get("active_stage") is None
                and state.get("identity_initialized") is True
                and type(state.get("completed")) is list
                and len(state["completed"]) == len(RESTORE_STAGES)
                and set(state["completed"]) == RESTORE_STAGES
                and proof == FreshRestoreRuntime._proof(transaction)
                and _json(stage / "listeners-ready.json") == {**proof, "state": "databases-ready"})
    except (OSError, ValueError, KeyError, TypeError, Refused):
        return False


def valid_restored_enrollment_state(state, paths, binding):
    """Validate activation's real enrollment intent without claiming completion."""
    try:
        context = state["restore"]
        operation = _uuid(context["id"])
        target = _uuid(context["target_installation_id"])
        stage = paths.data / "manager/restores" / operation
        _directory(stage, private=True)
        tx = _json(stage / "transaction.json")
        progress = tx["runtime"]
        completed, active = progress["completed"], progress.get("active_stage")
        unfinished = RESTORE_STAGES - {"installed-release"}
        expected_context = {key: tx[key] for key in ("id", "stage", "source_installation_id", "target_installation_id", "manifest_sha256")}
        return (context == expected_context and context["stage"] == str(stage)
                and _json(paths.data / "manager/restore.json") == {"schema": 2, "id": operation, "stage": str(stage)}
                and type(tx.get("schema")) is int and tx["schema"] == 1 and tx.get("kind") == state.get("kind") == "configuration-restore"
                and tx.get("state") in ("enrollment_pending", "verifying", "runtime_ready")
                and state.get("installation_id") == target == binding.get("installation_id")
                and state.get("factory_binding") == progress.get("factory_binding") == binding
                and state.get("identity_initialized") is True
                and isinstance(completed, list) and len(completed) == len(set(completed))
                and state.get("completed") == completed and state.get("active_stage") == active
                and ((set(completed) == unfinished and active == "installed-release")
                     or (set(completed) == RESTORE_STAGES and active is None))
                and _json(stage / "listeners-ready.json") == {**FreshRestoreRuntime._proof(tx), "state": "databases-ready"})
    except (OSError, ValueError, KeyError, TypeError, Refused):
        return False


def identity_rebind_sql(source, target, administrator_id, *, not_before):
    """Fixed Keycloak 26 tables; only appliance ownership attributes can change.

    The SQL transaction accepts all-source or all-target markers. A mixed state
    cannot be adopted. Credential, subject, role and signing-key rows are never
    updated. The caller must own a durable rebind intent before dispatch.
    """
    source, target, administrator_id = map(_uuid, (source, target, administrator_id))
    if source == target:
        raise Refused("A fresh restore requires a distinct target installation")
    if type(not_before) is not int or not 1577836800 <= not_before < 2**31:
        raise Refused("Restore authentication cutoff must be a canonical epoch second")
    return f"""BEGIN;
SET LOCAL lock_timeout = '15s'; SET LOCAL statement_timeout = '60s';
SET LOCAL search_path = pg_catalog, public;
DO $restore$
DECLARE r text; h text; m text; i text; owner text; n integer;
BEGIN
 IF (SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='realm' AND column_name='not_before' AND data_type='integer') <> 1
 OR (SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('offline_client_session','offline_user_session') AND column_name IN ('realm_id','offline_flag')) <> 4
 OR (SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='root_auth_session' AND column_name IN ('realm_id','id')) <> 2
 OR (SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='auth_session' AND column_name='root_auth_session_id') <> 1
 THEN RAISE EXCEPTION 'restore session schema'; END IF;
 IF (SELECT count(*) FROM realm WHERE name='nebulalog') <> 1 THEN RAISE EXCEPTION 'restore realm'; END IF;
 SELECT id INTO r FROM realm WHERE name='nebulalog';
 IF (SELECT count(*) FROM user_entity WHERE id='{administrator_id}' AND realm_id=r AND enabled AND federation_link IS NULL) <> 1
 OR (SELECT count(*) FROM user_attribute WHERE user_id='{administrator_id}' AND name='nebulalog-local-operator' AND value='true') <> 1
 THEN RAISE EXCEPTION 'restore administrator'; END IF;
 IF (SELECT count(DISTINCT type) FROM credential WHERE user_id='{administrator_id}' AND type IN ('password','otp','recovery-authn-codes')) <> 3
 OR EXISTS(SELECT 1 FROM user_required_action WHERE user_id='{administrator_id}' AND required_action IN ('CONFIGURE_TOTP','CONFIGURE_RECOVERY_AUTHN_CODES'))
 THEN RAISE EXCEPTION 'restore administrator factors'; END IF;
 IF NOT COALESCE((SELECT bool_and(NOT u.enabled) FROM user_entity u JOIN realm master ON master.id=u.realm_id WHERE master.name='master' AND u.username='nlbootstrap'), false)
 THEN RAISE EXCEPTION 'restore bootstrap enabled'; END IF;
 IF (SELECT count(*) FROM user_entity WHERE realm_id=r AND username='nebulalog-health') <> 1 THEN RAISE EXCEPTION 'restore health'; END IF;
 SELECT id INTO h FROM user_entity WHERE realm_id=r AND username='nebulalog-health';
 IF (SELECT count(*) FROM user_attribute WHERE user_id=h AND name='nebulalog-purpose' AND value='health-probe') <> 1 THEN RAISE EXCEPTION 'restore health purpose'; END IF;
 IF (SELECT count(*) FROM client WHERE realm_id=r AND client_id IN ('nebulalog-identity-manager','nebulalog-appliance-inspector')) <> 2 THEN RAISE EXCEPTION 'restore clients'; END IF;
 SELECT id INTO m FROM client WHERE realm_id=r AND client_id='nebulalog-identity-manager';
 SELECT id INTO i FROM client WHERE realm_id=r AND client_id='nebulalog-appliance-inspector';
 IF (SELECT count(*) FROM client_attributes WHERE client_id IN (m,i) AND name='nebulalog-managed' AND value='true') <> 2 THEN RAISE EXCEPTION 'restore managed clients'; END IF;
 PERFORM 1 FROM realm_attribute WHERE realm_id=r AND name='nebulalog.installation-id' FOR UPDATE;
 PERFORM 1 FROM user_attribute WHERE user_id IN ('{administrator_id}',h) AND name='nebulalog-installation' FOR UPDATE;
 PERFORM 1 FROM client_attributes WHERE client_id IN (m,i) AND name='nebulalog-installation' FOR UPDATE;
 SELECT value INTO owner FROM realm_attribute WHERE realm_id=r AND name='nebulalog.installation-id';
 IF owner IS NULL OR owner NOT IN ('{source}','{target}')
 OR (SELECT count(*) FROM realm_attribute WHERE realm_id=r AND name='nebulalog.installation-id' AND value=owner) <> 1
 OR (SELECT count(*) FROM user_attribute WHERE user_id IN ('{administrator_id}',h) AND name='nebulalog-installation') <> 2
 OR (SELECT count(*) FROM user_attribute WHERE user_id IN ('{administrator_id}',h) AND name='nebulalog-installation' AND value=owner AND long_value IS NULL) <> 2
 OR (SELECT count(*) FROM client_attributes WHERE client_id IN (m,i) AND name='nebulalog-installation') <> 2
 OR (SELECT count(*) FROM client_attributes WHERE client_id IN (m,i) AND name='nebulalog-installation' AND value=owner) <> 2
 THEN RAISE EXCEPTION 'restore ownership'; END IF;
 UPDATE realm_attribute SET value='{target}' WHERE realm_id=r AND name='nebulalog.installation-id' AND value=owner;
 GET DIAGNOSTICS n=ROW_COUNT; IF n<>1 THEN RAISE EXCEPTION 'restore realm count'; END IF;
 UPDATE user_attribute SET value='{target}' WHERE user_id IN ('{administrator_id}',h) AND name='nebulalog-installation' AND value=owner;
 GET DIAGNOSTICS n=ROW_COUNT; IF n<>2 THEN RAISE EXCEPTION 'restore user count'; END IF;
 UPDATE client_attributes SET value='{target}' WHERE client_id IN (m,i) AND name='nebulalog-installation' AND value=owner;
 GET DIAGNOSTICS n=ROW_COUNT; IF n<>2 THEN RAISE EXCEPTION 'restore client count'; END IF;
 -- All source realm sessions are invalid on the recovered appliance. Keep
 -- single_use_object replay/revocation records; they are not session storage.
 DELETE FROM offline_client_session WHERE realm_id IN (SELECT id FROM realm);
 DELETE FROM offline_user_session WHERE realm_id IN (SELECT id FROM realm);
 DELETE FROM auth_session WHERE root_auth_session_id IN (SELECT id FROM root_auth_session WHERE realm_id IN (SELECT id FROM realm));
 DELETE FROM root_auth_session WHERE realm_id IN (SELECT id FROM realm);
 UPDATE realm SET not_before=GREATEST(COALESCE(not_before,0),{not_before});
END $restore$;
COMMIT;
SELECT 'restore-identity-rebound';
"""


class FreshRestoreRuntime:
    def __init__(self, paths=Locations(), runner=run, firstboot=None):
        self.paths = paths
        self.firstboot = firstboot or FirstBoot(paths, runner=runner)
        self.bootstrap = Bootstrap(paths, runner=runner, firstboot=self.firstboot)
        self.runner = self.bootstrap.runner
        self.configuration = paths.data / "configuration"
        self.systemd = SYSTEMD

    def guard_fresh(self, transaction=None):
        require_linux_root()
        gate = self.firstboot.gate()
        if gate.get("host_ready") is not True or gate.get("setup_complete") is not False:
            raise Refused("Fresh restore requires enrolled encrypted storage and unfinished setup")
        target = _uuid(gate.get("installation_id"))
        _encrypted_staging(self.paths.data / "tmp", self.runner)
        for path in (self.paths.etc / "configured", self.paths.data / "manager/aide",
                     self.paths.data / "manager/aide-enrollment.json", self.paths.data / "manager/os-transaction.json"):
            if os.path.lexists(path):
                raise Refused("Existing host acceptance or operation prevents fresh restore")
        if transaction and transaction.get("runtime"):
            if transaction.get("target_installation_id") != target:
                raise Refused("Restore belongs to another target installation")
            self._context(transaction)
            if transaction["runtime"].get("active_stage"):
                raise Refused("Interrupted runtime action requires inspected recovery; it is not replayed")
            return target
        for name in ("postgresql", "clickhouse", "clickhouse-logs", "keycloak", "spool", "runtime", "containers", "exports"):
            path = self.paths.data / name
            if path.is_symlink() or path.exists() and (not path.is_dir() or any(path.iterdir())):
                raise Refused("Fresh restore refuses existing runtime data")
        for relative in ("bootstrap/runtime-state.json", "bootstrap/runtime-secrets.json", "lifecycle.json", "tls", "runtime", "security-policy.json"):
            if os.path.lexists(self.configuration / relative):
                raise Refused("Fresh restore refuses existing runtime configuration")
        if os.path.lexists(self.paths.data / "manager/updates"):
            raise Refused("Fresh restore cannot replace installed update provenance")
        self._stopped(LISTENERS + ("postgresql", "clickhouse"))
        return target

    def _stopped(self, names):
        for name in names:
            observed = self.runner(["systemctl", "show", "--property=ActiveState", "--value", "nebulalog-" + name + ".service"])
            if observed != "inactive":
                raise Refused("Fresh restore requires stopped appliance services")

    def _factory_inputs(self):
        from .bootstrap import INITIAL_RELEASE
        from .update_enrollment import UpdateEnrollment
        return UpdateEnrollment(data=self.paths.data, etc=self.paths.etc,
            share=INITIAL_RELEASE.parent, runner=self.runner, firstboot=self.firstboot).verify_initialization_inputs()

    def _verify_images(self):
        from .bootstrap import INITIAL_RELEASE
        from .update_enrollment import UpdateEnrollment
        enrollment = UpdateEnrollment(data=self.paths.data, etc=self.paths.etc,
            share=INITIAL_RELEASE.parent, runner=self.runner, firstboot=self.firstboot)
        for component in ("nebulalog", "postgresql", "clickhouse", "keycloak"):
            enrollment.verify_initialization_image(self._current_factory, component)

    def inspect_recovery(self, source, manifest, tx):
        """Validate compatibility without advancing the restore or its auth cutoff.

        Only protected reads and OpenSSL verification run here. The returned
        digest binds fresh setup, random target credentials and measured factory
        code; it does not expose any credential or source configuration values.
        """
        candidate = copy.deepcopy(tx)
        b = self._load(source, manifest, candidate)
        factory = self._current_factory
        binding = {"setup_sha256": _hash(b.bootstrap / "setup.json"),
                   "secrets_sha256": _hash(b.bootstrap / "secrets.json"),
                   "images_sha256": _hash(self.paths.etc / "images.json"),
                   "initial_release_sha256": factory["descriptor_sha256"], "host": factory["host"],
                   "schema_revision": manifest["runtime"]["schema_revision"]}
        names = {b.setup["hostname"], "localhost", "keycloak", "clickhouse"}
        addresses = {"127.0.0.1", "::1"}
        for family in (4, 6):
            network = b.setup.get("network", {}).get("ipv" + str(family), {})
            if network.get("method") == "manual":
                for configured in network.get("addresses", []):
                    try:
                        address = ipaddress.ip_interface(configured).ip
                        if address.version != family or "%" in str(address):
                            raise ValueError
                    except (ValueError, TypeError):
                        raise Refused("Invalid configured static TLS address") from None
                    addresses.add(str(address))
        tls = source / "configuration/tls"
        for flag, values in (("-verify_hostname", names), ("-verify_ip", addresses)):
            for value in sorted(values):
                self.runner(["openssl", "verify", "-CAfile", str(tls / "ca.crt"), flag, value, str(tls / "server.crt")])
        for name in ("ca", "server"):
            if self.runner(["openssl", "pkey", "-in", str(tls / (name + ".key")), "-pubout"]) != self.runner(
                    ["openssl", "x509", "-in", str(tls / (name + ".crt")), "-pubkey", "-noout"]):
                raise Refused("Recovery certificate does not match its private key")
        self.runner(["openssl", "x509", "-in", str(tls / "server.crt"), "-checkend", "86400", "-noout"])
        return {"resource_revision": hashlib.sha256(json.dumps(binding, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest(),
                "schema_revision": binding["schema_revision"], "certificates_verified": True}

    def _context(self, tx):
        context = {key: tx[key] for key in ("id", "source_installation_id", "target_installation_id", "manifest_sha256", "stage")}
        for key in ("id", "source_installation_id", "target_installation_id"):
            _uuid(context[key])
        _sha(context["manifest_sha256"])
        if context["source_installation_id"] == context["target_installation_id"]:
            raise Refused("Restore cannot transplant the source physical installation identity")
        stage = Path(context["stage"])
        if stage != self.paths.data / "manager/restores" / context["id"]:
            raise Refused("Restore runtime stage is outside its owned transaction")
        _directory(stage, private=True)
        if tx.get("runtime") and tx["runtime"].get("context") != context:
            raise Refused("Restore runtime bindings changed")
        progress = tx.get("runtime")
        if progress and (not isinstance(progress.get("completed"), list)
                or any(not isinstance(name, str) or name not in RESTORE_STAGES for name in progress["completed"])
                or len(progress["completed"]) != len(set(progress["completed"]))
                or progress.get("active_stage") not in RESTORE_STAGES | {None}):
            raise Refused("Restore runtime progress has unknown or duplicate stages")
        return context

    def _load(self, source, manifest, tx):
        context = self._context(tx)
        if not source.is_relative_to(Path(context["stage"])) or source == Path(context["stage"]):
            raise Refused("Restore source must remain inside its authenticated staging directory")
        _directory(source, private=True)
        if _hash(source / "backup.json") != context["manifest_sha256"] or _json(source / "backup.json") != manifest:
            raise Refused("Authenticated restore manifest changed")
        inventory = {entry["path"]: entry for entry in manifest["files"]}
        for name in SOURCE_FILES:
            raw = _private_file(source / name, maximum=1024 * 1024)
            entry = inventory.get(name, {})
            if len(raw) != entry.get("bytes") or hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
                raise Refused("Required runtime restore input differs from its archive")
        source_setup = _json(source / "configuration/bootstrap/setup.json")
        source_state = _json(source / "configuration/bootstrap/runtime-state.json")
        source_secret = _json(source / "configuration/bootstrap/secrets.json")
        source_runtime = _json(source / "configuration/bootstrap/runtime-secrets.json")
        source_lifecycle = _json(source / "configuration/lifecycle.json")
        b = self.bootstrap
        b.setup = _json(b.bootstrap / "setup.json")
        b.secret = _json(b.bootstrap / "secrets.json")
        from .aide import RUNTIME_STAGES
        source_stages = RESTORE_STAGES if source_state.get("kind") == "configuration-restore" else RUNTIME_STAGES
        if (manifest.get("installation_id") != context["source_installation_id"]
                or source_setup.get("installation_id") != context["source_installation_id"]
                or source_state.get("installation_id") != context["source_installation_id"]
                or source_state.get("identity_initialized") is not True
                or source_state.get("active_stage") is not None
                or type(source_state.get("completed")) is not list
                or any(not isinstance(name, str) for name in source_state["completed"])
                or len(source_state["completed"]) != len(source_stages)
                or set(source_state["completed"]) != source_stages
                or b.setup.get("installation_id") != context["target_installation_id"]
                or any(source_setup.get(key) != b.setup.get(key) for key in ("hostname", "baseline"))
                or source_setup.get("administrator", {}).get("username") != b.setup.get("administrator", {}).get("username")):
            raise Refused("Restore identity, hostname, administrator or baseline selection differs")
        administrator = _uuid(source_state.get("administrator_id"))
        runtime = manifest.get("runtime", {})
        installed = image_pins(_json(self.paths.etc / "images.json"))
        factory = self._factory_inputs()
        binding = factory["binding"]
        if (image_pins(runtime.get("images")) != installed or binding["images"] != installed
                or binding["installation_id"] != context["target_installation_id"]
                or runtime.get("schema_revision") != binding["schema_revision"]
                or binding["schema_revision"] not in ("3", "4")):
            raise Refused("Fresh restore requires the same installed image digests and schema")
        self._current_factory = factory
        if source_lifecycle.get("schema_revision") != runtime["schema_revision"]:
            raise Refused("Source lifecycle schema differs from backup provenance")
        if (set(source_runtime) != {"health_password", "health_totp", "inspector_service"}
                or not isinstance(source_runtime["health_password"], str) or not 14 <= len(source_runtime["health_password"]) <= 1024
                or any(c in source_runtime["health_password"] for c in "\r\n\0")
                or not re.fullmatch(r"[A-Z2-7]{32,128}", source_runtime["health_totp"])
                or not re.fullmatch(r"[a-f0-9]{64}", source_runtime["inspector_service"])
                or not re.fullmatch(r"[a-f0-9]{64}", source_secret.get("identity_service", ""))):
            raise Refused("Restored health/service credentials are incomplete")
        probe = source_lifecycle.get("auth_probe", {})
        origin = "https://" + b.setup["hostname"]
        if (source_lifecycle.get("issuer") != origin + "/realms/nebulalog"
                or probe.get("password") != source_runtime["health_password"] or probe.get("totp_secret") != source_runtime["health_totp"]
                or probe.get("username") != "nebulalog-health" or probe.get("client_id") != "nebulalog"
                or probe.get("redirect_uri") != origin + "/health-oidc"
                or (probe.get("totp_algorithm"), probe.get("totp_digits"), probe.get("totp_period")) != ("SHA256", 6, 30)):
            raise Refused("Restored lifecycle credentials disagree with the source identity")
        expected_secrets = {"postgresql_admin", "postgresql_app", "postgresql_keycloak", "clickhouse", "keycloak_bootstrap", "identity_service"}
        if set(b.secret) != expected_secrets or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in b.secret.values()):
            raise Refused("Target database/service credential bundle is invalid")
        b.secret["identity_service"] = source_secret["identity_service"]
        b.runtime, b.pins = source_runtime, installed
        if not tx.get("runtime"):
            tx["runtime"] = {"context": context, "completed": [], "active_stage": None, "factory_binding": binding}
        progress = tx["runtime"]
        if progress.get("factory_binding") != binding:
            raise Refused("Restore authenticated factory binding changed")
        if "token_not_before" not in progress:
            if progress["completed"] or progress.get("active_stage"):
                raise Refused("Existing restore lost its authentication cutoff")
            progress["token_not_before"] = int(time.time()) + 1
        if type(progress["token_not_before"]) is not int or not 1577836800 <= progress["token_not_before"] < 2**31:
            raise Refused("Invalid restored authentication cutoff")
        if "environment" in progress["completed"]:
            expected_auth = {"schema": 1, "installation_id": context["target_installation_id"],
                             "operation": context["id"], "token_not_before": progress["token_not_before"]}
            if _json(b.bootstrap / "restore-auth.json") != expected_auth:
                raise Refused("Restore authentication cutoff no longer matches its retained transaction")
            lines = _private_file(b.configuration / "runtime/api.env", maximum=65536).decode().splitlines()
            if [line for line in lines if line.startswith("OIDC_TOKEN_NOT_BEFORE=")] != ["OIDC_TOKEN_NOT_BEFORE=" + str(progress["token_not_before"])]:
                raise Refused("Runtime API is not configured to reject source authentication tokens")
        b.state = {"schema": 1, "installation_id": context["target_installation_id"], "kind": "configuration-restore",
                   "restore": context, "completed": list(progress["completed"]), "active_stage": progress.get("active_stage"),
                   "administrator_id": administrator, "identity_initialized": "identity-rebind" in progress["completed"],
                   "factory_binding": binding}
        return b

    def _save(self, tx, checkpoint):
        atomic_json(self.bootstrap.state_path, self.bootstrap.state)
        if checkpoint:
            checkpoint()
        else:
            atomic_json(Path(tx["stage"]) / "transaction.json", tx)

    def _step(self, name, action, tx, checkpoint):
        progress = tx["runtime"]
        if progress.get("active_stage"):
            raise Refused("An interrupted runtime action cannot be replayed automatically")
        if name in progress["completed"]:
            return
        progress["active_stage"] = self.bootstrap.state["active_stage"] = name
        self._save(tx, checkpoint)
        action()
        progress["completed"].append(name)
        self.bootstrap.state["completed"] = list(progress["completed"])
        progress["active_stage"] = self.bootstrap.state["active_stage"] = None
        self._save(tx, checkpoint)

    def _fence(self, tx):
        stage = Path(tx["stage"])
        body = ("[Unit]\nConditionPathExists=" + str(stage / "listeners-ready.json") + "\n").encode()
        for name in LISTENERS:
            directory = self.systemd / ("nebulalog-" + name + ".service.d")
            _directory(directory, create=True)
            target = directory / "80-nebulalog-restore.conf"
            if os.path.lexists(target):
                if trusted_file(target).read_bytes() != body:
                    raise Refused("Restore listener fence differs from its owning transaction")
            else:
                _write_bytes(target, body, 0o644)
        self.runner(["systemctl", "daemon-reload"])

    def prepare(self, source_dir, manifest, transaction, *, checkpoint=None):
        tx = transaction
        self.guard_fresh(tx)
        b = self._load(source_dir, manifest, tx)
        self._save(tx, checkpoint)  # Authenticated factory inputs precede service/database effects.
        self._fence(tx)  # Before writing any automatically startable Quadlet.
        if os.path.lexists(Path(tx["stage"]) / "listeners-ready.json"):
            raise Refused("Restore listeners were already released; preparation cannot restart")
        self._stopped(LISTENERS)
        def certificates():
            b.tls.mkdir(mode=0o750)
            for name in TLS_FILES:
                _write_bytes(b.tls / name, _private_file(source_dir / "configuration/tls" / name, maximum=65536))
            b._certificates()  # Verifies original key pairs, chain, expiry and all target SANs.
        def environment():
            atomic_json(b.bootstrap / "secrets.json", b.secret)
            atomic_json(b.bootstrap / "runtime-secrets.json", b.runtime)
            atomic_json(b.bootstrap / "restore-auth.json", {"schema": 1, "installation_id": tx["target_installation_id"],
                "operation": tx["id"], "token_not_before": tx["runtime"]["token_not_before"]})
            b._environment()
            directory = b.configuration / "keycloak/import"
            directory.mkdir(parents=True, mode=0o750)
            os.chown(directory.parent, 0, 1000)
            os.chown(directory, 0, 1000)
            self.runner(["restorecon", "-RF", str(directory.parent)])
        for name, action in (("directories", b._directories), ("storage-maintenance", b._storage_maintenance),
                             ("certificates", certificates), ("images", b._images), ("environment", environment),
                             ("postgresql", b._postgres)):
            self._step(name, action, tx, checkpoint)
        return {"prepared": True, "listeners_released": False, "setup_complete": False}

    def _databases(self, tx):
        for name in ("nebulalog", "keycloak"):
            item = tx.get("databases", {}).get(name, {})
            if item.get("state") != "restored":
                raise Refused("Both database restores must have durable successful receipts")
            _sha(item.get("archive_sha256"))
        self._catalog_proof(tx)
        if tx.get("operational_normalized") is not True:
            raise Refused("Source operational jobs must be quarantined before listeners start")
        if _hash(Path(tx["stage"]) / "normalization.json") != _sha(tx.get("normalization_sha256")):
            raise Refused("Restore normalization receipt changed")
        if _json(Path(tx["stage"]) / "normalization.json") != {"schema": 1, "operation": tx["id"],
                "source_installation_id": tx["source_installation_id"], "target_installation_id": tx["target_installation_id"], "observed": True}:
            raise Refused("Restore normalization receipt belongs to another operation")

    def _retained_owner(self, tx, *, held):
        """Validate this coordinator's actual journal and persistent listeners."""
        stage = Path(tx["stage"])
        if (type(tx.get("schema")) is not int or tx["schema"] != 1 or tx.get("kind") != "configuration-restore"
                or _json(self.paths.data / "manager/restore.json") != {"schema": 2, "id": tx["id"], "stage": str(stage)}
                or _json(stage / "transaction.json") != tx
                or not PREPARED_STAGES <= set(tx["runtime"]["completed"])):
            raise Refused("Restored catalog needs its retained coordinator and prepared runtime")
        body = ("[Unit]\nConditionPathExists=" + str(stage / "listeners-ready.json") + "\n").encode()
        for name in LISTENERS:
            path = self.systemd / ("nebulalog-" + name + ".service.d/80-nebulalog-restore.conf")
            if trusted_file(path).read_bytes() != body:
                raise Refused("Restored catalog lost its owned listener fence")
        if held:
            if os.path.lexists(stage / "listeners-ready.json"):
                raise Refused("Restored schema cannot change after listeners are released")
            self._stopped(LISTENERS)

    def _observe_pg_catalog(self, revision, tx):
        from nebulalog_adapters.lifecycle import _observe_fixed_pg_catalog
        return _observe_fixed_pg_catalog(self.runner, revision, hashlib.sha256(tx["stage"].encode()).hexdigest())

    def verify_restored_catalog(self, source_dir, manifest, transaction, *, checkpoint=None):
        """Observe exact restored structure before normalization; never run DDL."""
        tx = transaction
        self.guard_fresh(tx)
        self._load(source_dir, manifest, tx)
        self._retained_owner(tx, held=tx.get("operational_normalized") is not True)
        for name in ("nebulalog", "keycloak"):
            entry = tx.get("databases", {}).get(name, {})
            if entry.get("state") != "restored":
                raise Refused("Catalog observation requires both successful database restores")
            _sha(entry.get("archive_sha256"))
        revision = manifest["runtime"]["schema_revision"]
        if revision not in ("3", "4"):
            raise Refused("Connected restore requires the same supported schema 3 or 4 profile")
        self._verify_images()
        observed = self._observe_pg_catalog(revision, tx)
        previous = tx["runtime"].get("restored_catalog")
        if previous is not None and observed != previous:
            raise Refused("Restored database identity or structural catalog changed")
        if previous is None:
            if tx.get("operational_normalized") is True:
                raise Refused("Restore lacks its pre-normalization structural catalog proof")
            tx["runtime"]["restored_catalog"] = observed
            self._log_checkpoint(tx, checkpoint)
        return observed

    @staticmethod
    def _catalog_proof(tx):
        from .image_bundle import ApplicationSchema
        progress = tx["runtime"]
        binding = progress["factory_binding"]
        proof = progress.get("restored_catalog")
        if (not isinstance(proof, dict) or proof.get("schema_revision") != binding["schema_revision"]
                or proof.get("schema_revision") not in ("3", "4")
                or proof.get("schema_sha256") != ApplicationSchema.schema_digest(binding["schema_revision"])
                or not isinstance(proof.get("database"), dict)):
            raise Refused("Restore lacks its exact pre-normalization structural catalog")
        _sha(proof.get("catalog_sha256"))
        return proof

    def _log_checkpoint(self, tx, checkpoint):
        # The coordinator's transaction is the only authoritative progress log.
        if checkpoint:
            checkpoint()
        else:
            atomic_json(Path(tx["stage"]) / "transaction.json", tx)
        if _json(Path(tx["stage"]) / "transaction.json") != tx:
            raise Refused("Log restore progress was not durably retained")

    def _log_pg(self, query):
        return self.runner(_pg(["psql", "-X", "--no-password", "--host=/var/run/postgresql", "--username=nebulalog",
            "--dbname=nebulalog", "--tuples-only", "--no-align", "--quiet", "--set=ON_ERROR_STOP=1"], interactive=True),
            input=query.encode(), timeout=90)

    def _log_ch(self, query, params=()):
        return self.runner(["podman", "exec", "--user", "101:101", "nebulalog-clickhouse", "clickhouse-client",
            "--config-file=/etc/nebulalog/clickhouse-client.xml", "--max_execution_time=60", "--multiquery", "--query", query, *params], timeout=90)

    def log_restore_context(self, source, manifest, tx, *, held=True):
        """No caller assertion can substitute for the coordinator and boot fence."""
        from .log_recovery_set import validate_metadata
        self.guard_fresh(tx)
        b = self._load(source, manifest, tx)
        self._databases(tx)
        stage = Path(tx["stage"])
        if (type(tx.get("schema")) is not int or tx["schema"] != 1 or tx.get("kind") != "configuration-restore"
                or _json(self.paths.data / "manager/restore.json") != {"schema": 2, "id": tx["id"], "stage": str(stage)}
                or _json(stage / "transaction.json") != tx):
            raise Refused("Native restore is not the retained configuration transaction")
        if not {"directories", "storage-maintenance", "certificates", "images", "environment", "postgresql"} <= set(tx["runtime"]["completed"]):
            raise Refused("Native restore requires prepared databases and persistent fences")
        logs = tx.get("logs")
        if (not isinstance(logs, dict) or set(logs) - {"schema", "state", "archive", "metadata", "native", "restore_proof", "plan"}
                or type(logs.get("schema")) is not int or logs["schema"] != 1 or not isinstance(logs.get("native"), dict)):
            raise Refused("Missing authenticated log recovery transaction")
        validate_metadata(logs["metadata"])
        metadata, archive = logs["metadata"], logs["archive"]
        if (not isinstance(archive, dict) or set(archive) != {"path", "bytes", "sha256"}
                or archive["path"] != str(stage / "logs/events.tar")
                or any(archive[k] != metadata["archive"][k] for k in ("bytes", "sha256"))
                or metadata["link"] != {"source_installation_id": tx["source_installation_id"],
                    "configuration_backup": {"sha256": _sha(tx.get("archive_sha256")), "bytes": trusted_file(stage / "backup.cms").stat().st_size},
                    "runtime": manifest.get("runtime")}
                or manifest.get("runtime", {}).get("schema_revision") not in ("3", "4")):
            raise Refused("Log recovery set differs from this configuration, source or runtime")
        from .log_backup import VERSION
        if metadata["native"]["server_version"] != VERSION:
            raise Refused("Native recovery version differs from the pinned target")
        if os.path.lexists(stage / "listeners-ready.json"):
            raise Refused("Native restore cannot run after listeners are released")
        body = ("[Unit]\nConditionPathExists=" + str(stage / "listeners-ready.json") + "\n").encode()
        for name in LISTENERS:
            path = self.systemd / ("nebulalog-" + name + ".service.d/80-nebulalog-restore.conf")
            if trusted_file(path).read_bytes() != body:
                raise Refused("Native restore lost its persistent listener fence")
        self._stopped(LISTENERS)
        if "instance" in logs["native"]:
            from .log_backup import LogBackupAdapter
            if LogBackupAdapter.for_restore(self)._instance(b.pins["CLICKHOUSE_IMAGE"]) != logs["native"]["instance"]:
                raise Refused("Fresh native recovery server changed before activation")
        if held:
            self.log_restore_hold(tx)
        return b

    @staticmethod
    def _log_gate(tx, held=True):
        return {"schema": 1, "held": held, "delivery_held": held,
                "operation": hashlib.sha256(tx["stage"].encode()).hexdigest() if held else None}

    def _log_pg_state(self):
        raw = self._log_pg("""SELECT json_build_object(
 'gate',(SELECT value FROM public.settings WHERE key='storage_emergency_maintenance'),
 'engine',(SELECT value FROM public.settings WHERE key='retention_engine'),
 'policy',(SELECT value FROM public.settings WHERE key='retention'),
 'pending',(SELECT count(*) FROM public.storage_emergency_actions WHERE completed_at IS NULL)
   +(SELECT count(*) FROM public.retention_actions WHERE completed_at IS NULL)
   +(SELECT count(*) FROM public.storage_emergency_inserts));""")
        value = strict_json(raw.encode())
        if not isinstance(value, dict) or set(value) != {"gate", "engine", "policy", "pending"} or type(value["pending"]) is not int or value["pending"] != 0:
            raise Refused("Native restore has unresolved source storage operations")
        return value

    def log_restore_hold(self, tx):
        native = tx["logs"]["native"]
        expected = self._log_gate(tx)
        gate = self.paths.data / "manager/storage-maintenance/gate.json"
        row = self._log_pg_state()
        policy = row["policy"]
        revision = policy.get("revision", 1) if isinstance(policy, dict) else None
        if (type(revision) is not int or revision != tx["logs"]["metadata"]["native"]["retention_policy_revision"]
                or _json(gate) != expected or row["gate"] != expected
                or row["engine"] != native.get("engine", {"schema": 1, "mode": "uninitialized"})
                or _json(gate) != expected):
            raise Refused("Native restore lost its owned full storage hold or policy")
        if "policy" in native and policy != native["policy"]:
            raise Refused("Restored retention policy changed during native recovery")
        return row

    def _log_sql_transition(self, tx, *, old_gate, new_gate, old_engine, new_engine, policy=None):
        # Only validated fixed JSON values enter SQL; no names or expressions
        # come from an archive. The shared storage lock also fences insertions.
        def literal(value):
            return "'" + json.dumps(value, sort_keys=True, separators=(",", ":")).replace("'", "''") + "'::jsonb"
        policy = literal(tx["logs"]["native"]["policy"] if policy is None else policy)
        return f"""BEGIN; SET LOCAL lock_timeout='15s'; SET LOCAL statement_timeout='60s';
DO $restorelogs$ BEGIN
 PERFORM pg_advisory_xact_lock(4850182995969828167);
 IF (SELECT value FROM public.settings WHERE key='storage_emergency_maintenance' FOR UPDATE) IS DISTINCT FROM {literal(old_gate)}
 OR (SELECT value FROM public.settings WHERE key='retention_engine' FOR UPDATE) IS DISTINCT FROM {literal(old_engine)}
 OR (SELECT value FROM public.settings WHERE key='retention' FOR UPDATE) IS DISTINCT FROM {policy}
 OR EXISTS(SELECT 1 FROM public.storage_emergency_actions WHERE completed_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.retention_actions WHERE completed_at IS NULL)
 OR EXISTS(SELECT 1 FROM public.storage_emergency_inserts)
 THEN RAISE EXCEPTION 'Native restore storage preconditions changed'; END IF;
 UPDATE public.settings SET value={literal(new_gate)} WHERE key='storage_emergency_maintenance';
 UPDATE public.settings SET value={literal(new_engine)} WHERE key='retention_engine';
END $restorelogs$; COMMIT; SELECT 'native-restore-storage-settled';"""

    def prepare_log_restore(self, source_dir, manifest, transaction, *, checkpoint=None):
        """Create the exact empty schema before native data and UUID binding."""
        from .log_backup import SCHEMA3_SQL, VERSION, LogBackupAdapter
        from .image_bundle import ApplicationSchema
        tx = transaction
        b = self.log_restore_context(source_dir, manifest, tx, held=False)
        native = tx["logs"]["native"]
        if native:
            if native.get("state") not in {"table_ready", "planned", "dispatching", "running", "restored", "bound", "recovery_required"}:
                raise Refused("An interrupted fresh table/hold effect cannot be replayed")
            if native.get("state") == "recovery_required" and "dispatched_at" not in native:
                raise Refused("Interrupted native staging cannot be replayed")
            self.log_restore_hold(tx)
            return {"prepared": True, "listeners_released": False}
        if hashlib.sha256(SCHEMA3_SQL.encode()).hexdigest() != ApplicationSchema.SCHEMAS[manifest["runtime"]["schema_revision"]]["migrations/clickhouse.sql"]:
            raise Refused("Fresh native table DDL differs from its schema contract")
        row = self._log_pg_state()
        initial = {"schema": 1, "mode": "uninitialized"}
        gate_path = self.paths.data / "manager/storage-maintenance/gate.json"
        if row["engine"] != initial or row["gate"] != self._log_gate(tx, False) or _json(gate_path) != self._log_gate(tx, False):
            raise Refused("Fresh native recovery requires normalized, uninitialized storage")
        policy = row["policy"]
        if not isinstance(policy, dict) or type(policy.get("revision", 1)) is not int or policy.get("revision", 1) != tx["logs"]["metadata"]["native"]["retention_policy_revision"]:
            raise Refused("Restored configuration retention policy differs from the log snapshot")
        adapter = LogBackupAdapter.for_restore(self)
        instance = adapter._instance(b.pins["CLICKHOUSE_IMAGE"])
        native.update(state="preparing", policy=policy, engine=initial, instance=instance)
        self._log_checkpoint(tx, checkpoint)  # Before either hold or DDL.
        atomic_json(gate_path, self._log_gate(tx))
        if self._log_pg(self._log_sql_transition(tx, old_gate=self._log_gate(tx, False), new_gate=self._log_gate(tx), old_engine=initial, new_engine=initial)) != "native-restore-storage-settled":
            raise Refused("Fresh native storage hold did not settle")
        self.log_restore_hold(tx)
        if self._log_ch("SELECT count() FROM system.tables WHERE database='nebulalog' AND name='events'") != "0":
            raise Refused("Fresh native restore refuses any preexisting events table")
        self._log_ch(SCHEMA3_SQL)
        table = strict_json(self._log_ch("SELECT toString(uuid) AS uuid,version() AS version,create_table_query FROM system.tables "
            "WHERE database='nebulalog' AND name='events' FORMAT JSONEachRow").encode())
        if not isinstance(table, dict) or set(table) != {"uuid", "version", "create_table_query"} or table["version"] != VERSION:
            raise Refused("Fresh native table readback is incomplete")
        _uuid(table["uuid"])
        if self._log_ch("SELECT count() FROM system.parts WHERE database='nebulalog' AND table='events'") != "0":
            raise Refused("Fresh native events table is not empty")
        if adapter._instance(b.pins["CLICKHOUSE_IMAGE"]) != instance:
            raise Refused("Fresh native server changed during table preparation")
        native.update(state="table_ready", table={"table_uuid": table["uuid"], "server_version": table["version"],
            "table_definition_sha256": hashlib.sha256(table["create_table_query"].encode()).hexdigest()})
        self.log_restore_hold(tx)
        self._log_checkpoint(tx, checkpoint)
        return {"prepared": True, "listeners_released": False}

    def complete_log_restore(self, source_dir, manifest, transaction, *, checkpoint=None):
        tx = transaction
        self.log_restore_context(source_dir, manifest, tx)
        native = tx["logs"]["native"]
        if native.get("state") == "bound":
            return tx["logs"]["restore_proof"]
        result = native.get("result", {})
        if (native.get("state") != "restored" or result.get("state") != "restored"
                or result.get("table_uuid") != native["table"]["table_uuid"]
                or result.get("archive_sha256") != tx["logs"]["archive"]["sha256"]
                or result.get("rows") != native["inventory"]["rows"]
                or result.get("integrity_checked") is not True):
            raise Refused("Native restored data has no exact terminal integrity proof")
        observed = strict_json(self._log_ch("SELECT toString(uuid) AS uuid,(SELECT count() FROM nebulalog.events) AS rows FROM system.tables "
            "WHERE database='nebulalog' AND name='events' SETTINGS output_format_json_quote_64bit_integers=0 FORMAT JSONEachRow").encode())
        if observed != {"uuid": result["table_uuid"], "rows": result["rows"]} or type(observed.get("rows")) is not int:
            raise Refused("Restored target data changed before retention binding")
        old = native["engine"]
        engine = {"schema": 1, "mode": "partition", "table_uuid": _uuid(result["table_uuid"]),
                  "message": "Native log recovery verified before retention activation"}
        native["state"] = "binding"
        self._log_checkpoint(tx, checkpoint)
        if self._log_pg(self._log_sql_transition(tx, old_gate=self._log_gate(tx), new_gate=self._log_gate(tx), old_engine=old, new_engine=engine)) != "native-restore-storage-settled":
            raise Refused("Restored target retention binding did not settle")
        native.update(state="bound", engine=engine)
        self.log_restore_hold(tx)
        proof = {"schema": 1, "operation": tx["id"], "target_installation_id": tx["target_installation_id"],
            "table_uuid": engine["table_uuid"], "archive_sha256": tx["logs"]["archive"]["sha256"],
            "native_result_sha256": hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        tx["logs"]["restore_proof"] = proof
        tx["logs"]["state"] = "restored"
        self._log_checkpoint(tx, checkpoint)
        return proof

    def _release_log_restore(self, source, manifest, tx, checkpoint):
        native = tx["logs"]["native"]
        if native.get("state") == "released":
            return
        self.log_restore_context(source, manifest, tx)
        if native.get("state") != "bound" or not {"schema", "lifecycle", "identity-rebind"} <= set(tx["runtime"]["completed"]):
            raise Refused("Restored logs cannot release before schema and identity activation")
        native["state"] = "releasing"
        self._log_checkpoint(tx, checkpoint)
        if self._log_pg(self._log_sql_transition(tx, old_gate=self._log_gate(tx), new_gate=self._log_gate(tx, False), old_engine=native["engine"], new_engine=native["engine"])) != "native-restore-storage-settled":
            raise Refused("Restored storage hold release did not settle")
        atomic_json(self.paths.data / "manager/storage-maintenance/gate.json", self._log_gate(tx, False))
        row = self._log_pg_state()
        if row["gate"] != self._log_gate(tx, False) or row["engine"] != native["engine"]:
            raise Refused("Restored storage release failed readback")
        native["state"] = "released"
        self._log_checkpoint(tx, checkpoint)

    def _config_storage_hold(self, tx):
        storage = tx["runtime"]["storage"]
        row = self._log_pg_state()
        if (_json(self.paths.data / "manager/storage-maintenance/gate.json") != self._log_gate(tx)
                or row["gate"] != self._log_gate(tx) or row["engine"] != storage["engine"]
                or row["policy"] != storage["policy"]):
            raise Refused("Configuration restore lost its owned storage hold or original policy")
        return row

    def _initialize_config_storage(self, tx, checkpoint):
        """CH-only initialization of an absent table; restored PG is never migrated."""
        from .image_bundle import ApplicationSchema
        from .log_backup import LogBackupAdapter
        if "logs" in tx:
            raise Refused("Populated native recovery cannot initialize log storage")
        self._retained_owner(tx, held=True)
        b, progress = self.bootstrap, tx["runtime"]
        adapter = LogBackupAdapter.for_restore(self)
        instance = adapter._instance(b.pins["CLICKHOUSE_IMAGE"])
        sql_sha = ApplicationSchema.SCHEMAS[progress["factory_binding"]["schema_revision"]]["migrations/clickhouse.sql"]
        operation = self._log_gate(tx)["operation"]
        storage = progress.get("storage")
        if storage is not None:
            # No lost DDL acknowledgement is silently converted into success.
            if storage.get("state") != "initialized" or storage.get("instance") != instance:
                raise Refused("Interrupted or changed configuration storage initialization requires recovery")
            self._config_storage_hold(tx)
            return
        row = self._log_pg_state()
        initial = {"schema": 1, "mode": "uninitialized"}
        gate_path = self.paths.data / "manager/storage-maintenance/gate.json"
        if (row["engine"] != initial or row["gate"] != self._log_gate(tx, False)
                or _json(gate_path) != self._log_gate(tx, False) or not isinstance(row["policy"], dict)):
            raise Refused("Configuration restore requires normalized uninitialized storage")
        if self._log_ch("SELECT count() FROM system.tables WHERE database='nebulalog' AND name='events'") != "0":
            raise Refused("Configuration restore refuses an existing events table")
        policy_raw = self._log_pg("SELECT value::text FROM public.settings WHERE key='retention';")
        if strict_json(policy_raw.encode()) != row["policy"]:
            raise Refused("Restored policy changed during storage admission")
        storage = {"state": "holding", "operation": operation, "table_uuid": str(uuid.uuid4()),
            "instance": instance, "factory_binding_sha256": _digest(progress["factory_binding"]),
            "schema_sql_sha256": sql_sha, "absent_observed": True, "policy": row["policy"],
            "policy_sha256": hashlib.sha256(policy_raw.encode()).hexdigest(), "engine": initial,
            "database_query_id": _storage_query_id(operation, "database"),
            "table_query_id": _storage_query_id(operation, "table")}
        progress["storage"] = storage
        self._log_checkpoint(tx, checkpoint)  # Before host/DB holds or native DDL.
        atomic_json(gate_path, self._log_gate(tx))
        if self._log_pg(self._log_sql_transition(tx, old_gate=self._log_gate(tx, False), new_gate=self._log_gate(tx),
                old_engine=initial, new_engine=initial, policy=storage["policy"])) != "native-restore-storage-settled":
            raise Refused("Configuration storage hold did not settle")
        self._config_storage_hold(tx)
        if adapter._instance(b.pins["CLICKHOUSE_IMAGE"]) != instance:
            raise Refused("Configuration storage server changed before dispatch")
        storage["state"] = "dispatching"
        self._log_checkpoint(tx, checkpoint)
        command = ["podman", "run", "--rm", "--name", "nebulalog-restore-storage", "--network", "nebulalog", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--volume",
            str(b.tls / "trust-bundle.pem") + ":/etc/nebulalog/tls/trust-bundle.pem:ro,z", "--volume",
            str(gate_path.parent) + ":/run/nebulalog-storage-maintenance:ro,z", "--env-file", str(b.configuration / "runtime/api.env")]
        for key, value in {"STORAGE_INITIALIZATION_OPERATION": operation, "STORAGE_INITIALIZATION_TABLE_UUID": storage["table_uuid"],
                "STORAGE_INITIALIZATION_SCHEMA_SHA256": sql_sha, "STORAGE_MAINTENANCE_PATH": "/run/nebulalog-storage-maintenance/gate.json"}.items():
            command += ["--env", key + "=" + value]
        result = strict_json(self.runner([*command, b.pins["NEBULALOG_IMAGE"], "initialize-storage"], timeout=120).encode())
        fields = {"schema", "state", "operation", "table_uuid", "schema_sql_sha256", "ddl_sha256", "retention_policy_sha256", "database_query_id", "table_query_id"}
        if (not isinstance(result, dict) or set(result) != fields or type(result.get("schema")) is not int
                or result["schema"] != 1 or result["state"] != "initialized"
                or any(result[key] != storage[key] for key in ("operation", "table_uuid", "schema_sql_sha256", "database_query_id", "table_query_id"))
                or result["retention_policy_sha256"] != storage["policy_sha256"]):
            raise Refused("Configuration storage did not return its exact completion proof")
        _sha(result["ddl_sha256"])
        current = self._log_pg_state()
        engine = current["engine"]
        if (not isinstance(engine, dict) or engine.get("mode") != "partition" or engine.get("schema") != 1
                or engine.get("table_uuid") != storage["table_uuid"] or engine.get("operation") != operation
                or current["policy"] != storage["policy"] or adapter._instance(b.pins["CLICKHOUSE_IMAGE"]) != instance):
            raise Refused("Initialized configuration storage lost its policy or server identity")
        storage.update(engine=engine, result=result, state="initialized")
        self._config_storage_hold(tx)
        self._log_checkpoint(tx, checkpoint)

    def _observe_ready_catalog(self, tx):
        from nebulalog_adapters.lifecycle import _observe_ready_application_catalog
        return _observe_ready_application_catalog(self.runner, tx["runtime"]["factory_binding"]["schema_revision"],
            self._log_gate(tx)["operation"], data=self.paths.data, configuration=self.configuration)

    def _restore_schema(self, tx, checkpoint):
        self._retained_owner(tx, held=True)
        self._verify_images()
        before = self._catalog_proof(tx)
        if "logs" in tx:
            self.log_restore_hold(tx)  # Native restore already populated and bound this table.
            table = tx["logs"]["native"]["table"]
            expected_uuid, expected_ddl = table["table_uuid"], table["table_definition_sha256"]
        else:
            # Configuration recovery has only started PostgreSQL so far. Bring
            # up the verified ClickHouse dependency while listener fences hold.
            self.bootstrap._clickhouse()
            self._initialize_config_storage(tx, checkpoint)
            storage = tx["runtime"]["storage"]
            expected_uuid, expected_ddl = storage["table_uuid"], storage["result"]["ddl_sha256"]
        observed = self._observe_ready_catalog(tx)
        if (any(observed.get(key) != value for key, value in before.items())
                or observed.get("retention", {}).get("table_uuid") != expected_uuid
                or observed["retention"].get("ddl_sha256") != expected_ddl):
            raise Refused("Restored schema or physical log storage differs from its retained proof")
        tx["runtime"]["schema_proof"] = observed
        self._log_checkpoint(tx, checkpoint)

    def _release_config_storage(self, tx, checkpoint):
        storage = tx["runtime"]["storage"]
        if storage.get("state") == "released":
            return
        if (storage.get("state") != "initialized"
                or not {"schema", "identity-rebind", "lifecycle"} <= set(tx["runtime"]["completed"])):
            raise Refused("Configuration storage cannot release before verified activation")
        self._config_storage_hold(tx)
        storage["state"] = "releasing"
        self._log_checkpoint(tx, checkpoint)
        if self._log_pg(self._log_sql_transition(tx, old_gate=self._log_gate(tx), new_gate=self._log_gate(tx, False),
                old_engine=storage["engine"], new_engine=storage["engine"], policy=storage["policy"])) != "native-restore-storage-settled":
            raise Refused("Configuration storage hold release did not settle")
        atomic_json(self.paths.data / "manager/storage-maintenance/gate.json", self._log_gate(tx, False))
        row = self._log_pg_state()
        if row["gate"] != self._log_gate(tx, False) or row["engine"] != storage["engine"] or row["policy"] != storage["policy"]:
            raise Refused("Configuration storage release failed readback")
        storage["state"] = "released"
        self._log_checkpoint(tx, checkpoint)

    def _verify_released_catalog(self, tx):
        """Final readback without reacquiring a hold or rewriting recovered data."""
        self._verify_images()
        before = self._catalog_proof(tx)
        if self._observe_pg_catalog(before["schema_revision"], tx) != before:
            raise Refused("Activated restore database identity or structure changed")
        ready = tx["runtime"]["schema_proof"]["retention"]
        gate_path = self.paths.data / "manager/storage-maintenance/gate.json"
        expected_engine = tx["logs"]["native"]["engine"] if "logs" in tx else tx["runtime"]["storage"]["engine"]
        query = "SELECT value::text FROM public.settings WHERE key='retention_engine';"
        engine = strict_json(self._log_pg(query).encode())
        if engine != expected_engine or _json(gate_path) != self._log_gate(tx, False):
            raise Refused("Activated restore lost its retention binding or idle host gate")
        raw = self._log_ch("SELECT toString(uuid) AS uuid,engine,partition_key,create_table_query FROM system.tables "
            "WHERE database='nebulalog' AND name='events' "
            "SETTINGS show_table_uuid_in_table_create_query_if_not_nil=0 FORMAT JSONEachRow")
        if len(raw.encode()) > 65536:
            raise Refused("Oversized restored table readback")
        row = strict_json(raw.encode())
        if (not isinstance(row, dict) or set(row) != {"uuid", "engine", "partition_key", "create_table_query"}
                or row["uuid"] != ready["table_uuid"] or row["engine"] != "MergeTree"
                or row["partition_key"] != "(log_type, toDate(ingested_at))"
                or not isinstance(row["create_table_query"], str)
                or hashlib.sha256(row["create_table_query"].encode()).hexdigest() != ready["ddl_sha256"]
                or re.search(r"\bTTL\b", row["create_table_query"], flags=re.IGNORECASE)
                or strict_json(self._log_pg(query).encode()) != engine
                or _json(gate_path) != self._log_gate(tx, False)):
            raise Refused("Activated restore physical log table changed")

    def activate(self, source_dir, manifest, transaction, *, checkpoint=None):
        tx = transaction
        self.guard_fresh(tx)
        hold_path = Path(tx["stage"]) / "failure-fence.json"
        if os.path.lexists(hold_path):
            hold = _json(hold_path)
            if hold.get("context") != tx["runtime"]["context"] or hold.get("state") != "held":
                raise Refused("Listener isolation is incomplete; finish the retained hold before activation")
            # A crash after verified stops but before the coordinator's journal
            # checkpoint cannot cause a skipped restart of the stopped edge.
            if not os.path.lexists(Path(tx["stage"]) / "listeners-ready.json") and "edge" in tx["runtime"]["completed"]:
                self._stopped(LISTENERS)
                tx["runtime"]["completed"].remove("edge")
                if checkpoint:
                    checkpoint()
                else:
                    atomic_json(Path(tx["stage"]) / "transaction.json", tx)
        b = self._load(source_dir, manifest, tx)
        self._databases(tx)
        if not {"directories", "storage-maintenance", "certificates", "images", "environment", "postgresql"} <= set(tx["runtime"]["completed"]):
            raise Refused("Restore runtime preparation is incomplete")
        self._fence(tx)
        def rebind():
            self._stopped(LISTENERS)
            sql = identity_rebind_sql(tx["source_installation_id"], tx["target_installation_id"], b.state["administrator_id"],
                                     not_before=tx["runtime"]["token_not_before"])
            result = self.runner(_pg(["psql", "-X", "--no-password", "--host=/var/run/postgresql", "--username=keycloak",
                "--dbname=keycloak", "--tuples-only", "--no-align", "--quiet", "--set=ON_ERROR_STOP=1"], interactive=True), input=sql.encode(), timeout=90)
            if result != "restore-identity-rebound":
                raise Refused("Restored identity rebind did not return its completion marker")
            b.state["identity_initialized"] = True
        if "logs" in tx and tx["logs"].get("native", {}).get("state") not in {"bound", "released"}:
            raise Refused("Requested native logs must be restored and bound before activation")
        self._step("restored-databases", lambda: self._databases(tx), tx, checkpoint)
        self._step("identity-rebind", rebind, tx, checkpoint)
        self._step("schema", lambda: self._restore_schema(tx, checkpoint), tx, checkpoint)
        self._step("lifecycle", b._lifecycle, tx, checkpoint)
        if int(time.time()) < tx["runtime"]["token_not_before"]:
            raise Refused("Restore authentication cutoff is still in the future; resume after clock synchronization")
        if "logs" in tx:
            self._release_log_restore(source_dir, manifest, tx, checkpoint)
        else:
            self._release_config_storage(tx, checkpoint)
        self._verify_released_catalog(tx)
        proof = {**self._proof(tx), "state": "databases-ready"}
        # All database/identity effects are settled before the boot-persistent
        # fence is released. A crash after this point cannot seed an empty realm.
        atomic_json(Path(tx["stage"]) / "listeners-ready.json", proof)
        def edge():
            self.runner(["systemctl", "start", "nebulalog-keycloak.service"], timeout=900)
            b._wait(b._token, timeout=300)
            b._edge()
        self._step("edge", edge, tx, checkpoint)
        return {"activated": True, "enrollment_pending": True, "setup_complete": False}

    @staticmethod
    def _proof(tx):
        before = FreshRestoreRuntime._catalog_proof(tx)
        progress = tx["runtime"]
        ready = progress.get("schema_proof")
        if (not isinstance(ready, dict) or any(ready.get(key) != value for key, value in before.items())
                or ready.get("markers") != [] or ready.get("retention", {}).get("ttl") is not False
                or ready["retention"].get("mode") != "partition"):
            raise Refused("Activation lacks settled schema and physical log storage evidence")
        proof = {"schema": 1, **{key: tx[key] for key in ("id", "source_installation_id", "target_installation_id", "manifest_sha256")},
            "state": "runtime-ready", "factory_binding_sha256": _digest(progress["factory_binding"]), "schema_proof_sha256": _digest(ready)}
        if "logs" not in tx:
            storage = progress.get("storage", {})
            if (storage.get("state") != "released" or storage.get("table_uuid") != ready["retention"].get("table_uuid")
                    or storage.get("result", {}).get("ddl_sha256") != ready["retention"].get("ddl_sha256")):
                raise Refused("Activation lacks released configuration-only storage proof")
            proof["storage_initialization_sha256"] = _digest(storage)
        if "logs" in tx:
            logs = tx["logs"]
            native = logs.get("native", {})
            result = native.get("result", {})
            expected = {"schema": 1, "operation": tx["id"], "target_installation_id": tx["target_installation_id"],
                "table_uuid": native.get("table", {}).get("table_uuid"), "archive_sha256": logs["archive"]["sha256"],
                "native_result_sha256": hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
            if (logs.get("state") != "restored" or native.get("state") != "released" or logs.get("restore_proof") != expected
                    or result.get("state") != "restored" or result.get("integrity_checked") is not True
                    or result.get("rows") != native.get("inventory", {}).get("rows")):
                raise Refused("Activation lacks completed native log recovery evidence")
            proof["log_restore_sha256"] = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return proof

    def finish_enrollment(self, source_dir, manifest, transaction, *, checkpoint=None):
        """Call outside the four coordination locks; retain the restore owner lock."""
        tx = transaction
        self.guard_fresh(tx)
        b = self._load(source_dir, manifest, tx)
        self._databases(tx)
        if "edge" not in tx["runtime"]["completed"] or _json(Path(tx["stage"]) / "listeners-ready.json") != {**self._proof(tx), "state": "databases-ready"}:
            raise Refused("Restored services are not ready for measured installation enrollment")
        self._step("installed-release", b._installed_release, tx, checkpoint)
        return {"enrolled": True, "setup_complete": False, "verification_pending": True}

    def fence_failure(self, transaction):
        """Hold only this restore's released listeners; retain all data/evidence.

        The coordinator reacquires its four locks before calling this method.
        An uncertain active stage remains uncertain. A failed health observation
        after settled activation may retry the edge start under the same fence.
        """
        tx = transaction
        self._context(tx)
        stage = Path(tx["stage"])
        token = stage / "listeners-ready.json"
        hold_path = stage / "failure-fence.json"
        held = _json(hold_path) if os.path.lexists(hold_path) else None
        if not os.path.lexists(token) and held is None:
            self._stopped(LISTENERS)
            return {"held": True, "services_touched": False, "release_token_present": False, "inactive_verified": True}
        expected = {**self._proof(tx), "state": "databases-ready"}
        if os.path.lexists(token) and _json(token) != expected:
            raise Refused("Cannot hold an unowned listener release token")
        body = ("[Unit]\nConditionPathExists=" + str(token) + "\n").encode()
        for name in LISTENERS:
            path = self.systemd / ("nebulalog-" + name + ".service.d/80-nebulalog-restore.conf")
            _directory(path.parent)
            if trusted_file(path).read_bytes() != body:
                raise Refused("Cannot hold listeners without the exact persistent fence")
        state = _json(self.bootstrap.state_path)
        observed = state.get("completed")
        expected_completed = tx["runtime"]["completed"]
        consistent = observed == expected_completed
        if held is not None and isinstance(observed, list):
            consistent = consistent or [name for name in observed if name != "edge"] == [name for name in expected_completed if name != "edge"]
        if state.get("restore") != tx["runtime"]["context"] or not consistent:
            raise Refused("Restore runtime changed before listener isolation")
        if held is not None:
            if (set(held) != {"schema", "context", "suffix", "state"} or held["schema"] != 1
                    or held["context"] != tx["runtime"]["context"]
                    or not isinstance(held["suffix"], str) or not re.fullmatch(r"[0-9a-f]{32}", held["suffix"])
                    or held["state"] not in ("holding", "held")):
                raise Refused("Listener hold evidence belongs to another operation")
            if held["state"] == "held" and os.path.lexists(token):
                # A later failed health retry gets its own retained hold record.
                os.link(hold_path, stage / ("held-" + held["suffix"] + "-failure-fence.json"), follow_symlinks=False)
                held = None
        if held is None:
            held = {"schema": 1, "context": tx["runtime"]["context"], "suffix": uuid.uuid4().hex, "state": "holding"}
            atomic_json(hold_path, held)
        suffix = held["suffix"]
        for path in (token, stage / "runtime-activation.json"):
            if os.path.lexists(path):
                trusted_file(path)
                saved = stage / ("held-" + suffix + "-" + path.name)
                if os.path.lexists(saved):
                    if trusted_file(saved).read_bytes() != path.read_bytes():
                        raise Refused("Prior listener evidence changed")
                else:
                    os.link(path, saved, follow_symlinks=False)
                path.unlink()
        fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        for name in ("edge", "api", "ingest", "keycloak"):
            self.runner(["systemctl", "stop", "nebulalog-" + name + ".service"], timeout=180)
        self._stopped(LISTENERS)
        atomic_json(hold_path, {**held, "state": "held"})
        # The caller checkpoints this sole authoritative transaction. Runtime
        # state is derived again by the next _load/_step, avoiding another
        # two-file acknowledgement gap while preserving the old state evidence.
        if "edge" in tx["runtime"]["completed"]:
            tx["runtime"]["completed"].remove("edge")
        return {"held": True, "services_touched": True, "release_token_present": False,
                "preserved_evidence_prefix": "held-" + suffix, "postgresql_clickhouse_preserved": True}

    def verify(self, source_dir, manifest, transaction):
        self.guard_fresh(transaction)
        b = self._load(source_dir, manifest, transaction)
        self._databases(transaction)
        if set(transaction["runtime"]["completed"]) != RESTORE_STAGES or _json(b.state_path) != b.state:
            raise Refused("Restored runtime has not completed its measured activation stages")
        self._verify_released_catalog(transaction)
        result = b._evidence()
        if not all(result["checks"].get(key) is True for key in RUNTIME_CHECKS):
            raise Refused("Restored runtime failed verification")
        atomic_json(Path(transaction["stage"]) / "runtime-activation.json", self._proof(transaction))
        atomic_json(self.paths.bootstrap / "runtime-ready.json", result)
        (b.bootstrap / "administrator-password").unlink(missing_ok=True)
        if not valid_restored_state(_json(b.state_path), self.paths, pending=True):
            raise Refused("Restored runtime activation proof failed readback")
        return {**result, "setup_complete": False, "restored": True}
