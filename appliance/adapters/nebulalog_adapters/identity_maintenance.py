"""Fixed native boundaries for operation-owned Keycloak recovery.

No entrypoint invokes this backend until lifecycle admission/migration is wired
and qualified. In particular, ``hold`` never authorizes releasing maintenance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid
from urllib.error import URLError

from nebulalog_manager.backup import _encrypted_staging
from nebulalog_manager.common import Refused, atomic_json, trusted_file
from nebulalog_manager.host_payload import strict_json
from nebulalog_manager.identity_sessions import SessionCutoffJournal, TemporaryIdentityAuthority, _atomic_private_bytes
from .auth import IdentityHTTPFailure, MaintenanceIdentityAPI
from .commands import Commands

SHA = re.compile(r"[a-f0-9]{64}")
IDENTITY = re.compile(r"[A-Za-z0-9_-]{1,128}")
CLIENT = re.compile(r"cl-maint-[a-f0-9]{32}")
IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}")
LABEL = "io.captainslog.identity-maintenance"
PUBLIC_MAINTENANCE = Path("/run/nebulalog-public/maintenance.json")


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _quoted(value):
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise Refused("Invalid identity observation parameter")
    return "'" + value + "'"


def _environment(raw):
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise Refused("Identity environment must be canonical")
    result = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in result:
            raise Refused("Ambiguous identity environment")
        result[key] = value
    return result


def capture_before_database_restore(lifecycle, stage, context, *, resume):
    """Retain identity cutoff before the lifecycle can destroy its current DB.

    This is a read-only database boundary, separate from temporary authority.
    An orphaned recovery command must be reconciled before this boundary; it
    cannot be discarded merely because the main Keycloak unit is inactive.
    """
    life, stage = lifecycle, Path(stage)
    life.guard()
    if not stage.is_absolute() or stage.resolve() != stage or type(resume) is not bool:
        raise Refused("Identity restore capture requires a canonical stage and explicit retry state")
    _, transaction = life.release(stage)
    if transaction.get("activation_started") is not True:
        raise Refused("Identity restore capture requires durable activation admission")
    if type(life.cmd) is Commands and not getattr(life, "_component_ticket", None):
        raise Refused("Identity restore capture requires the active lifecycle hook lease")
    if context != life.database_restore_context(stage, life.checked_backup(stage)):
        raise Refused("Identity restore capture differs from the verified database recovery context")
    operation = _digest(json.dumps(context, sort_keys=True, separators=(",", ":")).encode())
    setup = life.configuration / "bootstrap/setup.json"
    setup_raw = SessionCutoffJournal._read(setup)
    installation = strict_json(setup_raw)["installation_id"]
    if str(uuid.UUID(installation)) != installation:
        raise Refused("Identity restore capture requires a canonical installation UUID")
    directory = life.data / "manager/identity-maintenance"

    def held(selected):
        life.guard()
        if selected != operation or SessionCutoffJournal._read(setup) != setup_raw:
            raise Refused("Identity restore capture binding changed")
        _, current = life.release(stage)
        if current.get("activation_started") is not True:
            raise Refused("Identity restore admission disappeared")
        marker = strict_json(SessionCutoffJournal._read(life.data / "manager/maintenance.json"))
        public = strict_json(trusted_file(PUBLIC_MAINTENANCE).read_bytes())
        gate = strict_json(SessionCutoffJournal._read(life.data / "manager/storage-maintenance/gate.json"))
        if (marker != public or marker.get("active") is not True or marker.get("release") != str(stage)
                or gate != {"schema": 1, "held": True, "delivery_held": True,
                            "operation": _digest(str(stage).encode())}):
            raise Refused("Identity restore requires continuous transaction-owned maintenance")
        for name in ("api", "ingest", "keycloak"):
            unit = "nebulalog-" + name
            if life.cmd(["systemctl", "show", "--property=ActiveState", "--value", unit + ".service"]) != "inactive":
                raise Refused("Identity restore requires stopped external and identity writers")
            ids = life.cmd(["podman", "ps", "--all", "--no-trunc", "--filter",
                            "name=^" + unit + "$", "--format", "{{.ID}}"]).splitlines()
            if len(ids) > 1 or any(not SHA.fullmatch(cid) for cid in ids):
                raise Refused("Identity restore writer inventory is ambiguous")
            if ids:
                observed = strict_json(life.cmd(["podman", "container", "inspect", ids[0]]).encode())
                if (not isinstance(observed, list) or len(observed) != 1
                        or observed[0].get("Id") != ids[0] or observed[0].get("Name") != unit
                        or observed[0].get("State", {}).get("Running") is not False):
                    raise Refused("Identity restore has an orphaned writer container")
        if life.cmd(["podman", "ps", "--all", "--no-trunc", "--filter",
                     "label=" + LABEL + "=" + installation, "--format", "{{.ID}}"]):
            raise Refused("Reconcile the retained identity recovery command before database replacement")
        life.encrypted()
        _encrypted_staging(directory, life.cmd)
        return True

    held(operation)
    if directory.resolve() != directory:
        raise Refused("Identity restore state cannot traverse links")
    directory.mkdir(mode=0o700, exist_ok=True)
    # Persist the new directory entry before recording a floor and allowing a
    # destructive restore intent. Fsync of the record's directory alone does
    # not establish durability of that directory's entry in its parent.
    parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    journal = SessionCutoffJournal(directory, installation)

    def observe():
        held(operation)
        query = """SELECT json_build_object('realm_id',r.id,'floor',r.not_before,
'installation_id',(SELECT value FROM realm_attribute
 WHERE realm_id=r.id AND name='nebulalog.installation-id'))
 FROM realm r WHERE r.name='nebulalog'"""
        def sql(value):
            return life.pg(["psql", "-X", "--quiet", "--username=postgres", "--dbname=keycloak",
                            "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--command",
                            "SET statement_timeout='30s'; " + value], timeout=45)
        if sql("SELECT count(*) FROM pg_stat_activity WHERE datname='keycloak' AND usename='keycloak'") != "0":
            raise Refused("Identity database still has a writer before restore capture")
        return strict_json(sql(query).encode())

    return journal.capture_restore(observe, operation, life.configuration / "runtime/api.env",
                                   int(time.time()), held, resume=resume)


class IdentityMaintenanceBackend:
    """Compose with TemporaryIdentityAuthority while the lifecycle lease is held.

    The caller stops API/ingest and establishes transaction/storage maintenance
    before calling hold(). The backend also stops host Apache, then retains
    that hold through every SQL, vendor-command and HTTPS operation. A successful
    return never restarts Apache or releases the caller's maintenance markers.
    """

    def __init__(self, lifecycle, stage, direction):
        self.life, self.stage = lifecycle, Path(stage)
        if not self.stage.is_absolute() or self.stage.resolve() != self.stage:
            raise Refused("Identity maintenance requires a canonical release stage")
        if direction not in ("activate", "rollback"):
            raise Refused("Unknown identity maintenance direction")
        self.life.guard()
        _, transaction = self.life.release(self.stage)
        if transaction.get("activation_started") is not True:
            raise Refused("Identity maintenance requires durable activation admission")
        if type(self.life.cmd) is Commands and not getattr(self.life, "_component_ticket", None):
            raise Refused("Identity maintenance requires the active lifecycle hook lease")
        self.operation = _digest((str(self.stage) + "/identity/" + direction).encode())
        self.gate_operation = _digest(str(self.stage).encode())
        self.directory = self.life.data / "manager/identity-maintenance"
        self.workdir = self.directory / "operations" / self.operation
        self.command_path = self.workdir / "command.json"
        self.environment_path = self.workdir / "recovery.env"
        self.work_path = self.workdir / "work.json"
        self.api_environment = self.life.configuration / "runtime/api.env"
        setup = self.life.configuration / "bootstrap/setup.json"
        env = self.life.configuration / "runtime/keycloak.env"
        quadlet = self.life.quadlets / "nebulalog-keycloak.container"
        ca = self.life.configuration / "tls/ca.crt"
        if self.life.config.get("ca_file") != str(ca):
            raise Refused("Identity maintenance must use the installed appliance CA")
        files = (setup, env, quadlet, ca, self.stage / "manifest.json")
        self.inputs = {str(p): _digest(trusted_file(p).read_bytes()) for p in files}
        value = strict_json(SessionCutoffJournal._read(setup))
        self.installation_id = str(uuid.UUID(value["installation_id"]))
        if value["installation_id"] != self.installation_id:
            raise Refused("Noncanonical installation identity")
        pins = re.findall(r"^Image=(.*)$", quadlet.read_text(), re.MULTILINE)
        if len(pins) != 1 or not IMAGE.fullmatch(pins[0]):
            raise Refused("Recovery requires the installed immutable Keycloak image")
        self.image = pins[0]
        images = strict_json(self.life.cmd(["podman", "image", "inspect", self.image]).encode())
        if len(images) != 1 or self.image not in images[0].get("RepoDigests", []):
            raise Refused("Installed identity image cannot be resolved")
        self.image_id = images[0].get("Id", "").removeprefix("sha256:")
        if not SHA.fullmatch(self.image_id):
            raise Refused("Installed identity image ID is malformed")
        self.environment = _environment(SessionCutoffJournal._read(env))
        if (self.environment.get("KC_DB") != "postgres"
                or self.environment.get("KC_DB_URL") != "jdbc:postgresql://postgresql:5432/keycloak"
                or self.environment.get("KC_DB_USERNAME") != "keycloak"
                or not self.environment.get("KC_DB_PASSWORD")
                or any(k.startswith("KC_DB_") and k not in ("KC_DB_URL", "KC_DB_USERNAME", "KC_DB_PASSWORD")
                       for k in self.environment)):
            raise Refused("Recovery requires the reviewed local identity database configuration")
        self.binding = {"schema": 1, "operation": self.operation, "installation_id": self.installation_id,
                        "stage": str(self.stage), "direction": direction, "image": self.image,
                        "image_id": self.image_id, "inputs": self.inputs}
        self.api = MaintenanceIdentityAPI(self.life.config, lambda: self.fenced(self.operation))

    def _hold_evidence(self):
        self.life.guard()
        _, transaction = self.life.release(self.stage)
        if transaction.get("activation_started") is not True:
            raise Refused("Identity activation admission disappeared")
        for path, expected in self.inputs.items():
            if _digest(trusted_file(Path(path)).read_bytes()) != expected:
                raise Refused("Identity maintenance configuration changed")
        private = self.life.data / "manager/maintenance.json"
        public = PUBLIC_MAINTENANCE
        marker = strict_json(SessionCutoffJournal._read(private))
        public_marker = strict_json(trusted_file(public).read_bytes())
        if marker != public_marker or marker.get("active") is not True or marker.get("release") != str(self.stage):
            raise Refused("Identity work requires this transaction's external maintenance marker")
        gate = strict_json(SessionCutoffJournal._read(self.life.data / "manager/storage-maintenance/gate.json"))
        if gate != {"schema": 1, "held": True, "delivery_held": True, "operation": self.gate_operation}:
            raise Refused("Identity work requires continuous transaction-owned delivery fencing")
        for name in ("api", "ingest"):
            self._inactive("nebulalog-" + name + ".service")

    def _inactive(self, unit):
        if self.life.cmd(["systemctl", "show", "--property=ActiveState", "--value", unit]) != "inactive":
            raise Refused("Identity maintenance requires stopped external writers")

    def hold(self):
        self._hold_evidence()
        self._storage()
        self.life.cmd(["systemctl", "stop", "nebulalog-edge.service"], timeout=180)
        self._inactive("nebulalog-edge.service")
        if self.life.cmd(["systemctl", "show", "--property=Result", "--value", "nebulalog-edge.service"]) != "success":
            raise Refused("Public edge did not stop gracefully")
        for path in (self.directory, self.directory / "operations", self.workdir):
            if path.resolve() != path:
                raise Refused("Identity recovery state cannot traverse links")
            _encrypted_staging(path, self.life.cmd)
            SessionCutoffJournal._directory(path)
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        self.fenced(self.operation)

    def restore_sessions(self):
        """Compose post-restore authority, session repair and verified removal.

        Admission requires a completed, bound database restore and its retained
        pre-restore cutoff. No caller may use this receipt as permission to
        release maintenance: host/AIDE preservation and service startup remain
        the lifecycle coordinator's responsibility.
        """
        if self.binding["direction"] != "rollback":
            raise Refused("Post-restore identity work requires the rollback direction")
        self.hold()
        backup = self.life.checked_backup(self.stage)
        context, restoring, restored = self.life.database_restore_status(self.stage, backup)
        if restoring is not True or restored is not True:
            raise Refused("Post-restore identity work requires completed database replacement")
        journal = SessionCutoffJournal(self.directory, self.installation_id)
        captured = journal._restore_record(self.api_environment)
        capture_operation = _digest(json.dumps(context, sort_keys=True, separators=(",", ":")).encode())
        if captured is None or captured["operation"] != capture_operation:
            raise Refused("Post-restore identity work lost its exact pre-restore cutoff")
        original = SessionCutoffJournal._read(self.stage / "recovery/configuration/runtime/api.env")
        original_floor, _, original_configuration = journal._environment(original)
        current = SessionCutoffJournal._read(self.api_environment)
        _, _, configuration = journal._environment(current)
        if configuration != original_configuration or captured["floor"] < original_floor:
            raise Refused("Restored API configuration differs beyond its authorized cutoff")
        admission_path = self.workdir / "restore-admission.json"
        fixed = {"schema": 1, "binding": self.binding, "restore_operation": capture_operation,
                 "capture_sha256": _digest(json.dumps(captured, sort_keys=True, separators=(",", ":")).encode()),
                 "original_api_sha256": _digest(original), "api_configuration_sha256": configuration}
        authority = TemporaryIdentityAuthority(self.directory, self.installation_id)
        if os.path.lexists(admission_path):
            admission = strict_json(SessionCutoffJournal._read(admission_path))
            if (not isinstance(admission, dict)
                    or set(admission) != set(fixed) | {"initialize_authority", "initialize_session"}
                    or any(admission.get(key) != value for key, value in fixed.items())
                    or any(type(admission[key]) is not bool for key in ("initialize_authority", "initialize_session"))):
                raise Refused("Post-restore identity admission changed")
        else:
            if (current != original or any(os.path.lexists(path) for path in
                    (self.command_path, self.work_path, self.workdir / "restore-complete.json"))):
                raise Refused("Missing post-restore admission cannot adopt existing recovery work")
            admission = {**fixed, "initialize_authority": not os.path.lexists(authority.path),
                         "initialize_session": not os.path.lexists(journal.path)}
            self.fenced(self.operation)
            atomic_json(admission_path, admission)
            if strict_json(SessionCutoffJournal._read(admission_path)) != admission:
                raise Refused("Post-restore identity admission did not persist")

        def work(token):
            result = journal.reconcile(
                lambda path, method="GET", body=None: self.call(token, path, method, body),
                self.operation, self.api_environment, max(captured["floor"], int(time.time())),
                self.fenced, initialize=admission["initialize_session"])
            return self.record_work(result)

        receipt = authority.run(self.operation, self, work, initialize=admission["initialize_authority"])
        # Verify removal again from the retained controller record rather than
        # treating a successful work callback as completed authority cleanup.
        record = strict_json(SessionCutoffJournal._read(authority.path))
        if (record.get("phase") != "removed" or record.get("operation") != self.operation
                or record.get("secret") is not None or record.get("token") is not None
                or record.get("work_receipt") != receipt or not self.settled(receipt)):
            raise Refused("Post-restore authority removal is not durably complete")
        result = {"schema": 1, "binding": self.binding,
                  "admission_sha256": _digest(SessionCutoffJournal._read(admission_path)),
                  "session": receipt, "authority_removed": True, "maintenance_released": False}
        complete = self.workdir / "restore-complete.json"
        if os.path.lexists(complete) and strict_json(SessionCutoffJournal._read(complete)) != result:
            raise Refused("Post-restore completion record changed")
        self.fenced(self.operation)
        atomic_json(complete, result)
        if strict_json(SessionCutoffJournal._read(complete)) != result:
            raise Refused("Post-restore completion record did not persist")
        return result

    def _storage(self):
        self.life.encrypted()
        graph = self.life.data / "containers"
        info = strict_json(self.life.cmd(["podman", "info", "--format", "json"]).encode())
        if info.get("store", {}).get("graphRoot") != str(graph):
            raise Refused("Recovery credentials require encrypted Podman metadata")
        _encrypted_staging(graph, self.life.cmd)
        SessionCutoffJournal._directory(graph)

    def fenced(self, operation):
        if operation != self.operation:
            raise Refused("Foreign identity maintenance operation")
        self._hold_evidence()
        self._inactive("nebulalog-edge.service")
        for path in (self.directory, self.directory / "operations", self.workdir):
            SessionCutoffJournal._directory(path)
        self._storage()
        _encrypted_staging(self.workdir, self.life.cmd)
        return True

    def sql(self, query):
        self.fenced(self.operation)
        return self.life.pg(["psql", "-X", "--quiet", "--username=postgres", "--dbname=keycloak",
                            "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1",
                            "--command", "SET statement_timeout='30s'; " + query], timeout=45)

    def observe(self, name, service_user_id):
        if not isinstance(name, str) or not CLIENT.fullmatch(name):
            raise Refused("Invalid recovery client name")
        selected = _quoted(name)
        known = "FALSE" if service_user_id is None else "u.id=" + _quoted(service_user_id)
        query = """SELECT json_build_object(
'installation_id',(SELECT value FROM realm_attribute WHERE realm_id=r.id AND name='nebulalog.installation-id'),
'realm_id',r.id,
'bootstrap_id',(SELECT id FROM user_entity WHERE realm_id=m.id AND username='nlbootstrap'),
'bootstrap_disabled',(SELECT NOT enabled FROM user_entity WHERE realm_id=m.id AND username='nlbootstrap'),
'other_temporary_clients',COALESCE((SELECT json_agg(other.name ORDER BY other.name)
 FROM (SELECT v.client_id AS name FROM client v WHERE v.realm_id=m.id AND v.client_id<>""" + selected + """
 AND (v.client_id LIKE 'cl-maint-%' OR EXISTS(SELECT FROM client_attributes
 WHERE client_id=v.id AND name='is_temporary_admin' AND value='true'))
 UNION ALL SELECT 'orphan:'||u.id FROM user_entity u WHERE u.realm_id=m.id
 AND u.username LIKE 'service-account-cl-maint-%' AND u.username<>'service-account-'||""" + selected + """
 AND NOT EXISTS(SELECT FROM client v WHERE v.id=u.service_account_client_link)) other),'[]'::json),
'client',(SELECT json_build_object('id',v.id,'client_name',v.client_id,'service_user_id',u.id,'realm','master',
 'temporary',EXISTS(SELECT FROM client_attributes WHERE client_id=v.id AND name='is_temporary_admin' AND value='true'),
 'enabled',v.enabled,'public',v.public_client,'service_accounts',v.service_accounts_enabled,
 'standard_flow',v.standard_flow_enabled,'implicit_flow',v.implicit_flow_enabled,'password_grant',v.direct_access_grants_enabled,
 'admin_role',EXISTS(SELECT FROM user_role_mapping ur JOIN keycloak_role kr ON kr.id=ur.role_id
 WHERE ur.user_id=u.id AND kr.realm_id=m.id AND kr.name='admin'))
 FROM client v LEFT JOIN user_entity u ON u.service_account_client_link=v.id
 WHERE v.realm_id=m.id AND v.client_id=""" + selected + """),
'service_users',COALESCE((SELECT json_agg(u.id ORDER BY u.id) FROM user_entity u WHERE u.realm_id=m.id
 AND (u.username='service-account-'||""" + selected + " OR " + known + """)),'[]'::json))
 FROM realm r JOIN realm m ON m.name='master' WHERE r.name='nebulalog'"""
        value = strict_json(self.sql(query).encode())
        if not isinstance(value, dict):
            raise Refused("Identity database observation is absent or ambiguous")
        return value

    def _read_command(self):
        if not os.path.lexists(self.command_path):
            return None
        value = strict_json(SessionCutoffJournal._read(self.command_path))
        if (not isinstance(value, dict) or set(value) != {"binding", "client", "attempt", "container_id", "phase", "environment_sha256"}
                or value["binding"] != self.binding or not isinstance(value["client"], str)
                or not CLIENT.fullmatch(value["client"]) or type(value["attempt"]) is not int
                or not 1 <= value["attempt"] <= 16 or value["phase"] not in ("intent", "created", "started", "exited", "removed")
                or value["container_id"] is not None and (not isinstance(value["container_id"], str) or not SHA.fullmatch(value["container_id"]))
                or not isinstance(value["environment_sha256"], str) or not SHA.fullmatch(value["environment_sha256"])):
            raise Refused("Recovery command journal changed or lost its binding")
        if value["phase"] in ("created", "started", "exited") and value["container_id"] is None:
            raise Refused("Recovery command lost its exact container identity")
        return value

    def _persist(self, record):
        self.fenced(self.operation)
        atomic_json(self.command_path, record)
        if self._read_command() != record:
            raise Refused("Recovery command journal did not persist")

    def _name(self, record):
        return "nebulalog-identity-" + self.operation[:24] + "-" + str(record["attempt"])

    def _argv(self, record):
        return ["podman", "create", "--pull=never", "--name", self._name(record),
                "--label", LABEL + "=" + self.installation_id, "--label", LABEL + ".operation=" + self.operation,
                "--label", LABEL + ".client=" + record["client"], "--network=nebulalog",
                "--user=1000:1000", "--group-add=20001", "--read-only", "--security-opt=no-new-privileges",
                "--cap-drop=all", "--restart=no", "--env-file", str(self.environment_path),
                "--volume", str(self.life.configuration / "tls/ca.crt") + ":/etc/nebulalog/tls/ca.crt:ro,z",
                "--tmpfs=/opt/keycloak/data:rw,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m", self.image,
                "bootstrap-admin", "service", "--optimized", "--client-id", record["client"],
                "--client-secret:env=CAPTAINSLOG_MAINT_SECRET", "--no-prompt"]

    def _container(self, record):
        listed = self.life.cmd(["podman", "ps", "--all", "--no-trunc", "--filter",
                               "label=" + LABEL + "=" + self.installation_id, "--format", "{{.ID}}"]).splitlines()
        named = self.life.cmd(["podman", "ps", "--all", "--no-trunc", "--filter",
                              "name=^" + self._name(record) + "$", "--format", "{{.ID}}"]).splitlines()
        if any(not SHA.fullmatch(cid) for cid in listed + named) or len(named) > 1 or listed != named:
            raise Refused("Untracked or foreign recovery command exists")
        if not named:
            return None
        cid = named[0]
        if record["phase"] == "removed" or record["container_id"] not in (None, cid):
            raise Refused("Removed or replaced recovery container reappeared")
        observed = strict_json(self.life.cmd(["podman", "container", "inspect", cid]).encode())
        if not isinstance(observed, list) or len(observed) != 1:
            raise Refused("Ambiguous recovery container inspection")
        value = observed[0];config = value.get("Config", {});host = value.get("HostConfig", {})
        labels = config.get("Labels", {})
        if (value.get("Id") != cid or value.get("Name") != self._name(record)
                or value.get("Image", "").removeprefix("sha256:") != self.image_id
                or value.get("ImageName") != self.image or config.get("CreateCommand") != self._argv(record)
                or labels.get(LABEL) != self.installation_id or labels.get(LABEL + ".operation") != self.operation
                or labels.get(LABEL + ".client") != record["client"] or config.get("User") != "1000:1000"
                or host.get("Privileged") is not False or host.get("ReadonlyRootfs") is not True
                or value.get("EffectiveCaps") != [] or value.get("BoundingCaps") != []
                or not isinstance(value.get("State", {}).get("Running"), bool)):
            raise Refused("Recovery container does not match its fixed owned recipe")
        raw = SessionCutoffJournal._read(self.environment_path)
        if _digest(raw) != record["environment_sha256"]:
            raise Refused("Recovery environment changed")
        wanted = _environment(raw)
        actual = {}
        for item in config.get("Env", []):
            key, sep, val = item.partition("=")
            if not sep or key in actual:
                raise Refused("Recovery container environment is ambiguous")
            actual[key] = val
        if any(actual.get(key) != val for key, val in wanted.items()):
            raise Refused("Recovery container credentials/configuration changed")
        return value

    def _cleanup_command(self, *, stop):
        record = self._read_command()
        if record is None:
            if self.life.cmd(["podman", "ps", "--all", "--no-trunc", "--filter",
                              "label=" + LABEL + "=" + self.installation_id, "--format", "{{.ID}}"]):
                raise Refused("Recovery container has no retained command intent")
            return
        container = self._container(record)
        if container is not None:
            cid = container["Id"]
            if record["container_id"] is None:
                record["container_id"] = cid
                self._persist(record)
            if container["State"]["Running"]:
                if not stop:
                    raise Refused("Recovery command is still running")
                self.life.cmd(["podman", "stop", "--time", "30", cid], timeout=60)
                if self._container(record)["State"]["Running"]:
                    raise Refused("Recovery command did not stop")
            self.life.cmd(["podman", "rm", cid], timeout=60)
            if self._container(record) is not None:
                raise Refused("Recovery container survived removal")
        record["phase"] = "removed"
        self._persist(record)
        if os.path.lexists(self.environment_path):
            if _digest(SessionCutoffJournal._read(self.environment_path)) != record["environment_sha256"]:
                raise Refused("Recovery credential file changed before cleanup")
            self.environment_path.unlink()
            fd = os.open(self.workdir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def quiesce(self, name):
        self.fenced(self.operation)
        record = self._read_command()
        if record is not None and record["client"] != name:
            raise Refused("Recovery command belongs to another temporary client")
        self.life.service("stop", ("keycloak",))
        self._server(stopped=True)
        self._cleanup_command(stop=True)
        if self.sql("SELECT count(*) FROM pg_stat_activity WHERE datname='keycloak' AND usename='keycloak'") != "0":
            raise Refused("Identity database still has a writer after recovery fencing")

    def create(self, name, secret):
        self.fenced(self.operation)
        MaintenanceIdentityAPI._credentials(name, secret)
        self._inactive("nebulalog-keycloak.service")
        self._server(stopped=True)
        previous = self._read_command()
        if previous is not None and (previous["phase"] != "removed" or previous["client"] != name):
            raise Refused("Previous recovery command has not been fenced and removed")
        self._cleanup_command(stop=False)
        if self.sql("SELECT count(*) FROM pg_stat_activity WHERE datname='keycloak' AND usename='keycloak'") != "0":
            raise Refused("Cannot run vendor recovery alongside an identity database writer")
        attempt = 1 if previous is None else previous["attempt"] + 1
        if attempt > 16:
            raise Refused("Recovery retry limit requires explicit reconciliation")
        env = {k: self.environment[k] for k in ("KC_DB", "KC_DB_URL", "KC_DB_USERNAME", "KC_DB_PASSWORD")}
        env.update(KC_FIPS_MODE="strict", KC_HEALTH_ENABLED="true",
                   KC_TRUSTSTORE_PATHS="/etc/nebulalog/tls/ca.crt", CAPTAINSLOG_MAINT_SECRET=secret)
        raw = "".join(k + "=" + env[k] + "\n" for k in sorted(env)).encode()
        _atomic_private_bytes(self.environment_path, raw)
        record = {"binding": self.binding, "client": name, "attempt": attempt, "container_id": None,
                  "phase": "intent", "environment_sha256": _digest(raw)}
        self._persist(record)
        cid = self.life.cmd(self._argv(record), timeout=180)
        if not SHA.fullmatch(cid):
            raise Refused("Vendor recovery container ID was not returned")
        record.update(container_id=cid, phase="created");self._persist(record)
        if self._container(record) is None:
            raise Refused("Created recovery container is missing")
        record["phase"] = "started";self._persist(record)
        self.life.cmd(["podman", "start", cid], timeout=180)
        exit_code = self.life.cmd(["podman", "wait", cid], timeout=600)
        observed = self._container(record)
        if (exit_code != "0" or observed is None or observed["State"]["Running"]
                or observed["State"].get("ExitCode") != 0):
            raise Refused("Vendor recovery did not finish successfully")
        record["phase"] = "exited";self._persist(record)

    def start(self):
        self.fenced(self.operation)
        if self._read_command() is None:
            raise Refused("Identity recovery cannot start without its retained command intent")
        self._cleanup_command(stop=False)
        self.life.service("start", ("keycloak",))
        self._server(stopped=False)
        deadline = time.monotonic() + 180
        while True:
            try:
                if self.api.ready():
                    return
            except (URLError, IdentityHTTPFailure):
                pass
            if time.monotonic() >= deadline:
                raise Refused("Identity HTTPS readiness deadline expired")
            time.sleep(1)

    def _server(self, *, stopped):
        ids = self.life.cmd(["podman", "ps", "--all", "--no-trunc", "--filter",
                            "name=^nebulalog-keycloak$", "--format", "{{.ID}}"]).splitlines()
        if not ids and stopped:
            return
        if len(ids) != 1 or not SHA.fullmatch(ids[0]):
            raise Refused("The installed identity server is absent or ambiguous")
        values = strict_json(self.life.cmd(["podman", "container", "inspect", ids[0]]).encode())
        if not isinstance(values, list) or len(values) != 1:
            raise Refused("Identity server inspection is ambiguous")
        value = values[0]
        if (value.get("Id") != ids[0] or value.get("Name") != "nebulalog-keycloak"
                or value.get("State", {}).get("Running") is not (not stopped)
                or not stopped and value.get("Image", "").removeprefix("sha256:") != self.image_id):
            raise Refused("Identity server state or image differs from the installed generation")

    def authenticate(self, name, secret):
        return self.api.authenticate(name, secret)

    def probe(self, token, installation_id, realm_id):
        return self.api.probe(token, installation_id, realm_id)

    def call(self, token, path="", method="GET", body=None):
        return self.api.call(token, path, method, body)

    def delete(self, token, client_id):
        return self.api.delete(token, client_id)

    def credentials_refused(self, name, secret):
        return self.api.credentials_refused(name, secret)

    def token_refused(self, token):
        return self.api.token_refused(token)

    def _scope_digest(self):
        # Capture only the product realm's authorization configuration. Master
        # recovery-account deletion must not change this readback.
        tables = {
            "clients": "SELECT to_jsonb(c) AS value FROM client c WHERE c.realm_id=r.id",
            "client_attributes": "SELECT to_jsonb(a) AS value FROM client_attributes a JOIN client c ON c.id=a.client_id WHERE c.realm_id=r.id",
            "scopes": "SELECT to_jsonb(s) AS value FROM client_scope s WHERE s.realm_id=r.id",
            "scope_attributes": "SELECT to_jsonb(a) AS value FROM client_scope_attributes a JOIN client_scope s ON s.id=a.scope_id WHERE s.realm_id=r.id",
            "scope_links": "SELECT to_jsonb(a) AS value FROM client_scope_client a JOIN client c ON c.id=a.client_id WHERE c.realm_id=r.id",
            "mappers": "SELECT to_jsonb(p) AS value FROM protocol_mapper p WHERE p.client_id IN (SELECT id FROM client WHERE realm_id=r.id) OR p.client_scope_id IN (SELECT id FROM client_scope WHERE realm_id=r.id)",
            "mapper_config": "SELECT to_jsonb(a) AS value FROM protocol_mapper_config a JOIN protocol_mapper p ON p.id=a.protocol_mapper_id WHERE p.client_id IN (SELECT id FROM client WHERE realm_id=r.id) OR p.client_scope_id IN (SELECT id FROM client_scope WHERE realm_id=r.id)",
            "roles": "SELECT to_jsonb(k) AS value FROM keycloak_role k WHERE k.realm_id=r.id OR k.client IN (SELECT id FROM client WHERE realm_id=r.id)",
            "composites": "SELECT to_jsonb(a) AS value FROM composite_role a JOIN keycloak_role k ON k.id=a.composite WHERE k.realm_id=r.id OR k.client IN (SELECT id FROM client WHERE realm_id=r.id)",
            "role_scopes": "SELECT to_jsonb(a) AS value FROM scope_mapping a JOIN client c ON c.id=a.client_id WHERE c.realm_id=r.id",
            "inherited_roles": "SELECT to_jsonb(a) AS value FROM client_scope_role_mapping a JOIN client_scope s ON s.id=a.scope_id WHERE s.realm_id=r.id",
            "service_grants": "SELECT to_jsonb(a) AS value FROM user_role_mapping a JOIN user_entity u ON u.id=a.user_id WHERE u.realm_id=r.id AND u.service_account_client_link IS NOT NULL",
            "service_users": "SELECT jsonb_build_object('id',u.id,'username',u.username,'enabled',u.enabled,'client',u.service_account_client_link) AS value FROM user_entity u WHERE u.realm_id=r.id AND u.service_account_client_link IS NOT NULL",
        }
        fields = []
        for name, query in tables.items():
            fields.extend(["'" + name + "'", "(SELECT COALESCE(jsonb_agg(value ORDER BY value::text),'[]'::jsonb) FROM (" + query + ") items)"])
        raw = self.sql("SELECT jsonb_build_object(" + ",".join(fields) + ") FROM realm r WHERE r.name='nebulalog'")
        value = strict_json(raw.encode())
        if not isinstance(value, dict) or set(value) != set(tables):
            raise Refused("Incomplete identity authorization readback")
        return _digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

    def _session_settled(self, receipt):
        TemporaryIdentityAuthority._receipt(receipt, self.installation_id, self.operation)
        journal = strict_json(SessionCutoffJournal._read(self.directory / "session-cutoff.json"))
        fields = {"schema", "installation_id", "operation", "floor", "phase",
                  "api_path", "api_configuration_sha256", "realm_id"}
        if (not isinstance(journal, dict) or set(journal) != fields
                or type(journal["schema"]) is not int or journal["schema"] != 1
                or type(journal["floor"]) is not int
                or not isinstance(journal["realm_id"], str) or not IDENTITY.fullmatch(journal["realm_id"])):
            raise Refused("Session completion journal is malformed")
        raw = SessionCutoffJournal._read(self.api_environment)
        floor, _, configuration = SessionCutoffJournal._environment(raw)
        realm = strict_json(self.sql(
            "SELECT json_build_object('realm_id',r.id,'floor',r.not_before,'installation_id',"
            "(SELECT value FROM realm_attribute WHERE realm_id=r.id AND name='nebulalog.installation-id')) "
            "FROM realm r WHERE r.name='nebulalog'").encode())
        captured = SessionCutoffJournal(self.directory, self.installation_id)._restore_record(self.api_environment)
        if captured is not None and (captured["realm_id"] != journal["realm_id"]
                                     or captured["floor"] > receipt["token_not_before"]):
            return False
        return (journal.get("installation_id") == self.installation_id and journal.get("operation") == self.operation
                and journal.get("phase") == "api" and journal.get("floor") == receipt["token_not_before"] == floor
                and journal.get("api_path") == str(self.api_environment)
                and journal.get("api_configuration_sha256") == configuration == receipt["api_configuration_sha256"]
                and _digest(raw) == receipt["api_sha256"]
                and realm == {"realm_id": journal["realm_id"], "floor": floor, "installation_id": self.installation_id})

    def _command_settled(self):
        record = self._read_command()
        return (record is not None and record["phase"] == "removed"
                and not os.path.lexists(self.environment_path) and self._container(record) is None)

    def record_work(self, receipt):
        self.fenced(self.operation)
        if not self._command_settled():
            raise Refused("Identity completion requires a removed recovery command and erased credential file")
        if os.path.lexists(self.work_path):
            retained = strict_json(SessionCutoffJournal._read(self.work_path))
            if (not isinstance(retained, dict) or set(retained) != {"binding", "receipt", "scope_sha256"}
                    or retained["binding"] != self.binding):
                raise Refused("Identity completion record belongs to another operation")
        if not self._session_settled(receipt):
            raise Refused("Identity work is not durably settled")
        value = {"binding": self.binding, "receipt": receipt, "scope_sha256": self._scope_digest()}
        atomic_json(self.work_path, value)
        if strict_json(SessionCutoffJournal._read(self.work_path)) != value:
            raise Refused("Identity completion readback failed")
        return receipt

    def settled(self, receipt):
        self.fenced(self.operation)
        if not self._command_settled():
            return False
        value = strict_json(SessionCutoffJournal._read(self.work_path))
        return (isinstance(value, dict) and set(value) == {"binding", "receipt", "scope_sha256"}
                and value.get("binding") == self.binding and value.get("receipt") == receipt
                and self._session_settled(receipt) and value.get("scope_sha256") == self._scope_digest())
