"""Native-boundary injections; these tests do not qualify Podman or LUKS."""
import copy
import base64
import time
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_adapters.identity_maintenance import (IdentityMaintenanceBackend, LABEL, capture_before_database_restore,
                                                    verify_restore_api_preservation)
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.identity_sessions import SessionCutoffJournal

IMAGE = "registry.example/keycloak@sha256:" + "a" * 64
IMAGE_ID = "b" * 64
NAME = "cl-maint-" + "c" * 32
SECRET = "d" * 64
CID = "e" * 64
SERVER = "f" * 64
INSTALLATION = "11111111-2222-4333-8444-555555555555"


class Native:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.units = {name: "inactive" for name in ("api", "ingest")}
        self.units.update(keycloak="active", edge="active")
        self.container = None
        self.server_running = True
        self.writers = "0"
        self.fault = None
        self.extra = False
        self.scope = {name: [] for name in ("clients", "client_attributes", "scopes", "scope_attributes", "scope_links",
                       "mappers", "mapper_config", "roles", "composites", "role_scopes", "inherited_roles",
                       "service_grants", "service_users")}
        self.floor = "1800000000"
        self.foreign_graph = False
        self.observation = {"installation_id": INSTALLATION, "realm_id": "realm", "bootstrap_id": "bootstrap",
                            "bootstrap_disabled": True, "other_temporary_clients": [], "client": None, "service_users": []}

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:3] == ["podman", "image", "inspect"]:
            return json.dumps([{"Id": IMAGE_ID, "RepoDigests": [IMAGE]}])
        if argv[:2] == ["podman", "info"]:
            return json.dumps({"store": {"graphRoot": "/untrusted" if self.foreign_graph else str(self.root / "data/containers")}})
        if argv[:2] == ["systemctl", "show"]:
            if "--property=Result" in argv:
                return "success"
            name = argv[-1].removeprefix("nebulalog-").removesuffix(".service")
            return self.units[name]
        if argv[:2] == ["systemctl", "stop"]:
            self.units[argv[-1].removeprefix("nebulalog-").removesuffix(".service")] = "inactive"
            return ""
        if argv[:2] == ["podman", "ps"]:
            selector = argv[argv.index("--filter") + 1]
            if selector == "name=^nebulalog-keycloak$":
                return SERVER
            if selector.startswith("label="):
                return "\n".join(([CID] if self.container else []) + (["1" * 64] if self.extra else []))
            return CID if self.container and selector == "name=^" + self.container["Name"] + "$" else ""
        if argv[:3] == ["podman", "container", "inspect"]:
            if argv[-1] == SERVER:
                return json.dumps([{"Id": SERVER, "Name": "nebulalog-keycloak", "Image": IMAGE_ID,
                                    "State": {"Running": self.server_running}}])
            return json.dumps([self.container])
        if argv[:2] == ["podman", "create"]:
            assert self.container is None
            name = argv[argv.index("--name") + 1]
            raw = Path(argv[argv.index("--env-file") + 1]).read_text()
            self.container = {"Id": CID, "Name": name, "Image": IMAGE_ID, "ImageName": IMAGE,
                "EffectiveCaps": [], "BoundingCaps": [], "State": {"Running": False, "ExitCode": 0},
                "HostConfig": {"Privileged": False, "ReadonlyRootfs": True},
                "Config": {"User": "1000:1000", "CreateCommand": argv.copy(), "Env": raw.splitlines(),
                           "Labels": dict(argv[i + 1].split("=", 1) for i, arg in enumerate(argv) if arg == "--label")}}
            if self.fault == "created":
                raise OSError("Injected lost creation acknowledgement")
            return CID
        if argv[:2] == ["podman", "start"]:
            self.container["State"]["Running"] = True
            if self.fault == "started":
                raise OSError("Injected lost start acknowledgement")
            return CID
        if argv[:2] == ["podman", "wait"]:
            if self.fault == "waiting":
                raise TimeoutError("Injected command timeout")
            self.container["State"]["Running"] = False
            self.container["State"]["ExitCode"] = 7 if self.fault == "failed" else 0
            return str(self.container["State"]["ExitCode"])
        if argv[:2] == ["podman", "stop"]:
            self.container["State"]["Running"] = False
            return CID
        if argv[:2] == ["podman", "rm"]:
            self.container = None
            if self.fault == "removed":
                raise OSError("Injected lost removal acknowledgement")
            return CID
        raise AssertionError("Unexpected native boundary: " + repr(argv))

    def service(self, action, names):
        for name in names:
            self.units[name] = "active" if action == "start" else "inactive"
            if name == "keycloak":
                self.server_running = action == "start"

    def pg(self, argv, **kwargs):
        self.calls.append(argv)
        query = argv[-1]
        if "pg_stat_activity" in query:
            return self.writers
        if "json_build_object('realm_id'" in query:
            return json.dumps({"realm_id": "realm", "floor": int(self.floor), "installation_id": INSTALLATION})
        if "jsonb_build_object(" in query:
            return json.dumps(self.scope)
        return json.dumps(self.observation)


class MaintenanceBackendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = self.root = Path(self.temporary.name)
        data = root / "data"; config = data / "configuration"; stage = data / "manager/updates/releases/candidate"
        for p in (config / "bootstrap", config / "runtime", config / "tls", stage, root / "quadlets",
                  data / "containers", data / "manager/storage-maintenance", root / "public"):
            p.mkdir(parents=True, mode=0o700)
        atomic_json(config / "bootstrap/setup.json", {"installation_id": INSTALLATION})
        env = config / "runtime/keycloak.env"
        env.write_text("KC_DB=postgres\nKC_DB_URL=jdbc:postgresql://postgresql:5432/keycloak\n"
                       "KC_DB_USERNAME=keycloak\nKC_DB_PASSWORD=synthetic-database-secret\n"
                       "KC_BOOTSTRAP_ADMIN_PASSWORD=must-not-copy-bootstrap-secret\n")
        env.chmod(0o600)
        (config / "tls/ca.crt").write_text("fixture CA: transport construction injected in these tests")
        (root / "quadlets/nebulalog-keycloak.container").write_text("[Container]\nImage=" + IMAGE + "\n")
        atomic_json(stage / "manifest.json", {"components": {}})
        marker = {"active": True, "release": str(stage)}
        atomic_json(data / "manager/maintenance.json", marker)
        atomic_json(root / "public/maintenance.json", marker)
        atomic_json(data / "manager/storage-maintenance/gate.json", {
            "schema": 1, "held": True, "delivery_held": True, "operation": hashlib.sha256(str(stage).encode()).hexdigest()})
        (data / "manager/storage-maintenance").chmod(0o755)
        (data / "manager/storage-maintenance/gate.json").chmod(0o644)
        self.native = Native(root)
        self.transaction = {"activation_started": True}
        self.life = SimpleNamespace(data=data, configuration=config, quadlets=root / "quadlets",
            config={"issuer": "https://logs.example.test/realms/nebulalog", "ca_file": str(config / "tls/ca.crt")},
            guard=Mock(), release=lambda stage: ({}, self.transaction), encrypted=Mock(),
            cmd=self.native, pg=self.native.pg, service=self.native.service)
        self.addCleanup(patch.stopall)
        patch("nebulalog_adapters.identity_maintenance.PUBLIC_MAINTENANCE", root / "public/maintenance.json").start()
        patch("nebulalog_adapters.identity_maintenance._encrypted_staging",
              lambda p, cmd: p.mkdir(parents=True, exist_ok=True, mode=0o700)).start()
        patch("nebulalog_adapters.identity_maintenance.MaintenanceIdentityAPI.__init__", return_value=None).start()
        self.backend = IdentityMaintenanceBackend(self.life, stage, "activate")
        self.backend.api.ready = Mock(return_value=True)
        self.backend.hold()

    def test_shared_gate_accepts_lifecycle_permissions_without_relaxing_private_reads(self):
        from nebulalog_adapters.identity_maintenance import _storage_gate
        from nebulalog_manager.identity_sessions import SessionCutoffJournal
        gate = self.life.data / "manager/storage-maintenance/gate.json"
        self.assertTrue(_storage_gate(gate)["delivery_held"])
        self.assertTrue(self.backend.fenced(self.backend.operation))
        with self.assertRaises(Refused):
            SessionCutoffJournal._read(gate)

    def test_shared_gate_rejects_write_access_links_oversize_and_bad_types(self):
        from nebulalog_adapters.identity_maintenance import _storage_gate
        gate = self.life.data / "manager/storage-maintenance/gate.json"
        raw = gate.read_bytes()
        for mode in (0o600, 0o664, 0o666):
            with self.subTest(mode=mode):
                gate.chmod(mode)
                with self.assertRaises(Refused): _storage_gate(gate)
        gate.chmod(0o644)
        for body in (b"x" * 4097, json.dumps({
                **json.loads(raw), "schema": True}).encode()):
            gate.write_bytes(body)
            with self.assertRaises(Refused): _storage_gate(gate)
        gate.write_bytes(raw)
        alias = gate.with_name("other.json")
        os.link(gate, alias)
        with self.assertRaises(Refused): _storage_gate(gate)
        alias.unlink()
        gate.rename(alias); gate.symlink_to(alias)
        with self.assertRaises(Refused): _storage_gate(gate)
        gate.unlink(); alias.rename(gate)
        gate.parent.chmod(0o777)
        with self.assertRaises(Refused): _storage_gate(gate)
        gate.parent.chmod(0o755)

    def test_fixed_vendor_command_private_credentials_and_cleanup(self):
        self.backend.quiesce(NAME)
        self.backend.create(NAME, SECRET)
        self.assertEqual(self.backend._read_command()["phase"], "exited")
        argv = self.native.container["Config"]["CreateCommand"]
        self.assertIn("--optimized", argv)
        self.assertNotIn("--entrypoint", " ".join(argv))
        self.assertFalse(any(str(self.life.data / "keycloak") in arg for arg in argv))
        self.assertTrue(any(arg.startswith("--tmpfs=/opt/keycloak/data:") for arg in argv))
        self.assertNotIn(SECRET, " ".join(argv))
        env = self.backend.environment_path.read_text()
        self.assertIn("KC_FIPS_MODE=strict", env)
        self.assertIn(SECRET, env)
        self.assertNotIn("must-not-copy-bootstrap-secret", env)
        self.assertEqual(self.backend.environment_path.stat().st_mode & 0o777, 0o600)
        self.backend.start()
        self.assertIsNone(self.native.container)
        self.assertFalse(self.backend.environment_path.exists())
        self.assertEqual(self.backend._read_command()["phase"], "removed")
        self.assertEqual(self.native.units["edge"], "inactive")
        self.backend.start()

    def test_lost_create_ack_adopts_exact_owned_container_before_cleanup(self):
        self.backend.quiesce(NAME)
        self.native.fault = "created"
        with self.assertRaises(OSError):
            self.backend.create(NAME, SECRET)
        self.assertIsNone(self.backend._read_command()["container_id"])
        self.native.fault = None
        self.backend.quiesce(NAME)
        record = self.backend._read_command()
        self.assertEqual((record["phase"], record["container_id"]), ("removed", CID))
        self.backend.create(NAME, SECRET)
        self.assertEqual(self.backend._read_command()["attempt"], 2)

    def test_orphan_running_command_blocks_server_start_until_quiesced(self):
        self.backend.quiesce(NAME)
        self.native.fault = "started"
        with self.assertRaises(OSError):
            self.backend.create(NAME, SECRET)
        with self.assertRaises(Refused):
            self.backend.start()
        self.assertEqual(self.native.units["keycloak"], "inactive")
        self.native.fault = None
        self.backend.quiesce(NAME)
        self.assertIsNone(self.native.container)
        self.assertTrue(any(argv[:2] == ["podman", "stop"] for argv in self.native.calls))

    def test_lost_remove_ack_recovers_and_erases_private_file(self):
        self.backend.quiesce(NAME);self.backend.create(NAME, SECRET)
        self.native.fault = "removed"
        with self.assertRaises(OSError):
            self.backend.start()
        self.assertTrue(self.backend.environment_path.exists())
        self.native.fault = None
        self.backend.start()
        self.assertFalse(self.backend.environment_path.exists())

    def test_wrong_container_recipe_or_identity_cannot_be_stopped_or_removed(self):
        self.backend.quiesce(NAME);self.backend.create(NAME, SECRET)
        original = copy.deepcopy(self.native.container)
        mutations = [
            lambda c: c.update(Image="1" * 64),
            lambda c: c.update(Id="2" * 64),
            lambda c: c["Config"]["Labels"].update({LABEL + ".operation": "3" * 64}),
            lambda c: c["Config"]["CreateCommand"].append("--untrusted"),
            lambda c: c["HostConfig"].update(Privileged=True),
            lambda c: c.update(EffectiveCaps=["CAP_SYS_ADMIN"]),
            lambda c: c["Config"]["Env"].append("KC_DB_PASSWORD=other"),
        ]
        for mutate in mutations:
            self.native.container = copy.deepcopy(original);mutate(self.native.container)
            before = len(self.native.calls)
            with self.subTest(mutate=mutate), self.assertRaises(Refused):
                self.backend.start()
            self.assertFalse(any(a[:2] in (["podman", "stop"], ["podman", "rm"]) for a in self.native.calls[before:]))
        self.native.container = original

    def test_unknown_command_and_foreign_client_are_refused(self):
        self.backend.quiesce(NAME);self.backend.create(NAME, SECRET)
        self.native.extra = True
        with self.assertRaises(Refused):
            self.backend.start()
        self.native.extra = False
        with self.assertRaises(Refused):
            self.backend.quiesce("cl-maint-" + "f" * 32)

    def test_missing_journal_does_not_adopt_an_existing_container(self):
        self.backend.quiesce(NAME);self.backend.create(NAME, SECRET)
        self.backend.command_path.unlink()
        with self.assertRaises(Refused):
            self.backend.start()
        self.assertIsNotNone(self.native.container)

    def test_active_database_writer_blocks_vendor_recovery(self):
        self.native.writers = "1"
        with self.assertRaises(Refused):
            self.backend.quiesce(NAME)
        with self.assertRaises(Refused):
            self.backend.create(NAME, SECRET)
        self.assertIsNone(self.native.container)

    def test_orphan_server_is_not_equivalent_to_inactive_systemd_unit(self):
        self.native.service = Mock()
        self.life.service = self.native.service
        self.native.units["keycloak"] = "inactive"
        with self.assertRaises(Refused):
            self.backend.quiesce(NAME)
        with self.assertRaises(Refused):
            self.backend.create(NAME, SECRET)

    def test_failed_command_does_not_prove_success(self):
        self.backend.quiesce(NAME)
        self.native.fault = "failed"
        with self.assertRaises(Refused):
            self.backend.create(NAME, SECRET)
        self.assertEqual(self.backend._read_command()["phase"], "started")
        self.assertTrue(self.backend.environment_path.exists())

    def test_markers_writers_and_input_changes_hold_every_operation(self):
        for unit in ("edge", "api", "ingest"):
            self.native.units[unit] = "active"
            with self.subTest(unit=unit), self.assertRaises(Refused):
                self.backend.fenced(self.backend.operation)
            self.native.units[unit] = "inactive"
        marker = self.life.data / "manager/maintenance.json"
        raw = marker.read_bytes()
        atomic_json(marker, {"active": True, "release": "foreign"})
        with self.assertRaises(Refused):
            self.backend.fenced(self.backend.operation)
        marker.write_bytes(raw)
        source = self.life.configuration / "runtime/keycloak.env"
        source.write_text(source.read_text() + "KC_DB_PASSWORD=changed\n")
        with self.assertRaises(Refused):
            self.backend.fenced(self.backend.operation)

    def test_foreign_operation_and_unapproved_activation_refused(self):
        with self.assertRaises(Refused):
            self.backend.fenced("0" * 64)
        self.transaction["activation_started"] = False
        with self.assertRaises(Refused):
            self.backend.fenced(self.backend.operation)
        with self.assertRaises(Refused):
            IdentityMaintenanceBackend(self.life, self.backend.stage, "activate")

    def test_graphroot_or_encrypted_admission_change_blocks_resume(self):
        self.native.foreign_graph = True
        with self.assertRaises(Refused):
            self.backend.fenced(self.backend.operation)
        self.native.foreign_graph = False
        self.life.encrypted.side_effect = Refused("Injected lost encrypted mount")
        with self.assertRaises(Refused):
            self.backend.create(NAME, SECRET)
        self.assertIsNone(self.native.container)

    def test_observation_parameters_cannot_inject_sql(self):
        self.assertEqual(self.backend.observe(NAME, None), self.native.observation)
        for name, uid in (("foreign", None), (NAME, "x' OR true--")):
            before = len(self.native.calls)
            with self.subTest(name=name, uid=uid), self.assertRaises(Refused):
                self.backend.observe(name, uid)
            self.assertEqual(len(self.native.calls), before)

    def test_completion_binds_actual_environment_journal_and_authorization(self):
        self.backend.quiesce(NAME);self.backend.create(NAME, SECRET);self.backend.start()
        api = self.backend.api_environment
        raw = b"OIDC_CLIENT_ID=nebulalog\nOIDC_ISSUER=https://logs.example.test/realms/nebulalog\nOIDC_TOKEN_NOT_BEFORE=1800000000\n"
        api.write_bytes(raw);api.chmod(0o600)
        _, _, configuration = SessionCutoffJournal._environment(raw)
        receipt = {"installation_id": INSTALLATION, "operation": self.backend.operation,
                   "token_not_before": 1800000000, "api_sha256": hashlib.sha256(raw).hexdigest(),
                   "api_configuration_sha256": configuration, "phase": "api",
                   "maintenance_release_authorized": False, "fresh_login_required": True}
        atomic_json(self.backend.directory / "session-cutoff.json", {
            "schema": 1, "realm_id": "realm", "installation_id": INSTALLATION,
            "operation": self.backend.operation, "phase": "api", "floor": 1800000000,
            "api_path": str(api), "api_configuration_sha256": configuration})
        self.assertEqual(self.backend.record_work(receipt), receipt)
        self.assertTrue(self.backend.settled(receipt))
        capture_path = self.backend.directory / "restore-cutoff.json"
        atomic_json(capture_path, {"schema": 1, "installation_id": INSTALLATION, "operation": "f" * 64,
                    "floor": 1800000001, "api_path": str(api), "realm_id": "realm"})
        self.assertFalse(self.backend.settled(receipt))
        with self.assertRaises(Refused):
            self.backend.record_work(receipt)
        capture_path.unlink()
        self.native.scope["roles"].append({"id": "changed"})
        self.assertFalse(self.backend.settled(receipt))
        self.native.scope["roles"].clear()
        self.native.floor = "1800000001"
        self.assertFalse(self.backend.settled(receipt))
        self.native.floor = "1800000000"
        api.write_bytes(raw.replace(b"CLIENT_ID=nebulalog", b"CLIENT_ID=foreign"))
        self.assertFalse(self.backend.settled(receipt))
        api.write_bytes(raw)
        journal_path = self.backend.directory / "session-cutoff.json"
        journal = json.loads(journal_path.read_text())
        atomic_json(journal_path, {**journal, "realm_id": "foreign"})
        self.assertFalse(self.backend.settled(receipt))
        atomic_json(journal_path, {**journal, "untracked": True})
        with self.assertRaises(Refused):
            self.backend.settled(receipt)

    def test_completion_requires_command_and_credential_cleanup(self):
        self.assertFalse(self.backend._command_settled())
        with self.assertRaises(Refused):
            self.backend.start()
        self.backend.quiesce(NAME);self.backend.create(NAME, SECRET)
        retained = copy.deepcopy(self.native.container)
        self.assertFalse(self.backend._command_settled())
        self.backend.start()
        self.assertTrue(self.backend._command_settled())
        self.backend.environment_path.write_text("reappeared credential file")
        self.assertFalse(self.backend._command_settled())
        self.backend.environment_path.unlink()
        self.native.container = retained
        with self.assertRaises(Refused):
            self.backend._command_settled()


    def restore_capture(self, *, resume=False):
        return capture_before_database_restore(self.life, self.backend.stage, self.restore_context, resume=resume)

    def prepare_restore_capture(self):
        self.native.service('stop', ('keycloak',))
        self.restore_context = {'schema':1, 'stage':str(self.backend.stage), 'backup_sha256':'a'*64}
        self.life.checked_backup = Mock(return_value={'verified':True})
        self.life.database_restore_context = Mock(return_value=self.restore_context)
        self.backend.api_environment.write_text('OIDC_CLIENT_ID=nebulalog\nOIDC_ISSUER=https://logs.example.test/realms/nebulalog\n')
        self.backend.api_environment.chmod(0o600)

    def test_restore_capture_uses_real_files_and_bound_sql_observation(self):
        self.prepare_restore_capture()
        result = self.restore_capture()
        self.assertEqual(result['floor'], 1800000000)
        self.assertEqual(result['realm_id'], 'realm')
        self.assertEqual(json.loads((self.backend.directory/'restore-cutoff.json').read_text()), result)
        self.assertFalse(any(call[:2] in (['podman','create'],['podman','rm']) for call in self.native.calls))
        before=len(self.native.calls)
        self.assertEqual(self.restore_capture(resume=True),result)
        self.assertFalse(any('--command' in call for call in self.native.calls[before:]))

    def test_restore_capture_preserves_pending_session_floor_above_database_and_api(self):
        self.prepare_restore_capture()
        _, _, configuration = SessionCutoffJournal._environment(self.backend.api_environment.read_bytes())
        path = self.backend.directory/'session-cutoff.json'
        pending = {'schema': 1, 'installation_id': INSTALLATION, 'operation': 'd'*64,
                   'realm_id': 'realm', 'floor': 1800000900, 'phase': 'intent',
                   'api_path': str(self.backend.api_environment),
                   'api_configuration_sha256': configuration}
        atomic_json(path, pending)
        result = self.restore_capture()
        self.assertEqual(result['floor'], 1800000900)
        self.assertEqual(json.loads(path.read_text()), pending)
        self.assertEqual(self.restore_capture(resume=True), result)
        self.assertFalse(any(call[:2] in (['podman', 'create'], ['podman', 'rm'])
                             for call in self.native.calls))

    def test_restore_capture_rejects_orphan_writer_or_recovery_command(self):
        self.prepare_restore_capture()
        self.native.server_running=True
        with self.assertRaises(Refused): self.restore_capture()
        self.native.server_running=False;self.native.extra=True
        with self.assertRaises(Refused): self.restore_capture()
        self.native.extra=False;self.native.writers='1'
        with self.assertRaises(Refused): self.restore_capture()
        self.assertFalse((self.backend.directory/'restore-cutoff.json').exists())

    def test_restore_capture_refuses_foreign_context_or_missing_resume(self):
        self.prepare_restore_capture()
        with self.assertRaises(Refused): self.restore_capture(resume=True)
        self.life.database_restore_context.return_value={'foreign':True}
        with self.assertRaises(Refused): self.restore_capture()
        self.assertFalse((self.backend.directory/'restore-cutoff.json').exists())

    def test_restore_capture_requires_admission_and_continuous_maintenance(self):
        self.prepare_restore_capture()
        self.transaction['activation_started']=False
        with self.assertRaises(Refused): self.restore_capture()
        self.transaction['activation_started']=True
        marker=self.root/'public/maintenance.json';atomic_json(marker,{'active':False})
        with self.assertRaises(Refused): self.restore_capture()
        self.assertFalse((self.backend.directory/'restore-cutoff.json').exists())

    def test_restore_capture_refuses_storage_loss_and_live_api(self):
        self.prepare_restore_capture()
        self.life.encrypted.side_effect=Refused('mount lost')
        with self.assertRaises(Refused): self.restore_capture()
        self.life.encrypted.side_effect=None;self.native.units['api']='active'
        with self.assertRaises(Refused): self.restore_capture()
        self.assertFalse((self.backend.directory/'restore-cutoff.json').exists())

    def test_restore_capture_requires_durable_state_directory_before_observation(self):
        self.prepare_restore_capture()
        before = len(self.native.calls)
        with patch("nebulalog_adapters.identity_maintenance.os.fsync", side_effect=OSError("parent sync failed")):
            with self.assertRaises(OSError):
                self.restore_capture()
        self.assertFalse((self.backend.directory/'restore-cutoff.json').exists())
        self.assertFalse(any("--command" in call for call in self.native.calls[before:]))


    def prepare_session_restore(self):
        stage=self.backend.stage
        self.backend=IdentityMaintenanceBackend(self.life,stage,'rollback')
        self.backend.hold()
        self.restore_context={'schema':1,'stage':str(stage),'backup_sha256':'a'*64}
        self.life.checked_backup=Mock(return_value={'verified':True})
        self.life.database_restore_status=Mock(return_value=(self.restore_context,True,True))
        self.original_api=b'OIDC_CLIENT_ID=nebulalog\nOIDC_ISSUER=https://logs.example.test/realms/nebulalog\nCH_PASSWORD=keep-this-fixture-value\n'
        original=stage/'recovery/configuration/runtime/api.env';original.parent.mkdir(parents=True,mode=0o700)
        original.write_bytes(self.original_api);original.chmod(0o600)
        self.backend.api_environment.write_bytes(self.original_api);self.backend.api_environment.chmod(0o600)
        capture_operation=hashlib.sha256(json.dumps(self.restore_context,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.capture_path=self.backend.directory/'restore-cutoff.json'
        self.capture_floor=int(time.time())+600
        atomic_json(self.capture_path,{'schema':1,'installation_id':INSTALLATION,'operation':capture_operation,
            'floor':self.capture_floor,'api_path':str(self.backend.api_environment),'realm_id':'realm'})
        self.native.floor='0';self.restore_secret=None;self.logout_calls=0;self.restore_fault=None
        original_command=self.native.__call__
        def command(argv,**kwargs):
            try:return original_command(argv,**kwargs)
            finally:
                if argv[:2]==['podman','create'] and self.native.container is not None:
                    record=self.backend._read_command()
                    self.restore_secret=dict(x.split('=',1)for x in self.native.container['Config']['Env'])['CAPTAINSLOG_MAINT_SECRET']
                    self.native.observation.update(client={'id':'owned-client','client_name':record['client'],
                        'service_user_id':'owned-user','realm':'master','temporary':True,'enabled':True,
                        'public':False,'service_accounts':True,'standard_flow':False,'implicit_flow':False,
                        'password_grant':False,'admin_role':True},service_users=['owned-user'])
        self.life.cmd=command
        def authenticate(name,secret):
            client=self.native.observation['client']
            assert client and client['client_name']==name and secret==self.restore_secret
            claims=base64.urlsafe_b64encode(json.dumps({'azp':name,'sub':'owned-user'}).encode()).decode().rstrip('=')
            return 'e30.'+claims+'.signature'
        def call(token,path='',method='GET',body=None):
            if method=='GET':return {'id':'realm','realm':'nebulalog','notBefore':int(self.native.floor),
                'attributes':{'nebulalog.installation-id':INSTALLATION}}
            if method=='PUT':self.native.floor=str(body['notBefore'])
            if path=='logout-all':
                self.logout_calls+=1;self.native.floor=str(int(time.time()))
                if self.restore_fault=='logout':
                    self.restore_fault=None;raise OSError('lost logout response')
        def delete(token,cid):
            assert cid=='owned-client';self.native.observation.update(client=None,service_users=[])
            if self.restore_fault=='delete':
                self.restore_fault=None;raise OSError('lost delete response')
        self.backend.api=SimpleNamespace(ready=lambda:True,authenticate=authenticate,probe=lambda *a:True,
            call=call,delete=delete,credentials_refused=lambda *a:self.native.observation['client'] is None,
            token_refused=lambda *a:self.native.observation['client'] is None)

    def test_post_restore_composes_authority_session_and_cleanup(self):
        self.prepare_session_restore();result=self.backend.restore_sessions()
        self.assertTrue(result['authority_removed']);self.assertFalse(result['maintenance_released'])
        self.assertEqual(result['session']['token_not_before'],self.capture_floor)
        self.assertEqual(self.backend.api_environment.read_bytes(),self.original_api+f'OIDC_TOKEN_NOT_BEFORE={self.capture_floor}\n'.encode())
        record=json.loads((self.backend.directory/'temporary-authority.json').read_text())
        self.assertEqual(record['phase'],'removed');self.assertIsNone(record['secret']);self.assertIsNone(record['token'])
        self.assertIsNone(self.native.container);self.assertFalse(self.backend.environment_path.exists())
        self.assertEqual(self.native.units['api'],'inactive');self.assertEqual(self.native.units['edge'],'inactive')
        calls=len(self.native.calls);self.assertEqual(self.backend.restore_sessions(),result)
        self.assertEqual(self.logout_calls,1)
        self.assertFalse(any(call[:2]==['podman','create']for call in self.native.calls[calls:]))

    def test_lifecycle_boundary_runs_recovery_and_independent_completion_verification(self):
        from nebulalog_adapters.lifecycle import Lifecycle
        self.prepare_session_restore()
        # Keep the real composed backend, durable journals and final verifier;
        # only construction uses this fixture's native/HTTPS boundaries.
        with patch("nebulalog_adapters.identity_maintenance.IdentityMaintenanceBackend",
                   return_value=self.backend) as constructor:
            result = Lifecycle.identity_restore_sessions(self.life, self.backend.stage)
            constructor.assert_called_once_with(self.life, self.backend.stage, "rollback")
        self.assertTrue(result["authority_removed"])
        self.assertFalse(result["maintenance_released"])
        self.assertEqual(self.verify_preservation()["token_not_before"], self.capture_floor)
        self.assertEqual(self.native.units["api"], "inactive")
        self.assertEqual(self.native.units["edge"], "inactive")

    def test_lifecycle_boundary_rejects_forged_backend_success(self):
        from nebulalog_adapters.lifecycle import Lifecycle
        self.prepare_session_restore()
        # A success-shaped callback cannot substitute for retained authority
        # removal/session completion evidence.
        with patch("nebulalog_adapters.identity_maintenance.IdentityMaintenanceBackend") as constructor:
            constructor.return_value.restore_sessions.return_value = {
                "authority_removed": True, "maintenance_released": False}
            with self.assertRaises((Refused, FileNotFoundError)):
                Lifecycle.identity_restore_sessions(self.life, self.backend.stage)

    def test_post_restore_resumes_lost_creation_logout_and_deletion(self):
        for fault in ('created','logout','delete'):
            with self.subTest(fault=fault):
                # Each case gets a separate test instance and private filesystem.
                case=MaintenanceBackendTests('test_post_restore_composes_authority_session_and_cleanup')
                case.setUp()
                try:
                    case.prepare_session_restore()
                    if fault=='created':case.native.fault=fault
                    else:case.restore_fault=fault
                    with self.assertRaises(OSError):case.backend.restore_sessions()
                    case.native.fault=None
                    before=case.logout_calls
                    result=case.backend.restore_sessions()
                    self.assertTrue(result['authority_removed'])
                    self.assertEqual(sum(call[:2]==['podman','create']for call in case.native.calls),1)
                    if fault=='delete':self.assertEqual(case.logout_calls,before)
                    self.assertEqual(result['session']['token_not_before'],case.capture_floor)
                finally:case.doCleanups()

    def test_post_restore_requires_completed_restore_and_bound_capture(self):
        self.prepare_session_restore()
        self.life.database_restore_status.return_value=(self.restore_context,True,False)
        with self.assertRaises(Refused):self.backend.restore_sessions()
        self.life.database_restore_status.return_value=(self.restore_context,True,True)
        captured=json.loads(self.capture_path.read_text());atomic_json(self.capture_path,{**captured,'operation':'f'*64})
        with self.assertRaises(Refused):self.backend.restore_sessions()
        self.capture_path.unlink()
        with self.assertRaises(Refused):self.backend.restore_sessions()
        self.assertIsNone(self.native.container)

    def test_post_restore_refuses_missing_admission_or_changed_customer_bytes(self):
        self.prepare_session_restore()
        self.backend.api_environment.write_bytes(self.original_api.replace(b'keep-this',b'changed'))
        with self.assertRaises(Refused):self.backend.restore_sessions()
        self.backend.api_environment.write_bytes(self.original_api)
        result=self.backend.restore_sessions()
        (self.backend.workdir/'restore-admission.json').unlink()
        with self.assertRaises(Refused):self.backend.restore_sessions()
        self.assertEqual(self.logout_calls,1)

    def test_post_restore_admission_and_completion_lost_acknowledgements(self):
        self.prepare_session_restore()
        actual=atomic_json
        def lost_admission(path,value):
            actual(path,value)
            if path.name=='restore-admission.json':raise OSError('lost admission acknowledgement')
        with patch('nebulalog_adapters.identity_maintenance.atomic_json',lost_admission):
            with self.assertRaises(OSError):self.backend.restore_sessions()
        self.assertIsNone(self.native.container)
        def lost_complete(path,value):
            actual(path,value)
            if path.name=='restore-complete.json':raise OSError('lost completion acknowledgement')
        with patch('nebulalog_adapters.identity_maintenance.atomic_json',lost_complete):
            with self.assertRaises(OSError):self.backend.restore_sessions()
        self.assertTrue(self.backend.restore_sessions()['authority_removed'])
        self.assertEqual(self.logout_calls,1)

    def test_post_restore_completion_and_capture_drift_are_refused(self):
        self.prepare_session_restore();self.backend.restore_sessions()
        complete=self.backend.workdir/'restore-complete.json';saved=complete.read_bytes()
        changed=json.loads(saved);changed['maintenance_released']=True;atomic_json(complete,changed)
        with self.assertRaises(Refused):self.backend.restore_sessions()
        complete.write_bytes(saved)
        captured=json.loads(self.capture_path.read_text());atomic_json(self.capture_path,{**captured,'floor':self.capture_floor+1})
        with self.assertRaises(Refused):self.backend.restore_sessions()
        self.assertEqual(self.logout_calls,1)

    def preservation_descriptors(self):
        from nebulalog_adapters.host_runtime import checked_file
        api = self.backend.api_environment
        before = {"path": str(api), **checked_file(self.backend.stage / "recovery/configuration/runtime/api.env")[1]}
        after = {"path": str(api), **checked_file(api)[1]}
        return before, after

    def verify_preservation(self, before=None, after=None):
        actual_before, actual_after = self.preservation_descriptors()
        return verify_restore_api_preservation(self.life, self.backend.stage,
                                              before or actual_before, after or actual_after)

    def test_restore_preservation_authorizes_exact_change_without_commands_or_secrets(self):
        self.prepare_session_restore(); self.backend.restore_sessions()
        before, after = self.preservation_descriptors()
        commands = len(self.native.calls)
        result = self.verify_preservation(before, after)
        self.assertEqual(result["before"], before); self.assertEqual(result["after"], after)
        self.assertEqual(result["token_not_before"], self.capture_floor)
        self.assertFalse(result["maintenance_release_authorized"])
        self.assertNotIn("keep-this-fixture-value", json.dumps(result))
        self.assertNotIn(self.restore_secret, json.dumps(result))
        self.assertEqual(len(self.native.calls), commands)

    def test_restore_preservation_rejects_customer_changes_even_with_fresh_descriptor(self):
        self.prepare_session_restore(); self.backend.restore_sessions()
        original = self.backend.api_environment.read_bytes()
        for altered in (original.replace(b"keep-this", b"changed"),
                        original.replace(str(self.capture_floor).encode(), str(self.capture_floor - 1).encode()),
                        b"UNEXPECTED_SETTING=value\n" + original,
                        original + b"OIDC_TOKEN_NOT_BEFORE=1800000000\n"):
            with self.subTest(altered=hashlib.sha256(altered).hexdigest()):
                self.backend.api_environment.write_bytes(altered)
                with self.assertRaises(Refused): self.verify_preservation()
        self.backend.api_environment.write_bytes(original)
        self.backend.api_environment.chmod(0o640)
        with self.assertRaises(Refused): self.verify_preservation()

    def test_restore_preservation_requires_exact_plan_preimage_and_measured_postimage(self):
        self.prepare_session_restore(); self.backend.restore_sessions()
        before, after = self.preservation_descriptors()
        for key, value in (("sha256", "f" * 64), ("bytes", before["bytes"] + 1),
                           ("mode", 0o644), ("path", str(self.root / "foreign.env"))):
            with self.subTest(key=key):
                with self.assertRaises(Refused): self.verify_preservation({**before, key: value}, after)
                with self.assertRaises(Refused): self.verify_preservation(before, {**after, key: value})
        original = self.backend.stage / "recovery/configuration/runtime/api.env"
        original.write_bytes(original.read_bytes().replace(b"keep-this", b"changed"))
        with self.assertRaises(Refused): self.verify_preservation(before, after)

    def test_restore_preservation_requires_bound_capture_and_completed_database_restore(self):
        self.prepare_session_restore(); self.backend.restore_sessions()
        self.life.database_restore_status.return_value = (self.restore_context, True, False)
        with self.assertRaises(Refused): self.verify_preservation()
        self.life.database_restore_status.return_value = (self.restore_context, True, True)
        self.transaction["activation_started"] = False
        with self.assertRaises(Refused): self.verify_preservation()
        self.transaction["activation_started"] = True
        saved = self.capture_path.read_bytes()
        capture = json.loads(saved)
        for key, value in (("operation", "f" * 64), ("floor", self.capture_floor + 1), ("realm_id", "foreign")):
            atomic_json(self.capture_path, {**capture, key: value})
            with self.assertRaises(Refused): self.verify_preservation()
        self.capture_path.write_bytes(saved)
        self.assertEqual(self.verify_preservation()["token_not_before"], self.capture_floor)

    def test_restore_preservation_rejects_foreign_completion_and_incomplete_authority(self):
        self.prepare_session_restore(); self.backend.restore_sessions()
        complete = self.backend.workdir / "restore-complete.json"
        authority = self.backend.directory / "temporary-authority.json"
        session = self.backend.directory / "session-cutoff.json"
        mutations = ((complete, "authority_removed", False), (complete, "maintenance_released", True),
                     (complete, "schema", True), (authority, "phase", "removing"),
                     (authority, "secret", "a" * 64), (authority, "operation", "f" * 64),
                     (session, "phase", "realm"), (session, "api_configuration_sha256", "f" * 64))
        for path, key, value in mutations:
            with self.subTest(path=path.name, key=key):
                raw = path.read_bytes(); changed = json.loads(raw); changed[key] = value
                atomic_json(path, changed)
                with self.assertRaises(Refused): self.verify_preservation()
                path.write_bytes(raw)
        raw = complete.read_bytes(); changed = json.loads(raw); changed["binding"]["direction"] = "activate"
        atomic_json(complete, changed)
        with self.assertRaises(Refused): self.verify_preservation()
        complete.write_bytes(raw)
        (self.backend.workdir / "restore-admission.json").unlink()
        with self.assertRaises(OSError): self.verify_preservation()

    def test_restore_preservation_rechecks_live_bytes_after_records(self):
        from nebulalog_adapters import host_runtime
        self.prepare_session_restore(); self.backend.restore_sessions()
        before, after = self.preservation_descriptors()
        read = host_runtime.checked_file
        calls = 0
        def changed(path, *args):
            nonlocal calls
            calls += 1
            if calls == 4:
                path.write_bytes(path.read_bytes() + b"EXTRA=value\n")
            return read(path, *args)
        with patch.object(host_runtime, "checked_file", changed), self.assertRaises(Refused):
            verify_restore_api_preservation(self.life, self.backend.stage, before, after)

    def test_host_preservation_uses_real_restore_validation_only_on_rollback(self):
        from nebulalog_adapters.host_runtime import HostRuntime
        self.prepare_session_restore(); self.backend.restore_sessions()
        before, after = self.preservation_descriptors()
        unchanged = {"path": str(self.root / "trust.json"), "sha256": "a" * 64}
        host = HostRuntime.__new__(HostRuntime)
        host.lifecycle = self.life; host.stage = self.backend.stage
        host.preserved = Mock(return_value=[after, unchanged])
        plan = {"preserved": [before, unchanged]}
        with self.assertRaises(Refused): host._preserved(plan)
        host._preserved(plan, rollback=True)
        for observed in ([after], [after, {**unchanged, "sha256": "b" * 64}],
                         [after, unchanged, {"path": "new-file"}], [unchanged, after]):
            host.preserved.return_value = observed
            with self.assertRaises(Refused): host._preserved(plan, rollback=True)


if __name__ == "__main__":
    unittest.main()
