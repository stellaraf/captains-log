"""Native-boundary injections; these tests do not qualify Podman or LUKS."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_adapters.identity_maintenance import IdentityMaintenanceBackend, LABEL
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


if __name__ == "__main__":
    unittest.main()
