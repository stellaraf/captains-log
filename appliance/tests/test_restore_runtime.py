"""Fresh restore runtime boundaries; no containers, services or host mutations."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import restore_runtime as restore
from nebulalog_manager.aide import RUNTIME_STAGES
from nebulalog_manager.bootstrap import Bootstrap
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.firstboot import Locations, RUNTIME_CHECKS

SOURCE = "11111111-2222-4333-8444-555555555555"
TARGET = "22222222-2222-4333-8444-555555555555"
OPERATION = "33333333-2222-4333-8444-555555555555"
ADMIN = "44444444-2222-4333-8444-555555555555"
PINS = {key: "example/" + key.lower() + "@sha256:" + "a" * 64 for key in (
    "NEBULALOG_IMAGE", "POSTGRESQL_IMAGE", "CLICKHOUSE_IMAGE", "KEYCLOAK_FIPS_IMAGE")}


class RestoreRuntimeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.paths = Locations(root / "etc", root / "data", root / "run")
        self.stage = self.paths.data / "manager/restores" / OPERATION
        self.source = self.stage / "source"
        self.source.mkdir(parents=True)
        self.paths.bootstrap.mkdir(parents=True)
        self.configuration = self.paths.data / "configuration"
        self.bootstrap = self.configuration / "bootstrap"
        self.bootstrap.mkdir(parents=True)
        self.tx = {"id": OPERATION, "source_installation_id": SOURCE, "target_installation_id": TARGET,
                   "manifest_sha256": "a" * 64, "stage": str(self.stage), "runtime": {}}
        self.calls = []
        def runner(argv, **kwargs):
            self.calls.append((argv, kwargs))
            if argv[:2] == ["systemctl", "show"]:
                return "inactive"
            if "psql" in argv:
                return "restore-identity-rebound"
            return ""
        self.runtime = restore.FreshRestoreRuntime(self.paths, runner=runner,
            firstboot=Mock(gate=Mock(return_value={"host_ready": True, "setup_complete": False, "installation_id": TARGET})))
        self.runtime.systemd = root / "systemd"
        self.runtime.systemd.mkdir()
        for name in ("require_linux_root", "_encrypted_staging", "_directory"):
            item = patch.object(restore, name)
            if name == "_directory":
                item = patch.object(restore, name, side_effect=lambda path, **kwargs: path.mkdir(parents=True, exist_ok=True) if kwargs.get("create") else None)
            item.start()
            self.addCleanup(item.stop)
        def private(path, **kwargs):
            if path.is_symlink() or not path.is_file():
                raise Refused("Unsafe fixture file")
            return path.read_bytes()
        for name, replacement in (("_private_file", private), ("trusted_file", lambda path: path if not path.is_symlink() else (_ for _ in ()).throw(Refused("symlink")))):
            item = patch.object(restore, name, side_effect=replacement)
            item.start()
            self.addCleanup(item.stop)
        self.runtime.bootstrap._schema_revision = Mock(return_value="2")
        setup = {"installation_id": SOURCE, "hostname": "logs.example.test", "baseline": "unified",
                 "administrator": {"username": "captain"}, "maintenance": {"timezone": "UTC"}}
        secrets = {key: "b" * 64 for key in ("postgresql_admin", "postgresql_app", "postgresql_keycloak", "clickhouse", "keycloak_bootstrap", "identity_service")}
        runtime = {"health_password": "long-health-password-Aa1!", "health_totp": "A" * 52, "inspector_service": "c" * 64}
        state = {"schema": 1, "installation_id": SOURCE, "administrator_id": ADMIN,
                 "identity_initialized": True, "completed": sorted(RUNTIME_STAGES), "active_stage": None}
        lifecycle = {"schema_revision": "2", "issuer": "https://logs.example.test/realms/nebulalog", "auth_probe": {
            "username": "nebulalog-health", "client_id": "nebulalog", "redirect_uri": "https://logs.example.test/health-oidc",
            "password": runtime["health_password"], "totp_secret": runtime["health_totp"],
            "totp_algorithm": "SHA256", "totp_digits": 6, "totp_period": 30}}
        for name, value in (("bootstrap/setup.json", setup), ("bootstrap/secrets.json", secrets),
                            ("bootstrap/runtime-secrets.json", runtime), ("bootstrap/runtime-state.json", state), ("lifecycle.json", lifecycle)):
            atomic_json(self.source / "configuration" / name, value)
        for name in restore.TLS_FILES:
            path = self.source / "configuration/tls" / name
            path.parent.mkdir(exist_ok=True)
            path.write_text("synthetic-public-or-private-test-bytes")
        atomic_json(self.bootstrap / "setup.json", {**setup, "installation_id": TARGET})
        atomic_json(self.bootstrap / "secrets.json", {key: "d" * 64 for key in secrets})
        atomic_json(self.paths.etc / "images.json", PINS)
        self.manifest = {"installation_id": SOURCE, "runtime": {"images": PINS, "schema_revision": "2"}, "files": []}
        self.reseal()

    def reseal(self):
        self.manifest["files"] = [{"path": name, "bytes": (self.source / name).stat().st_size,
            "sha256": hashlib.sha256((self.source / name).read_bytes()).hexdigest()} for name in restore.SOURCE_FILES]
        atomic_json(self.source / "backup.json", self.manifest)
        self.tx["manifest_sha256"] = hashlib.sha256((self.source / "backup.json").read_bytes()).hexdigest()

    def loaded(self):
        return self.runtime._load(self.source, self.manifest, self.tx)

    def normalized(self):
        self.tx["databases"] = {name: {"state": "restored", "archive_sha256": "f" * 64} for name in ("nebulalog", "keycloak")}
        self.tx["operational_normalized"] = True
        atomic_json(self.stage / "normalization.json", {"schema": 1, "operation": OPERATION,
            "source_installation_id": SOURCE, "target_installation_id": TARGET, "observed": True})
        self.tx["normalization_sha256"] = hashlib.sha256((self.stage / "normalization.json").read_bytes()).hexdigest()

    def test_fresh_guard_refuses_existing_data_and_enrolled_host(self):
        self.assertEqual(self.runtime.guard_fresh(), TARGET)
        self.runtime.firstboot.gate.return_value["setup_complete"] = True
        with self.assertRaises(Refused):
            self.runtime.guard_fresh()
        self.runtime.firstboot.gate.return_value["setup_complete"] = False
        (self.paths.data / "postgresql").mkdir()
        (self.paths.data / "postgresql/PG_VERSION").write_text("17")
        with self.assertRaises(Refused):
            self.runtime.guard_fresh()

    def test_credentials_keep_new_database_passwords_and_old_identity_only(self):
        b = self.loaded()
        self.assertEqual(b.secret["identity_service"], "b" * 64)
        for key in ("postgresql_admin", "postgresql_app", "postgresql_keycloak", "clickhouse", "keycloak_bootstrap"):
            self.assertEqual(b.secret[key], "d" * 64)
        self.assertEqual(b.runtime["inspector_service"], "c" * 64)
        self.assertEqual(b.state["administrator_id"], ADMIN)
        self.assertEqual(b.setup["installation_id"], TARGET)
        self.assertEqual(b.state["kind"], "configuration-restore")

    def test_review_inspection_binds_target_and_factory_without_disk_or_cutoff_mutation(self):
        tx = copy.deepcopy(self.tx)
        before = {str(path): path.read_bytes() for path in self.paths.data.rglob("*") if path.is_file()}
        proof = {"descriptor_sha256": "d" * 64, "host": {"generation": "e" * 64}}
        with patch("nebulalog_manager.update_enrollment.UpdateEnrollment") as factory:
            factory.return_value.verify_build_inputs.return_value = proof
            first = self.runtime.inspect_recovery(self.source, self.manifest, self.tx)
            factory.return_value.verify_build_inputs.assert_called_once_with(include_host=True)
            self.assertEqual(self.tx, tx)
            self.assertEqual(before, {str(path): path.read_bytes() for path in self.paths.data.rglob("*") if path.is_file()})
            self.assertTrue(first["certificates_verified"])
            self.assertTrue(all(argv[0] == "openssl" for argv, _ in self.calls))
            self.assertTrue(any("-verify_hostname" in argv for argv, _ in self.calls))
            self.assertTrue(any("-verify_ip" in argv for argv, _ in self.calls))
            target = json.loads((self.bootstrap / "secrets.json").read_text())
            target["postgresql_admin"] = "e" * 64
            atomic_json(self.bootstrap / "secrets.json", target)
            second = self.runtime.inspect_recovery(self.source, self.manifest, self.tx)
            self.assertNotEqual(first["resource_revision"], second["resource_revision"])

    def test_review_rejects_factory_or_tls_verification_failure_without_effects(self):
        with patch("nebulalog_manager.update_enrollment.UpdateEnrollment") as factory:
            factory.return_value.verify_build_inputs.side_effect = Refused("Synthetic factory mismatch")
            with self.assertRaisesRegex(Refused, "factory mismatch"):
                self.runtime.inspect_recovery(self.source, self.manifest, self.tx)
            self.assertEqual(self.calls, [])
            self.assertEqual(self.tx["runtime"], {})
            factory.return_value.verify_build_inputs.side_effect = None
            factory.return_value.verify_build_inputs.return_value = {"descriptor_sha256": "d" * 64, "host": {}}
            self.runtime.runner = Mock(side_effect=Refused("Synthetic certificate mismatch"))
            with self.assertRaisesRegex(Refused, "certificate mismatch"):
                self.runtime.inspect_recovery(self.source, self.manifest, self.tx)
            self.assertEqual(self.tx["runtime"], {})

    def test_source_byte_tamper_and_image_mismatch_refuse(self):
        path = self.source / "configuration/tls/ca.key"
        path.write_text("tampered")
        with self.assertRaises(Refused):
            self.loaded()
        self.reseal()
        self.manifest["runtime"]["schema_revision"] = "1"
        self.reseal()
        with self.assertRaises(Refused):
            self.loaded()

    def test_foreign_origin_and_missing_source_stage_refuse(self):
        setup = self.source / "configuration/bootstrap/setup.json"
        value = json.loads(setup.read_text())
        value["hostname"] = "foreign.example.test"
        atomic_json(setup, value)
        self.reseal()
        with self.assertRaises(Refused):
            self.loaded()
        value["hostname"] = "logs.example.test"
        atomic_json(setup, value)
        state = self.source / "configuration/bootstrap/runtime-state.json"
        value = json.loads(state.read_text())
        value["completed"].remove("storage-maintenance")
        atomic_json(state, value)
        self.reseal()
        with self.assertRaises(Refused):
            self.loaded()

    def test_listener_fence_is_persistent_owned_and_not_released_by_prepare(self):
        self.loaded()
        self.runtime._fence(self.tx)
        for name in restore.LISTENERS:
            path = self.runtime.systemd / ("nebulalog-" + name + ".service.d/80-nebulalog-restore.conf")
            self.assertIn(str(self.stage / "listeners-ready.json"), path.read_text())
        self.assertFalse((self.stage / "listeners-ready.json").exists())
        path.write_text("[Unit]\nConditionPathExists=/foreign\n")
        with self.assertRaises(Refused):
            self.runtime._fence(self.tx)

    def test_interrupted_action_keeps_intent_and_never_replays(self):
        self.loaded()
        operation = Mock(side_effect=Refused("injected failure"))
        with self.assertRaises(Refused):
            self.runtime._step("images", operation, self.tx, None)
        retained = json.loads((self.stage / "transaction.json").read_text())
        self.assertEqual(retained["runtime"]["active_stage"], "images")
        with self.assertRaises(Refused):
            self.runtime._step("images", operation, self.tx, None)
        self.assertEqual(operation.call_count, 1)
        with self.assertRaises(Refused):
            self.runtime.guard_fresh(self.tx)

    def test_database_and_quarantine_receipts_required_before_release(self):
        self.loaded()
        with self.assertRaises(Refused):
            self.runtime._databases(self.tx)
        self.normalized()
        self.runtime._databases(self.tx)
        self.tx["databases"]["keycloak"]["state"] = "restoring"
        with self.assertRaises(Refused):
            self.runtime._databases(self.tx)
        self.assertFalse((self.stage / "listeners-ready.json").exists())

    def test_activation_uses_restore_stages_and_does_not_import_or_reset(self):
        b = self.loaded()
        prepared = ["directories", "storage-maintenance", "certificates", "images", "environment", "postgresql"]
        self.tx["runtime"]["completed"] = prepared
        self.tx["runtime"]["token_not_before"] = 1700000000
        atomic_json(self.bootstrap / "restore-auth.json", {"schema": 1, "installation_id": TARGET,
            "operation": OPERATION, "token_not_before": 1700000000})
        (self.configuration / "runtime").mkdir()
        (self.configuration / "runtime/api.env").write_text("OIDC_TOKEN_NOT_BEFORE=1700000000\n")
        self.normalized()
        with patch.object(b, "_migrate") as migrate, patch.object(b, "_lifecycle"), patch.object(b, "_edge"), \
             patch.object(b, "_wait"), patch.object(b, "_realm") as realm, patch.object(b, "_identity") as identity:
            self.runtime.activate(self.source, self.manifest, self.tx)
        migrate.assert_called_once_with(initialize_retention=False)
        realm.assert_not_called()
        identity.assert_not_called()
        sql = next(kwargs["input"].decode() for argv, kwargs in self.calls if "psql" in argv)
        self.assertIn("--username=keycloak", next(argv for argv, _ in self.calls if "psql" in argv))
        self.assertNotIn("UPDATE credential", sql)
        self.assertNotIn("UPDATE user_entity", sql)
        self.assertEqual(json.loads((self.stage / "listeners-ready.json").read_text())["state"], "databases-ready")
        self.assertFalse((self.stage / "runtime-activation.json").exists())

    def test_final_restored_state_requires_genuine_proof_and_exact_stages(self):
        b = self.loaded()
        b.state.update(completed=sorted(restore.RESTORE_STAGES), identity_initialized=True)
        self.assertFalse(restore.valid_restored_state(b.state, self.paths))
        proof = self.runtime._proof(self.tx)
        atomic_json(self.stage / "runtime-activation.json", proof)
        atomic_json(self.stage / "listeners-ready.json", {**proof, "state": "databases-ready"})
        self.tx.update(kind="configuration-restore", state="runtime_ready")
        self.tx["runtime"]["completed"] = list(b.state["completed"])
        atomic_json(self.stage / "transaction.json", self.tx)
        pointer = {"schema": 2, "id": OPERATION, "stage": str(self.stage)}
        atomic_json(self.paths.data / "manager/restore.json", pointer)
        self.assertTrue(restore.valid_restored_state(b.state, self.paths))
        self.tx["state"] = "verifying"
        atomic_json(self.stage / "transaction.json", self.tx)
        self.assertFalse(restore.valid_restored_state(b.state, self.paths))
        self.tx["state"] = "runtime_ready"
        atomic_json(self.stage / "transaction.json", self.tx)
        for stage in ("realm", "foreign"):
            altered = copy.deepcopy(b.state)
            altered["completed"].append(stage)
            self.assertFalse(restore.valid_restored_state(altered, self.paths))
        b.state["completed"].remove("storage-maintenance")
        self.assertFalse(restore.valid_restored_state(b.state, self.paths))

    def test_normal_bootstrap_refuses_any_restore_pointer_before_seeding(self):
        atomic_json(self.paths.data / "manager/restore.json", {"state": "runtime_ready"})
        with self.assertRaises(Refused):
            restore.refuse_normal_provision(self.paths)
        with patch.object(self.runtime.bootstrap, "_load") as load:
            with self.assertRaises(Refused):
                self.runtime.bootstrap.prepare(self.bootstrap / "setup.json", self.bootstrap / "secrets.json")
            load.assert_not_called()

    def test_firstboot_apply_rechecks_restore_owner_after_lock(self):
        from contextlib import contextmanager
        from nebulalog_manager.firstboot import FirstBoot
        from test_firstboot import CONFIG
        manager = FirstBoot(self.paths, runner=Mock())
        @contextmanager
        def raced_lock(path):
            atomic_json(self.paths.data / "manager/restore.json", {"schema": 2, "id": OPERATION, "stage": str(self.stage)})
            yield
        with patch("nebulalog_manager.firstboot.locked", side_effect=raced_lock), \
             patch("nebulalog_manager.firstboot._private_file", return_value=b"test credential"), \
             patch("nebulalog_manager.firstboot._private_dir"), patch.object(manager, "_host"), \
             patch.object(manager, "plan") as plan:
            with self.assertRaises(Refused):
                manager.apply(CONFIG, "a" * 64)
            plan.assert_not_called()
            manager.runner.assert_not_called()

    def test_matching_schema_migration_preserves_restored_retention(self):
        b = self.loaded()
        b._migrate(initialize_retention=False)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0][-1], "migrate")
        self.assertNotIn("UPDATE settings", str(self.calls))

    def test_api_cutoff_comes_only_from_target_owned_restore_record(self):
        b = self.loaded()
        record = {"schema": 1, "installation_id": TARGET, "operation": OPERATION, "token_not_before": 1700000000}
        atomic_json(self.bootstrap / "restore-auth.json", record)
        with patch.object(b, "_read", side_effect=lambda path: json.loads(path.read_text())), patch("nebulalog_manager.bootstrap.os.chown"):
            b._environment()
            self.assertIn("OIDC_TOKEN_NOT_BEFORE=1700000000\n", (self.configuration / "runtime/api.env").read_text())
            self.assertNotIn("OIDC_TOKEN_NOT_BEFORE", (self.configuration / "runtime/ingest.env").read_text())
            record["installation_id"] = SOURCE
            atomic_json(self.bootstrap / "restore-auth.json", record)
            with self.assertRaises(Refused):
                b._environment()

    def test_failed_health_reholds_listeners_and_retains_previous_evidence(self):
        b = self.loaded()
        self.tx["runtime"]["completed"] = sorted(restore.RESTORE_STAGES)
        b.state.update(completed=list(self.tx["runtime"]["completed"]), identity_initialized=True)
        atomic_json(b.state_path, b.state)
        self.runtime._fence(self.tx)
        atomic_json(self.stage / "listeners-ready.json", {**self.runtime._proof(self.tx), "state": "databases-ready"})
        atomic_json(self.stage / "runtime-activation.json", self.runtime._proof(self.tx))
        result = self.runtime.fence_failure(self.tx)
        self.assertTrue(result["held"])
        self.assertFalse((self.stage / "listeners-ready.json").exists())
        self.assertEqual(len(list(self.stage.glob("held-*-listeners-ready.json"))), 1)
        self.assertEqual(len(list(self.stage.glob("held-*-runtime-activation.json"))), 1)
        self.assertNotIn("edge", self.tx["runtime"]["completed"])
        self.assertIn("installed-release", self.tx["runtime"]["completed"])
        stops = [argv[-1] for argv, _ in self.calls if argv[:2] == ["systemctl", "stop"]]
        self.assertEqual(stops, ["nebulalog-" + name + ".service" for name in ("edge", "api", "ingest", "keycloak")])

    def test_failed_stop_resumes_owned_hold_without_release_token(self):
        b = self.loaded()
        self.tx["runtime"]["completed"] = sorted(restore.RESTORE_STAGES)
        b.state.update(completed=list(self.tx["runtime"]["completed"]), identity_initialized=True)
        atomic_json(b.state_path, b.state)
        self.runtime._fence(self.tx)
        atomic_json(self.stage / "listeners-ready.json", {**self.runtime._proof(self.tx), "state": "databases-ready"})
        original = self.runtime.runner
        def failed(argv, **kwargs):
            if argv[:2] == ["systemctl", "stop"]:
                raise Refused("synthetic stop timeout")
            return original(argv, **kwargs)
        self.runtime.runner = failed
        with self.assertRaises(Refused):
            self.runtime.fence_failure(self.tx)
        self.assertFalse((self.stage / "listeners-ready.json").exists())
        self.assertEqual(json.loads((self.stage / "failure-fence.json").read_text())["state"], "holding")
        self.assertIn("edge", self.tx["runtime"]["completed"])
        self.runtime.runner = original
        result = self.runtime.fence_failure(self.tx)
        self.assertTrue(result["services_touched"])
        self.assertNotIn("edge", self.tx["runtime"]["completed"])

    def test_session_sql_expires_sessions_but_preserves_replay_and_account_rows(self):
        sql = restore.identity_rebind_sql(SOURCE, TARGET, ADMIN, not_before=1700000000)
        self.assertLess(sql.index("DELETE FROM offline_client_session"), sql.index("DELETE FROM offline_user_session"))
        self.assertLess(sql.index("DELETE FROM auth_session"), sql.index("DELETE FROM root_auth_session"))
        self.assertIn("not_before=GREATEST(COALESCE(not_before,0),1700000000)", sql)
        for table in ("credential", "user_entity", "user_role_mapping", "single_use_object"):
            self.assertNotIn("DELETE FROM " + table, sql)
        for cutoff in (0, True, "1700000000", 2**31):
            with self.assertRaises(Refused):
                restore.identity_rebind_sql(SOURCE, TARGET, ADMIN, not_before=cutoff)

    def test_coordinator_protocol_enrolls_then_checks_auth_once(self):
        b = self.runtime.bootstrap
        def checkpoint():
            atomic_json(self.stage / "transaction.json", self.tx)
            atomic_json(self.paths.data / "manager/restore.json", {"schema": 2, "id": OPERATION, "stage": str(self.stage)})
        def env():
            path = self.configuration / "runtime/api.env"
            path.parent.mkdir(exist_ok=True)
            path.write_text("OIDC_TOKEN_NOT_BEFORE=" + str(self.tx["runtime"]["token_not_before"]) + "\n")
        from contextlib import ExitStack
        self.tx.update(kind="configuration-restore", state="preparing")
        with ExitStack() as stack:
            stack.enter_context(patch("nebulalog_manager.restore_runtime.os.chown"))
            clock = stack.enter_context(patch("nebulalog_manager.restore_runtime.time.time", return_value=1700000000))
            for name in ("_directories", "_storage_maintenance", "_certificates", "_images", "_postgres", "_migrate", "_lifecycle", "_edge", "_wait", "_installed_release"):
                stack.enter_context(patch.object(b, name))
            stack.enter_context(patch.object(b, "_environment", side_effect=env))
            evidence = stack.enter_context(patch.object(b, "_evidence", return_value={"schema": 1, "installation_id": TARGET,
                "state": "runtime-ready", "checks": {name: True for name in RUNTIME_CHECKS}}))
            self.runtime.prepare(self.source, self.manifest, self.tx, checkpoint=checkpoint)
            self.assertFalse((self.stage / "listeners-ready.json").exists())
            self.normalized()
            clock.return_value = 1700000002
            self.runtime.activate(self.source, self.manifest, self.tx, checkpoint=checkpoint)
            self.runtime.finish_enrollment(self.source, self.manifest, self.tx, checkpoint=checkpoint)
            evidence.assert_not_called()
            self.tx["state"] = "verifying"
            checkpoint()
            result = self.runtime.verify(self.source, self.manifest, self.tx)
            evidence.assert_called_once_with()
            self.assertFalse(result["setup_complete"])
            self.assertFalse(restore.valid_restored_state(json.loads(b.state_path.read_text()), self.paths))
            self.tx["state"] = "runtime_ready"
            checkpoint()
            self.assertTrue(restore.valid_restored_state(json.loads(b.state_path.read_text()), self.paths))

    def test_keycloak_sql_rejects_noncanonical_ids_before_dispatch(self):
        for value in ("x'; DROP DATABASE keycloak; --", SOURCE.upper(), "not-a-uuid"):
            if value == SOURCE:
                continue
            with self.assertRaises(Refused):
                restore.identity_rebind_sql(value, TARGET, ADMIN, not_before=1700000000)
        with self.assertRaises(Refused):
            restore.identity_rebind_sql(TARGET, TARGET, ADMIN, not_before=1700000000)



class NativeLogRuntimeTests(unittest.TestCase):
    def setUp(self):
        fixture = RestoreRuntimeTests("runTest"); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        for name in ("runtime", "paths", "stage", "source", "tx", "manifest", "bootstrap", "configuration"):
            setattr(self, name, getattr(fixture, name))
        self.runtime.bootstrap._schema_revision.return_value = "3"
        self.manifest["runtime"]["schema_revision"] = "3"
        source_lifecycle = self.source / "configuration/lifecycle.json"
        value = json.loads(source_lifecycle.read_text()); value["schema_revision"] = "3"; atomic_json(source_lifecycle, value)
        fixture.reseal(); fixture.loaded(); fixture.normalized()
        self.tx.update(schema=1, kind="configuration-restore", state="restoring", archive_sha256="c"*64)
        self.tx["runtime"]["completed"] = ["directories", "storage-maintenance", "certificates", "images", "environment", "postgresql"]
        self.tx["runtime"]["token_not_before"] = 1700000000
        atomic_json(self.bootstrap / "restore-auth.json", {"schema": 1, "installation_id": TARGET, "operation": OPERATION, "token_not_before": 1700000000})
        (self.configuration / "runtime").mkdir()
        (self.configuration / "runtime/api.env").write_text("OIDC_TOKEN_NOT_BEFORE=1700000000\n")
        (self.stage / "backup.cms").write_bytes(b"CMS"); (self.stage / "backup.cms").chmod(0o600)
        (self.stage / "logs").mkdir(); (self.stage / "logs/events.tar").write_bytes(b"DATA")
        from nebulalog_manager.log_backup import VERSION, LogBackupAdapter
        self.table_uuid = "777e3820-f194-49f8-b20c-bc3487eeebba"
        self.tx["logs"] = {"schema": 1, "state": "authenticated", "native": {},
            "archive": {"path": str(self.stage / "logs/events.tar"), "sha256": "d"*64, "bytes": 4},
            "metadata": {"link": {"source_installation_id": SOURCE, "configuration_backup": {"sha256": "c"*64, "bytes": 3}, "runtime": self.manifest["runtime"]},
                "native": {"table": "nebulalog.events", "server_version": VERSION, "table_uuid": self.table_uuid,
                    "backup_id": SOURCE, "query_id": ADMIN, "started_at": "2026-10-19T12:00:00+00:00", "finished_at": "2026-10-19T12:01:00+00:00",
                    "table_definition_sha256": "f"*64, "retention_policy_revision": 1},
                "archive": {"format": "clickhouse-native-tar", "sha256": "d"*64, "bytes": 4}}}
        self.runtime._fence(self.tx)
        self.gate = self.paths.data / "manager/storage-maintenance/gate.json"
        atomic_json(self.gate, self.runtime._log_gate(self.tx, False))
        self.row = {"gate": self.runtime._log_gate(self.tx, False), "engine": {"schema": 1, "mode": "uninitialized"}, "policy": {"global_days": 90}, "pending": 0}
        self.runtime._log_pg_state = Mock(side_effect=lambda: copy.deepcopy(self.row))
        self.sql, self.queries = [], []
        def pg(query):
            import re
            self.sql.append(query)
            on_disk = json.loads((self.stage / "transaction.json").read_text())["logs"]["native"]["state"]
            self.assertIn(on_disk, {"preparing", "binding", "releasing"})
            self.assertIn("pg_advisory_xact_lock(4850182995969828167)", query)
            self.assertIn("public.storage_emergency_inserts", query)
            for column, setting in (("gate", "storage_emergency_maintenance"), ("engine", "retention_engine")):
                pattern = "UPDATE public.settings SET value='([^']+)'::jsonb WHERE key='" + setting + "'"
                self.row[column] = json.loads(re.search(pattern, query).group(1))
            return "native-restore-storage-settled"
        self.runtime._log_pg = Mock(side_effect=pg)
        def ch(query, params=()):
            from nebulalog_manager.log_backup import SCHEMA3_SQL
            self.queries.append(query)
            if query == SCHEMA3_SQL: return ""
            if query.startswith("SELECT count()"): return "0"
            if " AS rows " in query: return json.dumps({"uuid": self.table_uuid, "rows": 3})
            return json.dumps({"uuid": self.table_uuid, "version": VERSION, "create_table_query": "CREATE TABLE factory schema3"})
        self.runtime._log_ch = Mock(side_effect=ch)
        instance = patch.object(LogBackupAdapter, "_instance", return_value={"id": "fixed-image-process"})
        instance.start(); self.addCleanup(instance.stop)
        self.checkpoint()

    def checkpoint(self):
        atomic_json(self.paths.data / "manager/restore.json", {"schema": 2, "id": OPERATION, "stage": str(self.stage)})
        atomic_json(self.stage / "transaction.json", self.tx)

    def prepare(self):
        return self.runtime.prepare_log_restore(self.source, self.manifest, self.tx)

    def restored(self):
        self.prepare()
        n = self.tx["logs"]["native"]
        n.update(state="restored", inventory={"rows": 3}, result={"state": "restored", "rows": 3, "table_uuid": self.table_uuid,
            "archive_sha256": "d"*64, "integrity_checked": True})
        self.checkpoint()

    def test_prepare_holds_storage_and_uses_exact_schema_without_listeners(self):
        self.prepare()
        self.assertEqual(self.tx["logs"]["native"]["state"], "table_ready")
        self.assertTrue(self.row["gate"]["delivery_held"])
        self.assertEqual(self.row["engine"]["mode"], "uninitialized")
        self.assertFalse((self.stage / "listeners-ready.json").exists())
        count = len(self.queries); self.prepare(); self.assertEqual(len(self.queries), count)
        self.assertNotIn("schema", self.tx["runtime"]["completed"])

    def test_pointer_source_link_and_boot_fence_are_actual_admission_requirements(self):
        for change in ("pointer", "link", "fence", "listener"):
            with self.subTest(change=change):
                if change == "pointer": atomic_json(self.paths.data / "manager/restore.json", {"schema": 2, "id": SOURCE, "stage": str(self.stage)})
                if change == "link": self.tx["logs"]["metadata"]["link"]["configuration_backup"]["sha256"] = "e"*64; self.checkpoint()
                fence = self.runtime.systemd / "nebulalog-api.service.d/80-nebulalog-restore.conf"
                body = fence.read_bytes()
                if change == "fence": fence.write_text("[Unit]\n")
                if change == "listener": atomic_json(self.stage / "listeners-ready.json", {})
                with self.assertRaises(Refused): self.prepare()
                self.assertFalse(self.sql)
                self.tx["logs"]["metadata"]["link"]["configuration_backup"]["sha256"] = "c"*64
                fence.write_bytes(body)
                (self.stage / "listeners-ready.json").unlink(missing_ok=True)
                self.checkpoint()

    def test_existing_target_table_and_interrupted_ddl_never_replay(self):
        self.runtime._log_ch.side_effect = lambda query, params=(): "1"
        with self.assertRaises(Refused): self.prepare()
        self.assertEqual(self.tx["logs"]["native"]["state"], "preparing")
        count = self.runtime._log_ch.call_count
        with self.assertRaises(Refused): self.prepare()
        self.assertEqual(self.runtime._log_ch.call_count, count)
        self.assertTrue(json.loads(self.gate.read_text())["held"])

    def test_missing_policy_revision_defaults_only_absent_and_wrong_revision_refuses(self):
        self.row["policy"]["revision"] = None
        with self.assertRaises(Refused): self.prepare()
        self.assertEqual(self.tx["logs"]["native"], {})
        self.row["policy"]["revision"] = True
        with self.assertRaises(Refused): self.prepare()
        self.row["policy"]["revision"] = 2
        with self.assertRaises(Refused): self.prepare()

    def test_completed_restore_binds_only_target_uuid_and_keeps_hold(self):
        self.restored()
        proof = self.runtime.complete_log_restore(self.source, self.manifest, self.tx)
        self.assertEqual(proof["table_uuid"], self.table_uuid)
        self.assertEqual(self.row["engine"]["table_uuid"], self.table_uuid)
        self.assertEqual(self.tx["logs"]["native"]["state"], "bound")
        self.assertTrue(self.row["gate"]["delivery_held"])
        with self.assertRaises(Refused): self.runtime._proof(self.tx)  # Not released/activated.

    def test_wrong_rows_and_unrestored_logs_cannot_activate(self):
        self.prepare()
        with self.assertRaises(Refused): self.runtime.activate(self.source, self.manifest, self.tx)
        self.assertFalse((self.stage / "listeners-ready.json").exists())
        self.tx["logs"]["native"].update(state="restored", inventory={"rows": 3}, result={"state": "restored", "rows": 2,
            "table_uuid": self.table_uuid, "archive_sha256": "d"*64, "integrity_checked": True})
        self.checkpoint()
        with self.assertRaises(Refused): self.runtime.complete_log_restore(self.source, self.manifest, self.tx)
        self.assertEqual(self.row["engine"]["mode"], "uninitialized")

    def test_native_hold_releases_only_after_schema_identity_and_lifecycle(self):
        self.restored(); self.runtime.complete_log_restore(self.source, self.manifest, self.tx)
        b = self.runtime.bootstrap
        def held(*args, **kwargs): self.assertTrue(self.row["gate"]["delivery_held"])
        def edge():
            self.assertFalse(self.row["gate"]["held"])
            self.assertTrue((self.stage / "listeners-ready.json").exists())
        with patch.object(b, "_migrate", side_effect=held), patch.object(b, "_lifecycle", side_effect=held), \
             patch.object(b, "_edge", side_effect=edge), patch.object(b, "_wait"):
            self.runtime.activate(self.source, self.manifest, self.tx)
        self.assertEqual(self.tx["logs"]["native"]["state"], "released")
        self.assertIn("log_restore_sha256", self.runtime._proof(self.tx))
        self.assertEqual(set(self.tx["runtime"]["completed"]), restore.RESTORE_STAGES - {"installed-release"})
        self.tx["logs"]["native"]["result"]["rows"] = 1
        with self.assertRaises(Refused): self.runtime._proof(self.tx)


if __name__ == "__main__":
    unittest.main()
