import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from nebulalog_manager.common import CommandFailed, Refused, atomic_json
from nebulalog_manager.updates import digest_file, REQUIRED_CHECKS
from nebulalog_adapters.lifecycle import IDENTITY_GATES, Lifecycle, image_from_quadlet, inventory, verify_inventory

OLD = "registry.example/nebulalog@sha256:" + "a" * 64
NEW = "registry.example/nebulalog@sha256:" + "b" * 64


class Commands:
    def __init__(self):
        self.calls = []
        self.units = {}
        self.fail_dump = False
        self.bad_digest = False
        self.pg_unready = 0

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:2] == ["systemctl", "stop"]:
            self.units[argv[-1]] = "inactive"
        elif argv[:2] == ["systemctl", "start"]:
            self.units[argv[-1]] = "active"
        elif "--property=ActiveState" in argv:
            return self.units.get(argv[-1], "active")
        elif "--property=Result" in argv:
            return "success"
        elif argv[:3] == ["podman", "image", "inspect"]:
            return json.dumps([{"RepoDigests": [] if self.bad_digest else [argv[-1]]}])
        elif "--command" in argv:
            sql = argv[-1]
            if sql == "SELECT 1":
                if self.pg_unready:
                    self.pg_unready -= 1
                    raise Refused("not ready")
                return "1"
            if "pg_database" in sql:
                return json.dumps({"nebulalog": "nebulalog", "keycloak": "keycloak"})
            if "pg_authid" in sql:
                return json.dumps({"nebulalog": "synthetic-hash-one", "keycloak": "synthetic-hash-two"})
        return ""

    def capture(self, argv, target, **kwargs):
        self.calls.append(argv)
        if self.fail_dump:
            raise Refused("synthetic dump failure")
        target.write_bytes(b"PGDMP synthetic archive only used by fake commands")
        target.chmod(0o600)

    def feed(self, argv, source, **kwargs):
        self.calls.append(argv)
        if not source.read_bytes().startswith(b"PGDMP"):
            raise Refused("invalid archive")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.stage = self.root / "manager/updates/releases/one"
        self.stage.mkdir(parents=True)
        self.config_dir = self.root / "configuration"
        self.config_dir.mkdir()
        self.secret = self.config_dir / "api.env"
        self.secret.write_text("SYNTHETIC_SECRET=not-a-real-secret\n")
        self.secret.chmod(0o640)
        self.quadlets = self.root / "quadlets"
        self.quadlets.mkdir()
        for name in ("api", "ingest", "postgresql", "clickhouse", "keycloak"):
            (self.quadlets / ("nebulalog-" + name + ".container")).write_text("[Container]\nImage=" + OLD + "\nReadOnly=true\n")
        artifact = self.stage / "app.oci"
        artifact.write_bytes(b"synthetic OCI fixture")
        self.manifest = {"components": {"nebulalog": {"artifact": "app.oci", "version": "0.1.1", "image": NEW,
                         "rollback_safe": True, "database_migration": "none", "schema_revision": "1"}},
                         "artifacts": [{"name": "app.oci", "bytes": artifact.stat().st_size, "sha256": digest_file(artifact)}]}
        atomic_json(self.stage / "manifest.json", self.manifest)
        self.transaction = {"release": str(self.stage), "manifest_sha256": digest_file(self.stage / "manifest.json"),
                            "state": "preflight", "previous": {"components": {"nebulalog": {"version": "0.1.0"}}}}
        atomic_json(self.root / "manager/updates/transaction.json", self.transaction)
        self.commands = Commands()
        self.manager = Lifecycle({"schema_revision": "1"}, self.commands, state=self.root / "manager/updates",
                                 data=self.root, configuration=self.config_dir, quadlets=self.quadlets, guard=lambda: None)
        self.manager.encrypted = Mock()
        self.manager.maintenance = Mock()
        # Native holds/catalog execution have separate real PostgreSQL suites;
        # these coordinator tests inject those boundaries and test phase order.
        self.manager.storage_maintenance = Mock()
        self.manager.application_schema_catalog = Mock(return_value={"schema_revision": "1"})
        self.manager.api_ready = Mock()
        self.trusted = patch("nebulalog_adapters.lifecycle.trusted_file", side_effect=lambda path: path)
        self.trusted.start()

    def tearDown(self):
        self.trusted.stop()
        self.temporary.cleanup()

    def test_backup_quiesces_writers_and_preserves_configuration_permissions(self):
        receipt = self.manager.backup(self.stage)
        self.assertTrue(receipt["postgresql"] and receipt["configuration"])
        stop_api = self.commands.calls.index(["systemctl", "stop", "nebulalog-api.service"])
        first_dump = next(index for index, call in enumerate(self.commands.calls) if "pg_dump" in call)
        self.assertLess(stop_api, first_dump)
        recovered = self.stage / "recovery/configuration/api.env"
        self.assertEqual(recovered.stat().st_mode & 0o777, 0o640)
        self.assertEqual(recovered.stat().st_uid, self.secret.stat().st_uid)
        self.assertIn(["systemctl", "stop", "nebulalog-ingest.service"], self.commands.calls)

    def test_backup_failure_restores_writers_before_propagating_error(self):
        self.commands.fail_dump = True
        with self.assertRaises(Refused):
            self.manager.backup(self.stage)
        self.assertEqual(self.commands.units["nebulalog-api.service"], "active")
        self.assertEqual(self.commands.units["nebulalog-keycloak.service"], "active")
        self.manager.maintenance.assert_called_with(False, self.stage)

    def test_backup_writer_recovery_failure_keeps_maintenance_with_failed_receipt(self):
        self.commands.fail_dump = True
        self.manager.api_ready.side_effect = Refused("synthetic writer recovery failure")
        with self.assertRaisesRegex(Refused, "writer recovery failed"):
            self.manager.backup(self.stage)
        self.manager.maintenance.assert_called_once_with(True, self.stage)
        receipt = json.loads((self.stage / "adapter-backup-recovery.json").read_text())
        self.assertFalse(receipt["ok"])
        self.assertFalse(receipt["recovered"])

    def test_prepare_rejects_loaded_image_digest_mismatch_before_activation(self):
        self.manager.backup(self.stage)
        self.commands.bad_digest = True
        with self.assertRaises(Refused):
            self.manager.prepare(self.stage)
        self.assertEqual(image_from_quadlet((self.quadlets / "nebulalog-api.container").read_text()), OLD)

    def test_activation_stops_all_services_before_replacing_pins(self):
        self.manager.backup(self.stage)
        self.manager.prepare(self.stage)
        result = self.manager.activate(self.stage)
        self.assertTrue(result["durable_data_preserved"])
        self.assertEqual(image_from_quadlet((self.quadlets / "nebulalog-api.container").read_text()), NEW)
        self.assertEqual(image_from_quadlet((self.quadlets / "nebulalog-postgresql.container").read_text()), OLD)
        self.assertTrue(all(state == "active" for state in self.commands.units.values()))

    def test_emergency_rollback_restores_metadata_and_configuration_after_pg_ready(self):
        self.manager.backup(self.stage)
        self.manager.prepare(self.stage)
        self.manager.activate(self.stage)
        self.secret.write_text("SYNTHETIC_SECRET=changed\n")
        self.secret.chmod(0o600)
        self.commands.pg_unready = 1
        with patch("nebulalog_adapters.lifecycle.time.sleep"):
            result = self.manager.rollback(self.stage)
        self.assertEqual(result["restored_databases"], ["nebulalog", "keycloak"])
        self.assertEqual(self.secret.read_text(), "SYNTHETIC_SECRET=not-a-real-secret\n")
        self.assertEqual(self.secret.stat().st_mode & 0o777, 0o640)
        pg_start = max(index for index, call in enumerate(self.commands.calls) if call == ["systemctl", "start", "nebulalog-postgresql.service"])
        drop = next(index for index, call in enumerate(self.commands.calls) if "dropdb" in call)
        readiness = [call for call in self.commands.calls[pg_start:drop] if "--command" in call and call[-1] == "SELECT 1"]
        self.assertGreaterEqual(len(readiness), 1)
        self.assertEqual(self.commands.pg_unready, 0)
        self.assertIn(["restorecon", "-RF", str(self.config_dir)], self.commands.calls)

    def test_historical_operator_rollback_preserves_later_users_metadata_and_config(self):
        self.manager.backup(self.stage)
        self.manager.prepare(self.stage)
        self.manager.activate(self.stage)
        atomic_json(self.stage / "adapter-finalize.json", {"transaction_state": "committed"})
        self.secret.write_text("SYNTHETIC_SECRET=rotated-after-commit\n")
        unit = self.quadlets / "nebulalog-api.container"
        unit.write_text(unit.read_text() + "Environment=NEW_POST_COMMIT_SETTING=true\n")
        unrelated = self.quadlets / "nebulalog-postgresql.container"
        unrelated.write_text(unrelated.read_text().replace(OLD, "registry.example/postgresql@sha256:" + "c" * 64))
        result = self.manager.rollback(self.stage)
        self.assertTrue(result["current_databases_preserved"])
        self.assertFalse(any("dropdb" in call or "createdb" in call for call in self.commands.calls))
        self.assertEqual(self.secret.read_text(), "SYNTHETIC_SECRET=rotated-after-commit\n")
        self.assertIn("NEW_POST_COMMIT_SETTING=true", unit.read_text())
        self.assertEqual(image_from_quadlet(unit.read_text()), OLD)
        self.assertEqual(image_from_quadlet(unrelated.read_text()), "registry.example/postgresql@sha256:" + "c" * 64)

    def test_altered_backup_refused_before_any_service_stop(self):
        self.manager.backup(self.stage)
        (self.stage / "recovery/keycloak.dump").write_bytes(b"tampered")
        prior = len(self.commands.calls)
        with self.assertRaises(Refused):
            self.manager.rollback(self.stage)
        self.assertEqual(len(self.commands.calls), prior)

    def test_finalize_requires_durable_completion_and_all_checks(self):
        with self.assertRaises(Refused):
            self.manager.finalize(self.stage)
        self.transaction["state"] = "committed"
        atomic_json(self.root / "manager/updates/transaction.json", self.transaction)
        atomic_json(self.stage / "adapter-health.json", {"ok": True, "checks": {key: key != "local_auth" for key in REQUIRED_CHECKS}})
        with self.assertRaises(Refused):
            self.manager.finalize(self.stage)
        atomic_json(self.stage / "adapter-health.json", {"ok": True, "checks": {key: True for key in REQUIRED_CHECKS}})
        self.assertTrue(self.manager.finalize(self.stage)["ok"])
        self.manager.maintenance.assert_called_with(False, self.stage)

    def test_inventory_refuses_links_and_detects_permission_changes(self):
        observed = inventory(self.config_dir)
        self.secret.chmod(0o644)
        with self.assertRaises(Refused):
            verify_inventory(self.config_dir, observed)
        (self.config_dir / "linked.env").symlink_to(self.secret)
        with self.assertRaises(Refused):
            inventory(self.config_dir)

    def test_mutable_or_duplicate_image_pins_refused(self):
        for content in ("Image=latest", "Image=" + OLD + "\nImage=" + NEW):
            with self.assertRaises(Refused):
                image_from_quadlet(content)

    def test_keycloak_qualification_binds_real_browser_gates_to_signed_candidate(self):
        release = {"artifacts": [{"name": "identity.json"}, {"name": "browser-evidence.tar"}]}
        change = {"image": NEW, "qualification_artifact": "identity.json"}
        report = {"schema": 1, "source_commit": "a" * 40, "keycloak_image": NEW,
                  "checks": {gate: {"status": "passed", "method": "real_browser", "evidence_artifact": "browser-evidence.tar"} for gate in IDENTITY_GATES}}
        atomic_json(self.stage / "identity.json", report)
        self.assertEqual(set(self.manager.identity_qualification(self.stage, release, change)["checks"]), IDENTITY_GATES)
        report["checks"]["saml_entra"]["method"] = "service_token"
        atomic_json(self.stage / "identity.json", report)
        with self.assertRaisesRegex(Refused, "saml_entra"):
            self.manager.identity_qualification(self.stage, release, change)
        report["keycloak_image"] = OLD
        atomic_json(self.stage / "identity.json", report)
        with self.assertRaisesRegex(Refused, "match this candidate"):
            self.manager.identity_qualification(self.stage, release, change)

    def os_reboot_fixture(self):
        stage = self.root / "manager/os-updates/os-one"
        stage.mkdir(parents=True)
        self.manager.backup(stage, os_backup=True)
        atomic_json(self.root / "manager/os-latest.json", {"state": "reboot_prepared", "stage": str(stage),
                    "boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})
        atomic_json(self.root / "manager/os-transaction.json", {"state": "reboot_requested", "stage": str(stage),
                    "boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})
        self.manager.boot_id = Mock(return_value="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        self.manager.health = Mock(return_value={"ok": True, "checks": {name: True for name in REQUIRED_CHECKS}})
        self.manager.maintenance.reset_mock()
        return stage

    def os_postcheck_fixture(self):
        integrity = patch("nebulalog_adapters.lifecycle.os_payload.accept_integrity", return_value={"ok": True})
        self.os_integrity = integrity.start()
        self.addCleanup(integrity.stop)
        stage = self.root / "manager/os-updates/os-one"
        stage.mkdir(parents=True)
        self.manager.backup(stage, os_backup=True)
        self.manager.boot_id = Mock(return_value="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        atomic_json(self.root / "manager/os-latest.json", {"state": "prepared", "stage": str(stage), "boot_id": self.manager.boot_id()})
        atomic_json(self.root / "manager/os-transaction.json", {"state": "postcheck", "stage": str(stage), "boot_id": self.manager.boot_id()})
        self.manager.health = Mock(return_value={"ok": True, "checks": {name: True for name in REQUIRED_CHECKS}})
        self.manager.maintenance.reset_mock()
        return stage

    def test_os_postcheck_accepts_only_current_operation_and_all_runtime_checks(self):
        stage = self.os_postcheck_fixture()
        result = self.manager.os_postcheck()
        self.assertEqual(result["stage"], str(stage))
        self.assertEqual(result["checks"], {name: True for name in REQUIRED_CHECKS})
        self.manager.health.assert_called_once_with(stage, os_health=True)
        self.assertEqual(json.loads((self.root / "manager/os-latest.json").read_text())["state"], "postcheck_passed")
        self.assertTrue((stage / "adapter-os-postcheck.json").exists())

    def test_os_postcheck_refuses_package_or_integrity_failure_before_health(self):
        stage = self.os_postcheck_fixture()
        self.os_integrity.side_effect = Refused("installed RPM payload does not match exact plan")
        with self.assertRaisesRegex(Refused, "recovery evidence retained"):
            self.manager.os_postcheck()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_called_with(True, stage)

    def test_os_recovery_verifies_completed_payload_instead_of_repeating_install(self):
        stage, journal = self.os_recovery_fixture()
        value = json.loads(journal.read_text())
        atomic_json(journal, {**value, "recovery_phase": "updating"})
        result = self.manager.os_recover()
        self.assertEqual(result["status"], "updated")
        self.os_integrity.assert_called_once_with(stage, runner=self.manager.cmd)
        self.assertFalse(any(call[0] == "/usr/bin/rpm" for call in self.commands.calls))

    def test_os_postcheck_refuses_unrelated_stale_and_symlinked_stage(self):
        stage = self.os_postcheck_fixture()
        for transaction in ({"state": "postcheck", "stage": str(self.stage)},
                            {"state": "updating", "stage": str(stage)},
                            {"state": "complete", "stage": str(stage)}):
            with self.subTest(transaction=transaction):
                atomic_json(self.root / "manager/os-transaction.json", transaction)
                with self.assertRaisesRegex(Refused, "not bound"):
                    self.manager.os_postcheck()
        linked = stage.parent / "linked"
        linked.symlink_to(stage, target_is_directory=True)
        atomic_json(self.root / "manager/os-latest.json", {"state": "prepared", "stage": str(linked)})
        atomic_json(self.root / "manager/os-transaction.json", {"state": "postcheck", "stage": str(linked)})
        with self.assertRaisesRegex(Refused, "not bound"):
            self.manager.os_postcheck()
        self.manager.health.assert_not_called()

    def test_os_postcheck_verifies_retained_recovery_bytes_before_health(self):
        stage = self.os_postcheck_fixture()
        (stage / "recovery/keycloak.dump").write_bytes(b"tampered")
        with self.assertRaisesRegex(Refused, "recovery evidence retained"):
            self.manager.os_postcheck()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_called_once_with(True, stage)
        self.assertEqual(json.loads((self.root / "manager/os-latest.json").read_text())["state"], "postcheck_failed")
        self.assertTrue((stage / "recovery/configuration/api.env").exists())

    def test_every_failed_os_health_check_keeps_maintenance_and_recovery_evidence(self):
        stage = self.os_postcheck_fixture()
        for failed in REQUIRED_CHECKS:
            with self.subTest(check=failed):
                atomic_json(self.root / "manager/os-latest.json", {"state": "prepared", "stage": str(stage), "boot_id": self.manager.boot_id()})
                self.manager.health.return_value = {"ok": True, "checks": {name: name != failed for name in REQUIRED_CHECKS}}
                with self.assertRaisesRegex(Refused, "maintenance remains active"):
                    self.manager.os_postcheck()
                self.manager.maintenance.assert_called_with(True, stage)
                self.assertEqual(json.loads((self.root / "manager/os-latest.json").read_text())["state"], "postcheck_failed")
                self.assertTrue((stage / "recovery/keycloak.dump").exists())
                self.assertFalse((stage / "adapter-os-postcheck.json").exists())

    def test_os_health_exception_is_failure_and_never_discards_backup(self):
        stage = self.os_postcheck_fixture()
        self.manager.health.side_effect = Refused("probe unavailable")
        with self.assertRaisesRegex(Refused, "maintenance remains active"):
            self.manager.os_postcheck()
        self.manager.maintenance.assert_called_once_with(True, stage)
        self.assertTrue((stage / "adapter-backup-inventory.json").exists())

    def test_reboot_abort_requires_full_runtime_acceptance_before_releasing_gate(self):
        stage = self.os_reboot_fixture()
        self.manager.boot_id.return_value = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        self.manager.health.return_value = {"ok": True, "checks": {"api": True, "local_auth": True}}
        with self.assertRaisesRegex(Refused, "maintenance remains active"):
            self.manager.reboot_abort()
        self.manager.maintenance.assert_not_called()
        self.manager.health.return_value = {"ok": True, "checks": {name: True for name in REQUIRED_CHECKS}}
        result = self.manager.reboot_abort()
        self.assertEqual(result["health"], {name: True for name in REQUIRED_CHECKS})
        self.manager.maintenance.assert_called_once_with(False, stage)

    def os_recovery_fixture(self):
        stage = self.os_postcheck_fixture()
        journal = self.root / "manager/os-transaction.json"
        transaction = json.loads(journal.read_text())
        atomic_json(journal, {**transaction, "state": "recovery_required", "recovery_phase": "postcheck"})
        return stage, journal

    def test_os_recovery_rechecks_and_durably_accepts_before_releasing_maintenance(self):
        stage, journal = self.os_recovery_fixture()
        states_at_release = []
        def gate(active, directory):
            if not active:
                states_at_release.append(json.loads(journal.read_text()))
        self.manager.maintenance.side_effect = gate
        before = len(self.commands.calls)
        result = self.manager.os_recover()
        self.assertEqual(result["status"], "updated")
        self.assertFalse(result["reboot_pending"])
        self.manager.health.assert_called_once_with(stage, os_health=True)
        self.assertEqual(states_at_release[0]["state"], "complete")
        self.assertEqual(states_at_release[0]["finalization"], "pending")
        self.assertEqual(json.loads(journal.read_text())["finalization"], "complete")
        self.assertEqual(self.commands.calls[before:], [["dnf", "needs-restarting", "--reboothint"]])
        self.assertTrue((stage / "recovery/keycloak.dump").exists())

    def interrupted_reboot_fixture(self, latest_state="postcheck_passed"):
        stage, journal = self.os_recovery_fixture()
        transaction = json.loads(journal.read_text())
        atomic_json(journal, {**transaction, "state": "reboot_preparing", "recovery_phase": None,
                             "reboot_pending": True, "health": {name: True for name in REQUIRED_CHECKS}})
        latest_path = self.root / "manager/os-latest.json"
        latest = json.loads(latest_path.read_text())
        atomic_json(latest_path, {**latest, "state": latest_state})
        self.manager.service = Mock()
        return stage, journal

    def test_interrupted_reboot_preparation_restores_services_after_integrity_before_health(self):
        stage, journal = self.interrupted_reboot_fixture()
        observed = []
        self.os_integrity.side_effect = lambda *args, **kwargs: observed.append("integrity")
        self.manager.service.side_effect = lambda *args: observed.append("services")
        checks = {name: True for name in REQUIRED_CHECKS}
        self.manager.health.side_effect = lambda *args, **kwargs: observed.append("health") or {"ok": True, "checks": checks}
        result = self.manager.os_recover()
        self.assertEqual(result["status"], "updated")
        self.assertEqual(observed, ["integrity", "services", "health"])
        self.manager.service.assert_called_once_with("start", self.manager.services)
        self.manager.maintenance.assert_called_with(False, stage)
        self.assertEqual(json.loads(journal.read_text())["finalization"], "complete")
        self.assertFalse(any(call[:2] in (["systemctl", "reboot"], ["/usr/bin/dnf", "upgrade"]) for call in self.commands.calls))

    def test_prepared_reboot_interruption_preserves_retry_after_service_restart_failure(self):
        stage, journal = self.interrupted_reboot_fixture("reboot_prepared")
        self.manager.service.side_effect = Refused("service restart failed")
        with self.assertRaisesRegex(Refused, "recovery evidence remain intact"):
            self.manager.os_recover()
        failed = json.loads(journal.read_text())
        self.assertEqual(failed["state"], "recovery_required")
        self.assertEqual(failed["recovery_phase"], "reboot_preparing")
        self.assertTrue(failed["reboot_pending"])
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_called_once_with(True, stage)
        self.manager.service.side_effect = None
        result = self.manager.os_recover()
        self.assertEqual(result["status"], "updated")
        self.manager.maintenance.assert_called_with(False, stage)
        self.assertTrue((stage / "recovery/keycloak.dump").exists())

    def test_interrupted_reboot_refuses_invalid_identity_and_already_requested_reboot(self):
        _, journal = self.interrupted_reboot_fixture()
        original = json.loads(journal.read_text())
        for changed in ({"state": "reboot_requested"}, {"health": {}}, {"reboot_pending": False},
                        {"boot_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}):
            with self.subTest(changed=changed):
                atomic_json(journal, {**original, **changed})
                with self.assertRaisesRegex(Refused, "exact retained same-boot"):
                    self.manager.os_recover()
        self.manager.service.assert_not_called()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def test_interrupted_reboot_verifies_backup_and_integrity_before_starting_services(self):
        stage, journal = self.interrupted_reboot_fixture()
        self.os_integrity.side_effect = Refused("unplanned file drift")
        with self.assertRaisesRegex(Refused, "recovery evidence remain intact"):
            self.manager.os_recover()
        self.manager.service.assert_not_called()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_called_once_with(True, stage)
        self.assertTrue(json.loads(journal.read_text())["reboot_pending"])
        self.assertTrue((stage / "adapter-backup-inventory.json").exists())

    def test_interrupted_reboot_finalization_retries_after_reboot_requirement_clears(self):
        stage, journal = self.interrupted_reboot_fixture()
        def fail_release(active, directory):
            if not active:
                raise Refused("edge maintenance marker temporarily unavailable")
        self.manager.maintenance.side_effect = fail_release
        with self.assertRaisesRegex(Refused, "retry os-recover"):
            self.manager.os_recover()
        accepted = json.loads(journal.read_text())
        self.assertEqual(accepted["state"], "complete")
        self.assertEqual(accepted["finalization"], "failed")
        self.assertFalse(accepted["reboot_pending"])
        self.assertEqual(accepted["recovery_phase"], "postcheck")
        self.manager.maintenance.side_effect = None
        self.manager.service.reset_mock()
        self.manager.health.reset_mock()
        self.assertFalse(self.manager.os_recover()["reboot_pending"])
        self.manager.health.assert_called_once_with(stage, os_health=True)
        self.manager.service.assert_not_called()
        self.manager.maintenance.assert_called_with(False, stage)
        self.assertEqual(json.loads(journal.read_text())["finalization"], "complete")

    def test_no_package_recovery_keeps_no_updates_status_and_pending_reboot(self):
        _, journal = self.os_recovery_fixture()
        transaction = json.loads(journal.read_text())
        atomic_json(journal, {**transaction, "no_updates": True, "plan_sha256": None})
        original = self.manager.cmd
        def runner(argv, **kwargs):
            if argv == ["dnf", "needs-restarting", "--reboothint"]:
                raise CommandFailed("dnf", 1)
            return original(argv, **kwargs)
        self.manager.cmd = runner
        result = self.manager.os_recover()
        self.assertEqual(result["status"], "no_updates")
        self.assertTrue(result["reboot_pending"])
        self.assertEqual(json.loads(journal.read_text())["status"], "no_updates")
        self.assertFalse(any(call[0] == "/usr/bin/rpm" for call in self.commands.calls))

    def test_os_recovery_reports_needed_reboot_without_requesting_one(self):
        _, journal = self.os_recovery_fixture()
        self.manager.cmd = Mock(side_effect=CommandFailed("dnf", 1))
        result = self.manager.os_recover()
        self.assertTrue(result["reboot_pending"])
        self.assertTrue(json.loads(journal.read_text())["reboot_pending"])
        self.manager.cmd.assert_called_once_with(["dnf", "needs-restarting", "--reboothint"], timeout=120)

    def test_os_recovery_fails_closed_if_reboot_hint_is_unknown(self):
        stage, journal = self.os_recovery_fixture()
        self.manager.cmd = Mock(side_effect=CommandFailed("dnf", 2))
        with self.assertRaisesRegex(Refused, "recovery evidence remain intact"):
            self.manager.os_recover()
        self.assertEqual(json.loads(journal.read_text())["state"], "recovery_required")
        self.manager.maintenance.assert_called_once_with(True, stage)

    def test_os_recovery_does_not_accept_partial_dnf_unrelated_or_other_boot_work(self):
        stage, journal = self.os_recovery_fixture()
        expected = json.loads(journal.read_text())
        for changed in ({"recovery_phase": "planning"}, {"stage": str(self.stage)},
                        {"state": "updating"}, {"boot_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}):
            with self.subTest(changed=changed):
                atomic_json(journal, {**expected, **changed})
                with self.assertRaisesRegex(Refused, "exact retained same-boot"):
                    self.manager.os_recover()
        atomic_json(journal, expected)
        self.manager.boot_id.return_value = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        with self.assertRaisesRegex(Refused, "exact retained same-boot"):
            self.manager.os_recover()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def test_os_recovery_cannot_release_another_transactions_gate(self):
        _, journal = self.os_recovery_fixture()
        atomic_json(self.root / "manager/maintenance.json", {"active": True, "release": str(self.stage)})
        with self.assertRaisesRegex(Refused, "Another transaction owns"):
            self.manager.os_recover()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def test_os_recovery_finalization_failure_can_retry_current_health(self):
        stage, journal = self.os_recovery_fixture()
        def gate(active, directory):
            if not active:
                raise Refused("simulated gate-release failure")
        self.manager.maintenance.side_effect = gate
        with self.assertRaisesRegex(Refused, "retry os-recover"):
            self.manager.os_recover()
        self.assertEqual(json.loads(journal.read_text())["finalization"], "failed")
        self.manager.maintenance.side_effect = None
        self.manager.health.reset_mock()
        self.assertEqual(self.manager.os_recover()["status"], "updated")
        self.manager.health.assert_called_once_with(stage, os_health=True)
        self.assertEqual(json.loads(journal.read_text())["finalization"], "complete")

    def test_os_recovery_revalidates_backup_and_every_health_gate(self):
        stage, journal = self.os_recovery_fixture()
        for failed in REQUIRED_CHECKS:
            with self.subTest(check=failed):
                self.manager.health.return_value = {"ok": True, "checks": {name: name != failed for name in REQUIRED_CHECKS}}
                with self.assertRaisesRegex(Refused, "maintenance and recovery evidence"):
                    self.manager.os_recover()
                self.assertEqual(json.loads(journal.read_text())["state"], "recovery_required")
                self.manager.maintenance.assert_called_with(True, stage)
        self.manager.health.reset_mock()
        (stage / "recovery/keycloak.dump").write_bytes(b"tampered")
        with self.assertRaisesRegex(Refused, "maintenance and recovery evidence"):
            self.manager.os_recover()
        self.manager.health.assert_not_called()

    def test_boot_gate_reconstructs_public_gate_from_encrypted_marker(self):
        atomic_json(self.root / "manager/maintenance.json", {"active": True, "release": str(self.stage)})
        result = self.manager.boot_gate()
        self.assertTrue(result["maintenance"])
        self.manager.maintenance.assert_called_once_with(True, self.stage)

    def test_same_boot_cannot_complete_reboot_or_release_maintenance(self):
        self.os_reboot_fixture()
        self.manager.boot_id.return_value = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with self.assertRaisesRegex(Refused, "different observed boot"):
            self.manager.reboot_complete()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def test_reboot_completion_refuses_mixed_operation_and_boot_records(self):
        self.os_reboot_fixture()
        journal = self.root / "manager/os-transaction.json"
        original = json.loads(journal.read_text())
        for changed in ({"stage": str(self.stage)}, {"stage": None},
                        {"boot_id": "cccccccc-cccc-cccc-cccc-cccccccccccc"}, {"boot_id": None}):
            with self.subTest(changed=changed):
                atomic_json(journal, {**original, **changed})
                with self.assertRaisesRegex(Refused, "exact recovery operation"):
                    self.manager.reboot_complete()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def test_reboot_completion_never_replaces_another_maintenance_owner(self):
        self.os_reboot_fixture()
        marker = self.root / "manager/maintenance.json"
        other = {"active": True, "release": str(self.stage)}
        atomic_json(marker, other)
        with self.assertRaisesRegex(Refused, "Another transaction owns"):
            self.manager.reboot_complete()
        self.assertEqual(json.loads(marker.read_text()), other)
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def test_reboot_completion_retains_gate_if_recovery_bytes_changed(self):
        stage = self.os_reboot_fixture()
        (stage / "recovery/keycloak.dump").write_bytes(b"changed after reboot")
        with self.assertRaisesRegex(Refused, "maintenance remains active"):
            self.manager.reboot_complete()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_called_once_with(True, stage)
        self.assertEqual(json.loads((self.root / "manager/os-transaction.json").read_text())["state"], "recovery_required")
        self.assertTrue((stage / "adapter-backup-inventory.json").exists())

    def test_reboot_abort_refuses_other_boot_or_operation_before_service_start(self):
        self.os_reboot_fixture()
        self.manager.service = Mock()
        with self.assertRaisesRegex(Refused, "original boot"):
            self.manager.reboot_abort()
        self.manager.boot_id.return_value = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        journal = self.root / "manager/os-transaction.json"
        atomic_json(journal, {**json.loads(journal.read_text()), "stage": str(self.stage)})
        with self.assertRaisesRegex(Refused, "exact recovery operation"):
            self.manager.reboot_abort()
        self.manager.service.assert_not_called()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def reboot_preparation_fixture(self):
        stage = self.os_reboot_fixture()
        self.manager.boot_id.return_value = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        atomic_json(self.root / "manager/os-latest.json", {"state": "postcheck_passed", "stage": str(stage),
                    "boot_id": self.manager.boot_id(), "observed_at": datetime.now(timezone.utc).isoformat()})
        atomic_json(self.root / "manager/os-transaction.json", {"state": "reboot_preparing", "stage": str(stage),
                    "boot_id": self.manager.boot_id(), "reboot_pending": True,
                    "health": {name: True for name in REQUIRED_CHECKS}})
        self.manager.unlock_readiness = Mock(return_value={"token_test": True})
        self.manager.service = Mock()
        return stage

    def test_reboot_preparation_requires_current_accepted_pending_transaction(self):
        self.reboot_preparation_fixture()
        journal = self.root / "manager/os-transaction.json"
        original = json.loads(journal.read_text())
        for changed in ({"state": "postcheck"}, {"reboot_pending": False}, {"health": {}},
                        {"health": {name: name != "local_auth" for name in REQUIRED_CHECKS}}):
            with self.subTest(changed=changed):
                atomic_json(journal, {**original, **changed})
                with self.assertRaisesRegex(Refused, "accepted pending reboot"):
                    self.manager.reboot_prepare()
        self.manager.unlock_readiness.assert_not_called()
        self.manager.service.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def test_reboot_preparation_refuses_future_stale_or_naive_backup_time(self):
        self.reboot_preparation_fixture()
        latest = self.root / "manager/os-latest.json"
        original = json.loads(latest.read_text())
        for stamp in ((datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                      (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
                      datetime.now().isoformat(), "not a timestamp"):
            with self.subTest(timestamp=stamp):
                atomic_json(latest, {**original, "observed_at": stamp})
                with self.assertRaisesRegex(Refused, "backup (is stale|timestamp is invalid)"):
                    self.manager.reboot_prepare()
        self.manager.unlock_readiness.assert_not_called()
        self.manager.service.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def test_reboot_preparation_records_owned_stage_after_stopping_services(self):
        stage = self.reboot_preparation_fixture()
        with patch("nebulalog_adapters.lifecycle.local_auth", return_value=("synthetic", {})):
            result = self.manager.reboot_prepare()
        self.assertEqual(result["boot_id"], self.manager.boot_id())
        self.manager.service.assert_called_once_with("stop", tuple(reversed(self.manager.services)))
        self.manager.maintenance.assert_called_once_with(True, stage)
        self.assertEqual(json.loads((self.root / "manager/os-latest.json").read_text())["state"], "reboot_prepared")

    def test_reboot_prepare_stop_failure_keeps_gate_until_full_recovery(self):
        stage = self.reboot_preparation_fixture()
        self.manager.service.side_effect = [Refused("partial stop"), None]
        with patch("nebulalog_adapters.lifecycle.local_auth", return_value=("synthetic", {})):
            with self.assertRaisesRegex(Refused, "partial stop"):
                self.manager.reboot_prepare()
        self.assertEqual(self.manager.service.call_args_list[-1].args, ("start", self.manager.services))
        self.manager.maintenance.assert_called_once_with(True, stage)
        self.manager.health.assert_not_called()
        self.assertEqual(json.loads((self.root / "manager/os-latest.json").read_text())["state"], "postcheck_passed")

    def test_reboot_prepare_restart_failure_preserves_original_error_and_gate(self):
        stage = self.reboot_preparation_fixture()
        self.manager.service.side_effect = [Refused("partial stop"), Refused("restart failed")]
        with patch("nebulalog_adapters.lifecycle.local_auth", return_value=("synthetic", {})):
            with self.assertRaisesRegex(Refused, "partial stop"):
                self.manager.reboot_prepare()
        self.manager.maintenance.assert_called_once_with(True, stage)
        self.assertIn("os.reboot_prepare_restart_failed", (self.root / "manager/audit.jsonl").read_text())

    def test_unlock_readiness_inspects_candidate_instead_of_recovery_default(self):
        self.manager.config["unattended_reboot"] = True
        identity = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        candidate = "/boot/vmlinuz-5.14.0-687.57.1.el9_8.x86_64"
        calls = []
        def command(argv, **kwargs):
            calls.append(argv)
            if argv[0] == "findmnt":
                return json.dumps({"filesystems": [{"source": "/dev/mapper/root"}]})
            if argv[0] == "lsblk":
                return json.dumps({"blockdevices": [{"fstype": "crypto_LUKS", "uuid": identity}]})
            if argv[0] == "lsinitrd":
                return "root UUID=" + identity + " none tpm2-device=auto"
            if argv[:2] == ["cryptsetup", "luksDump"]:
                return json.dumps({"tokens": {"0": {"type": "systemd-tpm2"}}})
            if argv[:2] == ["cryptsetup", "open"]:
                return ""
            self.fail("Unexpected command: " + repr(argv))
        self.manager.cmd = command
        result = self.manager.unlock_readiness(candidate)
        self.assertEqual(result["candidate_kernel"], candidate)
        self.assertTrue(result["token_test"])
        self.assertIn(["lsinitrd", "--file", "/etc/crypttab", candidate.replace("vmlinuz-", "initramfs-") + ".img"], calls)
        self.assertFalse(any(argv[0] == "grubby" for argv in calls))

    def test_new_boot_is_committed_only_after_all_real_health_contracts(self):
        stage = self.os_reboot_fixture()
        result = self.manager.reboot_complete()
        self.assertEqual(result["status"], "complete")
        self.manager.health.assert_called_once_with(stage, os_health=True)
        transaction = json.loads((self.root / "manager/os-transaction.json").read_text())
        self.assertEqual(transaction["state"], "complete")
        self.assertEqual(transaction["finalization"], "complete")
        self.assertEqual(transaction["observed_boot_id"], self.manager.boot_id.return_value)
        self.manager.maintenance.assert_called_with(False, stage)

    def test_new_boot_failed_local_auth_keeps_gate_and_retries_without_rollback(self):
        stage = self.os_reboot_fixture()
        self.manager.health.return_value = {"ok": False, "checks": {name: name != "local_auth" for name in REQUIRED_CHECKS}}
        with self.assertRaisesRegex(Refused, "maintenance remains active"):
            self.manager.reboot_complete()
        self.manager.maintenance.assert_called_with(True, stage)
        self.assertEqual(json.loads((self.root / "manager/os-transaction.json").read_text())["state"], "recovery_required")
        self.manager.health.return_value = {"ok": True, "checks": {name: True for name in REQUIRED_CHECKS}}
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")
        self.assertFalse(any("dropdb" in call for call in self.commands.calls))

    def test_reboot_finalization_failure_keeps_good_os_and_can_retry(self):
        self.os_reboot_fixture()
        def release_failure(active, stage):
            if not active:
                raise Refused("synthetic marker release failure")
        self.manager.maintenance.side_effect = release_failure
        with self.assertRaisesRegex(Refused, "New OS boot passed"):
            self.manager.reboot_complete()
        transaction = json.loads((self.root / "manager/os-transaction.json").read_text())
        self.assertEqual(transaction["state"], "complete")
        self.assertEqual(transaction["finalization"], "failed")
        self.manager.maintenance.side_effect = None
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")

    def test_boot_gate_recovers_os_owner_after_marker_removed_before_finalization(self):
        stage = self.os_reboot_fixture()
        atomic_json(self.root / "manager/updates/transaction.json", {"state": "committed", "finalization": "complete"})
        journal = self.root / "manager/os-transaction.json"
        marker = self.root / "manager/maintenance.json"
        def gate(active, directory):
            if active:
                atomic_json(marker, {"active": True, "release": str(directory)})
            elif marker.exists():
                marker.unlink()
        self.manager.maintenance.side_effect = gate
        real_atomic_json = atomic_json
        def crash_at_finalization(path, value):
            if path == journal and value.get("finalization") == "complete":
                raise SystemExit("power loss after removing marker")
            return real_atomic_json(path, value)
        with patch("nebulalog_adapters.lifecycle.atomic_json", side_effect=crash_at_finalization):
            with self.assertRaisesRegex(SystemExit, "power loss"):
                self.manager.reboot_complete()
        self.assertFalse(marker.exists())
        self.assertEqual(json.loads(journal.read_text())["finalization"], "pending")
        self.assertTrue(self.manager.boot_gate()["maintenance"])
        self.assertEqual(json.loads(marker.read_text())["release"], str(stage))
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")
        self.assertFalse(marker.exists())
        self.assertEqual(json.loads(journal.read_text())["finalization"], "complete")

    def test_console_only_unlock_never_claims_unattended_reboot_ready(self):
        with self.assertRaisesRegex(Refused, "Unattended reboot"):
            self.manager.unlock_readiness()
        self.assertEqual(self.commands.calls, [])


if __name__ == "__main__":
    unittest.main()
