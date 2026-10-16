"""Coordinator interruption tests; DB/Podman boundaries are injected here.

Real SQL, dump/restore and executor fencing have separate PostgreSQL tests.
These cases exercise phase ordering, retained provenance and interrupted
restore decisions through the production lifecycle, not native acceptance.
"""
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock

import test_lifecycle as fixture
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.image_bundle import ApplicationSchema
from nebulalog_manager.updates import digest_file, REQUIRED_CHECKS


class SchemaCoordinatorTests(unittest.TestCase):
    tearDown = fixture.LifecycleTests.tearDown

    def setUp(self):
        fixture.LifecycleTests.setUp(self)
        self.events = []
        self.db_revision = "1"
        self.operation = hashlib.sha256(str(self.stage).encode()).hexdigest()
        self.gate_path = self.root / "manager/storage-maintenance/gate.json"
        self.gate_path.parent.mkdir()
        self.manager.storage_maintenance.side_effect = self.gate
        self.manager.application_schema_catalog.side_effect = self.catalog
        original_service = self.manager.service
        def service(action, names):
            self.events.append((action, tuple(names)))
            return original_service(action, names)
        self.manager.service = Mock(side_effect=service)
        self.manager.api_ready.side_effect = lambda: self.events.append(("ready", "api"))
        self.manager.maintenance.side_effect = lambda active, stage: self.events.append(("maintenance", active))
        self.original_feed = self.commands.feed
        def feed(argv, source, **kwargs):
            result = self.original_feed(argv, source, **kwargs)
            if "--dbname=nebulalog" in argv:
                self.db_revision = "1"
                self.events.append(("restored", "nebulalog"))
            return result
        self.commands.feed = feed

    def gate(self, stage, *, held, delivery_held=False, host_only=False):
        # Mirror only the external boundary's refusal signal. Production SQL
        # and continuous host-file semantics are tested independently.
        if not host_only and self.db_revision == "1" and self.manager.application_schema_current()["revision"] == "2":
            raise Refused("Missing emergency action evidence")
        value = {"schema": 1, "held": held, "delivery_held": delivery_held,
                 "operation": self.operation if held else None}
        atomic_json(self.gate_path, value)
        self.events.append(("gate", held, delivery_held, host_only))
        return {"gate": value}

    def catalog(self, stage, revision):
        self.assertEqual(self.db_revision, revision)
        self.assertEqual(json.loads(self.gate_path.read_text()),
                         {"schema": 1, "held": True, "delivery_held": True, "operation": self.operation})
        for name in ("api", "ingest", "keycloak"):
            self.assertEqual(self.commands.units.get("nebulalog-" + name + ".service"), "inactive")
        self.events.append(("catalog", revision))
        return {"schema_revision": revision}

    def declaration(self):
        self.manifest["components"]["nebulalog"].update(
            schema_revision="2", schema_sha256=ApplicationSchema.schema_digest("2"),
            database_migration=ApplicationSchema.ADDITIVE_UPGRADE)
        atomic_json(self.stage / "manifest.json", self.manifest)
        self.transaction["manifest_sha256"] = digest_file(self.stage / "manifest.json")
        atomic_json(self.root / "manager/updates/transaction.json", self.transaction)

    def migration(self):
        self.declaration()
        def migrated(stage):
            self.events.append(("migrate", "2"))
            self.db_revision = "2"
            atomic_json(stage / "adapter-application-schema-intent.json", {"synthetic": True})
            value = {"state": "complete", "ok": True, "schema_revision": "2"}
            atomic_json(stage / "adapter-application-schema.json", value)
            return value
        self.manager.application_schema_migrate = Mock(side_effect=migrated)
        def verify(stage, **kwargs):
            self.catalog(kwargs.get("maintenance_stage") or stage, "2")
            return json.loads((stage / "adapter-application-schema.json").read_text())
        self.manager.application_schema_verify = Mock(side_effect=verify)
        self.manager.application_schema_receipt = Mock(side_effect=lambda stage: json.loads((stage / "adapter-application-schema.json").read_text()))
        self.manager.application_schema_fence = Mock(side_effect=lambda stage: self.events.append(("executor", "fenced")))
        self.manager.application_schema_recover = Mock(return_value={"state": "complete", "ok": True})
        self.manager._schema_context = Mock(return_value={})
        self.manager._schema_intent = Mock(return_value={"executor": {"container_id": "c" * 64}})
        self.manager.backup(self.stage)
        self.manager.prepare(self.stage)
        return self.manager.activate(self.stage)

    def test_legacy_receiver_stops_before_backup_and_remains_held(self):
        self.manager.backup(self.stage)
        self.assertEqual(self.events[:3], [("maintenance", True), ("gate", True, True, False),
                                           ("stop", ("api", "keycloak", "ingest"))])
        stop = self.commands.calls.index(["systemctl", "stop", "nebulalog-ingest.service"])
        first_dump = next(i for i, call in enumerate(self.commands.calls) if "pg_dump" in call)
        self.assertLess(stop, first_dump)
        backup = self.manager.checked_backup(self.stage)
        self.assertEqual(backup["application_schema"], {"revision": "1", "state": None})
        self.assertTrue(json.loads(self.gate_path.read_text())["delivery_held"])

    def test_only_bound_gate_aware_image_can_keep_receiving(self):
        app = {"schema_revision": "2", "schema_sha256": ApplicationSchema.schema_digest("2"), "image": fixture.OLD}
        atomic_json(self.manager.state / "current.json", {"components": {"nebulalog": app}})
        command = self.manager.cmd
        running = "d" * 64
        environment = ["STORAGE_MAINTENANCE_PATH=/run/nebulalog-storage-maintenance/gate.json"]
        mounts = [{"Type": "bind", "Source": str(self.gate_path.parent.resolve()),
                   "Destination": "/run/nebulalog-storage-maintenance", "RW": False}]
        def inspected(argv, **kwargs):
            if argv[:2] == ["podman", "inspect"]:
                if "{{json .Config.Env}}" in argv: return json.dumps(environment)
                if "{{json .Mounts}}" in argv: return json.dumps(mounts)
                return running
            if argv[:4] == ["podman", "image", "inspect", "--format"]: return "sha256:" + "d" * 64
            return command(argv, **kwargs)
        inspected.capture, inspected.feed = command.capture, command.feed
        self.manager.cmd = inspected
        self.assertTrue(self.manager.storage_gate_aware_ingest())
        environment.clear()
        self.assertFalse(self.manager.storage_gate_aware_ingest())
        environment.append("STORAGE_MAINTENANCE_PATH=/run/nebulalog-storage-maintenance/gate.json")
        mounts[0]["RW"] = True
        self.assertFalse(self.manager.storage_gate_aware_ingest())
        mounts[0]["RW"] = False
        mounts.append({"Destination": "/run/nebulalog-storage-maintenance/gate.json"})
        self.assertFalse(self.manager.storage_gate_aware_ingest())
        mounts.pop()
        running = "e" * 64
        self.assertFalse(self.manager.storage_gate_aware_ingest())
        running = "d" * 64
        app["image"] = fixture.NEW
        atomic_json(self.manager.state / "current.json", {"components": {"nebulalog": app}})
        self.assertFalse(self.manager.storage_gate_aware_ingest())
        app["image"] = fixture.OLD
        atomic_json(self.manager.state / "current.json", {"components": {"nebulalog": app}})
        self.manager.backup(self.stage)
        self.assertNotIn(["systemctl", "stop", "nebulalog-ingest.service"], self.commands.calls)

    def test_unsettled_storage_barrier_never_backs_up_or_releases_hold(self):
        def pending(stage, **kwargs):
            self.gate(stage, **kwargs)
            raise Refused("unresolved insertion")
        self.manager.storage_maintenance.side_effect = pending
        with self.assertRaises(Refused): self.manager.backup(self.stage)
        self.assertFalse(any("pg_dump" in call for call in self.commands.calls))
        self.assertNotIn(("maintenance", False), self.events)
        self.assertTrue(json.loads(self.gate_path.read_text())["delivery_held"])

    def test_dump_failure_resumes_legacy_receiver_before_gate_release(self):
        self.commands.fail_dump = True
        with self.assertRaises(Refused): self.manager.backup(self.stage)
        self.assertEqual(self.commands.units["nebulalog-ingest.service"], "active")
        self.assertLess(self.events.index(("ready", "api")), self.events.index(("gate", False, False, False)))
        self.assertLess(self.events.index(("gate", False, False, False)), self.events.index(("maintenance", False)))

    def test_os_dump_failure_resumes_delivery_but_keeps_os_owned_storage_hold(self):
        self.commands.fail_dump = True
        with self.assertRaises(Refused): self.manager.backup(self.stage, os_backup=True)
        self.assertEqual(json.loads(self.gate_path.read_text()),
                         {"schema": 1, "held": True, "delivery_held": False, "operation": self.operation})
        self.assertEqual(self.commands.units["nebulalog-ingest.service"], "active")
        self.assertLess(self.events.index(("ready", "api")), self.events.index(("gate", True, False, False)))

    def failed_preactivation_backup(self):
        self.transaction["activation_started"] = False
        atomic_json(self.manager.state / "transaction.json", self.transaction)
        capture = self.commands.capture
        def interrupted(argv, target, **kwargs):
            if "--dbname=keycloak" in argv:
                raise OSError("interrupted second dump")
            return capture(argv, target, **kwargs)
        self.commands.capture = interrupted
        self.manager.api_ready.side_effect = Refused("writers not ready")
        with self.assertRaisesRegex(Refused, "writer recovery failed"):
            self.manager.backup(self.stage)
        self.commands.capture = capture
        self.manager.api_ready.side_effect = lambda: self.events.append(("ready", "api"))
        self.transaction["state"] = "rolling_back"
        atomic_json(self.manager.state / "transaction.json", self.transaction)
        self.assertFalse((self.stage / "adapter-backup.json").exists())

    def test_partial_backup_recovery_keeps_databases_and_partial_evidence(self):
        self.failed_preactivation_backup()
        partial = self.stage / "recovery/nebulalog.dump"
        before = partial.read_bytes()
        self.manager.checked_backup = Mock(side_effect=AssertionError("incomplete backup must never be used"))
        start = len(self.commands.calls)
        result = self.manager.rollback(self.stage)
        self.assertTrue(result["unchanged_runtime_recovered"])
        self.assertEqual(partial.read_bytes(), before)
        self.assertFalse((self.stage / "adapter-backup.json").exists())
        self.assertFalse(any(set(call) & {"dropdb", "createdb", "pg_restore"} for call in self.commands.calls[start:]))
        self.assertTrue(all(self.commands.units.get("nebulalog-" + name + ".service") == "active"
                            for name in self.manager.services))
        self.assertEqual(json.loads(self.gate_path.read_text()),
                         {"schema": 1, "held": True, "delivery_held": False, "operation": self.operation})
        self.assertNotIn(("maintenance", False), self.events)

    def test_partial_backup_recovery_still_refuses_unsettled_storage(self):
        self.failed_preactivation_backup()
        def unsettled(stage, **kwargs):
            result = self.gate(stage, **kwargs)
            if not kwargs.get("host_only"): raise Refused("unresolved INSERT")
            return result
        self.manager.storage_maintenance.side_effect = unsettled
        with self.assertRaisesRegex(Refused, "unresolved INSERT"): self.manager.rollback(self.stage)
        self.assertTrue(json.loads(self.gate_path.read_text())["delivery_held"])
        self.assertNotIn(("maintenance", False), self.events)
        self.manager.storage_maintenance.side_effect = self.gate
        self.assertTrue(self.manager.rollback(self.stage)["unchanged_runtime_recovered"])

    def test_preactivation_recovery_refuses_changed_runtime_before_effects(self):
        self.failed_preactivation_backup()
        for path in (self.secret, self.quadlets / "nebulalog-api.container",
                     self.stage / "adapter-backup-intent.json"):
            with self.subTest(path=path.name):
                before = path.read_bytes()
                path.write_bytes(before + (b" " if path.suffix == ".json" else b"changed"))
                if path.suffix == ".json":
                    value = json.loads(before); value["manifest_sha256"] = "f" * 64
                    atomic_json(path, value)
                count = len(self.commands.calls)
                with self.assertRaisesRegex(Refused, "Runtime changed"):
                    self.manager.rollback(self.stage)
                self.assertEqual(len(self.commands.calls), count)
                path.write_bytes(before)

    def test_preactivation_recovery_requires_false_flag_and_no_candidate_effects(self):
        self.failed_preactivation_backup()
        for value in (None, True, 0, "false"):
            with self.subTest(value=value):
                self.transaction["activation_started"] = value
                atomic_json(self.manager.state / "transaction.json", self.transaction)
                with self.assertRaisesRegex(Refused, "durable preactivation"):
                    self.manager.preactivation_recover(self.stage)
        self.transaction["activation_started"] = False
        atomic_json(self.manager.state / "transaction.json", self.transaction)
        for name in ("activate", "application-schema-intent", "database-restore-intent"):
            path = self.stage / ("adapter-" + name + ".json")
            atomic_json(path, {})
            with self.assertRaisesRegex(Refused, "Candidate effects"): self.manager.rollback(self.stage)
            path.unlink()

    def test_preactivation_recovery_refuses_directory_and_special_file_mode_drift(self):
        self.failed_preactivation_backup()
        for path in (self.config_dir, self.secret):
            with self.subTest(path=path.name):
                mode = path.stat().st_mode & 0o7777
                path.chmod(mode ^ 0o2000)
                before = len(self.commands.calls)
                with self.assertRaisesRegex(Refused, "Runtime changed"): self.manager.rollback(self.stage)
                self.assertEqual(len(self.commands.calls), before)
                path.chmod(mode)

    def test_preactivation_recovery_refuses_foreign_public_maintenance(self):
        self.failed_preactivation_backup()
        marker = self.root / "manager/maintenance.json"
        atomic_json(marker, {"active": True, "release": str(self.stage.parent / "other")})
        before = marker.read_bytes()
        with self.assertRaisesRegex(Refused, "Another operation"): self.manager.rollback(self.stage)
        self.assertEqual(marker.read_bytes(), before)

    def test_activation_refuses_preactivation_journal_before_any_runtime_effect(self):
        self.transaction["activation_started"] = False
        atomic_json(self.manager.state / "transaction.json", self.transaction)
        before = len(self.commands.calls)
        with self.assertRaisesRegex(Refused, "not durably authorized"): self.manager.activate(self.stage)
        self.assertEqual(len(self.commands.calls), before)

    def test_migration_acceptance_precedes_candidate_writers_and_destruction_stays_held(self):
        result = self.migration()
        self.assertEqual(result["migration"], ApplicationSchema.ADDITIVE_UPGRADE)
        self.assertEqual(self.manager.config["schema_revision"], "1")
        self.assertEqual(self.manager.application_schema_current()["revision"], "2")
        self.assertLess(self.events.index(("migrate", "2")), self.events.index(("start", ("clickhouse", "keycloak", "api", "ingest"))))
        self.assertEqual(json.loads(self.gate_path.read_text()),
                         {"schema": 1, "held": True, "delivery_held": False, "operation": self.operation})

    def test_failed_migration_does_not_start_candidate_writers(self):
        self.declaration()
        self.manager.backup(self.stage); self.manager.prepare(self.stage)
        self.manager.application_schema_migrate = Mock(side_effect=TimeoutError("lost acknowledgement"))
        with self.assertRaises(TimeoutError): self.manager.activate(self.stage)
        for name in ("api", "ingest", "keycloak"):
            self.assertEqual(self.commands.units["nebulalog-" + name + ".service"], "inactive")
        self.assertTrue(json.loads(self.gate_path.read_text())["delivery_held"])
        self.assertFalse((self.root / "manager/application-schema.json").exists())

    def test_immediate_rollback_fences_before_restore_and_clears_pointer_only_after_catalog(self):
        self.migration()
        self.events.clear()
        self.manager.rollback(self.stage)
        self.assertLess(self.events.index(("executor", "fenced")), self.events.index(("restored", "nebulalog")))
        self.assertEqual(self.manager.application_schema_current(), {"revision": "1", "state": None})
        self.assertTrue((self.stage / "adapter-database-restore-complete.json").exists())

    def test_crash_after_legacy_restore_before_pointer_removal_recovers(self):
        self.migration()
        restore = self.manager.application_schema_restore
        self.manager.application_schema_restore = Mock(side_effect=OSError("crash before pointer update"))
        with self.assertRaises(OSError): self.manager.rollback(self.stage)
        self.assertEqual(self.db_revision, "1")
        self.assertEqual(self.manager.application_schema_current()["revision"], "2")
        self.assertFalse((self.stage / "adapter-database-restore-complete.json").exists())
        self.manager.application_schema_restore = restore
        self.manager.rollback(self.stage)
        self.assertEqual(self.manager.application_schema_current()["revision"], "1")
        self.assertTrue((self.stage / "adapter-database-restore-complete.json").exists())

    def test_crash_after_drop_before_create_does_not_require_existing_database(self):
        self.migration()
        command = self.manager.cmd
        def drop_crash(argv, **kwargs):
            result = command(argv, **kwargs)
            if "dropdb" in argv and argv[-1] == "nebulalog":
                self.db_revision = None
                raise OSError("crash after drop")
            return result
        self.manager.cmd = drop_crash
        with self.assertRaises(OSError): self.manager.rollback(self.stage)
        self.assertIsNone(self.db_revision)
        self.manager.cmd = command
        self.manager.rollback(self.stage)
        self.assertEqual(self.manager.application_schema_current()["revision"], "1")

    def test_restore_retry_refuses_lost_continuous_host_hold(self):
        self.migration()
        self.manager.application_schema_restore = Mock(side_effect=OSError("interrupted"))
        with self.assertRaises(OSError): self.manager.rollback(self.stage)
        atomic_json(self.gate_path, {"schema": 1, "held": False, "delivery_held": False, "operation": None})
        before = len(self.commands.calls)
        with self.assertRaisesRegex(Refused, "continuous host hold"): self.manager.rollback(self.stage)
        self.assertEqual(len(self.commands.calls), before)

    def test_completed_restore_is_never_replayed_after_delivery_release_failure(self):
        self.migration()
        def fail_resume(stage, **kwargs):
            if kwargs.get("held") and not kwargs.get("delivery_held", False):
                raise OSError("crash before delivery resume")
            return self.gate(stage, **kwargs)
        self.manager.storage_maintenance.side_effect = fail_resume
        with self.assertRaises(OSError): self.manager.rollback(self.stage)
        drops = sum("dropdb" in call for call in self.commands.calls)
        self.assertTrue((self.stage / "adapter-database-restore-complete.json").exists())
        self.manager.storage_maintenance.side_effect = self.gate
        self.manager.rollback(self.stage)
        self.assertEqual(sum("dropdb" in call for call in self.commands.calls), drops)

    def test_historical_image_rollback_keeps_new_schema_and_current_data(self):
        self.migration()
        pointer = (self.root / "manager/application-schema.json").read_bytes()
        atomic_json(self.stage / "adapter-finalize.json", {"transaction_state": "committed"})
        self.secret.write_text("SYNTHETIC_SECRET=rotated\n")
        result = self.manager.rollback(self.stage)
        self.assertTrue(result["current_databases_preserved"])
        self.assertEqual((self.root / "manager/application-schema.json").read_bytes(), pointer)
        self.assertEqual(self.secret.read_text(), "SYNTHETIC_SECRET=rotated\n")
        self.assertFalse(any("dropdb" in call for call in self.commands.calls))
        change = self.manifest["components"]["nebulalog"]
        self.assertEqual(self.manager.application_schema_transition(change, "2"), "none")

    def test_altered_migration_receipt_refuses_current_schema(self):
        self.migration()
        atomic_json(self.stage / "adapter-application-schema.json", {"schema_revision": "2", "state": "different"})
        with self.assertRaisesRegex(Refused, "retained migration proof"):
            self.manager.application_schema_current()

    def test_empty_snapshot_cannot_fall_back_to_current_schema(self):
        with self.assertRaisesRegex(Refused, "Invalid retained"):
            self.manager.application_schema_check(self.stage, {})
        self.manager.application_schema_catalog.assert_not_called()

    def test_factory_schema_cannot_adopt_foreign_migration_marker(self):
        self.manager.config["schema_revision"] = "2"
        self.manager.application_schema_catalog.side_effect = None
        self.manager.application_schema_catalog.return_value = {"schema_revision": "2", "markers": [{"key": "foreign"}]}
        with self.assertRaisesRegex(Refused, "unowned migration provenance"):
            self.manager.application_schema_check(self.stage)
        self.assertFalse((self.root / "manager/application-schema.json").exists())

    def test_finalization_does_not_open_http_if_storage_release_fails(self):
        self.manager.backup(self.stage)
        self.transaction["state"] = "committed"
        atomic_json(self.manager.state / "transaction.json", self.transaction)
        atomic_json(self.stage / "adapter-health.json", {"ok": True, "checks": {key: True for key in REQUIRED_CHECKS}})
        self.manager.storage_maintenance.side_effect = Refused("unresolved insertion")
        with self.assertRaises(Refused): self.manager.finalize(self.stage)
        self.assertNotIn(("maintenance", False), self.events)
        self.assertFalse((self.stage / "adapter-finalize.json").exists())


if __name__ == "__main__": unittest.main()
