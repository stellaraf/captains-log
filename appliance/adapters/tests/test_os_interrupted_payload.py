"""Unknown payload execution must not be treated as completed or cancelled.

Actual scheduler/adapter journals are exercised. Native package, backup, service
and integrity operations use existing injected fixtures; no native recovery
qualification is claimed by these tests.
"""
import hashlib
import json
from unittest import TestCase
from unittest.mock import patch

import test_lifecycle as lifecycle_fixtures
import test_os_updates as scheduler_fixtures
from nebulalog_manager.common import Refused, atomic_json


class SchedulerPayloadProcessLossTests(TestCase):
    setUp = scheduler_fixtures.OSMaintenanceTests.setUp
    runner = scheduler_fixtures.OSMaintenanceTests.runner
    run_maintenance = scheduler_fixtures.OSMaintenanceTests.run_maintenance

    def assert_held_without_replay(self):
        path = self.root / "os-transaction.json"
        before = path.read_bytes()
        retained = json.loads(before)
        self.assertEqual(retained["state"], "updating")
        self.assertIs(retained["payload_started"], True)
        self.assertNotIn("recovery_phase", retained)
        calls = list(self.calls)
        with patch("nebulalog_manager.os_payload.apply") as apply:
            with self.assertRaisesRegex(Refused, "requires recovery"):
                self.run_maintenance()
            apply.assert_not_called()
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.calls, calls)

    def test_process_loss_during_apply_retains_unknown_payload_and_blocks_next_run(self):
        with patch("nebulalog_manager.os_payload.apply", side_effect=SystemExit("process loss")):
            with self.assertRaises(SystemExit):
                self.run_maintenance()
        self.assert_held_without_replay()

    def test_process_loss_after_apply_before_postcheck_write_is_still_unknown(self):
        def interrupted_write(path, value):
            if path.name == "os-transaction.json" and value.get("state") == "postcheck":
                raise SystemExit("process loss before durable postcheck")
            atomic_json(path, value)

        with patch("nebulalog_manager.os_payload.apply", return_value={"ok": True}) as apply, \
                patch("nebulalog_manager.os_updates.atomic_json", side_effect=interrupted_write):
            with self.assertRaises(SystemExit):
                self.run_maintenance()
            apply.assert_called_once()
        self.assert_held_without_replay()


class InterruptedPayloadRecoveryTests(TestCase):
    setUp = lifecycle_fixtures.LifecycleTests.setUp
    tearDown = lifecycle_fixtures.LifecycleTests.tearDown
    os_postcheck_fixture = lifecycle_fixtures.LifecycleTests.os_postcheck_fixture

    def snapshot(self):
        return {str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.root.rglob("*") if path.is_file() and path.suffix != ".lock"}

    def prepare_interrupted(self):
        stage = self.os_postcheck_fixture()
        journal = self.root / "manager/os-transaction.json"
        transaction = json.loads(journal.read_text())
        atomic_json(journal, {**transaction, "state": "updating", "payload_started": True,
                             "plan_sha256": "a" * 64, "storage_maintenance": "held"})
        atomic_json(self.root / "manager/maintenance.json", {"active": True, "release": str(stage)})
        self.manager.storage_maintenance.reset_mock()
        return stage, journal

    def assert_recovery_refused_without_effects(self):
        before = self.snapshot()
        commands = list(self.commands.calls)
        with patch("nebulalog_adapters.lifecycle.os_payload.apply") as apply:
            with self.assertRaisesRegex(Refused, "exact retained same-boot"):
                self.manager.os_recover()
            apply.assert_not_called()
        self.os_integrity.assert_not_called()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_not_called()
        self.manager.storage_maintenance.assert_not_called()
        self.assertEqual(self.commands.calls, commands)
        self.assertEqual(self.snapshot(), before)

    def test_raw_updating_cannot_release_owned_holds_or_change_recovery_evidence(self):
        self.prepare_interrupted()
        self.assert_recovery_refused_without_effects()

    def test_result_files_do_not_establish_dispatch_quiescence(self):
        stage, _ = self.prepare_interrupted()
        # Apparent result files are not authority to widen recovery admission.
        # Native dispatch may still have descendants with future effects.
        for name in ("rpm-result.json", "kernel-installed.json", "adapter-os-postcheck.json"):
            atomic_json(stage / name, {"ok": True, "plan_sha256": "a" * 64})
        self.assert_recovery_refused_without_effects()

    def test_raw_updating_cannot_be_reclassified_as_preapply_by_a_false_flag(self):
        _, journal = self.prepare_interrupted()
        retained = json.loads(journal.read_text())
        for value in (False, None):
            with self.subTest(payload_started=value):
                changed = {**retained, "payload_started": value}
                if value is None:
                    changed.pop("payload_started")
                atomic_json(journal, changed)
                self.assert_recovery_refused_without_effects()
