"""Lifecycle ordering uses real journals/locks; kernel mechanisms have separate tests."""
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import test_lifecycle as fixtures
from nebulalog_adapters import lifecycle
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.updates import REQUIRED_CHECKS

OLD = "5.14.0-687.56.1.el9_8.x86_64"
NEW = "5.14.0-687.57.1.el9_8.x86_64"
BOOT = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


class KernelRecoveryLifecycleTests(unittest.TestCase):
    setUpBase = fixtures.LifecycleTests.setUp
    tearDown = fixtures.LifecycleTests.tearDown
    os_reboot_fixture = fixtures.LifecycleTests.os_reboot_fixture

    def setUp(self):
        self.setUpBase()
        self.stage = self.os_reboot_fixture()
        self.journal = self.root / "manager/os-transaction.json"
        self.latest = self.root / "manager/os-latest.json"
        transaction = json.loads(self.journal.read_text())
        atomic_json(self.journal, {**transaction, "state": "complete", "finalization": "complete",
            "kernel_outcome": "recovery", "kernel_finalization": "recovery_required", "kernel_retry": "held"})
        atomic_json(self.latest, {**json.loads(self.latest.read_text()), "state": "reboot_completed"})
        self.events = []
        self.fail_reboot = False
        self.manager.cmd = Mock(side_effect=self.command)
        self.manager.service = Mock(side_effect=lambda action, units: self.events.append(action))
        self.manager.unlock_readiness = Mock(return_value={"token_test": True})
        self.manager._os_recovery_backup = Mock(side_effect=lambda stage, latest, transaction: (latest, transaction, stage))
        self.proof = {"ok": True, "boot_id": BOOT, "kernel": NEW, "recovery_kernel": OLD}
        self.raw = lifecycle.kernel_boot._result_fields({"phase": "retry_arm", "boot_id": BOOT,
            "kernel": NEW, "old_kernel": OLD, "running_kernel": OLD, "operation_sha256": "a" * 64,
            "candidate_plan_sha256": "b" * 64, "installed_sha256": "c" * 64})
        self.recovery = {**self.raw, "phase": "postboot"}
        self.mockers = []
        def patched(target, **kwargs):
            context = patch(target, **kwargs); self.mockers.append(context)
            value = context.start(); self.addCleanup(context.stop); return value
        self.reconcile = patched("nebulalog_adapters.lifecycle.kernel_boot.reconcile_recovery", return_value=self.recovery)
        self.verified = patched("nebulalog_adapters.lifecycle.kernel_boot.verified_recovery", return_value=self.proof)
        self.status = patched("nebulalog_adapters.lifecycle.kernel_boot.candidate_status", return_value={"phase": "retry_arm"})
        self.abort = patched("nebulalog_adapters.lifecycle.kernel_boot.abort_candidate", side_effect=lambda *_a, **_k: self.events.append("abort"))
        self.arm = patched("nebulalog_adapters.lifecycle.kernel_boot.retry_candidate", side_effect=self.retry)
        self.backup = patched("nebulalog_adapters.lifecycle.kernel_integrity.checked_backup", return_value="d" * 64)
        patched("nebulalog_adapters.lifecycle.local_auth", return_value=("synthetic", {}))
        patched("nebulalog_adapters.lifecycle.kernel_updates.record", side_effect=self.record)

    def record(self, directory, name, value):
        path = directory / name
        if path.exists() and json.loads(path.read_text()) != value:
            raise Refused("immutable receipt changed")
        atomic_json(path, value)

    def command(self, argv, **_):
        if argv == ["/usr/bin/uname", "-r"]:
            return OLD
        self.events.append(tuple(argv))
        if argv == ["systemctl", "reboot"]:
            self.assertTrue((self.stage / "kernel-retry-request.json").exists())
            self.assertEqual(json.loads(self.journal.read_text())["state"], "reboot_requested")
            if self.fail_reboot:
                raise Refused("synthetic systemd failure")
        return ""

    def retry(self, directory, *, authorize, **_):
        self.assertEqual(directory, self.stage)
        authority = authorize(directory)
        self.assertEqual(authority, {"ok": True, "stage": str(self.stage), "boot_id": BOOT,
            "kernel": OLD, "checks": {name: True for name in REQUIRED_CHECKS},
            "backup_stage": str(self.stage), "backup_sha256": "d" * 64})
        self.events.append("arm")
        return {"ok": True, "status": "retry_armed", "attempt": 2, **self.raw}

    def test_retry_preserves_origin_and_records_request_before_reboot(self):
        original = json.loads(self.journal.read_text())["boot_id"]
        self.manager.storage_maintenance.side_effect = lambda owner, **flags: self.events.append(("storage", flags))
        result = self.manager.kernel_retry()
        self.assertEqual(result["status"], "reboot_requested")
        self.assertFalse(result["release_accepted"])
        self.assertEqual(json.loads(self.journal.read_text())["boot_id"], original)
        self.assertEqual(json.loads(self.latest.read_text())["boot_id"], original)
        self.assertLess(self.events.index("arm"), self.events.index("stop"))
        self.assertLess(self.events.index(("storage", {"held": True, "delivery_held": True})), self.events.index("stop"))
        self.assertLess(self.events.index("stop"), self.events.index(("systemctl", "reboot")))
        self.manager.maintenance.assert_called_with(True, self.stage)
        self.abort.assert_not_called()
        with self.assertRaisesRegex(Refused, "already requested"):
            self.manager.kernel_retry()
        self.arm.assert_called_once()
        self.assertEqual(self.events.count(("systemctl", "reboot")), 1)

    def test_failed_reboot_restores_owned_arm_and_old_runtime_without_rearming(self):
        self.fail_reboot = True
        with self.assertRaisesRegex(Refused, "old kernel and runtime were verified"):
            self.manager.kernel_retry()
        self.assertLess(self.events.index("abort"), self.events.index("start"))
        self.arm.assert_called_once()
        transaction = json.loads(self.journal.read_text())
        self.assertEqual(transaction["kernel_finalization"], "recovery_required")
        self.assertEqual(transaction["finalization"], "complete")
        self.assertEqual(transaction["storage_maintenance"], "held")
        self.manager.storage_maintenance.assert_called_with(self.stage, held=True, delivery_held=False)
        self.manager.maintenance.assert_called_with(False, self.stage)

    def test_failure_after_reservation_cancels_without_published_retry_arm(self):
        self.status.return_value = {"phase": "recovery_resume"}
        self.arm.side_effect = Refused("interrupted before pointer publication")
        with self.assertRaisesRegex(Refused, "old kernel and runtime were verified"):
            self.manager.kernel_retry()
        self.abort.assert_called_once()
        self.assertNotIn(("systemctl", "reboot"), self.events)
        self.manager.maintenance.assert_called_with(False, self.stage)

    def test_failed_recovery_health_keeps_gate_and_never_requests_reboot(self):
        self.manager.health.return_value = {"ok": False, "checks": {}}
        with self.assertRaisesRegex(Refused, "maintenance remains active"):
            self.manager.kernel_retry()
        self.arm.assert_not_called()
        self.assertNotIn(("systemctl", "reboot"), self.events)
        self.manager.maintenance.assert_called_with(True, self.stage)
        self.assertEqual(json.loads(self.journal.read_text())["state"], "recovery_required")

    def test_accepted_candidate_is_refused_before_mutating_journals(self):
        atomic_json(self.stage / "kernel-acceptance-current.json", {"synthetic": True})
        before = self.journal.read_bytes()
        self.manager.maintenance.reset_mock()
        with self.assertRaisesRegex(Refused, "unaccepted candidate"):
            self.manager.kernel_retry()
        self.assertEqual(self.journal.read_bytes(), before)
        self.manager.maintenance.assert_not_called()
        self.arm.assert_not_called()

    def test_foreign_authorization_and_wrong_running_kernel_refuse(self):
        with self.assertRaisesRegex(Refused, "exact current recovery boot"):
            self.manager._kernel_recovery_health(self.stage, NEW, BOOT)
        self.manager.health.assert_not_called()

    def rollback_fixture(self, *, historical_boot=False):
        from nebulalog_manager import kernel_rollback, kernel_updates
        completion = {"schema": 1, "status": "rolled_back", "boot_id":
                      "cccccccc-cccc-cccc-cccc-cccccccccccc" if historical_boot else BOOT,
                      "kernel": NEW, "recovery_kernel": OLD, "release_accepted": False}
        context = patch.object(lifecycle.kernel_boot, "prepare_rollback_recovery",
            side_effect=lambda *_a, **_k: (self.events.append("prepare_recovery") or self.recovery))
        self.rollback_recovery = context.start(); self.addCleanup(context.stop)
        def remove(directory, *, authorize, **_):
            self.assertEqual(directory, self.stage)
            authority = authorize(directory)
            self.assertEqual(authority["kernel"], OLD)
            self.assertEqual(authority["boot_id"], BOOT)
            self.assertEqual(authority["backup_sha256"], "d" * 64)
            self.events.append("remove")
            return {"ok": True, **completion}
        def finish(directory, result, health, **_):
            self.assertEqual(result, completion)
            self.assertEqual(health, {"ok": True, "stage": str(self.stage), "boot_id": BOOT,
                "kernel": OLD, "checks": {name: True for name in REQUIRED_CHECKS}})
            self.assertEqual(json.loads(self.journal.read_text())["kernel_rollback"], "pending")
            self.events.append("finish")
            return {"ok": True, "status": "rolled_back", "release_accepted": False}
        for owner, name, callback in [(kernel_rollback, "rollback", remove),
                                      (kernel_updates, "mark_rolled_back", finish)]:
            context = patch.object(owner, name, side_effect=callback)
            value = context.start(); self.addCleanup(context.stop)
            if name == "rollback": self.remove = value
            else: self.finish = value
        return kernel_rollback

    def test_rollback_records_verified_disposition_before_releasing_gate(self):
        self.rollback_fixture()
        self.manager.storage_maintenance.reset_mock()
        def barrier(owner, **flags):
            journal = json.loads(self.journal.read_text())
            self.assertEqual(owner, self.stage)
            self.assertEqual(journal["state"], "complete")
            self.assertEqual(journal["kernel_rollback"], "complete")
            self.assertEqual(journal["kernel_outcome"], "rolled_back")
            self.assertEqual(journal["health_boot_id"], BOOT)
            self.assertFalse(flags["held"])
            self.events.append("storage-release")
        self.manager.storage_maintenance.side_effect = barrier
        result = self.manager.kernel_rollback()
        self.assertEqual(result["status"], "rolled_back")
        self.assertFalse(result["release_accepted"])
        self.assertLess(self.events.index("prepare_recovery"), self.events.index("start"))
        self.assertLess(self.events.index("start"), self.events.index("remove"))
        self.assertLess(self.events.index("remove"), self.events.index("finish"))
        self.assertLess(self.events.index("finish"), self.events.index("storage-release"))
        journal = json.loads(self.journal.read_text())
        self.assertEqual(journal["kernel_finalization"], "complete")
        self.assertEqual(journal["kernel_rollback"], "complete")
        self.assertEqual(journal["finalization"], "complete")
        self.assertFalse(journal["reboot_pending"])
        self.manager.maintenance.assert_called_with(False, self.stage)

    def test_interrupted_rollback_routes_before_candidate_payload_verification(self):
        module = self.rollback_fixture(historical_boot=True)
        atomic_json(self.stage / module.INTENT, {"owned": True})
        journal = json.loads(self.journal.read_text())
        atomic_json(self.journal, {**journal, "kernel_rollback": "failed", "finalization": "failed"})
        self.status.side_effect = Refused("candidate files are already absent")
        result = self.manager.reboot_complete()
        self.assertEqual(result["status"], "rolled_back")
        self.status.assert_not_called()
        self.reconcile.assert_not_called()
        self.rollback_recovery.assert_not_called()
        self.finish.assert_called_once()
        self.manager.maintenance.assert_called_with(False, self.stage)

    def test_failed_rollback_integrity_retains_gate_and_never_marks_completion(self):
        self.rollback_fixture()
        self.remove.side_effect = Refused("unrelated protected file changed")
        with self.assertRaisesRegex(Refused, "maintenance and exact evidence are retained"):
            self.manager.kernel_rollback()
        self.finish.assert_not_called()
        self.manager.maintenance.assert_called_with(True, self.stage)
        journal = json.loads(self.journal.read_text())
        self.assertEqual(journal["kernel_rollback"], "failed")
        self.assertEqual(journal["state"], "recovery_required")

    def test_failed_post_removal_health_cannot_release_gate_or_clear_pending(self):
        self.rollback_fixture()
        self.manager.health.side_effect = [{"ok": True, "checks": {name: True for name in REQUIRED_CHECKS}},
                                           {"ok": False, "checks": {}}]
        with self.assertRaisesRegex(Refused, "maintenance and exact evidence are retained"):
            self.manager.kernel_rollback()
        self.remove.assert_called_once()
        self.finish.assert_not_called()
        self.manager.maintenance.assert_called_with(True, self.stage)

    def test_rollback_accepted_candidate_refused_before_any_mutation(self):
        self.rollback_fixture()
        atomic_json(self.stage / "kernel-acceptance-current.json", {"accepted": True})
        before = self.journal.read_bytes()
        self.manager.maintenance.reset_mock()
        with self.assertRaisesRegex(Refused, "unaccepted fallback candidate"):
            self.manager.kernel_rollback()
        self.assertEqual(self.journal.read_bytes(), before)
        self.manager.maintenance.assert_not_called()
        self.remove.assert_not_called()
