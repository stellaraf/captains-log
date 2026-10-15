"""Lifecycle sequencing/failure tests; native kernel/AIDE checks are separate."""
import json
import hashlib
from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import Mock, patch

import test_lifecycle as fixtures
from nebulalog_manager import kernel_updates
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.updates import REQUIRED_CHECKS


class KernelLifecycleTests(TestCase):
    os_reboot_fixture = fixtures.LifecycleTests.os_reboot_fixture
    os_postcheck_fixture = fixtures.LifecycleTests.os_postcheck_fixture
    os_recovery_fixture = fixtures.LifecycleTests.os_recovery_fixture
    interrupted_reboot_fixture = fixtures.LifecycleTests.interrupted_reboot_fixture
    reboot_preparation_fixture = fixtures.LifecycleTests.reboot_preparation_fixture

    def setUp(self):
        fixtures.LifecycleTests.setUp(self)
        self.kernel = "5.14.0-687.57.1.el9_8.x86_64"
        self.old = "5.14.0-687.56.1.el9_8.x86_64"
        self.calls = []
        self.manager._kernel_retain = Mock(return_value={"ok": True})
        self.boot = {}
        for name in ("arm_candidate", "abort_candidate", "verify_postboot", "commit_candidate", "accepted_transitions"):
            context = patch("nebulalog_adapters.lifecycle.kernel_boot." + name)
            self.boot[name] = context.start()
            self.addCleanup(context.stop)
        context = patch("nebulalog_adapters.lifecycle.kernel_updates.mark_complete")
        self.mark_complete = context.start()
        self.addCleanup(context.stop)
        context = patch("nebulalog_adapters.lifecycle.kernel_updates.read_acceptance", side_effect=self.read_acceptance, create=True)
        context.start()
        self.addCleanup(context.stop)
        context = patch("nebulalog_adapters.lifecycle.kernel_updates.record", side_effect=self.record)
        self.record_mock = context.start()
        self.addCleanup(context.stop)

    def tearDown(self):
        fixtures.LifecycleTests.tearDown(self)

    def record(self, stage, name, value):
        target = stage / name
        if target.exists() and json.loads(target.read_text()) != value:
            raise Refused("Immutable acceptance changed")
        target.write_bytes(kernel_updates.encode(value))

    def acceptance_path(self, stage):
        return stage / ("kernel-acceptance-" + self.manager.boot_id() + ".json")

    def read_acceptance(self, stage):
        pointer = json.loads((stage / "kernel-acceptance-current.json").read_text())
        path = stage / ("kernel-acceptance-" + pointer["boot_id"] + ".json")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), pointer["sha256"])
        return json.loads(path.read_text()), pointer["sha256"], path.name

    def candidate(self, stage):
        self.manager._kernel_candidate = Mock(return_value=(stage, {"kernel": self.kernel, "old_kernel": self.old}, "a" * 64, {}))
        self.boot["verify_postboot"].side_effect = lambda *args, **kwargs: self.calls.append("postboot") or {"ok": True, "outcome": "candidate"}
        self.manager.health.side_effect = lambda *args, **kwargs: self.calls.append("health") or {
            "ok": True, "checks": {name: True for name in REQUIRED_CHECKS}}
        self.boot["commit_candidate"].side_effect = lambda *args, **kwargs: self.calls.append("promote") or {"ok": True}
        self.proof = {"operation_sha256": "1" * 64, "kernel_plan_sha256": "2" * 64, "installed_sha256": "3" * 64,
                      "postboot_sha256": "4" * 64, "promotion_sha256": "5" * 64, "resume_sha256": None,
                      "kernel": self.kernel, "recovery_kernel": self.old, "boot_id": self.manager.boot_id()}
        self.boot["accepted_transitions"].return_value = self.proof
        self.mark_complete.side_effect = lambda *args, **kwargs: self.calls.append("clear-pending") or {"ok": True}

    def test_prepare_checks_candidate_unlock_before_stop_and_arms_after_sync(self):
        stage = self.reboot_preparation_fixture()
        self.candidate(stage)
        observed = []
        self.manager.unlock_readiness.side_effect = lambda candidate: observed.append("unlock") or {"token_test": True}
        self.manager.service.side_effect = lambda *args: observed.append("stop")
        self.manager.cmd = lambda *args, **kwargs: observed.append("sync") or ""
        self.boot["arm_candidate"].side_effect = lambda *args, **kwargs: observed.append("arm") or {"ok": True}
        with patch("nebulalog_adapters.lifecycle.local_auth", return_value=("synthetic", {})):
            self.manager.reboot_prepare()
        self.assertEqual(observed, ["unlock", "stop", "sync", "arm"])
        self.manager.unlock_readiness.assert_called_once_with("/boot/vmlinuz-" + self.kernel)

    def test_failed_arm_keeps_gate_and_does_not_claim_prepared(self):
        stage = self.reboot_preparation_fixture()
        self.candidate(stage)
        self.boot["arm_candidate"].side_effect = Refused("AIDE arm acceptance failed")
        with patch("nebulalog_adapters.lifecycle.local_auth", return_value=("synthetic", {})):
            with self.assertRaisesRegex(Refused, "AIDE arm"):
                self.manager.reboot_prepare()
        self.manager.maintenance.assert_called_once_with(True, stage)
        self.assertEqual(self.manager.service.call_args_list[-1].args, ("start", self.manager.services))
        self.assertEqual(json.loads((self.root / "manager/os-latest.json").read_text())["state"], "postcheck_passed")

    def test_abort_requires_owned_boot_restoration_before_service_restart(self):
        stage = self.os_reboot_fixture()
        self.manager.boot_id.return_value = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        self.candidate(stage)
        self.manager.service = Mock()
        self.boot["abort_candidate"].side_effect = Refused("unowned next_entry")
        with self.assertRaisesRegex(Refused, "unowned next_entry"):
            self.manager.reboot_abort()
        self.manager.service.assert_not_called()
        self.manager.health.assert_not_called()
        self.manager.maintenance.assert_not_called()

    def test_preparing_recovery_aborts_before_payload_acceptance_and_forces_reboot(self):
        stage, journal = self.interrupted_reboot_fixture()
        self.candidate(stage)
        self.boot["abort_candidate"].side_effect = lambda *args, **kwargs: self.calls.append("abort")
        self.os_integrity.side_effect = lambda *args, **kwargs: self.calls.append("integrity")
        result = self.manager.os_recover()
        self.assertEqual(self.calls, ["abort", "integrity", "health"])
        self.assertTrue(result["reboot_pending"])
        self.assertTrue(json.loads(journal.read_text())["reboot_pending"])

    def test_candidate_is_promoted_only_after_postboot_and_all_runtime_checks(self):
        stage = self.os_reboot_fixture()
        self.candidate(stage)
        journal = self.root / "manager/os-transaction.json"
        def gate(active, directory):
            if not active:
                self.assertEqual(json.loads(journal.read_text())["kernel_finalization"], "pending")
                self.assertFalse(self.acceptance_path(stage).exists())
                self.calls.append("release-gate")
        self.manager.maintenance.side_effect = gate
        def finish(directory, acceptance, **kwargs):
            self.assertEqual(json.loads(journal.read_text())["finalization"], "complete")
            self.assertEqual(json.loads(self.acceptance_path(stage).read_text()), acceptance)
            self.calls.append("clear-pending")
            return {"ok": True}
        self.mark_complete.side_effect = finish
        result = self.manager.reboot_complete()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.calls, ["postboot", "health", "promote", "release-gate", "clear-pending"])
        self.assertEqual(json.loads(journal.read_text())["kernel_finalization"], "complete")
        self.assertEqual(self.boot["commit_candidate"].call_args.kwargs["health"]["kernel"], self.kernel)

    def test_failed_runtime_check_never_promotes_accepts_or_clears_pending(self):
        stage = self.os_reboot_fixture()
        self.candidate(stage)
        self.manager.health.side_effect = None
        self.manager.health.return_value = {"ok": True, "checks": {key: key != "local_auth" for key in REQUIRED_CHECKS}}
        with self.assertRaisesRegex(Refused, "maintenance remains active"):
            self.manager.reboot_complete()
        self.boot["commit_candidate"].assert_not_called()
        self.mark_complete.assert_not_called()
        self.record_mock.assert_not_called()
        self.manager.maintenance.assert_called_once_with(True, stage)

    def test_recovery_kernel_boot_keeps_candidate_pending_and_never_accepts_it(self):
        stage = self.os_reboot_fixture()
        self.candidate(stage)
        self.boot["verify_postboot"].side_effect = None
        self.boot["verify_postboot"].return_value = {"ok": True, "outcome": "recovery"}
        result = self.manager.reboot_complete()
        self.assertEqual(result["status"], "kernel_recovery_required")
        self.assertTrue(result["reboot_pending"])
        self.boot["commit_candidate"].assert_not_called()
        self.mark_complete.assert_not_called()
        self.record_mock.assert_not_called()
        self.assertEqual(json.loads((self.root / "manager/os-transaction.json").read_text())["kernel_finalization"], "recovery_required")
        self.manager.maintenance.assert_called_with(False, stage)

    def test_pending_cleanup_failure_retries_same_immutable_acceptance(self):
        stage = self.os_reboot_fixture()
        self.candidate(stage)
        self.mark_complete.side_effect = [Refused("pending unlink failed"), {"ok": True}]
        with self.assertRaisesRegex(Refused, "acceptance finalization requires retry"):
            self.manager.reboot_complete()
        accepted = self.acceptance_path(stage).read_bytes()
        journal = self.root / "manager/os-transaction.json"
        self.assertEqual(json.loads(journal.read_text())["kernel_finalization"], "failed")
        self.manager.maintenance.assert_called_with(True, stage)
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")
        self.assertEqual(self.acceptance_path(stage).read_bytes(), accepted)
        self.assertEqual(self.mark_complete.call_count, 2)
        self.assertEqual(json.loads(journal.read_text())["kernel_finalization"], "complete")

    def test_power_loss_after_acceptance_cleanup_cannot_skip_finalization_retry(self):
        stage = self.os_reboot_fixture()
        self.candidate(stage)
        journal = self.root / "manager/os-transaction.json"
        real_atomic_json = atomic_json
        def power_loss(path, value):
            if path == journal and value.get("kernel_finalization") == "complete":
                raise SystemExit("power loss after pending cleanup")
            return real_atomic_json(path, value)
        with patch("nebulalog_adapters.lifecycle.atomic_json", side_effect=power_loss):
            with self.assertRaisesRegex(SystemExit, "power loss"):
                self.manager.reboot_complete()
        self.assertEqual(json.loads(journal.read_text())["kernel_finalization"], "pending")
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")
        self.assertEqual(self.mark_complete.call_count, 2)

    def test_current_boot_binding_is_rechecked_before_final_acceptance(self):
        stage = self.os_reboot_fixture()
        self.candidate(stage)
        self.proof["boot_id"] = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        with self.assertRaisesRegex(Refused, "acceptance finalization requires retry"):
            self.manager.reboot_complete()
        self.record_mock.assert_not_called()
        self.mark_complete.assert_not_called()
        self.manager.maintenance.assert_called_with(True, stage)

    def test_new_boot_finalization_preserves_original_acceptance_and_links_new_generation(self):
        stage = self.os_reboot_fixture()
        self.candidate(stage)
        self.mark_complete.side_effect = [Refused("cleanup interrupted"), {"ok": True}]
        with self.assertRaisesRegex(Refused, "acceptance finalization"):
            self.manager.reboot_complete()
        original = self.acceptance_path(stage)
        retained = original.read_bytes()
        original_pointer = json.loads((stage / "kernel-acceptance-current.json").read_text())
        self.manager.boot_id.return_value = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        self.proof = {**self.proof, "boot_id": self.manager.boot_id(), "resume_sha256": "6" * 64}
        self.boot["accepted_transitions"].return_value = self.proof
        result = self.manager.reboot_complete()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(original.read_bytes(), retained)
        resumed = json.loads(self.acceptance_path(stage).read_text())
        self.assertEqual(resumed["previous_acceptance_sha256"], original_pointer["sha256"])
        self.assertEqual(resumed["postboot_sha256"], json.loads(retained)["postboot_sha256"])
        self.assertEqual(resumed["promotion_sha256"], json.loads(retained)["promotion_sha256"])
        self.assertEqual(resumed["resume_sha256"], "6" * 64)
        self.assertEqual(json.loads((stage / "kernel-acceptance-current.json").read_text())["boot_id"], self.manager.boot_id())

    def test_power_loss_before_acceptance_pointer_can_publish_same_retained_generation(self):
        stage = self.os_reboot_fixture()
        self.candidate(stage)
        pointer = stage / "kernel-acceptance-current.json"
        real_atomic_json = atomic_json
        def power_loss(path, value):
            if path == pointer:
                raise SystemExit("power loss before acceptance pointer")
            return real_atomic_json(path, value)
        with patch("nebulalog_adapters.lifecycle.atomic_json", side_effect=power_loss):
            with self.assertRaisesRegex(SystemExit, "power loss"):
                self.manager.reboot_complete()
        self.assertFalse(pointer.exists())
        retained = self.acceptance_path(stage).read_bytes()
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")
        self.assertEqual(self.acceptance_path(stage).read_bytes(), retained)
        self.assertTrue(pointer.exists())

    def private_gate(self, active, stage):
        marker = self.root / "manager/maintenance.json"
        if active:
            atomic_json(marker, {"active": True, "release": str(stage)})
        elif marker.exists():
            marker.unlink()

    def test_stale_recovery_backup_refresh_never_releases_existing_gate(self):
        stage, journal = self.os_recovery_fixture()
        receipt_path = stage / "adapter-backup.json"
        receipt = json.loads(receipt_path.read_text())
        atomic_json(receipt_path, {**receipt, "observed_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()})
        original = (stage / "recovery/keycloak.dump").read_bytes()
        self.manager.maintenance.side_effect = self.private_gate
        self.private_gate(True, stage)
        latest_path = self.root / "manager/os-latest.json"
        latest, transaction, backup = self.manager._os_recovery_backup(stage, json.loads(latest_path.read_text()), json.loads(journal.read_text()))
        self.assertNotEqual(backup, stage)
        self.assertEqual(backup.parent, stage.parent)
        self.assertEqual(latest["recovery_backup_stage"], transaction["recovery_backup_stage"])
        self.assertEqual((stage / "recovery/keycloak.dump").read_bytes(), original)
        self.assertTrue((backup / "recovery/keycloak.dump").exists())
        self.assertTrue(all(call.args == (True, stage) for call in self.manager.maintenance.call_args_list))
        self.assertEqual(json.loads((self.root / "manager/maintenance.json").read_text())["release"], str(stage))

    def test_failed_retained_backup_preserves_gate_after_service_recovery(self):
        stage, _ = self.os_recovery_fixture()
        backup = stage.parent / "new-recovery"
        backup.mkdir()
        self.manager.maintenance.side_effect = self.private_gate
        self.private_gate(True, stage)
        self.commands.fail_dump = True
        with self.assertRaisesRegex(Refused, "synthetic dump failure"):
            self.manager.backup(backup, os_backup=True, retain_maintenance=True, maintenance_owner=stage)
        self.assertTrue(all(call.args == (True, stage) for call in self.manager.maintenance.call_args_list))
        self.assertTrue(json.loads((backup / "adapter-backup-recovery.json").read_text())["maintenance_retained"])

    def test_backup_refresh_reconciles_power_loss_between_journal_references(self):
        stage, journal = self.os_recovery_fixture()
        receipt_path = stage / "adapter-backup.json"
        receipt = json.loads(receipt_path.read_text())
        atomic_json(receipt_path, {**receipt, "observed_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()})
        self.manager.maintenance.side_effect = self.private_gate
        self.private_gate(True, stage)
        latest_path = self.root / "manager/os-latest.json"
        real_atomic_json = atomic_json
        def crash(path, value):
            if path == journal and value.get("recovery_backup_stage"):
                raise SystemExit("power loss between backup references")
            return real_atomic_json(path, value)
        with patch("nebulalog_adapters.lifecycle.atomic_json", side_effect=crash):
            with self.assertRaisesRegex(SystemExit, "power loss"):
                self.manager._os_recovery_backup(stage, json.loads(latest_path.read_text()), json.loads(journal.read_text()))
        self.assertNotIn("recovery_backup_stage", json.loads(journal.read_text()))
        retained_backup = json.loads(latest_path.read_text())["recovery_backup_stage"]
        latest, transaction, backup = self.manager._os_recovery_backup(stage, json.loads(latest_path.read_text()), json.loads(journal.read_text()))
        self.assertEqual(str(backup), retained_backup)
        self.assertEqual(latest["recovery_backup_stage"], transaction["recovery_backup_stage"])
        self.assertTrue(all(call.args == (True, stage) for call in self.manager.maintenance.call_args_list))

    def crossboot_fixture(self):
        stage, journal = self.os_recovery_fixture()
        self.candidate(stage)
        (stage / "kernel-plan.json").write_text("{}")
        self.manager.boot_id.return_value = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        self.manager.service = Mock()
        original_cmd = self.manager.cmd
        self.manager.cmd = lambda argv, **kwargs: self.old if argv == ["/usr/bin/uname", "-r"] else original_cmd(argv, **kwargs)
        for target, kwargs in (("kernel_updates.load_plan", {"return_value": ({"old_kernel": self.old}, "a" * 64)}),
                               ("kernel_updates.verify_preserved", {}),
                               ("security_status", {"return_value": {"host_controls_ok": True}})):
            context = patch("nebulalog_adapters.lifecycle." + target, **kwargs)
            context.start()
            self.addCleanup(context.stop)
        return stage, journal

    def test_crossboot_old_kernel_repair_keeps_original_operation_boot(self):
        stage, journal = self.crossboot_fixture()
        def accept(*args, **kwargs):
            for path in (journal, self.root / "manager/os-latest.json"):
                value = json.loads(path.read_text())
                self.assertEqual(value["boot_id"], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                self.assertEqual(value["recovery_boot_id"], self.manager.boot_id())
                self.assertIn("recovery_observed_at", value)
        self.os_integrity.side_effect = accept
        result = self.manager.os_recover()
        self.assertTrue(result["reboot_pending"])
        self.os_integrity.assert_called_once_with(stage, runner=self.manager.cmd)
        self.assertEqual(json.loads(journal.read_text())["boot_id"], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        self.assertFalse(any("rpm" in call[0] for call in self.commands.calls))

    def test_crossboot_repair_refuses_unexpected_running_kernel_before_acceptance(self):
        stage, journal = self.crossboot_fixture()
        self.manager.cmd = Mock(return_value=self.kernel)
        with self.assertRaisesRegex(Refused, "recovery evidence remain intact"):
            self.manager.os_recover()
        self.os_integrity.assert_not_called()
        self.manager.service.assert_not_called()
        self.assertNotIn("recovery_boot_id", json.loads(journal.read_text()))
        self.manager.maintenance.assert_called_once_with(True, stage)

    def test_crossboot_armed_transition_requires_boot_reconciliation(self):
        stage, _ = self.crossboot_fixture()
        (stage / "kernel-boot-current.json").write_text("{}")
        with self.assertRaisesRegex(Refused, "recovery evidence remain intact"):
            self.manager.os_recover()
        self.os_integrity.assert_not_called()
        self.manager.service.assert_not_called()

    def test_owned_arm_can_complete_new_boot_after_crash_before_latest_prepared_write(self):
        stage = self.reboot_preparation_fixture()
        (stage / "kernel-boot-current.json").write_text("{}")
        self.manager.boot_id.return_value = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        self.candidate(stage)
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")
        self.boot["verify_postboot"].assert_called_once()

    def retention_fixture(self):
        stage = self.os_reboot_fixture()
        self.candidate(stage)
        self.manager._kernel_finalize(stage, {name: True for name in REQUIRED_CHECKS})
        journal = self.root / "manager/os-transaction.json"
        transaction = {**json.loads(journal.read_text()), "state": "complete", "finalization": "complete", "kernel_finalization": "complete", "kernel_retention": "pending"}
        atomic_json(journal, transaction)
        latest = json.loads((self.root / "manager/os-latest.json").read_text())
        self.manager._kernel_retain = fixtures.Lifecycle._kernel_retain.__get__(self.manager)
        context = patch("nebulalog_adapters.lifecycle.kernel_integrity.checked_backup", side_effect=self.manager.checked_backup)
        context.start()
        self.addCleanup(context.stop)
        return stage, latest, transaction

    def test_retention_checks_current_acceptance_backup_and_health_before_and_after(self):
        stage, latest, transaction = self.retention_fixture()
        approved = []
        def retain(directory, *, accepted, runner):
            approved.append(accepted(directory))
            return {"ok": True, "status": "complete"}
        with patch("nebulalog_adapters.lifecycle.kernel_integrity.retain_three", side_effect=retain):
            self.manager._kernel_retain(stage, latest, transaction)
        self.assertEqual(approved[0]["kernel"], self.kernel)
        self.assertEqual(approved[0]["recovery_kernel"], self.old)
        self.assertEqual(self.manager.health.call_count, 2)
        self.manager.maintenance.assert_called_with(False, stage)
        self.assertEqual(json.loads((self.root / "manager/os-transaction.json").read_text())["kernel_retention"], "complete")

    def test_retention_health_failure_holds_gate_and_never_releases_failed_transaction(self):
        stage, latest, transaction = self.retention_fixture()
        self.manager.health.side_effect = None
        self.manager.health.return_value = {"ok": True, "checks": {name: name != "ingestion" for name in REQUIRED_CHECKS}}
        def retain(directory, *, accepted, runner):
            accepted(directory)
            self.fail("Retention cannot proceed after failed current health")
        with patch("nebulalog_adapters.lifecycle.kernel_integrity.retain_three", side_effect=retain):
            with self.assertRaisesRegex(Refused, "retention requires recovery"):
                self.manager._kernel_retain(stage, latest, transaction)
        self.assertTrue(all(call.args == (True, stage) for call in self.manager.maintenance.call_args_list))
        value = json.loads((self.root / "manager/os-transaction.json").read_text())
        self.assertEqual(value["kernel_retention"], "failed")
        self.assertEqual(value["finalization"], "failed")

    def test_same_boot_retention_retry_does_not_replay_boot_promotion(self):
        stage, _, _ = self.retention_fixture()
        with patch("nebulalog_adapters.lifecycle.kernel_integrity.retain_three", return_value={"ok": True}):
            result = self.manager.reboot_complete()
        self.assertEqual(result["status"], "complete")
        self.boot["verify_postboot"].assert_not_called()
        self.boot["commit_candidate"].assert_not_called()

    def later_retention_fixture(self):
        stage, latest, transaction = self.retention_fixture()
        old_path = self.acceptance_path(stage)
        self.original_acceptance = (old_path, old_path.read_bytes())
        self.old_acceptance_sha = hashlib.sha256(old_path.read_bytes()).hexdigest()
        self.manager.boot_id.return_value = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.proof = {**self.proof, 'boot_id': self.manager.boot_id(),
                      'resume_sha256': 'd' * 64, 'retention_integrity_sha256': 'e' * 64}
        self.boot['accepted_transitions'].return_value = self.proof
        self.calls.clear()
        self.manager.health.reset_mock()
        from nebulalog_manager import kernel_retention as retain
        (stage / retain.PLAN).write_text('{}')
        (stage / retain.INTENT).write_text('{}')
        original = {'boot_id': 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'operation_sha256': '1' * 64}
        self.recovered = {'ok': True, 'status': 'integrity_reconciled', 'release_accepted': False,
                          'compound_ref': {'filename': 'kernel-retention-resume-' + 'c' * 32 + '-result.json',
                                           'sha256': 'e' * 64}}
        def recover(directory, *, authorize, runner):
            self.assertEqual(directory, stage)
            value = authorize(directory, 'a' * 64)
            self.assertEqual(value['boot_id'], self.manager.boot_id())
            self.assertEqual(value['operation_sha256'], original['operation_sha256'])
            self.assertEqual(value['retention_plan_sha256'], 'a' * 64)
            self.assertEqual(value['backup_stage'], str(stage))
            self.calls.append('reconcile')
            return self.recovered
        def finish(directory, reference, *, accepted, runner):
            self.assertEqual(reference, self.recovered['compound_ref'])
            approved = accepted(directory)
            self.assertEqual(approved['boot_id'], self.manager.boot_id())
            self.assertTrue(self.acceptance_path(stage).exists())
            self.calls.append('finish')
            return {'ok': True, 'status': 'complete'}
        for name, kwargs in (
            ('kernel_retention.load_historical_plan', {'return_value': (original, 'a' * 64)}),
            ('kernel_retention_integration.recover_later_boot', {'side_effect': recover}),
            ('kernel_retention_integration.finish_later_boot', {'side_effect': finish}),
            ('kernel_integrity.retain_three', {'side_effect': AssertionError('must never replay erase')}),
        ):
            context = patch('nebulalog_adapters.lifecycle.' + name, **kwargs)
            mock = context.start(); self.addCleanup(context.stop)
            if name.endswith('recover_later_boot'): self.recover_later = mock
            if name.endswith('finish_later_boot'): self.finish_later = mock
        return stage

    def test_later_boot_retention_reconciles_before_health_acceptance_and_gate_release(self):
        stage = self.later_retention_fixture()
        def gate(active, directory):
            if not active:
                journal = json.loads((self.root / 'manager/os-transaction.json').read_text())
                self.assertEqual(journal['kernel_retention'], 'pending')
                self.assertEqual(journal['kernel_finalization'], 'complete')
                self.calls.append('release-gate')
        self.manager.maintenance.side_effect = gate
        self.assertEqual(self.manager.reboot_complete()['status'], 'complete')
        self.assertEqual(self.calls, ['reconcile', 'health', 'clear-pending', 'health', 'finish', 'health', 'release-gate'])
        accepted, _, _ = self.read_acceptance(stage)
        self.assertEqual(accepted['previous_acceptance_sha256'], self.old_acceptance_sha)
        self.assertEqual(accepted['retention_integrity_sha256'], 'e' * 64)
        self.assertEqual(self.original_acceptance[0].read_bytes(), self.original_acceptance[1])
        self.boot['verify_postboot'].assert_not_called()
        self.boot['commit_candidate'].assert_not_called()

    def test_later_boot_failed_health_never_finalizes_or_releases_maintenance(self):
        stage = self.later_retention_fixture()
        self.manager.health.side_effect = None
        self.manager.health.return_value = {'ok': True, 'checks': {name: name != 'ingestion' for name in REQUIRED_CHECKS}}
        with self.assertRaisesRegex(Refused, 'Later-boot kernel retention'):
            self.manager.reboot_complete()
        self.finish_later.assert_not_called()
        self.assertFalse(self.acceptance_path(stage).exists())
        self.assertTrue(all(call.args == (True, stage) for call in self.manager.maintenance.call_args_list))

    def test_later_boot_final_receipt_retry_does_not_fall_back_to_same_boot_erase(self):
        stage = self.later_retention_fixture()
        finish = self.finish_later.side_effect
        self.finish_later.side_effect = OSError('power loss before completion receipt')
        with self.assertRaises(Refused): self.manager.reboot_complete()
        new_bytes = self.acceptance_path(stage).read_bytes()
        self.finish_later.side_effect = finish
        self.assertEqual(self.manager.reboot_complete()['status'], 'complete')
        self.assertEqual(self.acceptance_path(stage).read_bytes(), new_bytes)
        self.assertEqual(self.original_acceptance[0].read_bytes(), self.original_acceptance[1])
        self.assertEqual(self.recover_later.call_count, 2)

    def test_later_boot_reconciliation_cannot_claim_release_acceptance(self):
        stage = self.later_retention_fixture()
        self.recovered['release_accepted'] = True
        with self.assertRaises(Refused): self.manager.reboot_complete()
        self.manager.health.assert_not_called()
        self.finish_later.assert_not_called()
        self.assertFalse(self.acceptance_path(stage).exists())

    def test_unattempted_old_boot_retention_plan_is_held_without_erase_or_recovery(self):
        stage = self.later_retention_fixture()
        from nebulalog_manager import kernel_retention as retain
        (stage / retain.INTENT).unlink()
        with self.assertRaisesRegex(Refused, 'Later-boot kernel retention') as caught:
            self.manager.reboot_complete()
        self.assertIn('new execution generation', str(caught.exception.__cause__))
        self.recover_later.assert_not_called()
        self.finish_later.assert_not_called()
        self.assertTrue(all(call.args == (True, stage) for call in self.manager.maintenance.call_args_list))

    def test_legacy_current_acceptance_preserves_its_missing_optional_field(self):
        stage, _, _ = self.retention_fixture()
        previous = self.acceptance_path(stage).read_bytes()
        self.boot['accepted_transitions'].return_value = {**self.proof, 'retention_integrity_sha256': None}
        self.manager._kernel_finalize(stage, {name: True for name in REQUIRED_CHECKS})
        self.assertEqual(self.acceptance_path(stage).read_bytes(), previous)
