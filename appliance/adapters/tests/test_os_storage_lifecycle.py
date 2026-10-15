"""Real OS journals/coordinator; native health, package and storage barriers are injected.

The storage primitive has its own real PostgreSQL suite. These tests exercise
the callers' crash ordering and actual scheduler-to-adapter dispatch contract.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

import test_lifecycle as fixtures
from nebulalog_adapters import lifecycle
from nebulalog_manager import os_updates
from nebulalog_manager.common import CommandFailed, Refused, atomic_json
from nebulalog_manager.updates import REQUIRED_CHECKS

BOOT = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
NEXT = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
CHECKS = {name: True for name in REQUIRED_CHECKS}


class OSStorageLifecycleTests(TestCase):
    setUp = fixtures.LifecycleTests.setUp
    tearDown = fixtures.LifecycleTests.tearDown
    os_postcheck_fixture = fixtures.LifecycleTests.os_postcheck_fixture
    os_recovery_fixture = fixtures.LifecycleTests.os_recovery_fixture
    os_reboot_fixture = fixtures.LifecycleTests.os_reboot_fixture
    reboot_preparation_fixture = fixtures.LifecycleTests.reboot_preparation_fixture

    def read(self):
        return json.loads((self.root / "manager/os-transaction.json").read_text())

    def write(self, **changes):
        value = {**self.read(), **changes}
        atomic_json(self.root / "manager/os-transaction.json", value)
        return value

    def finalizing(self, reboot=False):
        stage = self.os_postcheck_fixture()
        self.write(state="complete", finalization="pending", reboot_pending=reboot,
                   health=CHECKS, health_boot_id=BOOT, recovery_phase="postcheck")
        self.manager.storage_maintenance.reset_mock()
        return stage

    def test_finalization_requires_fresh_health_and_durable_terminal_before_storage_release(self):
        stage = self.finalizing()
        def barrier(owner, **flags):
            value = self.read()
            self.assertEqual(owner, stage)
            self.assertEqual(value["state"], "complete")
            self.assertEqual(value["finalization"], "pending")
            self.assertEqual(value["health_boot_id"], BOOT)
            self.assertEqual(value["health"], CHECKS)
            self.manager.health.assert_called_once_with(stage, os_health=True)
            self.assertFalse(flags["held"])
            self.assertEqual(value["storage_maintenance"], "release_pending")
        self.manager.storage_maintenance.side_effect = barrier
        result = self.manager.os_postcheck()
        self.assertTrue(result["finalized"] and result["storage_released"])
        self.assertEqual(self.read()["storage_maintenance"], "released")

    def test_deferred_finalization_keeps_same_owner_with_delivery_allowed(self):
        stage = self.finalizing(True)
        result = self.manager.os_postcheck()
        self.assertTrue(result["finalized"])
        self.assertFalse(result["storage_released"])
        self.manager.storage_maintenance.assert_called_once_with(stage, held=True, delivery_held=False)
        self.assertEqual(self.read()["storage_maintenance"], "held")
        self.assertEqual(self.read()["finalization"], "complete")

    def test_new_reboot_hint_during_finalization_never_releases_storage(self):
        stage = self.finalizing()
        def command(argv, **kwargs):
            if argv[:2] == ["dnf", "needs-restarting"]:
                raise CommandFailed("dnf", 1)
            return self.commands(argv, **kwargs)
        self.manager.cmd = command
        self.assertFalse(self.manager.os_postcheck()["storage_released"])
        self.manager.storage_maintenance.assert_called_once_with(stage, held=True, delivery_held=False)

    def test_storage_clear_unknown_outcome_retains_retry_and_rechecks_health(self):
        stage = self.finalizing()
        self.manager.storage_maintenance.side_effect = Refused("lost acknowledgement")
        with self.assertRaisesRegex(Refused, "storage finalization requires retry"):
            self.manager.os_postcheck()
        self.assertEqual(self.read()["finalization"], "failed")
        self.assertEqual(self.read()["storage_maintenance"], "release_pending")
        self.manager.maintenance.assert_not_called()
        self.manager.storage_maintenance.side_effect = None
        self.manager.os_recover()
        self.assertEqual(self.manager.health.call_count, 2)
        self.assertEqual(self.read()["storage_maintenance"], "released")

    def test_crash_after_clear_before_final_journal_remains_recoverable(self):
        stage = self.finalizing()
        journal = self.root / "manager/os-transaction.json"
        def crash(path, value):
            if path == journal and value.get("finalization") == "complete":
                raise SystemExit("power loss")
            return atomic_json(path, value)
        with patch("nebulalog_adapters.lifecycle.atomic_json", side_effect=crash), self.assertRaises(SystemExit):
            self.manager.os_postcheck()
        self.assertEqual(self.read()["finalization"], "pending")
        self.assertEqual(self.read()["storage_maintenance"], "release_pending")
        self.manager.os_recover()
        self.assertEqual(self.read()["finalization"], "complete")
        self.assertEqual(self.manager.health.call_count, 2)

    def test_failed_fresh_health_never_releases_or_finalizes_storage(self):
        self.finalizing()
        self.manager.health.return_value = {"ok": False, "checks": CHECKS}
        with self.assertRaises(Refused):
            self.manager.os_postcheck()
        self.manager.storage_maintenance.assert_not_called()
        self.assertEqual(self.read()["finalization"], "pending")

    def test_foreign_http_owner_refused_before_storage_clear(self):
        self.finalizing()
        atomic_json(self.root / "manager/maintenance.json", {"active": True, "release": str(self.stage)})
        with self.assertRaises(Refused):
            self.manager.os_postcheck()
        self.manager.storage_maintenance.assert_not_called()
        self.manager.health.assert_not_called()

    def test_changed_boot_during_health_cannot_finalize(self):
        self.finalizing()
        self.manager.health.side_effect = lambda *a, **k: self.manager.boot_id.configure_mock(return_value=NEXT) or {"ok": True, "checks": CHECKS}
        with self.assertRaises(Refused):
            self.manager.os_postcheck()
        self.manager.storage_maintenance.assert_not_called()

    def test_reboot_delivery_hold_precedes_first_service_stop(self):
        stage = self.reboot_preparation_fixture()
        events = []
        self.manager.storage_maintenance.side_effect = lambda owner, **flags: events.append((owner, flags))
        self.manager.service.side_effect = lambda action, units: events.append(action)
        with patch("nebulalog_adapters.lifecycle.local_auth"):
            self.manager.reboot_prepare()
        self.assertEqual(events[0], (stage, {"held": True, "delivery_held": True}))
        self.assertEqual(events[1], "stop")

    def test_failed_storage_barrier_does_not_stop_services(self):
        self.reboot_preparation_fixture()
        self.manager.storage_maintenance.side_effect = Refused("in-flight delivery")
        with patch("nebulalog_adapters.lifecycle.local_auth"), self.assertRaises(Refused):
            self.manager.reboot_prepare()
        self.assertNotIn("stop", [call.args[0] for call in self.manager.service.call_args_list])

    def test_abort_health_keeps_purge_held_and_records_terminal_before_public_release(self):
        stage = self.os_reboot_fixture()
        self.manager.boot_id.return_value = BOOT
        self.manager.storage_maintenance.reset_mock()
        def barrier(owner, **flags):
            self.assertEqual(self.read()["state"], "reboot_aborted")
            self.assertTrue(self.read()["reboot_pending"])
            self.assertEqual(flags, {"held": True, "delivery_held": False})
        self.manager.storage_maintenance.side_effect = barrier
        self.assertTrue(self.manager.reboot_abort()["finalized"])
        self.assertEqual(self.read()["storage_maintenance"], "held")

    def test_actual_new_boot_releases_only_after_current_runtime_acceptance(self):
        stage = self.os_reboot_fixture()
        self.manager.storage_maintenance.reset_mock()
        def barrier(owner, **flags):
            self.assertEqual(self.read()["observed_boot_id"], NEXT)
            self.assertEqual(self.read()["health_boot_id"], NEXT)
            self.assertEqual(self.read()["state"], "complete")
            self.assertFalse(flags["held"])
        self.manager.storage_maintenance.side_effect = barrier
        self.manager.reboot_complete()
        self.assertEqual(self.read()["storage_maintenance"], "released")

    def test_aborted_finalization_failure_retries_fresh_health_without_service_or_rpm_replay(self):
        self.os_reboot_fixture()
        self.manager.boot_id.return_value = BOOT
        self.manager.storage_maintenance.side_effect = Refused("barrier acknowledgement lost")
        with self.assertRaises(Refused):
            self.manager.reboot_abort()
        self.assertEqual(self.read()["state"], "reboot_aborted")
        self.assertEqual(self.read()["finalization"], "failed")
        self.manager.storage_maintenance.side_effect = None
        self.manager.service = Mock(side_effect=AssertionError("service replay"))
        with patch("nebulalog_adapters.lifecycle.os_payload.accept_integrity", return_value={"ok": True}), \
             patch("nebulalog_adapters.lifecycle.os_payload.apply", side_effect=AssertionError("RPM replay")):
            self.manager.os_recover()
        self.assertEqual(self.read()["storage_maintenance"], "released")
        self.assertEqual(self.manager.health.call_count, 2)

    def test_aborted_finalization_crash_can_retry_after_another_failed_health_probe(self):
        self.os_reboot_fixture()
        self.manager.boot_id.return_value = BOOT
        journal = self.root / "manager/os-transaction.json"
        def crash(path, value):
            if path == journal and value.get("finalization") == "complete":
                raise SystemExit("crash")
            atomic_json(path, value)
        with patch("nebulalog_adapters.lifecycle.atomic_json", side_effect=crash), self.assertRaises(SystemExit):
            self.manager.reboot_abort()
        self.assertEqual(self.read()["finalization"], "pending")
        self.write(state="recovery_required", recovery_phase="reboot_abort")
        self.manager.health.return_value = {"ok": False, "checks": {}}
        with patch("nebulalog_adapters.lifecycle.os_payload.accept_integrity", return_value={"ok": True}):
            with self.assertRaises(Refused):
                self.manager.os_recover()
            self.manager.health.return_value = {"ok": True, "checks": CHECKS}
            self.manager.os_recover()
        self.assertEqual(self.read()["finalization"], "complete")

    def test_manual_later_boot_after_aborted_request_preserves_and_completes_exact_os_owner(self):
        self.os_reboot_fixture()
        self.manager.boot_id.return_value = BOOT
        self.manager.reboot_abort()
        self.manager.boot_id.return_value = NEXT
        self.manager._ordinary_boot_complete = Mock(side_effect=AssertionError("wrong owner"))
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")
        self.assertEqual(self.read()["storage_maintenance"], "released")

    def test_deferred_manual_new_boot_uses_os_owner_instead_of_ordinary_completion(self):
        self.os_reboot_fixture()
        self.write(state="complete", finalization="complete", storage_maintenance="held", reboot_pending=True,
                   health_boot_id=BOOT)
        path = self.root / "manager/os-latest.json"
        atomic_json(path, {**json.loads(path.read_text()), "state": "postcheck_passed"})
        self.manager._ordinary_boot_complete = Mock(side_effect=AssertionError("wrong boot owner"))
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")
        self.assertEqual(self.read()["storage_maintenance"], "released")

    def test_fresh_preflight_publishes_owner_before_backup_failure(self):
        self.manager.boot_id = Mock(return_value=BOOT)
        self.manager.trusted_repositories = Mock(return_value=["baseos"])
        atomic_json(self.root / "manager/os-transaction.json", {"state": "preflight"})
        def backup(stage, **flags):
            self.assertEqual(self.read()["stage"], str(stage))
            self.assertEqual(self.read()["storage_maintenance"], "held")
            raise SystemExit("backup interruption")
        self.manager.backup = backup
        with patch("nebulalog_adapters.lifecycle.security_status", return_value={"host_controls_ok": True}), \
             patch("nebulalog_adapters.lifecycle.local_auth"), self.assertRaises(SystemExit):
            self.manager.os_preflight()
        self.assertTrue(Path(self.read()["stage"]).is_dir())

    def test_scheduler_no_updates_runs_real_adapter_finalization(self):
        self.manager.boot_id = Mock(return_value=BOOT)
        self.manager.trusted_repositories = Mock(return_value=["baseos"])
        self.manager.health = Mock(return_value={"ok": True, "checks": CHECKS})
        state = self.root / "manager"
        atomic_json(state / "updates/transaction.json", {"state": "preflight_failed"})
        policy = self.root / "maintenance-policy.json"
        atomic_json(policy, {"automatic_os_updates": True, "timezone": "UTC"})
        calls = []
        def runner(argv, **kwargs):
            name = Path(argv[0]).name
            calls.append(name)
            if name == "update-os-preflight":
                return json.dumps(self.manager.os_preflight())
            if name == "update-os-postcheck":
                return json.dumps(self.manager.os_postcheck())
            return self.commands(argv, **kwargs)
        with patch("nebulalog_manager.os_updates.require_linux_root"), \
             patch("nebulalog_manager.os_updates.trusted_file", side_effect=lambda p: p), \
             patch("nebulalog_manager.os_updates.status", return_value={"host_controls_ok": True}), \
             patch("nebulalog_manager.os_updates.in_maintenance_window", return_value=True), \
             patch("nebulalog_adapters.lifecycle.security_status", return_value={"host_controls_ok": True}), \
             patch("nebulalog_adapters.lifecycle.local_auth"), \
             patch("nebulalog_manager.os_payload.prepare", return_value={"status": "no_updates"}), \
             patch("nebulalog_manager.os_payload.accept_integrity", return_value={"ok": True}), \
             patch("nebulalog_manager.os_payload.apply") as apply:
            result = os_updates.maintain(policy, state=state, runner=runner)
        self.assertEqual(result, {"status": "no_updates", "reboot_pending": False})
        self.assertEqual(self.read()["finalization"], "complete")
        self.assertEqual(self.read()["storage_maintenance"], "released")
        self.assertEqual(calls.count("update-os-postcheck"), 2)
        self.assertEqual(self.manager.health.call_count, 2)
        apply.assert_not_called()
