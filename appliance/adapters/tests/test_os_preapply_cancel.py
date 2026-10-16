"""Real coordinator/filesystem cancellation, with named native boundaries injected.

The final class retains the actual AIDE enrollment/history/report check; its
scanner subprocess and host measurements use the established private fixture.
"""
import copy
import hashlib
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

import test_lifecycle as fixtures
import test_aide_lifecycle as aide_fixture
import test_aide_updates as forward_fixture
from nebulalog_adapters import lifecycle
from nebulalog_manager import aide_updates
from nebulalog_manager.common import Refused, atomic_json, locked
from nebulalog_manager.updates import REQUIRED_CHECKS

BOOT = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
NEXT = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
CHECKS = {name: True for name in REQUIRED_CHECKS}
KERNEL = "5.14.0-687.57.1.el9_8.x86_64"


class PreapplyCancellationTests(TestCase):
    tearDown = fixtures.LifecycleTests.tearDown

    def setUp(self):
        fixtures.LifecycleTests.setUp(self)
        self.manager.boot_id = Mock(return_value=BOOT)
        self.manager.trusted_repositories = Mock(return_value=["baseos", "appstream"])
        self.manager.health = Mock(return_value={"ok": True, "checks": CHECKS})
        self.manager.service = Mock()
        self.manager.pg_ready = Mock()
        self.history = {"head": None, "database_sha256": "d" * 64, "original_enrollment": {"schema": 1}}
        self.aide = Mock()
        self.aide.guard.return_value.root = self.root
        self.aide.check_for_transaction.return_value = {"state": "clean", "exit_code": 0}
        self.packages = ["fixture-0:1-1.x86_64"]
        self.grub = {"kind": "file", "sha256": "e" * 64}
        for context in (
            patch.object(lifecycle.aide, "Aide", return_value=self.aide),
            patch.object(aide_updates, "accepted_plan_history", side_effect=lambda **_: copy.deepcopy(self.history)),
            patch.object(aide_updates, "_metadata", return_value={"xattrs_sha256": "f" * 64}),
            patch.object(lifecycle.os_payload, "inventory", side_effect=lambda _: ("fixture headers", [], list(self.packages))),
            patch.object(lifecycle.kernel_updates, "describe", side_effect=lambda _: copy.deepcopy(self.grub)),
            patch.object(lifecycle, "security_status", return_value={"host_controls_ok": True}),
            patch.object(lifecycle, "local_auth"),
        ):
            context.start(); self.addCleanup(context.stop)
        self.journal = self.root / "manager/os-transaction.json"
        self.latest = self.root / "manager/os-latest.json"
        atomic_json(self.journal, {"state": "preflight", "payload_started": False, "started_at": "fixed fixture"})

    def read(self):
        return json.loads(self.journal.read_text())

    def write(self, **details):
        value = {**self.read(), **details}
        atomic_json(self.journal, value)
        return value

    def interrupted(self, planning=False):
        def backup(stage, **kwargs):
            recovery = stage / "recovery"
            recovery.mkdir()
            (recovery / "nebulalog.dump").write_bytes(b"partial private dump")
            if not planning:
                raise SystemExit("hook interrupted during backup")
            return {"ok": True, "postgresql": True, "configuration": True}
        self.manager.backup = backup
        if planning:
            self.manager.os_preflight()
            self.write(state="recovery_required", recovery_phase="planning")
        else:
            with self.assertRaises(SystemExit):
                self.manager.os_preflight()
        self.stage = Path(self.read()["stage"])
        self.manager.checked_backup = Mock(side_effect=AssertionError("partial backup must never restore"))
        return self.stage

    def assert_no_release(self):
        self.assertFalse(any(call.kwargs.get("held") is False for call in self.manager.storage_maintenance.call_args_list))

    def test_partial_dump_cancel_preserves_bytes_and_terminal_precedes_storage_release(self):
        stage = self.interrupted()
        before = (stage / "recovery/nebulalog.dump").read_bytes()
        def barrier(owner, **flags):
            self.assertEqual(owner, stage)
            if flags["held"] is False:
                value = self.read()
                self.assertEqual((value["state"], value["status"], value["storage_maintenance"]),
                                 ("complete", "cancelled", "release_pending"))
                self.assertTrue((stage / "os-cancellation-complete.json").is_file())
        self.manager.storage_maintenance.side_effect = barrier
        result = self.manager.os_recover()
        self.assertEqual((result["status"], self.read()["finalization"]), ("cancelled", "complete"))
        self.assertEqual((stage / "recovery/nebulalog.dump").read_bytes(), before)
        self.manager.checked_backup.assert_not_called()
        self.manager.health.assert_called_once_with(stage, os_health=True)

    def test_inert_kernel_plan_and_private_downloads_are_preserved(self):
        stage = self.interrupted(planning=True)
        for name in ("operation.json", "kernel-plan.json", "kernel-inventory-before.xml", "os-integrity-plan.json"):
            (stage / name).write_text("retained inert fixture " + name)
        for name in ("kernel-packages", "kernel-keydb"):
            (stage / name).mkdir()
            (stage / name / "payload").write_bytes(b"private planning fixture")
        before = {str(path): path.read_bytes() for path in stage.rglob("*") if path.is_file()}
        self.manager.os_recover()
        for path, raw in before.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        self.assertFalse(self.read()["payload_started"])

    def test_owner_journal_publication_before_latest_is_recoverable_only_from_exact_predecessor(self):
        atomic_json(self.latest, {"stage": "previous terminal owner", "state": "postcheck_passed"})
        publish = lifecycle.atomic_json
        def crash(path, value):
            if path == self.latest and value.get("state") == "backup_preparing":
                raise SystemExit("before latest owner publication")
            return publish(path, value)
        self.manager.backup = Mock(side_effect=AssertionError("backup not yet entered"))
        with patch.object(lifecycle, "atomic_json", side_effect=crash), self.assertRaises(SystemExit):
            self.manager.os_preflight()
        self.assertEqual(self.manager.os_recover()["status"], "cancelled")
        self.manager.backup.assert_not_called()

    def test_foreign_latest_after_owner_publication_refuses(self):
        self.interrupted()
        atomic_json(self.latest, {"stage": "foreign owner"})
        with self.assertRaisesRegex(Refused, "foreign owner"):
            self.manager.os_recover()
        self.manager.service.assert_not_called()

    def test_any_actual_or_ambiguous_effect_evidence_refuses_before_service_actions(self):
        stage = self.interrupted(planning=True)
        for name in ("rpm-apply-intent.json", "rpm-result.json", "kernel-apply-intent.json", "kernel-rpm-command.json",
                     "kernel-deferred.json", "kernel-default-current.json", "kernel-installed.json",
                     "kernel-boot-current.json", "kernel-rollback-owner.json", "kernel-retention-plan.json"):
            with self.subTest(name=name):
                path = stage / name
                path.write_text("{}")
                with self.assertRaisesRegex(Refused, "execution evidence"):
                    self.manager.os_recover()
                path.unlink()
        self.manager.service.assert_not_called()
        self.assert_no_release()

    def test_explicit_payload_started_or_legacy_missing_flag_never_uses_cancellation(self):
        self.interrupted()
        for value in (True, None):
            self.write(payload_started=value)
            with self.assertRaises(Refused):
                self.manager.os_recover()
        self.manager.service.assert_not_called()

    def test_boot_package_grub_and_aide_chain_drift_refuse(self):
        self.interrupted()
        for target, key, changed in ((self.history, "database_sha256", "a" * 64), (self.grub, "sha256", "a" * 64)):
            previous = target[key]
            target[key] = changed
            with self.assertRaisesRegex(Refused, "Runtime|runtime"):
                self.manager.os_recover()
            target[key] = previous
        self.packages.append("unexpected-0:2-1.x86_64")
        with self.assertRaises(Refused):
            self.manager.os_recover()
        self.packages.pop()
        self.manager.boot_id.return_value = NEXT
        with self.assertRaises(Refused):
            self.manager.os_recover()
        self.manager.service.assert_not_called()

    def test_configuration_drift_refuses(self):
        self.interrupted()
        self.secret.write_text("changed private configuration")
        with self.assertRaises(Refused):
            self.manager.os_recover()
        self.assert_no_release()
        self.manager.service.assert_not_called()

    def test_pending_candidate_refuses_even_without_deferred_file(self):
        self.interrupted()
        atomic_json(self.root / "manager/kernel-pending.json", {"stage": "other"})
        with self.assertRaises(Refused):
            self.manager.os_recover()
        self.manager.service.assert_not_called()

    def test_new_kernel_planning_hint_without_any_attempt_can_be_cancelled(self):
        stage = self.interrupted(planning=True)
        (stage / "kernel-plan.json").write_text("retained unattempted plan fixture")
        self.write(reboot_pending=True, kernel_reboot_required=True)
        self.assertEqual(self.manager.os_recover()["status"], "cancelled")
        self.assertFalse(self.read()["reboot_pending"])

    def test_preexisting_reboot_obligation_cannot_be_cancelled(self):
        self.write(reboot_pending=True, prior_reboot_stage="earlier")
        self.interrupted()
        with self.assertRaisesRegex(Refused, "pending reboot"):
            self.manager.os_recover()
        self.manager.service.assert_not_called()

    def test_preflight_proof_tamper_and_missing_proof_refuse(self):
        stage = self.interrupted()
        path = stage / "os-preflight-intent.json"
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaises(Refused):
            self.manager.os_recover()
        path.unlink()
        with self.assertRaises(OSError):
            self.manager.os_recover()
        self.manager.service.assert_not_called()

    def test_living_preflight_executor_lock_prevents_cancellation(self):
        stage = self.interrupted()
        with locked(stage / "os-preflight.lock"), self.assertRaisesRegex(Refused, "already running"):
            self.manager.os_recover()
        self.manager.service.assert_not_called()

    def test_unknown_native_dispatch_keeps_hold_even_after_executor_lock_is_free(self):
        stage = self.interrupted()
        self.manager._os_command_event(stage, "dispatch", "call", argv=["systemctl", "stop", "fixed-fixture.service"])
        with self.assertRaisesRegex(Refused, "no successful completion"):
            self.manager.os_recover()
        self.manager.service.assert_not_called()
        self.assert_no_release()

    def test_terminal_cancellation_retry_cannot_bypass_unknown_command(self):
        stage = self.interrupted()
        def fail_clear(owner, **flags):
            if flags["held"] is False:
                raise Refused("lost clear acknowledgement")
        self.manager.storage_maintenance.side_effect = fail_clear
        with self.assertRaises(Refused):
            self.manager.os_recover()
        self.manager.storage_maintenance.side_effect = None
        self.manager.service.reset_mock()
        self.manager._os_command_event(stage, "dispatch", "call", argv=["systemctl", "start", "fixed-fixture.service"])
        with self.assertRaisesRegex(Refused, "no successful completion"):
            self.manager.os_recover()
        self.manager.service.assert_not_called()
        self.assertEqual(self.read()["finalization"], "failed")

    def test_failed_health_preserves_hold_and_retry_checks_health_again(self):
        self.interrupted()
        self.manager.health.return_value = {"ok": False, "checks": {}}
        with self.assertRaises(Refused):
            self.manager.os_recover()
        self.assertEqual(self.read()["recovery_phase"], "cancel_preapply")
        self.assert_no_release()
        self.manager.health.return_value = {"ok": True, "checks": CHECKS}
        self.manager.os_recover()
        self.assertEqual(self.manager.health.call_count, 2)

    def test_unknown_release_outcome_retries_same_intent_and_fresh_health(self):
        stage = self.interrupted()
        def fail_clear(owner, **flags):
            if flags["held"] is False:
                raise Refused("lost clear acknowledgement")
        self.manager.storage_maintenance.side_effect = fail_clear
        with self.assertRaises(Refused):
            self.manager.os_recover()
        self.assertEqual((self.read()["status"], self.read()["finalization"]), ("cancelled", "failed"))
        original = (stage / "os-cancellation-complete.json").read_bytes()
        self.manager.storage_maintenance.side_effect = None
        self.manager.os_recover()
        self.assertEqual((stage / "os-cancellation-complete.json").read_bytes(), original)
        self.assertEqual(self.manager.health.call_count, 2)

    def test_crash_after_release_before_final_journal_is_retryable(self):
        self.interrupted()
        publish = lifecycle.atomic_json
        def crash(path, value):
            if path == self.journal and value.get("finalization") == "complete":
                raise SystemExit("after gate clear")
            return publish(path, value)
        with patch.object(lifecycle, "atomic_json", side_effect=crash), self.assertRaises(SystemExit):
            self.manager.os_recover()
        self.assertEqual(self.read()["storage_maintenance"], "release_pending")
        self.manager.os_recover()
        self.assertEqual(self.read()["storage_maintenance"], "released")

    def test_crash_after_immutable_completion_before_terminal_journal_rechecks_health(self):
        stage = self.interrupted()
        record = self.manager._schema_record
        def crash(path, value):
            result = record(path, value)
            if path.name == "os-cancellation-complete.json":
                raise SystemExit("completion published before terminal journal")
            return result
        with patch.object(self.manager, "_schema_record", side_effect=crash), self.assertRaises(SystemExit):
            self.manager.os_recover()
        self.assertEqual(self.read()["state"], "recovery_required")
        self.assert_no_release()
        original = (stage / "os-cancellation-complete.json").read_bytes()
        self.manager.os_recover()
        self.assertEqual(self.manager.health.call_count, 2)
        self.assertEqual((stage / "os-cancellation-complete.json").read_bytes(), original)

    def test_drift_during_health_cannot_publish_cancellation_completion(self):
        stage = self.interrupted()
        def drift(*args, **kwargs):
            self.packages.append("late-drift-0:1-1.x86_64")
            return {"ok": True, "checks": CHECKS}
        self.manager.health.side_effect = drift
        with self.assertRaises(Refused):
            self.manager.os_recover()
        self.assertFalse((stage / "os-cancellation-complete.json").exists())
        self.assert_no_release()


class CancellationIntegrityTests(TestCase):
    for _name in ("write_private", "reader", "facts", "monitor", "fresh", "run_fixture", "enrolled"):
        locals()[_name] = getattr(aide_fixture.AideLifecycleTests, _name)

    def setUp(self):
        aide_fixture.AideLifecycleTests.setUp(self)
        self.enrolled()

    def test_plain_transaction_check_preserves_enrollment_database_and_acceptance_head(self):
        before = {path: path.read_bytes() for path in (self.marker, self.state / "aide.db.gz")}
        history = aide_updates.accepted_plan_history(manager=self.manager)
        with locked(self.root / "manager/transaction.lock") as descriptor:
            result = self.manager.check_for_transaction(descriptor)
        self.assertEqual((result["state"], result["exit_code"]), ("clean", 0))
        after = aide_updates.accepted_plan_history(manager=self.manager)
        self.assertEqual((history["head"], history["database_sha256"]), (after["head"], after["database_sha256"]))
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_unresolved_forward_without_preparation_is_not_unchanged_authority(self):
        authorized = self.state / "authorized"
        authorized.mkdir(mode=0o700)
        atomic_json(authorized / "pending.json", {"schema": 1, "state": "scanning", "id": BOOT,
            "prepared": {"id": NEXT, "sha256": "a" * 64}, "direction": "forward", "previous": None,
            "previous_database_sha256": "b" * 64})
        with self.assertRaises((Refused, OSError)):
            aide_updates.accepted_plan_history(manager=self.manager)

    def test_complete_cancellation_uses_actual_unchanged_aide_authority_and_check(self):
        configuration, quadlets = self.root / "configuration", self.root / "quadlets"
        configuration.mkdir(); quadlets.mkdir()
        (configuration / "settings").write_bytes(b"private configuration fixture")
        for name in ("api", "ingest", "postgresql", "clickhouse", "keycloak"):
            (quadlets / ("nebulalog-" + name + ".container")).write_text("[Container]\nImage=" + fixtures.OLD + "\n")
        commands = fixtures.Commands()
        adapter = lifecycle.Lifecycle({"schema_revision": "1"}, commands, state=self.root / "manager/updates",
            data=self.root, configuration=configuration, quadlets=quadlets, guard=lambda: None)
        for name in ("encrypted", "maintenance", "storage_maintenance", "service", "pg_ready", "application_schema_check"):
            setattr(adapter, name, Mock())
        adapter.boot_id = Mock(return_value=BOOT)
        adapter.trusted_repositories = Mock(return_value=["baseos", "appstream"])
        adapter.health = Mock(return_value={"ok": True, "checks": CHECKS})
        adapter.backup = Mock(side_effect=SystemExit("before backup completion"))
        journal = self.root / "manager/os-transaction.json"
        atomic_json(journal, {"state": "preflight", "payload_started": False})
        before = (self.state / "aide.db.gz").read_bytes()
        marker = self.marker.read_bytes()
        with patch.object(lifecycle.aide, "Aide", return_value=self.manager), \
             patch.object(aide_updates, "_metadata", return_value={"xattrs_sha256": "f" * 64}), \
             patch.object(lifecycle.os_payload, "inventory", return_value=("fixture", [], ["same package"])), \
             patch.object(lifecycle.kernel_updates, "describe", return_value={"sha256": "a" * 64}), \
             patch.object(lifecycle, "security_status", return_value={"host_controls_ok": True}), \
             patch.object(lifecycle, "trusted_file", side_effect=lambda path: path), \
             patch.object(lifecycle, "local_auth"):
            with self.assertRaises(SystemExit):
                adapter.os_preflight()
            self.assertEqual(adapter.os_recover()["status"], "cancelled")
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), before)
        self.assertEqual(self.marker.read_bytes(), marker)
        self.assertFalse((self.state / "authorized/pending.json").exists())
        self.assertEqual(json.loads(journal.read_text())["storage_maintenance"], "released")


class PreparedForwardCancellationTests(TestCase):
    for _name, _method in forward_fixture.AuthorizedAideTests.__dict__.items():
        if callable(_method) and not _name.startswith("test_"):
            locals()[_name] = _method

    def test_actual_prepared_pending_forward_cannot_supply_cancellation_authority(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError("interrupted forward scan")) if action == "update" else None
        with self.assertRaises(OSError):
            self.accept_update()
        with self.assertRaisesRegex(Refused, "history_pending_owner_required"):
            aide_updates.accepted_plan_history(manager=self.manager)
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)
