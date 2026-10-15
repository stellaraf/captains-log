from datetime import datetime, timezone
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from nebulalog_manager.common import CommandFailed, Refused, atomic_json
from nebulalog_manager.os_updates import maintain
from nebulalog_manager.updates import REQUIRED_CHECKS


class OSMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.policy=self.root/"maintenance-policy.json"
        atomic_json(self.policy,{"automatic_os_updates":True,"timezone":"UTC"})
        self.calls=[]
        self.reboot_fails=False
        self.abort_fails=False
        self.abort_incomplete=False
        self.reboot_needed=True
        self.postcheck_checks={name:True for name in REQUIRED_CHECKS}
        self.preflight_stage=str(self.root / "os-updates/one")
        self.postcheck_stage=self.preflight_stage
        self.patches=[patch("nebulalog_manager.os_updates.require_linux_root"),
                      patch("nebulalog_manager.os_updates.trusted_file",side_effect=lambda path:path),
                      patch("nebulalog_manager.os_updates.status",return_value={"host_controls_ok":True}),
                      patch("nebulalog_manager.os_updates.in_maintenance_window",return_value=True),
                      patch("nebulalog_manager.os_payload.prepare", return_value={"ok": True, "plan_sha256": "a"*64}),
                      patch("nebulalog_manager.os_payload.apply", return_value={"ok": True})]
        for item in self.patches:item.start();self.addCleanup(item.stop)

    def runner(self,argv,**kwargs):
        self.calls.append(argv)
        name=Path(argv[0]).name
        if name=="update-os-preflight":return json.dumps({"ok":True,"postgresql":True,"configuration":True,"stage":self.preflight_stage,"boot_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})
        if name=="update-os-postcheck":
            path = self.root / "os-transaction.json"
            transaction = json.loads(path.read_text())
            finalizing = transaction["state"] == "complete" and transaction.get("finalization") == "pending"
            released = finalizing and not transaction.get("reboot_pending")
            if finalizing:
                atomic_json(path, {**transaction, "finalization": "complete",
                                  "storage_maintenance": "released" if released else "held"})
            return json.dumps({"ok":True,"stage":self.postcheck_stage,"checks":self.postcheck_checks,
                "boot_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "finalized":finalizing,"storage_released":released})
        if name=="update-reboot-prepare":return json.dumps({"ok":True,"boot_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})
        if name=="update-reboot-abort":
            if self.abort_fails:raise Refused("simulated failed service restore")
            path = self.root / "os-transaction.json"
            atomic_json(path, {**json.loads(path.read_text()), "state": "reboot_aborted", "finalization": "complete", "storage_maintenance": "held"})
            return json.dumps({"ok":True,"recovered":True,"health":{} if self.abort_incomplete else {name:True for name in REQUIRED_CHECKS},
                "boot_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "finalized":True,"storage_released":False})
        if argv==["dnf","needs-restarting","--reboothint"] and self.reboot_needed:raise CommandFailed("dnf",1)
        if argv==["systemctl","reboot"] and self.reboot_fails:raise Refused("simulated rejected reboot")
        return ""

    def run_maintenance(self):
        return maintain(self.policy,self.root,runner=self.runner,now=datetime(2026,9,6,3,30,tzinfo=timezone.utc))

    def test_livepatch_recovery_prevents_os_hooks_and_package_mutation(self):
        with patch('nebulalog_manager.os_updates.livepatch.require_settled',
                   side_effect=Refused('Livepatch recovery')) as gate:
            with self.assertRaisesRegex(Refused, 'Livepatch recovery'):
                self.run_maintenance()
        gate.assert_called_once_with(self.root / 'updates')
        self.assertEqual(self.calls, [])
        self.assertFalse((self.root / 'os-transaction.json').exists())

    def test_kernel_finalization_or_retention_blocks_new_maintenance(self):
        for field in ('kernel_finalization', 'kernel_retention', 'kernel_rollback'):
            for status in ('pending', 'failed', 'recovery_required', 'unknown'):
                with self.subTest(field=field, status=status):
                    atomic_json(self.root / 'os-transaction.json', {'state': 'complete', 'finalization': 'complete', field: status})
                    with self.assertRaisesRegex(Refused, 'requires recovery'):
                        self.run_maintenance()
        self.assertEqual(self.calls, [])

    def test_unqualified_package_plan_refuses_before_any_package_application(self):
        with patch("nebulalog_manager.os_payload.prepare", side_effect=Refused("unsupported scriptlet")), \
             patch("nebulalog_manager.os_payload.apply") as apply:
            with self.assertRaisesRegex(Refused, "unsupported scriptlet"):self.run_maintenance()
            apply.assert_not_called()
        self.assertEqual(json.loads((self.root/"os-transaction.json").read_text())["state"], "recovery_required")
        self.assertNotIn(["systemctl", "reboot"], self.calls)

    def test_no_updates_does_not_apply_packages_or_request_reboot(self):
        self.reboot_needed=False
        with patch("nebulalog_manager.os_payload.prepare", return_value={"ok": True, "status": "no_updates", "plan_sha256": None}), \
             patch("nebulalog_manager.os_payload.apply") as apply:
            self.assertEqual(self.run_maintenance(), {"status": "no_updates", "reboot_pending": False})
            apply.assert_not_called()
        self.assertEqual(json.loads((self.root/"os-transaction.json").read_text())["state"], "complete")
        self.assertNotIn(["systemctl", "reboot"], self.calls)
        self.assertEqual(self.calls.count(["/usr/libexec/nebulalog/update-os-postcheck"]), 2)
        self.assertEqual(json.loads((self.root/"os-transaction.json").read_text())["storage_maintenance"], "released")

    def test_terminal_record_without_explicit_finalized_ack_cannot_report_success(self):
        self.reboot_needed = False
        def runner(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if Path(argv[0]).name == "update-os-postcheck":
                value = json.loads(result)
                value.pop("finalized", None)
                return json.dumps(value)
            return result
        with self.assertRaisesRegex(Refused, "explicitly finalize"):
            maintain(self.policy, self.root, runner=runner)
        transaction = json.loads((self.root / "os-transaction.json").read_text())
        self.assertEqual(transaction["state"], "complete")
        self.assertEqual(transaction["finalization"], "failed")

    def test_finalized_ack_requires_matching_durable_state(self):
        self.reboot_needed = False
        def runner(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if Path(argv[0]).name == "update-os-postcheck" and json.loads(result).get("finalized"):
                path = self.root / "os-transaction.json"
                atomic_json(path, {**json.loads(path.read_text()), "storage_maintenance": "held"})
            return result
        with self.assertRaisesRegex(Refused, "matching durable disposition"):
            maintain(self.policy, self.root, runner=runner)
        self.assertEqual(json.loads((self.root / "os-transaction.json").read_text())["finalization"], "failed")

    def test_wrong_boot_health_is_rejected_even_with_all_checks_true(self):
        def runner(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if Path(argv[0]).name == "update-os-postcheck":
                return json.dumps({**json.loads(result), "boot_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"})
            return result
        with self.assertRaisesRegex(Refused, "operation-bound"):
            maintain(self.policy, self.root, runner=runner)
        self.assertNotIn(["systemctl", "reboot"], self.calls)

    def test_adapter_refreshed_backup_reference_survives_scheduler_records(self):
        self.reboot_needed = False
        refreshed = self.preflight_stage + "-backup"
        def runner(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if Path(argv[0]).name == "update-os-postcheck":
                path = self.root / "os-transaction.json"
                atomic_json(path, {**json.loads(path.read_text()), "recovery_backup_stage": refreshed})
            return result
        self.assertEqual(maintain(self.policy, self.root, runner=runner)["status"], "updated")
        self.assertEqual(json.loads((self.root / "os-transaction.json").read_text())["recovery_backup_stage"], refreshed)

    def test_kernel_candidate_forces_reboot_despite_negative_generic_hint(self):
        self.reboot_needed = False
        for status in ('planned', 'kernel_pending'):
            with self.subTest(status=status):
                (self.root / 'os-transaction.json').unlink(missing_ok=True)
                self.calls.clear()
                with patch('nebulalog_manager.os_payload.prepare', return_value={
                        'ok': True, 'status': status, 'plan_sha256': 'a' * 64, 'reboot_required': True}):
                    self.assertEqual(self.run_maintenance(), {'status': 'reboot_requested'})
                journal = json.loads((self.root / 'os-transaction.json').read_text())
                self.assertTrue(journal['reboot_pending'])
                self.assertTrue(journal['kernel_reboot_required'])
                self.assertIn(['systemctl', 'reboot'], self.calls)

    def test_kernel_candidate_stays_pending_when_window_closes(self):
        self.reboot_needed = False
        with patch('nebulalog_manager.os_payload.prepare', return_value={
                'ok': True, 'status': 'kernel_pending', 'plan_sha256': 'a' * 64, 'reboot_required': True}), \
             patch('nebulalog_manager.os_updates.in_maintenance_window', side_effect=[True, False]):
            self.assertEqual(self.run_maintenance(), {'status': 'updated', 'reboot_pending': True})
        self.assertNotIn(['systemctl', 'reboot'], self.calls)

    def test_next_window_retries_deferred_reboot_under_original_owner_without_replanning(self):
        with patch("nebulalog_manager.os_updates.in_maintenance_window", side_effect=[True, False]):
            self.assertEqual(self.run_maintenance(), {"status": "updated", "reboot_pending": True})
        previous_stage=self.preflight_stage
        self.calls.clear()
        with patch("nebulalog_manager.os_payload.prepare") as prepare, \
             patch("nebulalog_manager.os_payload.apply") as apply:
            self.assertEqual(self.run_maintenance(), {"status": "reboot_requested"})
            apply.assert_not_called()
            prepare.assert_not_called()
        journal=json.loads((self.root / "os-transaction.json").read_text())
        self.assertNotIn("prior_reboot_stage", journal)
        self.assertEqual(journal["stage"], previous_stage)
        self.assertTrue(journal["resuming_deferred"])
        self.assertNotIn(["/usr/libexec/nebulalog/update-os-preflight"], self.calls)
        self.assertTrue(journal["reboot_pending"])
        self.assertIn(["/usr/libexec/nebulalog/update-os-postcheck"], self.calls)
        self.assertLess(self.calls.index(["/usr/libexec/nebulalog/update-os-postcheck"]),
                        self.calls.index(["/usr/libexec/nebulalog/update-reboot-prepare"]))

    def test_no_packages_still_observes_reboot_hint_and_rechecks_window(self):
        with patch("nebulalog_manager.os_payload.prepare", return_value={"ok": True, "status": "no_updates", "plan_sha256": None}), \
             patch("nebulalog_manager.os_updates.in_maintenance_window", side_effect=[True, False]), \
             patch("nebulalog_manager.os_payload.apply") as apply:
            self.assertEqual(self.run_maintenance(), {"status": "no_updates", "reboot_pending": True})
            apply.assert_not_called()
        self.assertNotIn(["systemctl", "reboot"], self.calls)
        self.assertIn(["/usr/libexec/nebulalog/update-os-postcheck"], self.calls)

    def test_failed_replanning_preserves_previously_pending_reboot(self):
        for failure in (CommandFailed("dnf", 1), Refused("unsupported scriptlet")):
            with self.subTest(failure=failure):
                atomic_json(self.root / "os-transaction.json", {"state": "complete", "stage": "/previous", "reboot_pending": True})
                with patch("nebulalog_manager.os_payload.prepare", side_effect=failure), self.assertRaises(Refused):
                    self.run_maintenance()
                journal=json.loads((self.root / "os-transaction.json").read_text())
                self.assertTrue(journal["reboot_pending"])
                self.assertEqual(journal["prior_reboot_stage"], "/previous")

    def test_unknown_no_packages_reboot_hint_cannot_clear_pending_reboot(self):
        atomic_json(self.root / "os-transaction.json", {"state": "complete", "reboot_pending": True})
        def runner(argv, **kwargs):
            if argv == ["dnf", "needs-restarting", "--reboothint"]:
                raise CommandFailed("dnf", 2)
            return self.runner(argv, **kwargs)
        with patch("nebulalog_manager.os_payload.prepare", return_value={"status": "no_updates"}):
            with self.assertRaisesRegex(Refused, "Cannot determine"):
                maintain(self.policy, self.root, runner=runner)
        self.assertTrue(json.loads((self.root / "os-transaction.json").read_text())["reboot_pending"])
        self.assertNotIn(["systemctl", "reboot"], self.calls)

    def test_no_packages_reboot_requires_every_runtime_check(self):
        for name in REQUIRED_CHECKS:
            with self.subTest(check=name):
                atomic_json(self.root / "os-transaction.json", {"state": "complete", "reboot_pending": True})
                self.calls.clear()
                self.postcheck_checks={key:key != name for key in REQUIRED_CHECKS}
                with patch("nebulalog_manager.os_payload.prepare", return_value={"status": "no_updates"}), self.assertRaises(Refused):
                    self.run_maintenance()
                journal=json.loads((self.root / "os-transaction.json").read_text())
                self.assertEqual(journal["state"], "recovery_required")
                self.assertTrue(journal["reboot_pending"])
                self.assertNotIn(["systemctl", "reboot"], self.calls)

    def test_pending_reboot_clears_only_after_fresh_health_and_negative_hint(self):
        atomic_json(self.root / "os-transaction.json", {"state": "complete", "reboot_pending": True})
        self.reboot_needed=False
        self.postcheck_checks["local_auth"]=False
        with patch("nebulalog_manager.os_payload.prepare", return_value={"status": "no_updates"}), self.assertRaises(Refused):
            self.run_maintenance()
        self.assertTrue(json.loads((self.root / "os-transaction.json").read_text())["reboot_pending"])
        atomic_json(self.root / "os-transaction.json", {"state": "complete", "reboot_pending": True})
        self.postcheck_checks["local_auth"]=True
        with patch("nebulalog_manager.os_payload.prepare", return_value={"status": "no_updates"}):
            self.assertEqual(self.run_maintenance(), {"status": "no_updates", "reboot_pending": False})
        self.assertIn(["/usr/libexec/nebulalog/update-os-postcheck"], self.calls)
        self.assertNotIn(["systemctl", "reboot"], self.calls)

    def test_successful_reboot_request_is_not_misreported_as_verified_reboot(self):
        self.assertEqual(self.run_maintenance()["status"],"reboot_requested")
        journal=json.loads((self.root/"os-transaction.json").read_text())
        self.assertEqual(journal["state"],"reboot_requested")
        self.assertIn("boot_id",journal)

    def test_interrupted_reboot_preparation_retains_same_boot_recovery_state(self):
        def runner(argv, **kwargs):
            if Path(argv[0]).name == "update-reboot-prepare":
                raise KeyboardInterrupt()
            return self.runner(argv, **kwargs)
        with self.assertRaises(KeyboardInterrupt):
            maintain(self.policy, self.root, runner=runner)
        journal=json.loads((self.root / "os-transaction.json").read_text())
        self.assertEqual(journal["state"], "reboot_preparing")
        self.assertTrue(journal["reboot_pending"])
        self.assertEqual(journal["health"], {name:True for name in REQUIRED_CHECKS})
        self.assertEqual(journal["stage"], self.preflight_stage)
        self.assertNotIn(["systemctl", "reboot"], self.calls)
        with self.assertRaisesRegex(Refused, "requires recovery"):
            self.run_maintenance()

    def test_failed_reboot_request_restarts_and_verifies_owned_services(self):
        self.reboot_fails=True
        with self.assertRaisesRegex(Refused,"restored and verified"):self.run_maintenance()
        self.assertIn(["/usr/libexec/nebulalog/update-reboot-abort"],self.calls)
        self.assertEqual(json.loads((self.root/"os-transaction.json").read_text())["state"],"reboot_aborted")

    def test_failed_or_unverified_abort_keeps_recovery_required(self):
        self.reboot_fails=True
        for failed,incomplete in ((True,False),(False,True)):
            with self.subTest(failed=failed,incomplete=incomplete):
                (self.root/"os-transaction.json").unlink(missing_ok=True)
                self.abort_fails,self.abort_incomplete=failed,incomplete
                with self.assertRaisesRegex(Refused,"recovery failed"):self.run_maintenance()
                self.assertEqual(json.loads((self.root/"os-transaction.json").read_text())["state"],"recovery_required")

    def test_maintenance_window_rechecked_before_reboot(self):
        with patch("nebulalog_manager.os_updates.in_maintenance_window",side_effect=[True,False]):
            self.assertEqual(self.run_maintenance(),{"status":"updated","reboot_pending":True})
        self.assertNotIn(["systemctl","reboot"],self.calls)
        self.assertIn(["/usr/libexec/nebulalog/update-os-postcheck"],self.calls)

    def test_no_reboot_completes_only_after_all_runtime_and_security_checks(self):
        self.reboot_needed=False
        self.assertEqual(self.run_maintenance(),{"status":"updated","reboot_pending":False})
        journal=json.loads((self.root/"os-transaction.json").read_text())
        self.assertEqual(journal["health"],{name:True for name in REQUIRED_CHECKS})
        self.assertEqual(journal["stage"],self.postcheck_stage)
        self.assertLess(self.calls.index(["/usr/libexec/nebulalog/update-os-postcheck"]),
                        self.calls.index(["dnf","needs-restarting","--reboothint"]))

    def test_each_failed_runtime_check_blocks_updated_pending_and_reboot_results(self):
        for reboot in (False,True):
            for name in REQUIRED_CHECKS:
                with self.subTest(reboot=reboot,check=name):
                    (self.root/"os-transaction.json").unlink(missing_ok=True)
                    self.calls.clear()
                    self.reboot_needed=reboot
                    self.postcheck_checks={key:key != name for key in REQUIRED_CHECKS}
                    with self.assertRaisesRegex(Refused,"runtime and security acceptance"):self.run_maintenance()
                    self.assertEqual(json.loads((self.root/"os-transaction.json").read_text())["state"],"recovery_required")
                    self.assertNotIn(["systemctl","reboot"],self.calls)
                    self.assertNotIn(["/usr/libexec/nebulalog/update-reboot-prepare"],self.calls)

    def test_health_from_another_operation_is_refused(self):
        self.postcheck_stage=str(self.root/"os-updates/unrelated")
        with self.assertRaisesRegex(Refused,"operation-bound"):self.run_maintenance()
        self.assertEqual(json.loads((self.root/"os-transaction.json").read_text())["state"],"recovery_required")

    def test_dnf_error_does_not_allow_another_automatic_update_over_partial_changes(self):
        with patch("nebulalog_manager.os_payload.apply", side_effect=CommandFailed("rpm", 1)):
            with self.assertRaises(CommandFailed):maintain(self.policy,self.root,runner=self.runner)
        self.assertEqual(json.loads((self.root/"os-transaction.json").read_text())["state"],"recovery_required")
        self.calls.clear()
        with self.assertRaisesRegex(Refused,"requires recovery"):self.run_maintenance()
        self.assertEqual(self.calls,[])

    def test_interrupted_or_unfinalized_work_blocks_package_changes(self):
        for prior in ({"state":"updating"},{"state":"complete","finalization":"failed"}):
            atomic_json(self.root/"os-transaction.json",prior)
            with self.assertRaises(Refused):self.run_maintenance()
        self.assertEqual(self.calls,[])

    def test_console_unlock_refusal_leaves_updated_packages_and_pending_reboot(self):
        def runner(argv,**kwargs):
            if Path(argv[0]).name == "update-reboot-prepare":raise Refused("console unlock only")
            return self.runner(argv,**kwargs)
        with self.assertRaisesRegex(Refused,"reboot remains pending"):
            maintain(self.policy,self.root,runner=runner,now=datetime(2026,9,6,3,30,tzinfo=timezone.utc))
        journal=json.loads((self.root/"os-transaction.json").read_text())
        self.assertEqual(journal["state"],"complete")
        self.assertTrue(journal["reboot_pending"])
        self.assertNotIn(["systemctl","reboot"],self.calls)
        self.assertEqual(self.calls.count(["/usr/libexec/nebulalog/update-os-postcheck"]),3)

    def test_prepare_refusal_cannot_reuse_health_from_before_service_changes(self):
        def runner(argv,**kwargs):
            if Path(argv[0]).name=="update-reboot-prepare":
                self.postcheck_checks["postgresql"]=False
                raise Refused("preparation failed after service changes")
            return self.runner(argv,**kwargs)
        with self.assertRaisesRegex(Refused,"current runtime acceptance requires recovery"):
            maintain(self.policy,self.root,runner=runner)
        self.assertEqual(json.loads((self.root/"os-transaction.json").read_text())["state"],"recovery_required")


class OSRecoveryCLITests(unittest.TestCase):
    def test_recovery_cli_invokes_only_the_fixed_installed_adapter(self):
        from nebulalog_manager.cli import main
        with patch("nebulalog_manager.common.require_linux_root") as root, \
             patch("nebulalog_manager.os_updates._hook", return_value={"ok": True, "status": "updated"}) as hook, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(["update", "os-recover"]), 0)
        root.assert_called_once_with()
        self.assertEqual(hook.call_count, 1)
        self.assertEqual(hook.call_args.args[0], "update-os-recover")


if __name__=="__main__":unittest.main()
