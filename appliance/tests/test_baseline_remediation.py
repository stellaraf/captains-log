"""Initial hardening refusal/receipt tests; not native compliance evidence."""
from contextlib import nullcontext
import json
import copy
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from nebulalog_manager import baseline
from nebulalog_manager.common import CommandFailed, Refused
import test_baseline as fixtures

INSTALLATION = fixtures.INSTALLATION


class RemediationTests(unittest.TestCase):
    setUp = fixtures.BaselineTests.setUp
    directory = fixtures.BaselineTests.directory
    runner = fixtures.BaselineTests.runner
    policy = fixtures.BaselineTests.policy
    select = fixtures.BaselineTests.select

    def invoke(self, intent="cis-level2", confirmation=None):
        with patch.object(baseline, "initial_hardening", return_value=nullcontext()):
            return self.manager.remediate(INSTALLATION, intent, confirmation or baseline._sha(self.manager.policy_path))

    def evaluations(self):
        return [argv for argv, _ in self.calls if argv[:3] == ["oscap", "xccdf", "eval"]]

    def test_grub_refresh_follows_verified_remediation_and_healthy_postconditions(self):
        from nebulalog_manager import bootloader
        self.select()
        original_host = self.manager.host
        for healthy in (True, False):
            observations = []
            def host(runner):
                observations.append('host')
                result = original_host(runner)
                return result if len(observations) == 1 or healthy else {**result, 'host_controls_ok':False}
            with self.subTest(healthy=healthy), \
                 patch.object(self.manager, 'host', side_effect=host), \
                 patch.object(bootloader, 'remediation_checkpoint', return_value={'bound':True}) as checkpoint, \
                 patch.object(bootloader, 'accept_remediation', return_value={'verified_refresh':True}) as refresh:
                if healthy:
                    result = self.invoke()
                    self.assertEqual(result['bootloader_refresh'], {'verified_refresh':True})
                    refresh.assert_called_once()
                    self.assertEqual(refresh.call_args.args[1], {'bound':True})
                    self.assertEqual(refresh.call_args.args[3], baseline._sha(self.manager.policy_path))
                    self.assertRegex(refresh.call_args.args[2], r'^[a-f0-9]{32}$')
                else:
                    with self.assertRaisesRegex(Refused, 'Host security checks failed'):
                        self.invoke()
                    refresh.assert_not_called()
                checkpoint.assert_called_once_with(self.configuration/'bootstrap', INSTALLATION)
                self.assertEqual(observations, ['host', 'host'])

    def merged_policy(self):
        policy = self.policy("unified")
        item = copy.deepcopy(policy["assessments"][1])
        tailoring = self.root / "unified-tailoring.xml"
        tailoring.write_text(f'<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_tailoring"><benchmark href="{self.source.name}"/><version time="2026-10-12T00:00:00Z">1</version><Profile id="xccdf_test_unified" extends="{fixtures.STIG}"><title>Reviewed fixture union</title><select idref="xccdf_rule_3" selected="false"/></Profile></Tailoring>')
        item.update(base_profile_id=fixtures.STIG, profile_id="xccdf_test_unified", tailoring=str(tailoring),
                    tailoring_sha256=baseline._sha(tailoring), tailoring_decisions=[{
                        "rule_id":"xccdf_rule_3", "selected":False, "rationale":"Fixture application exception",
                        "effective_control":"Manual fixture control reviewed separately"}])
        policy["unified_remediation"] = item
        path = Path(policy["unified_mapping"]["path"])
        mapping = baseline._json(path)
        mapping["remediation"] = {key:item[key] for key in ("sha256","profile_id","tailoring_sha256")}
        for control in mapping["controls"]:
            control["applied_rule"] = control["stig_rule"]
            if control["stig_rule"] == "xccdf_rule_3":
                control.update(decision="application-exception",applied_rule=None)
        path.write_text(json.dumps(mapping))
        policy["unified_mapping"]["sha256"] = baseline._sha(path)
        return policy

    def test_reviewed_unified_executes_one_merged_profile_and_retains_mapping(self):
        policy = self.merged_policy()
        self.select(policy)
        result = self.invoke("unified")
        calls = self.evaluations()
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][calls[0].index("--profile")+1],"xccdf_test_unified")
        self.assertTrue(result["assessment_required"])
        self.assertTrue(result["review_required"])
        retained = next((self.configuration/"baseline-remediations").glob("*/unified-mapping.json"))
        self.assertEqual(baseline._sha(retained),policy["unified_mapping"]["sha256"])
        self.assertEqual(result["unified_mapping_sha256"],policy["unified_mapping"]["sha256"])
        self.calls.clear()
        self.manager.scan(INSTALLATION,"unified")
        scans = self.evaluations()
        self.assertEqual(len(scans),2)
        self.assertEqual({call[call.index("--profile")+1] for call in scans},{fixtures.CIS,fixtures.STIG})
        self.assertTrue(all("--remediate" not in call for call in scans))

    def test_unified_mapping_changed_during_execution_is_not_accepted(self):
        self.select(self.merged_policy())
        original = self.manager.runner
        def changing(argv, **kwargs):
            value = original(argv, **kwargs)
            if "--remediate" in argv:
                retained = next((self.configuration/"baseline-remediations").glob("*/unified-mapping.json"))
                retained.write_text("{}")
            return value
        self.manager.runner = changing
        with self.assertRaisesRegex(Refused,"mapping changed"):
            self.invoke("unified")

    def test_unified_binding_missing_decision_and_effective_omission_are_refused(self):
        for mutation in ("binding","missing","extra","omitted"):
            policy = self.merged_policy()
            path = Path(policy["unified_mapping"]["path"])
            mapping = baseline._json(path)
            if mutation == "binding": mapping["remediation"]["tailoring_sha256"] = "f"*64
            elif mutation == "missing": del mapping["controls"][0]["applied_rule"]
            elif mutation == "extra": mapping["controls"][3].update(applied_rule="xccdf_rule_3")
            else: mapping["controls"][0].update(decision="application-exception",applied_rule=None)
            path.write_text(json.dumps(mapping));policy["unified_mapping"]["sha256"] = baseline._sha(path)
            with self.subTest(mutation=mutation),self.assertRaises(Refused):
                baseline.validate_policy(policy,self.runner,self.now)
        self.assertEqual(self.evaluations(),[])

    def test_cis_remediation_retains_findings_and_demands_separate_assessment(self):
        self.select()
        result = self.invoke()
        self.assertEqual(result["state"], "applied_scan_required")
        self.assertEqual(result["scanner_exit_code"], 2)
        self.assertTrue(result["assessment_required"])
        self.assertTrue(result["review_required"])
        self.assertFalse(self.manager.assessment_path.exists())
        self.assertFalse(self.manager.review_path.exists())
        self.assertEqual(json.loads(self.manager.attempt_path.read_text())["state"], "remediation_pending")
        command = self.evaluations()[0]
        self.assertIn("--remediate", command)
        self.assertNotEqual(command[-1], str(self.source))
        self.assertEqual(baseline._sha(command[-1]), result["content_sha256"])

    def test_stig_uses_the_selected_profile_without_cis_overlay(self):
        self.select(self.policy("stig"))
        result = self.invoke("stig")
        self.assertEqual(result["scanner_exit_code"], 0)
        commands = self.evaluations()
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][commands[0].index("--profile") + 1], result["profile_id"])
        self.assertTrue(result["profile_id"].endswith("_stig"))

    def test_changed_confirmation_never_executes_fixes(self):
        self.select()
        with self.assertRaisesRegex(Refused, "changed"):
            self.invoke(confirmation="f" * 64)
        self.assertEqual(self.evaluations(), [])

    def test_initial_setup_guard_cannot_be_bypassed(self):
        self.select()
        with patch.object(baseline, "initial_hardening", side_effect=Refused("already enrolled")):
            with self.assertRaisesRegex(Refused, "already enrolled"):
                self.manager.remediate(INSTALLATION, "cis-level2", baseline._sha(self.manager.policy_path))
        self.assertEqual(self.evaluations(), [])

    def test_unified_does_not_apply_conflicting_profiles_in_sequence(self):
        self.select(self.policy("unified"))
        with self.assertRaisesRegex(Refused, "conflict mapping"):
            self.invoke("unified")
        self.assertEqual(self.evaluations(), [])

    def test_execution_failure_preserves_receipt_and_invalidates_previous_acceptance(self):
        self.select()
        self.fail_scanner = 1
        with self.assertRaises(CommandFailed):
            self.invoke()
        records = list((self.configuration / "baseline-remediations").glob("*/remediation.json"))
        self.assertEqual(len(records), 1)
        self.assertEqual(json.loads(records[0].read_text())["state"], "failed_review_required")
        self.assertNotEqual(json.loads(self.manager.attempt_path.read_text())["state"], "complete")

    def test_unhealthy_host_prevents_remediation(self):
        self.select()
        self.host_value["host_controls_ok"] = False
        with self.assertRaisesRegex(Refused, "healthy host"):
            self.invoke()
        self.assertEqual(self.evaluations(), [])

    def test_postcondition_failure_is_not_an_accepted_remediation(self):
        self.select()
        original = self.manager.runner
        def run(argv, **kwargs):
            try:
                return original(argv, **kwargs)
            finally:
                if "--remediate" in argv:
                    self.host_value["host_controls_ok"] = False
        self.manager.runner = run
        with self.assertRaisesRegex(Refused, "after hardening"):
            self.invoke()
        record = next((self.configuration / "baseline-remediations").glob("*/remediation.json"))
        self.assertEqual(json.loads(record.read_text())["state"], "failed_review_required")

    def initial_manager(self):
        from nebulalog_manager.firstboot import Locations
        from nebulalog_manager.common import atomic_json
        paths = Locations(self.root / "etc", self.root, self.root / "run")
        paths.bootstrap.mkdir(parents=True)
        (self.root / "manager").mkdir()
        (self.configuration / "bootstrap").mkdir()
        atomic_json(self.configuration / "bootstrap/setup.json", {"installation_id": INSTALLATION, "baseline": "cis-level2"})
        return SimpleNamespace(paths=paths, runner=self.runner, gate=lambda: {"installation_id": INSTALLATION})

    def test_real_initial_guard_refuses_completed_enrolled_or_mismatched_setup(self):
        manager = self.initial_manager()
        with patch("nebulalog_manager.firstboot.FirstBoot", return_value=manager):
            with baseline.initial_hardening(self.configuration, INSTALLATION, "cis-level2"):
                pass
            with self.assertRaises(Refused):
                with baseline.initial_hardening(self.configuration, INSTALLATION, "stig"):
                    self.fail("wrong baseline")
            for marker in (manager.paths.etc / "configured", self.root / "manager/aide-enrollment.json", self.root / "manager/aide"):
                marker.write_text("retained state")
                try:
                    with self.assertRaises(Refused):
                        with baseline.initial_hardening(self.configuration, INSTALLATION, "cis-level2"):
                            self.fail("existing enrollment/completion")
                finally:
                    marker.unlink()

    def test_console_confirmation_binds_selected_policy_and_cancellation_does_not_apply(self):
        from nebulalog_manager import firstboot
        manager = self.initial_manager()
        self.select()
        with patch.object(baseline, "Baseline", return_value=self.manager), patch("builtins.print"), \
                patch.object(firstboot, "_bootloader_console") as bootloader, \
                patch.object(self.manager, "remediate", return_value={"state": "applied_scan_required"}) as remediate:
            with patch.object(firstboot, "_answer", return_value="CANCEL"):
                self.assertFalse(firstboot._hardening_console(manager, {"baseline": "cis-level2"})["host_modified"])
            remediate.assert_not_called()
            bootloader.assert_not_called()
            with patch.object(firstboot, "_answer", return_value="APPLY"):
                firstboot._hardening_console(manager, {"baseline": "cis-level2"})
            remediate.assert_called_once_with(INSTALLATION, "cis-level2", baseline._sha(self.manager.policy_path))
            bootloader.assert_called_once_with(manager, {"baseline": "cis-level2"}, INSTALLATION)

    def test_runtime_menu_exposes_hardening_and_does_not_complete_setup(self):
        from nebulalog_manager import firstboot
        manager = self.initial_manager()
        with patch.object(firstboot, "_answer", side_effect=["HARDENING", "LATER"]), \
                patch.object(firstboot, "_hardening_console") as hardening, \
                patch("nebulalog_manager.setup_integrity.pending_console"), patch("builtins.print"):
            result = firstboot._runtime_console(manager, {"baseline": "cis-level2", "hostname": "logs.example"}, {})
        hardening.assert_called_once()
        self.assertFalse(result["setup_complete"])


if __name__ == "__main__":
    unittest.main()
