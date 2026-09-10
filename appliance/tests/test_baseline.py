import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager import baseline, security
from nebulalog_manager.common import CommandFailed, Refused, atomic_json

INSTALLATION = "11111111-2222-4333-8444-555555555555"
CIS = "xccdf_org.ssgproject.content_profile_cis"
STIG = "xccdf_org.ssgproject.content_profile_stig"
CONTENT = f'''<data-stream-collection xmlns:x="http://checklists.nist.gov/xccdf/1.2">
<component><x:Benchmark id="xccdf_example_benchmark"><x:platform idref="cpe:/o:rocky:rocky:9"/>
<x:Profile id="{CIS}"><x:title>CIS Red Hat Enterprise Linux 9 Benchmark for Level 2 - Server</x:title></x:Profile>
<x:Profile id="{STIG}"><x:title>DISA STIG for Red Hat Enterprise Linux 9</x:title></x:Profile>
<x:Profile id="xccdf_example_l1"><x:title>CIS Level 1 Server</x:title></x:Profile>
<x:Rule id="xccdf_rule_0"><x:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"/></x:Rule>
<x:Rule id="xccdf_rule_1"><x:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"/></x:Rule>
<x:Rule id="xccdf_rule_2"/><x:Rule id="xccdf_rule_3"/>
</x:Benchmark></component></data-stream-collection>'''


class BaselineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.configuration = self.root / "configuration"
        self.configuration.mkdir(mode=0o700)
        self.source = self.root / "ssg-rl9-ds.xml"
        self.source.write_text(CONTENT)
        self.source.chmod(0o600)
        self.now = datetime.now(timezone.utc) + timedelta(seconds=2)
        self.calls = []
        self.results = {"cis": ["pass", "fail", "notapplicable", "notselected"], "stig": ["pass"]}
        self.fail_scanner = None
        self.wrong_profile = False
        self.host_value = {"machine_id_sha256": "a" * 64, "packages": "scap-v1", "host_controls_ok": True}
        self.manager = baseline.Baseline(self.configuration, runner=self.runner, host=lambda _: copy.deepcopy(self.host_value), clock=lambda: self.now)
        # These are fixture/argv tests on the development host, not guest proof.
        for target in ("nebulalog_manager.baseline.require_linux_root", "nebulalog_manager.security.require_linux_root"):
            context = patch(target)
            context.start()
            self.addCleanup(context.stop)
        for target in ("nebulalog_manager.baseline.trusted_file", "nebulalog_manager.security.trusted_file"):
            context = patch(target, side_effect=lambda path: Path(path))
            context.start()
            self.addCleanup(context.stop)
        context = patch("nebulalog_manager.baseline._directory", side_effect=self.directory)
        context.start()
        self.addCleanup(context.stop)
        context = patch("nebulalog_manager.security.status", return_value={"host_controls_ok": True, "certification": "not asserted"})
        context.start()
        self.addCleanup(context.stop)

    def directory(self, path, create=False):
        path = Path(path)
        if create:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:2] == ["oscap", "info"]:
            return "Profiles:\nID: " + CIS + "\nID: " + STIG
        if argv == ["oscap", "--version"]:
            return "OpenSCAP command line tool (oscap) 1.3.fixture"
        if argv[:2] == ["rpm", "-q"]:
            return "openscap-scanner.fixture\nscap-security-guide.fixture"
        if argv[:3] == ["oscap", "xccdf", "eval"]:
            profile = argv[argv.index("--profile") + 1]
            kind = "cis" if profile == CIS else "stig"
            xml = Path(argv[argv.index("--results") + 1])
            html = Path(argv[argv.index("--report") + 1])
            results = "".join(f'<rule-result idref="xccdf_rule_{i}"><result>{result}</result></rule-result>' for i, result in enumerate(self.results[kind]))
            xml.write_text(f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult><profile idref="{STIG if self.wrong_profile else profile}"/>{results}</TestResult></Benchmark>')
            html.write_text("<html><body>Fixture assessment</body></html>")
            if self.fail_scanner is not None:
                raise CommandFailed("oscap", self.fail_scanner)
            if "fail" in self.results[kind]:
                raise CommandFailed("oscap", 2)
            return ""
        raise AssertionError(argv)

    def policy(self, intent="cis-level2"):
        kinds = ("cis", "stig") if intent == "unified" else ("cis",) if intent == "cis-level2" else ("stig",)
        attestation = {"approved": True, "reviewer": "Fixture content reviewer", "platform_basis": "Fixture Rocky CPE check", "benchmark_basis": "Fixture mapping review only", "license_basis": "Fixture BSD notice review", "reviewed_at": (self.now - timedelta(days=1)).isoformat(), "expires_at": (self.now + timedelta(days=30)).isoformat()}
        policy = {"schema": 1, "baseline": intent, "assessments": [{"kind": kind, "platform": "rocky9", "reviewed": True,
            "datastream": str(self.source), "sha256": baseline._sha(self.source), "profile_id": CIS if kind == "cis" else STIG,
            "content_revision": "fixture-v1", "source_url": "https://example.invalid/fixture", "content_review": copy.deepcopy(attestation)} for kind in kinds]}
        if intent == "unified":
            mapping = self.root / "mapping.json"
            atomic_json(mapping, {"schema": 1, "baseline": "unified", "coverage_reviewed": True, "review": attestation,
                "assessments": {p["kind"]: {"sha256": p["sha256"], "profile_id": p["profile_id"]} for p in policy["assessments"]},
                "controls": [{"control": "fixture", "cis_rule": "xccdf_rule_0", "stig_rule": "xccdf_rule_0", "decision": "same-once", "rationale": "Same fixture requirement", "effective_setting": "Fixture setting"}]})
            policy["unified_mapping"] = {"path": str(mapping), "sha256": baseline._sha(mapping)}
        return policy

    def select(self, policy=None):
        policy = policy or self.policy()
        source = self.root / "reviewed-policy.json"
        atomic_json(source, policy)
        return self.manager.select(source, baseline._sha(source), INSTALLATION, policy["baseline"])

    def scan(self, intent="cis-level2"):
        self.select(self.policy(intent))
        return self.manager.scan(INSTALLATION, intent)

    def reviewed(self, intent="cis-level2"):
        value = self.manager.review_template(INSTALLATION, intent)
        value.update(approved=True, selection_reviewed=True, reviewer="Fixture reviewer", rationale="Reviewed every fixture control and exclusion", reviewed_at=self.now.isoformat(), expires_at=(self.now + timedelta(days=30)).isoformat())
        for finding in value["findings"]:
            finding.update(disposition="exception" if finding["result"] == "fail" else "not-applicable" if finding["result"] == "notapplicable" else "manual-review",
                reason="Documented fixture reason", compensating_control="Documented fixture control", owner="Fixture owner", approval="Fixture approval reference", expires_at=value["expires_at"], evidence="Fixture evidence reference")
        return value

    def approve(self, review=None, intent="cis-level2"):
        path = self.root / "findings-review.json"
        atomic_json(path, review or self.reviewed(intent))
        return self.manager.review(path, baseline._sha(self.manager.assessment_path), INSTALLATION, intent)

    def test_inventory_uses_actual_ids_titles_and_rocky_cpe(self):
        result = baseline.inventory(self.root, self.runner)
        stream = result["datastreams"][0]
        self.assertTrue(stream["rocky9_cpe_present"])
        self.assertEqual(stream["profiles"][0]["id"], CIS)
        self.assertIn("Red Hat", stream["profiles"][0]["title"])
        self.assertEqual(stream["profiles"][0]["candidate_for"], ["cis-level2"])
        self.assertEqual(stream["profiles"][2]["candidate_for"], [])

    def test_unavailable_scanner_is_explicit(self):
        result = baseline.inventory(self.root, lambda _: (_ for _ in ()).throw(FileNotFoundError("oscap unavailable")))
        self.assertTrue(result["unavailable"])
        self.assertFalse(result["datastreams"])

    def test_wrong_profile_hash_platform_or_unreviewed_content_refused(self):
        for key, value in (("profile_id", CIS + "_invented"), ("profile_id", "xccdf_example_l1"), ("sha256", "0" * 64), ("platform", "rhel9"), ("reviewed", False), ("content_review", {"approved": False})):
            with self.subTest(key=key, value=value):
                policy = self.policy()
                policy["assessments"][0][key] = value
                with self.assertRaises(Refused):
                    self.select(policy)
        self.assertFalse(any(call[0][:3] == ["oscap", "xccdf", "eval"] for call in self.calls))

    def test_native_platform_declaration_required(self):
        self.source.write_text(CONTENT.replace("cpe:/o:rocky:rocky:9", "cpe:/o:redhat:enterprise_linux:9"))
        with self.assertRaisesRegex(Refused, "native Rocky9"):
            self.select()

    def test_unified_requires_both_profiles_and_matching_reviewed_mapping(self):
        policy = self.policy("unified")
        without = copy.deepcopy(policy)
        without.pop("unified_mapping")
        with self.assertRaises(Refused):
            self.select(without)
        self.select(policy)
        result = self.manager.scan(INSTALLATION, "unified")
        self.assertEqual({item["kind"] for item in result["assessments"]}, {"cis", "stig"})

    def test_real_scan_adapter_retains_artifacts_without_remediation(self):
        report = self.scan()
        self.assertFalse(report["remediation_applied"])
        self.assertFalse(report["assessments"][0]["automated_assessment_passed"])
        self.assertEqual(report["assessments"][0]["counts"]["fail"], 1)
        self.assertEqual(set(report["artifacts"]), {"cis.xml", "cis.html", "cis-content.xml", "policy.json"})
        evaluations = [argv for argv, _ in self.calls if argv[:3] == ["oscap", "xccdf", "eval"]]
        self.assertEqual(len(evaluations), 1)
        self.assertNotIn("--remediate", evaluations[0])
        self.assertEqual(self.manager.checks(INSTALLATION, "cis-level2"), {"baseline_assessed": True, "baseline_review_complete": False})

    def test_all_pass_still_requires_explicit_review(self):
        self.results["cis"] = ["pass"]
        self.scan()
        self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_review_complete"])
        self.approve()
        self.assertTrue(self.manager.checks(INSTALLATION, "cis-level2")["baseline_review_complete"])

    def test_approved_exceptions_preserve_machine_failure(self):
        self.scan()
        self.approve()
        self.assertTrue(self.manager.checks(INSTALLATION, "cis-level2")["baseline_review_complete"])
        assessment = baseline._json(self.manager.assessment_path)
        self.assertFalse(assessment["assessments"][0]["automated_assessment_passed"])
        self.assertEqual(assessment["assessments"][0]["counts"]["fail"], 1)
        self.assertEqual(len(baseline._json(self.manager.review_path)["findings"]), 2)

    def test_missing_extra_duplicate_and_wrong_result_findings_refused(self):
        self.scan()
        valid = self.reviewed()
        variants = [valid["findings"][:-1], valid["findings"] + [valid["findings"][0]], [valid["findings"][0], valid["findings"][0]]]
        wrong = copy.deepcopy(valid["findings"])
        wrong[0]["result"] = "notapplicable"
        variants.append(wrong)
        for findings in variants:
            with self.subTest(findings=findings), self.assertRaises(Refused):
                self.approve({**valid, "findings": findings})

    def test_bad_review_identity_expiration_and_unapproved_refused(self):
        self.scan()
        valid = self.reviewed()
        for key, value in (("approved", False), ("selection_reviewed", False), ("installation_id", "foreign"), ("assessment_sha256", "0" * 64), ("expires_at", (self.now - timedelta(seconds=1)).isoformat()), ("expires_at", (self.now + timedelta(days=91)).isoformat())):
            with self.subTest(key=key), self.assertRaises(Refused):
                self.approve({**valid, key: value})

    def test_unassessable_results_and_empty_reports_cannot_be_approved(self):
        for results in ([], ["notapplicable"], ["notselected"], ["pass", "error"], ["pass", "notchecked"], ["pass", "unknown"]):
            with self.subTest(results=results):
                self.results["cis"] = results
                self.scan()
                self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_assessed"])
                with self.assertRaises(Refused):
                    self.approve()

    def test_execution_error_is_not_a_completed_scan_even_with_xml(self):
        self.fail_scanner = 1
        with self.assertRaises(CommandFailed):
            self.scan()
        self.assertFalse(self.manager.assessment_path.exists())

    def test_failed_rescan_and_reselection_invalidate_prior_approval(self):
        self.scan()
        self.approve()
        self.fail_scanner = 1
        with self.assertRaises(CommandFailed):
            self.manager.scan(INSTALLATION, "cis-level2")
        self.assertEqual(baseline._json(self.manager.attempt_path)["state"], "failed")
        self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_assessed"])
        self.fail_scanner = None
        self.scan()
        self.approve()
        self.select()
        self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_assessed"])

    def test_tailoring_is_explicitly_unavailable_not_silently_ignored(self):
        policy = self.policy()
        policy["assessments"][0]["tailoring"] = str(self.source)
        with self.assertRaisesRegex(Refused, "unavailable"):
            self.select(policy)

    def test_only_source_declared_manual_controls_accept_hashed_manual_evidence(self):
        self.results["cis"] = ["pass", "pass", "notchecked"]
        self.scan()
        review = self.reviewed()
        manual = review["findings"][0]
        manual["disposition"] = "manual-pass"
        with self.assertRaisesRegex(Refused, "evidence file"):
            self.approve(review)
        evidence = self.root / "manual-assessment.txt"
        evidence.write_text("Fixture manual evidence: reviewed control, method, observations and outcome.")
        manual["manual_evidence"] = {"path": str(evidence), "sha256": baseline._sha(evidence)}
        self.approve(review)
        self.assertTrue(self.manager.checks(INSTALLATION, "cis-level2")["baseline_review_complete"])
        self.assertFalse(baseline._json(self.manager.assessment_path)["assessments"][0]["automated_assessment_passed"])
        evidence.write_text("Changed evidence")
        self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_review_complete"])

    def test_oval_failure_cannot_be_reclassified_by_review_as_manual(self):
        self.results["cis"] = ["pass", "notchecked"]
        self.scan()
        review = self.reviewed()
        review["findings"][0].update(manual_only=True, disposition="manual-pass")
        with self.assertRaises(Refused):
            self.approve(review)

    def test_nonexistent_and_duplicate_mapping_rules_refused(self):
        for change in ("unknown-rule", "duplicate"):
            policy = self.policy("unified")
            path = Path(policy["unified_mapping"]["path"])
            mapping = baseline._json(path)
            if change == "unknown-rule":
                mapping["controls"][0]["cis_rule"] = "xccdf_rule_invented"
            else:
                mapping["controls"].append(copy.deepcopy(mapping["controls"][0]))
            atomic_json(path, mapping)
            policy["unified_mapping"]["sha256"] = baseline._sha(path)
            with self.subTest(change=change), self.assertRaises(Refused):
                self.select(policy)

    def test_mismatched_result_profile_refused(self):
        self.wrong_profile = True
        with self.assertRaisesRegex(Refused, "selected profile"):
            self.scan()

    def test_tamper_host_drift_policy_and_content_change_invalidate_review(self):
        self.scan()
        self.approve()
        self.assertFalse(self.manager.checks("foreign", "cis-level2")["baseline_assessed"])
        self.host_value["packages"] = "updated-content-package"
        self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_assessed"])
        self.host_value["packages"] = "scap-v1"
        report = baseline._json(self.manager.assessment_path)
        xml = self.configuration / "baseline-assessments" / report["artifact_directory"] / "cis.xml"
        xml.write_text(xml.read_text().replace("fail", "pass"))
        self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_assessed"])
        self.scan()
        self.approve()
        self.source.write_text(CONTENT + "\n")
        self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_assessed"])

    def test_expiry_or_new_scan_invalidates_previous_approval(self):
        self.scan()
        self.approve()
        self.manager.clock = lambda: self.now + timedelta(days=31)
        self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_review_complete"])
        self.manager.clock = lambda: self.now
        self.manager.scan(INSTALLATION, "cis-level2")
        self.assertFalse(self.manager.checks(INSTALLATION, "cis-level2")["baseline_review_complete"])

    def test_dtd_entity_and_duplicate_rule_instances_refused(self):
        path = self.root / "unsafe.xml"
        path.write_text('<!DOCTYPE x [<!ENTITY unsafe "bad">]><Benchmark/>')
        with self.assertRaises(Refused):
            baseline.rule_results(path, CIS)
        path.write_bytes('<!DOCTYPE x [<!ENTITY unsafe "bad">]><Benchmark/>'.encode("utf-16"))
        with self.assertRaises(Refused):
            baseline.rule_results(path, CIS)
        path.write_text(f'<Benchmark><TestResult><profile idref="{CIS}"/><rule-result idref="xccdf_duplicate"><result>pass</result></rule-result><rule-result idref="xccdf_duplicate"><result>pass</result></rule-result></TestResult></Benchmark>')
        with self.assertRaisesRegex(Refused, "instance-aware"):
            baseline.rule_results(path, CIS)


class EvidencePathTests(unittest.TestCase):
    def test_iso_utc_z_is_supported_on_guest_python39(self):
        self.assertEqual(baseline._date("2026-09-07T12:00:00Z"), datetime(2026, 9, 7, 12, tzinfo=timezone.utc))

    def test_relative_path_cannot_skip_ancestor_checks(self):
        with self.assertRaisesRegex(Refused, "absolute"):
            baseline._directory(Path("."))

    def test_symlink_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(Refused, "symlinks"):
                baseline._directory(link)


if __name__ == "__main__":
    unittest.main()
