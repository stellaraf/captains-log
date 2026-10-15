"""Real baseline/review parsers with synthetic SCAP commands; no guest mutations."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import baseline
from nebulalog_manager.common import CommandFailed, Refused, atomic_json
from nebulalog_adapters.lifecycle import Lifecycle, ORDER

INSTALLATION = "11111111-2222-4333-8444-555555555555"
PROFILE = "xccdf_org.ssgproject.content_profile_cis"
CONTENT = f'''<data-stream-collection xmlns:x="http://checklists.nist.gov/xccdf/1.2">
<component><x:Benchmark id="xccdf_fixture"><x:platform idref="cpe:/o:rocky:rocky:9"/>
<x:Profile id="{PROFILE}"><x:title>CIS Level 2 Server</x:title></x:Profile>
<x:Rule id="xccdf_rule_0"><x:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"/></x:Rule>
<x:Rule id="xccdf_rule_1"><x:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"/></x:Rule>
<x:Rule id="xccdf_rule_2"/><x:Rule id="xccdf_rule_3"/>
</x:Benchmark></component></data-stream-collection>'''


class LifecycleComplianceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.configuration = self.root / "configuration"
        self.configuration.mkdir(mode=0o700)
        self.stage = self.root / "manager/updates/releases/one"
        self.stage.mkdir(parents=True, mode=0o700)
        self.quadlets = self.root / "quadlets"
        self.quadlets.mkdir(mode=0o700)
        for name in ORDER:
            (self.quadlets / ("nebulalog-" + name + ".container")).write_text(
                "[Container]\nImage=registry.invalid/fixture@sha256:" + "a" * 64 + "\n")
        self.source = self.root / "fixture-datastream.xml"
        self.source.write_text(CONTENT)
        self.now = datetime.now(timezone.utc) + timedelta(seconds=2)
        self.results = ["pass", "fail", "notapplicable", "notchecked"]
        self.scans = 0
        self.scanner_failure = False
        self.after_scan = None
        self.packages = "fixture-package-1.x86_64"
        self.image = "sha256:" + "a" * 64
        self.boot = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        self.host = {"machine_id_sha256": "a" * 64, "kernel": "fixture-kernel", "host_controls_ok": True}
        for target in ("nebulalog_manager.baseline.require_linux_root", "nebulalog_manager.security.require_linux_root"):
            self.start_patch(target)
        for target in ("nebulalog_manager.baseline.trusted_file", "nebulalog_manager.security.trusted_file",
                       "nebulalog_adapters.lifecycle.trusted_file"):
            self.start_patch(target, side_effect=lambda path: Path(path))
        self.start_patch("nebulalog_manager.baseline._directory", side_effect=self.directory)
        self.scan_host = self.start_patch("nebulalog_manager.security.status", return_value={"host_controls_ok": True})
        self.start_patch("nebulalog_adapters.lifecycle.Baseline", side_effect=self.baseline_manager)
        atomic_json(self.configuration / "bootstrap/setup.json", {"installation_id": INSTALLATION, "baseline": "cis-level2"})
        review = {"approved": True, "reviewer": "Fixture reviewer", "platform_basis": "Fixture Rocky applicability",
                  "benchmark_basis": "Fixture control mapping", "license_basis": "Fixture license review",
                  "reviewed_at": (self.now - timedelta(days=1)).isoformat(), "expires_at": (self.now + timedelta(days=30)).isoformat()}
        policy = {"schema": 1, "baseline": "cis-level2", "assessments": [{"kind": "cis", "platform": "rocky9",
                  "reviewed": True, "datastream": str(self.source), "sha256": baseline._sha(self.source),
                  "profile_id": PROFILE, "content_revision": "fixture-v1", "source_url": "https://example.invalid/fixture",
                  "content_review": review}]}
        policy_file = self.root / "reviewed-policy.json"
        atomic_json(policy_file, policy)
        self.baseline_manager(self.configuration).select(policy_file, baseline._sha(policy_file), INSTALLATION, "cis-level2")
        self.manager = Lifecycle({"compliance_policy": str(self.configuration / "security-policy.json"), "issuer": "https://fixture.invalid"},
                                 self.runner, state=self.root / "manager/updates", data=self.root,
                                 configuration=self.configuration, quadlets=self.quadlets, guard=lambda: None)
        self.manager.boot_id = lambda: self.boot
        self.manager.release = Mock(return_value=({"components": {}}, {}))
        self.manager.encrypted = Mock(return_value=None)
        self.manager.maintenance = Mock()

    def start_patch(self, target, **kwargs):
        item = patch(target, **kwargs)
        value = item.start()
        self.addCleanup(item.stop)
        return value

    def directory(self, path, create=False):
        path = Path(path)
        if create:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def baseline_manager(self, path, *, runner=None):
        return baseline.Baseline(path, runner=runner or self.runner,
                                 host=lambda _: copy.deepcopy(self.host), clock=lambda: self.now)

    def runner(self, argv, **kwargs):
        if argv[:2] == ["rpm", "-qa"]:
            return self.packages
        if argv[:2] == ["podman", "inspect"]:
            return json.dumps(["KC_FIPS_MODE=strict"]) if "{{json .Config.Env}}" in argv else self.image
        if argv[:2] == ["oscap", "info"]:
            return "ID: " + PROFILE
        if argv == ["oscap", "--version"]:
            return "OpenSCAP fixture"
        if argv[:2] == ["rpm", "-q"]:
            return "openscap-fixture\nscap-security-guide-fixture"
        if argv[:3] == ["oscap", "xccdf", "eval"]:
            self.assertLessEqual(kwargs["timeout"], 900)
            self.scans += 1
            xml = Path(argv[argv.index("--results") + 1])
            rules = "".join(f'<rule-result idref="xccdf_rule_{i}"><result>{result}</result></rule-result>'
                            for i, result in enumerate(self.results))
            xml.write_text(f'<Benchmark><TestResult><profile idref="{PROFILE}"/>{rules}</TestResult></Benchmark>')
            Path(argv[argv.index("--report") + 1]).write_text("<html>Fixture</html>")
            if self.after_scan:
                self.after_scan()
            if self.scanner_failure:
                raise CommandFailed("oscap", 1)
            if "fail" in self.results:
                raise CommandFailed("oscap", 2)
            return ""
        raise AssertionError(argv)

    def retained(self, stage=None):
        value = json.loads(((stage or self.stage) / "adapter-compliance.json").read_text())
        return self.baseline_manager(Path(value["configuration"]))

    def approve(self, stage=None):
        manager = self.retained(stage)
        value = manager.review_template(INSTALLATION, "cis-level2")
        value.update(approved=True, selection_reviewed=True, reviewer="Fixture operator",
                     rationale="Explicit complete fixture findings review", reviewed_at=self.now.isoformat(),
                     expires_at=(self.now + timedelta(days=1)).isoformat())
        for finding in value["findings"]:
            finding.update(disposition={"fail": "exception", "notapplicable": "not-applicable", "notchecked": "manual-pass"}[finding["result"]],
                           reason="Fixture reviewed finding", compensating_control="Fixture compensation", owner="Fixture owner",
                           approval="Fixture approval", evidence="Fixture evidence", expires_at=value["expires_at"])
            if finding["result"] == "notchecked":
                manual = self.root / "manual-evidence.txt"
                manual.write_text("Synthetic evidence for the fixture manual-only control")
                finding["manual_evidence"] = {"path": str(manual), "sha256": baseline._sha(manual)}
        review = self.root / "operator-review.json"
        atomic_json(review, value)
        manager.review(review, baseline._sha(manager.assessment_path), INSTALLATION, "cis-level2")
        return manager

    def pending(self, stage=None):
        with self.assertRaisesRegex(Refused, "Review the exact"):
            self.manager.compliance(stage or self.stage)

    def test_unreviewed_retries_retain_exact_assessment_without_rescanning(self):
        self.pending()
        manager = self.retained()
        captured = manager.assessment_path.read_bytes()
        self.pending()
        self.assertEqual(self.scans, 1)
        self.assertEqual(manager.assessment_path.read_bytes(), captured)

    def test_current_approved_fail_na_and_manual_results_pass_without_changing_results(self):
        self.pending()
        manager = self.approve()
        original = manager.assessment_path.read_bytes()
        result = self.manager.compliance(self.stage)
        self.assertTrue(result["review_complete"])
        self.assertFalse(result["automated_assessment_passed"])
        self.assertEqual(self.scans, 2)  # Current verification, not a new review target.
        self.assertEqual(manager.assessment_path.read_bytes(), original)
        self.assertEqual(json.loads(original)["assessments"][0]["counts"]["fail"], 1)

    def test_all_pass_keeps_existing_automatic_health_behavior(self):
        self.results = ["pass", "pass"]
        result = self.manager.compliance(self.stage)
        self.assertTrue(result["automated_assessment_passed"])
        self.assertFalse(result["review_complete"])

    def test_expired_review_and_changed_manual_evidence_fail(self):
        self.pending()
        self.approve()
        (self.root / "manual-evidence.txt").write_text("Changed evidence")
        self.pending()
        self.approve()
        self.now += timedelta(days=2)
        self.pending()
        self.assertEqual(self.scans, 1)

    def test_boot_package_image_policy_changes_never_reuse_previous_approval(self):
        self.pending()
        self.approve()
        self.boot = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        self.pending()
        self.approve()
        self.packages = "fixture-package-2.x86_64"
        self.pending()
        self.approve()
        self.image = "sha256:" + "b" * 64
        self.pending()
        self.approve()
        path = self.configuration / "security-policy.json"
        policy = json.loads(path.read_text())
        policy["selection_id"] = "fresh-selection"
        atomic_json(path, policy)
        self.pending()
        self.assertEqual(self.scans, 5)

    def test_same_boot_rule_regression_invalidates_review_and_needs_new_assessment(self):
        self.pending()
        old = self.approve()
        old_hash = baseline._sha(old.assessment_path)
        self.results[0] = "fail"
        with self.assertRaisesRegex(Refused, "Current rule outcomes changed"):
            self.manager.compliance(self.stage)
        self.pending()
        self.assertNotEqual(baseline._sha(old.assessment_path), old_hash)
        self.assertEqual(self.scans, 3)

    def test_failed_new_scan_or_tampered_report_cannot_use_approved_success(self):
        self.pending()
        manager = self.approve()
        self.scanner_failure = True
        with self.assertRaises(CommandFailed):
            self.manager.compliance(self.stage)
        self.assertEqual(json.loads((self.stage / "adapter-compliance.json").read_text())["status"], "failed")
        self.scanner_failure = False
        report = json.loads(manager.assessment_path.read_text())
        (manager.configuration / "baseline-assessments" / report["artifact_directory"] / "cis.xml").write_text("tampered")
        with self.assertRaises(Refused):
            self.manager.compliance(self.stage)

    def test_other_operation_approval_is_not_a_review_of_new_exact_assessment(self):
        self.pending()
        original = self.approve().review_path.read_bytes()
        stage = self.stage.parent / "another-operation"
        stage.mkdir(mode=0o700)
        self.pending(stage)
        retained = self.retained(stage)
        retained.review_path.write_bytes(original)
        self.pending(stage)
        self.assertEqual(self.scans, 2)

    def test_review_expiring_during_current_verification_is_refused(self):
        self.pending()
        self.approve()
        self.after_scan = lambda: setattr(self, "now", self.now + timedelta(days=2))
        with self.assertRaises(Refused):
            self.manager.compliance(self.stage)
        self.assertEqual(json.loads((self.stage / "adapter-compliance.json").read_text())["status"], "failed")

    def test_image_change_during_initial_scan_cannot_publish_acceptance(self):
        self.after_scan = lambda: setattr(self, "image", "sha256:" + "c" * 64)
        with self.assertRaisesRegex(Refused, "changed during lifecycle"):
            self.manager.compliance(self.stage)
        self.assertEqual(json.loads((self.stage / "adapter-compliance.json").read_text())["status"], "failed")

    def test_host_security_failure_during_verification_cannot_publish_pass(self):
        self.pending()
        self.approve()
        self.after_scan = lambda: self.scan_host.return_value.update(host_controls_ok=False)
        with self.assertRaisesRegex(Refused, "Current host security controls failed"):
            self.manager.compliance(self.stage)
        self.assertEqual(json.loads((self.stage / "adapter-compliance.json").read_text())["status"], "failed")

    def test_current_host_provenance_is_revalidated_after_verification(self):
        self.pending()
        self.approve()
        self.after_scan = lambda: self.host.update(host_controls_ok=False)
        with self.assertRaisesRegex(Refused, "host provenance is stale"):
            self.manager.compliance(self.stage)
        self.assertEqual(json.loads((self.stage / "adapter-compliance.json").read_text())["status"], "failed")

    def health_fixture(self):
        self.manager.api_ready = Mock()
        self.manager.get = lambda path, token=None: json.dumps({"status": "ok", "application_crypto_fips_enabled": True}).encode()
        self.manager.web = lambda: b'<div id="root"></div>'
        self.manager.sql = self.manager.ch = lambda _: "1"
        self.manager.canary = lambda: True
        self.start_patch("nebulalog_adapters.lifecycle.local_auth", return_value=("synthetic-token", {"fixture": True}))
        return self.start_patch("nebulalog_adapters.lifecycle.security_status", return_value={
            "host_controls_ok": True, "selinux": {"value": "Enforcing"}, "firewalld": {"value": "active"}})

    def test_livepatch_health_retains_reviewed_findings_and_checks_current_services(self):
        self.health_fixture()
        self.stage = self.manager.state / 'livepatch-health' / self.boot
        self.stage.mkdir(parents=True, mode=0o700)
        self.assertFalse(self.manager.livepatch_health(self.stage)['ok'])
        self.approve()
        self.assertTrue(self.manager.livepatch_health(self.stage)['ok'])
        self.manager.release.assert_not_called()
        self.manager.sql = lambda _: 'unavailable'
        self.assertFalse(self.manager.livepatch_health(self.stage)['ok'])

    def test_livepatch_health_refuses_unowned_stage(self):
        with self.assertRaisesRegex(Refused, 'outside protected'):
            self.manager.livepatch_health(self.stage)

    def test_component_health_uses_review_and_still_refuses_failed_fips_selinux(self):
        host = self.health_fixture()
        self.assertFalse(self.manager.health(self.stage)["checks"]["compliance"])
        self.approve()
        self.assertTrue(self.manager.health(self.stage)["ok"])
        host.return_value["host_controls_ok"] = False
        host.return_value["selinux"]["value"] = "Permissive"
        result = self.manager.health(self.stage)
        self.assertFalse(result["ok"])
        self.assertFalse(result["checks"]["fips"])
        self.assertFalse(result["checks"]["selinux"])

    def test_new_boot_retains_maintenance_until_exact_review_then_retries(self):
        self.health_fixture()
        stage = self.root / "manager/os-updates/one"
        stage.mkdir(parents=True, mode=0o700)
        atomic_json(self.root / "manager/os-latest.json", {"state": "reboot_prepared", "stage": str(stage),
                    "boot_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"})
        journal = self.root / "manager/os-transaction.json"
        atomic_json(journal, {"state": "reboot_requested"})
        with self.assertRaisesRegex(Refused, "maintenance remains active"):
            self.manager.reboot_complete()
        self.assertEqual(json.loads(journal.read_text())["state"], "recovery_required")
        self.manager.maintenance.assert_called_with(True, stage)
        self.approve(stage)
        self.assertEqual(self.manager.reboot_complete()["status"], "complete")
        self.manager.maintenance.assert_called_with(False, stage)
        self.assertEqual(self.scans, 2)

    def test_same_boot_os_recovery_accepts_exact_review_without_repeating_dnf(self):
        integrity = patch("nebulalog_adapters.lifecycle.os_payload.accept_integrity", return_value={"ok": True})
        integrity.start()
        self.addCleanup(integrity.stop)
        self.health_fixture()
        stage = self.root / "manager/os-updates/one"
        stage.mkdir(parents=True, mode=0o700)
        self.manager.checked_backup = Mock()
        atomic_json(self.root / "manager/os-latest.json", {"state": "prepared", "stage": str(stage), "boot_id": self.boot})
        journal = self.root / "manager/os-transaction.json"
        atomic_json(journal, {"state": "recovery_required", "recovery_phase": "postcheck", "stage": str(stage), "boot_id": self.boot})
        original = self.manager.cmd
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            if argv == ["dnf", "needs-restarting", "--reboothint"]:
                return ""
            return original(argv, **kwargs)
        self.manager.cmd = runner
        with self.assertRaisesRegex(Refused, "maintenance and recovery evidence"):
            self.manager.os_recover()
        self.assertEqual(json.loads(journal.read_text())["state"], "recovery_required")
        self.manager.maintenance.assert_called_with(True, stage)
        self.approve(stage)
        self.assertEqual(self.manager.os_recover()["status"], "updated")
        self.manager.maintenance.assert_called_with(False, stage)
        self.assertEqual(self.scans, 2)
        self.assertEqual([call for call in calls if call[0] == "dnf"], [["dnf", "needs-restarting", "--reboothint"]])


if __name__ == "__main__":
    unittest.main()
