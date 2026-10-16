"""Reviewed factory packaging and conflict binding; fixtures are not compliance approval."""
import copy
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from nebulalog_manager import baseline
from nebulalog_manager.common import Refused
import test_baseline as fixtures
import test_baseline_remediation as remediation

spec = importlib.util.spec_from_file_location("build_unified_baseline", Path(__file__).parents[1] / "packer/build_unified_baseline.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class UnifiedFactoryTests(unittest.TestCase):
    setUp = fixtures.BaselineTests.setUp
    directory = fixtures.BaselineTests.directory
    runner = fixtures.BaselineTests.runner
    policy = fixtures.BaselineTests.policy
    merged_policy = remediation.RemediationTests.merged_policy

    def write_mapping(self, policy, mapping):
        path = Path(policy["unified_mapping"]["path"])
        path.write_text(json.dumps(mapping))
        policy["unified_mapping"]["sha256"] = baseline._sha(path)

    def conflict_policy(self):
        source = self.source.read_text().replace(
            '<x:Profile id="' + fixtures.CIS + '">',
            '<x:Profile id="' + fixtures.CIS + '"><x:refine-value idref="xccdf_timeout" selector="five"/>')
        source = source.replace('<x:Profile id="' + fixtures.STIG + '">',
                                '<x:Profile id="' + fixtures.STIG + '"><x:refine-value idref="xccdf_timeout" selector="ten"/>')
        self.source.write_text(source.replace('</x:Benchmark>',
            '<x:Value id="xccdf_timeout"><x:value>600</x:value><x:value selector="five">300</x:value>'
            '<x:value selector="ten">600</x:value></x:Value></x:Benchmark>'))
        policy = self.merged_policy()
        item = policy["unified_remediation"]
        path = Path(item["tailoring"])
        path.write_text(path.read_text().replace('</Profile>', '<refine-value idref="xccdf_timeout" selector="five"/></Profile>'))
        item.update(tailoring_sha256=baseline._sha(path), tailoring_values=[{
            "value_id": "xccdf_timeout", "selector": "five", "rationale": "Fixture shorter idle timeout"}])
        mapping = baseline._json(policy["unified_mapping"]["path"])
        mapping["remediation"]["tailoring_sha256"] = item["tailoring_sha256"]
        conflicts = baseline.unified_value_conflicts(policy["assessments"])
        mapping["value_decisions"] = [{"value_id": "xccdf_timeout", "choices": conflicts["xccdf_timeout"],
            "decision": "stricter-compatible", "rationale": "Fixture shorter idle timeout", "effective": {"selector": "five", "value": "300"}}]
        self.write_mapping(policy, mapping)
        return policy

    def test_actual_merged_value_must_match_each_original_conflict_decision(self):
        policy = self.conflict_policy()
        baseline.validate_policy(policy, self.runner, self.now)
        original = baseline._json(policy["unified_mapping"]["path"])
        for mutation in ("missing", "duplicate", "forged-source", "different-effective", "unreviewed"):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                decisions = value["value_decisions"]
                if mutation == "missing": decisions.clear()
                elif mutation == "duplicate": decisions.append(copy.deepcopy(decisions[0]))
                elif mutation == "forged-source": decisions[0]["choices"]["cis"]["value"] = "1"
                elif mutation == "different-effective": decisions[0]["effective"] = {"selector": "ten", "value": "600"}
                else: decisions[0]["decision"] = "pending"
                self.write_mapping(policy, value)
                with self.assertRaisesRegex(Refused, "Unified (mapping|value)"):
                    baseline.validate_policy(policy, self.runner, self.now)

    def test_assessment_tailoring_cannot_hide_original_value_conflict(self):
        policy = self.conflict_policy()
        policy["assessments"][0]["tailoring_values"] = [{"value_id": "xccdf_timeout", "selector": "ten"}]
        observed = baseline.unified_value_conflicts(policy["assessments"])
        self.assertEqual(observed["xccdf_timeout"]["cis"], {"selector": "five", "value": "300"})

    def test_ambiguous_default_or_unsupported_profile_value_is_refused(self):
        policy = self.conflict_policy()
        original = self.source.read_text()
        for changed, error in (
                (original.replace('<x:value>600</x:value>', '<x:value>600</x:value><x:value>300</x:value>'),
                 "unique source values and one default"),
                (original.replace('<x:refine-value idref="xccdf_timeout" selector="five"/>', '<x:set-value idref="xccdf_timeout">1</x:set-value>'),
                 "source profiles must use existing named values")):
            with self.subTest(error=error):
                self.source.write_text(changed)
                for item in policy["assessments"]:
                    item["sha256"] = baseline._sha(self.source)
                with self.assertRaisesRegex(Refused, error):
                    baseline.unified_value_conflicts(policy["assessments"])

    def factory_candidate(self):
        policy = self.conflict_policy()
        catalog = {key: policy["assessments"][0][key] for key in ("datastream", "sha256", "content_revision", "source_url")}
        catalog.update(schema=1, platform_basis="Fixture reviewed Rocky applicability", license_basis="Fixture content licensing", profiles={})
        for item in policy["assessments"]:
            kind = item["kind"]
            path = self.root / ("baseline-" + kind + ".xml")
            profile_id = "xccdf_test_" + kind
            base = item["profile_id"]
            path.write_text(f'<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_tailoring_{kind}"><benchmark href="{self.source.name}"/><Profile id="{profile_id}" extends="{base}"><select idref="xccdf_rule_3" selected="false"/></Profile></Tailoring>')
            item.update(base_profile_id=base, profile_id=profile_id, tailoring=str(path), tailoring_sha256=baseline._sha(path),
                        tailoring_decisions=[{"rule_id": "xccdf_rule_3", "selected": False, "rationale": "Fixture application exception", "effective_control": "Fixture manual control"}])
            profile = {key: item[key] for key in builder.PROFILE_FIELDS}
            profile.update(tailoring_file=path.name, benchmark_basis="Fixture coverage limits reviewed")
            catalog["profiles"]["cis-level2" if kind == "cis" else "stig"] = profile
        mapping = baseline._json(policy["unified_mapping"]["path"])
        mapping["assessments"] = {p["kind"]: baseline.assessment_binding(p) for p in policy["assessments"]}
        self.write_mapping(policy, mapping)
        (self.root / "baseline-catalog.json").write_text(json.dumps(catalog))
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps(policy))
        return policy, policy_path

    def test_draft_has_complete_rule_and_value_inventory_without_approval(self):
        self.factory_candidate()
        draft = builder.review_inputs(self.root, self.source, self.runner)
        self.assertFalse(draft["coverage_reviewed"])
        self.assertFalse(draft["review"]["approved"])
        self.assertEqual(len(draft["controls"]), 4)
        self.assertEqual(len(draft["value_decisions"]), 1)
        self.assertEqual({r["decision"] for r in draft["controls"]}, {"pending"})
        self.assertEqual({r["applied_rule"] for r in draft["controls"]}, {None})

    def test_package_roundtrip_preserves_review_and_separate_assessments(self):
        policy, path = self.factory_candidate()
        output = self.root / "package"
        with patch.object(builder, "trusted_file", side_effect=lambda p: Path(p)):
            receipt = builder.package_policy(self.root, path, output, self.runner, self.now)
        self.assertFalse(receipt["approval_created"])
        self.assertFalse(receipt["guest_remediation_performed"])
        result = baseline.factory_policy("unified", "Fixture operator", output, self.runner, self.now)
        self.assertEqual(len(result["assessments"]), 2)
        self.assertEqual(result["unified_remediation"]["profile_id"], "xccdf_test_unified")
        captured = baseline._json(result["unified_mapping"]["path"])
        self.assertEqual(captured, baseline._json(policy["unified_mapping"]["path"]))
        self.assertEqual(captured["review"]["reviewer"], "Fixture content reviewer")
        self.assertFalse(self.manager.review_path.exists())
        with self.assertRaisesRegex(Refused, "expired"):
            baseline.factory_policy("unified", "Another operator", output, self.runner, self.now + timedelta(days=31))
        with patch.object(builder, "trusted_file", side_effect=lambda p: Path(p)), self.assertRaises(FileExistsError):
            builder.package_policy(self.root, path, output, self.runner, self.now)

    def test_unreviewed_mapping_cannot_be_packaged_or_accepted_by_console(self):
        policy, path = self.factory_candidate()
        mapping = baseline._json(policy["unified_mapping"]["path"])
        mapping["coverage_reviewed"] = False
        self.write_mapping(policy, mapping)
        path.write_text(json.dumps(policy))
        with self.assertRaisesRegex(Refused, "review coverage"):
            builder.package_policy(self.root, path, self.root / "refused", self.runner, self.now)
        self.assertFalse((self.root / "refused").exists())

    def test_packaging_refuses_different_factory_assessment_provenance(self):
        policy, path = self.factory_candidate()
        policy["assessments"][0]["content_revision"] = "different-content-release"
        path.write_text(json.dumps(policy))
        with self.assertRaisesRegex(Refused, "exact factory candidates"):
            builder.package_policy(self.root, path, self.root / "refused", self.runner, self.now)
        self.assertFalse((self.root / "refused").exists())

    def test_mapping_filename_and_bytes_are_pinned(self):
        _, path = self.factory_candidate()
        output = self.root / "package"
        with patch.object(builder, "trusted_file", side_effect=lambda p: Path(p)):
            builder.package_policy(self.root, path, output, self.runner, self.now)
        catalog_path = output / "baseline-catalog.json"
        catalog = baseline._json(catalog_path)
        mapping = output / "baseline-unified-mapping.json"
        mapping.write_bytes(mapping.read_bytes() + b"\n")
        with self.assertRaisesRegex(Refused, "exact hashed conflict mapping"):
            baseline.factory_profile("unified", output)
        catalog["profiles"]["unified"]["mapping_file"] = "../mapping.json"
        catalog_path.write_text(json.dumps(catalog))
        with self.assertRaisesRegex(Refused, "exact hashed conflict mapping"):
            baseline.factory_profile("unified", output)

    def test_same_profile_ids_cannot_reuse_review_after_assessment_rules_or_values_change(self):
        _, path = self.factory_candidate()
        output = self.root / "package"
        with patch.object(builder, "trusted_file", side_effect=lambda p: Path(p)):
            builder.package_policy(self.root, path, output, self.runner, self.now)
        catalog_path = output / "baseline-catalog.json"
        original_catalog = baseline._json(catalog_path)
        originals = {kind: (output / profile["tailoring_file"]).read_text()
                     for kind, profile in original_catalog["profiles"].items() if kind != "unified"}
        original_mapping = (output / "baseline-unified-mapping.json").read_bytes()
        for mutation in ("exclude-rule", "change-value", "change-rationale"):
            catalog = copy.deepcopy(original_catalog)
            for kind, original in originals.items():
                profile = catalog["profiles"][kind]
                content = original
                if mutation == "exclude-rule":
                    content = original.replace('</Profile>', '<select idref="xccdf_rule_0" selected="false"/></Profile>')
                    profile["tailoring_decisions"].append({"rule_id": "xccdf_rule_0", "selected": False,
                        "rationale": "New unreviewed application exception", "effective_control": "New unreviewed manual control"})
                elif mutation == "change-value":
                    content = original.replace('</Profile>', '<refine-value idref="xccdf_timeout" selector="ten"/></Profile>')
                    profile["tailoring_values"] = [{"value_id": "xccdf_timeout", "selector": "ten",
                        "rationale": "New unreviewed timeout semantics"}]
                else:
                    profile["tailoring_decisions"][0]["rationale"] = "Different control review basis"
                tailoring = output / profile["tailoring_file"]
                tailoring.write_text(content)
                profile["tailoring_sha256"] = baseline._sha(tailoring)
            catalog_path.write_text(json.dumps(catalog))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(Refused, "does not match the selected benchmark content"):
                baseline.factory_policy("unified", "Another operator", output, self.runner, self.now)
            self.assertEqual((output / "baseline-unified-mapping.json").read_bytes(), original_mapping)


if __name__ == "__main__":
    unittest.main()
