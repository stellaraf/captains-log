"""Exact base/effective profile binding and retained tailoring evidence."""
import copy
from contextlib import nullcontext
from pathlib import Path
import unittest
from unittest.mock import patch

from nebulalog_manager import baseline
from nebulalog_manager.common import Refused
import test_baseline as fixtures


class TailoringTests(unittest.TestCase):
    setUp = fixtures.BaselineTests.setUp
    directory = fixtures.BaselineTests.directory
    runner = fixtures.BaselineTests.runner
    policy = fixtures.BaselineTests.policy
    select = fixtures.BaselineTests.select

    def tailored(self):
        policy = self.policy()
        item = policy['assessments'][0]
        self.tailoring = self.root / 'tailoring.xml'
        self.tailoring.write_text(f'''<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_tailoring">
<benchmark href="{self.source.name}"/><version time="2026-10-12T00:00:00Z">1</version>
<Profile id="xccdf_test_effective" extends="{fixtures.CIS}"><title>Appliance profile</title>
<select idref="xccdf_rule_1" selected="false"/></Profile></Tailoring>''')
        self.tailoring.chmod(0o600)
        item.update(base_profile_id=fixtures.CIS, profile_id='xccdf_test_effective',
                    tailoring=str(self.tailoring), tailoring_sha256=baseline._sha(self.tailoring),
                    tailoring_decisions=[{'rule_id': 'xccdf_rule_1', 'selected': False,
                        'rationale': 'Fixture required application service',
                        'effective_control': 'Fixture service hardened separately'}])
        return policy

    def rewrite(self, policy, old, new):
        self.tailoring.write_text(self.tailoring.read_text().replace(old, new))
        policy['assessments'][0]['tailoring_sha256'] = baseline._sha(self.tailoring)

    def grouped(self):
        policy = self.tailored()
        self.source.write_text(self.source.read_text().replace('<x:Rule id="xccdf_rule_2"/>',
            '<x:Group id="xccdf_group_fixture" selected="false"><x:Rule id="xccdf_rule_2"/></x:Group>'))
        item = policy['assessments'][0]
        item['sha256'] = baseline._sha(self.source)
        item['tailoring_groups'] = [{'group_id':'xccdf_group_fixture','selected':True,
            'affected_rules':['xccdf_rule_2'],'rationale':'Include the reviewed union rule',
            'effective_control':'Enable parent so the reviewed child can participate'}]
        self.rewrite(policy, '</Profile>', '<select idref="xccdf_group_fixture" selected="true"/></Profile>')
        return policy

    def test_reviewed_group_enablement_requires_full_descendant_inventory(self):
        policy = self.grouped()
        self.select(policy)
        for field,value in [('affected_rules',[]),('affected_rules',['xccdf_rule_2','unknown']),
                            ('selected',False),('group_id','unknown')]:
            candidate = copy.deepcopy(policy)
            candidate['assessments'][0]['tailoring_groups'][0][field] = value
            with self.subTest(field=field), self.assertRaises(Refused):
                baseline.validate_policy(candidate,self.runner,self.now)

    def test_unreviewed_and_duplicate_group_enablement_refused(self):
        policy = self.grouped()
        item = policy['assessments'][0]
        item['tailoring_groups'].append(copy.deepcopy(item['tailoring_groups'][0]))
        with self.assertRaises(Refused):self.select(policy)
        item['tailoring_groups'] = []
        with self.assertRaises(Refused):self.select(policy)

    def test_scan_uses_effective_profile_and_retains_exact_tailoring(self):
        policy = self.tailored()
        self.select(policy)
        self.manager.scan(fixtures.INSTALLATION, 'cis-level2')
        calls = [argv for argv, _ in self.calls if argv[:3] == ['oscap', 'xccdf', 'eval']]
        self.assertEqual(calls[0][calls[0].index('--profile') + 1], 'xccdf_test_effective')
        self.assertEqual(calls[0][calls[0].index('--tailoring-file') + 1], str(self.tailoring))
        retained = list((self.configuration / 'baseline-assessments').glob('*/cis-tailoring.xml'))
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), self.tailoring.read_bytes())

    def test_remediation_uses_captured_tailoring_and_content(self):
        policy = self.tailored()
        self.select(policy)
        with patch.object(baseline, 'initial_hardening', return_value=nullcontext()):
            result = self.manager.remediate(fixtures.INSTALLATION, 'cis-level2', baseline._sha(self.manager.policy_path))
        command = next(argv for argv, _ in self.calls if '--remediate' in argv)
        captured = Path(command[command.index('--tailoring-file') + 1])
        self.assertNotEqual(captured, self.tailoring)
        self.assertEqual(captured.read_bytes(), self.tailoring.read_bytes())
        self.assertEqual(Path(command[-1]).parent, captured.parent)
        self.assertEqual(Path(command[-1]).name, self.source.name)
        self.assertEqual(result['tailoring_sha256'], baseline._sha(captured))
        self.assertTrue(result['review_required'])

    def test_hash_change_refused_before_scan(self):
        policy = self.tailored()
        self.tailoring.write_text(self.tailoring.read_text() + '\n')
        with self.assertRaisesRegex(Refused, 'hash'):
            self.select(policy)

    def test_profile_switch_external_source_and_hidden_overrides_refused(self):
        changes = [
            (fixtures.CIS, fixtures.STIG),
            (self.source.name, 'https://example.invalid/source.xml'),
            ('selected="false"', 'selected="true"'),
            ('<select', '<select hidden="true"'),
            ('</Profile>', '<set-value idref="anything">0</set-value></Profile>'),
            ('</Profile>', '<select idref="xccdf_rule_1" selected="false"/></Profile>'),
            ('</Tailoring>', '<Profile id="xccdf_hidden"/></Tailoring>'),
        ]
        for old, new in changes:
            with self.subTest(change=new):
                policy = self.tailored()
                self.rewrite(policy, old, new)
                with self.assertRaises(Refused):
                    self.select(policy)

    def test_missing_or_ambiguous_review_decisions_refused(self):
        for decisions in ([], [{'rule_id': 'missing', 'selected': False}], None):
            policy = self.tailored()
            policy['assessments'][0]['tailoring_decisions'] = decisions
            with self.assertRaises(Refused):
                self.select(policy)

    def test_base_id_without_tailoring_refused(self):
        policy = self.policy()
        policy['assessments'][0]['base_profile_id'] = fixtures.CIS
        with self.assertRaises(Refused):
            self.select(policy)

    def value_tailoring(self):
        self.source.write_text(self.source.read_text().replace('</x:Benchmark>',
            '<x:Value id="xccdf_test_value_timeout"><x:value selector="five">300</x:value>'
            '<x:value selector="ten">600</x:value></x:Value></x:Benchmark>'))
        policy = self.tailored()
        item = policy['assessments'][0]
        item['tailoring_values'] = [{'value_id': 'xccdf_test_value_timeout', 'selector': 'five',
                                    'rationale': 'Use the stricter five-minute timeout'}]
        self.rewrite(policy, '</Profile>', '<refine-value idref="xccdf_test_value_timeout" selector="five"/></Profile>')
        return policy

    def test_named_value_selection_is_bound_to_source_and_review(self):
        policy = self.value_tailoring()
        self.select(policy)
        self.assertEqual(baseline._json(self.manager.policy_path)['assessments'][0]['tailoring_values'],
                         policy['assessments'][0]['tailoring_values'])

    def test_unknown_or_unreviewed_value_selection_is_refused(self):
        policy = self.value_tailoring()
        for value, selector in [('xccdf_missing_value', 'five'), ('xccdf_test_value_timeout', 'unknown'),
                                ('xccdf_test_value_timeout', 'ten')]:
            candidate = copy.deepcopy(policy)
            candidate['assessments'][0]['tailoring_values'][0].update(value_id=value, selector=selector)
            with self.subTest(value=value, selector=selector), self.assertRaises(Refused):
                self.select(candidate)

    def test_hidden_value_override_and_duplicate_decisions_are_refused(self):
        policy = self.value_tailoring()
        item = policy['assessments'][0]
        item['tailoring_values'].append(copy.deepcopy(item['tailoring_values'][0]))
        with self.assertRaisesRegex(Refused, 'Duplicate'):
            self.select(policy)
        item['tailoring_values'] = []
        with self.assertRaises(Refused):
            self.select(policy)
