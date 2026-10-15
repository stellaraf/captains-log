"""Bundled content selection remains distinct from findings approval."""
import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from nebulalog_manager import baseline, firstboot
from nebulalog_manager.common import Refused
import test_baseline_tailoring as tailoring_fixtures


class FactoryBaselineTests(unittest.TestCase):
    setUp = tailoring_fixtures.TailoringTests.setUp
    directory = tailoring_fixtures.TailoringTests.directory
    runner = tailoring_fixtures.TailoringTests.runner
    policy = tailoring_fixtures.TailoringTests.policy
    select = tailoring_fixtures.TailoringTests.select
    tailored = tailoring_fixtures.TailoringTests.tailored

    def catalog(self):
        item = self.tailored()['assessments'][0]
        target = self.root / 'baseline-cis.xml'
        self.tailoring.rename(target)
        value = {key: item[key] for key in ('datastream', 'sha256', 'source_url', 'content_revision')}
        value.update(schema=1, platform_basis='Fixture Rocky applicability review', license_basis='Fixture content license review',
                     profiles={'cis-level2': {key: item[key] for key in ('kind', 'profile_id', 'base_profile_id', 'tailoring_sha256', 'tailoring_decisions')}})
        value['profiles']['cis-level2'].update(tailoring_file=target.name, benchmark_basis='Fixture benchmark coverage limits')
        (self.root / 'baseline-catalog.json').write_text(json.dumps(value))
        return value

    def test_exact_candidate_and_named_acceptance_create_unapproved_installation_policy(self):
        self.catalog()
        policy = baseline.factory_policy('cis-level2', 'Fixture operator', self.root, self.runner, self.now)
        review = policy['assessments'][0]['content_review']
        self.assertEqual(review['reviewer'], 'Initial-console operator: Fixture operator')
        self.assertNotIn('installation_id', policy)
        self.assertFalse(self.manager.review_path.exists())
        self.select(policy)
        self.assertFalse(self.manager.assessment_path.exists())
        self.assertFalse(self.manager.review_path.exists())

    def test_missing_identity_modified_content_and_unmapped_unified_refused(self):
        self.catalog()
        with self.assertRaises(Refused):
            baseline.factory_policy('cis-level2', '', self.root, self.runner, self.now)
        with self.assertRaisesRegex(Refused, 'conflict mapping'):
            baseline.factory_policy('unified', 'Fixture operator', self.root, self.runner, self.now)
        self.source.write_text(self.source.read_text() + '\n')
        with self.assertRaises(Refused):
            baseline.factory_policy('cis-level2', 'Fixture operator', self.root, self.runner, self.now)

    def test_tailoring_filename_cannot_escape_catalog(self):
        value = self.catalog()
        value['profiles']['cis-level2']['tailoring_file'] = '../other.xml'
        (self.root / 'baseline-catalog.json').write_text(json.dumps(value))
        with self.assertRaisesRegex(Refused, 'fixed local filename'):
            baseline.factory_profile('cis-level2', self.root)

    def test_console_acceptance_and_application_are_separate_and_cancellable(self):
        self.catalog()
        original_profile, original_policy = baseline.factory_profile, baseline.factory_policy
        manager = SimpleNamespace(paths=SimpleNamespace(data=self.root), runner=self.runner,
                                  gate=lambda: {'installation_id': '11111111-2222-4333-8444-555555555555'})
        with patch.object(baseline, 'Baseline', return_value=self.manager), \
             patch.object(baseline, 'factory_profile', side_effect=lambda b, directory=None: original_profile(b, directory or self.root)), \
             patch.object(baseline, 'factory_policy', side_effect=lambda b, r, **kw: original_policy(b, r, self.root, self.runner, self.now, expected_catalog=kw.get("expected_catalog"))), \
             patch.object(baseline, 'initial_hardening', return_value=nullcontext()), \
             patch.object(self.manager, 'remediate') as apply, patch('builtins.print'):
            with patch.object(firstboot, '_answer', return_value='CANCEL'):
                result = firstboot._hardening_console(manager, {'baseline': 'cis-level2'})
            self.assertFalse(result['host_modified'])
            self.assertFalse(self.manager.policy_path.exists())
            with patch.object(firstboot, '_answer', side_effect=['ACCEPT', 'Fixture operator', 'CANCEL']):
                result = firstboot._hardening_console(manager, {'baseline': 'cis-level2'})
            self.assertTrue(self.manager.policy_path.exists())
            self.assertFalse(self.manager.review_path.exists())
            apply.assert_not_called()

    def test_changed_displayed_catalog_requires_new_content_review(self):
        displayed = self.catalog()
        displayed['content_revision'] = 'different displayed revision'
        with self.assertRaisesRegex(Refused, 'changed after content was displayed'):
            baseline.factory_policy('cis-level2', 'Fixture operator', self.root, self.runner, self.now, displayed)
