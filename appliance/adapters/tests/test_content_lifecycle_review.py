"""Independent real filesystem content/host integration.

Archive, selected-policy derivation, immutable generation ownership, exact host
plans, atomic apply and rollback are production code. Native scanner/service
commands, AIDE execution and assessment calls are explicit fixture boundaries;
these tests do not claim native assessment or whole-appliance acceptance.
"""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from nebulalog_adapters import host_runtime as runtime, lifecycle
from nebulalog_manager import host_activation as activation
from nebulalog_manager import baseline
from nebulalog_manager.baseline import ContentUpdate as Content
from nebulalog_manager.common import Refused, atomic_json
from test_baseline import INSTALLATION
from test_content_update import ContentFixture, closed_source
from test_host_runtime import RuntimeFixture
from test_host_payload import fixture_tree


@unittest.skipUnless(os.geteuid() == 0, 'Requires isolated root filesystem fixture')
class ContentRuntimeReviewTests(RuntimeFixture):
    policy = ContentFixture.policy
    archive = ContentFixture.archive
    approve_request = ContentFixture.approve_request

    def setUp(self):
        super().setUp()
        self.configuration = self.lifecycle.configuration
        self.source = self.root / 'selected-vendor.xml'
        self.source.write_bytes(closed_source())
        self.source.chmod(0o600)
        self.now = datetime.now(timezone.utc)
        self.calls = []
        def private_directory(path, create=False):
            path = Path(path)
            if create:
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
            fixture_tree(self.root)(path)
            return path
        # The fixture is below system /tmp; inspect its complete private
        # ancestry without claiming that the system temp parent is trusted.
        context = patch.object(baseline, '_directory', side_effect=private_directory)
        context.start(); self.addCleanup(context.stop)
        self.generation_root = self.root / 'content-generations'
        context = patch.object(Content, 'ROOT', self.generation_root)
        context.start(); self.addCleanup(context.stop)
        self.addCleanup(lambda: ContentFixture.writable(self))
        self.configure_content('cis-level2')
        self.assessments = []
        def assessment(stage, raw, role='candidate'):
            self.assertEqual(stage, self.stage)
            self.assertEqual((self.configuration / 'security-policy.json').read_bytes(), self.original)
            self.assertTrue(self.integrity_calls and self.integrity_calls[-1][0] == 'prepare')
            self.assessments.append((role, raw))
            return {'ok': True}
        context = patch.object(self.lifecycle, 'content_assessment', side_effect=assessment)
        context.start(); self.addCleanup(context.stop)

    def configure_content(self, selected):
        self.selected = self.policy(selected)
        self.selected.update(installation_id=INSTALLATION, selection_id='1' * 32,
            exceptions=[{'id': 'operator-exception', 'expires_at': '2099-01-01T00:00:00Z'}])
        atomic_json(self.configuration / 'security-policy.json', self.selected)
        self.original = (self.configuration / 'security-policy.json').read_bytes()
        self.identity = Content.measure(self.configuration / 'security-policy.json', self.command)
        self.archive()
        self.manifest['components']['baseline'] = self.release['components']['baseline']
        self.manifest['artifacts'] = [item for item in self.manifest['artifacts'] if item['name'] != 'content.tar'] + self.release['artifacts']
        self.transaction['previous']['components']['baseline'] = copy.deepcopy(self.identity)
        self.bind_manifest(); self.save_transaction('preflight')
        self.host = runtime.HostRuntime(self.lifecycle, self.stage)

    def command(self, argv, **kwargs):
        if argv[:1] in (['oscap'], ['rpm']):
            return ContentFixture.runner(self, argv, **kwargs)
        return super().command(argv, **kwargs)

    def reviewed(self):
        with self.assertRaisesRegex(Refused, 'semantics changed'):
            self.host.preflight()
        self.assertEqual((self.configuration / 'security-policy.json').read_bytes(), self.original)
        self.assertFalse(self.host.plan_path.exists())
        self.assertFalse(self.generation_root.exists())
        self.approve_request()

    def rollback(self):
        self.save_transaction('rolling_back')
        activation.restore_previous(self.stage)
        host = runtime.HostRuntime(self.lifecycle, self.stage)
        host.apply(rollback=True)
        host.runtime_evidence('update-health', accept_integrity=True)
        return host

    def test_exact_reviewed_policy_applies_and_rolls_back_with_customer_state_preserved(self):
        self.reviewed()
        credentials = (self.configuration / 'credentials.json').read_bytes()
        trust = (runtime.ETC / 'release-public.pem').read_bytes()
        self.select_and_apply()
        plan = self.host.checked_plan()
        self.assertEqual(plan['schema'], 2)
        candidate = (self.configuration / 'security-policy.json').read_bytes()
        policy = json.loads(candidate)
        self.assertNotEqual(candidate, self.original)
        for key in ('baseline', 'installation_id', 'selection_id', 'exceptions'):
            self.assertEqual(policy[key], self.selected[key])
        self.assertEqual(self.assessments, [('rollback', self.original), ('candidate', candidate)])
        selected = Content.selected_authority(policy)
        self.assertEqual(selected['plan'], plan['content'])
        self.assertEqual(Content.measure(self.configuration / 'security-policy.json', self.command)['version'], '1.2.3')
        self.save_transaction('checking')
        self.host.runtime_evidence('update-health', accept_integrity=True)
        self.assertEqual(self.integrity_calls[-1][0], 'forward')
        immutable = {p: p.read_bytes() for p in Path(plan['content']['root']).iterdir()}
        self.rollback()
        self.assertEqual((self.configuration / 'security-policy.json').read_bytes(), self.original)
        self.assertEqual(Content.measure(self.configuration / 'security-policy.json', self.command), self.identity)
        self.assertEqual((self.configuration / 'credentials.json').read_bytes(), credentials)
        self.assertEqual((runtime.ETC / 'release-public.pem').read_bytes(), trust)
        self.assertEqual(self.integrity_calls[-1][0], 'rollback')
        self.assertEqual({p: p.read_bytes() for p in immutable}, immutable)
        self.assertTrue(self.maintenance.exists())

    def test_missing_semantic_approval_has_no_active_policy_or_host_integrity_effect(self):
        before = {p: p.read_bytes() for p in self.host._target_paths()}
        with self.assertRaisesRegex(Refused, 'semantics changed'):
            self.host.preflight()
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertEqual(self.integrity_calls, [])
        self.assertEqual(self.assessments, [])
        self.assertFalse(self.host.root.exists())

    def other_selection(self, selected):
        self.configure_content(selected)
        mapping = baseline._json(self.selected['unified_mapping']['path']) if selected == 'unified' else None
        self.reviewed(); self.select_and_apply()
        policy = json.loads((self.configuration / 'security-policy.json').read_bytes())
        self.assertEqual(policy['baseline'], selected)
        self.assertEqual(policy['selection_id'], self.selected['selection_id'])
        self.assertEqual(policy['exceptions'], self.selected['exceptions'])
        self.assertEqual([a['kind'] for a in policy['assessments']], [a['kind'] for a in self.selected['assessments']])
        if mapping is not None:
            updated = baseline._json(policy['unified_mapping']['path'])
            self.assertEqual(updated['controls'], mapping['controls'])
            self.assertEqual(updated['review'], mapping['review'])
        self.rollback()
        self.assertEqual((self.configuration / 'security-policy.json').read_bytes(), self.original)

    def test_stig_selection_survives_real_policy_apply_and_rollback(self):
        self.other_selection('stig')

    def test_unified_mapping_and_selection_survive_real_policy_apply_and_rollback(self):
        self.other_selection('unified')

    def test_candidate_assessment_refusal_retains_pending_evidence_without_activation(self):
        self.reviewed()
        old_selection = self.selection.read_bytes()
        def refuse(stage, raw, role='candidate'):
            if role == 'candidate':
                raise Refused('fixture candidate facts changed')
            return {'ok': True}
        with patch.object(self.lifecycle, 'content_assessment', side_effect=refuse), self.assertRaisesRegex(Refused, 'facts changed'):
            self.host.preflight()
        self.assertEqual(self.selection.read_bytes(), old_selection)
        self.assertEqual((self.configuration / 'security-policy.json').read_bytes(), self.original)
        self.assertTrue(self.host.plan_path.exists())
        self.assertTrue(Path(self.host.checked_plan()['content']['root']).is_dir())
        self.assertFalse(self.host.root.exists())
        self.assertEqual([x[0] for x in self.integrity_calls], ['prepare'])
        self.assertTrue(self.maintenance.exists())

    def test_unenrolled_or_drifted_content_refuses_before_publication(self):
        for identity in (None, {**self.identity, 'generation': 'f' * 64}):
            with self.subTest(identity=identity is None):
                self.transaction['previous']['components']['baseline'] = identity
                self.save_transaction('preflight')
                with self.assertRaisesRegex(Refused, 'enrolled identity'):
                    runtime.HostRuntime(self.lifecycle, self.stage).preflight()
                self.assertFalse(self.generation_root.exists())
                self.assertEqual((self.configuration / 'security-policy.json').read_bytes(), self.original)
                self.assertFalse(self.integrity_calls)

    def test_partial_policy_activation_retries_exact_bytes_then_rolls_back(self):
        self.reviewed(); self.prepare()
        self.save_transaction('activating'); activation.select_candidate(self.stage)
        host = runtime.HostRuntime(self.lifecycle, self.stage)
        policy_path = self.configuration / 'security-policy.json'
        original_write = lifecycle.atomic_file
        def interrupted(path, raw, *args):
            original_write(path, raw, *args)
            if path == policy_path:
                raise OSError('interruption after policy rename')
        with patch.object(lifecycle, 'atomic_file', side_effect=interrupted), self.assertRaises(OSError):
            host.apply()
        candidate = policy_path.read_bytes()
        self.assertNotEqual(candidate, self.original)
        self.assertEqual([x[0] for x in self.integrity_calls], ['prepare'])
        host.apply()
        self.assertEqual(policy_path.read_bytes(), candidate)
        self.rollback()
        self.assertEqual(policy_path.read_bytes(), self.original)

    def test_unrelated_active_policy_change_is_not_overwritten_or_integrity_accepted(self):
        self.reviewed(); self.prepare()
        self.save_transaction('activating'); activation.select_candidate(self.stage)
        policy_path = self.configuration / 'security-policy.json'
        changed = {**self.selected, 'selection_id': '9' * 32}
        atomic_json(policy_path, changed)
        before = policy_path.read_bytes()
        with self.assertRaisesRegex(Refused, 'unrelated runtime file changes'):
            runtime.HostRuntime(self.lifecycle, self.stage).apply()
        self.assertEqual(policy_path.read_bytes(), before)
        self.assertEqual([x[0] for x in self.integrity_calls], ['prepare'])

    def test_generation_tamper_cannot_promote_integrity_after_activation(self):
        self.reviewed(); self.select_and_apply()
        self.save_transaction('checking')
        plan = self.host.checked_plan()
        path = Path(plan['content']['root']) / 'source.xml'
        path.chmod(0o644); path.write_bytes(path.read_bytes() + b'\n<!-- changed -->\n'); path.chmod(0o444)
        with self.assertRaisesRegex(Refused, 'Immutable content bytes'):
            self.host.runtime_evidence('update-health', accept_integrity=True)
        self.assertEqual([x[0] for x in self.integrity_calls], ['prepare'])

    def test_retained_policy_backup_tamper_refuses_rollback(self):
        self.reviewed(); self.select_and_apply()
        plan = self.host.checked_plan()
        index = next(i for i, row in enumerate(plan['files']) if row['path'] == str(self.configuration / 'security-policy.json'))
        (self.host.root / 'old' / str(index)).write_bytes(b'changed retained preimage')
        current = (self.configuration / 'security-policy.json').read_bytes()
        self.save_transaction('rolling_back'); activation.restore_previous(self.stage)
        with self.assertRaisesRegex(Refused, 'backup content'):
            runtime.HostRuntime(self.lifecycle, self.stage).apply(rollback=True)
        self.assertEqual((self.configuration / 'security-policy.json').read_bytes(), current)
        self.assertEqual([x[0] for x in self.integrity_calls], ['prepare'])

