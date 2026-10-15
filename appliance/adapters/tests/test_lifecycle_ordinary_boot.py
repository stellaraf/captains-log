"""Ordinary-boot lifecycle ordering; native and AIDE evidence have own suites."""
import json
from unittest import TestCase
from unittest.mock import Mock, patch

import test_lifecycle as fixtures
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.ordinary_boot import owns_maintenance as actual_owns_maintenance
from nebulalog_manager.updates import REQUIRED_CHECKS


class OrdinaryBootLifecycleTests(TestCase):
    def setUp(self):
        fixtures.LifecycleTests.setUp(self)
        self.boot = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.boot_stage = self.root / 'manager/boot-integrity' / ('b' * 32)
        self.boot_stage.mkdir(parents=True)
        self.manager.boot_id = Mock(return_value=self.boot)
        self.manager._ordinary_boot_stage = Mock(return_value=self.boot_stage)
        self.events = []
        self.manager.maintenance.side_effect = lambda active, stage: self.events.append('gate-on' if active else 'gate-off')
        self.manager.health = Mock(side_effect=lambda *args, **kwargs: self.events.append('health') or {
            'ok': True, 'checks': {name: True for name in REQUIRED_CHECKS}})
        for name, side_effect in (
            ('reconcile', lambda *args, **kwargs: self.events.append('integrity') or {'ok': True}),
            ('finalize', lambda *args, **kwargs: self.events.append('finalize') or {'ok': True, 'boot_id': self.boot}),
            ('owns_maintenance', lambda *args, **kwargs: True),
        ):
            context = patch('nebulalog_manager.ordinary_boot.' + name, side_effect=side_effect)
            setattr(self, name, context.start()); self.addCleanup(context.stop)
        # No unrelated application transaction is pending in these boot cases.
        (self.root / 'manager/updates/transaction.json').unlink()

    def tearDown(self):
        fixtures.LifecycleTests.tearDown(self)

    def test_pristine_enrolled_boot_without_os_journal_reconciles_before_release(self):
        result = self.manager.reboot_complete()
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(self.events, ['gate-on', 'integrity', 'health', 'finalize', 'gate-off'])
        self.manager.health.assert_called_once_with(self.boot_stage, boot_health=True)
        self.assertFalse((self.root / 'manager/os-latest.json').exists())
        self.assertFalse((self.root / 'manager/os-transaction.json').exists())

    def test_observation_failure_asserts_owned_hold_before_returning_failure(self):
        from nebulalog_adapters.lifecycle import Lifecycle
        actual = Lifecycle._ordinary_boot_stage.__get__(self.manager)
        atomic_json(self.root / 'manager/aide-enrollment.json', {'fixture': True})
        hold = self.boot_stage.parent / 'holds' / ('e' * 32)
        with patch('nebulalog_manager.ordinary_boot.pending_stage', side_effect=Refused('unrelated drift')), \
                patch('nebulalog_manager.ordinary_boot.observation_hold', return_value=hold) as acquire:
            with self.assertRaisesRegex(Refused, 'observation requires recovery; maintenance remains active'):
                actual()
        acquire.assert_called_once_with(self.root, boot_id=self.boot)
        self.manager.maintenance.assert_called_once_with(True, hold)
        self.reconcile.assert_not_called()

    def test_observation_failure_cannot_overwrite_foreign_hold(self):
        from nebulalog_adapters.lifecycle import Lifecycle
        actual = Lifecycle._ordinary_boot_stage.__get__(self.manager)
        atomic_json(self.root / 'manager/aide-enrollment.json', {'fixture': True})
        with patch('nebulalog_manager.ordinary_boot.pending_stage', side_effect=Refused('foreign owner')), \
                patch('nebulalog_manager.ordinary_boot.observation_hold', side_effect=Refused('foreign owner')):
            with self.assertRaisesRegex(Refused, 'foreign owner'):
                actual()
        self.manager.maintenance.assert_not_called()
        self.reconcile.assert_not_called()

    def test_completed_os_retention_does_not_skip_ordinary_verification(self):
        latest = {'state': 'reboot_completed', 'stage': str(self.stage), 'boot_id': 'a' * 36}
        transaction = {**latest, 'state': 'complete', 'finalization': 'complete',
                       'kernel_finalization': 'complete', 'kernel_retention': 'complete'}
        for name, value in (('os-latest.json', latest), ('os-transaction.json', transaction)):
            atomic_json(self.root / 'manager' / name, value)
        before = (self.root / 'manager/os-transaction.json').read_bytes()
        self.assertEqual(self.manager.reboot_complete()['status'], 'complete')
        self.assertEqual((self.root / 'manager/os-transaction.json').read_bytes(), before)
        self.reconcile.assert_called_once()

    def test_boot_gate_claims_ordinary_owner_before_edge(self):
        result = self.manager.boot_gate()
        self.assertTrue(result['maintenance'])
        self.assertEqual(result['source'], 'ordinary boot integrity')
        self.manager.maintenance.assert_called_once_with(True, self.boot_stage)
        self.reconcile.assert_not_called()
        self.manager.health.assert_not_called()

    def test_pending_os_retention_keeps_its_owner_and_skips_ordinary_gate(self):
        atomic_json(self.root / 'manager/os-transaction.json', {'state': 'complete', 'stage': str(self.stage),
                    'finalization': 'pending', 'kernel_retention': 'pending'})
        result = self.manager.boot_gate()
        self.assertEqual(result['source'], 'interrupted transaction')
        self.manager._ordinary_boot_stage.assert_not_called()
        self.manager.maintenance.assert_called_once_with(True, self.stage)

    def test_verified_nochange_does_not_claim_or_release_any_gate(self):
        self.manager._ordinary_boot_stage.return_value = None
        self.assertEqual(self.manager.reboot_complete()['status'], 'not_pending')
        self.manager.maintenance.assert_not_called()
        self.reconcile.assert_not_called()
        self.manager.health.assert_not_called()

    def test_foreign_maintenance_owner_is_never_overwritten(self):
        marker = self.root / 'manager/maintenance.json'
        atomic_json(marker, {'active': True, 'release': str(self.stage)})
        before = marker.read_bytes()
        self.owns_maintenance.side_effect = None
        self.owns_maintenance.return_value = False
        with self.assertRaisesRegex(Refused, 'Another operation owns maintenance'):
            self.manager.reboot_complete()
        self.manager.maintenance.assert_not_called()
        self.reconcile.assert_not_called()
        self.assertEqual(marker.read_bytes(), before)

    def test_real_owner_accepts_existing_current_and_ancestor_gate(self):
        ancestor = self.boot_stage.parent / ('a' * 32)
        self.owns_maintenance.side_effect = actual_owns_maintenance
        # Generation-file validation is covered by ordinary_boot's suite;
        # exercise the real cross-module owner interface here.
        with patch('nebulalog_manager.ordinary_boot._ancestors', return_value=[
                (self.boot_stage, {'hold': None}, 'b' * 64), (ancestor, {'hold': None}, 'a' * 64)]):
            for owner in (self.boot_stage, ancestor):
                with self.subTest(owner=owner):
                    atomic_json(self.root / 'manager/maintenance.json',
                                {'active': True, 'release': str(owner)})
                    self.assertEqual(self.manager.reboot_complete()['status'], 'complete')
            atomic_json(self.root / 'manager/maintenance.json',
                        {'active': True, 'release': str(self.boot_stage.parent / ('f' * 32))})
            with self.assertRaisesRegex(Refused, 'Another operation owns maintenance'):
                self.manager.reboot_complete()

    def test_failed_integrity_or_health_or_finalize_keeps_gate(self):
        for point in ('integrity', 'health', 'finalize'):
            with self.subTest(point=point):
                self.events.clear()
                target = {'integrity': self.reconcile, 'health': self.manager.health, 'finalize': self.finalize}[point]
                previous = target.side_effect
                target.side_effect = Refused('injected acceptance failure')
                try:
                    with self.assertRaisesRegex(Refused, 'maintenance remains active'):
                        self.manager.reboot_complete()
                    self.assertNotIn('gate-off', self.events)
                    self.assertEqual(self.events[-1], 'gate-on')
                finally:
                    target.side_effect = previous

    def test_missing_runtime_check_never_finalizes(self):
        self.manager.health.side_effect = None
        self.manager.health.return_value = {'ok': True, 'checks': {name: True for name in REQUIRED_CHECKS if name != 'ingestion'}}
        with self.assertRaises(Refused): self.manager.reboot_complete()
        self.finalize.assert_not_called()
        self.assertNotIn('gate-off', self.events)

    def test_wrong_finalized_boot_never_releases(self):
        self.finalize.side_effect = None
        self.finalize.return_value = {'ok': True, 'boot_id': 'cccccccc-cccc-cccc-cccc-cccccccccccc'}
        with self.assertRaises(Refused): self.manager.reboot_complete()
        self.assertNotIn('gate-off', self.events)

    def test_gate_release_failure_reverifies_before_retry(self):
        def gate(active, stage):
            if not active: raise OSError('gate publication interrupted')
        self.manager.maintenance.side_effect = gate
        with self.assertRaises(Refused): self.manager.reboot_complete()
        self.manager.maintenance.side_effect = None
        self.assertEqual(self.manager.reboot_complete()['status'], 'complete')
        self.assertEqual(self.reconcile.call_count, 2)
        self.assertEqual(self.manager.health.call_count, 2)
        self.assertEqual(self.finalize.call_count, 2)

    def test_health_rejects_foreign_stage_and_multiple_owners_before_probes(self):
        from nebulalog_adapters.lifecycle import Lifecycle
        actual = Lifecycle.health.__get__(self.manager)
        with self.assertRaisesRegex(Refused, 'owned integrity generation'):
            actual(self.stage, boot_health=True)
        with self.assertRaisesRegex(Refused, 'one owner'):
            actual(self.boot_stage, boot_health=True, os_health=True)
        self.manager.api_ready.assert_not_called()
