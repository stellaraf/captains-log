"""Real boot/AIDE retry chains with private native-host/scanner fixtures.

No boot validator, dispatcher, AIDE preparation, acceptance or retained chain
is mocked. Vendor payload/native host measurements remain fixture inputs.
"""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from nebulalog_manager import kernel_boot as boot, kernel_integrity, aide_updates as updates
from nebulalog_manager.common import Refused
from test_kernel_boot import OLD, NEW, MACHINE, block
from test_kernel_boot_aide import KernelAideIntegrationTests


class RetryAideTests(unittest.TestCase):
    for _name, _method in KernelAideIntegrationTests.__dict__.items():
        if callable(_method) and not _name.startswith('test_') and _name != 'setUp':
            locals()[_name] = _method

    def setUp(self):
        KernelAideIntegrationTests.setUp(self)
        for context in (patch.object(updates.aide, 'Aide', return_value=self.manager),
                        patch.object(kernel_integrity, 'checked_backup', return_value='b' * 64)):
            context.start()
            self.addCleanup(context.stop)

    def authorize(self, stage):
        self.assertEqual(stage, self.stage)
        return {'ok': True, 'stage': str(stage), 'boot_id': self.boot_id, 'kernel': OLD,
                'checks': {name: True for name in boot.REQUIRED_CHECKS},
                'backup_stage': str(stage), 'backup_sha256': 'b' * 64}

    def fallback(self):
        self.call(boot.arm_candidate)
        self.new_boot(candidate=False)
        self.call(boot.verify_postboot)
        return boot.verified_recovery(self.stage, runner=self.runner)

    def later(self, token, *, candidate=False):
        value = boot.parse_environment(self.env.read_bytes())
        value.pop('next_entry', None)
        value['boot_indeterminate'] = ('0' if value['boot_success'] == '1' else
                                       '2' if value['boot_indeterminate'] == '1' else value['boot_indeterminate'])
        value['boot_success'] = '0'
        self.env.write_bytes(block(value))
        self.boot_id, self.running = token * 8 + '-' + token * 4 + '-' + token * 4 + '-' + token * 4 + '-' + token * 12, NEW if candidate else OLD

    def test_fallback_later_boot_and_timer_then_single_retry_success(self):
        initial = self.fallback()
        self.later('c')
        self.assertEqual(self.call(boot.reconcile_recovery)['outcome'], 'recovery')
        current = boot.parse_environment(self.env.read_bytes())
        current['boot_success'] = '1'
        self.env.write_bytes(block(current))
        self.call(boot.reconcile_recovery)
        proof = boot.verified_recovery(self.stage, runner=self.runner)
        self.assertNotEqual(proof['boot_ref'], initial['boot_ref'])
        boot.validate_recovery_proof(self.stage, initial, historical=True, runner=self.runner)
        result = self.call(boot.retry_candidate, authorize=self.authorize)
        self.assertEqual((result['ok'], result['attempt'], result['status']), (True, 2, 'retry_armed'))
        self.assertEqual(boot.parse_environment(self.env.read_bytes())['saved_entry'], MACHINE + '-' + OLD)
        self.later('d', candidate=True)
        self.assertEqual(self.call(boot.verify_postboot)['outcome'], 'candidate')
        self.call(boot.commit_candidate, health=self.health())
        self.assertEqual(boot.accepted_transitions(self.stage, runner=self.runner)['kernel'], NEW)
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_second_fallback_cannot_arm_a_third_attempt(self):
        self.fallback()
        self.call(boot.retry_candidate, authorize=self.authorize)
        self.later('c')
        self.call(boot.verify_postboot)
        self.assertEqual(boot.verified_recovery(self.stage, runner=self.runner)['attempts'], 2)
        before = self.env.read_bytes()
        with self.assertRaisesRegex(Refused, 'retry_limit'):
            self.call(boot.retry_candidate, authorize=self.authorize)
        self.assertEqual(self.env.read_bytes(), before)

    def test_abort_retry_retains_fallback_proof_and_consumed_reservation(self):
        self.fallback()
        original = self.env.read_bytes()
        self.call(boot.retry_candidate, authorize=self.authorize)
        self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), original)
        self.assertEqual(boot.verified_recovery(self.stage, runner=self.runner)['attempts'], 2)
        with self.assertRaisesRegex(Refused, 'retry_limit'):
            self.call(boot.retry_candidate, authorize=self.authorize)
        self.later('c')
        self.call(boot.reconcile_recovery)
        self.assertEqual(boot.verified_recovery(self.stage, runner=self.runner)['boot_id'], self.boot_id)

    def test_preparation_failure_cancels_without_arming_and_cannot_retry(self):
        self.fallback()
        original = self.env.read_bytes()
        actual_prepare = self.prepare.side_effect
        self.prepare.side_effect = RuntimeError('interrupted before preparation')
        with self.assertRaises(RuntimeError):
            self.call(boot.retry_candidate, authorize=self.authorize)
        self.prepare.side_effect = actual_prepare
        result = self.call(boot.abort_candidate)
        self.assertEqual(result['phase'], 'retry_cancelled')
        self.assertEqual(self.env.read_bytes(), original)
        boot.verified_recovery(self.stage, runner=self.runner)
        with self.assertRaisesRegex(Refused, 'retry_limit'):
            self.call(boot.retry_candidate, authorize=self.authorize)

    def test_reservation_pointer_crash_resumes_exact_same_plan_once(self):
        self.fallback()
        actual = boot.atomic_json
        def crash(path, value):
            if path.name == 'kernel-boot-current.json':
                raise RuntimeError('pointer publication crash')
            return actual(path, value)
        with patch.object(boot, 'atomic_json', side_effect=crash), self.assertRaises(RuntimeError):
            self.call(boot.retry_candidate, authorize=self.authorize)
        reservation = (self.stage / boot.RETRY_RESERVATION).read_bytes()
        self.assertEqual(self.call(boot.retry_candidate, authorize=self.authorize)['attempt'], 2)
        self.assertEqual((self.stage / boot.RETRY_RESERVATION).read_bytes(), reservation)

    def test_unrelated_drift_or_incomplete_health_cannot_arm(self):
        self.fallback()
        value = boot.parse_environment(self.env.read_bytes())
        value['unexpected'] = '1'
        self.env.write_bytes(block(value))
        with self.assertRaises(Refused):
            self.call(boot.reconcile_recovery)
        self.assertFalse((self.stage / boot.RETRY_RESERVATION).exists())

    def test_recovery_proof_cannot_substitute_aide_entry_or_preboot_abort(self):
        proof = self.fallback()
        changed = copy.deepcopy(proof)
        changed['boot_integrity']['database_sha256'] = 'e' * 64
        with self.assertRaises(Refused):
            boot.validate_recovery_proof(self.stage, changed, historical=True, runner=self.runner)

    def test_incomplete_health_and_changed_backup_cannot_reserve_retry(self):
        self.fallback()
        for field, value in (('checks', {}), ('backup_sha256', 'e' * 64), ('kernel', NEW)):
            with self.subTest(field=field), self.assertRaises(Refused):
                self.call(boot.retry_candidate, authorize=lambda stage: {**self.authorize(stage), field: value})
            self.assertFalse((self.stage / boot.RETRY_RESERVATION).exists())

    def test_retry_arm_interrupted_scan_recovers_after_candidate_boot(self):
        self.fallback()
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError('scan interrupted')) if action == 'update' else None
        with self.assertRaises(OSError):
            self.call(boot.retry_candidate, authorize=self.authorize)
        arm = boot._current(self.stage)[1]
        self.scan_hook = None
        self.later('c', candidate=True)
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.assertFalse(boot._result_path(self.stage, arm).exists())
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_retry_arm_copied_aide_database_recovers_after_second_fallback(self):
        self.fallback()
        replace = updates._replace_current
        def stop(*args):
            replace(*args)
            raise OSError('power loss after retry database copy')
        with patch.object(updates, '_replace_current', side_effect=stop), self.assertRaises(OSError):
            self.call(boot.retry_candidate, authorize=self.authorize)
        arm = boot._current(self.stage)[1]
        self.later('c')
        self.call(boot.verify_postboot)
        self.assertEqual(boot.verified_recovery(self.stage, runner=self.runner)['attempts'], 2)
        self.assertFalse(boot._result_path(self.stage, arm).exists())
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_unpublished_retry_reservation_cancel_never_arms(self):
        self.fallback()
        original = self.env.read_bytes()
        with patch.object(boot, 'atomic_json', side_effect=OSError('pointer failed')), self.assertRaises(OSError):
            self.call(boot.retry_candidate, authorize=self.authorize)
        self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), original)
        with self.assertRaisesRegex(Refused, 'retry_limit'):
            self.call(boot.retry_candidate, authorize=self.authorize)

    def test_full_outer_manager_lock_allows_fallback_retry_aide_proof(self):
        from nebulalog_manager.common import locked
        with locked(self.root / 'manager/transaction.lock'):
            self.fallback()
            self.call(boot.retry_candidate, authorize=self.authorize)
            self.call(boot.abort_candidate)
            boot.verified_recovery(self.stage, runner=self.runner)

    def test_same_boot_failed_retry_acceptance_aborts_exact_bytes(self):
        self.fallback()
        original = self.env.read_bytes()
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError('scan interrupted')) if action == 'update' else None
        with self.assertRaises(OSError):
            self.call(boot.retry_candidate, authorize=self.authorize)
        self.scan_hook = None
        self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), original)
        self.assertEqual(boot.verified_recovery(self.stage, runner=self.runner)['attempts'], 2)
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_same_boot_timer_recovers_interrupted_fallback_scan(self):
        self.call(boot.arm_candidate)
        self.new_boot(candidate=False)
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError('scan interrupted')) if action == 'update' else None
        with self.assertRaises(OSError):
            self.call(boot.verify_postboot)
        self.scan_hook = None
        variables = boot.parse_environment(self.env.read_bytes())
        variables['boot_success'] = '1'
        self.env.write_bytes(block(variables))
        self.call(boot.reconcile_recovery)
        boot.verified_recovery(self.stage, runner=self.runner)
        self.assertTrue((self.stage / boot.FALLBACK).exists())
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_initial_preboot_abort_never_authorizes_failed_candidate_retry(self):
        self.call(boot.arm_candidate)
        self.call(boot.abort_candidate)
        with self.assertRaisesRegex(Refused, 'actual_fallback'):
            boot.verified_recovery(self.stage, runner=self.runner)
        self.assertFalse((self.stage / boot.RETRY_RESERVATION).exists())

    def test_rollback_owner_prevents_explicit_retry_before_erase(self):
        self.fallback()
        (self.stage / 'kernel-rollback-owner.json').write_text('{}')
        with self.assertRaisesRegex(Refused, 'rollback_already_owned'):
            self.call(boot.retry_candidate, authorize=self.authorize)
        self.assertFalse((self.stage / boot.RETRY_RESERVATION).exists())

    def test_unprepared_fallback_observation_survives_another_old_kernel_boot(self):
        self.call(boot.arm_candidate)
        self.new_boot(candidate=False)
        actual_prepare = self.prepare.side_effect
        self.prepare.side_effect = OSError('postboot plan published before preparation')
        with self.assertRaises(OSError):
            self.call(boot.verify_postboot)
        original = boot._current(self.stage)[1]
        self.assertFalse((self.stage / ('kernel-boot-' + original['id'] + '-intent.json')).exists())
        self.prepare.side_effect = actual_prepare
        self.later('c')
        self.call(boot.reconcile_recovery)
        boot.verified_recovery(self.stage, runner=self.runner)
        self.assertFalse(boot._result_path(self.stage, original).exists())
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_initial_arm_missing_intent_abort_preserves_original_contract(self):
        before = self.env.read_bytes()
        actual_prepare = self.prepare.side_effect
        self.prepare.side_effect = OSError('arm plan publication before prepare')
        with self.assertRaises(OSError):
            self.call(boot.arm_candidate)
        self.prepare.side_effect = actual_prepare
        self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), before)
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_late_timer_after_retry_arm_holds_exact_environment_and_baseline(self):
        self.fallback()
        self.call(boot.retry_candidate, authorize=self.authorize)
        database = (self.state / 'aide.db.gz').read_bytes()
        value = boot.parse_environment(self.env.read_bytes())
        value['boot_success'] = '1'
        self.env.write_bytes(block(value))
        observed = self.env.read_bytes()
        with self.assertRaises(Refused):
            self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), observed)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), database)
        self.assertEqual(value['saved_entry'], MACHINE + '-' + OLD)
        self.assertEqual(value['next_entry'], MACHINE + '-' + NEW)
        self.assertTrue(json.loads((self.root / 'manager/maintenance.json').read_text())['active'])

    def test_rollback_routes_historical_retry_arm_to_second_fallback_observation(self):
        self.fallback()
        self.call(boot.retry_candidate, authorize=self.authorize)
        arm = boot._current(self.stage)[1]
        self.later('c')
        with patch.object(boot, 'abort_candidate', wraps=boot.abort_candidate) as abort:
            result = self.call(boot.prepare_rollback_recovery)
        abort.assert_not_called()
        self.assertEqual((result['phase'], result['outcome'], result['boot_id']),
                         ('postboot', 'recovery', self.boot_id))
        self.assertEqual(boot._current(self.stage)[1]['previous']['id'], arm['id'])
        self.assertEqual(boot.verified_recovery(self.stage, runner=self.runner)['attempts'], 2)
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_rollback_routes_fallback_timer_to_exact_reconciliation(self):
        self.fallback()
        previous = boot._current(self.stage)[1]
        value = boot.parse_environment(self.env.read_bytes())
        value['boot_success'] = '1'
        self.env.write_bytes(block(value))
        with patch.object(boot, 'abort_candidate', wraps=boot.abort_candidate) as abort:
            result = self.call(boot.prepare_rollback_recovery)
        abort.assert_not_called()
        self.assertEqual((result['phase'], result['outcome'], result['boot_id']),
                         ('recovery_resume', 'recovery', self.boot_id))
        self.assertEqual(boot._current(self.stage)[1]['previous']['id'], previous['id'])
        boot.verified_recovery(self.stage, runner=self.runner)
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_rollback_cancels_only_current_boot_retry_arm(self):
        self.fallback()
        original = self.env.read_bytes()
        self.call(boot.retry_candidate, authorize=self.authorize)
        with patch.object(boot, 'abort_candidate', wraps=boot.abort_candidate) as abort:
            result = self.call(boot.prepare_rollback_recovery)
        abort.assert_called_once()
        self.assertEqual((result['phase'], result['outcome']), ('abort', 'recovery'))
        self.assertEqual(self.env.read_bytes(), original)
        self.assertEqual(boot.verified_recovery(self.stage, runner=self.runner)['attempts'], 2)

    def test_rollback_helper_rejects_unrelated_fallback_drift_before_aide_change(self):
        self.fallback()
        database = (self.state / 'aide.db.gz').read_bytes()
        value = boot.parse_environment(self.env.read_bytes())
        value['unowned'] = 'change'
        self.env.write_bytes(block(value))
        with self.assertRaises(Refused):
            self.call(boot.prepare_rollback_recovery)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), database)
