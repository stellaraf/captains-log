"""Kernel production dispatch and recovery boundaries; no native update claims."""
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import aide_updates, kernel_integrity as integrity, kernel_updates as kernel, os_payload as rpm
from nebulalog_manager.common import Refused
from nebulalog_adapters.lifecycle import inventory
from nebulalog_manager.updates import REQUIRED_CHECKS
from test_kernel_updates import BOOT, NEW_BOOT, OLD, NEW, PLAN_SHA


class KernelIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / 'manager/os-updates/original'
        self.stage.mkdir(parents=True)
        self.operation = {'schema': 1, 'id': 'cccccccc-cccc-cccc-cccc-cccccccccccc',
                          'stage': str(self.stage), 'boot_id': BOOT}
        self.journal = {'state': 'updating', 'stage': str(self.stage), 'boot_id': BOOT, 'plan_sha256': PLAN_SHA}
        self.write(self.stage / 'operation.json', self.operation)
        self.state()
        self.boot = BOOT
        self.manager = Mock()
        self.manager.guard.return_value = SimpleNamespace(root=self.root)
        self.manager.reader.side_effect = lambda path, **kw: Path(path).read_bytes()
        original = Path.read_text
        def read_text(path, *args, **kwargs):
            if str(path) == '/proc/sys/kernel/random/boot_id':
                return self.boot
            return original(path, *args, **kwargs)
        for item in (patch.object(rpm, 'read', side_effect=lambda path, *args, **kw: Path(path).read_bytes()),
                     patch.object(Path, 'read_text', read_text)):
            item.start()
            self.addCleanup(item.stop)

    def write(self, path, value):
        path.write_bytes(kernel.encode(value))

    def state(self):
        for name in ('os-transaction.json', 'os-latest.json'):
            self.write(self.root / 'manager' / name, self.journal)

    def acceptance(self, value):
        filename = 'kernel-acceptance-' + value['boot_id'] + '.json'
        self.write(self.stage / filename, value)
        self.write(self.stage / 'kernel-acceptance-current.json', {'boot_id': value['boot_id'], 'sha256': rpm.sha(kernel.encode(value))})

    def backup(self):
        directory = self.stage / 'recovery'
        directory.mkdir()
        (directory / 'nebulalog.dump').write_bytes(b'backup data')
        evidence = {'schema': 1, 'includes_clickhouse_logs': False, 'files': inventory(directory)}
        self.write(self.stage / 'adapter-backup-inventory.json', evidence)
        self.backup_receipt = {'ok': True, 'action': 'backup', 'postgresql': True, 'configuration': True,
                               'inventory_sha256': rpm.sha(kernel.encode(evidence)),
                               'observed_at': datetime.now(timezone.utc).isoformat()}
        self.write(self.stage / 'adapter-backup.json', self.backup_receipt)

    def test_backup_verifier_reads_actual_recovery_bytes_and_rejects_tampering(self):
        self.backup()
        self.assertEqual(integrity.checked_backup(self.stage), self.backup_receipt['inventory_sha256'])
        (self.stage / 'recovery/nebulalog.dump').write_bytes(b'corrupted backup')
        with self.assertRaisesRegex(Refused, 'Recovery inventory'):
            integrity.checked_backup(self.stage)

    def test_backup_requires_fresh_manifest_and_observation(self):
        self.backup()
        for field, value in [('inventory_sha256', 'd' * 64), ('postgresql', False),
                             ('observed_at', (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat())]:
            with self.subTest(field=field):
                self.write(self.stage / 'adapter-backup.json', {**self.backup_receipt, field: value})
                with self.assertRaises(Refused):
                    integrity.checked_backup(self.stage)

    def test_cross_boot_recovery_requires_fresh_matching_lifecycle_observation(self):
        integrity.operation(self.manager, self.stage)
        self.boot = NEW_BOOT
        with self.assertRaisesRegex(Refused, 'unbound_recovery_boot'):
            integrity.operation(self.manager, self.stage)
        self.journal.update(state='recovery_required', recovery_boot_id=NEW_BOOT,
                            recovery_observed_at=datetime.now(timezone.utc).isoformat())
        self.state()
        self.assertEqual(integrity.operation(self.manager, self.stage)[-1], NEW_BOOT)
        with self.assertRaises(Refused):
            integrity.operation(self.manager, self.stage, preparing=True)
        self.journal['recovery_observed_at'] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        self.state()
        with self.assertRaisesRegex(Refused, 'fresh_backup_required'):
            integrity.operation(self.manager, self.stage)

    def test_plan_reconstruction_binds_all_payload_and_mutable_metadata(self):
        payload = {'boot_id': BOOT, 'files': [{'path': '/usr/lib/modules/new'}], 'generated': ['/boot/new'],
                   'shared': {}, 'preserved': {}, 'mutable_before': {kernel.GRUBENV: {'xattrs_sha256': 'b' * 64}}}
        value = integrity.plan(self.stage, payload, PLAN_SHA)
        target = self.stage / 'os-integrity-plan.json'
        self.write(target, value)
        with patch.object(kernel, 'load_plan', return_value=(payload, PLAN_SHA)):
            self.assertEqual(integrity.bound_integrity_plan(self.manager, self.stage, target, preparing=False)[0], value)
            changed = copy.deepcopy(value)
            changed['payload']['mutable_before'][kernel.GRUBENV]['xattrs_sha256'] = 'c' * 64
            self.write(target, changed)
            with self.assertRaisesRegex(Refused, 'binding_changed'):
                integrity.bound_integrity_plan(self.manager, self.stage, target, preparing=False)

    def test_prepare_and_accept_use_existing_authorized_aide_chain(self):
        payload = {'boot_id': BOOT, 'files': [], 'generated': [], 'shared': {}, 'preserved': {}, 'mutable_before': {}}
        self.manager.authorized_update_prepare.return_value = {'ok': True}
        with patch.object(kernel, 'load_plan', return_value=(payload, PLAN_SHA)):
            integrity.prepare(self.stage, manager=self.manager)
        self.manager.authorized_update_prepare.assert_called_once_with(self.stage, self.stage / 'os-integrity-plan.json')
        self.manager.authorized_update_accept.return_value = {'ok': True}
        installed = {'plan_sha256': PLAN_SHA}
        with patch('nebulalog_manager.aide.Aide', return_value=self.manager), \
             patch.object(kernel, 'recover_generated', return_value=installed) as recovery, \
             patch.object(kernel, 'mark_pending') as pending:
            self.assertTrue(integrity.accept(self.stage)['ok'])
            recovery.assert_called_once()
            pending.assert_called_once_with(self.stage, installed)
        self.manager.authorized_update_accept.assert_called_once_with(self.stage, self.stage / 'os-integrity-plan.json')

    def test_kernel_dispatch_calls_guarded_install_path_not_inert_rpm_executor(self):
        (self.stage / 'kernel-plan.json').write_text('{}')
        with patch.object(integrity, 'apply', return_value={'ok': True}) as apply, \
             patch.object(rpm, 'execute_cached') as inert:
            self.assertEqual(rpm.apply(self.stage), {'ok': True})
            apply.assert_called_once_with(self.stage, runner=rpm.run)
            inert.assert_not_called()

    def test_apply_uses_distinct_before_install_and_after_install_authorization(self):
        self.manager.authorized_update_prepare.return_value = {'ok': True}
        def execute(stage, *, authorize, authorize_recovery, runner):
            authorize(stage, PLAN_SHA)
            authorize_recovery(stage, PLAN_SHA)
        with patch('nebulalog_manager.aide.Aide', return_value=self.manager), \
             patch.object(kernel, 'execute_cached', side_effect=execute), \
             patch.object(integrity, 'authorization', return_value={}) as authorize, \
             patch.object(integrity, 'accept', return_value={'ok': True}):
            self.assertTrue(integrity.apply(self.stage)['ok'])
            self.assertEqual(authorize.call_count, 2)
            self.assertNotIn('recovery', authorize.call_args_list[0].kwargs)
            self.assertIs(authorize.call_args_list[1].kwargs['recovery'], True)

    def test_deferred_candidate_dispatch_never_replays_install_or_acceptance(self):
        (self.stage / 'kernel-deferred.json').write_text('{}')
        with patch.object(integrity, 'accept_deferred', return_value={'ok': True}) as deferred, \
             patch.object(integrity, 'apply') as install, patch.object(integrity, 'accept') as accept:
            rpm.apply(self.stage)
            rpm.accept_integrity(self.stage)
            self.assertEqual(deferred.call_count, 2)
            install.assert_not_called()
            accept.assert_not_called()

    def pending_fixture(self):
        payload = {'operation_sha256': rpm.sha(kernel.encode(self.operation)), 'kernel': NEW, 'old_kernel': OLD}
        installed = {'plan_sha256': PLAN_SHA, 'kernel': NEW}
        self.write(self.stage / 'kernel-installed.json', installed)
        patcher = patch.object(kernel, 'load_plan', return_value=(payload, PLAN_SHA))
        patcher.start()
        self.addCleanup(patcher.stop)
        pending = kernel.mark_pending(self.stage, installed)
        return payload, installed, pending

    def test_deferred_reference_preserves_original_and_binds_current_operation(self):
        payload, installed, pending = self.pending_fixture()
        next_stage = self.stage.parent / 'next-window'
        next_stage.mkdir()
        self.write(next_stage / 'operation.json', {**self.operation, 'id': NEW_BOOT, 'stage': str(next_stage)})
        result = kernel.adopt_pending(next_stage)
        self.assertTrue(result['reboot_required'])
        self.assertEqual(kernel.load_candidate(next_stage), (self.stage, payload, PLAN_SHA, installed))
        self.write(next_stage / 'operation.json', {**self.operation, 'id': BOOT, 'stage': str(next_stage)})
        with self.assertRaisesRegex(Refused, 'deferred_candidate_binding_changed'):
            kernel.load_candidate(next_stage)
        self.assertEqual(json.loads((self.root / 'manager/kernel-pending.json').read_text()), pending)

    def test_final_acceptance_cleanup_retains_pointer_and_retries_without_pending(self):
        payload, installed, pending = self.pending_fixture()
        proof = {'operation_sha256': payload['operation_sha256'], 'kernel_plan_sha256': PLAN_SHA,
                 'installed_sha256': rpm.sha(kernel.encode(installed)), 'postboot_sha256': 'b' * 64,
                 'promotion_sha256': 'c' * 64, 'resume_sha256': None, 'kernel': NEW, 'boot_id': NEW_BOOT, 'recovery_kernel': OLD}
        accepted = {'schema': 1, **proof, 'checks': {name: True for name in REQUIRED_CHECKS}, 'finalization': 'complete', 'previous_acceptance_sha256': None}
        self.acceptance(accepted)
        with patch('nebulalog_manager.kernel_boot.accepted_transitions', return_value=proof):
            result = kernel.mark_complete(self.stage, accepted)
            self.assertTrue(result['ok'])
            self.assertFalse((self.root / 'manager/kernel-pending.json').exists())
            self.assertEqual(kernel.load_candidate(self.stage), (self.stage, payload, PLAN_SHA, installed))
            self.assertEqual(kernel.mark_complete(self.stage, accepted), result)
        completed = json.loads((self.stage / 'kernel-completed.json').read_text())
        self.assertEqual(completed['pending'], pending)
        later = {**accepted, 'boot_id': 'dddddddd-dddd-dddd-dddd-dddddddddddd', 'resume_sha256': 'f' * 64,
                 'previous_acceptance_sha256': rpm.sha(kernel.encode(accepted))}
        self.acceptance(later)
        with patch('nebulalog_manager.kernel_boot.accepted_transitions', return_value={**proof, 'boot_id': later['boot_id'], 'resume_sha256': later['resume_sha256']}):
            self.assertTrue(kernel.mark_complete(self.stage, later)['ok'])
        self.assertEqual(json.loads((self.stage / 'kernel-completed.json').read_text()), completed)
        self.assertEqual(kernel.read_acceptance(self.stage)[0], later)
        first = self.stage / ('kernel-acceptance-' + accepted['boot_id'] + '.json')
        first.unlink()
        with self.assertRaisesRegex(Refused, 'predecessor_missing'):
            kernel.read_acceptance(self.stage)

    def test_accepted_install_and_abort_retry_only_check_existing_aide_baseline(self):
        payload, installed, _ = self.pending_fixture()
        payload['mutable_before'] = {}
        installed.update(generated={}, mutable={})
        self.write(self.stage / 'kernel-installed.json', installed)
        pending = self.root / 'manager/kernel-pending.json'
        pending.unlink()
        kernel.mark_pending(self.stage, installed)
        self.write(self.stage / 'kernel-plan.json', payload)
        self.journal['plan_sha256'] = rpm.sha(kernel.encode(payload))
        self.state()
        self.backup()
        self.manager._check_locked.return_value = {'state': 'clean', 'exit_code': 0}
        @contextmanager
        def locked(manager):
            yield self.root / 'manager/aide', self.manager.guard()
        runner = Mock(side_effect=lambda args, **kw: OLD if args == ['/usr/bin/uname', '-r'] else '/boot/vmlinuz-' + OLD)
        with patch('nebulalog_manager.aide.Aide', return_value=self.manager), \
             patch.object(aide_updates, '_locked', locked), patch.object(kernel, 'verify_payload'), \
             patch.object(kernel, 'generated_snapshot', return_value={}), \
             patch.object(kernel, 'recover_generated') as replay, \
             patch('nebulalog_manager.kernel_boot.verified_abort', return_value={}) as aborted:
            self.assertTrue(integrity.accept(self.stage, runner=runner)['ok'])
            aborted.assert_not_called()
            (self.stage / 'kernel-boot-current.json').write_text('{}')
            self.assertTrue(integrity.accept(self.stage, runner=runner)['ok'])
            aborted.assert_called_once_with(self.stage, runner=runner)
            replay.assert_not_called()
            self.manager.authorized_update_accept.assert_not_called()
            self.assertEqual(self.manager._check_locked.call_count, 2)

    def test_incomplete_or_changed_acceptance_cannot_clear_pending(self):
        payload, installed, pending = self.pending_fixture()
        proof = {'operation_sha256': payload['operation_sha256'], 'kernel_plan_sha256': PLAN_SHA,
                 'installed_sha256': rpm.sha(kernel.encode(installed)), 'postboot_sha256': 'b' * 64,
                 'promotion_sha256': 'c' * 64, 'resume_sha256': None, 'kernel': NEW, 'boot_id': NEW_BOOT, 'recovery_kernel': OLD}
        accepted = {'schema': 1, **proof, 'checks': {name: True for name in REQUIRED_CHECKS}, 'finalization': 'complete', 'previous_acceptance_sha256': None}
        for field in ('checks', 'promotion_sha256'):
            bad = {**accepted, field: {} if field == 'checks' else 'd' * 64}
            self.acceptance(bad)
            with patch('nebulalog_manager.kernel_boot.accepted_transitions', return_value=proof), self.assertRaises(Refused):
                kernel.mark_complete(self.stage, bad)
            self.assertEqual(json.loads((self.root / 'manager/kernel-pending.json').read_text()), pending)

    def rollback_fixture(self):
        payload, installed, pending = self.pending_fixture()
        self.journal['state'] = 'recovery_required'
        self.state()
        self.write(self.root / 'manager/maintenance.json', {'active': True, 'release': str(self.stage)})
        completion = {'schema': 1, 'status': 'rolled_back', 'plan_sha256': 'b' * 64,
                      'result_sha256': 'c' * 64, 'integrity_sha256': 'd' * 64, 'database_sha256': 'e' * 64,
                      'boot_id': BOOT, 'kernel': NEW, 'recovery_kernel': OLD, 'candidate_plan_sha256': PLAN_SHA,
                      'installed_sha256': rpm.sha(kernel.encode(installed)), 'release_accepted': False}
        self.write(self.stage / 'kernel-rollback-complete.json', completion)
        health = {'ok': True, 'stage': str(self.stage), 'boot_id': self.boot, 'kernel': OLD,
                  'checks': {name: True for name in REQUIRED_CHECKS}}
        for context in (patch.object(kernel, 'require_linux_root'),
                        patch('nebulalog_manager.kernel_rollback.verified_completion', return_value=completion),
                        patch.object(kernel.security, 'status', return_value={'host_controls_ok': True})):
            context.start()
            self.addCleanup(context.stop)
        runner = Mock(side_effect=lambda argv, **kw: OLD if argv == ['/usr/bin/uname', '-r'] else '/boot/vmlinuz-' + OLD)
        return payload, installed, pending, completion, health, runner

    def test_verified_rollback_cleanup_retries_after_unlink_without_adopting_foreign_candidate(self):
        payload, installed, pending, completion, health, runner = self.rollback_fixture()
        result = kernel.mark_rolled_back(self.stage, completion, health, runner=runner)
        self.assertEqual((result['status'], result['release_accepted']), ('rolled_back', False))
        self.assertFalse((self.root / 'manager/kernel-pending.json').exists())
        self.assertEqual(kernel.load_candidate(self.stage), (self.stage, payload, PLAN_SHA, installed))
        self.assertEqual(kernel.mark_rolled_back(self.stage, completion, health, runner=runner), result)
        with self.assertRaisesRegex(Refused, 'quarantined'):
            kernel.reject_quarantined(self.stage, NEW)
        foreign = {**pending, 'stage': str(self.stage.parent / 'foreign')}
        self.write(self.root / 'manager/kernel-pending.json', foreign)
        self.assertEqual(kernel.load_candidate(self.stage), (self.stage, payload, PLAN_SHA, installed))
        with self.assertRaisesRegex(Refused, 'another_kernel_candidate'):
            kernel.mark_rolled_back(self.stage, completion, health, runner=runner)
        self.assertEqual(json.loads((self.root / 'manager/kernel-pending.json').read_text()), foreign)

    def test_rollback_requires_exact_completion_current_old_health_and_keeps_pending(self):
        _, _, pending, completion, health, runner = self.rollback_fixture()
        for value in ({**health, 'checks': {}}, {**health, 'kernel': NEW}, {**health, 'boot_id': NEW_BOOT}):
            with self.subTest(value=value), self.assertRaises(Refused):
                kernel.mark_rolled_back(self.stage, completion, value, runner=runner)
            self.assertEqual(json.loads((self.root / 'manager/kernel-pending.json').read_text()), pending)
        with self.assertRaisesRegex(Refused, 'verified_rollback_completion'):
            kernel.mark_rolled_back(self.stage, {**completion, 'database_sha256': 'f' * 64}, health, runner=runner)

    def test_rollback_disposition_precedes_pending_unlink_and_resumes_quarantine_failure(self):
        _, _, pending, completion, health, runner = self.rollback_fixture()
        record = kernel.record
        def crash(stage, name, value):
            if name.startswith('kernel-rejected-'):
                raise OSError('quarantine publication interrupted')
            return record(stage, name, value)
        with patch.object(kernel, 'record', side_effect=crash), self.assertRaises(OSError):
            kernel.mark_rolled_back(self.stage, completion, health, runner=runner)
        self.assertTrue((self.stage / 'kernel-rollback-pending.json').exists())
        self.assertEqual(json.loads((self.root / 'manager/kernel-pending.json').read_text()), pending)
        self.assertEqual(kernel.mark_rolled_back(self.stage, completion, health, runner=runner)['status'], 'rolled_back')

    def test_actual_fallback_or_rollback_ownership_prevents_new_automatic_adoption(self):
        _, _, pending = self.pending_fixture()
        next_stage = self.stage.parent / 'next-window'
        next_stage.mkdir()
        self.write(next_stage / 'operation.json', {**self.operation, 'stage': str(next_stage)})
        for name in ('kernel-fallback.json', 'kernel-retry-reservation.json', 'kernel-rollback-owner.json'):
            path = self.stage / name
            self.write(path, {})
            with self.subTest(name=name), self.assertRaisesRegex(Refused, 'explicit_recovery'):
                kernel.adopt_pending(next_stage)
            path.unlink()
        self.assertFalse((next_stage / 'kernel-deferred.json').exists())


class KernelResumeTests(unittest.TestCase):
    def test_old_kernel_reboot_can_use_fresh_backup_without_replaying_rpm(self):
        plan = {'boot_id': BOOT, 'old_kernel': OLD, 'kernel': NEW, 'after_inventory': ['after'], 'mutable_before': {}}
        before = {'ok': True, 'plan_sha256': PLAN_SHA, 'backup_sha256': 'b' * 64,
                  'aide_preparation_sha256': 'c' * 64, 'boot_id': BOOT}
        current = {**before, 'boot_id': NEW_BOOT, 'backup_sha256': 'd' * 64}
        intent = {'schema': 1, 'plan_sha256': PLAN_SHA, 'authorization': before}
        installed = {'plan_sha256': PLAN_SHA, 'generated': {}, 'mutable': {}}
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / 'kernel-installed.json').write_bytes(kernel.encode(installed))
            runner = Mock(side_effect=lambda args, **kw: OLD if args == ['/usr/bin/uname', '-r'] else '/boot/vmlinuz-' + OLD)
            with patch.object(kernel, 'require_linux_root'), patch.object(kernel, 'load_plan', return_value=(plan, PLAN_SHA)), \
                 patch.object(rpm, 'read', side_effect=lambda path, *a: kernel.encode(intent if str(path).endswith('kernel-apply-intent.json') else installed)), \
                 patch.object(Path, 'read_text', return_value=NEW_BOOT), patch.object(rpm, 'inventory', return_value=('', [], ['after'])), \
                 patch.object(kernel, 'verify_payload'), patch.object(kernel, 'generated_snapshot', return_value={}), \
                 patch.object(kernel, 'record') as record:
                self.assertEqual(kernel.recover_generated(stage, authorize=Mock(return_value=current), runner=runner), installed)
                self.assertEqual(record.call_count, 1)
                self.assertTrue(record.call_args.args[1].startswith('kernel-recovery-authorization-'))
                self.assertFalse(any('/usr/bin/rpm' in call.args[0] for call in runner.call_args_list))
                with self.assertRaisesRegex(Refused, 'recovery_authorization_changed'):
                    kernel.recover_generated(stage, authorize=Mock(return_value={**current, 'aide_preparation_sha256': 'e' * 64}), runner=runner)
                with self.assertRaisesRegex(Refused, 'execution_authorization_changed'):
                    kernel.authorize_execution(stage, plan, PLAN_SHA, Mock(return_value=current))


if __name__ == '__main__':
    unittest.main()
