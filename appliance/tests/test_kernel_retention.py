"""Retention safety boundaries; these tests do not claim native erase acceptance."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import kernel_retention as retain
from nebulalog_manager.common import Refused

VERSIONS = ['5.14.0-687.' + str(n) + '.1.el9_8.x86_64' for n in (54, 56, 57, 58)]
OLDEST, _, RECOVERY, CURRENT = VERSIONS
BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
SHA = 'a' * 64


def headers(versions=VERSIONS):
    return [{'Name': [name], 'Epoch': [0], 'Version': ['5.14.0'],
             'Release': [version.removeprefix('5.14.0-').removesuffix('.x86_64')], 'Arch': ['x86_64']}
            for version in versions for name in sorted(retain.kernel.NAMES)]


def projection():
    return {'ok': True, 'kernel': CURRENT, 'recovery_kernel': RECOVERY, 'boot_id': BOOT,
            'receipt_sha256': 'b' * 64, 'install_plan_sha256': 'c' * 64}


def packages():
    return [{'name': name, 'nevra': name + '-0:' + OLDEST, 'kernel': OLDEST}
            for name in sorted(retain.kernel.NAMES)]


class SelectionTests(unittest.TestCase):
    def test_only_oldest_of_four_complete_sets_is_selected(self):
        oldest, groups = retain.select_oldest(headers(), projection())
        self.assertEqual(oldest, OLDEST)
        self.assertEqual(set(groups), set(VERSIONS))

    def test_three_or_five_sets_and_partial_or_duplicate_sets_are_refused(self):
        for installed in (headers(VERSIONS[:3]), headers(VERSIONS + ['5.14.0-687.59.1.el9_8.x86_64']),
                          headers()[:-1], headers() + headers()[:1]):
            with self.subTest(count=len(installed)), self.assertRaises(Refused):
                retain.select_oldest(installed, projection())

    def test_protected_oldest_unknown_recovery_and_nonnewest_acceptance_refused(self):
        for changed in ({'recovery_kernel': OLDEST}, {'recovery_kernel': '5.14.0-687.1.1.el9_8.x86_64'},
                        {'kernel': RECOVERY}, {'kernel': OLDEST}):
            with self.subTest(changed=changed), self.assertRaises(Refused):
                retain.select_oldest(headers(), {**projection(), **changed})

    def test_decimal_version_order_and_custom_kernel_rejection(self):
        self.assertLess(retain.version_order('5.14.0-687.9.1.el9_8.x86_64'), retain.version_order(OLDEST))
        with self.assertRaises(Refused): retain.version_order('6.17.0-custom.x86_64')

    def test_exact_erase_has_no_solver_or_validation_bypass(self):
        plan = {'packages': packages()}
        self.assertEqual(retain.command(plan), ['/usr/bin/rpm', '--erase', *sorted(p['nevra'] for p in packages())])
        self.assertEqual(retain.command(plan, True), ['/usr/bin/rpm', '--erase', '--test', *sorted(p['nevra'] for p in packages())])


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.raw = {'operation.json': b'operation', 'kernel-plan.json': b'plan', 'kernel-installed.json': b'installed'}
        self.receipt = {'schema': 1, 'operation_sha256': retain.rpm.sha(b'operation'),
                        'kernel_plan_sha256': retain.rpm.sha(b'plan'), 'installed_sha256': retain.rpm.sha(b'installed'),
                        'postboot_sha256': 'd' * 64, 'promotion_sha256': 'e' * 64, 'resume_sha256': None, 'kernel': CURRENT,
                        'boot_id': BOOT, 'recovery_kernel': RECOVERY,
                        'checks': {k: True for k in retain.REQUIRED_CHECKS}, 'finalization': 'complete',
                        'previous_acceptance_sha256': None}
        def read(path, *args):
            return retain.kernel.encode(self.receipt) if Path(path).name == 'kernel-accepted.json' else self.raw[Path(path).name]
        for item in (patch.object(retain.rpm, 'read', side_effect=read), patch.object(retain, 'boot_id', return_value=BOOT),
                     patch.object(retain.kernel, 'read_acceptance', side_effect=lambda stage: (
                         self.receipt, retain.rpm.sha(retain.kernel.encode(self.receipt)), 'kernel-acceptance-' + BOOT + '.json')),
                     patch.object(retain.kernel, 'load_candidate', return_value=(Path('/stage'),
                                  {'kernel': CURRENT, 'old_kernel': RECOVERY}, retain.rpm.sha(b'plan'), {}))):
            item.start(); self.addCleanup(item.stop)
        self.runner = Mock(side_effect=lambda argv: CURRENT if argv[0] == '/usr/bin/uname' else '/boot/vmlinuz-' + CURRENT)

    def test_final_acceptance_and_fresh_callback_are_both_required(self):
        expected = retain.acceptance_record('/stage')
        callback = Mock(return_value=expected)
        self.assertEqual(retain.acceptance('/stage', callback, self.runner), expected)
        callback.assert_called_once_with(Path('/stage'))
        with self.assertRaisesRegex(Refused, 'fresh_lifecycle_acceptance'):
            retain.acceptance('/stage', Mock(return_value={**expected, 'receipt_sha256': SHA}), self.runner)

    def test_failed_or_missing_runtime_check_and_incomplete_finalization_refused(self):
        original = copy.deepcopy(self.receipt)
        mutations = [('failed check', lambda: self.receipt['checks'].update(local_auth=False)),
                     ('missing check', lambda: self.receipt['checks'].pop('compliance')),
                     ('truthy check', lambda: self.receipt['checks'].update(api=1)),
                     ('unfinished', lambda: self.receipt.update(finalization='pending')),
                     ('old boot', lambda: self.receipt.update(boot_id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'))]
        for label, change in mutations:
            self.receipt = copy.deepcopy(original); change()
            with self.subTest(label=label), self.assertRaises(Refused): retain.acceptance_record('/stage')

    def test_plan_installed_or_operation_bytes_must_match_receipt(self):
        for field in ('operation_sha256', 'kernel_plan_sha256', 'installed_sha256'):
            old = self.receipt[field]; self.receipt[field] = SHA
            with self.subTest(field=field), self.assertRaisesRegex(Refused, 'binding_changed'):
                retain.acceptance_record('/stage')
            self.receipt[field] = old

    def test_different_running_kernel_or_persistent_default_refused(self):
        expected = retain.acceptance_record('/stage')
        for answers in ([RECOVERY, '/boot/vmlinuz-' + CURRENT], [CURRENT, '/boot/vmlinuz-' + RECOVERY]):
            with self.subTest(answers=answers), self.assertRaisesRegex(Refused, 'running_default'):
                retain.acceptance('/stage', Mock(return_value=expected), Mock(side_effect=answers))

    def test_deferred_candidate_receipt_is_read_from_its_original_stage(self):
        retain.kernel.load_candidate.return_value = (Path('/original-stage'),
                    {'kernel': CURRENT, 'old_kernel': RECOVERY}, retain.rpm.sha(b'plan'), {})
        retain.acceptance_record('/stage')
        self.assertIn(Path('/original-stage/kernel-installed.json'), [call.args[0] for call in retain.rpm.read.call_args_list])
        self.assertNotIn(Path('/stage/kernel-plan.json'), [call.args[0] for call in retain.rpm.read.call_args_list])

    def test_acceptance_generation_and_resume_digest_are_retained(self):
        self.receipt.update(previous_acceptance_sha256='f' * 64, resume_sha256='e' * 64)
        value = retain.acceptance_record('/stage')
        self.assertEqual(value['receipt_sha256'], retain.rpm.sha(retain.kernel.encode(self.receipt)))
        retain.kernel.read_acceptance.assert_called_once_with(Path('/stage'))
        self.receipt['resume_sha256'] = 'invalid'
        with self.assertRaisesRegex(Refused, 'acceptance_binding'): retain.acceptance_record('/stage')


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.value = {'kind': 'file', 'sha256': SHA, 'mode': 0o644, 'uid': 0, 'gid': 0, 'xattrs_sha256': 'b' * 64}
        self.plan = {'removed': {'/boot/old': self.value}, 'preserved': {'/boot/new': self.value},
                     'mutable_directories': ['/boot']}

    def test_unrelated_removal_addition_or_file_mutation_is_refused(self):
        retain.allowed_integrity_report({'removed': {'/boot/old': 'removed'}, 'changed': {'/boot': 'mtime'}}, self.plan, 'forward')
        for report in ({'removed': {'/boot/new': 'removed'}}, {'added': {'/boot/new': 'added'}},
                       {'changed': {'/boot/new': 'content'}}, {'changed': {'/etc': 'mtime'}}):
            with self.subTest(report=report), self.assertRaisesRegex(Refused, 'unrelated_integrity'):
                retain.allowed_integrity_report(report, self.plan, 'forward')
        with self.assertRaises(Refused): retain.allowed_integrity_report({'removed': {'/boot/old': 'removed'}}, self.plan, 'prepare')

    def test_removed_paths_must_actually_be_absent_and_preserved_metadata_exact(self):
        with patch.object(retain, 'preserved_description', return_value=self.value), \
             patch.object(retain.os.path, 'lexists', return_value=False):
            self.assertEqual(retain.integrity_snapshot(None, self.plan, 'forward'),
                             {'/boot/new': self.value, '/boot/old': self.value})
        with patch.object(retain, 'preserved_description', return_value=self.value), \
             patch.object(retain.os.path, 'lexists', return_value=True), self.assertRaisesRegex(Refused, 'still_present'):
            retain.integrity_snapshot(None, self.plan, 'forward')
        with patch.object(retain, 'preserved_description', return_value={**self.value, 'xattrs_sha256': 'c' * 64}), \
             self.assertRaisesRegex(Refused, 'metadata_changed'):
            retain.integrity_snapshot(None, self.plan, 'forward')

    def test_metadata_from_preparation_cannot_be_replaced(self):
        with patch.object(retain, 'preserved_description', return_value=self.value), \
             self.assertRaisesRegex(Refused, 'metadata_changed'):
            retain.integrity_snapshot(None, self.plan, 'forward', {'/boot/new': {**self.value, 'mode': 0o600}})


class FrozenPlanTests(unittest.TestCase):
    def setUp(self):
        machine = 'f' * 32
        root = '/usr/lib/modules/' + OLDEST
        generated = retain.kernel.generated_paths(OLDEST, machine)
        files = [{'path': root, 'kind': 'directory'}, {'path': root + '/vmlinuz', 'kind': 'file'},
                 {'path': '/usr/lib/modules', 'kind': 'directory'}]
        removed = ({p['path'] for p in files} | generated) - {'/usr/lib/modules'}
        parents = {str(Path(p).parent) for p in removed} - removed
        preserved = {p: {'kind': 'directory'} for p in parents}
        for version in VERSIONS[1:]:
            preserved.update({p: {'kind': 'file'} for p in retain.kernel.generated_paths(version, machine)})
        preserved.update({p: {'kind': 'file'} for p in (retain.kernel.GRUBENV, retain.kernel.KERNEL_CONFIG,
                                                      '/etc/default/grub', '/boot/grub2/grub.cfg')})
        self.plan = {'schema': 1, 'kind': retain.KIND, 'operation_sha256': retain.rpm.sha(b'operation'),
                     'acceptance': projection(), 'boot_id': BOOT, 'kernel': OLDEST, 'machine_id': machine,
                     'key_sha256': retain.rpm.KEY_SHA256, 'keydb': 'kernel-retention-keydb-' + 'a' * 32, 'packages': packages(),
                     'target': {'kernel': OLDEST, 'old_kernel': OLDEST, 'machine_id': machine,
                                'packages': packages(), 'files': files, 'generated': sorted(generated),
                                'shared': {'/usr/lib/modules': {}}, 'preserved': {}, 'old_bls': 'fixture'},
                     'before_inventory': sorted(['unrelated'] + [p['nevra'] for p in packages()]),
                     'after_inventory': ['unrelated'], 'inventory_sha256': SHA,
                     'removed': {p: {} for p in removed}, 'preserved': preserved,
                     'mutable_directories': sorted(parents), 'retained_kernels': VERSIONS[1:]}
        def read(path, *args):
            return retain.kernel.encode(self.plan) if Path(path).name == retain.PLAN else b'operation'
        for item in (patch.object(retain.rpm, 'read', side_effect=read), patch.object(retain, 'boot_id', return_value=BOOT),
                     patch.object(retain, 'acceptance_record', return_value=projection())):
            item.start(); self.addCleanup(item.stop)

    def test_frozen_plan_validates_complete_path_and_package_scope(self):
        parsed, checksum = retain.load_plan('/stage')
        self.assertEqual(parsed, self.plan)
        self.assertEqual(checksum, retain.rpm.sha(retain.kernel.encode(self.plan)))

    def test_added_removal_parent_or_missing_recovery_artifact_refused(self):
        original = copy.deepcopy(self.plan)
        mutations = [lambda: self.plan['removed'].update({'/etc/shadow': {}}),
                     lambda: self.plan['mutable_directories'].append('/etc'),
                     lambda: self.plan['preserved'].pop('/boot/vmlinuz-' + RECOVERY),
                     lambda: self.plan['target']['files'].append({'path': '/etc/shadow', 'kind': 'file'}),
                     lambda: self.plan['packages'][0].update(nevra='--allmatches'),
                     lambda: self.plan['after_inventory'].append('injected')]
        for index, change in enumerate(mutations):
            self.plan = copy.deepcopy(original); change()
            with self.subTest(index=index), self.assertRaises(Refused): retain.load_plan('/stage')


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.stage = Path(temp.name)
        self.plan = {'boot_id': BOOT, 'acceptance': projection(), 'packages': [], 'before_inventory': ['before'],
                     'after_inventory': ['after'], 'inventory_sha256': retain.rpm.sha(b'xml'),
                     'key_sha256': retain.rpm.sha(b'key'), 'kernel': OLDEST, 'retained_kernels': VERSIONS[1:]}
        self.authorization = {'ok': True, 'plan_sha256': SHA, 'backup_sha256': 'b' * 64,
                              'aide_preparation_sha256': 'c' * 64, 'boot_id': BOOT}
        self.authorize = Mock(return_value=self.authorization)
        self.accepted = Mock()
        self.events = []
        self.runner = Mock(side_effect=lambda argv, **kw: self.events.append(('command', argv)))
        for item in (patch.object(retain, 'require_linux_root'), patch.object(retain, 'boot_id', return_value=BOOT),
                     patch.object(retain, 'load_plan', return_value=(self.plan, SHA)),
                     patch.object(retain, 'acceptance', return_value=projection()), patch.object(retain.rpm, 'platform'),
                     patch.object(retain, 'verify_remove_hooks'), patch.object(retain, 'verify_files'),
                     patch.object(retain.rpm, 'inventory', return_value=('xml', [], ['before'])),
                     patch.object(retain.rpm, 'read', return_value=b'key'),
                     patch.object(retain.kernel, 'record', side_effect=lambda stage, name, value: self.events.append(('record', name)))):
            item.start(); self.addCleanup(item.stop)

    def test_authorization_refusal_prevents_any_rpm_command_or_intent(self):
        self.authorize.return_value = {**self.authorization, 'ok': False}
        with self.assertRaises(Refused):
            retain.execute_cached(self.stage, authorize=self.authorize, accepted=self.accepted, runner=self.runner)
        self.assertEqual(self.events, [])

    def test_fresh_backup_change_after_preflight_prevents_intent_and_erase(self):
        self.authorize.side_effect = [self.authorization, {**self.authorization, 'backup_sha256': 'd' * 64}]
        with self.assertRaisesRegex(Refused, 'context_changed'):
            retain.execute_cached(self.stage, authorize=self.authorize, accepted=self.accepted, runner=self.runner)
        self.assertEqual(self.events, [('command', retain.command(self.plan, True))])

    def test_intent_is_durable_before_exact_erase_and_failure_is_not_replayed(self):
        def fail(argv, **kw):
            self.events.append(('command', argv))
            if '--test' not in argv: raise Refused('fixture interrupted RPM')
        self.runner.side_effect = fail
        with self.assertRaisesRegex(Refused, 'interrupted RPM'):
            retain.execute_cached(self.stage, authorize=self.authorize, accepted=self.accepted, runner=self.runner)
        self.assertEqual(self.events, [('command', retain.command(self.plan, True)), ('record', retain.INTENT),
                                       ('command', retain.command(self.plan))])

    def test_existing_intent_prevents_all_execution(self):
        (self.stage / retain.INTENT).write_text('{}')
        with self.assertRaisesRegex(Refused, 'already_attempted'):
            retain.execute_cached(self.stage, authorize=self.authorize, accepted=self.accepted, runner=self.runner)
        self.assertEqual(self.events, [])
        self.authorize.assert_not_called()

    def test_success_enters_readonly_recovery_and_does_not_accept_aide(self):
        with patch.object(retain, 'recover_cached', return_value={'status': 'erased_pending_integrity'}) as recovery:
            result = retain.execute_cached(self.stage, authorize=self.authorize, accepted=self.accepted, runner=self.runner)
        self.assertEqual(result['status'], 'erased_pending_integrity')
        recovery.assert_called_once()

    def test_recovery_refuses_partial_inventory_without_erase_or_deletion(self):
        intent = {'schema': 1, 'plan_sha256': SHA, 'authorization': self.authorization}
        retain.rpm.read.return_value = retain.kernel.encode(intent)
        with self.assertRaisesRegex(Refused, 'partial_erase'):
            retain.recover_cached(self.stage, authorize=self.authorize, accepted=self.accepted, runner=self.runner)
        self.assertEqual(self.events, [])

    def test_recovery_accepts_exact_erasure_only_as_pending_integrity(self):
        intent = {'schema': 1, 'plan_sha256': SHA, 'authorization': self.authorization}
        retain.rpm.read.return_value = retain.kernel.encode(intent)
        retain.rpm.inventory.return_value = ('xml', [], ['after'])
        result = retain.recover_cached(self.stage, authorize=self.authorize, accepted=self.accepted, runner=self.runner)
        self.assertEqual(result['status'], 'erased_pending_integrity')
        self.assertFalse(result['release_accepted'])
        self.assertEqual(self.events, [('record', retain.RESULT)])
        retain.verify_files.assert_called_once_with(self.plan, 'forward', runner=self.runner)

    def test_refreshed_backup_is_recorded_without_rewriting_original_intent(self):
        intent = {'schema': 1, 'plan_sha256': SHA, 'authorization': self.authorization}
        retain.rpm.read.return_value = retain.kernel.encode(intent)
        retain.rpm.inventory.return_value = ('xml', [], ['after'])
        self.authorize.return_value = {**self.authorization, 'backup_sha256': 'd' * 64}
        retain.recover_cached(self.stage, authorize=self.authorize, accepted=self.accepted, runner=self.runner)
        self.assertEqual(len(self.events), 2)
        self.assertTrue(self.events[0][1].startswith('kernel-retention-recovery-'))
        self.assertEqual(self.events[1], ('record', retain.RESULT))
        self.assertNotIn(('record', retain.INTENT), self.events)

    def test_recovery_cannot_change_original_aide_preparation(self):
        intent = {'schema': 1, 'plan_sha256': SHA, 'authorization': self.authorization}
        retain.rpm.read.return_value = retain.kernel.encode(intent)
        self.authorize.return_value = {**self.authorization, 'aide_preparation_sha256': 'd' * 64}
        with self.assertRaisesRegex(Refused, 'recovery_authorization'):
            retain.recover_cached(self.stage, authorize=self.authorize, accepted=self.accepted, runner=self.runner)
        self.assertEqual(self.events, [])


if __name__ == '__main__':
    unittest.main()
