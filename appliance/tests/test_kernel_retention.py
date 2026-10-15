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


class HistoricalPlanTests(FrozenPlanTests):
    def test_historical_parser_accepts_only_exact_retained_ancestor(self):
        with patch.object(retain, 'historical_acceptance') as history:
            retain.boot_id.return_value = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            self.assertEqual(retain.load_historical_plan('/stage')[0], self.plan)
            history.assert_called_once_with(Path('/stage'), projection())
            with self.assertRaisesRegex(Refused, 'plan_binding'):
                retain.load_plan('/stage')

    def test_historical_parser_does_not_skip_scope_or_ancestry(self):
        with patch.object(retain, 'historical_acceptance', side_effect=Refused('foreign ancestor')):
            with self.assertRaisesRegex(Refused, 'foreign ancestor'):
                retain.load_historical_plan('/stage')
        with patch.object(retain, 'historical_acceptance'):
            self.plan['after_inventory'].append('unrelated-change')
            with self.assertRaisesRegex(Refused, 'erase_set'):
                retain.load_historical_plan('/stage')


class RecoveryClassificationTests(unittest.TestCase):
    def test_attempted_original_inventory_is_ambiguous_and_cannot_replay(self):
        plan = {'before_inventory': ['a', 'b'], 'after_inventory': ['b']}
        self.assertEqual(retain.classify_inventory(plan, ['a', 'b'], attempted=False), 'unattempted')
        self.assertEqual(retain.classify_inventory(plan, ['b'], attempted=True), 'exact_erased')
        for inventory, attempted in ((['a', 'b'], True), (['b'], False), ([], True), (['b', 'x'], True)):
            with self.subTest(inventory=inventory, attempted=attempted), self.assertRaises(Refused):
                retain.classify_inventory(plan, inventory, attempted=attempted)

    def test_exact_inventory_still_requires_absence_and_protected_running_default(self):
        plan = {'before_inventory': ['before'], 'after_inventory': ['after'],
                'preserved': {retain.kernel.GRUBENV: {'sha256': SHA}, '/boot/new': {'kind': 'file'}},
                'removed': {'/boot/old': {}}, 'acceptance': projection()}
        runner = Mock(side_effect=lambda argv, **kw: CURRENT if argv[0] == '/usr/bin/uname' else '/boot/vmlinuz-' + CURRENT)
        with patch.object(retain, 'verify_signed_history') as signed, \
             patch.object(retain.rpm, 'inventory', return_value=('xml', [], ['after'])), \
             patch.object(retain, 'preserved_description', return_value={'kind': 'file'}) as describe, \
             patch.object(retain.os.path, 'lexists', return_value=False) as exists:
            self.assertEqual(retain._exact_erased('/stage', plan, runner=runner), ['after'])
            signed.assert_called_once()
            describe.assert_called_once_with('/boot/new')
            self.assertFalse(any('--erase' in call.args[0] for call in runner.call_args_list))
            exists.return_value = True
            with self.assertRaisesRegex(Refused, 'still_present'): retain._exact_erased('/stage', plan, runner=runner)
            exists.return_value = False
            describe.return_value = {'kind': 'link'}
            with self.assertRaisesRegex(Refused, 'protected_state'): retain._exact_erased('/stage', plan, runner=runner)
            describe.return_value = {'kind': 'file'}
            runner.side_effect = lambda argv, **kw: RECOVERY
            with self.assertRaisesRegex(Refused, 'running_default'): retain._exact_erased('/stage', plan, runner=runner)


class BootAuthorityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.stage = Path(temp.name)
        self.raw = b'# GRUB Environment Block\n' + b'#' * (1024 - len(b'# GRUB Environment Block\n'))
        self.description = {'kind': 'file', 'sha256': retain.rpm.sha(self.raw), 'bytes': 1024,
                            'uid': 0, 'gid': 0, 'mode': 0o600, 'xattrs_sha256': 'a' * 64}
        self.current = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.original = {'boot_id': BOOT, 'acceptance': projection(), 'operation_sha256': SHA,
                         'after_inventory': ['exact-after'], 'preserved': {retain.kernel.GRUBENV: self.description}}
        self.intent = {'schema': 1, 'plan_sha256': 'd' * 64,
                       'authorization': {'ok': True, 'plan_sha256': 'd' * 64, 'boot_id': BOOT,
                                         'backup_sha256': 'e' * 64, 'aide_preparation_sha256': 'f' * 64}}
        (self.stage / retain.INTENT).write_bytes(retain.kernel.encode(self.intent))
        (self.stage / 'kernel-installed.json').write_bytes(b'installed')
        def read(path, *args):
            return self.raw if str(path) == retain.kernel.GRUBENV else Path(path).read_bytes()
        def record(stage, name, value):
            path = stage / name; raw = retain.kernel.encode(value)
            if path.exists() and path.read_bytes() != raw: raise Refused('immutable changed')
            path.write_bytes(raw)
        self.patch(retain.rpm, 'read', side_effect=read)
        self.patch(retain.kernel, 'record', side_effect=record)
        self.patch(retain, 'require_linux_root')
        self.patch(retain, 'boot_id', return_value=self.current)
        self.patch(retain, 'load_historical_plan', return_value=(self.original, 'd' * 64))
        self.candidate = self.patch(retain.kernel, 'load_candidate', return_value=(self.stage,
                    {'kernel': CURRENT, 'old_kernel': RECOVERY}, 'c' * 64, {}))
        self.exact = self.patch(retain, '_exact_erased', return_value=self.original['after_inventory'])
        self.describe = self.patch(retain.kernel, 'describe', side_effect=lambda path: self.description)
        self.runner = Mock()

    def patch(self, target, name, **kwargs):
        item = patch.object(target, name, **kwargs); value = item.start(); self.addCleanup(item.stop); return value

    def test_record_is_immutable_and_current_authority_reobserves_actual_erasure(self):
        reference = retain.observe_boot_authority(self.stage, runner=self.runner)
        first = (self.stage / reference['filename']).read_bytes()
        value = retain.validate_boot_authority(self.stage, reference, runner=self.runner)
        self.assertEqual(value['after_inventory'], ['exact-after'])
        self.assertEqual(retain.observe_boot_authority(self.stage, runner=self.runner), reference)
        self.assertEqual((self.stage / reference['filename']).read_bytes(), first)
        self.assertEqual(self.exact.call_count, 3)
        self.runner.assert_not_called()

    def test_historical_authority_validates_bindings_without_claiming_current_boot(self):
        reference = retain.observe_boot_authority(self.stage, runner=self.runner)
        self.exact.reset_mock()
        retain.boot_id.return_value = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        retain.validate_boot_authority(self.stage, reference, runner=self.runner, historical=True)
        self.exact.assert_not_called()
        with self.assertRaisesRegex(Refused, 'no_longer_current'):
            retain.validate_boot_authority(self.stage, reference, runner=self.runner)

    def test_mutated_original_intent_or_candidate_invalidates_authority(self):
        reference = retain.observe_boot_authority(self.stage, runner=self.runner)
        self.intent['authorization']['aide_preparation_sha256'] = '1' * 64
        (self.stage / retain.INTENT).write_bytes(retain.kernel.encode(self.intent))
        with self.assertRaisesRegex(Refused, 'observation_binding'):
            retain.validate_boot_authority(self.stage, reference, historical=True)

    def test_missing_or_partial_erasure_creates_no_observation(self):
        self.exact.side_effect = Refused('partial erase')
        with self.assertRaisesRegex(Refused, 'partial erase'):
            retain.observe_boot_authority(self.stage, runner=self.runner)
        self.assertEqual(list(self.stage.glob('kernel-retention-observation-*')), [])

    def test_reference_traversal_or_noncanonical_encoding_refused(self):
        reference = retain.observe_boot_authority(self.stage, runner=self.runner)
        for changed in ({**reference, 'filename': '../' + reference['filename']}, {**reference, 'sha256': '0' * 64}):
            with self.subTest(changed=changed), self.assertRaises(Refused):
                retain.validate_boot_authority(self.stage, changed, historical=True)
        path = self.stage / reference['filename']; path.write_bytes(path.read_bytes() + b' ')
        reference['sha256'] = retain.rpm.sha(path.read_bytes())
        with self.assertRaisesRegex(Refused, 'reference_changed'):
            retain.validate_boot_authority(self.stage, reference, historical=True)


class SignedHistoryTests(unittest.TestCase):
    def setUp(self):
        self.original_xml = b'original inventory'
        self.values, self.raw, self.installed, packages, files = {}, {}, [], [], []
        for name in sorted(retain.kernel.NAMES):
            payload = {'name': name, 'nevra': name + '-0:' + OLDEST, 'kernel': OLDEST,
                       'files': [{'path': '/usr/lib/modules/' + OLDEST + '/' + name, 'kind': 'file'}]}
            raw = name.encode(); checksum = retain.rpm.sha(raw)
            item = {key: value for key, value in payload.items() if key != 'files'}
            item.update(rpm=checksum + '.rpm', sha256=checksum, bytes=len(raw), signature='signed')
            packages.append(item); files.extend(payload['files']); self.installed.append({'key': name})
            self.values[name] = payload
            self.raw[item['rpm']] = raw
        self.plan = {'key_sha256': retain.rpm.sha(b'key'), 'keydb': 'private-keydb', 'packages': packages,
                     'inventory_sha256': retain.rpm.sha(self.original_xml),
                     'before_inventory': sorted(value['nevra'] for value in self.values.values()), 'target': {'files': files}}
        def read(path, *args):
            if str(path) == str(retain.rpm.KEY): return b'key'
            if Path(path).name == 'kernel-retention-inventory.xml': return self.original_xml
            return self.raw[Path(path).name]
        self.patch(retain.rpm, 'platform'); self.patch(retain, 'verify_remove_hooks')
        self.patch(retain.os, 'readlink', return_value='usr/lib')
        self.patch(retain.rpm, 'read', side_effect=read)
        self.patch(retain.rpm, 'headers', side_effect=lambda raw: self.installed if raw == self.original_xml.decode() else [{'key': raw}])
        self.patch(retain.rpm, 'identity', side_effect=lambda header: {'nevra': self.values[header['key']]['nevra']})
        self.patch(retain.kernel, 'payload', side_effect=lambda header: copy.deepcopy(self.values[header['key']]))
        self.signature = self.patch(retain.rpm, 'signature', return_value='signed')
        self.runner = Mock(side_effect=lambda argv, **kw: self.raw[Path(argv[-1]).name].decode())

    def patch(self, target, name, **kwargs):
        item = patch.object(target, name, **kwargs); value = item.start(); self.addCleanup(item.stop); return value

    def test_all_four_vendor_signatures_and_original_payload_headers_are_verified(self):
        retain.verify_signed_history('/stage', self.plan, runner=self.runner)
        self.assertEqual(self.signature.call_count, 4)
        self.assertEqual(self.runner.call_count, 4)
        self.assertTrue(all(call.args[0][:4] == ['/usr/bin/rpm', '--query', '--package', '--xml'] for call in self.runner.call_args_list))

    def test_changed_signature_rpm_bytes_or_frozen_payload_refused(self):
        self.signature.return_value = 'other-key'
        with self.assertRaisesRegex(Refused, 'signed_package'): retain.verify_signed_history('/stage', self.plan, runner=self.runner)
        self.signature.return_value = 'signed'
        item = self.plan['packages'][0]; old = self.raw[item['rpm']]; self.raw[item['rpm']] = old + b'x'
        with self.assertRaisesRegex(Refused, 'signed_package'): retain.verify_signed_history('/stage', self.plan, runner=self.runner)
        self.raw[item['rpm']] = old
        self.plan['target']['files'].append({'path': '/etc/shadow', 'kind': 'file'})
        with self.assertRaisesRegex(Refused, 'frozen_payload'): retain.verify_signed_history('/stage', self.plan, runner=self.runner)

    def test_original_inventory_and_key_bytes_remain_required_after_erasure(self):
        self.plan['inventory_sha256'] = '0' * 64
        with self.assertRaisesRegex(Refused, 'historical_inventory'): retain.verify_signed_history('/stage', self.plan, runner=self.runner)
        self.plan['inventory_sha256'] = retain.rpm.sha(self.original_xml)
        self.plan['key_sha256'] = '0' * 64
        with self.assertRaisesRegex(Refused, 'vendor_trust'): retain.verify_signed_history('/stage', self.plan, runner=self.runner)
        self.runner.assert_not_called()


class CompoundResumeTests(unittest.TestCase):
    def setUp(self):
        from nebulalog_manager import kernel_boot
        self.boot_module = kernel_boot
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.stage = Path(temp.name) / ('1' * 32); self.stage.mkdir()
        self.new_boot = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.before = {'kind': 'file', 'sha256': 'a' * 64, 'bytes': 1024, 'mode': 0o600,
                       'uid': 0, 'gid': 0, 'xattrs_sha256': 'b' * 64}
        self.after = {**self.before, 'sha256': 'c' * 64}
        self.original = {'operation_sha256': SHA, 'acceptance': projection(), 'boot_id': BOOT,
                         'removed': {'/boot/old': self.before},
                         'preserved': {retain.kernel.GRUBENV: self.before, '/boot/new': self.before, '/boot': {'kind': 'directory'}},
                         'mutable_directories': ['/boot'], 'retained_kernels': VERSIONS[1:]}
        self.original_sha = 'd' * 64
        self.original_authorization = {'ok': True, 'plan_sha256': self.original_sha, 'boot_id': BOOT,
                                       'backup_sha256': 'e' * 64, 'aide_preparation_sha256': 'f' * 64}
        self.intent = {'schema': 1, 'plan_sha256': self.original_sha, 'authorization': self.original_authorization}
        self.write(retain.INTENT, self.intent)
        self.write(retain.INTEGRITY, retain.integrity_plan(self.original, self.original_sha))
        self.authority_ref = {'filename': 'kernel-retention-observation-' + self.new_boot + '.json', 'sha256': '1' * 64}
        self.boot_ref = {'filename': 'kernel-boot-' + '2' * 32 + '-plan.json', 'sha256': '2' * 64}
        self.observation = {'boot_id': self.new_boot, 'operation_sha256': SHA, 'retention_plan_sha256': self.original_sha,
                            'kernel': CURRENT, 'recovery_kernel': RECOVERY, 'grub_observed': self.after}
        self.boot = {'plan_sha256': self.boot_ref['sha256'], 'boot_id': self.new_boot, 'authority_ref': self.authority_ref,
                     'kernel': CURRENT, 'recovery_kernel': RECOVERY, 'operation_sha256': SHA,
                     'previous_retention_plan': None,
                     'files': [{'path': retain.kernel.GRUBENV, 'before': self.before, 'after': self.after}]}
        self.authorization = {'ok': True, 'stage': str(self.stage), 'boot_id': self.new_boot,
                              'backup_stage': str(self.stage), 'backup_sha256': '3' * 64,
                              'operation_sha256': SHA, 'retention_plan_sha256': self.original_sha}
        self.authorize = Mock(return_value=self.authorization)
        self.patch(retain, 'require_linux_root')
        self.patch(retain, 'boot_id', return_value=self.new_boot)
        self.patch(retain, 'load_historical_plan', return_value=(self.original, self.original_sha))
        self.patch(retain.rpm, 'read', side_effect=lambda path, *args: Path(path).read_bytes())
        self.patch(retain.kernel, 'record', side_effect=self.record)
        self.patch(retain, 'atomic_json', side_effect=lambda path, value: Path(path).write_bytes(retain.kernel.encode(value)))
        self.observed = self.patch(retain, 'validate_boot_authority', return_value=self.observation)
        self.validate_boot = self.patch(kernel_boot, 'validate_retention_resume', create=True, return_value=self.boot)
        self.linked = None
        self.read_link = self.patch(kernel_boot, 'read_retention_integrity_binding', create=True,
                                    side_effect=lambda *args: self.linked)
        def bind(stage, boot_ref, compound_ref, **kw):
            if self.linked is not None and self.linked != compound_ref: raise Refused('link changed')
            self.linked = compound_ref
        self.bind = self.patch(kernel_boot, 'bind_retention_integrity', create=True, side_effect=bind)
        self.verify_link = self.patch(kernel_boot, 'verify_retention_integrity_binding', create=True, return_value=True)
        self.runner = Mock()

    def patch(self, target, name, **kwargs):
        item = patch.object(target, name, **kwargs); value = item.start(); self.addCleanup(item.stop); return value

    def write(self, name, value):
        (self.stage / name).write_bytes(retain.kernel.encode(value))

    def record(self, stage, name, value):
        path = stage / name
        raw = retain.kernel.encode(value)
        if path.exists() and path.read_bytes() != raw: raise Refused('immutable changed')
        path.write_bytes(raw)

    def prepare(self):
        path, plan = retain.prepare_resume(self.stage, self.authority_ref, self.boot_ref,
                                          authorize=self.authorize, runner=self.runner)
        return path, plan, {'filename': path.name, 'sha256': retain.rpm.sha(path.read_bytes())}

    def test_compound_origin_is_original_preparation_and_single_exact_env_delta(self):
        intent = (self.stage / retain.INTENT).read_bytes()
        path, plan, reference = self.prepare()
        self.assertEqual(plan['files'], [{'path': retain.kernel.GRUBENV, 'before': self.before, 'after': self.after}])
        self.assertNotIn(retain.kernel.GRUBENV, plan['preserved'])
        origin = retain.resume_origin(self.stage, path)
        self.assertEqual(origin['prepared_sha256'], self.original_authorization['aide_preparation_sha256'])
        self.assertEqual(retain.load_resume(self.stage, reference)[0], plan)
        self.assertEqual((self.stage / retain.INTENT).read_bytes(), intent)
        self.runner.assert_not_called()

    def test_same_boot_retry_keeps_plan_and_original_backup_authorization(self):
        path, plan, reference = self.prepare()
        self.authorize.return_value = {**self.authorization, 'backup_sha256': '4' * 64}
        retry, again, ref = self.prepare()
        self.assertEqual((retry, again, ref), (path, plan, reference))
        self.assertEqual(plan['authorization']['backup_sha256'], '3' * 64)

    def test_crash_after_binding_before_pointer_reuses_exact_linked_plan(self):
        path, plan, reference = self.prepare()
        (self.stage / 'kernel-retention-resume-current.json').unlink()
        retry, again, ref = self.prepare()
        self.assertEqual((retry, again, ref), (path, plan, reference))
        self.assertEqual(self.bind.call_count, 1)

    def test_first_compound_predecessor_is_original_retention_preparation(self):
        path, plan, _ = self.prepare()
        predecessor, checksum = retain.resume_integrity_predecessor(self.stage, path)
        self.assertEqual(predecessor, retain.integrity_plan(self.original, self.original_sha))
        self.assertEqual(checksum, retain.rpm.sha((self.stage / retain.INTEGRITY).read_bytes()))
        self.verify_link.assert_called()

    def test_second_boot_ancestry_keeps_unprepared_prior_compound_exact(self):
        first_path, first, first_ref = self.prepare()
        first_boot, first_boot_ref = copy.deepcopy(self.boot), dict(self.boot_ref)
        first_observation, first_authority = copy.deepcopy(self.observation), dict(self.authority_ref)
        self.current = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.new_boot = self.current
        retain.boot_id.return_value = self.current
        self.authority_ref = {'filename': 'kernel-retention-observation-' + self.current + '.json', 'sha256': '7' * 64}
        self.boot_ref = {'filename': 'kernel-boot-' + '8' * 32 + '-plan.json', 'sha256': '8' * 64}
        self.observation = {**self.observation, 'boot_id': self.current}
        self.boot = {**self.boot, 'boot_id': self.current, 'plan_sha256': self.boot_ref['sha256'],
                     'authority_ref': self.authority_ref, 'previous_retention_plan': first_ref}
        self.authorization = {**self.authorization, 'boot_id': self.current}
        self.authorize.return_value = self.authorization
        self.observed.side_effect = lambda stage, ref, **kw: first_observation if ref == first_authority else self.observation
        self.validate_boot.side_effect = lambda stage, ref, **kw: first_boot if ref == first_boot_ref else self.boot
        self.linked = None
        path, second, second_ref = self.prepare()
        prior, checksum = retain.resume_integrity_predecessor(self.stage, path)
        self.assertEqual((prior, checksum), (first, first_ref['sha256']))
        original, original_sha = retain.resume_integrity_predecessor(self.stage, first_path)
        self.assertEqual(original, retain.integrity_plan(self.original, self.original_sha))
        self.assertNotEqual(first['id'], second['id'])
        # No AIDE preparation is fabricated merely to establish ancestry.
        self.assertFalse(any('prepared' in file.name for file in self.stage.iterdir()))

    def test_changed_scope_preparation_or_boot_reference_cannot_be_rehashed_into_authority(self):
        path, original, _ = self.prepare()
        mutations = [lambda p: p['removed'].update({'/etc/shadow': {}}),
                     lambda p: p.update(original_preparation_sha256='9' * 64),
                     lambda p: p['files'][0]['after'].update(mode=0o666),
                     lambda p: p['authority_ref'].update(sha256='8' * 64),
                     lambda p: p['authorization'].update(stage='/foreign')]
        for mutate in mutations:
            plan = copy.deepcopy(original); mutate(plan)
            plan['manifest_sha256'] = retain.digest({k: v for k, v in plan.items() if k != 'manifest_sha256'})
            self.write(path.name, plan)
            reference = {'filename': path.name, 'sha256': retain.rpm.sha(path.read_bytes())}
            with self.subTest(change=plan), self.assertRaises(Refused): retain.load_resume(self.stage, reference)

    def test_compound_snapshot_keeps_preimage_but_measures_absence_and_new_environment(self):
        _, plan, _ = self.prepare()
        with patch.object(retain, 'preserved_description', side_effect=lambda path: plan['preserved'][path]), \
             patch.object(retain.os.path, 'lexists', return_value=False), \
             patch.object(retain.kernel, 'describe', return_value=self.after) as describe:
            metadata = retain.resume_integrity_snapshot(None, plan, 'prepare')
            self.assertEqual(metadata[retain.kernel.GRUBENV], self.before)
            self.assertEqual(metadata['/boot/old'], self.before)
            self.assertEqual(retain.resume_integrity_snapshot(None, plan, 'forward', metadata), metadata)
            describe.return_value = self.before
            with self.assertRaisesRegex(Refused, 'environment_metadata'):
                retain.resume_integrity_snapshot(None, plan, 'forward', metadata)

    def test_only_combined_original_deletions_parents_and_grub_change_allowed(self):
        _, plan, _ = self.prepare()
        report = {'removed': {'/boot/old': {}}, 'changed': {'/boot': {}, retain.kernel.GRUBENV: {}}}
        for phase in ('prepare', 'forward'): retain.allowed_resume_integrity_report(report, plan, phase)
        for invalid in ({'added': {'/boot/x': {}}}, {'removed': {'/boot/new': {}}},
                        {'changed': {'/boot/new': {}}}, {'changed': {'/etc/grub.d': {}}}):
            with self.subTest(report=invalid), self.assertRaises(Refused):
                retain.allowed_resume_integrity_report(invalid, plan, 'forward')

    def test_boot_completion_verifies_real_aide_chain_and_never_accepts_a_boolean(self):
        from nebulalog_manager import aide_updates
        path, plan, reference = self.prepare()
        proof = {'entry': {'id': 'a', 'sha256': SHA}, 'original_enrollment_sha256': SHA,
                 'plan_sha256': reference['sha256'], 'prepared_sha256': '5' * 64, 'database_sha256': '6' * 64}
        value = {'schema': 1, 'status': 'integrity_reconciled', 'plan': reference, 'boot_ref': self.boot_ref,
                 'authority_ref': self.authority_ref, 'boot_id': self.new_boot, 'kernel': CURRENT,
                 'retention_plan_sha256': self.original_sha, 'aide': proof, 'release_accepted': False}
        name = 'kernel-retention-resume-' + plan['id'] + '-result.json'; self.write(name, value)
        result_ref = {'filename': name, 'sha256': retain.rpm.sha((self.stage / name).read_bytes())}
        verifier = self.patch(aide_updates, 'retained_plan_acceptance', create=True, return_value=proof)
        retain.validate_boot_completion(self.stage, self.boot_ref, result_ref, runner=self.runner)
        verifier.assert_called_once_with(self.stage, path, expected=proof, historical=False)
        verifier.side_effect = Refused('unpublished entry')
        with self.assertRaisesRegex(Refused, 'unpublished'):
            retain.validate_boot_completion(self.stage, self.boot_ref, result_ref, runner=self.runner)


if __name__ == '__main__':
    unittest.main()
