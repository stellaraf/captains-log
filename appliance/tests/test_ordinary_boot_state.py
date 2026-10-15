"""Private host fixtures; no live host boot files or commands are accessed."""
import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import ordinary_boot_state as state
from nebulalog_manager.common import Refused

BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
NEXT = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
KERNEL = '5.14.0-687.56.1.el9_8.x86_64'
MACHINE = 'e250a7dda5144f42b26a77d8329c2ce2'


def block(variables, *, warning=True):
    raw = state.boot.HEADER + (state.boot.WARNING if warning else b'')
    raw += ''.join(key + '=' + value + '\n' for key, value in variables.items()).encode()
    return raw + b'#' * (1024 - len(raw))


def description(raw=b'fixture', *, mode=0o644, kind='file'):
    value = {'kind': kind, 'uid': 0, 'gid': 0, 'mode': mode, 'xattrs_sha256': 'a' * 64}
    if kind == 'file': value.update(bytes=len(raw), sha256=state.rpm.sha(raw))
    if kind == 'symlink': value.update(target='../vendor-unit.service')
    return value


def fixture():
    artifacts = {path: description() for path in (*state.FIXED, *state.WRITERS)}
    artifacts.update({path: description(kind='directory', mode=0o755) for path in state.ROOTS})
    artifacts.update({path: description() for path in (
        '/boot/grub2/grub.cfg', '/boot/vmlinuz-' + KERNEL, '/boot/initramfs-' + KERNEL + '.img',
        '/boot/loader/entries/' + MACHINE + '-' + KERNEL + '.conf')})
    artifacts['/usr/lib/modules/' + KERNEL] = description(kind='directory', mode=0o755)
    for path, (checksum, _, mode) in state.WRITERS.items():
        artifacts[path].update(sha256=checksum, mode=mode)
    raw = block({'saved_entry': MACHINE + '-' + KERNEL, 'menu_auto_hide': '1',
                 'boot_success': '0', 'boot_indeterminate': '0', 'unknown_vendor_option': 'preserved'})
    return {'schema': 1, 'boot_id': BOOT, 'kernel': KERNEL, 'default_kernel': KERNEL,
            'machine_id': MACHINE, 'inventory': sorted([state.TOOLS, state.MINIMAL,
                *(name + '-0:' + KERNEL for name in state.kernel.NAMES)]),
            'artifacts': artifacts, 'grub': {'raw': base64.b64encode(raw).decode(), 'description': description(raw, mode=0o600)},
            'writers': {path: {'sha256': checksum, 'owner': owner} for path, (checksum, owner, _) in state.WRITERS.items()}}


def environment(snapshot, **changes):
    raw = base64.b64decode(snapshot['grub']['raw'])
    values = state.boot.parse_environment(raw)
    values.update(changes)
    changed = block(values, warning=state.boot.WARNING in raw)
    snapshot['grub'] = {'raw': base64.b64encode(changed).decode(),
                        'description': {**snapshot['grub']['description'], 'bytes': len(changed), 'sha256': state.rpm.sha(changed)}}
    return snapshot


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.before = fixture()

    def test_snapshot_is_pure_and_accepts_complete_qualified_shape(self):
        with patch.object(state, 'capture', side_effect=AssertionError('must not recapture')):
            self.assertEqual(state.validate_snapshot(self.before), self.before)

    def test_all_vendor_reboot_flag_combinations(self):
        for success in ('0', '1'):
            for uncertain in ('0', '1', '2'):
                for later_success in ('0', '1'):
                    before = environment(copy.deepcopy(self.before), boot_success=success, boot_indeterminate=uncertain)
                    after = copy.deepcopy(before); after['boot_id'] = NEXT
                    result = '0' if success == '1' else '2' if uncertain == '1' else uncertain
                    environment(after, boot_success=later_success, boot_indeterminate=result)
                    with self.subTest(success=success, uncertain=uncertain, observed=later_success):
                        delta = state.validate_transition(before, after, same_boot=False)
                        self.assertEqual(delta['kind'], 'ordinary-reboot')
                        self.assertEqual(delta['files'], [{'path': state.ENV,
                            'before': before['grub']['description'], 'after': after['grub']['description']}])

    def test_late_timer_only_changes_success_zero_to_one(self):
        after = environment(copy.deepcopy(self.before), boot_success='1')
        self.assertEqual(state.validate_transition(self.before, after, same_boot=True)['kind'], 'boot-success')
        for before, candidate in ((self.before, self.before), (after, self.before), (after, after)):
            with self.subTest(before=before['grub']['raw']), self.assertRaisesRegex(Refused, 'success_transition_required'):
                state.validate_transition(before, candidate, same_boot=True)

    def test_late_timer_cannot_reset_indeterminate_or_unknown_keys(self):
        for changes in ({'boot_indeterminate': '1'}, {'unknown_vendor_option': 'changed'}, {'menu_auto_hide': '0'}):
            after = environment(copy.deepcopy(self.before), boot_success='1', **changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(Refused, 'unqualified_environment_transition'):
                state.validate_transition(self.before, after, same_boot=True)

    def test_reboot_cannot_use_wrong_vendor_reset_or_change_boot_controls(self):
        before = environment(copy.deepcopy(self.before), boot_success='1', boot_indeterminate='1')
        for changes in ({'boot_indeterminate': '1'}, {'boot_indeterminate': '2'}, {'menu_auto_hide': '0'},
                        {'next_entry': MACHINE + '-' + KERNEL}, {'prev_saved_entry': 'other'}, {'boot_counter': '0'}):
            after = copy.deepcopy(before); after['boot_id'] = NEXT
            environment(after, **{'boot_success': '0', 'boot_indeterminate': '0', **changes})
            with self.subTest(changes=changes), self.assertRaises(Refused):
                state.validate_transition(before, after, same_boot=False)

    def test_empty_next_entry_is_preserved_not_added_or_removed(self):
        before = environment(copy.deepcopy(self.before), next_entry='')
        after = environment(copy.deepcopy(before), boot_success='1')
        state.validate_transition(before, after, same_boot=True)
        after['boot_id'] = NEXT
        state.validate_transition(before, after, same_boot=False)
        with self.assertRaisesRegex(Refused, 'unqualified_environment_transition'):
            state.validate_transition(self.before, after, same_boot=False)

    def test_boot_identity_must_match_claimed_transition(self):
        after = environment(copy.deepcopy(self.before), boot_success='1')
        with self.assertRaisesRegex(Refused, 'transition_boot_identity_changed'):
            state.validate_transition(self.before, after, same_boot=False)
        after['boot_id'] = NEXT
        for same_boot in (True, 1, None):
            with self.assertRaisesRegex(Refused, 'transition_boot_identity_changed'):
                state.validate_transition(self.before, after, same_boot=same_boot)

    def test_default_or_running_kernel_machine_and_inventory_changes_are_refused(self):
        for field, value in [('default_kernel', '5.14.0-687.57.1.el9_8.x86_64'),
                             ('kernel', '5.14.0-687.57.1.el9_8.x86_64'), ('machine_id', 'a' * 32),
                             ('inventory', sorted(self.before['inventory'] + ['unrelated-0:1-1.x86_64']))]:
            after = environment(copy.deepcopy(self.before), boot_success='1'); after[field] = value
            with self.subTest(field=field), self.assertRaises(Refused):
                state.validate_transition(self.before, after, same_boot=True)

    def test_artifact_content_permissions_acl_and_path_set_changes_are_refused(self):
        for field, value in [('sha256', 'f' * 64), ('bytes', 888), ('mode', 0o600), ('xattrs_sha256', 'e' * 64)]:
            after = environment(copy.deepcopy(self.before), boot_success='1')
            after['artifacts']['/boot/grub2/grub.cfg'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(Refused, 'protected_host_state_changed'):
                state.validate_transition(self.before, after, same_boot=True)
        after = environment(copy.deepcopy(self.before), boot_success='1')
        after['artifacts']['/boot/extra-config'] = description()
        with self.assertRaisesRegex(Refused, 'protected_host_state_changed'):
            state.validate_transition(self.before, after, same_boot=True)

    def test_grub_security_metadata_changes_are_refused(self):
        for field, value in [('xattrs_sha256', 'f' * 64), ('mode', 0o644), ('uid', 9), ('gid', 9)]:
            after = environment(copy.deepcopy(self.before), boot_success='1')
            after['grub']['description'][field] = value
            with self.subTest(field=field), self.assertRaises(Refused):
                state.validate_transition(self.before, after, same_boot=True)

    def test_reordering_or_header_changes_cannot_hide_in_semantic_equality(self):
        after = environment(copy.deepcopy(self.before), boot_success='1')
        variables = state.boot.parse_environment(base64.b64decode(after['grub']['raw']))
        for raw in (block(dict(reversed(list(variables.items())))), block(variables, warning=False)):
            after['grub']['raw'] = base64.b64encode(raw).decode()
            after['grub']['description']['sha256'] = state.rpm.sha(raw)
            with self.assertRaisesRegex(Refused, 'bytes_outside_qualified_writer'):
                state.validate_transition(self.before, after, same_boot=True)

    def test_substring_success_target_is_ambiguous_to_pinned_native_writer(self):
        for changes in ({'other_boot_success': '0'}, {'unknown_vendor_option': 'boot_success=0'}):
            after = environment(copy.deepcopy(self.before), **changes)
            with self.assertRaisesRegex(Refused, 'ambiguous_success_writer_target'):
                state.validate_snapshot(after)

    def test_writers_require_exact_package_hash_mode_and_inventory(self):
        path = '/usr/sbin/grub2-set-bootflag'
        for mutate in (lambda v: v['writers'][path].update(sha256='f' * 64),
                       lambda v: v['writers'][path].update(owner='other-package'),
                       lambda v: v['artifacts'][path].update(sha256='f' * 64),
                       lambda v: v['artifacts'][path].update(mode=0o755),
                       lambda v: v['inventory'].remove(state.MINIMAL)):
            value = copy.deepcopy(self.before); mutate(value)
            with self.assertRaises(Refused): state.validate_snapshot(value)

    def test_native_writer_epoch_is_required_even_with_identical_file_bytes(self):
        self.assertEqual(state.TOOLS, 'grub2-tools-1:2.06-126.el9_8.rocky.0.3.x86_64')
        self.assertEqual(state.MINIMAL, 'grub2-tools-minimal-1:2.06-126.el9_8.rocky.0.3.x86_64')
        state.validate_snapshot(self.before)
        for owner in (state.TOOLS, state.MINIMAL):
            value = copy.deepcopy(self.before)
            substitute = owner.replace('-1:', '-0:')
            value['inventory'] = sorted(substitute if item == owner else item for item in value['inventory'])
            with self.subTest(owner=owner, field='inventory'), self.assertRaisesRegex(Refused, 'flag_writer_artifact_changed'):
                state.validate_snapshot(value)
            for writer in value['writers'].values():
                if writer['owner'] == owner: writer['owner'] = substitute
            with self.subTest(owner=owner, field='inventory_and_owner'), self.assertRaisesRegex(Refused, 'unqualified_flag_writer'):
                state.validate_snapshot(value)

    def test_running_kernel_requires_the_complete_installed_vendor_set(self):
        for name in state.kernel.NAMES:
            value = copy.deepcopy(self.before)
            value['inventory'].remove(name + '-0:' + KERNEL)
            with self.subTest(name=name), self.assertRaisesRegex(Refused, 'running_kernel_not_installed'):
                state.validate_snapshot(value)

    def test_malformed_snapshot_and_unsafe_paths_are_refused(self):
        for mutate in (lambda v: v.update(schema=True), lambda v: v.update(boot_id='not-uuid'),
                       lambda v: v['inventory'].append(v['inventory'][0]),
                       lambda v: v['artifacts'].pop('/boot/grub2/grub.cfg'),
                       lambda v: v['artifacts'].update({'/boot/../etc/passwd': description()}),
                       lambda v: v['artifacts'].update({'/etc/shadow': description()}),
                       lambda v: v['grub'].update(raw='!!!!')):
            value = copy.deepcopy(self.before); mutate(value)
            with self.assertRaises(Refused): state.validate_snapshot(value)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.value = fixture()
        self.raw = base64.b64decode(self.value['grub']['raw'])
        self.paths = sorted(self.value['artifacts'])
        self.descriptions = {**self.value['artifacts'], state.ENV: self.value['grub']['description']}
        def runner(argv, **kwargs):
            if argv == ['/usr/bin/uname', '-r']: return KERNEL
            if argv == ['/usr/sbin/grubby', '--default-kernel']: return '/boot/vmlinuz-' + KERNEL
            if argv[:3] == ['/usr/bin/rpm', '--query', '--file']: return state.WRITERS[argv[3]][1] + '\n'
            self.fail('unexpected host command')
        self.runner = Mock(side_effect=runner)
        self.patch(state, 'require_linux_root')
        self.patch(state.boot, 'boot_id', return_value=BOOT)
        self.patch(state.rpm, 'inventory', return_value=('', [], self.value['inventory']))
        self.patch(state.rpm, 'read', side_effect=lambda path, maximum: self.raw if str(path) == state.ENV else (MACHINE + '\n').encode())
        self.paths_mock = self.patch(state, '_paths', side_effect=lambda: list(self.paths))
        self.describe_mock = self.patch(state, 'describe', side_effect=lambda path: copy.deepcopy(self.descriptions[str(path)]))

    def patch(self, target, name, **kwargs):
        context = patch.object(target, name, **kwargs); result = context.start(); self.addCleanup(context.stop); return result

    def test_capture_is_read_only_and_measures_complete_state_twice(self):
        self.assertEqual(state.capture(runner=self.runner), self.value)
        self.assertEqual(self.describe_mock.call_count, 2 * (len(self.paths) + 1))
        self.assertEqual(self.paths_mock.call_count, 2)

    def test_inventory_race_is_refused(self):
        state.rpm.inventory.side_effect = [('', [], self.value['inventory']), ('', [], ['changed'])]
        with self.assertRaisesRegex(Refused, 'snapshot_changed_during_capture'): state.capture(runner=self.runner)

    def test_artifact_set_race_is_refused(self):
        self.paths_mock.side_effect = [self.paths, self.paths + ['/boot/new']]
        with self.assertRaisesRegex(Refused, 'snapshot_changed_during_capture'): state.capture(runner=self.runner)

    def test_environment_or_protected_metadata_race_is_refused(self):
        original = self.describe_mock.side_effect
        calls = {}
        def changed(path):
            calls[path] = calls.get(path, 0) + 1
            result = original(path)
            if path == state.ENV and calls[path] > 1: result['xattrs_sha256'] = 'e' * 64
            return result
        self.describe_mock.side_effect = changed
        with self.assertRaisesRegex(Refused, 'snapshot_changed_during_capture'): state.capture(runner=self.runner)

    def test_owner_query_cannot_substitute_another_vendor_package(self):
        self.runner.side_effect = lambda argv, **kwargs: KERNEL if argv[0].endswith('uname') else '/boot/vmlinuz-' + KERNEL if argv[0].endswith('grubby') else 'other-package'
        with self.assertRaisesRegex(Refused, 'flag_writer_package_changed'): state.capture(runner=self.runner)


class EnumerationTests(unittest.TestCase):
    def test_nested_directory_failure_is_not_an_incomplete_successful_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            nested = root / 'nested'; nested.mkdir()
            scan = state.os.scandir
            def fail_nested(path):
                if Path(path) == nested: raise OSError('injected enumeration failure')
                return scan(path)
            with patch.object(state, 'ROOTS', (str(root),)), patch.object(state.os, 'scandir', side_effect=fail_nested):
                with self.assertRaisesRegex(Refused, 'artifact_enumeration_failed'): state._paths()

    def test_root_symlink_is_refused_before_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / 'target'; target.mkdir()
            alias = root / 'alias'; alias.symlink_to(target)
            with patch.object(state, 'ROOTS', (str(alias),)), patch.object(state.os, 'walk', side_effect=AssertionError('followed root symlink')):
                with self.assertRaisesRegex(Refused, 'artifact_root_not_directory'): state._paths()


if __name__ == '__main__':
    unittest.main()
