"""Private-file boot transaction tests; these do not qualify a native reboot."""
import copy
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import kernel_boot as boot
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.host_job_storage import digest

OLD = '5.14.0-687.56.1.el9_8.x86_64'
NEW = '5.14.0-687.57.1.el9_8.x86_64'
MACHINE = 'e250a7dda5144f42b26a77d8329c2ce2'
ORIGINAL_BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
NEW_BOOT = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
PLAN_SHA = 'a' * 64


def block(variables, *, warning=True):
    raw = boot.HEADER + (boot.WARNING if warning else b'')
    raw += ''.join(key + '=' + value + '\n' for key, value in variables.items()).encode()
    return raw + b'#' * (1024 - len(raw))


def variables():
    return {'saved_entry': MACHINE + '-' + OLD, 'menu_auto_hide': '1',
            'boot_success': '0', 'boot_indeterminate': '0'}


class EnvironmentTests(unittest.TestCase):
    def test_fixed_size_native_formats_and_duplicate_refusal(self):
        for warning in (True, False):
            self.assertEqual(boot.parse_environment(block(variables(), warning=warning)), variables())
        bad = boot.HEADER + b'saved_entry=a\nsaved_entry=b\n'
        for raw in (block(variables())[:-1], b'x' + block(variables())[1:],
                    bad + b'#' * (1024 - len(bad)), block({'a': 'bad\rvalue'}),
                    block({'a': 'valid'})[:-1] + b'\x00'):
            with self.subTest(raw=raw[:55]), self.assertRaises(Refused):
                boot.parse_environment(raw)

    def test_no_competing_one_shot_or_boot_counter(self):
        for key, value in [('next_entry', 'someone-else'), ('prev_saved_entry', 'old'),
                           ('boot_counter', '0'), ('menu_show_once', '1')]:
            with self.subTest(key=key), self.assertRaises(Refused):
                boot.transition_variables({**variables(), key: value}, 'arm', MACHINE + '-' + OLD, MACHINE + '-' + NEW)

    def test_postboot_accepts_only_exact_vendor_reset_and_consumption(self):
        for success, indeterminate, result in [('0', '0', '0'), ('0', '1', '2'),
                                              ('0', '2', '2'), ('1', '2', '0')]:
            before = {**variables(), 'boot_success': success, 'boot_indeterminate': indeterminate,
                      'next_entry': MACHINE + '-' + NEW}
            after = {**variables(), 'boot_success': '1', 'boot_indeterminate': result}
            self.assertEqual(boot.transition_variables(before, 'postboot', MACHINE + '-' + OLD,
                                                       MACHINE + '-' + NEW, observed=after), after)
            for changed in ({'boot_indeterminate': '3'}, {'menu_auto_hide': '0'},
                            {'saved_entry': MACHINE + '-' + NEW}, {'next_entry': MACHINE + '-' + NEW}):
                with self.subTest(changed=changed), self.assertRaises(Refused):
                    boot.transition_variables(before, 'postboot', MACHINE + '-' + OLD,
                                              MACHINE + '-' + NEW, observed={**after, **changed})


class BootTransactionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stage = self.root / 'manager/os-updates/test-operation'
        self.stage.mkdir(parents=True)
        self.env = self.root / 'grubenv'
        self.env.write_bytes(block(variables()))
        self.env.chmod(0o600)
        self.tool = self.root / 'grub2-editenv'
        self.tool.write_bytes(b'private synthetic renderer')
        self.tool.chmod(0o700)
        self.boot_id, self.running = ORIGINAL_BOOT, OLD
        self.metadata_hash = digest({'security.selinux': 'f' * 64})
        self.candidate = {'kernel': NEW, 'old_kernel': OLD, 'machine_id': MACHINE,
                          'after_inventory': ['after'], 'boot_id': ORIGINAL_BOOT}
        self.installed = {'kernel': NEW, 'plan_sha256': PLAN_SHA, 'generated': {},
                          'mutable': {str(self.env): self.description(self.env)}}
        (self.stage / 'kernel-installed.json').write_bytes(boot.kernel.encode(self.installed))
        atomic_json(self.stage / 'operation.json', {'id': 'test-operation', 'boot_id': ORIGINAL_BOOT})
        self.transaction = {'state': 'reboot_preparing', 'stage': str(self.stage), 'boot_id': ORIGINAL_BOOT}
        atomic_json(self.root / 'manager/os-transaction.json', self.transaction)
        atomic_json(self.root / 'manager/os-latest.json', {'stage': str(self.stage), 'boot_id': ORIGINAL_BOOT})
        atomic_json(self.root / 'manager/maintenance.json', {'active': True, 'release': str(self.stage)})
        self.prepare = Mock(side_effect=self.integrity_callback)
        self.accept = Mock(side_effect=self.integrity_callback)
        self.renderer_calls = []
        for patcher in (patch.object(boot, 'ENV', str(self.env)), patch.object(boot, 'TOOL', str(self.tool)),
                        patch.object(boot, 'TOOL_SHA256', boot.rpm.sha(self.tool.read_bytes())),
                        patch.object(boot, 'boot_id', side_effect=lambda: self.boot_id),
                        patch.object(boot, 'require_linux_root'), patch.object(boot.os, 'fchown'),
                        patch.object(boot.os, 'listxattr', return_value=['security.selinux'], create=True),
                        patch.object(boot.os, 'getxattr', return_value=b'synthetic:boot_t', create=True),
                        patch.object(boot.os, 'setxattr', create=True),
                        patch.object(boot.rpm, 'read', side_effect=self.read_private),
                        patch.object(boot.kernel, 'describe', side_effect=self.description),
                        patch.object(boot.kernel, 'load_candidate', side_effect=lambda stage: (self.stage, self.candidate, PLAN_SHA, self.installed)),
                        patch.object(boot.kernel, 'verify_payload'),
                        patch.object(boot.kernel, 'generated_snapshot', return_value={}),
                        patch.object(boot.rpm, 'inventory', return_value=('', [], ['after'])),
                        patch.object(boot.kernel, 'verify_postboot', return_value={'ok': True}),
                        patch.object(boot.kernel.security, 'status', return_value={'host_controls_ok': True})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def description(self, path):
        raw = Path(path).read_bytes()
        return {'kind': 'file', 'bytes': len(raw), 'sha256': boot.rpm.sha(raw), 'uid': 0, 'gid': 0,
                'mode': Path(path).stat().st_mode & 0o7777, 'xattrs_sha256': self.metadata_hash}

    def read_private(self, path, maximum=10000000):
        path = Path(path)
        self.assertTrue(path.is_relative_to(self.root), 'test must never access host boot files')
        value = path.read_bytes()
        self.assertLessEqual(len(value), maximum)
        return value

    def runner(self, argv, **kwargs):
        if argv == ['/usr/bin/uname', '-r']:
            return self.running
        if argv == ['/usr/sbin/grubby', '--default-kernel']:
            selected = boot.parse_environment(self.env.read_bytes())['saved_entry']
            return '/boot/vmlinuz-' + selected[len(MACHINE) + 1:]
        self.assertEqual(argv[0], str(self.tool))
        path = Path(argv[1])
        self.assertEqual(path.parent, self.stage)
        self.assertNotEqual(path, self.env)
        self.renderer_calls.append(argv)
        value = boot.parse_environment(path.read_bytes())
        if argv[2] == 'set':
            for assignment in argv[3:]:
                key, content = assignment.split('=', 1)
                value[key] = content
        elif argv[2] == 'unset':
            for key in argv[3:]:
                value.pop(key, None)
        else:
            self.fail('unexpected native command')
        path.write_bytes(block(value))
        return ''

    def integrity_callback(self, stage, path):
        plan, checksum = boot.validate_transition(stage, path, runner=self.runner)
        if plan['phase'] == 'resume':
            previous, previous_sha = boot.resume_predecessor(stage, path, runner=self.runner)
            self.assertEqual(previous['phase'], 'commit')
            self.assertEqual(previous_sha, boot.rpm.sha(boot.kernel.encode(previous)))
        if plan['phase'] in {'postboot', 'resume'}:
            immediate, checksum = boot.integrity_predecessor(stage, path, runner=self.runner)
            self.assertEqual(checksum, boot.rpm.sha(boot.kernel.encode(immediate)))
            self.assertNotEqual(immediate['boot_id'], plan['boot_id'])
            checksum = boot.rpm.sha(boot.kernel.encode(plan))
        return {'ok': True, 'plan_sha256': checksum, 'baseline_changed': True}

    def call(self, function, **kwargs):
        return function(self.stage, prepare=self.prepare, accept=self.accept, runner=self.runner, **kwargs)

    def new_boot(self, candidate=True):
        value = boot.parse_environment(self.env.read_bytes())
        value.pop('next_entry', None)
        value['boot_success'] = '0'
        self.env.write_bytes(block(value))
        self.boot_id, self.running = NEW_BOOT, NEW if candidate else OLD
        atomic_json(self.root / 'manager/os-transaction.json', {**self.transaction, 'state': 'reboot_requested'})

    def health(self):
        return {'ok': True, 'stage': str(self.stage), 'boot_id': self.boot_id, 'kernel': NEW,
                'checks': {name: True for name in boot.REQUIRED_CHECKS}}

    def replace_plan(self, plan):
        plan = copy.deepcopy(plan)
        plan['manifest_sha256'] = digest({key: value for key, value in plan.items() if key != 'manifest_sha256'})
        path = self.stage / ('kernel-boot-' + plan['id'] + '-plan.json')
        path.write_bytes(boot.kernel.encode(plan))
        atomic_json(self.stage / 'kernel-boot-current.json', {'id': plan['id'], 'sha256': boot.rpm.sha(path.read_bytes())})
        return path

    def test_arm_abort_keep_default_and_clear_only_owned_one_shot(self):
        original = self.env.read_bytes()
        self.assertIsNone(boot.candidate_status(self.stage, runner=self.runner)['phase'])
        self.assertEqual(self.call(boot.abort_candidate)['phase'], 'unarmed')
        result = self.call(boot.arm_candidate)
        self.assertFalse(result['release_accepted'])
        self.assertEqual(boot.parse_environment(self.env.read_bytes())['next_entry'], MACHINE + '-' + NEW)
        self.assertEqual(self.runner(['/usr/sbin/grubby', '--default-kernel']), '/boot/vmlinuz-' + OLD)
        self.assertEqual(self.call(boot.arm_candidate), result)
        self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), original)
        self.assertEqual(boot.verified_abort(self.stage, runner=self.runner)['mutable'][str(self.env)], self.description(self.env))
        self.assertEqual(self.prepare.call_count, 2)

    def test_candidate_postboot_promotion_and_finalization_retry(self):
        self.call(boot.arm_candidate)
        self.new_boot()
        self.assertEqual(boot.candidate_status(self.stage, runner=self.runner)['phase'], 'arm')
        postboot = self.call(boot.verify_postboot)
        self.assertEqual(postboot['outcome'], 'candidate')
        self.assertEqual(self.runner(['/usr/sbin/grubby', '--default-kernel']), '/boot/vmlinuz-' + OLD)
        promoted = self.call(boot.commit_candidate, health=self.health())
        self.assertEqual(self.runner(['/usr/sbin/grubby', '--default-kernel']), '/boot/vmlinuz-' + NEW)
        self.assertEqual(self.call(boot.commit_candidate, health=self.health()), promoted)
        self.assertEqual(self.call(boot.verify_postboot), postboot)
        binding = boot.accepted_transitions(self.stage, runner=self.runner)
        self.assertEqual(binding['kernel'], NEW)
        self.assertEqual(binding['recovery_kernel'], OLD)
        self.assertEqual(binding['boot_id'], NEW_BOOT)
        atomic_json(self.root / 'manager/os-transaction.json', {**self.transaction, 'state': 'complete', 'finalization': 'complete'})
        (self.root / 'manager/maintenance.json').unlink()
        self.assertEqual(boot.accepted_transitions(self.stage, runner=self.runner), binding)
        with self.assertRaisesRegex(Refused, 'maintenance_not_owned'):
            self.call(boot.commit_candidate, health=self.health())

    def test_abort_restores_empty_next_entry_and_allows_later_stage_arm(self):
        original = block({**variables(), 'next_entry': ''})
        self.env.write_bytes(original)
        self.installed['mutable'][str(self.env)] = self.description(self.env)
        (self.stage / 'kernel-installed.json').write_bytes(boot.kernel.encode(self.installed))
        self.call(boot.arm_candidate)
        self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), original)
        candidate_stage = self.stage
        self.stage = self.stage.parent / 'next-window'
        self.stage.mkdir()
        atomic_json(self.stage / 'operation.json', {'id': 'next-window'})
        atomic_json(self.root / 'manager/os-transaction.json', {**self.transaction, 'stage': str(self.stage)})
        atomic_json(self.root / 'manager/os-latest.json', {'stage': str(self.stage), 'boot_id': ORIGINAL_BOOT})
        atomic_json(self.root / 'manager/maintenance.json', {'active': True, 'release': str(self.stage)})
        with patch.object(boot.kernel, 'load_candidate', return_value=(candidate_stage, self.candidate, PLAN_SHA, self.installed)):
            self.call(boot.arm_candidate)
        self.assertEqual(boot.parse_environment(self.env.read_bytes())['next_entry'], MACHINE + '-' + NEW)

    def test_old_kernel_boot_is_recovery_and_cannot_be_promoted(self):
        self.call(boot.arm_candidate)
        self.new_boot(candidate=False)
        self.assertEqual(self.call(boot.verify_postboot)['outcome'], 'recovery')
        with self.assertRaisesRegex(Refused, 'verified_candidate_boot_required'):
            self.call(boot.commit_candidate, health=self.health())
        self.assertEqual(self.runner(['/usr/sbin/grubby', '--default-kernel']), '/boot/vmlinuz-' + OLD)

    def test_prepare_failure_leaves_live_environment_unchanged(self):
        original = self.env.read_bytes()
        self.prepare.return_value = {'ok': False}
        self.prepare.side_effect = None
        with self.assertRaisesRegex(Refused, 'preparation_not_bound'):
            self.call(boot.arm_candidate)
        self.assertEqual(self.env.read_bytes(), original)
        self.accept.assert_not_called()
        self.assertEqual(list(self.stage.glob('*-intent.json')), [])

    def test_accept_failure_resumes_without_repreparing_or_replacing(self):
        self.accept.side_effect = Refused('synthetic AIDE outage')
        with self.assertRaisesRegex(Refused, 'synthetic'):
            self.call(boot.arm_candidate)
        armed = self.env.read_bytes()
        self.accept.side_effect = self.integrity_callback
        with patch.object(boot, '_replace') as replace:
            self.call(boot.arm_candidate)
        replace.assert_not_called()
        self.assertEqual(self.env.read_bytes(), armed)
        self.assertEqual(self.prepare.call_count, 1)

    def test_failed_arm_acceptance_can_finish_and_abort_in_same_boot(self):
        original = self.env.read_bytes()
        self.accept.side_effect = Refused('synthetic outage')
        with self.assertRaises(Refused): self.call(boot.arm_candidate)
        self.accept.side_effect = self.integrity_callback
        self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), original)

    def test_promotion_accept_failure_retry_uses_persisted_intent(self):
        self.call(boot.arm_candidate)
        self.new_boot()
        self.call(boot.verify_postboot)
        self.accept.side_effect = Refused('synthetic outage')
        with self.assertRaises(Refused): self.call(boot.commit_candidate, health=self.health())
        self.assertEqual(self.runner(['/usr/sbin/grubby', '--default-kernel']), '/boot/vmlinuz-' + NEW)
        status = boot.candidate_status(self.stage, runner=self.runner)
        self.assertEqual(status, {'phase': 'commit', 'accepted': False, 'outcome': 'candidate', 'release_accepted': False})
        self.assertEqual(self.call(boot.verify_postboot)['outcome'], 'candidate')
        with self.assertRaisesRegex(Refused, 'runtime_acceptance_required'):
            self.call(boot.commit_candidate, health={**self.health(), 'checks': {}})
        self.accept.side_effect = self.integrity_callback
        with patch.object(boot, '_replace') as replace:
            self.call(boot.commit_candidate, health=self.health())
        replace.assert_not_called()
        self.assertEqual(self.prepare.call_count, 3)

    def test_partial_health_and_other_boot_refuse_promotion(self):
        self.call(boot.arm_candidate)
        self.new_boot()
        self.call(boot.verify_postboot)
        for changed in ({'checks': {'api': True}}, {'boot_id': ORIGINAL_BOOT}, {'stage': '/other'}, {'kernel': OLD}):
            with self.subTest(changed=changed), self.assertRaisesRegex(Refused, 'runtime_acceptance_required'):
                self.call(boot.commit_candidate, health={**self.health(), **changed})
        self.assertEqual(self.runner(['/usr/sbin/grubby', '--default-kernel']), '/boot/vmlinuz-' + OLD)

    def test_drift_and_other_maintenance_owner_prevent_mutation(self):
        self.env.write_bytes(block({**variables(), 'menu_auto_hide': '0'}))
        with self.assertRaisesRegex(Refused, 'installed_environment_changed'):
            self.call(boot.arm_candidate)
        self.prepare.assert_not_called()
        self.env.write_bytes(block(variables()))
        atomic_json(self.root / 'manager/maintenance.json', {'active': True, 'release': '/another'})
        with self.assertRaisesRegex(Refused, 'maintenance_not_owned'):
            self.call(boot.arm_candidate)
        self.prepare.assert_not_called()

    def test_predecessor_aide_receipt_and_environment_are_bound(self):
        self.call(boot.arm_candidate)
        _, arm = boot._current(self.stage)
        receipt = boot._result_path(self.stage, arm)
        accepted = json.loads(receipt.read_text())
        receipt.write_bytes(boot.kernel.encode({**accepted, 'aide': {'ok': True, 'plan_sha256': 'b' * 64}}))
        self.new_boot()
        with self.assertRaisesRegex(Refused, 'prior_transition_not_accepted'):
            self.call(boot.verify_postboot)
        receipt.write_bytes(boot.kernel.encode(accepted))
        self.call(boot.verify_postboot)
        _, postboot = boot._current(self.stage)
        changed = copy.deepcopy(postboot)
        changed['files'][0]['before']['xattrs_sha256'] = 'd' * 64
        changed['files'][0]['after']['xattrs_sha256'] = 'd' * 64
        path = self.replace_plan(changed)
        with self.assertRaisesRegex(Refused, 'predecessor_environment_changed'):
            boot.validate_transition(self.stage, path, runner=self.runner)

    def test_same_boot_postboot_and_changed_operation_are_refused(self):
        self.call(boot.arm_candidate)
        with self.assertRaisesRegex(Refused, 'new_boot_required'):
            self.call(boot.verify_postboot)
        atomic_json(self.stage / 'operation.json', {'id': 'replacement'})
        with self.assertRaisesRegex(Refused, 'binding_changed'):
            self.call(boot.arm_candidate)

    def test_tool_identity_changed_prevents_render_or_live_write(self):
        original = self.env.read_bytes()
        self.tool.write_bytes(b'changed executable')
        with self.assertRaisesRegex(Refused, 'tool_not_qualified'):
            self.call(boot.arm_candidate)
        self.assertEqual(self.env.read_bytes(), original)
        self.assertEqual(self.renderer_calls, [])

    def test_postboot_rejects_unrelated_grub_change_before_aide(self):
        self.call(boot.arm_candidate)
        self.new_boot()
        self.env.write_bytes(block({**boot.parse_environment(self.env.read_bytes()), 'menu_auto_hide': '0'}))
        with self.assertRaisesRegex(Refused, 'unrelated_boot_environment_change'):
            self.call(boot.verify_postboot)
        self.assertEqual(self.prepare.call_count, 1)

    def test_replayed_arm_plan_cannot_cross_boot(self):
        self.call(boot.arm_candidate)
        self.new_boot()
        with self.assertRaisesRegex(Refused, 'current_boot_changed'):
            self.call(boot.arm_candidate)

    def test_aide_report_has_no_broad_mutable_exemption(self):
        self.call(boot.arm_candidate)
        _, plan = boot._current(self.stage)
        boot.allowed_integrity_report({'changed': {str(self.env): {}}}, plan, 'forward')
        for report in ({'changed': {'/etc/shadow': {}}}, {'added': {str(self.env): {}}},
                       {'removed': {str(self.env): {}}}, {'changed': {str(self.env): {}}}):
            with self.assertRaisesRegex(Refused, 'unrelated_integrity_change'):
                boot.allowed_integrity_report(report, plan, 'prepare')

    def test_aide_snapshots_require_exact_bytes_and_retained_security_metadata(self):
        from nebulalog_manager import aide_updates
        self.call(boot.arm_candidate)
        _, plan = boot._current(self.stage)
        description = {key: value for key, value in self.description(self.env).items() if key != 'xattrs_sha256'}
        metadata = {'xattrs_sha256': self.metadata_hash, 'selinux_sha256': 'c' * 64, 'acl_sha256': 'd' * 64}
        with patch.object(aide_updates, '_measure', return_value=(description, metadata)):
            retained = boot.integrity_snapshot(None, plan, 'forward')
            self.assertEqual(retained, {str(self.env): metadata})
            self.assertEqual(boot.integrity_snapshot(None, plan, 'forward', retained), retained)
            with self.assertRaisesRegex(Refused, 'snapshot_changed'):
                boot.integrity_snapshot(None, plan, 'prepare')
            with self.assertRaisesRegex(Refused, 'metadata_changed'):
                boot.integrity_snapshot(None, plan, 'forward', {str(self.env): {**metadata, 'acl_sha256': 'e' * 64}})
        with patch.object(aide_updates, '_measure', return_value=(description, {**metadata, 'xattrs_sha256': 'f' * 64})):
            with self.assertRaisesRegex(Refused, 'snapshot_changed'):
                boot.integrity_snapshot(None, plan, 'forward')

    def test_postboot_prepare_allows_only_exact_observed_environment(self):
        from nebulalog_manager import aide_updates
        self.call(boot.arm_candidate)
        self.new_boot()
        self.call(boot.verify_postboot)
        _, plan = boot._current(self.stage)
        description = {key: value for key, value in self.description(self.env).items() if key != 'xattrs_sha256'}
        metadata = {'xattrs_sha256': self.metadata_hash, 'selinux_sha256': 'c' * 64, 'acl_sha256': 'd' * 64}
        with patch.object(aide_updates, '_measure', return_value=(description, metadata)):
            self.assertEqual(boot.integrity_snapshot(None, plan, 'prepare'), {str(self.env): metadata})
        boot.allowed_integrity_report({'changed': {str(self.env): {}}}, plan, 'prepare')
        with self.assertRaisesRegex(Refused, 'unrelated_integrity_change'):
            boot.allowed_integrity_report({'changed': {str(self.env): {}, '/boot/unrelated': {}}}, plan, 'prepare')

    def test_intent_preparation_cannot_be_rebound_to_other_aide_plan(self):
        self.accept.side_effect = Refused('synthetic outage')
        with self.assertRaises(Refused): self.call(boot.arm_candidate)
        intent = next(self.stage.glob('*-intent.json'))
        value = json.loads(intent.read_text())
        value['prepared']['plan_sha256'] = 'f' * 64
        intent.write_bytes(boot.kernel.encode(value))
        self.accept.reset_mock()
        self.accept.side_effect = self.integrity_callback
        with self.assertRaisesRegex(Refused, 'intent_changed'):
            self.call(boot.arm_candidate)
        self.accept.assert_not_called()

    def test_replacement_security_metadata_failure_keeps_live_preimage(self):
        original = self.env.read_bytes()
        def describe(path):
            value = self.description(path)
            if Path(path).name.startswith('.captains-log-grubenv-'):
                value['xattrs_sha256'] = 'f' * 64
            return value
        with patch.object(boot.kernel, 'describe', side_effect=describe):
            with self.assertRaisesRegex(Refused, 'replacement_metadata_changed'):
                self.call(boot.arm_candidate)
        self.assertEqual(self.env.read_bytes(), original)
        self.accept.assert_not_called()

    def test_operation_boot_and_arm_preimage_are_independently_bound(self):
        atomic_json(self.root / 'manager/os-latest.json', {'stage': str(self.stage), 'boot_id': NEW_BOOT})
        with self.assertRaisesRegex(Refused, 'operation_boot_binding_changed'):
            self.call(boot.arm_candidate)
        atomic_json(self.root / 'manager/os-latest.json', {'stage': str(self.stage), 'boot_id': ORIGINAL_BOOT})
        self.call(boot.arm_candidate)
        _, plan = boot._current(self.stage)
        changed = copy.deepcopy(plan)
        changed['files'][0]['before']['xattrs_sha256'] = 'e' * 64
        changed['files'][0]['after']['xattrs_sha256'] = 'e' * 64
        path = self.replace_plan(changed)
        with self.assertRaisesRegex(Refused, 'arm_origin_changed'):
            boot.validate_transition(self.stage, path, runner=self.runner)

    def promote(self, *, accepted=True):
        self.call(boot.arm_candidate)
        self.new_boot()
        self.env.write_bytes(block({**boot.parse_environment(self.env.read_bytes()), 'boot_success': '1'}))
        self.call(boot.verify_postboot)
        if accepted:
            self.call(boot.commit_candidate, health=self.health())
        else:
            self.accept.side_effect = Refused('power loss before promotion acceptance')
            with self.assertRaises(Refused): self.call(boot.commit_candidate, health=self.health())
            self.accept.side_effect = self.integrity_callback
        return boot._current(self.stage)[1]

    def next_candidate_boot(self, identity):
        self.boot_id = identity
        current = boot.parse_environment(self.env.read_bytes())
        self.env.write_bytes(block({**current, 'boot_success': '0', 'boot_indeterminate': '0'}))

    def test_later_boot_preserves_original_receipts_and_accepts_separate_resume(self):
        promotion = self.promote()
        original = boot.accepted_transitions(self.stage, runner=self.runner)
        self.assertIsNone(original['resume_sha256'])
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.assertEqual(boot.candidate_status(self.stage, runner=self.runner)['phase'], 'commit')
        resumed = self.call(boot.verify_postboot)
        self.assertEqual(resumed['phase'], 'resume')
        self.assertEqual(resumed['boot_id'], self.boot_id)
        self.assertEqual(self.call(boot.commit_candidate, health=self.health()), resumed)
        observed = boot.accepted_transitions(self.stage, runner=self.runner)
        for name in ('postboot_sha256', 'promotion_sha256', 'kernel_plan_sha256', 'installed_sha256'):
            self.assertEqual(observed[name], original[name])
        self.assertIsNotNone(observed['resume_sha256'])
        self.assertNotEqual(observed['boot_id'], original['boot_id'])
        self.assertEqual(promotion['boot_id'], NEW_BOOT)
        self.next_candidate_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        latest = boot.accepted_transitions(self.stage, runner=self.runner)
        self.assertEqual(latest['promotion_sha256'], original['promotion_sha256'])
        self.assertNotEqual(latest['resume_sha256'], observed['resume_sha256'])

    def test_later_boot_after_unaccepted_promotion_uses_exact_intent_without_fabricated_result(self):
        promotion = self.promote(accepted=False)
        original_path = boot._result_path(self.stage, promotion)
        self.assertFalse(original_path.exists())
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.assertFalse(boot.candidate_status(self.stage, runner=self.runner)['accepted'])
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        value = boot.accepted_transitions(self.stage, runner=self.runner)
        self.assertEqual(value['promotion_sha256'], boot.rpm.sha(boot.kernel.encode(promotion)))
        self.assertEqual(value['boot_id'], self.boot_id)
        self.assertIsNotNone(value['resume_sha256'])
        self.assertFalse(original_path.exists())

    def test_later_boot_refuses_changed_promotion_intent_or_unrelated_environment(self):
        promotion = self.promote(accepted=False)
        intent_path = self.stage / ('kernel-boot-' + promotion['id'] + '-intent.json')
        original = intent_path.read_bytes()
        intent = json.loads(original)
        intent['prepared']['plan_sha256'] = 'f' * 64
        intent_path.write_bytes(boot.kernel.encode(intent))
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        with self.assertRaisesRegex(Refused, 'promotion_intent_changed'):
            self.call(boot.verify_postboot)
        intent_path.write_bytes(original)
        self.env.write_bytes(block({**boot.parse_environment(self.env.read_bytes()), 'unexpected': '1'}))
        with self.assertRaisesRegex(Refused, 'unrelated_boot_environment_change'):
            self.call(boot.verify_postboot)

    def test_final_binding_refuses_extra_variable_or_metadata_with_unchanged_default(self):
        self.promote()
        original = self.env.read_bytes()
        self.env.write_bytes(block({**boot.parse_environment(original), 'unexpected': '1'}))
        with self.assertRaises(Refused):
            boot.accepted_transitions(self.stage, runner=self.runner)
        self.env.write_bytes(original)
        self.metadata_hash = 'e' * 64
        with self.assertRaisesRegex(Refused, 'environment_changed'):
            boot.accepted_transitions(self.stage, runner=self.runner)

    def test_new_boot_reconciles_interrupted_arm_without_claiming_old_acceptance(self):
        self.accept.side_effect = Refused('arm AIDE interrupted')
        with self.assertRaises(Refused): self.call(boot.arm_candidate)
        arm = boot._current(self.stage)[1]
        self.assertFalse(boot._result_path(self.stage, arm).exists())
        self.new_boot()
        self.accept.side_effect = self.integrity_callback
        result = self.call(boot.verify_postboot)
        self.assertEqual(result['outcome'], 'candidate')
        self.assertFalse(boot._result_path(self.stage, arm).exists())
        self.call(boot.commit_candidate, health=self.health())

    def test_repeated_new_boot_reconciles_interrupted_resume_intent(self):
        self.promote()
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.accept.side_effect = Refused('resume AIDE interrupted')
        with self.assertRaises(Refused): self.call(boot.verify_postboot)
        interrupted = boot._current(self.stage)[1]
        self.assertEqual(interrupted['phase'], 'resume')
        self.next_candidate_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        self.accept.side_effect = self.integrity_callback
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        proof = boot.accepted_transitions(self.stage, runner=self.runner)
        self.assertEqual(proof['boot_id'], self.boot_id)
        self.assertFalse(boot._result_path(self.stage, interrupted).exists())

    def test_next_boot_retains_unexecuted_resume_and_uses_last_durable_aide_predecessor(self):
        promotion = self.promote()
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.prepare.side_effect = Refused('power loss during resume preparation')
        with self.assertRaises(Refused): self.call(boot.verify_postboot)
        unexecuted = boot._current(self.stage)[1]
        self.assertEqual(unexecuted['phase'], 'resume')
        self.assertFalse((self.stage / ('kernel-boot-' + unexecuted['id'] + '-intent.json')).exists())
        self.next_candidate_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        self.prepare.side_effect = self.integrity_callback
        self.call(boot.verify_postboot)
        path, current = boot._current(self.stage)
        self.assertEqual(current['previous']['id'], unexecuted['id'])
        previous, checksum = boot.integrity_predecessor(self.stage, path, runner=self.runner)
        self.assertEqual(previous['id'], promotion['id'])
        self.assertEqual(checksum, boot.rpm.sha(boot.kernel.encode(promotion)))
        self.call(boot.commit_candidate, health=self.health())
        self.assertEqual(boot.accepted_transitions(self.stage, runner=self.runner)['boot_id'], self.boot_id)
        self.assertFalse(boot._result_path(self.stage, unexecuted).exists())

    def retention_fixture(self):
        """Inject retention provenance at its boundary, not boot/inventory logic.

        Retention's RPM/signature fixtures live in its own suite. These tests use
        the real shared inventory resolver and real compound completion reader;
        the AIDE chain fixture below supplies that independent boundary only.
        """
        from nebulalog_manager import kernel_retention as retention, aide_updates
        self.promote()
        self.initial_acceptance = boot.accepted_transitions(self.stage, runner=self.runner)
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.live_inventory = ['retained-exact']
        self.retention_authorities = {}
        original_read_text = Path.read_text
        def read_text(path, *args, **kwargs):
            if str(path) == '/proc/sys/kernel/random/boot_id':
                return self.boot_id
            return original_read_text(path, *args, **kwargs)
        def authority(stage, reference, *, historical=False, **kwargs):
            self.assertEqual(stage, self.stage)
            boot.exact(reference, {'filename', 'sha256'})
            path = self.stage / reference['filename']
            if path.parent != self.stage or not path.is_file() or boot.rpm.sha(path.read_bytes()) != reference['sha256']:
                raise Refused('fixture_retention_authority_changed')
            value = json.loads(path.read_bytes())
            if value != self.retention_authorities.get(value['boot_id']):
                raise Refused('fixture_retention_authority_changed')
            if not historical and value['boot_id'] != self.boot_id:
                raise Refused('fixture_retention_authority_stale')
            return value
        def compound(stage, reference, **kwargs):
            path = self.stage / reference['filename']
            value = json.loads(path.read_bytes())
            if boot.rpm.sha(path.read_bytes()) != reference['sha256']:
                raise Refused('fixture_compound_plan_changed')
            return value, reference['sha256']
        self.aide_chain = Mock(return_value={'published': True})
        for context in (patch.object(boot.kernel, 'load_plan', return_value=(self.candidate, PLAN_SHA)),
                        patch.object(Path, 'read_text', new=read_text),
                        patch.object(boot.rpm, 'inventory', side_effect=lambda runner: ('', [], list(self.live_inventory))),
                        patch.object(retention, 'validate_boot_authority', side_effect=authority),
                        patch.object(retention, 'load_resume', side_effect=compound),
                        patch.object(aide_updates, 'retained_plan_acceptance', self.aide_chain)):
            context.start()
            self.addCleanup(context.stop)
        return self.observe_retention()

    def observe_retention(self, **changes):
        value = {'schema': 1, 'stage': str(self.stage), 'operation_sha256': boot._operation_sha(self.stage),
                 'candidate_plan_sha256': PLAN_SHA,
                 'installed_sha256': boot.rpm.sha((self.stage / 'kernel-installed.json').read_bytes()),
                 'boot_id': self.boot_id, 'kernel': NEW, 'recovery_kernel': OLD,
                 'retention_plan_sha256': 'e' * 64, 'after_inventory': ['retained-exact'],
                 'grub_observed': self.description(self.env),
                 'grub_observed_raw': base64.b64encode(self.env.read_bytes()).decode(), **changes}
        self.retention_authorities[self.boot_id] = value
        name = 'kernel-retention-observation-' + self.boot_id + '.json'
        (self.stage / name).write_bytes(boot.kernel.encode(value))
        return {'filename': name, 'sha256': boot.rpm.sha(boot.kernel.encode(value))}

    def compound_fixture(self, plan):
        """Retain a distinct compound plan/result and bind the actual boot ref."""
        token = plan['id']
        boot_ref = boot._plan_reference(plan)
        compound = {'id': token, 'boot_ref': boot_ref, 'authority_ref': plan['retention_authority'],
                    'boot_id': plan['boot_id'], 'retention_plan_sha256': 'e' * 64}
        name = 'kernel-retention-resume-' + token + '-plan.json'
        (self.stage / name).write_bytes(boot.kernel.encode(compound))
        reference = {'filename': name, 'sha256': boot.rpm.sha(boot.kernel.encode(compound))}
        boot.bind_retention_integrity(self.stage, boot_ref, reference, runner=self.runner)
        result = {'schema': 1, 'status': 'integrity_reconciled', 'plan': reference, 'boot_ref': boot_ref,
                  'authority_ref': plan['retention_authority'], 'boot_id': plan['boot_id'], 'kernel': NEW,
                  'retention_plan_sha256': 'e' * 64, 'aide': {'entry': {'id': 'synthetic', 'sha256': 'e' * 64}},
                  'release_accepted': False}
        name = 'kernel-retention-resume-' + token + '-result.json'
        (self.stage / name).write_bytes(boot.kernel.encode(result))
        return {'filename': name, 'sha256': boot.rpm.sha(boot.kernel.encode(result))}, reference

    def test_retention_requires_explicit_authority_and_keeps_original_inventory_strict(self):
        authority = self.retention_fixture()
        with self.assertRaisesRegex(Refused, 'package_inventory_changed'):
            self.call(boot.verify_postboot)
        with self.assertRaises(Refused):
            boot.plan_retention_resume(self.stage, {'after_inventory': self.live_inventory}, runner=self.runner)
        with self.assertRaisesRegex(Refused, 'authority_changed'):
            boot.plan_retention_resume(self.stage, {**authority, 'sha256': 'f' * 64}, runner=self.runner)
        self.live_inventory.append('unrelated-extra-package')
        with self.assertRaisesRegex(Refused, 'package_inventory_changed'):
            boot.plan_retention_resume(self.stage, authority, runner=self.runner)
        self.assertEqual(boot._current(self.stage)[1]['phase'], 'commit')

    def test_retention_authority_cannot_rebind_candidate_or_observed_grub(self):
        self.retention_fixture()
        for change in ({'candidate_plan_sha256': 'f' * 64}, {'operation_sha256': 'f' * 64},
                       {'installed_sha256': 'f' * 64}, {'grub_observed_raw': base64.b64encode(block(variables())).decode()}):
            with self.subTest(change=change):
                authority = self.observe_retention(**change)
                with self.assertRaises(Refused):
                    boot.plan_retention_resume(self.stage, authority, runner=self.runner)
                self.assertEqual(boot._current(self.stage)[1]['phase'], 'commit')

    def test_retention_observation_never_accepts_a_boot_only_integrity_delta(self):
        authority = self.retention_fixture()
        calls, raw = self.prepare.call_count, self.env.read_bytes()
        path, plan = boot.plan_retention_resume(self.stage, authority, runner=self.runner)
        self.assertEqual(boot.plan_retention_resume(self.stage, authority, runner=self.runner), (path, plan))
        self.assertFalse(boot._result_path(self.stage, plan).exists())
        self.assertEqual(self.prepare.call_count, calls)
        self.assertEqual(self.env.read_bytes(), raw)
        for function in (boot.verify_postboot, boot.resume_candidate):
            with self.subTest(function=function), self.assertRaises(Refused): self.call(function)
        for phase in ('prepare', 'forward'):
            with self.assertRaisesRegex(Refused, 'compound_integrity_plan_required'):
                boot.allowed_integrity_report({}, plan, phase)
            with self.assertRaisesRegex(Refused, 'compound_integrity_plan_required'):
                boot.integrity_snapshot(None, plan, phase)

    def test_compound_completion_requires_real_chain_and_keeps_original_proof_hashes(self):
        authority = self.retention_fixture()
        _, plan = boot.plan_retention_resume(self.stage, authority, runner=self.runner)
        reference, compound = self.compound_fixture(plan)
        boot_ref = boot._plan_reference(plan)
        self.aide_chain.side_effect = Refused('fixture_missing_published_aide_entry')
        with self.assertRaisesRegex(Refused, 'published_aide_entry'):
            boot.complete_retention_resume(self.stage, boot_ref, reference, runner=self.runner)
        self.assertFalse(boot._result_path(self.stage, plan).exists())
        self.aide_chain.side_effect = None
        result = boot.complete_retention_resume(self.stage, boot_ref, reference, runner=self.runner)
        self.assertNotIn('aide', result)
        self.assertEqual(result['retention_integrity'], reference)
        self.assertEqual(boot.complete_retention_resume(self.stage, boot_ref, reference, runner=self.runner), result)
        current = boot.accepted_transitions(self.stage, runner=self.runner)
        self.assertEqual(current['retention_integrity_sha256'], reference['sha256'])
        for key in ('postboot_sha256', 'promotion_sha256', 'kernel_plan_sha256', 'installed_sha256'):
            self.assertEqual(current[key], self.initial_acceptance[key])
        self.assertEqual(current['boot_id'], self.boot_id)
        self.assertEqual(boot.read_retention_integrity_binding(self.stage, boot_ref), compound)
        self.assertEqual(self.call(boot.commit_candidate, health=self.health()), result)

    def test_later_boot_binds_prior_compound_even_before_boot_result(self):
        authority = self.retention_fixture()
        _, first = boot.plan_retention_resume(self.stage, authority, runner=self.runner)
        _, compound = self.compound_fixture(first)
        self.assertFalse(boot._result_path(self.stage, first).exists())
        self.next_candidate_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        next_authority = self.observe_retention()
        _, second = boot.plan_retention_resume(self.stage, next_authority, runner=self.runner)
        self.assertEqual(second['previous_retention_plan'], compound)
        proof = boot.validate_retention_resume(self.stage, boot._plan_reference(second), runner=self.runner)
        self.assertEqual(proof['previous_retention_plan'], compound)
        self.assertFalse(boot._result_path(self.stage, first).exists())

    def test_unlinked_retention_observation_is_retained_without_inventing_compound_work(self):
        authority = self.retention_fixture()
        _, first = boot.plan_retention_resume(self.stage, authority, runner=self.runner)
        self.next_candidate_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        _, second = boot.plan_retention_resume(self.stage, self.observe_retention(), runner=self.runner)
        self.assertEqual(second['previous']['id'], first['id'])
        self.assertIsNone(second['previous_retention_plan'])
        self.assertFalse(boot._result_path(self.stage, first).exists())

    def test_compound_result_or_environment_drift_refuses_final_proof(self):
        authority = self.retention_fixture()
        _, plan = boot.plan_retention_resume(self.stage, authority, runner=self.runner)
        reference, _ = self.compound_fixture(plan)
        boot.complete_retention_resume(self.stage, boot._plan_reference(plan), reference, runner=self.runner)
        self.env.write_bytes(block({**boot.parse_environment(self.env.read_bytes()), 'unexpected': '1'}))
        with self.assertRaises(Refused): boot.accepted_transitions(self.stage, runner=self.runner)
        self.env.write_bytes(base64.b64decode(plan['after_raw']))
        path = self.stage / reference['filename']
        result = json.loads(path.read_bytes());result['aide'] = {'ok': True}
        path.write_bytes(boot.kernel.encode(result))
        with self.assertRaisesRegex(Refused, 'compound_integrity_reference_changed'):
            boot.accepted_transitions(self.stage, runner=self.runner)


if __name__ == '__main__':
    unittest.main()
