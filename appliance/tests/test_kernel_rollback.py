"""Rejected-candidate erase/reboot recovery with actual private AIDE chains.

Native signed-RPM provenance and scanner inputs are injected. Dispatch, boot
proof, generation binding, once-only intent, reports, AIDE CAS and completion
validation remain real. These tests never run a host RPM command.
"""
import copy
import json
from pathlib import Path
import uuid
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import aide_updates as updates, kernel_boot as boot, kernel_rollback as rollback
from nebulalog_manager.common import Refused, atomic_json
import test_kernel_boot as native
import test_kernel_boot_aide as integration

REAL_LOAD_CANDIDATE = rollback.kernel.load_candidate


class RollbackAideTests(TestCase):
    for _name, _value in integration.KernelAideIntegrationTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_') and _name != 'setUp':
            locals()[_name] = _value

    def setUp(self):
        integration.KernelAideIntegrationTests.setUp(self)
        operation = {'schema': 1, 'id': str(uuid.UUID(self.stage.name)), 'stage': str(self.stage), 'boot_id': self.boot_id}
        atomic_json(self.stage / 'operation.json', operation)
        self.candidate['operation_sha256'] = boot._operation_sha(self.stage)
        self.candidate['before_inventory'] = ['before']
        self.live_inventory = ['after']
        self.erase_commands = []
        self.native_runner = self.runner
        self.runner = self.rollback_runner
        for context in (
                patch.object(rollback, 'require_linux_root'),
                patch.object(rollback.kernel, 'require_linux_root'),
                patch.object(rollback.kernel, 'GRUBENV', str(self.env)),
                patch.object(rollback.mechanical, 'preserved_description', side_effect=lambda p: self.description(Path(p))),
                patch.object(rollback.rpm, 'inventory', side_effect=lambda runner: ('fixture inventory', [], list(self.live_inventory))),
                patch.object(rollback, 'verify_signed_history'),
                patch.object(rollback, 'run', side_effect=self.runner),
                patch.object(updates.aide, 'Aide', return_value=self.manager),
                patch.object(rollback, '_candidate', side_effect=lambda stage, plan: (self.stage, self.candidate, self.installed)),
                patch.object(boot.kernel, 'load_plan', return_value=(self.candidate, native.PLAN_SHA)),
                patch.object(boot, 'recovery_authorization', side_effect=lambda stage, authorize, **kw: authorize(stage))):
            context.start(); self.addCleanup(context.stop)
        self.call(boot.arm_candidate)
        self.new_boot(candidate=False)
        self.call(boot.verify_postboot)
        proof = boot.verified_recovery(self.stage, runner=self.runner)
        self.original = {'schema': 1, 'kind': rollback.KIND, 'operation_sha256': boot._operation_sha(self.stage),
                         'boot_id': self.boot_id, 'candidate_stage': str(self.stage),
                         'candidate_plan_sha256': native.PLAN_SHA,
                         'installed_sha256': rollback.rpm.sha((self.stage / 'kernel-installed.json').read_bytes()),
                         'kernel': native.NEW, 'recovery_kernel': native.OLD, 'recovery': proof,
                         'before_inventory': ['after'], 'after_inventory': ['before'],
                         'inventory_sha256': rollback.rpm.sha(b'fixture inventory'), 'packages': [],
                         'removed': {str(self.retired): self.description(self.retired)},
                         'preserved': {str(p): self.description(p) for p in (self.env, self.unrelated)},
                         'mutable_directories': [], 'retained_kernels': [native.OLD]}
        self.original_sha = rollback.rpm.sha(rollback.kernel.encode(self.original))
        self.write_private(self.stage / rollback.PLAN, rollback.kernel.encode(self.original))
        self.write_private(self.stage / rollback.INTEGRITY,
                           rollback.kernel.encode(rollback.integrity_plan(self.original, self.original_sha)))
        context = patch.object(rollback, '_load_frozen', side_effect=self.frozen)
        context.start(); self.addCleanup(context.stop)
        self.original_bytes = (self.stage / rollback.PLAN).read_bytes()
        self.integrity_bytes = (self.stage / rollback.INTEGRITY).read_bytes()
        self.enrollment_bytes = self.marker.read_bytes()

    def frozen(self, stage, path, **kwargs):
        self.assertEqual(Path(stage), self.stage)
        value = json.loads(Path(path).read_text())
        # Native RPM/file-scope qualification is the injected boundary. Actual
        # historical boot acceptance and source binding are not bypassed.
        boot.validate_recovery_proof(stage, value['recovery'], historical=True, runner=self.runner)
        self.assertEqual(value['candidate_plan_sha256'], native.PLAN_SHA)
        return value, rollback.rpm.sha(Path(path).read_bytes())

    def authorize(self, stage):
        self.assertEqual(stage, self.stage)
        return {'ok': True, 'stage': str(stage), 'boot_id': self.boot_id, 'kernel': native.OLD,
                'checks': {name: True for name in boot.REQUIRED_CHECKS},
                'backup_stage': str(stage), 'backup_sha256': 'f' * 64}

    def rollback_runner(self, argv, **kwargs):
        if argv[:2] == ['/usr/bin/rpm', '--erase']:
            self.erase_commands.append(argv)
            if '--test' not in argv:
                self.retired.unlink()
                self.live_inventory = ['before']
            return ''
        return self.native_runner(argv, **kwargs)

    def execute(self):
        return rollback.rollback(self.stage, authorize=self.authorize, runner=self.runner)

    def prepare_only(self):
        path = rollback.execution_integrity_path(self.stage)
        updates.prepare(self.manager, self.stage, path)
        return path

    def attempt_only(self):
        path = self.prepare_only()
        callback = lambda stage, checksum: rollback.authorization(stage, checksum, manager=self.manager,
            authorize=self.authorize, recovery=(stage / rollback.INTENT).exists(), runner=self.runner)
        rollback.execute_cached(self.stage, authorize=callback, runner=self.runner)
        return path

    def later_boot(self, identity='cccccccc-cccc-cccc-cccc-cccccccccccc'):
        values = boot.parse_environment(self.env.read_bytes())
        values['boot_indeterminate'] = ('0' if values['boot_success'] == '1'
                                        else '2' if values['boot_indeterminate'] == '1' else values['boot_indeterminate'])
        values['boot_success'] = '0'
        self.env.write_bytes(native.block(values))
        self.boot_id = identity
        self.running = native.OLD

    def originals(self):
        self.assertEqual((self.stage / rollback.PLAN).read_bytes(), self.original_bytes)
        self.assertEqual((self.stage / rollback.INTEGRITY).read_bytes(), self.integrity_bytes)
        self.assertEqual(self.marker.read_bytes(), self.enrollment_bytes)
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_successful_exact_rollback_keeps_old_default_and_original_enrollment(self):
        result = self.execute()
        self.assertTrue(result['ok'])
        self.assertEqual(result['status'], 'rolled_back')
        self.assertFalse(result['release_accepted'])
        self.assertEqual(len([argv for argv in self.erase_commands if '--test' not in argv]), 1)
        self.assertEqual(self.runner(['/usr/sbin/grubby', '--default-kernel']), '/boot/vmlinuz-' + native.OLD)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.originals()

    def test_absence_without_global_intent_cannot_advance_aide(self):
        path = self.prepare_only()
        self.retired.unlink(); self.live_inventory = ['before']
        before = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaises((Refused, FileNotFoundError)):
            updates.accept(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assertFalse((self.stage / rollback.INTENT).exists())

    def test_wrong_prepared_digest_cannot_accept_even_exact_erasure(self):
        path = self.attempt_only()
        value = json.loads((self.stage / rollback.INTENT).read_text())
        value['authorization']['aide_preparation_sha256'] = '0' * 64
        self.write_private(self.stage / rollback.INTENT, rollback.kernel.encode(value))
        before = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaisesRegex(Refused, 'preparation_changed'):
            updates.accept(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)

    def test_unrelated_drift_prevents_rpm_and_baseline_change(self):
        self.unrelated.write_bytes(b'not authorized\n')
        before = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaises(Refused): self.execute()
        self.assertFalse((self.stage / rollback.INTENT).exists())
        self.assertEqual(self.erase_commands, [])
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)

    def test_once_only_after_erase_recovery_does_not_issue_another_command(self):
        self.attempt_only()
        commands = list(self.erase_commands)
        self.assertEqual(self.execute()['status'], 'rolled_back')
        self.assertEqual(self.erase_commands, commands)
        self.originals()

    def test_intent_with_unchanged_inventory_remains_ambiguous(self):
        self.attempt_only()
        self.live_inventory = ['after']
        commands = list(self.erase_commands)
        with self.assertRaisesRegex(Refused, 'ambiguous_no_replay'): self.execute()
        self.assertEqual(self.erase_commands, commands)
        self.assertFalse((self.stage / rollback.COMPLETE).exists())

    def test_partial_inventory_or_leftover_target_cannot_complete(self):
        self.attempt_only()
        self.live_inventory = ['partial']
        with self.assertRaisesRegex(Refused, 'partial_or_unowned'): self.execute()
        self.live_inventory = ['before']
        self.retired.write_bytes(b'leftover')
        with self.assertRaisesRegex(Refused, 'still_present'): self.execute()
        self.assertFalse((self.stage / rollback.COMPLETE).exists())

    def test_reboot_before_first_attempt_keeps_original_and_uses_new_generation(self):
        self.prepare_only()
        self.later_boot()
        result = self.execute()
        self.assertEqual(result['boot_id'], self.boot_id)
        intent = json.loads((self.stage / rollback.INTENT).read_text())
        self.assertEqual(intent['schema'], 2)
        self.assertNotEqual(intent['plan_sha256'], self.original_sha)
        self.assertEqual(len([argv for argv in self.erase_commands if '--test' not in argv]), 1)
        self.originals()

    def test_reboot_after_exact_erase_uses_compound_aide_without_rpm(self):
        self.attempt_only()
        commands = list(self.erase_commands)
        self.later_boot()
        result = self.execute()
        self.assertEqual(result['boot_id'], self.boot_id)
        self.assertEqual(self.erase_commands, commands)
        pointer = json.loads((self.stage / rollback.RESUME_CURRENT).read_text())
        proof = updates.retained_plan_acceptance(self.stage, self.stage / pointer['filename'], manager=self.manager)
        self.assertEqual(proof['database_sha256'], result['database_sha256'])
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.originals()

    def test_reboot_after_completion_retains_first_completion_and_accepts_new_boot(self):
        first = self.execute()
        completion = (self.stage / rollback.COMPLETE).read_bytes()
        commands = list(self.erase_commands)
        self.later_boot()
        self.assertEqual(self.execute(), first)
        self.assertEqual((self.stage / rollback.COMPLETE).read_bytes(), completion)
        self.assertEqual(self.erase_commands, commands)
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_unrelated_grub_change_after_erase_is_not_baselined(self):
        self.attempt_only(); self.later_boot()
        value = boot.parse_environment(self.env.read_bytes()); value['menu_auto_hide'] = '0'
        self.env.write_bytes(native.block(value))
        before = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaisesRegex(Refused, 'unrelated_boot_environment'): self.execute()
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)

    def interrupted(self, point):
        path = self.attempt_only()
        if point == 'scanning':
            def crash(action, *args):
                if action == 'update': raise OSError('injected scanner interruption')
            self.scan_hook = crash
            with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
            self.scan_hook = None
        elif point == 'ready_input':
            with patch.object(updates, '_complete', side_effect=OSError('injected before copy')):
                with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
        else:
            replace = updates._replace_current
            def crash(*args):
                replace(*args); raise OSError('injected after copy')
            with patch.object(updates, '_replace_current', side_effect=crash):
                with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
        commands = list(self.erase_commands)
        self.later_boot()
        self.execute()
        self.assertEqual(self.erase_commands, commands)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.originals()

    def test_crossboot_scanning_interruption_recovers(self): self.interrupted('scanning')
    def test_crossboot_ready_input_interruption_recovers(self): self.interrupted('ready_input')
    def test_crossboot_ready_output_interruption_recovers(self): self.interrupted('ready_output')

    def test_second_boot_before_compound_prepare_preserves_ancestry(self):
        self.attempt_only(); self.later_boot()
        first_path, _ = rollback.prepare_resume(self.stage, authorize=self.authorize, runner=self.runner)
        first = first_path.read_bytes()
        self.later_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        self.execute()
        self.assertEqual(first_path.read_bytes(), first)
        pointer = json.loads((self.stage / rollback.RESUME_CURRENT).read_text())
        value = json.loads((self.stage / pointer['filename']).read_text())
        self.assertEqual(value['previous']['filename'], first_path.name)
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_same_boot_vendor_success_before_erase_gets_verified_execution_generation(self):
        value = boot.parse_environment(self.env.read_bytes()); value['boot_success'] = '1'
        self.env.write_bytes(native.block(value))
        self.execute()
        intent = json.loads((self.stage / rollback.INTENT).read_text())
        self.assertEqual(intent['schema'], 2)
        self.assertEqual(self.original['boot_id'], self.boot_id)
        self.originals()

    def test_same_boot_vendor_success_after_erase_gets_compound_integrity(self):
        self.attempt_only()
        value = boot.parse_environment(self.env.read_bytes()); value['boot_success'] = '1'
        self.env.write_bytes(native.block(value))
        self.execute()
        self.assertTrue((self.stage / rollback.RESUME_CURRENT).exists())
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.originals()

    def test_second_unattempted_execution_generation_preserves_first_preparation(self):
        self.later_boot()
        rollback.prepare_execution(self.stage, authorize=self.authorize, manager=self.manager, runner=self.runner)
        first_path = self.prepare_only(); first = first_path.read_bytes()
        self.later_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        self.execute()
        self.assertEqual(first_path.read_bytes(), first)
        self.assertNotEqual(rollback.execution_integrity_path(self.stage), first_path)
        self.originals()

    def test_execution_generation_cannot_expand_removal_even_with_rehashed_reference(self):
        self.later_boot()
        rollback.prepare_execution(self.stage, authorize=self.authorize, manager=self.manager, runner=self.runner)
        pointer = json.loads((self.stage / rollback.EXECUTION_CURRENT).read_text())
        path = self.stage / pointer['filename']
        value = json.loads(path.read_text()); value['removed'][str(self.unrelated)] = self.description(self.unrelated)
        self.write_private(path, rollback.kernel.encode(value))
        pointer['sha256'] = rollback.rpm.sha(path.read_bytes())
        atomic_json(self.stage / rollback.EXECUTION_CURRENT, pointer)
        with self.assertRaisesRegex(Refused, 'execution_original_scope_changed'):
            rollback.load_plan(self.stage, runner=self.runner)
        self.assertFalse((self.stage / rollback.INTENT).exists())

    def test_compound_cannot_expand_removal_even_with_rehashed_manifest(self):
        self.attempt_only(); self.later_boot()
        path, value = rollback.prepare_resume(self.stage, authorize=self.authorize, runner=self.runner)
        value['removed'][str(self.unrelated)] = self.description(self.unrelated)
        value['manifest_sha256'] = updates.digest({k: v for k, v in value.items() if k != 'manifest_sha256'})
        self.write_private(path, rollback.kernel.encode(value))
        reference = {'filename': path.name, 'sha256': rollback.rpm.sha(path.read_bytes())}
        with self.assertRaisesRegex(Refused, 'resume_scope_changed'):
            rollback.load_resume(self.stage, reference, runner=self.runner)

    def test_compound_wrong_original_preparation_cannot_change_database(self):
        self.attempt_only(); self.later_boot()
        path, value = rollback.prepare_resume(self.stage, authorize=self.authorize, runner=self.runner)
        intent = json.loads((self.stage / rollback.INTENT).read_text())
        intent['authorization']['aide_preparation_sha256'] = '0' * 64
        self.write_private(self.stage / rollback.INTENT, rollback.kernel.encode(intent))
        value['original_preparation_sha256'] = '0' * 64
        value['erase_intent_sha256'] = rollback.rpm.sha((self.stage / rollback.INTENT).read_bytes())
        value['manifest_sha256'] = updates.digest({k: v for k, v in value.items() if k != 'manifest_sha256'})
        self.write_private(path, rollback.kernel.encode(value))
        before = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaisesRegex(Refused, 'original_preparation_changed'):
            updates.prepare(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)

    def test_first_completion_proof_survives_reboot_before_completion_publication(self):
        record = rollback.kernel.record
        def crash(stage, name, value):
            if name == rollback.COMPLETE: raise OSError('after proof before completion')
            return record(stage, name, value)
        with patch.object(rollback.kernel, 'record', side_effect=crash):
            with self.assertRaises(OSError): self.execute()
        proof = (self.stage / 'kernel-rollback-completion-proof.json').read_bytes()
        self.later_boot()
        result = self.execute()
        self.assertEqual(result['boot_id'], self.original['boot_id'])
        self.assertEqual((self.stage / 'kernel-rollback-completion-proof.json').read_bytes(), proof)
        self.assertEqual(self.manager.check()['state'], 'clean')

    def terminal_pending(self):
        value = {'schema': 1, 'stage': str(self.stage), 'plan_sha256': native.PLAN_SHA,
                 'installed_sha256': rollback.rpm.sha((self.stage / 'kernel-installed.json').read_bytes()),
                 'operation_sha256': self.candidate['operation_sha256'],
                 'kernel': native.NEW, 'old_kernel': native.OLD}
        atomic_json(self.root / 'manager/kernel-pending.json', value)
        return value

    def test_real_completion_quarantines_failed_version_before_clearing_owned_pending(self):
        pending = self.terminal_pending()
        completion = {k: v for k, v in self.execute().items() if k != 'ok'}
        health = {k: v for k, v in self.authorize(self.stage).items() if k not in {'backup_stage', 'backup_sha256'}}
        with patch.object(rollback.kernel, 'load_candidate', new=REAL_LOAD_CANDIDATE):
            result = rollback.kernel.mark_rolled_back(self.stage, completion, health, runner=self.runner)
            self.assertEqual(result['status'], 'rolled_back')
            self.assertFalse((self.root / 'manager/kernel-pending.json').exists())
            self.assertEqual(rollback.kernel.load_candidate(self.stage)[1], self.candidate)
            self.assertEqual(json.loads((self.stage / 'kernel-rollback-pending.json').read_text())['pending'], pending)
            with self.assertRaisesRegex(Refused, 'quarantined_after_rollback'):
                rollback.kernel.reject_quarantined(self.stage, native.NEW)
            self.later_boot()
            self.assertEqual(self.execute()['status'], 'rolled_back')
        self.originals()

    def test_failed_final_health_preserves_pending_and_does_not_publish_quarantine(self):
        self.terminal_pending()
        completion = {k: v for k, v in self.execute().items() if k != 'ok'}
        health = {k: v for k, v in self.authorize(self.stage).items() if k not in {'backup_stage', 'backup_sha256'}}
        health['checks']['local_auth'] = False
        with patch.object(rollback.kernel, 'load_candidate', new=REAL_LOAD_CANDIDATE):
            with self.assertRaises(Refused):
                rollback.kernel.mark_rolled_back(self.stage, completion, health, runner=self.runner)
        self.assertTrue((self.root / 'manager/kernel-pending.json').exists())
        self.assertFalse((self.root / ('manager/kernel-rejected-' + native.NEW + '.json')).exists())


class CandidateScopeTests(TestCase):
    def candidate(self):
        root = '/usr/lib/modules/' + native.NEW
        return {'kernel': native.NEW, 'machine_id': native.MACHINE,
                'files': [{'path': root, 'kind': 'directory'}, {'path': root + '/vmlinuz', 'kind': 'file'},
                          {'path': '/usr/lib/modules', 'kind': 'directory'}],
                'generated': sorted(rollback.kernel.generated_paths(native.NEW, native.MACHINE)),
                'shared': {'/usr/lib/modules': {'kind': 'directory'}}}

    def test_scope_removes_candidate_and_generated_but_never_shared_parent(self):
        value = self.candidate()
        removed, parents = rollback._scope(value)
        self.assertTrue(set(value['generated']) <= removed)
        self.assertNotIn('/usr/lib/modules', removed)
        self.assertIn('/usr/lib/modules', parents)
        self.assertNotIn('/boot/vmlinuz-' + native.OLD, removed)

    def test_unrelated_path_duplicate_target_missing_generated_or_shared_file_refused(self):
        original = self.candidate()
        changes = [lambda value: value['files'].append({'path': '/etc/shadow', 'kind': 'file'}),
                   lambda value: value['files'].append(value['files'][0]),
                   lambda value: value['generated'].pop(),
                   lambda value: value['files'][-1].update(kind='file')]
        for change in changes:
            value = copy.deepcopy(original); change(value)
            with self.subTest(change=change), self.assertRaises(Refused): rollback._scope(value)

    def test_exact_command_contains_only_failed_candidate_four_nevras(self):
        packages = [{'nevra': name + '-0:' + native.NEW} for name in sorted(rollback.kernel.NAMES)]
        self.assertEqual(rollback.mechanical.command({'packages': packages}),
                         ['/usr/bin/rpm', '--erase', *sorted(p['nevra'] for p in packages)])


class FrozenRecipeTests(TestCase):
    def setUp(self):
        from test_kernel_retention import headers
        self.stage = Path('/fixture/manager/os-updates/' + '1' * 32)
        self.candidate = CandidateScopeTests.candidate(self)
        self.candidate.update(old_kernel=native.OLD, packages=[
            {'name': name, 'nevra': name + '-0:' + native.NEW, 'kernel': native.NEW}
            for name in sorted(rollback.kernel.NAMES)])
        self.headers = headers([native.OLD, native.NEW])
        before = sorted(rollback.rpm.identity(h)['nevra'] for h in self.headers)
        after = sorted(rollback.rpm.identity(h)['nevra'] for h in headers([native.OLD]))
        self.candidate.update(before_inventory=after, after_inventory=before)
        removed, parents = rollback._scope(self.candidate)
        self.descriptor = {'kind': 'file', 'sha256': 'a' * 64, 'bytes': 10, 'uid': 0, 'gid': 0,
                           'mode': 0o600, 'xattrs_sha256': 'b' * 64}
        protected = set(rollback.kernel.generated_paths(native.OLD, native.MACHINE)) | {
            rollback.kernel.GRUBENV, rollback.kernel.KERNEL_CONFIG, '/etc/default/grub', '/boot/grub2/grub.cfg'}
        self.protected = protected
        preserved = {p: copy.deepcopy(self.descriptor) for p in protected | parents}
        for path in parents: preserved[path] = {'kind': 'directory'}
        operation_sha = rollback.rpm.sha(b'operation')
        self.recovery = {'boot_id': native.NEW_BOOT, 'kernel': native.NEW, 'recovery_kernel': native.OLD,
                         'candidate_plan_sha256': native.PLAN_SHA, 'installed_sha256': 'c' * 64,
                         'operation_sha256': operation_sha,
                         'mutable': {rollback.kernel.GRUBENV: copy.deepcopy(self.descriptor)}}
        self.plan = {'schema': 1, 'kind': rollback.KIND, 'operation_sha256': operation_sha,
                     'boot_id': native.NEW_BOOT, 'candidate_stage': str(self.stage),
                     'candidate_plan_sha256': native.PLAN_SHA, 'installed_sha256': 'c' * 64,
                     'kernel': native.NEW, 'recovery_kernel': native.OLD, 'recovery': self.recovery,
                     'before_inventory': before, 'after_inventory': after, 'inventory_sha256': rollback.rpm.sha(b'xml'),
                     'packages': self.candidate['packages'], 'removed': {p: copy.deepcopy(self.descriptor) for p in removed},
                     'preserved': preserved, 'mutable_directories': sorted(parents), 'retained_kernels': [native.OLD]}
        self.installed = {'generated': {p: copy.deepcopy(self.descriptor) for p in self.candidate['generated']}}
        def read(path, *args):
            if Path(path).name == rollback.PLAN: return rollback.kernel.encode(self.plan)
            if Path(path).name == 'operation.json': return b'operation'
            if Path(path).name == 'kernel-rollback-inventory.xml': return b'xml'
            self.fail('unexpected fixture path: ' + str(path))
        for context in (
                patch.object(rollback.rpm, 'read', side_effect=read),
                patch.object(rollback.rpm, 'headers', return_value=self.headers),
                patch.object(rollback, '_candidate', side_effect=lambda stage, plan: (self.stage, self.candidate, self.installed)),
                patch.object(rollback, 'verify_signed_history', return_value=self.candidate),
                patch.object(rollback, '_installed_scope', side_effect=lambda *args: ([native.OLD], set(self.protected))),
                patch.object(boot, 'validate_recovery_proof')):
            context.start(); self.addCleanup(context.stop)

    def load(self):
        return rollback._load_frozen(self.stage, self.stage / rollback.PLAN)

    def test_recipe_requires_exact_candidate_before_and_after_inventories(self):
        self.assertEqual(self.load()[0], self.plan)
        self.plan['after_inventory'] = self.plan['before_inventory']
        with self.assertRaisesRegex(Refused, 'frozen_rollback_scope'): self.load()

    def test_rehashed_removal_expansion_missing_parent_and_missing_protected_old_artifact_refused(self):
        original = copy.deepcopy(self.plan)
        changes = [lambda: self.plan['removed'].update({'/etc/shadow': self.descriptor}),
                   lambda: self.plan['mutable_directories'].append('/etc'),
                   lambda: self.plan['preserved'].pop('/boot/vmlinuz-' + native.OLD),
                   lambda: self.plan['preserved'].update({'/new/unrelated': self.descriptor})]
        for change in changes:
            self.plan = copy.deepcopy(original); change()
            with self.subTest(change=change), self.assertRaises(Refused): self.load()

    def test_generated_removal_preimages_must_match_installed_receipt(self):
        self.plan['removed']['/boot/vmlinuz-' + native.NEW]['sha256'] = '0' * 64
        with self.assertRaisesRegex(Refused, 'historical_inventory_or_artifacts'): self.load()

    def test_failed_candidate_old_default_and_proof_checksums_cannot_be_rebound(self):
        original = copy.deepcopy(self.plan)
        for field in ('kernel', 'recovery_kernel', 'candidate_plan_sha256', 'installed_sha256', 'operation_sha256', 'boot_id'):
            self.plan = copy.deepcopy(original)
            self.plan[field] = 'changed'
            with self.subTest(field=field), self.assertRaises(Refused): self.load()


class OriginOwnershipTests(TestCase):
    def setUp(self):
        from nebulalog_manager import kernel_retention_integration as provenance
        self.stage = Path('/fixture/manager/os-updates/' + '1' * 32)
        self.source = self.stage.with_name('2' * 32)
        self.candidate = {'kernel': native.NEW, 'old_kernel': native.OLD}
        self.installed = {'schema': 1, 'status': 'installed_pending_integrity_and_reboot',
                          'kernel': native.NEW, 'old_kernel': native.OLD, 'release_accepted': False,
                          'plan_sha256': native.PLAN_SHA}
        self.plan = {'candidate_stage': str(self.source), 'candidate_plan_sha256': native.PLAN_SHA,
                     'installed_sha256': 'b' * 64, 'operation_sha256': 'c' * 64,
                     'kernel': native.NEW, 'recovery_kernel': native.OLD}
        self.owner = {'schema': 1, 'stage': str(self.stage), 'candidate_plan_sha256': native.PLAN_SHA,
                      'installed_sha256': 'b' * 64, 'operation_sha256': 'c' * 64}
        for context in (patch.object(provenance, 'owned_stage'),
                        patch.object(rollback.kernel, 'load_plan', return_value=(self.candidate, native.PLAN_SHA)),
                        patch.object(rollback, '_read', side_effect=lambda path: (
                            (self.installed, 'b' * 64) if Path(path).name == 'kernel-installed.json' else (self.owner, 'd' * 64)))):
            context.start(); self.addCleanup(context.stop)

    def test_origin_installed_receipt_and_exclusive_owner_bind_exact_operation(self):
        self.assertEqual(rollback._candidate(self.stage, self.plan)[0], self.source)
        original = copy.deepcopy(self.owner)
        for field in ('stage', 'candidate_plan_sha256', 'installed_sha256', 'operation_sha256', 'schema'):
            self.owner = {**original, field: True if field == 'schema' else 'foreign'}
            with self.subTest(field=field), self.assertRaises(Refused): rollback._candidate(self.stage, self.plan)

    def test_failed_install_or_candidate_acceptance_is_not_rollback_install_authority(self):
        original = copy.deepcopy(self.installed)
        for change in ({'status': 'installing'}, {'schema': True}, {'release_accepted': True}, {'plan_sha256': '0' * 64}):
            self.installed = {**original, **change}
            with self.subTest(change=change), self.assertRaises(Refused): rollback._candidate(self.stage, self.plan)
