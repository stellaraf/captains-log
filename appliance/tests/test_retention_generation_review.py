"""Independent generation/boot/AIDE integration with private host fixtures.

Signed RPM provenance and the native host are injected. Boot transitions,
execution-generation binding, AIDE dispatch, reports, database CAS, retained
acceptance and ordinary-boot history are real. No host package is erased.
"""
import base64
import copy
import json
from pathlib import Path
import uuid
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import aide_updates as updates, kernel_boot as boot
from nebulalog_manager import kernel_retention as retain, kernel_retention_generation as generation
from nebulalog_manager import ordinary_boot as ordinary
from nebulalog_manager.common import Refused, atomic_json
import test_kernel_boot as native_fixture
import test_kernel_boot_aide as integration
from test_ordinary_boot_state import fixture


class RetentionGenerationReviewTests(TestCase):
    for _name, _value in integration.KernelAideIntegrationTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_') and _name != 'setUp':
            locals()[_name] = _value

    def setUp(self):
        integration.KernelAideIntegrationTests.setUp(self)
        self.initial_snapshot = fixture()
        self.initial_snapshot['grub'] = {'raw': base64.b64encode(self.env.read_bytes()).decode(),
                                         'description': self.description(self.env)}
        self.initial_snapshot['inventory'] = ['after']
        self.initial_snapshot['artifacts'][str(self.retired)] = self.description(self.retired)
        operation = {'schema': 1, 'id': str(uuid.UUID(self.stage.name)), 'stage': str(self.stage),
                     'boot_id': self.boot_id}
        atomic_json(self.stage / 'operation.json', operation)
        self.live_inventory = ['after']
        original_read_text = Path.read_text
        def native_boot_id(path, *args, **kwargs):
            if str(path) == '/proc/sys/kernel/random/boot_id':
                return self.boot_id
            return original_read_text(path, *args, **kwargs)
        for context in (
                patch.object(retain, 'require_linux_root'),
                patch.object(generation, 'require_linux_root'),
                patch.object(retain, 'boot_id', side_effect=lambda: self.boot_id),
                patch.object(retain.kernel, 'GRUBENV', str(self.env)),
                patch.object(retain, 'preserved_description', side_effect=lambda p: self.description(Path(p))),
                patch.object(retain, 'verify_signed_history'),
                patch.object(Path, 'read_text', new=native_boot_id),
                patch.object(retain.rpm, 'inventory', side_effect=lambda runner: ('fixture inventory', [], list(self.live_inventory))),
                patch.object(retain, 'run', side_effect=self.runner),
                patch.object(generation, 'run', side_effect=self.runner),
                patch.object(updates.aide, 'Aide', return_value=self.manager),
                patch.object(ordinary.native, 'ENV', str(self.env)),
                patch.object(ordinary.native, 'ROOTS', (*ordinary.native.ROOTS, str(self.retired))),
                patch.object(boot.kernel, 'load_plan', return_value=(self.candidate, native_fixture.PLAN_SHA))):
            context.start(); self.addCleanup(context.stop)
        self.call(boot.arm_candidate)
        self.new_boot()
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.publish_acceptance()
        self.original = {'operation_sha256': boot._operation_sha(self.stage), 'boot_id': self.boot_id,
                         'acceptance': retain.acceptance_record(self.stage),
                         'removed': {str(self.retired): self.description(self.retired)},
                         'preserved': {str(p): self.description(p) for p in (self.env, self.unrelated)},
                         'mutable_directories': [], 'before_inventory': ['after'],
                         'after_inventory': ['retained-exact'],
                         'inventory_sha256': retain.rpm.sha(b'fixture inventory'),
                         'retained_kernels': [native_fixture.OLD, native_fixture.NEW]}
        self.original_sha = retain.rpm.sha(retain.kernel.encode(self.original))
        self.write_private(self.stage / retain.PLAN, retain.kernel.encode(self.original))
        self.original_path = self.stage / retain.INTEGRITY
        self.original_integrity = retain.integrity_plan(self.original, self.original_sha)
        self.write_private(self.original_path, retain.kernel.encode(self.original_integrity))
        # Only signed/native root-plan provenance is injected. Derived plans
        # must pass the actual generation loader, binding and ancestry checks.
        context = patch.object(retain, '_load_plan', side_effect=self.load_original)
        context.start(); self.addCleanup(context.stop)
        atomic_json(self.root / 'manager/os-transaction.json', {
            **self.transaction, 'state': 'complete', 'kernel_retention': 'pending'})
        updates.prepare(self.manager, self.stage, self.original_path)
        self.original_bytes = (self.stage / retain.PLAN).read_bytes()
        self.original_integrity_bytes = self.original_path.read_bytes()
        self.enrollment_bytes = self.marker.read_bytes()

    def load_original(self, stage, *, historical=False):
        self.assertEqual(stage, self.stage)
        self.assertEqual((self.stage / retain.PLAN).read_bytes(), retain.kernel.encode(self.original))
        return copy.deepcopy(self.original), self.original_sha

    def publish_acceptance(self):
        previous = None
        if (self.stage / 'kernel-acceptance-current.json').exists():
            _, previous, _ = retain.kernel.read_acceptance(self.stage)
        value = {'schema': 1, **boot.accepted_transitions(self.stage, runner=self.runner),
                 'checks': {name: True for name in boot.REQUIRED_CHECKS}, 'finalization': 'complete',
                 'previous_acceptance_sha256': previous}
        retain.kernel.record(self.stage, 'kernel-acceptance-' + self.boot_id + '.json', value)
        atomic_json(self.stage / 'kernel-acceptance-current.json', {
            'boot_id': self.boot_id, 'sha256': retain.rpm.sha(retain.kernel.encode(value))})

    def later_boot(self, current='cccccccc-cccc-cccc-cccc-cccccccccccc'):
        self.next_candidate_boot(current)
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.publish_acceptance()
        atomic_json(self.root / 'manager/os-transaction.json', {
            **self.transaction, 'state': 'complete', 'kernel_retention': 'pending'})

    def prepare_generation(self):
        reference, plan, checksum = generation.prepare(self.stage,
            accepted=lambda stage: retain.acceptance_record(stage), runner=self.runner)
        path = generation.integrity_path(self.stage, reference)
        prepared = updates.prepare(self.manager, self.stage, path)
        self.assertTrue(prepared['ok'])
        self.assertEqual(prepared['plan_sha256'], retain.rpm.sha(path.read_bytes()))
        return reference, plan, checksum, path

    def attempt(self, reference, plan, checksum, path):
        integrity = json.loads(path.read_text())
        _, prepared = updates._prepared(self.manager, self.state, self.identity, self.stage,
                                        integrity, retain.rpm.sha(path.read_bytes()))
        self.write_private(self.stage / retain.INTENT, retain.kernel.encode({
            'schema': 2, 'plan_sha256': checksum, 'generation': reference,
            'authorization': {'ok': True, 'plan_sha256': checksum, 'boot_id': self.boot_id,
                              'backup_sha256': 'f' * 64, 'aide_preparation_sha256': updates.digest(prepared)}}))
        self.retired.unlink()
        self.live_inventory = ['retained-exact']

    def assert_originals(self):
        self.assertEqual((self.stage / retain.PLAN).read_bytes(), self.original_bytes)
        self.assertEqual(self.original_path.read_bytes(), self.original_integrity_bytes)
        self.assertEqual(self.marker.read_bytes(), self.enrollment_bytes)
        self.assertEqual(self.scan_calls.count('init'), 1)

    def compound_boot(self, identity='dddddddd-dddd-dddd-dddd-dddddddddddd'):
        self.next_candidate_boot(identity)
        atomic_json(self.root / 'manager/os-transaction.json', {
            **self.transaction, 'state': 'retention_recovery_required', 'kernel_retention': 'pending'})
        authority = retain.observe_boot_authority(self.stage, runner=self.runner)
        _, observed = boot.plan_retention_resume(self.stage, authority, runner=self.runner)
        authorization = lambda stage, checksum: {
            'ok': True, 'stage': str(stage), 'boot_id': self.boot_id,
            'operation_sha256': boot._operation_sha(stage), 'retention_plan_sha256': checksum,
            'backup_stage': str(stage), 'backup_sha256': 'f' * 64}
        path, plan = retain.prepare_resume(self.stage, authority, boot._plan_reference(observed),
                                            authorize=authorization, runner=self.runner)
        return path, plan

    def finish_generation_compound(self, path, plan):
        updates.prepare(self.manager, self.stage, path)
        updates.accept(self.manager, self.stage, path)
        proof = updates.retained_plan_acceptance(self.stage, path, manager=self.manager)
        value = {'schema': 1, 'status': 'integrity_reconciled',
                 'plan': {'filename': path.name, 'sha256': retain.rpm.sha(path.read_bytes())},
                 'boot_ref': plan['boot_ref'], 'authority_ref': plan['authority_ref'],
                 'boot_id': self.boot_id, 'kernel': native_fixture.NEW,
                 'retention_plan_sha256': plan['retention_plan_sha256'], 'aide': proof,
                 'release_accepted': False}
        name = 'kernel-retention-resume-' + plan['id'] + '-result.json'
        retain.kernel.record(self.stage, name, value)
        result_ref = {'filename': name, 'sha256': retain.rpm.sha(retain.kernel.encode(value))}
        boot.complete_retention_resume(self.stage, plan['boot_ref'], result_ref, runner=self.runner)
        self.assertEqual(boot.accepted_transitions(self.stage, runner=self.runner)['retention_integrity_sha256'],
                         result_ref['sha256'])
        history = updates.accepted_plan_history(manager=self.manager)
        state, unresolved, _ = ordinary._fold(self.initial_snapshot, history['history'], self.identity)
        self.assertEqual(state['inventory'], ['retained-exact'])
        self.assertNotIn(str(self.retired), state['artifacts'])
        self.assertEqual(state['grub']['raw'], base64.b64encode(self.env.read_bytes()).decode())
        self.assertEqual(state['boot_id'], self.boot_id)
        self.assertEqual(unresolved, set())
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assert_originals()

    def interrupted_generation(self, point):
        self.later_boot()
        reference, plan, checksum, path = self.prepare_generation()
        self.attempt(reference, plan, checksum, path)
        intent = (self.stage / retain.INTENT).read_bytes()
        if point == 'scanning':
            def crash(action, *_):
                if action == 'update': raise OSError('generation scan interrupted')
            self.scan_hook = crash
            with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
            self.scan_hook = None
        elif point == 'ready_input':
            with patch.object(updates, '_complete', side_effect=OSError('generation before copy')):
                with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
        elif point == 'ready_output':
            replace = updates._replace_current
            def crash(*args):
                replace(*args)
                raise OSError('generation after copy')
            with patch.object(updates, '_replace_current', side_effect=crash):
                with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
        elif point == 'accepted':
            updates.accept(self.manager, self.stage, path)
        elif point != 'before_accept':
            self.fail('invalid interruption')
        compound_path, compound = self.compound_boot()
        self.assertEqual(compound['retention_plan_sha256'], checksum)
        self.assertEqual(compound['original_integrity_sha256'], retain.rpm.sha(path.read_bytes()))
        self.assertNotEqual(compound['original_integrity_sha256'], retain.rpm.sha(self.original_path.read_bytes()))
        self.finish_generation_compound(compound_path, compound)
        self.assertEqual((self.stage / retain.INTENT).read_bytes(), intent)

    def test_generation_erase_before_aide_acceptance_recovers_on_next_boot(self):
        self.interrupted_generation('before_accept')

    def test_generation_interrupted_scan_recovers_actual_preparation_on_next_boot(self):
        self.interrupted_generation('scanning')

    def test_generation_ready_input_recovers_without_copying_historical_database(self):
        self.interrupted_generation('ready_input')

    def test_generation_ready_output_retains_copied_database_before_new_scan(self):
        self.interrupted_generation('ready_output')

    def test_generation_accepted_erase_is_reduced_once_after_later_compound_boot(self):
        self.interrupted_generation('accepted')

    def test_unattempted_preparation_survives_normal_boot_resume_then_generation_acceptance(self):
        self.later_boot()
        reference, plan, checksum, path = self.prepare_generation()
        self.assertNotEqual(checksum, self.original_sha)
        self.assertEqual(plan['removed'], self.original['removed'])
        self.assertEqual(plan['preserved'][str(self.env)], self.description(self.env))
        self.attempt(reference, plan, checksum, path)
        accepted = updates.accept(self.manager, self.stage, path)
        proof = updates.retained_plan_acceptance(self.stage, path, manager=self.manager)
        self.assertEqual(proof['database_sha256'], accepted['database_sha256'])
        history = updates.accepted_plan_history(manager=self.manager)
        state, unresolved, checkpoint = ordinary._fold(self.initial_snapshot, history['history'], self.identity)
        self.assertEqual(state['inventory'], ['retained-exact'])
        self.assertNotIn(str(self.retired), state['artifacts'])
        self.assertEqual(state['grub']['raw'], base64.b64encode(self.env.read_bytes()).decode())
        self.assertEqual(unresolved, set())
        self.assertTrue(checkpoint)
        self.assert_originals()

    def test_second_boot_before_intent_uses_new_generation_and_retains_unattempted_one(self):
        self.later_boot()
        first, _, _, first_path = self.prepare_generation()
        first_bytes = first_path.read_bytes()
        self.later_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        second, _, _, second_path = self.prepare_generation()
        self.assertNotEqual(first, second)
        self.assertNotEqual(first_path, second_path)
        self.assertEqual(first_path.read_bytes(), first_bytes)
        self.assertEqual(generation.load(self.stage, first, historical=True, runner=self.runner)[0]['boot_id'],
                         'cccccccc-cccc-cccc-cccc-cccccccccccc')
        with self.assertRaisesRegex(Refused, 'current_acceptance'):
            generation.load(self.stage, first, runner=self.runner)
        self.assertFalse((self.stage / retain.INTENT).exists())
        self.assert_originals()

    def test_same_boot_retry_after_generation_database_copy_uses_fresh_check(self):
        self.later_boot()
        reference, plan, checksum, path = self.prepare_generation()
        self.attempt(reference, plan, checksum, path)
        replace = updates._replace_current
        def crash(*args):
            replace(*args)
            raise OSError('copied before publishing head')
        with patch.object(updates, '_replace_current', side_effect=crash):
            with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
        before_updates = self.scan_calls.count('update')
        before_checks = self.scan_calls.count('check')
        updates.accept(self.manager, self.stage, path)
        self.assertEqual(self.scan_calls.count('update'), before_updates)
        self.assertGreater(self.scan_calls.count('check'), before_checks)
        updates.retained_plan_acceptance(self.stage, path, manager=self.manager)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assert_originals()

    def test_rehashed_generation_cannot_claim_an_unpublished_boot_database(self):
        self.later_boot()
        reference, _, _, _ = self.prepare_generation()
        path = self.stage / reference['filename']
        binding = json.loads(path.read_text())
        binding['boot_integrity']['database_sha256'] = '0' * 64
        self.write_private(path, retain.kernel.encode(binding))
        changed = {'filename': path.name, 'sha256': retain.rpm.sha(path.read_bytes())}
        database = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaisesRegex(Refused, 'acceptance_reference'):
            generation.load(self.stage, changed, historical=True, runner=self.runner)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), database)
        self.assertFalse((self.stage / retain.INTENT).exists())
        self.assert_originals()

    def test_unrelated_drift_after_generation_never_becomes_aide_baseline(self):
        self.later_boot()
        reference, plan, checksum, path = self.prepare_generation()
        self.attempt(reference, plan, checksum, path)
        self.unrelated.write_bytes(b'not authorized by the retention generation\n')
        before = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaises(Refused): updates.accept(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assert_originals()

    def test_unowned_absence_without_global_intent_cannot_accept_generation(self):
        self.later_boot()
        _, _, _, path = self.prepare_generation()
        self.retired.unlink()
        self.live_inventory = ['retained-exact']
        before = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaises(Refused): updates.accept(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assertFalse((self.stage / retain.INTENT).exists())
        self.assert_originals()

    def test_generation_intent_must_bind_actual_aide_preparation(self):
        self.later_boot()
        reference, plan, checksum, path = self.prepare_generation()
        self.attempt(reference, plan, checksum, path)
        intent_path = self.stage / retain.INTENT
        intent = json.loads(intent_path.read_text())
        intent['authorization']['aide_preparation_sha256'] = '0' * 64
        self.write_private(intent_path, retain.kernel.encode(intent))
        before = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaisesRegex(Refused, 'attempt_preparation_changed'):
            updates.accept(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assert_originals()

    def test_generation_dispatcher_does_not_accept_foreign_or_traversal_paths(self):
        self.later_boot()
        _, _, _, path = self.prepare_generation()
        for invalid in (path.parent.parent / path.name, path.parent / ('../' + path.name),
                        path.with_name(path.name.replace('-integrity', '-plan'))):
            with self.subTest(path=invalid), self.assertRaises(Refused):
                updates._bound_plan(self.manager, self.stage, invalid, preparing=True)


if __name__ == '__main__':
    __import__('unittest').main()
