"""Canceled reboot rearm with actual AIDE preparation, chain and CAS.

Signed host provenance, boot state and scanner process use private fixtures;
the typed boot validators and acceptance history are not mocked.
"""
import copy
import json
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import aide_updates as updates, boot_metadata_lineage as lineage
from nebulalog_manager import kernel_boot as boot, kernel_integrity
from nebulalog_manager.common import Refused
from test_kernel_boot import OLD, NEW, MACHINE, ORIGINAL_BOOT, NEW_BOOT, block
import test_kernel_boot_aide as aide_fixture
import test_boot_metadata_aide as metadata_fixture


class RearmAideTests(TestCase):
    for _name, _method in aide_fixture.KernelAideIntegrationTests.__dict__.items():
        if callable(_method) and not _name.startswith('test_') and _name != 'setUp':
            locals()[_name] = _method

    def setUp(self):
        aide_fixture.KernelAideIntegrationTests.setUp(self)
        self.install_authorization_boundary()

    def install_authorization_boundary(self):
        for context in (patch.object(updates.aide, 'Aide', return_value=self.manager),
                        patch.object(kernel_integrity, 'checked_backup', return_value='b' * 64)):
            context.start(); self.addCleanup(context.stop)

    def authorize(self, stage):
        self.assertEqual(stage, self.stage)
        return {'ok': True, 'stage': str(stage), 'boot_id': self.boot_id, 'kernel': OLD,
                'checks': {name: True for name in boot.REQUIRED_CHECKS},
                'backup_stage': str(stage), 'backup_sha256': 'b' * 64}

    def canceled(self):
        self.call(boot.arm_candidate)
        self.call(boot.abort_candidate)
        self.originals = {path.name: path.read_bytes() for path in self.stage.glob('kernel-boot-*') if path.is_file()}
        self.abort_ref = boot._plan_reference(boot._current(self.stage)[1])
        return self.env.read_bytes()

    def test_same_operation_rearm_preserves_abort_then_accepts_candidate_boot(self):
        self.canceled()
        result = self.call(boot.rearm_candidate, authorize=self.authorize)
        self.assertEqual((result['status'], result['phase'], result['boot_id']), ('rearmed', 'rearm', ORIGINAL_BOOT))
        plan = boot._current(self.stage)[1]
        self.assertEqual(plan['abort_proof']['boot_ref'], self.abort_ref)
        for name, raw in self.originals.items():
            if name != 'kernel-boot-current.json':
                self.assertEqual((self.stage / name).read_bytes(), raw)
        self.assertEqual(boot.parse_environment(self.env.read_bytes())['next_entry'], MACHINE + '-' + NEW)
        self.new_boot()
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.assertEqual(boot.accepted_transitions(self.stage, runner=self.runner)['boot_id'], NEW_BOOT)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_normal_arm_remains_forbidden_after_abort(self):
        before = self.canceled()
        with self.assertRaisesRegex(Refused, 'unarmed_recovery_kernel'):
            self.call(boot.arm_candidate)
        self.assertEqual(self.env.read_bytes(), before)

    def test_actual_fallback_retry_and_rollback_reservations_refuse_rearm(self):
        before = self.canceled()
        for name in (boot.FALLBACK, boot.RETRY_RESERVATION, 'kernel-rollback-owner.json'):
            path = self.stage / name
            path.write_text('{}')
            with self.subTest(name=name), self.assertRaisesRegex(Refused, 'original_unattempted_boot'):
                self.call(boot.rearm_candidate, authorize=self.authorize)
            self.assertEqual(self.env.read_bytes(), before)
            path.unlink()

    def test_foreign_boot_cannot_rearm_old_abort(self):
        before = self.canceled()
        self.boot_id = NEW_BOOT
        with self.assertRaises(Refused):
            self.call(boot.rearm_candidate, authorize=self.authorize)
        self.assertEqual(self.env.read_bytes(), before)

    def test_incomplete_health_or_changed_backup_cannot_publish_rearm(self):
        before = self.canceled()
        pointer = (self.stage / 'kernel-boot-current.json').read_bytes()
        for changed in ({'checks': {}}, {'backup_sha256': 'c' * 64}, {'stage': '/another-operation'}):
            with self.subTest(changed=changed), self.assertRaises(Refused):
                self.call(boot.rearm_candidate, authorize=lambda stage: {**self.authorize(stage), **changed})
            self.assertEqual((self.stage / 'kernel-boot-current.json').read_bytes(), pointer)
            self.assertEqual(self.env.read_bytes(), before)

    def test_unprepared_rearm_abort_never_creates_one_shot(self):
        before = self.canceled()
        self.prepare.side_effect = OSError('preparation interruption')
        with self.assertRaises(OSError):
            self.call(boot.rearm_candidate, authorize=self.authorize)
        plan = boot._current(self.stage)[1]
        self.assertEqual(plan['phase'], 'rearm')
        self.assertEqual(self.env.read_bytes(), before)
        self.assertFalse((self.stage / ('kernel-boot-' + plan['id'] + '-intent.json')).exists())
        result = self.call(boot.abort_candidate)
        self.assertEqual(result['phase'], 'rearm_cancelled')
        self.assertEqual(self.env.read_bytes(), before)
        self.assertEqual(boot._plan_reference(boot._current(self.stage)[1]), self.abort_ref)
        self.assertTrue((self.stage / ('kernel-boot-' + plan['id'] + '-cancelled.json')).exists())

    def test_failed_rearm_acceptance_aborts_owned_intent_and_exact_bytes(self):
        before = self.canceled()
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError('scan interruption')) if action == 'update' else None
        with self.assertRaises(OSError):
            self.call(boot.rearm_candidate, authorize=self.authorize)
        self.scan_hook = None
        self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), before)
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_cancellation_pointer_crash_never_reuses_canceled_generation(self):
        before = self.canceled()
        self.prepare.side_effect = OSError('before intent')
        with self.assertRaises(OSError):
            self.call(boot.rearm_candidate, authorize=self.authorize)
        cancelled = boot._current(self.stage)[1]
        publish = boot.atomic_json
        def crash(path, value):
            if path == self.stage / 'kernel-boot-current.json':
                raise OSError('pointer publication interrupted')
            return publish(path, value)
        with patch.object(boot, 'atomic_json', side_effect=crash), self.assertRaises(OSError):
            self.call(boot.abort_candidate)
        self.assertEqual(self.env.read_bytes(), before)
        self.prepare.side_effect = lambda stage, path: updates.prepare(self.manager, stage, path)
        self.call(boot.rearm_candidate, authorize=self.authorize)
        self.assertNotEqual(boot._current(self.stage)[1]['id'], cancelled['id'])
        self.assertFalse((self.stage / ('kernel-boot-' + cancelled['id'] + '-intent.json')).exists())

    def test_interrupted_rearm_scan_then_candidate_boot_uses_exact_preparation(self):
        self.canceled()
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError('scan interruption')) if action == 'update' else None
        with self.assertRaises(OSError):
            self.call(boot.rearm_candidate, authorize=self.authorize)
        plan = boot._current(self.stage)[1]
        self.scan_hook = None
        self.new_boot()
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.assertFalse(boot._result_path(self.stage, plan).exists())
        self.assertEqual(self.manager.check()['state'], 'clean')

    def test_copied_rearm_database_then_boot_retains_exact_historical_entry(self):
        self.canceled()
        replace = updates._replace_current
        def crash(*args):
            replace(*args)
            raise OSError('power loss after database copy')
        with patch.object(updates, '_replace_current', side_effect=crash), self.assertRaises(OSError):
            self.call(boot.rearm_candidate, authorize=self.authorize)
        plan = boot._current(self.stage)[1]
        self.new_boot()
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.assertFalse(boot._result_path(self.stage, plan).exists())
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_real_fallback_after_rearm_still_has_only_one_explicit_retry(self):
        self.canceled()
        self.call(boot.rearm_candidate, authorize=self.authorize)
        self.new_boot(candidate=False)
        self.call(boot.verify_postboot)
        self.assertEqual(boot.verified_recovery(self.stage, runner=self.runner)['attempts'], 1)
        self.assertEqual(self.call(boot.retry_candidate, authorize=self.authorize)['attempt'], 2)
        self.call(boot.abort_candidate)
        with self.assertRaises(Refused):
            self.call(boot.rearm_candidate, authorize=self.authorize)

    def test_tampered_abort_integrity_proof_cannot_validate(self):
        self.canceled()
        self.call(boot.rearm_candidate, authorize=self.authorize)
        path, plan = boot._current(self.stage)
        forged = copy.deepcopy(plan)
        forged['abort_proof']['result_sha256'] = 'f' * 64
        forged['manifest_sha256'] = boot.digest({k: v for k, v in forged.items() if k != 'manifest_sha256'})
        with self.assertRaisesRegex(Refused, 'abort_proof_changed'):
            boot._validate_plan(self.stage, forged, self.stage, self.candidate, plan['candidate_plan_sha256'],
                self.installed, plan['installed_sha256'], self.transaction, runner=self.runner)

    def test_eight_canceled_generations_are_bounded_and_original_remains_immutable(self):
        before = self.canceled()
        for _ in range(boot.MAX_REARMS):
            self.call(boot.rearm_candidate, authorize=self.authorize)
            self.call(boot.abort_candidate)
        with self.assertRaisesRegex(Refused, 'rearm_limit'):
            self.call(boot.rearm_candidate, authorize=self.authorize)
        self.assertEqual(self.env.read_bytes(), before)
        for name, raw in self.originals.items():
            if name != 'kernel-boot-current.json': self.assertEqual((self.stage / name).read_bytes(), raw)


class RearmMetadataAideTests(TestCase):
    for _name, _method in metadata_fixture.KernelMetadataAideTests.__dict__.items():
        if (callable(_method) or isinstance(_method, (staticmethod, classmethod))) and not _name.startswith('test_'):
            locals()[_name] = _method
    for _name in ('install_authorization_boundary', 'authorize', 'canceled',
                  'test_same_operation_rearm_preserves_abort_then_accepts_candidate_boot',
                  'test_copied_rearm_database_then_boot_retains_exact_historical_entry'):
        locals()[_name] = RearmAideTests.__dict__[_name]

    def setUp(self):
        metadata_fixture.KernelMetadataAideTests.setUp(self)
        self.install_authorization_boundary()

    def test_pure_lineage_binds_rearm_to_original_boot_and_exact_abort(self):
        self.canceled()
        self.call(boot.rearm_candidate, authorize=self.authorize)
        path, plan = boot._current(self.stage)
        checksum = boot.rpm.sha(path.read_bytes())
        evidence = lineage.capture(self.manager, self.stage, path, plan, checksum)
        self.assertEqual(lineage.validate(evidence, plan, checksum, ORIGINAL_BOOT, ORIGINAL_BOOT), evidence)
        with self.assertRaises(Refused):
            lineage.validate(evidence, plan, checksum, NEW_BOOT, ORIGINAL_BOOT)
