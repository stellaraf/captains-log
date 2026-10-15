"""Source tests for orchestration boundaries; no native kernel is erased."""
from contextlib import nullcontext
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import aide, aide_updates, kernel_integrity
from nebulalog_manager import kernel_boot
from nebulalog_manager import kernel_retention_integration as integration
from nebulalog_manager.common import Refused
from test_kernel_retention import headers, projection, VERSIONS, OLDEST, CURRENT, RECOVERY, BOOT, SHA


class Fixtures(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / ('1' * 32)
        self.stage.mkdir(mode=0o700)
        self.patch(integration.rpm, 'read', side_effect=lambda path, *args: Path(path).read_bytes())

    def patch(self, target, name, **kwargs):
        item = patch.object(target, name, **kwargs)
        result = item.start(); self.addCleanup(item.stop)
        return result

    def write(self, path, value):
        Path(path).write_bytes(integration.kernel.encode(value))


class ProvisionalRecoveryTests(Fixtures):
    def setUp(self):
        super().setUp()
        self.manager = Mock()
        self.latest = {'stage': str(self.stage), 'boot_id': BOOT}
        self.journal = {**self.latest, 'state': 'complete', 'kernel_retention': 'pending'}
        self.patch(integration, 'context', side_effect=lambda *args: (None, self.latest, self.journal))
        self.patch(integration, 'owned_directory', side_effect=lambda path, **kw: path)
        self.patch(integration.retain, 'load_historical_plan', return_value=({'operation_sha256': SHA}, 'b' * 64))
        self.patch(integration.retain, 'boot_id', return_value='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')
        self.backup = self.patch(kernel_integrity, 'checked_backup', return_value='c' * 64)
        self.value = {'ok': True, 'stage': str(self.stage), 'boot_id': integration.retain.boot_id(),
                      'backup_stage': str(self.stage), 'backup_sha256': 'c' * 64,
                      'operation_sha256': SHA, 'retention_plan_sha256': 'b' * 64}
        self.authorize = Mock(return_value=self.value)

    def check(self):
        return integration.provisional_authorization(self.stage, 'b' * 64,
                                                       authorize=self.authorize, manager=self.manager)

    def test_original_backup_is_reverified_not_trusted_from_callback(self):
        self.assertEqual(self.check(), self.value)
        self.backup.assert_called_once_with(self.stage)
        self.backup.return_value = 'd' * 64
        with self.assertRaisesRegex(Refused, 'backup_inventory'): self.check()

    def test_wrong_boot_operation_owner_pending_state_or_backup_refuses(self):
        original = copy.deepcopy(self.value)
        for changed in ({'boot_id': BOOT}, {'stage': '/foreign'}, {'ok': False},
                        {'operation_sha256': 'd' * 64}, {'retention_plan_sha256': 'd' * 64},
                        {'backup_stage': str(self.stage.parent / ('2' * 32))}):
            self.authorize.return_value = {**original, **changed}
            with self.subTest(changed=changed), self.assertRaises(Refused): self.check()
        self.authorize.return_value = original
        self.journal['kernel_retention'] = 'complete'
        with self.assertRaisesRegex(Refused, 'operation_changed'): self.check()

    def test_refreshed_backup_requires_exact_immutable_two_journal_intent(self):
        backup = self.root / ('2' * 32); backup.mkdir()
        self.value['backup_stage'] = str(backup)
        self.latest['recovery_backup_stage'] = str(backup)
        self.journal['recovery_backup_stage'] = str(backup)
        intent = {'schema': 1, 'owner_stage': str(self.stage), 'boot_id': BOOT,
                  'previous': str(self.stage), 'backup': str(backup), 'inventory_sha256': 'c' * 64}
        path = self.stage / ('recovery-backup-' + backup.name + '.json'); self.write(path, intent)
        reference = {'filename': path.name, 'sha256': integration.rpm.sha(path.read_bytes())}
        self.write(self.stage / 'recovery-backup-current.json', reference)
        self.assertEqual(self.check(), self.value)
        self.journal['recovery_backup_stage'] = str(self.stage)
        with self.assertRaisesRegex(Refused, 'owner_changed'): self.check()
        self.journal['recovery_backup_stage'] = str(backup)
        intent['owner_stage'] = str(backup); self.write(path, intent)
        reference['sha256'] = integration.rpm.sha(path.read_bytes())
        self.write(self.stage / 'recovery-backup-current.json', reference)
        with self.assertRaisesRegex(Refused, 'intent_changed'): self.check()


class LaterBootOrchestrationTests(Fixtures):
    def setUp(self):
        super().setUp()
        self.manager = Mock()
        self.patch(aide, 'Aide', return_value=self.manager)
        self.patch(integration, 'require_linux_root')
        self.patch(integration, 'context', return_value=(None, {}, {}))
        self.current_boot = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.original = {'acceptance': projection(), 'retained_kernels': VERSIONS[1:]}
        self.patch(integration.retain, 'load_historical_plan', return_value=(self.original, SHA))
        self.patch(integration.retain, 'erase_intent')
        self.authorization = {'ok': True, 'stage': str(self.stage), 'boot_id': self.current_boot,
                              'backup_stage': str(self.stage), 'backup_sha256': '3' * 64,
                              'operation_sha256': '4' * 64, 'retention_plan_sha256': SHA}
        self.checked = self.patch(integration, 'provisional_authorization', return_value=self.authorization)
        self.authority = {'filename': 'observation.json', 'sha256': 'b' * 64}
        self.observer = self.patch(integration.retain, 'observe_boot_authority', return_value=self.authority)
        self.boot_path = self.stage / ('kernel-boot-' + '5' * 32 + '-plan.json')
        self.boot_plan = {'boot_id': self.current_boot}
        self.boot_ref = {'filename': self.boot_path.name, 'sha256': integration.rpm.sha(integration.kernel.encode(self.boot_plan))}
        self.boot_prepare = self.patch(kernel_boot, 'plan_retention_resume', create=True,
                                       return_value=(self.boot_path, self.boot_plan))
        self.plan = {'id': '6' * 32, 'boot_id': self.current_boot, 'authorization': self.authorization}
        self.path = self.stage / ('kernel-retention-resume-' + self.plan['id'] + '-plan.json')
        self.write(self.path, self.plan)
        self.plan_ref = {'filename': self.path.name, 'sha256': integration.rpm.sha(self.path.read_bytes())}
        self.patch(integration.retain, 'prepare_resume', return_value=(self.path, self.plan))
        self.patch(integration.retain, 'load_resume', return_value=(self.plan, self.plan_ref['sha256']))
        self.complete_validator = self.patch(integration.retain, 'validate_boot_completion')
        self.boot_complete = self.patch(kernel_boot, 'complete_retention_resume', create=True,
                                        return_value={'outcome': 'candidate'})
        self.proof = {'entry': {'id': '7', 'sha256': '7' * 64}, 'original_enrollment_sha256': '8' * 64,
                      'plan_sha256': self.plan_ref['sha256'], 'prepared_sha256': '9' * 64, 'database_sha256': 'd' * 64}
        self.prove = self.patch(aide_updates, 'retained_plan_acceptance', create=True, return_value=self.proof)
        self.manager.authorized_update_prepare.return_value = {'ok': True, 'plan_sha256': self.plan_ref['sha256']}
        self.manager.authorized_update_accept.return_value = {'ok': True, 'direction': 'forward',
            'plan_sha256': self.plan_ref['sha256'], 'database_sha256': self.proof['database_sha256']}
        self.events = []
        self.records = {}
        def record(stage, name, value):
            if name in self.records and self.records[name] != value: raise Refused('immutable changed')
            self.events.append(name); self.records[name] = copy.deepcopy(value); self.write(stage / name, value)
        self.patch(integration.kernel, 'record', side_effect=record)
        self.runner = Mock(side_effect=AssertionError('Recovery must not execute an RPM command'))
        self.authorize = Mock()

    def recover(self):
        return integration.recover_later_boot(self.stage, authorize=self.authorize, runner=self.runner)

    def test_aide_acceptance_precedes_boot_result_and_never_claims_final_acceptance(self):
        def boot_complete(*args, **kw):
            self.manager.authorized_update_accept.assert_called_once()
            self.prove.assert_called_once()
            self.assertTrue(any(name.endswith('-result.json') for name in self.events))
            return {'outcome': 'candidate'}
        self.boot_complete.side_effect = boot_complete
        result = self.recover()
        self.assertFalse(result['release_accepted'])
        self.assertEqual(result['status'], 'integrity_reconciled')
        self.assertNotIn(integration.COMPLETE, self.records)
        self.runner.assert_not_called()

    def test_ambiguous_or_partial_erasure_never_reaches_aide_or_boot_planning(self):
        self.observer.side_effect = Refused('partial_erase')
        with self.assertRaisesRegex(Refused, 'partial_erase'): self.recover()
        self.boot_prepare.assert_not_called()
        self.manager.authorized_update_prepare.assert_not_called()
        self.boot_complete.assert_not_called()
        self.runner.assert_not_called()

    def test_rejected_or_unpublished_aide_result_keeps_evidence_without_boot_acceptance(self):
        self.manager.authorized_update_accept.return_value['ok'] = False
        with self.assertRaisesRegex(Refused, 'compound_acceptance'): self.recover()
        self.boot_complete.assert_not_called()
        self.assertTrue(any(name.endswith('-intent.json') for name in self.events))
        self.assertFalse(any(name.endswith('-result.json') for name in self.events))
        self.manager.authorized_update_accept.return_value['ok'] = True
        self.prove.side_effect = Refused('no published chain')
        with self.assertRaisesRegex(Refused, 'published chain'): self.recover()
        self.boot_complete.assert_not_called()

    def test_retry_with_new_backup_keeps_original_plan_intent_and_result(self):
        first = self.recover()
        original = copy.deepcopy(self.records)
        self.checked.return_value = {**self.authorization, 'backup_sha256': 'f' * 64}
        second = self.recover()
        self.assertEqual(first, second)
        for name, value in original.items(): self.assertEqual(self.records[name], value)
        self.assertEqual(len([name for name in self.records if '-authorization-' in name]), 2)
        self.runner.assert_not_called()

    def test_final_completion_requires_fresh_acceptance_bound_to_this_compound_result(self):
        result = self.recover()
        approved = {**projection(), 'boot_id': self.current_boot}
        self.patch(integration.retain, 'acceptance', return_value=approved)
        value = {'retention_integrity_sha256': result['compound_ref']['sha256']}
        self.patch(integration.kernel, 'read_acceptance', return_value=(value, approved['receipt_sha256'], 'generation.json'))
        completion = integration.finish_later_boot(self.stage, result['compound_ref'], accepted=Mock(), runner=self.runner)
        self.assertEqual(completion['status'], 'complete')
        self.assertEqual(completion['retained_kernels'], VERSIONS[1:])
        value['retention_integrity_sha256'] = None
        with self.assertRaisesRegex(Refused, 'final_acceptance'):
            integration.finish_later_boot(self.stage, result['compound_ref'], accepted=Mock(), runner=self.runner)



class InventoryTests(unittest.TestCase):
    def test_two_three_or_four_complete_sets_preserve_current_and_recovery(self):
        for versions in (VERSIONS[-2:], VERSIONS[-3:], VERSIONS):
            self.assertEqual(integration.complete_sets(headers(versions), projection()), versions)

    def test_small_inventory_still_requires_complete_accepted_recovery(self):
        invalid = (headers(VERSIONS[:2]), headers(VERSIONS[-2:])[:-1], headers(VERSIONS[-1:]),
                   headers(VERSIONS[-2:]) + headers(VERSIONS[-2:])[:1])
        for value in invalid:
            with self.subTest(count=len(value)), self.assertRaises(Refused):
                integration.complete_sets(value, projection())


class ProvenanceTests(Fixtures):
    def setUp(self):
        super().setUp()
        self.patch(integration, 'owned_directory', side_effect=lambda path, **kwargs: Path(path))
        self.patch(integration, 'owned_stage', return_value={})
        self.factory = self.root / 'factory' / 'manifest.json'
        self.factory.parent.mkdir()
        self.patch(integration, 'FACTORY', new=self.factory)
        self.items = []
        for name in sorted(integration.kernel.NAMES):
            raw = name.encode()
            checksum = integration.rpm.sha(raw)
            self.items.append({'name': name, 'nevra': name + '-0:' + OLDEST,
                               'rpm': checksum + '.rpm', 'sha256': checksum, 'bytes': len(raw)})
            (self.factory.parent / (checksum + '.rpm')).write_bytes(raw)
        self.value = {'schema': 1, 'kernel': OLDEST, 'packages': self.items}
        self.write(self.factory, self.value)
        self.runner = Mock(side_effect=lambda argv, **kwargs: Path(argv[-1]).read_text())
        self.patch(integration.rpm, 'headers', side_effect=lambda name: [{'name': name}])
        self.patch(integration.kernel, 'payload', side_effect=lambda h: {
            'name': h['name'], 'nevra': h['name'] + '-0:' + OLDEST, 'kernel': OLDEST})

    def test_factory_exact_four_sha_named_packages(self):
        paths = integration.retained_packages(self.stage, OLDEST, runner=self.runner)
        self.assertEqual(paths, [self.factory.parent / p['rpm'] for p in self.items])
        self.assertEqual(self.runner.call_count, 4)

    def test_missing_factory_is_refused_without_network_or_erase(self):
        self.factory.unlink()
        with self.assertRaisesRegex(Refused, 'provenance_required'):
            integration.retained_packages(self.stage, OLDEST, runner=self.runner)
        self.runner.assert_not_called()

    def test_factory_manifest_exact_shape_and_kernel_are_mandatory(self):
        for change in ({'kernel': CURRENT}, {'packages': None}, {'packages': self.items[:3]},
                       {'schema': True}, {'unrecognized': 'field'}):
            self.write(self.factory, {**self.value, **change})
            with self.subTest(change=change), self.assertRaises(Refused):
                integration.retained_packages(self.stage, OLDEST, runner=self.runner)

    def test_package_path_escape_hash_size_duplicate_and_header_mismatch_refused(self):
        for changes in ({'rpm': '../escape.rpm'}, {'sha256': SHA}, {'bytes': 999},
                        {'nevra': 'kernel-0:' + CURRENT}, {'name': self.items[1]['name']}):
            items = copy.deepcopy(self.items); items[0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(Refused):
                integration.package_paths(self.factory.parent, items, OLDEST, runner=self.runner)
        integration.kernel.payload.return_value = None
        integration.kernel.payload.side_effect = lambda h: {'name': h['name'], 'nevra': h['name'] + '-0:' + CURRENT, 'kernel': CURRENT}
        with self.assertRaisesRegex(Refused, 'header_changed'):
            integration.retained_packages(self.stage, OLDEST, runner=self.runner)

    def test_prior_owned_stage_is_preferred_and_retains_exact_package_path(self):
        prior = self.root / ('2' * 32); prior.mkdir()
        (prior / 'kernel-plan.json').touch()
        load = self.patch(integration.kernel, 'load_plan', return_value=({'kernel': OLDEST, 'packages': self.items}, SHA))
        paths = self.patch(integration, 'package_paths', return_value=['retained'])
        self.assertEqual(integration.retained_packages(self.stage, OLDEST, runner=self.runner), ['retained'])
        load.assert_called_once_with(prior)
        paths.assert_called_once_with(prior / 'kernel-packages', self.items, OLDEST, runner=self.runner)

    def test_bounded_scan_does_not_accept_symlink_or_unowned_stage(self):
        (self.root / ('2' * 32)).symlink_to(self.factory.parent, target_is_directory=True)
        (self.factory.parent / 'kernel-plan.json').touch()
        integration.owned_stage.side_effect = lambda path, parent: (_ for _ in ()).throw(Refused('unsafe')) if path.is_symlink() else {}
        with self.assertRaisesRegex(Refused, 'unsafe'):
            integration.retained_packages(self.stage, OLDEST, runner=self.runner)
        integration.owned_stage.side_effect = None
        self.patch(integration, 'MAX_STAGES', new=1)
        with self.assertRaisesRegex(Refused, 'stage_limit'):
            integration.retained_packages(self.stage, OLDEST, runner=self.runner)


class StageTests(Fixtures):
    def setUp(self):
        super().setUp()
        self.patch(integration, 'owned_directory', side_effect=lambda path, **kwargs: Path(path))
        self.value = {'schema': 1, 'id': BOOT, 'boot_id': BOOT, 'stage': str(self.stage)}
        self.write(self.stage / 'operation.json', self.value)

    def test_real_operation_identity_is_required(self):
        self.assertEqual(integration.owned_stage(self.stage, self.root), self.value)
        for changed in ({'id': 'invalid'}, {'stage': '/another'}, {'schema': True}):
            self.write(self.stage / 'operation.json', {**self.value, **changed})
            with self.subTest(changed=changed), self.assertRaises(Refused):
                integration.owned_stage(self.stage, self.root)
        with self.assertRaises(Refused): integration.owned_stage(self.stage, self.root / 'other')


class OrchestrationTests(Fixtures):
    def setUp(self):
        super().setUp()
        self.patch(integration, 'require_linux_root')
        self.manager = Mock()
        self.patch(aide, 'Aide', return_value=self.manager)
        self.patch(integration, 'context', return_value=(None, {}, {}))
        self.approved = projection()
        self.patch(integration.retain, 'acceptance', return_value=self.approved)
        self.installed = headers()
        self.inventory = self.patch(integration.rpm, 'inventory', side_effect=lambda runner: ('xml', self.installed, ['before'] if len(self.installed) == 16 else ['after']))
        self.provenance = self.patch(integration, 'retained_packages', return_value=['signed-rpm'] * 4)
        self.plan = {'boot_id': BOOT, 'acceptance': self.approved, 'after_inventory': ['after'], 'retained_kernels': VERSIONS[1:]}
        self.patch(integration.retain, 'load_plan', return_value=(self.plan, SHA))
        self.patch(integration.retain, 'load_historical_plan', return_value=(self.plan, SHA))
        self.plan_cached = self.patch(integration.retain, 'plan_cached', side_effect=self.make_plan)
        self.execute = self.patch(integration.retain, 'execute_cached', side_effect=self.erase)
        self.recover = self.patch(integration.retain, 'recover_cached', side_effect=self.observe)
        self.verify = self.patch(integration.retain, 'verify_files')
        self.records = {}
        def record(stage, name, value):
            if name in self.records and self.records[name] != value:
                raise Refused('retained_evidence_changed')
            self.records[name] = value
            self.write(stage / name, value)
        self.patch(integration.kernel, 'record', side_effect=record)
        self.integrity_sha = integration.rpm.sha(b'integrity')
        self.manager.authorized_update_prepare.return_value = {'ok': True, 'plan_sha256': self.integrity_sha}
        self.manager.authorized_update_accept.return_value = {'ok': True, 'direction': 'forward',
            'plan_sha256': self.integrity_sha, 'database_sha256': 'd' * 64, 'baseline_changed': True}
        self.callback = Mock()
        self.runner = Mock()

    def make_plan(self, *args, **kwargs):
        (self.stage / integration.retain.PLAN).write_bytes(b'plan')
        (self.stage / integration.retain.INTEGRITY).write_bytes(b'integrity')

    def observe(self, *args, **kwargs):
        value = {'status': 'erased_pending_integrity', 'plan_sha256': SHA}
        self.write(self.stage / integration.retain.RESULT, value)
        return value

    def erase(self, *args, **kwargs):
        self.write(self.stage / integration.retain.INTENT, {'schema': 1, 'plan_sha256': SHA, 'authorization': {}})
        self.installed = headers(VERSIONS[1:])
        return self.observe()

    def run_retention(self):
        return integration.retain_three(self.stage, accepted=self.callback, runner=self.runner)

    def test_prepare_single_erase_accept_and_complete_are_ordered(self):
        result = self.run_retention()
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['retained_kernels'], VERSIONS[1:])
        self.assertEqual(self.execute.call_count, 1)
        self.recover.assert_not_called()
        self.manager.authorized_update_prepare.assert_called_once()
        self.manager.authorized_update_accept.assert_called_once()
        self.assertIn(integration.REQUIRED, self.records)
        self.assertIn(integration.COMPLETE, self.records)
        self.assertNotIn('baseline_changed', self.records[integration.COMPLETE])

    def test_missing_provenance_keeps_required_evidence_without_prepare_or_erase(self):
        self.provenance.side_effect = Refused('signed_provenance_missing')
        with self.assertRaisesRegex(Refused, 'signed_provenance_missing'): self.run_retention()
        self.assertIn(integration.REQUIRED, self.records)
        self.execute.assert_not_called()
        self.manager.authorized_update_prepare.assert_not_called()

    def test_three_complete_sets_no_prune_but_missing_recovery_refuses(self):
        self.installed = headers(VERSIONS[1:])
        self.assertEqual(self.run_retention()['status'], 'not_required')
        self.installed = headers([OLDEST, CURRENT])
        with self.assertRaisesRegex(Refused, 'recovery_kernel_missing'): self.run_retention()
        self.execute.assert_not_called()

    def test_existing_intent_with_three_sets_recovers_without_replaying_erase(self):
        self.make_plan(); self.erase()
        self.execute.reset_mock()
        self.assertEqual(self.run_retention()['status'], 'complete')
        self.execute.assert_not_called()
        self.provenance.assert_not_called()
        self.manager.authorized_update_prepare.assert_not_called()
        self.recover.assert_called_once()

    def test_interrupted_erase_refuses_complete_until_actual_inventory_proven(self):
        self.make_plan()
        self.write(self.stage / integration.retain.INTENT, {'schema': 1, 'plan_sha256': SHA, 'authorization': {}})
        self.recover.side_effect = Refused('partial_erase_requires_recovery')
        with self.assertRaisesRegex(Refused, 'partial_erase'): self.run_retention()
        self.execute.assert_not_called()
        self.manager.authorized_update_accept.assert_not_called()
        self.assertNotIn(integration.COMPLETE, self.records)

    def test_aide_rejection_keeps_intent_and_never_marks_complete(self):
        self.manager.authorized_update_accept.return_value['ok'] = False
        with self.assertRaisesRegex(Refused, 'integrity_acceptance_failed'): self.run_retention()
        self.assertTrue((self.stage / integration.retain.INTENT).exists())
        self.assertNotIn(integration.COMPLETE, self.records)

    def test_completed_retry_reverifies_without_erase_and_uses_stable_receipt(self):
        first = self.run_retention()
        self.manager.authorized_update_accept.return_value['baseline_changed'] = False
        second = self.run_retention()
        self.assertEqual(first, second)
        self.assertEqual(self.execute.call_count, 1)
        self.assertEqual(self.recover.call_count, 1)
        self.assertEqual(self.manager.authorized_update_accept.call_count, 2)

    def test_preparation_wrong_plan_or_orphan_intent_refuses(self):
        self.manager.authorized_update_prepare.return_value['plan_sha256'] = 'e' * 64
        with self.assertRaisesRegex(Refused, 'preparation_failed'): self.run_retention()
        self.execute.assert_not_called()
        (self.stage / integration.retain.PLAN).unlink()
        (self.stage / integration.retain.INTENT).touch()
        with self.assertRaisesRegex(Refused, 'plan_missing'): self.run_retention()

    def test_crash_between_plan_and_integrity_write_reconstructs_exact_projection(self):
        self.make_plan()
        (self.stage / integration.retain.INTEGRITY).unlink()
        projected = {'exact': 'retained-plan-projection'}
        self.patch(integration.retain, 'integrity_plan', return_value=projected)
        checksum = integration.rpm.sha(integration.kernel.encode(projected))
        self.manager.authorized_update_prepare.return_value['plan_sha256'] = checksum
        self.manager.authorized_update_accept.return_value['plan_sha256'] = checksum
        self.assertEqual(self.run_retention()['status'], 'complete')
        self.assertEqual(self.records[integration.retain.INTEGRITY], projected)
        self.plan_cached.assert_not_called()


class AuthorizationTests(Fixtures):
    def setUp(self):
        super().setUp()
        self.manager = Mock()
        self.identity = SimpleNamespace(root=self.root)
        self.patch(aide_updates, '_locked', side_effect=lambda manager: nullcontext((self.root, self.identity)))
        self.latest, self.journal = {}, {}
        self.patch(integration, 'context', return_value=(self.identity, self.latest, self.journal))
        self.integrity = {'manifest_sha256': SHA}
        self.patch(integration.retain, 'bound_integrity_plan', return_value=(self.integrity, 'c' * 64))
        self.patch(integration.retain, 'boot_id', return_value=BOOT)
        self.base = {'baseline': 'original'}
        self.manager._initial_enrollment.return_value = self.base
        self.prepared = {'original_enrollment_sha256': integration.digest(self.base),
                         'database_sha256': 'd' * 64, 'metadata': {'exact': 'preimage'}}
        self.patch(aide_updates, '_prepared', return_value=(self.root, self.prepared))
        self.patch(aide_updates, 'active_enrollment', return_value={'database_sha256': 'd' * 64})
        self.snapshot = self.patch(integration.retain, 'integrity_snapshot')
        self.backup = self.patch(kernel_integrity, 'checked_backup', return_value='e' * 64)

    def test_backup_and_aide_preparation_are_independently_verified(self):
        result = integration.authorization(self.stage, SHA, manager=self.manager)
        self.assertEqual(result, {'ok': True, 'plan_sha256': SHA, 'backup_sha256': 'e' * 64,
                                 'aide_preparation_sha256': integration.digest(self.prepared), 'boot_id': BOOT})
        self.backup.assert_called_once_with(self.stage)
        self.snapshot.assert_called_once_with(self.manager, self.integrity, 'prepare', self.prepared['metadata'])

    def test_recovery_requires_original_preparation_and_fresh_backup_but_not_preimage_files(self):
        integration.authorization(self.stage, SHA, manager=self.manager, recovery=True)
        self.backup.assert_called_once()
        self.snapshot.assert_not_called()
        self.prepared['original_enrollment_sha256'] = 'f' * 64
        with self.assertRaisesRegex(Refused, 'aide_preparation_required'):
            integration.authorization(self.stage, SHA, manager=self.manager, recovery=True)

    def test_drifted_database_bad_backup_and_unbound_backup_path_refused(self):
        aide_updates.active_enrollment.return_value['database_sha256'] = 'f' * 64
        with self.assertRaisesRegex(Refused, 'database_changed'):
            integration.authorization(self.stage, SHA, manager=self.manager)
        self.backup.side_effect = Refused('stale_backup')
        with self.assertRaisesRegex(Refused, 'stale_backup'):
            integration.authorization(self.stage, SHA, manager=self.manager, recovery=True)

    def test_bound_refreshed_same_parent_backup_is_reverified(self):
        backup = self.root / ('2' * 32)
        self.latest['recovery_backup_stage'] = self.journal['recovery_backup_stage'] = str(backup)
        owned = self.patch(integration, 'owned_directory', return_value=backup)
        integration.authorization(self.stage, SHA, manager=self.manager, recovery=True)
        owned.assert_called_once_with(backup, private=True)
        self.backup.assert_called_once_with(backup)
        self.latest['recovery_backup_stage'] = '/arbitrary'
        with self.assertRaisesRegex(Refused, 'backup_stage_changed'):
            integration.authorization(self.stage, SHA, manager=self.manager, recovery=True)


if __name__ == '__main__':
    unittest.main()
