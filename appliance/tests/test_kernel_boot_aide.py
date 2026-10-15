"""Actual boot plans and AIDE chain with private host/scanner fixtures.

No boot dispatcher, plan validator, snapshot, phase policy or retained database
chain method is mocked. Native host identity/renderer/scanner inputs are injected;
this does not establish native GRUB, FIPS or encrypted appliance boot acceptance.
"""
import copy
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from nebulalog_manager import aide_updates as updates, host_payload
from nebulalog_manager import kernel_boot as boot, kernel_retention as retention
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.host_job_storage import digest
import test_aide_lifecycle as aide_fixture
import test_aide_updates as authorized_fixture
import test_kernel_boot as boot_fixture


class KernelAideIntegrationTests(TestCase):
    for _name in ('write_private', 'reader', 'facts', 'monitor', 'fresh', 'run_fixture', 'enrolled'):
        locals()[_name] = getattr(aide_fixture.AideLifecycleTests, _name)
    for _name in ('trusted_tree', 'desc', 'snapshot_files', 'scan_runner'):
        locals()[_name] = getattr(authorized_fixture.AuthorizedAideTests, _name)
    for _name in ('description', 'read_private', 'runner', 'new_boot', 'health', 'next_candidate_boot', 'call', 'integrity_callback', 'observe_retention'):
        locals()[_name] = getattr(boot_fixture.BootTransactionTests, _name)

    def setUp(self):
        # Initialize the independently tested host fixture, then construct the
        # AIDE storage identity over that same private root before enrollment.
        boot_fixture.BootTransactionTests.setUp(self)
        old_stage = self.stage
        self.stage = old_stage.with_name('1' * 32)
        old_stage.rename(self.stage)
        self.stage.chmod(0o700)
        self.stage.parent.chmod(0o700)
        atomic_json(self.stage / 'operation.json', {'id': self.stage.name, 'boot_id': self.boot_id})
        self.transaction.update(stage=str(self.stage))
        atomic_json(self.root / 'manager/os-transaction.json', self.transaction)
        atomic_json(self.root / 'manager/os-latest.json', {'stage': str(self.stage), 'boot_id': self.boot_id})
        atomic_json(self.root / 'manager/maintenance.json', {'active': True, 'release': str(self.stage)})
        temporary_root, stage, environment = self.root, self.stage, self.env
        aide_fixture.AideLifecycleTests.setUp(self)
        self.root, self.stage, self.env = temporary_root, stage, environment
        (self.root / 'manager').chmod(0o700)
        from nebulalog_manager.host_job_storage import StorageIdentity
        self.identity = StorageIdentity(aide_fixture.INSTALLATION, self.root, self.root.stat().st_dev)
        self.state = self.root / 'manager/aide'
        self.marker = self.root / 'manager/aide-enrollment.json'
        self.policy = self.root / 'policy.conf'
        self.write_private(self.policy, aide_fixture.POLICY.encode())
        self.manager = self.fresh()
        self.manager.runner = self.scan_runner
        self.unrelated = self.root / 'unrelated.conf'
        self.write_private(self.unrelated, b'protected unrelated file\n')
        self.retired = self.root / 'retired-kernel-file'
        self.write_private(self.retired, b'old signed vendor payload fixture\n')
        self.monitored = [self.env, self.unrelated, self.retired]
        self.scan_calls, self.scan_hook = [], None
        self.metadata = {'xattrs_sha256': self.metadata_hash, 'acl_sha256': 'd' * 64, 'selinux_sha256': 'e' * 64}
        for context in (patch.object(updates, '_metadata', side_effect=lambda path: copy.deepcopy(self.metadata)),
                        patch.object(host_payload, '_trusted_tree', side_effect=self.trusted_tree),
                        patch.object(boot, 'run', side_effect=self.runner)):
            context.start()
            self.addCleanup(context.stop)
        measure = updates._measure
        def host_measure(manager, item, **kwargs):
            description, metadata = measure(manager, item, **kwargs)
            # The private fixture belongs to the test user; emulate only native
            # root ownership after measuring real current bytes and metadata.
            return {**description, 'uid': 0, 'gid': 0}, metadata
        context = patch.object(updates, '_measure', side_effect=host_measure)
        context.start()
        self.addCleanup(context.stop)
        _, self.base = self.enrolled()
        self.initial_db = (self.state / 'aide.db.gz').read_bytes()
        self.prepare = Mock(side_effect=lambda stage, path: updates.prepare(self.manager, stage, path))
        self.accept = Mock(side_effect=lambda stage, path: updates.accept(self.manager, stage, path))

    def retention_origin(self):
        """Inject signed host provenance; keep all compound/AIDE logic real."""
        self.call(boot.arm_candidate)
        self.new_boot()
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.initial_acceptance = boot.accepted_transitions(self.stage, runner=self.runner)
        self.original_retention = {
            'operation_sha256': boot._operation_sha(self.stage), 'boot_id': self.boot_id,
            'removed': {str(self.retired): self.description(self.retired)},
            'preserved': {str(path): self.description(path) for path in (self.env, self.unrelated)},
            'mutable_directories': []}
        self.original_sha = 'e' * 64
        self.retention_authorities = {}
        self.live_inventory = ['after']
        original_read_text = Path.read_text
        def read_text(path, *args, **kwargs):
            if str(path) == '/proc/sys/kernel/random/boot_id':
                return self.boot_id
            return original_read_text(path, *args, **kwargs)
        def authority(stage, reference, *, historical=False, **kwargs):
            self.assertEqual(stage, self.stage)
            boot.exact(reference, {'filename', 'sha256'})
            path = stage / reference['filename']
            raw = path.read_bytes()
            value = json.loads(raw)
            if (path.parent != stage or boot.rpm.sha(raw) != reference['sha256']
                    or value != self.retention_authorities.get(value['boot_id'])
                    or not historical and value['boot_id'] != self.boot_id):
                raise Refused('fixture_signed_retention_authority_changed')
            return value
        for context in (
                patch.object(boot.kernel, 'GRUBENV', str(self.env)),
                patch.object(boot.kernel, 'load_plan', return_value=(self.candidate, boot_fixture.PLAN_SHA)),
                patch.object(Path, 'read_text', new=read_text),
                patch.object(boot.rpm, 'inventory', side_effect=lambda runner: ('', [], list(self.live_inventory))),
                patch.object(retention, 'validate_boot_authority', side_effect=authority),
                patch.object(retention, 'load_plan', return_value=(self.original_retention, self.original_sha)),
                patch.object(retention, 'load_historical_plan', return_value=(self.original_retention, self.original_sha)),
                patch.object(retention, 'require_linux_root'),
                patch.object(retention, 'run', side_effect=self.runner),
                patch.object(updates.aide, 'Aide', return_value=self.manager)):
            context.start()
            self.addCleanup(context.stop)
        atomic_json(self.root / 'manager/os-transaction.json', {
            **self.transaction, 'state': 'retaining', 'kernel_retention': 'pending'})
        self.original_integrity = retention.integrity_plan(self.original_retention, self.original_sha)
        self.original_path = self.stage / retention.INTEGRITY
        self.write_private(self.original_path, boot.kernel.encode(self.original_integrity))
        updates.prepare(self.manager, self.stage, self.original_path)
        _, prepared = updates._prepared(self.manager, self.state, self.identity, self.stage,
                                         self.original_integrity, boot.rpm.sha(self.original_path.read_bytes()))
        intent = {'schema': 1, 'plan_sha256': self.original_sha, 'authorization': {
            'ok': True, 'plan_sha256': self.original_sha, 'boot_id': self.boot_id,
            'backup_sha256': 'f' * 64, 'aide_preparation_sha256': digest(prepared)}}
        self.write_private(self.stage / retention.INTENT, boot.kernel.encode(intent))
        self.retired.unlink()
        self.live_inventory = ['retained-exact']

    def compound_after_boot(self, boot_id='cccccccc-cccc-cccc-cccc-cccccccccccc'):
        self.next_candidate_boot(boot_id)
        atomic_json(self.root / 'manager/os-transaction.json', {
            **self.transaction, 'state': 'retention_recovery_required', 'kernel_retention': 'pending'})
        authority_ref = self.observe_retention()
        _, observation = boot.plan_retention_resume(self.stage, authority_ref, runner=self.runner)
        boot_ref = boot._plan_reference(observation)
        authorize = lambda stage, checksum: {
            'ok': True, 'stage': str(stage), 'boot_id': self.boot_id,
            'operation_sha256': boot._operation_sha(stage), 'retention_plan_sha256': checksum,
            'backup_stage': str(stage), 'backup_sha256': 'f' * 64}
        path, plan = retention.prepare_resume(self.stage, authority_ref, boot_ref,
                                               authorize=authorize, runner=self.runner)
        return path, plan, observation

    def finish_compound(self, path, plan, observation):
        updates.prepare(self.manager, self.stage, path)
        updates.accept(self.manager, self.stage, path)
        proof = updates.retained_plan_acceptance(self.stage, path, manager=self.manager)
        result = {'schema': 1, 'status': 'integrity_reconciled',
                  'plan': {'filename': path.name, 'sha256': boot.rpm.sha(path.read_bytes())},
                  'boot_ref': plan['boot_ref'], 'authority_ref': plan['authority_ref'],
                  'boot_id': self.boot_id, 'kernel': boot_fixture.NEW,
                  'retention_plan_sha256': self.original_sha, 'aide': proof, 'release_accepted': False}
        name = 'kernel-retention-resume-' + plan['id'] + '-result.json'
        boot.kernel.record(self.stage, name, result)
        reference = {'filename': name, 'sha256': boot.rpm.sha(boot.kernel.encode(result))}
        boot.complete_retention_resume(self.stage, plan['boot_ref'], reference, runner=self.runner)
        final = boot.accepted_transitions(self.stage, runner=self.runner)
        self.assertEqual(final['retention_integrity_sha256'], reference['sha256'])
        self.assertEqual(final['promotion_sha256'], self.initial_acceptance['promotion_sha256'])
        self.assertEqual(final['postboot_sha256'], self.initial_acceptance['postboot_sha256'])
        self.assertEqual(final['boot_id'], self.boot_id)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertFalse(self.retired.exists())
        self.assertEqual(self.scan_calls.count('init'), 1)
        return reference

    def test_compound_boot_retention_accepts_only_real_published_aide_chain(self):
        self.retention_origin()
        path, plan, observation = self.compound_after_boot()
        with self.assertRaisesRegex(Refused, 'retained_plan_acceptance_missing'):
            updates.retained_plan_acceptance(self.stage, path, manager=self.manager)
        self.finish_compound(path, plan, observation)
        self.assertEqual(len(list((self.state / 'authorized/entries').glob('*.json'))), 4)
        # A real completion cannot outlive alteration of its retained database.
        (self.state / 'aide.db.gz').write_bytes(b'changed outside accepted CAS')
        with self.assertRaises(Refused):
            boot.accepted_transitions(self.stage, runner=self.runner)

    def test_compound_recovers_original_scan_then_second_boot_interrupted_compound(self):
        self.retention_origin()
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError('scan interrupted')) if action == 'update' else None
        with self.assertRaises(OSError):
            updates.accept(self.manager, self.stage, self.original_path)
        self.scan_hook = None
        path, plan, observation = self.compound_after_boot()
        updates.prepare(self.manager, self.stage, path)
        replace = updates._replace_current
        def crash(*args):
            replace(*args)
            raise OSError('compound database copied before publication')
        with patch.object(updates, '_replace_current', side_effect=crash):
            with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
        self.assertFalse(boot._result_path(self.stage, observation).exists())
        second_path, second, second_observation = self.compound_after_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        self.assertEqual(second['previous_retention_plan'], {
            'filename': path.name, 'sha256': boot.rpm.sha(path.read_bytes())})
        self.finish_compound(second_path, second, second_observation)
        self.assertFalse(boot._result_path(self.stage, observation).exists())
        self.assertEqual(len(list((self.state / 'authorized/artifacts').glob('*.retention-resume.json'))), 2)

    def test_compound_refuses_unrelated_drift_without_database_change(self):
        self.retention_origin()
        path, plan, observation = self.compound_after_boot()
        before = (self.state / 'aide.db.gz').read_bytes()
        extra = self.root / 'unrelated-new-file'
        self.write_private(extra, b'not authorized by kernel retention\n')
        self.monitored.append(extra)
        with self.assertRaisesRegex(Refused, 'unrelated_integrity_change'):
            updates.prepare(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assertFalse(boot._result_path(self.stage, observation).exists())

    def test_arm_boot_promote_and_resume_use_actual_aide_dispatch_and_chain(self):
        self.call(boot.arm_candidate)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.new_boot()
        self.assertEqual(self.call(boot.verify_postboot)['outcome'], 'candidate')
        self.call(boot.commit_candidate, health=self.health())
        original = boot.accepted_transitions(self.stage, runner=self.runner)
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        resumed = boot.accepted_transitions(self.stage, runner=self.runner)
        self.assertEqual(resumed['promotion_sha256'], original['promotion_sha256'])
        self.assertEqual(resumed['postboot_sha256'], original['postboot_sha256'])
        self.assertIsNotNone(resumed['resume_sha256'])
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)
        self.assertEqual(len(list((self.state / 'authorized/entries').glob('*.json'))), 4)

    def test_interrupted_arm_scan_recovers_on_new_boot_without_reinitialization(self):
        def stop(action, *_):
            if action == 'update':
                raise OSError('power loss during arm AIDE scan')
        self.scan_hook = stop
        with self.assertRaises(OSError): self.call(boot.arm_candidate)
        armed = boot._current(self.stage)[1]
        self.assertEqual(json.loads((self.state / 'authorized/pending.json').read_text())['state'], 'scanning')
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.scan_hook = None
        self.new_boot()
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)
        self.assertFalse(boot._result_path(self.stage, armed).exists())
        self.assertEqual(len(list((self.state / 'authorized/artifacts').glob('*.kernel-resume.json'))), 1)

    def test_interrupted_promotion_after_database_copy_preserves_chain_before_new_boot_acceptance(self):
        self.call(boot.arm_candidate)
        self.new_boot()
        self.call(boot.verify_postboot)
        replace = updates._replace_current
        def stop(*args):
            replace(*args)
            raise OSError('power loss after promotion database copy')
        with patch.object(updates, '_replace_current', side_effect=stop):
            with self.assertRaises(OSError): self.call(boot.commit_candidate, health=self.health())
        promotion = boot._current(self.stage)[1]
        copied_database = (self.state / 'aide.db.gz').read_bytes()
        self.assertEqual(json.loads((self.state / 'authorized/pending.json').read_text())['state'], 'ready')
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        proof = boot.accepted_transitions(self.stage, runner=self.runner)
        self.assertEqual(proof['promotion_sha256'], boot.rpm.sha(boot.kernel.encode(promotion)))
        self.assertIsNotNone(proof['resume_sha256'])
        self.assertFalse(boot._result_path(self.stage, promotion).exists())
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)
        self.assertTrue(any(path.read_bytes() == copied_database for path in (self.state / 'authorized/artifacts').glob('*.db.gz')))

    def test_new_boot_reconciliation_rejects_unrelated_drift(self):
        self.call(boot.arm_candidate)
        self.new_boot()
        self.unrelated.write_bytes(b'changed outside transition\n')
        with self.assertRaisesRegex(Refused, 'unrelated_integrity_change'):
            self.call(boot.verify_postboot)
        self.assertEqual(self.scan_calls.count('update'), 1)
        self.assertEqual(self.scan_calls.count('init'), 1)
