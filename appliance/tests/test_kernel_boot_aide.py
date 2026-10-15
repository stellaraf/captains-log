"""Actual boot plans and AIDE chain with private host/scanner fixtures.

No boot dispatcher, plan validator, snapshot, phase policy or retained database
chain method is mocked. Native host identity/renderer/scanner inputs are injected;
this does not establish native GRUB, FIPS or encrypted appliance boot acceptance.
"""
import copy
import json
from unittest import TestCase
from unittest.mock import Mock, patch

from nebulalog_manager import aide_updates as updates, host_payload
from nebulalog_manager import kernel_boot as boot
from nebulalog_manager.common import Refused
import test_aide_lifecycle as aide_fixture
import test_aide_updates as authorized_fixture
import test_kernel_boot as boot_fixture


class KernelAideIntegrationTests(TestCase):
    for _name in ('write_private', 'reader', 'facts', 'monitor', 'fresh', 'run_fixture', 'enrolled'):
        locals()[_name] = getattr(aide_fixture.AideLifecycleTests, _name)
    for _name in ('trusted_tree', 'desc', 'snapshot_files', 'scan_runner'):
        locals()[_name] = getattr(authorized_fixture.AuthorizedAideTests, _name)
    for _name in ('description', 'read_private', 'runner', 'new_boot', 'health', 'next_candidate_boot', 'call', 'integrity_callback'):
        locals()[_name] = getattr(boot_fixture.BootTransactionTests, _name)

    def setUp(self):
        # Initialize the independently tested host fixture, then construct the
        # AIDE storage identity over that same private root before enrollment.
        boot_fixture.BootTransactionTests.setUp(self)
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
        self.monitored = [self.env, self.unrelated]
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
