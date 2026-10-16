"""Real AIDE CAS/scan fixtures with injected boot and RPM plan authority.

The ancestry resolver and host ownership are isolated dependencies here. Scan
parsing, retained reports/databases, CAS, immutable enrollment and delta policy
are real; this suite does not establish native boot or RPM acceptance.
"""
import copy
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import aide_updates as updates, kernel_retention as retain
from nebulalog_manager.common import Refused
import test_aide_updates as fixture


class RetentionResumeAideTests(TestCase):
    for _name in ('write_private', 'reader', 'facts', 'monitor', 'fresh', 'run_fixture', 'enrolled',
                  'authorized_fixture', 'trusted_tree', 'desc', 'snapshot_files', 'scan_runner', 'assert_original'):
        locals()[_name] = getattr(fixture.AuthorizedAideTests, _name)

    def setUp(self):
        fixture.AuthorizedAideTests.setUp(self)
        self.authorized_fixture()
        self.bound.stop()
        self.monitored = [self.runtime, self.selection, self.unrelated]
        parent = self.root / 'manager/os-updates'
        parent.mkdir(mode=0o700)
        destination = parent / ('a' * 32)
        self.stage.rename(destination)
        self.stage = destination
        self.old = {'schema': 1, 'kind': retain.KIND, 'sequence': 0, 'manifest_sha256': 'b' * 64,
                    'removed': {str(self.runtime): self.desc(self.runtime)},
                    'preserved': {str(p): self.desc(p) for p in (self.selection, self.unrelated)},
                    'mutable_directories': []}
        self.old_path = self.stage / retain.INTEGRITY
        self.write_private(self.old_path, retain.kernel.encode(self.old))
        self.parents = {}
        for context in (
            patch.object(updates, '_bound_plan', side_effect=self.bound_plan),
            patch.object(retain.kernel, 'GRUBENV', str(self.selection)),
            patch.object(retain.kernel, 'describe', side_effect=lambda p: self.desc(Path(p))),
            patch.object(retain, 'preserved_description', side_effect=lambda p: self.desc(Path(p))),
            patch.object(retain, 'resume_origin', side_effect=lambda *_: copy.deepcopy(self.origin)),
            patch.object(retain, 'resume_integrity_predecessor', side_effect=self.predecessor),
        ):
            context.start(); self.addCleanup(context.stop)
        updates.prepare(self.manager, self.stage, self.old_path)
        _, prepared = updates._prepared(self.manager, self.state, self.identity, self.stage,
                                        self.old, updates._sha(self.old_path.read_bytes()))
        self.origin = {'integrity': self.old, 'integrity_sha256': updates._sha(self.old_path.read_bytes()),
                       'prepared_sha256': updates.digest(prepared)}
        self.old_prepared = prepared

    def bound_plan(self, manager, stage, path, *, preparing):
        self.assertEqual(stage, self.stage)
        raw = Path(path).read_bytes()
        return json.loads(raw), updates._sha(raw)

    def predecessor(self, stage, path):
        self.assertEqual(stage, self.stage)
        prior = self.parents[Path(path)]
        return json.loads(prior.read_bytes()), updates._sha(prior.read_bytes())

    def interrupt(self, path, point):
        if point == 'scanning':
            def stop(action, *_):
                if action == 'update':
                    raise OSError('power loss during scan')
            self.scan_hook = stop
            try:
                with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
            finally:
                self.scan_hook = None
        elif point == 'ready_input':
            with patch.object(updates, '_complete', side_effect=OSError('power loss before copy')):
                with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
        elif point == 'ready_output':
            replace = updates._replace_current
            def stop(*args):
                replace(*args)
                raise OSError('power loss after copy')
            with patch.object(updates, '_replace_current', side_effect=stop):
                with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
        elif point == 'accepted':
            updates.accept(self.manager, self.stage, path)
        elif point != 'before_accept':
            self.fail('unknown interruption point')

    def new_boot(self, token='c', prior=None):
        self.selection.write_bytes(('qualified boot ' + token + '\n').encode())
        plan = {'schema': 1, 'kind': retain.RESUME_KIND, 'sequence': 0, 'id': token * 32,
                'removed': self.old['removed'], 'preserved': {str(self.unrelated): self.desc(self.unrelated)},
                'mutable_directories': [],
                'files': [{'path': str(self.selection), 'before': self.old['preserved'][str(self.selection)],
                           'after': self.desc(self.selection)}]}
        plan['manifest_sha256'] = updates.digest(plan)
        path = self.stage / ('kernel-retention-resume-' + token * 32 + '-plan.json')
        self.write_private(path, retain.kernel.encode(plan))
        self.parents[path] = prior or self.old_path
        return path

    def finish(self, path):
        updates.prepare(self.manager, self.stage, path)
        updates.accept(self.manager, self.stage, path)
        proof = updates.retained_plan_acceptance(self.stage, path, manager=self.manager)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)
        self.assert_original()
        return proof

    def test_each_original_acceptance_interruption_reconciles_without_reinitialization(self):
        # Separate cases use independent storage and immutable original roots.
        self.runtime.unlink()
        self.interrupt(self.old_path, self.point)
        self.finish(self.new_boot())

    point = 'scanning'

    def test_ready_input_recovery(self):
        self.point = 'ready_input'
        self.test_each_original_acceptance_interruption_reconciles_without_reinitialization()

    def test_ready_output_recovery(self):
        self.point = 'ready_output'
        self.test_each_original_acceptance_interruption_reconciles_without_reinitialization()

    def test_completed_original_acceptance_recovery(self):
        self.point = 'accepted'
        self.test_each_original_acceptance_interruption_reconciles_without_reinitialization()

    def test_erase_before_acceptance_scan_recovery(self):
        self.point = 'before_accept'
        self.test_each_original_acceptance_interruption_reconciles_without_reinitialization()

    def test_second_reboot_before_intermediate_preparation_keeps_exact_original_owner(self):
        self.runtime.unlink()
        self.interrupt(self.old_path, 'scanning')
        first = self.new_boot()
        second = self.new_boot('d', first)
        self.finish(second)

    def test_second_reboot_after_compound_database_copy_preserves_its_history(self):
        self.runtime.unlink()
        first = self.new_boot()
        updates.prepare(self.manager, self.stage, first)
        self.interrupt(first, 'ready_output')
        copied = (self.state / 'aide.db.gz').read_bytes()
        self.finish(self.new_boot('d', first))
        self.assertTrue(any(p.read_bytes() == copied for p in (self.state / 'authorized/artifacts').glob('*.db.gz')))

    def test_same_boot_retry_after_compound_copy_uses_fresh_check(self):
        self.runtime.unlink()
        path = self.new_boot()
        updates.prepare(self.manager, self.stage, path)
        self.interrupt(path, 'ready_output')
        before = self.scan_calls.count('update')
        self.finish(path)
        self.assertEqual(self.scan_calls.count('update'), before)

    def test_unrelated_drift_never_becomes_accepted(self):
        self.runtime.unlink()
        self.interrupt(self.old_path, 'ready_input')
        path = self.new_boot()
        self.unrelated.write_bytes(b'unauthorized content\n')
        before = (self.state / 'aide.db.gz').read_bytes()
        with self.assertRaises(Refused): updates.prepare(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assert_original()

    def test_original_authorization_must_bind_exact_preparation(self):
        self.runtime.unlink()
        path = self.new_boot()
        self.origin['prepared_sha256'] = 'f' * 64
        with self.assertRaisesRegex(Refused, 'original_preparation_changed'):
            updates.prepare(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_foreign_pending_preparation_and_ancestry_cycle_are_refused(self):
        self.runtime.unlink()
        self.interrupt(self.old_path, 'scanning')
        pending_path = self.state / 'authorized/pending.json'
        pending = json.loads(pending_path.read_text())
        pending['prepared'] = {'id': 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'sha256': 'f' * 64}
        self.write_private(pending_path, retain.kernel.encode(pending))
        path = self.new_boot()
        with self.assertRaisesRegex(Refused, 'different_acceptance_pending'):
            updates.prepare(self.manager, self.stage, path)
        self.parents[path] = path
        with self.assertRaisesRegex(Refused, 'ancestry_limit'):
            updates.prepare(self.manager, self.stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_corrupt_retained_output_refuses_before_current_database_change(self):
        self.runtime.unlink()
        self.interrupt(self.old_path, 'ready_input')
        pending = json.loads((self.state / 'authorized/pending.json').read_text())
        output = self.state / 'authorized/artifacts' / (pending['proposed_entry']['output'] + '.db.gz')
        self.write_private(output, self.initial_db)
        with self.assertRaises(Refused): updates.prepare(self.manager, self.stage, self.new_boot())
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
