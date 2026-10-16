"""Real ordinary/AIDE dispatch and CAS over private scanner/host fixtures.

Plan ownership, typed folding, allowed delta, retained scan/database chain and
generation finalization are real. The native snapshot and scanner are injected;
these tests do not establish native AIDE, FIPS or appliance boot acceptance.
"""
import base64
import copy
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import ordinary_boot as core, aide_updates as updates
from nebulalog_manager.common import Refused, locked
import test_aide_lifecycle as baseline
import test_aide_updates as scanner
from test_ordinary_boot_state import fixture, environment, NEXT


class OrdinaryAideTests(TestCase):
    for _name in ('write_private', 'reader', 'facts', 'monitor', 'fresh', 'run_fixture', 'enrolled'):
        locals()[_name] = getattr(baseline.AideLifecycleTests, _name)
    for _name in ('desc', 'snapshot_files', 'scan_runner', 'trusted_tree'):
        locals()[_name] = getattr(scanner.AuthorizedAideTests, _name)

    def setUp(self):
        baseline.AideLifecycleTests.setUp(self)
        self.owner = self.root / 'manager/boot-integrity'
        self.owner.mkdir(parents=True, mode=0o700)
        self.owner.parent.chmod(0o700)
        self.env = self.root / 'private-grubenv'
        self.unrelated = self.root / 'unrelated.conf'
        self.initial = fixture(); self.observed = copy.deepcopy(self.initial)
        self.write_private(self.env, base64.b64decode(self.initial['grub']['raw']))
        self.write_private(self.unrelated, b'protected unrelated content\n')
        self.monitored = [self.env, self.unrelated]
        self.scan_calls, self.scan_hook = [], None
        self.manager.runner = self.scan_runner
        self.metadata = {'xattrs_sha256': 'a' * 64, 'acl_sha256': 'b' * 64, 'selinux_sha256': 'c' * 64}
        for context in (
                patch.object(updates, '_metadata', side_effect=lambda path: dict(self.metadata)),
                patch.object(core.native, 'ENV', str(self.env)),
                patch.object(core.native, 'capture', side_effect=self.capture),
                patch.object(core.rpm, 'read', side_effect=lambda path, maximum=core.rpm.MAX_XML: self.reader(path, maximum=maximum)),
                patch.object(core.aide, 'verify_initial_boot_snapshot', side_effect=self.original_snapshot)):
            context.start(); self.addCleanup(context.stop)
        self.values['ordinary_boot_snapshot_sha256'] = core.rpm.sha(core.kernel.encode(self.initial))
        self.boot_snapshot.side_effect = self.original_snapshot
        self.write_private(self.owner / 'initial.json', core.kernel.encode(self.initial))
        _, self.base = self.enrolled()
        self.initial_db = (self.state / 'aide.db.gz').read_bytes()
        self.original = {path: path.read_bytes() for path in
                         (self.marker, self.state / 'candidate.json', self.state / 'candidate.db.gz', self.state / 'commit-pending.json')}

    def capture(self, **kwargs):
        value = copy.deepcopy(self.observed)
        raw = self.env.read_bytes()
        value['grub']['raw'] = base64.b64encode(raw).decode()
        value['grub']['description'].update(bytes=len(raw), sha256=core.rpm.sha(raw))
        return core.native.validate_snapshot(value)

    def original_snapshot(self, identity, checksum):
        self.assertEqual(identity, self.identity)
        raw = (self.owner / 'initial.json').read_bytes()
        if core.rpm.sha(raw) != checksum: raise Refused('original snapshot changed')
        return core.native.validate_snapshot(core.strict_json(raw))

    def change(self, *, boot=None, success=None):
        if boot is not None: self.observed['boot_id'] = boot
        if success is not None: environment(self.observed, boot_success=success)
        self.write_private(self.env, base64.b64decode(self.observed['grub']['raw']))

    def pending(self):
        return core.pending_stage(self.root, manager=self.manager)

    def reconcile(self, stage):
        return core.reconcile(stage, prepare=lambda s, p: updates.prepare(self.manager, s, p),
                              accept=lambda s, p: updates.accept(self.manager, s, p), manager=self.manager)

    def finish(self, stage):
        result = self.reconcile(stage)
        health = {'ok': True, 'stage': str(stage), 'boot_id': self.observed['boot_id'],
                  'checks': {key: True for key in core.REQUIRED_CHECKS}}
        receipt = core.finalize(stage, health, manager=self.manager)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)
        self.assertIsNone(self.pending())
        for path, raw in self.original.items(): self.assertEqual(path.read_bytes(), raw)
        return result, receipt

    def interrupt(self, stage, point):
        path = stage / core.PLAN
        updates.prepare(self.manager, stage, path)
        if point == 'scanning':
            def crash(action, *_):
                if action == 'update': raise OSError('private scan interruption')
            self.scan_hook = crash
            try:
                with self.assertRaises(OSError): updates.accept(self.manager, stage, path)
            finally: self.scan_hook = None
        elif point == 'ready_input':
            with patch.object(updates, '_complete', side_effect=OSError('private before-copy interruption')):
                with self.assertRaises(OSError): updates.accept(self.manager, stage, path)
        elif point == 'ready_output':
            original = updates._replace_current
            def crash(*args):
                original(*args); raise OSError('private after-copy interruption')
            with patch.object(updates, '_replace_current', side_effect=crash):
                with self.assertRaises(OSError): updates.accept(self.manager, stage, path)
        elif point == 'published_head':
            original = self.manager.records.write
            def crash(path, value, identity):
                original(path, value, identity)
                if path.name == 'head.json': raise OSError('private after-head interruption')
            with patch.object(self.manager.records, 'write', side_effect=crash):
                with self.assertRaises(OSError): updates.accept(self.manager, stage, path)
        else: self.fail('unknown private interruption')

    def test_pristine_reboot_real_chain_and_late_flag_same_boot(self):
        self.assertIsNone(self.pending())
        self.change(boot=NEXT)
        first = self.pending(); self.finish(first)
        self.change(success='1')
        later = self.pending(); self.assertNotEqual(first, later)
        self.finish(later)
        history = updates.accepted_plan_history(manager=self.manager)
        self.assertEqual(len(history['history']), 2)
        self.assertEqual(history['history'][1]['entry']['previous'], history['history'][0]['entry_ref'])

    def test_unrelated_scan_drift_never_becomes_new_baseline(self):
        self.change(boot=NEXT); stage = self.pending()
        self.unrelated.write_bytes(b'unrelated corruption\n')
        with self.assertRaisesRegex(Refused, 'unrelated_integrity_change'): self.reconcile(stage)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertFalse((stage / core.RESULT).exists())

    def test_second_reboot_after_scanning_interruption(self):
        self.interrupted_reboot('scanning')

    def test_second_reboot_before_database_copy(self):
        self.interrupted_reboot('ready_input')

    def test_second_reboot_after_database_copy(self):
        self.interrupted_reboot('ready_output')

    def test_second_reboot_after_head_publication_before_pending_completion(self):
        self.interrupted_reboot('published_head')

    def test_identical_input_output_database_ready_recovery_uses_exact_output_branch(self):
        self.observed['boot_id'] = NEXT  # No private file write: DBs really equal.
        first = self.pending(); self.interrupt(first, 'ready_input')
        pending = self.manager.records.read(self.state / 'authorized/pending.json', self.identity)
        self.assertEqual(pending['database_sha256'], pending['previous_database_sha256'])
        self.change(boot='cccccccc-cccc-cccc-cccc-cccccccccccc')
        second = self.pending(); self.finish(second)

    def interrupted_reboot(self, point):
        self.change(boot=NEXT, success='1'); first = self.pending()
        self.interrupt(first, point)
        copied = (self.state / 'aide.db.gz').read_bytes()
        self.change(boot='cccccccc-cccc-cccc-cccc-cccccccccccc', success='0')
        second = self.pending()
        self.assertTrue(core.owns_maintenance(second, str(first)))
        self.finish(second)
        if point == 'ready_output':
            self.assertTrue(any(path.read_bytes() == copied for path in (self.state / 'authorized/artifacts').glob('*.db.gz')))
        self.assertFalse((first / core.FINAL).exists())

    def test_third_boot_skips_unprepared_middle_generation_using_real_pending_owner(self):
        self.change(boot=NEXT, success='1'); first = self.pending(); self.interrupt(first, 'ready_output')
        self.change(boot='cccccccc-cccc-cccc-cccc-cccccccccccc', success='0'); second = self.pending()
        self.change(boot='dddddddd-dddd-dddd-dddd-dddddddddddd'); third = self.pending()
        self.assertTrue(core.owns_maintenance(third, str(first)))
        self.assertEqual(core.integrity_predecessor(third, third / core.PLAN)[0]['stage'], str(second))
        self.finish(third)

    def test_same_boot_retry_after_database_copy(self):
        self.change(boot=NEXT, success='1'); stage = self.pending(); self.interrupt(stage, 'ready_output')
        self.assertEqual(self.pending(), stage)
        self.finish(stage)

    def test_finalization_crash_retry_uses_real_retained_proof_and_fresh_health(self):
        self.change(boot=NEXT); stage = self.pending(); self.reconcile(stage)
        self.assertEqual(self.pending(), stage)
        self.assertFalse((stage / core.FINAL).exists())
        self.finish(stage)

    def test_old_proposed_output_is_not_adopted_if_new_boot_has_unrelated_drift(self):
        self.change(boot=NEXT); first = self.pending(); self.interrupt(first, 'ready_input')
        self.change(boot='cccccccc-cccc-cccc-cccc-cccccccccccc'); second = self.pending()
        self.unrelated.write_bytes(b'new boot unrelated drift\n')
        with self.assertRaisesRegex(Refused, 'unrelated_integrity_change'): self.reconcile(second)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertFalse((second / core.FINAL).exists())

    def test_nochange_failure_hold_requires_actual_scan_and_health(self):
        hold = core.observation_hold(self.root, boot_id=self.observed['boot_id'], manager=self.manager)
        self.manager.records.write(self.root / 'manager/maintenance.json', {'active': True, 'release': str(hold)}, self.identity)
        stage = self.pending()
        self.assertTrue(core.owns_maintenance(stage, str(hold)))
        old_checks = self.scan_calls.count('check')
        self.reconcile(stage)
        self.assertGreater(self.scan_calls.count('check'), old_checks)
        self.assertFalse((stage / core.FINAL).exists())
        health = {'ok': True, 'stage': str(stage), 'boot_id': self.observed['boot_id'],
                  'checks': {key: True for key in core.REQUIRED_CHECKS}}
        core.finalize(stage, health, manager=self.manager)
        self.assertFalse((self.owner / core.HOLD).exists())
        self.assertEqual(self.pending(), stage)  # Gate release still pending.
        (self.root / 'manager/maintenance.json').unlink()
        self.assertIsNone(self.pending())

    def test_completed_generation_new_hold_requires_new_bound_checkpoint(self):
        self.change(boot=NEXT); old = self.pending(); self.finish(old)
        hold = core.observation_hold(self.root, boot_id=NEXT, manager=self.manager)
        self.manager.records.write(self.root / 'manager/maintenance.json', {'active': True, 'release': str(hold)}, self.identity)
        new = self.pending()
        self.assertNotEqual(new, old)
        plan, _ = core._load(new)
        self.assertEqual(plan['hold']['stage'], str(hold))
        self.assertEqual(plan['previous']['stage'], str(old))
        self.reconcile(new)

    def test_fresh_full_scan_does_not_reacquire_outer_lifecycle_lock(self):
        self.change(boot=NEXT); stage = self.pending()
        health = {'ok': True, 'stage': str(stage), 'boot_id': NEXT,
                  'checks': {key: True for key in core.REQUIRED_CHECKS}}
        with locked(self.root / 'manager/transaction.lock'):
            self.reconcile(stage)
            self.reconcile(stage)  # Existing-result full scan under outer lock.
            core.finalize(stage, health, manager=self.manager)
        self.assertEqual(self.manager.check()['state'], 'clean')
