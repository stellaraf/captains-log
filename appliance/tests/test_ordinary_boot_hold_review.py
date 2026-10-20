"""Independent hold-publication failures with the actual AIDE chain fixture.

Private host observation and scanner inputs are injected. Receipt validation,
generation ownership, AIDE CAS, and retry handling remain real; no native boot
or filesystem power-loss qualification is claimed.
"""
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import ordinary_boot as core
from nebulalog_manager.common import Refused, locked
import test_ordinary_boot_aide as integration


class HoldPublicationTests(TestCase):
    for _name, _value in integration.OrdinaryAideTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_') and _name != 'setUp':
            locals()[_name] = _value

    def setUp(self):
        integration.OrdinaryAideTests.setUp(self)
        # Match lifecycle's real outer lock context. A plain manager.check()
        # would reacquire transaction.lock and refuse here, unlike an isolated
        # helper test that accidentally hides the production lock interaction.
        for path in (self.root / 'manager/transaction.lock',
                     self.root / 'manager/updates/transaction.lock'):
            context = locked(path)
            context.__enter__()
            self.addCleanup(context.__exit__, None, None, None)

    def acquire_hold(self):
        hold = core.observation_hold(self.root, boot_id=self.observed['boot_id'], manager=self.manager)
        self.manager.records.write(self.root / 'manager/maintenance.json',
                                   {'active': True, 'release': str(hold)}, self.identity)
        return hold

    def ready(self):
        hold = self.acquire_hold()
        stage = self.pending()
        self.reconcile(stage)
        health = {'ok': True, 'stage': str(stage), 'boot_id': self.observed['boot_id'],
                  'checks': {key: True for key in core.REQUIRED_CHECKS}}
        return hold, stage, health

    def assert_retry(self, hold, stage, health):
        before = (self.state / 'aide.db.gz').read_bytes()
        self.assertEqual(self.pending(), stage)
        self.assertTrue(core.owns_maintenance(stage, str(hold)))
        self.reconcile(stage)
        core.finalize(stage, health, manager=self.manager)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assertFalse((self.owner / core.HOLD).exists())
        self.assertFalse((self.owner / core.PENDING).exists())
        self.assertEqual(self.pending(), stage)  # The lifecycle gate is still held.
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_after_current_pointer_publication_retries_same_owned_generation(self):
        hold, stage, health = self.ready()
        original = self.manager.records.write
        def interrupted(path, value, identity):
            original(path, value, identity)
            if path == self.owner / core.CURRENT:
                raise OSError('after current pointer publication')
        with patch.object(self.manager.records, 'write', side_effect=interrupted):
            with self.assertRaises(OSError): core.finalize(stage, health, manager=self.manager)
        self.assertTrue((self.owner / core.HOLD).exists())
        self.assertTrue((self.owner / core.PENDING).exists())
        self.assert_retry(hold, stage, health)

    def test_after_pending_unlink_retries_from_current_with_hold_retained(self):
        hold, stage, health = self.ready()
        original = Path.unlink
        def interrupted(path, *args, **kwargs):
            original(path, *args, **kwargs)
            if path == self.owner / core.PENDING:
                raise OSError('after pending pointer unlink')
        with patch.object(Path, 'unlink', new=interrupted):
            with self.assertRaises(OSError): core.finalize(stage, health, manager=self.manager)
        self.assertTrue((self.owner / core.HOLD).exists())
        self.assertFalse((self.owner / core.PENDING).exists())
        self.assert_retry(hold, stage, health)

    def test_after_hold_unlink_retained_plan_still_owns_gate(self):
        hold, stage, health = self.ready()
        original = Path.unlink
        def interrupted(path, *args, **kwargs):
            original(path, *args, **kwargs)
            if path == self.owner / core.HOLD:
                raise OSError('after hold pointer unlink')
        with patch.object(Path, 'unlink', new=interrupted):
            with self.assertRaises(OSError): core.finalize(stage, health, manager=self.manager)
        self.assertFalse((self.owner / core.HOLD).exists())
        self.assertTrue((hold / 'receipt.json').exists())
        self.assert_retry(hold, stage, health)

    def test_unpublished_hold_receipt_is_preserved_and_never_adopted(self):
        original = self.manager.records.write
        def interrupted(path, value, identity):
            if path == self.owner / core.HOLD:
                raise OSError('before hold pointer publication')
            original(path, value, identity)
        with patch.object(self.manager.records, 'write', side_effect=interrupted):
            with self.assertRaises(OSError):
                core.observation_hold(self.root, boot_id=self.observed['boot_id'], manager=self.manager)
        retained = {path: path.read_bytes() for path in (self.owner / 'holds').glob('*/receipt.json')}
        self.assertEqual(len(retained), 1)
        self.assertFalse((self.owner / core.HOLD).exists())
        hold = self.acquire_hold()
        self.assertNotIn(hold / 'receipt.json', retained)
        for path, content in retained.items(): self.assertEqual(path.read_bytes(), content)
        for path, content in self.original.items(): self.assertEqual(path.read_bytes(), content)

    def test_gate_release_retry_rechecks_unrelated_protected_files(self):
        hold, stage, health = self.ready()
        core.finalize(stage, health, manager=self.manager)
        before = (self.state / 'aide.db.gz').read_bytes()
        self.unrelated.write_bytes(b'drift after final receipt but before gate release retry\n')
        self.assertEqual(self.pending(), stage)
        with self.assertRaises(Refused): self.reconcile(stage)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assertTrue(core.owns_maintenance(stage, str(hold)))
        self.assertTrue((self.root / 'manager/maintenance.json').exists())


if __name__ == '__main__':
    __import__('unittest').main()
