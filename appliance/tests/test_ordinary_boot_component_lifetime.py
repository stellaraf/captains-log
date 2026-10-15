"""Boot ownership cannot adopt state while an old component hook is unresolved.

The real hook ledger and boot-admission code run against private filesystem
journals. Host capture and AIDE history use the existing ordinary-boot fixtures.
"""
import json
import os
import sys
import unittest

from nebulalog_manager import host_dispatch, host_payload, ordinary_boot
from nebulalog_manager.common import Refused, atomic_json
from test_ordinary_boot import Fixtures


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'protected native Linux hook-journal ownership')
class ComponentBootAdmissionTests(Fixtures):
    def setUp(self):
        super().setUp()
        self.stage = self.root / 'manager/updates/releases/1-component'
        self.stage.mkdir(parents=True, mode=0o700)
        raw = host_payload.encoded({'product': 'nebulalog', 'sequence': 1, 'components': {}})
        (self.stage / 'manifest.json').write_bytes(raw)
        self.transaction = {'hook_protocol': 1, 'sequence': 1, 'release': str(self.stage),
            'manifest_sha256': host_payload.digest(raw), 'state': 'preflight',
            'previous': {'sequence': 0, 'components': {}}, 'host_coordinator': None}
        self.journal_path = self.stage.parent.parent / 'transaction.json'
        self.journal = host_dispatch.HookJournal(self.stage, self.transaction)

    def write_transaction(self, state, *, legacy=False):
        value = {**self.transaction, 'state': state, 'finalization': 'complete'}
        if legacy:
            value.pop('hook_protocol')
        atomic_json(self.journal_path, value)

    def assert_held_before_capture(self):
        before = self.journal_path.read_bytes()
        with self.assertRaises(Refused):
            self.reboot()
        ordinary_boot.native.capture.assert_not_called()
        self.reader.assert_not_called()
        self.assertEqual(self.journal_path.read_bytes(), before)
        self.assertEqual(list(self.owner.iterdir()), [])

    def test_unresolved_hook_blocks_boot_even_with_terminal_looking_component_journal(self):
        self.journal.begin('update-backup', {'fixture': 'undelivered hook result'})
        for state in ('preflight_failed', 'committed', 'rolled_back'):
            with self.subTest(state=state):
                self.write_transaction(state)
                self.assert_held_before_capture()

    def test_unacknowledged_native_command_cannot_be_adopted_as_boot_metadata(self):
        ref = self.journal.begin('update-backup', {'fixture': 'lost native result'})
        self.journal.enter('update-backup')
        self.journal.command_event(ref, 'dispatch', 'call', argv=['inert-fixture-command'])
        self.write_transaction('preflight_failed')
        self.assert_held_before_capture()

    def test_known_terminal_failure_allows_ordinary_boot_without_replaying_hook(self):
        ref = self.journal.begin('update-preflight', {'fixture': 'known preflight failure'})
        self.journal.enter('update-preflight')
        self.journal.finish(ref, 'failed')
        self.write_transaction('preflight_failed')
        before = {p.name: p.read_bytes() for p in self.stage.iterdir()}
        stage = self.reboot()
        self.assertEqual(stage.parent, self.owner)
        self.assertEqual({p.name: p.read_bytes() for p in self.stage.iterdir()}, before)
        self.assertEqual(self.journal.assert_settled(), 1)

    def test_legacy_failed_preflight_has_no_boot_acceptance_authority(self):
        self.write_transaction('preflight_failed', legacy=True)
        self.assert_held_before_capture()

    def test_exact_legacy_accepted_history_remains_a_valid_boot_starting_point(self):
        self.write_transaction('committed', legacy=True)
        atomic_json(self.stage.parent.parent / 'current.json',
                    {'sequence': 1, 'release': str(self.stage), 'components': {}})
        stage = self.reboot()
        self.assertEqual(stage.parent, self.owner)
        self.assertNotIn('hook_protocol', json.loads(self.journal_path.read_text()))
