"""Retained acceptance authority uses real private-file AIDE chain fixtures."""
import copy
import gzip
import json
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import aide_updates as updates
from nebulalog_manager.common import Refused
import test_aide_updates as fixture


class RetainedAcceptanceTests(TestCase):
    for _name in ('write_private', 'reader', 'facts', 'monitor', 'fresh', 'run_fixture', 'enrolled',
                  'authorized_fixture', 'trusted_tree', 'desc', 'snapshot_files', 'scan_runner',
                  'prepare_update', 'activate', 'accept_update', 'assert_original'):
        locals()[_name] = getattr(fixture.AuthorizedAideTests, _name)

    def setUp(self):
        fixture.AuthorizedAideTests.setUp(self)
        self.authorized_fixture()
        parent = self.root / 'manager/os-updates'
        parent.mkdir(mode=0o700)
        destination = parent / ('a' * 32)
        self.stage.rename(destination)
        self.stage = destination
        self.plan_path = destination / 'host-runtime-plan.json'

    def accept(self):
        self.prepare_update()
        self.activate()
        self.accept_update()
        return self.proof()

    def proof(self, **kwargs):
        return updates.retained_plan_acceptance(self.stage, self.plan_path, manager=self.manager, **kwargs)

    def test_current_acceptance_verifies_chain_without_writes_or_new_scan(self):
        proof = self.accept()
        original = {str(path): path.read_bytes() for path in self.state.rglob('*') if path.is_file()}
        calls = list(self.scan_calls)
        self.assertEqual(self.proof(expected=proof), proof)
        self.assertEqual(self.proof(expected=proof, historical=True), proof)
        self.assertEqual(proof['plan_sha256'], updates._sha(self.plan_path.read_bytes()))
        self.assertEqual(self.scan_calls, calls)
        self.assertEqual(original, {str(path): path.read_bytes() for path in self.state.rglob('*') if path.is_file()})
        self.assert_original()

    def test_preparation_is_not_acceptance(self):
        self.prepare_update()
        with self.assertRaisesRegex(Refused, 'acceptance_missing'):
            self.proof()
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_uncommitted_ready_proposal_cannot_be_historical_authority(self):
        self.prepare_update()
        self.activate()
        with patch.object(updates, '_complete', side_effect=OSError('power loss before database copy')):
            with self.assertRaises(OSError):
                self.accept_update()
        pending = json.loads((self.state / 'authorized/pending.json').read_text())
        entry = pending['proposed_entry']
        prepared = json.loads((self.state / 'authorized/prepared' / (entry['prepared']['id'] + '.json')).read_text())
        proposed = {'entry': pending['entry'], 'original_enrollment_sha256': entry['original_enrollment_sha256'],
                    'plan_sha256': entry['plan_sha256'], 'prepared_sha256': updates.digest(prepared),
                    'database_sha256': entry['database_sha256']}
        with self.assertRaisesRegex(Refused, 'pending_recovery'):
            self.proof()
        with self.assertRaises((Refused, FileNotFoundError)):
            self.proof(expected=proposed, historical=True)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_historical_prefix_does_not_claim_unknown_live_database_clean(self):
        proof = self.accept()
        path = self.state / 'aide.db.gz'
        changed = gzip.compress(b'unknown current database', mtime=0)
        self.write_private(path, changed)
        self.assertEqual(self.proof(expected=proof, historical=True), proof)
        with self.assertRaisesRegex(Refused, 'current_database_changed'):
            self.proof(expected=proof)
        self.assertEqual(path.read_bytes(), changed)

    def test_retained_report_or_database_corruption_refuses_both_modes(self):
        proof = self.accept()
        entry = json.loads((self.state / 'authorized/entries' / (proof['entry']['id'] + '.json')).read_text())
        retained = self.state / 'authorized/artifacts' / (entry['input'] + '.db.gz')
        self.write_private(retained, gzip.compress(b'changed retained input', mtime=0))
        for historical in (False, True):
            with self.subTest(historical=historical), self.assertRaisesRegex(Refused, 'retained_database_changed'):
                self.proof(expected=proof, historical=historical)

    def test_changed_reference_and_plan_bytes_are_refused(self):
        proof = self.accept()
        changed = copy.deepcopy(proof)
        changed['prepared_sha256'] = 'f' * 64
        with self.assertRaisesRegex(Refused, 'reference_changed'):
            self.proof(expected=changed)
        self.write_private(self.plan_path, self.plan_path.read_bytes() + b'\n')
        with self.assertRaisesRegex(Refused, 'acceptance_missing'):
            self.proof(expected=proof, historical=True)

    def test_historical_lookup_requires_exact_reference_and_owned_stage(self):
        self.accept()
        with self.assertRaisesRegex(Refused, 'reference_required'):
            self.proof(historical=True)
        with self.assertRaisesRegex(Refused, 'stage_changed'):
            updates.retained_plan_acceptance(self.root, self.plan_path, manager=self.manager)

    def test_nested_read_reuses_owner_locks_and_nested_mutation_is_refused(self):
        proof = self.accept()
        with updates._locked(self.manager):
            with patch.object(updates, '_locked', side_effect=AssertionError('must reuse current owner')):
                result = updates.retained_plan_acceptance(self.stage, self.plan_path, expected=proof)
                self.assertEqual(result, proof)
            with self.assertRaisesRegex(Refused, 'nested_integrity_mutation'):
                self.prepare_update()
        self.assertIsNone(updates._LOCK_CONTEXT.get())

    def test_nested_read_refuses_a_different_manager(self):
        proof = self.accept()
        with updates._locked(self.manager):
            with self.assertRaisesRegex(Refused, 'lock_owner_changed'):
                updates.retained_plan_acceptance(self.stage, self.plan_path, manager=self.fresh(), expected=proof)

    def test_verified_history_is_chronological_and_read_only(self):
        proof = self.accept()
        before = {str(path): path.read_bytes() for path in self.state.rglob('*') if path.is_file()}
        history = updates.accepted_plan_history(manager=self.manager)
        self.assertEqual(history['head'], proof['entry'])
        self.assertEqual(history['database_sha256'], proof['database_sha256'])
        self.assertEqual(history['current_database_sha256'], proof['database_sha256'])
        self.assertEqual(len(history['history']), 1)
        row = history['history'][0]
        self.assertEqual(row['entry_ref'], proof['entry'])
        self.assertEqual(row['plan'], self.plan)
        self.assertEqual(row['prepared']['release'], str(self.stage))
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.state.rglob('*') if path.is_file()})

    def test_verified_history_does_not_adopt_unknown_current_database(self):
        self.accept()
        self.write_private(self.state / 'aide.db.gz', gzip.compress(b'unknown', mtime=0))
        with self.assertRaisesRegex(Refused, 'current_database_changed'):
            updates.accepted_plan_history(manager=self.manager)

    def test_pending_update_cannot_be_read_as_an_ordinary_boot_owner(self):
        self.prepare_update()
        self.activate()
        with patch.object(updates, '_complete', side_effect=OSError('interrupted update')):
            with self.assertRaises(OSError): self.accept_update()
        for owner in (None, self.stage):
            with self.subTest(owner=owner), self.assertRaisesRegex(Refused, 'history_pending_owner_required'):
                updates.accepted_plan_history(manager=self.manager, allow_pending_owner=owner)
