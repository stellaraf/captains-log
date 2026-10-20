"""Actual durable files with injected REST failures; live rollback is separate."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager.common import Refused
from nebulalog_manager import identity_sessions as sessions


class SessionCutoffJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.config = self.root / 'config'; self.config.mkdir(mode=0o700)
        self.api = self.config / 'api.env'
        self.original = b'CH_PASSWORD=unchanged=secret\nOIDC_CLIENT_ID=nebulalog\nOIDC_ISSUER=https://test/realms/nebulalog\n'
        self.api.write_bytes(self.original); self.api.chmod(0o600)
        self.installation = 'a' * 32; self.operation = 'b' * 64
        self.cutoff = 1792480000
        self.realm = {'id': 'realm-owned', 'realm': 'nebulalog', 'notBefore': 0,
                      'attributes': {'nebulalog.installation-id': self.installation}}
        self.calls = []
        self.journal = sessions.SessionCutoffJournal(self.state, self.installation)
        self.initialize = True

    def call(self, path, method='GET', body=None):
        self.calls.append((path, method, body))
        if method == 'GET': return copy.deepcopy(self.realm)
        if method == 'PUT': self.realm.update(body)
        if path == 'logout-all': self.realm['notBefore'] = self.cutoff + 10

    def reconcile(self, call=None, minimum=None, fence=None, operation=None):
        result = self.journal.reconcile(call or self.call, operation or self.operation,
            self.api, minimum or self.cutoff, fence or (lambda op: op == self.operation),
            initialize=self.initialize)
        self.initialize = False
        return result

    def test_persists_effective_floor_and_preserves_customer_bytes(self):
        result = self.reconcile()
        self.assertEqual(result['token_not_before'], self.cutoff + 10)
        self.assertFalse(result['maintenance_release_authorized'])
        self.assertTrue(result['fresh_login_required'])
        self.assertEqual(self.api.read_bytes(), self.original + f'OIDC_TOKEN_NOT_BEFORE={self.cutoff+10}\n'.encode())
        record = json.loads(self.journal.path.read_text())
        self.assertEqual(record['floor'], self.cutoff + 10)
        self.assertEqual(record['phase'], 'api')
        self.assertEqual(self.journal.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.api.stat().st_mode & 0o777, 0o600)

    def test_database_and_configuration_rollback_does_not_lower_retained_floor(self):
        self.reconcile()
        self.realm['notBefore'] = 0
        self.api.write_bytes(self.original)
        result = self.reconcile(minimum=self.cutoff-100)
        self.assertEqual(result['token_not_before'], self.cutoff + 10)
        self.assertEqual(self.realm['notBefore'], self.cutoff + 10)

    def test_lost_logout_response_retains_intent_and_replans_newer_floor(self):
        def lost(path, method='GET', body=None):
            value = self.call(path, method, body)
            if path == 'logout-all': raise OSError('Lost committed logout response')
            return value
        with self.assertRaises(OSError): self.reconcile(lost)
        self.assertEqual(json.loads(self.journal.path.read_text())['phase'], 'intent')
        self.assertEqual(self.api.read_bytes(), self.original)
        self.initialize = False
        self.assertEqual(self.reconcile()['token_not_before'], self.cutoff + 10)

    def test_lost_api_write_response_reconciles_without_changing_other_values(self):
        actual = sessions._atomic_private_bytes
        def lost(path, body, **kwargs):
            actual(path, body, **kwargs)
            raise OSError('Lost API write acknowledgement')
        with patch.object(sessions, '_atomic_private_bytes', lost), self.assertRaises(OSError):
            self.reconcile()
        self.assertEqual(json.loads(self.journal.path.read_text())['phase'], 'realm')
        self.initialize = False
        self.assertEqual(self.reconcile()['token_not_before'], self.cutoff + 10)
        self.assertEqual(self.api.read_bytes().count(b'OIDC_TOKEN_NOT_BEFORE='), 1)

    def test_replacement_and_retry_preserve_extended_attributes_and_group(self):
        os.setxattr(self.api, 'user.captainslog-test', b'customer metadata\0binary')
        os.chown(self.api, 0, 12345)
        original_inode = self.api.stat().st_ino
        self.reconcile()
        self.assertNotEqual(self.api.stat().st_ino, original_inode)
        self.reconcile()
        self.assertEqual(os.getxattr(self.api, 'user.captainslog-test'), b'customer metadata\0binary')
        self.assertEqual(self.api.stat().st_gid, 12345)
        self.assertEqual(self.api.stat().st_mode & 0o777, 0o600)

    def test_posix_acl_survives_atomic_replacement(self):
        import errno
        import struct
        # Linux POSIX ACL v2: named user permissions remain masked off by 0600.
        # Retain the actual ACL, not merely the equivalent permission bits.
        entries = [(1, 6, 0xffffffff), (2, 4, 12345), (4, 0, 0xffffffff),
                   (16, 0, 0xffffffff), (32, 0, 0xffffffff)]
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *e) for e in entries)
        try:
            os.setxattr(self.api, 'system.posix_acl_access', acl)
        except OSError as error:
            if error.errno in {errno.ENOSYS, errno.ENOTSUP}:
                self.skipTest('fixture filesystem lacks POSIX ACL support')
            raise
        self.assertEqual(self.api.stat().st_mode & 0o777, 0o600)
        self.reconcile()
        self.assertEqual(os.getxattr(self.api, 'system.posix_acl_access'), acl)
        self.assertEqual(self.api.stat().st_mode & 0o777, 0o600)

    def test_metadata_copy_failure_keeps_original_and_recoverable_journal(self):
        os.setxattr(self.api, 'user.captainslog-test', b'retain')
        inode = self.api.stat().st_ino
        with patch('os.setxattr', side_effect=PermissionError('metadata write denied')):
            with self.assertRaises(PermissionError):
                self.reconcile()
        self.assertEqual(self.api.read_bytes(), self.original)
        self.assertEqual(self.api.stat().st_ino, inode)
        self.assertEqual(os.getxattr(self.api, 'user.captainslog-test'), b'retain')
        self.assertEqual(json.loads(self.journal.path.read_text())['phase'], 'realm')
        self.assertEqual(list(self.config.glob('.session-cutoff-*')), [])
        self.initialize = False
        self.reconcile()
        self.assertEqual(os.getxattr(self.api, 'user.captainslog-test'), b'retain')

    def test_unacknowledged_metadata_copy_never_replaces_original(self):
        os.setxattr(self.api, 'user.captainslog-test', b'retain')
        with patch('os.setxattr', return_value=None):
            with self.assertRaisesRegex(Refused, 'metadata did not persist'):
                self.reconcile()
        self.assertEqual(self.api.read_bytes(), self.original)
        self.assertEqual(json.loads(self.journal.path.read_text())['phase'], 'realm')

    def test_concurrent_metadata_change_is_not_overwritten(self):
        os.setxattr(self.api, 'user.captainslog-test', b'before')
        original_set = os.setxattr
        def changed(fd, key, value):
            original_set(fd, key, value)
            original_set(self.api, key, b'changed')
        with patch('os.setxattr', changed):
            with self.assertRaisesRegex(Refused, 'changed during'):
                self.reconcile()
        self.assertEqual(self.api.read_bytes(), self.original)
        self.assertEqual(os.getxattr(self.api, 'user.captainslog-test'), b'changed')

    def test_metadata_enumeration_failure_does_not_replace_original(self):
        with patch('os.listxattr', side_effect=OSError('metadata unavailable')):
            with self.assertRaises(OSError):
                self.reconcile()
        self.assertEqual(self.api.read_bytes(), self.original)
        self.assertEqual(list(self.config.glob('.session-cutoff-*')), [])

    def test_durable_intent_write_failure_prevents_rest_mutation(self):
        with patch('nebulalog_manager.common.atomic_json', side_effect=OSError('disk full')), self.assertRaises(OSError):
            self.reconcile()
        self.assertFalse(any(method != 'GET' for _, method, _ in self.calls))
        self.assertEqual(self.api.read_bytes(), self.original)

    def test_fence_loss_before_api_write_leaves_persisted_floor(self):
        def fenced(op):
            return not self.journal.path.exists() or json.loads(self.journal.path.read_text())['phase'] != 'realm'
        with self.assertRaises(Refused): self.reconcile(fence=fenced)
        self.assertEqual(json.loads(self.journal.path.read_text())['phase'], 'realm')
        self.assertEqual(self.api.read_bytes(), self.original)

    def test_changed_customer_configuration_is_not_adopted(self):
        self.reconcile(); self.calls.clear()
        self.api.write_bytes(self.api.read_bytes().replace(b'unchanged=secret', b'changed'))
        with self.assertRaises(Refused): self.reconcile()
        self.assertEqual(self.calls, [])

    def test_changed_configuration_during_rest_is_not_overwritten(self):
        def concurrent(path, method='GET', body=None):
            result = self.call(path, method, body)
            if path == 'logout-all': self.api.write_bytes(self.original.replace(b'unchanged', b'changed'))
            return result
        with self.assertRaises(Refused): self.reconcile(concurrent)
        self.assertIn(b'changed=secret', self.api.read_bytes())

    def test_missing_journal_is_not_silently_reinitialized_after_rollback(self):
        self.reconcile(); self.journal.path.unlink(); self.calls.clear()
        self.realm['notBefore'] = 0; self.api.write_bytes(self.original)
        with self.assertRaisesRegex(Refused, 'Missing session journal'): self.reconcile()
        self.assertEqual(self.calls, [])

    def test_unsafe_paths_and_modes_refused(self):
        self.api.chmod(0o644)
        with self.assertRaises(Refused): self.reconcile()
        self.api.chmod(0o600); target=self.config/'other.env'; target.write_bytes(self.original); target.chmod(0o600)
        self.api.unlink(); self.api.symlink_to(target)
        with self.assertRaises(Refused): self.reconcile()
        self.assertEqual(self.calls, [])

    def test_duplicate_cutoff_refused_without_rest_mutation(self):
        self.api.write_bytes(self.original + f'OIDC_TOKEN_NOT_BEFORE={self.cutoff}\nOIDC_TOKEN_NOT_BEFORE={self.cutoff}\n'.encode())
        with self.assertRaises(Refused): self.reconcile()
        self.assertEqual(self.calls, [])

    def test_foreign_realm_or_record_refused(self):
        self.realm['attributes']['nebulalog.installation-id'] = 'foreign'
        with self.assertRaises(Refused): self.reconcile()
        self.assertFalse(self.journal.path.exists())
        self.realm['attributes']['nebulalog.installation-id'] = self.installation
        self.reconcile(); self.realm['id'] = 'another-realm'
        with self.assertRaises(Refused): self.reconcile()

    def test_other_operation_cannot_take_over_incomplete_recovery(self):
        with patch.object(sessions, '_atomic_private_bytes', side_effect=OSError('disk full')), self.assertRaises(OSError):
            self.reconcile()
        with self.assertRaises(Refused):
            self.reconcile(operation='c'*64, fence=lambda op: True)

    def test_completed_operation_allows_next_operation_without_lowering_floor(self):
        self.reconcile()
        result = self.reconcile(operation='c'*64, fence=lambda op: True)
        self.assertEqual(result['token_not_before'], self.cutoff+10)
        self.assertEqual(json.loads(self.journal.path.read_text())['operation'], 'c'*64)

    def test_new_authorized_operation_binds_changed_customer_settings(self):
        self.reconcile()
        self.api.write_bytes(self.api.read_bytes().replace(b'unchanged=secret', b'new-secret'))
        result = self.reconcile(operation='c'*64, fence=lambda op: op == 'c'*64)
        self.assertEqual(result['token_not_before'], self.cutoff+10)
        self.assertIn(b'CH_PASSWORD=new-secret\n', self.api.read_bytes())
        self.assertEqual(json.loads(self.journal.path.read_text())['operation'], 'c'*64)

    def test_replaced_journal_or_api_hardlink_is_refused(self):
        self.reconcile()
        duplicate=self.config/'api-copy.env';os.link(self.api,duplicate)
        with self.assertRaises(Refused): self.reconcile()
        duplicate.unlink()
        self.journal.path.chmod(0o644)
        with self.assertRaises(Refused): self.reconcile()

    def test_duplicate_journal_fields_are_refused(self):
        self.reconcile()
        raw=self.journal.path.read_text().replace('"schema": 1', '"schema": 1, "schema": 1')
        self.journal.path.write_text(raw)
        with self.assertRaises(Refused): self.reconcile()


    def capture(self, *, resume=False, operation=None, observe=None, fence=None):
        return self.journal.capture_restore(observe or (lambda: {
            'realm_id': self.realm['id'], 'installation_id': self.installation,
            'floor': self.realm['notBefore']}), operation or self.operation, self.api,
            self.cutoff, fence or (lambda op: True), resume=resume)

    def test_pre_restore_capture_survives_database_and_api_rollback(self):
        self.realm['notBefore'] = self.cutoff + 600
        captured = self.capture()
        self.assertEqual(captured['floor'], self.cutoff + 600)
        self.assertEqual(self.api.read_bytes(), self.original)
        self.assertFalse(self.journal.path.exists())
        self.realm['notBefore'] = 0
        result = self.reconcile()
        self.assertEqual(result['token_not_before'], self.cutoff + 600)
        self.assertEqual(self.realm['notBefore'], self.cutoff + 600)
        self.assertFalse(result['maintenance_release_authorized'])

    def test_restore_resume_never_queries_a_partially_replaced_database(self):
        captured = self.capture()
        self.api.unlink()
        def unavailable(): raise AssertionError('Partial restore must not observe the DB')
        self.assertEqual(self.capture(resume=True, observe=unavailable), captured)
        with self.assertRaises(Refused): self.capture(resume=True, operation='f'*64)
        (self.state/'restore-cutoff.json').unlink()
        with self.assertRaises(Refused): self.capture(resume=True, observe=unavailable)

    def test_new_restore_retains_greatest_observed_floor(self):
        self.realm['notBefore'] = self.cutoff + 1000
        self.capture()
        self.realm['notBefore'] = 0
        self.assertEqual(self.capture(operation='c'*64)['floor'], self.cutoff + 1000)

    def test_capture_write_failure_cannot_authorize_replacement(self):
        with patch('nebulalog_manager.common.atomic_json', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.capture()
        self.assertFalse((self.state/'restore-cutoff.json').exists())
        with self.assertRaises(Refused): self.capture(resume=True)

    def test_capture_lost_write_acknowledgement_reuses_durable_floor(self):
        from nebulalog_manager.common import atomic_json
        def lost(path, value):
            atomic_json(path, value)
            raise OSError('lost persisted capture acknowledgement')
        self.realm['notBefore'] = self.cutoff + 900
        with patch('nebulalog_manager.common.atomic_json', side_effect=lost):
            with self.assertRaises(OSError): self.capture()
        self.realm['notBefore'] = 0
        self.assertEqual(self.capture()['floor'], self.cutoff + 900)

    def test_capture_foreign_identity_and_malformed_state_are_refused(self):
        self.capture()
        path = self.state/'restore-cutoff.json'; original = path.read_bytes()
        for key, value in [('installation_id','f'*32), ('operation','foreign'),
                           ('floor',True), ('realm_id','x\' OR true'), ('api_path','/tmp/foreign')]:
            record=json.loads(original); record[key]=value; path.write_text(json.dumps(record))
            with self.subTest(key=key), self.assertRaises(Refused): self.capture(resume=True)
        path.write_bytes(original);self.realm['id']='foreign'
        with self.assertRaises(Refused): self.reconcile()
        self.assertFalse(any(method != 'GET' for _,method,_ in self.calls))

    def test_capture_requires_fence_before_observation_and_after_persistence(self):
        with self.assertRaises(Refused): self.capture(fence=lambda op: False)
        self.assertFalse((self.state/'restore-cutoff.json').exists())
        with self.assertRaises(Refused):
            self.capture(fence=lambda op: not (self.state/'restore-cutoff.json').exists())
        self.assertTrue((self.state/'restore-cutoff.json').exists())

    def test_capture_permissions_and_links_are_not_accepted(self):
        self.capture();path=self.state/'restore-cutoff.json'
        path.chmod(0o644)
        with self.assertRaises(Refused): self.capture(resume=True)
        path.chmod(0o600);os.link(path,self.state/'duplicate')
        with self.assertRaises(Refused): self.capture(resume=True)


if __name__ == '__main__': unittest.main()
