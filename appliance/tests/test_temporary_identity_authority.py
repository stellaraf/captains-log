"""Private durable authority state; actual vendor/SQL/HTTP coverage is separate."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager.common import Refused
from nebulalog_manager.identity_sessions import TemporaryIdentityAuthority


class Backend:
    def __init__(self, installation):
        self.installation = installation
        self.client = None; self.secret = None; self.orphans = []
        self.creations = self.deletions = self.starts = 0
        self.disabled = True; self.held = True; self.lost_create = self.lost_delete = False
        self.orphan_on_delete = False; self.accept_deleted_secret = False
        self.accept_deleted_token = False; self.foreign_token = False
        self.server_running = True; self.other_temporary_clients = []; self.settled_ok = True

    def settled(self, receipt): return self.settled_ok
    def fenced(self, operation): return self.held
    def observe(self, name, uid):
        return {'installation_id':self.installation,'realm_id':'realm-owned','bootstrap_id':'bootstrap-owned',
                'bootstrap_disabled':self.disabled,'other_temporary_clients':self.other_temporary_clients,'client':copy.deepcopy(self.client),
                'service_users':[self.client['service_user_id']] if self.client else self.orphans}
    def quiesce(self, name): self.server_running = False
    def create(self, name, secret):
        assert not self.server_running
        self.creations += 1; self.secret = secret
        self.client = {'id':'client-owned','client_name':name,'service_user_id':'service-owned','realm':'master',
                       'temporary':True,'enabled':True,'public':False,'service_accounts':True,'standard_flow':False,
                       'implicit_flow':False,'password_grant':False,'admin_role':True}
        if self.lost_create:
            self.lost_create = False
            raise OSError('Lost committed create response')
    def start(self): self.server_running = True; self.starts += 1
    def authenticate(self, name, secret):
        assert self.server_running and self.client and name==self.client['client_name'] and secret==self.secret
        claims={'sub':'service-owned' if not self.foreign_token else 'foreign','azp':name}
        payload=base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
        return 'e30.'+payload+'.signature'
    def probe(self, token, installation, realm): return installation==self.installation and realm=='realm-owned'
    def delete(self, token, cid):
        assert self.client and self.client['id']==cid
        if self.orphan_on_delete: self.orphans=[self.client['service_user_id']]
        self.deletions += 1; self.client=None
        if self.lost_delete:
            self.lost_delete=False
            raise OSError('Lost committed delete response')
    def credentials_refused(self, name, secret): return self.client is None and not self.accept_deleted_secret
    def token_refused(self, token): return self.client is None and not self.accept_deleted_token


class TemporaryAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.installation='a'*32;self.operation='b'*64
        self.authority=TemporaryIdentityAuthority(self.root,self.installation)
        self.backend=Backend(self.installation);self.work_calls=0
    def work(self, token):
        self.work_calls += 1
        return {'installation_id':self.installation,'operation':self.operation,'token_not_before':1792480000,
                'api_sha256':'c'*64,'api_configuration_sha256':'d'*64,'phase':'api',
                'maintenance_release_authorized':False,'fresh_login_required':True}
    def run_authority(self, initialize=True, work=None):
        return self.authority.run(self.operation,self.backend,work or self.work,initialize=initialize)
    def record(self): return json.loads(self.authority.path.read_text())

    def test_complete_lifecycle_erases_credentials_only_after_removal(self):
        result=self.run_authority();record=self.record()
        self.assertEqual((self.backend.creations,self.backend.deletions,self.work_calls),(1,1,1))
        self.assertEqual(record['phase'],'removed');self.assertIsNone(record['secret']);self.assertIsNone(record['token'])
        self.assertFalse(result['maintenance_release_authorized'])
        self.assertEqual(self.authority.path.stat().st_mode & 0o777,0o600)
        self.run_authority(False)
        self.assertEqual((self.backend.creations,self.backend.deletions,self.work_calls),(1,1,1))

    def test_lost_creation_response_reuses_owned_identity(self):
        self.backend.lost_create=True
        with self.assertRaises(OSError): self.run_authority()
        before=self.record();self.assertEqual(before['phase'],'creating');self.assertTrue(before['secret'])
        self.authority=TemporaryIdentityAuthority(self.root,self.installation)
        self.run_authority(False)
        self.assertEqual(self.backend.creations,1)
        self.assertEqual(self.record()['client_name'],before['client_name'])

    def test_lost_deletion_response_does_not_repeat_work_or_recreate(self):
        self.backend.lost_delete=True
        with self.assertRaises(OSError): self.run_authority()
        self.assertEqual(self.record()['phase'],'removing');self.assertTrue(self.record()['secret'])
        self.run_authority(False)
        self.assertEqual((self.backend.creations,self.backend.deletions,self.work_calls),(1,1,1))
        self.assertEqual(self.record()['phase'],'removed')

    def test_failed_work_retains_owned_recovery_authority(self):
        def fail(token): raise OSError('work interrupted')
        with self.assertRaises(OSError): self.run_authority(work=fail)
        self.assertEqual(self.record()['phase'],'ready');self.assertEqual(self.backend.deletions,0)
        self.backend.server_running=False
        self.run_authority(False);self.assertEqual(self.backend.creations,1)

    def test_missing_record_cannot_initialize_during_recovery(self):
        with self.assertRaisesRegex(Refused,'Missing'): self.run_authority(False)
        self.assertEqual(self.backend.creations,0)

    def test_foreign_installation_or_enabled_bootstrap_refused(self):
        self.backend.installation='foreign'
        with self.assertRaises(Refused): self.run_authority()
        self.backend.installation=self.installation;self.backend.disabled=False
        with self.assertRaises(Refused): self.run_authority()
        self.assertEqual(self.backend.creations,0)

    def test_changed_vendor_client_not_adopted_after_uncertain_create(self):
        self.backend.lost_create=True
        with self.assertRaises(OSError): self.run_authority()
        self.backend.client['temporary']=False
        with self.assertRaises(Refused): self.run_authority(False)
        self.assertEqual(self.work_calls,0)

    def test_foreign_token_refused_before_work(self):
        self.backend.foreign_token=True
        with self.assertRaises(Refused): self.run_authority()
        self.assertEqual(self.work_calls,0)

    def test_wrong_secret_does_not_adopt_existing_client(self):
        self.backend.lost_create=True
        with self.assertRaises(OSError): self.run_authority()
        self.backend.secret='different'
        with self.assertRaises(AssertionError): self.run_authority(False)
        self.assertEqual(self.work_calls,0)

    def test_other_operation_cannot_take_over_incomplete_authority(self):
        self.backend.lost_create=True
        with self.assertRaises(OSError): self.run_authority()
        self.operation='e'*64
        with self.assertRaises(Refused): self.run_authority(False)
        self.assertEqual(self.backend.creations,1)

    def test_new_operation_after_removal_uses_new_credentials(self):
        self.run_authority();old=self.record()['client_name'];self.operation='e'*64
        self.run_authority(False)
        self.assertNotEqual(self.record()['client_name'],old)
        self.assertEqual((self.backend.creations,self.backend.deletions),(2,2))

    def test_orphan_or_usable_credentials_do_not_allow_redaction(self):
        for attr in ('orphan_on_delete','accept_deleted_secret','accept_deleted_token'):
            with self.subTest(attr=attr):
                if self.authority.path.exists(): self.authority.path.unlink()
                self.backend=Backend(self.installation);setattr(self.backend,attr,True)
                with self.assertRaises(Refused): self.run_authority()
                self.assertEqual(self.record()['phase'],'removing');self.assertTrue(self.record()['secret'])

    def test_fence_loss_prevents_account_creation(self):
        self.backend.held=False
        with self.assertRaises(Refused): self.run_authority()
        self.assertEqual(self.backend.creations,0)

    def test_durable_write_failure_prevents_account_creation(self):
        with patch('nebulalog_manager.common.atomic_json',side_effect=OSError('disk full')),self.assertRaises(OSError):
            self.run_authority()
        self.assertEqual(self.backend.creations,0)

    def test_unbounded_work_receipt_is_not_retained_or_reported_complete(self):
        def extra(token): return {**self.work(token),'secret':'must not be persisted'}
        with self.assertRaises(Refused): self.run_authority(work=extra)
        self.assertEqual(self.record()['phase'],'ready');self.assertIsNone(self.record()['work_receipt'])
        self.assertNotIn('must not be persisted',self.authority.path.read_text())

    def test_removed_actor_reappearance_is_not_ignored(self):
        self.run_authority();record=self.record()
        self.backend.server_running=False;self.backend.create(record['client_name'],'f'*64)
        with self.assertRaises(Refused): self.run_authority(False)

    def test_untracked_temporary_actor_prevents_new_authority(self):
        self.backend.other_temporary_clients=['cl-maint-'+('f'*32)]
        with self.assertRaises(Refused): self.run_authority()
        self.assertEqual(self.backend.creations,0)

    def test_completed_receipt_is_not_reused_after_live_state_changes(self):
        self.run_authority();self.backend.settled_ok=False
        with self.assertRaisesRegex(Refused,'live state'): self.run_authority(False)
        self.assertEqual(self.backend.creations,1)


if __name__=='__main__': unittest.main()
