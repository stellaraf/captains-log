"""Signed manager transactions; lifecycle-produced inventory/host receipts are fixtures."""
import copy
import json
from pathlib import Path
from unittest.mock import patch

from nebulalog_manager import host_dispatch as dispatch, updates
from nebulalog_manager.common import Refused, atomic_json
from test_host_updates import HostUpdateFixture, PowerLoss
from test_assemble_release import content_archive
from nebulalog_manager.baseline import ContentUpdate


class ContentTransactionTests(HostUpdateFixture):
    def setUp(self):
        super().setUp()
        self.content_identity={'version':'sha256:'+'d'*64,'generation':'b'*64,'policy_sha256':'c'*64,
            'engine':{'scanner_nevra':'openscap-scanner-1.3.14-1.el9.x86_64','version_sha256':'e'*64}}
        self.omit_content=False
        self.wrong_content=False

    def hook(self,pin,name,stage):
        tx,manifest=dispatch.transaction_binding(stage)
        if name=='update-preflight':
            if manifest.get('content_enrollment'):
                atomic_json(stage/'content-enrollment.json',{'identity':self.content_identity})
            if 'baseline' in manifest['components']:
                atomic_json(stage/'content-plan.json',{'after_policy_sha256':self.content_identity['policy_sha256']})
        finish=dispatch.HookJournal.finish
        def terminal(journal,ticket,outcome,*,result=None):
            if name=='update-health' and result is not None and not self.omit_content and ('baseline' in manifest['components'] or manifest.get('content_enrollment')):
                result['content']=copy.deepcopy(self.content_identity)
                if self.wrong_content:result['content']['policy_sha256']='f'*64
            return finish(journal,ticket,outcome,result=result)
        with patch.object(dispatch.HookJournal,'finish',terminal):
            return super().hook(pin,name,stage)

    def enroll(self):
        self.manifest['content_enrollment']='selected-baseline-v1';self.sign()

    def baseline_release(self):
        self.enroll();self.install();self.initial=copy.deepcopy(self.manager.status()['current'])
        self.old=self.new
        self.manifest.pop('content_enrollment')
        self.manifest['sequence']+=1;self.manifest['version']='0.1.2'
        self.manifest['components']['host']['from_versions']=[self.old['version']]
        self.manifest['components']['nebulalog'].update(version='0.1.2',from_versions=['0.1.1'])
        self.calls.clear()
        path=self.bundle/'baseline-content.tar';descriptor=content_archive(path)
        self.manifest['components']['baseline']={'version':'1.2.3','from_versions':[self.content_identity['version']],
            'artifact':path.name,'rollback_safe':True,'content_schema':1,'descriptor_sha256':ContentUpdate.digest(ContentUpdate.encoded(descriptor))}
        self.manifest['artifacts'].append({'name':path.name,'bytes':path.stat().st_size,'sha256':ContentUpdate.digest(path.read_bytes())})
        self.content_identity['version']='1.2.3';self.sign()

    def test_normal_capability_release_precedes_later_explicit_enrollment(self):
        self.assertEqual(self.install()['state'],'committed')
        current=self.manager.status()['current'];self.assertNotIn('baseline',current['components'])
        # Next invocation is under the newly selected coordinator. Reusing the
        # same host generation is valid for an app+enrollment-only release.
        self.old=self.new
        self.manifest['sequence']+=1;self.manifest['version']='0.1.2'
        self.manifest['components']['host']['from_versions']=[self.old['version']]
        self.manifest['components']['nebulalog'].update(version='0.1.2',from_versions=['0.1.1'])
        original=(self.state/'initial-enrollment.json').read_bytes()
        self.enroll();self.assertEqual(self.install()['state'],'committed')
        self.assertEqual(self.manager.status()['current']['components']['baseline'],self.content_identity)
        self.assertEqual((self.state/'initial-enrollment.json').read_bytes(),original)

    def test_new_manager_refuses_missing_content_receipt_before_enrollment(self):
        self.enroll();self.omit_content=True
        with self.assertRaisesRegex(Refused,'previous application restored'):self.install()
        self.assertEqual(self.manager.status()['transaction']['state'],'rolled_back')
        self.assertNotIn('baseline',self.manager.status()['current']['components'])

    def test_content_commit_uses_measured_semver_and_rejects_wrong_identity(self):
        self.baseline_release();self.assertEqual(self.install()['state'],'committed')
        measured=self.manager.status()['current']['components']['baseline']
        self.assertEqual(measured,self.content_identity)
        self.assertNotIn('artifact',measured)

    def test_wrong_measured_policy_rolls_back_to_exact_prior_content_inventory(self):
        self.baseline_release();old=copy.deepcopy(self.initial['components']['baseline']);self.wrong_content=True
        with self.assertRaisesRegex(Refused,'previous application restored'):self.install()
        self.assertEqual(self.manager.status()['current']['components']['baseline'],old)
        self.assertIn('update-rollback',[call[0] for call in self.calls])

    def test_pointer_before_commit_journal_crash_recovers_prior_unenrolled_state(self):
        self.enroll();write=updates.atomic_json
        def interrupted(path,value):
            write(path,value)
            if path==self.state/'current.json' and 'baseline' in value.get('components',{}):raise PowerLoss()
        with patch.object(updates,'atomic_json',side_effect=interrupted),self.assertRaises(PowerLoss):self.install()
        self.assertEqual(self.manager.status()['transaction']['state'],'checking')
        self.assertIn('baseline',self.manager.status()['current']['components'])
        self.assertEqual(self.manager.recover(self.public)['state'],'rolled_back')
        self.assertNotIn('baseline',self.manager.status()['current']['components'])

    def test_baseline_archive_requires_prior_enrollment_before_any_hook(self):
        self.baseline_release();self.initial['components'].pop('baseline');atomic_json(self.state/'current.json',self.initial)
        with self.assertRaises(Refused):self.install()
        self.assertEqual(self.calls,[])
