"""Actual vendor AIDE cutoff recovery on a disposable native Rocky x86 guest.

Requires FIPS enabled, SELinux Enforcing, the pinned vendor AIDE package and
Python 3.14.8. Native restore admission, storage identity and source/plan binding
are test fixtures. No production enrollment or real customer files are changed.
Run only in an isolated test guest with CAPTAINS_LOG_TEST_RECEIPTS set to a new
private directory. This runner does not qualify the complete appliance lifecycle.
"""
import hashlib,json,os,pathlib,shutil,subprocess,sys,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/p) for p in ('appliance','appliance/adapters','appliance/tests','appliance/adapters/tests')]
assert pathlib.Path('/proc/sys/crypto/fips_enabled').read_text().strip()=='1'
assert subprocess.check_output(['/usr/sbin/getenforce'],text=True).strip()=='Enforcing'
assert subprocess.check_output(['rpm','-q','aide'],text=True).strip()=='aide-0.19.2-5.el9_8.1.x86_64'
assert sys.version_info[:3]==(3,14,8)
REAL_POPEN=subprocess.Popen
from test_aide_identity_cutoff import IdentityCutoffAideTests
from nebulalog_manager import aide,aide_updates
REAL_METADATA=aide_updates._metadata
out=pathlib.Path(os.environ['CAPTAINS_LOG_TEST_RECEIPTS']).resolve()
assert out.is_absolute() and not out.exists()
out.mkdir(mode=0o700)
class RealScanner(IdentityCutoffAideTests):
 def setUp(self):
  super().setUp();self.scan_number=0;self.case_out=out/self._testMethodName;self.case_out.mkdir(mode=0o700)
  policy='NEBULA = ftype+p+i+l+n+u+g+s+m+c+acl+selinux+xattrs+sha512\nNEBULADIR = ftype+p+i+u+g+acl+selinux+xattrs\n'
  for name in ('managed.conf','host-selection.json','configuration/runtime/api.env','unrelated-extra'):
   policy+=str(self.root/name)+'$ NEBULA\n'
  generation=str(self.root/('d'*64))
  policy+=generation+'(/.*)? d NEBULADIR\n'+generation+'(/.*)? f NEBULA\n'
  self.write_private(self.policy,policy.encode());self.values['policy_sha256']=hashlib.sha256(policy.encode()).hexdigest()
 def authorized_fixture(self,**kwargs):
  super().authorized_fixture(**kwargs)
  p=patch.object(aide_updates,'_metadata',REAL_METADATA);p.start();self.addCleanup(p.stop)
 def scan_runner(self,argv,*,tmpdir,**kwargs):
  if argv[0]=='/usr/sbin/restorecon':
   with patch('subprocess.Popen',REAL_POPEN):p=subprocess.run(argv,capture_output=True,text=True,timeout=60)
   return aide.Result(p.returncode,p.stdout,p.stderr)
  assert argv[0]=='/usr/sbin/aide'
  action=argv[-1].removeprefix('--');config=pathlib.Path(argv[1].split('=',1)[1])
  options=dict(line.split('=',1)for line in config.read_text().splitlines()if '='in line and not line.startswith('#'))
  source,target=[pathlib.Path(options[k].removeprefix('file:'))for k in ('database_in','database_out')]
  if action!='config-check':self.scan_calls.append(action)
  with patch('subprocess.Popen',REAL_POPEN):p=subprocess.run(argv,capture_output=True,text=True,timeout=60)
  if target.is_file():target.chmod(0o600)
  self.scan_number+=1
  (self.case_out/(str(self.scan_number)+'-'+action+'.json')).write_text(json.dumps({'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}))
  if self.scan_hook and action!='config-check':self.scan_hook(action,source,target)
  return aide.Result(p.returncode,p.stdout,p.stderr)
 def tearDown(self):
  if self.state.exists():shutil.copytree(self.state,self.case_out/'retained-evidence')
 def test_real_xattr_change_is_refused(self):
  self.cutoff_fixture();self.restore()
  os.setxattr(self.api,'user.captainslog-fixture',b'changed',follow_symlinks=False)
  with self.assertRaisesRegex(aide.Refused,'acl_xattrs_or_selinux_changed'):self.accept_update('rollback')
  self.assertEqual(self.scan_calls.count('update'),0)

names=[name for name in unittest.defaultTestLoader.getTestCaseNames(RealScanner)if name!='test_retained_output_metadata_change_is_rejected_even_if_scan_claims_clean']
result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(RealScanner(name)for name in names))
paths=['appliance/nebulalog_manager/aide_updates.py','appliance/nebulalog_manager/ordinary_boot_metadata.py','appliance/adapters/nebulalog_adapters/identity_maintenance.py','appliance/tests/test_aide_identity_cutoff.py','appliance/tests/test_aide_updates.py']
receipt={'passed':result.wasSuccessful(),'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'python':sys.version,'aide_package':subprocess.check_output(['rpm','-q','aide'],text=True).strip(),'guest_fips_flag_required':True,'selinux_enforcing_required':True,'full_appliance_qualified':False,'restore_admission_and_storage_injected':True,'actual_scanner':True,'actual_database_parser':True,'source':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest()for p in paths}}
(out/'scanner-result.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt));sys.exit(not result.wasSuccessful())
