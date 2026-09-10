"""Real AIDE 0.19.2 scanner over isolated fixtures, never an enrolled guest.

Storage identity, package/source facts and runtime-plan binding are fixture inputs.
Native installed AIDE and actual restorecon commands execute under FIPS/SELinux. AIDE reports/databases and Linux xattrs are measured by real
tools. Factory enrollment and whole-guest health are not qualified by this runner.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

REAL_POPEN = subprocess.Popen
from test_aide_updates import AuthorizedAideTests
from nebulalog_manager import aide, aide_updates

REAL_METADATA = aide_updates._metadata
ARTIFACTS = Path(os.environ['CAPTAINS_LOG_TEST_RECEIPTS']).resolve()
assert ARTIFACTS.is_absolute() and not ARTIFACTS.exists()
AIDE_BINARY = '/usr/sbin/aide'
assert Path('/proc/sys/crypto/fips_enabled').read_text().strip() == '1'
assert subprocess.check_output(['/usr/sbin/getenforce'], text=True).strip() == 'Enforcing'
ARTIFACTS.mkdir(mode=0o700, exist_ok=True)


class RealScannerTests(AuthorizedAideTests):
    def setUp(self):
        super().setUp()
        self.number = 0
        self.output = ARTIFACTS / self._testMethodName
        self.output.mkdir(mode=0o700)
        policy = 'NEBULA = ftype+p+i+l+n+u+g+s+m+c+acl+selinux+xattrs+sha512\n'
        policy += ''.join(str(self.root / name) + '$ NEBULA\n' for name in ('managed.conf', 'host-selection.json', 'unrelated.conf', 'extra.conf'))
        policy += str(self.root / 'candidate-generation') + '(/|$) NEBULA\n'
        self.write_private(self.policy, policy.encode())
        self.values['policy_sha256'] = hashlib.sha256(policy.encode()).hexdigest()

    def authorized_fixture(self):
        super().authorized_fixture()
        actual = patch.object(aide_updates, '_metadata', REAL_METADATA)
        actual.start()
        self.addCleanup(actual.stop)

    def scan_runner(self, argv, *, tmpdir, **kwargs):
        if argv[0] == '/usr/sbin/restorecon':
            with patch('subprocess.Popen', REAL_POPEN):
                result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            return aide.Result(result.returncode, result.stdout, result.stderr)
        self.assertEqual(argv[0], '/usr/sbin/aide')
        action = argv[-1].removeprefix('--')
        config = Path(argv[1].split('=', 1)[1])
        options = dict(line.split('=', 1) for line in config.read_text().splitlines() if '=' in line and not line.startswith('#'))
        source, output = [Path(options[key].removeprefix('file:')) for key in ('database_in', 'database_out')]
        if action != 'config-check':
            self.scan_calls.append(action)
        with patch('subprocess.Popen', REAL_POPEN):
            result = subprocess.run([AIDE_BINARY, *argv[1:]], capture_output=True, text=True, timeout=60)
        if output.is_file():
            output.chmod(0o600)
        self.number += 1
        name = f'{self.number:03}-{action}'
        (self.output / (name + '.stdout')).write_text(result.stdout)
        (self.output / (name + '.stderr')).write_text(result.stderr)
        (self.output / (name + '.json')).write_text(json.dumps({'argv': [AIDE_BINARY, *argv[1:]], 'exit_code': result.returncode}))
        if self.scan_hook and action != 'config-check':
            self.scan_hook(action, source, output)
        return aide.Result(result.returncode, result.stdout, result.stderr)

    def test_real_xattr_drift_refused(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        os.setxattr(self.runtime, 'user.captains-log-fixture', b'unexpected metadata', follow_symlinks=False)
        with self.assertRaisesRegex(aide.Refused, 'acl_xattrs_or_selinux_changed'):
            self.accept_update()
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)


names = [
    'test_authorized_forward_and_rollback_preserve_original_and_publish_fresh_checks',
    'test_authorized_update_refuses_unrelated_race_in_fresh_check',
    'test_authorized_update_refuses_unrelated_report_and_never_runs_init',
    'test_authorized_crash_after_database_cas_recovers_exact_entry',
    'test_authorized_scanning_crash_retries_new_output_without_reinitializing',
    'test_real_xattr_drift_refused',
]
result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(RealScannerTests(name) for name in names))
receipt = {'scope': 'Rocky native AIDE scanner and SELinux restorecon with fixture storage/source/plan evidence',
           'aide_version': '0.19.2', 'tests_run': result.testsRun, 'failures': len(result.failures),
           'errors': len(result.errors), 'skipped': len(result.skipped), 'passed': result.wasSuccessful()}
(ARTIFACTS / 'qualification.json').write_text(json.dumps(receipt, indent=2) + '\n')
raise SystemExit(0 if result.wasSuccessful() else 1)
