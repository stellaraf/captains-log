import json
from pathlib import Path
import tempfile
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

from nebulalog_manager import bootloader as b
from nebulalog_manager.common import Refused


USERS = '#!/usr/bin/sh -e\nset superusers="root"\npassword_pbkdf2 root \\${GRUB2_PASSWORD}\n'
CONFIG = 'set superusers="root"\npassword_pbkdf2 root ${GRUB2_PASSWORD}\nblscfg\n'
HASH = 'grub.pbkdf2.sha512.100000.' + 'A' * 128 + '.' + 'B' * 128


class BootloaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.paths = b.Paths(self.root/'01_users', self.root/'user.cfg', self.root/'grub.cfg')
        self.paths.users.write_text(USERS)
        self.paths.config.write_text(CONFIG)
        self.calls = []
        self.fail = False
        for item in (patch.object(b, 'require_linux_root'), patch.object(b, '_tree'),
                     patch('nebulalog_manager.update_enrollment._tree')):
            item.start()
            self.addCleanup(item.stop)

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == 'grub2-mkpasswd-pbkdf2':
            self.assertEqual(kwargs['input'], b'test-password-value\ntest-password-value\n')
            return 'PBKDF2 hash of your password is ' + HASH
        if argv[0] == 'grub2-mkconfig':
            if self.fail:
                raise Refused('fixture interrupted')
            Path(argv[2]).write_text(CONFIG.replace('root', 'recovery-user'))
        return ''

    def enroll(self, password='test-password-value', **kwargs):
        return b.enroll(self.root, 'installation-1', 'recovery-user', password,
                        paths=self.paths, runner=self.runner, **kwargs)

    def test_enroll_preserves_boot_commands_and_keeps_password_out_of_journal(self):
        self.assertEqual(self.enroll()['state'], 'enrolled')
        record = (self.root/'bootloader-enrollment.json').read_text()
        self.assertNotIn('test-password-value', record)
        self.assertEqual(self.paths.credential.read_text(), 'GRUB2_PASSWORD=' + HASH + '\n')
        self.assertEqual(self.paths.credential.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.paths.config.read_text(), CONFIG.replace('root', 'recovery-user'))
        count = len(self.calls)
        self.enroll(password=None)
        self.assertEqual(len(self.calls), count)

    def test_interruption_resumes_exact_credential_without_new_password(self):
        self.fail = True
        with self.assertRaisesRegex(Refused, 'interrupted'):
            self.enroll()
        credential = self.paths.credential.read_bytes()
        self.assertEqual(json.loads((self.root/'bootloader-enrollment.json').read_text())['state'], 'recovery_required')
        self.fail = False
        self.enroll(password=None)
        self.assertEqual(self.paths.credential.read_bytes(), credential)
        self.assertEqual(sum(c[0]=='grub2-mkpasswd-pbkdf2' for c in self.calls), 1)

    def test_changed_configuration_and_other_installation_are_refused(self):
        self.enroll()
        with self.assertRaisesRegex(Refused, 'another installation'):
            b.enroll(self.root, 'different', 'recovery-user', paths=self.paths)
        self.paths.config.write_text('unrelated configuration')
        with self.assertRaisesRegex(Refused, 'differs'):
            self.enroll(password=None)
        self.assertEqual(self.paths.config.read_text(), 'unrelated configuration')

    def test_unknown_existing_credential_is_not_overwritten(self):
        self.paths.credential.write_text('existing credential')
        with self.assertRaisesRegex(Refused, 'existing GRUB credential'):
            self.enroll()
        self.assertFalse(self.calls)

    def test_unexpected_generated_configuration_keeps_original_boot_config(self):
        original = self.runner
        def runner(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv[0] == 'grub2-mkconfig':
                Path(argv[2]).write_text('different kernel parameters')
            return result
        self.runner = runner
        with self.assertRaisesRegex(Refused, 'beyond recovery identity'):
            self.enroll()
        self.assertEqual(self.paths.config.read_text(), CONFIG)

    def test_invalid_password_does_not_mutate_boot_files(self):
        for password in ('short', 'with whitespace here', 'nonascii-password-\u2603', None):
            with self.subTest(password=password), self.assertRaises(Refused):
                self.enroll(password=password)
        self.assertFalse(self.calls)
        self.assertFalse(self.paths.credential.exists())

    def test_changed_credential_permissions_and_symlink_refused(self):
        self.enroll()
        self.paths.credential.chmod(0o644)
        with self.assertRaisesRegex(Refused, 'permissions changed'):
            self.enroll(password=None)
        self.paths.credential.unlink()
        self.paths.credential.symlink_to(self.paths.config)
        with self.assertRaises((Refused, OSError)):
            self.enroll(password=None)

    def test_console_requires_terminal_and_stored_acknowledgment(self):
        from nebulalog_manager import firstboot, baseline
        manager = SimpleNamespace(paths=SimpleNamespace(data=self.root), runner=self.runner)
        with patch.object(firstboot.sys.stdin, 'isatty', return_value=False):
            with self.assertRaisesRegex(Refused, 'interactive local console'):
                firstboot._bootloader_console(manager, {'baseline':'stig'}, 'installation-1')
        with patch.object(firstboot.sys.stdin, 'isatty', return_value=True), \
             patch.object(firstboot.sys.stdout, 'isatty', return_value=True), \
             patch.object(baseline, 'initial_hardening', return_value=nullcontext()) as guard, \
             patch.object(firstboot.getpass, 'getpass', return_value='test-password-value'), \
             patch.object(firstboot, '_answer', side_effect=['recovery-user', 'CANCEL']), \
             patch.object(b, 'enroll') as enroll, patch('builtins.print'):
            with self.assertRaisesRegex(Refused, 'not acknowledged'):
                firstboot._bootloader_console(manager, {'baseline':'stig'}, 'installation-1')
            guard.assert_called_once_with(self.root/'configuration', 'installation-1', 'stig')
            enroll.assert_not_called()

    def test_regeneration_accepts_only_fips_boot_movement_and_preserves_other_order(self):
        old = b'  set kernelopts="root=/dev/mapper/system-root ro fips=1 boot=UUID=123 console=ttyS0 "\nblscfg\n'
        new = b'  set kernelopts="root=/dev/mapper/system-root ro console=ttyS0 fips=1 boot=UUID=123 "\nblscfg\n'
        self.assertTrue(b._same_configuration(old, new))
        for changed in (new.replace(b'fips=1', b'fips=0'), new.replace(b'blscfg', b'othercommand'),
                        new.replace(b'ro ', b'ro fips=0 '), new.replace(b'ro ', b'ro init=/bin/sh ')):
            self.assertFalse(b._same_configuration(old, changed))
        duplicate = old.replace(b'ro ', b'ro console=tty0 ')
        reversed_console = duplicate.replace(b'console=tty0 ', b'').replace(b'console=ttyS0', b'console=ttyS0 console=tty0')
        self.assertFalse(b._same_configuration(duplicate, reversed_console))
        self.assertTrue(b._same_configuration(old.replace(b'ro ', b'ro rd.lvm.lv=a rd.lvm.lv=b '),
                                             new.replace(b'ro ', b'ro rd.lvm.lv=a rd.lvm.lv=b ')))
        self.assertFalse(b._same_configuration(old.replace(b'ro ', b'ro fips=0 '),
                                              new.replace(b'ro ', b'ro fips=0 ')))

    def test_failed_credential_enrollment_prevents_baseline_remediation(self):
        from nebulalog_manager import firstboot, baseline
        policy = self.root/'policy.json'
        policy.write_text('{}')
        manager = SimpleNamespace(paths=SimpleNamespace(data=self.root), runner=self.runner,
                                  gate=lambda: {'installation_id':'installation-1'})
        with patch.object(baseline, 'Baseline') as factory, patch('builtins.print'), \
             patch.object(baseline, '_sha', return_value=b.sha(policy.read_bytes())), \
             patch.object(firstboot, '_answer', return_value='APPLY'), \
             patch.object(firstboot, '_bootloader_console', side_effect=Refused('credential incomplete')):
            factory.return_value.policy_path = policy
            with self.assertRaisesRegex(Refused, 'credential incomplete'):
                firstboot._hardening_console(manager, {'baseline':'stig'})
            factory.return_value.remediate.assert_not_called()

    def test_verified_baseline_refresh_allows_later_enrollment_readback(self):
        self.enroll()
        checkpoint = b.remediation_checkpoint(self.root, 'installation-1', paths=self.paths)
        self.paths.config.write_text(self.paths.config.read_text() + 'set timeout=5\n')
        with self.assertRaisesRegex(Refused, 'differs'):
            self.enroll(password=None)
        refresh = b.accept_remediation(self.root, checkpoint, 'a'*32, 'b'*64,
                                       paths=self.paths, runner=self.runner)
        self.assertNotEqual(refresh['previous_config_sha256'], refresh['config_sha256'])
        self.assertEqual(self.enroll(password=None)['state'], 'enrolled')
        record = json.loads((self.root/'bootloader-enrollment.json').read_text())
        self.assertEqual(record['last_baseline_refresh']['policy_sha256'], 'b'*64)

    def test_baseline_cannot_adopt_changed_grub_credential(self):
        self.enroll()
        checkpoint = b.remediation_checkpoint(self.root, 'installation-1', paths=self.paths)
        self.paths.credential.write_text('unexpected credential')
        with self.assertRaisesRegex(Refused, 'identity or credential'):
            b.accept_remediation(self.root, checkpoint, 'a'*32, 'b'*64, paths=self.paths, runner=self.runner)

    def test_incomplete_enrollment_and_changed_receipt_block_baseline_checkpoint(self):
        self.fail = True
        with self.assertRaises(Refused):
            self.enroll()
        with self.assertRaisesRegex(Refused, 'Complete GRUB'):
            b.remediation_checkpoint(self.root, 'installation-1', paths=self.paths)
        self.fail = False
        self.enroll(password=None)
        checkpoint = b.remediation_checkpoint(self.root, 'installation-1', paths=self.paths)
        journal = self.root/'bootloader-enrollment.json'
        journal.write_text(journal.read_text() + '\n')
        with self.assertRaisesRegex(Refused, 'changed during'):
            b.accept_remediation(self.root, checkpoint, 'a'*32, 'b'*64, paths=self.paths, runner=self.runner)

    def test_baseline_cannot_remove_recovery_authentication(self):
        self.enroll()
        checkpoint = b.remediation_checkpoint(self.root, 'installation-1', paths=self.paths)
        self.paths.config.write_text('blscfg\n')
        with self.assertRaisesRegex(Refused, 'lost the enrolled'):
            b.accept_remediation(self.root, checkpoint, 'a'*32, 'b'*64, paths=self.paths, runner=self.runner)


if __name__ == '__main__':
    unittest.main()
