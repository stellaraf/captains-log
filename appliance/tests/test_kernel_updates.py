"""Kernel transaction boundaries; native encrypted/AIDE acceptance is separate."""
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import kernel_updates as kernel
from nebulalog_manager.common import Refused

OLD = '5.14.0-687.56.1.el9_8.x86_64'
NEW = '5.14.0-687.57.1.el9_8.x86_64'
MACHINE = 'e250a7dda5144f42b26a77d8329c2ce2'
BOOT = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
NEW_BOOT = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
PLAN_SHA = 'a' * 64


def header():
    return {'Name': ['kernel-modules-core'], 'Version': ['5.14.0'], 'Release': ['687.57.1.el9_8'],
            'Arch': ['x86_64'], 'Filedigestalgo': [8],
            'Posttrans': ['/sbin/depmod -a ' + NEW], 'Posttransprog': ['/bin/sh'],
            'Basenames': ['kernel', 'one.ko.xz', 'modules.dep', 'source'],
            'Dirnames': ['/lib/modules/' + NEW + '/'], 'Dirindexes': [0] * 4,
            'Filemodes': [stat.S_IFDIR | 0o755, stat.S_IFREG | 0o644, stat.S_IFREG | 0o644, stat.S_IFLNK | 0o777],
            'Filesizes': [0, 6, 0, 5], 'Filedigests': ['', hashlib.sha256(b'module').hexdigest(), '', ''],
            'Fileusername': ['root'] * 4, 'Filegroupname': ['root'] * 4,
            'Fileflags': [0, 0, 64, 0], 'Filelinktos': ['', '', '', 'build'], 'Fileinodes': [1, 2, 3, 4]}


def bls(version):
    return ('title Rocky Linux (' + version + ') 9.8 (Blue Onyx)\nversion ' + version + '\nlinux /vmlinuz-' + version
            + '\ninitrd /initramfs-' + version + '.img\noptions root=/dev/mapper/system-root ro fips=1 module.sig_enforce=1 audit=1 boot=UUID=fixture\n'
            + 'grub_users $grub_users\ngrub_arg --unrestricted\ngrub_class rocky\n')


class KernelPolicyTests(unittest.TestCase):
    def test_space_reservations_are_summed_on_shared_filesystems(self):
        with patch.object(kernel.os, 'stat', return_value=SimpleNamespace(st_dev=1)), \
             patch.object(kernel.os, 'statvfs', return_value=SimpleNamespace(f_bavail=100, f_frsize=1)):
            kernel.verify_space({'/boot': 40, '/usr/lib/modules': 60})
            with self.assertRaisesRegex(Refused, 'insufficient_space'):
                kernel.verify_space({'/boot': 60, '/usr/lib/modules': 60})

    def test_qualified_script_template_and_payload_types(self):
        value = kernel.payload(header())
        self.assertEqual(value['kernel'], NEW)
        self.assertEqual([p['kind'] for p in value['files']], ['directory', 'file', 'file', 'symlink'])
        self.assertTrue(value['files'][2]['ghost'])
        self.assertTrue(all(p['path'].startswith('/usr/lib/modules/') for p in value['files']))

    def test_vendor_script_change_or_new_trigger_requires_recipe_review(self):
        for key, value in [('Posttrans', ['/bin/touch /etc/arbitrary']), ('Posttransprog', ['/bin/bash']),
                           ('Filetriggerscripts', ['arbitrary']), ('Verifyscript', ['arbitrary'])]:
            with self.subTest(key=key), self.assertRaisesRegex(Refused, 'script_template'):
                kernel.payload({**header(), key: value})

    def test_template_normalization_allows_version_only_change(self):
        changed = header()
        changed['Release'] = ['687.58.1.el9_8']
        changed['Posttrans'] = ['/sbin/depmod -a 5.14.0-687.58.1.el9_8.x86_64']
        self.assertNotEqual(kernel.script_binding(header()), kernel.script_binding(changed))

    def test_unknown_links_capabilities_hardlinks_and_paths_refused(self):
        for key, value in [('Filelinktos', ['', '', '', '/etc/shadow']), ('Filecaps', ['', 'cap_sys_admin=ep', '', '']),
                           ('Fileinodes', [1, 2, 2, 4]), ('Dirnames', ['/etc/']),
                           ('Dirnames', ['/lib/modules/' + NEW + '/../']), ('Fileflags', [0, 1, 64, 0])]:
            with self.subTest(key=key), self.assertRaises(Refused):
                kernel.payload({**header(), key: value})

    def test_generated_scope_exact_and_version_bound(self):
        paths = kernel.generated_paths(NEW, MACHINE)
        self.assertEqual(len(paths), 17)
        self.assertIn('/boot/loader/entries/' + MACHINE + '-' + NEW + '.conf', paths)
        self.assertNotIn(kernel.GRUBENV, paths)
        for value, machine in [(OLD + '/../../etc', MACHINE), (NEW, '../escape')]:
            with self.assertRaises(Refused): kernel.generated_paths(value, machine)

    def test_downgrade_repeat_and_unqualified_version_refused(self):
        kernel.newer_kernel(NEW, OLD)
        for candidate in (OLD, '5.14.0-687.55.1.el9_8.x86_64', '6.0.0-custom.x86_64'):
            with self.assertRaises(Refused): kernel.newer_kernel(candidate, OLD)

    def test_offline_solve_cannot_erase_upgrade_or_add_dependency(self):
        packages = [{'nevra': name + '-0:' + NEW} for name in sorted(kernel.NAMES)]
        rows = sorted([{'action': 'install', 'nevra': p['nevra'], 'repo': '@commandline'} for p in packages], key=lambda p:p['nevra'])
        kernel.validate_solve(rows, packages)
        for mutation in ('erase', 'upgrade', 'extra', 'missing', 'remote'):
            changed = copy.deepcopy(rows)
            if mutation == 'extra': changed.append({'action':'install', 'nevra':'unexpected', 'repo':'@commandline'})
            elif mutation == 'missing': changed.pop()
            elif mutation == 'remote': changed[0]['repo'] = 'baseos'
            else: changed[0]['action'] = mutation
            with self.subTest(mutation=mutation), self.assertRaises(Refused): kernel.validate_solve(changed, packages)

    def test_install_argv_does_not_erase_old_kernel_or_disable_validation(self):
        plan = {'packages': [{'rpm': 'a' * 64 + '.rpm'}]}
        self.assertEqual(kernel.command(Path('/stage'), plan), ['/usr/bin/env', 'GRUB_UPDATE_DEFAULT_KERNEL=false', '/usr/bin/rpm', '--install', '/stage/kernel-packages/' + 'a' * 64 + '.rpm'])
        self.assertEqual(kernel.command(Path('/stage'), plan, True)[4], '--test')

    def test_default_pin_preserves_policy_and_refuses_ambiguous_or_executable_settings(self):
        original = '# keep comment\nUPDATEDEFAULT=yes\nDEFAULTKERNEL=kernel-core\n'
        self.assertEqual(kernel.default_policy(original), original.replace('UPDATEDEFAULT=yes', 'UPDATEDEFAULT=no'))
        for text in (original + 'UPDATEDEFAULT=yes\n', original.replace('UPDATEDEFAULT=yes', 'UPDATEDEFAULT=$(command)'),
                     original.replace('kernel-core', 'custom'), original + ' UPDATEDEFAULT=yes\n',
                     original + 'export UPDATEDEFAULT=yes\n', original + 'DEFAULTKERNEL=kernel-core\n', original + 'MAKEDEBUG=yes\n',
                     original.replace('\n', '\r\n'), original.replace('\n', '\u2028')):
            with self.assertRaises(Refused): kernel.default_policy(text)

    def test_bls_requires_exact_inherited_root_encryption_and_security_arguments(self):
        kernel.validate_bls(bls(NEW), bls(OLD), OLD, NEW)
        for text in (bls(NEW).replace('fips=1', 'fips=0'), bls(NEW) + 'options fips=1\n',
                     bls(NEW).replace('system-root', 'other-root'), bls(NEW).replace('.img', '.img /other.img')):
            with self.assertRaises(Refused): kernel.validate_bls(text, bls(OLD), OLD, NEW)
        with self.assertRaises(Refused):
            kernel.validate_bls(bls(NEW).replace('audit=1', 'audit=1 audit=0'), bls(OLD).replace('audit=1', 'audit=1 audit=0'), OLD, NEW)

    def test_integrity_delta_never_accepts_unrelated_or_removed_files(self):
        plan = {'kernel': NEW, 'generated': ['/boot/new'], 'files': [{'path': '/usr/lib/modules'}, {'path': '/usr/lib/modules/new'}],
                'shared': {'/usr/lib/modules': {}}, 'mutable_before': {kernel.GRUBENV: {}, '/etc/sysconfig/kernel': {}}}
        installed = {'kernel': NEW, 'generated': {'/boot/new': {}}}
        delta = kernel.integrity_delta(plan, installed)
        kernel.check_integrity_report({'added': {'/boot/new': {}}, 'changed': {kernel.GRUBENV: {}}}, delta)
        for report in ({'added': {'/etc/shadow': {}}}, {'changed': {'/boot/old': {}}}, {'removed': {'/usr/lib/modules/new': {}}}):
            with self.assertRaises(Refused): kernel.check_integrity_report(report, delta)

    def test_labels_are_checked_against_policy_and_unknown_xattrs_refused(self):
        path = '/usr/lib/modules/' + NEW + '/one.ko.xz'
        expected = 'system_u:object_r:modules_object_t:s0'
        with patch.object(kernel.os, 'listxattr', create=True, return_value=['security.selinux']), \
             patch.object(kernel.os, 'getxattr', create=True, return_value=(expected + '\0').encode()):
            kernel.verify_labels([path], runner=Mock(return_value=expected))
            with self.assertRaisesRegex(Refused, 'differs_from_policy'):
                kernel.verify_labels([path], runner=Mock(return_value='system_u:object_r:unlabeled_t:s0'))
        with patch.object(kernel.os, 'listxattr', create=True, return_value=['security.selinux', 'user.unreviewed']), \
             self.assertRaisesRegex(Refused, 'differs_from_policy'):
            kernel.verify_labels([path], runner=Mock(return_value=expected))

    def test_missing_generated_module_file_is_repairable_but_extra_file_is_not(self):
        root = '/usr/lib/modules/' + NEW
        directory = {'kind':'directory', 'uid':0, 'gid':0, 'mode':0o755}
        plan = {'kernel':NEW, 'files':[{'path':root, 'ghost':False, **directory},
                {'path':root+'/modules.dep', 'ghost':True}], 'shared':{}, 'packages':[]}
        with patch.object(kernel, 'describe', return_value=directory), patch.object(kernel, 'verify_labels'), \
             patch.object(kernel, 'verify_preserved'), patch.object(Path, 'rglob', return_value=[]):
            kernel.verify_payload(plan, allow_missing_generated=True)
            with self.assertRaisesRegex(Refused, 'unplanned_module_tree'):
                kernel.verify_payload(plan)
        with patch.object(kernel, 'describe', return_value=directory), patch.object(Path, 'rglob', return_value=[Path(root+'/unexpected')]), \
             self.assertRaisesRegex(Refused, 'unplanned_module_tree'):
            kernel.verify_payload(plan, allow_missing_generated=True)


class KernelExecutionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.stage = Path(temp.name)
        self.plan = {'boot_id': BOOT, 'old_kernel': OLD, 'kernel': NEW, 'before_inventory': ['before'],
                     'after_inventory': ['after'], 'inventory_sha256': kernel.rpm.sha(b'xml'), 'key_sha256': kernel.rpm.sha(b'key'),
                     'packages': [], 'generated': [], 'mutable_before': {}, 'shared': {}, 'preserved': {},
                     'space_requirements': {}}
        self.authorized = {'ok': True, 'plan_sha256': PLAN_SHA, 'backup_sha256': 'b' * 64,
                           'aide_preparation_sha256': 'c' * 64, 'boot_id': BOOT}
        self.authorize = Mock(return_value=self.authorized)
        self.runner = Mock(side_effect=lambda argv, **kw: '/boot/vmlinuz-' + OLD if '--default-kernel' in argv else '')
        self.records = []
        original = Path.read_text
        def read_text(path, *args, **kw):
            if str(path) == '/proc/sys/kernel/random/boot_id': return BOOT
            if str(path) == '/proc/sys/kernel/tainted': return '0'
            return original(path, *args, **kw)
        for patcher in (patch.object(kernel, 'require_linux_root'), patch.object(kernel, 'load_plan', return_value=(self.plan, PLAN_SHA)),
                        patch.object(kernel, 'verify_preserved'), patch.object(kernel.rpm, 'platform'),
                        patch.object(kernel, 'pin_default'),
                        patch.object(kernel, 'verify_space'),
                        patch.object(kernel.rpm, 'inventory', return_value=('xml', [], ['before'])),
                        patch.object(kernel.rpm, 'read', return_value=b'key'), patch.object(Path, 'read_text', read_text),
                        patch.object(kernel, 'record', side_effect=lambda stage, name, value: self.records.append((name, value))),
                        patch.object(kernel, 'recover_generated', return_value={'status':'installed_pending_integrity_and_reboot'})):
            patcher.start(); self.addCleanup(patcher.stop)

    def test_authorization_failure_prevents_rpm_and_intent(self):
        self.authorize.return_value = {**self.authorized, 'ok': False}
        with self.assertRaises(Refused): kernel.execute_cached(self.stage, authorize=self.authorize, runner=self.runner)
        self.runner.assert_not_called()
        self.assertFalse(self.records)

    def test_authorization_rechecked_before_durable_intent_and_install(self):
        self.authorize.side_effect = [self.authorized, {**self.authorized, 'backup_sha256': 'd' * 64}]
        with self.assertRaisesRegex(Refused, 'context_changed'):
            kernel.execute_cached(self.stage, authorize=self.authorize, runner=self.runner)
        self.assertFalse(self.records)
        self.assertNotIn(kernel.command(self.stage, self.plan), [c.args[0] for c in self.runner.call_args_list])

    def test_partial_rpm_failure_restores_old_default_and_does_not_complete(self):
        def run(argv, **kw):
            if '--default-kernel' in argv: return '/boot/vmlinuz-' + OLD
            if argv == kernel.command(self.stage, self.plan): raise Refused('fixture RPM failure')
            return ''
        self.runner.side_effect = run
        with self.assertRaisesRegex(Refused, 'RPM failure'):
            kernel.execute_cached(self.stage, authorize=self.authorize, runner=self.runner)
        self.assertEqual(self.records[0][0], 'kernel-apply-intent.json')
        kernel.pin_default.assert_called_once_with(self.plan)
        self.assertEqual(self.runner.call_args.args[0], ['/usr/sbin/grubby', '--set-default=/boot/vmlinuz-' + OLD])
        kernel.recover_generated.assert_not_called()

    def test_existing_intent_never_replays_rpm(self):
        (self.stage / 'kernel-apply-intent.json').write_text('{}')
        with self.assertRaisesRegex(Refused, 'already_attempted'):
            kernel.execute_cached(self.stage, authorize=self.authorize, runner=self.runner)
        self.authorize.assert_not_called()
        self.runner.assert_not_called()


class KernelBootTests(unittest.TestCase):
    def test_new_boot_matching_kernel_with_failed_crypto_is_refused(self):
        plan = {'boot_id': BOOT, 'kernel': NEW, 'after_inventory': ['after']}
        installed = {'plan_sha256': PLAN_SHA, 'generated': {}}
        def read_text(path, *args, **kw):
            return NEW_BOOT if str(path).endswith('boot_id') else '0'
        with patch.object(kernel, 'load_plan', return_value=(plan, PLAN_SHA)), \
             patch.object(kernel.rpm, 'read', return_value=kernel.encode(installed)), \
             patch.object(kernel.rpm, 'inventory', return_value=('', [], ['after'])), \
             patch.object(kernel, 'verify_payload'), patch.object(kernel, 'generated_snapshot', return_value={}), \
             patch.object(Path, 'read_text', read_text), patch.object(kernel.security, 'status', return_value={'host_controls_ok': False}):
            with self.assertRaisesRegex(Refused, 'host_security_failed'):
                kernel.verify_postboot('/stage', runner=Mock(return_value=NEW))

    def test_same_boot_wrong_kernel_and_tainted_kernel_refused(self):
        plan = {'boot_id': BOOT, 'kernel': NEW, 'after_inventory': ['after']}
        installed = {'plan_sha256': PLAN_SHA, 'generated': {}}
        with patch.object(kernel, 'load_plan', return_value=(plan, PLAN_SHA)), \
             patch.object(kernel.rpm, 'read', return_value=kernel.encode(installed)), \
             patch.object(kernel.rpm, 'inventory', return_value=('', [], ['after'])):
            for boot, running, taint in ((BOOT, NEW, '0'), (NEW_BOOT, OLD, '0'), (NEW_BOOT, NEW, '8192')):
                with self.subTest(boot=boot,running=running,taint=taint), \
                     patch.object(Path, 'read_text', lambda path, *a, **kw: boot if str(path).endswith('boot_id') else taint), \
                     self.assertRaisesRegex(Refused, 'candidate_boot_not_proven'):
                    kernel.verify_postboot('/stage', runner=Mock(return_value=running))


if __name__ == '__main__':
    unittest.main()
