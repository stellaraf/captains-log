"""Kernel transaction boundaries; native encrypted/AIDE acceptance is separate."""
import copy
import hashlib
import json
import os
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
        kernel.pin_default.assert_called_once_with(self.stage, self.plan)
        self.assertEqual(self.runner.call_args.args[0], ['/usr/sbin/grubby', '--set-default=/boot/vmlinuz-' + OLD])
        kernel.recover_generated.assert_not_called()

    def test_existing_intent_never_replays_rpm(self):
        (self.stage / 'kernel-apply-intent.json').write_text('{}')
        with self.assertRaisesRegex(Refused, 'already_attempted'):
            kernel.execute_cached(self.stage, authorize=self.authorize, runner=self.runner)
        self.authorize.assert_not_called()
        self.runner.assert_not_called()


class KernelConfigurationPublicationTests(unittest.TestCase):
    """Real private-file rename/retry; only host root/SELinux are fixture inputs."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / 'stage'; self.stage.mkdir(mode=0o700)
        self.path = self.root / 'kernel'
        self.original = b'# retained comment\nUPDATEDEFAULT=yes\nDEFAULTKERNEL=kernel-core\n'
        self.pinned = self.original.replace(b'UPDATEDEFAULT=yes', b'UPDATEDEFAULT=no')
        self.path.write_bytes(self.original); self.path.chmod(0o600)
        self.attributes = {}
        self.label = b'system_u:object_r:etc_t:s0\0'
        self.attrs(self.path)['security.selinux'] = self.label
        def read(path, *args, **kwargs):
            path = Path(path)
            if path.is_symlink() or path.stat().st_nlink != 1:
                raise Refused('fixture_unsafe_file')
            return path.read_bytes()
        for item in (patch.object(kernel, 'KERNEL_CONFIG', str(self.path)),
                     patch.object(kernel, 'describe', side_effect=self.describe),
                     patch.object(kernel.rpm, 'read', side_effect=read),
                     patch.object(kernel, 'verify_install_hooks'),
                     patch.object(kernel.os, 'fchown'),
                     patch.object(kernel.os, 'listxattr', create=True, side_effect=lambda path, **kw:list(self.attrs(path))),
                     patch.object(kernel.os, 'getxattr', create=True, side_effect=lambda path,key,**kw:self.attrs(path)[key]),
                     patch.object(kernel.os, 'setxattr', create=True, side_effect=lambda path,key,value,**kw:self.attrs(path).__setitem__(key,value))):
            item.start(); self.addCleanup(item.stop)
        self.plan = {'kernel_configuration': self.original.decode(), 'mutable_before': {str(self.path): self.describe(self.path)}}

    def attrs(self, path):
        return self.attributes.setdefault(Path(path).stat().st_ino, {})

    def describe(self, path):
        path = Path(path); value = path.lstat()
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_mode & 0o022:
            raise Refused('fixture_unsafe_file')
        raw = path.read_bytes()
        return {'kind':'file','uid':0,'gid':0,'mode':stat.S_IMODE(value.st_mode),'bytes':len(raw),
                'sha256':kernel.rpm.sha(raw),'xattrs_sha256':kernel.digest({key:kernel.rpm.sha(value) for key,value in self.attrs(path).items()})}

    def pin(self):
        kernel.pin_default(self.stage, self.plan)

    def interrupted_before_preparation(self):
        real = kernel.record
        def record(stage,name,value):
            if name.endswith('-prepared.json'):
                raise SystemExit('power loss before preparation receipt')
            return real(stage,name,value)
        with patch.object(kernel,'record',side_effect=record), self.assertRaises(SystemExit):
            self.pin()
        return next(self.root.glob('.captains-log-kernel-*'))

    def test_pin_and_restore_preserve_bytes_security_metadata_and_recovery_preimage(self):
        inode = self.path.stat().st_ino
        self.pin()
        self.assertEqual(self.path.read_bytes(),self.pinned)
        self.assertNotEqual(self.path.stat().st_ino,inode)
        kernel.restore_default_policy(self.stage,self.plan)
        self.assertEqual(self.path.read_bytes(),self.original)
        self.assertEqual(self.describe(self.path),self.plan['mutable_before'][str(self.path)])
        intents=[json.loads(path.read_text()) for path in self.stage.glob('kernel-default-*-intent.json')]
        self.assertEqual({value['phase'] for value in intents},{'pin','restore'})
        self.assertTrue(any(value['before_raw']==self.original.hex() for value in intents))
        self.assertFalse(list(self.root.glob('.captains-log-kernel-*')))

    def test_unpublished_partial_temporary_is_retained_before_retry(self):
        temporary=self.interrupted_before_preparation()
        temporary.write_bytes(self.pinned[:19])
        self.assertEqual(self.path.read_bytes(),self.original)
        self.pin()
        evidence=[json.loads(path.read_text()) for path in self.stage.glob('kernel-default-interrupted-*.json')]
        self.assertEqual([bytes.fromhex(value['raw']) for value in evidence],[self.pinned[:19]])
        self.assertEqual(self.path.read_bytes(),self.pinned)

    def test_crash_after_prepared_before_rename_reuses_exact_temporary(self):
        replace=os.replace
        def crash(source,destination):
            if Path(destination)==self.path: raise SystemExit('before rename')
            return replace(source,destination)
        with patch.object(kernel.os,'replace',side_effect=crash),self.assertRaises(SystemExit): self.pin()
        identity=next(self.root.glob('.captains-log-kernel-*')).stat().st_ino
        self.assertEqual(self.path.read_bytes(),self.original)
        self.pin()
        self.assertEqual(self.path.stat().st_ino,identity)

    def test_crash_after_rename_before_result_finishes_without_second_replacement(self):
        replace=os.replace
        def crash(source,destination):
            replace(source,destination)
            if Path(destination)==self.path: raise SystemExit('after rename')
        with patch.object(kernel.os,'replace',side_effect=crash),self.assertRaises(SystemExit): self.pin()
        identity=self.path.stat().st_ino
        with patch.object(kernel.os,'replace',side_effect=AssertionError('replayed replacement')): self.pin()
        self.assertEqual(self.path.stat().st_ino,identity)

    def test_directory_sync_failure_after_rename_is_resumed_before_success(self):
        sync=kernel._sync_directory
        def fail(path):
            if self.path.read_bytes()==self.pinned: raise OSError('directory sync interrupted')
            return sync(path)
        with patch.object(kernel,'_sync_directory',side_effect=fail),self.assertRaisesRegex(OSError,'sync interrupted'): self.pin()
        self.assertFalse(list(self.stage.glob('kernel-default-*-result.json')))
        inode=self.path.stat().st_ino
        self.pin()
        self.assertEqual(self.path.stat().st_ino,inode)
        self.assertTrue(list(self.stage.glob('kernel-default-*-result.json')))

    def test_pointer_substitution_and_prepared_inode_substitution_are_refused(self):
        replace=os.replace
        def crash(source,destination):
            if Path(destination)==self.path: raise SystemExit('before rename')
            return replace(source,destination)
        with patch.object(kernel.os,'replace',side_effect=crash),self.assertRaises(SystemExit): self.pin()
        temporary=next(self.root.glob('.captains-log-kernel-*'))
        other=self.root/'replacement'; other.write_bytes(self.pinned); other.chmod(0o600)
        self.attrs(other)['security.selinux']=self.label
        other.replace(temporary)
        with self.assertRaisesRegex(Refused,'configuration_replaced'): self.pin()
        pointer=self.stage/'kernel-default-current.json'
        reference=json.loads(pointer.read_text()); reference['sha256']='e'*64
        pointer.write_bytes(kernel.encode(reference))
        with self.assertRaisesRegex(Refused,'intent_changed'): self.pin()
        self.assertEqual(self.path.read_bytes(),self.original)

    def test_changed_live_bytes_inode_label_and_unowned_temp_are_refused(self):
        temporary=self.interrupted_before_preparation()
        temporary.write_bytes(b'unrelated bytes')
        with self.assertRaisesRegex(Refused,'unowned_temporary'): self.pin()
        self.assertEqual(temporary.read_bytes(),b'unrelated bytes')
        temporary.write_bytes(self.pinned)
        self.attrs(self.path)['security.selinux']=b'wrong'
        with self.assertRaisesRegex(Refused,'configuration_changed'): self.pin()
        self.attrs(self.path)['security.selinux']=self.label
        self.path.write_bytes(b'changed live bytes')
        with self.assertRaisesRegex(Refused,'configuration_changed'): self.pin()
        self.path.write_bytes(self.original)
        other=self.root/'other'; other.write_bytes(self.original); other.chmod(0o600)
        self.attrs(other)['security.selinux']=self.label
        other.replace(self.path)
        with self.assertRaisesRegex(Refused,'configuration_changed'): self.pin()


class KernelPrecommandRecoveryTests(unittest.TestCase):
    setUp = KernelConfigurationPublicationTests.setUp
    attrs = KernelConfigurationPublicationTests.attrs
    describe = KernelConfigurationPublicationTests.describe

    def prepare_recovery(self, schema=2):
        self.plan.update(boot_id=BOOT, old_kernel=OLD, kernel=NEW, before_inventory=['before'],
                         after_inventory=['after'], inventory_sha256=kernel.rpm.sha(b'xml'),
                         key_sha256=kernel.rpm.sha(b'key'), packages=[], generated=[], space_requirements={})
        self.authorization={'ok':True,'plan_sha256':PLAN_SHA,'backup_sha256':'b'*64,
                            'aide_preparation_sha256':'c'*64,'boot_id':BOOT}
        self.intent={'schema':schema,'plan_sha256':PLAN_SHA,'authorization':self.authorization}
        kernel.record(self.stage,'kernel-apply-intent.json',self.intent)
        read=kernel.rpm.read
        for item in (patch.object(kernel,'require_linux_root'),patch.object(kernel,'load_plan',return_value=(self.plan,PLAN_SHA)),
                     patch.object(kernel,'authorize_execution',return_value=self.authorization),
                     patch.object(kernel.rpm,'inventory',return_value=('xml',[],['before'])),
                     patch.object(kernel.rpm,'platform'),patch.object(kernel,'verify_space'),patch.object(kernel,'verify_preserved'),
                     patch.object(kernel.rpm,'read',side_effect=lambda path,*a,**k:b'key' if str(path)==str(kernel.rpm.KEY) else read(path,*a,**k))):
            item.start(); self.addCleanup(item.stop)
        self.rpm_calls=[]
        def runner(argv,**kwargs):
            if '--default-kernel' in argv: return '/boot/vmlinuz-'+OLD
            if argv==kernel.command(self.stage,self.plan):
                self.rpm_calls.append(argv)
                self.assertEqual(self.path.read_bytes(),self.pinned)
                self.assertTrue((self.stage/'kernel-rpm-command.json').exists())
                raise SystemExit('native command entered')
            return ''
        self.runner=runner

    def test_interrupted_pin_resumes_first_command_once_and_ambiguous_attempt_never_replays(self):
        self.prepare_recovery()
        real=kernel.record
        def crash(stage,name,value):
            if name.endswith('-prepared.json'): raise SystemExit('pin interrupted before command')
            return real(stage,name,value)
        with patch.object(kernel,'record',side_effect=crash),self.assertRaisesRegex(SystemExit,'pin interrupted'):
            kernel.recover_generated(self.stage,authorize=Mock(),runner=self.runner)
        self.assertFalse(self.rpm_calls)
        self.assertFalse((self.stage/'kernel-rpm-command.json').exists())
        self.assertEqual(self.path.read_bytes(),self.original)
        with self.assertRaisesRegex(SystemExit,'native command entered'):
            kernel.recover_generated(self.stage,authorize=Mock(),runner=self.runner)
        self.assertEqual(len(self.rpm_calls),1)
        with self.assertRaisesRegex(Refused,'partial_package_install'):
            kernel.recover_generated(self.stage,authorize=Mock(),runner=self.runner)
        self.assertEqual(len(self.rpm_calls),1)

    def test_legacy_ambiguous_intent_cannot_start_first_command(self):
        self.prepare_recovery(schema=1)
        with self.assertRaisesRegex(Refused,'partial_package_install'):
            kernel.recover_generated(self.stage,authorize=Mock(),runner=self.runner)
        self.assertFalse(self.rpm_calls)
        self.assertEqual(self.path.read_bytes(),self.original)

    def test_schema_two_missing_sentinel_cannot_adopt_changed_inventory(self):
        self.prepare_recovery()
        with patch.object(kernel.rpm,'inventory',return_value=('xml',[],['after'])),self.assertRaisesRegex(Refused,'precommand_inventory'):
            kernel.recover_generated(self.stage,authorize=Mock(),runner=self.runner)
        self.assertFalse(self.rpm_calls)

    def test_changed_sentinel_authorization_is_refused_without_command(self):
        self.prepare_recovery()
        kernel.record(self.stage,'kernel-rpm-command.json',{'schema':1,'plan_sha256':PLAN_SHA,
                      'intent_sha256':kernel.rpm.sha(kernel.encode(self.intent)),
                      'authorization':{**self.authorization,'aide_preparation_sha256':'e'*64}})
        with self.assertRaisesRegex(Refused,'sentinel_changed'):
            kernel.recover_generated(self.stage,authorize=Mock(),runner=self.runner)
        self.assertFalse(self.rpm_calls)


class KernelBootTests(unittest.TestCase):
    def test_retention_inventory_requires_reloaded_authority_and_all_current_bindings(self):
        from nebulalog_manager import kernel_retention
        stage, owner = Path('/candidate'), Path('/owner')
        plan={'boot_id':BOOT,'kernel':NEW,'old_kernel':OLD,'after_inventory':['original-four']}
        installed={'plan_sha256':PLAN_SHA}
        raw=kernel.encode(installed)
        reference={'filename':'kernel-retention-observation-'+NEW_BOOT+'.json','sha256':'b'*64}
        authority={'candidate_plan_sha256':PLAN_SHA,'installed_sha256':kernel.rpm.sha(raw),
                   'operation_sha256':kernel.rpm.sha(b'operation'),'boot_id':NEW_BOOT,'kernel':NEW,
                   'recovery_kernel':OLD,'after_inventory':['verified-three']}
        runner=Mock()
        with patch.object(kernel,'load_plan',return_value=(plan,PLAN_SHA)), \
             patch.object(kernel.rpm,'read',side_effect=lambda path,*a:b'operation' if Path(path).name=='operation.json' else raw), \
             patch.object(kernel,'load_candidate',return_value=(stage,plan,PLAN_SHA,installed)), \
             patch.object(Path,'read_text',return_value=NEW_BOOT), \
             patch.object(kernel_retention,'validate_boot_authority',return_value=authority) as validate:
            self.assertEqual(kernel.postboot_inventory(stage),['original-four'])
            validate.assert_not_called()
            self.assertEqual(kernel.postboot_inventory(stage,owner_stage=owner,retention_authority=reference,runner=runner),['verified-three'])
            validate.assert_called_once_with(owner,reference,runner=runner)
            for field in ('candidate_plan_sha256','installed_sha256','operation_sha256','boot_id','kernel','recovery_kernel'):
                with self.subTest(field=field),patch.object(kernel_retention,'validate_boot_authority',return_value={**authority,field:'wrong'}),self.assertRaisesRegex(Refused,'retention_boot_authority'):
                    kernel.postboot_inventory(stage,owner_stage=owner,retention_authority=reference,runner=runner)
            with self.assertRaisesRegex(Refused,'retention_owner_required'):
                kernel.postboot_inventory(stage,retention_authority=reference,runner=runner)
            with patch.object(kernel_retention,'validate_boot_authority',side_effect=Refused('tampered authority')),self.assertRaisesRegex(Refused,'tampered authority'):
                kernel.postboot_inventory(stage,owner_stage=owner,retention_authority=reference,runner=runner)

    def test_optional_retention_acceptance_proof_preserves_legacy_canonical_bytes(self):
        from nebulalog_manager.updates import REQUIRED_CHECKS
        fields={'schema':1,'operation_sha256':'1'*64,'kernel_plan_sha256':'2'*64,'installed_sha256':'3'*64,
                'postboot_sha256':'4'*64,'promotion_sha256':'5'*64,'resume_sha256':None,
                'kernel':NEW,'boot_id':NEW_BOOT,'recovery_kernel':OLD,
                'checks':{name:True for name in REQUIRED_CHECKS},'finalization':'complete','previous_acceptance_sha256':None}
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary); path=stage/('kernel-acceptance-'+NEW_BOOT+'.json')
            with patch.object(kernel.rpm,'read',side_effect=lambda path,*a:Path(path).read_bytes()):
                for value in (fields,{**fields,'retention_integrity_sha256':None},{**fields,'retention_integrity_sha256':'6'*64}):
                    raw=kernel.encode(value); path.write_bytes(raw)
                    loaded,checksum,_=kernel._acceptance_file(stage,path.name)
                    self.assertEqual(loaded,value); self.assertEqual(checksum,kernel.rpm.sha(raw))
                    self.assertEqual(path.read_bytes(),raw)
                for value in ({**fields,'retention_integrity_sha256':'bad'},{**fields,'unexpected':None}):
                    path.write_bytes(kernel.encode(value))
                    with self.assertRaises(Refused): kernel._acceptance_file(stage,path.name)

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
