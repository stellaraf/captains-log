"""OS package policy and integrity-chain tests; native RPM proof is separate."""
import copy
from contextlib import contextmanager
from types import SimpleNamespace
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import os_payload as rpm, aide_updates
from nebulalog_manager.common import Refused
import test_aide_updates as aide_fixture


def header():
    # The names/types are observed from native Rocky RPM 4.16 --xml, including
    # the unchanged two-path linux-firmware-whence July/August 2026 payload set.
    return {'Name':['linux-firmware-whence'], 'Epoch':[0], 'Version':['20260804'],
            'Release':['161.2.el9_8'], 'Arch':['noarch'], 'Filedigestalgo':[8],
            'Basenames':['linux-firmware-whence','WHENCE'],
            'Dirnames':['/usr/share/licenses/','/usr/share/licenses/linux-firmware-whence/'],
            'Dirindexes':[0,1], 'Filemodes':[stat.S_IFDIR|0o755,stat.S_IFREG|0o644],
            'Filesizes':[0,7], 'Filedigests':['',hashlib.sha256(b'license').hexdigest()],
            'Fileusername':['root','root'], 'Filegroupname':['root','root'],
            'Fileflags':[0,128], 'Filelinktos':['','']}


class RpmPolicyTests(unittest.TestCase):
    def test_native_xml_types_and_epoch_version_identity(self):
        data = '<rpmHeader><rpmTag name="Name"><string>passt</string></rpmTag><rpmTag name="Version"><string>0^20251210.gd04c480</string></rpmTag><rpmTag name="Release"><string>6.el9_8</string></rpmTag><rpmTag name="Arch"><string>x86_64</string></rpmTag></rpmHeader>'
        self.assertEqual(rpm.identity(rpm.headers(data)[0])['nevra'], 'passt-0:0^20251210.gd04c480-6.el9_8.x86_64')
        self.assertEqual(rpm.payload(header())['files'][1]['sha256'], hashlib.sha256(b'license').hexdigest())

    def test_native_missing_arch_key_record_is_preserved_in_complete_inventory(self):
        # Exact scalar shape observed on the Rocky qualification guest. RPM
        # renders its missing Arch as (none) in queryformat, but omits the XML tag.
        key = '<rpmHeader><rpmTag name="Name"><string>gpg-pubkey</string></rpmTag><rpmTag name="Version"><string>350d275d</string></rpmTag><rpmTag name="Release"><string>6279464b</string></rpmTag></rpmHeader>'
        package = '<rpmHeader><rpmTag name="Name"><string>passt</string></rpmTag><rpmTag name="Version"><string>0^20251210.gd04c480</string></rpmTag><rpmTag name="Release"><string>6.el9_8</string></rpmTag><rpmTag name="Arch"><string>x86_64</string></rpmTag></rpmHeader>'
        xml = key + package
        runner = Mock(return_value=xml)
        retained, headers, inventory = rpm.inventory(runner)
        self.assertEqual(retained, xml)
        self.assertEqual(len(headers), 2)
        self.assertNotIn('Arch', headers[0])
        self.assertEqual(rpm.identity(headers[0]), {'name': 'gpg-pubkey', 'arch': 'none',
                         'nevra': 'gpg-pubkey-0:350d275d-6279464b.none'})
        self.assertEqual(inventory, ['gpg-pubkey-0:350d275d-6279464b.none', 'passt-0:0^20251210.gd04c480-6.el9_8.x86_64'])
        self.assertNotEqual(inventory, rpm.inventory(Mock(return_value=package))[2])
        rotated = key.replace('350d275d', 'deadbeef') + package
        self.assertNotEqual(inventory, rpm.inventory(Mock(return_value=rotated))[2])
        runner.assert_called_once_with(['/usr/bin/rpm', '--query', '--all', '--xml'], timeout=180)

    def test_absent_arch_exception_rejects_malformed_or_ambiguous_key_records(self):
        key = {'Name': ['gpg-pubkey'], 'Version': ['350d275d'], 'Release': ['6279464b']}
        for change in ({'Arch': []}, {'Arch': ['none']}, {'Arch': ['noarch']}, {'Arch': ['x86_64']},
                       {'Arch': ['noarch', 'x86_64']}, {'Epoch': [1]}, {'Epoch': [False]},
                       {'Version': ['350d275']}, {'Version': ['350D275D']}, {'Version': ['invalid!']},
                       {'Release': ['not-time']}, {'Release': ['6279464b', '6279464c']},
                       {'Name': ['gpg-pubkey', 'other']}):
            with self.subTest(change=change), self.assertRaises(Refused):
                rpm.identity({**key, **change})
        self.assertEqual(rpm.identity({**key, 'Epoch': [0]})['arch'], 'none')

    def test_normal_package_missing_arch_does_not_acquire_pseudo_architecture(self):
        for name in ('kernel-core', 'linux-firmware-whence', 'gpg-pubkey-extra', 'GPG-pubkey'):
            for arch in (None, [], ['']):
                value = {'Name': [name], 'Version': ['350d275d'], 'Release': ['6279464b']}
                if arch is not None: value['Arch'] = arch
                with self.subTest(name=name, arch=arch), self.assertRaises(Refused): rpm.identity(value)

    def test_inventory_pseudo_package_cannot_enter_inert_payload_installer(self):
        value = {**header(), 'Name': ['gpg-pubkey'], 'Version': ['350d275d'], 'Release': ['6279464b']}
        del value['Arch']
        self.assertEqual(rpm.identity(value)['arch'], 'none')
        with self.assertRaisesRegex(Refused, 'package_requires_migration_recipe'):
            rpm.payload(value)

    def test_header_parser_refuses_entities_duplicates_and_unexpected_types(self):
        for data in ('<!DOCTYPE rpmHeader><rpmHeader/>', '<rpmHeader><rpmTag name="Name"/><rpmTag name="Name"/></rpmHeader>', '<rpmHeader><rpmTag name="Name"><file>bad</file></rpmTag></rpmHeader>'):
            with self.subTest(data=data), self.assertRaises(Refused):rpm.headers(data)

    def test_payload_refuses_scripts_links_config_ghost_setuid_and_unknown_hash(self):
        for key,value in [('Postin',['touch /etc/arbitrary']),('Filelinktos',['','elsewhere']),
                          ('Fileflags',[0,1]),('Fileflags',[0,16]),('Fileflags',[0,64]),('Filemodes',[stat.S_IFDIR|0o755,stat.S_IFREG|0o4755]),
                          ('Filedigestalgo',[1]),('Filecaps',['','cap_net_admin=ep'])]:
            with self.subTest(key=key,value=value), self.assertRaises(Refused):
                rpm.payload({**header(),key:value})

    def test_boot_checker_and_package_manager_require_explicit_migration(self):
        for name in ('kernel-core','aide','rpm','dnf','python3','openssl-libs','shim-x64','dracut','cryptsetup-libs'):
            with self.subTest(name=name), self.assertRaisesRegex(Refused,'migration_recipe'):
                rpm.payload({**header(),'Name':[name]})

    def test_external_triggers_match_package_or_file_prefix_not_neighbor(self):
        rpm.external_triggers([{'Filetriggername':['/usr/lib']}],['license'],['/usr/library/file'])
        for installed,paths in [([{'Triggername':['license']}],['/usr/share/license']),
                                ([{'Transfiletriggername':['/usr/lib']}],['/usr/lib/modprobe.d/file']),
                                ([{'Filetriggername':['unexpected']}],['/usr/share/license'])]:
            with self.subTest(installed=installed), self.assertRaises(Refused):rpm.external_triggers(installed,['license'],paths)

    def test_signature_requires_enrolled_rsa_signature_not_digest_only(self):
        valid='test.rpm:\n Header V4 RSA/SHA256 Signature, key ID 350d275d: OK\n Header SHA256 digest: OK\n Payload SHA256 digest: OK\n'
        self.assertEqual(rpm.signature(Path('/retained/test.rpm'),Path('/keys'),Mock(return_value=valid))['key_id'],'350d275d')
        for text in ('Header SHA256 digest: OK', valid.replace('350d275d','deadbeef'),valid.replace('RSA/SHA256','DSA/SHA1'),valid+'BAD signature'):
            with self.subTest(text=text), self.assertRaises(Refused):rpm.signature(Path('/retained/test.rpm'),Path('/keys'),Mock(return_value=text))

    def test_private_signature_database_is_labeled_without_changing_global_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"keydb"
            runner = Mock(return_value="gpg-pubkey 350d275d")
            rpm.init_keydb(path, runner)
            self.assertEqual(runner.call_args_list[0].args[0], ["/usr/bin/chcon", "--reference=/var/lib/rpm", str(path)])
            self.assertEqual(runner.call_args_list[1].args[0], ["/usr/bin/rpm", "--dbpath", str(path), "--initdb"])
            with self.assertRaises(FileExistsError):rpm.init_keydb(path, runner)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(Refused, "isolated_keyring_changed"):
                rpm.init_keydb(Path(directory)/"keydb", Mock(return_value="gpg-pubkey 350d275d\ngpg-pubkey deadbeef"))

    def test_exact_apply_argv_has_no_solver_or_validation_bypass(self):
        plan={'excludedocs':False,'packages':[{'rpm':'a'*64+'.rpm'}]}
        expected=['/usr/bin/rpm','--upgrade','/stage/packages/'+'a'*64+'.rpm']
        self.assertEqual(rpm.command(Path('/stage'),plan),expected)
        self.assertEqual(rpm.command(Path('/stage'),plan,test=True),expected[:2]+['--test']+expected[2:])
        for forbidden in ('--nodeps','--nosignature','--noscripts','--notriggers','--oldpackage','--replacefiles'):
            self.assertNotIn(forbidden,rpm.command(Path('/stage'),plan))

    def test_prepare_report_refuses_any_drift_and_forward_only_exact_files(self):
        plan={'files':[{'path':'/usr/share/licenses/example'}]}
        rpm.allowed_integrity_report({'changed':{'/usr/share/licenses/example':'f ...'}},plan,'forward')
        for report,phase in [({'changed':{'/usr/share/licenses/example':'f ...'}},'prepare'),
                             ({'changed':{'/etc/passwd':'f ...'}},'forward'),
                             ({'added':{'/usr/share/licenses/example':'f ...'}},'forward'),
                             ({'removed':{'/usr/share/licenses/example':'f ...'}},'forward'), ({},'rollback')]:
            with self.subTest(report=report,phase=phase),self.assertRaises(Refused):rpm.allowed_integrity_report(report,plan,phase)


class NoUpdatesObservationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.stage=self.root / "manager/os-updates/one"
        self.stage.mkdir(parents=True)
        self.boot="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        self.journal=self.root / "manager/os-transaction.json"
        self.latest=self.root / "manager/os-latest.json"
        self.journal.write_text(json.dumps({"state": "planning", "stage": str(self.stage), "boot_id": self.boot}))
        self.inventory=["linux-firmware-whence-0:20260804-161.2.el9_8.noarch"]
        self.runner=Mock(return_value="")
        self.manager=Mock()
        self.manager._check_locked.return_value={"state": "clean", "exit_code": 0}
        original_read=Path.read_text
        boot=self.boot
        def read_text(path, *args, **kwargs):
            if str(path) == "/proc/sys/kernel/random/boot_id":
                return boot
            return original_read(path, *args, **kwargs)
        @contextmanager
        def coordination(manager):
            self.assertIs(manager, self.manager)
            yield self.root / "manager/aide", SimpleNamespace(root=self.root)
        patches=[patch.object(rpm, 'read', side_effect=lambda path, maximum=rpm.MAX_RPM: Path(path).read_bytes()),
                 patch.object(rpm, 'inventory', return_value=('fixture XML', [], self.inventory)),
                 patch.object(Path, 'read_text', read_text),
                 patch('nebulalog_manager.aide.Aide', return_value=self.manager),
                 patch.object(aide_updates, '_locked', coordination)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def prepare(self):
        result=rpm.prepare(self.stage, {}, runner=self.runner)
        self.assertEqual(result['status'], 'no_updates')
        self.journal.write_text(json.dumps({"state": "postcheck", "stage": str(self.stage), "boot_id": self.boot,
                                           "no_updates": True, "plan_sha256": None}))
        self.latest.write_text(json.dumps({"state": "prepared", "stage": str(self.stage), "boot_id": self.boot}))
        return result

    def test_empty_download_can_check_existing_integrity_without_accepting_new_baseline(self):
        self.prepare()
        result=rpm.accept_integrity(self.stage, runner=self.runner)
        self.assertTrue(result['ok'])
        self.assertEqual(result['package']['status'], 'no_updates')
        self.manager._check_locked.assert_called_once()
        self.manager.authorized_update_accept.assert_not_called()
        self.manager.authorized_update_prepare.assert_not_called()
        self.assertEqual(len(self.runner.call_args_list), 1)
        command=self.runner.call_args.args[0]
        self.assertEqual(command[0], '/usr/bin/dnf')
        self.assertIn('--downloadonly', command)
        self.assertFalse((self.stage / 'rpm-apply-intent.json').exists())

    def test_changed_inventory_during_download_creates_no_empty_transaction_proof(self):
        with patch.object(rpm, 'inventory', side_effect=[('before', [], self.inventory), ('after', [], ['other'])]):
            with self.assertRaisesRegex(Refused, 'inventory_changed_during_download'):
                rpm.prepare(self.stage, {}, runner=self.runner)
        self.assertFalse((self.stage / 'os-no-updates.json').exists())

    def test_no_updates_refuses_changed_operation_boot_or_transaction(self):
        self.prepare()
        original=self.journal.read_bytes()
        record=json.loads(original)
        for changes in ({'stage': '/other'}, {'boot_id': 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'},
                        {'state': 'planning'}, {'no_updates': False}, {'plan_sha256': 'a'*64}):
            with self.subTest(changes=changes):
                self.journal.write_text(json.dumps({**record, **changes}))
                with self.assertRaisesRegex(Refused, 'operation_binding_changed'):
                    rpm.accept_integrity(self.stage, runner=self.runner)
                self.journal.write_bytes(original)
        operation=self.stage / 'operation.json'
        value=json.loads(operation.read_text())
        operation.write_text(json.dumps({**value, 'id': 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}))
        with self.assertRaisesRegex(Refused, 'operation_binding_changed'):
            rpm.accept_integrity(self.stage, runner=self.runner)
        self.manager._check_locked.assert_not_called()

    def test_changed_current_boot_or_latest_stage_cannot_reuse_observation(self):
        self.prepare()
        self.latest.write_text(json.dumps({'stage': '/other', 'boot_id': self.boot}))
        with self.assertRaisesRegex(Refused, 'operation_binding_changed'):
            rpm.accept_integrity(self.stage, runner=self.runner)
        self.latest.write_text(json.dumps({'stage': str(self.stage), 'boot_id': self.boot}))
        original_read=Path.read_text
        def different_boot(path, *args, **kwargs):
            if str(path) == '/proc/sys/kernel/random/boot_id':
                return 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            return original_read(path, *args, **kwargs)
        with patch.object(Path, 'read_text', different_boot), self.assertRaisesRegex(Refused, 'operation_binding_changed'):
            rpm.accept_integrity(self.stage, runner=self.runner)
        self.manager._check_locked.assert_not_called()

    def test_empty_transaction_cannot_mask_planned_or_attempted_rpm_mutation(self):
        self.prepare()
        for name in ('os-payload-plan.json', 'os-integrity-plan.json', 'rpm-apply-intent.json'):
            with self.subTest(name=name):
                path=self.stage / name
                path.write_text('{}')
                with self.assertRaisesRegex(Refused, 'conflicts_with_package_transaction'):
                    rpm.accept_integrity(self.stage, runner=self.runner)
                path.unlink()
        self.manager._check_locked.assert_not_called()

    def test_inventory_drift_before_or_during_aide_refuses_without_baseline_replacement(self):
        self.prepare()
        with patch.object(rpm, 'inventory', return_value=('changed', [], ['other'])):
            with self.assertRaisesRegex(Refused, 'package_inventory_changed'):
                rpm.accept_integrity(self.stage, runner=self.runner)
        self.manager._check_locked.assert_not_called()
        with patch.object(rpm, 'inventory', side_effect=[('before', [], self.inventory), ('changed', [], ['other'])]):
            with self.assertRaisesRegex(Refused, 'package_inventory_changed'):
                rpm.accept_integrity(self.stage, runner=self.runner)
        self.manager.authorized_update_accept.assert_not_called()

    def test_integrity_drift_or_unusable_check_cannot_authorize_reboot(self):
        self.prepare()
        for result in ({'state': 'differences', 'exit_code': 4}, {'state': 'clean', 'exit_code': 1}, {'state': 'clean'}):
            with self.subTest(result=result):
                self.manager._check_locked.return_value=result
                with self.assertRaisesRegex(Refused, 'integrity_not_clean'):
                    rpm.accept_integrity(self.stage, runner=self.runner)
        self.manager.authorized_update_accept.assert_not_called()


class OSIntegrityTransitionTests(unittest.TestCase):
    for _name,_value in aide_fixture.AuthorizedAideTests.__dict__.items():
        if not _name.startswith('__') and not _name.startswith('test_'):
            locals()[_name]=_value

    def os_fixture(self):
        self.authorized_fixture()
        self.monitored.remove(self.generation)
        self.monitored.remove(self.code)
        self.plan={'schema':1,'kind':'os-payload-v1','sequence':0,'manifest_sha256':'a'*64,
                   'files':[{'path':str(self.runtime),'before':self.desc(self.runtime),'after':self.desc(self.runtime,b'new managed\n')}],
                   'directories':[],'skipped_docs':[]}
        self.plan_path=self.stage/'os-integrity-plan.json'
        self.write_private(self.plan_path,json.dumps(self.plan).encode())

    def activate(self):self.runtime.write_bytes(b'new managed\n')

    def test_no_package_reboot_check_preserves_enrolled_baseline_and_rejects_real_fixture_drift(self):
        self.os_fixture()
        self.write_private(self.stage / 'os-no-updates.json', b'{}')
        with patch('nebulalog_manager.aide.Aide', return_value=self.manager), \
             patch.object(rpm, '_verify_no_updates', return_value={'kind': 'rocky-no-updates-v1'}):
            self.assertTrue(rpm.accept_integrity(self.stage)['ok'])
            self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
            self.assertEqual(self.scan_calls.count('update'), 0)
            checks=self.scan_calls.count('check')
            self.unrelated.write_bytes(b'unrelated drift')
            with self.assertRaisesRegex(Refused, 'no_updates_integrity_not_clean'):
                rpm.accept_integrity(self.stage)
            self.assertEqual(self.scan_calls.count('check'), checks + 1)
            self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
            self.assertEqual(self.scan_calls.count('update'), 0)
            self.assert_original()

    def test_os_payload_uses_retained_aide_update_chain_and_fresh_acceptance(self):
        self.os_fixture();self.prepare_update();self.activate()
        result=self.accept_update()
        self.assertTrue(result['ok'])
        self.assertEqual(self.manager.check()['state'],'clean')
        self.assertFalse(self.accept_update()['baseline_changed'])
        self.assertEqual(self.scan_calls.count('update'),1)
        self.assert_original()

    def test_os_prepare_refuses_preexisting_drift_even_in_replaced_file(self):
        self.os_fixture();self.runtime.write_bytes(b'unexpected')
        with self.assertRaisesRegex(Refused,'live_file_not_planned'):self.prepare_update()
        self.assertEqual(self.scan_calls.count('update'),0)

    def test_os_acceptance_refuses_unrelated_drift_without_adopting_database(self):
        self.os_fixture();self.prepare_update();self.activate();self.unrelated.write_bytes(b'unrelated drift')
        with self.assertRaisesRegex(Refused,'unrelated_integrity_change'):self.accept_update()
        self.assertEqual((self.state/'aide.db.gz').read_bytes(),self.initial_db)
        self.assertEqual(json.loads((self.state/'authorized/pending.json').read_text())['state'],'scanning')
        self.assert_original()

    def test_os_acceptance_refuses_metadata_and_automatic_rpm_rollback(self):
        self.os_fixture();self.prepare_update();self.activate()
        with patch.object(aide_updates,'_metadata',return_value={'xattrs_sha256':'d'*64,'acl_sha256':'e'*64,'selinux_sha256':'f'*64}):
            with self.assertRaisesRegex(Refused,'acl_xattrs_or_selinux_changed'):self.accept_update()
        with self.assertRaisesRegex(Refused,'rollback_requires'):self.accept_update('rollback')
        self.assertEqual(self.scan_calls.count('update'),0)

    def test_os_cas_interruption_recovers_same_scan_without_reexecuting_package(self):
        self.os_fixture();self.prepare_update();self.activate()
        original=aide_updates._replace_current
        def interrupt(*args,**kwargs):
            original(*args,**kwargs)
            raise OSError('after CAS interruption')
        with patch.object(aide_updates,'_replace_current',side_effect=interrupt),self.assertRaises(OSError):self.accept_update()
        self.assertEqual(json.loads((self.state/'authorized/pending.json').read_text())['state'],'ready')
        self.assertTrue(self.accept_update()['ok'])
        self.assertEqual(self.scan_calls.count('update'),1)
        self.assertEqual(self.manager.check()['state'],'clean')
        self.assert_original()


if __name__=='__main__':unittest.main()
