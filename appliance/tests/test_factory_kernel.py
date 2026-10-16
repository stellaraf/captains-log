"""Factory provenance source tests; never invoke DNF, RPM or a real guest."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager.common import Refused

APPLIANCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('factory_kernel_fixture', APPLIANCE / 'factory_kernel.py')
factory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(factory)
VERSION = '5.14.0-687.57.1.el9_8.x86_64'


class FactoryKernelTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.destination = self.root / 'provenance'
        self.headers = [{'Name': [name], 'payload': {'name': name, 'kernel': VERSION,
                        'nevra': name + '-0:' + VERSION, 'files': [], 'scripts_sha256': 'a' * 64}}
                       for name in sorted(factory.kernel.NAMES)]
        self.patch(factory, 'DESTINATION', new=self.destination)
        self.patch(factory, 'SCRATCH', new=self.root)
        self.guard = self.patch(factory, 'guard')
        self.patch(factory, 'require_linux_root')
        self.patch(factory, 'directory')
        self.patch(factory, 'ancestry')
        self.key = self.patch(factory, 'trusted_key')
        self.patch(factory.rpm, 'platform')
        self.patch(factory.rpm, 'inventory', side_effect=lambda runner: (
            json.dumps(self.headers), copy.deepcopy(self.headers), [h['payload']['nevra'] for h in self.headers]))
        self.patch(factory.rpm, 'headers', side_effect=json.loads)
        self.patch(factory.kernel, 'payload', side_effect=lambda header: header['payload'])
        self.patch(factory.rpm, 'read', side_effect=lambda path, *args: Path(path).read_bytes())
        self.patch(factory.rpm, 'init_keydb')
        self.signature = self.patch(factory.rpm, 'signature', side_effect=lambda path, keydb, runner: {
            'key_id': factory.rpm.KEY_ID, 'report_sha256': factory.rpm.sha(Path(path).read_bytes())})
        self.runner = Mock(side_effect=self.command)
        self.patch(factory, 'run', side_effect=AssertionError('No host command allowed'))
        self.patch(factory.os, 'getuid', return_value=0)
        self.patch(factory.os, 'geteuid', return_value=0)

    def patch(self, target, name, **kwargs):
        item = patch.object(target, name, **kwargs)
        value = item.start(); self.addCleanup(item.stop)
        return value

    def command(self, argv, **kwargs):
        if argv == ['/usr/bin/uname', '-r']: return VERSION
        if argv == ['/usr/sbin/grubby', '--default-kernel']: return '/boot/vmlinuz-' + VERSION
        if argv[:2] == ['/usr/bin/rpm', '--verify']: return ''
        if argv[0] == '/usr/bin/dnf':
            folder = Path(argv[argv.index('--destdir') + 1])
            for header in self.headers:
                (folder / (header['payload']['name'] + '.rpm')).write_bytes(json.dumps([header]).encode())
            return ''
        if argv[:4] == ['/usr/bin/rpm', '--query', '--package', '--xml']:
            return Path(argv[-1]).read_text()
        if argv[:2] == ['/usr/sbin/restorecon', '-RF']: return ''
        raise AssertionError('Unexpected command: ' + repr(argv))

    def capture(self):
        return factory.capture(runner=self.runner)

    def test_capture_preserves_exact_signed_four_set_and_manifest_last(self):
        result = self.capture()
        self.assertTrue(result['verified'])
        self.assertEqual(result['kernel'], VERSION)
        self.assertEqual(len(list(self.destination.iterdir())), 7)
        manifest = json.loads((self.destination / 'manifest.json').read_bytes())
        self.assertEqual(set(manifest), {'schema', 'kernel', 'packages'})
        self.assertEqual({p['name'] for p in manifest['packages']}, factory.kernel.NAMES)
        for item in manifest['packages']:
            self.assertEqual(item['rpm'], item['sha256'] + '.rpm')
            self.assertEqual(factory.rpm.sha((self.destination / item['rpm']).read_bytes()), item['sha256'])
        capture = json.loads((self.destination / 'capture.json').read_bytes())
        self.assertFalse(capture['release_accepted'])
        self.assertEqual(capture['manifest_sha256'], result['manifest_sha256'])

    def test_download_is_exact_https_only_no_install_resolve_or_dependency_erasure(self):
        self.capture()
        argv = next(call.args[0] for call in self.runner.call_args_list if call.args[0][0] == '/usr/bin/dnf')
        self.assertIn('download', argv)
        self.assertIn('--disablerepo=*', argv)
        self.assertIn('--disableplugin=*', argv)
        self.assertIn('--repofrompath=captainslog-factory,' + factory.REPOSITORY, argv)
        self.assertIn('--setopt=captainslog-factory.sslverify=1', argv)
        self.assertEqual(argv[-4:], sorted(h['payload']['nevra'] for h in self.headers))
        self.assertFalse({'install', 'update', 'upgrade', '--resolve', '--nogpgcheck', '--allowerasing'} & set(argv))

    def test_existing_complete_capture_is_verified_without_redownload_or_overwrite(self):
        result = self.capture()
        before = {p.name: (p.stat().st_ino, p.read_bytes()) for p in self.destination.iterdir()}
        self.runner.reset_mock()
        self.assertEqual(self.capture(), result)
        self.assertEqual(before, {p.name: (p.stat().st_ino, p.read_bytes()) for p in self.destination.iterdir()})
        self.assertFalse(any(call.args[0][0] == '/usr/bin/dnf' for call in self.runner.call_args_list))

    def test_partial_capture_retries_only_same_bytes_preserving_original_evidence(self):
        original = factory.rpm.immutable
        def interruption(path, raw):
            if path.name == 'manifest.json': raise OSError('power loss')
            return original(path, raw)
        with patch.object(factory.rpm, 'immutable', side_effect=interruption), self.assertRaises(OSError): self.capture()
        before = {p.name: (p.stat().st_ino, p.read_bytes()) for p in self.destination.iterdir()}
        self.assertNotIn('manifest.json', before)
        self.assertTrue(self.capture()['verified'])
        for name, original_value in before.items():
            path = self.destination / name
            self.assertEqual((path.stat().st_ino, path.read_bytes()), original_value)

    def test_bad_signature_stops_before_manifest_or_inventory_publication(self):
        self.signature.side_effect = Refused('rocky_signature_not_verified')
        with self.assertRaisesRegex(Refused, 'signature_not_verified'): self.capture()
        self.assertFalse((self.destination / 'manifest.json').exists())
        self.assertFalse((self.destination / 'capture.json').exists())

    def test_missing_multiple_or_different_running_kernel_refuses_before_download(self):
        original = copy.deepcopy(self.headers)
        for changed in (original[:3], original + original[:1]):
            self.headers = changed
            with self.subTest(count=len(changed)), self.assertRaisesRegex(Refused, 'one complete'): self.capture()
        self.headers = original
        command = self.command
        self.runner.side_effect = lambda argv, **kw: 'other' if argv == ['/usr/bin/uname', '-r'] else command(argv, **kw)
        with self.assertRaisesRegex(Refused, 'running/default'): self.capture()
        self.assertFalse(any(call.args[0][0] == '/usr/bin/dnf' for call in self.runner.call_args_list))

    def test_installed_payload_verification_is_mandatory(self):
        self.runner.side_effect = lambda argv, **kw: 'changed /boot/vmlinuz' if argv[:2] == ['/usr/bin/rpm', '--verify'] else self.command(argv, **kw)
        with self.assertRaisesRegex(Refused, 'payload does not verify'): self.capture()
        self.assertFalse(self.destination.exists())

    def test_exact_download_header_and_count_are_required(self):
        command = self.command
        def wrong(argv, **kw):
            result = command(argv, **kw)
            if argv[0] == '/usr/bin/dnf':
                folder = Path(argv[argv.index('--destdir') + 1])
                next(folder.iterdir()).unlink()
            return result
        self.runner.side_effect = wrong
        with self.assertRaisesRegex(Refused, 'exactly four'): self.capture()
        self.assertFalse((self.destination / 'manifest.json').exists())

    def test_retained_rpm_or_receipt_tampering_and_extra_files_refuse(self):
        self.capture()
        target = next(self.destination.glob('*.rpm'))
        original = target.read_bytes(); target.write_bytes(b'changed')
        with self.assertRaisesRegex(Refused, 'RPM bytes changed'): factory.verify(runner=self.runner)
        target.write_bytes(original)
        receipt = self.destination / 'capture.json'
        original = receipt.read_bytes(); value = json.loads(original); value['key_sha256'] = 'f' * 64
        receipt.write_text(json.dumps(value))
        with self.assertRaisesRegex(Refused, 'receipt changed'): factory.verify(runner=self.runner)
        receipt.write_bytes(original)
        (self.destination / 'unrelated').write_bytes(b'evidence')
        with self.assertRaisesRegex(Refused, 'Unexpected'): factory.verify(runner=self.runner)

    def test_private_build_and_vendor_key_guards_precede_every_download(self):
        self.guard.side_effect = Refused('private build guard')
        with self.assertRaisesRegex(Refused, 'private build guard'): self.capture()
        self.runner.assert_not_called()
        self.guard.side_effect = None
        self.key.side_effect = Refused('vendor trust changed')
        with self.assertRaisesRegex(Refused, 'vendor trust changed'): self.capture()
        self.runner.assert_not_called()

    def test_build_and_integrity_wiring_is_mandatory(self):
        installer = (APPLIANCE / 'install-host.sh').read_text()
        self.assertIn('python3 "$APPLIANCE_SOURCE/factory_kernel.py"', installer)
        self.assertLess(installer.index('python3 "$APPLIANCE_SOURCE/factory_kernel.py"'), installer.index('python3 "$APPLIANCE_SOURCE/factory_host.py"'))
        for name in ('factory_host.py', 'host_boot.py', 'nebulalog_manager/update_enrollment.py', 'packer/stage_sources.py'):
            self.assertIn('appliance/factory_kernel.py', (APPLIANCE / name).read_text())
        self.assertIn("'/usr/libexec/nebulalog/factory-kernel', '--verify'", (APPLIANCE / 'provision_guard.py').read_text())
        policy = (APPLIANCE / 'security/aide-policy.conf').read_text()
        self.assertIn('/usr(/.*)? f,l,p,s,c,b NEBULALOGSTATIC', policy)
        self.assertNotIn('-/usr/share/nebulalog/kernel-provenance', policy)


class OwnershipTests(unittest.TestCase):
    def test_symlink_writable_or_foreign_ancestry_is_refused(self):
        good = {'st_mode': stat.S_IFDIR | 0o755, 'st_uid': 0, 'st_gid': 0}
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(**good)):
            factory.ancestry(Path('/usr/share/nebulalog/kernel-provenance'))
        for changed in ({'st_mode': stat.S_IFLNK | 0o755}, {'st_mode': stat.S_IFDIR | 0o777},
                        {'st_uid': 1}, {'st_gid': 1}):
            with self.subTest(changed=changed), patch.object(Path, 'lstat', return_value=SimpleNamespace(**{**good, **changed})), self.assertRaises(Refused):
                factory.ancestry(Path('/usr/share/nebulalog/kernel-provenance'))


class SourceBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.content = b'measured factory dependency'
        self.source = {'schema': 1, 'files': {'appliance/nebulalog_manager/' + name: factory.rpm.sha(self.content)
                         for name in ('kernel_updates.py', 'os_payload.py', 'common.py', 'host_job_storage.py')}}
        self.descriptor_hash = None
        def read(path, maximum):
            raw = json.dumps(self.source).encode()
            if path.name == 'source-manifest.json': return raw
            if path.name == 'initial-release.json':
                return json.dumps({'source_snapshot_sha256': self.descriptor_hash or factory.rpm.sha(raw)}).encode()
            return self.content
        item = patch.object(factory, 'protected_source', side_effect=read)
        self.read = item.start(); self.addCleanup(item.stop)

    def test_factory_original_dependencies_are_source_measured_before_import(self):
        factory.verify_runtime_source()
        self.assertEqual(self.read.call_count, 6)
        text = (APPLIANCE / 'factory_kernel.py').read_text()
        self.assertLess(text.index('    verify_runtime_source()'), text.index('from nebulalog_manager import'))

    def test_mismatched_descriptor_dependency_and_missing_required_source_refuse(self):
        self.descriptor_hash = 'f' * 64
        with self.assertRaisesRegex(RuntimeError, 'source binding'): factory.verify_runtime_source()
        self.descriptor_hash = None
        name = 'appliance/nebulalog_manager/common.py'
        self.source['files'][name] = 'f' * 64
        with self.assertRaisesRegex(RuntimeError, 'differs from captured'): factory.verify_runtime_source()
        del self.source['files'][name]
        with self.assertRaisesRegex(RuntimeError, 'inventory is incomplete'): factory.verify_runtime_source()

    def test_manifest_path_escape_is_rejected_before_dependency_read(self):
        self.source['files']['appliance/nebulalog_manager/../../escape.py'] = 'a' * 64
        with self.assertRaisesRegex(RuntimeError, 'source identity'): factory.verify_runtime_source()


if __name__ == '__main__':
    unittest.main()
