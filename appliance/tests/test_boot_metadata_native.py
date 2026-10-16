"""Native metadata is evidence only; exercise precise drift and read boundaries."""
import base64
import copy
import ctypes
import ctypes.util
import errno
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from nebulalog_manager import boot_metadata_native as native
from nebulalog_manager import ordinary_boot_metadata as db
from nebulalog_manager.common import Refused
from nebulalog_manager.host_job_storage import digest
from test_ordinary_boot_metadata import compressed, parse

OLD_BOOT = '11111111-1111-4111-8111-111111111111'
NEW_BOOT = '22222222-2222-4222-8222-222222222222'


def description(checksum, mode=0o644):
    return {'kind': 'file', 'uid': 0, 'gid': 0, 'mode': mode, 'sha256': checksum,
            'bytes': 7, 'xattrs_sha256': digest({})}


def stable_authority():
    rows = parse(compressed())['rows']
    directories = {}
    for path in db.EFI_DIRECTORIES:
        children = {}
        for name in native.DIRECTORY_CHILDREN[path]:
            row = copy.deepcopy(rows[path + '/' + name]); del row['inode']
            row.update(ctime_ns=row['ctime_s'] * 1_000_000_000, mtime_ns=row['mtime_s'] * 1_000_000_000)
            children[name] = row
        directories[path] = {'kind': 'directory', 'mode': 0o700, 'uid': 0, 'gid': 0,
                             'bytes': 4096, 'nlink': 2, 'ctime_ns': 1760000000_000000000,
                             'mtime_ns': 1750000000_000000000, 'acl': None,
                             'selinux': rows[path]['selinux'], 'xattrs': rows[path]['xattrs'], 'children': children}
    writers = {path: {'owner': owner, 'description': description(checksum, mode)}
               for path, (checksum, owner, mode) in native.WRITERS.items()}
    writers[native.ACL_LINK] = {'owner': native.ACL_OWNER, 'description': {
        'kind': 'symlink', 'uid': 0, 'gid': 0, 'mode': 0o777,
        'target': Path(native.LIBACL).name, 'xattrs_sha256': digest({})}}
    return {'schema': 1, 'writers': writers, 'execution': copy.deepcopy(native.EXECUTION), 'configuration': {
        directory: None if entries is None else {
            name: description(checksum, native.CONFIGURATION_MODES.get(directory + '/' + name, 0o644))
            for name, checksum in entries.items()}
        for directory, entries in native.CONFIGURATION_PINS.items()},
        'mount': {'target': '/boot/efi', 'fstype': 'vfat', 'options': native.MOUNT_OPTIONS,
                  'uuid': '116A-392B', 'partuuid': '021c7f09-9e81-47d7-81b7-f0ddf5a6dcf8', 'fsroot': '/'},
        'targets': sorted(db.TARGETS), 'directories': directories}


def fixture():
    database = parse(compressed())
    database['source'] = {'basis': 'published', 'head': {'id': 'a' * 32, 'sha256': 'b' * 64},
                          'observed_head': {'id': 'a' * 32, 'sha256': 'b' * 64},
                          'original_enrollment_sha256': 'c' * 64, 'pending_sha256': None}
    rows = copy.deepcopy(database['rows'])
    for path, row in rows.items():
        row['ctime_ns'] = row['ctime_s'] * 1_000_000_000
        row['mtime_ns'] = row['mtime_s'] * 1_000_000_000
    snapshot = {'schema': 1, 'boot_id': NEW_BOOT, 'authority': stable_authority(), 'rows': rows,
                'service': {'invocation_id': 'd' * 32, 'result': 'success', 'exit_code': 1, 'exit_status': 0,
                            'start_us': 1760000100_000000, 'end_us': 1760000101_000000,
                            'start_monotonic_us': 75_000000, 'end_monotonic_us': 76_000000,
                            'active_monotonic_us': 76_001000, 'credentials': []},
                'observed_at_ns': 1760000200_000000000, 'uptime_us': 176_000000}
    return database, snapshot


def with_changes():
    database, snapshot = fixture()
    for path in db.TMPFILES:
        snapshot['rows'][path]['ctime_s'] = 1760000100
        snapshot['rows'][path]['ctime_ns'] = 1760000100_500000000
    for path in db.EFI_TARGETS:
        snapshot['rows'][path]['inode'] += 1
    return database, snapshot


class NativeTransitionTests(unittest.TestCase):
    def proof(self, database, snapshot, source_boot=OLD_BOOT, authority=None):
        return native.transition(authority or stable_authority(), snapshot,
                                 database=database, source_boot_id=source_boot)

    def test_twenty_exact_changes_bind_full_authenticated_source_and_capture(self):
        database, snapshot = with_changes()
        proof = self.proof(database, snapshot)
        self.assertEqual(len(proof['changes']), 20)
        self.assertEqual(proof['authority_sha256'], digest(snapshot['authority']))
        self.assertEqual(proof['database_sha256'], database['database_sha256'])
        self.assertEqual(proof['database_source'], database['source'])
        self.assertEqual(proof['database_rows_sha256'], digest(database['rows']))
        self.assertEqual(proof['snapshot_sha256'], digest(snapshot))
        for change in proof['changes']:
            self.assertEqual(change['attribute'], 'inode' if change['path'] in db.EFI_TARGETS else 'ctime')
            db.validate_change_summary(change['path'], change['summary'], row=database['rows'][change['path']],
                                       attribute=change['attribute'])

    def test_same_boot_never_authorizes_any_target_metadata_change(self):
        database, snapshot = with_changes()
        for path in db.TARGETS:
            with self.subTest(path=path), self.assertRaises(Refused):
                value = fixture()[1]
                value['rows'][path] = snapshot['rows'][path]
                self.proof(database, value, NEW_BOOT)

    def test_same_boot_and_reboot_no_change_are_empty_observations(self):
        database, snapshot = fixture()
        for source in (OLD_BOOT, NEW_BOOT):
            self.assertEqual(self.proof(database, snapshot, source)['changes'], [])

    def test_historical_seconds_are_from_database_not_stale_capture(self):
        database, snapshot = with_changes()
        # Accepted software update can replace content; authority has no stale rows.
        for value in (database['rows']['/etc/issue'], snapshot['rows']['/etc/issue']):
            value['sha512'] = 'e' * 128
            value['bytes'] = 99
            value['mtime_s'] = 1759999900
        snapshot['rows']['/etc/issue']['mtime_ns'] = 1759999900_123456789
        self.assertEqual(len(self.proof(database, snapshot)['changes']), 20)
        database['rows']['/etc/issue']['ctime_ns'] = 1760000000_123456789
        with self.assertRaises(Refused):
            self.proof(database, snapshot)

    def test_content_security_and_nonqualified_scalars_are_never_exempt(self):
        changes = {'sha512': 'f' * 128, 'bytes': 8, 'mode': 0o600, 'uid': 1, 'gid': 1,
                   'nlink': 2, 'inode': 100, 'mtime_s': 1750000001,
                   'acl': {'access': base64.b64encode(b'user::rwx\ngroup::---\nother::---\n').decode(), 'default': None},
                   'xattrs': {'user.added': 'eA=='}}
        for key, value in changes.items():
            database, snapshot = with_changes()
            snapshot['rows']['/etc/issue'][key] = value
            if key == 'mtime_s':
                snapshot['rows']['/etc/issue']['mtime_ns'] = value * 1_000_000_000
            with self.subTest(key=key), self.assertRaises(Refused):
                self.proof(database, snapshot)

    def test_symlink_target_and_efi_ctime_refuse(self):
        for path, key, value in [('/etc/os-release', 'target', '../usr/lib/other'),
                                  (db.EFI[0], 'ctime_s', 1760000100)]:
            database, snapshot = with_changes()
            snapshot['rows'][path][key] = value
            if key == 'ctime_s':
                snapshot['rows'][path]['ctime_ns'] = value * 1_000_000_000
            with self.assertRaises(Refused):
                self.proof(database, snapshot)

    def test_ctime_requires_exact_successful_interval_with_live_ns(self):
        for when in (1760000099_999999999, 1760000101_000001000, 1759999999_500000000):
            database, snapshot = with_changes()
            snapshot['rows']['/etc/issue'].update(ctime_ns=when, ctime_s=when // 1_000_000_000)
            with self.subTest(when=when), self.assertRaises(Refused):
                self.proof(database, snapshot)
        for when in (1760000100_000000000, 1760000101_000000999):
            database, snapshot = with_changes()
            snapshot['rows']['/etc/issue'].update(ctime_ns=when, ctime_s=when // 1_000_000_000)
            self.proof(database, snapshot)

    def test_failed_service_rerun_late_or_ambiguous_interval_refuses(self):
        for key, value in [('result', 'exit-code'), ('exit_status', 73), ('exit_code', True),
                           ('invocation_id', 'x' * 32), ('credentials', ['tmpfiles.extra']),
                           ('start_monotonic_us', 301_000000), ('end_monotonic_us', 175_000000),
                           ('end_us', 1760000300_000000), ('active_monotonic_us', 74_000000)]:
            database, snapshot = with_changes()
            snapshot['service'][key] = value
            with self.subTest(key=key), self.assertRaises(Refused):
                self.proof(database, snapshot)

    def test_pure_parsed_or_missing_database_rows_have_no_authority(self):
        database, snapshot = fixture()
        del database['source']
        with self.assertRaises(Refused):
            self.proof(database, snapshot)
        database, snapshot = fixture()
        del database['rows'][db.EFI[0]]
        with self.assertRaises(Refused):
            self.proof(database, snapshot)

    def test_strict_row_types_masks_and_encodings(self):
        for key, value in [('attributes', db.EFI_MASK), ('inode', True), ('ctime_ns', 1),
                           ('selinux', 'bad!'), ('sha512', 'A' * 128), ('mode', 0o4755),
                           ('xattrs', {'security.selinux': 'b29wcw=='})]:
            _, snapshot = fixture()
            snapshot['rows']['/etc/issue'][key] = value
            with self.subTest(key=key), self.assertRaises(Refused):
                native.validate_snapshot(snapshot)


class AuthorityTests(unittest.TestCase):
    def test_authority_excludes_rows_and_service_and_returns_copy(self):
        _, snapshot = fixture()
        value = native.authority(snapshot)
        self.assertEqual(value, stable_authority())
        value['mount']['uuid'] = 'AAAA-BBBB'
        self.assertNotEqual(value, snapshot['authority'])

    def test_comparable_snapshot_strips_only_validated_advancing_clocks(self):
        _, snapshot = fixture()
        later = copy.deepcopy(snapshot)
        later['observed_at_ns'] += 1000000000
        later['uptime_us'] += 1000000
        self.assertEqual(native.stable_snapshot(snapshot), native.stable_snapshot(later))
        later['rows']['/etc/issue']['inode'] += 1
        self.assertNotEqual(native.stable_snapshot(snapshot), native.stable_snapshot(later))
        later['uptime_us'] = 0
        with self.assertRaises(Refused):
            native.stable_snapshot(later)

    def test_vendor_library_hash_owner_link_or_permissions_fail_closed(self):
        for path, field, change in [(native.LIBACL, 'sha256', '1' * 64),
                                    (native.LIBACL, 'mode', 0o777),
                                    (native.ACL_LINK, 'target', 'other.so'),
                                    (native.SERVICE, 'uid', True)]:
            value = stable_authority()
            value['writers'][path]['description'][field] = change
            with self.subTest(field=field), self.assertRaises(Refused):
                native.validate_authority(value)
        value = stable_authority()
        value['writers'][native.LIBACL]['owner'] = 'untrusted-1'
        with self.assertRaises(Refused):
            native.validate_authority(value)

    def test_effective_configuration_added_removed_overridden_or_changed_refuses(self):
        for action in ('add', 'remove', 'override', 'content', 'symlink'):
            value = stable_authority()
            if action == 'add':
                value['configuration']['/etc/tmpfiles.d']['extra.conf'] = description('0' * 64)
            elif action == 'remove':
                del value['configuration']['/usr/lib/tmpfiles.d']['etc.conf']
            elif action == 'override':
                value['configuration']['/usr/local/lib/tmpfiles.d'] = {}
            elif action == 'content':
                value['configuration']['/run/tmpfiles.d']['static-nodes.conf']['sha256'] = '0' * 64
            else:
                value['configuration']['/usr/lib/tmpfiles.d']['etc.conf']['kind'] = 'symlink'
            with self.subTest(action=action), self.assertRaises(Refused):
                native.validate_authority(value)

    def test_volume_identity_must_equal_enrolled_authority(self):
        database, snapshot = fixture()
        for key, change in [('uuid', 'ABCD-1234'), ('partuuid', NEW_BOOT)]:
            value = copy.deepcopy(snapshot)
            value['authority']['mount'][key] = change
            native.validate_snapshot(value)
            with self.assertRaises(Refused):
                native.transition(stable_authority(), value, database=database, source_boot_id=OLD_BOOT)

    def test_filesystem_mount_options_target_scope_and_schema_are_exact(self):
        for key, change in [('fstype', 'ext4'), ('options', native.MOUNT_OPTIONS + ',nosuid'),
                            ('fsroot', '/subdir'), ('target', '/boot/efi/EFI'), ('uuid', 'abcd-1234')]:
            value = stable_authority(); value['mount'][key] = change
            with self.subTest(key=key), self.assertRaises(Refused):
                native.validate_authority(value)
        value = stable_authority(); value['targets'].append('/etc/passwd')
        with self.assertRaises(Refused):
            native.validate_authority(value)

    def test_bare_command_resolution_is_fixed_and_shadowing_refuses(self):
        value = stable_authority(); value['execution']['absent'].pop()
        with self.assertRaises(Refused):
            native.validate_authority(value)
        with patch.object(native, '_parents', return_value={}), \
                patch.object(native.os.path, 'lexists', return_value=True), self.assertRaises(Refused):
            native._authority(lambda argv: self.fail('shadow must refuse before executing tools'))
        value = stable_authority(); value['schema'] = True
        with self.assertRaises(Refused):
            native.validate_authority(value)


class NativeReadTests(unittest.TestCase):
    def service_text(self):
        start, end = 'Thu 2026-10-15 17:20:54.888384 UTC', 'Thu 2026-10-15 17:20:55.671696 UTC'
        values = {'Type': 'oneshot', 'RemainAfterExit': 'yes', 'Result': 'success', 'ExecMainCode': '1',
                  'ExecMainStatus': '0', 'InvocationID': 'd' * 32, 'FragmentPath': native.SERVICE,
                  'DropInPaths': '', 'Environment': '', 'RootDirectory': '', 'RootImage': '',
                  'User': '', 'Group': '', 'NeedDaemonReload': 'no', 'ExecSearchPath': '',
                  'ExecMainStartTimestamp': start, 'ExecMainExitTimestamp': end,
                  'ExecMainStartTimestampMonotonic': '76126564', 'ExecMainExitTimestampMonotonic': '76909875',
                  'ActiveEnterTimestampMonotonic': '76911055',
                  'ExecStart': '{ path=systemd-tmpfiles ; argv[]=systemd-tmpfiles --create --remove --boot --exclude-prefix=/dev ; '
                               'ignore_errors=no ; start_time=[' + start + '] ; stop_time=[' + end + '] ; pid=933 ; code=exited ; status=0 }'}
        return '\n'.join(key + '=' + value for key, value in values.items())

    def service(self, text, credentials=()):
        directory = MagicMock()
        directory.lstat.return_value = type('Info', (), {'st_mode': 0o40500, 'st_uid': 0, 'st_gid': 0})()
        directory.iterdir.return_value = iter(credentials)
        with patch.object(native, 'Path', return_value=directory), patch.object(native, '_parents', return_value={}):
            return native._service(lambda argv: text)

    def test_service_reads_vendor_command_precise_interval_and_empty_credentials(self):
        value = self.service(self.service_text())
        self.assertEqual(value['start_us'], 1792084854888384)
        self.assertEqual(value['end_us'], 1792084855671696)
        self.assertEqual(value['start_monotonic_us'], 76126564)
        self.assertEqual(value['credentials'], [])

    def test_service_effective_overrides_extra_commands_credentials_and_bad_output_refuse(self):
        original = self.service_text()
        bad = [original.replace('--exclude-prefix=/dev', '--prefix=/etc'),
               original.replace('DropInPaths=', 'DropInPaths=/etc/systemd/override.conf'),
               original.replace('NeedDaemonReload=no', 'NeedDaemonReload=yes'),
               original.replace('ExecSearchPath=', 'ExecSearchPath=/opt/extra'),
               original + '\nExecStartPre=/bad', original + '\nEnvironmentFiles=/etc/extra',
               original + '\nResult=success', original.replace('pid=933', 'pid=0')]
        for text in bad:
            with self.subTest(text=text[-30:]), self.assertRaises(Refused):
                self.service(text)
        with self.assertRaises(Refused):
            self.service(original, ['tmpfiles.extra'])

    def test_capture_checks_complete_second_observation_without_kernel_default_assumption(self):
        _, snapshot = fixture()
        def observe(path, acl): return copy.deepcopy(snapshot['rows'][path])
        path = MagicMock(); path.read_text.return_value = NEW_BOOT
        with patch.object(native, 'require_linux_root'), patch.object(native, 'Path', side_effect=lambda value: path if value == '/proc/sys/kernel/random/boot_id' else Path(value)), \
                patch.object(native, '_authority', return_value=snapshot['authority']) as stable, \
                patch.object(native, '_service', return_value=snapshot['service']), \
                patch.object(native, '_Acl'), patch.object(native, '_target', side_effect=observe) as target, \
                patch.object(native.time, 'time_ns', return_value=snapshot['observed_at_ns']), \
                patch.object(native.time, 'clock_gettime_ns', return_value=snapshot['uptime_us'] * 1000), \
                patch.object(native.time, 'CLOCK_BOOTTIME', 7, create=True):
            value = native.capture(runner=lambda argv: self.fail('no unrelated kernel/default query'))
        self.assertEqual(value, snapshot)
        self.assertEqual(stable.call_count, 2)
        self.assertEqual(target.call_count, 40)

    def test_capture_refuses_changed_authority_before_producing_observation(self):
        _, snapshot = fixture()
        changed = copy.deepcopy(snapshot['authority']); changed['mount']['uuid'] = 'ABCD-1234'
        path = MagicMock(); path.read_text.return_value = NEW_BOOT
        with patch.object(native, 'require_linux_root'), patch.object(native, 'Path', side_effect=lambda value: path if value == '/proc/sys/kernel/random/boot_id' else Path(value)), \
                patch.object(native, '_authority', side_effect=[snapshot['authority'], changed]), \
                patch.object(native, '_service', return_value=snapshot['service']), patch.object(native, '_Acl'), \
                patch.object(native, '_target', side_effect=lambda path, acl: snapshot['rows'][path]), self.assertRaises(Refused):
            native.capture()

    def test_timestamp_uses_exact_microseconds_and_rejects_ambiguous_format(self):
        self.assertEqual(native._timestamp('Thu 1970-01-01 00:00:01.000123 UTC'), 1_000123)
        for value in ('1970-01-01 00:00:01 UTC', 'Thu 1970-01-01 00:00:01.123 UTC', None):
            with self.assertRaises(Refused):
                native._timestamp(value)

    def test_libacl_calls_preserve_exact_text_and_always_free(self):
        class Fn:
            def __init__(self, callback): self.callback = callback
            def __call__(self, *args): return self.callback(*args)
        buffer = ctypes.create_string_buffer(b'user::rw-\ngroup::r--\nother::r--\n')
        freed = []
        def to_text(acl, length):
            ctypes.cast(length, ctypes.POINTER(ctypes.c_ssize_t))[0] = len(buffer.value)
            return ctypes.addressof(buffer)
        library = type('Library', (), {})()
        library.acl_get_fd = Fn(lambda fd: 123)
        library.acl_to_text = Fn(to_text)
        library.acl_free = Fn(lambda pointer: freed.append(pointer) or 0)
        with patch.object(native, '_file', return_value=description(native.WRITERS[native.LIBACL][0], 0o755)), \
                patch.object(native.ctypes, 'CDLL', return_value=library):
            acl = native._Acl()
        self.assertEqual(acl.access(1), {'access': base64.b64encode(buffer.value).decode(), 'default': None})
        self.assertEqual(freed, [ctypes.addressof(buffer), 123])
        with self.assertRaises(Refused):
            acl.access(1, unsupported=True)
        self.assertEqual(len(freed), 4)

    def test_acl_unsupported_only_for_exact_filesystem_case(self):
        acl = object.__new__(native._Acl)
        class Library:
            @staticmethod
            def acl_get_fd(fd):
                ctypes.set_errno(errno.ENOTSUP)
                return None
        acl.library = Library()
        self.assertIsNone(acl.access(1, unsupported=True))
        with self.assertRaises(Refused):
            acl.access(1)
        Library.acl_get_fd = staticmethod(lambda fd: (ctypes.set_errno(errno.EIO), None)[1])
        with self.assertRaises(Refused):
            acl.access(1, unsupported=True)

    @unittest.skipUnless(os.uname().sysname == 'Linux', 'native ACL ABI runs in Rocky tests')
    def test_actual_read_only_acl_abi_on_private_regular_fixture(self):
        library_name = ctypes.util.find_library('acl')
        self.assertIsNotNone(library_name)
        # Real ABI, private fixture; pin verification is tested separately above.
        acl = object.__new__(native._Acl)
        acl.library = ctypes.CDLL(library_name, use_errno=True)
        acl.library.acl_get_fd.argtypes = [ctypes.c_int]; acl.library.acl_get_fd.restype = ctypes.c_void_p
        acl.library.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
        acl.library.acl_to_text.restype = ctypes.c_void_p
        acl.library.acl_free.argtypes = [ctypes.c_void_p]; acl.library.acl_free.restype = ctypes.c_int
        with tempfile.TemporaryFile() as file:
            os.fchmod(file.fileno(), 0o640)
            before = os.fstat(file.fileno())
            ctypes.set_errno(0)
            probe = acl.library.acl_get_fd(file.fileno())
            if not probe and ctypes.get_errno() in {errno.ENOSYS, errno.ENOTSUP}:
                self.skipTest('isolated fixture filesystem lacks POSIX ACL; native guest qualification required')
            if probe:
                acl.library.acl_free(probe)
            actual = acl.access(file.fileno())
            self.assertEqual(base64.b64decode(actual['access']), b'user::rw-\ngroup::r--\nother::---\n')
            self.assertEqual(native._identity(os.fstat(file.fileno())), native._identity(before))


if __name__ == '__main__':
    unittest.main()
