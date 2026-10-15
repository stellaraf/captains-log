"""Only the two measured VFAT directory inode effects receive boot authority."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from nebulalog_manager import boot_metadata_native as native
from nebulalog_manager import ordinary_boot_metadata as db
from nebulalog_manager.common import Refused
from test_boot_metadata_native import fixture, stable_authority, with_changes, OLD_BOOT, NEW_BOOT


class DirectoryTransitionTests(unittest.TestCase):
    def prove(self, database, value, boot=OLD_BOOT):
        return native.transition(stable_authority(), value, database=database, source_boot_id=boot)

    def test_two_directories_use_native_directory_summary_and_historical_inode(self):
        database, value = with_changes()
        changes = self.prove(database, value)['changes']
        selected = [item for item in changes if item['path'] in db.EFI_DIRECTORIES]
        self.assertEqual(len(selected), 2)
        for item in selected:
            self.assertEqual(item['summary'], 'd   ...   i   ..  ')
            self.assertEqual(item['before'], database['rows'][item['path']]['inode'])
            self.assertEqual(item['after'], value['rows'][item['path']]['inode'])

    def test_same_boot_directory_inode_replacement_never_qualifies(self):
        for path in db.EFI_DIRECTORIES:
            database, value = fixture()
            value['rows'][path]['inode'] += 1
            with self.subTest(path=path), self.assertRaisesRegex(Refused, 'unqualified_target_change'):
                self.prove(database, value, NEW_BOOT)

    def test_full_unmonitored_directory_scalars_are_bound_to_original_authority(self):
        for path in db.EFI_DIRECTORIES:
            for key in ('bytes', 'ctime_ns', 'mtime_ns'):
                database, value = with_changes()
                value['authority']['directories'][path][key] += 1
                native.validate_snapshot(value)
                with self.subTest(path=path, key=key), self.assertRaisesRegex(Refused, 'authority_changed'):
                    self.prove(database, value)
            for key, changed in [('kind', 'file'), ('nlink', 3), ('mode', 0o755), ('uid', 1), ('gid', 1),
                                 ('acl', {'access': 'eA==', 'default': None}), ('bytes', 0), ('ctime_ns', True)]:
                database, value = with_changes()
                value['authority']['directories'][path][key] = changed
                with self.subTest(path=path, key=key), self.assertRaises(Refused):
                    self.prove(database, value)

    def test_added_removed_or_renamed_child_is_never_hidden_by_inode_exception(self):
        for path in db.EFI_DIRECTORIES:
            for action in ('add', 'remove', 'rename'):
                database, value = with_changes()
                children = value['authority']['directories'][path]['children']
                name = next(iter(children))
                if action == 'add':
                    children['unowned.efi'] = copy.deepcopy(children[name])
                elif action == 'remove':
                    del children[name]
                else:
                    children['renamed.efi'] = children.pop(name)
                with self.subTest(path=path, action=action), self.assertRaises(Refused):
                    self.prove(database, value)

    def test_child_content_times_security_and_link_type_remain_exact(self):
        changes = {'sha512': 'e' * 128, 'bytes': 8, 'mode': 0o600, 'uid': 1, 'gid': 1,
                   'nlink': 2, 'kind': 'symlink', 'target': 'elsewhere', 'ctime_ns': 1760000000_000000001,
                   'mtime_ns': 1750000000_000000001, 'xattrs': {'user.extra': 'eA=='}}
        for path in db.EFI_DIRECTORIES:
            name = native.DIRECTORY_CHILDREN[path][0]
            for key, changed in changes.items():
                database, value = with_changes()
                value['authority']['directories'][path]['children'][name][key] = changed
                value['rows'][path + '/' + name][key] = changed
                with self.subTest(path=path, key=key), self.assertRaises(Refused):
                    self.prove(database, value)

    def test_directory_security_must_match_retained_authority_even_if_projection_matches(self):
        for path in db.EFI_DIRECTORIES:
            database, value = with_changes()
            value['authority']['directories'][path]['xattrs']['user.extra'] = 'eA=='
            value['rows'][path]['xattrs']['user.extra'] = 'eA=='
            native.validate_snapshot(value)
            with self.assertRaisesRegex(Refused, 'authority_changed'):
                self.prove(database, value)

    def test_live_directory_projection_cannot_invent_unmeasured_database_fields(self):
        for path in db.EFI_DIRECTORIES:
            for key in ('bytes', 'nlink', 'ctime_s', 'mtime_s', 'ctime_ns', 'mtime_ns'):
                database, value = with_changes()
                value['rows'][path][key] = 1
                with self.subTest(path=path, key=key), self.assertRaises(Refused):
                    self.prove(database, value)

    def test_missing_old_authority_or_nonfixed_scope_requires_explicit_migration(self):
        for mutation in ('legacy', 'missing', 'extra', 'mount'):
            database, value = with_changes()
            if mutation == 'legacy': del value['authority']['directories']
            elif mutation == 'missing': del value['authority']['directories'][db.EFI_DIRECTORIES[0]]
            elif mutation == 'extra': value['authority']['directories']['/boot/efi/EFI/other'] = value['authority']['directories'][db.EFI_DIRECTORIES[0]]
            else: value['authority']['mount']['uuid'] = 'ABCD-1234'
            with self.subTest(mutation=mutation), self.assertRaises(Refused):
                self.prove(database, value)


class DirectoryMountTests(unittest.TestCase):
    def measured(self, *, altered=None, device_changed=None):
        expected = {**stable_authority()['mount'], 'source': '/dev/vda1'}
        observed = []
        def runner(argv):
            self.assertEqual(argv[:3], ['/usr/bin/findmnt', '--json', '--target'])
            path = argv[3]; observed.append(path)
            result = copy.deepcopy(expected)
            if path == altered:
                result['source'] = '/dev/vdb1'
            return json.dumps({'filesystems': [result]})
        def path(value):
            result = MagicMock()
            result.stat.return_value.st_dev = 101
            result.lstat.return_value.st_dev = 102 if value == device_changed else 101
            return result
        with patch.object(native, 'Path', side_effect=path):
            result = native._mount(runner)
        return result, observed

    def test_both_directories_are_measured_on_the_same_mount_as_every_fixed_file(self):
        value, observed = self.measured()
        self.assertEqual(value, stable_authority()['mount'])
        self.assertEqual(observed, ['/boot/efi', *db.EFI_TARGETS])

    def test_directory_mount_or_device_substitution_refuses(self):
        for path in db.EFI_DIRECTORIES:
            for key in ('altered', 'device_changed'):
                with self.subTest(path=path, key=key), self.assertRaisesRegex(Refused, 'efi_target_mount_changed'):
                    self.measured(**{key: path})


@unittest.skipUnless(os.geteuid() == 0, 'actual descriptor ownership is exercised in root Rocky tests')
class DirectoryReadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = str(Path(temporary.name))
        os.chmod(self.path, 0o700)
        self.names = ('BOOTX64.EFI', 'fbx64.efi')
        for name in self.names:
            target = Path(self.path) / name
            target.write_bytes(b'fixture')
            target.chmod(0o700)
        files = tuple(self.path + '/' + name for name in self.names)
        self.acl = MagicMock(); self.acl.access.return_value = None
        # Only the fixture location/mount security boundary is substituted.
        # Directory enumeration, descriptors, hashing and scalar races are real.
        for context in [patch.object(db, 'EFI', files), patch.object(db, 'EFI_DIRECTORIES', (self.path,)),
                        patch.object(db, 'EFI_TARGETS', files + (self.path,)),
                        patch.object(native, 'DIRECTORY_CHILDREN', {self.path: self.names}),
                        patch.object(native, '_parents', return_value={}),
                        patch.object(native, '_xattrs', return_value={'security.selinux': b'system_u:object_r:dosfs_t:s0\0'})]:
            context.start(); self.addCleanup(context.stop)

    def test_actual_directory_descriptor_listing_hashes_and_scalars_are_retained(self):
        before = os.lstat(self.path)
        value = native._directory(self.path, self.acl)
        self.assertEqual(value['inode'], before.st_ino)
        self.assertEqual((value['bytes'], value['nlink'], value['ctime_ns'], value['mtime_ns']),
                         (before.st_size, before.st_nlink, before.st_ctime_ns, before.st_mtime_ns))
        self.assertEqual(set(value['children']), set(self.names))
        self.assertTrue(all(item['kind'] == 'file' and item['bytes'] == 7 for item in value['children'].values()))
        self.assertEqual(native._identity(os.lstat(self.path)), native._identity(before))

    def test_unexpected_child_and_symlink_refuse_without_repair(self):
        extra = Path(self.path) / 'extra'
        extra.write_bytes(b'extra')
        with self.assertRaisesRegex(Refused, 'directory_listing_changed'):
            native._directory(self.path, self.acl)
        self.assertEqual(extra.read_bytes(), b'extra')
        extra.unlink()
        child = Path(self.path) / self.names[0]
        child.unlink(); child.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(Refused, 'unsafe_target'):
            native._directory(self.path, self.acl)
        self.assertTrue(child.is_symlink())

    def test_real_directory_mutation_during_child_measurement_refuses(self):
        original = native._target
        changed = False
        def measured(path, acl):
            nonlocal changed
            result = original(path, acl)
            if not changed:
                changed = True
                (Path(self.path) / 'raced').write_bytes(b'not adopted')
            return result
        with patch.object(native, '_target', side_effect=measured), self.assertRaisesRegex(Refused, 'directory_changed_during_read'):
            native._directory(self.path, self.acl)
        self.assertTrue((Path(self.path) / 'raced').exists())


if __name__ == '__main__':
    unittest.main()
