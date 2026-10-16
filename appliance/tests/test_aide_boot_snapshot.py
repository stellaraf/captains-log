"""Private initial snapshot publication; capture/measurement are separate tests."""
import copy
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import aide, host_job_storage, kernel_updates, ordinary_boot_state
from nebulalog_manager.common import Refused


class InitialBootSnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.identity = host_job_storage.StorageIdentity('458a08e3-ef3b-4cd1-83e5-b402a2c1e913',
                                                        self.root, self.root.stat().st_dev)
        self.path = self.root / 'manager/boot-integrity/initial.json'
        self.tmpdir = self.root / 'manager/aide/tmp'
        self.tmpdir.mkdir(parents=True, mode=0o700)
        for path in (self.root, self.root / 'manager', self.tmpdir.parent):
            path.chmod(0o700)
        self.value = {'schema': 1, 'fixture_capture': 'original measured boot'}
        self.capture = Mock(side_effect=lambda **_: copy.deepcopy(self.value))
        self.real_validate = ordinary_boot_state.validate_snapshot
        self.validate = Mock()
        self.runner = Mock(return_value=aide.Result(0, 'command output\n'))
        for item in (patch.object(host_job_storage, 'ROOT_UID', os.getuid()),
                     patch.object(aide, 'ROOT_UID', os.getuid()),
                     patch.object(aide, 'protected_bytes', self.read),
                     patch.object(ordinary_boot_state, 'capture', self.capture),
                     patch.object(ordinary_boot_state, 'validate_snapshot', self.validate)):
            item.start()
            self.addCleanup(item.stop)

    def read(self, path, *, maximum=aide.MAX_DATABASE, private=False, device=None):
        path = Path(path)
        self.assertTrue(path.is_relative_to(self.root))
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size <= 0 or info.st_size > maximum
                or device is not None and info.st_dev != device):
            raise Refused('unsafe_snapshot_fixture')
        return path.read_bytes()

    def initial(self):
        return aide.initial_boot_snapshot(self.identity, self.runner, self.tmpdir)

    def test_capture_is_canonical_private_durable_and_retry_never_rewrites(self):
        facts = self.initial()
        raw = self.path.read_bytes()
        before = self.path.stat()
        self.assertEqual(raw, kernel_updates.encode(self.value))
        self.assertEqual(facts, {'ordinary_boot_snapshot_sha256': aide.sha(raw)})
        self.assertEqual(stat.S_IMODE(before.st_mode), 0o600)
        self.assertEqual(self.capture.call_count, 2)
        self.assertEqual(self.initial(), facts)
        self.assertEqual(self.path.stat().st_ino, before.st_ino)
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertEqual(self.capture.call_count, 3)

    def test_late_writer_during_first_capture_retains_original_and_refuses(self):
        before = copy.deepcopy(self.value)
        self.capture.side_effect = [before, {**before, 'fixture_capture': 'late writer'}]
        with self.assertRaisesRegex(Refused, 'not_current'):
            self.initial()
        self.assertEqual(self.path.read_bytes(), kernel_updates.encode(before))
        self.assertFalse((self.root / 'manager/aide/candidate.db.gz').exists())

    def test_late_writer_on_retry_cannot_recapture_original(self):
        facts = self.initial()
        raw = self.path.read_bytes()
        self.value['fixture_capture'] = 'later boot'
        with self.assertRaisesRegex(Refused, 'not_current'):
            self.initial()
        self.assertEqual(self.path.read_bytes(), raw)
        self.capture.reset_mock()
        retained = aide.verify_initial_boot_snapshot(self.identity, facts['ordinary_boot_snapshot_sha256'])
        self.assertEqual(retained['fixture_capture'], 'original measured boot')
        self.capture.assert_not_called()

    def test_missing_snapshot_with_any_existing_aide_authority_never_creates(self):
        names = ('candidate.json', 'candidate.db.gz', 'aide.db.gz', 'commit-pending.json', '../aide-enrollment.json')
        for name in names:
            path = self.tmpdir.parent / name
            path.write_bytes(b'existing authority')
            path.chmod(0o600)
            with self.subTest(name=name), self.assertRaisesRegex(Refused, 'snapshot_missing'):
                self.initial()
            path.unlink()
        self.capture.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_unknown_boot_integrity_state_cannot_be_adopted(self):
        self.path.parent.mkdir(mode=0o700)
        orphan = self.path.parent / 'orphan.json'
        orphan.write_bytes(b'preserve this evidence')
        orphan.chmod(0o600)
        with self.assertRaisesRegex(Refused, 'unowned_boot_integrity'):
            self.initial()
        self.assertEqual(orphan.read_bytes(), b'preserve this evidence')
        self.capture.assert_not_called()

    def test_changed_noncanonical_or_unsafe_snapshot_refuses_without_capture(self):
        facts = self.initial()
        checksum = facts['ordinary_boot_snapshot_sha256']
        raw = self.path.read_bytes()
        self.capture.reset_mock()
        self.path.write_bytes(raw + b'\n')
        with self.assertRaisesRegex(Refused, 'snapshot_changed'):
            aide.verify_initial_boot_snapshot(self.identity, aide.sha(raw + b'\n'))
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(Refused, 'snapshot_changed'):
            aide.verify_initial_boot_snapshot(self.identity, 'f' * 64)
        self.path.chmod(0o644)
        with self.assertRaisesRegex(Refused, 'unsafe_snapshot'):
            aide.verify_initial_boot_snapshot(self.identity, checksum)
        self.capture.assert_not_called()

    def test_capture_runner_is_bounded_and_refuses_diagnostics(self):
        def capture(*, runner):
            self.assertEqual(runner(['/usr/bin/uname', '-r'], timeout=17), 'command output')
            return copy.deepcopy(self.value)
        self.capture.side_effect = capture
        self.initial()
        self.runner.assert_called_with(['/usr/bin/uname', '-r'], tmpdir=self.tmpdir, timeout=17, maximum=aide.MAX_REPORT)
        for result in (aide.Result(1), aide.Result(0, '', 'warning')):
            self.runner.return_value = result
            with self.subTest(result=result), self.assertRaisesRegex(Refused, 'boot_command_failed'):
                self.initial()

    def test_inventory_capture_uses_rpm_xml_limit_without_unbounding_other_commands(self):
        def capture(*, runner):
            runner(['/usr/bin/rpm', '--query', '--all', '--xml'], timeout=180)
            return copy.deepcopy(self.value)
        self.capture.side_effect = capture
        self.initial()
        self.runner.assert_called_with(['/usr/bin/rpm', '--query', '--all', '--xml'], tmpdir=self.tmpdir,
                                       timeout=180, maximum=kernel_updates.rpm.MAX_XML)

    def test_retry_flushes_snapshot_after_publication_fsync_interruption(self):
        with patch.object(aide.Aide, '_sync', side_effect=OSError('interrupted directory sync')):
            with self.assertRaises(OSError):
                self.initial()
        original = self.path.read_bytes()
        original_inode = self.path.stat().st_ino
        sync = aide.Aide._sync
        calls = []
        def retain_barriers(manager, *paths):
            calls.extend(paths)
            return sync(manager, *paths)
        with patch.object(aide.Aide, '_sync', retain_barriers):
            self.initial()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.path.stat().st_ino, original_inode)
        self.assertTrue({self.path, self.path.parent, self.root / 'manager', self.root} <= set(calls))

    def test_real_snapshot_schema_binds_full_boot_state_and_rejects_rehashed_missing_artifact(self):
        from test_ordinary_boot_state import fixture
        self.value = fixture()
        self.validate.side_effect = self.real_validate
        facts = self.initial()
        self.assertEqual(aide.verify_initial_boot_snapshot(self.identity, facts['ordinary_boot_snapshot_sha256']), self.value)
        changed = copy.deepcopy(self.value)
        del changed['artifacts']['/boot/grub2/grub.cfg']
        raw = kernel_updates.encode(changed)
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(Refused, 'required_boot_artifact_missing'):
            aide.verify_initial_boot_snapshot(self.identity, aide.sha(raw))


if __name__ == '__main__':
    unittest.main()
