"""Prevent unqualified component selection from undoing restore token revocation."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import updates
from nebulalog_manager.common import Refused


class RestoredUpdateGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "data/manager/updates"
        self.state.mkdir(parents=True)
        self.auth = self.root / "data/configuration/bootstrap/restore-auth.json"
        self.auth.parent.mkdir(parents=True)
        self.pointer = self.state.parent / "restore.json"
        self.manager = updates.UpdateManager(self.state, runner=Mock())
        self.current = self.state / "current.json"
        self.current.write_bytes(b'{"preserved":"accepted release"}\n')
        guard = patch.object(updates, "require_linux_root")
        guard.start()
        self.addCleanup(guard.stop)

    def actions(self):
        key = self.root / "public.pem"
        return (lambda: self.manager.install(self.root / "manifest", self.root / "signature", self.root / "bundle", key),
                lambda: self.manager.rollback(key), lambda: self.manager.recover(key))

    def test_each_marker_refuses_before_key_reads_locks_hooks_or_journal_changes(self):
        for marker in (self.pointer, self.auth):
            for kind in ("file", "dangling-link"):
                with self.subTest(marker=marker.name, kind=kind):
                    if kind == "file":
                        marker.write_bytes(b"malformed evidence must still fence selection")
                    else:
                        marker.symlink_to(self.root / "missing")
                    with patch.object(updates, "trusted_file") as trust, patch.object(updates, "locked") as lock, \
                         patch.object(self.manager, "_hook") as hook:
                        for action in self.actions():
                            with self.assertRaisesRegex(Refused, "token issuance cutoff"):
                                action()
                        trust.assert_not_called()
                        lock.assert_not_called()
                        hook.assert_not_called()
                    self.assertEqual(self.current.read_bytes(), b'{"preserved":"accepted release"}\n')
                    self.assertEqual(list(self.state.iterdir()), [self.current])
                    marker.unlink()
        self.manager.runner.assert_not_called()

    def test_marker_arriving_during_lock_acquisition_refuses_before_effects(self):
        for action in self.actions():
            acquired = []
            @contextmanager
            def lock(path):
                acquired.append(path)
                if len(acquired) == 2:
                    self.pointer.write_bytes(b"restore claimed the host")
                yield 10
            with patch.object(updates, "locked", side_effect=lock), patch.object(updates, "trusted_file"), \
                 patch.object(updates.livepatch, "require_settled") as settled, \
                 patch.object(updates, "enrolled_key") as enrolled, patch.object(self.manager, "status") as status:
                with self.assertRaisesRegex(Refused, "token issuance cutoff"):
                    action()
                settled.assert_not_called()
                enrolled.assert_not_called()
                status.assert_not_called()
            self.assertEqual(len(acquired), 2)
            self.pointer.unlink()
        self.manager.runner.assert_not_called()

    def test_internal_host_rollback_also_refuses_before_generation_selection(self):
        self.auth.write_bytes(b"{}")
        with patch.object(self.manager, "_guard_hooks") as journal, \
             patch.object(updates.host_activation, "restore_previous") as select:
            with self.assertRaisesRegex(Refused, "token issuance cutoff"):
                self.manager._restore_host({"host_update": True}, self.root / "release")
            journal.assert_not_called()
            select.assert_not_called()

    def test_never_restored_host_passes_without_reading_or_changing_state(self):
        with patch.object(updates, "trusted_file") as trust:
            self.manager._require_restore_update_compatibility()
            trust.assert_not_called()
        self.assertEqual(list(self.state.iterdir()), [self.current])
        self.manager.runner.assert_not_called()
