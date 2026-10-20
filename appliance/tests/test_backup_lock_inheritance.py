"""Backup runner binding and actual local child/flock lifetime boundaries.

These tests execute no database, container, system service or appliance command.
The fixture substitutes only directory ancestry admission and the UID/GID view
of exact test-owned lock files, permitting an unprivileged macOS/Linux run.
Production Commands descriptor/inode/mode/link validation, flock, pass_fds and
subprocess execution remain real. This is not native root/FIPS qualification.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_adapters import commands
from nebulalog_adapters.commands import Commands
from nebulalog_manager import backup
from nebulalog_manager.common import CommandFailed, Refused, locked
from nebulalog_manager.log_backup import LogBackupAdapter
from nebulalog_manager.log_recovery_set import LogRecoverySet
from nebulalog_manager.recovery_set import FullBackupManager


class SyntheticInterruption(BaseException):
    pass


class FixtureOwnershipOS:
    """Present root ownership only for an exact allowlisted fixture inode.

    Do not replace _inherited_fds or flock: the actual production checker must
    still reject replaced files, duplicate/closed descriptors and unsafe modes.
    """
    def __init__(self, paths):
        self.paths = paths

    def __getattr__(self, name):
        return getattr(os, name)

    def fstat(self, descriptor):
        observed = os.fstat(descriptor)
        for path in self.paths:
            try:
                retained = path.lstat()
            except FileNotFoundError:
                continue
            if ((observed.st_dev, observed.st_ino) == (retained.st_dev, retained.st_ino)
                    and observed.st_uid == os.getuid() and observed.st_gid == os.getgid()
                    and stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1
                    and stat.S_IMODE(observed.st_mode) == 0o600):
                fields = list(observed)
                fields[4] = fields[5] = 0
                return os.stat_result(fields)
        return observed


@unittest.skipUnless(os.name == "posix", "POSIX descriptor/flock fixture")
class BackupLockInheritanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="backup-lock-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.allowed_locks = set()
        owner_patch = patch.object(commands, "os", FixtureOwnershipOS(self.allowed_locks))
        owner_patch.start()
        self.addCleanup(owner_patch.stop)

        def fixture_directory(path, *, create=False, private=False):
            path = Path(path)
            if not path.is_relative_to(self.root) or path.resolve() != path:
                raise Refused("Directory escaped the owned lock fixture")
            if create:
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
            for item in (path, *path.parents):
                info = item.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077):
                    raise Refused("Untrusted owned fixture directory")
                if item == self.root:
                    break

        directory_patch = patch.object(backup, "_directory", side_effect=fixture_directory)
        directory_patch.start()
        self.addCleanup(directory_patch.stop)

    def graph(self, name, inherited=()):
        root = self.root / name
        data, bootstrap = root / "data", root / "bootstrap"
        for path in (data / "manager", data / "configuration/bootstrap", bootstrap):
            path.mkdir(parents=True, mode=0o700)
            for item in (path, *path.parents):
                item.chmod(0o700)
                if item == self.root:
                    break
        lifecycle = SimpleNamespace(cmd=Commands(inherited_locks=inherited), data=data)
        configuration = backup.ConfigurationBackup(lifecycle, data=data, bootstrap=bootstrap)
        native = LogBackupAdapter(lifecycle)
        native.backup.bootstrap = bootstrap
        transport = LogRecoverySet(configuration.cmd)
        manager = FullBackupManager(configuration, native, transport)
        paths = (configuration.manager / "transaction.lock", bootstrap / "firstboot.lock",
                 configuration.configuration / "bootstrap/runtime.lock",
                 configuration.configuration / "baseline.lock")
        self.allowed_locks.update((*paths, manager.manager / "recovery-set.lock"))
        return configuration, native, transport, manager, paths

    def outer_lock(self, stack, name="existing-coordinator.lock"):
        path = self.root / name
        self.allowed_locks.add(path)
        return (stack.enter_context(locked(path)), path)

    def assert_locked(self, path):
        with self.assertRaisesRegex(Refused, "already running"):
            with locked(path):
                self.fail("A competing owner acquired the retained lock")

    def assert_unlocked(self, path):
        with locked(path):
            pass

    def assert_closed(self, pairs):
        for descriptor, _ in pairs:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_configuration_binds_four_locks_and_restores_distinct_runners(self):
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted), ExitStack() as outer:
                inherited = self.outer_lock(outer)
                configuration, _, _, _, paths = self.graph("configuration-" + str(interrupted))
                observer, failure = Mock(), Mock()
                original = Commands(inherited_locks=(inherited,), observer=observer, failure_observer=failure)
                lifecycle_original = Commands(observer=Mock(), failure_observer=Mock())
                configuration.cmd, configuration.lifecycle.cmd = original, lifecycle_original
                descriptors = []
                try:
                    with ExitStack() as stack:
                        descriptors = configuration._locks(stack)
                        self.assertEqual(tuple(path for _, path in descriptors), paths)
                        bound = configuration.cmd
                        self.assertIs(bound, configuration.lifecycle.cmd)
                        self.assertIsNot(bound, original)
                        self.assertEqual(bound.inherited_locks, (inherited, *descriptors))
                        self.assertIs(bound.observer, observer)
                        self.assertIs(bound.failure_observer, failure)
                        self.assertEqual(bound._inherited_fds(), tuple(fd for fd, _ in (inherited, *descriptors)))
                        for path in paths:
                            self.assert_locked(path)
                        if interrupted:
                            raise SyntheticInterruption()
                except SyntheticInterruption:
                    self.assertTrue(interrupted)
                self.assertIs(configuration.cmd, original)
                self.assertIs(configuration.lifecycle.cmd, lifecycle_original)
                self.assert_closed(descriptors)
                self.assert_locked(inherited[1])
                for path in paths:
                    self.assert_unlocked(path)

    def test_partial_configuration_acquisition_releases_prior_lock_without_rebinding(self):
        configuration, _, _, _, paths = self.graph("partial-acquisition")
        original, lifecycle_original = configuration.cmd, configuration.lifecycle.cmd
        with locked(paths[1]):
            with self.assertRaisesRegex(Refused, "already running"):
                with ExitStack() as stack:
                    configuration._locks(stack)
            self.assertIs(configuration.cmd, original)
            self.assertIs(configuration.lifecycle.cmd, lifecycle_original)
            self.assert_unlocked(paths[0])
            self.assert_locked(paths[1])
        for path in paths[:2]:
            self.assert_unlocked(path)

    def test_bound_command_failure_preserves_original_dispatch_and_failure_observers(self):
        configuration, _, _, _, paths = self.graph("command-failure")
        observer, failure = Mock(return_value="existing-ticket"), Mock()
        original = Commands(observer=observer, failure_observer=failure)
        lifecycle_original = configuration.lifecycle.cmd
        configuration.cmd = original
        with self.assertRaises(CommandFailed) as caught:
            with ExitStack() as stack:
                configuration._locks(stack)
                configuration.cmd([sys.executable, "-B", "-c", "raise SystemExit(7)"], timeout=5)
        self.assertEqual(caught.exception.execution_ticket, "existing-ticket")
        self.assertEqual([call.args[:2] for call in observer.call_args_list], [("dispatch", "call")])
        failure.assert_called_once_with("call", ticket="existing-ticket", returncode=7)
        self.assertIs(configuration.cmd, original)
        self.assertIs(configuration.lifecycle.cmd, lifecycle_original)
        for path in paths:
            self.assert_unlocked(path)

    def test_full_manager_binds_every_owner_preserves_observers_and_restores(self):
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted), ExitStack() as outer:
                inherited = self.outer_lock(outer)
                configuration, native, transport, manager, _ = self.graph("full-" + str(interrupted))
                owners = (configuration, configuration.lifecycle, native, native.backup, transport)
                originals = []
                for owner in owners:
                    owner.cmd = Commands(inherited_locks=(inherited,), observer=Mock(), failure_observer=Mock())
                    originals.append(owner.cmd)
                acquired = None
                try:
                    with manager._lock():
                        for owner, original in zip(owners, originals):
                            self.assertIsNot(owner.cmd, original)
                            self.assertEqual(owner.cmd.inherited_locks[:-1], original.inherited_locks)
                            self.assertIs(owner.cmd.observer, original.observer)
                            self.assertIs(owner.cmd.failure_observer, original.failure_observer)
                            if acquired is None:
                                acquired = owner.cmd.inherited_locks[-1]
                            self.assertEqual(owner.cmd.inherited_locks[-1], acquired)
                            self.assertEqual(len(owner.cmd._inherited_fds()), 2)
                        self.assertEqual(acquired[1], manager.manager / "recovery-set.lock")
                        self.assert_locked(acquired[1])
                        if interrupted:
                            raise SyntheticInterruption()
                except SyntheticInterruption:
                    self.assertTrue(interrupted)
                for owner, original in zip(owners, originals):
                    self.assertIs(owner.cmd, original)
                self.assert_closed((acquired,))
                self.assert_locked(inherited[1])
                self.assert_unlocked(acquired[1])

    def test_full_manager_deduplicates_aliased_owners_and_leaves_non_commands_untouched(self):
        configuration, native, _, manager, _ = self.graph("aliased")
        original = configuration.cmd
        native.backup = configuration
        manager.transport = configuration
        untouched = object()
        native.cmd = untouched
        with manager._lock():
            self.assertEqual(len(configuration.cmd.inherited_locks), 1)
            self.assertEqual(len(configuration.cmd._inherited_fds()), 1)
            self.assertIs(native.cmd, untouched)
        self.assertIs(configuration.cmd, original)
        self.assertIs(native.cmd, untouched)

    def test_binding_failure_restores_earlier_owners_and_releases_coordinator(self):
        configuration, native, transport, manager, _ = self.graph("binding-failure")
        owners = (configuration, configuration.lifecycle, native, native.backup, transport)
        stale_path = self.root / "stale.lock"
        self.allowed_locks.add(stale_path)
        with locked(stale_path) as descriptor:
            stale = Commands(inherited_locks=((descriptor, stale_path),))
        native.cmd = stale
        originals = [owner.cmd for owner in owners]
        with self.assertRaises(Refused):
            with manager._lock():
                self.fail("A closed inherited descriptor admitted dispatch")
        for owner, original in zip(owners, originals):
            self.assertIs(owner.cmd, original)
        self.assert_unlocked(manager.manager / "recovery-set.lock")

    def test_nested_configuration_and_native_bindings_keep_existing_coordinator(self):
        with ExitStack() as outer:
            inherited = self.outer_lock(outer)
            configuration, native, transport, manager, paths = self.graph("nested", (inherited,))
            owners = (configuration, configuration.lifecycle, native, native.backup, transport)
            originals = [owner.cmd for owner in owners]
            with manager._lock():
                coordinated = [owner.cmd for owner in owners]
                coordinator = configuration.cmd.inherited_locks[-1]
                with ExitStack() as stack:
                    descriptors = configuration._locks(stack)
                    self.assertEqual(configuration.cmd.inherited_locks, (inherited, coordinator, *descriptors))
                    self.assertIs(configuration.cmd, configuration.lifecycle.cmd)
                for owner, command in zip(owners, coordinated):
                    self.assertIs(owner.cmd, command)
                with native._locks():
                    self.assertIs(native.cmd, native.backup.cmd)
                    self.assertIs(native.cmd, configuration.lifecycle.cmd)
                    self.assertEqual(native.cmd.inherited_locks[:2], (inherited, coordinator))
                    self.assertEqual(tuple(path for _, path in native.cmd.inherited_locks[2:]), paths)
                    self.assertEqual(len(native.cmd._inherited_fds()), 6)
                for owner, command in zip(owners, coordinated):
                    self.assertIs(owner.cmd, command)
            for owner, command in zip(owners, originals):
                self.assertIs(owner.cmd, command)

    def test_real_child_keeps_all_flocks_after_parent_context_closes(self):
        # All three Commands execution paths use actual subprocess.run/pass_fds.
        # Closing the parent's descriptors models loss of its lock ownership;
        # no unrelated process is killed and the child has a bounded deadline.
        for method in ("call", "capture", "feed"):
            with self.subTest(method=method):
                parent = ExitStack()
                thread = None
                release = self.root / (method + "-release")
                results, errors = [], []
                try:
                    inherited = self.outer_lock(parent, method + "-outer.lock")
                    configuration, _, _, manager, _ = self.graph("child-" + method, (inherited,))
                    observer, failure = Mock(return_value="synthetic-ticket"), Mock()
                    configuration.cmd = Commands(inherited_locks=(inherited,), observer=observer, failure_observer=failure)
                    original = configuration.cmd
                    parent.enter_context(manager._lock())
                    inner = parent.enter_context(ExitStack())
                    configuration._locks(inner)
                    bound = configuration.cmd
                    retained = bound.inherited_locks
                    expected = {str(fd): [os.fstat(fd).st_dev, os.fstat(fd).st_ino] for fd, _ in retained}
                    ready = self.root / (method + "-ready.json")
                    script = """import json,os,sys,time
from pathlib import Path
ready,release=Path(sys.argv[1]),Path(sys.argv[2])
descriptors=json.loads(sys.argv[3])
observed={str(fd):[os.fstat(fd).st_dev,os.fstat(fd).st_ino] for fd in descriptors}
temporary=ready.with_suffix('.pending')
with os.fdopen(os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:
    json.dump(observed,stream);stream.flush();os.fsync(stream.fileno())
temporary.replace(ready)
deadline=time.monotonic()+10
while not release.exists():
    if time.monotonic()>=deadline: raise SystemExit(3)
    time.sleep(.01)
print('released')
"""
                    argv = [sys.executable, "-B", "-c", script, str(ready), str(release),
                            json.dumps([fd for fd, _ in retained])]
                    captured = self.root / (method + "-capture")
                    source = self.root / (method + "-input")
                    source.write_bytes(b"synthetic fixture input")
                    source.chmod(0o600)

                    def invoke():
                        try:
                            if method == "call":
                                results.append(bound(argv, timeout=15))
                            elif method == "capture":
                                bound.capture(argv, captured, timeout=15)
                                results.append(captured.read_text().strip())
                            else:
                                bound.feed(argv, source, timeout=15)
                                results.append("released")
                        except BaseException as exc:
                            errors.append(exc)

                    thread = threading.Thread(target=invoke, daemon=True)
                    thread.start()
                    deadline = time.monotonic() + 5
                    while not ready.exists() and thread.is_alive() and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue(ready.exists(), "Child readiness failed: " + repr(errors))
                    self.assertEqual(json.loads(ready.read_text()), expected)
                    parent.close()
                    self.assertIs(configuration.cmd, original)
                    self.assert_closed(retained)
                    for _, path in retained:
                        self.assert_locked(path)
                    release.touch(mode=0o600)
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive(), "Bounded local child did not settle")
                    self.assertEqual(errors, [])
                    self.assertEqual(results, ["released"])
                    self.assertEqual([call.args[:2] for call in observer.call_args_list],
                                     [("dispatch", method), ("complete", method)])
                    failure.assert_not_called()
                    for _, path in retained:
                        self.assert_unlocked(path)
                finally:
                    release.touch(mode=0o600)
                    parent.close()
                    if thread is not None:
                        thread.join(timeout=16)
                        self.assertFalse(thread.is_alive(), "Local child cleanup exceeded its command timeout")


if __name__ == "__main__":
    unittest.main()
