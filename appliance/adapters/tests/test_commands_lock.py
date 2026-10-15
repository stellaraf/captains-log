"""Actual subprocess/flock survival; no system service or VM is touched."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from nebulalog_adapters.commands import Commands
from nebulalog_adapters.lifecycle import Lifecycle
from nebulalog_manager.common import CommandFailed, Refused, locked


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "native root-owned Linux descriptor contract")
class InheritedCommandLockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_native_child_retains_exact_flock_after_lifecycle_parent_is_killed(self):
        for method in ("call", "capture", "feed"):
            with self.subTest(method=method):
                directory = self.root / method
                directory.mkdir()
                lock = directory / "os-preflight.lock"
                ready, release = directory / "ready.json", directory / "release"
                child = """import json,os,time
from pathlib import Path
Path(%r).write_text(json.dumps({'pid':os.getpid()}))
while not Path(%r).exists(): time.sleep(0.02)
""" % (str(ready), str(release))
                parent = """import sys
from pathlib import Path
from nebulalog_manager.common import locked
from nebulalog_adapters.commands import Commands
with locked(Path(%r)) as descriptor:
    command=Commands(inherited_locks=((descriptor,Path(%r)),))
    argv=[sys.executable,'-c',%r]
    if %r=='call': command(argv,timeout=30)
    elif %r=='capture': command.capture(argv,Path(%r),timeout=30)
    else:
        source=Path(%r);source.write_bytes(b'private fixture')
        command.feed(argv,source,timeout=30)
""" % (str(lock), str(lock), child, method, method, str(directory / "output"), str(directory / "input"))
                environment = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
                process = subprocess.Popen([sys.executable, "-c", parent], env=environment,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                child_pid = None
                try:
                    deadline = time.monotonic() + 10
                    while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(ready.exists(), process.stderr.read().decode() if process.poll() is not None else "child readiness timeout")
                    child_pid = json.loads(ready.read_text())["pid"]
                    process.kill(); process.wait(timeout=5)
                    with self.assertRaisesRegex(Refused, "already running"):
                        with locked(lock):
                            self.fail("orphan child lost the OS preflight fence")
                    release.touch()
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            with locked(lock):
                                break
                        except Refused:
                            if time.monotonic() >= deadline:
                                self.fail("child did not release its inherited lock")
                            time.sleep(0.02)
                finally:
                    release.touch()
                    if process.poll() is None:
                        process.kill(); process.wait(timeout=5)
                    if child_pid is not None:
                        try:
                            os.kill(child_pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    process.stderr.close()

    def test_foreign_replaced_symlink_and_closed_descriptors_refuse(self):
        path = self.root / "os-preflight.lock"
        with locked(path) as descriptor:
            Commands(inherited_locks=((descriptor, path),))
            linked = self.root / "alias"
            linked.symlink_to(path)
            with self.assertRaises(Refused):
                Commands(inherited_locks=((descriptor, linked),))
            replacement = self.root / "replacement"
            replacement.write_bytes(b"")
            replacement.chmod(0o600)
            os.replace(replacement, path)
            with self.assertRaises(Refused):
                Commands(inherited_locks=((descriptor, path),))
        with self.assertRaises(Refused):
            Commands(inherited_locks=((descriptor, path),))

    def recorded(self, stage):
        manager = Lifecycle({}, Commands(), data=self.root, guard=lambda: None)
        manager.boot_id = lambda: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        observer = lambda phase, kind, **details: manager._os_command_event(stage, phase, kind, **details)
        return manager, observer

    def test_failed_command_retains_dispatch_and_blocks_next_command_before_spawn(self):
        manager, observer = self.recorded(self.root)
        command = Commands(observer=observer)
        with self.assertRaises(CommandFailed):
            command([sys.executable, "-c", "raise SystemExit(3)"])
        marker = self.root / "must-not-run"
        with self.assertRaisesRegex(Refused, "no successful completion"):
            command([sys.executable, "-c", "from pathlib import Path;Path(" + repr(str(marker)) + ").touch()"])
        self.assertFalse(marker.exists())
        self.assertEqual(len(list(self.root.glob("os-command-*-intent.json"))), 1)
        self.assertEqual(len(list(self.root.glob("os-command-*-complete.json"))), 0)

    def test_lost_success_acknowledgement_does_not_authorize_replay(self):
        manager, observer = self.recorded(self.root)
        def lose_ack(phase, kind, **details):
            if phase == "complete":
                raise SystemExit("after actual child success, before acknowledgement")
            return observer(phase, kind, **details)
        marker = self.root / "actual-child-effect"
        argv = [sys.executable, "-c", "from pathlib import Path;Path(" + repr(str(marker)) + ").touch()"]
        with self.assertRaises(SystemExit):
            Commands(observer=lose_ack)(argv)
        self.assertTrue(marker.exists())
        with self.assertRaisesRegex(Refused, "no successful completion"):
            Commands(observer=observer)(argv)
        self.assertEqual(len(list(self.root.glob("os-command-*-intent.json"))), 1)

    def test_records_contain_no_raw_argv_input_or_output(self):
        manager, observer = self.recorded(self.root)
        command = Commands(observer=observer)
        output = command([sys.executable, "-c", "print('synthetic-output-only')"], input=b"synthetic-input-only")
        self.assertEqual(output, "synthetic-output-only")
        self.assertEqual(manager._os_command_records(self.root), 1)
        for path in self.root.glob("os-command-*"):
            raw = path.read_bytes()
            self.assertNotIn(b"synthetic-output-only", raw)
            self.assertNotIn(b"synthetic-input-only", raw)
            self.assertNotIn(sys.executable.encode(), raw)
