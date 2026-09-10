"""Check immutable-input and process-ownership gates without mounting a disk."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PACKER = Path(__file__).resolve().parents[1] / "packer"
sys.path.insert(0, str(PACKER))
try:
    spec = importlib.util.spec_from_file_location("sanitize_image", PACKER / "sanitize_image.py")
    sanitize = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sanitize)
finally:
    sys.path.pop(0)


class SanitizationSupervisorTests(unittest.TestCase):
    def qcow_header(self, path, **fields):
        header = bytearray(65536)
        header[:4] = b"QFI\xfb"
        for offset, fmt, value in ((4, ">I", 3), (20, ">I", 16), (24, ">Q", 80 * sanitize.GIB),
                                   (100, ">I", 104)):
            struct.pack_into(fmt, header, offset, value)
        for offset, (fmt, value) in fields.items():
            struct.pack_into(fmt, header, int(offset), value)
        path.write_bytes(header)

    def test_external_data_and_backing_headers_refuse_before_qemu(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "input.qcow2"
            self.qcow_header(path)
            sanitize.inspect_header(path)
            for fields in ({"72": (">Q", 4)}, {"8": (">Q", 1024)},
                           {"104": (">I", 0x44415441)}, {"60": (">I", 1)}):
                with self.subTest(fields=fields), mock.patch.object(sanitize.subprocess, "check_output") as command:
                    self.qcow_header(path, **fields)
                    with self.assertRaises(ValueError):
                        sanitize.disk_info(path)
                    command.assert_not_called()

    def test_pending_output_publication_is_atomic_and_never_clobbers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            pending, output = root / "pending", root / "final"
            pending.write_bytes(b"verified bytes")
            output.symlink_to(root / "absent")
            with self.assertRaises(FileExistsError):
                sanitize.publish_verified(pending, output)
            self.assertEqual(pending.read_bytes(), b"verified bytes")
            self.assertTrue(output.is_symlink())
            output.unlink()
            sanitize.publish_verified(pending, output)
            self.assertEqual(output.read_bytes(), b"verified bytes")
            self.assertFalse(pending.exists())
            self.assertEqual(output.stat().st_nlink, 1)

    def test_failed_final_audit_never_exposes_final_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, output, work = root / "source", root / "final", root / "work"
            source.write_bytes(b"original unchanged")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"files": {"/payload": {"sha256": "0" * 64}}}))
            argv = ["sanitize_image", "--input", str(source), "--expected-sha256", sanitize.sha(source),
                    "--output", str(output), "--work-dir", str(work), "--payload-manifest", str(manifest)]
            def tool(command, *args, **kwargs):
                Path(command[-1]).write_bytes(b"private intermediate")
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(sanitize.os, "statvfs", return_value=mock.Mock(f_flag=os.ST_RDONLY)), \
                    mock.patch.object(sanitize.shutil, "disk_usage", return_value=mock.Mock(free=1000 * sanitize.GIB)), \
                    mock.patch.object(sanitize, "disk_info", return_value={"virtual-size": 80 * sanitize.GIB}), \
                    mock.patch.object(sanitize, "run_guarded", side_effect=tool), \
                    mock.patch.object(sanitize.subprocess, "run"), \
                    mock.patch.object(sanitize, "open_image"), mock.patch.object(sanitize, "close_image"), \
                    mock.patch.object(sanitize, "create_plan", return_value={"actions": []}), \
                    mock.patch.object(sanitize, "apply_plan", return_value={}), \
                    mock.patch.object(sanitize, "verify_plan", side_effect=ValueError("audit refused")):
                with self.assertRaisesRegex(ValueError, "audit refused"):
                    sanitize.main()
            self.assertFalse(output.exists())
            self.assertTrue((work / "pending-sanitized.qcow2").exists())
            self.assertFalse((work / "sanitization-receipt.json").exists())
            self.assertEqual(source.read_bytes(), b"original unchanged")

    def test_symlink_and_group_writable_parent_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "untrusted parent"):
                sanitize.protected_parent(alias / "output")
            real.chmod(0o770)
            with self.assertRaisesRegex(ValueError, "writable"):
                sanitize.protected_parent(real / "output")

    def test_guestfs_launch_failure_closes_handle(self):
        handle = mock.Mock()
        handle.launch.side_effect = RuntimeError("launch failure")
        module = mock.Mock()
        module.GuestFS.return_value = handle
        with mock.patch.dict(sys.modules, {"guestfs": module}):
            with self.assertRaisesRegex(RuntimeError, "launch failure"):
                sanitize.open_image(Path("unused"), True)
        handle.close.assert_called_once()

    def test_exited_leader_does_not_leave_sigterm_ignoring_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            pid_path, marker = root / "child-pid", root / "must-not-survive"
            child = ("import os,signal,time,pathlib; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                     "pathlib.Path(" + repr(str(pid_path)) + ").write_text(str(os.getpid())); "
                     "time.sleep(6); pathlib.Path(" + repr(str(marker)) + ").write_text('late')")
            leader = ("import subprocess,sys,time,pathlib; subprocess.Popen([sys.executable,'-c'," + repr(child) + "]); "
                      "\nwhile not pathlib.Path(" + repr(str(pid_path)) + ").exists(): time.sleep(.01)\n")
            with self.assertRaisesRegex(RuntimeError, "background descendants"):
                sanitize.run_guarded([sys.executable, "-c", leader], root, 0, 10, "descendant.log")
            pid = int(pid_path.read_text())
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
            self.assertTrue(not state or state.startswith("Z"), state)
            self.assertFalse(marker.exists())

    def test_free_space_failure_stops_only_the_new_test_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            marker = root / "must-not-be-written"
            command = [sys.executable, "-c", "import time,pathlib; time.sleep(3); pathlib.Path(" + repr(str(marker)) + ").write_text('late')"]
            with self.assertRaisesRegex(RuntimeError, "free-space guard"):
                sanitize.run_guarded(command, root, 10**30, 30, "guard.log")
            self.assertFalse(marker.exists())
            self.assertTrue((root / "guard.log").exists())

    def test_successful_owned_process_preserves_its_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            sanitize.run_guarded([sys.executable, "-c", "print('owned-test-complete')"], root, 0, 10, "job.log")
            self.assertEqual((root / "job.log").read_text(), "owned-test-complete\n")

    def test_readwrite_original_refuses_before_disk_tool_or_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "input.qcow2"
            source.write_bytes(b"preserved original fixture")
            manifest = root / "payload.json"
            manifest.write_text(json.dumps({"files": {}}))
            output, work = root / "output.qcow2", root / "work"
            result = subprocess.run([sys.executable, str(PACKER / "sanitize_image.py"),
                "--input", str(source), "--expected-sha256", sanitize.sha(source),
                "--output", str(output), "--work-dir", str(work), "--payload-manifest", str(manifest)],
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bind-mounted read-only", result.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(work.exists())
            self.assertEqual(source.read_bytes(), b"preserved original fixture")

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, output = root / "input.qcow2", root / "output.qcow2"
            source.write_bytes(b"input")
            output.write_bytes(b"keep")
            result = subprocess.run([sys.executable, str(PACKER / "sanitize_image.py"),
                "--input", str(source), "--expected-sha256", sanitize.sha(source),
                "--output", str(output), "--work-dir", str(root / "work"), "--payload-manifest", str(root / "unused")],
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("new output/work paths", result.stderr)
            self.assertEqual(output.read_bytes(), b"keep")


if __name__ == "__main__": unittest.main()
