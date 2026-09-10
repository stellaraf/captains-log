import configparser
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from nebulalog_manager.common import Refused
from nebulalog_manager.console import local_console, safe_error, sealed_state, serve
from nebulalog_manager.firstboot import Locations

APPLIANCE = Path(__file__).resolve().parents[1]


class Stream:
    def __init__(self, fd, tty=True):
        self.fd, self.tty = fd, tty
    def fileno(self):
        return self.fd
    def isatty(self):
        return self.tty


class TerminalBoundaryTests(unittest.TestCase):
    def test_all_stdio_must_be_local_tty1(self):
        with patch("nebulalog_manager.console.require_linux_root"):
            local_console([Stream(0), Stream(1), Stream(2)], {}, lambda fd: "/dev/tty1")
            for wrong in range(3):
                with self.subTest(fd=wrong), self.assertRaises(Refused):
                    local_console([Stream(0), Stream(1), Stream(2)], {}, lambda fd: "/dev/pts/0" if fd == wrong else "/dev/tty1")
            with self.assertRaises(Refused):
                local_console([Stream(0), Stream(1, tty=False), Stream(2)], {}, lambda fd: "/dev/tty1")

    def test_ssh_context_refused_even_if_tty_is_spoofed(self):
        with patch("nebulalog_manager.console.require_linux_root"):
            for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"):
                with self.subTest(name=name), self.assertRaises(Refused):
                    local_console([Stream(0), Stream(1), Stream(2)], {name: "present"}, lambda fd: "/dev/tty1")

    def test_os_root_requirement_is_not_bypassed(self):
        with patch("nebulalog_manager.console.require_linux_root", side_effect=Refused("root required")):
            with self.assertRaisesRegex(Refused, "root required"):
                local_console([Stream(0), Stream(1), Stream(2)], {}, lambda fd: "/dev/tty1")

    def test_arbitrary_error_text_cannot_expose_a_password(self):
        for error in (ValueError("entered-secret"), OSError("entered-secret"), KeyError("entered-secret")):
            self.assertNotIn("entered-secret", safe_error(error))
        self.assertEqual(safe_error(Refused("Reviewed disk changed")), "Reviewed disk changed")


class ConsoleWorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        paths = Locations(base / "etc", base / "data", base / "run")
        paths.bootstrap.mkdir(parents=True)
        image = paths.bootstrap / "image-state"
        image.write_text("sealed\n")
        image.chmod(0o600)
        self.completed = False
        self.manager = SimpleNamespace(paths=paths, status=lambda: {"setup_complete": self.completed})
        patcher = patch("nebulalog_manager.console.trusted_file", lambda path: path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.output, self.calls = [], []

    def invoke(self, wizard, read=lambda prompt: ""):
        return serve(self.manager, wizard_fn=wizard, guard=lambda: None, read=read, write=self.output.append, runner=lambda argv: self.calls.append(argv))

    def test_unsealed_build_never_launches_wizard_or_getty_commands(self):
        (self.manager.paths.bootstrap / "unsealed-build").write_text("private build")
        result = self.invoke(lambda manager: self.fail("wizard must not start"))
        self.assertEqual(result["state"], "unsealed")
        self.assertEqual(self.calls, [])

    def test_completed_setup_cannot_reenter_privileged_wizard(self):
        self.completed = True
        result = self.invoke(lambda manager: self.fail("wizard must not restart"))
        self.assertEqual(result["state"], "setup-complete")
        self.assertEqual(self.calls, [])
        self.assertIn("Captain’s Log setup is complete.", " ".join(self.output))

    def test_invalid_completion_marker_refuses_privileged_restart(self):
        (self.manager.paths.etc / "configured").write_text("just a marker")
        with self.assertRaisesRegex(Refused, "marker is invalid"):
            self.invoke(lambda manager: self.fail("wizard must not start"))

    def test_image_must_be_sealed_and_private(self):
        image = self.manager.paths.bootstrap / "image-state"
        image.write_text("unsealed")
        with self.assertRaisesRegex(Refused, "sealed appliance"):
            sealed_state(self.manager)
        image.write_text("sealed")
        image.chmod(0o644)
        with self.assertRaises(Refused):
            sealed_state(self.manager)

    def test_retry_does_not_open_shell_and_handoffs_only_after_verified_complete(self):
        attempts = []
        def wizard(manager):
            attempts.append(True)
            if len(attempts) == 1:
                raise Refused("Disk changed; refresh required")
            self.completed = True
            return {"setup_complete": True}
        result = self.invoke(wizard)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(result["state"], "setup-complete")
        self.assertEqual(self.calls, [["systemctl", "--no-block", "start", "getty@tty1.service"]])
        self.assertTrue(any("Disk changed" in line for line in self.output))
        self.assertIn("Captain’s Log appliance console", " ".join(self.output))
        self.assertIn("Captain’s Log setup is complete.", " ".join(self.output))

    def test_wizard_return_value_alone_cannot_fake_completion(self):
        inputs = iter(["", EOFError()])
        def read(prompt):
            value = next(inputs)
            if isinstance(value, Exception):
                raise value
            return value
        result = self.invoke(lambda manager: {"setup_complete": True}, read)
        self.assertEqual(result["state"], "console-closed")
        self.assertEqual(self.calls, [])

    def test_keyboard_interrupt_and_eof_do_not_open_shell(self):
        inputs = iter([KeyboardInterrupt(), "", EOFError()])
        def read(prompt):
            value = next(inputs)
            if isinstance(value, BaseException):
                raise value
            return value
        def wizard(manager):
            raise KeyboardInterrupt()
        result = self.invoke(wizard, read)
        self.assertEqual(result["state"], "console-closed")
        self.assertEqual(self.calls, [])
        self.assertTrue(any("No root shell" in line for line in self.output))

    def test_unexpected_error_is_redacted_and_exits_without_shell(self):
        def wizard(manager):
            raise TypeError("secret-from-input")
        result = self.invoke(wizard)
        self.assertEqual(result["state"], "console-error")
        self.assertNotIn("secret-from-input", " ".join(self.output))
        self.assertEqual(self.calls, [])

    def test_sealed_state_rechecked_after_user_wait(self):
        def read(prompt):
            self.completed = True
            return ""
        result = self.invoke(lambda manager: self.fail("completion occurred while waiting"), read)
        self.assertEqual(result["state"], "setup-complete")


class SystemdContractTests(unittest.TestCase):
    def text(self, name):
        return (APPLIANCE / "systemd" / name).read_text()

    def test_console_stdio_never_reaches_journal_and_has_no_shell(self):
        text = self.text("nebulalog-console.service")
        config = configparser.ConfigParser(strict=False)
        config.read_string(text)
        service = config["Service"]
        self.assertEqual(service["StandardInput"], "tty-fail")
        self.assertEqual(service["StandardOutput"], "tty")
        self.assertEqual(service["StandardError"], "tty")
        self.assertEqual(service["TTYPath"], "/dev/tty1")
        self.assertEqual(service["ExecStart"], "/usr/libexec/nebulalog/nebulalog-console")
        self.assertEqual(service["LimitCORE"], "0")
        self.assertEqual(service["Restart"], "no")
        self.assertNotIn("ExecStartPost", service)
        self.assertNotIn("Conflicts", config["Unit"])
        self.assertIn("ConditionPathExists=!/etc/nebulalog/bootstrap/unsealed-build", text)
        self.assertIn("ConditionPathExists=!/etc/nebulalog/configured", text)
        launcher = (APPLIANCE / "bin/nebulalog-console").read_text()
        self.assertIn("exec /usr/bin/python3 -I -B /usr/libexec/nebulalog/host-boot nebulalog-console", launcher)
        self.assertNotIn("/bin/bash", launcher)
        self.assertNotIn("--autologin", launcher + text)

    def test_getty_or_conditions_preserve_unsealed_and_completed_login(self):
        text = self.text("getty@tty1.service.d/50-nebulalog-firstboot.conf")
        conditions = [line.removeprefix("ConditionPathExists=|") for line in text.splitlines() if line.startswith("ConditionPathExists=|")]
        self.assertEqual(set(conditions), {"/etc/nebulalog/bootstrap/unsealed-build", "/etc/nebulalog/configured"})
        self.assertNotIn("ExecStart", text)
        self.assertNotIn("After=nebulalog-console.service", text)


if __name__ == "__main__":
    unittest.main()
