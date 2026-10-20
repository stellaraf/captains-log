import configparser
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager.common import Refused
from nebulalog_manager.console import host_ready_console, local_console, safe_error, sealed_state, serve
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


class RecoveryConsoleTests(unittest.TestCase):
    def setUp(self):
        from test_firstboot import CONFIG
        self.config = CONFIG
        self.manager = SimpleNamespace(
            paths=Locations(), gate=Mock(return_value={"host_ready": True, "setup_complete": False}),
            runner=Mock(), provision=Mock(return_value={"state": "runtime-ready"}))
        self.recovery = SimpleNamespace(status=Mock(return_value={"state": "not_started"}),
                                        start=Mock(), prepare=Mock(), apply_prepared=Mock(), resume=Mock(), runtime=SimpleNamespace(guard_fresh=Mock()))
        self.output = []
        self.operation = "11111111-2222-4333-8444-555555555555"
        self.recovery.prepare.return_value = {"id": self.operation, "scope": "configuration", "source_installation_id": self.operation,
            "target_installation_id": self.operation, "archive_sha256": "a" * 64, "expires_at": 1800000300, "review_digest": "b" * 64}
        guard = patch("nebulalog_manager.setup_integrity.pending_console")
        self.guard = guard.start()
        self.addCleanup(guard.stop)

    def retained(self, state="recovery_required", blocked=False):
        return {"id": self.operation, "state": state, "databases": {"nebulalog": "restored", "keycloak": "restoring" if blocked else "not_started"},
                "runtime_active_stage": None, "resume_blocked": blocked, "listener_hold_recorded": False}

    def invoke(self, answers, **kwargs):
        values = iter(answers)
        return host_ready_console(self.manager, self.config, recovery=self.recovery,
                                  read=lambda prompt: next(values), write=self.output.append, **kwargs)

    def test_host_ready_later_and_status_never_provision_or_restore(self):
        self.assertEqual(self.invoke(["STATUS", "LATER"]), {"state": "host-ready", "setup_complete": False})
        self.manager.runner.assert_not_called()
        self.manager.provision.assert_not_called()
        self.recovery.start.assert_not_called()
        self.recovery.resume.assert_not_called()

    def test_new_requires_explicit_confirmation_and_uses_existing_provision(self):
        with patch("nebulalog_manager.firstboot._runtime_console", return_value={"setup_complete": False}) as complete:
            self.invoke(["NEW", "wrong", "NEW", "NEW"])
        self.manager.provision.assert_called_once_with()
        self.manager.runner.assert_called_once_with(["systemctl", "start", "nebulalog-firstboot.service"], timeout=180)
        complete.assert_called_once()
        self.recovery.start.assert_not_called()

    def test_restore_uses_only_paths_and_verified_completion_without_normal_provision(self):
        self.recovery.status.side_effect = [{"state": "not_started"}, self.retained("runtime_ready")]
        with patch("nebulalog_manager.setup_integrity.resume_runtime", return_value={"https_url": "https://logs.example.test"}), \
                patch("nebulalog_manager.firstboot._runtime_console", return_value={"setup_complete": False}) as complete:
            self.invoke(["RESTORE", "/recovery/backup.cms", "/recovery/public.pem", "/run/nebulalog/private.pem",
                         "RESTORE logs.example.test", "CONTINUE"])
        self.recovery.prepare.assert_called_once_with(Path("/recovery/backup.cms"), Path("/run/nebulalog/private.pem"), Path("/recovery/public.pem"))
        self.recovery.apply_prepared.assert_called_once_with(self.operation, "b" * 64)
        self.assertIn("Authenticated recovery review", " ".join(self.output))
        self.assertTrue(complete.call_args.args[2]["restored"])
        self.manager.runner.assert_not_called()
        self.manager.provision.assert_not_called()
        self.assertNotIn("/run/nebulalog/private.pem", " ".join(self.output))
        self.assertIn("existing MFA", " ".join(self.output))

    def test_resume_uses_exact_retained_uuid_without_replacement_inputs(self):
        self.recovery.status.return_value = self.retained()
        self.invoke(["NEW", "RESUME", "wrong", "RESUME", self.operation, "LATER"], restore_only=True)
        self.recovery.resume.assert_called_once_with(self.operation)
        self.recovery.start.assert_not_called()
        self.manager.provision.assert_not_called()

    def test_explicit_media_selection_uses_shared_import_and_target_confirmation(self):
        with patch("nebulalog_manager.recovery_media.restore_from_media", return_value={"state": "cancelled"}) as imported:
            self.invoke(["MEDIA", "/dev/sr1", "LATER"])
        self.assertEqual(imported.call_args.args, (self.recovery, Path("/dev/sr1")))
        self.assertEqual(imported.call_args.kwargs["target_confirmation"], "RESTORE logs.example.test")
        imported.call_args.kwargs["guard"]()
        self.manager.provision.assert_not_called()
        self.recovery.start.assert_not_called()

    def test_cancelled_or_retained_media_choice_never_mounts(self):
        with patch("nebulalog_manager.recovery_media.restore_from_media") as imported:
            self.invoke(["MEDIA", "CANCEL", "LATER"])
            self.recovery.status.return_value = self.retained()
            self.invoke(["MEDIA", "LATER"])
        imported.assert_not_called()
        self.manager.provision.assert_not_called()

    def test_uncertain_outcome_never_dispatches_resume(self):
        self.recovery.status.return_value = self.retained(blocked=True)
        self.invoke(["RESUME", "LATER"], restore_only=True)
        self.recovery.resume.assert_not_called()
        self.assertIn("uncertain outcome", " ".join(self.output))
        self.assertIn("not established", " ".join(self.output))

    def test_missing_retained_pointer_cannot_fall_back_to_new(self):
        with self.assertRaisesRegex(Refused, "normal provisioning"):
            self.invoke([], restore_only=True)
        self.manager.provision.assert_not_called()

    def test_invalid_paths_cancel_and_unconfirmed_restore_have_no_effect(self):
        for value in ("https://example.test/backup", "relative", "/tmp/../etc/key", "/tmp/key\nsecret", "-----BEGIN PRIVATE KEY-----"):
            with self.subTest(value=value), self.assertRaises(Refused):
                self.invoke(["RESTORE", value])
        self.invoke(["RESTORE", "CANCEL", "LATER"])
        self.invoke(["RESTORE", "/recovery/backup.cms", "/recovery/public.pem", "/run/nebulalog/key", "wrong", "LATER"])
        self.recovery.start.assert_not_called()
        self.recovery.apply_prepared.assert_not_called()

    def test_console_boundary_rechecked_before_dispatch_after_input(self):
        self.guard.side_effect = [None, None, None, Refused("console boundary changed")]
        with self.assertRaisesRegex(Refused, "boundary changed"):
            self.invoke(["RESTORE", "/recovery/backup.cms", "/recovery/public.pem", "/run/nebulalog/key", "RESTORE logs.example.test"])
        self.recovery.start.assert_not_called()
        self.recovery.apply_prepared.assert_not_called()

    def test_retained_ready_flag_alone_cannot_complete_setup(self):
        self.recovery.status.return_value = self.retained("runtime_ready")
        with patch("nebulalog_manager.setup_integrity.resume_runtime", return_value=None), \
                patch("nebulalog_manager.firstboot._runtime_console") as complete:
            with self.assertRaisesRegex(Refused, "evidence is incomplete"):
                self.invoke(["CONTINUE"])
        complete.assert_not_called()


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
        self.assertIn("exec /usr/bin/python3.14 -I -B /usr/libexec/nebulalog/host-boot nebulalog-console", launcher)
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
