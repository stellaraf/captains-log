import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import cli


class RecoveryMediaCliTests(unittest.TestCase):
    def test_explicit_media_routes_only_to_fresh_import(self):
        recovery = Mock()
        with patch("nebulalog_manager.configuration_restore.ConfigurationRestore", return_value=recovery), \
                patch("nebulalog_manager.recovery_media.restore_from_media", return_value={"state": "runtime_ready"}) as imported, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["restore", "--apply-fresh", "--media", "/dev/sr0"]), 0)
        self.assertEqual(imported.call_args.args, (recovery, Path("/dev/sr0")))
        recovery.start.assert_not_called()
        recovery.resume.assert_not_called()

    def test_media_does_not_mix_with_status_resume_or_local_inputs(self):
        combinations = [[], ["--status"], ["--resume", "11111111-2222-4333-8444-555555555555"],
                        ["--apply-fresh", "--backup", "/backup.cms"], ["--apply-fresh", "--private-key", "/private.key"],
                        ["--apply-fresh", "--certificate", "/recipient.pem"], ["--apply-fresh", "--destination", "/scratch"]]
        with patch("nebulalog_manager.recovery_media.restore_from_media") as imported:
            for extra in combinations:
                with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main(["restore", "--media", "/dev/sr0", *extra]), 1)
            imported.assert_not_called()


class LocalLogRestoreCliTests(unittest.TestCase):
    def setUp(self):
        self.inputs = ["--backup", "/protected/backup.cms", "--private-key", "/protected/private.key",
                       "--certificate", "/protected/recipient.pem"]
        self.logs = ["--log-recovery-set", "/protected/logs", "--log-deadline-seconds", "3600",
                     "--log-minimum-free-bytes", "1073741824"]
        self.recovery = Mock()
        self.recovery.start.return_value = {"state": "runtime_ready"}

    def invoke(self, arguments):
        with patch("nebulalog_manager.configuration_restore.ConfigurationRestore", return_value=self.recovery), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return cli.main(["restore", *arguments])

    def test_local_full_restore_passes_exact_explicit_plan(self):
        self.assertEqual(self.invoke(["--apply-fresh", *self.inputs, *self.logs]), 0)
        self.recovery.start.assert_called_once_with(Path("/protected/backup.cms"), Path("/protected/private.key"),
                                                   Path("/protected/recipient.pem"), log_recovery_set=Path("/protected/logs"),
                                                   log_restore_deadline_seconds=3600, log_restore_minimum_free_bytes=1073741824)

    def test_configuration_only_preserves_three_positional_arguments(self):
        self.assertEqual(self.invoke(["--apply-fresh", *self.inputs]), 0)
        self.recovery.start.assert_called_once_with(Path("/protected/backup.cms"), Path("/protected/private.key"), Path("/protected/recipient.pem"))

    def test_partial_plan_or_nonlocal_mode_cannot_dispatch(self):
        for index in range(0, len(self.logs), 2):
            self.assertEqual(self.invoke(["--apply-fresh", *self.inputs, *self.logs[:index], *self.logs[index + 2:]]), 1)
        for mode in (["--status"], ["--resume", "11111111-2222-4333-8444-555555555555"],
                     [*self.inputs, "--destination", "/protected/stage"], ["--apply-fresh", "--media", "/dev/sr0"]):
            self.assertEqual(self.invoke([*mode, *self.logs]), 1)
        self.recovery.start.assert_not_called()
        self.recovery.status.assert_not_called()
        self.recovery.resume.assert_not_called()


if __name__ == "__main__":
    unittest.main()
