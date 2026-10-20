"""Backup flags route to mocked coordinators only; no capture or runtime action."""
import contextlib
import io
import itertools
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import cli
from nebulalog_manager.common import Refused


class BackupCliTests(unittest.TestCase):
    def setUp(self):
        self.manager = Mock()
        self.manager.create.return_value = {"state": "complete"}
        self.manager.resume.return_value = {"state": "complete"}
        self.manager.status.return_value = {"state": "working"}
        self.manager.retire.return_value = {"state": "retired_without_backup", "complete": False}
        self.operation = "11111111-2222-4333-8444-555555555555"
        self.capture = ["--output", "/protected/new-output", "--recipient-certificate", "/protected/recipient.pem"]
        self.budgets = ["--maximum-archive-bytes", "1073741824", "--growth-reserve-bytes", "268435456",
                        "--minimum-free-bytes", "1073741824", "--deadline-seconds", "3600"]
        patcher = patch("nebulalog_manager.recovery_set.FullBackupManager", return_value=self.manager)
        self.factory = patcher.start()
        self.addCleanup(patcher.stop)

    def invoke(self, arguments):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return cli.main(["backup", *arguments])

    def test_configuration_capture_stays_default_and_requires_explicit_outputs(self):
        with patch.object(cli.backup, "create_backup", return_value={"ok": True}) as capture:
            self.assertEqual(self.invoke(self.capture), 0)
            capture.assert_called_once_with(Path("/var/lib/nebulalog/configuration"), Path("/protected/new-output"), Path("/protected/recipient.pem"))
            self.assertEqual(self.invoke([]), 1)
            self.assertEqual(self.invoke(["--output", "/protected/new-output"]), 1)
        self.manager.create.assert_not_called()

    def test_include_logs_requires_and_preserves_all_four_budgets(self):
        self.assertEqual(self.invoke(["--include-logs", *self.capture, *self.budgets]), 0)
        self.manager.create.assert_called_once_with(Path("/protected/new-output"), Path("/protected/recipient.pem"),
                                                   maximum_archive_bytes=1073741824, growth_reserve_bytes=268435456,
                                                   minimum_free_bytes=1073741824, deadline_seconds=3600)
        self.manager.reset_mock()
        for index in range(0, len(self.budgets), 2):
            with self.subTest(missing=self.budgets[index]):
                self.assertEqual(self.invoke(["--include-logs", *self.capture, *self.budgets[:index], *self.budgets[index + 2:]]), 1)
        self.manager.create.assert_not_called()

    def test_configuration_capture_rejects_budget_flags_and_noncanonical_source(self):
        with patch.object(cli.backup, "create_backup") as capture:
            for index in range(0, len(self.budgets), 2):
                self.assertEqual(self.invoke([*self.capture, *self.budgets[index:index + 2]]), 1)
            for mode in ([], ["--include-logs", *self.budgets]):
                self.assertEqual(self.invoke([*mode, *self.capture, "--configuration", "/arbitrary"]), 1)
            capture.assert_not_called()
        self.manager.create.assert_not_called()

    def test_status_resume_retire_use_only_exact_uuid_and_reject_even_canonical_override(self):
        for action in ("--status", "--resume", "--retire"):
            with self.subTest(action=action):
                self.assertEqual(self.invoke([action, self.operation]), 0)
                getattr(self.manager, action[2:]).assert_called_with(self.operation)
                self.manager.reset_mock()
                self.factory.reset_mock()
                overrides = [["--configuration", "/var/lib/nebulalog/configuration"],
                             self.capture[:2], self.capture[2:]] + [self.budgets[index:index + 2] for index in range(0, len(self.budgets), 2)]
                for override in overrides:
                    self.assertEqual(self.invoke([action, self.operation, *override]), 1)
                self.manager.status.assert_not_called()
                self.manager.resume.assert_not_called()
                self.manager.retire.assert_not_called()
                self.manager.create.assert_not_called()
                self.factory.assert_not_called()

    def test_capture_status_resume_and_retire_modes_are_mutually_exclusive(self):
        modes = [["--include-logs"], ["--status", self.operation], ["--resume", self.operation], ["--retire", self.operation]]
        for first, second in itertools.combinations(modes, 2):
            with self.subTest(first=first, second=second), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                cli.main(["backup", *first, *second])
            self.assertEqual(raised.exception.code, 2)
        self.factory.assert_not_called()

    def test_retire_prints_unsuccessful_result_without_capture_or_resume(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch.object(cli.backup, "create_backup") as capture:
            self.assertEqual(cli.main(["backup", "--retire", self.operation]), 0)
            capture.assert_not_called()
        self.assertEqual(json.loads(out.getvalue()), {"state": "retired_without_backup", "complete": False})
        self.assertEqual(self.manager.method_calls, [("retire", (self.operation,), {})])

    def test_retire_refusal_stays_refused_without_fallback(self):
        self.manager.retire.side_effect = Refused("Original native job is unsettled")
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err), patch.object(cli.backup, "create_backup") as capture:
            self.assertEqual(cli.main(["backup", "--retire", self.operation]), 1)
            capture.assert_not_called()
        self.assertEqual(json.loads(err.getvalue()), {"status": "refused", "error": "Original native job is unsettled"})
        self.assertEqual(self.manager.method_calls, [("retire", (self.operation,), {})])

    def test_retire_requires_uuid_and_delegates_validation_without_new_capture(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            cli.main(["backup", "--retire"])
        self.assertEqual(raised.exception.code, 2)
        self.factory.assert_not_called()
        self.manager.retire.side_effect = Refused("Exact operation UUID required")
        self.assertEqual(self.invoke(["--retire", ""]), 1)
        self.manager.retire.assert_called_once_with("")
        self.manager.create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
