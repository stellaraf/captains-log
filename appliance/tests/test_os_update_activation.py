"""Scheduled OS maintenance must fail closed before enrollment is usable."""
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager.common import Refused
from nebulalog_manager.os_updates import maintain


class ScheduledOSActivationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = self.root / "maintenance.json"
        self.state = self.root / "manager"
        self.calls = []
        self.now = datetime(2026, 9, 6, 3, 30, tzinfo=timezone.utc)
        for target, kwargs in (
            ("require_linux_root", {}),
            ("trusted_file", {"side_effect": lambda path: path}),
            ("status", {"return_value": {"host_controls_ok": True}}),
            ("in_maintenance_window", {"return_value": True}),
        ):
            mocked = patch("nebulalog_manager.os_updates." + target, **kwargs)
            mocked.start()
            self.addCleanup(mocked.stop)

    def run_maintenance(self, preflight):
        def runner(argv, **kwargs):
            self.calls.append(argv)
            if Path(argv[0]).name == "update-os-preflight":
                if isinstance(preflight, Exception):
                    raise preflight
                return json.dumps(preflight)
            raise AssertionError("Package or reboot command ran before usable enrollment")
        return maintain(self.policy, self.state, runner=runner, now=self.now)

    def enrolled_policy(self, enabled=True):
        self.policy.write_text(json.dumps({"automatic_os_updates": enabled, "timezone": "UTC"}))

    def test_missing_enrollment_policy_runs_nothing_and_creates_no_state(self):
        with self.assertRaises(FileNotFoundError):
            self.run_maintenance(None)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.state.exists())

    def test_disabled_policy_runs_nothing(self):
        self.enrolled_policy(enabled=False)
        self.assertEqual(self.run_maintenance(None), {"status": "disabled"})
        self.assertEqual(self.calls, [])
        self.assertFalse(self.state.exists())

    def test_unusable_enrollment_preflight_cannot_run_dnf(self):
        self.enrolled_policy()
        with self.assertRaisesRegex(Refused, "enrollment fixture unavailable"):
            self.run_maintenance(Refused("enrollment fixture unavailable"))
        self.assertEqual(self.calls, [["/usr/libexec/nebulalog/update-os-preflight"]])
        self.assertEqual(json.loads((self.state / "os-transaction.json").read_text())["state"], "failed")

    def test_incomplete_backup_receipt_cannot_run_dnf(self):
        self.enrolled_policy()
        with self.assertRaisesRegex(Refused, "verified metadata and configuration backups"):
            self.run_maintenance({"ok": True, "postgresql": True, "configuration": False})
        self.assertEqual(self.calls, [["/usr/libexec/nebulalog/update-os-preflight"]])

    def test_unhealthy_host_cannot_run_preflight_or_dnf(self):
        self.enrolled_policy()
        with patch("nebulalog_manager.os_updates.status", return_value={"host_controls_ok": False}):
            with self.assertRaisesRegex(Refused, "healthy FIPS"):
                self.run_maintenance(None)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
