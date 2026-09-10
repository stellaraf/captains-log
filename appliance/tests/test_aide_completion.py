"""Read-only first-boot AIDE evidence checks using the isolated lifecycle fixture."""
from dataclasses import replace
from datetime import datetime, timedelta
import gzip
import hashlib
import json
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager.common import Refused, atomic_json, locked
import test_aide_lifecycle as lifecycle


class AideCompletionTests(unittest.TestCase):
    def setUp(self):
        # Compose the fixture without inheriting/re-running its lifecycle tests.
        self.fixture = lifecycle.AideLifecycleTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.enrolled()

    def complete_check(self):
        return self.fixture.manager.check()

    def completion(self, installation_id=lifecycle.INSTALLATION):
        return self.fixture.manager.firstboot_checks(installation_id)

    def snapshot(self):
        result = {}
        for path in self.fixture.root.rglob("*"):
            info = path.lstat()
            result[str(path.relative_to(self.fixture.root))] = (
                info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
        return result

    def test_enrollment_verification_does_not_replace_an_explicit_completed_check(self):
        self.assertEqual(self.fixture.record("last-result.json")["state"], "clean")
        self.assertFalse((self.fixture.state / "last-attempt.json").exists())
        with self.assertRaises(Refused):
            self.completion()
        self.assertFalse((self.fixture.state / "last-attempt.json").exists())

    def test_recent_clean_completed_check_returns_only_exact_bootstrap_fields(self):
        self.complete_check()
        self.assertEqual(self.completion(), {"aide_enrolled": True, "aide_checked_clean": True})

    def test_freshness_accepts_zero_through_300_seconds_and_rejects_old_or_future(self):
        self.complete_check()
        observed = datetime.fromisoformat(self.fixture.now)
        for age in (0, 299, 300):
            self.fixture.now = (observed + timedelta(seconds=age)).isoformat()
            with self.subTest(age=age):
                self.assertEqual(self.completion(), {"aide_enrolled": True, "aide_checked_clean": True})
        for age in (300.001, 301, 3600, -0.001, -1):
            self.fixture.now = (observed + timedelta(seconds=age)).isoformat()
            with self.subTest(age=age), self.assertRaises(Refused):
                self.completion()

    def test_new_failed_or_running_attempt_prevents_using_an_older_clean_report(self):
        previous = self.complete_check()
        self.fixture.config_code = 17
        with self.assertRaises(Refused):
            self.fixture.manager.check()
        self.assertEqual(self.fixture.record("last-result.json")["id"], previous["id"])
        with self.assertRaises(Refused):
            self.completion()
        attempt = self.fixture.record("last-attempt.json")
        attempt.update(state="running", report_id=None)
        atomic_json(self.fixture.state / "last-attempt.json", attempt)
        with self.assertRaises(Refused):
            self.completion()

    def test_new_completed_findings_prevent_using_an_older_clean_report(self):
        self.complete_check()
        self.fixture.check_code = 4
        self.assertEqual(self.fixture.manager.check()["state"], "differences")
        with self.assertRaises(Refused):
            self.completion()

    def test_database_and_report_tampering_refuse_completion(self):
        result = self.complete_check()
        database = self.fixture.state / "aide.db.gz"
        original = database.read_bytes()
        self.fixture.write_private(database, gzip.compress(b"different baseline", mtime=0))
        with self.assertRaises(Refused):
            self.completion()
        self.fixture.write_private(database, original)
        report_path = self.fixture.state / "reports" / (result["id"] + ".json")
        report = json.loads(report_path.read_text())
        report["stdout"] = "tampered private report"
        atomic_json(report_path, report)
        with self.assertRaises(Refused):
            self.completion()

    def test_busy_existing_manager_lock_is_refused_without_waiting_or_replacing_it(self):
        self.complete_check()
        lock_path = self.fixture.root / "manager/transaction.lock"
        before = lock_path.stat().st_ino
        with locked(lock_path):
            with self.assertRaisesRegex(Refused, "aide_completion_evidence_busy"):
                self.completion()
        self.assertEqual(lock_path.stat().st_ino, before)

    def test_completion_never_acquires_coordination_locks_writes_or_runs_commands(self):
        self.complete_check()
        manager = self.fixture.manager
        manager.lock_paths = Mock(side_effect=AssertionError("firstboot/runtime locks are caller-owned"))
        manager.runner = Mock(side_effect=AssertionError("completion must not invoke lifecycle commands"))
        manager.monitor = Mock(side_effect=self.fixture.monitor)
        before = self.snapshot()
        with patch.object(manager.records, "write", side_effect=AssertionError("completion wrote a record")), \
                patch.object(manager, "_write_bytes", side_effect=AssertionError("completion wrote an artifact")), \
                patch.object(manager, "_locked", side_effect=AssertionError("completion acquired full lifecycle locks")):
            self.assertEqual(self.completion(), {"aide_enrolled": True, "aide_checked_clean": True})
        manager.lock_paths.assert_not_called()
        manager.runner.assert_not_called()
        manager.monitor.assert_called_once()
        self.assertEqual(self.snapshot(), before)

    def test_missing_manager_lock_is_not_created_by_completion(self):
        self.complete_check()
        lock_path = self.fixture.root / "manager/transaction.lock"
        lock_path.unlink()
        before = self.snapshot()
        with self.assertRaises(Refused):
            self.completion()
        self.assertFalse(lock_path.exists())
        self.assertEqual(self.snapshot(), before)

    def test_requested_installation_must_match_and_guard_is_rechecked(self):
        self.complete_check()
        for identity in ("028917b1-f04e-42a2-85d6-776c0b260a21", "not-an-installation", None):
            with self.subTest(identity=identity), self.assertRaises(Refused):
                self.completion(identity)

        def changed_guard(*args):
            result = self.fixture.monitor(*args)
            self.fixture.identity = replace(self.fixture.identity,
                                            installation_id="028917b1-f04e-42a2-85d6-776c0b260a21")
            return result

        self.fixture.manager.monitor = changed_guard
        with self.assertRaises(Refused):
            self.completion()

    def test_latest_attempt_must_reference_the_verified_latest_report(self):
        self.complete_check()
        attempt = self.fixture.record("last-attempt.json")
        attempt["report_id"] = "028917b1-f04e-42a2-85d6-776c0b260a21"
        atomic_json(self.fixture.state / "last-attempt.json", attempt)
        with self.assertRaises(Refused):
            self.completion()


if __name__ == "__main__":
    unittest.main()
