"""Candidate review tests use private fixtures and never execute host commands."""
from contextlib import ExitStack, contextmanager
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import aide
from nebulalog_manager.common import Refused, atomic_json, locked
from nebulalog_manager.host_job_storage import digest
import test_aide_lifecycle as lifecycle


class AideReviewTests(unittest.TestCase):
    def setUp(self):
        self.fixture = lifecycle.AideLifecycleTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.candidate = self.fixture.manager.prepare()
        self.report_path = self.fixture.state / "reports" / (self.candidate["report_id"] + ".json")

    def review(self):
        return self.fixture.manager.review()

    def candidate_record(self, value):
        value = copy.deepcopy(value)
        value["confirmation"] = digest({key: item for key, item in value.items() if key != "confirmation"})
        atomic_json(self.fixture.state / "candidate.json", value)
        return value

    def report_record(self, value, *, rebind=False):
        atomic_json(self.report_path, value)
        if rebind:
            self.candidate_record({**self.candidate, "report_sha256": digest(value)})

    def snapshot(self):
        return {str(path.relative_to(self.fixture.root)):
                (path.stat().st_ino, path.stat().st_mode, path.stat().st_mtime_ns,
                 hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
                for path in self.fixture.root.rglob("*")}

    @contextmanager
    def enrollment_preflight_only(self):
        manager = self.fixture.manager
        before, calls = self.snapshot(), list(self.fixture.calls)
        with ExitStack() as stack:
            for owner, method in ((manager, "_config"), (manager, "_report"),
                                  (manager, "_write_bytes"), (manager, "_sync"),
                                  (manager.records, "write"), (aide.os, "fsync")):
                stack.enter_context(patch.object(owner, method, side_effect=AssertionError("enrollment wrote before evidence validation")))
            yield
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.fixture.calls, calls)

    @contextmanager
    def coordination(self):
        directory = self.fixture.root / "coordination"
        directory.mkdir(mode=0o700)
        paths = tuple(directory / name for name in ("firstboot.lock", "runtime.lock", "baseline.lock"))
        for path in paths:
            self.fixture.write_private(path, b"")
        self.fixture.manager.lock_paths = lambda _: paths
        original = Path.lstat

        def fixture_ancestry(path):
            info = original(path)
            if not path.is_relative_to(self.fixture.root):
                # Simulate protected root-owned ancestry outside the test tree;
                # the actual test directories and lock files retain real checks.
                fields = list(info)
                fields[0] &= ~0o022
                fields[4] = os.getuid()
                return os.stat_result(fields)
            return info

        with patch.object(Path, "lstat", fixture_ancestry):
            yield (self.fixture.root / "manager/transaction.lock", *paths)

    def test_exact_allowlisted_summary_is_bound_to_original_candidate_report(self):
        value = self.review()
        self.assertEqual(set(value), {"candidate_id", "created_at", "confirmation", "database_sha256", "facts", "report", "enrolled"})
        self.assertEqual(value["candidate_id"], self.candidate["id"])
        self.assertEqual(value["confirmation"], self.candidate["confirmation"])
        self.assertEqual(value["database_sha256"], self.candidate["database_sha256"])
        self.assertEqual(value["facts"], self.candidate["facts"])
        self.assertFalse(value["enrolled"])
        self.assertEqual(value["report"], {"id": self.candidate["report_id"], "observed_at": self.fixture.now,
                                         "state": "clean", "exit_code": 0,
                                         "counts": {"total": 12, "added": 0, "removed": 0, "changed": 0}})
        self.assertNotIn("stdout", json.dumps(value))
        self.assertNotIn("stderr", json.dumps(value))
        self.assertNotIn(str(self.fixture.root), json.dumps(value))
        value["facts"]["policy_sha256"] = "f" * 64
        self.assertEqual(self.review()["facts"], self.candidate["facts"])

    def test_review_does_not_write_initialize_scan_or_accept(self):
        manager = self.fixture.manager
        manager.runner = Mock(side_effect=AssertionError("review attempted a lifecycle command"))
        manager.facts = Mock(side_effect=self.fixture.facts)
        before = self.snapshot()
        with patch.object(manager, "_locked", side_effect=AssertionError("creating lock helper used")), \
                patch.object(manager, "prepare", side_effect=AssertionError("review initialized")), \
                patch.object(manager, "check", side_effect=AssertionError("review scanned")), \
                patch.object(manager, "enroll", side_effect=AssertionError("review enrolled")), \
                patch.object(manager.records, "write", side_effect=AssertionError("review wrote a record")), \
                patch.object(manager, "_write_bytes", side_effect=AssertionError("review wrote an artifact")), \
                patch.object(manager, "_sync", side_effect=AssertionError("review rewrote durability metadata")):
            self.assertFalse(self.review()["enrolled"])
        manager.runner.assert_not_called()
        manager.facts.assert_called_once()
        self.assertEqual(self.snapshot(), before)
        self.fixture.assert_inactive()

    def test_missing_initializing_and_old_candidates_refuse_without_creation(self):
        path = self.fixture.state / "candidate.json"
        path.unlink()
        before = self.snapshot()
        with self.assertRaises(Refused):
            self.review()
        self.assertEqual(self.snapshot(), before)
        for candidate in ({**self.candidate, "state": "initializing"},
                          {key: value for key, value in self.candidate.items() if key != "report_sha256"}):
            self.candidate_record(candidate)
            before = self.snapshot()
            with self.assertRaises(Refused):
                self.review()
            self.assertEqual(self.snapshot(), before)

    def test_candidate_confirmation_database_and_report_digests_are_verified(self):
        for field in ("confirmation", "database_sha256", "report_sha256"):
            candidate = {**self.candidate, field: "f" * 64}
            atomic_json(self.fixture.state / "candidate.json", candidate)
            with self.subTest(field=field, rebound=False), self.assertRaises(Refused):
                self.review()
            if field != "confirmation":
                self.candidate_record(candidate)
                with self.subTest(field=field, rebound=True), self.assertRaises(Refused):
                    self.review()
        atomic_json(self.fixture.state / "candidate.json", self.candidate)
        self.fixture.write_private(self.fixture.state / "candidate.db.gz", gzip.compress(b"changed candidate", mtime=0))
        with self.assertRaises(Refused):
            self.review()

    def test_original_report_changes_refuse_even_after_latest_result_is_replaced(self):
        self.fixture.manager.enroll(self.candidate["confirmation"])
        self.fixture.manager.check()
        self.assertNotEqual(self.fixture.record("last-result.json")["id"], self.candidate["report_id"])
        value = self.review()
        self.assertTrue(value["enrolled"])
        self.assertEqual(value["report"]["id"], self.candidate["report_id"])
        report = json.loads(self.report_path.read_text())
        report["stdout"] += " "
        self.report_record(report)
        with self.assertRaises(Refused):
            self.review()

    def test_enrollment_refuses_changed_or_missing_reviewed_report_before_scan_or_writes(self):
        reviewed = self.review()
        original = self.report_path.read_bytes()
        for missing in (False, True):
            self.fixture.write_private(self.report_path, original)
            if missing:
                self.report_path.unlink()
            else:
                report = json.loads(original)
                report["stdout"] += " "
                self.report_record(report)
            with self.subTest(missing=missing), self.enrollment_preflight_only():
                with self.assertRaises(Refused):
                    self.fixture.manager.enroll(reviewed["confirmation"])
            self.fixture.assert_inactive()
            self.assertFalse((self.fixture.state / "commit-pending.json").exists())

    def test_enrollment_reparses_original_report_even_with_rebound_digest(self):
        original = json.loads(self.report_path.read_text())
        variants = []
        for field, bad in (("schema", True), ("id", lifecycle.INSTALLATION),
                           ("facts_sha256", "f" * 64), ("database_sha256", "f" * 64),
                           ("stderr", lifecycle.SECRET)):
            variants.append({**original, field: bad})
        variants.append({**original, "counts": {**original["counts"], "total": 99}})
        raw = json.loads(original["stdout"])
        raw["databases"] = {str(self.fixture.state / "aide.db.gz"): {"sha512": "b" * 128}}
        variants.append({**original, "stdout": json.dumps(raw)})
        for index, report in enumerate(variants):
            self.report_record(report, rebind=True)
            confirmation = self.fixture.record("candidate.json")["confirmation"]
            with self.subTest(variant=index), self.enrollment_preflight_only():
                with self.assertRaises(Refused) as caught:
                    self.fixture.manager.enroll(confirmation)
                self.assertNotIn(lifecycle.SECRET, str(caught.exception))
            self.fixture.assert_inactive()
            self.assertFalse((self.fixture.state / "commit-pending.json").exists())

    def test_original_report_change_during_fresh_enrollment_check_prevents_activation(self):
        original = self.report_path.read_bytes()
        for missing in (False, True):
            self.fixture.write_private(self.report_path, original)

            def change_original(_):
                if missing:
                    self.report_path.unlink()
                else:
                    report = json.loads(original)
                    report["stdout"] += " "
                    self.report_record(report)

            self.fixture.on_check = change_original
            before = self.fixture.count_calls("check")
            with self.subTest(missing=missing), self.assertRaises(Refused):
                self.fixture.manager.enroll(self.candidate["confirmation"])
            self.assertEqual(self.fixture.count_calls("check"), before + 1)
            self.fixture.assert_inactive()
            self.assertFalse((self.fixture.state / "commit-pending.json").exists())
            self.assertEqual(self.fixture.record("candidate.json"), self.candidate)

    def test_enrollment_retry_requires_original_report_before_any_durability_write(self):
        self.fixture.manager.enroll(self.candidate["confirmation"])
        original = self.report_path.read_bytes()
        for missing in (False, True):
            self.fixture.write_private(self.report_path, original)
            if missing:
                self.report_path.unlink()
            else:
                report = json.loads(original)
                report["counts"]["total"] = 99
                self.report_record(report)
            with self.subTest(missing=missing), self.enrollment_preflight_only():
                with self.assertRaises(Refused):
                    self.fixture.manager.enroll(self.candidate["confirmation"])

    def test_enrolled_check_status_and_completion_require_original_review_evidence(self):
        manager = self.fixture.manager
        manager.enroll(self.candidate["confirmation"])
        original = self.report_path.read_bytes()
        for missing in (False, True):
            self.fixture.write_private(self.report_path, original)
            manager.check()
            self.assertEqual(manager.status()["last_check"]["state"], "clean")
            self.assertTrue(manager.firstboot_checks(lifecycle.INSTALLATION)["aide_checked_clean"])
            if missing:
                self.report_path.unlink()
            else:
                report = json.loads(original)
                report["stdout"] += " "
                self.report_record(report)
            calls = list(self.fixture.calls)
            for action in (manager.status, lambda: manager.firstboot_checks(lifecycle.INSTALLATION), manager.check):
                with self.subTest(missing=missing, action=action), self.assertRaises(Refused):
                    action()
            self.assertEqual(self.fixture.calls, calls)
            self.assertEqual(self.fixture.record("last-attempt.json")["state"], "error")

    def test_validated_enrollment_anchor_and_database_are_required_for_enrolled_flag(self):
        self.fixture.manager.enroll(self.candidate["confirmation"])
        self.assertTrue(self.review()["enrolled"])
        baseline = self.fixture.state / "aide.db.gz"
        original = baseline.read_bytes()
        self.fixture.write_private(baseline, gzip.compress(b"changed enrolled database", mtime=0))
        with self.assertRaises(Refused):
            self.review()
        self.fixture.write_private(baseline, original)
        receipt = json.loads(self.fixture.marker.read_text())
        receipt["candidate_confirmation"] = "c" * 64
        atomic_json(self.fixture.marker, receipt)
        with self.assertRaises(Refused):
            self.review()

    def test_all_stored_counts_must_match_the_reparsed_report_with_exact_types(self):
        original = json.loads(self.report_path.read_text())
        for field in ("total", "added", "removed", "changed"):
            for bad in (-1, True, 0.0, "0", None, 99):
                report = copy.deepcopy(original)
                report["counts"][field] = bad
                self.report_record(report, rebind=True)
                with self.subTest(field=field, bad=bad), self.assertRaises(Refused):
                    self.review()

    def test_report_metadata_raw_diagnostics_and_schema_are_not_trusted(self):
        original = json.loads(self.report_path.read_text())
        for field, bad in (("id", "028917b1-f04e-42a2-85d6-776c0b260a21"), ("schema", True),
                           ("action", "init"), ("state", "differences"), ("exit_code", False),
                           ("aide_version", "0.19.3"), ("facts_sha256", "e" * 64),
                           ("database_sha256", "b" * 64), ("stderr", lifecycle.SECRET + "\x1b[31m")):
            report = copy.deepcopy(original)
            report[field] = bad
            self.report_record(report, rebind=True)
            with self.subTest(field=field), self.assertRaises(Refused) as caught:
                self.review()
            self.assertNotIn(lifecycle.SECRET, str(caught.exception))
            self.assertNotIn("\x1b", str(caught.exception))
        report = {**original, "unexpected": lifecycle.SECRET}
        self.report_record(report, rebind=True)
        with self.assertRaises(Refused):
            self.review()

    def test_stale_context_wrong_fact_types_and_extra_fields_refuse(self):
        self.fixture.values["source_snapshot_sha256"] = "b" * 64
        with self.assertRaises(Refused):
            self.review()
        self.fixture.values = copy.deepcopy(self.candidate["facts"])
        for change in ({"source_dirty": 1}, {"unexpected": lifecycle.SECRET},
                       {"aide_package": lifecycle.SECRET + "\x1b[31m"}):
            self.candidate_record({**self.candidate, "facts": {**self.candidate["facts"], **change}})
            with self.subTest(change=change), self.assertRaises(Refused) as caught:
                self.review()
            self.assertNotIn(lifecycle.SECRET, str(caught.exception))

    def test_display_timestamps_are_canonical_and_never_emit_control_characters(self):
        report = json.loads(self.report_path.read_text())
        report["observed_at"] = "2026-09-07\x1b10:00:00+00:00"
        self.report_record(report, rebind=True)
        candidate = self.fixture.record("candidate.json")
        candidate["created_at"] = "2026-09-07\x1b10:00:00+00:00"
        self.candidate_record(candidate)
        value = self.review()
        self.assertEqual(value["created_at"], self.fixture.now)
        self.assertEqual(value["report"]["observed_at"], self.fixture.now)
        self.assertNotIn("\x1b", json.dumps(value))
        for invalid in ("not-a-date", "2026-09-07T10:00:00", lifecycle.SECRET, None):
            candidate["created_at"] = invalid
            self.candidate_record(candidate)
            with self.subTest(invalid=invalid), self.assertRaises(Refused) as caught:
                self.review()
            self.assertNotIn(lifecycle.SECRET, str(caught.exception))

    def test_all_existing_locks_are_opened_readonly_in_fixed_order(self):
        with self.coordination() as paths:
            seen = []
            original = os.open

            def capture(path, flags, *args, **kwargs):
                if Path(path) in paths:
                    seen.append(Path(path))
                    self.assertFalse(flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR))
                    self.assertTrue(flags & os.O_NOFOLLOW)
                return original(path, flags, *args, **kwargs)

            with patch.object(aide.os, "open", side_effect=capture):
                self.review()
            self.assertEqual(seen, list(paths))

    def test_missing_or_busy_locks_refuse_without_creating_or_retaining_locks(self):
        with self.coordination() as paths:
            for path in paths:
                with self.subTest(path=path, condition="busy"):
                    with locked(path):
                        with self.assertRaisesRegex(Refused, "aide_review_busy"):
                            self.review()
                    self.review()  # A failed acquisition released earlier locks.
                path.unlink()
                before = self.snapshot()
                with self.subTest(path=path, condition="missing"), self.assertRaises(Refused):
                    self.review()
                self.assertEqual(self.snapshot(), before)
                self.assertFalse(path.exists())
                self.fixture.write_private(path, b"")

    def test_unsafe_coordination_lock_and_parent_are_refused(self):
        with self.coordination() as paths:
            path = paths[1]
            path.chmod(0o644)
            with self.assertRaises(Refused):
                self.review()
            path.chmod(0o600)
            path.parent.chmod(0o770)
            with self.assertRaises(Refused):
                self.review()
            path.parent.chmod(0o700)
            path.unlink()
            path.symlink_to(paths[2])
            with self.assertRaises(Refused):
                self.review()


if __name__ == "__main__":
    unittest.main()
