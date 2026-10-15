"""AIDE lifecycle tests use private temporary fixtures, never host commands.

The fake runner produces the pinned JSON report format, not real scan evidence.
Storage and package evidence are explicitly injected; this is not guest/FIPS QA.
"""
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import aide, host_job_storage
from nebulalog_manager.common import Refused, atomic_json, locked
from nebulalog_manager.host_job_storage import StorageIdentity


INSTALLATION = "458a08e3-ef3b-4cd1-83e5-b402a2c1e913"
SECRET = "PRIVATE-AIDE-REPORT-FIXTURE-DO-NOT-PUBLISH"
POLICY = "NEBULA = ftype+p+u+g+s+sha512\n/etc NEBULA\n/usr NEBULA\n"


class AideLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.identity = StorageIdentity(INSTALLATION, self.root, self.root.stat().st_dev)
        self.state = self.root / "manager/aide"
        self.marker = self.root / "manager/aide-enrollment.json"
        self.policy = self.root / "policy.conf"
        self.write_private(self.policy, POLICY.encode())
        self.values = {field: "a" * 64 for field in aide.FACTS}
        self.values.update(installation_id=INSTALLATION, aide_version="0.19.2", source_dirty=True,
                           aide_package="aide-0.19.2-5.el9_8.1.x86_64",
                           policy_sha256=hashlib.sha256(POLICY.encode()).hexdigest())
        self.calls = []
        self.init_code = self.check_code = self.config_code = 0
        self.stderr = ""
        self.on_check = None
        self.now = "2026-09-07T10:00:00+00:00"
        self.boot_snapshot = Mock(return_value={})
        for module in (aide, host_job_storage):
            patcher = patch.object(module, "ROOT_UID", os.getuid())
            patcher.start()
            self.addCleanup(patcher.stop)
        # Any accidental fallthrough to real commands fails this test immediately.
        patcher = patch("subprocess.Popen", side_effect=AssertionError("host command forbidden in lifecycle tests"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.manager = self.fresh()

    def write_private(self, path, content):
        path.write_bytes(content)
        path.chmod(0o600)

    def reader(self, path, *, maximum=aide.MAX_DATABASE, private=False, device=None):
        path = Path(path)
        self.assertTrue(path.is_relative_to(self.root), "fixture reader escaped its temporary root")
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or info.st_mode & (0o077 if private else 0o022)
                or not 0 < info.st_size <= maximum or device is not None and info.st_dev != device):
            raise Refused("unsafe_aide_fixture_file")
        return path.read_bytes()

    def facts(self, *_):
        return copy.deepcopy(self.values)

    def monitor(self, *_):
        return {key: copy.deepcopy(self.values[key]) for key in aide.MONITOR_FACTS}

    def fresh(self):
        return aide.Aide(storage_guard=lambda: self.identity, facts=self.facts, monitor=self.monitor,
                         policy=self.policy, runner=self.run_fixture, reader=self.reader,
                         clock=lambda: self.now, lock_paths=lambda _: (), boot_snapshot=self.boot_snapshot)

    def run_fixture(self, argv, *, tmpdir, **_):
        self.calls.append(tuple(argv))
        self.assertEqual(Path(tmpdir), self.state / "tmp")
        if argv[0] == "/usr/sbin/restorecon":
            self.assertEqual(argv, ["/usr/sbin/restorecon", "-R", str(self.state)])
            return aide.Result(0)
        self.assertEqual(argv[0], "/usr/sbin/aide")
        self.assertEqual(len(argv), 3)
        self.assertTrue(argv[1].startswith("--config="))
        config = Path(argv[1].removeprefix("--config="))
        self.assertEqual(config.parent, self.state)
        options = dict(line.split("=", 1) for line in config.read_text().splitlines()
                       if "=" in line and not line.startswith("#"))
        self.assertEqual(options["report_format"], "json")
        self.assertEqual(options["report_url"], "stdout")
        source = Path(options["database_in"].removeprefix("file:"))
        output = Path(options["database_out"].removeprefix("file:"))
        self.assertNotEqual(source, output)
        self.assertEqual(source.parent, self.state)
        self.assertEqual(output.parent, self.state)
        if argv[2] == "--config-check":
            return aide.Result(self.config_code)
        self.assertIn(argv[2], ("--init", "--check"))
        initializing = argv[2] == "--init"
        code = self.init_code if initializing else self.check_code
        if code not in range(8):
            return aide.Result(code, "", SECRET)
        if initializing:
            self.assertFalse(output.exists(), "init must not overwrite an existing candidate")
            self.write_private(output, gzip.compress(b"fixture initialized AIDE database\n", mtime=0))
        else:
            self.assertTrue(source.is_file())
            if self.on_check:
                self.on_check(source)
        report = {
            "aide_version": "0.19.2", "start_time": self.now, "end_time": self.now,
            "run_time_seconds": 0, "outline": "AIDE fixture result",
            "number_of_entries": {"total": 12},
            "databases": {str(output if initializing else source): {"sha512": "b" * 128}},
        }
        if initializing:
            report["new_database"] = str(output)
        if code:
            for name, bit in (("added", 1), ("removed", 2), ("changed", 4)):
                count = int(bool(code & bit))
                report["number_of_entries"][name] = count
                if count:
                    report[name] = {"/etc/" + name: "f+++++++++++++++"}
        return aide.Result(code, json.dumps(report), self.stderr)

    def count_calls(self, action):
        return sum(call[-1] == "--" + action for call in self.calls)

    def enrolled(self):
        candidate = self.manager.prepare()
        receipt = self.manager.enroll(candidate["confirmation"])
        return candidate, receipt

    def record(self, name):
        return json.loads((self.state / name).read_text())

    def assert_inactive(self):
        self.assertFalse(self.marker.exists())
        self.assertFalse((self.state / "aide.db.gz").exists())

    def test_prepare_enroll_check_are_explicit_private_and_idempotent(self):
        candidate = self.manager.prepare()
        self.assertEqual(candidate["state"], "prepared")
        self.assert_inactive()
        self.assertEqual(self.fresh().prepare(), candidate)
        self.assertEqual(self.count_calls("init"), 1)
        receipt = self.manager.enroll(candidate["confirmation"])
        check_count = self.count_calls("check")
        self.assertEqual(self.fresh().enroll(candidate["confirmation"]), receipt)
        self.assertEqual(self.count_calls("check"), check_count)
        self.assertEqual(self.manager.check()["state"], "clean")
        status = self.manager.status()
        self.assertEqual(status["baseline"], "enrolled")
        self.assertEqual(status["last_check"]["state"], "clean")
        self.assertFalse(status["last_check"]["stale"])
        with self.assertRaises(Refused):
            self.manager.prepare()
        for path in self.state.rglob("*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        self.assertEqual(stat.S_IMODE(self.marker.stat().st_mode), 0o600)

    def test_transaction_check_uses_existing_lock_without_reenrolling(self):
        self.enrolled()
        original = (self.state / 'aide.db.gz').read_bytes()
        with locked(self.root / 'manager/transaction.lock') as descriptor:
            with self.assertRaises(Refused):
                self.manager.check()
            result = self.manager.check_for_transaction(descriptor)
            self.assertEqual(result['state'], 'clean')
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), original)

    def test_transaction_check_refuses_unrelated_descriptor(self):
        self.enrolled()
        with locked(self.root / 'unrelated.lock') as descriptor:
            with self.assertRaisesRegex(Refused, 'lock_identity_changed'):
                self.manager.check_for_transaction(descriptor)
        with self.assertRaisesRegex(Refused, 'lock_unavailable'):
            self.manager.check_for_transaction(descriptor)

    def test_all_eight_check_results_preserve_the_enrolled_database(self):
        _, receipt = self.enrolled()
        baseline = (self.state / "aide.db.gz").read_bytes()
        marker = self.marker.read_bytes()
        for code in range(8):
            with self.subTest(code=code):
                self.check_code = code
                result = self.manager.check()
                self.assertEqual(result["exit_code"], code)
                self.assertEqual(result["state"], "differences" if code else "clean")
                self.assertEqual(self.manager.status()["last_check"]["state"], result["state"])
                self.assertEqual(result["database_sha256"], receipt["database_sha256"])
                self.assertEqual((self.state / "aide.db.gz").read_bytes(), baseline)
                self.assertEqual(self.marker.read_bytes(), marker)

    def test_failed_initialization_cannot_activate_and_retry_reuses_candidate_identity(self):
        self.init_code = 17
        with self.assertRaises(Refused):
            self.manager.prepare()
        candidate_id = self.record("candidate.json")["id"]
        self.assert_inactive()
        self.assertEqual(self.record("last-result.json")["state"], "error")
        self.init_code = 0
        self.assertEqual(self.fresh().prepare()["id"], candidate_id)
        self.assert_inactive()

    def test_findings_during_prepare_or_enrollment_never_activate(self):
        self.check_code = 4
        with self.assertRaises(Refused):
            self.manager.prepare()
        self.assert_inactive()
        self.assertEqual(self.record("candidate.json")["state"], "initializing")
        self.check_code = 0
        candidate = self.manager.prepare()
        self.check_code = 1
        with self.assertRaises(Refused):
            self.manager.enroll(candidate["confirmation"])
        self.assert_inactive()

    def test_changed_candidate_before_enrollment_is_refused_without_scan(self):
        candidate = self.manager.prepare()
        before = self.count_calls("check")
        self.write_private(self.state / "candidate.db.gz", gzip.compress(b"changed database", mtime=0))
        with self.assertRaises(Refused):
            self.manager.enroll(candidate["confirmation"])
        self.assertEqual(self.count_calls("check"), before)
        self.assert_inactive()

    def test_candidate_changed_during_verification_is_not_marked_prepared(self):
        self.on_check = lambda path: self.write_private(path, gzip.compress(b"changed during verification", mtime=0))
        with self.assertRaises(Refused):
            self.manager.prepare()
        self.assertEqual(self.record("candidate.json")["state"], "initializing")
        self.assert_inactive()

    def test_candidate_changed_during_enrollment_verification_is_not_committed(self):
        candidate = self.manager.prepare()
        self.on_check = lambda path: self.write_private(path, gzip.compress(b"changed during enrollment", mtime=0))
        with self.assertRaises(Refused):
            self.manager.enroll(candidate["confirmation"])
        self.assert_inactive()

    def test_failed_diagnostics_are_private_and_replace_previous_clean_status(self):
        self.enrolled()
        self.manager.check()
        self.stderr = "WARNING " + SECRET
        result = self.manager.check()
        self.assertEqual(result["state"], "error")
        status = self.manager.status()
        self.assertEqual(status["last_check"]["state"], "error")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(SECRET, json.dumps(status))
        report = self.record("reports/" + result["id"] + ".json")
        self.assertIn(SECRET, report["stderr"])

    def test_early_failure_and_interrupted_attempt_override_old_clean_report(self):
        self.enrolled()
        previous = self.manager.check()
        self.config_code = 17
        with self.assertRaises(Refused):
            self.manager.check()
        self.assertEqual(self.record("last-result.json")["id"], previous["id"])
        self.assertEqual(self.manager.status()["last_check"]["state"], "error")
        attempt = self.record("last-attempt.json")
        attempt.update(state="running", report_id=None)
        atomic_json(self.state / "last-attempt.json", attempt)
        self.assertEqual(self.manager.status()["last_check"]["state"], "interrupted")

    def test_summary_cannot_claim_clean_for_a_hashed_finding_report(self):
        self.enrolled()
        self.check_code = 4
        self.manager.check()
        summary = self.record("last-result.json")
        summary["state"] = "clean"
        atomic_json(self.state / "last-result.json", summary)
        with self.assertRaises(Refused):
            self.manager.status()

    def test_missing_state_and_dangling_anchor_never_restart_initialization(self):
        self.enrolled()
        before = len(self.calls)
        shutil.rmtree(self.state)  # Only this test's generated temporary tree.
        for action in (self.manager.status, self.manager.prepare, self.manager.check):
            with self.assertRaises(Refused):
                action()
        self.marker.unlink()
        self.marker.symlink_to(self.root / "missing-anchor-target")
        for action in (self.manager.status, self.manager.prepare, self.manager.check):
            with self.assertRaises(Refused):
                action()
        self.assertFalse(self.state.exists())
        self.assertEqual(len(self.calls), before)

    def test_interrupted_commit_before_anchor_recovers_the_exact_pending_receipt(self):
        candidate = self.manager.prepare()
        write = self.manager.records.write

        def fail_anchor(path, value, identity):
            if path == self.marker:
                raise OSError("fixture crash before marker")
            return write(path, value, identity)

        with patch.object(self.manager.records, "write", side_effect=fail_anchor), self.assertRaises(Refused):
            self.manager.enroll(candidate["confirmation"])
        pending = self.record("commit-pending.json")
        baseline = (self.state / "aide.db.gz").read_bytes()
        self.assertFalse(self.marker.exists())
        receipt = self.fresh().enroll(candidate["confirmation"])
        self.assertEqual(receipt, pending)
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), baseline)
        self.assertEqual(self.count_calls("init"), 1)

    def test_uncertain_anchor_write_retry_confirms_durability_without_reinitializing(self):
        candidate = self.manager.prepare()
        write = self.manager.records.write

        def uncertain_anchor(path, value, identity):
            write(path, value, identity)
            if path == self.marker:
                raise OSError("fixture uncertain marker directory flush")

        with patch.object(self.manager.records, "write", side_effect=uncertain_anchor), self.assertRaises(Refused):
            self.manager.enroll(candidate["confirmation"])
        self.assertTrue(self.marker.exists())
        before = self.count_calls("check")
        retry = self.fresh()
        with patch.object(retry, "_sync", wraps=retry._sync) as barriers:
            receipt = retry.enroll(candidate["confirmation"])
        flushed = {path for call in barriers.call_args_list for path in call.args}
        self.assertTrue({self.marker, self.state / "aide.db.gz", self.state, self.root / "manager", self.root} <= flushed)
        self.assertEqual(receipt["candidate_confirmation"], candidate["confirmation"])
        self.assertEqual(self.count_calls("check"), before)
        self.assertEqual(self.count_calls("init"), 1)

    def test_version_policy_or_initial_context_changes_refuse_enrollment(self):
        candidate = self.manager.prepare()
        original = copy.deepcopy(self.values)
        for field, value in (("aide_version", "0.19.3"), ("policy_sha256", "c" * 64),
                             ("source_snapshot_sha256", "d" * 64), ("configured_sha256", "e" * 64)):
            self.values = copy.deepcopy(original)
            self.values[field] = value
            with self.subTest(field=field), self.assertRaises(Refused):
                self.manager.enroll(candidate["confirmation"])
            self.assert_inactive()
        self.values = original
        self.write_private(self.policy, POLICY.encode() + b"# changed policy\n")
        with self.assertRaises(Refused):
            self.manager.enroll(candidate["confirmation"])
        self.assert_inactive()

    def test_boot_snapshot_change_during_candidate_check_preserves_unenrolled_evidence(self):
        original = self.values['ordinary_boot_snapshot_sha256']
        self.on_check = lambda _: self.values.update(ordinary_boot_snapshot_sha256='f' * 64)
        with self.assertRaisesRegex(Refused, 'candidate_not_clean'):
            self.manager.prepare()
        self.assertEqual(self.record('candidate.json')['facts']['ordinary_boot_snapshot_sha256'], original)
        self.assertEqual(self.record('candidate.json')['state'], 'initializing')
        self.assert_inactive()

    def test_late_boot_writer_before_enrollment_or_review_does_not_reinitialize(self):
        candidate = self.manager.prepare()
        initializations, checks = self.count_calls('init'), self.count_calls('check')
        self.values['ordinary_boot_snapshot_sha256'] = 'f' * 64
        for action in (self.manager.prepare, self.manager.review,
                       lambda: self.manager.enroll(candidate['confirmation'])):
            with self.assertRaisesRegex(Refused, 'context_changed'):
                action()
        self.assertEqual((self.count_calls('init'), self.count_calls('check')), (initializations, checks))
        self.assertEqual(self.record('candidate.json'), candidate)
        self.assert_inactive()

    def test_enrolled_checks_verify_retained_initial_snapshot_without_refreshing_facts(self):
        _, receipt = self.enrolled()
        expected = receipt['facts']['ordinary_boot_snapshot_sha256']
        self.values['ordinary_boot_snapshot_sha256'] = 'f' * 64
        self.boot_snapshot.reset_mock()
        self.manager.check()
        self.boot_snapshot.assert_called_once_with(self.identity, expected)
        checks = self.count_calls('check')
        self.boot_snapshot.side_effect = Refused('retained snapshot missing')
        with self.assertRaisesRegex(Refused, 'retained snapshot missing'):
            self.manager.check()
        self.assertEqual(self.count_calls('check'), checks)
        self.assertEqual(self.record('commit-pending.json'), receipt)

    def test_legacy_enrollment_without_boot_snapshot_fact_requires_migration(self):
        _, receipt = self.enrolled()
        del receipt['facts']['ordinary_boot_snapshot_sha256']
        self.write_private(self.marker, json.dumps(receipt).encode())
        checks = self.count_calls('check')
        with self.assertRaises(Refused):
            self.manager.check()
        self.assertEqual(self.count_calls('check'), checks)
        self.assertNotIn('ordinary_boot_snapshot_sha256', json.loads(self.marker.read_text())['facts'])

    def test_prepared_retry_flushes_candidate_and_its_evidence_before_acknowledgment(self):
        candidate = self.manager.prepare()
        retry = self.fresh()
        before = self.count_calls("check")
        with patch.object(retry, "_sync", wraps=retry._sync) as barriers:
            self.assertEqual(retry.prepare(), candidate)
        flushed = {path for call in barriers.call_args_list for path in call.args}
        self.assertTrue({self.state / "candidate.db.gz", self.state / "candidate.json",
                         self.state / "reports" / (candidate["report_id"] + ".json"),
                         self.state / "reports", self.state, self.root / "manager", self.root} <= flushed)
        self.assertEqual(self.count_calls("check"), before)
        self.assertEqual(self.count_calls("init"), 1)


if __name__ == "__main__":
    unittest.main()
