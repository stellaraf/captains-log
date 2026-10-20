"""Fresh review/apply failure boundaries; small files, no native runtime effects."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_configuration_restore as fixtures
from nebulalog_manager import configuration_restore as restore
from nebulalog_manager.common import Refused, atomic_json


class RestoreReviewTests(unittest.TestCase):
    def setUp(self):
        fixtures.CoordinatorTests.setUp(self)
        self.manager.pointer.unlink()
        (self.stage / "transaction.json").unlink()
        encrypted = self.stage / "backup.cms"
        encrypted.write_bytes(b"synthetic fixture; authentication exercised separately")
        encrypted.chmod(0o600)
        self.tx["archive_sha256"] = hashlib.sha256(encrypted.read_bytes()).hexdigest()
        self.now = 1800000000
        self.manager.clock = lambda: self.now
        self.runtime.inspect_recovery = Mock(return_value={"resource_revision": "b" * 64,
            "schema_revision": "3", "certificates_verified": True})
        self.continue_restore = Mock(return_value={"state": "synthetic-dispatched"})
        self.manager._continue = self.continue_restore
        for item in (patch("nebulalog_manager.log_recovery_set.ROOT_UID", os.getuid()),
                     patch.object(restore, "_encrypted_staging"),
                     patch.object(restore.shutil, "disk_usage", return_value=SimpleNamespace(total=1024**4, free=800 * 1024**3))):
            value = item.start()
            self.addCleanup(item.stop)
            if hasattr(value, "return_value"):
                self.capacity = value

    def review(self):
        return self.manager._prepared_review(copy.deepcopy(self.tx))

    def apply(self, review):
        return self.manager.apply_prepared(review["id"], review["review_digest"])

    def test_preview_does_not_install_pointer_or_advance_runtime(self):
        review = self.review()
        self.assertFalse(self.manager.pointer.exists())
        self.assertFalse((self.stage / "transaction.json").exists())
        self.assertFalse((self.stage / "apply-admission.json").exists())
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(json.loads((self.stage / "prepared.json").read_text())["runtime"], {})
        self.assertEqual(review["expires_at"], self.now + 300)
        self.assertNotIn(str(self.stage), json.dumps(review))
        self.assertIsNone(review["eta_seconds"])

    def test_expiry_starts_after_input_validation(self):
        result = self.runtime.inspect_recovery.return_value
        def slow(*args):
            self.now += 700
            return result
        self.runtime.inspect_recovery.side_effect = slow
        review = self.review()
        self.assertEqual(review["issued_at"], self.now)
        self.assertEqual(review["expires_at"], self.now + 300)

    def test_expired_or_future_preview_never_admits(self):
        review = self.review()
        for value in (review["expires_at"], review["issued_at"] - 1):
            self.now = value
            with self.assertRaises(Refused):
                self.apply(review)
        self.assertFalse((self.stage / "apply-admission.json").exists())
        self.continue_restore.assert_not_called()

    def test_expiry_is_rechecked_after_target_guard(self):
        review = self.review()
        def guard():
            self.now = review["expires_at"]
            return self.tx["target_installation_id"]
        self.runtime.guard_fresh = guard
        with self.assertRaisesRegex(Refused, "expired during admission"):
            self.apply(review)
        self.assertFalse((self.stage / "apply-admission.json").exists())

    def test_admitted_verification_may_outlive_preview_without_renewal(self):
        review = self.review()
        result = self.runtime.inspect_recovery.return_value
        def slow(*args):
            self.now += 900
            return result
        self.runtime.inspect_recovery.side_effect = slow
        self.apply(review)
        intent = json.loads((self.stage / "apply-admission.json").read_text())
        self.assertLess(intent["admitted_at"], review["expires_at"])
        self.assertGreater(self.now, review["expires_at"])
        self.continue_restore.assert_called_once()

    def test_duplicate_apply_reads_status_without_continuation_even_after_expiry(self):
        review = self.review()
        self.apply(review)
        self.now += 999
        self.assertEqual(self.apply(review)["state"], "prepared")
        self.continue_restore.assert_called_once()
        with self.assertRaises(Refused):
            self.manager.apply_prepared(review["id"], "c" * 64)

    def test_changed_source_fails_before_pointer_and_keeps_admission_evidence(self):
        review = self.review()
        (self.stage / "source/nebulalog.dump").write_bytes(b"altered source")
        with self.assertRaises(Refused):
            self.apply(review)
        self.assertFalse(self.manager.pointer.exists())
        before = (self.stage / "apply-admission.json").read_bytes()
        with self.assertRaisesRegex(Refused, "interrupted apply"):
            self.apply(review)
        self.assertEqual((self.stage / "apply-admission.json").read_bytes(), before)
        self.continue_restore.assert_not_called()

    def test_changed_target_provenance_fails_before_pointer(self):
        review = self.review()
        self.runtime.inspect_recovery.return_value["resource_revision"] = "c" * 64
        with self.assertRaises(Refused):
            self.apply(review)
        self.assertFalse(self.manager.pointer.exists())
        self.continue_restore.assert_not_called()

    def test_changed_prepared_transaction_and_wrong_digest_never_admit(self):
        review = self.review()
        with self.assertRaises(Refused):
            self.manager.apply_prepared(review["id"], "c" * 64)
        tx = json.loads((self.stage / "prepared.json").read_text())
        tx["runtime"] = {"completed": ["environment"]}
        atomic_json(self.stage / "prepared.json", tx)
        with self.assertRaises(Refused):
            self.apply(review)
        self.assertFalse((self.stage / "apply-admission.json").exists())

    def test_capacity_drop_during_admission_refuses(self):
        review = self.review()
        self.capacity.return_value.free = 1024**3
        with self.assertRaisesRegex(Refused, "reserves"):
            self.apply(review)
        self.assertFalse(self.manager.pointer.exists())
        self.continue_restore.assert_not_called()

    def test_full_review_binds_native_inventory_without_dispatch_and_rechecks_it(self):
        fixtures.CoordinatorTests.with_logs(self)
        self.manager.pointer.unlink()
        (self.stage / "transaction.json").unlink()
        self.tx["logs"]["plan"]["minimum_free_bytes"] = 110 * 1024**3
        inventory = {"metadata_sha256": "c" * 64, "logical_bytes": 1024, "rows": 7,
                     "logical_files": 3, "parts": 1, "part_checksum_files": 1, "inventory_complete": True}
        with patch("nebulalog_manager.log_backup.inspect_native_archive", return_value=inventory) as inspected:
            review = self.review()
            self.assertEqual(review["scope"], "full")
            self.assertEqual(review["inspection"]["native_inventory"]["rows"], 7)
            self.assertFalse(self.manager.pointer.exists())
            self.native_adapter.start_restore.assert_not_called()
            inspected.return_value = {**inventory, "rows": 8}
            with self.assertRaisesRegex(Refused, "native inventory"):
                self.apply(review)
            self.continue_restore.assert_not_called()

    def test_full_review_refuses_insufficient_ten_percent_reserve(self):
        fixtures.CoordinatorTests.with_logs(self)
        self.manager.pointer.unlink()
        (self.stage / "transaction.json").unlink()
        with patch("nebulalog_manager.log_backup.inspect_native_archive", return_value={"logical_bytes": 1024}):
            with self.assertRaisesRegex(Refused, "reserves"):
                self.review()
        self.assertFalse((self.stage / "review.json").exists())
        self.native_adapter.start_restore.assert_not_called()

    def test_pointer_save_failure_never_dispatches_and_retry_never_adopts(self):
        review = self.review()
        original = restore.atomic_json
        def fail_pointer(path, value):
            if path == self.manager.pointer:
                raise OSError("synthetic pointer failure")
            return original(path, value)
        with patch.object(restore, "atomic_json", side_effect=fail_pointer), self.assertRaises(OSError):
            self.apply(review)
        self.assertTrue((self.stage / "transaction.json").exists())
        self.assertFalse(self.manager.pointer.exists())
        with self.assertRaisesRegex(Refused, "interrupted apply"):
            self.apply(review)
        self.continue_restore.assert_not_called()

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_real_authenticated_prepare_preserves_no_private_key_and_no_runtime_effect(self):
        if not subprocess.check_output(["openssl", "version"], text=True).startswith("OpenSSL 3."):
            self.skipTest("OpenSSL3 required")
        archive, key, cert, encrypted = [self.root / name for name in ("input.tar", "private.pem", "public.pem", "input.cms")]
        with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as out:
            for path in sorted((self.stage / "source").iterdir()):
                out.add(path, arcname=path.name, recursive=False)
        def run(args):
            return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Synthetic",
             "-keyout", str(key), "-out", str(cert)])
        run(["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER", "-in", str(archive),
             "-out", str(encrypted), str(cert)])
        key.chmod(0o600)
        invocations = []
        def commands(argv, **kwargs):
            invocations.append(argv)
            self.assertEqual(argv[:4], ["prlimit", "--core=0", "--fsize=" + str(restore.ARCHIVE_LIMIT), "--"])
            return run(argv[4:]).stdout.decode()
        self.manager.cmd = commands
        review = self.manager.prepare(encrypted, key, cert)
        stage = self.manager.manager / "restores" / review["id"]
        self.assertEqual(len(invocations), 1)
        self.assertFalse(self.manager.pointer.exists())
        self.assertFalse(list(stage.glob("decrypt-*")))
        self.assertFalse((stage / "transaction.json").exists())
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(review["archive_sha256"], hashlib.sha256(encrypted.read_bytes()).hexdigest())
        self.continue_restore.assert_not_called()


class RestoreReviewCliTests(unittest.TestCase):
    def invoke(self, args, runtime):
        from nebulalog_manager.cli import main
        with patch.object(restore, "ConfigurationRestore", return_value=runtime), patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
            return main(["restore", *args])

    def test_prepare_and_apply_are_separate_commands_with_no_apply_input_overrides(self):
        runtime = Mock()
        runtime.prepare.return_value = {"state": "review_ready"}
        runtime.apply_prepared.return_value = {"state": "runtime_ready"}
        args = ["--prepare-fresh", "--backup", "/protected/b", "--private-key", "/protected/k", "--certificate", "/protected/c"]
        self.assertEqual(self.invoke(args, runtime), 0)
        runtime.prepare.assert_called_once_with(Path("/protected/b"), Path("/protected/k"), Path("/protected/c"))
        runtime.start.assert_not_called()
        apply = ["--apply-plan", fixtures.OP, "--plan-digest", "a" * 64]
        self.assertEqual(self.invoke(apply, runtime), 0)
        runtime.apply_prepared.assert_called_once_with(fixtures.OP, "a" * 64)
        runtime.reset_mock()
        for option in ("--backup", "--private-key", "--certificate", "--destination", "--media", "--log-recovery-set"):
            self.assertEqual(self.invoke([*apply, option, "/protected/override"], runtime), 1)
        runtime.apply_prepared.assert_not_called()
        self.assertEqual(self.invoke(["--status", "--plan-digest", "a" * 64], runtime), 1)


if __name__ == "__main__":
    unittest.main()
