"""Restore effects and interruption boundaries; no native-host claims."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager.common import Refused
from nebulalog_manager.restore_database import RestoreDatabases

OP = "24ef487e-9257-40bf-a504-bd1c394287bc"
SOURCE = "a1e8d10a-7129-4d41-a07c-c6b24dbe2c45"
TARGET = "93ec0baf-50b3-41e4-8a4e-d6ed82221a13"


class Commands:
    def __init__(self):
        self.calls = []
        self.catalog = {"database": "nebulalog", "user": "nebulalog", "owner": "nebulalog",
                        "privileged": False, "memberships": 0, "sessions": 0, "objects": 0}
        self.failure = None
        self.audit_count = "1"

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if "--command" in argv:
            return self.audit_count if "SELECT count(*) FROM audit_events" in argv[-1] else json.dumps(self.catalog)
        return ""

    def feed(self, argv, source, **kwargs):
        self.calls.append((argv, {"source": source, **kwargs}))
        if self.failure and "--single-transaction" in argv:
            raise self.failure


class RestoreDatabaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = Path(temporary.name) / "nebulalog.dump"
        self.archive.write_bytes(b"PGDMP synthetic fixture")
        self.archive.chmod(0o600)
        self.entry = {"path": "nebulalog.dump", "bytes": self.archive.stat().st_size,
                      "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest()}
        self.tx = {"id": OP, "source_installation_id": SOURCE, "target_installation_id": TARGET}
        self.cmd = Commands()
        self.db = RestoreDatabases(self.cmd)
        self.checkpoints = []
        def trusted(path):
            if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
                raise Refused("Unsafe test archive")
            return path
        # Test-only owner mapping. Production remains root-only on Linux.
        guard = patch("nebulalog_manager.restore_database.trusted_file", side_effect=trusted)
        guard.start()
        self.addCleanup(guard.stop)

    def apply(self):
        return self.db.apply("nebulalog", self.archive, self.entry, self.tx,
                             lambda: self.checkpoints.append(copy.deepcopy(self.tx)))

    def test_single_transaction_non_superuser_and_durable_intent(self):
        self.apply()
        self.assertEqual([t["databases"]["nebulalog"]["state"] for t in self.checkpoints], ["restoring", "restored"])
        command = next(argv for argv, _ in self.cmd.calls if "--single-transaction" in argv)
        self.assertIn("--exit-on-error", command)
        self.assertIn("--username=nebulalog", command)
        self.assertIn("--dbname=nebulalog", command)
        self.assertIn("--no-owner", command)
        self.assertIn("--no-privileges", command)
        self.assertNotIn("--clean", command)
        self.assertNotIn("--create", command)
        self.assertIn("env", command)
        self.assertIn("PGAPPNAME=captainslog-restore-" + OP, command)

    def test_nonempty_busy_privileged_foreign_database_refuses_before_dispatch(self):
        for key, value in (("objects", 1), ("sessions", 1), ("memberships", 1), ("privileged", True),
                           ("owner", "postgres"), ("database", "foreign"), ("user", "postgres"),
                           ("objects", False)):
            with self.subTest(key=key, value=value):
                previous = self.cmd.catalog[key]
                self.cmd.catalog[key] = value
                with self.assertRaises(Refused):
                    self.apply()
                self.cmd.catalog[key] = previous
        self.assertNotIn("databases", self.tx)
        self.assertFalse(any("pg_restore" in argv for argv, _ in self.cmd.calls))

    def test_tamper_and_permissions_refuse_before_any_database_contact(self):
        self.archive.write_bytes(b"PGDMP wrong bytes")
        with self.assertRaises(Refused):
            self.apply()
        self.assertEqual(self.cmd.calls, [])
        self.archive.write_bytes(b"PGDMP synthetic fixture")
        self.archive.chmod(0o644)
        with self.assertRaises(Refused):
            self.apply()
        self.assertEqual(self.cmd.calls, [])

    def test_failed_or_interrupted_dispatch_never_automatically_retries(self):
        for failure in (Refused("private details"), TimeoutError("private details"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                self.tx.pop("databases", None)
                self.cmd.failure = failure
                with self.assertRaisesRegex(Refused, "durable acknowledgement") as caught:
                    self.apply()
                self.assertNotIn("private details", str(caught.exception))
                self.assertEqual(self.tx["databases"]["nebulalog"]["state"], "restoring")
                calls = len(self.cmd.calls)
                self.cmd.failure = None
                with self.assertRaisesRegex(Refused, "ambiguous"):
                    self.apply()
                self.assertEqual(len(self.cmd.calls), calls)

    def test_checkpoint_failure_prevents_dispatch(self):
        def failed():
            raise OSError("disk full")
        with self.assertRaises(OSError):
            self.db.apply("nebulalog", self.archive, self.entry, self.tx, failed)
        self.assertFalse(any("--single-transaction" in argv for argv, _ in self.cmd.calls))

    def test_completed_archive_not_reapplied_but_changed_inventory_refuses(self):
        self.apply()
        calls = len(self.cmd.calls)
        self.apply()
        self.assertEqual(len(self.cmd.calls), calls)
        self.archive.write_bytes(b"other authentic backup")
        self.entry.update(bytes=self.archive.stat().st_size, sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest())
        with self.assertRaisesRegex(Refused, "ambiguous"):
            self.apply()

    def test_quarantine_requires_both_databases_and_exact_audit_readback(self):
        with self.assertRaises(Refused):
            self.db.quarantine_source_operations(self.tx)
        self.assertEqual(self.cmd.calls, [])
        self.tx["databases"] = {name: {"state": "restored"} for name in ("nebulalog", "keycloak")}
        self.cmd.audit_count = "0"
        with self.assertRaisesRegex(Refused, "audit receipt"):
            self.db.quarantine_source_operations(self.tx)
        sql = self.cmd.calls[0][1]["input"].decode()
        self.assertIn("--interactive", self.cmd.calls[0][0])
        self.assertTrue(sql.startswith("BEGIN;"))
        self.assertTrue(sql.endswith("COMMIT;\n"))
        self.assertIn("appliance.restore.configuration", sql)
        self.assertNotIn("DELETE FROM saved_filters", sql)
        self.assertNotIn("DELETE FROM firewalls", sql)
        self.assertNotIn("WHERE key='retention'", sql)
        self.assertIn("UPDATE export_jobs SET status='failed'", sql)
        # Neither old nor host-challenge-bound OAuth transactions survive a
        # restore. Both deletions share the quarantine audit transaction.
        self.assertIn("DELETE FROM public.host_stepup_pending';", sql)
        self.assertIn("DELETE FROM public.host_stepup_pending_v2';", sql)
        self.assertIn("transient := transient + affected;", sql)

    def test_noncanonical_operation_rejected_without_dispatch(self):
        self.tx["id"] = OP.upper()
        with self.assertRaises(Refused):
            self.apply()
        self.assertEqual(self.cmd.calls, [])


if __name__ == "__main__":
    unittest.main()
