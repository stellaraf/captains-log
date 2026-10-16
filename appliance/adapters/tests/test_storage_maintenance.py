"""Real PostgreSQL coordination in a dedicated disposable database.

Opt in with CAPTAINSLOG_GATE_TEST_CONTAINER naming the isolated, labelled
emergency fixture. These are host-source/SQL tests, not native Podman acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from nebulalog_adapters import lifecycle
from nebulalog_manager.common import Refused

IDLE = {"schema": 1, "held": False, "delivery_held": False, "operation": None}


class GateShapeTests(unittest.TestCase):
    def test_exact_owner_and_boolean_contract(self):
        self.assertEqual(lifecycle.storage_gate_value(IDLE), IDLE)
        for value in ({**IDLE, "extra": 1}, {**IDLE, "held": 0}, {**IDLE, "schema": True},
                      {**IDLE, "operation": "a" * 64}, {**IDLE, "delivery_held": True},
                      {**IDLE, "held": True}, {**IDLE, "held": True, "operation": "a" * 64 + "\n"}):
            with self.subTest(value=value), self.assertRaises(Refused):
                lifecycle.storage_gate_value(value)


@unittest.skipUnless(os.environ.get("CAPTAINSLOG_GATE_TEST_CONTAINER"), "isolated PostgreSQL fixture not selected")
class StorageMaintenancePostgresTests(unittest.TestCase):
    def setUp(self):
        self.container = os.environ["CAPTAINSLOG_GATE_TEST_CONTAINER"]
        labels = json.loads(subprocess.check_output(["docker", "inspect", "--format", "{{json .Config.Labels}}", self.container]))
        self.assertEqual(labels.get("captainslog.fixture"), "emergency-destructive")
        self.database = "captainslog_gate_" + uuid.uuid4().hex
        self.psql("CREATE DATABASE " + self.database, database="emergency_test")
        self.addCleanup(lambda: self.psql("DROP DATABASE " + self.database + " WITH (FORCE)", database="emergency_test"))
        root = Path(__file__).resolve().parents[3]
        self.psql((root / "migrations/postgres.sql").read_text())
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.stage = self.root / "manager/updates/releases/one"
        self.stage.mkdir(parents=True)
        self.gate = self.root / "manager/storage-maintenance/gate.json"
        self.gate.parent.mkdir(mode=0o755)
        self.gate.write_text(json.dumps(IDLE))
        self.gate.chmod(0o644)
        self.calls = []
        self.manager = lifecycle.Lifecycle({"schema_revision": "2"}, self.command,
            state=self.root / "manager/updates", data=self.root, guard=lambda: None)
        for mock in (patch.object(lifecycle, "STORAGE_OWNER_UID", os.getuid()),
                     patch.object(lifecycle, "STORAGE_OWNER_GID", os.getgid()),
                     patch.object(lifecycle, "trusted_file", side_effect=lambda p: p)):
            mock.start()
            self.addCleanup(mock.stop)

    def prefix(self, database=None):
        return ["docker", "exec", "-i", self.container, "psql", "-X", "--username=emergency_test",
                "--dbname=" + (database or self.database), "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1"]

    def psql(self, text, database=None):
        return subprocess.check_output(self.prefix(database), input=text.encode(), stderr=subprocess.PIPE).decode().strip()

    def command(self, argv, *, input, timeout):
        self.calls.append(argv)
        self.assertIn("--dbname=nebulalog", argv)
        self.assertIn("--single-transaction", argv)
        return subprocess.check_output(self.prefix() + ["--single-transaction"], input=input,
            stderr=subprocess.PIPE, timeout=timeout).decode().strip()

    def hold(self, **kwargs):
        return self.manager.storage_maintenance(self.stage, held=True, **kwargs)

    def read(self):
        return json.loads(self.gate.read_text())

    def db_gate(self):
        return json.loads(self.psql("SELECT value FROM settings WHERE key='storage_emergency_maintenance'"))

    def test_hold_delivery_resume_and_exact_owner_release(self):
        self.hold(delivery_held=True)
        operation = hashlib.sha256(str(self.stage.resolve()).encode()).hexdigest()
        self.assertEqual(self.read(), {"schema": 1, "held": True, "delivery_held": True, "operation": operation})
        self.assertEqual(self.read(), self.db_gate())
        self.hold(delivery_held=False)
        self.assertTrue(self.read()["held"])
        self.assertFalse(self.read()["delivery_held"])
        self.manager.storage_maintenance(self.stage, held=False)
        self.assertEqual(self.read(), IDLE)
        self.assertEqual(self.db_gate(), IDLE)
        self.assertEqual(self.psql("SELECT count(*) FROM audit_events WHERE action='storage.emergency.maintenance'"), "3")

    def test_host_only_fence_does_not_claim_database_barrier(self):
        result = self.hold(delivery_held=True, host_only=True)
        self.assertFalse(result["database_barrier"])
        self.assertTrue(self.read()["delivery_held"])
        self.assertEqual(self.db_gate(), IDLE)
        self.assertEqual(self.calls, [])
        self.assertEqual(json.loads((self.stage / "adapter-storage-maintenance.json").read_text())["state"], "intent")
        self.hold(delivery_held=True)
        self.assertEqual(self.db_gate(), self.read())

    def test_host_only_cannot_release_either_hold(self):
        for held, delivery in ((False, False), (True, False)):
            with self.subTest(held=held, delivery=delivery):
                with self.assertRaises(Refused):
                    self.manager.storage_maintenance(self.stage, held=held, delivery_held=delivery, host_only=True)
        self.assertEqual(self.read(), IDLE)
        self.assertEqual(self.db_gate(), IDLE)
        self.assertEqual(self.calls, [])

    def test_real_application_shared_lock_blocks_host_after_file_fence(self):
        client = subprocess.Popen(self.prefix(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            client.stdin.write("BEGIN; SELECT pg_advisory_xact_lock_shared(%d);\n\\echo LOCKED\n" % lifecycle.STORAGE_LOCK)
            client.stdin.flush()
            while client.stdout.readline().strip() != "LOCKED":
                self.assertIsNone(client.poll())
            errors = []
            def run():
                try: self.hold(delivery_held=True)
                except Exception as exc: errors.append(exc)
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.read()["held"] and self.psql("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())") == "1":
                    break
                time.sleep(.05)
            else: self.fail("Host never reached the shared application lock barrier")
            self.assertTrue(worker.is_alive())
            self.assertEqual(self.db_gate(), IDLE)
            client.stdin.write("COMMIT;\n\\q\n"); client.stdin.flush()
            worker.join(10)
            self.assertFalse(worker.is_alive())
            self.assertFalse(errors, errors)
            self.assertEqual(self.db_gate(), self.read())
        finally:
            if client.poll() is None: client.terminate()
            client.communicate(timeout=10)

    def test_unresolved_insert_keeps_host_fence_and_rolls_back_sql(self):
        self.psql("INSERT INTO storage_emergency_inserts(id,table_uuid,partitions,query_id) VALUES(gen_random_uuid(),gen_random_uuid(),'[]',gen_random_uuid())")
        with self.assertRaises(subprocess.CalledProcessError): self.hold(delivery_held=True)
        self.assertTrue(self.read()["delivery_held"])
        self.assertEqual(self.db_gate(), IDLE)
        self.assertEqual(self.psql("SELECT count(*) FROM audit_events"), "0")

    def test_lost_commit_acknowledgement_retains_stronger_file_fence(self):
        self.hold(delivery_held=True)
        def lost(*args, **kwargs):
            self.command(*args, **kwargs)
            raise TimeoutError("synthetic lost acknowledgement after real commit")
        self.manager.cmd = lost
        with self.assertRaises(TimeoutError): self.hold(delivery_held=False)
        self.assertTrue(self.read()["delivery_held"])
        self.assertFalse(self.db_gate()["delivery_held"])
        self.manager.cmd = self.command
        self.hold(delivery_held=False)
        self.assertEqual(self.read(), self.db_gate())

    def test_restore_of_idle_db_cannot_erase_host_hold(self):
        self.hold(delivery_held=True)
        self.psql("UPDATE settings SET value='" + json.dumps(IDLE) + "'::jsonb WHERE key='storage_emergency_maintenance'")
        self.assertTrue(self.read()["held"])
        self.hold(delivery_held=True)
        self.assertEqual(self.read(), self.db_gate())

    def test_missing_or_foreign_host_evidence_never_dispatches_sql(self):
        self.gate.unlink()
        with self.assertRaises(Refused): self.hold(delivery_held=True)
        self.assertFalse(self.calls)
        self.gate.write_text(json.dumps({**IDLE, "held": True, "operation": "f" * 64}))
        with self.assertRaises(Refused): self.hold(delivery_held=True)
        self.assertFalse(self.calls)

    def test_foreign_db_owner_never_gets_cleared(self):
        other = {**IDLE, "held": True, "operation": "f" * 64}
        self.psql("UPDATE settings SET value='" + json.dumps(other) + "'::jsonb WHERE key='storage_emergency_maintenance'")
        with self.assertRaises(subprocess.CalledProcessError): self.hold(delivery_held=True)
        self.assertEqual(self.db_gate(), other)
        self.assertTrue(self.read()["delivery_held"])

    def test_string_schema_is_not_silently_normalized(self):
        malformed = {**IDLE, "schema": "1"}
        self.psql("UPDATE settings SET value='" + json.dumps(malformed) + "'::jsonb WHERE key='storage_emergency_maintenance'")
        with self.assertRaises(subprocess.CalledProcessError): self.hold(delivery_held=True)
        self.assertEqual(self.db_gate(), malformed)
        self.assertTrue(self.read()["delivery_held"])

    def test_release_interruption_after_idle_publication_is_recoverable(self):
        with self.assertRaises(Refused): self.manager.storage_maintenance(self.stage, held=False)
        self.assertFalse(self.calls)
        self.hold(delivery_held=True)
        with patch.object(self.manager, "receipt", side_effect=OSError("synthetic lost final receipt")):
            with self.assertRaises(OSError): self.manager.storage_maintenance(self.stage, held=False)
        self.assertEqual(self.read(), IDLE)
        self.assertEqual(self.db_gate(), IDLE)
        self.manager.storage_maintenance(self.stage, held=False)
        self.assertEqual(self.read(), IDLE)
        self.assertEqual(self.db_gate(), IDLE)

    def test_bridge_initialization_survives_service_private_umask(self):
        self.manager.config["schema_revision"] = "1"
        self.gate.unlink()
        self.gate.parent.rmdir()
        prior = os.umask(0o077)
        try:
            self.hold(delivery_held=True)
        finally:
            os.umask(prior)
        self.assertEqual(self.gate.parent.stat().st_mode & 0o7777, 0o755)
        self.assertEqual(self.gate.stat().st_mode & 0o7777, 0o644)
        self.manager.storage_maintenance(self.stage, held=False)
        self.assertEqual(self.read(), IDLE)
        self.assertEqual(self.db_gate(), IDLE)
