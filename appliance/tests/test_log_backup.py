"""Native-backup contracts with fake engine responses and real durable files.

No database, container, FIPS gate, filesystem mount or guest action executes.
"""
import copy
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import hashlib
import json
import io
import tarfile
import xml.etree.ElementTree as ET
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import Mock, patch

from nebulalog_manager import log_backup as native
from nebulalog_manager.common import Refused, atomic_json

INSTALLATION = "81f0f122-7654-486c-80b9-aa4f90453044"
TABLE = "777e3820-f194-49f8-b20c-bc3487eeebba"
PIN = "registry.example/component@sha256:" + "a" * 64
MOUNT_LABEL = "system_u:object_r:container_file_t:s0:c123,c456"


class NativeBackupTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        for path in (self.root / "manager", self.root / "clickhouse"):
            path.mkdir(mode=0o700)
        self.stage = self.root / "manager/log-backups" / str(uuid.uuid4())
        self.runtime = {"images": {key: PIN for key in ("NEBULALOG_IMAGE", "POSTGRESQL_IMAGE", "CLICKHOUSE_IMAGE", "KEYCLOAK_FIPS_IMAGE")}, "schema_revision": "3"}
        self.link = {"source_installation_id": INSTALLATION, "configuration_backup": {"sha256": "c" * 64, "bytes": 1234}, "runtime": self.runtime}
        self.instance = {"pin": PIN, "container_id": "d" * 64, "pid": 2500, "started_at": "2026-10-19T20:00:00Z",
                         "restart_count": 0, "host_boot_id": str(uuid.uuid4()), "image_id": "e" * 64, "mount_label": MOUNT_LABEL}
        self.table = {"uuid": TABLE, "engine": "MergeTree", "partition_key": "(log_type, toDate(ingested_at))",
                      "create_table_query": "CREATE TABLE nebulalog.events (id UUID) ENGINE = MergeTree PARTITION BY (log_type, toDate(ingested_at))",
                      "version": native.VERSION, "bytes_on_disk": 100, "pending_mutations": 0}
        self.calls, self.holds = [], []
        self.status, self.error, self.ack_error, self.pending, self.revision = "CREATING_BACKUP", "", False, 0, 7
        self.row_change = None
        self.job_exists, self.matching_processes = False, 0
        self.gate = {"schema": 1, "held": False, "delivery_held": False, "operation": None}
        atomic_json(self.root / "manager/storage-maintenance/gate.json", self.gate)
        self.life = SimpleNamespace(data=self.root, cmd=self.command, ch=self.ch, _schema_psql=self.psql,
                                    storage_maintenance=self.hold, storage_gate_aware_ingest=lambda: True)
        self.adapter = native.LogBackupAdapter(self.life)
        self.adapter._guard = Mock(return_value=INSTALLATION)
        self.adapter._locks = lambda: nullcontext()
        self.adapter._instance = lambda pin: copy.deepcopy(self.instance)
        self.adapter.backup._runtime_metadata = lambda: copy.deepcopy(self.runtime)
        self.adapter._capacity = Mock(return_value={"free_bytes": 100 * 1024**3, "hard_native_quota": False})
        for item in (patch.object(native, "_directory", side_effect=self.directory),
                     patch.object(native, "trusted_file", side_effect=self.trusted),
                     patch.object(native, "_encrypted_staging"), patch.object(native, "_verify_or_inherit_label"),
                     patch.object(native, "ROOT_UID", os.getuid()), patch.object(native, "SERVICE_UID", os.getuid()), patch.object(native, "SERVICE_GID", os.getgid())):
            item.start(); self.addCleanup(item.stop)

    def directory(self, path, *, private=False, create=False):
        if create: path.mkdir(parents=True, mode=0o700, exist_ok=True)
        if path.is_symlink() or not path.is_dir() or private and path.stat().st_mode & 0o077:
            raise Refused("Unsafe test directory")

    def test_native_guard_accepts_only_fixed_same_source_profiles_three_and_four(self):
        self.adapter.backup._guard = Mock(return_value=INSTALLATION)
        self.adapter.backup._pending = Mock()
        for revision in ("3", "4"):
            self.life.application_schema_current = lambda: {"revision": revision}
            self.assertEqual(native.LogBackupAdapter._guard(self.adapter), INSTALLATION)
        for revision in ("1", "2", "5", 4, [], None):
            self.life.application_schema_current = lambda: {"revision": revision}
            with self.subTest(revision=revision), self.assertRaises(Refused):
                native.LogBackupAdapter._guard(self.adapter)
        self.assertFalse(self.calls)

    def test_native_guard_refuses_different_clickhouse_sql_for_supported_profile(self):
        self.adapter.backup._guard = Mock(return_value=INSTALLATION)
        self.adapter.backup._pending = Mock()
        self.life.application_schema_current = lambda: {"revision": "4"}
        with patch.object(native, "SCHEMA3_SQL", native.SCHEMA3_SQL + "\n"), self.assertRaises(Refused):
            native.LogBackupAdapter._guard(self.adapter)
        self.assertFalse(self.calls)

    def trusted(self, path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise Refused("Unsafe test file")
        return path

    def read(self):
        return json.loads((self.stage / "native.json").read_text())

    def plan(self, **changes):
        args = dict(mode="backup", maximum_archive_bytes=1024**3, deadline_seconds=600,
                    linked_metadata=self.link, growth_reserve_bytes=1024**3, minimum_free_bytes=10 * 1024**3)
        args.update(changes)
        return self.adapter.plan(self.stage, **args)

    def hold(self, stage, *, held, delivery_held=False):
        self.holds.append((held, delivery_held))
        if self.pending:
            raise Refused("Pending removal")
        self.gate = {"schema": 1, "held": held, "delivery_held": delivery_held,
                     "operation": hashlib.sha256(str(stage).encode()).hexdigest() if held else None}
        atomic_json(self.root / "manager/storage-maintenance/gate.json", self.gate)
        atomic_json(stage / "adapter-storage-maintenance.json", {"state": "complete", "ok": True,
            "action": "storage-maintenance", "operation": hashlib.sha256(str(stage).encode()).hexdigest(), "gate": self.gate})

    def psql(self, query):
        if "'pending'" in query:
            return json.dumps({"gate": self.gate, "engine": {"schema": 1, "mode": "partition", "table_uuid": TABLE}, "pending": self.pending})
        return json.dumps({"revision": self.revision})

    def command(self, argv, *, timeout):
        self.assertEqual(timeout, 30)
        self.assertIn("--max_execution_time=600", argv)
        self.assertIn("--config-file=/etc/nebulalog/clickhouse-client.xml", argv)
        self.assertEqual(argv[:5], ["podman", "exec", "--user", "101:101", "nebulalog-clickhouse"])
        return self.life.ch(argv[argv.index("--query") + 1], tuple(argv[argv.index("--query") + 2:]))

    def ch(self, query, params=()):
        self.calls.append((query, params))
        if query.startswith("BACKUP"):
            value = self.read()
            self.assertEqual(value["state"], "dispatching")  # Already durably observable.
            self.assertIn("--query_id=" + value["query_id"], params)
            self.assertNotIn("compression_method", query)
            self.job_exists = True
            self.timestamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
            if self.ack_error:
                raise Refused("Synthetic credential must never be copied to journal")
            return json.dumps({"id": value["backup_id"], "status": "CREATING_BACKUP"})
        if "FROM system.tables" in query:
            self.assertIn("output_format_json_quote_64bit_integers=0", query)
            return json.dumps(self.table)
        if "FROM system.backups" in query:
            if not self.job_exists: return ""
            value = self.read()
            timestamp = self.timestamp
            row = dict.fromkeys(native.STATUS_COLUMNS[8:], 0)
            row.update(id=value["backup_id"], query_id=value["query_id"], name="File('" + str(native.CONTAINER_ROOT / self.stage.name / "events.tar") + "')",
                       base_backup_name="", status=self.status, error=self.error, start_time=timestamp, end_time=timestamp,
                       compressed_size=4, num_files=1)
            if self.row_change:
                return self.row_change(row)
            return json.dumps(row)
        if "FROM system.processes" in query:
            self.assertIn("initial_query_id={query:String}", query)
            return json.dumps({"matching": self.matching_processes})
        raise AssertionError(query)

    def dispatch(self):
        self.plan()
        self.adapter.start_backup(self.stage)

    def complete(self):
        self.dispatch()
        archive = self.root / "clickhouse/backup-staging" / self.stage.name / "events.tar"
        archive.write_bytes(b"DATA"); archive.chmod(0o600)
        self.status = "BACKUP_CREATED"
        return archive

    def test_terminal_archive_matches_transport_and_requires_explicit_release(self):
        self.complete()
        result = self.adapter.observe(self.stage)
        native.validate_metadata(result["metadata"])
        self.assertEqual(result["archive"]["sha256"], hashlib.sha256(b"DATA").hexdigest())
        self.assertEqual(self.read()["state"], "succeeded")
        self.assertEqual(self.holds, [(True, False)])
        self.assertEqual(result, self.adapter.observe(self.stage))
        self.adapter.release(self.stage)
        self.assertEqual(self.holds[-1], (False, False))

    def test_async_ack_does_not_publish_terminal_or_replay(self):
        self.dispatch()
        self.assertEqual(self.read()["state"], "running")
        self.assertNotIn("result", self.read())
        self.assertFalse(self.adapter.observe(self.stage)["archive_ready"])
        with self.assertRaisesRegex(Refused, "single-dispatch"):
            self.adapter.start_backup(self.stage)
        with self.assertRaises(Refused): self.adapter.release(self.stage)
        self.assertEqual(sum(q.startswith("BACKUP") for q, _ in self.calls), 1)

    def test_lost_ack_can_only_observe_exact_original_job(self):
        self.plan(); self.ack_error = True
        with self.assertRaises(Refused): self.adapter.start_backup(self.stage)
        self.assertEqual(self.read()["state"], "recovery_required")
        self.assertNotIn("Synthetic credential", (self.stage / "native.json").read_text())
        with self.assertRaises(Refused): self.adapter.start_backup(self.stage)
        self.assertFalse(self.adapter.observe(self.stage)["archive_ready"])
        self.assertEqual(sum(q.startswith("BACKUP") for q, _ in self.calls), 1)

    def test_missing_status_row_never_means_safe_retry(self):
        self.dispatch(); self.row_change = lambda row: ""
        with self.assertRaises(Refused): self.adapter.observe(self.stage)
        self.assertEqual(self.read()["state"], "recovery_required")
        with self.assertRaises(Refused): self.adapter.start_backup(self.stage)

    def test_foreign_status_query_id_name_and_duplicate_rows_refuse(self):
        self.dispatch()
        for field, replacement in (("query_id", str(uuid.uuid4())), ("name", "File('/tmp/other.tar')"),
                                   ("base_backup_name", "File('/tmp/base.tar')"), ("status", "RESTORED")):
            self.row_change = lambda row, f=field, v=replacement: json.dumps({**row, f: v})
            with self.subTest(field=field), self.assertRaises(Refused): self.adapter.observe(self.stage)
        self.row_change = lambda row: json.dumps(row) + "\n" + json.dumps(row)
        with self.assertRaises(Refused): self.adapter.observe(self.stage)

    def test_server_restart_even_same_container_prevents_observation(self):
        self.dispatch()
        count = len(self.calls)
        self.instance["restart_count"] += 1
        with self.assertRaises(Refused): self.adapter.observe(self.stage)
        self.assertEqual(len(self.calls), count)
        self.assertEqual(self.read()["state"], "recovery_required")

    def test_instance_change_after_query_refuses_ack(self):
        self.plan()
        original = self.life.ch
        def changed(query, params=()):
            raw = original(query, params)
            if query.startswith("BACKUP"): self.instance["pid"] += 1
            return raw
        self.life.ch = changed
        with self.assertRaises(Refused): self.adapter.start_backup(self.stage)
        self.assertEqual(self.read()["state"], "recovery_required")

    def test_native_error_is_retained_sanitized_and_does_not_release(self):
        self.dispatch(); self.status = "BACKUP_FAILED"; self.error = "synthetic-secret"
        self.assertEqual(self.adapter.observe(self.stage)["state"], "failed")
        self.assertTrue(self.read()["last_status"]["error_present"])
        self.assertNotIn("synthetic-secret", (self.stage / "native.json").read_text())
        self.assertEqual(self.holds, [(True, False)])

    def test_failed_and_cancelled_recovery_preserves_original_and_releases_only_after_intent(self):
        self.dispatch(); self.status = "BACKUP_FAILED"; self.error = "synthetic-secret"
        self.adapter.observe(self.stage)
        before = (self.stage / "native.json").read_bytes()
        original = self.life.storage_maintenance
        def guarded(stage, **kwargs):
            if kwargs["held"] is False:
                self.assertEqual(self.read()["recovery"]["state"], "release_intent")
                self.assertEqual((stage / "recovery-before.json").read_bytes(), before)
            return original(stage, **kwargs)
        self.life.storage_maintenance = guarded
        result = self.adapter.recover_backup(self.stage)
        self.assertEqual(result["outcome"], "backup_failed")
        self.assertFalse(result["backup_complete"])
        self.assertTrue(result["settled"] and result["holds_released"])
        self.assertEqual(result["before_journal_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(result["journal_sha256"], hashlib.sha256((self.stage / "native.json").read_bytes()).hexdigest())
        self.assertNotIn("synthetic-secret", (self.stage / "native.json").read_text())
        self.assertEqual(self.holds, [(True, False), (False, False)])
        final = (self.stage / "native.json").read_bytes()
        self.assertEqual(self.adapter.recover_backup(self.stage), result)
        self.assertEqual((self.stage / "native.json").read_bytes(), final)
        self.assertEqual(len(self.holds), 2)
        with self.assertRaises(Refused): self.adapter.start_backup(self.stage)
        self.assertEqual(sum(q.startswith("BACKUP") for q, _ in self.calls), 1)
        self.assertFalse(any("KILL" in q for q, _ in self.calls))

    def test_cancelled_job_can_settle_after_expired_observation_budget(self):
        self.dispatch(); self.status = "BACKUP_CANCELLED"
        value = self.read(); value["deadline_at"] = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        atomic_json(self.stage / "native.json", value)
        result = self.adapter.recover_backup(self.stage)
        self.assertEqual(result["outcome"], "backup_cancelled")
        self.assertFalse(self.gate["held"])

    def test_recovery_unknown_active_or_missing_job_never_releases_or_dispatches(self):
        self.dispatch()
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.status = "BACKUP_FAILED"; self.matching_processes = 1
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.matching_processes = 0; self.row_change = lambda row: ""
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.row_change = lambda row: json.dumps({**row, "end_time": "1970-01-01 00:00:00"})
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.row_change = None; self.instance["pid"] += 1
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.assertEqual(self.holds, [(True, False)])
        self.assertFalse((self.stage / "recovery-before.json").exists())

    def test_recovery_foreign_hold_policy_table_and_pending_removal_refuse(self):
        self.dispatch(); self.status = "BACKUP_FAILED"
        self.revision += 1
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.revision -= 1; self.table["uuid"] = str(uuid.uuid4())
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.table["uuid"] = TABLE; self.pending = 1
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.pending = 0; self.gate["operation"] = "f"*64
        atomic_json(self.root / "manager/storage-maintenance/gate.json", self.gate)
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.assertEqual(self.holds, [(True, False)])

    def test_no_dispatch_planned_and_partial_hold_recovery_requires_retained_evidence(self):
        self.plan()
        result = self.adapter.recover_backup(self.stage)
        self.assertEqual(result["outcome"], "not_dispatched")
        self.assertFalse(self.holds)
        self.assertFalse(any(q.startswith("BACKUP") for q, _ in self.calls))

    def test_interrupted_hold_with_host_fence_only_can_release_without_dispatch(self):
        self.plan()
        value = self.read(); value["state"] = "holding"
        atomic_json(self.stage / "native.json", value)
        owner = hashlib.sha256(str(self.stage).encode()).hexdigest()
        atomic_json(self.root / "manager/storage-maintenance/gate.json",
            {"schema": 1, "held": True, "delivery_held": True, "operation": owner})
        atomic_json(self.stage / "adapter-storage-maintenance.json", {"state": "intent", "operation": owner,
            "desired": {"schema": 1, "held": True, "delivery_held": False, "operation": owner}})
        self.assertFalse(self.gate["held"])  # The database hold was never acknowledged.
        result = self.adapter.recover_backup(self.stage)
        self.assertEqual(result["outcome"], "not_dispatched")
        self.assertEqual(self.holds, [(False, False)])
        self.assertFalse(any(q.startswith("BACKUP") for q, _ in self.calls))

    def test_recovery_post_release_observation_failure_rearms_owned_hold(self):
        self.dispatch(); self.status = "BACKUP_FAILED"
        original = self.life.storage_maintenance
        def changed(stage, **kwargs):
            original(stage, **kwargs)
            if kwargs["held"] is False: self.instance["pid"] += 1
        self.life.storage_maintenance = changed
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.assertTrue(self.gate["held"])
        self.assertEqual(self.read()["state"], "recovering")
        self.assertEqual(self.holds, [(True, False), (False, False), (True, False)])

    def test_backup_dispatch_runner_inherits_lock_bound_command_scope(self):
        previous = self.adapter.cmd
        inherited = Mock()
        def enter(stack):
            original = self.adapter.backup.cmd
            self.adapter.backup.cmd = inherited
            stack.callback(setattr, self.adapter.backup, "cmd", original)
        self.adapter.backup._locks = enter
        with native.LogBackupAdapter._locks(self.adapter):
            self.assertIs(self.adapter.cmd, inherited)
        self.assertIs(self.adapter.cmd, previous)

    def test_pre_dispatch_failed_policy_check_can_release_owned_hold(self):
        self.plan()
        with self.assertRaises(Refused): self.adapter.start_backup(self.stage, expected_policy_revision=8)
        result = self.adapter.recover_backup(self.stage)
        self.assertEqual(result["outcome"], "not_dispatched")
        self.assertFalse(self.gate["held"])
        self.assertFalse(any(q.startswith("BACKUP") for q, _ in self.calls))

    def test_preflight_failure_is_durable_but_missing_and_interrupted_plan_are_not_proof(self):
        self.adapter._capacity.side_effect = Refused("capacity")
        with self.assertRaises(Refused): self.plan()
        self.assertEqual(self.read()["state"], "preflight_failed")
        self.assertTrue(self.read()["preflight_no_effects"])
        self.assertEqual(self.adapter.recover_backup(self.stage)["outcome"], "not_dispatched")
        self.assertFalse(self.holds)
        value = self.read(); value.pop("recovery"); value["state"] = "planning"
        atomic_json(self.stage / "native.json", value)
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        (self.stage / "native.json").unlink()
        with self.assertRaises((Refused, FileNotFoundError)): self.adapter.recover_backup(self.stage)

    def test_preflight_missing_first_instance_can_bind_only_new_readonly_context(self):
        original = self.adapter._instance
        self.adapter._instance = Mock(side_effect=Refused("instance unavailable"))
        with self.assertRaises(Refused): self.plan()
        self.assertNotIn("instance", self.read())
        self.adapter._instance = original
        result = self.adapter.recover_backup(self.stage)
        self.assertEqual(result["proof"]["instance"], self.instance)
        self.assertNotIn("instance", json.loads((self.stage / "recovery-before.json").read_text()))
        self.assertFalse(self.holds)

    def test_pre_dispatch_record_never_overrules_an_existing_job(self):
        self.plan(); self.job_exists = True; self.timestamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.assertFalse(self.holds)

    def test_recovery_release_failure_rearms_and_retry_preserves_original(self):
        self.dispatch(); self.status = "BACKUP_FAILED"
        original = self.life.storage_maintenance
        def interrupted(stage, **kwargs):
            original(stage, **kwargs)
            if kwargs["held"] is False: raise Refused("lost release reply")
        self.life.storage_maintenance = interrupted
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.assertTrue(self.gate["held"])
        self.assertEqual(self.read()["state"], "recovering")
        retained = (self.stage / "recovery-before.json").read_bytes()
        self.life.storage_maintenance = original
        self.assertTrue(self.adapter.recover_backup(self.stage)["holds_released"])
        self.assertEqual((self.stage / "recovery-before.json").read_bytes(), retained)

    def test_committed_release_crash_can_only_finish_with_owned_release_receipt(self):
        self.dispatch(); self.status = "BACKUP_FAILED"
        original = self.adapter._save
        def interrupted(stage, value):
            if value["state"] == "recovered": raise Refused("crash before final journal")
            return original(stage, value)
        self.adapter._save = interrupted
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        self.assertFalse(self.gate["held"])
        self.assertEqual(self.read()["state"], "recovering")
        receipt = self.stage / "adapter-storage-maintenance.json"
        saved = receipt.read_bytes(); receipt.unlink()
        with self.assertRaises(FileNotFoundError): self.adapter.recover_backup(self.stage)
        receipt.write_bytes(saved); receipt.chmod(0o600)
        self.adapter._save = original
        self.assertTrue(self.adapter.recover_backup(self.stage)["holds_released"])
        self.assertEqual(self.holds, [(True, False), (False, False)])

    def test_explicit_abandoned_export_proves_archive_and_inventory_without_claiming_success(self):
        archive = self.complete(); native_tar(archive)
        size = archive.stat().st_size
        self.row_change = lambda row: json.dumps({**row, "compressed_size": size})
        self.adapter.observe(self.stage)
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)
        result = self.adapter.recover_backup(self.stage, abandon_export=True)
        self.assertEqual(result["outcome"], "unsuccessful_export")
        self.assertTrue(result["proof"]["inventory"]["inventory_complete"])
        self.assertFalse(result["backup_complete"])
        self.assertTrue(archive.exists())
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage)

    def test_running_retirement_can_later_settle_success_after_original_deadline(self):
        self.dispatch()
        with self.assertRaises(Refused): self.adapter.recover_backup(self.stage, abandon_export=True)
        self.assertEqual(self.holds, [(True, False)])
        value = self.read(); value["deadline_at"] = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        atomic_json(self.stage / "native.json", value)
        self.status = "BACKUP_CREATED"
        archive = native_tar(self.root / "clickhouse/backup-staging" / self.stage.name / "events.tar")
        self.row_change = lambda row: json.dumps({**row, "compressed_size": archive.stat().st_size})
        before = (self.stage / "native.json").read_bytes()
        result = self.adapter.recover_backup(self.stage, abandon_export=True)
        self.assertEqual(result["outcome"], "unsuccessful_export")
        native.validate_metadata(result["proof"]["metadata"])
        self.assertTrue(result["proof"]["inventory"]["inventory_complete"])
        self.assertEqual((self.stage / "recovery-before.json").read_bytes(), before)
        self.assertEqual(json.loads(before)["state"], "running")
        self.assertEqual(sum(q.startswith("BACKUP") for q, _ in self.calls), 1)

    def test_success_after_lost_dispatch_ack_is_verified_without_replay(self):
        self.plan(); self.ack_error = True
        with self.assertRaises(Refused): self.adapter.start_backup(self.stage)
        self.status = "BACKUP_CREATED"
        archive = native_tar(self.root / "clickhouse/backup-staging" / self.stage.name / "events.tar")
        self.row_change = lambda row: json.dumps({**row, "compressed_size": archive.stat().st_size})
        result = self.adapter.recover_backup(self.stage, abandon_export=True)
        self.assertEqual(result["outcome"], "unsuccessful_export")
        self.assertEqual(sum(q.startswith("BACKUP") for q, _ in self.calls), 1)
        self.assertEqual(json.loads((self.stage / "recovery-before.json").read_text())["state"], "recovery_required")

    def test_prior_normal_release_needs_exact_owned_receipt_and_never_releases_again(self):
        archive = self.complete(); native_tar(archive)
        self.row_change = lambda row: json.dumps({**row, "compressed_size": archive.stat().st_size})
        self.adapter.observe(self.stage); self.adapter.release(self.stage)
        receipt = self.stage / "adapter-storage-maintenance.json"
        before = receipt.read_bytes(); receipt.unlink()
        with self.assertRaises(FileNotFoundError): self.adapter.recover_backup(self.stage, abandon_export=True)
        receipt.write_bytes(before); receipt.chmod(0o600)
        result = self.adapter.recover_backup(self.stage, abandon_export=True)
        self.assertEqual(result["outcome"], "unsuccessful_export")
        self.assertFalse(result["backup_complete"])
        self.assertEqual(self.holds, [(True, False), (False, False)])
        self.assertEqual(json.loads((self.stage / "recovery-before.json").read_text())["state"], "released")

    def test_normal_release_ack_loss_before_child_commit_uses_owned_receipt(self):
        archive = self.complete(); native_tar(archive)
        self.row_change = lambda row: json.dumps({**row, "compressed_size": archive.stat().st_size})
        self.adapter.observe(self.stage)
        save = self.adapter._save
        def fail_released(stage, value):
            if value["state"] == "released": raise OSError("child release journal was not saved")
            return save(stage, value)
        with patch.object(self.adapter, "_save", side_effect=fail_released), self.assertRaises(OSError):
            self.adapter.release(self.stage)
        self.assertEqual(self.read()["state"], "succeeded")
        self.assertFalse(self.gate["held"])
        result = self.adapter.recover_backup(self.stage, abandon_export=True)
        self.assertEqual(result["outcome"], "unsuccessful_export")
        self.assertEqual(self.holds, [(True, False), (False, False)])

    def test_late_success_archive_change_after_recovery_intent_is_refused(self):
        self.dispatch(); self.status = "BACKUP_CREATED"
        archive = native_tar(self.root / "clickhouse/backup-staging" / self.stage.name / "events.tar")
        self.row_change = lambda row: json.dumps({**row, "compressed_size": archive.stat().st_size})
        original = self.life.storage_maintenance
        def fail_release(stage, **kwargs):
            if kwargs["held"] is False: raise OSError("release was not dispatched")
            return original(stage, **kwargs)
        with patch.object(self.life, "storage_maintenance", side_effect=fail_release), self.assertRaises(OSError):
            self.adapter.recover_backup(self.stage, abandon_export=True)
        self.assertEqual(self.read()["state"], "recovering")
        self.assertTrue(self.gate["held"])
        # Keep the tar and logical inventory valid while altering payload bytes.
        # A retry must use its earlier durable SHA, not adopt the replacement.
        raw = archive.read_bytes(); changed = raw.replace(b"CREATE TABLE nebulalog.events ...", b"CREATE TABLE nebulalog.events xxx")
        self.assertNotEqual(raw, changed); self.assertEqual(len(raw), len(changed))
        archive.write_bytes(changed)
        with self.assertRaisesRegex(Refused, "durable recovery proof"):
            self.adapter.recover_backup(self.stage, abandon_export=True)
        self.assertTrue(self.gate["held"])
        self.assertEqual(sum(q.startswith("BACKUP") for q, _ in self.calls), 1)

    def real_parent_fixture(self):
        # Reuse only the existing fake configuration/crypto fixture; both the
        # parent retirement and native recovery implementations execute here.
        import test_recovery_set as parent_tests
        parent = parent_tests.RecoverySetTests("runTest")
        parent.setUp(); self.addCleanup(parent.doCleanups)
        parent.root, parent.data, parent.manager = self.root, self.root, self.root / "manager"
        parent.output, parent.certificate = self.root / "export", self.root / "recipient.pem"
        parent.certificate.write_bytes(b"synthetic public certificate"); parent.certificate.chmod(0o600)
        parent.config.data, parent.config.manager = self.root, parent.manager
        parent.config.configuration = self.root / "configuration"
        parent.config._guard.return_value = INSTALLATION
        parent.policy = self.adapter._policy()
        parent.budgets["deadline_seconds"] = 600
        self.runtime["images"] = {key: "registry.example/image@sha256:" + "a"*64 for key in self.runtime["images"]}
        self.instance["pin"] = self.runtime["images"]["CLICKHOUSE_IMAGE"]
        parent.subject = parent_tests.module.FullBackupManager(parent.config, self.adapter, parent.transport)
        real_plan = self.adapter.plan
        def planned(stage, **kwargs):
            self.stage = stage
            return real_plan(stage, **kwargs)
        for item in (patch.object(parent_tests, "IDENTITY", INSTALLATION), patch.object(self.adapter, "plan", side_effect=planned)):
            item.start(); self.addCleanup(item.stop)
        return parent

    def test_real_parent_retirement_commit_retry_keeps_real_native_receipt_identical(self):
        parent = self.real_parent_fixture()
        identifier = parent.create()["id"]
        self.status = "BACKUP_FAILED"
        original = parent.subject._save
        def fail_terminal(tx):
            if tx["state"] == "retired_without_backup": raise OSError("parent final commit lost")
            return original(tx)
        with patch.object(parent.subject, "_save", side_effect=fail_terminal), self.assertRaises(OSError):
            parent.subject.retire(identifier)
        receipt = Path(parent.current()["stage"]) / "retirement.json"
        before = {path: path.read_bytes() for path in (receipt, self.stage / "native.json", self.stage / "recovery-before.json")}
        result = parent.subject.retire(identifier)
        self.assertTrue(result["retired"])
        self.assertFalse(result["complete"])
        for path, content in before.items(): self.assertEqual(path.read_bytes(), content)
        self.assertEqual(sum(q.startswith("BACKUP") for q, _ in self.calls), 1)
        self.assertEqual(self.holds, [(True, False), (False, False)])
        parent.config.create_for_log_set.assert_called_once()

    def test_real_parent_running_retirement_resumes_after_late_native_success(self):
        parent = self.real_parent_fixture()
        identifier = parent.create()["id"]
        with self.assertRaises(Refused): parent.subject.retire(identifier)
        self.assertEqual(parent.current()["state"], "retiring")
        value = self.read(); value["deadline_at"] = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        atomic_json(self.stage / "native.json", value)
        self.status = "BACKUP_CREATED"
        archive = native_tar(self.root / "clickhouse/backup-staging" / self.stage.name / "events.tar")
        self.row_change = lambda row: json.dumps({**row, "compressed_size": archive.stat().st_size})
        result = parent.subject.retire(identifier)
        self.assertTrue(result["retired"])
        self.assertFalse(result["complete"])
        self.assertEqual(sum(q.startswith("BACKUP") for q, _ in self.calls), 1)
        self.assertEqual(self.holds, [(True, False), (False, False)])
        self.assertTrue(archive.exists())

    def test_expired_running_operation_is_not_cancelled_or_retried(self):
        self.dispatch()
        value = self.read(); value["deadline_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        atomic_json(self.stage / "native.json", value)
        with self.assertRaises(Refused): self.adapter.observe(self.stage)
        self.assertEqual(self.read()["state"], "recovery_required")
        self.assertFalse(any("KILL" in q or "RESTORE" in q for q, _ in self.calls))

    def test_pending_removal_prevents_native_dispatch(self):
        self.plan(); self.pending = 1
        with self.assertRaisesRegex(Refused, "Pending removal"): self.adapter.start_backup(self.stage)
        self.assertFalse(any(q.startswith("BACKUP") for q, _ in self.calls))
        self.assertEqual(self.read()["state"], "holding")

    def test_pending_deletion_or_lost_hold_cannot_publish_archive(self):
        self.complete(); self.pending = 1
        with self.assertRaises(Refused): self.adapter.observe(self.stage)
        self.assertNotIn("result", self.read())

    def test_changed_table_policy_or_mutation_refuses(self):
        self.complete()
        for key, value in (("uuid", str(uuid.uuid4())), ("pending_mutations", 1), ("create_table_query", self.table["create_table_query"] + " TTL received_at")):
            before = self.table[key]; self.table[key] = value
            with self.subTest(key=key), self.assertRaises(Refused): self.adapter.observe(self.stage)
            self.table[key] = before
        self.revision += 1
        with self.assertRaises(Refused): self.adapter.observe(self.stage)

    def test_archive_symlink_hardlink_side_file_and_size_mismatch_refuse(self):
        archive = self.complete()
        other = archive.with_name("other"); other.write_bytes(b"DATA"); other.chmod(0o600)
        archive.unlink(); archive.symlink_to(other)
        with self.assertRaises(Refused): self.adapter.observe(self.stage)
        archive.unlink(); os.link(other, archive); other.unlink()
        extra = self.root / "link"; os.link(archive, extra)
        with self.assertRaises(Refused): self.adapter.observe(self.stage)
        extra.unlink()
        side = archive.with_name("events.tar.lock"); side.write_bytes(b"lock")
        with self.assertRaises(Refused): self.adapter.observe(self.stage)
        side.unlink(); archive.write_bytes(b"changed-size")
        with self.assertRaises(Refused): self.adapter.observe(self.stage)

    def test_archive_change_during_hash_refuses(self):
        archive = self.complete()
        original = os.read
        changed = False
        def mutate(fd, length):
            nonlocal changed
            data = original(fd, length)
            if not changed:
                changed = True
                with archive.open("ab") as out: out.write(b"changed")
            return data
        with patch.object(native.os, "read", side_effect=mutate), self.assertRaises(Refused):
            self.adapter.observe(self.stage)

    def test_source_runtime_and_budget_refusals_precede_dispatch(self):
        for change in ({"mode": "restore"}, {"maximum_archive_bytes": True}, {"deadline_seconds": 0}, {"growth_reserve_bytes": 0}):
            with self.subTest(change=change), self.assertRaises(Refused): self.plan(**change)
        self.link["source_installation_id"] = str(uuid.uuid4())
        with self.assertRaises(Refused): self.plan()
        self.assertFalse(self.stage.exists())
        self.assertFalse(self.calls)

    def test_existing_or_noncanonical_stage_refuses(self):
        self.plan()
        with self.assertRaises(Refused): self.plan()
        self.stage = self.root / "manager/log-backups/not-a-uuid"
        with self.assertRaises(Refused): self.plan()

    def test_actual_reserve_math_and_archive_estimate_refuse(self):
        capacity = native.LogBackupAdapter._capacity.__get__(self.adapter)
        plan = {"maximum_archive_bytes": 1024**3, "growth_reserve_bytes": 1024**3, "minimum_free_bytes": 10 * 1024**3}
        sample = SimpleNamespace(f_bavail=20 * 1024**3, f_blocks=100 * 1024**3, f_frsize=1)
        with patch.object(native.os, "statvfs", return_value=sample):
            self.assertEqual(capacity(plan, 100)["reserved_operation_bytes"], 4 * 1024**3)
            sample.f_bavail = 13 * 1024**3
            with self.assertRaises(Refused): capacity(plan, 100)
            sample.f_bavail = 90 * 1024**3
            with self.assertRaises(Refused): capacity(plan, 1024**3)
            with self.assertRaises(Refused): capacity({**plan, "minimum_free_bytes": 1}, 100)

    def test_restore_primitive_cannot_bypass_retained_coordinator(self):
        with self.assertRaisesRegex(Refused, "another target"):
            self.adapter.start_restore(self.stage, self.root / "archive", "a" * 64, self.link)
        self.assertFalse(self.calls)
        self.assertFalse(self.holds)

    def test_configuration_revision_or_policy_hash_drift_prevents_dispatch(self):
        self.plan()
        with self.assertRaises(Refused):
            self.adapter.start_backup(self.stage, expected_policy_revision=8)
        self.assertFalse(any(q.startswith("BACKUP") for q, _ in self.calls))
        self.assertTrue(self.gate["held"])

    def test_matching_revision_with_changed_policy_bytes_still_refuses(self):
        self.plan()
        with self.assertRaises(Refused):
            self.adapter.start_backup(self.stage, expected_policy_revision=self.revision, expected_raw_policy_sha256="0"*64)
        self.assertFalse(any(q.startswith("BACKUP") for q, _ in self.calls))

    def test_matching_configuration_policy_binds_exact_raw_content(self):
        self.plan()
        raw = json.dumps({"revision": self.revision})
        self.adapter.start_backup(self.stage, expected_policy_revision=self.revision,
            expected_raw_policy_sha256=hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(self.read()["policy"]["raw_policy_sha256"], hashlib.sha256(raw.encode()).hexdigest())

    def test_stored_policy_revision_must_be_explicit_integer(self):
        self.plan()
        for invalid in (None, True, 0, "1"):
            self.revision = invalid
            with self.subTest(invalid=invalid), self.assertRaises(Refused): self.adapter._policy()

    def test_absent_legacy_policy_revision_defaults_only_that_case(self):
        raw = '{"global_days":90,"per_type":{}}'
        self.life._schema_psql = lambda query: raw
        self.assertEqual(self.adapter._policy(), {"revision": 1, "normalization": "absent_defaults_to_1",
                         "raw_policy_sha256": hashlib.sha256(raw.encode()).hexdigest()})

    def test_replaced_new_directory_never_receives_path_based_chown(self):
        directory = self.root / "clickhouse/backup-staging" / str(uuid.uuid4())
        victim = self.root / "victim"; victim.mkdir(mode=0o700)
        original = native.os.mkdir
        def replaced(name, mode=0o777, *, dir_fd=None):
            original(name, mode, dir_fd=dir_fd)
            if name == "backup-staging" and dir_fd is not None:
                native.os.rmdir(name, dir_fd=dir_fd)
                native.os.symlink(str(victim), name, dir_fd=dir_fd)
        with patch.object(native.os, "mkdir", side_effect=replaced), patch.object(native.os, "chown") as path_chown, patch.object(native.os, "fchown") as fd_chown:
            with self.assertRaises(Refused):
                self.adapter._service_directory(directory, create=True, mount_label=MOUNT_LABEL)
        path_chown.assert_not_called()
        fd_chown.assert_not_called()
        self.assertEqual(victim.stat().st_uid, os.getuid())

    def test_archive_fifo_is_nonblocking_and_refused(self):
        archive = self.complete(); archive.unlink(); os.mkfifo(archive, 0o600)
        with self.assertRaises(Refused): self.adapter.observe(self.stage)

    def test_completed_archive_mutation_is_not_accepted_on_resume(self):
        archive = self.complete(); self.adapter.observe(self.stage)
        archive.write_bytes(b"EVIL")
        with self.assertRaises(Refused): self.adapter.observe(self.stage)

    def test_actual_instance_projection_checks_pin_runtime_and_boot_identity(self):
        state = {"Running": True, "Paused": False, "Restarting": False, "Dead": False,
                 "Pid": 2500, "StartedAt": "2026-10-19T20:00:00Z"}
        row = {"id": "d" * 64, "image": "e" * 64, "state": state, "restarts": 0, "mount_label": MOUNT_LABEL}
        def command(argv):
            if argv[:3] == ["podman", "container", "inspect"]:
                self.assertIn("{{json .ID}}", argv[4])
                return json.dumps(row)
            if "{{json .RepoDigests}}" in argv: return json.dumps([PIN])
            return "e" * 64
        self.adapter.cmd = command
        method = native.LogBackupAdapter._instance.__get__(self.adapter)
        with patch.object(native.Path, "read_text", return_value=self.instance["host_boot_id"]):
            self.assertEqual(method(PIN), self.instance)
            for field, replacement in (("Running", False), ("Paused", True), ("Dead", True), ("Pid", 0)):
                original = state[field]; state[field] = replacement
                with self.subTest(field=field), self.assertRaises(Refused): method(PIN)
                state[field] = original
            row["image"] = "f" * 64
            with self.assertRaises(Refused): method(PIN)


def native_tar(path, *, rows=3, extra=None, missing=None, deduplicate=False):
    files = {"metadata/nebulalog/events.sql": b"CREATE TABLE nebulalog.events ...",
             "data/nebulalog/events/abc_1_1_0/count.txt": str(rows).encode() + b"\n",
             "data/nebulalog/events/abc_1_1_0/checksums.txt": b"checksums format version: 4\n",
             "data/nebulalog/events/abc_1_1_0/columns.txt": b"columns format version: 1\n"}
    if missing: files.pop(missing)
    if extra: files.update(extra)
    root = ET.Element("config")
    for key, value in (("version", "1"), ("deduplicate_files", "1"), ("timestamp", "2026-10-19 12:00:00"), ("uuid", INSTALLATION)):
        ET.SubElement(root, key).text = value
    contents = ET.SubElement(root, "contents")
    for name, data in list(files.items()):
        item = ET.SubElement(contents, "file")
        ET.SubElement(item, "name").text = "/" + name
        ET.SubElement(item, "size").text = str(len(data))
        ET.SubElement(item, "checksum").text = "f" * 32
    if deduplicate:
        for suffix in ("count.txt", "columns.txt", "checksums.txt"):
            old = "data/nebulalog/events/abc_1_1_0/" + suffix
            item = ET.SubElement(contents, "file")
            for key, value in (("name", "/data/nebulalog/events/def_2_2_0/" + suffix), ("size", str(len(files[old]))),
                               ("checksum", "f" * 32), ("data_file", "/" + old)):
                ET.SubElement(item, key).text = value
    files[".backup"] = ET.tostring(root)
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name); info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    path.chmod(0o600)
    return path


class SELinuxLabelTests(unittest.TestCase):
    def test_open_parent_label_is_copied_only_to_new_fd_and_read_back(self):
        raw = MOUNT_LABEL.encode() + b"\0"
        with patch.object(native.os, "getxattr", create=True, side_effect=[raw, raw]) as get, patch.object(native.os, "setxattr", create=True) as put:
            native._verify_or_inherit_label(21, MOUNT_LABEL, parent_fd=20)
        self.assertEqual(get.call_args_list[0].args, (20, "security.selinux"))
        self.assertEqual(get.call_args_list[1].args, (21, "security.selinux"))
        put.assert_called_once_with(21, "security.selinux", raw)

    def test_existing_label_verification_never_relabels(self):
        with patch.object(native.os, "getxattr", create=True, return_value=MOUNT_LABEL.encode()), patch.object(native.os, "setxattr", create=True) as put:
            native._verify_or_inherit_label(21, MOUNT_LABEL)
        put.assert_not_called()

    def test_missing_malformed_or_foreign_parent_cannot_be_copied(self):
        for raw in (b"", b"system_u:object_r:container_file_t:s0", b"system_u:object_r:container_file_t:s0:c123,c789", b"bad\0label"):
            with self.subTest(raw=raw), patch.object(native.os, "getxattr", create=True, return_value=raw), patch.object(native.os, "setxattr", create=True) as put:
                with self.assertRaises(Refused): native._verify_or_inherit_label(21, MOUNT_LABEL, parent_fd=20)
                put.assert_not_called()
        with patch.object(native.os, "getxattr", create=True, side_effect=OSError("no label")), self.assertRaises(Refused):
            native._verify_or_inherit_label(21, MOUNT_LABEL)

    def test_failed_set_or_different_readback_is_not_accepted(self):
        with patch.object(native.os, "getxattr", create=True, return_value=MOUNT_LABEL.encode()), patch.object(native.os, "setxattr", create=True, side_effect=OSError("denied")), self.assertRaises(Refused):
            native._verify_or_inherit_label(21, MOUNT_LABEL, parent_fd=20)
        with patch.object(native.os, "getxattr", create=True, side_effect=[MOUNT_LABEL.encode(), MOUNT_LABEL.replace("456", "789").encode()]), patch.object(native.os, "setxattr", create=True), self.assertRaises(Refused):
            native._verify_or_inherit_label(21, MOUNT_LABEL, parent_fd=20)


class NativeArchiveTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "events.tar"

    def inspect(self):
        return native.inspect_native_archive(self.path, expected_bytes=self.path.stat().st_size,
            deadline=datetime.now(timezone.utc) + timedelta(seconds=60))

    def test_complete_snapshot_inventory_including_deduplicated_counts(self):
        native_tar(self.path, deduplicate=True)
        result = self.inspect()
        self.assertEqual((result["parts"], result["rows"], result["logical_files"]), (2, 6, 7))
        self.assertTrue(result["inventory_complete"])

    def test_unrelated_table_missing_count_and_projection_refuse(self):
        for changes in ({"extra": {"data/another/events/x/y": b"x"}},
                        {"missing": "data/nebulalog/events/abc_1_1_0/count.txt"},
                        {"extra": {"data/nebulalog/events/abc_1_1_0/projection/data.bin": b"x"}}):
            with self.subTest(changes=changes):
                native_tar(self.path, **changes)
                with self.assertRaises(Refused): self.inspect()

    def test_tar_link_sparse_oversize_xml_and_timeout_refuse(self):
        for kind in (tarfile.SYMTYPE, tarfile.GNUTYPE_SPARSE):
            with tarfile.open(self.path, "w") as archive:
                info = tarfile.TarInfo(".backup"); info.type = kind; archive.addfile(info)
            with self.subTest(kind=kind), self.assertRaises(Refused): self.inspect()
        native_tar(self.path)
        with patch.object(native, "MAX_NATIVE_METADATA", 2), self.assertRaises(Refused): self.inspect()
        with self.assertRaises(Refused):
            native.inspect_native_archive(self.path, expected_bytes=self.path.stat().st_size, deadline=datetime.now(timezone.utc)-timedelta(seconds=1))

    def test_duplicate_and_incremental_native_metadata_refuse(self):
        native_tar(self.path)
        with tarfile.open(self.path, "a") as archive:
            info = tarfile.TarInfo(".backup"); info.size = 1; archive.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(Refused): self.inspect()
        native_tar(self.path)
        raw = self.path.read_bytes().replace(b"<version>1</version>", b"<version>2</version>")
        self.path.write_bytes(raw)
        with self.assertRaises(Refused): self.inspect()

    def test_fixed_ddl_is_exact_current_schema3_source(self):
        actual = Path(__file__).resolve().parents[2] / "migrations/clickhouse.sql"
        self.assertEqual(native.SCHEMA3_SQL.encode(), actual.read_bytes())
        self.assertEqual(hashlib.sha256(native.SCHEMA3_SQL.encode()).hexdigest(), native.ApplicationSchema.SCHEMAS["3"]["migrations/clickhouse.sql"])


class NativeRestoreTests(unittest.TestCase):
    def setUp(self):
        fixture = NativeBackupTests("runTest"); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        self.fixture, self.adapter, self.root = fixture, fixture.adapter, fixture.root
        self.stage = self.root / "manager/restores" / str(uuid.uuid4())
        (self.stage / "logs").mkdir(parents=True, mode=0o700)
        path = native_tar(self.stage / "logs/events.tar")
        archive = {"path": str(path), "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        self.tx = {"stage": str(self.stage), "id": self.stage.name, "logs": {"archive": archive,
            "metadata": {"link": fixture.link}, "native": {"state": "table_ready", "instance": copy.deepcopy(fixture.instance),
                "table": {"table_uuid": TABLE, "server_version": native.VERSION,
                    "table_definition_sha256": hashlib.sha256(fixture.table["create_table_query"].encode()).hexdigest()}}}}
        from nebulalog_manager.restore_runtime import FreshRestoreRuntime
        self.runtime = Mock(spec=FreshRestoreRuntime)
        self.runtime.paths = SimpleNamespace(data=self.root)
        self.runtime._log_checkpoint.side_effect = lambda tx, checkpoint: atomic_json(self.stage / "transaction.json", tx)
        self.runtime.log_restore_context.side_effect = lambda *args, **kwargs: self.assertEqual(json.loads((self.stage / "transaction.json").read_text()), self.tx)
        self.checkpoint()
        self.stats = {"rows": 0, "part_rows": 0, "bytes_on_disk": 0, "parts": 0, "detached": 0}
        self.status, self.corrupt = "RESTORING", False
        fixture.table["bytes_on_disk"] = 0
        self.calls = []
        self.adapter.lifecycle.ch = self.ch
        self.adapter.cmd = lambda argv, **kwargs: self.ch(argv[argv.index("--query") + 1], ())
        self.adapter._restore_stats = lambda value: copy.deepcopy(self.stats)
        self.patch = patch.object(native, "ROOT_UID", os.getuid()); self.patch.start(); self.addCleanup(self.patch.stop)
        self.space = patch.object(native.os, "statvfs", return_value=SimpleNamespace(f_bavail=100*1024**3, f_blocks=100*1024**3, f_frsize=1))
        self.space.start(); self.addCleanup(self.space.stop)
        self.manifest = {"runtime": fixture.runtime}

    def checkpoint(self):
        atomic_json(self.stage / "transaction.json", self.tx)

    def ch(self, query, params=()):
        self.calls.append(query)
        if query.startswith("RESTORE"):
            self.assertEqual(json.loads((self.stage / "transaction.json").read_text())["logs"]["native"]["state"], "dispatching")
            if self.corrupt: raise Refused("lost acknowledgement")
            self.assertIn("allow_non_empty_tables=false", query)
            self.assertIn("restore_broken_parts_as_detached=false", query)
            return json.dumps({"id": self.tx["logs"]["native"]["backup_id"], "status": "RESTORING"})
        if query.startswith("CHECK TABLE"):
            return '{"result":1}'
        if "FROM system.backups" in query:
            n = self.tx["logs"]["native"]
            row = dict.fromkeys(native.STATUS_COLUMNS[8:], 0)
            stamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
            row.update(id=n["backup_id"], query_id=n["query_id"], name="File('" + str(native.CONTAINER_ROOT / self.stage.name / "events.tar") + "')",
                base_backup_name="", status=self.status, error="", start_time=stamp, end_time=stamp,
                compressed_size=self.tx["logs"]["archive"]["bytes"], num_files=n["inventory"]["logical_files"], total_size=n["inventory"]["logical_bytes"])
            return json.dumps(row)
        return json.dumps(self.fixture.table)

    def plan(self):
        return self.adapter.plan_restore(self.runtime, self.stage / "source", self.manifest, self.tx,
            maximum_archive_bytes=self.tx["logs"]["archive"]["bytes"], deadline_seconds=600, minimum_free_bytes=10*1024**3)

    def start(self):
        self.plan()
        return self.adapter.start_restore(self.runtime, self.stage / "source", self.manifest, self.tx)

    def observe(self):
        return self.adapter.observe_restore(self.runtime, self.stage / "source", self.manifest, self.tx)

    def test_single_restore_intent_and_snapshot_rows_have_terminal_proof(self):
        self.start()
        self.assertEqual(self.observe()["state"], "running")
        self.stats.update(rows=3, part_rows=3, bytes_on_disk=100, parts=1)
        self.status = "RESTORED"
        result = self.observe()
        self.assertTrue(result["integrity_checked"])
        self.assertEqual(result["rows"], 3)
        self.assertFalse(result["listeners_released"])
        with self.assertRaises(Refused): self.adapter.start_restore(self.runtime, self.stage / "source", self.manifest, self.tx)
        self.assertEqual(sum(q.startswith("RESTORE") for q in self.calls), 1)

    def test_lost_ack_only_observes_original_job_never_redispatches(self):
        self.corrupt = True
        with self.assertRaises(Refused): self.start()
        self.assertEqual(self.tx["logs"]["native"]["state"], "recovery_required")
        self.assertEqual(self.observe()["state"], "running")
        with self.assertRaises(Refused): self.adapter.start_restore(self.runtime, self.stage / "source", self.manifest, self.tx)
        self.assertEqual(sum(q.startswith("RESTORE") for q in self.calls), 1)

    def test_wrong_snapshot_rows_or_checksum_cannot_complete(self):
        self.start(); self.status = "RESTORED"
        self.stats.update(rows=2, part_rows=2, bytes_on_disk=100, parts=1)
        with self.assertRaises(Refused): self.observe()
        self.assertNotIn("result", self.tx["logs"]["native"])
        self.runtime.log_restore_hold.assert_called()

    def test_restarted_server_and_modified_archive_refuse_without_dispatch(self):
        self.plan(); self.fixture.instance["pid"] += 1
        with self.assertRaises(Refused): self.adapter.start_restore(self.runtime, self.stage / "source", self.manifest, self.tx)
        self.assertFalse(any(q.startswith("RESTORE") for q in self.calls))

    def test_copy_stays_on_open_directory_when_service_replaces_ancestor(self):
        self.plan()
        directory = self.root / "clickhouse/backup-staging" / self.stage.name
        retained = directory.with_name(directory.name + "-retained")
        victim = self.root / "outside-copy"; victim.mkdir(mode=0o700)
        original = native.os.open
        replaced = False
        def opened(name, flags, mode=0o777, **kwargs):
            nonlocal replaced
            if name == "events.tar" and flags & os.O_CREAT and kwargs.get("dir_fd") is not None and not replaced:
                replaced = True
                directory.rename(retained)
                directory.symlink_to(victim, target_is_directory=True)
            return original(name, flags, mode, **kwargs)
        with patch.object(native.os, "open", side_effect=opened), self.assertRaises(Refused):
            self.adapter.start_restore(self.runtime, self.stage / "source", self.manifest, self.tx)
        self.assertTrue(replaced)
        self.assertFalse((victim / "events.tar").exists())
        self.assertTrue((retained / "events.tar").exists())
        self.assertFalse(any(q.startswith("RESTORE") for q in self.calls))
        self.assertEqual(self.tx["logs"]["native"]["state"], "recovery_required")

    def test_staging_ambiguity_keeps_copy_and_never_retries(self):
        self.plan()
        path = Path(self.tx["logs"]["archive"]["path"]); path.write_bytes(b"X" * path.stat().st_size)
        with self.assertRaises(Refused): self.adapter.start_restore(self.runtime, self.stage / "source", self.manifest, self.tx)
        self.assertEqual(self.tx["logs"]["native"]["state"], "recovery_required")
        self.assertNotIn("dispatched_at", self.tx["logs"]["native"])
        self.assertTrue((self.root / "clickhouse/backup-staging" / self.stage.name / "events.tar").exists())
        with self.assertRaises(Refused): self.observe()
        self.assertFalse(any(q.startswith("RESTORE") for q in self.calls))

    def test_insufficient_capacity_and_existing_data_refuse_before_native_action(self):
        self.stats["rows"] = 1
        with self.assertRaises(Refused): self.plan()
        self.assertFalse(any(q.startswith("RESTORE") for q in self.calls))


if __name__ == "__main__":
    unittest.main()
