"""Pure snapshots and a private fixture journal; not Linux storage qualification."""
from dataclasses import replace
import json
import os
import socket
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from nebulalog_manager import host_job_storage, host_plans
from nebulalog_manager import host_plan_socket
from nebulalog_manager.common import Refused
from nebulalog_manager.host_job_storage import PrivateRecords, StorageIdentity, digest
from nebulalog_manager.host_jobs import Actor
from nebulalog_manager.host_plans import HostPlans, StorageObserver, pool_id
from nebulalog_manager.storage import Identity, Snapshot, MIB

INSTALLATION = "458a08e3-ef3b-4cd1-83e5-b402a2c1e913"
OWNER = {"subject": "a" * 64, "session_id": "b" * 64}
IDENTITY = Identity("/dev/disk/by-id/private-device", "PRIVATE-SERIAL", "/dev/disk/by-id/private-device-part1",
                    "part", "luks", "nebulalog-data", "pv", "vg", "lv")
GIB = 1024**3


class PlanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        patcher = patch.object(host_job_storage, "ROOT_UID", os.getuid())
        patcher.start(); self.addCleanup(patcher.stop)
        self.now, self.monotonic = 1800000000, 100.0
        self.identity = IDENTITY
        self.snapshot = Snapshot(IDENTITY, 12*GIB, 8*GIB+18*MIB, MIB, 8*GIB+2*MIB, 8*GIB, 8*GIB,
                                 8*GIB-64*MIB, 0, filesystem_geometry_bytes=8*GIB)
        self.records = PrivateRecords(lambda: StorageIdentity(INSTALLATION, self.root, self.root.stat().st_dev))
        self.inspector = Mock(side_effect=lambda identity, runner: self.snapshot)
        self.observer = StorageObserver(INSTALLATION, identity_reader=lambda: self.identity, inspector=self.inspector,
                                        clock=lambda: self.now, monotonic=lambda: self.monotonic)
        self.service = HostPlans(INSTALLATION, records=self.records, observer=self.observer,
                                 clock=lambda: self.now, monotonic=lambda: self.monotonic)
        self.service.initialize()
        for method in ("accept", "cancel", "capabilities", "_executor", "_verify"):
            setattr(self.service.jobs, method, Mock(side_effect=AssertionError("execution boundary invoked")))
        self.service.jobs.executor_probe = Mock(side_effect=AssertionError("executor probe invoked"))
        self.service.jobs.grant_verifier = Mock(side_effect=AssertionError("grant verifier invoked"))

    def call(self, action="capabilities", **fields):
        return self.service.handle({"schema": 1, "action": action, "actor": dict(OWNER), **fields})

    def create(self):
        result = self.call("plan.create", operation="storage.grow", parameters={"pool_id": pool_id(INSTALLATION)})
        self.assertEqual(result["status"], "ok", result)
        return result["data"]

    def ledger(self):
        return (self.root/"manager/jobs/ledger.json").read_bytes()

    def lookup(self, plan, **fields):
        return self.call("plan.lookup", plan_id=plan["id"], plan_digest=plan["digest"], **fields)

    def test_capabilities_current_snapshot_without_journal_mutation(self):
        before = self.ledger()
        result = self.call()
        self.assertEqual(result, {"schema": 1, "status": "ok", "data": {
            "control": "read_only", "execution_available": False, "pool_id": pool_id(INSTALLATION),
            "operations": [{"operation": "storage.grow", "planning_available": True, "execution_available": False,
                            "reason": "execution_not_qualified"}]}})
        self.assertEqual(self.ledger(), before)

    def test_create_lookup_review_binding_redaction_and_no_execution(self):
        plan = self.create()
        self.assertEqual(set(plan), {"id", "installation_id", "operation", "parameters", "resource_revision", "issued_at", "expires_at", "digest", "review", "execution_available"})
        self.assertEqual(plan["review"], {"current_bytes": 8*GIB-64*MIB, "presented_bytes": 12*GIB,
                         "unallocated_disk_bytes": 4*GIB-19*MIB, "stages": ["partition", "luks", "pv", "lv", "xfs"],
                         "requires_unlock_credential": True, "irreversible": True})
        before = self.ledger()
        self.assertEqual(self.lookup(plan)["data"], plan)
        self.assertEqual(self.ledger(), before)
        wire = json.dumps(plan)
        for forbidden in ("PRIVATE-SERIAL", "/dev/", "actor", OWNER["subject"], OWNER["session_id"]):
            self.assertNotIn(forbidden, wire)
        ledger = json.loads(before)
        self.assertEqual((ledger["jobs"], ledger["grants"], ledger["idempotency"]), ({}, {}, {}))
        self.assertEqual([v["action"] for v in ledger["audit"]], ["plan.created"])

    def test_wrong_owner_session_digest_and_missing_plan_do_not_disclose(self):
        plan = self.create(); before = self.ledger()
        count = self.inspector.call_count
        for changes in ({"actor": {**OWNER, "subject": "c"*64}}, {"actor": {**OWNER, "session_id": "c"*64}},
                        {"plan_digest": "f"*64}, {"plan_id": str(uuid.uuid4())}):
            body = {"schema": 1, "action": "plan.lookup", "actor": OWNER, "plan_id": plan["id"], "plan_digest": plan["digest"], **changes}
            self.assertEqual(self.service.handle(body)["reason"], "plan_unavailable")
        self.assertEqual(self.inspector.call_count, count)
        self.assertEqual(self.ledger(), before)

    def test_resource_and_planner_changes_invalidate_without_writes(self):
        plan = self.create(); before = self.ledger()
        self.snapshot = replace(self.snapshot, disk_bytes=16*GIB)
        self.assertEqual(self.lookup(plan)["reason"], "resource_changed")
        self.snapshot = replace(self.snapshot, disk_bytes=12*GIB)
        with patch.object(host_plans, "planner_revision", return_value="e"*64):
            self.assertEqual(self.lookup(plan)["reason"], "resource_changed")
        self.assertEqual(self.ledger(), before)

    def test_expiry_and_observation_delay_refuse(self):
        plan = self.create(); before = self.ledger()
        self.now = plan["expires_at"]
        self.assertEqual(self.lookup(plan)["reason"], "plan_expired")
        self.now = plan["issued_at"]
        def late(identity, runner):
            self.now = plan["expires_at"]
            return self.snapshot
        self.inspector.side_effect = late
        self.assertEqual(self.lookup(plan)["reason"], "plan_expired")
        self.assertEqual(self.ledger(), before)

    def test_missing_or_changed_registry_never_recreated_by_requests(self):
        registry = self.root/"manager/host-plan-pool.json"
        value = json.loads(registry.read_text()); value["pool_id"] = str(uuid.uuid4())
        registry.write_text(json.dumps(value))
        self.assertEqual(self.call()["reason"], "resource_changed")
        registry.unlink()
        self.assertEqual(self.call()["status"], "unavailable")
        self.assertFalse(registry.exists())

    def test_registry_binds_identity_and_initial_slice_rejects_multiple_pvs(self):
        self.identity = replace(IDENTITY, serial="different")
        self.assertEqual(self.call()["reason"], "resource_changed")
        self.identity = replace(IDENTITY, additional_pvs=(("second-pv", "second-luks"),))
        self.assertEqual(self.call()["reason"], "host_unavailable")

    def test_wrong_pool_and_unsupported_extra_or_unhashed_actor_are_invalid(self):
        base = {"schema": 1, "action": "capabilities", "actor": OWNER}
        cases = [base|{"schema": True}, base|{"extra": True}, base|{"action": "job.accept"},
                 base|{"actor": OWNER|{"role": "ADMINISTRATOR"}}, base|{"actor": OWNER|{"subject": "raw-subject"}},
                 base|{"actor": OWNER|{"session_id": "B"*64}}, base|{"action": []},
                 {"schema": 1, "action": "plan.create", "actor": OWNER, "operation": "storage.grow", "parameters": {"pool_id": str(uuid.uuid4())}},
                 {"schema": 1, "action": "plan.create", "actor": OWNER, "operation": "os.apply", "parameters": {"pool_id": pool_id(INSTALLATION)}}]
        before = self.ledger()
        for body in cases:
            with self.subTest(body=body):self.assertEqual(self.service.handle(body)["reason"], "invalid_request")
        self.assertEqual(self.ledger(), before)

    def test_deadline_and_untrusted_guard_or_inspector_fail_closed(self):
        before = self.ledger()
        def late(identity, runner):
            self.monotonic += 9
            return self.snapshot
        self.inspector.side_effect = late
        self.assertEqual(self.call()["reason"], "request_timeout")
        self.inspector.side_effect = RuntimeError("SECRET-RAW-PATH")
        self.assertEqual(self.call(), {"schema": 1, "status": "unavailable", "reason": "host_unavailable"})
        self.records.storage_guard = lambda: True
        self.assertEqual(self.call()["reason"], "host_unavailable")
        self.assertEqual(self.ledger(), before)

    def test_explicit_initialize_retry_does_not_change_registry_or_journal(self):
        before = self.ledger()
        registry = self.root/"manager/host-plan-pool.json"
        original = registry.read_bytes()
        self.service.initialize()
        self.assertEqual(self.ledger(), before)
        self.assertEqual(registry.read_bytes(), original)
        self.identity = replace(IDENTITY, lv_uuid="changed")
        with self.assertRaises(Refused):self.service.initialize()
        self.assertEqual(registry.read_bytes(), original)

    def test_command_budget_shared_across_inspection(self):
        seen = []
        def runner(argv, **kwargs):
            seen.append(kwargs["timeout"]); self.monotonic += 3
            return "{}"
        self.observer.runner = runner
        self.observer.begin(self.monotonic+8)
        self.observer.command(["lsblk"])
        self.observer.command(["pvs"])
        with self.assertRaisesRegex(Refused, "request_timeout"):self.observer.command(["vgs"])
        self.assertEqual(seen, [5, 5, 2])

    def test_real_socketpair_create_lookup_preserves_private_journal(self):
        def exchange(body):
            client, server = socket.socketpair()
            try:
                raw = json.dumps(body).encode()
                client.sendall(struct.pack("!I", len(raw))+raw)
                client.shutdown(socket.SHUT_WR)
                host_plan_socket.handle_connection(server, self.service, credentials=lambda _: (71, 10001, 10001))
                response = bytearray()
                while data := client.recv(65536):response.extend(data)
                size = struct.unpack("!I", response[:4])[0]
                self.assertEqual(size, len(response)-4)
                return json.loads(response[4:])
            finally:
                client.close(); server.close()
        body = {"schema": 1, "action": "plan.create", "actor": OWNER, "operation": "storage.grow", "parameters": {"pool_id": self.service.pool}}
        created = exchange(body)
        self.assertEqual(created["status"], "ok")
        before = self.ledger()
        lookup = {"schema": 1, "action": "plan.lookup", "actor": OWNER, "plan_id": created["data"]["id"], "plan_digest": created["data"]["digest"]}
        self.assertEqual(exchange(lookup), created)
        self.assertEqual(self.ledger(), before)
        self.assertEqual(exchange(lookup|{"actor": OWNER|{"session_id": "f"*64}})["reason"], "plan_unavailable")

    def test_explicit_pool_registry_cannot_be_symlink_or_multi_pv_enrolled(self):
        registry = self.root/"manager/host-plan-pool.json"
        registry.unlink(); target = self.root/"unrelated"; target.write_text("preserve")
        registry.symlink_to(target)
        with self.assertRaises(Refused):self.service.initialize()
        self.assertEqual(target.read_text(), "preserve")
        registry.unlink()
        self.identity = replace(IDENTITY, additional_pvs=(("pv2", "luks2"),))
        with self.assertRaises(Refused):self.service.initialize()
        self.assertFalse(registry.exists())

    def test_explicit_initialize_cannot_reset_missing_established_registry(self):
        self.create()
        registry = self.root/"manager/host-plan-pool.json"
        genesis = self.root/"manager/jobs/host-plan-pool-genesis.json"
        original = genesis.read_bytes(); before = self.ledger()
        registry.unlink()
        self.identity = replace(IDENTITY, serial="changed-disk")
        self.snapshot = replace(self.snapshot, identity=self.identity)
        with self.assertRaises(Refused):self.service.initialize()
        self.assertFalse(registry.exists())
        self.assertEqual(genesis.read_bytes(), original)
        genesis.unlink()
        with self.assertRaises(Refused):self.service.initialize()
        self.assertFalse(registry.exists())
        self.assertEqual(self.ledger(), before)

    def test_registry_genesis_required_on_reads_and_retry_only_before_plans(self):
        genesis = self.root/"manager/jobs/host-plan-pool-genesis.json"
        original = genesis.read_bytes(); genesis.unlink()
        self.assertEqual(self.call()["reason"], "host_unavailable")
        self.assertFalse(genesis.exists())
        self.service.initialize()  # exact enrollment interrupted before first plan
        self.assertEqual(genesis.read_bytes(), original)
        self.create(); genesis.unlink()
        with self.assertRaises(Refused):self.service.initialize()
        self.assertFalse(genesis.exists())

    def test_registry_requires_strict_integer_schema_and_valid_canonical_seal(self):
        before = self.ledger()
        for path in (self.root/"manager/host-plan-pool.json", self.root/"manager/jobs/host-plan-pool-genesis.json"):
            original = path.read_bytes()
            for change in ({"schema": True}, {"schema": 1.0}, {"digest": "f"*64}):
                with self.subTest(path=path.name, change=change):
                    value = json.loads(original) | change
                    path.write_text(json.dumps(value))
                    self.assertEqual(self.call()["reason"], "resource_changed")
                    with self.assertRaises(Refused):self.service.initialize()
                    self.assertEqual(json.loads(path.read_text()), value)
                    self.assertEqual(self.ledger(), before)
            path.write_bytes(original)

    def test_snapshot_and_both_registry_checks_share_actual_manager_lock(self):
        observed = []
        def inspector(identity, runner):
            self.assertIsNotNone(self.service.records.active)
            with self.assertRaisesRegex(Refused, "manager_busy"):
                with self.records.locked():self.fail("second lock acquired")
            # Recursive library use must fail before changing observer state.
            self.assertEqual(self.call()["reason"], "manager_busy")
            observed.append(True)
            return self.snapshot
        self.inspector.side_effect = inspector
        self.assertEqual(self.call()["status"], "ok")
        plan = self.create()
        self.assertEqual(self.lookup(plan)["data"], plan)
        self.assertEqual(len(observed), 3)
        self.assertIsNone(self.service.records.active)

    def test_registry_changed_before_inspection_refuses_create_and_lookup(self):
        plan = self.create()
        path = self.root/"manager/host-plan-pool.json"
        before = self.ledger(); original = path.read_bytes()
        count = self.inspector.call_count
        path.write_text(json.dumps(json.loads(original) | {"identity_digest": "d"*64}))
        for body in ({"action": "plan.create", "operation": "storage.grow", "parameters": {"pool_id": self.service.pool}},
                     {"action": "plan.lookup", "plan_id": plan["id"], "plan_digest": plan["digest"]}):
            result = self.service.handle({"schema": 1, "actor": OWNER, **body})
            self.assertEqual(result["status"], "unavailable")
        self.assertEqual(self.inspector.call_count, count)
        self.assertEqual(self.ledger(), before)

    def test_registry_changed_during_inspection_refuses_without_plan_write(self):
        plan = self.create()
        path = self.root/"manager/jobs/host-plan-pool-genesis.json"
        before = self.ledger(); original = path.read_bytes()
        def inspector(identity, runner):
            path.write_text(json.dumps(json.loads(original) | {"identity_digest": "d"*64}))
            return self.snapshot
        self.inspector.side_effect = inspector
        for body in ({"action": "capabilities"},
                     {"action": "plan.create", "operation": "storage.grow", "parameters": {"pool_id": self.service.pool}},
                     {"action": "plan.lookup", "plan_id": plan["id"], "plan_digest": plan["digest"]}):
            path.write_bytes(original)
            result = self.service.handle({"schema": 1, "actor": OWNER, **body})
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(self.ledger(), before)
            self.assertIsNone(self.service.records.active)

    def test_fixed_plan_service_uses_expired_review_admission_without_deletion(self):
        first = self.create()
        before = json.loads(self.ledger())
        with patch("nebulalog_manager.host_jobs.MAX_PLANS", 1):
            self.assertEqual(self.call("plan.create", operation="storage.grow", parameters={"pool_id": self.service.pool})["reason"], "journal_full")
            self.now = first["expires_at"]
            second = self.create()
        after = json.loads(self.ledger())
        self.assertEqual(after["plans"][first["id"]], before["plans"][first["id"]])
        self.assertEqual(after["audit"][:-1], before["audit"])
        self.assertEqual(self.lookup(second)["data"], second)
        self.assertEqual(self.lookup(first)["reason"], "plan_expired")
        self.assertEqual(len(after["plans"]), 2)

    def test_read_only_admission_is_not_a_wire_field(self):
        self.assertEqual(self.call("plan.create", operation="storage.grow", parameters={"pool_id": self.service.pool},
                                   read_only_admission=True)["reason"], "invalid_request")


if __name__ == "__main__":unittest.main()
