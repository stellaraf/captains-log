"""Journal/authorization failure tests use private fixtures, never host services.

Fixture callbacks are deliberately not a real issuer/MFA/executor integration.
They exercise the boundary; runtime capability remains explicitly unavailable.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from nebulalog_manager.common import Refused, atomic_json, locked
from nebulalog_manager import host_job_storage as storage
from nebulalog_manager.host_job_storage import PrivateRecords, StorageIdentity, digest
from nebulalog_manager.host_jobs import Actor, ExecutorEvidence, HostJobs, Observation, VerifiedGrant

INSTALLATION = "458a08e3-ef3b-4cd1-83e5-b402a2c1e913"
RESOURCE = "028917b1-f04e-42a2-85d6-776c0b260a21"
ACTOR = Actor("administrator-subject", "session-1")
PROOF = "SECRET-JWT-PASSWORD-AND-PRIVATE-KEY-MUST-NEVER-BE-JOURNALED"


class JobTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.identity = StorageIdentity(INSTALLATION, self.root, self.root.stat().st_dev)
        self.now = 1_800_000_000
        self.revision = "a" * 64
        self.grant_id = str(uuid.uuid4())
        self.grant_transform = lambda grant: grant
        self.verifier = Mock(side_effect=self.verify)
        self.observer = Mock(side_effect=lambda *_: Observation(self.revision, self.now))
        self.executor = Mock(side_effect=lambda operation: ExecutorEvidence(operation, "b" * 64, "c" * 64, self.now))
        self.records = PrivateRecords(lambda: self.identity)
        patcher = patch.object(storage, "ROOT_UID", os.getuid())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.manager = self.fresh()
        self.manager.initialize()
        self.state = self.root / "manager/jobs"

    def fresh(self, **overrides):
        return HostJobs(**({"records": self.records, "observer": self.observer, "executor_probe": self.executor,
                           "grant_verifier": self.verifier, "clock": lambda: self.now} | overrides))

    def verify(self, proof, binding):
        self.assertEqual(proof, PROOF)
        return self.grant_transform(VerifiedGrant(self.grant_id, binding, self.now - 1, self.now + 60, self.now - 20, "d" * 64))

    def plan(self, **overrides):
        return self.manager.plan(**({"operation": "storage.grow", "values": {"pool_id": RESOURCE}, "actor": ACTOR} | overrides))

    def request(self, plan, **overrides):
        return {"plan_id": plan["id"], "plan_digest": plan["digest"], "operation": plan["operation"],
                "values": plan["parameters"], "actor": ACTOR, "idempotency_key": str(uuid.uuid4()), "proof": PROOF} | overrides

    def ledger(self):
        return json.loads((self.state / "ledger.json").read_text())

    def rewrite(self, value):
        value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
        atomic_json(self.state / "ledger.json", value)

    def test_default_capabilities_never_enable_execution(self):
        default = HostJobs()
        capabilities = default.capabilities()
        self.assertTrue(capabilities["operations"])
        self.assertTrue(all(not op["execution_available"] and op["reason"] == "executor_not_registered" for op in capabilities["operations"]))
        enabled_fixture = self.manager.capabilities()
        self.assertTrue(all(not op["execution_available"] and op["reason"] == "dispatch_not_implemented" for op in enabled_fixture["operations"]))

    def test_unavailable_executor_refuses_without_verifying_or_consuming_grant(self):
        request = self.request(self.plan())
        before = self.ledger()
        for probe in (None, lambda _: True, lambda _: {"available": True}, lambda _: ExecutorEvidence("storage.add_disk", "b" * 64, "c" * 64, self.now)):
            with self.subTest(probe=type(probe).__name__), self.assertRaisesRegex(Refused, "executor_"):
                self.fresh(executor_probe=probe).accept(**request)
        self.verifier.assert_not_called()
        self.assertEqual(self.ledger(), before)

    def test_no_verifier_refuses_without_job_or_grant_use(self):
        request = self.request(self.plan())
        with self.assertRaisesRegex(Refused, "authorization_verifier_unavailable"):
            self.fresh(grant_verifier=None).accept(**request)
        self.assertEqual(self.ledger()["grants"], {})
        self.assertEqual(self.ledger()["jobs"], {})

    def test_host_issued_immutable_plan_bound_to_actor_revision_and_lifetime(self):
        one, two = self.plan(), self.plan()
        self.assertNotEqual(one["id"], two["id"])
        self.assertNotEqual(one["digest"], two["digest"])
        self.assertEqual(one["installation_id"], INSTALLATION)
        self.assertEqual(one["resource_revision"], self.revision)
        self.assertEqual(one["expires_at"] - one["issued_at"], 300)
        one["parameters"]["pool_id"] = str(uuid.uuid4())
        self.assertEqual(self.ledger()["plans"][one["id"]]["parameters"], {"pool_id": RESOURCE})
        with self.assertRaisesRegex(Refused, "host_observation_unavailable"):
            self.fresh(observer=None).plan("storage.grow", {"pool_id": RESOURCE}, ACTOR)

    def test_read_only_admission_beyond_1024_expired_plans_retains_full_history(self):
        # A real generated record supplies the schema; seed the bounded fixture
        # in one write instead of performing 1,024 unrelated filesystem commits.
        seed = self.plan(ttl=30)
        value = self.ledger()
        event = value["audit"][0]
        value["plans"], value["audit"] = {}, []
        previous = "0"*64
        for index in range(1024):
            plan = seed | {"id": str(uuid.uuid5(uuid.UUID(seed["id"]), str(index)))}
            plan["digest"] = digest({key: item for key, item in plan.items() if key != "digest"})
            audit = event | {"sequence": index+1, "plan_id": plan["id"], "request_digest": plan["digest"], "previous": previous}
            audit["digest"] = digest({key: item for key, item in audit.items() if key != "digest"})
            value["plans"][plan["id"]] = plan
            value["audit"].append(audit)
            previous = audit["digest"]
        value["revision"] = 1024
        self.rewrite(value)
        before = self.ledger()
        self.observer.reset_mock()
        with self.assertRaisesRegex(Refused, "job_journal_full"):
            self.plan(read_only_admission=True)  # none have expired
        self.observer.assert_not_called()
        self.now += 30
        with self.assertRaisesRegex(Refused, "job_journal_full"):
            self.plan()  # generic primitive keeps its original admission policy
        created = self.plan(read_only_admission=True)
        after = self.ledger()
        self.assertEqual(len(after["plans"]), 1025)
        self.assertEqual({key: after["plans"][key] for key in before["plans"]}, before["plans"])
        self.assertEqual(after["audit"][:-1], before["audit"])
        self.assertEqual(after["audit"][-1]["plan_id"], created["id"])
        self.assertEqual((after["jobs"], after["grants"], after["idempotency"]), ({}, {}, {}))
        self.assertEqual(self.fresh().get_plan(created["id"], created["digest"], ACTOR), created)
        self.executor.assert_not_called(); self.verifier.assert_not_called()

    def test_read_only_admission_does_not_credit_other_pool_or_operation(self):
        for changes in ({"values": {"pool_id": str(uuid.uuid4())}},
                        {"operation": "updates.check", "values": {"channel": "stable"}}):
            with self.subTest(changes=changes):
                plan = self.plan(**changes)
                self.now = plan["expires_at"]
                before = self.ledger()
                self.observer.reset_mock()
                with patch("nebulalog_manager.host_jobs.MAX_PLANS", 1), self.assertRaisesRegex(Refused, "job_journal_full"):
                    self.plan(read_only_admission=True)
                self.observer.assert_not_called()
                self.assertEqual(self.ledger(), before)

    def test_accepted_and_cancelled_plans_keep_slots_and_retry_evidence(self):
        plan = self.plan()
        request = self.request(plan)
        job = self.manager.accept(**request)
        self.now = plan["expires_at"]
        self.grant_id = str(uuid.uuid4())
        before = self.ledger()
        with patch("nebulalog_manager.host_jobs.MAX_PLANS", 1), self.assertRaisesRegex(Refused, "job_journal_full"):
            self.plan(read_only_admission=True)
        self.assertEqual(self.manager.accept(**request), job)
        self.manager.cancel(job["id"], ACTOR, PROOF)
        cancelled = self.ledger()
        self.assertEqual(cancelled["plans"], before["plans"])
        self.assertEqual(cancelled["idempotency"], before["idempotency"])
        with patch("nebulalog_manager.host_jobs.MAX_PLANS", 1), self.assertRaisesRegex(Refused, "job_journal_full"):
            self.plan(read_only_admission=True)
        created = self.plan(read_only_admission=True)
        after = self.ledger()
        for key in ("jobs", "grants", "idempotency"):
            self.assertEqual(after[key], cancelled[key])
        self.assertEqual(after["plans"][plan["id"]], plan)
        self.assertEqual(after["audit"][:-1], cancelled["audit"])
        self.assertEqual(self.fresh().cancel(job["id"], ACTOR, PROOF)["status"], "cancelled")
        self.grant_id = str(uuid.uuid4())
        self.assertEqual(self.fresh().accept(**request)["id"], job["id"])
        self.assertIn(created["id"], self.ledger()["plans"])

    def test_read_only_admission_clock_rollback_refuses_without_write(self):
        plan = self.plan(ttl=30)
        before = self.ledger()
        self.now = plan["issued_at"] - 1
        self.observer.reset_mock()
        with self.assertRaisesRegex(Refused, "invalid_plan_clock"):
            self.plan(read_only_admission=True)
        self.observer.assert_not_called()
        self.now = plan["expires_at"]
        def rollback(*_):
            self.now -= 1
            return Observation(self.revision, self.now)
        self.observer.side_effect = rollback
        with self.assertRaisesRegex(Refused, "invalid_plan_clock"):
            self.plan(read_only_admission=True)
        self.assertEqual(self.ledger(), before)

    def test_read_only_admission_refuses_forward_clock_jump_during_bounded_observation(self):
        plan = self.plan(ttl=30)
        self.now = plan["expires_at"]
        before = (self.state / "ledger.json").read_bytes()
        def jump(*_):
            self.now += 31
            return Observation(self.revision, self.now)
        self.observer.side_effect = jump
        with self.assertRaisesRegex(Refused, "invalid_plan_clock"):
            self.plan(read_only_admission=True)
        self.assertEqual((self.state / "ledger.json").read_bytes(), before)
        # The generic primitive does not promise the service's 8/10s runtime
        # deadline; retain its existing fresh-observation behavior.
        self.assertIn(self.plan()["id"], self.ledger()["plans"])

    def test_read_only_admission_preserves_retained_audit_and_byte_limits(self):
        plan = self.plan(ttl=30)
        self.now = plan["expires_at"]
        before = (self.state / "ledger.json").read_bytes()
        for limit in ("MAX_RETAINED_PLANS", "MAX_AUDIT"):
            self.observer.reset_mock()
            with patch("nebulalog_manager.host_jobs."+limit, 1), self.assertRaisesRegex(Refused, "job_journal_full"):
                self.plan(read_only_admission=True)
            self.observer.assert_not_called()
        with patch.object(storage, "MAX_BYTES", len(before)+100), self.assertRaisesRegex(Refused, "job_journal_full"):
            self.plan(read_only_admission=True)
        self.assertEqual((self.state / "ledger.json").read_bytes(), before)

    def test_read_only_admission_validates_history_and_cannot_be_claimed_for_other_operations(self):
        plan = self.plan(ttl=30)
        self.now = plan["expires_at"]
        for value in (1, "true", None):
            with self.assertRaisesRegex(Refused, "invalid_plan_admission"):
                self.plan(read_only_admission=value)
        with self.assertRaisesRegex(Refused, "invalid_plan_admission"):
            self.plan(operation="updates.check", values={"channel": "stable"}, read_only_admission=True)
        value = self.ledger()
        value["audit"][0]["request_digest"] = "f"*64
        self.rewrite(value)
        before = (self.state / "ledger.json").read_bytes()
        self.observer.reset_mock()
        with self.assertRaises(Refused):
            self.plan(read_only_admission=True)
        self.observer.assert_not_called()
        self.assertEqual((self.state / "ledger.json").read_bytes(), before)

    def test_get_plan_owned_read_reobserves_without_execution_audit_or_fsync(self):
        plan = self.plan()
        before = (self.state / "ledger.json").read_bytes()
        with patch.object(self.records, "write", side_effect=AssertionError("lookup wrote journal")), \
                patch.object(self.records, "confirm", side_effect=AssertionError("lookup fsynced journal")):
            result = self.manager.get_plan(plan["id"], plan["digest"], ACTOR)
        self.assertEqual(result, plan)
        result["parameters"]["pool_id"] = str(uuid.uuid4())
        self.assertEqual((self.state / "ledger.json").read_bytes(), before)
        self.executor.assert_not_called(); self.verifier.assert_not_called()

    def test_get_plan_mismatch_precedes_observation_and_is_read_only(self):
        plan = self.plan(); before = self.ledger()
        self.observer.reset_mock()
        for plan_id, plan_digest, actor in ((str(uuid.uuid4()), plan["digest"], ACTOR),
                                           (plan["id"], "f"*64, ACTOR),
                                           (plan["id"], plan["digest"], Actor(ACTOR.subject, "other-session"))):
            with self.assertRaisesRegex(Refused, "reviewed_plan_mismatch"):
                self.manager.get_plan(plan_id, plan_digest, actor)
        self.observer.assert_not_called()
        self.assertEqual(self.ledger(), before)

    def test_get_plan_refuses_expiry_clock_rollback_and_resource_change(self):
        plan = self.plan(); before = self.ledger()
        for now in (plan["expires_at"], plan["issued_at"]-1):
            self.now = now
            with self.assertRaisesRegex(Refused, "reviewed_plan_expired"):
                self.manager.get_plan(plan["id"], plan["digest"], ACTOR)
        self.now = plan["issued_at"]; self.revision = "c"*64
        with self.assertRaisesRegex(Refused, "resource_revision_changed"):
            self.manager.get_plan(plan["id"], plan["digest"], ACTOR)
        self.assertEqual(self.ledger(), before)

    def test_get_plan_checks_expiry_after_inspection(self):
        plan = self.plan(); before = self.ledger()
        def observe(*_):
            self.now = plan["expires_at"]
            return Observation(self.revision, self.now)
        self.observer.side_effect = observe
        with self.assertRaisesRegex(Refused, "reviewed_plan_expired"):
            self.manager.get_plan(plan["id"], plan["digest"], ACTOR)
        self.assertEqual(self.ledger(), before)

    def test_acceptance_and_retry_are_one_atomic_job_grant_and_audit(self):
        request = self.request(self.plan())
        result = self.manager.accept(**request)
        self.assertEqual(result["status"], "accepted_pending_dispatch")
        self.assertFalse(result["execution_started"])
        self.assertFalse(result["dispatch_available"])
        self.assertEqual(self.fresh().accept(**request), result)
        ledger = self.ledger()
        self.assertEqual(len(ledger["jobs"]), 1)
        self.assertEqual(len(ledger["grants"]), 1)
        self.assertEqual(len(ledger["idempotency"]), 1)
        self.assertEqual([e["action"] for e in ledger["audit"]], ["plan.created", "job.accepted"])
        self.assertEqual(self.fresh().status(ACTOR)["jobs"], [result])
        self.assertEqual(self.manager.status(Actor("other", "session-2"))["jobs"], [])
        self.assertEqual((self.state / "ledger.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)

    def test_idempotency_body_mismatch_and_plan_body_tampering_refused(self):
        first, second = self.plan(), self.plan()
        request = self.request(first)
        self.manager.accept(**request)
        with self.assertRaisesRegex(Refused, "idempotency_body_mismatch"):
            self.manager.accept(**self.request(second, idempotency_key=request["idempotency_key"]))
        for override in ({"values": {"pool_id": str(uuid.uuid4())}}, {"plan_digest": "f" * 64},
                         {"actor": Actor("administrator-subject", "different-session")},
                         {"operation": "updates.install", "values": {"release_id": RESOURCE}}):
            with self.subTest(override=list(override)), self.assertRaisesRegex(Refused, "reviewed_plan_mismatch"):
                self.manager.accept(**(request | override))

    def test_replay_new_key_after_cancel_refused_and_cancel_retry_is_verified(self):
        request = self.request(self.plan())
        first_grant = self.grant_id
        result = self.manager.accept(**request)
        self.grant_id = str(uuid.uuid4())
        cancelled = self.manager.cancel(result["id"], ACTOR, PROOF)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(self.fresh().cancel(result["id"], ACTOR, PROOF), cancelled)
        self.assertEqual(len(self.ledger()["grants"]), 2)
        self.grant_id = first_grant
        with self.assertRaisesRegex(Refused, "authorization_grant_replayed"):
            self.manager.accept(**(request | {"idempotency_key": str(uuid.uuid4())}))
        with self.assertRaisesRegex(Refused, "authorization_grant_replayed"):
            self.manager.cancel(result["id"], ACTOR, PROOF)
        self.assertEqual(len(self.ledger()["jobs"]), 1)

    def test_one_pending_job_and_global_writer_lock_without_host_calls(self):
        first, second = self.request(self.plan()), self.request(self.plan())
        self.manager.accept(**first)
        count = self.verifier.call_count
        with self.assertRaisesRegex(Refused, "accepted_job_pending_recovery"):
            self.manager.accept(**second)
        self.assertEqual(self.verifier.call_count, count)
        with locked(self.root / "manager/transaction.lock"):
            with self.assertRaisesRegex(Refused, "manager_busy"):
                self.manager.status(ACTOR)
        self.assertEqual(self.fresh().status(ACTOR)["jobs"][0]["status"], "accepted_pending_dispatch")

    def test_expiry_revision_and_clock_rollback_never_accept(self):
        request = self.request(self.plan())
        self.revision = "e" * 64
        with self.assertRaisesRegex(Refused, "resource_revision_changed"):
            self.manager.accept(**request)
        self.revision = "a" * 64
        self.now += 300
        with self.assertRaisesRegex(Refused, "reviewed_plan_expired"):
            self.manager.accept(**request)
        self.now -= 301
        with self.assertRaisesRegex(Refused, "reviewed_plan_expired"):
            self.manager.accept(**request)
        self.verifier.assert_not_called()

    def test_all_grant_bindings_and_fresh_auth_are_checked(self):
        request = self.request(self.plan())
        transforms = [lambda g: True, lambda g: {"verified": True}, lambda g: replace(g, id="../bad"),
                      lambda g: replace(g, auth_time=self.now - 301), lambda g: replace(g, issued_at=self.now + 10),
                      lambda g: replace(g, expires_at=self.now), lambda g: replace(g, expires_at=self.now + 1000),
                      lambda g: replace(g, assurance_policy="not-a-hash")]
        changes = {"installation_id": str(uuid.uuid4()), "actor": Actor("other", "session-2"), "action": "job.cancel",
                   "operation": "storage.add_disk", "plan_id": str(uuid.uuid4()), "plan_digest": "e" * 64,
                   "request_digest": "e" * 64, "resource_revision": "e" * 64}
        transforms.extend(lambda g, key=key, val=val: replace(g, binding=replace(g.binding, **{key: val})) for key, val in changes.items())
        for transform in transforms:
            self.grant_transform = transform
            with self.subTest(transform=transforms.index(transform)), self.assertRaisesRegex(Refused, "authorization_not_verified"):
                self.manager.accept(**request)
        self.assertEqual(self.ledger()["jobs"], {})

    def test_consumed_grant_evidence_cannot_change_even_on_identical_retry(self):
        request = self.request(self.plan())
        self.manager.accept(**request)
        self.grant_transform = lambda grant: replace(grant, assurance_policy="e" * 64)
        with self.assertRaisesRegex(Refused, "authorization_grant_replayed"):
            self.manager.accept(**request)
        self.assertEqual(len(self.ledger()["grants"]), 1)

    def test_evidence_expiring_during_verification_is_refused(self):
        request = self.request(self.plan())
        def delay(grant):
            self.now += 31
            return grant
        self.grant_transform = delay
        with self.assertRaisesRegex(Refused, "acceptance_evidence_expired"):
            self.manager.accept(**request)
        self.assertEqual(self.ledger()["grants"], {})
        self.assertEqual(self.ledger()["jobs"], {})

    def test_expired_plan_retry_needs_fresh_grant_but_does_not_require_executor(self):
        request = self.request(self.plan())
        first = self.manager.accept(**request)
        self.now += 1000
        self.grant_id = str(uuid.uuid4())
        self.assertEqual(self.fresh(executor_probe=None).accept(**request), first)
        self.assertEqual(len(self.ledger()["grants"]), 1)
        with self.assertRaisesRegex(Refused, "authorization_verifier_unavailable"):
            self.fresh(grant_verifier=None).accept(**request)

    def test_cancel_wrong_actor_unverified_and_unsupported_state_fail_closed(self):
        job = self.manager.accept(**self.request(self.plan()))
        self.grant_id = str(uuid.uuid4())
        with self.assertRaisesRegex(Refused, "job_not_available_to_actor"):
            self.manager.cancel(job["id"], Actor("other", "session-2"), PROOF)
        with self.assertRaisesRegex(Refused, "authorization_verifier_unavailable"):
            self.fresh(grant_verifier=None).cancel(job["id"], ACTOR, PROOF)
        new_session = Actor(ACTOR.subject, "new-session-after-login")
        self.assertEqual(self.manager.status(new_session)["jobs"], [])
        with self.assertRaisesRegex(Refused, "job_not_available_to_actor"):
            self.manager.cancel(job["id"], new_session, PROOF)
        value = self.ledger()
        value["jobs"][job["id"]]["status"] = "running"
        self.rewrite(value)
        with self.assertRaisesRegex(Refused, "unsupported_job_state"):
            self.manager.cancel(job["id"], ACTOR, PROOF)

    def test_pre_and_post_commit_failure_retries_never_duplicate_acceptance(self):
        for after in (False, True):
            with self.subTest(after=after):
                request = self.request(self.plan())
                def fail(path, value):
                    if path.name == "ledger.json":
                        if after:
                            atomic_json(path, value)
                        raise OSError("sensitive disk diagnostics")
                    atomic_json(path, value)
                with patch.object(storage, "atomic_json", side_effect=fail), self.assertRaisesRegex(Refused, "job_storage_unavailable"):
                    self.manager.accept(**request)
                count = len(self.ledger()["jobs"])
                result = self.fresh().accept(**request)
                self.assertEqual(len(self.ledger()["jobs"]), count + (0 if after else 1))
                self.assertEqual(self.fresh().accept(**request), result)
                self.grant_id = str(uuid.uuid4())
                self.manager.cancel(result["id"], ACTOR, PROOF)
                self.grant_id = str(uuid.uuid4())
        self.assertEqual(len(self.ledger()["jobs"]), 2)
        self.assertEqual(sum(e["action"] == "job.accepted" for e in self.ledger()["audit"]), 2)

    def test_failure_after_cancellation_commit_is_recovered_without_second_event(self):
        job = self.manager.accept(**self.request(self.plan()))
        self.grant_id = str(uuid.uuid4())
        def fail(path, value):
            atomic_json(path, value)
            raise OSError("uncertain acknowledgement")
        with patch.object(storage, "atomic_json", side_effect=fail), self.assertRaises(Refused):
            self.manager.cancel(job["id"], ACTOR, PROOF)
        self.assertEqual(self.fresh().cancel(job["id"], ACTOR, PROOF)["status"], "cancelled")
        self.assertEqual(sum(e["action"] == "job.cancelled" for e in self.ledger()["audit"]), 1)

    def test_init_recovers_each_pre_and_post_write_interruption(self):
        for step in range(1, 4):
            for after in (False, True):
                with self.subTest(step=step, after=after), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    identity = StorageIdentity(INSTALLATION, root, root.stat().st_dev)
                    fresh = self.fresh(records=PrivateRecords(lambda: identity))
                    calls = 0
                    def fail(path, value):
                        nonlocal calls
                        calls += 1
                        if calls == step:
                            if after:
                                atomic_json(path, value)
                            raise OSError("simulated power cut")
                        atomic_json(path, value)
                    with patch.object(storage, "atomic_json", side_effect=fail), self.assertRaises(Refused):
                        fresh.initialize()
                    receipt = fresh.initialize()
                    self.assertEqual(fresh.initialize(), receipt)
                    self.assertEqual(fresh.status(ACTOR)["jobs"], [])

    def test_missing_marker_or_ledger_never_resets_accepted_work(self):
        self.manager.accept(**self.request(self.plan()))
        for filename in ("../host-jobs-identity.json", "ledger.json", "initial-pending.json"):
            path = self.state / filename
            original = path.read_bytes()
            path.unlink()
            try:
                with self.subTest(filename=filename), self.assertRaises(Refused):
                    self.fresh().initialize()
            finally:
                path.write_bytes(original)
                path.chmod(0o600)
        self.assertEqual(len(self.manager.status(ACTOR)["jobs"]), 1)

    def test_missing_entire_jobs_directory_cannot_reset_existing_registry(self):
        self.manager.accept(**self.request(self.plan()))
        marker = self.state.parent / "host-jobs-identity.json"
        original = marker.read_bytes()
        shutil.rmtree(self.state)
        with self.assertRaisesRegex(Refused, "initialized_job_directory_missing"):
            self.manager.initialize()
        self.assertEqual(marker.read_bytes(), original)
        self.assertFalse(self.state.exists())

    def test_idempotent_acknowledgement_retries_failed_durability_barrier(self):
        request = self.request(self.plan())
        first = self.manager.accept(**request)
        with patch.object(storage.os, "fsync", side_effect=OSError("failed directory fsync")):
            with self.assertRaisesRegex(Refused, "job_storage_unavailable"):
                self.fresh().accept(**request)
        self.assertEqual(self.fresh().accept(**request), first)
        self.assertEqual(len(self.ledger()["jobs"]), 1)

    def test_initialization_retry_flushes_uncertain_manager_parent_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            identity = StorageIdentity(INSTALLATION, root, root.stat().st_dev)
            manager = self.fresh(records=PrivateRecords(lambda: identity))
            fsync = os.fsync
            root_inode = root.stat().st_ino
            calls = []
            def fail_once(fd):
                if os.fstat(fd).st_ino == root_inode:
                    calls.append(fd)
                    if len(calls) == 1:
                        raise OSError("parent flush failed after mkdir")
                fsync(fd)
            with patch.object(storage.os, "fsync", side_effect=fail_once):
                with self.assertRaisesRegex(Refused, "job_storage_unavailable"):
                    manager.initialize()
                self.assertTrue((root / "manager").exists())
                self.assertTrue(manager.initialize()["initialized"])
            self.assertGreaterEqual(len(calls), 2)

    def test_corruption_unknown_fields_bad_indices_and_audit_are_refused(self):
        self.manager.accept(**self.request(self.plan()))
        original = self.ledger()
        variants = []
        for mutation in (lambda v: v["jobs"].clear(), lambda v: v["idempotency"].clear(), lambda v: v["grants"].clear(),
                         lambda v: v["audit"].pop(), lambda v: v.update(revision=True), lambda v: v.update(secret=PROOF),
                         lambda v: v["audit"][0].update(actor={"subject": "other", "session_id": "session"})):
            value = json.loads(json.dumps(original))
            mutation(value)
            variants.append(value)
        for value in variants:
            self.rewrite(value)
            with self.assertRaises(Refused):
                self.fresh().status(ACTOR)
        atomic_json(self.state / "ledger.json", original)
        for raw in ('{"schema":1,"schema":1}', '{"schema":NaN}', '{"schema":', '[' * 1000, '{}'):
            (self.state / "ledger.json").write_text(raw)
            with self.subTest(raw=raw[:20]), self.assertRaises(Refused):
                self.manager.status(ACTOR)

    def test_orphan_temporary_record_is_not_promoted(self):
        (self.state / ".pending-crashed").write_text(PROOF)
        self.assertEqual(self.fresh().status(ACTOR)["jobs"], [])
        self.assertEqual(self.fresh().initialize()["installation_id"], INSTALLATION)
        self.assertEqual((self.state / ".pending-crashed").read_text(), PROOF)

    def test_guard_wrong_installation_or_device_prevents_journal_use(self):
        original = (self.state / "ledger.json").read_bytes()
        self.identity = replace(self.identity, installation_id=str(uuid.uuid4()))
        with self.assertRaisesRegex(Refused, "identity_mismatch"):
            self.manager.status(ACTOR)
        self.identity = replace(self.identity, installation_id=INSTALLATION, device=self.identity.device + 1)
        with self.assertRaisesRegex(Refused, "unsafe_or_unencrypted_job_directory"):
            self.manager.status(ACTOR)
        self.assertEqual((self.state / "ledger.json").read_bytes(), original)

    def test_nested_different_filesystem_is_refused_without_host_mounts(self):
        original = (self.state / "ledger.json").read_bytes()
        lstat = Path.lstat
        def nested_mount(path, *args, **kwargs):
            result = lstat(path, *args, **kwargs)
            if path == self.state:
                parts = list(result)
                parts[2] = result.st_dev + 1
                return os.stat_result(parts)
            return result
        with patch.object(Path, "lstat", nested_mount), self.assertRaisesRegex(Refused, "unsafe_or_unencrypted_job_directory"):
            self.manager.plan("storage.grow", {"pool_id": RESOURCE}, ACTOR)
        self.assertEqual((self.state / "ledger.json").read_bytes(), original)

    def test_unverified_guard_fails_before_creating_any_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guard = Mock(side_effect=RuntimeError(PROOF))
            with patch.object(Path, "mkdir") as mkdir, patch.object(os, "open") as opened, self.assertRaisesRegex(Refused, "encrypted_storage_not_verified") as caught:
                self.fresh(records=PrivateRecords(guard)).initialize()
            mkdir.assert_not_called()
            opened.assert_not_called()
            self.assertNotIn(PROOF, str(caught.exception))
            self.assertEqual(list(root.iterdir()), [])

    def test_unsafe_permissions_symlinks_hardlinks_and_record_size_are_refused(self):
        path = self.state / "ledger.json"
        for mode in (0o644, 0o666):
            path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaisesRegex(Refused, "unsafe_job_record"):
                self.manager.status(ACTOR)
        path.chmod(0o600)
        hardlink = self.state / "copy.json"
        os.link(path, hardlink)
        with self.assertRaisesRegex(Refused, "unsafe_job_record"):
            self.manager.status(ACTOR)
        hardlink.unlink()
        saved = self.state / "saved.json"
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaises(Refused):
            self.manager.status(ACTOR)
        path.unlink()
        saved.rename(path)
        self.state.chmod(0o755)
        with self.assertRaisesRegex(Refused, "unsafe_or_unencrypted_job_directory"):
            self.manager.status(ACTOR)
        self.state.chmod(0o700)
        with patch.object(storage, "MAX_BYTES", 20), self.assertRaisesRegex(Refused, "unsafe_job_record"):
            self.manager.status(ACTOR)

    def test_nested_symlink_rejected_and_no_arbitrary_path_inputs(self):
        self.state.rename(self.state.with_name("actual-jobs"))
        self.state.symlink_to(self.state.with_name("actual-jobs"), target_is_directory=True)
        with self.assertRaisesRegex(Refused, "unsafe_or_unencrypted_job_directory"):
            self.manager.initialize()
        with self.assertRaises(Refused):
            self.manager.plan("shell", {"command": "id"}, ACTOR)
        with self.assertRaises(Refused):
            self.manager.plan("restore.apply", {"backup_id": "/tmp/private-key"}, ACTOR)

    def test_journal_and_safe_errors_never_include_proof_or_callback_error(self):
        request = self.request(self.plan())
        for keyword in ("observer", "executor_probe", "grant_verifier"):
            callback = Mock(side_effect=RuntimeError(PROOF))
            with self.subTest(keyword=keyword), self.assertRaises(Refused) as caught:
                self.fresh(**{keyword: callback}).accept(**request)
            self.assertNotIn(PROOF, str(caught.exception))
        self.manager.accept(**request)
        for path in self.state.iterdir():
            self.assertNotIn(PROOF, path.read_text())
        for event in self.ledger()["audit"]:
            self.assertNotIn("parameters", event)
            self.assertNotIn("proof", event)

    def test_capacity_limits_refuse_before_accepting_or_consuming(self):
        request = self.request(self.plan())
        with patch("nebulalog_manager.host_jobs.MAX_JOBS", 0), self.assertRaisesRegex(Refused, "job_journal_full"):
            self.manager.accept(**request)
        self.verifier.assert_not_called()
        self.assertEqual(self.ledger()["grants"], {})


if __name__ == "__main__":
    unittest.main()
