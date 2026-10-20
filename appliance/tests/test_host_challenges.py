"""Private small filesystem fixtures; assertions and fake grants are not MFA.

Only the encrypted/root admission gate is substituted. Real private files,
flock, atomic replace and fsync exercise persistence without native services.
"""
from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

from nebulalog_manager import host_challenges as challenges
from nebulalog_manager import host_job_storage as storage
from nebulalog_manager.common import Refused
from nebulalog_manager.host_job_storage import StorageIdentity, digest
from nebulalog_manager.host_jobs import Actor, ExecutorEvidence, HostJobs, Observation, VerifiedGrant, request_digest

INSTALLATION = "458a08e3-ef3b-4cd1-83e5-b402a2c1e913"
PLAN = "028917b1-f04e-42a2-85d6-776c0b260a21"


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.identity = StorageIdentity(INSTALLATION, self.root, self.root.stat().st_dev)
        self.now = 1_800_000_000
        self.records = challenges.ChallengeRecords(lambda:self.identity)
        patcher = patch.object(storage, "ROOT_UID", os.getuid()); patcher.start(); self.addCleanup(patcher.stop)
        self.subject = challenges.HostChallenges(records=self.records, clock=lambda:self.now)
        self.binding = challenges.ChallengeBinding(INSTALLATION, "a"*64, "b"*64, "backup.create", 1,
            "job.accept", PLAN, "c"*64, "d"*64, "e"*64, "f"*64)
        self.request = str(uuid.uuid4())
        self.state = self.root/"manager/jobs"
        self.subject.initialize()

    def issue(self, binding=None, **changes):
        return self.subject.issue(binding or self.binding, **({"request_id":self.request,
            "plan_expires_at":self.now+300, "policy_expires_at":self.now+600, "ttl_seconds":120}|changes))

    def ledger(self):
        return json.loads((self.state/challenges.LEDGER).read_text())

    def ledger_bytes(self):
        return (self.state/challenges.LEDGER).read_bytes()

    def rewrite(self, value):
        value["digest"] = digest({k:v for k,v in value.items() if k != "digest"})
        with self.records.locked() as (state,identity): self.records.write(state/challenges.LEDGER,value,identity)

    def test_explicit_genesis_is_idempotent_and_does_not_initialize_jobs(self):
        first = self.subject.initialize(); before = self.ledger_bytes()
        self.assertEqual(first,self.subject.initialize()); self.assertEqual(before,self.ledger_bytes())
        self.assertFalse((self.state/"ledger.json").exists())
        self.assertFalse((self.state.parent/"host-jobs-identity.json").exists())
        self.assertEqual(self.ledger()["records"],{})

    def test_exact_wire_nonce_and_stable_one_use_identity_without_authorization(self):
        value = self.issue(); before=self.ledger_bytes()
        self.assertEqual(set(value),set(challenges.CHALLENGE_FIELDS))
        self.assertEqual(len(value["nonce"]),43); self.assertNotIn("=",value["nonce"])
        self.assertEqual(len(challenges.base64.urlsafe_b64decode(value["nonce"]+"=")),32)
        self.assertEqual(value,self.issue()); self.assertEqual(before,self.ledger_bytes())
        self.assertEqual(value,self.subject.lookup(value["id"],self.binding))
        self.assertEqual(before,self.ledger_bytes())
        value["nonce"]="changed"
        self.assertNotEqual(value["nonce"],self.subject.lookup(value["id"],self.binding)["nonce"])
        self.assertNotIn("grants",self.ledger()); self.assertFalse(hasattr(self.subject,"consume"))

    def test_exact_request_reuse_cannot_replace_binding_or_lifetime(self):
        self.issue(); before=self.ledger_bytes()
        for field,value in (("operation","restore.apply"),("action","job.cancel"),("plan_id",str(uuid.uuid4())),
                            ("plan_digest","1"*64),("request_digest","2"*64),("resource_revision","3"*64),("policy_generation","4"*64)):
            with self.subTest(field=field),self.assertRaisesRegex(Refused,"request_reused"):
                self.issue(replace(self.binding,**{field:value}))
        for field,value in (("ttl_seconds",60),("plan_expires_at",self.now+299),("policy_expires_at",self.now+599)):
            with self.subTest(field=field),self.assertRaisesRegex(Refused,"request_reused"): self.issue(**{field:value})
        self.assertEqual(before,self.ledger_bytes())

    def test_exclusive_expiry_is_minimum_of_ttl_plan_and_policy(self):
        first=self.issue(plan_expires_at=self.now+50,policy_expires_at=self.now+30)
        self.assertEqual(first["expires_at"],self.now+30)
        original_now=self.now; self.now+=30; before=self.ledger_bytes()
        with self.assertRaisesRegex(Refused,"expired"): self.subject.lookup(first["id"],self.binding)
        with self.assertRaisesRegex(Refused,"expired"):
            self.issue(plan_expires_at=original_now+50,policy_expires_at=original_now+30)
        self.assertEqual(before,self.ledger_bytes())
        with self.assertRaisesRegex(Refused,"window_expired"): self.issue(request_id=str(uuid.uuid4()),plan_expires_at=self.now)
        next_value=self.issue(request_id=str(uuid.uuid4()))
        self.assertNotEqual(next_value["id"],first["id"]); self.assertNotEqual(next_value["nonce"],first["nonce"])

    def test_lock_owned_lookup_refuses_outside_and_foreign_thread_and_nested_lock(self):
        value=self.issue(); errors=[]
        with self.assertRaisesRegex(Refused,"owned_lock"): self.subject.lookup_locked(value["id"],self.binding)
        with self.records.locked():
            self.assertEqual(value,self.subject.lookup_locked(value["id"],self.binding))
            with self.assertRaisesRegex(Refused,"manager_busy"): self.subject.lookup(value["id"],self.binding)
            def foreign():
                try:self.subject.lookup_locked(value["id"],self.binding)
                except Exception as exc:errors.append(str(exc))
            worker=threading.Thread(target=foreign);worker.start();worker.join(2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors,["challenge_lookup_requires_owned_lock"])
        with self.assertRaisesRegex(Refused,"owned_lock"): self.records.owned()

    def test_forked_or_forged_lock_lease_is_not_accepted(self):
        value=self.issue()
        with self.records.locked():
            with patch.object(challenges.os,"getpid",return_value=os.getpid()+1),self.assertRaisesRegex(Refused,"owned_lock"):
                self.subject.lookup_locked(value["id"],self.binding)
        with self.assertRaisesRegex(Refused,"records_required"):
            challenges.HostChallenges(records=storage.PrivateRecords(lambda:self.identity))

    def test_wrong_owner_session_action_policy_installation_never_returns_nonce(self):
        value=self.issue(); before=self.ledger_bytes()
        for field,replacement in (("subject_digest","1"*64),("session_digest","2"*64),("action","job.cancel"),
                                  ("policy_generation","3"*64),("request_digest","4"*64),("plan_digest","5"*64)):
            with self.subTest(field=field),self.assertRaises(Refused): self.subject.lookup(value["id"],replace(self.binding,**{field:replacement}))
        self.identity=replace(self.identity,installation_id=str(uuid.uuid4()))
        with self.assertRaises(Refused): self.subject.lookup(value["id"],self.binding)
        self.assertEqual(before,self.ledger_bytes())

    def test_exact_types_and_unsupported_fields_refuse_before_persistence(self):
        before=self.ledger_bytes()
        for field,replacement in (("operation_schema",True),("operation_schema",2),("operation","arbitrary.exec"),
                                  ("action","execute"),("subject_digest","UPPER"),("plan_id","0"*36)):
            with self.subTest(field=field),self.assertRaises(Refused): self.issue(replace(self.binding,**{field:replacement}))
        for changes in ({"ttl_seconds":True},{"ttl_seconds":121},{"ttl_seconds":0},{"request_id":"../file"},
                        {"plan_expires_at":True},{"policy_expires_at":0}):
            with self.subTest(changes=changes),self.assertRaises(Refused):self.issue(**changes)
        with self.assertRaisesRegex(Refused,"typed"):self.subject.issue({},request_id=self.request,plan_expires_at=self.now+1,policy_expires_at=self.now+1)
        self.assertEqual(before,self.ledger_bytes())

    def test_year_9999_timestamp_boundary_matches_go_wire_contract(self):
        maximum = 253402300799
        self.now = maximum - 120
        value = self.issue(plan_expires_at=maximum, policy_expires_at=maximum)
        self.assertEqual(value["expires_at"], maximum)
        self.assertEqual(challenges.validate_challenge(value), value)
        before = self.ledger_bytes()
        for field in ("plan_expires_at", "policy_expires_at"):
            with self.subTest(field=field), self.assertRaisesRegex(Refused, "invalid_challenge_time"):
                self.issue(**{"request_id": str(uuid.uuid4()), "plan_expires_at": maximum,
                              "policy_expires_at": maximum, field: maximum + 1})
        with self.assertRaisesRegex(Refused, "invalid_challenge_time"):
            challenges.validate_challenge({**value, "expires_at": maximum + 1})
        self.now = maximum + 1
        with self.assertRaisesRegex(Refused, "invalid_challenge_time"):
            self.subject.lookup(value["id"], self.binding)
        self.assertEqual(before, self.ledger_bytes())

    def test_ledger_indices_nonce_and_genesis_corruption_refuse(self):
        value=self.issue(); original=self.ledger()
        for mutate in (lambda v:v["requests"].clear(),lambda v:v.update(revision=0),
                       lambda v:v["records"][value["id"]]["challenge"].update(nonce="A"*42+"B"),
                       lambda v:v["records"][value["id"]].update(policy_expires_at=self.now+1)):
            changed=copy.deepcopy(original);mutate(changed);self.rewrite(changed)
            with self.assertRaises(Refused):self.subject.lookup(value["id"],self.binding)
        self.rewrite(original)
        (self.state/challenges.GENESIS).unlink()
        with self.assertRaises((Refused,OSError)):self.subject.initialize()
        self.assertFalse((self.state/challenges.GENESIS).exists())

    def test_symlink_permissions_and_missing_initialized_ledger_refuse(self):
        path=self.state/challenges.LEDGER
        path.chmod(0o644)
        with self.assertRaises(Refused):self.issue()
        path.chmod(0o600); saved=path.read_bytes(); path.unlink()
        with self.assertRaises((Refused,OSError)):self.subject.initialize()
        self.assertFalse(path.exists())
        other=self.root/"other.json";other.write_bytes(saved);other.chmod(0o600);path.symlink_to(other)
        with self.assertRaises(Refused):self.issue()

    def test_lost_issue_ack_returns_original_uuid_nonce_without_second_record(self):
        original=self.records.write
        def write(path,value,identity):
            original(path,value,identity)
            if path.name==challenges.LEDGER and value["revision"]==1:raise OSError("lost acknowledgement")
        with patch.object(self.records,"write",side_effect=write),self.assertRaisesRegex(Refused,"storage_unavailable"):self.issue()
        retained=self.ledger(); expected=next(iter(retained["records"].values()))["challenge"]
        with patch.object(challenges.secrets,"token_urlsafe",side_effect=AssertionError("No new nonce on retry")):
            self.assertEqual(self.issue(),expected)
        self.assertEqual(self.ledger(),retained)

    def test_failed_precommit_and_expiry_during_confirm_never_return_usable_replacement(self):
        original=self.records.write
        def write(path,value,identity):
            if path.name==challenges.LEDGER and value["revision"]:raise OSError("before commit")
            original(path,value,identity)
        with patch.object(self.records,"write",side_effect=write),self.assertRaisesRegex(Refused,"storage_unavailable"):self.issue()
        self.assertFalse(self.ledger()["records"])
        original_confirm=self.subject._confirm
        def confirm(state,identity):
            original_confirm(state,identity);self.now+=120
        with patch.object(self.subject,"_confirm",side_effect=confirm),self.assertRaisesRegex(Refused,"expired"):self.issue()
        self.assertEqual(len(self.ledger()["records"]),1)

    def test_rate_limits_and_expired_ledger_capacity_fail_closed(self):
        with patch.object(challenges,"MAX_ACTOR_ACTIVE",1):
            self.issue()
            with self.assertRaisesRegex(Refused,"rate_limited"):self.issue(request_id=str(uuid.uuid4()))
        self.now+=121
        with patch.object(challenges,"MAX_ACTOR_WINDOW",1),self.assertRaisesRegex(Refused,"rate_limited"):
            self.issue(request_id=str(uuid.uuid4()))
        self.now+=300
        before=self.ledger_bytes()
        with patch.object(challenges,"MAX_RECORDS",1),self.assertRaisesRegex(Refused,"ledger_full"):
            self.issue(request_id=str(uuid.uuid4()))
        self.assertEqual(before,self.ledger_bytes())

    def test_global_rate_clock_and_entropy_collision_refuse(self):
        first=self.issue()
        with patch.object(challenges,"MAX_ACTIVE",1),self.assertRaisesRegex(Refused,"rate_limited"):
            self.issue(replace(self.binding,subject_digest="1"*64),request_id=str(uuid.uuid4()))
        self.now-=1
        with self.assertRaisesRegex(Refused,"clock_regressed"):self.subject.lookup(first["id"],self.binding)
        self.now+=1
        with patch.object(challenges.secrets,"token_urlsafe",return_value=first["nonce"]),self.assertRaisesRegex(Refused,"collision"):
            self.issue(request_id=str(uuid.uuid4()))
        self.assertEqual(len(self.ledger()["records"]),1)

    def test_initialize_ack_loss_preserves_original_registry(self):
        other_root=self.root/"fresh";other_root.mkdir(mode=0o700)
        identity=StorageIdentity(INSTALLATION,other_root,other_root.stat().st_dev)
        records=challenges.ChallengeRecords(lambda:identity)
        subject=challenges.HostChallenges(records=records,clock=lambda:self.now)
        original=records.write
        def write(path,value,identity):
            original(path,value,identity)
            if path.name==challenges.MARKER:raise OSError("marker acknowledgement lost")
        with patch.object(records,"write",side_effect=write),self.assertRaisesRegex(Refused,"storage_unavailable"):subject.initialize()
        registry=json.loads((other_root/"manager"/challenges.MARKER).read_text())["registry_id"]
        self.assertEqual(subject.initialize()["registry_id"],registry)

    def test_same_shared_lock_integrates_without_consuming_outside_host_jobs(self):
        actor=Actor(self.binding.subject_digest,self.binding.session_digest)
        jobs=HostJobs(records=self.records,clock=lambda:self.now,
            observer=lambda *_:Observation("d"*64,self.now),
            executor_probe=lambda op:ExecutorEvidence(op,"1"*64,"2"*64,self.now))
        jobs.initialize()
        plan=jobs.plan("backup.create",{"recipient_id":str(uuid.uuid4()),"scope":"configuration"},actor)
        body=request_digest(plan["id"],plan["digest"],plan["operation"],plan["parameters"],actor)
        binding=replace(self.binding,plan_id=plan["id"],plan_digest=plan["digest"],request_digest=body)
        challenge=self.issue(binding,plan_expires_at=plan["expires_at"])
        before=self.ledger_bytes()
        def fixture_verifier(proof,grant_binding):
            self.assertEqual(proof,"explicit-fixture-only")
            found=self.subject.lookup_locked(challenge["id"],binding)
            return VerifiedGrant(found["id"],grant_binding,found["issued_at"],found["expires_at"],self.now,"f"*64)
        jobs.grant_verifier=fixture_verifier
        request={"plan_id":plan["id"],"plan_digest":plan["digest"],"operation":plan["operation"],"values":plan["parameters"],
                 "actor":actor,"idempotency_key":str(uuid.uuid4()),"proof":"explicit-fixture-only"}
        accepted=jobs.accept(**request)
        self.assertEqual(accepted,jobs.accept(**request))
        self.assertEqual(self.ledger_bytes(),before)
        ledger=json.loads((self.state/"ledger.json").read_text())
        self.assertEqual(set(ledger["grants"]),{challenge["id"]})
        self.assertFalse(accepted["execution_started"] or accepted["dispatch_available"])


if __name__ == "__main__":
    unittest.main()
