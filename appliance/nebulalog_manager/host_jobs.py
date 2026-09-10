"""Internal host plan/job primitives. No transport, executor or dispatch exists.

Callbacks are trusted host integrations: observation is read-only, the executor
probe verifies a fixed qualified adapter, and the grant verifier independently
checks issuer/session/Administrator/recent MFA and returns bound evidence. The
verifier MUST be side-effect-free: this ledger atomically consumes one-use IDs.
No request boolean can substitute for these callbacks.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import re
import time
import uuid

from .common import Refused
from .host_job_storage import PrivateRecords, digest, exact
from .host_operations import SCHEMAS, digest_value, parameters, uuid_value

MAX_PLANS = 1024
MAX_JOBS = 1024
MAX_AUDIT = 4096
MAX_RETAINED_PLANS = 4096
PLAN_FIELDS = ("id", "installation_id", "actor", "operation", "parameters", "resource_revision", "issued_at", "expires_at", "digest")
JOB_FIELDS = ("id", "plan_id", "actor", "request_digest", "idempotency_key", "status", "accepted_at", "cancelled_at",
              "accept_grant_id", "cancel_grant_id", "executor_revision", "qualification_revision")
GRANT_FIELDS = ("id", "job_id", "action", "actor", "request_digest", "issued_at", "expires_at", "auth_time", "assurance_policy")
AUDIT_FIELDS = ("sequence", "time", "action", "actor", "operation", "plan_id", "job_id", "request_digest", "previous", "digest")


def stamp(value):
    if type(value) is not int or not 0 <= value < 2**53:
        raise Refused("invalid_timestamp")
    return value


def opaque(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}", value):
        raise Refused("invalid_actor")
    return value


@dataclass(frozen=True)
class Actor:
    subject: str
    session_id: str


def actor_record(actor):
    if type(actor) is not Actor:
        raise Refused("trusted_actor_required")
    return {"subject": opaque(actor.subject), "session_id": opaque(actor.session_id)}


def check_actor(value):
    exact(value, ("subject", "session_id"))
    return actor_record(Actor(**value))


@dataclass(frozen=True)
class Observation:
    resource_revision: str
    observed_at: int


@dataclass(frozen=True)
class ExecutorEvidence:
    operation: str
    adapter_revision: str
    qualification_revision: str
    observed_at: int


@dataclass(frozen=True)
class GrantBinding:
    installation_id: str
    actor: Actor
    action: str
    operation: str
    plan_id: str
    plan_digest: str
    request_digest: str
    resource_revision: str


@dataclass(frozen=True)
class VerifiedGrant:
    id: str
    binding: GrantBinding
    issued_at: int
    expires_at: int
    auth_time: int
    assurance_policy: str


def request_digest(plan_id, plan_digest, operation, values, actor):
    """Canonical body binding; the idempotency key is a separate immutable index."""
    return digest({"action": "job.accept", "plan_id": uuid_value(plan_id), "plan_digest": digest_value(plan_digest),
                   "operation": operation, "parameters": parameters(operation, values), "actor": actor_record(actor)})


def cancellation_digest(job_id, actor):
    return digest({"action": "job.cancel", "job_id": uuid_value(job_id), "actor": actor_record(actor)})


def _sealed(value):
    return {**value, "digest": digest(value)}


def _check_seal(value):
    if value["digest"] != digest({key: item for key, item in value.items() if key != "digest"}):
        raise Refused("job_record_digest_mismatch")


class HostJobs:
    def __init__(self, *, records=None, observer=None, executor_probe=None, grant_verifier=None, clock=None):
        self.records = records if records is not None else PrivateRecords()
        self.observer = observer
        self.executor_probe = executor_probe
        self.grant_verifier = grant_verifier
        self.clock = clock if clock is not None else lambda: int(time.time())

    def _now(self):
        return stamp(self.clock())

    def initialize(self):
        """Explicit retry-safe genesis only; missing/changed existing state is never reset."""
        with self.records.locked(initialize=True) as (state, identity):
            pending, ledger = (state / name for name in ("initial-pending.json", "ledger.json"))
            marker = state.parent / "host-jobs-identity.json"
            if marker.exists() or marker.is_symlink():
                value = self._load(state, identity)
                self.records.confirm(state, identity)
                return {"installation_id": identity.installation_id, "registry_id": value["registry_id"], "initialized": True}
            if not pending.exists() and not pending.is_symlink():
                if ledger.exists() or ledger.is_symlink():
                    raise Refused("orphan_job_journal")
                genesis = _sealed({"schema": 1, "installation_id": identity.installation_id, "registry_id": str(uuid.uuid4()),
                                   "revision": 0, "plans": {}, "jobs": {}, "idempotency": {}, "grants": {}, "audit": []})
                self.records.write(pending, genesis, identity)
            genesis = self.records.read(pending, identity)
            self._validate(genesis, identity.installation_id)
            if genesis["revision"] != 0 or any(genesis[key] for key in ("plans", "jobs", "idempotency", "grants", "audit")):
                raise Refused("invalid_job_genesis")
            if ledger.exists() or ledger.is_symlink():
                if self.records.read(ledger, identity) != genesis:
                    raise Refused("unbound_job_journal")
            else:
                self.records.write(ledger, genesis, identity)
            self.records.write(marker, {"schema": 1, "installation_id": identity.installation_id,
                                       "registry_id": genesis["registry_id"], "genesis_digest": genesis["digest"]}, identity)
            self.records.confirm(state, identity)
            return {"installation_id": identity.installation_id, "registry_id": genesis["registry_id"], "initialized": True}

    def _load(self, state, identity):
        marker = self.records.read(state.parent / "host-jobs-identity.json", identity)
        exact(marker, ("schema", "installation_id", "registry_id", "genesis_digest"))
        if type(marker["schema"]) is not int or marker["schema"] != 1 or marker["installation_id"] != identity.installation_id:
            raise Refused("job_registry_identity_mismatch")
        uuid_value(marker["registry_id"])
        digest_value(marker["genesis_digest"])
        genesis = self.records.read(state / "initial-pending.json", identity)
        self._validate(genesis, identity.installation_id)
        if (genesis["revision"] != 0 or genesis["registry_id"] != marker["registry_id"]
                or genesis["digest"] != marker["genesis_digest"]):
            raise Refused("job_genesis_changed")
        value = self.records.read(state / "ledger.json", identity)
        self._validate(value, identity.installation_id)
        if value["registry_id"] != marker["registry_id"]:
            raise Refused("job_registry_identity_mismatch")
        return value

    def _validate(self, value, installation_id):
        """Validate all indices and lifecycle/audit relations, even on read-only access."""
        try:
            self._validate_inner(value, installation_id)
        except (TypeError, ValueError, KeyError, AttributeError):
            raise Refused("invalid_job_journal") from None

    def _validate_inner(self, value, installation_id):
        exact(value, ("schema", "installation_id", "registry_id", "revision", "plans", "jobs", "idempotency", "grants", "audit", "digest"))
        if type(value["schema"]) is not int or value["schema"] != 1 or value["installation_id"] != installation_id:
            raise Refused("job_registry_identity_mismatch")
        uuid_value(value["registry_id"])
        _check_seal(value)
        for key, maximum in (("plans", MAX_RETAINED_PLANS), ("jobs", MAX_JOBS), ("idempotency", MAX_JOBS), ("grants", MAX_JOBS * 2)):
            if type(value[key]) is not dict or len(value[key]) > maximum:
                raise Refused("invalid_job_journal_size")
        if type(value["audit"]) is not list or len(value["audit"]) > MAX_AUDIT or type(value["revision"]) is not int or value["revision"] != len(value["audit"]):
            raise Refused("invalid_job_revision")
        for key, plan in value["plans"].items():
            exact(plan, PLAN_FIELDS)
            if uuid_value(key) != plan["id"] or plan["installation_id"] != installation_id:
                raise Refused("invalid_plan_identity")
            check_actor(plan["actor"])
            parameters(plan["operation"], plan["parameters"])
            digest_value(plan["resource_revision"])
            if not 30 <= stamp(plan["expires_at"]) - stamp(plan["issued_at"]) <= 300:
                raise Refused("invalid_plan_lifetime")
            _check_seal(plan)
        indices, grants, active = {}, set(), 0
        for key, job in value["jobs"].items():
            exact(job, JOB_FIELDS)
            if uuid_value(key) != job["id"] or job["plan_id"] not in value["plans"]:
                raise Refused("invalid_job_identity")
            plan = value["plans"][job["plan_id"]]
            check_actor(job["actor"])
            if job["actor"] != plan["actor"] or job["status"] not in ("accepted_pending_dispatch", "cancelled"):
                raise Refused("unsupported_job_state")
            expected = request_digest(plan["id"], plan["digest"], plan["operation"], plan["parameters"], Actor(**job["actor"]))
            if job["request_digest"] != expected or not plan["issued_at"] <= stamp(job["accepted_at"]) < plan["expires_at"]:
                raise Refused("invalid_job_binding")
            digest_value(job["executor_revision"])
            digest_value(job["qualification_revision"])
            index = digest({"actor": job["actor"], "key": uuid_value(job["idempotency_key"])})
            if index in indices:
                raise Refused("duplicate_job_idempotency")
            indices[index] = {"job_id": key, "request_digest": expected}
            for action, field in (("job.accept", "accept_grant_id"), ("job.cancel", "cancel_grant_id")):
                grant_id = job[field]
                if field == "cancel_grant_id" and job["status"] == "accepted_pending_dispatch":
                    if grant_id is not None or job["cancelled_at"] is not None:
                        raise Refused("invalid_job_cancellation")
                    active += 1
                    continue
                uuid_value(grant_id)
                if grant_id in grants or grant_id not in value["grants"]:
                    raise Refused("invalid_consumed_grant")
                grants.add(grant_id)
                grant = value["grants"][grant_id]
                exact(grant, GRANT_FIELDS)
                event_time = job["accepted_at"] if action == "job.accept" else stamp(job["cancelled_at"])
                if event_time < job["accepted_at"]:
                    raise Refused("invalid_job_cancellation")
                if (grant["id"] != grant_id or grant["job_id"] != key or grant["action"] != action or grant["actor"] != job["actor"]
                        or grant["request_digest"] != (expected if action == "job.accept" else cancellation_digest(key, Actor(**job["actor"])))
                        or not stamp(grant["issued_at"]) - 5 <= event_time < stamp(grant["expires_at"])
                        or not 0 < grant["expires_at"] - grant["issued_at"] <= 120
                        or not -5 <= event_time - stamp(grant["auth_time"]) <= 300):
                    raise Refused("invalid_consumed_grant")
                digest_value(grant["assurance_policy"])
        if active > 1 or value["idempotency"] != indices or set(value["grants"]) != grants:
            raise Refused("inconsistent_job_indices")
        previous, created, accepted, cancelled, last_time = "0" * 64, set(), set(), set(), 0
        for sequence, event in enumerate(value["audit"], 1):
            exact(event, AUDIT_FIELDS)
            _check_seal(event)
            if type(event["sequence"]) is not int or event["sequence"] != sequence or event["previous"] != previous or stamp(event["time"]) < last_time:
                raise Refused("invalid_job_audit_chain")
            previous, last_time = event["digest"], event["time"]
            plan = value["plans"][event["plan_id"]]
            if event["actor"] != plan["actor"] or event["operation"] != plan["operation"]:
                raise Refused("invalid_job_audit_binding")
            if event["action"] == "plan.created":
                if plan["id"] in created or event["job_id"] is not None or event["request_digest"] != plan["digest"] or event["time"] != plan["issued_at"]:
                    raise Refused("invalid_plan_audit")
                created.add(plan["id"])
            else:
                job = value["jobs"][event["job_id"]]
                if job["plan_id"] != plan["id"] or plan["id"] not in created:
                    raise Refused("invalid_job_audit_binding")
                if event["action"] == "job.accepted":
                    if job["id"] in accepted or event["request_digest"] != job["request_digest"] or event["time"] != job["accepted_at"]:
                        raise Refused("invalid_job_acceptance_audit")
                    accepted.add(job["id"])
                elif event["action"] == "job.cancelled":
                    if (job["id"] not in accepted or job["id"] in cancelled or job["status"] != "cancelled"
                            or event["request_digest"] != cancellation_digest(job["id"], Actor(**job["actor"])) or event["time"] != job["cancelled_at"]):
                        raise Refused("invalid_job_cancellation_audit")
                    cancelled.add(job["id"])
                else:
                    raise Refused("unsupported_job_audit_action")
        if (created != set(value["plans"]) or accepted != set(value["jobs"])
                or cancelled != {key for key, job in value["jobs"].items() if job["status"] == "cancelled"}):
            raise Refused("incomplete_job_audit")

    def _save(self, state, value, identity, *, action, actor, plan, job_id, request, now):
        if len(value["audit"]) >= MAX_AUDIT:
            raise Refused("job_journal_full")
        event = _sealed({"sequence": value["revision"] + 1, "time": now, "action": action, "actor": actor,
                         "operation": plan["operation"], "plan_id": plan["id"], "job_id": job_id, "request_digest": request,
                         "previous": value["audit"][-1]["digest"] if value["audit"] else "0" * 64})
        value["audit"].append(event)
        value["revision"] += 1
        value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
        self._validate(value, identity.installation_id)
        self.records.write(state / "ledger.json", value, identity)

    def _observe(self, operation, values, now):
        if self.observer is None:
            raise Refused("host_observation_unavailable")
        try:
            result = self.observer(operation, parameters(operation, values))
            now = self._now()
            if type(result) is not Observation or not -5 <= now - stamp(result.observed_at) <= 30:
                raise Refused("invalid_host_observation")
            digest_value(result.resource_revision)
            return result
        except Exception:
            raise Refused("host_observation_unavailable") from None

    def _executor(self, operation, now):
        if self.executor_probe is None:
            raise Refused("executor_not_registered")
        try:
            evidence = self.executor_probe(operation)
            now = self._now()
            if (type(evidence) is not ExecutorEvidence or evidence.operation != operation
                    or not -5 <= now - stamp(evidence.observed_at) <= 60):
                raise Refused("invalid_executor_evidence")
            digest_value(evidence.adapter_revision)
            digest_value(evidence.qualification_revision)
            return evidence
        except Exception:
            raise Refused("executor_unavailable") from None

    def capabilities(self):
        now, result = self._now(), []
        for operation in SCHEMAS:
            reason = "dispatch_not_implemented"
            try:
                self._executor(operation, now)
                if self.observer is None:
                    reason = "host_observation_unavailable"
                elif self.grant_verifier is None:
                    reason = "authorization_verifier_unavailable"
            except Refused as exc:
                reason = str(exc)
            result.append({"operation": operation, "execution_available": False, "reason": reason})
        return {"schema": 1, "control": "internal_primitives_only", "operations": result}

    def plan(self, operation, values, actor, *, ttl=300, read_only_admission=False):
        """Durably create a review without discarding historical evidence.

        The trusted fixed storage planner may reclaim admission slots from
        expired, never-job-referenced reviews for its exact pool. Every full
        plan/audit record remains present; this is not physical compaction or
        permission to accept work. Other callers retain the original strict
        total-plan admission limit. Neither policy overrides hard journal limits.
        """
        values, owner = parameters(operation, values), actor_record(actor)
        if type(ttl) is not int or not 30 <= ttl <= 300:
            raise Refused("invalid_plan_lifetime")
        if type(read_only_admission) is not bool or (read_only_admission and operation != "storage.grow"):
            raise Refused("invalid_plan_admission")
        with self.records.locked() as (state, identity):
            value, now = self._load(state, identity), self._now()
            if now < (value["audit"][-1]["time"] if value["audit"] else 0):
                raise Refused("invalid_plan_clock")
            charged = len(value["plans"])
            if read_only_admission:
                referenced = {job["plan_id"] for job in value["jobs"].values()}
                charged -= sum(plan["operation"] == operation and plan["parameters"] == values
                               and plan["expires_at"] <= now and plan["id"] not in referenced
                               for plan in value["plans"].values())
            if charged >= MAX_PLANS or len(value["plans"]) >= MAX_RETAINED_PLANS or len(value["audit"]) >= MAX_AUDIT:
                raise Refused("job_journal_full")
            admitted_at = now
            observed = self._observe(operation, values, now)
            now = self._now()
            if now < admitted_at or (read_only_admission and now - admitted_at > 30):
                raise Refused("invalid_plan_clock")
            plan = _sealed({"id": str(uuid.uuid4()), "installation_id": identity.installation_id, "actor": owner,
                            "operation": operation, "parameters": values, "resource_revision": observed.resource_revision,
                            "issued_at": now, "expires_at": now + ttl})
            value["plans"][plan["id"]] = plan
            self._save(state, value, identity, action="plan.created", actor=owner, plan=plan, job_id=None, request=plan["digest"], now=now)
            return plan

    def get_plan(self, plan_id, plan_digest, actor):
        """Owner-bound read that reinspects resources; never invokes execution/grants.

        A transport may assert API-peer identity for this read, but that assertion
        is not a verified human grant and cannot authorize accept/cancel/dispatch.
        No journal or audit record is modified, including on a failed lookup.
        """
        plan_id, plan_digest, owner = uuid_value(plan_id), digest_value(plan_digest), actor_record(actor)
        with self.records.locked() as (state, identity):
            value, now = self._load(state, identity), self._now()
            plan = value["plans"].get(plan_id)
            if plan is None or plan["digest"] != plan_digest or plan["actor"] != owner:
                raise Refused("reviewed_plan_mismatch")
            if not plan["issued_at"] <= now < plan["expires_at"]:
                raise Refused("reviewed_plan_expired")
            observed = self._observe(plan["operation"], plan["parameters"], now)
            if observed.resource_revision != plan["resource_revision"]:
                raise Refused("resource_revision_changed")
            now = self._now()
            if not plan["issued_at"] <= now < plan["expires_at"]:
                raise Refused("reviewed_plan_expired")
            if not -5 <= now - observed.observed_at <= 30:
                raise Refused("invalid_host_observation")
            return copy.deepcopy(plan)

    def _binding(self, identity, actor, action, plan, request):
        return GrantBinding(identity.installation_id, actor, action, plan["operation"], plan["id"], plan["digest"], request, plan["resource_revision"])

    def _verify(self, proof, binding, now):
        if self.grant_verifier is None:
            raise Refused("authorization_verifier_unavailable")
        try:
            if type(proof) not in (bytes, str) or not 1 <= len(proof) <= 16384:
                raise Refused("invalid_grant_proof")
            grant = self.grant_verifier(proof, binding)
            now = self._now()  # Verification/inspection callbacks may have taken time.
            if (type(grant) is not VerifiedGrant or type(grant.binding) is not GrantBinding or grant.binding != binding
                    or not stamp(grant.issued_at) - 5 <= now < stamp(grant.expires_at)
                    or not 0 < grant.expires_at - grant.issued_at <= 120
                    or not -5 <= now - stamp(grant.auth_time) <= 300):
                raise Refused("invalid_grant_evidence")
            uuid_value(grant.id)
            digest_value(grant.assurance_policy)
            return grant
        except Exception:
            raise Refused("authorization_not_verified") from None

    def _acceptance_time(self, plan, observation, executor, grant):
        now = self._now()
        if not plan["issued_at"] <= now < plan["expires_at"]:
            raise Refused("reviewed_plan_expired")
        if not -5 <= now - observation.observed_at <= 30 or not -5 <= now - executor.observed_at <= 60:
            raise Refused("acceptance_evidence_expired")
        if not grant.issued_at - 5 <= now < grant.expires_at or not -5 <= now - grant.auth_time <= 300:
            raise Refused("authorization_not_verified")
        return now

    def _grant_record(self, grant, job_id):
        return {"id": grant.id, "job_id": job_id, "action": grant.binding.action,
                "actor": actor_record(grant.binding.actor), "request_digest": grant.binding.request_digest,
                "issued_at": grant.issued_at, "expires_at": grant.expires_at, "auth_time": grant.auth_time,
                "assurance_policy": grant.assurance_policy}

    def _consume(self, value, grant, job_id):
        if grant.id in value["grants"]:
            raise Refused("authorization_grant_replayed")
        value["grants"][grant.id] = self._grant_record(grant, job_id)

    def _retry_grant(self, value, grant, job_id):
        consumed = value["grants"].get(grant.id)
        if consumed is not None and consumed != self._grant_record(grant, job_id):
            raise Refused("authorization_grant_replayed")

    def accept(self, *, plan_id, plan_digest, operation, values, actor, idempotency_key, proof):
        request = request_digest(plan_id, plan_digest, operation, values, actor)
        owner = actor_record(actor)
        index = digest({"actor": owner, "key": uuid_value(idempotency_key)})
        with self.records.locked() as (state, identity):
            value, now = self._load(state, identity), self._now()
            plan = value["plans"].get(plan_id)
            if (plan is None or plan["digest"] != plan_digest or plan["actor"] != owner
                    or plan["operation"] != operation or plan["parameters"] != parameters(operation, values)):
                raise Refused("reviewed_plan_mismatch")
            binding = self._binding(identity, actor, "job.accept", plan, request)
            existing = value["idempotency"].get(index)
            if existing is not None:
                if existing["request_digest"] != request:
                    raise Refused("idempotency_body_mismatch")
                grant = self._verify(proof, binding, now)
                self._retry_grant(value, grant, existing["job_id"])
                # Retry is a verified read of the original acceptance; no new grant use.
                self.records.confirm(state, identity)
                return self._summary(value["jobs"][existing["job_id"]])
            if not plan["issued_at"] <= now < plan["expires_at"]:
                raise Refused("reviewed_plan_expired")
            if any(job["status"] == "accepted_pending_dispatch" for job in value["jobs"].values()):
                raise Refused("accepted_job_pending_recovery")
            if len(value["jobs"]) >= MAX_JOBS:
                raise Refused("job_journal_full")
            observation = self._observe(operation, values, now)
            if observation.resource_revision != plan["resource_revision"]:
                raise Refused("resource_revision_changed")
            executor = self._executor(operation, now)  # Refuse before verifying/consuming a one-use grant.
            grant = self._verify(proof, binding, now)
            now = self._acceptance_time(plan, observation, executor, grant)
            job = {"id": str(uuid.uuid4()), "plan_id": plan_id, "actor": owner, "request_digest": request,
                   "idempotency_key": idempotency_key, "status": "accepted_pending_dispatch", "accepted_at": now,
                   "cancelled_at": None, "accept_grant_id": grant.id, "cancel_grant_id": None,
                   "executor_revision": executor.adapter_revision, "qualification_revision": executor.qualification_revision}
            self._consume(value, grant, job["id"])
            value["jobs"][job["id"]] = job
            value["idempotency"][index] = {"job_id": job["id"], "request_digest": request}
            self._save(state, value, identity, action="job.accepted", actor=owner, plan=plan, job_id=job["id"], request=request, now=now)
            return self._summary(job)

    def cancel(self, job_id, actor, proof):
        owner, request = actor_record(actor), cancellation_digest(job_id, actor)
        with self.records.locked() as (state, identity):
            value, now = self._load(state, identity), self._now()
            job = value["jobs"].get(job_id)
            if job is None or job["actor"] != owner:
                raise Refused("job_not_available_to_actor")
            plan = value["plans"][job["plan_id"]]
            grant = self._verify(proof, self._binding(identity, actor, "job.cancel", plan, request), now)
            now = self._now()
            if not grant.issued_at - 5 <= now < grant.expires_at or not -5 <= now - grant.auth_time <= 300:
                raise Refused("authorization_not_verified")
            if job["status"] == "cancelled":
                self._retry_grant(value, grant, job_id)
                self.records.confirm(state, identity)
                return self._summary(job)
            if job["status"] != "accepted_pending_dispatch":
                raise Refused("job_not_safely_cancellable")
            self._consume(value, grant, job_id)
            job.update(status="cancelled", cancelled_at=now, cancel_grant_id=grant.id)
            self._save(state, value, identity, action="job.cancelled", actor=owner, plan=plan, job_id=job_id, request=request, now=now)
            return self._summary(job)

    def _summary(self, job):
        return {key: job[key] for key in ("id", "plan_id", "status", "accepted_at", "cancelled_at")} | {
            "execution_started": False, "dispatch_available": False,
            "recovery": "verified_cancel_or_future_dispatch_integration" if job["status"] == "accepted_pending_dispatch" else None}

    def status(self, actor):
        """Internal authorized caller supplies identity; a future transport must authenticate every read."""
        owner = actor_record(actor)
        with self.records.locked() as (state, identity):
            value = self._load(state, identity)
            return {"schema": 1, "control": "internal_primitives_only", "installation_id": identity.installation_id,
                    "revision": value["revision"], "execution_available": False,
                    "jobs": [self._summary(job) for job in value["jobs"].values() if job["actor"] == owner]}
