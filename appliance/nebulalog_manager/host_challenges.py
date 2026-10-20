"""Inactive root challenge persistence, not an authentication or grant service.

The caller independently verifies the original actor and current protected plan
and policy before issuance, and verifies tokens/live authority before acceptance.
No assertion, nonce, record or lookup from this module authorizes an action.
HostJobs alone atomically consumes the challenge UUID as a verified grant ID.

Expired records remain bounded replay tombstones. This first storage protocol
refuses a full ledger instead of silently renewing a pruned request. Safe pruning
needs a separately specified request/cancellation lifecycle; it must never erase
HostJobs consumed-grant audit. There is no transport, verifier or token spool.
In particular, cancellation after an original plan expires needs a fresh
review-window protocol; callers must not invent a replacement plan expiry here.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import base64
import copy
import os
import re
import secrets
import threading
import time
import uuid

from .common import Refused
from .host_job_storage import PrivateRecords, digest, exact
from .host_operations import SCHEMAS, digest_value, uuid_value

MAX_RECORDS = 1024
MAX_ACTIVE = 64
MAX_ACTOR_ACTIVE = 8
MAX_ACTOR_WINDOW = 16
RATE_WINDOW_SECONDS = 300
MAX_TTL_SECONDS = 120
MAX_UTC_SECONDS = 253402300799  # Year 9999, shared with the Go/JWT wire contract.
CHALLENGE_FIELDS = ("schema", "id", "nonce", "installation_id", "subject_digest", "session_digest", "operation",
                    "operation_schema", "action", "plan_id", "plan_digest", "resource_revision", "request_digest",
                    "policy_generation", "issued_at", "expires_at")
LEDGER = "challenges.json"
GENESIS = "challenges-initial.json"
MARKER = "host-challenges-identity.json"


def _stamp(value):
    if type(value) is not int or not 0 < value <= MAX_UTC_SECONDS:
        raise Refused("invalid_challenge_time")
    return value


def _uuid(value):
    if type(value) is not str or uuid_value(value) != value or uuid.UUID(value).int == 0:
        raise Refused("invalid_challenge_id")
    return value


def _nonce(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise Refused("invalid_challenge_nonce")
    raw = base64.urlsafe_b64decode(value + "=")
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise Refused("invalid_challenge_nonce")
    return value


def _seal(value):
    return {**value, "digest": digest(value)}


def _check_seal(value):
    if value["digest"] != digest({k:v for k,v in value.items() if k != "digest"}):
        raise Refused("challenge_record_changed")


@dataclass(frozen=True)
class ChallengeBinding:
    installation_id: str
    subject_digest: str
    session_digest: str
    operation: str
    operation_schema: int
    action: str
    plan_id: str
    plan_digest: str
    resource_revision: str
    request_digest: str
    policy_generation: str

    def validate(self):
        _uuid(self.installation_id); _uuid(self.plan_id)
        for name in ("subject_digest", "session_digest", "plan_digest", "resource_revision", "request_digest", "policy_generation"):
            digest_value(getattr(self, name))
        if (type(self.operation) is not str or self.operation not in SCHEMAS
                or type(self.operation_schema) is not int or self.operation_schema != 1
                or self.action not in ("job.accept", "job.cancel")):
            raise Refused("unsupported_challenge_binding")


def _binding(value):
    if type(value) is not ChallengeBinding:
        raise Refused("typed_challenge_binding_required")
    value.validate()
    return asdict(value)


def validate_challenge(value):
    """Validate only the exact data contract; never authenticate its contents."""
    exact(value, CHALLENGE_FIELDS)
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise Refused("unsupported_challenge_schema")
    _uuid(value["id"]); _nonce(value["nonce"])
    _binding(ChallengeBinding(**{k:value[k] for k in ChallengeBinding.__dataclass_fields__}))
    if not 0 < _stamp(value["expires_at"]) - _stamp(value["issued_at"]) <= MAX_TTL_SECONDS:
        raise Refused("invalid_challenge_lifetime")
    return copy.deepcopy(value)


class ChallengeRecords(PrivateRecords):
    """Share this instance with HostJobs to permit lookup inside its owned lock.

    The active lease is process/thread bound and ends on context exit. No caller
    path, boolean, descriptor number or asserted installation creates a lease.
    Inherited encrypted admission, private files and lock semantics stay intact.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._local = threading.local()

    @contextmanager
    def locked(self, *, initialize=False):
        if getattr(self._local, "lease", None) is not None:
            raise Refused("manager_busy")
        with super().locked(initialize=initialize) as (state, identity):
            self._local.lease = (os.getpid(), threading.get_ident(), state, identity)
            try:
                yield state, identity
            finally:
                self._local.lease = None

    def owned(self):
        lease = getattr(self._local, "lease", None)
        if lease is None or lease[:2] != (os.getpid(), threading.get_ident()):
            raise Refused("challenge_lookup_requires_owned_lock")
        return lease[2:]


class HostChallenges:
    def __init__(self, *, records=None, clock=None):
        self.records = records if records is not None else ChallengeRecords()
        if not isinstance(self.records, ChallengeRecords):
            raise Refused("challenge_lock_records_required")
        self.clock = clock if clock is not None else lambda: int(time.time())

    def _now(self):
        return _stamp(self.clock())

    def _confirm(self, state, identity):
        # Readback and barriers also settle a lost directory-fsync acknowledgement.
        for path in (state/LEDGER, state/GENESIS, state.parent/MARKER):
            self.records.read(path, identity)
            fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                self.records._file(os.fstat(fd), identity)
                os.fsync(fd)
            finally:
                os.close(fd)
        for path in (state, state.parent, identity.root):
            self.records.directory(path, identity)
            fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)

    def initialize(self):
        """Explicit retry-safe genesis. It neither initializes HostJobs nor grants."""
        with self.records.locked(initialize=True) as (state, identity):
            _uuid(identity.installation_id)
            pending, ledger, marker = state/GENESIS, state/LEDGER, state.parent/MARKER
            if os.path.lexists(marker):
                value = self._load(state, identity)
                self._confirm(state, identity)
                return {"schema":1, "installation_id":identity.installation_id, "registry_id":value["registry_id"]}
            if not os.path.lexists(pending):
                if os.path.lexists(ledger): raise Refused("orphan_challenge_ledger")
                genesis = _seal({"schema":1, "installation_id":identity.installation_id,
                    "registry_id":str(uuid.uuid4()), "revision":0, "last_issued_at":0, "records":{}, "requests":{}})
                self.records.write(pending, genesis, identity)
            genesis = self.records.read(pending, identity)
            self._validate(genesis, identity.installation_id)
            if genesis["revision"] or genesis["records"] or genesis["last_issued_at"]:
                raise Refused("invalid_challenge_genesis")
            if os.path.lexists(ledger):
                if self.records.read(ledger, identity) != genesis: raise Refused("unbound_challenge_ledger")
            else:
                self.records.write(ledger, genesis, identity)
            self.records.write(marker, {"schema":1, "installation_id":identity.installation_id,
                "registry_id":genesis["registry_id"], "genesis_digest":genesis["digest"]}, identity)
            self._confirm(state, identity)
            return {"schema":1, "installation_id":identity.installation_id, "registry_id":genesis["registry_id"]}

    def _validate(self, value, installation):
        try:
            _uuid(installation)
            exact(value, ("schema", "installation_id", "registry_id", "revision", "last_issued_at", "records", "requests", "digest"))
            if type(value["schema"]) is not int or value["schema"] != 1 or value["installation_id"] != installation:
                raise Refused("challenge_installation_changed")
            _uuid(value["registry_id"]); _check_seal(value)
            if (type(value["records"]) is not dict or len(value["records"]) > MAX_RECORDS
                    or type(value["requests"]) is not dict or len(value["requests"]) != len(value["records"])
                    or type(value["revision"]) is not int or value["revision"] != len(value["records"])):
                raise Refused("invalid_challenge_ledger_size")
            indices, nonces, latest = {}, set(), 0
            for identifier, entry in value["records"].items():
                exact(entry, ("request_id", "ttl_seconds", "plan_expires_at", "policy_expires_at", "challenge"))
                challenge = validate_challenge(entry["challenge"])
                if identifier != challenge["id"] or challenge["installation_id"] != installation:
                    raise Refused("challenge_installation_changed")
                _uuid(entry["request_id"])
                ttl = entry["ttl_seconds"]
                if type(ttl) is not int or not 1 <= ttl <= MAX_TTL_SECONDS:
                    raise Refused("invalid_challenge_lifetime")
                if challenge["expires_at"] != min(challenge["issued_at"]+ttl,
                        _stamp(entry["plan_expires_at"]), _stamp(entry["policy_expires_at"])):
                    raise Refused("challenge_lifetime_binding_changed")
                index = self._request_index(challenge, entry["request_id"])
                if index in indices or challenge["nonce"] in nonces: raise Refused("duplicate_challenge_identity")
                indices[index] = identifier; nonces.add(challenge["nonce"])
                latest = max(latest, challenge["issued_at"])
            if (value["requests"] != indices or type(value["last_issued_at"]) is not int
                    or value["last_issued_at"] != latest):
                raise Refused("invalid_challenge_indices")
        except (TypeError, ValueError, KeyError, AttributeError):
            raise Refused("invalid_challenge_ledger") from None

    def _load(self, state, identity):
        marker = self.records.read(state.parent/MARKER, identity)
        exact(marker, ("schema", "installation_id", "registry_id", "genesis_digest"))
        if (type(marker["schema"]) is not int or marker["schema"] != 1
                or marker["installation_id"] != identity.installation_id):
            raise Refused("challenge_installation_changed")
        _uuid(marker["registry_id"]); digest_value(marker["genesis_digest"])
        genesis = self.records.read(state/GENESIS, identity)
        self._validate(genesis, identity.installation_id)
        if (genesis["revision"] != 0 or genesis["registry_id"] != marker["registry_id"]
                or genesis["digest"] != marker["genesis_digest"]):
            raise Refused("challenge_genesis_changed")
        value = self.records.read(state/LEDGER, identity)
        self._validate(value, identity.installation_id)
        if value["registry_id"] != marker["registry_id"]: raise Refused("challenge_registry_changed")
        return value

    @staticmethod
    def _request_index(binding, request_id):
        return digest({"subject_digest":binding["subject_digest"], "session_digest":binding["session_digest"],
                       "request_id":request_id})

    def issue(self, binding, *, request_id, plan_expires_at, policy_expires_at, ttl_seconds=MAX_TTL_SECONDS):
        body = _binding(binding); _uuid(request_id)
        _stamp(plan_expires_at); _stamp(policy_expires_at)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise Refused("invalid_challenge_lifetime")
        with self.records.locked() as (state, identity):
            value, now = self._load(state, identity), self._now()
            if body["installation_id"] != identity.installation_id: raise Refused("challenge_installation_changed")
            if now < value["last_issued_at"]: raise Refused("challenge_clock_regressed")
            index = self._request_index(body, request_id)
            prior = value["requests"].get(index)
            if prior is not None:
                entry = value["records"][prior]
                if (any(entry["challenge"][k] != v for k,v in body.items()) or entry["ttl_seconds"] != ttl_seconds
                        or entry["plan_expires_at"] != plan_expires_at or entry["policy_expires_at"] != policy_expires_at):
                    raise Refused("challenge_request_reused")
                if not entry["challenge"]["issued_at"] <= now < entry["challenge"]["expires_at"]:
                    raise Refused("challenge_expired_new_request_required")
                self._confirm(state, identity)
                if not entry["challenge"]["issued_at"] <= self._now() < entry["challenge"]["expires_at"]:
                    raise Refused("challenge_expired_new_request_required")
                return copy.deepcopy(entry["challenge"])
            if now >= min(plan_expires_at, policy_expires_at): raise Refused("challenge_authority_window_expired")
            if len(value["records"]) >= MAX_RECORDS: raise Refused("challenge_ledger_full")
            active, actor_active, actor_window = 0, 0, 0
            for entry in value["records"].values():
                challenge = entry["challenge"]
                same = all(challenge[k] == body[k] for k in ("subject_digest", "session_digest"))
                active += now < challenge["expires_at"]
                actor_active += same and now < challenge["expires_at"]
                actor_window += same and now-RATE_WINDOW_SECONDS < challenge["issued_at"]
            if active >= MAX_ACTIVE or actor_active >= MAX_ACTOR_ACTIVE or actor_window >= MAX_ACTOR_WINDOW:
                raise Refused("challenge_rate_limited")
            challenge = {"schema":1, "id":str(uuid.uuid4()), "nonce":secrets.token_urlsafe(32), **body,
                         "issued_at":now, "expires_at":min(now+ttl_seconds, plan_expires_at, policy_expires_at)}
            validate_challenge(challenge)
            if challenge["id"] in value["records"] or any(entry["challenge"]["nonce"] == challenge["nonce"] for entry in value["records"].values()):
                raise Refused("challenge_entropy_collision")
            value["records"][challenge["id"]] = {"request_id":request_id, "ttl_seconds":ttl_seconds,
                "plan_expires_at":plan_expires_at, "policy_expires_at":policy_expires_at, "challenge":challenge}
            value["requests"][index] = challenge["id"]
            value.update(revision=value["revision"]+1, last_issued_at=now)
            value = _seal({k:v for k,v in value.items() if k != "digest"})
            self._validate(value, identity.installation_id)
            self.records.write(state/LEDGER, value, identity)
            if self._load(state, identity) != value: raise Refused("challenge_readback_changed")
            self._confirm(state, identity)
            if not challenge["issued_at"] <= self._now() < challenge["expires_at"]:
                raise Refused("challenge_expired_new_request_required")
            return copy.deepcopy(challenge)

    def lookup(self, identifier, binding):
        with self.records.locked():
            return self.lookup_locked(identifier, binding)

    def lookup_locked(self, identifier, binding):
        """Side-effect-free verifier lookup under the shared actual manager lock."""
        _uuid(identifier); expected = _binding(binding)
        state, identity = self.records.owned()
        value, now = self._load(state, identity), self._now()
        if expected["installation_id"] != identity.installation_id: raise Refused("challenge_installation_changed")
        if now < value["last_issued_at"]: raise Refused("challenge_clock_regressed")
        entry = value["records"].get(identifier)
        if entry is None or any(entry["challenge"][k] != v for k,v in expected.items()):
            raise Refused("challenge_binding_mismatch")
        result = entry["challenge"]
        if not result["issued_at"] <= now < result["expires_at"]:
            raise Refused("challenge_expired_new_request_required")
        return copy.deepcopy(result)
