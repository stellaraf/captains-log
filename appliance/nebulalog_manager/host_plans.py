"""Read-only host storage planning candidate; no executor/grant/dispatch surface.

The API's peer-asserted hashed actor provides plan ownership only. It is not
independent human authentication, MFA evidence, or permission to mutate storage.
No default journal initialization, bootstrap integration or service enablement.
"""
from __future__ import annotations

import copy
import contextlib
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import stat
import threading
import time
import uuid

from .common import Refused, run
from .host_job_storage import PrivateRecords, digest, exact, strict_json
from .host_jobs import Actor, HostJobs, Observation
from .host_operations import digest_value, uuid_value
from . import storage

IDENTITY_PATH = Path("/etc/nebulalog/storage.json")
INSPECTION_SECONDS = 8.0
MAX_COMMAND_BYTES = 1024 * 1024
REVIEW_FIELDS = ("current_bytes", "presented_bytes", "unallocated_disk_bytes", "stages", "requires_unlock_credential", "irreversible")
REGISTRY_FIELDS = ("schema", "installation_id", "pool_id", "identity_digest", "digest")
REASONS = frozenset({"invalid_request", "peer_not_authorized", "request_timeout", "host_unavailable", "plan_unavailable",
                     "plan_expired", "resource_changed", "manager_busy", "journal_full"})


def unavailable(reason):
    return {"schema": 1, "status": "unavailable", "reason": reason if reason in REASONS else "host_unavailable"}


def pool_id(installation_id):
    return str(uuid.uuid5(uuid.UUID(uuid_value(installation_id)), "nebulalog.storage.data.v1"))


def planner_revision():
    # Bind reviewed code bytes as well as data. This is change detection, not a
    # publisher signature or a qualification claim. Replacing code invalidates
    # outstanding plans; requests cannot supply their own planner revision.
    base = Path(__file__).parent
    result = hashlib.sha256()
    for name in ("host_plans.py", "storage.py", "host_jobs.py"):
        raw = (base / name).read_bytes()
        if len(raw) > 1024 * 1024:
            raise Refused("host_unavailable")
        result.update(name.encode() + b"\0" + hashlib.sha256(raw).digest())
    return result.hexdigest()


def actor(value):
    exact(value, ("subject", "session_id"))
    return Actor(digest_value(value["subject"]), digest_value(value["session_id"]))


def request(value):
    if type(value) is not dict or type(value.get("schema")) is not int or value["schema"] != 1:
        raise Refused("invalid_request")
    action = value.get("action")
    fields = {"capabilities": (), "plan.create": ("operation", "parameters"), "plan.lookup": ("plan_id", "plan_digest")}
    if type(action) is not str or action not in fields:
        raise Refused("invalid_request")
    exact(value, ("schema", "action", "actor", *fields[action]))
    owner = actor(value["actor"])
    if action == "plan.create":
        if value["operation"] != "storage.grow":
            raise Refused("invalid_request")
        exact(value["parameters"], ("pool_id",))
        uuid_value(value["parameters"]["pool_id"])
    elif action == "plan.lookup":
        uuid_value(value["plan_id"])
        digest_value(value["plan_digest"])
    return action, owner


def read_identity(path=IDENTITY_PATH):
    """Only the fixed root-controlled installed identity; never a request path."""
    for directory in path.parents:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused("host_unavailable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or before.st_nlink != 1 or not 0 < before.st_size <= 16384):
            raise Refused("host_unavailable")
        raw = stream.read(16385)
        after = os.fstat(stream.fileno())
    if len(raw) > 16384 or any(getattr(before, key) != getattr(after, key) for key in ("st_ino", "st_dev", "st_size", "st_mtime_ns", "st_ctime_ns")):
        raise Refused("host_unavailable")
    value = strict_json(raw.decode("utf-8", "strict"))
    if type(value) is not dict:
        raise Refused("host_unavailable")
    result = storage.Identity(**value)
    result.validate()
    return result


class StorageObserver:
    def __init__(self, installation_id, *, identity_reader=read_identity, inspector=storage.inspect,
                 runner=run, clock=lambda: int(time.time()), monotonic=time.monotonic):
        self.installation_id = uuid_value(installation_id)
        self.pool = pool_id(installation_id)
        self.identity_reader, self.inspector, self.runner = identity_reader, inspector, runner
        self.clock, self.monotonic = clock, monotonic
        self.deadline = None
        self.review = self.revision = None
        self.expected_identity = None

    def enrolled_identity(self):
        self.check_time()
        identity = self.identity_reader()
        if type(identity) is not storage.Identity:
            raise Refused("host_unavailable")
        identity.validate()
        if identity.additional_pvs:
            raise Refused("host_unavailable")
        return identity, digest(asdict(identity))

    def begin(self, deadline):
        self.deadline = min(deadline, self.monotonic() + INSPECTION_SECONDS)
        self.review = self.revision = None

    def check_time(self):
        if self.deadline is None or self.monotonic() >= self.deadline:
            raise Refused("request_timeout")

    def command(self, argv, **kwargs):
        self.check_time()
        kwargs["timeout"] = min(5.0, self.deadline - self.monotonic(), kwargs.get("timeout", 5.0))
        value = self.runner(argv, **kwargs)
        self.check_time()
        if type(value) is not str or len(value.encode("utf-8")) > MAX_COMMAND_BYTES:
            raise Refused("host_unavailable")
        return value

    def __call__(self, operation, values):
        self.check_time()
        if operation != "storage.grow" or values != {"pool_id": self.pool}:
            raise Refused("host_unavailable")
        identity, identity_digest = self.enrolled_identity()
        if identity_digest != self.expected_identity:
            raise Refused("resource_revision_changed")
        observed = self.inspector(identity, runner=self.command)
        if type(observed) is not storage.Snapshot or observed.identity != identity:
            raise Refused("host_unavailable")
        plan = storage.growth_plan(observed)
        review = {key: plan[key] for key in REVIEW_FIELDS if key != "irreversible"}
        review["irreversible"] = True
        for key in ("current_bytes", "presented_bytes", "unallocated_disk_bytes"):
            if type(review[key]) is not int or not 0 <= review[key] < 2**53:
                raise Refused("host_unavailable")
        self.check_time()
        revision = digest({"schema": 1, "installation_id": self.installation_id, "pool_id": self.pool,
                           "snapshot_fingerprint": observed.fingerprint, "review": review, "planner_revision": planner_revision()})
        self.review, self.revision = copy.deepcopy(review), revision
        return Observation(revision, self.clock())


class _LockedRecords:
    """Expose the actual held PrivateRecords lock to a read-only observer.

    All filesystem verification and lock acquisition still belong to the
    supplied PrivateRecords. An observer cannot substitute earlier evidence or
    open a nested lock while HostJobs is already holding the manager lock.
    """
    def __init__(self, records):
        self.records = records
        self.active = None

    def __getattr__(self, name):
        return getattr(self.records, name)

    @contextlib.contextmanager
    def locked(self, *, initialize=False):
        if self.active is not None:
            raise Refused("manager_busy")
        with self.records.locked(initialize=initialize) as context:
            self.active = context
            try:
                yield context
            finally:
                self.active = None


class HostPlans:
    """Fixed planning operations with trusted injection seams for isolated tests."""
    def __init__(self, installation_id, *, records=None, observer=None, clock=lambda: int(time.time()), monotonic=time.monotonic):
        self.installation_id = uuid_value(installation_id)
        self.pool = pool_id(installation_id)
        self.monotonic, self.clock = monotonic, clock
        self.observer = observer if observer is not None else StorageObserver(installation_id, clock=clock, monotonic=monotonic)
        self._requests = threading.Lock()
        self.records = _LockedRecords(records if records is not None else PrivateRecords())
        self.jobs = HostJobs(records=self.records, observer=self._observe, clock=clock)

    @contextlib.contextmanager
    def _exclusive(self):
        # The foreground socket server is serial. Also fail closed if trusted
        # library callers accidentally share its mutable observer concurrently.
        if not self._requests.acquire(blocking=False):
            raise Refused("manager_busy")
        try:
            yield
        finally:
            self._requests.release()

    def initialize(self):
        """Explicit journal genesis only; never called by handle or the factory."""
        with self._exclusive():
            result = self.jobs.initialize()
            if result["installation_id"] != self.installation_id:
                raise Refused("host_unavailable")
            self.observer.begin(self.monotonic() + INSPECTION_SECONDS)
            with self.records.locked():
                self._registry_locked(initialize=True)
            return result

    @staticmethod
    def _check_registry(value, expected):
        exact(value, REGISTRY_FIELDS)
        if (type(value["schema"]) is not int or value["schema"] != 1
                or value["digest"] != digest({key: item for key, item in value.items() if key != "digest"})):
            raise Refused("resource_revision_changed")
        for key in ("installation_id", "pool_id"):
            uuid_value(value[key])
        for key in ("identity_digest", "digest"):
            digest_value(value[key])
        if value != expected:
            raise Refused("resource_revision_changed")

    def _registry_locked(self, *, initialize=False):
        if self.records.active is None:
            raise Refused("host_unavailable")
        state, identity = self.records.active
        journal = self.jobs._load(state, identity)
        if identity.installation_id != self.installation_id:
            raise Refused("host_unavailable")
        pristine = journal["revision"] == 0 and not any(journal[key] for key in ("plans", "jobs", "audit", "grants", "idempotency"))
        _, identity_digest = self.observer.enrolled_identity()
        expected = {"schema": 1, "installation_id": self.installation_id, "pool_id": self.pool,
                    "identity_digest": identity_digest}
        expected["digest"] = digest(expected)
        path = state.parent / "host-plan-pool.json"
        genesis = state / "host-plan-pool-genesis.json"
        if initialize and not path.exists() and not path.is_symlink():
            if genesis.exists() or genesis.is_symlink() or not pristine:
                raise Refused("host_unavailable")
            # First enrollment requires a valid snapshot before either record
            # is published. Missing both copies is resumable only at pristine
            # journal genesis; root rollback of all records is not detectable.
            self.observer.expected_identity = identity_digest
            self.observer("storage.grow", {"pool_id": self.pool})
            self.records.write(path, expected, identity)
        self._check_registry(self.records.read(path, identity), expected)
        # Retry a crash between the two enrollment writes only at pristine
        # journal genesis and only with the identical first record present.
        if initialize and not genesis.exists() and not genesis.is_symlink():
            if not pristine:
                raise Refused("host_unavailable")
            self.records.write(genesis, expected, identity)
        self._check_registry(self.records.read(genesis, identity), expected)
        self.observer.expected_identity = identity_digest

    def _observe(self, operation, values):
        self._registry_locked()
        result = self.observer(operation, values)
        self._registry_locked()
        return result

    def handle(self, value, *, deadline=None):
        try:
            action, owner = request(value)
        except (Refused, TypeError, ValueError):
            return unavailable("invalid_request")
        deadline = min(deadline if deadline is not None else self.monotonic() + INSPECTION_SECONDS,
                       self.monotonic() + INSPECTION_SECONDS)
        try:
            with self._exclusive():
                return self._handle(value, action, owner, deadline)
        except Refused as exc:
            return unavailable(str(exc))

    def _handle(self, value, action, owner, deadline):
        self.observer.begin(deadline)
        try:
            if action == "capabilities":
                with self.records.locked():
                    self._observe("storage.grow", {"pool_id": self.pool})
                data = {"control": "read_only", "execution_available": False, "pool_id": self.pool,
                        "operations": [{"operation": "storage.grow", "planning_available": True,
                                        "execution_available": False, "reason": "execution_not_qualified"}]}
            else:
                if action == "plan.create":
                    if value["parameters"] != {"pool_id": self.pool}:
                        return unavailable("invalid_request")
                    plan = self.jobs.plan("storage.grow", {"pool_id": self.pool}, owner, read_only_admission=True)
                else:
                    plan = self.jobs.get_plan(value["plan_id"], value["plan_digest"], owner)
                if (plan["installation_id"] != self.installation_id or plan["operation"] != "storage.grow"
                        or plan["parameters"] != {"pool_id": self.pool} or plan["resource_revision"] != self.observer.revision):
                    raise Refused("resource_revision_changed")
                if not plan["issued_at"] <= self.clock() < plan["expires_at"]:
                    raise Refused("reviewed_plan_expired")
                data = {key: copy.deepcopy(plan[key]) for key in ("id", "installation_id", "operation", "parameters",
                        "resource_revision", "issued_at", "expires_at", "digest")}
                data.update(review=copy.deepcopy(self.observer.review), execution_available=False)
            self.observer.check_time()
            return {"schema": 1, "status": "ok", "data": data}
        except Exception as exc:
            if self.monotonic() >= deadline:
                return unavailable("request_timeout")
            reasons = {"reviewed_plan_mismatch": "plan_unavailable", "reviewed_plan_expired": "plan_expired",
                       "resource_revision_changed": "resource_changed", "manager_busy": "manager_busy", "job_journal_full": "journal_full"}
            return unavailable(reasons.get(str(exc), "host_unavailable"))


def create_service():
    """Require real encrypted storage and an already initialized journal."""
    records = PrivateRecords()
    evidence = HostJobs(records=records).status(Actor("0" * 64, "0" * 64))
    return HostPlans(evidence["installation_id"], records=records)


def initialize_journal():
    """Explicit library entry for later qualified first-boot integration only."""
    records = PrivateRecords()
    initialized = HostJobs(records=records).initialize()
    service = HostPlans(initialized["installation_id"], records=records)
    return service.initialize()
