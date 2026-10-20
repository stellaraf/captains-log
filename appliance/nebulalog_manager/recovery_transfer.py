"""Private resumable ciphertext input storage; no network or restore authority.

Only a trusted root controller constructs Owner/Policy. They are bindings, not
proof of authentication: never construct them from browser assertions. Every
future transport must authenticate/authorize requests and bound blocking reads.
Sealed inputs remain unauthenticated until the recovery coordinator verifies
CMS, manifests, source/runtime links and fresh-target policy. No key is unlocked.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import uuid

from .backup import DATA, _directory, _encrypted_staging
from .common import Refused, atomic_json, locked, require_linux_root, run
from .configuration_restore import ARCHIVE_LIMIT
from .host_payload import strict_json
from .log_recovery_set import CHUNK_BYTES, MAX_CHUNKS, MANIFEST_BYTES, ENVELOPE_OVERHEAD
from .recovery_media import certificate_envelope, encrypted_key_parameters

ROOT = DATA / "manager/recovery-transfers"
ROOT_UID = 0
SEGMENT_BYTES = 4 * 1024**2
COPY_BYTES = 1024**2
MIN_RESERVE = 10 * 1024**3
MAX_OBJECTS = MAX_CHUNKS + 4
MAX_TOTAL = ARCHIVE_LIMIT + 2 * 65536 + MANIFEST_BYTES + ENVELOPE_OVERHEAD + MAX_CHUNKS * (CHUNK_BYTES + ENVELOPE_OVERHEAD)
MAX_TRANSFERS = 64
PAGE_LIMIT = 128
METADATA_BYTES = 16384
OBJECT_OVERHEAD = 16384
SHA = re.compile(r"[a-f0-9]{64}")


def _uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Refused("An exact nonzero transfer UUID is required") from None
    return value


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Refused("Transfer integer exceeds its bounds")
    return value


def _sha(value):
    if type(value) is not str or not SHA.fullmatch(value):
        raise Refused("An exact SHA256 is required")
    return value


def _exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Refused("Unexpected transfer metadata")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _identity(info):
    return [info.st_dev, info.st_ino]


def _stable(info):
    return (*_identity(info), info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise Refused("Transfer file is not a private owned regular file")


def _sync(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _opened(path, *, writable=False, create=False):
    """Pin both containing directory and file; never follow a final symlink."""
    _directory(path.parent, private=True)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        directory = os.fstat(parent)
        if _identity(directory) != _identity(path.parent.lstat()):
            raise Refused("Transfer directory changed before open")
        flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent)
        info = os.fstat(descriptor)
        _private(info)
        if _identity(info) != _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)):
            raise Refused("Transfer file changed before open")
        yield descriptor, info
        if (_identity(directory) != _identity(path.parent.lstat())
                or _identity(info) != _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))):
            raise Refused("Transfer path changed while open")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _read(path):
    with _opened(path) as (fd, before):
        if not 0 < before.st_size <= METADATA_BYTES:
            raise Refused("Transfer metadata exceeds its bound")
        raw = os.read(fd, before.st_size + 1)
        if len(raw) != before.st_size or _stable(os.fstat(fd)) != _stable(before):
            raise Refused("Transfer metadata changed while read")
    return strict_json(raw)


def _save(path, value):
    if len(_canonical(value)) > METADATA_BYTES:
        raise Refused("Transfer metadata exceeds its bound")
    if os.path.lexists(path):
        _read(path)
    atomic_json(path, value)


def _range_hash(fd, offset, length):
    digest = hashlib.sha256()
    while length:
        value = os.pread(fd, min(length, COPY_BYTES), offset)
        if not value:
            raise Refused("Transfer bytes were truncated")
        digest.update(value)
        offset += len(value)
        length -= len(value)
    return digest.hexdigest()


@dataclass(frozen=True)
class Owner:
    installation_id: str
    subject_sha256: str
    session_sha256: str

    def validate(self):
        _uuid(self.installation_id)
        _sha(self.subject_sha256)
        _sha(self.session_sha256)


@dataclass(frozen=True)
class Policy:
    maximum_bytes: int
    minimum_free_bytes: int

    def validate(self):
        _integer(self.maximum_bytes, 1, MAX_TOTAL)
        _integer(self.minimum_free_bytes, MIN_RESERVE, MAX_TOTAL)


class RecoveryTransfer:
    def __init__(self, owner, policy, *, root=ROOT, commands=run):
        if type(owner) is not Owner or type(policy) is not Policy:
            raise Refused("Trusted host transfer owner and policy are required")
        owner.validate()
        policy.validate()
        self.owner, self.policy, self.root, self.commands = owner, policy, Path(root), commands
        if not self.root.is_absolute() or self.root.resolve() != self.root:
            raise Refused("Transfer root must be a fixed canonical host directory")

    @contextmanager
    def _lock(self, *, create=False):
        require_linux_root()
        _directory(self.root.parent, private=True)
        _encrypted_staging(self.root.parent, self.commands)
        if create and not os.path.lexists(self.root):
            self.root.mkdir(mode=0o700)
            _sync(self.root.parent)
        _directory(self.root, private=True)
        path = self.root / "transfer.lock"
        if os.path.lexists(path):
            with _opened(path):
                pass
        with locked(path) as fd:
            _private(os.fstat(fd))
            yield

    def _capacity(self, required):
        sample = os.statvfs(self.root)
        free, total = sample.f_bavail * sample.f_frsize, sample.f_blocks * sample.f_frsize
        reserve = max(self.policy.minimum_free_bytes, MIN_RESERVE, total // 10)
        if free - required < reserve:
            raise Refused("Transfer lacks its protected filesystem reserve")

    @staticmethod
    def _count(scope, chunks):
        if type(scope) is not str or type(chunks) is not int:
            raise Refused("Unsupported recovery transfer scope or chunk count")
        if scope == "configuration" and chunks == 0:
            return 3
        if scope == "full" and type(chunks) is int and 1 <= chunks <= MAX_CHUNKS:
            return chunks + 4
        raise Refused("Unsupported recovery transfer scope or chunk count")

    @staticmethod
    def _name(tx, ordinal):
        if ordinal < 3:
            return ("configuration.cms", "recipient.pem", "recovery-key.pk8")[ordinal]
        return "logs/manifest.cms" if ordinal == 3 else f"logs/chunks/{ordinal - 4:06d}.cms"

    @staticmethod
    def _object_id(tx, name):
        return str(uuid.uuid5(uuid.UUID(tx["id"]), name))

    def _entry(self, tx, metadata):
        _exact(metadata, ("name", "bytes", "sha256"))
        name = metadata["name"]
        bounds = {"configuration.cms": ARCHIVE_LIMIT, "recipient.pem": 65536, "recovery-key.pk8": 65536}
        if tx["scope"] == "full":
            bounds["logs/manifest.cms"] = MANIFEST_BYTES + ENVELOPE_OVERHEAD
        maximum = bounds.get(name) if type(name) is str else None
        if maximum is None and type(name) is str and tx["scope"] == "full":
            match = re.fullmatch(r"logs/chunks/([0-9]{6})\.cms", name)
            if match and int(match[1]) < tx["chunk_count"]:
                maximum = CHUNK_BYTES + ENVELOPE_OVERHEAD
        if maximum is None:
            raise Refused("Unsupported recovery input name")
        _integer(metadata["bytes"], 1, maximum)
        _sha(metadata["sha256"])
        return dict(metadata)

    def _load(self, identifier, *, owner=True):
        path = self.root / _uuid(identifier)
        _directory(path, private=True)
        tx = _read(path / "transfer.json")
        _exact(tx, ("schema", "id", "owner", "policy", "request_id", "scope", "chunk_count", "total_bytes",
                    "object_count", "declared_count", "declared_bytes", "state", "pending", "seal_sha256"))
        if (type(tx["schema"]) is not int or tx["schema"] != 1 or tx["id"] != identifier
                or tx["state"] not in ("open", "sealed") or tx["object_count"] != self._count(tx["scope"], tx["chunk_count"])):
            raise Refused("Invalid transfer journal")
        _uuid(tx["request_id"])
        _exact(tx["owner"], ("installation_id", "subject_sha256", "session_sha256"))
        Owner(**tx["owner"]).validate()
        _exact(tx["policy"], ("maximum_bytes", "minimum_free_bytes"))
        Policy(**tx["policy"]).validate()
        if owner and (tx["owner"] != asdict(self.owner) or tx["policy"] != asdict(self.policy)):
            raise Refused("Transfer owner, session or host policy changed")
        _integer(tx["total_bytes"], tx["object_count"], tx["policy"]["maximum_bytes"])
        _integer(tx["declared_count"], 0, tx["object_count"])
        _integer(tx["declared_bytes"], 0, tx["total_bytes"])
        if tx["pending"] is not None:
            self._entry(tx, tx["pending"])
            if tx["state"] != "open":
                raise Refused("Sealed transfer has unfinished admission")
        if tx["state"] == "sealed":
            _sha(tx["seal_sha256"])
        elif tx["seal_sha256"] is not None:
            raise Refused("Unexpected transfer seal")
        return tx

    def _txsave(self, tx):
        _save(self.root / tx["id"] / "transfer.json", tx)

    def create(self, request_id, *, scope, chunk_count, total_bytes):
        """Request UUID is an idempotency key, never an authorization grant."""
        _uuid(request_id)
        count = self._count(scope, chunk_count)
        _integer(total_bytes, count, self.policy.maximum_bytes)
        identifier = str(uuid.uuid5(uuid.UUID(self.owner.installation_id),
            hashlib.sha256(_canonical(asdict(self.owner))).hexdigest() + ":" + request_id))
        with self._lock(create=True):
            active = self.root / "active.json"
            if os.path.lexists(active):
                pointer = _read(active)
                _exact(pointer, ("id",))
                previous = self._load(_uuid(pointer["id"]), owner=False)
                if previous["state"] != "sealed" and previous["id"] != identifier:
                    raise Refused("An unfinished transfer already owns input staging")
            stage = self.root / identifier
            if os.path.lexists(stage):
                tx = self._load(identifier)
                if any(tx[k] != v for k, v in {"request_id": request_id, "scope": scope,
                        "chunk_count": chunk_count, "total_bytes": total_bytes}.items()):
                    raise Refused("Transfer request ID was reused with different metadata")
            else:
                retained = 0
                reserved = 0
                with os.scandir(self.root) as entries:
                    for item in entries:
                        if item.name in ("active.json", "transfer.lock"):
                            continue
                        retained += 1
                        if retained >= MAX_TRANSFERS:
                            raise Refused("Retained transfer limit reached")
                        _uuid(item.name)
                        _directory(Path(item.path), private=True)
                        retained_tx = self._load(item.name, owner=False)
                        if retained_tx["state"] != "sealed":
                            # The stage is durable before active.json. A crash
                            # in that publication window must not admit a second
                            # unfinished request; retry the original UUID.
                            raise Refused("An unfinished retained transfer already owns input staging")
                        reserved += retained_tx["total_bytes"]
                if reserved + total_bytes > self.policy.maximum_bytes:
                    raise Refused("Retained transfers exceed the host storage allocation")
                self._capacity(total_bytes + count * OBJECT_OVERHEAD + SEGMENT_BYTES)
                stage.mkdir(mode=0o700)
                for relative in ("objects", "payload", "scratch"):
                    (stage / relative).mkdir(mode=0o700)
                if scope == "full":
                    (stage / "payload/logs").mkdir(mode=0o700)
                    (stage / "payload/logs/chunks").mkdir(mode=0o700)
                    _sync(stage / "payload/logs/chunks")
                    _sync(stage / "payload/logs")
                tx = {"schema": 1, "id": identifier, "owner": asdict(self.owner), "policy": asdict(self.policy),
                      "request_id": request_id, "scope": scope, "chunk_count": chunk_count, "total_bytes": total_bytes,
                      "object_count": count, "declared_count": 0, "declared_bytes": 0,
                      "state": "open", "pending": None, "seal_sha256": None}
                self._txsave(tx)
                for directory in (stage / "payload", stage / "objects", stage / "scratch", stage):
                    _sync(directory)
                _sync(self.root)
            _sync(stage)
            _save(active, {"id": identifier})
            return {"id": identifier, "state": tx["state"], "authenticated": False}

    def _object_path(self, tx, identifier):
        return self.root / tx["id"] / "objects" / (_uuid(identifier) + ".json")

    def _object(self, tx, identifier):
        value = _read(self._object_path(tx, identifier))
        _exact(value, ("id", "name", "bytes", "sha256", "identity", "offset", "pending", "state", "completed_identity"))
        self._entry(tx, {k: value[k] for k in ("name", "bytes", "sha256")})
        if value["id"] != identifier or self._object_id(tx, value["name"]) != identifier:
            raise Refused("Transfer object belongs to another input")
        if (type(value["identity"]) is not list or len(value["identity"]) != 2
                or any(type(v) is not int or v < 0 for v in value["identity"])
                or value["state"] not in ("receiving", "complete", "rejected")):
            raise Refused("Invalid transfer object state")
        _integer(value["offset"], 0, value["bytes"])
        if value["pending"] is not None:
            _exact(value["pending"], ("offset", "bytes", "sha256"))
            _integer(value["pending"]["offset"], 0, value["bytes"])
            _integer(value["pending"]["bytes"], 1, SEGMENT_BYTES)
            _sha(value["pending"]["sha256"])
            if (value["pending"]["offset"] != value["offset"]
                    or value["offset"] + value["pending"]["bytes"] > value["bytes"] or value["state"] != "receiving"):
                raise Refused("Invalid pending transfer range")
        if value["state"] == "complete":
            if (value["offset"] != value["bytes"] or value["pending"] is not None
                    or type(value["completed_identity"]) is not list or len(value["completed_identity"]) != 9
                    or any(type(v) is not int or v < 0 for v in value["completed_identity"])):
                raise Refused("Invalid completed transfer object")
        elif value["completed_identity"] is not None:
            raise Refused("Unexpected completed transfer identity")
        return value

    def _data(self, tx, entry):
        return self.root / tx["id"] / "payload" / entry["name"]

    def declare(self, identifier, metadata):
        with self._lock():
            tx = self._load(identifier)
            metadata = self._entry(tx, metadata)
            object_id = self._object_id(tx, metadata["name"])
            path = self._object_path(tx, object_id)
            if tx["state"] != "open":
                raise Refused("Sealed transfer inputs cannot be changed")
            if tx["pending"] is not None and tx["pending"] != metadata:
                raise Refused("Retry the exact unfinished object declaration")
            if tx["pending"] is None:
                if os.path.lexists(path):
                    existing = self._object(tx, object_id)
                    if any(existing[k] != v for k, v in metadata.items()):
                        raise Refused("Transfer object metadata cannot be replaced")
                    _sync(path.parent)
                    _sync(path.parent.parent)
                    return {"id": object_id, "name": metadata["name"]}
                if tx["declared_count"] >= tx["object_count"] or tx["declared_bytes"] + metadata["bytes"] > tx["total_bytes"]:
                    raise Refused("Transfer declaration exceeds aggregate bounds")
            self._capacity(OBJECT_OVERHEAD)
            if tx["pending"] is None:
                tx["pending"] = metadata
                self._txsave(tx)
            data = self._data(tx, metadata)
            if not os.path.lexists(data):
                with _opened(data, writable=True, create=True) as (fd, _):
                    os.fsync(fd)
                _sync(data.parent)
            with _opened(data) as (_, info):
                if info.st_size:
                    raise Refused("Unfinished object admission contains unexpected bytes")
                value = {"id": object_id, **metadata, "identity": _identity(info), "offset": 0,
                         "pending": None, "state": "receiving", "completed_identity": None}
            if os.path.lexists(path):
                if self._object(tx, object_id) != value:
                    raise Refused("Unfinished object admission changed")
            else:
                _save(path, value)
            _sync(data.parent)
            _sync(path.parent)
            tx["declared_count"] += 1
            tx["declared_bytes"] += metadata["bytes"]
            tx["pending"] = None
            self._txsave(tx)
            return {"id": object_id, "name": metadata["name"]}

    @contextmanager
    def _segment(self, tx, object_id, offset, length, checksum, stream):
        scratch = self.root / tx["id"] / "scratch"
        _directory(scratch, private=True)
        # One exact range name permits a complete scratch file to survive a
        # killed process without a separate unbounded segment ledger. Any
        # partial/different/extra scratch remains untouched and blocks progress.
        path = scratch / f"segment-{object_id}-{offset}-{checksum}"
        with os.scandir(scratch) as entries:
            names = [item.name for _, item in zip(range(2), entries)]
        if names and names != [path.name]:
            raise Refused("Uncertain transfer scratch is preserved for operator recovery")
        created, success, owned_identity = not names, False, None
        try:
            with _opened(path, writable=created, create=created) as (fd, before):
                owned_identity = _identity(before)
                if not created and (before.st_size != length or _range_hash(fd, 0, length) != checksum
                                    or _stable(os.fstat(fd)) != _stable(before)):
                    raise Refused("Uncertain scratch segment is incomplete or changed")
                digest, remaining, deadline = hashlib.sha256(), length, time.monotonic() + 30
                while remaining:
                    request = min(remaining, COPY_BYTES)
                    if time.monotonic() >= deadline:
                        raise Refused("Transfer segment exceeded its processing deadline")
                    value = stream.read(request)
                    if type(value) is not bytes or not 0 < len(value) <= request or time.monotonic() >= deadline:
                        raise Refused("Transfer segment is truncated, oversized or expired")
                    written = 0
                    while created and written < len(value):
                        count = os.write(fd, value[written:])
                        if count <= 0:
                            raise Refused("Transfer segment write did not progress")
                        written += count
                    digest.update(value)
                    remaining -= len(value)
                if stream.read(1) != b"" or digest.hexdigest() != checksum or time.monotonic() >= deadline:
                    raise Refused("Transfer segment length or hash differs")
                if not created and _stable(os.fstat(fd)) != _stable(before):
                    raise Refused("Pinned transfer scratch changed")
                os.fsync(fd)
                _sync(scratch)
                yield fd, path
                success = True
        finally:
            if (created or success) and owned_identity is not None:
                current = path.lstat()
                _private(current)
                if _identity(current) != owned_identity:
                    raise Refused("Transfer scratch path changed before cleanup")
                path.unlink(missing_ok=True)
                _sync(scratch)

    def _scratch_empty(self, tx):
        scratch = self.root / tx["id"] / "scratch"
        _directory(scratch, private=True)
        with os.scandir(scratch) as entries:
            if next(entries, None) is not None:
                raise Refused("Uncertain transfer scratch is preserved for operator recovery")

    def append(self, identifier, object_id, *, offset, length, sha256, stream):
        _integer(offset, 0, MAX_TOTAL)
        _integer(length, 1, SEGMENT_BYTES)
        _sha(sha256)
        with self._lock():
            tx = self._load(identifier)
            if tx["state"] != "open" or tx["pending"] is not None:
                raise Refused("Transfer is sealed or has unfinished object admission")
            entry = self._object(tx, object_id)
            # A fixed range grid makes retries exact without retaining a ledger
            # proportional to every segment of a multi-terabyte input.
            if offset % SEGMENT_BYTES or length != min(SEGMENT_BYTES, entry["bytes"] - offset):
                raise Refused("Transfer requires its exact fixed-size segment range")
            if entry["state"] == "rejected" or offset + length > entry["bytes"] or offset > entry["offset"]:
                raise Refused("Transfer range is not an allowed append or retry")
            pending = {"offset": offset, "bytes": length, "sha256": sha256}
            if entry["pending"] is not None and entry["pending"] != pending:
                raise Refused("Retry the exact unfinished transfer range")
            if offset < entry["offset"] and offset + length > entry["offset"]:
                raise Refused("Transfer retry overlaps unwritten bytes")
            self._capacity(2 * length + OBJECT_OVERHEAD)
            with self._segment(tx, object_id, offset, length, sha256, stream) as (segment, pinned):
                if entry["name"] == "recipient.pem":
                    certificate_envelope(pinned)
                elif entry["name"] == "recovery-key.pk8":
                    encrypted_key_parameters(pinned)
                path = self._data(tx, entry)
                with _opened(path, writable=True) as (fd, info):
                    if _identity(info) != entry["identity"]:
                        raise Refused("Transfer data file was replaced")
                    if entry["pending"] is not None:
                        # Full write with a lost checkpoint is recoverable. A
                        # partial or zero-byte uncertain write is not overwritten.
                        if info.st_size != offset + length or _range_hash(fd, offset, length) != sha256:
                            raise Refused("Uncertain transfer write requires preserved recovery evidence")
                    elif offset < entry["offset"]:
                        if info.st_size != entry["offset"] or _range_hash(fd, offset, length) != sha256:
                            raise Refused("Committed transfer retry differs from retained bytes")
                        os.fsync(fd)
                        _sync(path.parent)
                        _sync(self._object_path(tx, object_id).parent)
                        return {"id": object_id, "offset": entry["offset"], "retry": True}
                    else:
                        if entry["state"] != "receiving" or info.st_size != offset:
                            raise Refused("Transfer data length or state changed")
                        self._capacity(length + OBJECT_OVERHEAD)
                        entry["pending"] = pending
                        _save(self._object_path(tx, object_id), entry)
                        copied = 0
                        while copied < length:
                            value = os.pread(segment, min(COPY_BYTES, length - copied), copied)
                            if not value:
                                raise Refused("Pinned transfer segment was truncated")
                            written = os.pwrite(fd, value, offset + copied)
                            if written <= 0:
                                raise Refused("Transfer write did not progress")
                            copied += written
                    os.fsync(fd)
                    if os.fstat(fd).st_size != offset + length or _range_hash(fd, offset, length) != sha256:
                        raise Refused("Transfer write readback differs")
                _sync(path.parent)
                entry.update(offset=offset + length, pending=None)
                self._capacity(OBJECT_OVERHEAD)
                _save(self._object_path(tx, object_id), entry)
                return {"id": object_id, "offset": entry["offset"], "retry": False}

    def _verify(self, tx, entry, *, admission=False):
        if entry["pending"] is not None or entry["offset"] != entry["bytes"]:
            raise Refused("Recovery input is incomplete or has an uncertain write")
        path = self._data(tx, entry)
        with _opened(path) as (fd, before):
            if _identity(before) != entry["identity"] or before.st_size != entry["bytes"]:
                raise Refused("Recovery input identity or length changed")
            if entry["state"] == "complete" and list(_stable(before)) != entry["completed_identity"]:
                raise Refused("Completed recovery input changed")
            if _range_hash(fd, 0, before.st_size) != entry["sha256"]:
                raise Refused("Recovery input hash differs")
            if admission and entry["name"] in ("recipient.pem", "recovery-key.pk8"):
                scratch = self.root / tx["id"] / "scratch"
                self._scratch_empty(tx)
                descriptor, name = tempfile.mkstemp(prefix="credential-", dir=scratch)
                pinned = Path(name)
                try:
                    with os.fdopen(descriptor, "wb") as target:
                        raw = os.pread(fd, before.st_size + 1, 0)
                        if len(raw) != before.st_size:
                            raise Refused("Recovery credential changed")
                        target.write(raw)
                        target.flush()
                        os.fsync(target.fileno())
                    if entry["name"] == "recipient.pem":
                        certificate_envelope(pinned)
                    else:
                        encrypted_key_parameters(pinned)
                finally:
                    pinned.unlink(missing_ok=True)
                    _sync(scratch)
            if _stable(os.fstat(fd)) != _stable(before):
                raise Refused("Recovery input changed during verification")
            os.fsync(fd)
        _sync(path.parent)
        return list(_stable(before))

    def finalize_object(self, identifier, object_id):
        with self._lock():
            tx = self._load(identifier)
            if tx["state"] != "open" or tx["pending"] is not None:
                raise Refused("Transfer cannot finalize another input")
            entry = self._object(tx, object_id)
            if entry["state"] == "rejected":
                raise Refused("Rejected recovery input is preserved")
            self._capacity(OBJECT_OVERHEAD + (65536 if entry["name"] in ("recipient.pem", "recovery-key.pk8") else 0))
            identity = self._verify(tx, entry, admission=True)
            entry.update(state="complete", completed_identity=identity)
            self._capacity(OBJECT_OVERHEAD)
            _save(self._object_path(tx, object_id), entry)
            return {"id": object_id, "state": "complete", "authenticated": False}

    def _inventory(self, tx):
        stage = self.root / tx["id"]
        self._scratch_empty(tx)
        count = 0
        _directory(stage / "objects", private=True)
        with os.scandir(stage / "objects") as entries:
            for item in entries:
                count += 1
                if count > tx["object_count"] or not item.name.endswith(".json"):
                    raise Refused("Unexpected transfer object journal")
                _uuid(item.name[:-5])
        if count != tx["object_count"]:
            raise Refused("Missing transfer object journal")
        for path, expected in ((stage / "payload", {"configuration.cms", "recipient.pem", "recovery-key.pk8"}
                              | ({"logs"} if tx["scope"] == "full" else set())),):
            names = set()
            with os.scandir(path) as entries:
                for item in entries:
                    if len(names) >= len(expected) or item.name not in expected:
                        raise Refused("Unexpected transfer payload member")
                    names.add(item.name)
            if names != expected:
                raise Refused("Missing transfer payload member")
        if tx["scope"] == "full":
            logs = stage / "payload/logs"
            _directory(logs, private=True)
            _directory(logs / "chunks", private=True)
            with os.scandir(logs) as entries:
                names = [item.name for _, item in zip(range(3), entries)]
            if len(names) != 2 or set(names) != {"manifest.cms", "chunks"}:
                raise Refused("Unexpected log transfer layout")
            count = 0
            with os.scandir(logs / "chunks") as entries:
                for item in entries:
                    count += 1
                    if count > tx["chunk_count"] or not re.fullmatch(r"[0-9]{6}\.cms", item.name) or int(item.name[:6]) >= tx["chunk_count"]:
                        raise Refused("Unexpected encrypted log chunk")
            if count != tx["chunk_count"]:
                raise Refused("Missing encrypted log chunk")

    def seal(self, identifier):
        with self._lock():
            tx = self._load(identifier)
            if (tx["pending"] is not None or tx["declared_count"] != tx["object_count"]
                    or tx["declared_bytes"] != tx["total_bytes"]):
                raise Refused("Transfer inventory or aggregate bytes are incomplete")
            self._capacity(OBJECT_OVERHEAD)
            self._inventory(tx)
            digest = hashlib.sha256()
            total = 0
            for ordinal in range(tx["object_count"]):
                name = self._name(tx, ordinal)
                entry = self._object(tx, self._object_id(tx, name))
                if entry["state"] != "complete":
                    raise Refused("Transfer has an unfinished recovery input")
                self._verify(tx, entry)
                total += entry["bytes"]
                digest.update(_canonical({k: entry[k] for k in ("id", "name", "bytes", "sha256", "completed_identity")}))
                digest.update(b"\n")
            if total != tx["total_bytes"] or (tx["state"] == "sealed" and tx["seal_sha256"] != digest.hexdigest()):
                raise Refused("Recovery transfer seal changed")
            tx.update(state="sealed", seal_sha256=digest.hexdigest())
            self._capacity(OBJECT_OVERHEAD)
            self._txsave(tx)
            return {"id": identifier, "state": "sealed", "authenticated": False,
                    "coordinator_ready": False, "seal_sha256": tx["seal_sha256"]}

    def status(self, identifier, *, cursor=0, limit=PAGE_LIMIT):
        _integer(cursor, 0, MAX_OBJECTS)
        _integer(limit, 1, PAGE_LIMIT)
        with self._lock():
            tx = self._load(identifier)
            if cursor > tx["object_count"]:
                raise Refused("Transfer inventory cursor is out of range")
            end = min(cursor + limit, tx["object_count"])
            rows = []
            for ordinal in range(cursor, end):
                name = self._name(tx, ordinal)
                object_id = self._object_id(tx, name)
                if not os.path.lexists(self._object_path(tx, object_id)):
                    rows.append({"name": name, "state": "undeclared"})
                else:
                    entry = self._object(tx, object_id)
                    rows.append({"id": object_id, "name": name, "bytes": entry["bytes"], "offset": entry["offset"],
                                 "state": "uncertain" if entry["pending"] is not None else entry["state"]})
            return {"id": identifier, "state": tx["state"], "authenticated": False,
                    "observation": "Retained transfer journal; bytes require seal and coordinator verification",
                    "pending_admission": tx["pending"] is not None, "object_count": tx["object_count"],
                    "total_bytes": tx["total_bytes"], "declared_bytes": tx["declared_bytes"],
                    "objects": rows, "next_cursor": end if end < tx["object_count"] else None}
