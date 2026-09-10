"""Private, bounded job records; the default guard proves the encrypted mount.

There is deliberately no alternate public path/configuration or CLI entry point.
The injectable storage guard is a trusted test/integration boundary, not a claim
accepted from a request. Hashes detect corruption, not malicious root rollback.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat

from .common import Refused, atomic_json, require_linux_root
from .host_operations import uuid_value

ROOT_UID = 0
MAX_BYTES = 8 * 1024 * 1024
DATA = Path("/var/lib/nebulalog")


@dataclass(frozen=True)
class StorageIdentity:
    installation_id: str
    root: Path
    device: int


def encrypted_storage() -> StorageIdentity:
    require_linux_root()
    # Import lazily: constructing the data-only primitives must not probe a host.
    from .firstboot import FirstBoot
    result = FirstBoot().gate()
    if result.get("host_ready") is not True or result.get("setup_complete") is not True:
        raise Refused("host_setup_incomplete")
    for directory in (DATA, *DATA.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise Refused("unsafe_storage_ancestry")
    return StorageIdentity(uuid_value(result.get("installation_id")), DATA, DATA.stat().st_dev)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise Refused("invalid_record_shape")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refused("duplicate_record_key")
            result[key] = value
        return result

    def invalid(_):
        raise Refused("invalid_record_number")

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
        def depth(value, level=0):
            if level > 16:
                raise Refused("record_too_deep")
            if isinstance(value, dict):
                for item in value.values():
                    depth(item, level + 1)
            elif isinstance(value, list):
                for item in value:
                    depth(item, level + 1)
        depth(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Refused("invalid_record_json") from None


class PrivateRecords:
    def __init__(self, storage_guard=encrypted_storage):
        self.storage_guard = storage_guard

    def directory(self, path, identity, *, create=False):
        root = identity.root
        if (not root.is_absolute() or root != Path(os.path.normpath(root))
                or not path.is_relative_to(root)):
            raise Refused("unsafe_storage_path")
        for item in (root, *(root / Path(*path.relative_to(root).parts[:i])
                              for i in range(1, len(path.relative_to(root).parts) + 1))):
            if create and not item.exists() and not item.is_symlink():
                if item == root:
                    raise Refused("encrypted_storage_root_missing")
                item.mkdir(mode=0o700)
                parentfd = os.open(item.parent, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(parentfd)
                finally:
                    os.close(parentfd)
            info = item.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID
                    or stat.S_IMODE(info.st_mode) != 0o700 or info.st_dev != identity.device):
                raise Refused("unsafe_or_unencrypted_job_directory")

    @contextlib.contextmanager
    def locked(self, *, initialize=False):
        try:
            try:
                identity = self.storage_guard()
            except Exception:
                raise Refused("encrypted_storage_not_verified") from None
            if (type(identity) is not StorageIdentity or type(identity.device) is not int
                    or not isinstance(identity.root, Path)):
                raise Refused("invalid_storage_evidence")
            uuid_value(identity.installation_id)
            manager = identity.root / "manager"
            self.directory(manager, identity, create=initialize)
            path = manager / "transaction.lock"
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            try:
                info = os.fstat(fd)
                self._file(info, identity, allow_empty=True)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                state = manager / "jobs"
                marker = manager / "host-jobs-identity.json"
                if (marker.exists() or marker.is_symlink()) and not state.exists():
                    raise Refused("initialized_job_directory_missing")
                self.directory(state, identity, create=initialize)
                yield state, identity
            finally:
                os.close(fd)
        except BlockingIOError:
            raise Refused("manager_busy") from None
        except OSError:
            raise Refused("job_storage_unavailable") from None

    def _file(self, info, identity, *, allow_empty=False):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_dev != identity.device or not (0 if allow_empty else 1) <= info.st_size <= MAX_BYTES):
            raise Refused("unsafe_job_record")

    def read(self, path, identity):
        self.directory(path.parent, identity)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            self._file(before, identity)
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
            if len(raw) > MAX_BYTES or any(getattr(before, key) != getattr(after, key)
                                          for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
                raise Refused("job_record_changed")
        return strict_json(raw)

    def write(self, path, value, identity):
        self.directory(path.parent, identity)
        if path.exists() or path.is_symlink():
            self.read(path, identity)
        # atomic_json uses pretty JSON; account for its exact encoding before any write.
        size = len((json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode())
        if size > MAX_BYTES:
            raise Refused("job_journal_full")
        atomic_json(path, value)

    def confirm(self, state, identity):
        """Retry acknowledgement must also cover a prior failed directory fsync."""
        for path in (state / "ledger.json", state / "initial-pending.json", state.parent / "host-jobs-identity.json"):
            self.read(path, identity)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                self._file(os.fstat(fd), identity)
                os.fsync(fd)
            finally:
                os.close(fd)
        for path in (state, state.parent, identity.root):
            self.directory(path, identity)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
