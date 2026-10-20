"""Bounded CMS transport for a native log snapshot linked to a configuration backup.

This module never snapshots a database, restores a table, or opens listeners. A
coordinator must supply verified native evidence and retain the storage hold. The
encrypted manifest is published last; its absence means an incomplete export.
Each chunk is definite DER AuthEnvelopedData, keeping OpenSSL memory bounded
without accepting a second, indefinite BER format. Native qualification remains
separate from these filesystem/cryptographic transport checks.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid

from .backup import ROOT_UID, _directory, _encrypted_staging
from .common import Refused, require_linux_root, run, trusted_file
from .host_payload import strict_json
from .updates import digest_file

CHUNK_BYTES = 256 * 1024**2
MAX_CHUNKS = 262144
MANIFEST_BYTES = 64 * 1024**2
ENVELOPE_OVERHEAD = 65536
COPY_BYTES = 1024**2
RESERVE_BYTES = 1024**3
SHA = re.compile(r"[a-f0-9]{64}")
IMAGE = re.compile(r"[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}")
IMAGE_KEYS = {"NEBULALOG_IMAGE", "POSTGRESQL_IMAGE", "CLICKHOUSE_IMAGE", "KEYCLOAK_FIPS_IMAGE"}
FORMAT = "captains-log-native-recovery-set-v1"


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise Refused("Log recovery metadata has an invalid identity") from None


def _hash(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise Refused("Log recovery metadata has an invalid digest")


def _size(value, maximum):
    if type(value) is not int or not 0 < value <= maximum:
        raise Refused("Log recovery size is outside its bounded format")


def validate_link(link):
    """The exact source/configuration/runtime binding required at both ends."""
    if not isinstance(link, dict) or set(link) != {"source_installation_id", "configuration_backup", "runtime"}:
        raise Refused("Log recovery requires its configuration recovery-set binding")
    _uuid(link["source_installation_id"])
    configuration = link["configuration_backup"]
    if not isinstance(configuration, dict) or set(configuration) != {"sha256", "bytes"}:
        raise Refused("Log recovery requires the exact encrypted configuration backup")
    _hash(configuration["sha256"])
    _size(configuration["bytes"], 21 * 1024**3)
    runtime = link["runtime"]
    if (not isinstance(runtime, dict) or set(runtime) != {"images", "schema_revision"}
            or not isinstance(runtime["schema_revision"], str)
            or not re.fullmatch(r"[1-9][0-9]{0,5}", runtime["schema_revision"])
            or not isinstance(runtime["images"], dict) or set(runtime["images"]) != IMAGE_KEYS
            or any(not isinstance(pin, str) or not IMAGE.fullmatch(pin) for pin in runtime["images"].values())):
        raise Refused("Log recovery runtime must contain the exact immutable image pins and schema")


def validate_metadata(metadata):
    if not isinstance(metadata, dict) or set(metadata) != {"link", "native", "archive"}:
        raise Refused("Invalid native log recovery metadata")
    validate_link(metadata["link"])
    native = metadata["native"]
    keys = {"table", "server_version", "table_uuid", "backup_id", "query_id", "started_at", "finished_at",
            "table_definition_sha256", "retention_policy_revision"}
    if not isinstance(native, dict) or set(native) != keys or native["table"] != "nebulalog.events":
        raise Refused("Only the fixed native events table belongs in this recovery set")
    for key in ("table_uuid", "backup_id", "query_id"):
        _uuid(native[key])
    if not isinstance(native["server_version"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", native["server_version"]):
        raise Refused("Invalid native backup version")
    from datetime import datetime
    times = []
    for key in ("started_at", "finished_at"):
        try:
            value = native[key]
            if not isinstance(value, str) or len(value) > 40:
                raise ValueError
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            times.append(parsed)
        except (ValueError, TypeError):
            raise Refused("Native snapshot times must include their timezone") from None
    if times[1] < times[0]:
        raise Refused("Native snapshot completion precedes dispatch")
    _hash(native["table_definition_sha256"])
    _size(native["retention_policy_revision"], 2**63 - 1)
    archive = metadata["archive"]
    if not isinstance(archive, dict) or set(archive) != {"format", "sha256", "bytes"} or archive["format"] != "clickhouse-native-tar":
        raise Refused("Invalid native log archive format")
    _hash(archive["sha256"])
    _size(archive["bytes"], CHUNK_BYTES * MAX_CHUNKS)


def _file(path, maximum, *, native=False):
    info = path.lstat()
    owners = {ROOT_UID, 101} if native else {ROOT_UID}
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or info.st_nlink != 1
            or info.st_mode & (0o022 if native else 0o077)):
        raise Refused("Recovery inputs must be private regular files with no links")
    _size(info.st_size, maximum)
    return info


def _identity(info):
    # Reading is permitted to advance atime; content/ownership identity is not.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _names(path, maximum):
    names = set()
    with os.scandir(path) as entries:
        for entry in entries:
            if len(names) >= maximum:
                raise Refused("Log recovery directory exceeds its inventory budget")
            names.add(entry.name)
    return names


def _copy_bounded(source, target, original, maximum):
    """Pin bytes before a subprocess opens them; never trust a prior path stat."""
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as incoming, target.open("xb") as outgoing:
        os.fchmod(outgoing.fileno(), 0o600)
        if _identity(os.fstat(incoming.fileno())) != _identity(original):
            raise Refused("Recovery input changed before it was pinned")
        remaining = original.st_size
        if not 0 < remaining <= maximum:
            raise Refused("Recovery input exceeds its copy budget")
        while remaining:
            data = incoming.read(min(remaining, COPY_BYTES))
            if not data:
                raise Refused("Recovery input was truncated while being pinned")
            outgoing.write(data)
            remaining -= len(data)
        if (incoming.read(1) or _identity(os.fstat(incoming.fileno())) != _identity(original)
                or _identity(source.lstat()) != _identity(original)):
            raise Refused("Recovery input changed while being pinned")


def _digest_bounded(source, original, maximum):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    value = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as incoming:
        if _identity(os.fstat(incoming.fileno())) != _identity(original) or not 0 < original.st_size <= maximum:
            raise Refused("Recovery input changed before hash admission")
        remaining = original.st_size
        while remaining:
            data = incoming.read(min(remaining, COPY_BYTES))
            if not data:
                raise Refused("Recovery input was truncated during hash admission")
            value.update(data)
            remaining -= len(data)
        if (incoming.read(1) or _identity(os.fstat(incoming.fileno())) != _identity(original)
                or _identity(source.lstat()) != _identity(original)):
            raise Refused("Recovery input changed during hash admission")
    return value.hexdigest()


def _fsync(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish(pending, target):
    _fsync(pending)
    os.link(pending, target, follow_symlinks=False)
    _fsync(target.parent)


class LogRecoverySet:
    def __init__(self, commands=run):
        self.cmd = commands

    def _workspace(self, staging):
        require_linux_root()
        _encrypted_staging(staging, self.cmd)
        _directory(staging, private=True)

    def _credential(self, path, work, name, *, certificate=False, check_expiry=True):
        _directory(path.parent)
        trusted_file(path)
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022
                or info.st_nlink != 1 or not certificate and info.st_mode & 0o077):
            raise Refused("Recovery keys must be private and credentials must not be linked")
        _size(info.st_size, 65536)
        target = work / name
        _copy_bounded(path, target, info, 65536)
        if certificate and check_expiry:
            self.cmd(["openssl", "x509", "-in", str(target), "-noout", "-checkend", "0"])
        return target

    def _encrypt(self, plain, target, certificate):
        from .backup import cms_encrypt_command
        self.cmd(cms_encrypt_command(plain, target, certificate), timeout=3600)
        target.chmod(0o600)
        _file(target, plain.stat().st_size + ENVELOPE_OVERHEAD)
        from .configuration_restore import authenticated_cms
        authenticated_cms(target)
        _fsync(target)

    def _decrypt(self, encrypted, plain, certificate, key, maximum, *, expected=None):
        info = _file(encrypted, maximum + ENVELOPE_OVERHEAD)
        from .configuration_restore import authenticated_cms
        pinned = plain.parent / "encrypted-input.cms"
        try:
            _copy_bounded(encrypted, pinned, info, maximum + ENVELOPE_OVERHEAD)
            if expected is not None and (info.st_size != expected["encrypted_bytes"]
                    or _digest_bounded(pinned, pinned.lstat(), maximum + ENVELOPE_OVERHEAD) != expected["encrypted_sha256"]):
                raise Refused("Pinned log ciphertext differs from its manifest")
            authenticated_cms(pinned)
            # OpenSSL can emit plaintext before discovering a bad tag. The target
            # is private encrypted scratch and is not consumed on command failure.
            self.cmd(["openssl", "cms", "-decrypt", "-binary", "-inform", "DER", "-in", str(pinned),
                      "-recip", str(certificate), "-inkey", str(key), "-out", str(plain)], timeout=3600)
            plain.chmod(0o600)
            _file(plain, maximum)
        finally:
            pinned.unlink(missing_ok=True)

    def seal(self, archive, output, recipient_certificate, staging, metadata, *, checkpoint=None):
        """Export ciphertext chunks; source native archive is retained unchanged."""
        self._workspace(staging)
        validate_metadata(metadata)
        if output.exists() or output.is_symlink() or output.is_relative_to(staging):
            raise Refused("Recovery-set output must be new and outside plaintext scratch")
        _directory(output.parent)
        _encrypted_staging(archive.parent, self.cmd)
        original = _file(archive, CHUNK_BYTES * MAX_CHUNKS, native=True)
        if original.st_size != metadata["archive"]["bytes"]:
            raise Refused("Native archive size differs from its terminal evidence")
        count = (original.st_size + CHUNK_BYTES - 1) // CHUNK_BYTES
        ciphertext_space = original.st_size + count * ENVELOPE_OVERHEAD + MANIFEST_BYTES
        scratch_space = CHUNK_BYTES + MANIFEST_BYTES + RESERVE_BYTES
        if staging.stat().st_dev == output.parent.stat().st_dev:
            scratch_space += ciphertext_space
        if (shutil.disk_usage(staging).free < scratch_space
                or shutil.disk_usage(output.parent).free < ciphertext_space + RESERVE_BYTES):
            raise Refused("Insufficient space for the encrypted log recovery set")
        output.mkdir(mode=0o700)  # Never overwrite, including a partial prior export.
        (output / "chunks").mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="log-seal-", dir=staging) as temporary:
            work = Path(temporary)
            certificate = self._credential(recipient_certificate, work, "recipient.pem", certificate=True)
            from .backup import probe_recipient
            probe_recipient(certificate, work, self.cmd)
            whole = hashlib.sha256()
            entries = []
            descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as source:
                if _identity(os.fstat(source.fileno())) != _identity(original):
                    raise Refused("Native archive changed before encryption")
                for index in range(count):
                    plain = work / "chunk"
                    part_hash = hashlib.sha256()
                    remaining = min(CHUNK_BYTES, original.st_size - index * CHUNK_BYTES)
                    size = remaining
                    with plain.open("xb") as target:
                        os.fchmod(target.fileno(), 0o600)
                        while remaining:
                            data = source.read(min(remaining, COPY_BYTES))
                            if not data:
                                raise Refused("Native archive was truncated during encryption")
                            target.write(data)
                            whole.update(data)
                            part_hash.update(data)
                            remaining -= len(data)
                    encrypted = output / "chunks" / (f"{index:06d}.cms")
                    self._encrypt(plain, encrypted, certificate)
                    entries.append({"index": index, "bytes": size, "sha256": part_hash.hexdigest(),
                                    "encrypted_bytes": encrypted.stat().st_size, "encrypted_sha256": digest_file(encrypted)})
                    plain.unlink()
                if (source.read(1) or _identity(os.fstat(source.fileno())) != _identity(original)
                        or _identity(archive.lstat()) != _identity(original)):
                    raise Refused("Native archive changed during encryption")
            if whole.hexdigest() != metadata["archive"]["sha256"]:
                raise Refused("Native archive hash differs from its terminal evidence")
            manifest = {"format": FORMAT, "chunk_bytes": CHUNK_BYTES, "metadata": metadata, "chunks": entries}
            plain = work / "manifest.json"
            with plain.open("x") as target:
                os.fchmod(target.fileno(), 0o600)
                json.dump(manifest, target, sort_keys=True, separators=(",", ":"), allow_nan=False)
            _file(plain, MANIFEST_BYTES)
            pending = output / ".manifest.pending"
            self._encrypt(plain, pending, certificate)
            _fsync(output / "chunks")
            if checkpoint is not None:
                # The coordinator durably retains this private receipt before
                # publication. After a crash it can verify the exact exported
                # bytes without possessing the offline recovery private key.
                checkpoint({"schema": 1, "format": FORMAT, "metadata": metadata,
                    "manifest": {"bytes": pending.stat().st_size, "sha256": digest_file(pending)},
                    "chunks": [{"index": e["index"], "bytes": e["encrypted_bytes"],
                                "sha256": e["encrypted_sha256"]} for e in entries]})
            _publish(pending, output / "manifest.cms")
            pending.unlink()
            _fsync(output)
            _fsync(output.parent)  # Make the new recovery-set directory durable.
        return {"format": FORMAT, "complete": True, "chunks": count, "archive_bytes": original.st_size,
                "manifest_sha256": digest_file(output / "manifest.cms"), "native_qualified": False}

    def inspect_sealed(self, source, receipt, expected_metadata):
        """Verify publication against a coordinator-owned private seal receipt.

        This is ciphertext readback, not a decryption/restore test. The caller
        must load the receipt from its protected transaction journal; arbitrary
        exported receipt files are never recovery authority.
        """
        require_linux_root()
        validate_metadata(expected_metadata)
        if (not isinstance(receipt, dict) or set(receipt) != {"schema", "format", "metadata", "manifest", "chunks"}
                or type(receipt["schema"]) is not int or receipt["schema"] != 1
                or receipt["format"] != FORMAT or receipt["metadata"] != expected_metadata):
            raise Refused("Sealed recovery receipt does not belong to this native snapshot")
        _directory(source, private=True)
        _directory(source / "chunks", private=True)
        count = (expected_metadata["archive"]["bytes"] + CHUNK_BYTES - 1) // CHUNK_BYTES
        entries = receipt["chunks"]
        if not isinstance(entries, list) or len(entries) != count:
            raise Refused("Sealed recovery receipt has an incomplete chunk inventory")
        if (_names(source, 2) != {"chunks", "manifest.cms"}
                or _names(source / "chunks", count) != {f"{i:06d}.cms" for i in range(count)}):
            raise Refused("Sealed recovery publication is incomplete or has unexpected files")
        records = [(source / "manifest.cms", receipt["manifest"], MANIFEST_BYTES + ENVELOPE_OVERHEAD)]
        for index, entry in enumerate(entries):
            if (not isinstance(entry, dict) or set(entry) != {"index", "bytes", "sha256"}
                    or type(entry["index"]) is not int or entry["index"] != index):
                raise Refused("Sealed recovery chunk order is invalid")
            bound = min(CHUNK_BYTES, expected_metadata["archive"]["bytes"] - index * CHUNK_BYTES) + ENVELOPE_OVERHEAD
            records.append((source / "chunks" / f"{index:06d}.cms",
                            {"bytes": entry["bytes"], "sha256": entry["sha256"]}, bound))
        for path, record, bound in records:
            if not isinstance(record, dict) or set(record) != {"bytes", "sha256"}:
                raise Refused("Sealed recovery file receipt is invalid")
            _hash(record["sha256"])
            _size(record["bytes"], bound)
            info = _file(path, bound)
            if info.st_size != record["bytes"] or _digest_bounded(path, info, bound) != record["sha256"]:
                raise Refused("Sealed recovery ciphertext differs from its retained receipt")
            _fsync(path)
        # Resume may observe a clean namespace after the publish/unlink calls
        # but before seal's final barriers completed. Reestablish durability
        # before this readback can authorize releasing the native storage hold.
        _fsync(source / "chunks")
        _fsync(source)
        _fsync(source.parent)
        return {"format": FORMAT, "complete": True, "chunks": count,
                "archive_bytes": expected_metadata["archive"]["bytes"],
                "manifest_sha256": receipt["manifest"]["sha256"], "native_qualified": False}

    def unseal(self, source, output, certificate, private_key, staging, expected_link):
        """Return a fully verified native archive on encrypted scratch; no SQL."""
        self._workspace(staging)
        validate_link(expected_link)
        _directory(source, private=True)
        _directory(source / "chunks", private=True)
        _directory(output.parent, private=True)
        if not output.is_relative_to(staging) or output.exists() or output.is_symlink():
            raise Refused("Recovered log archive must be new and inside encrypted scratch")
        if _names(source, 2) != {"chunks", "manifest.cms"}:
            raise Refused("Log recovery set is incomplete or has unexpected files")
        with tempfile.TemporaryDirectory(prefix="log-unseal-", dir=staging) as temporary:
            work = Path(temporary)
            cert = self._credential(certificate, work, "recipient.pem", certificate=True, check_expiry=False)
            key = self._credential(private_key, work, "recipient.key")
            manifest_path = work / "manifest.json"
            self._decrypt(source / "manifest.cms", manifest_path, cert, key, MANIFEST_BYTES)
            manifest = strict_json(manifest_path.read_bytes())
            if (not isinstance(manifest, dict) or set(manifest) != {"format", "chunk_bytes", "metadata", "chunks"}
                    or manifest["format"] != FORMAT or type(manifest["chunk_bytes"]) is not int or manifest["chunk_bytes"] != CHUNK_BYTES):
                raise Refused("Unsupported log recovery transport format")
            metadata = manifest["metadata"]
            validate_metadata(metadata)
            if metadata["link"] != expected_link:
                raise Refused("Log backup belongs to a different configuration backup or runtime")
            entries = manifest["chunks"]
            size = metadata["archive"]["bytes"]
            count = (size + CHUNK_BYTES - 1) // CHUNK_BYTES
            if not isinstance(entries, list) or len(entries) != count:
                raise Refused("Log recovery chunk inventory is incomplete")
            expected_files = {f"{index:06d}.cms" for index in range(count)}
            if _names(source / "chunks", count) != expected_files:
                raise Refused("Log recovery chunk directory differs from its manifest")
            for index, entry in enumerate(entries):
                if (not isinstance(entry, dict) or set(entry) != {"index", "bytes", "sha256", "encrypted_bytes", "encrypted_sha256"}
                        or type(entry["index"]) is not int or entry["index"] != index
                        or type(entry["bytes"]) is not int or entry["bytes"] != min(CHUNK_BYTES, size - index * CHUNK_BYTES)):
                    raise Refused("Log recovery chunk order or size is invalid")
                _hash(entry["sha256"])
                _hash(entry["encrypted_sha256"])
                _size(entry["encrypted_bytes"], entry["bytes"] + ENVELOPE_OVERHEAD)
                chunk = source / "chunks" / f"{index:06d}.cms"
                info = _file(chunk, entry["bytes"] + ENVELOPE_OVERHEAD)
                if (info.st_size != entry["encrypted_bytes"]
                        or _digest_bounded(chunk, info, entry["bytes"] + ENVELOPE_OVERHEAD) != entry["encrypted_sha256"]):
                    raise Refused("Encrypted log chunk differs from its manifest")
            if shutil.disk_usage(staging).free < size + 2 * CHUNK_BYTES + 2 * MANIFEST_BYTES + ENVELOPE_OVERHEAD + RESERVE_BYTES:
                raise Refused("Insufficient encrypted scratch for log recovery")
            pending = work / "archive.tar"
            whole = hashlib.sha256()
            with pending.open("xb") as target:
                os.fchmod(target.fileno(), 0o600)
                for index, entry in enumerate(entries):
                    plain = work / "chunk"
                    self._decrypt(source / "chunks" / f"{index:06d}.cms", plain, cert, key, entry["bytes"], expected=entry)
                    if plain.stat().st_size != entry["bytes"] or digest_file(plain) != entry["sha256"]:
                        raise Refused("Decrypted log chunk differs from its manifest")
                    with plain.open("rb") as incoming:
                        while data := incoming.read(COPY_BYTES):
                            target.write(data)
                            whole.update(data)
                    plain.unlink()
                target.flush()
                os.fsync(target.fileno())
            if pending.stat().st_size != size or whole.hexdigest() != metadata["archive"]["sha256"]:
                raise Refused("Recovered native archive failed its complete-file check")
            _publish(pending, output)
            pending.unlink()
            _fsync(work)  # Persist the old link removal before reporting success.
            _fsync(output)
            _fsync(output.parent)
        return {"metadata": metadata, "archive": str(output), "verified": True, "native_restored": False}
