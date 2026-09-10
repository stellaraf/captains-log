#!/usr/bin/env python3
"""Retain a verified, deterministic full-source tar and receipt; never run a build."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_application import open_source
from prepare_provenance import application_hash, git, publisher_inputs, sha
from stage_sources import captured, read_bounded, strict_json

MAX_FILES = 10000
MAX_FILE = 128 * 1024**2
MAX_BYTES = 512 * 1024**2
MAX_ARCHIVE = MAX_BYTES + MAX_FILES * 1024 + 10240
IDENTITY = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
PRIVATE_KEY = re.compile(rb"(?m)^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----\r?$")


def fingerprint(info):
    return tuple(getattr(info, name) for name in IDENTITY)


def source_files(manifest):
    files = manifest["files"]
    if not 1 <= len(files) <= MAX_FILES:
        raise ValueError("Captured source exceeds its file limit")
    for name in files:
        parts = name.lower().split("/")
        if (any(part in ("secrets", ".secrets", ".ssh", ".aws", ".npmrc", ".netrc", ".pypirc", ".git-credentials",
                         "__pycache__", "output", "node_modules", "dist", "test-results", "playwright-report", ".local", ".git") for part in parts)
                or any(part.startswith((".env", "id_rsa", "id_ed25519", "id_ecdsa")) for part in parts)
                or Path(name).suffix.lower() in (".pem", ".key", ".p12", ".pfx", ".jks", ".bcfks", ".pyc", ".pyo", ".qcow2", ".ova", ".iso")):
            raise ValueError("Captured source contains a generated or credential file")
        # Validate USTAR representability before creating any output.
        tar_info(name, 0).tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")
    return files


def tar_info(name, size):
    item = tarfile.TarInfo(name)
    item.size, item.mode = size, 0o644
    item.uid = item.gid = item.mtime = 0
    item.uname = item.gname = ""
    return item


def source_stat(root, name):
    """Inspect Git-listed paths without following either directory or leaf links."""
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None  # A captured tracked deletion has no source member.
    finally:
        os.close(directory)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 <= info.st_size <= MAX_FILE:
        raise ValueError("Source must remain bounded regular files without links")
    return fingerprint(info)


def repository_state(root, files, descriptor):
    if Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip()).resolve() != root:
        raise ValueError("Source must be the Git repository root")
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    status = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    raw = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if len(raw) > 8 * 1024**2 or len(status) > 8 * 1024**2:
        raise ValueError("Source inventory exceeds its limit")
    names = sorted(set(raw.split(b"\0")) - {b""})
    if len(names) > MAX_FILES:
        raise ValueError("Source inventory exceeds its file limit")
    observations = {}
    for raw_name in names:
        name = raw_name.decode("utf-8")
        if (not re.fullmatch(r"[A-Za-z0-9_@.-]+(?:/[A-Za-z0-9_@.-]+)*", name)
                or any(part in (".", "..", ".git", ".local", "node_modules") for part in name.split("/"))):
            raise ValueError("Unsafe or generated source inventory path")
        info = source_stat(root, name)
        if info is not None:
            observations[name] = info
    if set(observations) != set(files) or commit != descriptor["source_commit"] or bool(status) != descriptor["source_dirty"]:
        raise ValueError("Source inventory or Git identity changed after capture")
    if sum(info[2] for info in observations.values()) > MAX_BYTES:
        raise ValueError("Source exceeds its total byte limit")
    return commit, status, observations


def source_bytes(root, name, expected, observation):
    stream, before = open_source(root, name)
    with stream:
        if before.st_size > MAX_FILE or fingerprint(before) != observation:
            raise ValueError("Source changed before reading")
        raw = stream.read(MAX_FILE + 1)
        if len(raw) != before.st_size or fingerprint(os.fstat(stream.fileno())) != observation or sha(raw) != expected:
            raise ValueError("Source bytes changed after capture or during reading")
    if PRIVATE_KEY.search(raw):
        raise ValueError("Private key material is forbidden in a source archive")
    return raw


def _archive_evidence(path, files, publisher=None):
    """Verify every member and every tar byte, including canonical headers/padding."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ARCHIVE:
            raise ValueError("Source archive must be a bounded regular file")
        actual, total, members = hashlib.sha256(), 0, 0
        public_inputs = {}
        for name, expected in sorted(files.items()):
            header = stream.read(512)
            # Parse only the bounded octal size, then demand the exact USTAR
            # header before reading payload. Never let tarfile interpret PAX,
            # sparse, longname or other extension headers from an input tar.
            if len(header) != 512 or not re.fullmatch(rb"[0-7]{11}\x00", header[124:136]):
                raise ValueError("Source archive header is not canonical USTAR")
            size = int(header[124:135], 8)
            if size > MAX_FILE or header != tar_info(name, size).tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii"):
                raise ValueError("Source archive member inventory or metadata changed")
            total += size
            if total > MAX_BYTES:
                raise ValueError("Source archive exceeds its total byte limit")
            raw = stream.read(size)
            if len(raw) != size or sha(raw) != expected or PRIVATE_KEY.search(raw):
                raise ValueError("Source archive member bytes differ from capture")
            if name in (publisher_inputs.DESCRIPTOR_SOURCE, publisher_inputs.PUBLIC_SOURCE):
                if len(raw) > 16384:
                    raise ValueError("Archived publisher public inputs exceed their size limit")
                public_inputs[name] = raw
            padding = stream.read(-size % 512)
            if padding != b"\0" * (-size % 512):
                raise ValueError("Source archive member padding is not canonical")
            actual.update(header)
            actual.update(raw)
            actual.update(padding)
            members += 512 + size + len(padding)
        # Python's USTAR writer closes with two empty blocks, then a 10 KiB record.
        trailer_size = 1024 + (-(members + 1024) % tarfile.RECORDSIZE)
        trailer = stream.read(trailer_size)
        actual.update(trailer)
        expected_size = members + trailer_size
        if (trailer != b"\0" * trailer_size or stream.read(1) or before.st_size != expected_size
                or fingerprint(before) != fingerprint(os.fstat(stream.fileno()))
                or fingerprint(before) != fingerprint(path.lstat())):
            raise ValueError("Source archive changed or is not canonical USTAR")
    if publisher is not None:
        publisher_inputs.validate(publisher, files, *(public_inputs.get(name) for name in
                                  (publisher_inputs.DESCRIPTOR_SOURCE, publisher_inputs.PUBLIC_SOURCE)))
    return {"archive_sha256": actual.hexdigest(), "archive_bytes": expected_size,
            "source_bytes": total, "source_files": len(files)}


def receipt_record(manifest, descriptor, source, release, evidence):
    return {"schema": 1, "purpose": "captured-complete-source-archive", "archive_format": "ustar",
            "source_snapshot_sha256": sha(source), "initial_release_sha256": sha(release),
            "source_commit": descriptor["source_commit"], "source_dirty": descriptor["source_dirty"],
            "application_source_sha256": application_hash(manifest), **evidence,
            "runtime_executed": False, "signature_created": False}


def receipt_path(output):
    return output.with_name(output.name + ".receipt.json")


def verify(output, provenance):
    if output.is_symlink() or provenance.is_symlink():
        raise ValueError("Archive and provenance cannot be symlinks")
    receipt = receipt_path(output)
    identities = {}
    for path in (output, receipt):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400 or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError("Source archive and receipt must remain owned read-only regular files")
        identities[path] = fingerprint(info)
    manifest, descriptor, source, release = captured(provenance)
    files = source_files(manifest)
    evidence = _archive_evidence(output, files, descriptor["publisher"])
    record = strict_json(read_bounded(receipt.parent, receipt.name, 16384))
    wanted = receipt_record(manifest, descriptor, source, release, evidence)
    if (not isinstance(record, dict) or record != wanted
            or any(type(record[name]) is not type(value) for name, value in wanted.items())):
        raise ValueError("Source archive receipt differs from verified capture")
    if (any(fingerprint(path.lstat()) != identity for path, identity in identities.items())
            or captured(provenance) != (manifest, descriptor, source, release)):
        raise ValueError("Source archive, receipt or provenance changed during verification")
    return {"status": "verified", **wanted}


def archive_sources(root, provenance, output):
    if root.is_symlink() or provenance.is_symlink() or output.suffix != ".tar":
        raise ValueError("Use regular source/provenance roots and a new .tar destination")
    root, provenance = root.resolve(strict=True), provenance.resolve(strict=True)
    output = output.parent.resolve(strict=True) / output.name
    receipt = receipt_path(output)
    if any(path.exists() or path.is_symlink() for path in (output, receipt)):
        raise ValueError("Archive and adjacent receipt must be exclusive new files")
    manifest, descriptor, source, release = captured(provenance)
    files = source_files(manifest)
    root_identity = fingerprint(root.stat())[:2]
    state = repository_state(root, files, descriptor)
    with tempfile.TemporaryDirectory(prefix=".nebulalog-source-archive-", dir=output.parent) as temporary:
        staged = Path(temporary) / "source.tar"
        with staged.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT, encoding="ascii") as archive:
                for name, expected in sorted(files.items()):
                    raw = source_bytes(root, name, expected, state[2][name])
                    archive.addfile(tar_info(name, len(raw)), io.BytesIO(raw))
            stream.flush()
            os.fsync(stream.fileno())
        evidence = _archive_evidence(staged, files, descriptor["publisher"])
        # Re-read all source bytes, then compare the complete inventory and file
        # identities again so edits to already copied files also refuse publish.
        for name, expected in sorted(files.items()):
            source_bytes(root, name, expected, state[2][name])
        record = receipt_record(manifest, descriptor, source, release, evidence)
        staged_receipt = Path(temporary) / "receipt.json"
        with staged_receipt.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o400)
            stream.write((json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        staged.chmod(0o400)
        if (captured(provenance) != (manifest, descriptor, source, release)
                or fingerprint(root.lstat())[:2] != root_identity or root.is_symlink()
                or repository_state(root, files, descriptor) != state):
            raise ValueError("Source or provenance changed while archiving")
        os.link(staged, output)  # Exclusive publication; never replace a path.
        # If this second exclusive link fails, retain the fully verified tar.
        # Pathname rollback could delete a competing writer's replacement. An
        # archive without a matching verified receipt must not be accepted.
        os.link(staged_receipt, receipt)
    directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return verify(output, provenance)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)
    if args.verify_only == (args.source is not None):
        parser.error("Supply --source to archive, or --verify-only without --source")
    try:
        result = verify(args.output, args.provenance) if args.verify_only else archive_sources(args.source, args.provenance, args.output)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError, publisher_inputs.Refused):
        print(json.dumps({"status": "refused", "error": "Full-source archive or capture verification failed; require a verified archive and adjacent receipt"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
