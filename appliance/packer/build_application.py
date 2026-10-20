#!/usr/bin/env python3
"""Build the appliance application from its exact captured source, never cwd."""
from __future__ import annotations

import argparse
import hashlib
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
from prepare_provenance import application_hash, source_snapshot

CONTAINERFILE = "appliance/images/application/Containerfile"
REQUIRED = {CONTAINERFILE, "go.mod", "go.sum", "LICENSE", "cmd/nebulalog/main.go", "web/package.json", "web/package-lock.json"}
MAX_FILE = 128 * 1024**2
MAX_CONTEXT = 512 * 1024**2
MAX_FILES = 20000
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,100})?")
TAG = re.compile(r"nebulalog/[a-z0-9]+(?:[._-][a-z0-9]+)*:[a-z0-9][a-z0-9._-]{0,100}")


def selected_files(manifest):
    files = manifest["files"]
    selected = {path: sha for path, sha in files.items()
                if path.startswith(("cmd/", "internal/", "web/", "migrations/"))
                or path in ("go.mod", "go.sum", "LICENSE", CONTAINERFILE)}
    if (not REQUIRED <= set(selected) or not any(path.startswith("internal/") for path in selected)
            or not any(path.startswith("migrations/") for path in selected) or not 1 <= len(selected) <= MAX_FILES):
        raise ValueError("Captured application source is incomplete or exceeds the file limit")
    for path, sha in selected.items():
        parts = path.split("/")
        if (not re.fullmatch(r"[A-Za-z0-9_@.-]+(?:/[A-Za-z0-9_@.-]+)*", path)
                or any(part in (".", "..", ".git", ".local", "node_modules", "dist", "test-results", "playwright-report") for part in parts)
                or any(part.startswith(".env") for part in parts)
                or any(part in (".npmrc", ".netrc", ".pypirc", ".git-credentials", ".ssh", ".aws") for part in parts)
                or Path(path).suffix.lower() in (".pem", ".key", ".p12", ".pfx", ".jks")
                or not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha)):
            raise ValueError("Captured application source contains an unsafe, generated or credential file")
    if application_hash({"files": selected}) != application_hash(manifest):
        raise ValueError("Application context selection no longer matches the provenance contract")
    return selected


def open_source(root, name):
    """Use directory descriptors so a symlink replacement cannot escape root."""
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= MAX_FILE:
        os.close(descriptor)
        raise ValueError("Captured source must remain a bounded regular file")
    return os.fdopen(descriptor, "rb"), info


class HashingReader:
    def __init__(self, source):
        self.source, self.digest, self.bytes = source, hashlib.sha256(), 0

    def read(self, size):
        value = self.source.read(size)
        self.digest.update(value)
        self.bytes += len(value)
        return value


def write_context(root: Path, selected: dict, destination: Path):
    """Finish the full, byte-verified context before Docker sees any input."""
    selected = selected_files({"files": selected})
    total = 0
    with destination.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, expected in sorted(selected.items()):
                source, before = open_source(root, name)
                with source:
                    total += before.st_size
                    if total > MAX_CONTEXT:
                        raise ValueError("Application context exceeds its byte limit")
                    item = tarfile.TarInfo(name)
                    item.size, item.mode = before.st_size, 0o644
                    item.uid = item.gid = item.mtime = 0
                    item.uname = item.gname = ""
                    reader = HashingReader(source)
                    archive.addfile(item, reader)
                    after = os.fstat(source.fileno())
                    if (reader.bytes != before.st_size or reader.digest.hexdigest() != expected or source.read(1)
                            or any(getattr(before, key) != getattr(after, key) for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
                        raise ValueError("Application source changed after capture or while creating context")
                    if output.tell() > MAX_CONTEXT:
                        raise ValueError("Application tar context exceeds its byte limit")
        if output.tell() > MAX_CONTEXT:
            raise ValueError("Application tar context exceeds its byte limit")
        output.flush()
        os.fsync(output.fileno())
    digest = hashlib.sha256()
    with destination.open("rb") as source:
        for chunk in iter(lambda: source.read(1024**2), b""):
            digest.update(chunk)
    return {"context_sha256": digest.hexdigest(), "context_bytes": destination.stat().st_size,
            "source_bytes": total, "source_files": len(selected)}


def write_receipt(path, receipt):
    """Publish once; a failed build never overwrites previous evidence."""
    raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    fd, name = tempfile.mkstemp(prefix=".application-build-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(name, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.unlink(name)


def build(source: Path, tag: str, receipt: Path, *, version="0.2.0-appliance-candidate", runner=subprocess.run):
    if not isinstance(tag, str) or len(tag) > 200 or not TAG.fullmatch(tag):
        raise ValueError("Use an explicit local nebulalog/name:tag; registry addresses and options are refused")
    if not isinstance(version, str) or len(version) > 128 or not VERSION.fullmatch(version):
        raise ValueError("Application version must be a bounded semantic version without shell characters")
    source, receipt = source.resolve(), receipt.absolute()
    if receipt.exists() or receipt.is_symlink():
        raise ValueError("Build receipt must be a new file")
    receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest, commit, dirty = source_snapshot(source)
    selected = selected_files(manifest)
    source_sha = application_hash(manifest)
    # Docker receives a completed private tar as stdin, not the source directory.
    # No .dockerignore, live workspace files, SSH keys or secret flags are added.
    # Keep the captured context beside its requested receipt on build storage,
    # even when the invoking shell has a system/default TMPDIR. Only this
    # invocation's context is removed; Docker's shared cache is not ours.
    with tempfile.TemporaryDirectory(prefix="nebulalog-application-build-", dir=receipt.parent) as temporary:
        stage = Path(temporary)
        context, iid = stage / "context.tar", stage / "image.id"
        evidence = write_context(source, selected, context)
        command = ["docker", "build", "--platform=linux/amd64", "--progress=plain", "--tag", tag,
                   "--file", CONTAINERFILE, "--iidfile", str(iid), "--build-arg", "APPLICATION_SOURCE_SHA256=" + source_sha,
                   "--build-arg", "VERSION=" + version, "-"]
        with context.open("rb") as stream:
            runner(command, stdin=stream, stdout=sys.stderr, stderr=sys.stderr, check=True, timeout=3600)
        if iid.is_symlink() or not iid.is_file() or iid.stat().st_size > 128:
            raise ValueError("Docker did not produce a bounded regular immutable image ID")
        image_id = iid.read_text().strip()
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
            raise ValueError("Docker did not produce a valid immutable image ID")
        result = runner(["docker", "image", "inspect", image_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
        if len(result.stdout) > 1024**2:
            raise ValueError("Oversized built image metadata")
        images = json.loads(result.stdout)
        if (not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict)
                or images[0].get("Id") != image_id or images[0].get("Architecture") != "amd64" or images[0].get("Os") != "linux"
                or not isinstance(images[0].get("Config"), dict) or not isinstance(images[0]["Config"].get("Labels"), dict)
                or images[0].get("Config", {}).get("Labels", {}).get("io.nebulalog.application-source-sha256") != source_sha):
            raise ValueError("Built image identity, platform or source label differs from the captured context")
        result = {"schema": 1, "status": "built", "tag": tag, "local_image_id": image_id, "platform": "linux/amd64",
                  "requested_version": version, "application_source_sha256": source_sha, "source_commit": commit,
                  "source_dirty": dirty, "application_files": selected, **evidence,
                  "context_mode": "captured_source_tar_stdin", "runtime_executed": False, "signature_created": False}
        write_receipt(receipt, result)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--version", default="0.2.0-appliance-candidate")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build(args.source, args.tag, args.receipt, version=args.version), sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError):
        print(json.dumps({"status": "refused", "error": "Application build or captured-source verification failed; no successful receipt was published"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
