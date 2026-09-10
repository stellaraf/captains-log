#!/usr/bin/env python3
"""Build an inert deterministic host archive from a frozen source manifest."""
from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nebulalog_manager import host_payload as payload
from nebulalog_manager.common import Refused


def build(source: Path, manifest: Path, output: Path, *, version: str):
    if not isinstance(version, str) or not payload.VERSION.fullmatch(version):
        raise Refused("An explicit host release version is required")
    if output.exists() or output.is_symlink():
        raise Refused("Host archive output must not already exist")
    raw_manifest = payload.read_regular(manifest, payload.MAX_SOURCE_MANIFEST)
    snapshot = payload.source_manifest(raw_manifest)
    contents, files, observations, total = {}, [], {}, 0
    for entry in payload.CATALOG:
        path = source / entry["source"]
        stream, before = payload.open_regular(path, payload.MAX_FILE)
        with stream:
            raw = stream.read(payload.MAX_FILE + 1)
            if not payload.same_file(before, os.fstat(stream.fileno())) or len(raw) != before.st_size:
                raise Refused("Frozen host source changed while reading")
        if payload.digest(raw) != snapshot["files"][entry["source"]]:
            raise Refused("Host source differs from its frozen manifest")
        if payload.PRIVATE_KEY.search(raw):
            raise Refused("Private key material is forbidden in host source")
        total += len(raw)
        if total > payload.MAX_TOTAL:
            raise Refused("Host source exceeds the aggregate payload limit")
        contents[entry["path"]] = raw
        observations[entry["source"]] = before
        files.append({**entry, "bytes": len(raw), "sha256": payload.digest(raw)})
    metadata = {"schema": 1, "product": "captains-log", "component": "host", "abi": payload.ABI,
                "platform": payload.PLATFORM, "version": version, "catalog_sha256": payload.CATALOG_SHA256,
                "source_snapshot_sha256": payload.digest(raw_manifest),
                "host_source_sha256": payload.host_source_hash(snapshot["files"]), "files": files}
    payload.validate_metadata(metadata)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".pending-host-bundle-", dir=output.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT, encoding="ascii") as archive:
                body = payload.encoded(metadata)
                archive.addfile(payload.tar_header("host-payload.json", len(body), 0o644), io.BytesIO(body))
                for entry in files:
                    archive.addfile(payload.tar_header("payload/" + entry["path"], entry["bytes"], entry["mode"]),
                                    io.BytesIO(contents[entry["path"]]))
            stream.flush()
            os.fsync(stream.fileno())
        # Reopen every selected source using the same no-link rules before
        # publication, so the archive cannot silently represent a racing freeze.
        for source_name, before in observations.items():
            stream, current = payload.open_regular(source / source_name, payload.MAX_FILE)
            with stream:
                if not payload.same_file(before, current):
                    raise Refused("Frozen host source changed before publication")
        if payload.read_regular(manifest, payload.MAX_SOURCE_MANIFEST) != raw_manifest:
            raise Refused("Frozen source manifest changed before publication")
        raw_hash = payload.digest(payload.read_regular(temporary, payload.MAX_ARCHIVE))
        result = payload.verify_archive(temporary, expected_sha256=raw_hash, expected_host_source_sha256=metadata["host_source_sha256"])
        os.link(temporary, output, follow_symlinks=False)  # Atomic no replacement.
        temporary.unlink()
        payload._sync_directory(output.parent)
        return {**result, "output": str(output), "signature_created": False}
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        import json
        print(json.dumps(build(args.source, args.source_manifest, args.output, version=args.version), sort_keys=True))
        return 0
    except (OSError, ValueError, Refused):
        print('{"status":"refused","message":"Host payload build or verification failed"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
