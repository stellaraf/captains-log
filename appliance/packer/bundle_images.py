#!/usr/bin/env python3
"""Build a verified offline Linux/amd64 OCI bundle from local images only."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.image_bundle import (MAX_ARCHIVE_BYTES, MAX_BUNDLE_BYTES, NAMES,
                                           strict_json, validate_pins, verify_bundle,
                                           verify_oci_archive)

ARCHIVES = {"NEBULALOG_IMAGE": "nebulalog.oci.tar", "POSTGRESQL_IMAGE": "postgresql.oci.tar", "CLICKHOUSE_IMAGE": "clickhouse.oci.tar", "KEYCLOAK_FIPS_IMAGE": "keycloak-fips.oci.tar"}
RESERVE_BYTES = 2 * 1024**3


def source_map(value):
    if not isinstance(value, dict) or set(value) != NAMES:
        raise Refused("Bundle input requires exactly four component entries")
    for item in value.values():
        if not isinstance(item, dict) or set(item) not in ({"source", "reference"}, {"archive", "reference"}):
            raise Refused("Each image needs a reference and exactly one local source or archive")
        if "source" in item and (not isinstance(item["source"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}", item["source"]) or "://" in item["source"]):
            raise Refused("Docker source must be a local image name or ID, never an option or transport")
        if "archive" in item and (not isinstance(item["archive"], str) or "\0" in item["archive"]):
            raise Refused("Existing OCI archive path is invalid")
    validate_pins({name: item["reference"] for name, item in value.items()})
    return value


def export_image(source, destination, maximum):
    """Bounded stream; terminate only the docker-save child started here."""
    proc = subprocess.Popen(["docker", "image", "save", "--platform=linux/amd64", source], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    deadline, written = time.monotonic() + 1800, 0
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as output:
            while True:
                if time.monotonic() >= deadline:
                    raise Refused("Local Docker image export timed out")
                if not selector.select(timeout=1):
                    continue
                chunk = os.read(proc.stdout.fileno(), 1024**2)
                if not chunk:
                    break
                written += len(chunk)
                if written > maximum:
                    raise Refused("Local image export exceeds its archive or free-space budget")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if proc.wait(timeout=30) != 0:
            raise Refused("Docker could not export the local Linux/amd64 image; no image was pulled")
    finally:
        selector.close()
        proc.stdout.close()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def build_bundle(images, output: Path, *, reuse_existing_archives=False, exporter=export_image, progress=None):
    source_map(images)
    if output.exists() or output.is_symlink():
        raise Refused("Bundle output must be a new directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".nebulalog-images-", dir=output.parent))
    pins = {name: item["reference"] for name, item in images.items()}
    manifest = {"schema": 1, "images": {}}
    total = 0
    try:
        for name in sorted(NAMES):
            item = images[name]
            destination = staging / ARCHIVES[name]
            free = shutil.disk_usage(staging).free
            maximum = min(MAX_ARCHIVE_BYTES, MAX_BUNDLE_BYTES - total, free - RESERVE_BYTES)
            if maximum <= 0:
                raise Refused("Insufficient scratch space for an offline image bundle")
            if progress:
                progress(name)
            if "archive" in item:
                source = Path(item["archive"])
                observed = verify_oci_archive(source, item["reference"])
                if observed["archive_bytes"] > min(MAX_ARCHIVE_BYTES, MAX_BUNDLE_BYTES - total) or not reuse_existing_archives and observed["archive_bytes"] > maximum:
                    raise Refused("Existing archive exceeds the bundle or available scratch budget")
                if reuse_existing_archives:
                    # The operator explicitly selected this no-copy mode. Inputs
                    # must stay immutable; seal/loader verify bytes again later.
                    os.link(source, destination, follow_symlinks=False)
                else:
                    shutil.copyfile(source, destination, follow_symlinks=False)
                    os.chmod(destination, 0o600)
            else:
                exporter(item["source"], destination, maximum)
            observed = verify_oci_archive(destination, item["reference"])
            total += observed["archive_bytes"]
            if total > MAX_BUNDLE_BYTES:
                raise Refused("Image bundle exceeds its aggregate budget")
            manifest["images"][name] = {"archive": ARCHIVES[name], "sha256": observed["archive_sha256"], "reference": item["reference"]}
        atomic_json(staging / "manifest.json", manifest)
        atomic_json(staging / "images.json", pins)
        evidence = verify_bundle(staging, pins)
        if output.exists() or output.is_symlink():
            raise Refused("Bundle output appeared during preparation; refusing to replace it")
        os.rename(staging, output)
        directory = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return {"status": "verified", "output": str(output), "total_archive_bytes": evidence["total_archive_bytes"], "images": pins,
                "hard_link_reuse": reuse_existing_archives, "network_used": False}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reuse-existing-archives", action="store_true", help="Explicitly hard-link verified local archives without a second allocation; inputs must remain immutable")
    args = parser.parse_args(argv)
    try:
        if args.input.stat().st_size > 1024**2:
            raise Refused("Bundle input configuration exceeds its size budget")
        result = build_bundle(strict_json(args.input.read_bytes()), args.output, reuse_existing_archives=args.reuse_existing_archives,
                              progress=lambda name: print("Verifying local image: " + name, file=sys.stderr, flush=True))
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc) if isinstance(exc, Refused) else "Local offline bundle construction failed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
