#!/usr/bin/python3
"""Build and enroll the initial host generation in a guarded disposable image.

Never called during customer boot or updates. Fixed public trust stays outside
generations. Inputs are the measured staged source, not installed substitutions.
"""
import argparse
import fcntl
import io
import os
from pathlib import Path
import stat
import tarfile
import tempfile

from nebulalog_manager import host_payload as payload
from nebulalog_manager.common import Refused, require_linux_root
from nebulalog_manager.update_enrollment import UpdateEnrollment, _read, _json, _same_or_write

ETC = Path("/etc/nebulalog")
SHARE = Path("/usr/share/nebulalog")
DATA = Path("/var/lib/nebulalog")
FIXED = {"appliance/host_boot.py": Path("/usr/libexec/nebulalog/host-boot"),
         "appliance/factory_host.py": Path("/usr/libexec/nebulalog/factory-host"),
         "appliance/factory_kernel.py": Path("/usr/libexec/nebulalog/factory-kernel")}


def guard():
    require_linux_root()
    # The provisioner's /etc lock must be inherited, not bypassed by a separate
    # helper invocation racing the parent transaction or sealer.
    descriptor, directory = os.fstat(9), Path("/etc").stat()
    if (descriptor.st_dev, descriptor.st_ino) != (directory.st_dev, directory.st_ino):
        raise Refused("Initial generation requires the inherited installer lock")
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
    record = _json(ETC / "bootstrap/private-build.json")
    if (record.get("purpose") != "private-packer-build" or record.get("phase") != "provisioning"
            or os.path.ismount(DATA) or DATA.exists() and any(DATA.iterdir())
            or any((ETC / name).exists() or (ETC / name).is_symlink() for name in ("configured", "storage.json", "bootstrap/firstboot.json"))):
        raise Refused("Initial generation enrollment is restricted to pristine guarded image provisioning")


def enroll(source: Path, realm: Path, manager=None):
    guard()
    manager = manager or UpdateEnrollment()
    verified = manager.verify_build_inputs(include_host=False)
    descriptor, descriptor_sha = verified["descriptor"], verified["descriptor_sha256"]
    source_raw = _read(SHARE / "source-manifest.json", payload.MAX_SOURCE_MANIFEST)
    snapshot = payload.source_manifest(source_raw)
    if payload.digest(source_raw) != descriptor["source_snapshot_sha256"]:
        raise Refused("Initial host source manifest changed")
    contents, files = {}, []
    for entry in payload.CATALOG:
        path = realm if entry["source"] == "deploy/keycloak/realm.json" else source / entry["source"].removeprefix("appliance/")
        raw = payload.read_regular(path, payload.MAX_FILE)
        if payload.digest(raw) != snapshot["files"][entry["source"]] or payload.PRIVATE_KEY.search(raw):
            raise Refused("Initial host input differs from captured source or contains a private key")
        contents[entry["path"]] = raw
        files.append({**entry, "bytes": len(raw), "sha256": payload.digest(raw)})
    fixed_files = {}
    for name, installed in FIXED.items():
        expected = snapshot["files"].get(name)
        if (not isinstance(expected, str) or not payload.SHA256.fullmatch(expected)
                or payload.digest(payload.read_regular(source / name.removeprefix("appliance/"), payload.MAX_FILE)) != expected
                or payload.digest(_read(installed, payload.MAX_FILE)) != expected):
            raise Refused("Fixed host shim/helper must match the captured source and installed bytes")
        fixed_files[name] = expected
    host_source = payload.host_source_hash(snapshot["files"])
    version = "0.0.0-factory." + host_source[:16]
    metadata = {"schema": 1, "product": "captains-log", "component": "host", "abi": payload.ABI,
                "platform": payload.PLATFORM, "version": version, "catalog_sha256": payload.CATALOG_SHA256,
                "source_snapshot_sha256": payload.digest(source_raw), "host_source_sha256": host_source, "files": files}
    payload.validate_metadata(metadata)
    # Generate the same canonical archive as build_host_bundle.py without using
    # install-time paths or executing staged release code.
    with tempfile.TemporaryDirectory(prefix=".initial-host-", dir=SHARE) as temporary:
        archive = Path(temporary) / "host.tar"
        with archive.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT, encoding="ascii") as tar:
                raw = payload.encoded(metadata)
                tar.addfile(payload.tar_header("host-payload.json", len(raw), 0o644), io.BytesIO(raw))
                for entry in files:
                    tar.addfile(payload.tar_header("payload/" + entry["path"], entry["bytes"], entry["mode"]), io.BytesIO(contents[entry["path"]]))
            stream.flush()
            os.fsync(stream.fileno())
        generation = payload.digest(payload.read_regular(archive, payload.MAX_ARCHIVE))
        record = {"schema": 1, "abi": 1,
                  "host": {"generation": generation, "version": version, "host_source_sha256": host_source, "abi": 1},
                  "initial_release_sha256": descriptor_sha, "source_snapshot_sha256": descriptor["source_snapshot_sha256"],
                  "catalog": list(payload.CATALOG), "catalog_sha256": payload.CATALOG_SHA256, "fixed_files": fixed_files}
        selection = {"schema": 1, "generation": generation, "sequence": descriptor["sequence"]}
        pending, final = SHARE / "initial-host-pending.json", SHARE / "initial-host.json"
        selected = ETC / "host-selection.json"
        # Inspect all existing evidence before any durable write. There is no
        # adoption of a selection or record without this exact pending proposal.
        if (final.exists() or final.is_symlink() or selected.exists() or selected.is_symlink()) and not pending.exists():
            raise Refused("Initial host state has no durable factory proposal")
        for path, value in ((pending, record), (final, record), (selected, selection)):
            if (path.exists() or path.is_symlink()) and _json(path) != value:
                raise Refused("Existing initial host identity differs; refusing replacement")
        _same_or_write(pending, record)
        payload.stage_generation(archive, expected_sha256=generation, expected_host_source_sha256=host_source)
        _same_or_write(final, record)
        _same_or_write(selected, selection)
    manager._factory_host(descriptor)
    return {"schema": 1, "status": "factory-host-enrolled", "host": record["host"],
            "initial_release_sha256": descriptor_sha, "runtime_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    try:
        import json
        print(json.dumps(enroll(args.source, Path("/tmp/nebulalog-keycloak-realm.json")), sort_keys=True))
        return 0
    except (OSError, ValueError, Refused):
        print('{"ok":false,"status":"refused","message":"Initial host generation enrollment failed closed."}', file=__import__("sys").stderr)
        return 1


if __name__ == "__main__": raise SystemExit(main())
