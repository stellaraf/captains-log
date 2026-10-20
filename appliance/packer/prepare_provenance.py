#!/usr/bin/env python3
"""Capture candidate source and exact offline bundle provenance; never sign it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nebulalog_manager import publisher_inputs
from nebulalog_manager.image_bundle import ApplicationSchema as application_schema
from nebulalog_manager.image_bundle import RestoredAuthContract as restored_auth, verify_bundle
from nebulalog_manager import host_payload


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def source_snapshot(root: Path):
    root = root.resolve()
    if Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip()).resolve() != root:
        raise ValueError("Source must be the Git repository root")
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Source needs a base Git commit")
    before = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    names = sorted(set(git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""})
    files, observations = {}, {}
    for raw in names:
        name = raw.decode("utf-8")
        parts = name.split("/")
        if not re.fullmatch(r"[A-Za-z0-9_@.-]+(?:/[A-Za-z0-9_@.-]+)*", name) or any(p in (".", "..", ".local", "node_modules", ".git") for p in parts):
            raise ValueError("Unsafe or generated source manifest path")
        path = root / name
        if path.is_symlink():
            raise ValueError("Resolve repository symlinks before capturing appliance source")
        if not path.exists():
            continue  # A tracked deletion is represented by its absence and dirty state.
        if not path.is_file() or path.resolve().is_relative_to(root) is False:
            raise ValueError("Source manifest accepts regular repository files only")
        info = path.stat()
        observations[name] = (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        files[name] = sha(path.read_bytes())
    if not files:
        raise ValueError("Source manifest is empty")
    # A captured snapshot must not race ongoing source edits. Retry after writers finish.
    for name, expected in observations.items():
        info = (root / name).stat()
        if expected != (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
            raise ValueError("Source changed while capturing provenance")
    if before != git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise ValueError("Source file set changed while capturing provenance")
    return {"schema": 1, "files": files}, commit, bool(before)


def application_hash(source):
    selected = {key: value for key, value in source["files"].items()
                if key in ("go.mod", "go.sum", "LICENSE", "appliance/images/application/Containerfile")
                or key.startswith(("cmd/", "internal/", "web/", "migrations/"))}
    return sha(json.dumps(selected, sort_keys=True, separators=(",", ":")).encode())


def publisher_provenance(root, files, *, private_unsealed=False):
    from build_application import open_source
    names = (publisher_inputs.DESCRIPTOR_SOURCE, publisher_inputs.PUBLIC_SOURCE)
    if private_unsealed:
        publisher_inputs.binding(publisher_inputs.PRIVATE_BINDING, files)
        return dict(publisher_inputs.PRIVATE_BINDING)
    if not all(name in files for name in names):
        raise ValueError("Factory publisher inputs are required; explicitly select --private-unsealed for a non-distributable candidate")
    raw = []
    for name in names:
        stream, before = open_source(root, name)
        with stream:
            if not 0 < before.st_size <= 16384:
                raise ValueError("Factory publisher inputs must be bounded public source files")
            value = stream.read(16385)
            after = os.fstat(stream.fileno())
            if (len(value) != before.st_size or sha(value) != files[name]
                    or any(getattr(before, field) != getattr(after, field)
                           for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
                raise ValueError("Publisher input changed after source capture")
        raw.append(value)
    description = publisher_inputs.descriptor(raw[0])
    value = {"mode": "factory", "descriptor_sha256": sha(raw[0]), "public_spki_pem_sha256": sha(raw[1]),
             **{key: description[key] for key in ("spki_sha256", "repository", "key_id")}}
    publisher_inputs.validate(value, files, *raw, require_factory=True)
    return value


def capture(root: Path, bundle: Path, output: Path, *, sequence: int, schema_revision: str, private_unsealed=False,
            restore_auth_evidence: Path | None = None, private_qualification=False):
    if type(private_qualification) is not bool:
        raise ValueError("Private qualification must be an explicit boolean")
    if private_qualification and (schema_revision != application_schema.HOST_CHALLENGE_REVISION or restore_auth_evidence is None):
        raise ValueError("Private schema 4 qualification requires exact-image restored authentication evidence")
    if schema_revision == application_schema.HOST_CHALLENGE_REVISION and not private_qualification:
        raise ValueError("Schema 4 packaging awaits fresh initialization, restored authentication, and image qualification")
    root, bundle = root.resolve(), bundle.resolve()
    if type(sequence) is not int or not 0 <= sequence < 2**63 or not re.fullmatch(r"[1-9][0-9]{0,8}", schema_revision):
        raise ValueError("Explicit sequence and schema revision are required")
    if output.exists() or output.is_symlink():
        raise ValueError("Provenance output must be a new directory")
    manifest, commit, dirty = source_snapshot(root)
    application_schema.bind_source(manifest["files"], schema_revision)
    publisher = publisher_provenance(root, manifest["files"], private_unsealed=private_unsealed)
    source = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    bundle_manifest = bundle / "manifest.json"
    if bundle_manifest.is_symlink() or not bundle_manifest.is_file() or bundle_manifest.stat().st_size > 1024**2:
        raise ValueError("A bounded regular offline bundle manifest is required")
    descriptor = {"schema": 1, "product": "nebulalog", "sequence": sequence,
                  "schema_revision": schema_revision, "source_commit": commit,
                  "source_dirty": dirty, "source_snapshot_sha256": sha(source),
                  "bundle_manifest_sha256": sha(bundle_manifest.read_bytes()),
                  "qualification_status": "pending", "publisher": publisher}
    if private_qualification:
        # Bind the non-distributable status into the factory descriptor. This
        # permits building a guest to test; it cannot authorize sealing/release.
        descriptor["private_qualification"] = True
    auth_raw = {}
    if restore_auth_evidence is not None:
        if schema_revision != "3" and not private_qualification:
            raise ValueError("Restored authentication evidence requires the supported fresh schema 3 baseline")
        restore_auth_evidence = Path(restore_auth_evidence).absolute()
        for name in sorted(restored_auth.EVIDENCE):
            auth_raw[name] = host_payload.read_regular(restore_auth_evidence / name, restored_auth.MAX_RECEIPT)
        pins = host_payload.strict_json(host_payload.read_regular(bundle / "images.json", 1024**2))
        image = verify_bundle(bundle, pins)["images"]["NEBULALOG_IMAGE"]
        descriptor["restore_auth"] = restored_auth.factory_capture(manifest["files"], image,
            auth_raw[restored_auth.BUILD], auth_raw[restored_auth.BEHAVIOR], schema_revision=schema_revision)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".nebulalog-provenance-", dir=output.parent))
    try:
        (staging / "restore-auth").mkdir(mode=0o700)
        for name, raw in auth_raw.items():
            with (staging / "restore-auth" / name).open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            if host_payload.read_regular(restore_auth_evidence / name, restored_auth.MAX_RECEIPT) != raw:
                raise ValueError("Restored authentication evidence changed during capture")
        for name, value in (("source-manifest.json", source), ("initial-release.json", (json.dumps(descriptor, sort_keys=True, indent=2)+"\n").encode())):
            path = staging / name
            with path.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        if output.exists() or output.is_symlink():
            raise ValueError("Provenance output appeared during capture")
        os.rename(staging, output)
        directory = os.open(output.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if staging.exists():shutil.rmtree(staging)
    return {"status": "captured", "source_files": len(manifest["files"]), **descriptor,
            "application_source_sha256": application_hash(manifest),
            "output": str(output), "signature_created": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--application-hash-only", action="store_true", help="Print the application source hash before building its image")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sequence", type=int)
    parser.add_argument("--schema-revision")
    parser.add_argument("--private-unsealed", action="store_true", help="Explicit non-distributable candidate without factory publisher trust; sealing is refused")
    parser.add_argument("--private-qualification", action="store_true", help="Build a non-distributable schema 4 test guest with measured authentication evidence; sealing remains refused")
    parser.add_argument("--restore-auth-evidence", type=Path, help="Reviewed exact-image build and normal-API behavior receipts; does not claim native acceptance")
    args = parser.parse_args()
    if args.application_hash_only:
        print(application_hash(source_snapshot(args.source)[0]))
    else:
        if any(value is None for value in (args.bundle, args.output, args.sequence, args.schema_revision)):
            parser.error("Capture requires --bundle, --output, --sequence and --schema-revision")
        print(json.dumps(capture(args.source, args.bundle, args.output, sequence=args.sequence,
                                 schema_revision=args.schema_revision, private_unsealed=args.private_unsealed,
                                 restore_auth_evidence=args.restore_auth_evidence,
                                 private_qualification=args.private_qualification), indent=2, sort_keys=True))
