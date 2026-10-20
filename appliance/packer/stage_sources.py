#!/usr/bin/env python3
"""Freeze verified installer inputs for Packer; never build or operate a guest."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_provenance import application_hash, publisher_inputs, sha, source_snapshot
from build_application import open_source
from nebulalog_manager.image_bundle import ApplicationSchema, RestoredAuthContract

PREFIXES = ("appliance/bin/", "appliance/nebulalog_manager/", "appliance/adapters/bin/",
            "appliance/adapters/nebulalog_adapters/", "appliance/systemd/", "appliance/quadlet/",
            "appliance/httpd/", "appliance/security/", "appliance/packer/http/")
RECIPE = "appliance/packer/nebulalog.pkr.hcl"
REALM = "deploy/keycloak/realm.json"
REQUIRED = {RECIPE, REALM, "appliance/install-host.sh", "appliance/provision_guard.py", "appliance/host_boot.py", "appliance/factory_host.py", "appliance/factory_kernel.py",
            "appliance/packer/http/nebulalog.ks", "appliance/packer/http/nebulalog-uefi.ks", "appliance/bin/nebulalog-seal",
            "appliance/bin/nebulalog-firstboot", "appliance/bin/bootstrap-runtime",
            "appliance/bin/nebulalog-aide", "appliance/security/aide-policy.conf", "appliance/security/aide.conf",
            "appliance/security/trust.json"}
METADATA = {"source-manifest.json", "initial-release.json", "frozen-sources.pkrvars.hcl", "staging-receipt.json"}
MAX_FILES = 10000
MAX_BYTES = 64 * 1024**2
DIGEST = re.compile(r"[a-f0-9]{64}")
PRIVATE_KEY = re.compile(rb"(?m)^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----\r?$")


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate provenance JSON member")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def read_bounded(root, name, maximum):
    stream, before = open_source(root, name)
    with stream:
        if before.st_size > maximum:
            raise ValueError("Staging input exceeds its byte limit")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key)
                for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
            raise ValueError("Staging input changed while being read")
    return raw


def captured(provenance):
    source = read_bounded(provenance, "source-manifest.json", 8 * 1024**2)
    release = read_bounded(provenance, "initial-release.json", 16384)
    manifest, descriptor = strict_json(source), strict_json(release)
    fields = {"schema", "product", "sequence", "schema_revision", "source_commit", "source_dirty",
              "source_snapshot_sha256", "bundle_manifest_sha256", "qualification_status", "publisher"}
    if (not isinstance(descriptor, dict) or not fields <= set(descriptor) or set(descriptor) - fields - {"restore_auth"} or type(descriptor.get("schema")) is not int
            or descriptor["schema"] != 1 or descriptor["product"] != "nebulalog"
            or type(descriptor["sequence"]) is not int or not 0 <= descriptor["sequence"] < 2**63
            or not isinstance(descriptor["schema_revision"], str) or not re.fullmatch(r"[1-9][0-9]{0,8}", descriptor["schema_revision"])
            or not isinstance(descriptor["source_commit"], str) or not re.fullmatch(r"[a-f0-9]{40}", descriptor["source_commit"])
            or type(descriptor["source_dirty"]) is not bool or descriptor["qualification_status"] != "pending"
            or any(not isinstance(descriptor[name], str) or not DIGEST.fullmatch(descriptor[name])
                   for name in ("source_snapshot_sha256", "bundle_manifest_sha256"))
            or descriptor["source_snapshot_sha256"] != sha(source)):
        raise ValueError("Source manifest must match the existing pending initial-release provenance")
    if descriptor["schema_revision"] == ApplicationSchema.HOST_CHALLENGE_REVISION:
        raise ValueError("Schema 4 packaging awaits fresh initialization, restored authentication, and image qualification")
    if "restore_auth" in descriptor:
        RestoredAuthContract.factory_descriptor(descriptor["restore_auth"])
        if descriptor["schema_revision"] != "3":
            raise ValueError("Restored authentication factory inputs require fresh schema 3")
    if (not isinstance(manifest, dict) or set(manifest) != {"schema", "files"}
            or type(manifest["schema"]) is not int or manifest["schema"] != 1
            or not isinstance(manifest["files"], dict) or not 1 <= len(manifest["files"]) <= MAX_FILES):
        raise ValueError("Unsupported source manifest")
    for name, digest in manifest["files"].items():
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_@.-]+(?:/[A-Za-z0-9_@.-]+)*", name)
                or any(part in (".", "..", ".local", ".git", "node_modules") for part in name.split("/"))
                or not isinstance(digest, str) or not DIGEST.fullmatch(digest)):
            raise ValueError("Unsafe source manifest entry")
    publisher_inputs.binding(descriptor["publisher"], manifest["files"])
    return manifest, descriptor, source, release


def restore_auth_files(root, descriptor):
    if "restore_auth" not in descriptor:
        return {}
    value = RestoredAuthContract.factory_descriptor(descriptor["restore_auth"])
    result = {}
    for name, expected in value["artifacts"].items():
        relative = "restore-auth/" + name
        raw = read_bounded(root, relative, RestoredAuthContract.MAX_RECEIPT)
        if {"bytes": len(raw), "sha256": sha(raw)} != expected or PRIVATE_KEY.search(raw):
            raise ValueError("Factory restored authentication evidence changed or contains private key material")
        result[relative] = raw
    return result


def selected_files(manifest):
    selected = {name: digest for name, digest in manifest["files"].items()
                if name in REQUIRED or name.startswith(PREFIXES)}
    if not REQUIRED <= selected.keys() or any(not any(name.startswith(prefix) for name in selected) for prefix in PREFIXES):
        raise ValueError("Captured installer source is incomplete")
    for name in selected:
        parts = name.lower().split("/")
        if (any(part in ("secrets", ".secrets", ".ssh", ".aws", ".npmrc", ".netrc", ".pypirc",
                         ".git-credentials", "__pycache__", "output", "node_modules", ".local", ".git") for part in parts)
                or any(part.startswith((".env", "id_rsa", "id_ed25519", "id_ecdsa")) for part in parts)
                or Path(name).suffix.lower() in (".pem", ".key", ".p12", ".pfx", ".jks", ".bcfks", ".pyc", ".pyo")):
            raise ValueError("Installer selection contains a generated or credential file")
    return selected


def file_mode(name):
    # Source schema v1 hashes bytes only, so do not trust mutable worktree modes.
    executable = name.startswith(("appliance/bin/", "appliance/adapters/bin/")) or name in {
        "appliance/install-host.sh", "appliance/provision_guard.py"}
    return 0o500 if executable else 0o400


def write_new(path, raw, mode):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def variables(output, build_disk_id):
    return {"appliance_source_directory": str(output / "appliance"),
            "provenance_directory": str(output),
            "keycloak_realm_template": str(output / REALM),
            "kickstart_directory": str(output / "appliance/packer/http"),
            "build_disk_id": build_disk_id}


def varfile(values):
    # HCL strings interpolate ${...} and %{...}; paths must remain literal.
    return "".join(name + " = " + json.dumps(value).replace("${", "$${").replace("%{", "%%{") + "\n"
                   for name, value in sorted(values.items())).encode()


def inventory(root):
    files, directories = set(), set()
    for current, subdirs, names in os.walk(root, followlinks=False):
        for name in subdirs + names:
            path = Path(current) / name
            info = path.lstat()
            if info.st_uid != os.getuid() or path.is_symlink():
                raise ValueError("Staged inputs must remain owned regular files/directories without symlinks")
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError("Staged directories must remain private and transfer-compatible")
                directories.add(relative)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                files.add(relative)
            else:
                raise ValueError("Staged inputs cannot include devices, pipes or linked files")
    return files, directories


def verify(output: Path, *, _unpublished_record=None):
    output = output.absolute()
    root_info = output.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or output.is_symlink() or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700):
        raise ValueError("Staging root must remain a private directory owned by the invoking user")
    manifest, descriptor, source, release = captured(output)
    auth_files = restore_auth_files(output, descriptor)
    selected = selected_files(manifest)
    record = (_unpublished_record if _unpublished_record is not None
              else strict_json(read_bounded(output, "staging-receipt.json", 4 * 1024**2)))
    build_disk_id = record.get("variables", {}).get("build_disk_id") if isinstance(record, dict) and isinstance(record.get("variables"), dict) else None
    if not isinstance(build_disk_id, str) or not re.fullmatch(r"[a-f0-9]{16}", build_disk_id):
        raise ValueError("A recorded per-build disk identity is required")
    expected_modes = {name: format(file_mode(name), "04o") for name in selected}
    wanted = {"schema": 1, "purpose": "frozen-packer-source-inputs", "source_snapshot_sha256": sha(source),
              "initial_release_sha256": sha(release), "application_source_sha256": application_hash(manifest),
              "source_commit": descriptor["source_commit"], "source_dirty": descriptor["source_dirty"],
              "source_files": len(manifest["files"]), "staged_files": selected, "staged_modes": expected_modes,
              "variables": variables(output, build_disk_id), "packer_template": str(output / RECIPE),
              "packer_varfile": str(output / "frozen-sources.pkrvars.hcl"),
              "runtime_executed": False, "signature_created": False}
    if not isinstance(record, dict) or type(record.get("schema")) is not int or record != wanted:
        raise ValueError("Staging receipt differs from its captured source and fixed path/mode contract")
    files, directories = inventory(output)
    metadata = METADATA - {"staging-receipt.json"} if _unpublished_record is not None else METADATA
    expected_files = set(selected) | metadata | set(auth_files)
    expected_dirs = {str(parent) for name in selected for parent in Path(name).parents if str(parent) != "."} | {"restore-auth"}
    if files != expected_files or directories != expected_dirs:
        raise ValueError("Staged file/directory inventory changed or includes unlisted inputs")
    total = 0
    for name, expected in selected.items():
        raw = read_bounded(output, name, MAX_BYTES)
        total += len(raw)
        if total > MAX_BYTES or sha(raw) != expected or stat.S_IMODE((output / name).lstat().st_mode) != file_mode(name):
            raise ValueError("Staged source bytes or mode changed")
    publisher_inputs.validate(descriptor["publisher"], manifest["files"],
                              *(read_bounded(output, name, 16384) if name in selected else None
                                for name in (publisher_inputs.DESCRIPTOR_SOURCE, publisher_inputs.PUBLIC_SOURCE)))
    for name in metadata:
        if stat.S_IMODE((output / name).lstat().st_mode) != 0o400:
            raise ValueError("Staging metadata must remain read-only")
    for name in auth_files:
        if stat.S_IMODE((output / name).lstat().st_mode) != 0o400:
            raise ValueError("Factory restored authentication evidence must remain read-only")
    if read_bounded(output, "frozen-sources.pkrvars.hcl", 65536) != varfile(variables(output, build_disk_id)):
        raise ValueError("Packer variable file differs from frozen paths")
    return {"status": "verified", **wanted}


def stage(root: Path, provenance: Path, output: Path):
    if root.is_symlink() or provenance.is_symlink() or output.is_symlink() or output.exists():
        raise ValueError("Inputs cannot be symlink roots; output must be an exclusive new directory")
    root, provenance = root.resolve(), provenance.resolve()
    output = output.parent.resolve(strict=True) / output.name
    manifest, descriptor, source, release = captured(provenance)
    auth_files = restore_auth_files(provenance, descriptor)
    selected = selected_files(manifest)
    current, commit, dirty = source_snapshot(root)
    if current != manifest or commit != descriptor["source_commit"] or dirty != descriptor["source_dirty"]:
        raise ValueError("Repository changed after prepare_provenance capture; recapture after all source writers finish")
    # mkdir is exclusive: a partial/previous destination is never adopted/deleted.
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)
    (output / "restore-auth").mkdir(mode=0o700)
    for name, raw in auth_files.items():
        write_new(output / name, raw, 0o400)
    total = 0
    for name, expected in sorted(selected.items()):
        raw = read_bounded(root, name, MAX_BYTES)
        total += len(raw)
        if total > MAX_BYTES or sha(raw) != expected:
            raise ValueError("Source changed after capture or exceeds the staging bound")
        if PRIVATE_KEY.search(raw):
            raise ValueError("Private key material is forbidden in installer staging")
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # mkdir(parents=True) does not apply mode to intermediate directories.
        for parent in path.parents:
            if parent == output:
                break
            os.chmod(parent, 0o700)
        write_new(path, raw, file_mode(name))
    # Re-run the established complete source capture after copying; this detects
    # file-set or unrelated source changes, not only the selected runtime files.
    after, commit_after, dirty_after = source_snapshot(root)
    if after != manifest or commit_after != commit or dirty_after != dirty:
        raise ValueError("Source changed while staging; this partial output must not be used")
    # Public device identity only, not a credential. Persist once for this stage.
    build_disk_id = uuid.uuid4().hex[:16]
    for name, raw in (("source-manifest.json", source), ("initial-release.json", release),
                      ("frozen-sources.pkrvars.hcl", varfile(variables(output, build_disk_id)))):
        write_new(output / name, raw, 0o400)
    receipt = {"schema": 1, "purpose": "frozen-packer-source-inputs", "source_snapshot_sha256": sha(source),
               "initial_release_sha256": sha(release), "application_source_sha256": application_hash(manifest),
               "source_commit": descriptor["source_commit"], "source_dirty": descriptor["source_dirty"],
               "source_files": len(manifest["files"]), "staged_files": selected,
               "staged_modes": {name: format(file_mode(name), "04o") for name in selected},
               "variables": variables(output, build_disk_id), "packer_template": str(output / RECIPE),
               "packer_varfile": str(output / "frozen-sources.pkrvars.hcl"),
               "runtime_executed": False, "signature_created": False}
    # Do not publish a success receipt until an independent read of every output
    # byte, mode, path and metadata document has passed.
    verify(output, _unpublished_record=receipt)
    write_new(output / "staging-receipt.json", (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode(), 0o400)
    result = verify(output)
    for directory in sorted({output, *(p.parent for p in output.rglob("*"))}, key=lambda p: len(p.parts), reverse=True):
        descriptor_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor_fd)
        finally:
            os.close(descriptor_fd)
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_only:
            if args.source is not None or args.provenance is not None:
                parser.error("Verification uses only the captured output; omit --source and --provenance")
            result = verify(args.output.resolve() if not args.output.is_symlink() else args.output)
        else:
            if args.source is None or args.provenance is None:
                parser.error("Staging requires --source and --provenance")
            result = stage(args.source, args.provenance, args.output)
        print(json.dumps({key: value for key, value in result.items() if key not in ("staged_files", "staged_modes")}, indent=2, sort_keys=True))
    except (OSError, ValueError, publisher_inputs.Refused) as exc:
        raise SystemExit(str(exc)) from None
