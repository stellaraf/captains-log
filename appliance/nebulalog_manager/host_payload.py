"""Verify and stage an inert host generation; never activate or execute it.

The outer hash must come from the signed release verifier. This module does not
authenticate a publisher, run candidate code, install live configuration, switch
generations, or change services. Staging is Linux-root-only with a fixed target.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile

from .common import Refused, locked, require_linux_root

ABI = 1
MAX_FILE = 8 * 1024**2
MAX_TOTAL = 32 * 1024**2
MAX_ARCHIVE = 64 * 1024**2
MAX_METADATA = 1024**2
MAX_SOURCE_MANIFEST = 8 * 1024**2
GENERATIONS = Path("/usr/lib/nebulalog/generations")
_OWNER_UID = 0
SHA256 = re.compile(r"[a-f0-9]{64}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,100})?")
PRIVATE_KEY = re.compile(rb"(?m)^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----\r?$")
PLATFORM = {"os": "linux", "distribution": "rocky", "major": 9, "architecture": "x86_64"}

# Explicit release ABI, not globs or caller-selected install paths. New runtime
# files require a reviewed catalog change. Customer/trust inputs never belong here.
MANAGER_MODULES = (
    "__init__.py", "aide.py", "aide_report.py", "aide_updates.py", "backup.py", "baseline.py", "bootstrap.py", "cli.py",
    "common.py", "console.py", "enrollment.py", "firstboot.py", "github_updates.py", "guest_validation.py",
    "host_activation.py", "host_dispatch.py", "host_identity.py", "host_job_storage.py", "host_jobs.py", "host_operations.py", "host_payload.py",
    "host_plan_socket.py", "host_plans.py", "image_bundle.py", "image_seal_network.py", "os_payload.py", "os_updates.py",
    "publisher_inputs.py", "security.py", "setup_integrity.py", "sizing.py", "status_snapshot.py", "storage.py", "update_enrollment.py", "updates.py",
)
ADAPTER_MODULES = ("__init__.py", "auth.py", "cli.py", "commands.py", "host_runtime.py", "lifecycle.py")
COMMANDS = ("bootstrap-runtime", "enroll-installed-release", "load-image-bundle", "nebulalog", "nebulalog-aide",
            "nebulalog-baseline", "nebulalog-console", "nebulalog-firstboot", "nebulalog-seal", "nebulalog-setup",
            "publish-status", "validate-guest")
ADAPTER_COMMANDS = ("update-activate", "update-backup", "update-boot-gate", "update-finalize", "update-health",
                    "update-os-postcheck", "update-os-preflight", "update-os-recover", "update-preflight",
                    "update-prepare", "update-reboot-abort", "update-reboot-complete", "update-reboot-prepare", "update-rollback")
UNITS = ("nebulalog-aide.service", "nebulalog-aide.timer", "nebulalog-app-update.service", "nebulalog-app-update.timer",
         "nebulalog-console.service", "nebulalog-edge.service", "nebulalog-firstboot.service",
         "nebulalog-maintenance-gate.service", "nebulalog-os-update.service", "nebulalog-os-update.timer",
         "nebulalog-reboot-verify.service", "nebulalog-status.service", "nebulalog-status.timer",
         "nebulalog-storage.service", "nebulalog-storage.timer", "getty@tty1.service.d/50-nebulalog-firstboot.conf")
QUADLETS = ("nebulalog-api.container.in", "nebulalog-clickhouse.container.in", "nebulalog-ingest.container.in",
            "nebulalog-keycloak.container.in", "nebulalog-postgresql.container.in", "nebulalog.network")
DEFAULTS = ("90-nebulalog.conf", "90-nebulalog.rules", "aide-policy.conf", "aide.conf", "dracut-nebulalog.conf",
            "github-updates.json", "storage.conf")


def _catalog():
    entries = []
    for prefix, destination, names, mode in (
        ("appliance/nebulalog_manager/", "lib/nebulalog_manager/", MANAGER_MODULES, 0o644),
        ("appliance/adapters/nebulalog_adapters/", "lib/nebulalog_adapters/", ADAPTER_MODULES, 0o644),
        ("appliance/bin/", "bin/", COMMANDS, 0o755),
        ("appliance/adapters/bin/", "bin/", ADAPTER_COMMANDS, 0o755),
        ("appliance/systemd/", "share/templates/systemd/", UNITS, 0o644),
        ("appliance/quadlet/", "share/templates/quadlet/", QUADLETS, 0o644),
        ("appliance/security/", "share/defaults/", DEFAULTS, 0o644),
    ):
        entries.extend({"source": prefix + name, "path": destination + name, "mode": mode} for name in names)
    entries += [
        {"source": "appliance/httpd/nebulalog.conf.in", "path": "share/templates/httpd/nebulalog.conf.in", "mode": 0o644},
        {"source": "deploy/keycloak/realm.json", "path": "share/templates/keycloak/realm.json", "mode": 0o644},
    ]
    return tuple(sorted(entries, key=lambda entry: entry["path"]))


CATALOG = _catalog()
CATALOG_BY_PATH = {entry["path"]: entry for entry in CATALOG}
CATALOG_BY_SOURCE = {entry["source"]: entry for entry in CATALOG}
MANAGED_PREFIXES = ("appliance/nebulalog_manager/", "appliance/adapters/nebulalog_adapters/", "appliance/bin/",
                    "appliance/adapters/bin/", "appliance/systemd/", "appliance/quadlet/", "appliance/httpd/")


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


CATALOG_SHA256 = digest(encoded(CATALOG))


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refused("Duplicate host metadata property")
        value[key] = item
    return value


def strict_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite host metadata")))
    except (ValueError, UnicodeError) as exc:
        raise Refused("Invalid host metadata JSON") from exc


def safe_source_path(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_@.-]+(?:/[A-Za-z0-9_@.-]+)*", name):
        raise Refused("Unsafe captured source path")
    parts = name.lower().split("/")
    if (any(part in (".", "..", ".local", ".git", "node_modules", "dist", "output", "__pycache__", "secrets",
                     ".secrets", ".ssh", ".aws", ".npmrc", ".netrc", ".pypirc", ".git-credentials",
                     "test-results", "playwright-report") or part.startswith((".env", "id_rsa", "id_ecdsa", "id_ed25519")) for part in parts)
            or Path(name).suffix.lower() in (".pem", ".key", ".p12", ".pfx", ".jks", ".bcfks", ".pyc", ".pyo",
                                             ".ova", ".qcow2", ".vmdk", ".iso", ".partial")):
        raise Refused("Captured source contains a generated or credential path")


def same_file(before, after):
    return all(getattr(before, key) == getattr(after, key)
               for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink"))


def open_regular(path: Path, maximum, *, trusted=False):
    """Refuse symlinks in every path component and nonregular/hardlinked leaves."""
    path = path.absolute()
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            if part in (".", ".."):
                raise Refused("Unsafe input ancestry")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    except OSError as exc:
        raise Refused("Host input is unavailable, linked or unsafe") from exc
    finally:
        os.close(descriptor)
    info = os.fstat(leaf)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 <= info.st_size <= maximum
            or info.st_mode & 0o7022 or trusted and info.st_uid != _OWNER_UID):
        os.close(leaf)
        raise Refused("Host input must be a bounded, protected regular file without links")
    return os.fdopen(leaf, "rb"), info


def read_regular(path, maximum, *, trusted=False):
    stream, before = open_regular(path, maximum, trusted=trusted)
    with stream:
        raw = stream.read(maximum + 1)
        if len(raw) != before.st_size or not same_file(before, os.fstat(stream.fileno())):
            raise Refused("Host input changed during verification")
    return raw


def source_manifest(raw):
    value = strict_json(raw)
    if (not isinstance(value, dict) or set(value) != {"schema", "files"} or type(value["schema"]) is not int
            or value["schema"] != 1 or not isinstance(value["files"], dict) or not 1 <= len(value["files"]) <= 10000):
        raise Refused("Invalid frozen source manifest")
    for name, sha in value["files"].items():
        safe_source_path(name)
        if not isinstance(sha, str) or not SHA256.fullmatch(sha):
            raise Refused("Invalid captured source digest")
        if name.startswith(MANAGED_PREFIXES) and name not in CATALOG_BY_SOURCE:
            raise Refused("Captured host source is outside the fixed payload catalog")
    if not CATALOG_BY_SOURCE.keys() <= value["files"].keys():
        raise Refused("Frozen source lacks required host payload files")
    return value


def host_source_hash(files):
    return digest(encoded({name: files[name] for name in sorted(CATALOG_BY_SOURCE)}))


def validate_metadata(value):
    fields = {"schema", "product", "component", "abi", "platform", "version", "catalog_sha256",
              "source_snapshot_sha256", "host_source_sha256", "files"}
    if (not isinstance(value, dict) or set(value) != fields or type(value["schema"]) is not int or value["schema"] != 1
            or value["product"] != "captains-log" or value["component"] != "host" or type(value["abi"]) is not int or value["abi"] != ABI
            or value["platform"] != PLATFORM or type(value["platform"].get("major")) is not int
            or not isinstance(value["version"], str) or not VERSION.fullmatch(value["version"])
            or value["catalog_sha256"] != CATALOG_SHA256
            or any(not isinstance(value[key], str) or not SHA256.fullmatch(value[key]) for key in ("source_snapshot_sha256", "host_source_sha256"))
            or not isinstance(value["files"], list) or len(value["files"]) != len(CATALOG)):
        raise Refused("Unsupported host payload metadata, platform or ABI")
    total, sources = 0, {}
    for item, expected in zip(value["files"], CATALOG):
        if (not isinstance(item, dict) or set(item) != {"source", "path", "mode", "bytes", "sha256"}
                or any(item.get(key) != expected[key] for key in ("source", "path", "mode"))
                or type(item["mode"]) is not int or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAX_FILE
                or not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"])):
            raise Refused("Host file inventory differs from the fixed catalog")
        total += item["bytes"]
        sources[item["source"]] = item["sha256"]
    if total > MAX_TOTAL or host_source_hash(sources) != value["host_source_sha256"]:
        raise Refused("Host payload source identity or size is inconsistent")
    return value


def tar_header(name, size, mode):
    item = tarfile.TarInfo(name)
    item.size, item.mode = size, mode
    item.uid = item.gid = item.mtime = 0
    item.uname = item.gname = ""
    return item


def _scan_archive(stream, size, *, extract=None):
    """Parse bounded canonical USTAR directly; no extension expansion/extractall."""
    count, total, metadata = 0, 0, None
    while True:
        header = stream.read(512)
        if len(header) != 512:
            raise Refused("Truncated host archive header or end marker")
        if header == b"\0" * 512:
            remaining = size - stream.tell()
            canonical_size = ((stream.tell() - 512 + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
            if remaining < 512 or size != canonical_size:
                raise Refused("Incomplete host archive end marker")
            if any(stream.read(remaining)):
                raise Refused("Unexpected data after the host archive")
            if metadata is None or count != len(CATALOG) + 1:
                raise Refused("Host archive lacks its complete fixed payload")
            return metadata
        try:
            member = tarfile.TarInfo.frombuf(header, "ascii", "strict")
            canonical_header = tar_header(member.name, member.size, member.mode).tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")
        except (tarfile.HeaderError, UnicodeError, ValueError) as exc:
            raise Refused("Invalid host archive header") from exc
        maximum = MAX_METADATA if count == 0 else MAX_FILE
        if (member.type != tarfile.REGTYPE or member.linkname or member.pax_headers or member.size < 0 or member.size > maximum
                or header != canonical_header):
            raise Refused("Host archive has unsupported links, modes or metadata extensions")
        if count > len(CATALOG):
            raise Refused("Host archive has unexpected or duplicate members")
        if count == 0:
            expected_name, expected_mode = "host-payload.json", 0o644
        else:
            expected_name, expected_mode = "payload/" + CATALOG[count - 1]["path"], CATALOG[count - 1]["mode"]
        if member.name != expected_name or member.mode != expected_mode:
            raise Refused("Host archive path, order or mode differs from its fixed catalog")
        padded = (member.size + 511) // 512 * 512
        if padded > size - stream.tell():
            raise Refused("Host archive member exceeds the available bytes")
        raw = stream.read(member.size)
        padding = stream.read(padded - member.size)
        if len(raw) != member.size or any(padding):
            raise Refused("Truncated host payload or noncanonical padding")
        if count == 0:
            metadata = validate_metadata(strict_json(raw))
            if raw != encoded(metadata):
                raise Refused("Host metadata encoding is not canonical")
        else:
            item = metadata["files"][count - 1]
            total += member.size
            if total > MAX_TOTAL or member.size != item["bytes"] or digest(raw) != item["sha256"]:
                raise Refused("Host file hash or length mismatch")
            if PRIVATE_KEY.search(raw):
                raise Refused("Private key material is forbidden in host payloads")
        if extract is not None:
            extract(member.name.removeprefix("payload/"), raw, expected_mode)
        count += 1


def verify_archive(path: Path, *, expected_sha256: str, expected_host_source_sha256=None):
    if not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256):
        raise Refused("An externally verified host archive digest is required")
    stream, before = open_regular(path, MAX_ARCHIVE)
    with stream:
        raw_hash = hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else _stream_hash(stream)
        if raw_hash != expected_sha256:
            raise Refused("Host archive SHA256 mismatch")
        stream.seek(0)
        metadata = _scan_archive(stream, before.st_size)
        if not same_file(before, os.fstat(stream.fileno())):
            raise Refused("Host archive changed during verification")
    if expected_host_source_sha256 is not None and metadata["host_source_sha256"] != expected_host_source_sha256:
        raise Refused("Host source differs from the selected release")
    return {"schema": 1, "archive_sha256": raw_hash, "archive_bytes": before.st_size,
            "metadata": metadata, "archive_verified": True, "signature_verified": False,
            "runtime_executed": False, "activated": False}


def _stream_hash(stream):
    value = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024**2), b""):
        value.update(chunk)
    return value.hexdigest()


def _trusted_tree(path):
    if not path.is_absolute():
        raise Refused("Generation storage must be absolute")
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER_UID or info.st_mode & 0o022:
            raise Refused("Generation ancestry must remain protected, root-owned and nonsymlink")


def _rename_noreplace(source, destination):
    """Atomic no-clobber publication, including a competing empty directory."""
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux" and hasattr(library, "renameat2"):
        function = library.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = function(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    elif sys.platform == "darwin" and hasattr(library, "renamex_np"):
        # Allows the pure filesystem publication primitive to be tested on the
        # development Mac. stage_generation still unconditionally requires Linux root.
        function = library.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        result = function(os.fsencode(source), os.fsencode(destination), 4)
    else:
        raise Refused("Atomic no-replace directory publication is unavailable")
    if result:
        number = ctypes.get_errno()
        raise Refused("Generation publication refused an existing target" if number in (errno.EEXIST, errno.ENOTEMPTY)
                      else "Atomic generation publication failed")


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _walk_bounded(path, maximum):
    pending, count = [path], 0
    while pending:
        current = pending.pop()
        count += 1
        if count > maximum:
            raise Refused("Generation exceeds its fixed inventory")
        yield current
        if current.is_dir() and not current.is_symlink():
            with os.scandir(current) as entries:
                for entry in entries:
                    if len(pending) + count >= maximum:
                        raise Refused("Generation exceeds its fixed inventory")
                    pending.append(Path(entry.path))


def verify_generation(path: Path, evidence):
    _trusted_tree(path)
    raw_metadata = read_regular(path / "host-payload.json", MAX_METADATA, trusted=True)
    metadata = validate_metadata(strict_json(raw_metadata))
    if metadata != evidence["metadata"] or raw_metadata != encoded(evidence["metadata"]):
        raise Refused("Existing generation metadata differs from the selected release")
    expected = {entry["path"]: entry for entry in metadata["files"]}
    expected.update({"host-payload.json": {"mode": 0o644}, "staging-receipt.json": {"mode": 0o644}})
    directories = {"."}
    for name in expected:
        directories.update(str(parent) for parent in Path(name).parents)
    observed = set()
    for item in _walk_bounded(path, len(expected) + len(directories)):
        name = str(item.relative_to(path))
        info = item.lstat()
        if info.st_uid != _OWNER_UID:
            raise Refused("Generation ownership changed")
        if name in directories and stat.S_ISDIR(info.st_mode):
            if stat.S_IMODE(info.st_mode) != 0o555:
                raise Refused("Generation directories are not immutable")
            continue
        if name not in expected or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Refused("Generation contains an unexpected or linked file")
        if stat.S_IMODE(info.st_mode) != expected[name]["mode"] & ~0o222:
            raise Refused("Generation file mode changed")
        raw = read_regular(item, MAX_METADATA if name in ("host-payload.json", "staging-receipt.json") else MAX_FILE, trusted=True)
        if "bytes" in expected[name] and (len(raw) != expected[name]["bytes"] or digest(raw) != expected[name]["sha256"]):
            raise Refused("Existing generation content changed")
        observed.add(name)
    if observed != expected.keys() or read_regular(path / "staging-receipt.json", MAX_METADATA, trusted=True) != encoded(_receipt(evidence)):
        raise Refused("Generation inventory or staging receipt is incomplete")


def _receipt(evidence):
    return {"schema": 1, "abi": ABI, "archive_sha256": evidence["archive_sha256"],
            "host_source_sha256": evidence["metadata"]["host_source_sha256"],
            "source_snapshot_sha256": evidence["metadata"]["source_snapshot_sha256"],
            "archive_verified": True, "signature_verified": False, "activated": False, "runtime_executed": False}


def stage_generation(archive: Path, *, expected_sha256: str, expected_host_source_sha256: str):
    require_linux_root()
    if not isinstance(expected_host_source_sha256, str) or not SHA256.fullmatch(expected_host_source_sha256):
        raise Refused("The selected release must supply its host source digest")
    _trusted_tree(GENERATIONS.parent)
    GENERATIONS.mkdir(mode=0o755, exist_ok=True)
    _trusted_tree(GENERATIONS)
    with locked(GENERATIONS / ".stage.lock"):
        evidence = verify_archive(archive, expected_sha256=expected_sha256, expected_host_source_sha256=expected_host_source_sha256)
        destination = GENERATIONS / expected_sha256
        if destination.exists() or destination.is_symlink():
            verify_generation(destination, evidence)
            return {**_receipt(evidence), "generation": str(destination), "already_staged": True}
        if shutil.disk_usage(GENERATIONS).free < sum(entry["bytes"] for entry in evidence["metadata"]["files"]) + 64 * 1024**2:
            raise Refused("Insufficient space for an immutable host generation")
        temporary = Path(tempfile.mkdtemp(prefix=".pending-host-", dir=GENERATIONS))
        def write(name, raw, mode):
            destination = temporary / name
            destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fchmod(stream.fileno(), mode & ~0o222)
                os.fsync(stream.fileno())
        try:
            stream, before = open_regular(archive, MAX_ARCHIVE, trusted=True)
            with stream:
                if _stream_hash(stream) != expected_sha256:
                    raise Refused("Host archive changed before staging")
                stream.seek(0)
                metadata = _scan_archive(stream, before.st_size, extract=write)
                if metadata != evidence["metadata"] or not same_file(before, os.fstat(stream.fileno())):
                    raise Refused("Host archive changed during staging")
            write("staging-receipt.json", encoded(_receipt(evidence)), 0o644)
            for directory in sorted((item for item in temporary.rglob("*") if item.is_dir()), key=lambda item: len(item.parts), reverse=True):
                directory.chmod(0o555)
                _sync_directory(directory)
            temporary.chmod(0o555)
            _sync_directory(temporary)
            verify_generation(temporary, evidence)
            _rename_noreplace(temporary, destination)
            _sync_directory(GENERATIONS)
            return {**_receipt(evidence), "generation": str(destination), "already_staged": False}
        finally:
            if temporary.exists():
                # Only this newly allocated unpublished directory; never an
                # existing generation, source archive, or customer data path.
                for directory in (temporary, *temporary.rglob("*")):
                    if directory.is_dir() and not directory.is_symlink():
                        directory.chmod(0o700)
                shutil.rmtree(temporary)
