"""Explicit runtime-ready AIDE baseline enrollment and measured periodic checking.

Never initializes at image build, promotes findings, or resets an enrolled DB.
The default guard proves real FIPS/SELinux/encrypted runtime readiness. All
database, reports and scratch remain private on that verified filesystem.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import uuid

from .common import Refused, locked, require_linux_root
from .host_job_storage import PrivateRecords, StorageIdentity, digest, exact, strict_json
from .host_operations import digest_value, uuid_value
from .aide_report import parse_report, render_config

ROOT_UID = 0
MAX_DATABASE = 128 * 1024 * 1024
MAX_UNCOMPRESSED = 512 * 1024 * 1024
MAX_REPORTS = 1000
MAX_REPORT = 8 * 1024 * 1024
POLICY = Path("/usr/share/nebulalog/aide/policy.conf")
DEFAULT_CONFIG = Path("/etc/aide.conf")
BINARY = Path("/usr/sbin/aide")
DATA = Path("/var/lib/nebulalog")
RUNTIME_STAGES = {"directories", "storage-maintenance", "certificates", "images", "environment", "realm", "postgresql", "migrations", "identity", "lifecycle", "edge", "installed-release"}
FACTS = {"installation_id", "aide_version", "aide_package", "aide_binary_sha256", "policy_sha256",
         "default_config_sha256", "source_snapshot_sha256", "source_dirty", "installed_release_sha256", "runtime_ready_sha256", "runtime_configuration_sha256",
         "factory_kernel_manifest_sha256", "factory_kernel_inventory_sha256", "ordinary_boot_snapshot_sha256"}
MONITOR_FACTS = {"installation_id", "aide_version", "aide_package", "aide_binary_sha256", "policy_sha256", "default_config_sha256"}


@dataclass
class Result:
    code: int
    stdout: str = ""
    stderr: str = ""


def command(argv, *, tmpdir, timeout=30, maximum=MAX_REPORT):
    """Bound output/time/files; terminate only this invocation's owned child group."""
    def file_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_DATABASE, MAX_DATABASE))
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin", "TMPDIR": str(tmpdir)},
                               start_new_session=True, preexec_fn=file_limit)
    output, size, deadline = {"stdout": bytearray(), "stderr": bytearray()}, 0, time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as select:
            select.register(process.stdout, selectors.EVENT_READ, "stdout")
            select.register(process.stderr, selectors.EVENT_READ, "stderr")
            while select.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refused("aide_command_timeout")
                for key, _ in select.select(min(remaining, 1)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        select.unregister(key.fileobj)
                        continue
                    size += len(chunk)
                    if size > maximum:
                        raise Refused("aide_output_limit")
                    output[key.data].extend(chunk)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return Result(code, output["stdout"].decode("utf-8", "strict"), output["stderr"].decode("utf-8", "strict"))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()
        process.stderr.close()


def protected_bytes(path, *, maximum=MAX_DATABASE, private=False, device=None):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise Refused("unsafe_aide_ancestry")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != ROOT_UID or before.st_nlink != 1
                or before.st_mode & (0o077 if private else 0o022) or not 0 < before.st_size <= maximum
                or device is not None and before.st_dev != device):
            raise Refused("unsafe_aide_file")
        value = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        if len(value) > maximum or any(getattr(before, key) != getattr(after, key) for key in ("st_ino", "st_dev", "st_size", "st_mtime_ns", "st_ctime_ns")):
            raise Refused("aide_file_changed")
        return value


def sha(value):
    return hashlib.sha256(value).hexdigest()


def present(path):
    return path.exists() or path.is_symlink()


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def runtime_storage():
    """AIDE-only prefinalization gate; never weakens the general job/storage gate."""
    require_linux_root()
    from .firstboot import FirstBoot, RUNTIME_CHECKS
    gate = FirstBoot().gate()  # Actual foundation controls and enrolled LUKS/XFS.
    if gate.get("host_ready") is not True:
        raise Refused("aide_host_not_ready")
    installation = uuid_value(gate.get("installation_id"))
    for directory in (DATA, *DATA.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise Refused("aide_unsafe_storage_ancestry")
    device = DATA.stat().st_dev
    ready = strict_json(protected_bytes(Path("/etc/nebulalog/bootstrap/runtime-ready.json"), maximum=65536, private=True))
    state = strict_json(protected_bytes(DATA / "configuration/bootstrap/runtime-state.json", maximum=65536, private=True, device=device))
    from .firstboot import Locations
    from .restore_runtime import valid_restored_state
    restored = valid_restored_state(state, Locations(data=DATA)) if isinstance(state, dict) and state.get("kind") == "configuration-restore" else False
    if (type(ready) is not dict or type(state) is not dict
            or type(ready.get("schema")) is not int or ready["schema"] != 1
            or type(state.get("schema")) is not int or state["schema"] != 1
            or ready.get("state") != "runtime-ready" or ready.get("installation_id") != installation
            or type(ready.get("checks")) is not dict
            or not all(ready.get("checks", {}).get(key) is True for key in RUNTIME_CHECKS)
            or state.get("installation_id") != installation or state.get("identity_initialized") is not True
            or state.get("active_stage") is not None or type(state.get("completed")) is not list
            or any(type(stage) is not str for stage in state["completed"])
            or not restored and (len(state["completed"]) != len(RUNTIME_STAGES) or set(state["completed"]) != RUNTIME_STAGES)
            or state.get("kind") == "configuration-restore" and not restored):
        raise Refused("aide_runtime_configuration_incomplete")
    return StorageIdentity(installation, DATA, device)


def coordination_locks(identity):
    return (Path("/etc/nebulalog/bootstrap/firstboot.lock"), identity.root / "configuration/bootstrap/runtime.lock",
            identity.root / "configuration/baseline.lock")


def default_monitor(identity, policy, runner, tmpdir):
    """Validate the trusted checker, not the files whose changes it should detect."""
    package = runner(["/usr/bin/rpm", "--query", "--queryformat", "%{NEVRA}\n", "aide"], tmpdir=tmpdir)
    verified = runner(["/usr/bin/rpm", "--verify", "aide"], tmpdir=tmpdir)
    version = runner([str(BINARY), "--version"], tmpdir=tmpdir)
    if (package.code != 0 or package.stderr.strip() or not re.fullmatch(r"aide-0\.19\.2-[A-Za-z0-9._+]+\.x86_64", package.stdout.strip())
            or verified.code not in (0, 1) or verified.stderr.strip()
            or verified.code == 0 and verified.stdout.strip()
            or verified.code == 1 and not re.fullmatch(r"[S.]\.[5.]\.{4}[T.]\.\s+c\s+/etc/aide\.conf", verified.stdout.strip())
            or version.code != 0 or not re.search(r"(?m)^AIDE 0\.19\.2\s*$", version.stdout + version.stderr)):
        raise Refused("aide_package_not_verified")
    return {"installation_id": identity.installation_id, "aide_version": "0.19.2", "aide_package": package.stdout.strip(),
            "aide_binary_sha256": sha(protected_bytes(BINARY, maximum=16 * 1024 * 1024)),
            "policy_sha256": sha(protected_bytes(policy, maximum=65536)),
            "default_config_sha256": sha(protected_bytes(DEFAULT_CONFIG, maximum=65536, private=True))}


def factory_kernel_facts(source, runner, tmpdir):
    """Initial enrollment only; later pruning cannot rewrite factory facts."""
    helper = Path('/usr/libexec/nebulalog/factory-kernel')
    if source['files'].get('appliance/factory_kernel.py') != sha(protected_bytes(helper, maximum=2 * 1024 * 1024)):
        raise Refused('aide_factory_kernel_helper_changed')
    result = runner(['/usr/bin/python3.14', '-I', '-B', str(helper), '--verify'], tmpdir=tmpdir, timeout=600)
    if result.code != 0 or result.stderr.strip():
        raise Refused('aide_factory_kernel_provenance_not_verified')
    value = strict_json(result.stdout)
    exact(value, {'schema', 'verified', 'kernel', 'manifest_sha256', 'inventory_sha256'})
    root = Path('/usr/share/nebulalog/kernel-provenance')
    if (type(value['schema']) is not int or value['schema'] != 1 or value['verified'] is not True
            or not re.fullmatch(r'5\.14\.0-[0-9.]+\.el9_8\.x86_64', str(value['kernel']))
            or value['manifest_sha256'] != sha(protected_bytes(root / 'manifest.json', maximum=65536, private=True))
            or value['inventory_sha256'] != sha(protected_bytes(root / 'installed-inventory.xml', maximum=MAX_DATABASE, private=True))):
        raise Refused('aide_factory_kernel_provenance_changed')
    return {'factory_kernel_manifest_sha256': value['manifest_sha256'],
            'factory_kernel_inventory_sha256': value['inventory_sha256']}


def verify_initial_boot_snapshot(identity, expected_sha):
    """Read the immutable enrollment root, never recapture a later boot."""
    from . import kernel_updates, ordinary_boot_state
    digest_value(expected_sha)
    path = identity.root / 'manager/boot-integrity/initial.json'
    PrivateRecords(lambda: identity).directory(path.parent, identity)
    raw = protected_bytes(path, maximum=MAX_DATABASE, private=True, device=identity.device)
    value = strict_json(raw)
    ordinary_boot_state.validate_snapshot(value)
    if raw != kernel_updates.encode(value) or sha(raw) != expected_sha:
        raise Refused('aide_initial_boot_snapshot_changed')
    return value


def initial_boot_snapshot(identity, runner, tmpdir):
    """Capture before the first init and require exact stability through enroll.

    A late writer invalidates the candidate; its original snapshot is retained.
    Missing evidence after any candidate or enrollment exists requires explicit
    recovery, never automatic recapture or re-enrollment.
    """
    from . import kernel_updates, ordinary_boot_state
    path = identity.root / 'manager/boot-integrity/initial.json'
    state = identity.root / 'manager/aide'
    records = PrivateRecords(lambda: identity)

    def native(argv, *, timeout=120):
        maximum = kernel_updates.rpm.MAX_XML if argv == ['/usr/bin/rpm', '--query', '--all', '--xml'] else MAX_REPORT
        result = runner(argv, tmpdir=tmpdir, timeout=timeout, maximum=maximum)
        if result.code != 0 or result.stderr.strip():
            raise Refused('aide_initial_boot_command_failed')
        return result.stdout.strip()

    if not present(path):
        if any(present(item) for item in (state.parent / 'aide-enrollment.json',
                state / 'candidate.json', state / 'candidate.db.gz', state / 'aide.db.gz', state / 'commit-pending.json')):
            raise Refused('aide_initial_boot_snapshot_missing')
        records.directory(path.parent, identity, create=True)
        if any(path.parent.iterdir()):
            raise Refused('aide_unowned_boot_integrity_state')
        value = ordinary_boot_state.capture(runner=native)
        ordinary_boot_state.validate_snapshot(value)
        raw = kernel_updates.encode(value)
        if not 0 < len(raw) <= MAX_DATABASE:
            raise Refused('aide_initial_boot_snapshot_too_large')
        # Reuse AIDE's private atomic writer and durability barriers. The caller
        # already holds manager/firstboot/runtime/baseline locks.
        Aide(storage_guard=lambda: identity, reader=protected_bytes)._write_bytes(path, raw, identity)
    raw = protected_bytes(path, maximum=MAX_DATABASE, private=True, device=identity.device)
    checksum = sha(raw)
    retained = verify_initial_boot_snapshot(identity, checksum)
    current = ordinary_boot_state.capture(runner=native)
    ordinary_boot_state.validate_snapshot(current)
    if current != retained:
        raise Refused('aide_initial_boot_snapshot_not_current')
    # Retry also crosses durability barriers after a prior rename succeeded
    # but its directory fsync failed; reading the retained file is not enough.
    Aide(storage_guard=lambda: identity, reader=protected_bytes)._sync(
        path, path.parent, path.parent.parent, identity.root)
    return {'ordinary_boot_snapshot_sha256': checksum}


def default_facts(identity, policy, runner, tmpdir):
    """Bind the first baseline to sealed setup, measured AIDE and captured code."""
    base = Path("/etc/nebulalog")
    if protected_bytes(base / "bootstrap/image-state", maximum=64, private=True) != b"sealed\n":
        raise Refused("aide_requires_sealed_image")
    for path in (base / "bootstrap/unsealed-build", base / "bootstrap/private-build.json", Path("/home/packer"), Path("/etc/sudoers.d/nebulalog-build")):
        if path.exists() or path.is_symlink():
            raise Refused("aide_refuses_build_identity")
    try:
        pwd.getpwnam("packer")
    except KeyError:
        pass
    else:
        raise Refused("aide_refuses_build_identity")
    from .update_enrollment import UpdateEnrollment, _installed_state
    descriptor, descriptor_hash, _ = UpdateEnrollment()._descriptor()
    _, enrolled, current = _installed_state(identity.root / "manager/updates")
    if (enrolled["installation_id"] != identity.installation_id or enrolled["initial_release_sha256"] != descriptor_hash
            or enrolled["provenance"] != descriptor or current != enrolled["current"]):
        raise Refused("aide_initial_release_changed")
    source = strict_json(protected_bytes(Path("/usr/share/nebulalog/source-manifest.json"), maximum=8 * 1024 * 1024))
    # Factory generations use fixed captured wrappers and immutable module paths.
    # Verify their measured installation before creating the first baseline.
    if present(Path("/usr/share/nebulalog/initial-host.json")):
        host = UpdateEnrollment().verify_initial_host_installation()
        if (type(host) is not dict or type(host.get("schema")) is not int or host["schema"] != 1
                or host.get("verified") is not True
                or host.get("source_snapshot_sha256") != descriptor["source_snapshot_sha256"]
                or host.get("initial_release_sha256") != descriptor_hash
                or host.get("host") != current["components"].get("host")
                or not isinstance(host.get("source_mappings"), dict)
                or "appliance/nebulalog_manager/aide.py" not in host["source_mappings"]):
            raise Refused("aide_initial_host_identity_changed")
        mappings = {}
    else:
        mappings = {name: Path("/usr/lib/nebulalog") / name.removeprefix("appliance/")
                    for name in source["files"] if name.startswith("appliance/nebulalog_manager/") and name.endswith(".py")}
        mappings.update({name: Path("/usr/lib/nebulalog/nebulalog_adapters") / name.rsplit("/", 1)[1]
                         for name in source["files"] if name.startswith("appliance/adapters/nebulalog_adapters/") and name.endswith(".py")})
        if "appliance/nebulalog_manager/aide.py" not in mappings:
            raise Refused("aide_missing_captured_source")
        mappings["appliance/bin/nebulalog-aide"] = Path("/usr/libexec/nebulalog/nebulalog-aide")
    mappings.update({"appliance/security/aide-policy.conf": policy,
                     "appliance/security/aide.conf": DEFAULT_CONFIG,
                     "appliance/systemd/nebulalog-aide.service": Path("/etc/systemd/system/nebulalog-aide.service"),
                     "appliance/systemd/nebulalog-aide.timer": Path("/etc/systemd/system/nebulalog-aide.timer")})
    for source_path, installed in mappings.items():
        if source["files"].get(source_path) != sha(protected_bytes(installed, maximum=2 * 1024 * 1024)):
            raise Refused("aide_installed_source_mismatch")
    monitor = default_monitor(identity, policy, runner, tmpdir)
    ready = protected_bytes(base / "bootstrap/runtime-ready.json", maximum=65536, private=True)
    setup = protected_bytes(identity.root / "configuration/bootstrap/setup.json", maximum=65536, private=True, device=identity.device)
    state = protected_bytes(identity.root / "configuration/bootstrap/runtime-state.json", maximum=65536, private=True, device=identity.device)
    if any(strict_json(item).get("installation_id") != identity.installation_id for item in (ready, setup, state)):
        raise Refused("aide_runtime_identity_changed")
    # Selection must be fixed before AIDE enrollment; scan/review outputs come later.
    selected = strict_json(protected_bytes(identity.root / "configuration/security-policy.json", maximum=1024 * 1024, private=True, device=identity.device))
    if selected.get("installation_id") != identity.installation_id or selected.get("baseline") != strict_json(setup).get("baseline"):
        raise Refused("aide_baseline_policy_not_selected")
    factory = factory_kernel_facts(source, runner, tmpdir)
    return {**monitor, **factory, **initial_boot_snapshot(identity, runner, tmpdir),
            "source_snapshot_sha256": descriptor["source_snapshot_sha256"], "source_dirty": descriptor["source_dirty"],
            "installed_release_sha256": descriptor_hash, "runtime_ready_sha256": sha(ready),
            "runtime_configuration_sha256": digest({"setup": sha(setup), "state": sha(state)})}


class Aide:
    def __init__(self, *, storage_guard=runtime_storage, facts=default_facts, policy=POLICY,
                 runner=command, reader=protected_bytes, clock=timestamp, monitor=default_monitor, lock_paths=coordination_locks,
                 boot_snapshot=verify_initial_boot_snapshot):
        self.guard, self.facts, self.policy, self.runner, self.reader, self.clock = storage_guard, facts, policy, runner, reader, clock
        self.monitor = monitor
        self.lock_paths = lock_paths
        self.boot_snapshot = boot_snapshot
        self.records = PrivateRecords(storage_guard)

    @contextlib.contextmanager
    def _locked(self, *, create=False):
        try:
            identity = self.guard()
            manager = identity.root / "manager"
            self.records.directory(manager, identity, create=create)
            lock = manager / "transaction.lock"
            if lock.exists() or lock.is_symlink():
                self.records._file(lock.lstat(), identity, allow_empty=True)
            with locked(lock), contextlib.ExitStack() as extra_locks:
                # One order across cooperating managers: manager -> firstboot -> runtime -> baseline.
                for path in self.lock_paths(identity):
                    for parent in path.parents:
                        info = parent.lstat()
                        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
                            raise Refused("aide_unsafe_lock_ancestry")
                    if present(path):
                        info = path.lstat()
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                            raise Refused("aide_unsafe_coordination_lock")
                    extra_locks.enter_context(locked(path))
                state = manager / "aide"
                if present(manager / "aide-enrollment.json") and not state.exists():
                    raise Refused("aide_enrolled_state_missing")
                if create or state.exists() or state.is_symlink():
                    self.records.directory(state, identity, create=create)
                    for name in ("reports", "tmp"):
                        self.records.directory(state / name, identity, create=create)
                yield state, identity
        except OSError:
            raise Refused("aide_storage_unavailable") from None

    def _bytes(self, path, identity, maximum=MAX_DATABASE):
        return self.reader(path, maximum=maximum, private=True, device=identity.device)

    @contextlib.contextmanager
    def _review_locked(self):
        """Read existing review state under the normal lock order, without creation."""
        try:
            identity = self.guard()
            if type(identity) is not StorageIdentity:
                raise Refused("aide_review_identity_invalid")
            uuid_value(identity.installation_id)
            manager = identity.root / "manager"
            self.records.directory(manager, identity)
            with contextlib.ExitStack() as opened:
                paths = (manager / "transaction.lock", *self.lock_paths(identity))
                for index, path in enumerate(paths):
                    if not isinstance(path, Path) or not path.is_absolute() or path != Path(os.path.normpath(path)):
                        raise Refused("aide_unsafe_coordination_lock")
                    if index:
                        for parent in path.parents:
                            info = parent.lstat()
                            if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
                                raise Refused("aide_unsafe_lock_ancestry")
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    opened.callback(os.close, fd)
                    info = os.fstat(fd)
                    if index == 0:
                        self.records._file(info, identity, allow_empty=True)
                    elif (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID
                          or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                        raise Refused("aide_unsafe_coordination_lock")
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        raise Refused("aide_review_busy") from None
                state = manager / "aide"
                self.records.directory(state, identity)
                self.records.directory(state / "reports", identity)
                self.records.directory(state / "tmp", identity)
                yield state, identity
        except OSError:
            raise Refused("aide_review_evidence_unavailable") from None

    def _write_bytes(self, path, content, identity):
        self.records.directory(path.parent, identity)
        if path.exists() or path.is_symlink():
            if self._bytes(path, identity) != content:
                raise Refused("aide_existing_artifact_differs")
            self._sync(path, path.parent)
            return
        fd, temporary = tempfile.mkstemp(prefix=".aide-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            # Root-only directory and the global lock exclude concurrent writers.
            # Rename avoids a two-hard-link crash window during initial enrollment.
            os.rename(temporary, path)
            self._sync(path.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _sync(self, *paths):
        for path in paths:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def _facts(self, identity, state):
        if self.guard() != identity:
            raise Refused("aide_host_guard_changed")
        value = self.facts(identity, self.policy, self.runner, state / "tmp")
        exact(value, FACTS)
        if (value["installation_id"] != identity.installation_id or value["aide_version"] != "0.19.2"
                or type(value["source_dirty"]) is not bool
                or not re.fullmatch(r"aide-0\.19\.2-[A-Za-z0-9._+]+\.x86_64", value["aide_package"])):
            raise Refused("aide_invalid_host_evidence")
        for key in FACTS - {"installation_id", "aide_version", "aide_package", "source_dirty"}:
            digest_value(value[key])
        policy = self.reader(self.policy, maximum=65536).decode("utf-8", "strict")
        if sha(policy.encode()) != value["policy_sha256"]:
            raise Refused("aide_policy_changed")
        return value, policy

    def _monitor(self, identity, state, enrolled):
        if self.guard() != identity:
            raise Refused("aide_host_guard_changed")
        current = self.monitor(identity, self.policy, self.runner, state / "tmp")
        exact(current, MONITOR_FACTS)
        if current != {key: enrolled["facts"][key] for key in MONITOR_FACTS}:
            raise Refused("aide_monitor_context_changed")
        policy = self.reader(self.policy, maximum=65536).decode("utf-8", "strict")
        if sha(policy.encode()) != current["policy_sha256"]:
            raise Refused("aide_policy_changed")
        return policy

    def _confirm_candidate(self, state, identity, candidate):
        report = state / "reports" / (uuid_value(candidate["report_id"]) + ".json")
        if digest(self.records.read(report, identity)) != candidate["report_sha256"]:
            raise Refused("aide_candidate_report_changed")
        self._sync(state / "candidate.db.gz", state / "candidate.json", report,
                   state / "reports", state, state.parent, identity.root)

    def _config(self, state, identity, policy, *, stage):
        if stage not in ("init", "candidate", "enrolled"):
            raise Refused("aide_invalid_stage")
        name = stage + ".conf"
        database_in = state / ("candidate.db.gz" if stage == "candidate" else "aide.db.gz")
        database_out = state / ("candidate.db.gz" if stage == "init" else "unused-output.db.gz")
        content = render_config(policy, str(database_in), str(database_out)).encode()
        path = state / name
        self._write_bytes(path, content, identity)
        result = self.runner(["/usr/sbin/restorecon", "-R", str(state)], tmpdir=state / "tmp")
        if result.code != 0:
            raise Refused("aide_labels_not_applied")
        result = self.runner([str(BINARY), "--config=" + str(path), "--config-check"], tmpdir=state / "tmp")
        if result.code != 0 or result.stderr.strip():
            raise Refused("aide_configuration_invalid")
        return path

    def _database(self, path, identity):
        data = self._bytes(path, identity)
        # Validate compressed stream completion and bound decompression before use.
        import io
        size = 0
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
                while block := source.read(1024 * 1024):
                    size += len(block)
                    if size > MAX_UNCOMPRESSED:
                        raise Refused("aide_database_expansion_limit")
        except (OSError, EOFError):
            raise Refused("aide_database_invalid") from None
        if size == 0:
            raise Refused("aide_database_empty")
        return data, sha(data)

    def _report(self, state, identity, config, action, facts, database_sha=None):
        if len(list((state / "reports").iterdir())) >= MAX_REPORTS:
            raise Refused("aide_report_storage_full")
        report_id = str(uuid.uuid4())
        record = {"schema": 1, "id": report_id, "action": action, "observed_at": self.clock(), "facts_sha256": digest(facts),
                  "database_sha256": database_sha, "state": "error", "exit_code": None}
        try:
            result = self.runner([str(BINARY), "--config=" + str(config), "--" + action], tmpdir=state / "tmp", timeout=3600)
            record.update(exit_code=result.code, stdout=result.stdout, stderr=result.stderr)
            expected = state / ("candidate.db.gz" if config.name in ("init.conf", "candidate.conf") else "aide.db.gz")
            record.update(parse_report(result.stdout, result.stderr, result.code, action, str(expected)))
        except Exception:
            # Full bounded output, when available, stays only in the encrypted report.
            record["state"] = "error"
        record["observed_at"] = self.clock()  # Completed observation, not scan-start time.
        self.records.write(state / "reports" / (report_id + ".json"), record, identity)
        summary = {key: record[key] for key in ("schema", "id", "action", "observed_at", "facts_sha256", "database_sha256", "state", "exit_code")}
        if "counts" in record:
            summary["counts"] = record["counts"]
        summary["report_sha256"] = digest(record)
        self.records.write(state / "last-result.json", summary, identity)
        return summary

    def _candidate(self, state, identity):
        value = self.records.read(state / "candidate.json", identity)
        exact(value, ("schema", "id", "state", "facts", "created_at", "database_sha256", "report_id", "report_sha256", "confirmation"))
        if type(value["schema"]) is not int or value["schema"] != 1 or value["state"] not in ("initializing", "prepared") or value["facts"]["installation_id"] != identity.installation_id:
            raise Refused("aide_candidate_invalid")
        uuid_value(value["id"])
        if value["confirmation"] != digest({key: item for key, item in value.items() if key != "confirmation"}):
            raise Refused("aide_candidate_changed")
        if value["state"] == "prepared":
            digest_value(value["database_sha256"])
            uuid_value(value["report_id"])
            digest_value(value["report_sha256"])
        return value

    def _verified_candidate_report(self, state, identity, candidate, facts):
        """Read and reparse the original evidence bound to a confirmation; no writes."""
        try:
            exact(candidate["facts"], FACTS)
            if digest(candidate["facts"]) != digest(facts):
                raise Refused("aide_candidate_context_changed")
            report = self.records.read(state / "reports" / (candidate["report_id"] + ".json"), identity)
            exact(report, ("schema", "id", "action", "observed_at", "facts_sha256", "database_sha256",
                           "state", "exit_code", "stdout", "stderr", "counts", "aide_version"))
            if (digest(report) != candidate["report_sha256"] or type(report["schema"]) is not int
                    or report["schema"] != 1 or report["id"] != candidate["report_id"]
                    or report["action"] != "check" or report["state"] != "clean"
                    or type(report["exit_code"]) is not int or report["exit_code"] != 0
                    or report["facts_sha256"] != digest(facts)
                    or report["database_sha256"] != candidate["database_sha256"]):
                raise Refused("aide_candidate_report_changed")
            measured = parse_report(report["stdout"], report["stderr"], report["exit_code"], "check",
                                    str(state / "candidate.db.gz"))
            if (measured["state"] != "clean" or report["aide_version"] != measured["aide_version"]
                    or digest(report["counts"]) != digest(measured["counts"])):
                raise Refused("aide_candidate_report_changed")
            return report, measured
        except (OSError, ValueError, KeyError, TypeError):
            raise Refused("aide_candidate_report_unavailable") from None

    def review(self):
        """Return only verified candidate metadata; never initialize or scan.

        The original clean verification report is content-bound into the typed
        enrollment confirmation.  Its timestamp describes historical evidence;
        enrollment still performs its separate fresh filesystem check.
        """
        try:
            with self._review_locked() as (state, identity):
                candidate = self._candidate(state, identity)
                if candidate["state"] != "prepared":
                    raise Refused("aide_review_requires_prepared_candidate")
                exact(candidate["facts"], FACTS)
                facts, _ = self._facts(identity, state)
                if digest(candidate["facts"]) != digest(facts):
                    raise Refused("aide_candidate_context_changed")
                if self._database(state / "candidate.db.gz", identity)[1] != candidate["database_sha256"]:
                    raise Refused("aide_candidate_database_changed")
                report_path = state / "reports" / (candidate["report_id"] + ".json")
                report, measured = self._verified_candidate_report(state, identity, candidate, facts)

                def safe_time(value):
                    if not isinstance(value, str) or len(value) > 64:
                        raise Refused("aide_review_timestamp_invalid")
                    parsed = datetime.fromisoformat(value)
                    if parsed.tzinfo is None:
                        raise Refused("aide_review_timestamp_invalid")
                    return parsed.isoformat()

                created = safe_time(candidate["created_at"])
                observed = safe_time(report["observed_at"])
                enrolled = present(state.parent / "aide-enrollment.json")
                if enrolled:
                    receipt = self._enrolled(state, identity)
                    if self._database(state / "aide.db.gz", identity)[1] != receipt["database_sha256"]:
                        raise Refused("aide_enrolled_database_changed")
                if self.guard() != identity:
                    raise Refused("aide_review_identity_changed")
                # Recheck mutable evidence after the final injected guard callback.
                if (digest(self._candidate(state, identity)) != digest(candidate)
                        or digest(self.records.read(report_path, identity)) != candidate["report_sha256"]
                        or self._database(state / "candidate.db.gz", identity)[1] != candidate["database_sha256"]):
                    raise Refused("aide_review_evidence_changed")
                return {"candidate_id": candidate["id"], "created_at": created,
                        "confirmation": candidate["confirmation"], "database_sha256": candidate["database_sha256"],
                        "facts": dict(facts), "report": {"id": report["id"], "observed_at": observed,
                        "state": "clean", "exit_code": 0, "counts": dict(measured["counts"])}, "enrolled": enrolled}
        except (OSError, ValueError, KeyError, TypeError):
            raise Refused("aide_review_evidence_unavailable") from None

    def _initial_enrollment(self, state, identity):
        """Validate the immutable, explicitly reviewed factory baseline."""
        value = self.records.read(state.parent / "aide-enrollment.json", identity)
        exact(value, ("schema", "state", "installation_id", "facts", "candidate_confirmation", "database_sha256", "verified_report_id", "enrolled_at"))
        if type(value["schema"]) is not int or value["schema"] != 1 or value["state"] != "enrolled" or value["installation_id"] != identity.installation_id:
            raise Refused("aide_enrollment_invalid")
        digest_value(value["candidate_confirmation"])
        digest_value(value["database_sha256"])
        uuid_value(value["verified_report_id"])
        exact(value["facts"], FACTS)
        self.boot_snapshot(identity, value['facts']['ordinary_boot_snapshot_sha256'])
        if self.records.read(state / "commit-pending.json", identity) != value:
            raise Refused("aide_enrollment_receipt_changed")
        candidate = self._candidate(state, identity)
        if (candidate["state"] != "prepared" or candidate["confirmation"] != value["candidate_confirmation"]
                or candidate["facts"] != value["facts"] or candidate["database_sha256"] != value["database_sha256"]):
            raise Refused("aide_enrollment_receipt_changed")
        self._verified_candidate_report(state, identity, candidate, value["facts"])
        return value

    def _enrolled(self, state, identity):
        from .aide_updates import active_enrollment
        return active_enrollment(self, state, identity, self._initial_enrollment(state, identity))

    def authorized_update_prepare(self, stage, plan_path):
        """Fixed lifecycle integration; caller already owns both update locks."""
        from .aide_updates import prepare
        return prepare(self, stage, plan_path)

    def authorized_update_accept(self, stage, plan_path, *, direction="forward"):
        """Accept only the measured filesystem delta of this host transaction."""
        from .aide_updates import accept
        return accept(self, stage, plan_path, direction=direction)

    def prepare(self):
        with self._locked(create=True) as (state, identity):
            if present(state.parent / "aide-enrollment.json") or present(state / "aide.db.gz"):
                raise Refused("aide_already_enrolled_or_commit_pending")
            facts, policy = self._facts(identity, state)
            if present(state / "candidate.json"):
                candidate = self._candidate(state, identity)
                if candidate["facts"] != facts:
                    raise Refused("aide_candidate_context_changed")
                if candidate["state"] == "prepared":
                    if self._database(state / "candidate.db.gz", identity)[1] != candidate["database_sha256"]:
                        raise Refused("aide_candidate_database_changed")
                    self._confirm_candidate(state, identity, candidate)
                    return candidate
            else:
                if any((state / name).exists() or (state / name).is_symlink() for name in ("candidate.db.gz", "commit-pending.json")):
                    raise Refused("aide_unowned_candidate")
                candidate = {"schema": 1, "id": str(uuid.uuid4()), "state": "initializing", "facts": facts,
                             "created_at": self.clock(), "database_sha256": None, "report_id": None, "report_sha256": None}
                candidate["confirmation"] = digest(candidate)
                self.records.write(state / "candidate.json", candidate, identity)
            if not present(state / "candidate.db.gz"):
                config = self._config(state, identity, policy, stage="init")
                result = self._report(state, identity, config, "init", facts)
                if result["state"] != "initialized":
                    raise Refused("aide_initialization_failed_review_report")
            _, database_sha = self._database(state / "candidate.db.gz", identity)
            config = self._config(state, identity, policy, stage="candidate")
            result = self._report(state, identity, config, "check", facts, database_sha)
            if (result["state"] != "clean" or self._facts(identity, state)[0] != facts
                    or self._database(state / "candidate.db.gz", identity)[1] != database_sha):
                raise Refused("aide_candidate_not_clean_review_report")
            candidate.update(state="prepared", database_sha256=database_sha, report_id=result["id"], report_sha256=result["report_sha256"])
            candidate["confirmation"] = digest({key: item for key, item in candidate.items() if key != "confirmation"})
            self.records.write(state / "candidate.json", candidate, identity)
            self._confirm_candidate(state, identity, candidate)
            return candidate

    def enroll(self, confirmation):
        digest_value(confirmation)
        with self._locked() as (state, identity):
            candidate = self._candidate(state, identity)
            if candidate["state"] != "prepared" or candidate["confirmation"] != confirmation:
                raise Refused("aide_enrollment_review_mismatch")
            facts, policy = self._facts(identity, state)
            if facts != candidate["facts"]:
                raise Refused("aide_enrollment_context_changed")
            data, database_sha = self._database(state / "candidate.db.gz", identity)
            if database_sha != candidate["database_sha256"]:
                raise Refused("aide_candidate_database_changed")
            # Refuse lost or changed reviewed evidence before any scan or write,
            # including an idempotent enrollment retry's durability barriers.
            self._verified_candidate_report(state, identity, candidate, facts)
            marker = state.parent / "aide-enrollment.json"
            if marker.exists() or marker.is_symlink():
                enrolled = self._enrolled(state, identity)
                if enrolled.get("candidate_confirmation") != confirmation or self._database(state / "aide.db.gz", identity)[1] != database_sha:
                    raise Refused("aide_existing_enrollment_changed")
                self._sync(state / "aide.db.gz", marker, state, state.parent, identity.root)
                return enrolled
            config = self._config(state, identity, policy, stage="candidate")
            result = self._report(state, identity, config, "check", facts, database_sha)
            if (result["state"] != "clean" or self._facts(identity, state)[0] != facts
                    or self._database(state / "candidate.db.gz", identity)[1] != database_sha):
                raise Refused("aide_enrollment_not_clean_review_report")
            self._verified_candidate_report(state, identity, candidate, facts)
            receipt = {"schema": 1, "state": "enrolled", "installation_id": identity.installation_id, "facts": facts,
                       "candidate_confirmation": confirmation, "database_sha256": database_sha, "verified_report_id": result["id"], "enrolled_at": self.clock()}
            pending = state / "commit-pending.json"
            if present(pending):
                original = self.records.read(pending, identity)
                if any(original.get(key) != receipt[key] for key in ("schema", "state", "installation_id", "facts", "candidate_confirmation", "database_sha256")):
                    raise Refused("aide_pending_enrollment_changed")
                receipt = original
            else:
                self.records.write(pending, receipt, identity)
            self._write_bytes(state / "aide.db.gz", data, identity)
            self.records.write(marker, receipt, identity)
            self._sync(state / "aide.db.gz", marker, state, state.parent, identity.root)
            return receipt

    def check(self):
        with self._locked() as (state, identity):
            return self._check_locked(state, identity)

    def check_for_transaction(self, manager_lock_fd):
        """Check without reacquiring the caller's live manager-lock descriptor.

        The caller retains and closes the descriptor. No database acceptance or
        baseline change is performed; ordinary check/report semantics apply.
        """
        from .aide_updates import _locked as coordination
        identity = self.guard()
        manager = identity.root / "manager"
        self.records.directory(manager, identity)
        try:
            if type(manager_lock_fd) is not int:
                raise Refused("aide_transaction_lock_descriptor_required")
            info = os.fstat(manager_lock_fd)
            self.records._file(info, identity, allow_empty=True)
            expected = (manager / "transaction.lock").lstat()
            self.records._file(expected, identity, allow_empty=True)
            if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
                raise Refused("aide_transaction_lock_identity_changed")
            # Same open description as the outer transaction: reacquiring is
            # harmless. An unrelated competing lock refuses nonblockingly.
            fcntl.flock(manager_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with coordination(self) as (state, current):
                if current != identity:
                    raise Refused("aide_transaction_storage_changed")
                return self._check_locked(state, identity)
        except OSError:
            raise Refused("aide_transaction_lock_unavailable") from None

    def _check_locked(self, state, identity):
        marker = state.parent / "aide-enrollment.json"
        if not present(marker):
            raise Refused("aide_baseline_not_enrolled")
        attempt = {"schema": 1, "id": str(uuid.uuid4()), "observed_at": self.clock(), "state": "running", "report_id": None}
        self.records.write(state / "last-attempt.json", attempt, identity)
        try:
            enrolled = self._enrolled(state, identity)
            policy = self._monitor(identity, state, enrolled)
            facts = enrolled["facts"]
            if enrolled.get("installation_id") != identity.installation_id:
                raise Refused("aide_monitor_context_changed")
            _, database_sha = self._database(state / "aide.db.gz", identity)
            if database_sha != enrolled.get("database_sha256"):
                raise Refused("aide_enrolled_database_changed")
            config = self._config(state, identity, policy, stage="enrolled")
            result = self._report(state, identity, config, "check", facts, database_sha)
            if self._database(state / "aide.db.gz", identity)[1] != database_sha or self._monitor(identity, state, enrolled) != policy:
                raise Refused("aide_context_changed_during_check")
            attempt.update(state="complete", report_id=result["id"])
            self.records.write(state / "last-attempt.json", attempt, identity)
            return result
        except Exception:
            attempt["state"] = "error"
            self.records.write(state / "last-attempt.json", attempt, identity)
            raise

    def status(self):
        with self._locked() as (state, identity):
            return self._read_status(state, identity)

    def firstboot_checks(self, installation_id):
        """Caller owns firstboot/runtime locks; take only existing manager lock, nonblocking.

        No scan, initialization, state creation, baseline acceptance or promotion.
        This verifies recent recorded evidence, never continuous filesystem integrity.
        """
        try:
            return self._firstboot_checks(installation_id)
        except (OSError, ValueError, KeyError, TypeError):
            raise Refused("aide_completion_evidence_unavailable") from None

    def _firstboot_checks(self, installation_id):
        identity = self.guard()
        if identity.installation_id != uuid_value(installation_id):
            raise Refused("aide_completion_identity_changed")
        manager = identity.root / "manager"
        self.records.directory(manager, identity)
        fd = os.open(manager / "transaction.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            self.records._file(os.fstat(fd), identity, allow_empty=True)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused("aide_completion_evidence_busy") from None
            state = manager / "aide"
            self.records.directory(state, identity)
            try:
                attempt = self.records.read(state / "last-attempt.json", identity)
            except FileNotFoundError:
                raise Refused("aide_completion_requires_completed_check") from None
            if attempt.get("state") != "complete" or not attempt.get("report_id"):
                raise Refused("aide_completion_requires_completed_check")
            status = self._read_status(state, identity)
            last = status.get("last_check") or {}
            if (status["baseline"] != "enrolled" or last.get("state") != "clean" or last.get("exit_code") != 0
                    or last.get("id") != attempt["report_id"] or not last.get("counts", {}).get("total")):
                raise Refused("aide_completion_requires_clean_check")
            observed, now = datetime.fromisoformat(last["observed_at"]), datetime.fromisoformat(self.clock())
            if observed.tzinfo is None or now.tzinfo is None or not 0 <= (now - observed).total_seconds() <= 300:
                raise Refused("aide_completion_check_stale")
            if self.guard() != identity:
                raise Refused("aide_completion_identity_changed")
            return {"aide_enrolled": True, "aide_checked_clean": True}
        finally:
            os.close(fd)

    def _read_status(self, state, identity):
        result = {"schema": 1, "installation_id": identity.installation_id, "baseline": "not_enrolled", "last_check": None,
                  "certification": "not asserted"}
        marker = state.parent / "aide-enrollment.json"
        if not present(marker):
            return result
        enrolled = self._enrolled(state, identity)
        self._monitor(identity, state, enrolled)
        if enrolled.get("installation_id") != identity.installation_id or self._database(state / "aide.db.gz", identity)[1] != enrolled.get("database_sha256"):
            raise Refused("aide_enrolled_database_changed")
        result["baseline"] = "enrolled"
        result["database_sha256"] = enrolled["database_sha256"]
        result["enrolled_at"] = enrolled["enrolled_at"]
        if (state / "last-attempt.json").exists():
            attempt = self.records.read(state / "last-attempt.json", identity)
            exact(attempt, ("schema", "id", "observed_at", "state", "report_id"))
            uuid_value(attempt["id"])
            if attempt["state"] in ("running", "error"):
                result["last_check"] = {"observed_at": attempt["observed_at"], "state": "interrupted" if attempt["state"] == "running" else "error", "id": attempt["id"]}
                return result
            if attempt["state"] != "complete":
                raise Refused("aide_check_attempt_invalid")
        else:
            attempt = None
        if (state / "last-result.json").exists():
            summary = self.records.read(state / "last-result.json", identity)
            report_id = uuid_value(summary.get("id"))
            report = self.records.read(state / "reports" / (report_id + ".json"), identity)
            if (digest(report) != summary.get("report_sha256") or summary.get("database_sha256") != enrolled["database_sha256"]
                    or report.get("facts_sha256") != digest(enrolled["facts"])
                    or attempt is not None and attempt["report_id"] != report_id
                    or any(summary.get(key) != report.get(key) for key in ("state", "counts", "exit_code", "observed_at", "facts_sha256", "database_sha256"))):
                raise Refused("aide_check_report_changed")
            result["last_check"] = {key: summary[key] for key in ("observed_at", "state", "exit_code", "id")}
            if "counts" in summary:
                result["last_check"]["counts"] = summary["counts"]
            when = datetime.fromisoformat(summary["observed_at"])
            now = datetime.fromisoformat(self.clock())
            if when.tzinfo is None or now.tzinfo is None:
                raise Refused("aide_check_timestamp_invalid")
            result["last_check"]["stale"] = not 0 <= (now - when).total_seconds() <= 48 * 3600
        return result


def firstboot_checks(installation_id):
    """Fixed read-only bootstrap integration; errors keep final setup incomplete."""
    return Aide().firstboot_checks(installation_id)


def authorized_update_prepare(stage, plan_path):
    return Aide().authorized_update_prepare(stage, plan_path)


def authorized_update_accept(stage, plan_path, *, direction="forward"):
    return Aide().authorized_update_accept(stage, plan_path, direction=direction)

def main():
    parser = argparse.ArgumentParser(description="Explicit runtime-ready AIDE baseline and integrity checks")
    parser.add_argument("action", choices=("prepare", "enroll", "check", "status"))
    parser.add_argument("--confirmation")
    args = parser.parse_args()
    try:
        os.umask(0o077)
        if (args.action == "enroll") != bool(args.confirmation):
            raise Refused("aide_enroll_requires_exact_review_confirmation")
        manager = Aide()
        value = manager.enroll(args.confirmation) if args.action == "enroll" else getattr(manager, args.action)()
        print(json.dumps(value, sort_keys=True, allow_nan=False))
        return value.get("exit_code", 0) if value.get("state") in ("clean", "differences") else (78 if value.get("state") == "error" else 0)
    except Exception as exc:
        # No callback/command output is allowed onto the system journal.
        reason = str(exc) if isinstance(exc, Refused) and re.fullmatch(r"aide_[a-z_]+", str(exc)) else "aide_operation_unavailable"
        print(json.dumps({"schema": 1, "state": "error", "reason": reason, "certification": "not asserted"}))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
