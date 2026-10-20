"""Read-only backup sizing. A preview neither reserves space nor authorizes work.

The observer uses existing fixed runtime queries, never the backup admission
helpers which initialize directories. Secret configuration contents are not read.
Sizes and phase peaks are conservative budgets, not compression/throughput claims.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

from .backup import ConfigurationBackup, DATA, MAX_BYTES, _directory
from .common import Refused, require_linux_root
from .image_bundle import ApplicationSchema, strict_json
from .log_backup import LogBackupAdapter, MAX_ARCHIVE_BYTES, MIN_RESERVE_BYTES
from .log_recovery_set import CHUNK_BYTES, ENVELOPE_OVERHEAD, MANIFEST_BYTES, IMAGE_KEYS, IMAGE

GIB = 1024**3
MIB = 1024**2
ROOT_UID = 0
MAX_FILES = 8192
MAX_DIRECTORIES = 1024
OBSERVATION_SECONDS = 120
MAX_RESPONSE_BYTES = 65536
PHASES = ("configuration_capture", "configuration_encryption", "native_backup", "log_encryption", "transfer")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise Refused("Recovery sizing fields do not match the fixed contract")


def _int(value, low=0, high=2**63-1):
    if type(value) is not int or not low <= value <= high:
        raise Refused("Recovery sizing integer is outside its supported range")
    return value


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise Refused("Recovery sizing requires an exact digest")
    return value


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
            raise ValueError
    except (ValueError, AttributeError):
        raise Refused("Recovery sizing requires a canonical installation identity") from None
    return value


def _runtime(value):
    _exact(value, ("images", "schema_revision"))
    _exact(value["images"], IMAGE_KEYS)
    if any(not isinstance(pin, str) or not IMAGE.fullmatch(pin) for pin in value["images"].values()):
        raise Refused("Recovery sizing requires the four immutable runtime pins")
    ApplicationSchema.schema_digest(value["schema_revision"])


def _policy(value):
    _exact(value, ("revision", "normalization", "raw_policy_sha256"))
    _int(value["revision"], 1)
    _sha(value["raw_policy_sha256"])
    if value["normalization"] not in ("stored", "absent_defaults_to_1"):
        raise Refused("Unknown retention normalization")


def build_backup_plan(observation, scope, budgets, *, now, expires_at, throughput=None):
    """Pure bounded arithmetic on a host-produced, redacted observation."""
    _exact(observation, ("schema", "installation_id", "runtime", "policy", "configuration", "postgresql",
                        "clickhouse", "recipient", "storage", "observed_at", "sampling_ms", "planner_revision"))
    if observation["schema"] != 1 or type(observation["schema"]) is not int or scope not in ("config", "full"):
        raise Refused("Unsupported recovery sizing scope")
    _uuid(observation["installation_id"]); _runtime(observation["runtime"]); _policy(observation["policy"])
    _sha(observation["planner_revision"])
    _int(now, 1); _int(expires_at, now+1, now+900)
    _int(observation["observed_at"], max(1, now-120), now)
    _int(observation["sampling_ms"], 0, OBSERVATION_SECONDS*1000)
    configuration = observation["configuration"]
    _exact(configuration, ("bytes", "files", "revision"))
    _int(configuration["bytes"], 0, MAX_BYTES); _int(configuration["files"], 1, MAX_FILES); _sha(configuration["revision"])
    pg = observation["postgresql"]
    _exact(pg, ("bytes", "server_version", "revision"))
    _int(pg["bytes"], 1, MAX_ARCHIVE_BYTES); _sha(pg["revision"])
    if not isinstance(pg["server_version"], str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?: \([^\n]{1,150}\))?", pg["server_version"]):
        raise Refused("Unsupported observed PostgreSQL version")
    _exact(observation["recipient"], ("sha256", "bytes"))
    _sha(observation["recipient"]["sha256"]); _int(observation["recipient"]["bytes"], 1, 65536)
    storage = observation["storage"]
    _exact(storage, ("identity_sha256", "destination_revision", "data", "output", "filesystems"))
    _sha(storage["identity_sha256"]); _sha(storage["destination_revision"])
    if type(storage["filesystems"]) is not list or not 1 <= len(storage["filesystems"]) <= 2:
        raise Refused("Recovery sizing needs one or two physical filesystems")
    filesystems = {}
    for fs in storage["filesystems"]:
        _exact(fs, ("id", "revision", "total_bytes", "free_bytes", "free_inodes", "block_bytes"))
        _sha(fs["id"]); _sha(fs["revision"])
        if fs["id"] in filesystems: raise Refused("Duplicate recovery filesystem identity")
        _int(fs["total_bytes"], 1); _int(fs["free_bytes"], 0, fs["total_bytes"])
        _int(fs["free_inodes"]); _int(fs["block_bytes"], 512, MIB)
        filesystems[fs["id"]] = fs
    if set(filesystems) != {storage["data"], storage["output"]}:
        raise Refused("Recovery filesystem roles do not bind the measured devices")
    data, output = filesystems[storage["data"]], filesystems[storage["output"]]
    if scope == "config":
        _exact(budgets, ("minimum_free_bytes",))
        minimum = _int(budgets["minimum_free_bytes"], GIB, MAX_ARCHIVE_BYTES)
        if observation["clickhouse"] is not None:
            raise Refused("Configuration-only sizing cannot imply a log snapshot")
    else:
        _exact(budgets, ("maximum_archive_bytes", "growth_reserve_bytes", "minimum_free_bytes", "deadline_seconds"))
        _int(budgets["maximum_archive_bytes"], 64*MIB, MAX_ARCHIVE_BYTES)
        _int(budgets["growth_reserve_bytes"], 64*MIB, MAX_ARCHIVE_BYTES)
        minimum = _int(budgets["minimum_free_bytes"], MIN_RESERVE_BYTES, MAX_ARCHIVE_BYTES)
        _int(budgets["deadline_seconds"], 60, 86400)
        ch = observation["clickhouse"]
        _exact(ch, ("table_bytes", "table_uuid", "definition_sha256", "server_version", "instance_revision", "gate_revision"))
        _int(ch["table_bytes"], 0, MAX_ARCHIVE_BYTES); _uuid(ch["table_uuid"])
        _sha(ch["definition_sha256"]); _sha(ch["instance_revision"]); _sha(ch["gate_revision"])
        from .log_backup import VERSION
        if observation["runtime"]["schema_revision"] != "3" or ch["server_version"] != VERSION:
            raise Refused("Full backup sizing requires the current fixed native schema/version")
    measured = configuration["bytes"] + pg["bytes"]
    # Same maximum dump/copy payload chosen by ConfigurationBackup.create.
    payload_cap = min(MAX_BYTES-MIB, max(0, (data["free_bytes"]-GIB)//3))
    tar_cap = payload_cap + 256*MIB
    config_cipher = tar_cap + ENVELOPE_OVERHEAD
    floor = 3*measured
    phase_allocations = {}
    inode_counts = {}
    def phase(name, data_bytes, output_bytes, data_inodes, output_inodes):
        allocations, inodes = {}, {}
        for fs, amount, count in ((data, data_bytes, data_inodes), (output, output_bytes, output_inodes)):
            # Charge each object's possible final partial block once. Existing
            # retained artifacts are already subtracted from statvfs free space.
            allocations[fs["id"]] = allocations.get(fs["id"], 0) + amount + count*fs["block_bytes"]
            inodes[fs["id"]] = inodes.get(fs["id"], 0) + count
        phase_allocations[name], inode_counts[name] = allocations, inodes
    phase("configuration_capture", payload_cap+tar_cap, config_cipher, configuration["files"]+MAX_DIRECTORIES+8, 4)
    phase_bytes = {"configuration_capture": measured, "configuration_encryption": tar_cap, "transfer": config_cipher}
    reasons = []
    if measured > MAX_BYTES or measured > payload_cap:
        reasons.append("configuration_exceeds_plaintext_or_staging_budget")
    native_floor = None
    if scope == "full":
        archive = budgets["maximum_archive_bytes"]
        table = observation["clickhouse"]["table_bytes"]
        retained = max(table, GIB) + budgets["growth_reserve_bytes"]
        native_floor = 2*archive + retained
        floor = max(floor, native_floor)
        if archive < table + max(64*MIB, table//10):
            reasons.append("native_archive_budget_below_observed_table_margin")
        if minimum < max(MIN_RESERVE_BYTES, data["total_bytes"]//10):
            reasons.append("native_reserve_below_ten_percent")
        count = (archive+CHUNK_BYTES-1)//CHUNK_BYTES
        ciphertext = archive + count*ENVELOPE_OVERHEAD + MANIFEST_BYTES + ENVELOPE_OVERHEAD
        phase("native_backup", archive+retained, config_cipher, 16, 4)
        # Account for plaintext chunk/manifest and private checkpoint temporary
        # JSON alongside the retained native tar and complete ciphertext set.
        phase("log_encryption", archive+retained+CHUNK_BYTES+3*MANIFEST_BYTES,
              config_cipher+ciphertext, 24, count+8)
        phase_bytes.update(native_backup=table, log_encryption=archive, transfer=config_cipher+ciphertext)
    rows = []
    for identifier, fs in sorted(filesystems.items()):
        phases = {name: amounts.get(identifier, 0) for name, amounts in phase_allocations.items()}
        existing_floor = floor if identifier == data["id"] else 0
        # A native-admission call happens after config ciphertext is retained.
        if scope == "full" and identifier == data["id"] == output["id"]:
            existing_floor = max(3*measured, native_floor+config_cipher+4*fs["block_bytes"])
        peak = max(existing_floor, *phases.values())
        reserve = max(minimum if identifier == data["id"] else 0, GIB if identifier == output["id"] else 0)
        required_inodes = max(counts.get(identifier, 0) for counts in inode_counts.values())
        enough = fs["free_bytes"] >= peak+reserve and fs["free_inodes"] >= required_inodes
        if not enough: reasons.append("insufficient_filesystem_reserve:"+identifier)
        rows.append({"id": identifier, "roles": [r for r in ("data", "output") if storage[r] == identifier],
                     "free_bytes": fs["free_bytes"], "total_bytes": fs["total_bytes"], "phase_peak_bytes": phases,
                     "existing_admission_floor_bytes": existing_floor, "peak_additional_bytes": peak,
                     "minimum_free_after_bytes": reserve, "required_free_bytes": peak+reserve,
                     "required_inodes": required_inodes, "free_inodes": fs["free_inodes"], "sufficient": enough})
    runtime_revision = _digest(observation["runtime"])
    storage_revision = _digest({"identity": storage["identity_sha256"], "roles": {k:storage[k] for k in ("data", "output")},
                                "filesystems": sorted((f["id"], f["revision"]) for f in filesystems.values())})
    estimates = {phase: {"status": "unknown", "seconds": None} for phase in phase_bytes}
    if throughput is not None:
        if type(throughput) is not list or len(throughput) > len(PHASES):
            raise Refused("Measured throughput evidence exceeds the fixed phase catalog")
        seen = set()
        for sample in throughput:
            _exact(sample, ("phase", "scope", "bytes", "duration_ms", "measured_at", "runtime_revision", "storage_revision", "evidence_sha256"))
            name = sample["phase"]
            if name not in phase_bytes or name in seen or sample["scope"] != scope:
                raise Refused("Throughput measurement has a duplicate or incompatible phase")
            seen.add(name); _int(sample["bytes"], 1, MAX_ARCHIVE_BYTES); _int(sample["duration_ms"], 1, 30*86400*1000)
            _int(sample["measured_at"], max(1, now-30*86400), now); _sha(sample["evidence_sha256"])
            if sample["runtime_revision"] != runtime_revision or sample["storage_revision"] != storage_revision:
                raise Refused("Throughput provenance differs from the current runtime/storage")
            seconds = (phase_bytes[name]*sample["duration_ms"] + sample["bytes"]*1000-1)//(sample["bytes"]*1000)
            estimates[name] = {"status": "estimate_from_supplied_measurement", "seconds": seconds,
                "basis_bytes": phase_bytes[name], "evidence_sha256": sample["evidence_sha256"], "measured_at": sample["measured_at"]}
            if name == "native_backup" and seconds > budgets["deadline_seconds"]:
                reasons.append("measured_native_duration_exceeds_deadline")
    resource = {k:v for k,v in observation.items() if k not in ("observed_at", "sampling_ms")}
    result = {"schema": 1, "kind": "backup-sizing-plan", "scope": scope, "ready": not reasons,
        "reasons": reasons, "installation_id": observation["installation_id"], "runtime": observation["runtime"],
        "policy": observation["policy"], "recipient": observation["recipient"], "observed_at": observation["observed_at"],
        "sampling_ms": observation["sampling_ms"], "expires_at": expires_at, "planner_revision": observation["planner_revision"],
        "runtime_revision": runtime_revision, "storage_revision": storage_revision, "resource_revision": _digest(resource),
        "destination_revision": storage["destination_revision"],
        "budgets": budgets, "configuration": {"measured_bytes": measured, "plaintext_limit_bytes": MAX_BYTES,
            "capture_payload_cap_bytes": payload_cap, "ciphertext_budget_bytes": config_cipher,
            "measurement_is_dump_upper_bound": False, "inventory_revision": configuration["revision"]},
        "clickhouse": observation["clickhouse"], "filesystems": rows, "estimates": estimates,
        "native_hard_quota": False, "growth_reserve_basis": "operator_budget_not_arrival_forecast" if scope == "full" else None,
        "space_reserved": False, "execution_authorized": False, "native_qualified": False}
    result["plan_digest"] = _digest(result)
    if len(json.dumps(result).encode()) > MAX_RESPONSE_BYTES:
        raise Refused("Recovery sizing response exceeds its bounded projection")
    return result


def planner_revision():
    base = Path(__file__).parent
    values = {}
    for name in ("recovery_plans.py", "backup.py", "log_backup.py", "log_recovery_set.py", "recovery_set.py"):
        raw = (base/name).read_bytes()
        if len(raw) > 2*MIB: raise Refused("Recovery planner source is oversized")
        values[name] = hashlib.sha256(raw).hexdigest()
    return _digest(values)


def _identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def configuration_measurement(directory, check_time=lambda: None):
    """Bounded fd-relative metadata inventory; never open secret file contents."""
    _directory(directory)
    records, total, directories = [], 0, 0
    def walk(fd, prefix, depth):
        nonlocal total, directories
        if depth > 24: raise Refused("Configuration inventory is too deep")
        before = os.fstat(fd)
        with os.scandir(fd) as entries:
            for entry in entries:
                check_time()
                info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                relative = prefix+entry.name
                realm_import = (relative == "keycloak/import/nebulalog-realm.json" and stat.S_ISREG(info.st_mode)
                                and info.st_uid == 1000 and info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o400)
                if info.st_dev != before.st_dev or info.st_mode & 0o022 or info.st_uid != ROOT_UID and not realm_import:
                    raise Refused("Configuration sizing requires protected entries")
                if len(relative.encode()) > 1024: raise Refused("Configuration path exceeds inventory bounds")
                if stat.S_ISDIR(info.st_mode):
                    directories += 1
                    if directories > MAX_DIRECTORIES: raise Refused("Configuration directory count exceeds sizing bounds")
                    child = os.open(entry.name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        if _identity(os.fstat(child)) != _identity(info): raise Refused("Configuration directory changed")
                        walk(child, relative+"/", depth+1)
                    finally: os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    total += info.st_size
                    records.append([relative, _identity(info)])
                    if len(records) > MAX_FILES or total > MAX_BYTES: raise Refused("Configuration inventory exceeds its backup limits")
                else: raise Refused("Configuration inventory refuses links and special files")
                if _identity(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) != _identity(info):
                    raise Refused("Configuration entry changed during measurement")
        if _identity(os.fstat(fd)) != _identity(before): raise Refused("Configuration changed during measurement")
    descriptor = os.open(directory, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        root = os.fstat(descriptor)
        walk(descriptor, "", 0)
        if _identity(directory.lstat()) != _identity(root): raise Refused("Configuration root changed during measurement")
    finally: os.close(descriptor)
    if not records: raise Refused("Configuration inventory is empty")
    return {"bytes": total, "files": len(records), "revision": _digest(sorted(records))}


class RecoveryPlanner:
    """Trusted local entrypoint. Browser requests never supply these paths."""
    def __init__(self, configuration=None, *, output_parent, recipient_certificate,
                 clock=time.time, monotonic=time.monotonic):
        self.backup = configuration or ConfigurationBackup()
        self.output, self.recipient = Path(output_parent), Path(recipient_certificate)
        self.clock, self.monotonic = clock, monotonic
        self.deadline = None
        self._busy = threading.Lock()

    def _time(self):
        if self.deadline is None or self.monotonic() >= self.deadline:
            raise Refused("Recovery sizing observation expired")

    @contextmanager
    def _commands(self):
        original, life_original = self.backup.cmd, self.backup.lifecycle.cmd
        def command(argv, **kwargs):
            self._time()
            kwargs["timeout"] = min(kwargs.get("timeout", 30), 30, self.deadline-self.monotonic())
            result = original(argv, **kwargs)
            self._time()
            if type(result) is not str or len(result.encode()) > 16*MIB:
                raise Refused("Oversized recovery observation")
            return result
        self.backup.cmd = self.backup.lifecycle.cmd = command
        gate = getattr(self.backup.gate, "__self__", None)
        from .firstboot import FirstBoot
        if isinstance(gate, FirstBoot):
            from .storage import inspect
            old_runner, old_inspector = gate.runner, gate.inspector
            gate.runner = command
            gate.inspector = lambda identity: inspect(identity, runner=command)
        try: yield command
        finally:
            self.backup.cmd, self.backup.lifecycle.cmd = original, life_original
            if isinstance(gate, FirstBoot): gate.runner, gate.inspector = old_runner, old_inspector

    def _mount(self, path, command, *, encrypted=False):
        raw = strict_json(command(["findmnt", "--json", "--target", str(path)]))
        values = raw.get("filesystems") if type(raw) is dict else None
        if type(values) is not list or len(values) != 1 or type(values[0]) is not dict:
            raise Refused("Missing exact recovery filesystem mount")
        mount = values[0]
        if any(not isinstance(mount.get(k), str) or not mount[k] or len(mount[k]) > 4096 for k in ("target", "source", "fstype")):
            raise Refused("Malformed recovery filesystem identity")
        if encrypted:
            if mount["target"] != str(DATA) or mount["fstype"] != "xfs" or not mount["source"].startswith("/dev/"):
                raise Refused("Sizing requires the mounted appliance XFS data filesystem")
            tree = strict_json(command(["lsblk", "--json", "--inverse", "--output", "NAME,TYPE,FSTYPE", mount["source"]]))
            items, count, luks = tree.get("blockdevices", []), 0, False
            while items:
                if type(items) is not list: raise Refused("Malformed encrypted ancestry")
                item, items = items[0], items[1:]
                count += 1
                if count > 64 or type(item) is not dict: raise Refused("Encrypted ancestry exceeds bounds")
                luks |= item.get("fstype") == "crypto_LUKS"
                children = item.get("children", [])
                if type(children) is not list: raise Refused("Malformed encrypted ancestry")
                items += children
            if not luks: raise Refused("Sizing cannot establish LUKS ancestry")
        before = path.lstat(); sample = os.statvfs(path)
        if before.st_dev != path.lstat().st_dev or before.st_ino != path.lstat().st_ino:
            raise Refused("Recovery filesystem changed during measurement")
        # st_dev determines coexistence; a bind mount is not a separate budget.
        identifier = _digest({"device": before.st_dev})
        return {"id": identifier, "revision": _digest({"device": before.st_dev, "mount": mount}),
            "total_bytes": sample.f_blocks*sample.f_frsize, "free_bytes": sample.f_bavail*sample.f_frsize,
            "free_inodes": sample.f_favail, "block_bytes": sample.f_frsize}

    def _protected_bytes(self, path, maximum):
        _directory(path.parent)
        fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != ROOT_UID or before.st_nlink != 1
                    or before.st_mode & 0o022 or not 0 < before.st_size <= maximum):
                raise Refused("Recovery observation requires a bounded protected regular file")
            raw = os.read(fd, before.st_size+1)
            if len(raw) != before.st_size or _identity(os.fstat(fd)) != _identity(before) or _identity(path.lstat()) != _identity(before):
                raise Refused("Recovery protected input changed while reading")
        finally: os.close(fd)
        return raw

    def _certificate(self, command, ttl):
        raw = self._protected_bytes(self.recipient, 65536)
        if not re.fullmatch(rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*", raw):
            raise Refused("Sizing accepts one public certificate, never a private key or appended PEM")
        command(["openssl", "x509", "-inform", "PEM", "-noout", "-checkend", str(ttl)], input=raw)
        return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}

    def _idle_storage(self, table_uuid):
        from nebulalog_adapters.lifecycle import storage_gate_value
        path = self.backup.manager/"storage-maintenance/gate.json"
        host = storage_gate_value(strict_json(self._protected_bytes(path, 4096)))
        row = strict_json(self.backup.lifecycle._schema_psql("""SELECT json_build_object(
 'gate',(SELECT value FROM public.settings WHERE key='storage_emergency_maintenance'),
 'engine',(SELECT value FROM public.settings WHERE key='retention_engine'),
 'pending',(SELECT count(*) FROM public.storage_emergency_actions WHERE completed_at IS NULL)
          +(SELECT count(*) FROM public.retention_actions WHERE completed_at IS NULL));"""))
        _exact(row, ("gate", "engine", "pending"))
        idle = {"schema": 1, "held": False, "delivery_held": False, "operation": None}
        engine = row["engine"]
        if (host != idle or storage_gate_value(row["gate"]) != idle
                or type(engine) is not dict or set(engine)-{"schema", "mode", "table_uuid", "message"}
                or type(engine.get("schema")) is not int or engine["schema"] != 1
                or engine.get("mode") != "partition" or engine.get("table_uuid") != table_uuid
                or type(row["pending"]) is not int or row["pending"] != 0
                or strict_json(self._protected_bytes(path, 4096)) != host):
            raise Refused("Recovery sizing requires settled idle deletion gates and retention engine")
        return _digest({"host": host, **row})

    def plan(self, *, scope, budgets, throughput=None, ttl_seconds=300):
        if not self._busy.acquire(blocking=False):
            raise Refused("This recovery observer is already in use")
        try:
            return self._plan(scope=scope, budgets=budgets, throughput=throughput, ttl_seconds=ttl_seconds)
        finally:
            self.deadline = None
            self._busy.release()

    def _plan(self, *, scope, budgets, throughput, ttl_seconds):
        require_linux_root()
        _int(ttl_seconds, 10, 900)
        if scope not in ("config", "full"): raise Refused("Unknown backup plan scope")
        if self.backup.data != DATA or self.backup.configuration != DATA/"configuration" or self.backup.manager != DATA/"manager":
            raise Refused("Recovery sizing paths differ from the installed appliance")
        for path in (self.output, self.recipient, self.backup.data, self.backup.configuration, self.backup.manager):
            if not path.is_absolute() or ".." in path.parts or path.resolve() != path:
                raise Refused("Recovery sizing paths must be canonical and protected")
        _directory(self.output); _directory(self.backup.manager, private=True); _directory(self.backup.configuration)
        data_device = self.backup.data.lstat().st_dev
        if any(path.lstat().st_dev != data_device for path in (self.backup.manager, self.backup.configuration)):
            raise Refused("Recovery configuration and scratch must share the encrypted data device")
        destination_identity = _identity(self.output.lstat())
        destination_revision = _digest({"path": str(self.output), "identity": destination_identity})
        for protected in (self.backup.manager, self.backup.configuration, DATA/"clickhouse", DATA/"backup-staging"):
            if self.output.is_relative_to(protected): raise Refused("Ciphertext destination overlaps protected runtime/scratch")
        began = self.monotonic(); self.deadline = began+OBSERVATION_SECONDS
        from .host_plans import read_identity
        with self._commands() as command:
            identity = _digest(asdict(read_identity()))
            host = self.backup.gate()
            if host.get("host_ready") is not True or host.get("setup_complete") is not True:
                raise Refused("Recovery planning requires completed enrollment")
            installation = _uuid(host.get("installation_id"))
            self.backup._pending(); self.backup._active(("postgresql", "clickhouse", "keycloak", "api", "ingest"))
            runtime = self.backup._runtime_metadata(); _runtime(runtime)
            policy = self.backup._log_policy(); _policy(policy)
            recipient = self._certificate(command, ttl_seconds)
            configuration = configuration_measurement(self.backup.configuration, self._time)
            pg = self.backup._metadata()
            postgres = {"bytes": sum(v["bytes"] for v in pg["databases"].values()), "server_version": pg["server_version"], "revision": _digest(pg)}
            clickhouse = None
            if scope == "full":
                native = LogBackupAdapter(self.backup.lifecycle)
                instance = native._instance(runtime["images"]["CLICKHOUSE_IMAGE"])
                table = native._table({"link": {"runtime": runtime}, "instance": instance})
                clickhouse = {"table_bytes": table["bytes_on_disk"], "table_uuid": table["table_uuid"],
                    "definition_sha256": table["table_definition_sha256"], "server_version": table["server_version"],
                    "instance_revision": _digest(instance), "gate_revision": self._idle_storage(table["table_uuid"])}
            data = self._mount(DATA, command, encrypted=True)
            output = self._mount(self.output, command)
            if data["id"] == output["id"]:
                if (data["total_bytes"], data["block_bytes"]) != (output["total_bytes"], output["block_bytes"]):
                    raise Refused("One filesystem returned inconsistent capacity geometry")
                # Conservative shared free-space sample; identity uses device,
                # while mount aliases stay included in the resource revision.
                data["free_bytes"] = min(data["free_bytes"], output["free_bytes"])
                data["free_inodes"] = min(data["free_inodes"], output["free_inodes"])
                data["revision"] = _digest(sorted((data["revision"], output["revision"])))
                filesystems = [data]
            else: filesystems = [data, output]
            if (self.backup.gate() != host or _digest(asdict(read_identity())) != identity
                    or self.backup._runtime_metadata() != runtime or self.backup._log_policy() != policy
                    or configuration_measurement(self.backup.configuration, self._time) != configuration
                    or self._certificate(command, ttl_seconds) != recipient
                    or _identity(self.output.lstat()) != destination_identity
                    or any(path.lstat().st_dev != data_device for path in (self.backup.data, self.backup.manager, self.backup.configuration))):
                raise Refused("Recovery identity/configuration changed during observation")
            self.backup._pending(); self.backup._active(("postgresql", "clickhouse", "keycloak", "api", "ingest"))
            if scope == "full":
                after = native._table({"link": {"runtime": runtime}, "instance": instance})
                if (native._instance(runtime["images"]["CLICKHOUSE_IMAGE"]) != instance
                        or any(after[k] != table[k] for k in ("table_uuid", "table_definition_sha256", "server_version"))
                        or self._idle_storage(table["table_uuid"]) != clickhouse["gate_revision"]):
                    raise Refused("Native table/process/gates changed during sizing")
                # Ingestion remains active: use the larger observed endpoint,
                # without describing these independent reads as a snapshot.
                clickhouse["table_bytes"] = max(table["bytes_on_disk"], after["bytes_on_disk"])
            self._time()
            now = int(self.clock())
            observation = {"schema": 1, "installation_id": installation, "runtime": runtime, "policy": policy,
                "configuration": configuration, "postgresql": postgres, "clickhouse": clickhouse, "recipient": recipient,
                "storage": {"identity_sha256": identity, "destination_revision": destination_revision,
                    "data": data["id"], "output": output["id"], "filesystems": filesystems},
                "observed_at": now, "sampling_ms": int((self.monotonic()-began)*1000), "planner_revision": planner_revision()}
            return build_backup_plan(observation, scope, budgets, now=now, expires_at=now+ttl_seconds, throughput=throughput)
