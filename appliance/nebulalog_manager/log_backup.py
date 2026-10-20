"""Fixed-table native snapshots on encrypted appliance storage.

An ASYNC acknowledgement is not completion. Intent is durable before dispatch;
only the original server instance and its exact system.backups row can settle it.
Lost replies, restarts and expired plans never authorize another BACKUP. Limits
are admission/observation budgets, not a claim that ClickHouse has a byte quota
or that an expired asynchronous job was cancelled. The storage hold stays owned
until verified export or an explicit, positively settled unsuccessful retirement.

Fresh restore uses the configuration coordinator's sole durable transaction,
protected archive and persistent listener fences. It never uses the normal
completed-enrollment guard to adopt a partly initialized target.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import tarfile
import xml.etree.ElementTree as ET
import uuid
from types import SimpleNamespace

from .backup import ConfigurationBackup, _directory, _encrypted_staging
from .common import Refused, atomic_json, trusted_file
from .image_bundle import ApplicationSchema, strict_json
from .log_recovery_set import validate_link, validate_metadata

ROOT_UID = 0
SERVICE_UID = 101
SERVICE_GID = 101
MAX_ARCHIVE_BYTES = 64 * 1024**4
MIN_RESERVE_BYTES = 10 * 1024**3
MAX_JOURNAL_BYTES = 128 * 1024
VERSION = "25.3.8.30001.altinityfips"
CONTAINER_ROOT = Path("/var/lib/clickhouse/backup-staging")
STATES = {"planning", "preflight_failed", "planned", "holding", "dispatching", "running", "recovery_required", "failed", "succeeded", "released", "recovering", "recovered"}
SCHEMA3_SQL = "CREATE DATABASE IF NOT EXISTS nebulalog;\nCREATE TABLE IF NOT EXISTS nebulalog.events\n(\n id String, ingested_at DateTime64(6, 'UTC'), received_at DateTime64(6, 'UTC'),\n generated_at Nullable(DateTime64(6, 'UTC')), expires_at DateTime('UTC'),\n sender_ip String, serial LowCardinality(String), device_name LowCardinality(String),\n vsys LowCardinality(String), log_type LowCardinality(String), wire_type LowCardinality(String),\n subtype LowCardinality(String), schema_version LowCardinality(String), schema_id LowCardinality(String),\n panos_version LowCardinality(String), timestamp_timezone LowCardinality(String),\n parser_version LowCardinality(String), parse_status LowCardinality(String), parse_error String,\n raw String CODEC(ZSTD(3)), raw_base64 String CODEC(ZSTD(3)), fields String CODEC(ZSTD(3)), extra_fields String CODEC(ZSTD(3)),\n src_ip String, dst_ip String, src_port UInt16, dst_port UInt16,\n src_zone LowCardinality(String), dst_zone LowCardinality(String), src_user String, dst_user String,\n app LowCardinality(String), previous_app LowCardinality(String), action LowCardinality(String), rule LowCardinality(String),\n session_end_reason LowCardinality(String), bytes UInt64, bytes_sent UInt64, bytes_received UInt64,\n packets UInt64, session_id String, nat_src_ip String, nat_dst_ip String,\n severity LowCardinality(String), description String CODEC(ZSTD(3)),\n INDEX src_bloom src_ip TYPE bloom_filter(0.01) GRANULARITY 4,\n INDEX dst_bloom dst_ip TYPE bloom_filter(0.01) GRANULARITY 4,\n INDEX action_set action TYPE set(64) GRANULARITY 4\n)\nENGINE=MergeTree\nPARTITION BY (log_type, toDate(ingested_at))\nORDER BY (log_type, received_at, serial, id)\nSETTINGS index_granularity=8192;\n"
MAX_NATIVE_ENTRIES = 262144
MAX_NATIVE_METADATA = 32 * 1024**2
STATUS_COLUMNS = ("id", "name", "base_backup_name", "query_id", "status", "error", "start_time", "end_time",
                  "num_files", "total_size", "num_entries", "uncompressed_size", "compressed_size", "files_read", "bytes_read")


def _now():
    return datetime.now(timezone.utc)


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise Refused("Native log operations require canonical nonzero UUIDs") from None
    return value


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Refused("Native log backup budget or counter is outside its bounded range")
    return value


def _json(raw, maximum=65536):
    if not isinstance(raw, (str, bytes)) or len(raw if isinstance(raw, bytes) else raw.encode()) > maximum:
        raise Refused("Oversized native log backup evidence")
    try:
        return strict_json(raw.encode() if isinstance(raw, str) else raw)
    except (ValueError, TypeError):
        raise Refused("Malformed native log backup evidence") from None


def _stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _mount_label(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z_]+_u:object_r:container_file_t:s0:c[0-9]{1,4},c[0-9]{1,4}", value):
        raise Refused("Native archive requires the private ClickHouse SELinux mount label")
    categories = value.rsplit(":", 1)[1].split(",")
    if len(set(categories)) != 2 or any(int(item[1:]) > 1023 for item in categories):
        raise Refused("Invalid private container MCS categories")
    return value


def _verify_or_inherit_label(fd, expected=None, *, parent_fd=None):
    """Use verified open descriptors; never relabel the volume or relax policy."""
    try:
        if parent_fd is not None:
            raw = os.getxattr(parent_fd, "security.selinux")
            label = _mount_label(raw.removesuffix(b"\0").decode("ascii"))
            if expected is not None and label != _mount_label(expected):
                raise Refused("Archive parent differs from the running ClickHouse mount label")
            os.setxattr(fd, "security.selinux", raw)
        observed = os.getxattr(fd, "security.selinux")
        label = _mount_label(observed.removesuffix(b"\0").decode("ascii"))
        if (expected is not None and label != _mount_label(expected)) or (parent_fd is not None and observed != raw):
            raise Refused("Native archive SELinux label did not match its parent and server")
    except (OSError, UnicodeError, AttributeError):
        raise Refused("Native archive SELinux label could not be verified or preserved") from None


def _native_name(name):
    # Native metadata uses leading '/', whereas tar writers may omit it.
    if not isinstance(name, str) or len(name) > 1024 or "\\" in name or "\0" in name:
        raise Refused("Invalid native archive entry name")
    value = name.removeprefix("/").removesuffix("/")
    if not value or any(part in ("", ".", "..") for part in value.split("/")):
        raise Refused("Native archive entry leaves its fixed namespace")
    if value != ".backup" and value not in ("metadata/nebulalog.sql", "metadata/nebulalog/events.sql") and not value.startswith("data/nebulalog/events/"):
        raise Refused("Native archive contains an unrelated database or table")
    return value


def inspect_native_archive(path, *, expected_bytes, deadline):
    """Bounded tar/XML inspection, with no extraction and no tarfile PAX parser.

    The authenticated outer SHA protects these bytes. Native part checksums and
    CHECK TABLE validate restored data. count.txt supplies snapshot row counts;
    live ingestion counters are deliberately never used as the source oracle.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != expected_bytes:
            raise Refused("Native archive is not its authenticated regular file")
        entries, pax, offset, headers = {}, None, 0, 0
        def read_at(position, size):
            if _now() > deadline or size < 0 or position < 0 or position + size > before.st_size:
                raise Refused("Native archive inspection exceeded its bounds")
            os.lseek(fd, position, os.SEEK_SET)
            out = bytearray()
            while len(out) < size:
                chunk = os.read(fd, min(size - len(out), 1024**2))
                if not chunk or _now() > deadline:
                    raise Refused("Native archive ended during inspection")
                out.extend(chunk)
            return bytes(out)
        while True:
            header = read_at(offset, 512)
            if header == bytes(512):
                if pax is not None or before.st_size - offset > 10240 or any(read_at(offset, before.st_size - offset)):
                    raise Refused("Invalid native tar terminator")
                break
            headers += 1
            if headers > 2 * MAX_NATIVE_ENTRIES:
                raise Refused("Native archive inventory exceeds the supported bound")
            try:
                item = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            except (ValueError, tarfile.HeaderError, UnicodeError):
                raise Refused("Malformed native tar header") from None
            size = item.size
            if item.type == tarfile.XHDTYPE:
                if pax is not None or not 1 <= size <= 65536:
                    raise Refused("Nested or oversized native PAX header")
                raw, cursor, pax = read_at(offset + 512, size), 0, {}
                while cursor < len(raw):
                    space = raw.find(b" ", cursor, min(len(raw), cursor + 16))
                    if space < 0 or not raw[cursor:space].isdigit():
                        raise Refused("Malformed native PAX record")
                    length = int(raw[cursor:space])
                    if length <= space - cursor + 2 or cursor + length > len(raw) or raw[cursor + length - 1] != 10:
                        raise Refused("Invalid native PAX record length")
                    try:
                        key, val = raw[space + 1:cursor + length - 1].decode("utf-8").split("=", 1)
                    except (ValueError, UnicodeError):
                        raise Refused("Invalid native PAX record") from None
                    if key in pax or key not in {"path", "size", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname"}:
                        raise Refused("Unsupported native PAX attribute")
                    pax[key] = val
                    cursor += length
                offset += 512 + ((size + 511) // 512) * 512
                continue
            if pax:
                item.name = pax.get("path", item.name)
                if "size" in pax:
                    if not re.fullmatch(r"0|[1-9][0-9]{0,19}", pax["size"]):
                        raise Refused("Invalid native PAX size")
                    size = int(pax["size"])
            pax = None
            if item.type not in {tarfile.REGTYPE, tarfile.AREGTYPE} or not 0 <= size <= MAX_ARCHIVE_BYTES:
                raise Refused("Native archive accepts regular files only")
            name = _native_name(item.name)
            if name in entries or len(entries) >= MAX_NATIVE_ENTRIES:
                raise Refused("Duplicate or oversized native archive inventory")
            end = offset + 512 + ((size + 511) // 512) * 512
            if end > before.st_size:
                raise Refused("Native archive member exceeds the authenticated length")
            entries[name] = (offset + 512, size)
            offset = end
        if ".backup" not in entries or not 1 <= entries[".backup"][1] <= MAX_NATIVE_METADATA:
            raise Refused("Missing or oversized native backup metadata")
        raw = read_at(*entries[".backup"])
        if b"<!" in raw or b"<?" in raw:
            raise Refused("Native XML declarations and entities are not accepted")
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            raise Refused("Malformed native metadata XML") from None
        if (root.tag != "config" or root.attrib or root.findtext("version") != "1"
                or root.findtext("deduplicate_files") not in {"0", "1"}
                or len(root.findall("contents")) != 1 or any(c.tag not in {"version", "deduplicate_files", "timestamp", "uuid", "contents"} for c in root)
                or any(len(root.findall(tag)) != 1 for tag in ("version", "deduplicate_files", "timestamp", "uuid"))):
            raise Refused("Unsupported or incremental native backup metadata")
        _uuid(root.findtext("uuid"))
        logical, used, parts, total = {}, {".backup"}, {}, 0
        for element in root.find("contents"):
            if element.tag != "file" or element.attrib or len(element) > 4:
                raise Refused("Unsupported native metadata file")
            fields = {}
            for child in element:
                if child.tag in fields or child.tag not in {"name", "size", "checksum", "data_file"} or child.attrib or len(child):
                    raise Refused("Native base backups, disk encryption and unknown entries are not accepted")
                fields[child.tag] = child.text or ""
            if not {"name", "size"} <= set(fields) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", fields["size"]):
                raise Refused("Invalid native metadata file size")
            name, size = _native_name(fields["name"]), int(fields["size"])
            if name == ".backup" or name in logical or len(logical) >= MAX_NATIVE_ENTRIES or size > MAX_ARCHIVE_BYTES:
                raise Refused("Invalid native logical inventory")
            physical = _native_name(fields.get("data_file", name))
            if size:
                if not re.fullmatch(r"[0-9a-fA-F]{32}", fields.get("checksum", "")) or physical not in entries or entries[physical][1] != size:
                    raise Refused("Native metadata does not cover its physical bytes")
                used.add(physical)
            elif physical in entries and entries[physical][1] == 0:
                used.add(physical)
            logical[name] = (physical, size)
            total += size
            if total > MAX_ARCHIVE_BYTES:
                raise Refused("Native logical payload exceeds its supported bound")
            if name.startswith("data/"):
                components = name.split("/")
                if len(components) != 5 or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", components[3]):
                    raise Refused("Native recovery accepts the current non-projection MergeTree profile only")
                parts.setdefault(components[3], set()).add(components[4])
        if set(entries) != used or "metadata/nebulalog/events.sql" not in logical:
            raise Refused("Native archive has unaccounted entries or lacks its table definition")
        rows = 0
        for part, names in parts.items():
            if not {"count.txt", "checksums.txt", "columns.txt"} <= names:
                raise Refused("Native part lacks its row count, columns or checksum inventory")
            physical, size = logical["data/nebulalog/events/" + part + "/count.txt"]
            if not 1 <= size <= 32:
                raise Refused("Native part row count is oversized")
            value = read_at(*entries[physical])
            if not re.fullmatch(rb"[0-9]{1,20}\n?", value):
                raise Refused("Native part row count is malformed")
            rows += int(value)
            _integer(rows, 0, 2**64 - 1)
        if _stable(before) != _stable(os.fstat(fd)) or _stable(before) != _stable(Path(path).lstat()):
            raise Refused("Native archive changed during metadata inspection")
        return {"metadata_sha256": hashlib.sha256(raw).hexdigest(), "logical_files": len(logical),
                "logical_bytes": total, "parts": len(parts), "rows": rows,
                "part_checksum_files": len(parts), "inventory_complete": True}
    finally:
        os.close(fd)


def owned_stage(stage, data):
    """The sole extra stage admitted by Lifecycle.storage_maintenance."""
    stage, data = Path(stage), Path(data)
    if (not stage.is_absolute() or stage.resolve() != stage
            or stage.parent != data / "manager/log-backups"):
        raise Refused("Native log backup requires its fixed protected operation directory")
    _uuid(stage.name)
    _directory(stage, private=True)
    path = trusted_file(stage / "native.json")
    info = path.stat()
    if info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > MAX_JOURNAL_BYTES:
        raise Refused("Unsafe native log operation journal")
    value = _json(path.read_bytes(), MAX_JOURNAL_BYTES)
    if (not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("kind") != "log-backup" or value.get("mode") != "backup"
            or value.get("id") != stage.name or value.get("stage") != str(stage)
            or value.get("state") not in STATES):
        raise Refused("Native log operation journal does not own this stage")
    return value


class LogBackupAdapter:
    def __init__(self, lifecycle, checkpoint=None):
        self.lifecycle, self.cmd, self.data = lifecycle, lifecycle.cmd, lifecycle.data
        self.backup = ConfigurationBackup(lifecycle, data=self.data)
        self.checkpoint = checkpoint

    @classmethod
    def for_restore(cls, runtime):
        # A fresh target has no completed lifecycle configuration yet. Reuse
        # only fixed database I/O; every operation still validates the retained
        # coordinator transaction through _restore_context.
        return cls(SimpleNamespace(data=runtime.paths.data, cmd=runtime.runner,
            ch=runtime._log_ch, _schema_psql=runtime._log_pg))

    @contextmanager
    def _locks(self):
        with ExitStack() as stack:
            self.backup._locks(stack)
            previous = self.cmd
            self.cmd = self.backup.cmd
            try:
                yield
            finally:
                self.cmd = previous

    def _guard(self):
        installation = self.backup._guard()
        self.backup._pending()
        if self.lifecycle.application_schema_current()["revision"] != "3":
            raise Refused("Native log recovery currently requires the factory schema 3 profile")
        return installation

    def _save(self, stage, value):
        _directory(stage, private=True)
        atomic_json(stage / "native.json", value)
        if self.checkpoint is not None:
            self.checkpoint()

    def _uncertain(self, stage, value, reason):
        value.update(state="recovery_required", reason=reason, observed_at=_now().isoformat())
        self._save(stage, value)
        raise Refused("Native log operation requires recovery; its archive, journal and storage hold are retained")

    def _paths(self, stage):
        return self.data / "clickhouse/backup-staging" / stage.name, CONTAINER_ROOT / stage.name / "events.tar"

    @contextmanager
    def _service_directory_fd(self, path, *, create=False, mount_label=None):
        # Anchor every lookup beneath opened, verified parents. Service-owned
        # directories may change names; no privileged ownership/label operation
        # follows a path supplied by a replaceable child entry.
        if path != self.data / "clickhouse/backup-staging" / path.name:
            raise Refused("Native archive path is outside the fixed service staging directory")
        _uuid(path.name)
        _directory(self.data)
        _encrypted_staging(self.data / "clickhouse", self.cmd)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
        with ExitStack() as stack:
            def opened(name, **kwargs):
                descriptor = os.open(name, flags, **kwargs)
                stack.callback(os.close, descriptor)
                return descriptor
            parent = opened(self.data)
            root = os.fstat(parent)
            if identity(root) != identity(self.data.lstat()):
                raise Refused("Encrypted data directory changed before staging")
            bindings = []
            for name in ("clickhouse", "backup-staging", path.name):
                created = False
                try:
                    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    if not create or name == "clickhouse":
                        raise Refused("The installed native archive parent must already exist") from None
                    os.mkdir(name, mode=0o700, dir_fd=parent)
                    created = True
                    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    raise Refused("Native staging child is not a directory")
                child = opened(name, dir_fd=parent)
                current = os.fstat(child)
                if identity(current) != identity(before) or current.st_dev != root.st_dev or stat.S_IMODE(current.st_mode) != 0o700:
                    raise Refused("Native staging directory changed before descriptor verification")
                if created:
                    if current.st_uid != ROOT_UID:
                        raise Refused("A replaced directory cannot acquire native service ownership")
                    os.fchown(child, SERVICE_UID, SERVICE_GID)
                    current = os.fstat(child)
                if current.st_uid != SERVICE_UID or current.st_gid != SERVICE_GID:
                    raise Refused("Native staging directory has unexpected ownership")
                _verify_or_inherit_label(child, mount_label, parent_fd=parent if created else None)
                os.fsync(child)
                if created:
                    os.fsync(parent)
                bindings.append((parent, name, child))
                parent = child
            yield parent
            for parent, name, child in bindings:
                if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(os.fstat(child)):
                    raise Refused("Native archive directory binding changed during preparation")

    def _service_directory(self, path, *, create=False, mount_label=None):
        with self._service_directory_fd(path, create=create, mount_label=mount_label):
            pass

    def _instance(self, pin):
        # The fixed wrapper owns the ClickHouse child lifetime. PID1 is a shell;
        # neither its numeric PID nor SELECT uptime alone establishes identity.
        raw = self.cmd(["podman", "container", "inspect", "--format",
                        '{"id":{{json .ID}},"image":{{json .Image}},"state":{{json .State}},"restarts":{{json .RestartCount}},"mount_label":{{json .MountLabel}}}',
                        "nebulalog-clickhouse"])
        value = _json(raw)
        if not isinstance(value, dict) or set(value) != {"id", "image", "state", "restarts", "mount_label"}:
            raise Refused("Missing exact ClickHouse process identity")
        state = value["state"]
        image = self.cmd(["podman", "image", "inspect", "--format", "{{.Id}}", pin])
        repos = _json(self.cmd(["podman", "image", "inspect", "--format", "{{json .RepoDigests}}", pin]))
        if (not isinstance(value["id"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["id"])
                or not isinstance(image, str) or not re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", image)
                or not isinstance(value["image"], str) or value["image"].removeprefix("sha256:") != image.removeprefix("sha256:")
                or not isinstance(repos, list) or pin not in repos or not isinstance(state, dict)
                or state.get("Running") is not True or state.get("Paused") is not False
                or state.get("Restarting") is not False or state.get("Dead") is not False
                or not isinstance(state.get("StartedAt"), str) or not state["StartedAt"].endswith("Z")):
            raise Refused("ClickHouse no longer matches the running pinned server instance")
        _integer(state.get("Pid"), 1, 2**31 - 1)
        _integer(value["restarts"], 0, 2**31 - 1)
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        _uuid(boot)
        return {"container_id": value["id"], "image_id": image.removeprefix("sha256:"), "pin": pin,
                "pid": state["Pid"], "started_at": state["StartedAt"], "restart_count": value["restarts"], "host_boot_id": boot,
                "mount_label": _mount_label(value["mount_label"])}

    def _bound_query(self, value, query, params=(), *, dispatch=False):
        before = self._instance(value["link"]["runtime"]["images"]["CLICKHOUSE_IMAGE"])
        if before != value["instance"]:
            raise Refused("Native backup server instance changed")
        if dispatch:
            # Lifecycle.ch's 15-second read limit would also become the async
            # job's inherited execution setting. The native job gets its
            # admitted budget; only its initial acknowledgement is awaited here.
            raw = self.cmd(["podman", "exec", "--user", "101:101", "nebulalog-clickhouse", "clickhouse-client",
                            "--config-file=/etc/nebulalog/clickhouse-client.xml",
                            "--max_execution_time=" + str(value["plan"]["deadline_seconds"]), "--query", query, *params], timeout=30)
        else:
            raw = self.lifecycle.ch(query, params)
        if self._instance(before["pin"]) != before:
            raise Refused("Native backup server instance changed during observation")
        return raw

    def _table(self, value):
        row = _json(self._bound_query(value,
            "SELECT toString(uuid) AS uuid,engine,partition_key,create_table_query,version() AS version,"
            "(SELECT sum(bytes_on_disk) FROM system.parts WHERE database='nebulalog' AND table='events' AND active) AS bytes_on_disk,"
            "(SELECT count() FROM system.mutations WHERE database='nebulalog' AND table='events' AND NOT is_done) AS pending_mutations "
            "FROM system.tables WHERE database='nebulalog' AND name='events' "
            "SETTINGS output_format_json_quote_64bit_integers=0 FORMAT JSONEachRow"))
        if (not isinstance(row, dict) or set(row) != {"uuid", "engine", "partition_key", "create_table_query", "version", "bytes_on_disk", "pending_mutations"}
                or row["engine"] != "MergeTree" or row["partition_key"] != "(log_type, toDate(ingested_at))"
                or row["version"] != VERSION or not isinstance(row["create_table_query"], str)
                or not row["create_table_query"].startswith("CREATE TABLE ")
                or re.search(r"\bTTL\b", row["create_table_query"], re.IGNORECASE)):
            raise Refused("Native backup table definition or server version is unsupported")
        _uuid(row["uuid"])
        # ClickHouse's JSON format quotes UInt64 values by default. Request
        # numeric JSON explicitly below, and reject ambiguous textual counters.
        _integer(row["bytes_on_disk"], 0, MAX_ARCHIVE_BYTES)
        _integer(row["pending_mutations"], 0, 0)
        return {"table_uuid": row["uuid"], "table_definition_sha256": hashlib.sha256(row["create_table_query"].encode()).hexdigest(),
                "server_version": row["version"], "bytes_on_disk": row["bytes_on_disk"]}

    def _policy(self):
        raw = self.lifecycle._schema_psql("SELECT value::text FROM public.settings WHERE key='retention';")
        value = _json(raw)
        if not isinstance(value, dict):
            raise Refused("Missing retention policy")
        # Existing factory settings omit revision; Go readRetention exposes
        # that exact legacy case as revision 1. Explicit malformed values do not
        # acquire the default. Keep the original bytes and normalization bound.
        revision = _integer(value["revision"], 1, 2**63 - 1) if "revision" in value else 1
        return {"revision": revision, "normalization": "stored" if "revision" in value else "absent_defaults_to_1",
                "raw_policy_sha256": hashlib.sha256(raw.encode()).hexdigest()}

    def _hold_readback(self, stage, value):
        expected = {"schema": 1, "held": True, "delivery_held": False,
                    "operation": hashlib.sha256(str(stage).encode()).hexdigest()}
        host = _json(trusted_file(self.data / "manager/storage-maintenance/gate.json").read_bytes(), 4096)
        query = """SELECT json_build_object(
 'gate',(SELECT value FROM public.settings WHERE key='storage_emergency_maintenance'),
 'engine',(SELECT value FROM public.settings WHERE key='retention_engine'),
 'pending',(SELECT count(*) FROM public.storage_emergency_actions WHERE completed_at IS NULL)
          +(SELECT count(*) FROM public.retention_actions WHERE completed_at IS NULL));"""
        row = _json(self.lifecycle._schema_psql(query))
        if (host != expected or not isinstance(row, dict) or set(row) != {"gate", "engine", "pending"}
                or row["gate"] != expected or (not isinstance(row["engine"], dict) or any(row["engine"].get(k) != v for k, v in {"schema": 1, "mode": "partition", "table_uuid": value["table"]["table_uuid"]}.items()) or set(row["engine"]) - {"schema", "mode", "table_uuid", "message"})
                or type(row["pending"]) is not int or row["pending"] != 0
                or _json(trusted_file(self.data / "manager/storage-maintenance/gate.json").read_bytes(), 4096) != expected):
            raise Refused("Native snapshot lost its settled deletion hold")

    def _capacity(self, plan, table_bytes):
        sample = os.statvfs(self.data)
        free, total = sample.f_bavail * sample.f_frsize, sample.f_blocks * sample.f_frsize
        minimum = max(MIN_RESERVE_BYTES, total // 10)
        if plan["minimum_free_bytes"] < minimum:
            raise Refused("Native snapshot reserve must retain at least 10 GiB and ten percent of the data filesystem")
        # Native archive plus encrypted export, retained parts during merges,
        # and an explicit arrival/spool allowance. No throughput is invented.
        required = 2 * plan["maximum_archive_bytes"] + max(table_bytes, 1024**3) + plan["growth_reserve_bytes"]
        if (plan["maximum_archive_bytes"] < table_bytes + max(64 * 1024**2, table_bytes // 10)
                or free - required < plan["minimum_free_bytes"]):
            raise Refused("Native log snapshot lacks its planned encrypted storage and growth reserve")
        return {"free_bytes": free, "total_bytes": total, "reserved_operation_bytes": required,
                "measured_at": _now().isoformat(), "hard_native_quota": False}

    def plan(self, stage, *, mode, maximum_archive_bytes, deadline_seconds, linked_metadata,
             growth_reserve_bytes, minimum_free_bytes):
        """Admit one fresh backup; budgets require explicit operator sizing."""
        validate_link(linked_metadata)
        if mode != "backup":
            raise Refused("Fresh native restore coordination is not yet wired; no restore was dispatched")
        stage = Path(stage)
        _uuid(stage.name)
        if (not stage.is_absolute() or stage.resolve() != stage or stage.parent != self.data / "manager/log-backups"
                or os.path.lexists(stage)):
            raise Refused("Native backup planning requires a new canonical operation directory")
        plan = {"maximum_archive_bytes": _integer(maximum_archive_bytes, 64 * 1024**2, MAX_ARCHIVE_BYTES),
                "deadline_seconds": _integer(deadline_seconds, 60, 86400),
                "growth_reserve_bytes": _integer(growth_reserve_bytes, 64 * 1024**2, MAX_ARCHIVE_BYTES),
                "minimum_free_bytes": _integer(minimum_free_bytes, MIN_RESERVE_BYTES, MAX_ARCHIVE_BYTES)}
        with self._locks():
            installation = self._guard()
            if (installation != linked_metadata["source_installation_id"]
                    or self.backup._runtime_metadata() != linked_metadata["runtime"]):
                raise Refused("Configuration recovery set does not match this installed source/runtime")
            if not self.lifecycle.storage_gate_aware_ingest():
                raise Refused("Backup requires the installed ingestion storage-gate contract")
            _directory(stage.parent, private=True, create=True)
            stage.mkdir(mode=0o700)
            value = {"schema": 1, "kind": "log-backup", "id": stage.name, "stage": str(stage), "mode": "backup",
                     "state": "planning", "link": linked_metadata, "plan": plan, "planned_at": _now().isoformat(),
                     "backup_id": str(uuid.uuid4()), "query_id": str(uuid.uuid4())}
            self._save(stage, value)
            try:
                value["instance"] = self._instance(linked_metadata["runtime"]["images"]["CLICKHOUSE_IMAGE"])
                value["table"] = self._table(value)
                value["capacity"] = self._capacity(plan, value["table"]["bytes_on_disk"])
            except BaseException:
                # Only this same invocation can attest that planning failed
                # before any hold intent or native dispatch was possible.
                value.update(state="preflight_failed", preflight_failed_at=_now().isoformat(),
                             preflight_no_effects=True)
                self._save(stage, value)
                raise
            value["state"] = "planned"
            self._save(stage, value)
            return value

    def start_backup(self, stage, *, expected_policy_revision=None, expected_raw_policy_sha256=None):
        stage = Path(stage)
        with self._locks():
            value = owned_stage(stage, self.data)
            self._guard()
            if value["state"] != "planned":
                raise Refused("Native BACKUP is single-dispatch; retained intent cannot be replayed")
            if self.backup._runtime_metadata() != value["link"]["runtime"]:
                raise Refused("Runtime changed after native snapshot planning")
            if not self.lifecycle.storage_gate_aware_ingest():
                raise Refused("Ingestion lost its installed storage-gate contract")
            value["state"] = "holding"
            self._save(stage, value)
            # A failure here keeps the conservative fence. No automatic retry
            # converts a partial hold into authority to send the SQL statement.
            self.lifecycle.storage_maintenance(stage, held=True, delivery_held=False)
            try:
                table = self._table(value)
                if any(table[k] != value["table"][k] for k in ("table_uuid", "table_definition_sha256", "server_version")):
                    raise Refused("Table changed after snapshot planning")
                value["table"] = table
                value["capacity_at_dispatch"] = self._capacity(value["plan"], table["bytes_on_disk"])
                value["policy"] = self._policy()
                value["retention_policy_revision"] = value["policy"]["revision"]
                if expected_policy_revision is not None and _integer(expected_policy_revision, 1, 2**63 - 1) != value["retention_policy_revision"]:
                    raise Refused("Configuration and native snapshot retention revisions differ")
                if expected_raw_policy_sha256 is not None and (not isinstance(expected_raw_policy_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_raw_policy_sha256) or expected_raw_policy_sha256 != value["policy"]["raw_policy_sha256"]):
                    raise Refused("Configuration and native snapshot policy content differs")
                self._hold_readback(stage, value)
                directory, container = self._paths(stage)
                if os.path.lexists(directory):
                    raise Refused("Native archive operation directory already exists")
                self._service_directory(directory, create=True, mount_label=value["instance"]["mount_label"])
                now = _now()
                value.update(state="dispatching", dispatched_at=now.isoformat(),
                             deadline_at=(now + timedelta(seconds=value["plan"]["deadline_seconds"])).isoformat())
                self._save(stage, value)  # This is the sole dispatch authority.
                query = ("BACKUP TABLE nebulalog.events TO File('" + str(container) + "') SETTINGS id='"
                         + value["backup_id"] + "', check_parts=true, async=true")
                reply = _json(self._bound_query(value, query, ("--query_id=" + value["query_id"], "--format=JSONEachRow"), dispatch=True))
                if (not isinstance(reply, dict) or set(reply) != {"id", "status"} or reply["id"] != value["backup_id"]
                        or reply["status"] not in ("CREATING_BACKUP", "BACKUP_CREATED")):
                    raise Refused("Native asynchronous acknowledgement was not exact")
                value.update(state="running", acknowledged_at=_now().isoformat())
                self._save(stage, value)
                return {"state": "running", "id": value["id"], "archive_ready": False}
            except BaseException:
                self._uncertain(stage, value, "start_not_confirmed")

    def _archive(self, stage, maximum, deadline, *, mount_label=None):
        directory, _ = self._paths(stage)
        with self._service_directory_fd(directory, mount_label=mount_label) as descriptor:
            with os.scandir(descriptor) as entries:
                first, second = next(entries, None), next(entries, None)
                if first is None or first.name != "events.tar" or second is not None:
                    raise Refused("Native archive has incomplete or unexpected side files")
            archive = os.open("events.tar", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            try:
                _verify_or_inherit_label(archive, mount_label)
                before = os.fstat(archive)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != SERVICE_UID
                        or before.st_gid != SERVICE_GID or before.st_mode & 0o077):
                    raise Refused("Native archive must be a single private service-owned regular file")
                _integer(before.st_size, 1, maximum)
                digest = hashlib.sha256()
                remaining = before.st_size
                while remaining:
                    if _now() > deadline:
                        raise Refused("Native archive verification exceeded its bounded deadline")
                    chunk = os.read(archive, min(remaining, 1024**2))
                    if not chunk:
                        raise Refused("Native archive ended before its admitted size")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if os.read(archive, 1):
                    raise Refused("Native archive exceeded its admitted size")
                os.fsync(archive)
                after = os.fstat(archive)
                path_after = os.stat("events.tar", dir_fd=descriptor, follow_symlinks=False)
                if _stable(before) != _stable(after) or _stable(after) != _stable(path_after):
                    raise Refused("Native archive changed while being verified")
                os.fsync(descriptor)
            finally:
                os.close(archive)
        return {"path": str(directory / "events.tar"), "sha256": digest.hexdigest(), "bytes": before.st_size}

    def observe(self, stage):
        stage = Path(stage)
        with self._locks():
            value = owned_stage(stage, self.data)
            self._guard()
            if value["state"] in ("succeeded", "released"):
                if self._archive(stage, value["plan"]["maximum_archive_bytes"], _now() + timedelta(seconds=value["plan"]["deadline_seconds"]), mount_label=value["instance"]["mount_label"]) != value["result"]["archive"]:
                    raise Refused("Retained native snapshot differs from its completed evidence")
                return value["result"]
            if value["state"] not in ("dispatching", "running", "recovery_required") or "dispatched_at" not in value:
                raise Refused("This operation has no native dispatch to observe")
            try:
                self._hold_readback(stage, value)
                # ISO times are explicitly UTC; never interpret server-local
                # wall time as a timezone-aware recovery-set capture time.
                columns = ",".join("toString(" + key + ", 'UTC') AS " + key if key in ("start_time", "end_time") else key
                                   for key in STATUS_COLUMNS)
                raw = self._bound_query(value, "SELECT " + columns + " FROM system.backups WHERE id={operation:String} "
                    "SETTINGS output_format_json_quote_64bit_integers=0 FORMAT JSONEachRow", ("--param_operation=" + value["backup_id"],))
                row = _json(raw)
                _, container = self._paths(stage)
                if (not isinstance(row, dict) or set(row) != set(STATUS_COLUMNS) or row["id"] != value["backup_id"]
                        or row["query_id"] != value["query_id"] or row["name"] != "File('" + str(container) + "')"
                        or row["base_backup_name"] != "" or not isinstance(row["error"], str)
                        or row["status"] not in ("CREATING_BACKUP", "BACKUP_CREATED", "BACKUP_FAILED", "BACKUP_CANCELLED")):
                    raise Refused("Native status does not match the exact retained operation")
                for key in STATUS_COLUMNS[8:]:
                    _integer(row[key], 0, 2**64 - 1)
                value["last_status"] = {k: v for k, v in row.items() if k != "error"}
                value["last_status"]["error_present"] = bool(row["error"])
                if row["status"] in ("BACKUP_FAILED", "BACKUP_CANCELLED"):
                    value.update(state="failed", observed_at=_now().isoformat())
                    self._save(stage, value)
                    return {"state": "failed", "id": value["id"], "archive_ready": False}
                if _now() > datetime.fromisoformat(value["deadline_at"]):
                    raise Refused("Native operation exceeded its observation deadline; cancellation is not established")
                if row["error"]:
                    raise Refused("Native backup status contains an error")
                if row["status"] == "CREATING_BACKUP":
                    self._save(stage, value)
                    return {"state": "running", "id": value["id"], "archive_ready": False}
                table = self._table(value)
                if any(table[k] != value["table"][k] for k in ("table_uuid", "table_definition_sha256", "server_version")) or self._policy() != value["policy"]:
                    raise Refused("Native snapshot table or retention identity changed")
                archive = self._archive(stage, value["plan"]["maximum_archive_bytes"], datetime.fromisoformat(value["deadline_at"]), mount_label=value["instance"]["mount_label"])
                if row["compressed_size"] != archive["bytes"]:
                    raise Refused("Native archive length differs from the completed server receipt")
                self._hold_readback(stage, value)
                if self._instance(value["instance"]["pin"]) != value["instance"]:
                    raise Refused("Native server changed during archive verification")
                times = [datetime.fromisoformat(row[key]).replace(tzinfo=timezone.utc) for key in ("start_time", "end_time")]
                if times[0] < datetime.fromisoformat(value["dispatched_at"]) - timedelta(seconds=5) or times[1] < times[0] or times[1] > _now() + timedelta(seconds=5):
                    raise Refused("Native completion time does not belong to this dispatch")
                metadata = {"link": value["link"], "native": {"table": "nebulalog.events", "server_version": table["server_version"],
                    "table_uuid": table["table_uuid"], "backup_id": value["backup_id"], "query_id": value["query_id"],
                    "started_at": times[0].isoformat(), "finished_at": times[1].isoformat(),
                    "table_definition_sha256": table["table_definition_sha256"], "retention_policy_revision": value["retention_policy_revision"]},
                    "archive": {"format": "clickhouse-native-tar", "sha256": archive["sha256"], "bytes": archive["bytes"]}}
                validate_metadata(metadata)
                result = {"archive": archive, "metadata": metadata}
                value.update(state="succeeded", result=result, observed_at=_now().isoformat())
                self._save(stage, value)
                return result
            except BaseException:
                self._uncertain(stage, value, "observation_not_confirmed")

    def release(self, stage):
        """Coordinator calls only after authenticated encrypted export completes."""
        stage = Path(stage)
        with self._locks():
            value = owned_stage(stage, self.data)
            self._guard()
            if value["state"] not in ("succeeded", "released"):
                raise Refused("An unsettled native job cannot release its deletion hold")
            self.lifecycle.storage_maintenance(stage, held=False)
            value.update(state="released", released_at=_now().isoformat())
            self._save(stage, value)
            return {"state": "released", "id": value["id"]}

    def _recovery_gates(self, stage, value):
        """Read both fences without treating an absent/foreign fence as idle."""
        from nebulalog_adapters.lifecycle import storage_gate_value
        path = self.data / "manager/storage-maintenance/gate.json"
        host = storage_gate_value(_json(trusted_file(path).read_bytes(), 4096))
        row = _json(self.lifecycle._schema_psql("""SELECT json_build_object(
 'gate',(SELECT value FROM public.settings WHERE key='storage_emergency_maintenance'),
 'engine',(SELECT value FROM public.settings WHERE key='retention_engine'),
 'pending',(SELECT count(*) FROM public.storage_emergency_actions WHERE completed_at IS NULL)
          +(SELECT count(*) FROM public.retention_actions WHERE completed_at IS NULL));"""))
        if not isinstance(row, dict) or set(row) != {"gate", "engine", "pending"}:
            raise Refused("Missing recovery fence evidence")
        database = storage_gate_value(row["gate"])
        owner = hashlib.sha256(str(stage).encode()).hexdigest()
        for gate in (host, database):
            if gate["held"] and gate["operation"] != owner:
                raise Refused("A foreign operation owns the recovery fence")
        engine = row["engine"]
        if (not isinstance(engine, dict) or set(engine) - {"schema", "mode", "table_uuid", "message"}
                or type(engine.get("schema")) is not int or engine["schema"] != 1
                or engine.get("mode") != "partition" or engine.get("table_uuid") != value["table"]["table_uuid"]
                or type(row["pending"]) is not int or row["pending"] != 0
                or _json(trusted_file(path).read_bytes(), 4096) != host
                or not host["held"] and database["held"]):
            raise Refused("Recovery fences or retention engine are unsettled")
        return {"host": host, "database": database, "engine": engine, "pending": 0}

    def _recovery_status(self, stage, value, *, dispatched):
        columns = ",".join("toString(" + key + ", 'UTC') AS " + key if key in ("start_time", "end_time") else key
                           for key in STATUS_COLUMNS)
        _, container = self._paths(stage)
        name = "File('" + str(container) + "')"
        raw = self._bound_query(value, "SELECT " + columns + " FROM system.backups WHERE id={operation:String} "
            "OR query_id={query:String} OR name={name:String} "
            "SETTINGS output_format_json_quote_64bit_integers=0 FORMAT JSONEachRow",
            ("--param_operation=" + _uuid(value["backup_id"]), "--param_query=" + _uuid(value["query_id"]), "--param_name=" + name))
        if not dispatched:
            if not isinstance(raw, str) or raw.strip():
                raise Refused("A native job exists despite the retained no-dispatch journal")
            row = None
        else:
            row = _json(raw)
            if (not isinstance(row, dict) or set(row) != set(STATUS_COLUMNS) or row["id"] != value["backup_id"]
                    or row["query_id"] != value["query_id"] or row["name"] != name or row["base_backup_name"] != ""
                    or not isinstance(row["error"], str)
                    or row["status"] not in ("BACKUP_FAILED", "BACKUP_CANCELLED", "BACKUP_CREATED")):
                raise Refused("Recovery needs the exact positively terminal native job")
            for key in STATUS_COLUMNS[8:]:
                _integer(row[key], 0, 2**64 - 1)
            try:
                times = [datetime.fromisoformat(row[key]) for key in ("start_time", "end_time")]
                dispatch = datetime.fromisoformat(value["dispatched_at"])
                if any(t.tzinfo is not None for t in times) or dispatch.utcoffset() != timedelta(0):
                    raise ValueError
                times = [t.replace(tzinfo=timezone.utc) for t in times]
                if (times[0] < dispatch - timedelta(seconds=5) or times[1] < times[0]
                        or times[1] > _now() + timedelta(seconds=5)):
                    raise ValueError
            except (ValueError, TypeError, KeyError):
                raise Refused("Native terminal time does not belong to the retained dispatch") from None
            # Retain error presence, never server error text which can contain data.
            row = {**{k: v for k, v in row.items() if k != "error"}, "error_present": bool(row["error"])}
        processes = _json(self._bound_query(value,
            "SELECT count() AS matching FROM system.processes WHERE query_id={query:String} OR initial_query_id={query:String} "
            "SETTINGS output_format_json_quote_64bit_integers=0 FORMAT JSONEachRow", ("--param_query=" + value["query_id"],)))
        if not isinstance(processes, dict) or set(processes) != {"matching"} or type(processes["matching"]) is not int or processes["matching"] != 0:
            raise Refused("The native job still has an active process or unknown settlement")
        return row

    def _release_receipt(self, stage):
        path = trusted_file(stage / "adapter-storage-maintenance.json")
        if path.stat().st_size > 65536 or path.stat().st_nlink != 1:
            raise Refused("Unsafe native hold release evidence")
        receipt = _json(path.read_bytes())
        idle = {"schema": 1, "held": False, "delivery_held": False, "operation": None}
        if (not isinstance(receipt, dict) or receipt.get("operation") != hashlib.sha256(str(stage).encode()).hexdigest()
                or not (receipt.get("state") == "intent" and receipt.get("desired") == idle
                        or receipt.get("state") == "complete" and receipt.get("action") == "storage-maintenance"
                        and receipt.get("ok") is True and receipt.get("gate") == idle)):
            raise Refused("Idle gates lack this operation's retained release intent")

    def recover_backup(self, stage, *, abandon_export=False):
        """Retire a proven failed/no-dispatch child; never cancel or redispatch.

        Explicit abandonment can also retire a positively completed native tar,
        while recording unsuccessful encrypted export. All original files stay.
        Missing status, changed instances and incomplete evidence retain fences.
        """
        if type(abandon_export) is not bool:
            raise Refused("Export abandonment must be explicit")
        stage = Path(stage)
        with self._locks():
            value = owned_stage(stage, self.data)
            validate_link(value["link"])
            if (self._guard() != value["link"]["source_installation_id"]
                    or self.backup._runtime_metadata() != value["link"]["runtime"]
                    or not self.lifecycle.storage_gate_aware_ingest()):
                raise Refused("Recovery no longer belongs to this installed source/runtime")
            path = stage / "native.json"
            before_path = stage / "recovery-before.json"
            recovery = value.get("recovery")
            if recovery is None:
                original, before = value.copy(), trusted_file(path).read_bytes()
                if original["state"] not in ("preflight_failed", "planned", "holding", "dispatching", "running", "recovery_required", "failed", "succeeded", "released"):
                    raise Refused("This native child cannot enter unsuccessful recovery")
            else:
                if (not isinstance(recovery, dict) or recovery.get("state") not in ("release_intent", "released")
                        or value["state"] not in ("recovering", "recovered")
                        or recovery.get("abandon_export") is not abandon_export):
                    raise Refused("Recovery intent or abandonment choice differs")
                trusted_file(before_path)
                info = before_path.stat()
                if info.st_size > MAX_JOURNAL_BYTES or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise Refused("Unsafe original native recovery evidence")
                before = before_path.read_bytes()
                if hashlib.sha256(before).hexdigest() != recovery.get("before_journal_sha256"):
                    raise Refused("Original native recovery evidence changed")
                original = _json(before, MAX_JOURNAL_BYTES)
                if {k: v for k, v in value.items() if k not in ("state", "recovery")} != {k: v for k, v in original.items() if k != "state"}:
                    raise Refused("Native child changed outside its recovery journal")
            dispatched = "dispatched_at" in original
            if not dispatched and (original["state"] not in ("preflight_failed", "planned", "holding", "recovery_required")
                    or any(k in original for k in ("acknowledged_at", "last_status", "result", "deadline_at"))):
                raise Refused("Retained journal does not prove a pre-dispatch stop")
            if original["state"] == "preflight_failed" and original.get("preflight_no_effects") is not True:
                raise Refused("Failed planning lacks its same-invocation no-effects receipt")
            # A positively caught preflight failure may precede its first
            # successful observation. Bind a current read-only context without
            # rewriting the original evidence or inventing an earlier process.
            context = original.copy()
            if original["state"] == "preflight_failed":
                if "instance" not in context:
                    context["instance"] = recovery["proof"]["instance"] if recovery else self._instance(value["link"]["runtime"]["images"]["CLICKHOUSE_IMAGE"])
                if "table" not in context:
                    context["table"] = recovery["proof"]["table"] if recovery else self._table(context)
            if original["state"] in ("succeeded", "released") and not abandon_export:
                raise Refused("A completed native archive requires explicit export abandonment")
            terminal = self._recovery_status(stage, context, dispatched=dispatched)
            prior_terminal = original.get("last_status", {})
            if prior_terminal.get("status") in ("BACKUP_FAILED", "BACKUP_CANCELLED", "BACKUP_CREATED") and prior_terminal != terminal:
                raise Refused("Native terminal evidence differs from its previous observation")
            outcome = "not_dispatched" if terminal is None else terminal["status"].lower()
            if terminal is not None and terminal["status"] == "BACKUP_CREATED":
                if not abandon_export or terminal["error_present"]:
                    raise Refused("Native success requires explicit abandonment and fresh archive verification")
                outcome = "unsuccessful_export"
            elif original["state"] in ("succeeded", "released"):
                raise Refused("The successful native result no longer matches its terminal status")
            table = self._table(context)
            if any(table[k] != context["table"][k] for k in ("table_uuid", "table_definition_sha256", "server_version")):
                raise Refused("Recovery table identity changed")
            policy = self._policy()
            if "policy" in original and original["policy"] != policy:
                raise Refused("Recovery retention policy differs from the retained snapshot")
            if recovery is not None and (recovery["proof"]["policy"] != policy or recovery["proof"]["terminal"] != terminal):
                raise Refused("Recovery policy or terminal proof changed after release intent")
            archive, inventory, metadata = None, None, None
            if outcome == "unsuccessful_export":
                # The old budget expiring never cancelled the async job. This
                # is a fresh bounded read of a positively terminal job, not an
                # extension or replay of its original execution authority.
                deadline = _now() + timedelta(seconds=original["plan"]["deadline_seconds"])
                archive = self._archive(stage, original["plan"]["maximum_archive_bytes"], deadline, mount_label=original["instance"]["mount_label"])
                if terminal["compressed_size"] != archive["bytes"] or "result" in original and archive != original["result"]["archive"]:
                    raise Refused("Abandoned native archive differs from retained terminal evidence")
                inventory = inspect_native_archive(Path(archive["path"]), expected_bytes=archive["bytes"], deadline=deadline)
                times = [datetime.fromisoformat(terminal[k]).replace(tzinfo=timezone.utc).isoformat() for k in ("start_time", "end_time")]
                metadata = {"link": original["link"], "native": {"table": "nebulalog.events",
                    "server_version": table["server_version"], "table_uuid": table["table_uuid"],
                    "backup_id": original["backup_id"], "query_id": original["query_id"],
                    "started_at": times[0], "finished_at": times[1],
                    "table_definition_sha256": table["table_definition_sha256"], "retention_policy_revision": policy["revision"]},
                    "archive": {"format": "clickhouse-native-tar", "sha256": archive["sha256"], "bytes": archive["bytes"]}}
                validate_metadata(metadata)
                if "result" in original and original["result"]["metadata"] != metadata:
                    raise Refused("Abandoned native metadata differs from retained terminal evidence")
                if recovery is not None and any(recovery["proof"][k] != v for k, v in
                        (("archive", archive), ("inventory", inventory), ("metadata", metadata))):
                    raise Refused("Abandoned archive differs from the durable recovery proof")
            gates = self._recovery_gates(stage, context)
            if recovery is None and original["state"] in ("planned", "preflight_failed") and (gates["host"]["held"] or gates["database"]["held"]):
                raise Refused("A no-hold planning record cannot adopt an existing hold")
            if original["state"] == "released" and (gates["host"]["held"] or gates["database"]["held"]):
                raise Refused("A previously released native child has an unexpected current hold")
            if dispatched and outcome == "unsuccessful_export" and not gates["host"]["held"]:
                # Normal release may have cleared both gates before its child
                # journal advanced from succeeded to released. Idle alone is
                # not authority; the exact operation's release receipt is.
                self._release_receipt(stage)
            elif recovery is None and dispatched and not (gates["host"]["held"] and gates["database"]["held"]):
                raise Refused("The dispatched native child no longer owns both deletion holds")
            if recovery is not None and recovery["release_needed"] and not gates["host"]["held"]:
                self._release_receipt(stage)
            if recovery is None:
                # This immutable, bounded copy preserves the failed record even
                # when the sole authoritative journal advances to recovery.
                if os.path.lexists(before_path):
                    trusted_file(before_path)
                    prior = before_path.stat()
                    if prior.st_nlink != 1 or prior.st_mode & 0o077 or prior.st_size != len(before) or before_path.read_bytes() != before:
                        raise Refused("A different original recovery record already exists")
                else:
                    fd = os.open(before_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    try:
                        remaining = memoryview(before)
                        while remaining:
                            written = os.write(fd, remaining)
                            if written <= 0:
                                raise Refused("Original recovery evidence was not persisted")
                            remaining = remaining[written:]
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    parent = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(parent)
                    finally:
                        os.close(parent)
                recovery = {"state": "release_intent", "abandon_export": abandon_export,
                    "before_journal_sha256": hashlib.sha256(before).hexdigest(), "release_intent_at": _now().isoformat(),
                    "proof": {"outcome": outcome, "terminal": terminal, "policy": policy, "table": table,
                              "instance": context["instance"], "matching_processes": 0, "gates_before": gates,
                              "archive": archive, "inventory": inventory, "metadata": metadata}, "release_needed": gates["host"]["held"]}
                value.update(state="recovering", recovery=recovery)
                self._save(stage, value)  # Durable intent precedes any release.
            if self._recovery_status(stage, context, dispatched=dispatched) != terminal or self._policy() != policy:
                raise Refused("Native recovery evidence changed before release")
            try:
                if recovery["state"] == "release_intent" and gates["host"]["held"]:
                    self.lifecycle.storage_maintenance(stage, held=False)
                after = self._recovery_gates(stage, context)
                if after["host"]["held"] or after["database"]["held"]:
                    raise Refused("Native recovery hold release is not confirmed")
                if recovery["release_needed"]:
                    self._release_receipt(stage)
                if self._recovery_status(stage, context, dispatched=dispatched) != terminal or self._policy() != policy:
                    raise Refused("Native recovery evidence changed during release")
            except BaseException:
                # A positive release proof was not published. Re-establish the
                # owned conservative fence; the lifecycle primitive itself
                # retains its host fence if the database barrier is uncertain.
                if recovery["state"] == "release_intent" and recovery["release_needed"]:
                    self.lifecycle.storage_maintenance(stage, held=True, delivery_held=False)
                raise
            if recovery["state"] != "released":
                recovery.update(state="released", released_at=_now().isoformat(), gates_after=after)
                value["state"] = "recovered"
                self._save(stage, value)
            return {"state": "recovered", "id": value["id"], "settled": True, "holds_released": True,
                    "backup_complete": False, "outcome": outcome, "proof": recovery["proof"],
                    "before_journal_sha256": recovery["before_journal_sha256"],
                    "journal_sha256": hashlib.sha256(trusted_file(path).read_bytes()).hexdigest()}

    def _restore_context(self, runtime, source, manifest, tx):
        from .restore_runtime import FreshRestoreRuntime
        if not isinstance(runtime, FreshRestoreRuntime) or runtime.paths.data != self.data:
            raise Refused("Native restore adapter belongs to another target")
        runtime.log_restore_context(source, manifest, tx)
        native = tx["logs"]["native"]
        value = {**native, "link": tx["logs"]["metadata"]["link"]}
        if "instance" in native and self._instance(value["link"]["runtime"]["images"]["CLICKHOUSE_IMAGE"]) != native["instance"]:
            raise Refused("Native restore server instance changed")
        return native, value

    def _restore_stats(self, value):
        row = _json(self._bound_query(value, "SELECT (SELECT count() FROM nebulalog.events) AS rows,"
            "sumIf(p.rows,p.active) AS part_rows,sumIf(p.bytes_on_disk,p.active) AS bytes_on_disk,countIf(p.active) AS parts,"
            "(SELECT count() FROM system.detached_parts WHERE database='nebulalog' AND table='events') AS detached "
            "FROM system.parts AS p WHERE p.database='nebulalog' AND p.table='events' "
            "SETTINGS output_format_json_quote_64bit_integers=0 FORMAT JSONEachRow"))
        if not isinstance(row, dict) or set(row) != {"rows", "part_rows", "bytes_on_disk", "parts", "detached"}:
            raise Refused("Native restore data counters are incomplete")
        for count in row.values():
            _integer(count, 0, 2**64 - 1)
        if row["rows"] != row["part_rows"] or row["detached"] != 0:
            raise Refused("Native restore has inconsistent or detached rows")
        return row

    def plan_restore(self, runtime, source, manifest, tx, *, maximum_archive_bytes, deadline_seconds,
                     minimum_free_bytes, checkpoint=None):
        native, _ = self._restore_context(runtime, source, manifest, tx)
        plan = {"maximum_archive_bytes": _integer(maximum_archive_bytes, 1, MAX_ARCHIVE_BYTES),
                "deadline_seconds": _integer(deadline_seconds, 60, 86400),
                "minimum_free_bytes": _integer(minimum_free_bytes, MIN_RESERVE_BYTES, MAX_ARCHIVE_BYTES)}
        if native.get("state") == "planned" and native.get("plan") == plan:
            return {"state": "planned", "archive_ready": True}
        if native.get("state") != "table_ready":
            raise Refused("Native restore planning cannot replace an existing operation")
        archive = tx["logs"]["archive"]
        if archive["bytes"] > plan["maximum_archive_bytes"]:
            raise Refused("Authenticated log archive exceeds the restore plan")
        path = Path(archive["path"])
        _directory(path.parent, private=True)
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != ROOT_UID
                or info.st_mode & 0o077 or info.st_size != archive["bytes"]):
            raise Refused("Log restore input is not the protected authenticated archive")
        deadline = _now() + timedelta(seconds=plan["deadline_seconds"])
        inventory = inspect_native_archive(path, expected_bytes=archive["bytes"], deadline=deadline)
        sample = os.statvfs(self.data)
        free, total = sample.f_bavail * sample.f_frsize, sample.f_blocks * sample.f_frsize
        required = plan["maximum_archive_bytes"] + 2 * inventory["logical_bytes"] + 1024**3
        if minimum_free_bytes < max(MIN_RESERVE_BYTES, total // 10) or free - required < minimum_free_bytes:
            raise Refused("Native restore lacks archive-copy, data and filesystem reserves")
        native.update(plan=plan, inventory=inventory,
            backup_id=str(uuid.uuid4()), query_id=str(uuid.uuid4()),
            capacity={"free_bytes": free, "reserved_operation_bytes": required, "measured_at": _now().isoformat(), "hard_native_quota": False})
        value = {**native, "link": tx["logs"]["metadata"]["link"]}
        table = self._table(value)
        if any(table[k] != native["table"][k] for k in native["table"]) or any(self._restore_stats(value).values()):
            raise Refused("Fresh native restore target is no longer the empty factory table")
        native["state"] = "planned"
        runtime._log_checkpoint(tx, checkpoint)
        return {"state": "planned", "archive_ready": True}

    def _copy_restore_archive(self, tx, deadline):
        original = tx["logs"]["archive"]
        stage = Path(tx["stage"])
        directory, _ = self._paths(stage)
        if os.path.lexists(directory):
            raise Refused("Native restore staging already exists; interrupted copy cannot be replayed")
        label = tx["logs"]["native"]["instance"]["mount_label"]
        with self._service_directory_fd(directory, create=True, mount_label=label) as parent:
            source = os.open(original["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            target = None
            try:
                before = os.fstat(source)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != ROOT_UID
                        or before.st_mode & 0o077 or before.st_size != original["bytes"]):
                    raise Refused("Protected native restore archive changed")
                target = os.open("events.tar", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
                remaining, digest = before.st_size, hashlib.sha256()
                while remaining:
                    if _now() > deadline:
                        raise Refused("Native archive copy exceeded its admitted deadline")
                    chunk = os.read(source, min(remaining, 1024**2))
                    if not chunk:
                        raise Refused("Native archive copy ended early")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target, view)
                        if written <= 0:
                            raise Refused("Native archive copy did not progress")
                        view = view[written:]
                    remaining -= len(chunk)
                if os.read(source, 1) or digest.hexdigest() != original["sha256"] or _stable(before) != _stable(os.fstat(source)) or _stable(before) != _stable(Path(original["path"]).lstat()):
                    raise Refused("Authenticated native archive copy does not match its receipt")
                os.fchown(target, SERVICE_UID, SERVICE_GID)
                _verify_or_inherit_label(target, label, parent_fd=parent)
                os.fsync(target)
                os.fsync(parent)
                if _stable(os.fstat(target)) != _stable(os.stat("events.tar", dir_fd=parent, follow_symlinks=False)):
                    raise Refused("Native archive name changed while copying")
            finally:
                os.close(source)
                if target is not None:
                    os.close(target)
        copied = self._archive(stage, original["bytes"], deadline, mount_label=label)
        if any(copied[key] != original[key] for key in ("sha256", "bytes")):
            raise Refused("Native service copy failed immutable readback")
        return copied

    def start_restore(self, runtime, source, manifest, tx, *, checkpoint=None):
        native, value = self._restore_context(runtime, source, manifest, tx)
        if native.get("state") != "planned":
            raise Refused("Native RESTORE is single-dispatch; retained intent cannot be replayed")
        if any(self._restore_stats(value).values()):
            raise Refused("Native RESTORE target has acquired data")
        sample = os.statvfs(self.data)
        if sample.f_bavail * sample.f_frsize - native["capacity"]["reserved_operation_bytes"] < native["plan"]["minimum_free_bytes"]:
            raise Refused("Native restore capacity changed before dispatch")
        now = _now()
        native.update(state="staging", deadline_at=(now + timedelta(seconds=native["plan"]["deadline_seconds"])).isoformat())
        runtime._log_checkpoint(tx, checkpoint)
        try:
            deadline = datetime.fromisoformat(native["deadline_at"])
            native["service_archive"] = self._copy_restore_archive(tx, deadline)
            # The anchored copy/readback matches the authenticated whole-file
            # digest used by the protected source inventory; do not reopen a
            # service-owned absolute path just to parse the same metadata again.
            runtime.log_restore_hold(tx)
            native.update(state="dispatching", dispatched_at=_now().isoformat())
            runtime._log_checkpoint(tx, checkpoint)  # Before the only RESTORE dispatch.
            value = {**native, "link": tx["logs"]["metadata"]["link"]}
            _, container = self._paths(Path(tx["stage"]))
            query = ("RESTORE TABLE nebulalog.events FROM File('" + str(container) + "') SETTINGS id='" + native["backup_id"]
                + "', create_table=false, create_database=false, allow_non_empty_tables=false, allow_different_table_def=false,"
                  " restore_broken_parts_as_detached=false, structure_only=false, async=true")
            reply = _json(self._bound_query(value, query, ("--query_id=" + native["query_id"], "--format=JSONEachRow"), dispatch=True))
            if not isinstance(reply, dict) or set(reply) != {"id", "status"} or reply["id"] != native["backup_id"] or reply["status"] not in {"RESTORING", "RESTORED"}:
                raise Refused("Native RESTORE acknowledgement was not exact")
            native["state"] = "running"
            runtime._log_checkpoint(tx, checkpoint)
            return {"state": "running", "restored": False}
        except BaseException:
            native.update(state="recovery_required", reason="restore_dispatch_not_confirmed")
            runtime._log_checkpoint(tx, checkpoint)
            raise Refused("Native restore requires recovery; data, archive and fences are retained") from None

    def _check_restored(self, value, deadline):
        remaining = int((deadline - _now()).total_seconds())
        if remaining < 1 or self._instance(value["instance"]["pin"]) != value["instance"]:
            raise Refused("Restored checksum verification has no original instance or remaining budget")
        raw = self.cmd(["podman", "exec", "--user", "101:101", "nebulalog-clickhouse", "clickhouse-client",
            "--config-file=/etc/nebulalog/clickhouse-client.xml", "--max_execution_time=" + str(remaining),
            "--query", "CHECK TABLE nebulalog.events SETTINGS check_query_single_value_result=1 FORMAT JSONEachRow"], timeout=remaining)
        if self._instance(value["instance"]["pin"]) != value["instance"]:
            raise Refused("Native restore server changed during the checksum check")
        checked = _json(raw)
        if checked != {"result": 1} or type(checked.get("result")) is not int:
            raise Refused("Restored MergeTree data failed its full checksum check")

    def observe_restore(self, runtime, source, manifest, tx, *, checkpoint=None):
        native, value = self._restore_context(runtime, source, manifest, tx)
        if native.get("state") == "restored":
            return native["result"]
        if native.get("state") not in {"dispatching", "running", "recovery_required"} or "dispatched_at" not in native:
            raise Refused("Native restore has no dispatch to observe")
        try:
            columns = ",".join("toString(" + k + ", 'UTC') AS " + k if k in ("start_time", "end_time") else k for k in STATUS_COLUMNS)
            row = _json(self._bound_query(value, "SELECT " + columns + " FROM system.backups WHERE id={operation:String} "
                "SETTINGS output_format_json_quote_64bit_integers=0 FORMAT JSONEachRow", ("--param_operation=" + native["backup_id"],)))
            _, container = self._paths(Path(tx["stage"]))
            if (not isinstance(row, dict) or set(row) != set(STATUS_COLUMNS) or row["id"] != native["backup_id"] or row["query_id"] != native["query_id"]
                    or row["name"] != "File('" + str(container) + "')" or row["base_backup_name"] != "" or not isinstance(row["error"], str)
                    or row["status"] not in {"RESTORING", "RESTORED", "RESTORE_FAILED", "RESTORE_CANCELLED"}):
                raise Refused("Native restore status does not belong to this exact operation")
            for key in STATUS_COLUMNS[8:]:
                _integer(row[key], 0, 2**64 - 1)
            native["last_status"] = {k: v for k, v in row.items() if k != "error"}
            native["last_status"]["error_present"] = bool(row["error"])
            if row["status"] in {"RESTORE_FAILED", "RESTORE_CANCELLED"}:
                native["state"] = "failed"
                runtime._log_checkpoint(tx, checkpoint)
                return {"state": "failed", "restored": False}
            deadline = datetime.fromisoformat(native["deadline_at"])
            if _now() > deadline or row["error"]:
                raise Refused("Native restore is expired or contains an error; cancellation is not established")
            if row["status"] == "RESTORING":
                runtime._log_checkpoint(tx, checkpoint)
                return {"state": "running", "restored": False}
            if row["compressed_size"] != tx["logs"]["archive"]["bytes"] or row["num_files"] != native["inventory"]["logical_files"] or row["total_size"] != native["inventory"]["logical_bytes"]:
                raise Refused("Native RESTORE did not consume the admitted backup inventory")
            table = self._table(value)
            if any(table[k] != native["table"][k] for k in native["table"]):
                raise Refused("Native RESTORE changed the factory table identity")
            self._check_restored(value, deadline)
            stats = self._restore_stats(value)
            if stats["rows"] != native["inventory"]["rows"] or (stats["rows"] > 0 and stats["bytes_on_disk"] == 0) or stats["parts"] > native["inventory"]["parts"]:
                raise Refused("Restored rows/parts differ from the authenticated snapshot inventory")
            archive = self._archive(Path(tx["stage"]), tx["logs"]["archive"]["bytes"], deadline, mount_label=native["instance"]["mount_label"])
            if archive != native["service_archive"]:
                raise Refused("Native archive changed during RESTORE")
            times = [datetime.fromisoformat(row[k]).replace(tzinfo=timezone.utc) for k in ("start_time", "end_time")]
            if times[0] < datetime.fromisoformat(native["dispatched_at"]) - timedelta(seconds=5) or times[1] < times[0] or times[1] > _now() + timedelta(seconds=5):
                raise Refused("Native completion time is outside its retained dispatch")
            runtime.log_restore_hold(tx)
            native["result"] = {"state": "restored", "table_uuid": table["table_uuid"], "archive_sha256": archive["sha256"],
                **stats, "integrity_checked": True, "inventory_sha256": native["inventory"]["metadata_sha256"],
                "server_instance": native["instance"], "restore_id": native["backup_id"], "query_id": native["query_id"],
                "started_at": times[0].isoformat(), "finished_at": times[1].isoformat(), "listeners_released": False}
            native["state"] = "restored"
            runtime._log_checkpoint(tx, checkpoint)
            return native["result"]
        except BaseException:
            native.update(state="recovery_required", reason="restore_observation_not_confirmed")
            runtime._log_checkpoint(tx, checkpoint)
            raise Refused("Native restore requires recovery; data, archive and fences are retained") from None
