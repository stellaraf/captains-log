"""Durable fresh-appliance restore coordinator; no live replacement mode."""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
import uuid

from .backup import DATABASES, DATA, MAX_BYTES, _directory, _encrypted_staging, _now, _pg, unpack_backup
from .common import Refused, atomic_json, locked, require_linux_root, trusted_file
from .host_payload import strict_json
from .restore_database import RestoreDatabases
from .updates import digest_file

ARCHIVE_LIMIT = MAX_BYTES + 256 * 1024**2
TERMINAL = "runtime_ready"


def review_text(review):
    """Fixed secret-free console projection from a host-authenticated review."""
    return "Authenticated recovery review:\n" + json.dumps({key: review[key] for key in (
        "id", "scope", "source_installation_id", "target_installation_id", "archive_sha256",
        "expires_at", "review_digest")}, indent=2, sort_keys=True)


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise Refused("Restore requires an exact operation UUID") from None
    return value


def _json(path, limit=1024 * 1024):
    trusted_file(path)
    if path.stat().st_mode & 0o077 or not 0 < path.stat().st_size <= limit:
        raise Refused("Restore evidence must be bounded and root-only")
    return strict_json(path.read_bytes())


def authenticated_cms(path):
    """Accept the definite DER AuthEnvelopedData/AES-256-GCM format we emit.

    OpenSSL also decrypts unauthenticated CBC envelopes. Inspect only bounded
    ASN.1 headers and algorithm OIDs before asking it to validate the GCM tag;
    never load ciphertext or a textual ASN.1 dump into process memory.
    """
    length = path.stat().st_size
    with path.open("rb") as stream:
        def tlv(offset, end, expected=None):
            if not 0 <= offset < end <= length:
                raise Refused("Invalid encrypted backup envelope")
            stream.seek(offset)
            head = stream.read(2)
            if len(head) != 2 or expected is not None and head[0] != expected:
                raise Refused("Unexpected encrypted backup envelope")
            size = head[1]
            if size & 128:
                count = size & 127
                raw = stream.read(count) if 1 <= count <= 8 else b""
                if len(raw) != count or not raw or raw[0] == 0:
                    raise Refused("Unsupported encrypted backup length")
                size = int.from_bytes(raw, "big")
                if size < 128:
                    raise Refused("Noncanonical encrypted backup length")
            start = stream.tell()
            if start + size > end:
                raise Refused("Truncated encrypted backup envelope")
            return head[0], start, start + size

        def oid(offset, end, expected):
            _, start, stop = tlv(offset, end, 6)
            if stop - start != len(expected) or stream.read(len(expected)) != expected:
                raise Refused("Restore requires CMS authenticated AES-256-GCM encryption")
            return stop

        _, outer, end = tlv(0, length, 0x30)
        if end != length:
            raise Refused("Trailing encrypted backup data")
        offset = oid(outer, end, bytes.fromhex("2a864886f70d0109100117"))
        _, wrapped, wrapped_end = tlv(offset, end, 0xa0)
        _, body, body_end = tlv(wrapped, wrapped_end, 0x30)
        if wrapped_end != end or body_end != wrapped_end:
            raise Refused("Invalid authenticated envelope boundary")
        _, version, offset = tlv(body, body_end, 2)
        if offset - version != 1 or stream.read(1) != b"\x00":
            raise Refused("Unsupported authenticated envelope version")
        tag, _, next_offset = tlv(offset, body_end)
        if tag == 0xa0:  # Optional originatorInfo precedes recipientInfos.
            offset = next_offset
        _, _, offset = tlv(offset, body_end, 0x31)
        _, encrypted, encrypted_end = tlv(offset, body_end, 0x30)
        algorithm = oid(encrypted, encrypted_end, bytes.fromhex("2a864886f70d010701"))
        _, algorithm_start, algorithm_end = tlv(algorithm, encrypted_end, 0x30)
        parameters = oid(algorithm_start, algorithm_end, bytes.fromhex("60864801650304012e"))
        _, params, params_end = tlv(parameters, algorithm_end, 0x30)
        if params_end != algorithm_end:
            raise Refused("Invalid authenticated encryption parameters")
        _, nonce, nonce_end = tlv(params, params_end, 4)
        if nonce_end - nonce != 12:
            raise Refused("Unexpected authenticated encryption nonce length")
        _, tag_length, tag_end = tlv(nonce_end, params_end, 2)
        if tag_end != params_end or tag_end - tag_length != 1 or stream.read(1) != b"\x10":
            raise Refused("Restore requires a 128-bit authentication tag")
        _, _, ciphertext_end = tlv(algorithm_end, encrypted_end, 0x80)
        if ciphertext_end != encrypted_end:
            raise Refused("Invalid encrypted content boundary")
        # The MAC follows optional authenticated attributes.
        cursor = encrypted_end
        if tlv(cursor, body_end)[0] == 0xa1:
            cursor = tlv(cursor, body_end)[2]
        _, mac_start, mac_end = tlv(cursor, body_end, 4)
        if mac_end - mac_start != 16:
            raise Refused("Invalid encrypted backup authentication tag")
        if mac_end != body_end:
            _, _, attr_end = tlv(mac_end, body_end, 0xa2)
            if attr_end != body_end:
                raise Refused("Unexpected authenticated envelope suffix")


class ConfigurationRestore:
    def __init__(self, runtime=None, commands=None, *, clock=time.time):
        from .restore_runtime import FreshRestoreRuntime
        from nebulalog_adapters.commands import Commands
        self.runtime = runtime or FreshRestoreRuntime()
        self.cmd = commands or Commands()
        self.paths = self.runtime.paths
        self.data = self.paths.data
        self.manager = self.data / "manager"
        self.pointer = self.manager / "restore.json"
        self.injected_commands = commands is not None
        self.restore_descriptor = None
        self.clock = clock

    @staticmethod
    def _review_digest(review):
        return hashlib.sha256(json.dumps(review, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    def _review_inputs(self, tx):
        source, manifest = self._source(tx)
        encrypted = Path(tx["stage"]) / "backup.cms"
        from .log_recovery_set import _file, _digest_bounded
        info = _file(encrypted, ARCHIVE_LIMIT)
        if _digest_bounded(encrypted, info, ARCHIVE_LIMIT) != tx["archive_sha256"]:
            raise Refused("Prepared configuration ciphertext changed")
        compatible = self.runtime.inspect_recovery(source, manifest, tx)
        inventory = None
        required = 3 * ARCHIVE_LIMIT + 1024**3
        reserve = 0
        if "logs" in tx:
            from .log_backup import inspect_native_archive
            logs = tx["logs"]
            inventory = inspect_native_archive(Path(logs["archive"]["path"]), expected_bytes=logs["archive"]["bytes"],
                deadline=datetime.now(timezone.utc) + timedelta(seconds=logs["plan"]["deadline_seconds"]))
            required += logs["archive"]["bytes"] + 2 * inventory["logical_bytes"] + 1024**3
            reserve = logs["plan"]["minimum_free_bytes"]
        capacity = shutil.disk_usage(self.data)
        if ("logs" in tx and reserve < max(10 * 1024**3, capacity.total // 10)
                or capacity.free - required < reserve):
            raise Refused("Prepared restore lacks its configuration, native-copy and filesystem reserves")
        return {"compatibility": compatible, "native_inventory": inventory,
                "configuration_ciphertext_bytes": info.st_size, "required_free_bytes": required + reserve}

    def _prepared_review(self, tx):
        inspected = self._review_inputs(tx)
        stage = Path(tx["stage"])
        atomic_json(stage / "prepared.json", tx)
        now = int(self.clock())
        review = {"schema": 1, "kind": "fresh-restore-review", "id": tx["id"],
                  "state": "review_ready", "scope": "full" if "logs" in tx else "configuration",
                  "source_installation_id": tx["source_installation_id"],
                  "target_installation_id": tx["target_installation_id"],
                  "manifest_sha256": tx["manifest_sha256"], "archive_sha256": tx["archive_sha256"],
                  "prepared_sha256": digest_file(stage / "prepared.json"), "inspection": inspected,
                  "issued_at": now, "expires_at": now + 300, "setup_complete": False,
                  "runtime_changed": False, "eta_seconds": None}
        atomic_json(stage / "review.json", review)
        return {**review, "review_digest": self._review_digest(review)}

    def apply_prepared(self, identifier, review_digest):
        """Explicit root admission. An exact retry only reads retained status.

        Admission must begin before preview expiry; full TB input verification
        may take longer. An interrupted admission never silently renews a plan
        or dispatches effects: prepare another review while preserving evidence.
        """
        require_linux_root()
        identifier = _uuid(identifier)
        if not isinstance(review_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", review_digest):
            raise Refused("Apply requires the exact authenticated review digest")
        _directory(self.manager, private=True)
        with locked(self.manager / "restore.lock") as descriptor:
            self.restore_descriptor = descriptor
            if os.path.lexists(self.pointer):
                tx = self._load(identifier)
                if tx.get("review_digest") != review_digest:
                    raise Refused("Apply does not match the retained restore review")
                return self.status()
            with ExitStack() as stack:
                self._locks(stack)
                stage = self.manager / "restores" / identifier
                _directory(stage, private=True)
                review = _json(stage / "review.json")
                if (self._review_digest(review) != review_digest or review.get("id") != identifier
                        or review.get("schema") != 1 or review.get("kind") != "fresh-restore-review"
                        or review.get("state") != "review_ready"
                        or type(review.get("issued_at")) is not int or type(review.get("expires_at")) is not int
                        or review["expires_at"] - review["issued_at"] != 300
                        or not review["issued_at"] <= self.clock() < review["expires_at"]):
                    raise Refused("Restore review changed or expired; prepare and review the inputs again")
                tx = _json(stage / "prepared.json")
                if (digest_file(stage / "prepared.json") != review.get("prepared_sha256")
                        or tx.get("schema") != 1 or tx.get("kind") != "configuration-restore"
                        or tx.get("id") != identifier or tx.get("stage") != str(stage)
                        or tx.get("state") != "prepared" or tx.get("runtime") != {} or tx.get("databases") != {}
                        or any(tx.get(key) != review.get(key) for key in
                               ("source_installation_id", "target_installation_id", "archive_sha256", "manifest_sha256"))):
                    raise Refused("Prepared restore transaction differs from the reviewed inputs")
                if (os.path.lexists(stage / "apply-admission.json") or os.path.lexists(stage / "transaction.json")):
                    raise Refused("An interrupted apply admission requires a new explicit preview; retained inputs are preserved")
                if self.runtime.guard_fresh() != tx["target_installation_id"]:
                    raise Refused("Reviewed target installation changed")
                admitted_at = self.clock()
                if not review["issued_at"] <= admitted_at < review["expires_at"]:
                    raise Refused("Restore review expired during admission; prepare and review again")
                atomic_json(stage / "apply-admission.json", {"schema": 1, "id": identifier,
                    "review_digest": review_digest, "prepared_sha256": review["prepared_sha256"],
                    "target_installation_id": tx["target_installation_id"], "admitted_at": int(admitted_at)})
                if self._review_inputs(tx) != review["inspection"]:
                    raise Refused("Recovery compatibility, native inventory or target resources changed after review")
                if self.runtime.guard_fresh() != tx["target_installation_id"]:
                    raise Refused("Target changed during restore admission")
                if shutil.disk_usage(self.data).free < review["inspection"]["required_free_bytes"]:
                    raise Refused("Restore reserve changed before apply dispatch")
                # No runtime command can precede the durable transaction/pointer.
                tx["review_digest"] = review_digest
                self._save(tx)
            return self._continue(tx)

    def _runner(self, descriptors=()):
        if not self.injected_commands:
            from nebulalog_adapters.commands import Commands
            inherited = list(descriptors)
            if self.restore_descriptor is not None:
                inherited.append((self.restore_descriptor, self.manager / "restore.lock"))
            self.cmd = Commands(inherited_locks=inherited)
        self.runtime.runner = self.cmd
        if hasattr(self.runtime, "bootstrap"):
            self.runtime.bootstrap.runner = self.cmd

    def _locks(self, stack):
        descriptors = []
        for path in (self.manager / "transaction.lock", self.paths.bootstrap / "firstboot.lock",
                     self.data / "configuration/bootstrap/runtime.lock", self.data / "configuration/baseline.lock"):
            _directory(path.parent)
            descriptors.append((stack.enter_context(locked(path)), path))
        self._runner(descriptors)
        return descriptors

    def _save(self, tx):
        stage = self.manager / "restores" / _uuid(tx["id"])
        if tx.get("stage") != str(stage):
            raise Refused("Restore staging identity changed")
        pointer = {"schema": 2, "id": tx["id"], "stage": str(stage)}
        exists = os.path.lexists(self.pointer)
        if exists and _json(self.pointer) != pointer:
            raise Refused("Restore ownership pointer changed")
        tx["observed_at"] = _now()
        atomic_json(stage / "transaction.json", tx)
        # This immutable pointer is installed before any runtime effect. Every
        # later checkpoint changes only the authoritative journal, so a crash
        # cannot leave two independently replaced state/hash records disagreeing.
        if not exists:
            atomic_json(self.pointer, pointer)

    def _load(self, identifier):
        identifier = _uuid(identifier)
        pointer = _json(self.pointer)
        stage = self.manager / "restores" / identifier
        _directory(stage, private=True)
        tx = _json(stage / "transaction.json")
        if (pointer != {"schema": 2, "id": identifier, "stage": str(stage)} or tx.get("schema") != 1
                or tx.get("kind") != "configuration-restore" or tx.get("id") != identifier
                or tx.get("stage") != str(stage)):
            raise Refused("Restore transaction does not match its retained pointer")
        return tx

    def _source(self, tx):
        source = Path(tx["stage"]) / "source"
        _directory(source, private=True)
        if digest_file(trusted_file(source / "backup.json")) != tx["manifest_sha256"]:
            raise Refused("Restore manifest changed")
        manifest = _json(source / "backup.json")
        if (manifest.get("schema") != 1 or manifest.get("product") != "nebulalog"
                or manifest.get("kind") != "configuration" or manifest.get("includes_logs") is not False
                or _uuid(manifest.get("installation_id")) != tx["source_installation_id"]):
            raise Refused("Restore source identity or scope changed")
        expected = {"backup.json"}
        for entry in manifest["files"]:
            relative = entry["path"]
            if (not isinstance(relative, str) or Path(relative).as_posix() != relative
                    or Path(relative).is_absolute() or ".." in Path(relative).parts or relative in expected):
                raise Refused("Unsafe recovery inventory")
            expected.add(relative)
            path = trusted_file(source / relative)
            if (path.stat().st_nlink != 1 or path.stat().st_mode & 0o077
                    or type(entry.get("bytes")) is not int or path.stat().st_size != entry["bytes"]
                    or digest_file(path) != entry.get("sha256")):
                raise Refused("Restore source bytes differ from the authenticated inventory")
        actual = set()
        for path in source.rglob("*"):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise Refused("Unsafe recovery source member")
            if path.is_file():
                actual.add(path.relative_to(source).as_posix())
        if actual != expected or not set(name + ".dump" for name in DATABASES) <= expected:
            raise Refused("Restore source file set changed")
        if "logs" in tx:
            self._log_source(tx, manifest)
        return source, manifest

    def _log_source(self, tx, manifest):
        from .log_recovery_set import validate_metadata, _file, _digest_bounded, CHUNK_BYTES, MAX_CHUNKS
        logs, stage = tx["logs"], Path(tx["stage"])
        if (not isinstance(logs, dict) or set(logs) - {"schema", "state", "archive", "metadata", "native", "plan", "restore_proof"}
                or type(logs.get("schema")) is not int or logs["schema"] != 1
                or logs.get("state") not in {"authenticated", "restored"} or not isinstance(logs.get("native"), dict)):
            raise Refused("Invalid retained log recovery transaction")
        validate_metadata(logs.get("metadata"))
        encrypted = stage / "backup.cms"
        encrypted_info = _file(encrypted, ARCHIVE_LIMIT)
        link = {"source_installation_id": tx["source_installation_id"],
                "configuration_backup": {"sha256": tx["archive_sha256"], "bytes": encrypted_info.st_size},
                "runtime": manifest.get("runtime")}
        if (logs["metadata"]["link"] != link
                or _digest_bounded(encrypted, encrypted_info, ARCHIVE_LIMIT) != tx["archive_sha256"]):
            raise Refused("Retained logs belong to a different configuration recovery set")
        policy = manifest.get("snapshot", {}).get("retention_policy", {})
        if (type(policy.get("revision")) is not int
                or policy["revision"] != logs["metadata"]["native"]["retention_policy_revision"]):
            raise Refused("Configuration policy differs from the native log capture")
        archive = logs.get("archive")
        if (not isinstance(archive, dict) or set(archive) != {"path", "bytes", "sha256"}
                or archive["path"] != str(stage / "logs/events.tar")
                or any(archive[k] != logs["metadata"]["archive"][k] for k in ("bytes", "sha256"))):
            raise Refused("Retained native archive does not match its authenticated manifest")
        _directory(stage / "logs", private=True)
        path = Path(archive["path"])
        info = _file(path, CHUNK_BYTES * MAX_CHUNKS)
        if info.st_size != archive["bytes"] or _digest_bounded(path, info, archive["bytes"]) != archive["sha256"]:
            raise Refused("Retained native archive changed after authenticated decryption")
        plan = logs.get("plan")
        if (not isinstance(plan, dict) or set(plan) != {"maximum_archive_bytes", "deadline_seconds", "minimum_free_bytes"}
                or type(plan["maximum_archive_bytes"]) is not int or plan["maximum_archive_bytes"] != archive["bytes"]
                or type(plan["deadline_seconds"]) is not int or not 60 <= plan["deadline_seconds"] <= 86400
                or type(plan["minimum_free_bytes"]) is not int or not 10 * 1024**3 <= plan["minimum_free_bytes"] <= CHUNK_BYTES * MAX_CHUNKS):
            raise Refused("Retained native restore budgets changed or are invalid")

    def status(self):
        """Return a bounded journal projection, never secrets or a live health claim."""
        from .restore_runtime import RESTORE_STAGES
        require_linux_root()
        _directory(self.data)
        if not os.path.lexists(self.manager):
            return {"state": "not_started", "setup_complete": False}
        _directory(self.manager, private=True)
        if not os.path.lexists(self.pointer):
            return {"state": "not_started", "setup_complete": False}
        pointer = _json(self.pointer)
        if not isinstance(pointer, dict):
            raise Refused("Invalid restore ownership pointer")
        tx = self._load(pointer.get("id"))
        states = {"prepared", "preparing", "restoring", "normalizing", "restoring_logs", "activating",
                  "enrollment_pending", "verifying", "recovery_required", TERMINAL}
        progress, databases = tx.get("runtime"), tx.get("databases")
        if (not isinstance(tx.get("state"), str) or tx["state"] not in states or not isinstance(progress, dict)
                or not isinstance(databases, dict) or set(databases) - set(DATABASES)):
            raise Refused("Restore progress is invalid; retained evidence requires review")
        active, completed = progress.get("active_stage"), progress.get("completed", [])
        if (active is not None and (not isinstance(active, str) or active not in RESTORE_STAGES)
                or not isinstance(completed, list)
                or any(not isinstance(stage, str) or stage not in RESTORE_STAGES for stage in completed)
                or len(completed) != len(set(completed))):
            raise Refused("Restore runtime progress is invalid")
        observed = {}
        for name in DATABASES:
            row = databases.get(name, {"state": "not_started"})
            if (not isinstance(row, dict) or not isinstance(row.get("state"), str)
                    or row["state"] not in {"not_started", "restoring", "restored"}):
                raise Refused("Restore database progress is invalid")
            observed[name] = row["state"]
        fence = tx.get("failure_fence", {})
        result = {"id": tx["id"], "state": tx["state"], "setup_complete": False,
                "databases": observed, "runtime_active_stage": active,
                "runtime_completed": sorted(completed),
                "resume_blocked": active is not None or "restoring" in observed.values(),
                "listener_hold_recorded": isinstance(fence, dict) and fence.get("held") is True,
                "observation": "retained journal; not a current service or recovery acceptance check"}
        if "logs" in tx:
            if not isinstance(tx["logs"], dict) or not isinstance(tx["logs"].get("native"), dict):
                raise Refused("Invalid retained native recovery progress")
            native = tx["logs"].get("native", {})
            phase = native.get("state", "not_started")
            if not isinstance(phase, str) or phase not in {"not_started", "preparing", "table_ready", "planned", "staging", "dispatching", "running",
                             "restored", "binding", "bound", "releasing", "released", "failed", "recovery_required"}:
                raise Refused("Invalid retained native recovery phase")
            result["logs"] = {"requested": True, "phase": phase,
                              "verified_restore_recorded": tx["logs"].get("state") == "restored"}
            result["resume_blocked"] |= phase in {"preparing", "staging", "binding", "releasing", "failed"}
            if phase == "recovery_required" and "dispatched_at" not in native:
                result["resume_blocked"] = True
        return result

    def start(self, backup: Path, private_key: Path, certificate: Path, *, log_recovery_set=None,
              log_restore_deadline_seconds=None, log_restore_minimum_free_bytes=None):
        """Explicit root one-shot convenience over the same prepare/apply boundary."""
        review = self.prepare(backup, private_key, certificate, log_recovery_set=log_recovery_set,
            log_restore_deadline_seconds=log_restore_deadline_seconds,
            log_restore_minimum_free_bytes=log_restore_minimum_free_bytes)
        return self.apply_prepared(review["id"], review["review_digest"])

    def prepare(self, backup: Path, private_key: Path, certificate: Path, *, log_recovery_set=None,
                log_restore_deadline_seconds=None, log_restore_minimum_free_bytes=None):
        """Authenticate into private encrypted staging, without installing ownership.

        No database, service, listener or restore pointer is changed. Failed or
        expired previews preserve their input evidence for inspected cleanup.
        """
        if log_recovery_set is None:
            if log_restore_deadline_seconds is not None or log_restore_minimum_free_bytes is not None:
                raise Refused("Native restore budgets require an explicit encrypted log recovery set")
        elif (type(log_restore_deadline_seconds) is not int or not 60 <= log_restore_deadline_seconds <= 86400
              or type(log_restore_minimum_free_bytes) is not int
              or not 10 * 1024**3 <= log_restore_minimum_free_bytes <= 64 * 1024**4):
            raise Refused("Log recovery requires an explicit bounded deadline and free-space reserve")
        require_linux_root()
        installation = self.runtime.guard_fresh()
        _encrypted_staging(self.manager, self.cmd)
        _directory(self.manager, private=True)
        with locked(self.manager / "restore.lock") as descriptor:
            self.restore_descriptor = descriptor
            with ExitStack() as stack:
                self._locks(stack)
                if os.path.lexists(self.pointer):
                    raise Refused("A retained restore already owns this appliance; use its resume operation")
                if self.runtime.guard_fresh() != installation:
                    raise Refused("Target installation changed before recovery lock acquisition")
                for path in (backup, private_key, certificate):
                    trusted_file(path)
                    _directory(path.parent)
                    if path.lstat().st_nlink != 1:
                        raise Refused("Restore inputs must have exactly one filesystem link")
                if private_key.stat().st_mode & 0o077:
                    raise Refused("Restore private key must be root-only")
                if not 0 < backup.stat().st_size <= ARCHIVE_LIMIT:
                    raise Refused("Encrypted backup exceeds the recovery budget")
                if shutil.disk_usage(self.data).free < 3 * ARCHIVE_LIMIT + 1024**3:
                    raise Refused("Insufficient encrypted restore reserve")
                identifier = str(uuid.uuid4())
                stage = self.manager / "restores" / identifier
                _directory(stage, private=True, create=True)
                encrypted = stage / "backup.cms"
                from .log_recovery_set import _copy_bounded
                _copy_bounded(backup, encrypted, backup.lstat(), ARCHIVE_LIMIT)
                with encrypted.open("rb") as sealed:
                    os.fsync(sealed.fileno())
                authenticated_cms(encrypted)
                with tempfile.TemporaryDirectory(prefix="decrypt-", dir=stage) as temporary:
                    pinned_key, pinned_cert = Path(temporary) / "key.pem", Path(temporary) / "recipient.pem"
                    for original, pinned in ((private_key, pinned_key), (certificate, pinned_cert)):
                        info = original.lstat()
                        if info.st_nlink != 1 or not 0 < info.st_size <= 65536:
                            raise Refused("Recovery key/certificate must be bounded single-link inputs")
                        _copy_bounded(original, pinned, info, 65536)
                    archive = Path(temporary) / "backup.tar"
                    self.cmd(["prlimit", "--core=0", "--fsize=" + str(ARCHIVE_LIMIT), "--", "openssl", "cms",
                              "-decrypt", "-binary", "-inform", "DER", "-in", str(encrypted),
                              "-recip", str(pinned_cert), "-inkey", str(pinned_key), "-out", str(archive)], timeout=3600)
                    manifest = unpack_backup(archive, stage / "source")
                    tx = {"schema": 1, "kind": "configuration-restore", "id": identifier, "stage": str(stage),
                          "source_installation_id": _uuid(manifest.get("installation_id")),
                          "target_installation_id": installation, "manifest_sha256": digest_file(stage / "source/backup.json"),
                          "archive_sha256": digest_file(encrypted), "state": "prepared", "started_at": _now(),
                          "databases": {}, "runtime": {}}
                    if log_recovery_set is not None:
                        from .log_recovery_set import LogRecoverySet
                        log_stage = stage / "logs"
                        _directory(log_stage, private=True, create=True)
                        link = {"source_installation_id": tx["source_installation_id"],
                                "configuration_backup": {"sha256": tx["archive_sha256"], "bytes": encrypted.stat().st_size},
                                "runtime": manifest.get("runtime")}
                        recovered = LogRecoverySet(self.cmd).unseal(Path(log_recovery_set), log_stage / "events.tar",
                            pinned_cert, pinned_key, log_stage, link)
                        metadata = recovered["metadata"]
                        tx["logs"] = {"schema": 1, "state": "authenticated", "native": {}, "metadata": metadata,
                            "archive": {"path": str(log_stage / "events.tar"), "bytes": metadata["archive"]["bytes"],
                                        "sha256": metadata["archive"]["sha256"]},
                            "plan": {"maximum_archive_bytes": metadata["archive"]["bytes"],
                                     "deadline_seconds": log_restore_deadline_seconds,
                                     "minimum_free_bytes": log_restore_minimum_free_bytes}}
                    return self._prepared_review(tx)

    def resume(self, identifier):
        require_linux_root()
        _directory(self.manager, private=True)
        with locked(self.manager / "restore.lock") as descriptor:
            self.restore_descriptor = descriptor
            return self._continue(self._load(identifier))

    def _continue(self, tx):
        try:
            with ExitStack() as stack:
                self._locks(stack)
                self.runtime.guard_fresh(tx)
                source, manifest = self._source(tx)
                if tx["state"] == TERMINAL:
                    return {"ok": True, "id": tx["id"], "state": TERMINAL, "setup_complete": False,
                            "next": "Verify restored login and forwarding, enroll this host integrity baseline and export its new disk recovery material, then complete setup"}
                if any(item.get("state") == "restoring" for item in tx["databases"].values()):
                    raise Refused("Database completion is ambiguous; retained recovery data requires operator review or a new fresh target")
                tx["state"] = "preparing"
                self._save(tx)
                prepared = {"directories", "storage-maintenance", "certificates", "images", "environment", "postgresql"}
                if not prepared <= set(tx["runtime"].get("completed", [])):
                    self.runtime.prepare(source, manifest, tx, checkpoint=lambda: self._save(tx))
                metadata = manifest.get("postgresql", {})
                version = self.cmd(_pg(["psql", "-X", "--no-password", "--host=/var/run/postgresql", "--username=nebulalog",
                                       "--dbname=nebulalog", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1",
                                       "--command", "SHOW server_version"]))
                if (not isinstance(metadata.get("server_version"), str) or version != metadata["server_version"]
                        or metadata.get("image") != manifest["runtime"]["images"]["POSTGRESQL_IMAGE"]):
                    raise Refused("PostgreSQL version/image differs from the source backup")
                tx["state"] = "restoring"
                self._save(tx)
                databases = RestoreDatabases(self.cmd)
                entries = {entry["path"]: entry for entry in manifest["files"]}
                pending = [name for name in DATABASES if name not in tx["databases"]]
                # Discover a bad second target/archive before applying either
                # database. apply() repeats its own immediate idle/empty check.
                for name in pending:
                    databases.empty(name, tx["id"])
                for name in pending:
                    self.cmd.feed(_pg(["pg_restore", "--list"], interactive=True), source / (name + ".dump"), timeout=3600)
                for name in DATABASES:
                    databases.apply(name, source / (name + ".dump"), entries[name + ".dump"], tx, lambda: self._save(tx))
                receipt = {"schema": 1, "operation": tx["id"], "source_installation_id": tx["source_installation_id"],
                           "target_installation_id": tx["target_installation_id"], "observed": True}
                normalization = Path(tx["stage"]) / "normalization.json"
                if tx.get("operational_normalized") is True:
                    if _json(normalization) != receipt or digest_file(normalization) != tx.get("normalization_sha256"):
                        raise Refused("Retained source-operation normalization changed")
                else:
                    if tx.get("logs", {}).get("native"):
                        raise Refused("Native recovery cannot repeat source-operation normalization")
                    tx["state"] = "normalizing"
                    self._save(tx)
                    databases.quarantine_source_operations(tx)
                    atomic_json(normalization, receipt)
                    tx.update(operational_normalized=True, normalization_sha256=digest_file(normalization))
                if "logs" in tx and tx["logs"]["native"].get("state") not in {"bound", "released"}:
                    from .log_backup import LogBackupAdapter
                    tx["state"] = "restoring_logs"
                    self._save(tx)
                    checkpoint = lambda: self._save(tx)
                    self.runtime.prepare_log_restore(source, manifest, tx, checkpoint=checkpoint)
                    adapter = LogBackupAdapter.for_restore(self.runtime)
                    if tx["logs"]["native"].get("state") == "table_ready":
                        adapter.plan_restore(self.runtime, source, manifest, tx, **tx["logs"]["plan"], checkpoint=checkpoint)
                    if tx["logs"]["native"].get("state") == "planned":
                        adapter.start_restore(self.runtime, source, manifest, tx, checkpoint=checkpoint)
                    if tx["logs"]["native"].get("state") != "restored":
                        observed = adapter.observe_restore(self.runtime, source, manifest, tx, checkpoint=checkpoint)
                        if observed.get("state") == "running":
                            return {"ok": True, "id": tx["id"], "state": "restoring_logs", "setup_complete": False,
                                    "next": "Resume this exact operation to observe native recovery; listeners remain held"}
                        if observed.get("state") != "restored":
                            raise Refused("Native log restore has not completed successfully")
                    self.runtime.complete_log_restore(source, manifest, tx, checkpoint=checkpoint)
                tx["state"] = "activating"
                self._save(tx)
                self.runtime.activate(source, manifest, tx, checkpoint=lambda: self._save(tx))
                tx["state"] = "enrollment_pending"
                self._save(tx)
            # Installed-release enrollment takes its own manager lock. The
            # restore lock and durable pointer still prohibit another restore.
            self._runner()
            self.runtime.finish_enrollment(source, manifest, tx, checkpoint=lambda: self._save(tx))
            with ExitStack() as stack:
                self._locks(stack)
                current = self._load(tx["id"])
                if current != tx:
                    raise Refused("Restore transaction changed during release enrollment")
                self.runtime.guard_fresh(tx)
                source, manifest = self._source(tx)
                tx["state"] = "verifying"
                self._save(tx)
                result = self.runtime.verify(source, manifest, tx)
                tx.update(state=TERMINAL, result=result)
                self._save(tx)
                return {"ok": True, "id": tx["id"], "state": TERMINAL, "setup_complete": False,
                        "runtime": result, "next": "Verify restored login/forwarding and complete this host baseline, integrity and disk recovery checks"}
        except BaseException as exc:
            tx.update(state="recovery_required", error=type(exc).__name__)
            try:
                with ExitStack() as stack:
                    self._locks(stack)
                    tx["failure_fence"] = self.runtime.fence_failure(tx)
            except BaseException as fence_error:
                # Failure to establish a service hold is a separate unresolved
                # fact. Never report that listeners stopped based on intent.
                tx["failure_fence"] = {"verified": False, "error": type(fence_error).__name__}
            self._save(tx)
            raise Refused("Configuration restore " + tx["id"] + " requires recovery; retained archives and transaction were preserved, and setup is incomplete") from None
