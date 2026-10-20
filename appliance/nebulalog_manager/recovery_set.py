"""Durable coordination of configuration capture and optional native log backup.

Each database retains its own recorded capture time. A matching policy, immutable
runtime and encrypted configuration digest bind them into one recovery set; this
does not claim a cross-database atomic snapshot. Ambiguous child dispatches are
observed, never replayed. Successful completion requires exact ciphertext readback;
explicit unsuccessful retirement instead requires positive child settlement.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
import uuid

from .backup import ConfigurationBackup, _directory, _encrypted_staging, _now
from .common import Refused, atomic_json, locked, require_linux_root
from .host_payload import strict_json
from .log_backup import LogBackupAdapter, MAX_ARCHIVE_BYTES, MIN_RESERVE_BYTES, owned_stage
from .log_recovery_set import (LogRecoverySet, MANIFEST_BYTES, _file, _identity,
                               _digest_bounded, _hash, _fsync, validate_link, validate_metadata)


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise Refused("Recovery-set operations require an exact nonzero UUID") from None
    return value


def _read(path, maximum=1024**2):
    _directory(path.parent, private=True)
    before = _file(path, maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise Refused("Recovery-set journal changed before reading")
        raw = stream.read(before.st_size + 1)
        if (len(raw) != before.st_size or _identity(os.fstat(stream.fileno())) != _identity(before)
                or _identity(path.lstat()) != _identity(before)):
            raise Refused("Recovery-set journal changed while reading")
    value = strict_json(raw)
    if not isinstance(value, dict):
        raise Refused("Recovery-set journal must be an object")
    return value


class FullBackupManager:
    def __init__(self, configuration=None, native=None, transport=None):
        self.configuration = configuration or ConfigurationBackup()
        self.native = native or LogBackupAdapter(self.configuration.lifecycle)
        self.transport = transport or LogRecoverySet(self.configuration.cmd)
        self.data, self.manager = self.configuration.data, self.configuration.manager
        self.root = self.manager / "recovery-sets"
        self.pointer = self.manager / "recovery-set.json"

    @contextmanager
    def _lock(self):
        # Local encryption/capture children keep this lock if the coordinator
        # dies. Native asynchronous jobs still require independent DB proof.
        from nebulalog_adapters.commands import Commands
        path = self.manager / "recovery-set.lock"
        with locked(path) as descriptor:
            replacements, seen = [], set()
            owners = (self.configuration, self.configuration.lifecycle, self.native,
                      getattr(self.native, "backup", None), self.transport)
            try:
                for owner in owners:
                    if owner is None or id(owner) in seen:
                        continue
                    seen.add(id(owner))
                    original = getattr(owner, "cmd", None)
                    if type(original) is Commands:
                        owner.cmd = Commands(inherited_locks=(*original.inherited_locks, (descriptor, path)),
                            observer=original.observer, failure_observer=original.failure_observer)
                        replacements.append((owner, original))
                yield
            finally:
                for owner, original in reversed(replacements):
                    owner.cmd = original

    def _guard(self):
        require_linux_root()
        installation = self.configuration._guard()
        _encrypted_staging(self.manager, self.configuration.cmd)
        _directory(self.manager, private=True)
        return installation

    def _save(self, tx):
        stage = self.root / _uuid(tx["id"])
        if tx.get("stage") != str(stage):
            raise Refused("Recovery-set staging identity changed")
        _directory(stage, private=True)
        tx["observed_at"] = _now()
        atomic_json(stage / "transaction.json", tx)

    def _load(self, identifier):
        stage = self.root / _uuid(identifier)
        tx = _read(stage / "transaction.json")
        if (type(tx.get("schema")) is not int or tx["schema"] != 1
                or tx.get("kind") != "full-backup" or tx.get("id") != identifier or tx.get("stage") != str(stage)
                or tx.get("phase") not in {"prepared", "configuration", "planning", "native", "sealing", "releasing", "complete", "retired"}
                or tx.get("state") not in {"working", "running", "recovery_required", "complete", "retiring", "retired_without_backup"}):
            raise Refused("Recovery-set journal does not own this operation")
        _uuid(tx.get("installation_id"))
        if tx.get("children") != {"configuration": identifier, "native": identifier}:
            raise Refused("Recovery-set child ownership changed")
        output = Path(tx.get("output", ""))
        self._output(output, existing=True)
        certificate = stage / "recipient.pem"
        before = _file(certificate, 65536)
        if _digest_bounded(certificate, before, 65536) != tx.get("recipient_sha256"):
            raise Refused("Recovery-set recipient changed")
        self._budgets(tx.get("plan"))
        return tx

    def _output(self, output, *, existing=False):
        if not output.is_absolute() or ".." in output.parts or output == output.parent:
            raise Refused("Recovery-set output must be a new absolute directory")
        for protected in (self.manager, self.configuration.configuration, self.data / "clickhouse", self.data / "backup-staging"):
            if output.is_relative_to(protected) or protected.is_relative_to(output):
                raise Refused("Recovery-set output overlaps appliance configuration or scratch")
        _directory(output.parent)
        if existing:
            _directory(output, private=True)
        elif os.path.lexists(output):
            raise Refused("Recovery-set output already exists; retained exports are never overwritten")

    @staticmethod
    def _budgets(plan):
        bounds = {"maximum_archive_bytes": (64 * 1024**2, MAX_ARCHIVE_BYTES),
                  "growth_reserve_bytes": (64 * 1024**2, MAX_ARCHIVE_BYTES),
                  "minimum_free_bytes": (MIN_RESERVE_BYTES, MAX_ARCHIVE_BYTES),
                  "deadline_seconds": (60, 86400)}
        if (not isinstance(plan, dict) or set(plan) != set(bounds)
                or any(type(plan[k]) is not int or not lo <= plan[k] <= hi for k, (lo, hi) in bounds.items())):
            raise Refused("Full backup requires bounded archive, growth, free-space and deadline budgets")
        return plan

    def create(self, output, recipient_certificate, *, maximum_archive_bytes,
               growth_reserve_bytes, minimum_free_bytes, deadline_seconds):
        plan = self._budgets(dict(maximum_archive_bytes=maximum_archive_bytes,
            growth_reserve_bytes=growth_reserve_bytes, minimum_free_bytes=minimum_free_bytes,
            deadline_seconds=deadline_seconds))
        installation = self._guard()
        output = Path(output)
        self._output(output)
        # This distinct lock serializes coordinators, while children acquire the
        # existing four appliance locks themselves. Never nest those four here.
        with self._lock():
            if self._guard() != installation:
                raise Refused("Installation changed before full-backup admission")
            if os.path.lexists(self.pointer):
                previous = self._current()
                if previous["state"] == "retired_without_backup":
                    self._retirement(previous)
                elif previous["state"] != "complete" or previous["phase"] != "complete":
                    raise Refused("An unfinished recovery set owns this appliance; resume its exact UUID")
            identifier = str(uuid.uuid4())
            stage = self.root / identifier
            _directory(stage, private=True, create=True)
            certificate = self.transport._credential(Path(recipient_certificate), stage, "recipient.pem", certificate=True)
            output.mkdir(mode=0o700)
            tx = {"schema": 1, "kind": "full-backup", "id": identifier, "stage": str(stage),
                  "installation_id": installation, "output": str(output),
                  "recipient_sha256": _digest_bounded(certificate, _file(certificate, 65536), 65536),
                  "children": {"configuration": identifier, "native": identifier},
                  "plan": plan, "state": "working", "phase": "prepared", "started_at": _now()}
            self._save(tx)
            atomic_json(self.pointer, {"schema": 1, "id": identifier, "stage": str(stage)})
            return self._continue(tx)

    def _current(self):
        pointer = _read(self.pointer)
        identifier = _uuid(pointer.get("id"))
        if pointer != {"schema": 1, "id": identifier, "stage": str(self.root / identifier)}:
            raise Refused("Recovery-set ownership pointer changed")
        return self._load(identifier)

    def status(self, identifier):
        require_linux_root()
        tx = self._load(identifier)
        return self._projection(tx)

    @staticmethod
    def _projection(tx):
        return {"id": tx["id"], "state": tx["state"], "phase": tx["phase"],
                "includes_logs": True, "complete": tx["state"] == tx["phase"] == "complete",
                "retired": tx["state"] == "retired_without_backup", "native_qualified": False,
                "observation": "retained journal; not a restore acceptance check"}

    def resume(self, identifier):
        installation = self._guard()
        with self._lock():
            tx = self._current()
            if tx["id"] != _uuid(identifier) or tx["installation_id"] != installation:
                raise Refused("Resume does not own the active recovery set or installation")
            if tx["state"] in {"retiring", "retired_without_backup"}:
                raise Refused("Retirement cannot resume capture; use the exact retirement command for pending settlement")
            return self._continue(tx)

    @staticmethod
    def _journal_hash(path):
        return _digest_bounded(path, _file(path, 1024**2), 1024**2)

    def _retirement(self, tx):
        stage = Path(tx["stage"])
        receipt = _read(stage / "retirement.json")
        if (tx["state"] != "retired_without_backup" or tx["phase"] != "retired"
                or tx.get("retirement_sha256") != self._journal_hash(stage / "retirement.json")
                or receipt.get("schema") != 1 or receipt.get("id") != tx["id"]
                or receipt.get("installation_id") != tx["installation_id"]
                or receipt.get("state") != "retired_without_backup" or receipt.get("complete") is not False
                or receipt.get("settled") is not True or receipt.get("holds_released") is not True
                or receipt.get("intent_sha256") != self._journal_hash(stage / "retirement-intent.json")):
            raise Refused("Retirement receipt does not prove this operation settled unsuccessfully")
        for name, path in (("configuration", self.manager / "backups" / tx["id"] / "transaction.json"),
                           ("admission", self.manager / "backup-admissions" / tx["id"] / "admission.json"),
                           ("native", self.manager / "log-backups" / tx["id"] / "native.json")):
            expected = receipt.get("child_journals", {}).get(name)
            if (expected is None and os.path.lexists(path)) or (expected is not None and expected != self._journal_hash(path)):
                raise Refused("Retired child evidence changed; another backup cannot supersede it")
        return receipt

    def retire(self, identifier):
        """Explicitly abandon an export only after positive child settlement.

        No child is cancelled, replayed, deleted or labelled a successful backup.
        Lost recovery acknowledgements are reconciled by the child's own API.
        """
        installation = self._guard()
        with self._lock():
            tx = self._current()
            if tx["id"] != _uuid(identifier) or tx["installation_id"] != installation:
                raise Refused("Retirement does not own the active recovery set or installation")
            if tx["state"] == "retired_without_backup":
                self._retirement(tx)
                return self._projection(tx)
            if tx["state"] == "complete" or tx["phase"] in {"prepared", "complete", "retired"}:
                raise Refused("This operation has no supported unsuccessful retirement stage")
            stage = Path(tx["stage"])
            paths = {"configuration": self.manager / "backups" / tx["id"] / "transaction.json",
                     "admission": self.manager / "backup-admissions" / tx["id"] / "admission.json",
                     "native": self.manager / "log-backups" / tx["id"] / "native.json"}
            intent_path = stage / "retirement-intent.json"
            if os.path.lexists(intent_path):
                intent = _read(intent_path)
                if (intent.get("schema") != 1 or intent.get("id") != tx["id"]
                        or intent.get("installation_id") != installation or intent.get("phase") != tx["phase"]):
                    raise Refused("Retirement intent changed identity or capture phase")
                if (tx.get("retirement_intent_sha256") is not None
                        and tx["retirement_intent_sha256"] != self._journal_hash(intent_path)):
                    raise Refused("Retained retirement intent changed")
                if (tx.get("retirement_intent_sha256") is None
                        and (intent.get("parent_sha256") != self._journal_hash(stage / "transaction.json")
                             or intent.get("parent") != tx
                             or intent.get("child_journals") != {name: self._journal_hash(path) if os.path.lexists(path) else None
                                                                for name, path in paths.items()})):
                    raise Refused("Unacknowledged retirement intent does not bind its original parent")
            else:
                intent = {"schema": 1, "id": tx["id"], "installation_id": installation, "phase": tx["phase"],
                          "parent": tx, "parent_sha256": self._journal_hash(stage / "transaction.json"),
                          "child_journals": {name: self._journal_hash(path) if os.path.lexists(path) else None
                                             for name, path in paths.items()}, "started_at": _now()}
                atomic_json(intent_path, intent)
            tx.update(state="retiring", retirement_intent_sha256=self._journal_hash(intent_path))
            self._save(tx)
            # A synchronous configuration failure only qualifies with its own
            # positive no-capture or settled-command receipt and fresh health.
            configuration = self.configuration.settle_for_log_set(tx["id"], Path(tx["output"]) / "configuration.cms")
            if (configuration.get("id") != tx["id"] or configuration.get("installation_id") != installation
                    or configuration.get("settled") is not True):
                raise Refused("Configuration recovery did not prove exact child settlement")
            if tx["phase"] == "configuration":
                # The durable parent phase precedes native planning authority.
                # Absence alone is not this proof, and conflicting child evidence
                # still refuses adoption.
                if os.path.lexists(paths["native"].parent):
                    raise Refused("Unplanned native evidence conflicts with configuration-only retirement")
                native = {"settled": True, "holds_released": True, "backup_complete": False,
                          "outcome": "native_not_invoked"}
            else:
                config = self._configuration_result(tx)
                native_stage, child = self._native(tx, config)
                native = self.native.recover_backup(native_stage, abandon_export=True)
                if (native.get("id") != tx["id"] or native.get("settled") is not True
                        or native.get("holds_released") is not True or native.get("backup_complete") is not False):
                    raise Refused("Native recovery did not prove settled unsuccessful export")
            if self._guard() != installation or self._current()["id"] != tx["id"]:
                raise Refused("Retirement ownership changed before final commitment")
            receipt_path = stage / "retirement.json"
            receipt = {"schema": 1, "id": tx["id"], "installation_id": installation,
                       "state": "retired_without_backup", "complete": False, "settled": True, "holds_released": True,
                       "intent_sha256": self._journal_hash(intent_path), "configuration": configuration, "native": native,
                       "child_journals": {name: self._journal_hash(path) if os.path.lexists(path) else None
                                          for name, path in paths.items()}, "observed_at": _now()}
            if os.path.lexists(receipt_path):
                retained = _read(receipt_path)
                for key in ("schema", "id", "installation_id", "state", "complete", "settled", "holds_released", "intent_sha256", "child_journals"):
                    if retained.get(key) != receipt[key]:
                        raise Refused("Retained retirement receipt conflicts with child settlement")
            else:
                atomic_json(receipt_path, receipt)
            tx.update(state="retired_without_backup", phase="retired", retirement_sha256=self._journal_hash(receipt_path))
            self._save(tx)
            self._retirement(tx)
            return self._projection(tx)

    def _configuration_result(self, tx):
        child = _read(self.manager / "backups" / tx["id"] / "transaction.json")
        result = child.get("result")
        if (child.get("schema") != 1 or child.get("kind") != "configuration-backup"
                or child.get("id") != tx["id"] or child.get("installation_id") != tx["installation_id"]
                or child.get("state") != "complete" or not isinstance(result, dict)
                or result.get("id") != tx["id"] or result.get("path") != str(Path(tx["output"]) / "configuration.cms")):
            raise Refused("Configuration capture is incomplete or ambiguous; it cannot be replayed")
        link = result.get("log_link")
        validate_link(link)
        if (link["source_installation_id"] != tx["installation_id"]
                or link["configuration_backup"] != {"sha256": result.get("sha256"), "bytes": result.get("bytes")}
                or link["runtime"]["schema_revision"] != "3"):
            raise Refused("Configuration capture does not bind this supported recovery set")
        path = Path(result["path"])
        before = _file(path, 21 * 1024**3)
        if before.st_size != result["bytes"] or _digest_bounded(path, before, 21 * 1024**3) != result["sha256"]:
            raise Refused("Encrypted configuration differs from its completed capture")
        capture = result.get("configuration_capture")
        policy = capture.get("retention_policy") if isinstance(capture, dict) else None
        if (not isinstance(policy, dict) or set(policy) != {"revision", "raw_policy_sha256", "normalization"}
                or type(policy["revision"]) is not int or not 1 <= policy["revision"] < 2**63
                or policy["normalization"] not in {"stored", "absent_defaults_to_1"}):
            raise Refused("Configuration capture has no exact retention-policy binding")
        _hash(policy["raw_policy_sha256"])
        return result

    def _native(self, tx, config):
        stage = self.manager / "log-backups" / tx["id"]
        value = owned_stage(stage, self.data)
        if value.get("link") != config["log_link"] or value.get("plan") != tx["plan"]:
            raise Refused("Native operation belongs to different configuration or budgets")
        return stage, value

    def _continue(self, tx):
        try:
            output, stage = Path(tx["output"]), Path(tx["stage"])
            if tx["phase"] == "prepared":
                tx.update(phase="configuration", state="working")
                self._save(tx)  # Write child identity/intent before pausing writers.
                self.configuration.create_for_log_set(output / "configuration.cms", stage / "recipient.pem", tx["id"])
            config = self._configuration_result(tx)
            policy = config["configuration_capture"]["retention_policy"]
            native_stage = self.manager / "log-backups" / tx["id"]
            if tx["phase"] == "configuration":
                tx.update(phase="planning", state="working")
                self._save(tx)
                self.native.plan(native_stage, mode="backup", linked_metadata=config["log_link"], **tx["plan"])
            native_stage, native = self._native(tx, config)
            if tx["phase"] == "planning":
                if native["state"] != "planned":
                    raise Refused("Unacknowledged native plan cannot be replayed")
                tx.update(phase="native", state="working")
                self._save(tx)
            if tx["phase"] == "native":
                if native["state"] == "planned":
                    self.native.start_backup(native_stage, expected_policy_revision=policy["revision"],
                                             expected_raw_policy_sha256=policy["raw_policy_sha256"])
                result = self.native.observe(native_stage)
                if result.get("state") == "running":
                    tx["state"] = "running"
                    self._save(tx)
                    return self._projection(tx)
                if result.get("state") == "failed":
                    raise Refused("Native backup failed; retained archive and deletion hold require recovery")
                validate_metadata(result.get("metadata"))
                if (result["metadata"]["link"] != config["log_link"]
                        or result["metadata"]["native"]["retention_policy_revision"] != policy["revision"]
                        or result["archive"]["path"] != str(self.data / "clickhouse/backup-staging" / tx["id"] / "events.tar")):
                    raise Refused("Completed native snapshot does not belong to this recovery set")
                tx.update(phase="sealing", state="working", native_result=result)
                self._save(tx)
                self.transport.seal(Path(result["archive"]["path"]), output / "logs", stage / "recipient.pem",
                    self.data / "backup-staging", result["metadata"],
                    checkpoint=lambda receipt: atomic_json(stage / "seal.json", receipt))
            result = tx.get("native_result")
            if not isinstance(result, dict):
                raise Refused("Recovery set has no retained completed native evidence")
            _, settled = self._native(tx, config)
            if (settled.get("state") not in {"succeeded", "released"} or settled.get("result") != result
                    or settled.get("policy") != policy
                    or result["metadata"]["archive"] != {"format": "clickhouse-native-tar",
                        "sha256": result["archive"]["sha256"], "bytes": result["archive"]["bytes"]}):
                raise Refused("Retained native completion or policy differs from the recovery set")
            # A crash during seal is recovered only if its complete publication
            # matches the private pre-publication receipt. Partial output stays.
            exported = self.transport.inspect_sealed(output / "logs", _read(stage / "seal.json", MANIFEST_BYTES), result["metadata"])
            _fsync(output / "configuration.cms")
            _fsync(output)
            _fsync(output.parent)  # Persist the top-level export entry too.
            if tx["phase"] == "sealing":
                tx.update(phase="releasing", state="working", encrypted_export=exported)
                self._save(tx)
            if tx["phase"] == "releasing":
                self.native.release(native_stage)
                tx.update(phase="complete", state="complete", completed_at=_now())
                self._save(tx)
            if tx["phase"] != "complete" or tx["state"] != "complete":
                raise Refused("Unsupported full-backup continuation state")
            return {**self._projection(tx), "output": str(output), "configuration_sha256": config["sha256"],
                    "logs_manifest_sha256": exported["manifest_sha256"], "cross_database_atomic": False}
        except BaseException as exc:
            tx.update(state="recovery_required", error=type(exc).__name__)
            self._save(tx)
            raise Refused("Full backup " + tx["id"] + " requires recovery; child journals, archives and any storage hold were retained") from None
