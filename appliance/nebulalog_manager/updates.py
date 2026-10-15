"""Signed, expiring release verification and auditable component transactions.

The download channel supplies data only. Executable hooks are installed locally,
root-owned and not selected by the manifest. Verification public keys are trusted
out of band; no private key ships with NebulaLog.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, time, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Callable
from zoneinfo import ZoneInfo
from .common import Refused, atomic_json, audit, locked, require_linux_root, run, trusted_file
from .update_enrollment import enrolled_key, enrollment_status
from . import host_activation, host_dispatch, host_payload, livepatch

COMPONENTS = frozenset(("nebulalog", "keycloak", "postgresql", "clickhouse", "scap", "baseline", "host"))
REQUIRED_CHECKS = frozenset(("api", "web", "clickhouse", "postgresql", "keycloak", "local_auth", "ingestion", "fips", "selinux", "luks", "firewall", "compliance"))
CLICKHOUSE_VERSION = re.compile(r"([0-9]+(?:\.[0-9]+){2,3})(\.altinityfips)?")
HOST_PHASE_CHECKS = {
    "update-preflight": {"dispatcher_ready", "reconciliation_supported", "rollback_supported", "provenance_supported"},
    "update-backup": {"backup_verified", "customer_state_preserved", "trust_preserved"},
    "update-prepare": {"prepared_files", "backup_verified", "customer_state_preserved", "trust_preserved"},
    "update-activate": {"runtime_files", "runtime_processes", "services", "customer_state_preserved", "trust_preserved"},
    "update-rollback": {"runtime_files", "runtime_processes", "services", "customer_state_preserved", "trust_preserved"},
    "update-health": {"runtime_files", "runtime_processes", "services", "customer_state_preserved", "trust_preserved"},
    "update-finalize": {"runtime_files", "runtime_processes", "maintenance_released", "trust_preserved"},
}


def os_maintenance_pending(transaction):
    """An OS-owned storage hold or kernel recovery survives runtime health."""
    return bool(transaction and (
        transaction.get("state") not in {"complete", "failed", "reboot_aborted"}
        or transaction.get("finalization", "complete") != "complete"
        or transaction.get("storage_maintenance") in {"held", "release_pending"}
        or any(transaction.get(field, "complete") not in (None, "complete")
               for field in ("kernel_finalization", "kernel_retention", "kernel_rollback"))))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("Duplicate JSON key in signed manifest")
        result[key] = value
    return result


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while data := source.read(1024 * 1024):
            digest.update(data)
    return digest.hexdigest()


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except (ValueError, AttributeError) as exc:
        raise Refused("Manifest timestamp must have a timezone") from exc


def validate_clickhouse_change(change: dict):
    """Retain the exact installed vendor identity and every signed range endpoint."""
    versions = change.get("from_versions")
    if not isinstance(versions, list) or not 1 <= len(versions) <= 64:
        raise Refused("ClickHouse requires bounded explicit source versions")
    versions = [change.get("version"), *versions]
    if any(not isinstance(version, str) or len(version) > 128 or not CLICKHOUSE_VERSION.fullmatch(version)
           for version in versions):
        raise Refused("ClickHouse version or vendor suffix is unsupported")
    parsed = [CLICKHOUSE_VERSION.fullmatch(version) for version in versions]
    family = ".".join(parsed[0][1].split(".")[:2])
    if (change.get("family") != family or any(".".join(item[1].split(".")[:2]) != family for item in parsed)
            or any(item[2] != parsed[0][2] for item in parsed)):
        raise Refused("ClickHouse must retain its signed family and vendor suffix")
    bounds = [change.get(field) for field in ("tested_minimum", "tested_maximum")]
    if any(not isinstance(value, str) or len(value) > 128 or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2,3}", value)
           for value in bounds):
        raise Refused("ClickHouse requires explicit numeric tested range bounds")
    def numeric(value):
        parts = value.split(".")
        return tuple(int(part) for part in parts) + (0,) * (4 - len(parts))
    minimum, maximum = map(numeric, bounds)
    if minimum > maximum or any(not minimum <= numeric(item[1]) <= maximum for item in parsed):
        raise Refused("Every ClickHouse upgrade endpoint must lie in its signed tested range")


def verify_release(manifest_path: Path, signature: Path, public_key: Path, bundle: Path,
                   *, current_sequence: int = 0, current_versions: dict | None = None,
                   now: datetime | None = None, runner: Callable = run, allow_expired: bool = False,
                   metadata_only: bool = False) -> dict:
    now = now or datetime.now(timezone.utc)
    if manifest_path.stat().st_size > 1024*1024 or signature.stat().st_size > 16384:
        raise Refused("Oversized update metadata")
    raw = manifest_path.read_bytes()
    if len(raw) > 1024*1024:
        raise Refused("Manifest grew while being read")
    # RSA-PSS + SHA256 with fixed SHA256-length salt; uses appliance OpenSSL provider.
    runner(["openssl", "dgst", "-sha256", "-verify", str(public_key),
            "-signature", str(signature), "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:32", str(manifest_path)])
    # Reject TOCTOU metadata replacements after signature verification.
    if manifest_path.read_bytes() != raw:
        raise Refused("Manifest changed during signature verification")
    try:
        manifest = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError) as exc:
        raise Refused("Invalid signed JSON manifest") from exc
    if (not isinstance(manifest, dict) or type(manifest.get("schema")) is not int or manifest["schema"] != 1
            or manifest.get("product") != "nebulalog" or manifest.get("channel") != "stable"):
        raise Refused("Unsupported product, schema or update channel")
    sequence = manifest.get("sequence")
    if type(sequence) is not int or not 0 < sequence < 2**63 or sequence <= current_sequence:
        raise Refused("Replay or downgrade rejected by monotonic release sequence")
    issued, expires = _utc(manifest.get("issued_at")), _utc(manifest.get("expires_at"))
    if issued > now or expires <= issued or (now >= expires and not allow_expired):
        raise Refused("Release metadata is expired or not yet valid; verify system time")
    if (not isinstance(manifest.get("version"), str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", manifest["version"])):
        raise Refused("Invalid release version")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise Refused("Release has no artifacts")
    names = set()
    total = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise Refused("Invalid artifact metadata")
        name, sha, size = artifact.get("name"), artifact.get("sha256"), artifact.get("bytes")
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}", name)
                or name in names or name in {"manifest.json", "manifest.sig", "host-activation.json"}):
            raise Refused("Duplicate or unsafe artifact path")
        names.add(name)
        if type(size) is not int or size <= 0:
            raise Refused("Invalid artifact length")
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha):
            raise Refused("Invalid artifact hash")
        if not metadata_only:
            path = bundle / name
            if path.is_symlink() or not path.is_file() or path.resolve().parent != bundle.resolve():
                raise Refused("Artifacts must be regular files directly inside the bundle")
            if path.stat().st_size != size:
                raise Refused("Artifact length mismatch")
            if digest_file(path) != sha:
                raise Refused("Artifact hash mismatch")
        total += size
    components = manifest.get("components")
    if not isinstance(components, dict) or not components or not set(components) <= COMPONENTS:
        raise Refused("Unknown release components")
    for name, change in components.items():
        if not isinstance(change, dict) or not isinstance(change.get("artifact"), str) or change["artifact"] not in names:
            raise Refused("Component references an unverified artifact")
        if not isinstance(change.get("version"), str) or not change["version"]:
            raise Refused("Component version missing")
        if not isinstance(change.get("from_versions"), list) or not change["from_versions"]:
            raise Refused("An explicit supported component upgrade path is required")
        if current_versions is not None and current_versions.get(name) not in change["from_versions"]:
            raise Refused(f"Unsupported {name} upgrade path")
        if type(change.get("rollback_safe")) is not bool:
            raise Refused("Component must explicitly declare rollback safety")
        if name == "host":
            if (set(change) != {"artifact", "version", "from_versions", "rollback_safe", "abi", "host_source_sha256"}
                    or any(not isinstance(version, str) or not host_payload.VERSION.fullmatch(version) for version in change["from_versions"])
                    or any(other != "host" and item.get("artifact") == change["artifact"] for other, item in components.items() if isinstance(item, dict))):
                raise Refused("Host releases require the exact fixed component contract and their own artifact")
            identity, artifact = host_activation._candidate_identity(manifest)
            if not metadata_only:
                evidence = host_payload.verify_archive(bundle / artifact["name"], expected_sha256=artifact["sha256"],
                                                       expected_host_source_sha256=identity["host_source_sha256"])
                if evidence["metadata"]["version"] != identity["version"]:
                    raise Refused("Host archive version differs from its signed component")
        if name == "clickhouse":
            validate_clickhouse_change(change)
    return {**manifest, "verified_bytes": 0 if metadata_only else total, "declared_bytes": total,
            "artifacts_verified": not metadata_only, "manifest_sha256": hashlib.sha256(raw).hexdigest()}


def in_maintenance_window(now: datetime, *, weekday: int = 6, start: str = "03:00", end: str = "05:00", zone: str = "UTC") -> bool:
    if now.utcoffset() is None or not 0 <= weekday <= 6:
        raise ValueError("An aware timestamp and weekday 0..6 are required")
    local = now.astimezone(ZoneInfo(zone))
    begin, finish = time.fromisoformat(start), time.fromisoformat(end)
    if begin == finish:
        raise ValueError("Maintenance window cannot be empty or all-day")
    wall = local.time().replace(tzinfo=None)
    if finish > begin:
        return local.weekday() == weekday and begin <= wall < finish
    return (local.weekday() == weekday and wall >= begin) or (local.weekday() == (weekday+1) % 7 and wall < finish)


class UpdateManager:
    """Runs only fixed root-owned lifecycle adapters; durable journal precedes writes.

    Adapters are part of the installed appliance policy, not downloaded shell code.
    Each accepts a staged verified release directory argument and returns JSON.
    Components with irreversible migrations are refused by automatic install.
    """
    def __init__(self, state: Path = Path("/var/lib/nebulalog/manager/updates"),
                 hooks: Path = Path("/usr/libexec/nebulalog"), runner: Callable = run):
        self.state, self.hooks, self.runner = state, hooks, runner

    def status(self) -> dict:
        current = self.state / "current.json"
        transaction = self.state / "transaction.json"
        record = json.loads(transaction.read_text()) if transaction.exists() else None
        pending = bool(record and record.get("state") in ("committed", "rolled_back") and record.get("finalization") != "complete")
        os_path = self.state.parent / "os-transaction.json"
        os_transaction = json.loads(os_path.read_text()) if os_path.exists() else None
        os_pending = os_maintenance_pending(os_transaction)
        interrupted = bool(record and record.get("state") in {"preflight", "preparing", "activating", "checking", "rolling_back", "recovery_required"})
        recovery = "nebulalog update finalize" if pending else "nebulalog update recover" if interrupted else None
        return {"current": json.loads(current.read_text()) if current.exists() else {"sequence": 0, "components": {}},
                "enrollment": enrollment_status(self.state),
                "transaction": record, "maintenance_release_pending": pending,
                "recovery_action": None if os_pending else recovery,
                "recovery_blocked_by": "os_update" if os_pending and recovery else None,
                "os_transaction": os_transaction}

    def _retain_host_refusal(self, transaction: dict, stage: Path):
        """Copy only the fixed public-safe refusal schema; never adapter text."""
        try:
            raw = host_payload.read_regular(stage / "host-refusal.json", 4096, trusted=True)
            value = json.loads(raw)
            if (not isinstance(value, dict) or set(value) != {"schema", "reason", "resource", "sequence", "manifest_sha256"}
                    or type(value["schema"]) is not int or value["schema"] != 1
                    or value["reason"] != "qualified_migration_required"
                    or type(value["resource"]) is not str or value["resource"] not in host_payload.CATALOG_BY_PATH
                    or type(value["sequence"]) is not int or value["sequence"] != transaction["sequence"]
                    or value["manifest_sha256"] != transaction["manifest_sha256"]):
                return
            transaction["host_refusal"] = value
        except (OSError, ValueError, Refused):
            return

    def _hook(self, name: str, release: Path) -> dict:
        transaction = json.loads((self.state / "transaction.json").read_text())
        manifest = json.loads((release / "manifest.json").read_text())
        if "host" in manifest.get("components", {}):
            if self.state != host_dispatch.STATE or transaction.get("host_update") is not True:
                raise Refused("Host update requires the fixed enrolled manager and coordinator pin")
            result = host_dispatch.run_hook(transaction.get("host_coordinator"), name, release)
            self._host_evidence(result, name, release)
            return result
        path = trusted_file(self.hooks / name)
        result = json.loads(self.runner([str(path), str(release)], timeout=3600))
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise Refused(f"Appliance {name} did not report success")
        return result

    def _host_evidence(self, result: dict, name: str, stage: Path):
        transaction, manifest = host_dispatch.transaction_binding(stage)
        pin = host_dispatch.coordinator_pin(stage)
        candidate, _ = host_activation._candidate_identity(manifest)
        active_candidate = name == "update-activate" or name in {"update-health", "update-finalize"} and transaction["state"] in {"checking", "committed"}
        expected = candidate if active_candidate else {key: pin[key] for key in candidate}
        evidence = result.get("host")
        checks = evidence.get("checks") if isinstance(evidence, dict) else None
        if (not isinstance(evidence, dict) or type(evidence.get("schema")) is not int or evidence["schema"] != 1
                or type(evidence.get("abi")) is not int or evidence["abi"] != host_payload.ABI
                or evidence.get("generation") != expected["generation"]
                or evidence.get("host_source_sha256") != expected["host_source_sha256"]
                or evidence.get("coordinator_generation") != pin["generation"]
                or evidence.get("candidate_generation") != candidate["generation"]
                or evidence.get("plan_sha256") != host_payload.digest(host_payload.read_regular(stage / "host-runtime-plan.json", host_payload.MAX_METADATA, trusted=True))
                or not isinstance(checks, dict) or any(checks.get(key) is not True for key in HOST_PHASE_CHECKS[name])):
            raise Refused("Host lifecycle did not supply the required measured runtime acceptance evidence")
        observed = host_dispatch.generation_info(expected["generation"])
        if observed != expected:
            raise Refused("Accepted host evidence differs from its retained immutable generation")
        selection = host_activation.selection()
        expected_sequence = transaction["previous"]["sequence"] if name in {"update-preflight", "update-backup", "update-prepare"} else transaction["sequence"]
        if selection != {"schema": 1, "generation": expected["generation"], "sequence": expected_sequence}:
            raise Refused("Measured host runtime does not match the durable selected generation")

    def _restore_host(self, transaction: dict, stage: Path):
        if transaction.get("host_update") is True:
            host_activation.restore_previous(stage)

    def _advance_host_sequence(self, transaction: dict, stage: Path):
        if transaction.get("host_update") is not True and "host" in transaction["previous"]["components"]:
            host_activation.advance_unchanged(stage)

    def _finalize(self, transaction: dict, stage: Path) -> dict:
        """A failed maintenance release never reverses an already accepted update."""
        if transaction.get("state") not in ("committed", "rolled_back"):
            raise Refused("Only a durably completed component transaction may finalize")
        transaction["finalization"] = "pending"
        atomic_json(self.state / "transaction.json", transaction)
        try:
            self._hook("update-finalize", stage)
        except Exception as exc:
            transaction["finalization"] = "failed"
            transaction["finalization_error"] = type(exc).__name__
            atomic_json(self.state / "transaction.json", transaction)
            audit(self.state / "history.jsonl", "update.finalization_failed", sequence=transaction["sequence"], error=type(exc).__name__)
            raise Refused("Component transaction is complete; maintenance release failed. Run nebulalog update finalize after correcting the reported adapter condition") from exc
        transaction["finalization"] = "complete"
        transaction.pop("finalization_error", None)
        atomic_json(self.state / "transaction.json", transaction)
        audit(self.state / "history.jsonl", "update.finalized", sequence=transaction["sequence"])
        return transaction

    def _retained_release(self, transaction: dict, public_key: Path, *, finalization=False, recovery=False) -> tuple[Path, dict]:
        stage = Path(transaction["release"])
        if stage.is_symlink() or stage.resolve().parent != (self.state / "releases").resolve():
            raise Refused("Retained release is outside the manager staging directory")
        release = verify_release(stage / "manifest.json", stage / "manifest.sig", public_key, stage,
                                 current_sequence=0, runner=self.runner, allow_expired=finalization or recovery,
                                 metadata_only=transaction.get("host_update") is True and (recovery or transaction.get("state") == "rolled_back"))
        if release["manifest_sha256"] != transaction["manifest_sha256"]:
            raise Refused("Retained release metadata does not match the transaction")
        return stage, release

    def finalize(self, public_key: Path) -> dict:
        """Retry only health verification and maintenance release, never activation/restore."""
        require_linux_root()
        trusted_file(public_key)
        with locked(self.state.parent / "transaction.lock"), locked(self.state / "transaction.lock"):
            livepatch.require_settled(self.state)
            enrolled_key(self.state, public_key)
            status = self.status()
            if os_maintenance_pending(status["os_transaction"]):
                raise Refused("OS recovery must finish before component finalization")
            transaction = status["transaction"]
            if not transaction or transaction.get("state") not in ("committed", "rolled_back"):
                raise Refused("No completed component transaction is awaiting finalization")
            if transaction.get("finalization") == "complete":
                return transaction
            # Expiry blocks new activation, not recovering access to software that
            # was already accepted. Signature and durable exact-hash binding remain.
            stage, _ = self._retained_release(transaction, public_key, finalization=True)
            try:
                health = self._hook("update-health", stage)
                if not REQUIRED_CHECKS <= set(health.get("checks", {})) or any(health["checks"].get(k) is not True for k in REQUIRED_CHECKS):
                    raise Refused("Current runtime acceptance checks failed")
            except Exception as exc:
                transaction["finalization"] = "failed"
                transaction["finalization_error"] = type(exc).__name__
                atomic_json(self.state / "transaction.json", transaction)
                audit(self.state / "history.jsonl", "update.finalization_health_failed", sequence=transaction["sequence"])
                raise Refused("Maintenance remains active because current runtime health verification failed") from exc
            return self._finalize(transaction, stage)

    def install(self, manifest: Path, signature: Path, bundle: Path, public_key: Path) -> dict:
        require_linux_root()
        trusted_file(public_key)
        with locked(self.state.parent / "transaction.lock"), locked(self.state / "transaction.lock"):
            livepatch.require_settled(self.state)
            enrolled_key(self.state, public_key)
            status = self.status()
            if status["maintenance_release_pending"]:
                raise Refused("Complete pending maintenance release with nebulalog update finalize before another update")
            os_transaction = status["os_transaction"]
            if os_maintenance_pending(os_transaction):
                raise Refused("OS maintenance or reboot recovery must finish before a component update")
            if status["transaction"] and status["transaction"].get("state") not in ("committed", "rolled_back", "preflight_failed"):
                raise Refused("An interrupted or failed update requires recovery before another install")
            current = status["current"]
            release = verify_release(manifest, signature, public_key, bundle,
                                     current_sequence=current["sequence"],
                                     current_versions={k:v["version"] for k,v in current["components"].items()}, runner=self.runner)
            host_update = "host" in release["components"]
            if "host" in current["components"] and not host_update:
                raise Refused("Host-enrolled appliances require a combined release with a versioned host bundle; OCI-only updates lack authorized integrity acceptance")
            if host_update:
                previous_host = current["components"].get("host")
                if (self.state != host_dispatch.STATE or not isinstance(previous_host, dict)
                        or any(previous_host.get(key) != value for key, value in host_dispatch.generation_info(previous_host.get("generation")).items())
                        or host_activation.selection() != {"schema": 1, "generation": previous_host["generation"], "sequence": current["sequence"]}):
                    raise Refused("Host update requires the factory-enrolled current immutable generation")
            if any(not c["rollback_safe"] for c in release["components"].values()):
                raise Refused("Controlled migration release requires an approved database-specific recovery procedure")
            if shutil.disk_usage(self.state.parent).free < release["verified_bytes"] * 3 + 1024**3:
                raise Refused("Insufficient staging/backup reserve")
            # Check every adapter before changing any component.
            if not host_update:
                for hook in ("update-preflight", "update-backup", "update-prepare", "update-activate", "update-health", "update-rollback", "update-finalize"):
                    trusted_file(self.hooks / hook)
            releases = self.state / "releases"
            releases.mkdir(parents=True, exist_ok=True, mode=0o700)
            stage = Path(tempfile.mkdtemp(prefix=str(release["sequence"])+"-", dir=releases))
            for item in release["artifacts"]:
                shutil.copyfile(bundle / item["name"], stage / item["name"])
                os.chmod(stage / item["name"], 0o600)
            shutil.copyfile(manifest, stage / "manifest.json")
            shutil.copyfile(signature, stage / "manifest.sig")
            # Validate copies before invoking any adapters; they only consume this root-owned directory.
            verify_release(stage / "manifest.json", stage / "manifest.sig", public_key, stage,
                           current_sequence=current["sequence"], runner=self.runner)
            transaction = {"state": "preflight", "sequence": release["sequence"], "previous": current,
                           "release": str(stage), "manifest_sha256": release["manifest_sha256"],
                           "activation_started": False}
            if host_update:
                transaction["host_update"] = True
            def record(state):
                transaction["state"] = state
                atomic_json(self.state / "transaction.json", transaction)
                audit(self.state / "history.jsonl", "update."+state, sequence=release["sequence"])
            record("preflight")
            try:
                if host_update:
                    transaction["host_coordinator"] = host_dispatch.coordinator_pin(stage)
                    atomic_json(self.state / "transaction.json", transaction)
                    candidate, artifact = host_activation._candidate_identity(release)
                    host_payload.stage_generation(stage / artifact["name"], expected_sha256=candidate["generation"],
                                                  expected_host_source_sha256=candidate["host_source_sha256"])
                self._hook("update-preflight", stage)
                backup = self._hook("update-backup", stage)
                if not backup.get("postgresql") or not backup.get("configuration"):
                    raise Refused("Verified PostgreSQL and configuration backups are mandatory")
            except Exception:
                # A failed backup may also fail to restart writers. Its durable
                # gate is authoritative even if the hook was killed before a receipt.
                if host_update:
                    self._retain_host_refusal(transaction, stage)
                record("recovery_required" if (self.state.parent / "maintenance.json").exists() else "preflight_failed")
                raise
            try:
                record("preparing")
                if host_update:
                    host_activation.prepare(stage)
                self._hook("update-prepare", stage)
                # This is durable before selecting candidate host code or
                # allowing an adapter to mutate runtime files/databases.
                transaction["activation_started"] = True
                record("activating")
                if host_update:
                    host_activation.select_candidate(stage)
                self._hook("update-activate", stage)
                record("checking")
                health = self._hook("update-health", stage)
                if not REQUIRED_CHECKS <= set(health.get("checks", {})) or any(health["checks"].get(k) is not True for k in REQUIRED_CHECKS):
                    raise Refused("Post-update health/security acceptance failed")
                versions = {**current["components"], **release["components"]}
                if host_update:
                    versions["host"] = candidate
                self._advance_host_sequence(transaction, stage)
                atomic_json(self.state / "current.json", {"sequence": release["sequence"], "version": release["version"],
                                                         "components": versions, "release": str(stage)})
                record("committed")
            except Exception:
                record("rolling_back")
                try:
                    self._restore_host(transaction, stage)
                    self._hook("update-rollback", stage)
                    restored = self._hook("update-health", stage)
                    if not REQUIRED_CHECKS <= set(restored.get("checks", {})) or any(restored["checks"].get(k) is not True for k in REQUIRED_CHECKS):
                        raise Refused("Rollback health checks failed")
                    # High-water sequence remains advanced after rollback, preventing replay.
                    self._advance_host_sequence(transaction, stage)
                    atomic_json(self.state / "current.json", {**current, "sequence": release["sequence"]})
                    record("rolled_back")
                except Exception:
                    record("recovery_required")
                    raise Refused("Update and rollback failed; appliance recovery is required")
                self._finalize(transaction, stage)
                raise Refused("Update failed; previous application restored and checked")
            # Keep finalization outside the activation exception handler: failure
            # here must preserve the newly committed component/database state.
            return self._finalize(transaction, stage)


    def rollback(self, public_key: Path) -> dict:
        """Roll back the last committed reversible release using retained evidence."""
        require_linux_root()
        trusted_file(public_key)
        with locked(self.state.parent / "transaction.lock"), locked(self.state / "transaction.lock"):
            livepatch.require_settled(self.state)
            enrolled_key(self.state, public_key)
            status = self.status()
            if status["maintenance_release_pending"]:
                raise Refused("Finalize the completed transaction before requesting operator rollback")
            if os_maintenance_pending(status["os_transaction"]):
                raise Refused("OS recovery must finish before component rollback")
            transaction = status["transaction"]
            if not transaction or transaction.get("state") != "committed" or not transaction.get("previous"):
                raise Refused("No last committed reversible transaction is available")
            stage, release = self._retained_release(transaction, public_key)
            if any(not c["rollback_safe"] for c in release["components"].values()):
                raise Refused("Release does not permit this rollback")
            transaction["state"] = "rolling_back"
            transaction["finalization"] = "pending"
            atomic_json(self.state / "transaction.json", transaction)
            audit(self.state / "history.jsonl", "update.operator_rollback", sequence=release["sequence"])
            try:
                self._restore_host(transaction, stage)
                self._hook("update-rollback", stage)
                health = self._hook("update-health", stage)
                if not REQUIRED_CHECKS <= set(health.get("checks", {})) or any(health["checks"].get(k) is not True for k in REQUIRED_CHECKS):
                    raise Refused("Rollback health checks failed")
                restored = {**transaction["previous"], "sequence": status["current"]["sequence"]}
                self._advance_host_sequence(transaction, stage)
                atomic_json(self.state / "current.json", restored)
                transaction["state"] = "rolled_back"
                atomic_json(self.state / "transaction.json", transaction)
                audit(self.state / "history.jsonl", "update.rolled_back", sequence=release["sequence"])
            except Exception:
                transaction["state"] = "recovery_required"
                atomic_json(self.state / "transaction.json", transaction)
                audit(self.state / "history.jsonl", "update.recovery_required", sequence=release["sequence"])
                raise
            return self._finalize(transaction, stage)

    def recover(self, public_key: Path) -> dict:
        """Restore an interrupted transaction through its retained old coordinator.

        Completed transactions use finalize() instead: recovery never silently
        reverses a committed database/application state. Expiry cannot strand an
        already staged recovery, but retained signature and journal identity bind.
        """
        require_linux_root()
        trusted_file(public_key)
        with locked(self.state.parent / "transaction.lock"), locked(self.state / "transaction.lock"):
            livepatch.require_settled(self.state)
            enrolled_key(self.state, public_key)
            status = self.status()
            transaction = status["transaction"]
            if not transaction or transaction.get("state") not in {"preflight", "preparing", "activating", "checking", "rolling_back", "recovery_required"}:
                raise Refused("No interrupted component transaction is available for recovery")
            os_transaction = status["os_transaction"]
            if os_maintenance_pending(os_transaction):
                raise Refused("OS recovery must finish before component recovery")
            stage, _ = self._retained_release(transaction, public_key, recovery=True)
            intent = stage / "adapter-backup-intent.json"
            if transaction.get("activation_started") is False and not os.path.lexists(intent):
                # A crash before preflight finished has not authorized backup,
                # service stops or candidate selection. Recheck only the fixed
                # preflight while its original phase/selection remain durable.
                # Never manufacture a snapshot after any possible runtime effect.
                forbidden = ("recovery", "prepared-quadlets", "host-runtime", "host-activation.json",
                    "adapter-backup.json", "adapter-backup-inventory.json", "adapter-backup-recovery.json",
                    "adapter-storage-maintenance.json", "adapter-prepare.json", "adapter-activate.json",
                    "adapter-application-schema-intent.json", "adapter-database-restore-intent.json")
                gate = self.state.parent / "storage-maintenance/gate.json"
                idle = {"schema": 1, "held": False, "delivery_held": False, "operation": None}
                observed_gate = json.loads(trusted_file(gate).read_text()) if os.path.lexists(gate) else idle
                gate_idle = (isinstance(observed_gate, dict) and observed_gate == idle
                    and type(observed_gate["schema"]) is int and observed_gate["held"] is False
                    and observed_gate["delivery_held"] is False)
                if (transaction.get("state") != "preflight"
                        or os.path.lexists(self.state.parent / "maintenance.json")
                        or any(os.path.lexists(stage / name) for name in forbidden)
                        or not gate_idle):
                    raise Refused("Missing preactivation proof cannot authorize recovery after possible runtime effects")
                self._hook("update-preflight", stage)
                trusted_file(intent)
            transaction["state"] = "rolling_back"
            transaction["finalization"] = "pending"
            atomic_json(self.state / "transaction.json", transaction)
            try:
                self._restore_host(transaction, stage)
                self._hook("update-rollback", stage)
                health = self._hook("update-health", stage)
                if not REQUIRED_CHECKS <= set(health.get("checks", {})) or any(health["checks"].get(key) is not True for key in REQUIRED_CHECKS):
                    raise Refused("Recovered runtime acceptance failed")
                self._advance_host_sequence(transaction, stage)
                atomic_json(self.state / "current.json", {**transaction["previous"], "sequence": transaction["sequence"]})
                transaction["state"] = "rolled_back"
                atomic_json(self.state / "transaction.json", transaction)
                audit(self.state / "history.jsonl", "update.recovered", sequence=transaction["sequence"])
            except Exception:
                transaction["state"] = "recovery_required"
                atomic_json(self.state / "transaction.json", transaction)
                audit(self.state / "history.jsonl", "update.recovery_required", sequence=transaction["sequence"])
                raise
            return self._finalize(transaction, stage)
