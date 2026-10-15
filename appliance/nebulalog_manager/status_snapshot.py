"""Publish bounded, allowlisted host observations; never expose private journals."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from . import baseline, github_updates, host_payload, security, storage, updates
from .common import CommandFailed, Refused, require_linux_root, run, trusted_file

CONFIGURATION = Path("/var/lib/nebulalog/configuration")
STATE = Path("/var/lib/nebulalog/manager")
OUTPUT = Path("/run/nebulalog-status/status.json")
TRANSACTIONS = {"preflight", "preflight_failed", "preparing", "activating", "checking", "committed", "rolling_back", "rolled_back", "recovery_required", "updating", "postcheck", "failed", "complete", "reboot_preparing", "reboot_requested", "reboot_aborted"}
HISTORY = {"update." + action for action in TRANSACTIONS | {"operator_rollback", "finalized", "finalization_failed", "finalization_health_failed", "recovered"}}
HISTORY |= {"os." + action for action in TRANSACTIONS | {"reboot_health_failed", "reboot_verified"}}


def read_json(path):
    trusted_file(path)
    if path.stat().st_size > 1024 * 1024:
        raise Refused("Oversized private status source")
    with path.open("rb") as source:
        data = source.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise Refused("Private status source grew while being read")
    return json.loads(data)


def timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return ""
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return observed.astimezone(timezone.utc).isoformat() if observed.tzinfo else ""
    except ValueError:
        return ""


def integer(value):
    return value if type(value) is int and 0 <= value <= 2**53 else 0


def host_refusal(transaction):
    value = transaction.get("host_refusal")
    if value is None:
        return None
    if (not isinstance(value, dict) or set(value) != {"schema", "reason", "resource", "sequence", "manifest_sha256"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["reason"] != "qualified_migration_required"
            or not isinstance(value["resource"], str) or value["resource"] not in host_payload.CATALOG_BY_PATH
            or type(value["sequence"]) is not int or not 0 < value["sequence"] <= 2**53
            or value["sequence"] != transaction.get("sequence")
            or not isinstance(value["manifest_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["manifest_sha256"])
            or value["manifest_sha256"] != transaction.get("manifest_sha256")):
        raise Refused("Invalid retained host refusal")
    return {key: value[key] for key in ("reason", "resource", "sequence")}


def history(paths):
    result = []
    for path in paths:
        if not path.exists():
            continue
        trusted_file(path)
        with path.open("rb") as source:
            size = source.seek(0, os.SEEK_END)
            source.seek(max(0, size - 32768))
            if size > 32768:
                source.readline(32768)
            lines = source.read(32768).splitlines()
        for line in lines:
            try:
                value = json.loads(line)
                if not isinstance(value, dict) or value.get("action") not in HISTORY:
                    continue
                stamp = timestamp(value.get("timestamp"))
                if stamp:
                    result.append({"timestamp": stamp, "action": value["action"], "sequence": integer(value.get("sequence"))})
            except (ValueError, UnicodeError):
                continue
    return sorted(result, key=lambda item: item["timestamp"])[-20:]


class Collector:
    def __init__(self, *, configuration=CONFIGURATION, state=STATE,
                 identity=Path("/etc/nebulalog/storage.json"), runner=run,
                 maintenance=Path("/etc/nebulalog/maintenance.json"),
                 github_policy=github_updates.CONFIG,
                 host=security.status, inspect=storage.inspect, baseline_factory=baseline.Baseline,
                 update_factory=updates.UpdateManager, clock=lambda: datetime.now(timezone.utc)):
        self.configuration, self.state, self.identity = configuration, state, identity
        self.maintenance = maintenance
        self.github_policy = github_policy
        self.runner, self.host, self.inspect = runner, host, inspect
        self.baseline_factory, self.update_factory, self.clock = baseline_factory, update_factory, clock
        self.deadline = None

    def command(self, argv, **kwargs):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Refused("Status collection deadline exceeded")
        kwargs["timeout"] = min(5, remaining, kwargs.get("timeout", 5))
        value = self.runner(argv, **kwargs)
        if len(value) > 1024 * 1024:
            raise Refused("Oversized status command result")
        return value

    def collect(self):
        self.deadline = time.monotonic() + 35
        result = {"schema": 1, "observed_at": self.clock().isoformat()}
        for name, operation in (("security", self.security), ("storage", self.storage),
                                ("baseline", self.baseline), ("updates", self.updates)):
            try:
                result[name] = operation()
            except (OSError, Refused, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                result[name] = {"status": "unavailable"}
        return result

    def security(self):
        value = self.host(self.command)
        crypto_status = value.get("kernel_crypto_diagnostics", {}).get("status")
        if crypto_status not in {"no_failure_observed", "failed", "unavailable"}:
            crypto_status = "unavailable"
        def observed(name, allowed):
            probe = value.get(name, {})
            return probe.get("value") if probe.get("ok") is True and probe.get("value") in allowed else "unavailable"
        return {"status": "observed", "fips_kernel": value.get("fips_kernel") is True,
                "fips_tool_passed": value.get("fips_tool", {}).get("ok") is True,
                "module_signatures_enforced": value.get("module_signatures_enforced") is True,
                "crypto_policy": observed("crypto_policy", {"FIPS", "DEFAULT", "LEGACY", "FUTURE"}),
                "selinux": observed("selinux", {"Enforcing", "Permissive", "Disabled"}),
                "firewall": observed("firewalld", {"active", "inactive", "failed"}),
                "audit": observed("auditd", {"active", "inactive", "failed"}),
                "kernel_crypto_status": crypto_status,
                "host_controls_ok": value.get("host_controls_ok") is True and crypto_status == "no_failure_observed"}

    def storage(self):
        identity = storage.Identity(**read_json(self.identity))
        observed = self.inspect(identity, self.command)
        observed.validate()
        plan = storage.growth_plan(observed)
        # Do not publish paths, serials or plan fingerprints in the general
        # status feed. This observation cannot authorize a growth operation.
        result = {"status": "observed", "luks2_verified": observed.luks_version == 2,
                "filesystem": observed.filesystem, "capacity_bytes": observed.filesystem_bytes,
                "vg_free_bytes": observed.vg_free_bytes, "encrypted_members": 1 + len(identity.additional_pvs),
                "growth": {"presented_disk_bytes": observed.disk_bytes,
                           "unallocated_disk_bytes": plan["unallocated_disk_bytes"],
                           "required_stages": plan["stages"],
                           "expansion_needed": bool(plan["stages"])}}
        if observed.filesystem_geometry_bytes is not None:
            result.update(filesystem_geometry_bytes=observed.filesystem_geometry_bytes, logical_volume_bytes=observed.lv_bytes)
        return result

    def baseline(self):
        setup = read_json(self.configuration / "bootstrap/setup.json")
        selected = setup.get("baseline")
        if selected not in security.BASELINES:
            raise Refused("Unknown selected baseline")
        value = self.baseline_factory(self.configuration, runner=self.command).status(setup["installation_id"], selected)
        counts = {}
        for assessment in value.get("assessments", []):
            for outcome, count in assessment.get("counts", {}).items():
                if outcome in baseline.RESULTS:
                    counts[outcome] = counts.get(outcome, 0) + integer(count)
        return {"status": "observed", "selected": selected, "assessed": value.get("baseline_assessed") is True,
                "review_complete": value.get("baseline_review_complete") is True,
                "last_assessment": timestamp(value.get("last_assessment")),
                "review_expires_at": timestamp(value.get("review_expires_at")), "counts": counts}

    def github_channel(self, enrollment):
        if not self.github_policy.exists():
            return {"status": "not_connected", "automatic_updates": False}
        policy = read_json(self.github_policy)
        repository = policy.get("repository")
        if (policy.get("schema") != 1 or not isinstance(repository, str) or not github_updates.REPOSITORY.fullmatch(repository)
                or type(policy.get("automatic_updates")) is not bool or policy.get("poll_interval_seconds") != github_updates.POLL_SECONDS):
            raise Refused("Invalid GitHub update observation policy")
        def enabled(command, expected):
            try:
                return self.command(command).strip() == expected
            except CommandFailed:
                return False
        channel = {"repository": repository, "status": "awaiting_first_check", "automatic_updates": False,
                   "configured": policy["automatic_updates"], "poll_interval_seconds": github_updates.POLL_SECONDS,
                   "timer_enabled": enabled(["systemctl", "is-enabled", "nebulalog-app-update.timer"], "enabled"),
                   "timer_active": enabled(["systemctl", "is-active", "nebulalog-app-update.timer"], "active"),
                   "publisher_enrolled": enrollment.get("update_ready") is True, "fresh": False,
                   "checked_at": "", "next_check_at": ""}
        path = self.state / "updates/github-status.json"
        if path.exists():
            record = read_json(path)
            stamp = timestamp(record.get("checked_at"))
            if (record.get("schema") != 1 or record.get("repository") != repository or record.get("status") not in github_updates.STATES
                    or record.get("automatic_updates") != policy["automatic_updates"] or not stamp):
                raise Refused("GitHub observation differs from the installed policy")
            age = (self.clock() - datetime.fromisoformat(stamp)).total_seconds()
            channel.update(status=record["status"], checked_at=stamp, next_check_at=timestamp(record.get("next_check_at")), fresh=-5 <= age <= 1860)
            if not channel["fresh"]:
                channel["status"] = "stale"
        if not channel["configured"] or not channel["timer_enabled"] or not channel["timer_active"]:
            channel["status"] = "disabled"
        elif not channel["publisher_enrolled"]:
            channel["status"] = "awaiting_enrollment"
        channel["automatic_updates"] = bool(channel["configured"] and channel["timer_enabled"] and channel["timer_active"]
                and channel["publisher_enrolled"] and channel["fresh"] and channel["status"] in
                {"checking", "no_release", "up_to_date", "downloading", "installing", "installed"})
        return channel

    def updates(self):
        for name in ("updates/current.json", "updates/transaction.json", "os-transaction.json"):
            if (self.state / name).exists():
                read_json(self.state / name)
        value = self.update_factory(self.state / "updates").status()
        current, transaction, os_transaction = value["current"], value.get("transaction") or {}, value.get("os_transaction") or {}
        components = {}
        for name, change in current.get("components", {}).items():
            version = change.get("version", "")
            if name in updates.COMPONENTS and isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,79}", version):
                components[name] = version
        try:
            timer = self.command(["systemctl", "is-enabled", "nebulalog-os-update.timer"])
        except CommandFailed as exc:
            timer = "disabled" if exc.returncode == 1 else "unavailable"
        if timer not in {"enabled", "disabled", "masked", "static"}:
            timer = "unavailable"
        try:
            policy = read_json(self.maintenance)
            configured = policy.get("automatic_os_updates") is True
        except FileNotFoundError:
            configured = False
        marker = self.state / "maintenance.json"
        maintenance_active = read_json(marker).get("active") is True if marker.exists() else False
        os_blocks_recovery = updates.os_maintenance_pending(os_transaction)
        recovery_action = "nebulalog update finalize" if value.get("maintenance_release_pending") is True and not os_blocks_recovery else ""
        if (os_transaction.get("kernel_rollback") in {"pending", "failed"}
                or os_transaction.get("kernel_finalization") == "recovery_required"
                and os_transaction.get("kernel_outcome") == "recovery"
                and os_transaction.get("kernel_retry") != "requested"):
            recovery_action = "nebulalog update kernel-rollback"
        elif (os_transaction.get("kernel_finalization") in {"pending", "failed"}
                or os_transaction.get("kernel_retention") in {"pending", "failed"}):
            recovery_action = "nebulalog update reboot-complete"
        if not recovery_action and os_transaction.get("recovery_phase") == "postcheck" and (os_transaction.get("state") == "recovery_required" or
                os_transaction.get("state") == "complete" and os_transaction.get("finalization") in {"pending", "failed"}):
            recovery_action = "nebulalog update os-recover"
        if not recovery_action and os_transaction.get("boot_id") and (os_transaction.get("state") in {"reboot_requested", "recovery_required"} or os_transaction.get("state") == "complete" and os_transaction.get("finalization") in {"failed", "pending"}):
            recovery_action = "nebulalog update reboot-complete"
        if not recovery_action and not os_blocks_recovery and transaction.get("state") in {
                "preflight", "preparing", "activating", "checking", "rolling_back", "recovery_required"}:
            recovery_action = "nebulalog update recover"
        try:
            channel = self.github_channel(value.get("enrollment") or {})
        except Exception:
            channel = {"status": "unavailable", "automatic_updates": False}
        if channel["automatic_updates"] and (maintenance_active or value.get("maintenance_release_pending") or
                transaction.get("state", "committed") not in {"committed", "rolled_back", "preflight_failed"} or
                os_blocks_recovery):
            channel.update(status="blocked", automatic_updates=False)
        return {"status": "observed", "current_sequence": integer(current.get("sequence")), "components": components,
                "github": channel,
                "transaction": transaction.get("state") if transaction.get("state") in TRANSACTIONS else "none",
                "transaction_sequence": integer(transaction.get("sequence")),
                "finalization": transaction.get("finalization") if transaction.get("finalization") in {"pending", "failed", "complete"} else "none",
                "maintenance_release_pending": value.get("maintenance_release_pending") is True,
                "maintenance_active": maintenance_active, "recovery_action": recovery_action,
                "host_refusal": host_refusal(transaction),
                "os_transaction": os_transaction.get("state") if os_transaction.get("state") in TRANSACTIONS else "none",
                "os_finalization": os_transaction.get("finalization") if os_transaction.get("finalization") in {"pending", "failed", "complete"} else "none",
                "reboot_pending": os_transaction.get("reboot_pending") is True or os_transaction.get("state") == "reboot_requested",
                "os_updates_configured": configured, "os_timer_enabled": timer == "enabled", "os_timer_status": timer,
                "history": history((self.state / "updates/history.jsonl", self.state / "audit.jsonl"))}


def public_directory(directory):
    directory.mkdir(mode=0o755, exist_ok=True)
    for parent in (directory, *directory.parents):
        info = parent.lstat()
        if parent.is_symlink() or not parent.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused("Public status directory is not root-controlled")


def publish(value, path=OUTPUT, *, runner=run):
    # Dedicated container-readable directory; keep Apache maintenance labels separate.
    public_directory(path.parent)
    if path.is_symlink():
        raise Refused("Refusing a symlink status target")
    os.chmod(path.parent, 0o755)
    runner(["restorecon", str(path.parent)])
    data = (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()
    if len(data) > 64 * 1024:
        raise Refused("Public status exceeds the schema limit")
    fd, temporary = tempfile.mkstemp(prefix=".status-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o644)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        # Label the new inode before publishing it. A replacement must not
        # briefly become unreadable to the API or inherit Apache's marker type.
        runner(["restorecon", temporary])
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    try:
        require_linux_root()
        os.umask(0o077)
        publish(Collector().collect())
        return 0
    except Exception:
        # Existing observations naturally expire if collection/publication fails.
        print("Host status publication failed; no fresh observation is available.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
