"""Maintenance-window OS updates. Application/database images remain release-pinned."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from .common import CommandFailed, Refused, atomic_json, audit, locked, require_linux_root, run, trusted_file
from .security import status
from . import os_payload, livepatch
from .updates import REQUIRED_CHECKS, in_maintenance_window, os_maintenance_pending


def _hook(name, runner, *, timeout=3600):
    path = trusted_file(Path("/usr/libexec/nebulalog") / name)
    result = json.loads(runner([str(path)], timeout=timeout))
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise Refused("OS lifecycle adapter did not report success")
    return result


def _runtime_postcheck(runner, stage):
    result = _hook("update-os-postcheck", runner)
    if result.get("stage") != stage or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS):
        raise Refused("OS update requires operation-bound runtime and security acceptance")
    return result


def _reboot_required(runner):
    try:
        runner(["dnf", "needs-restarting", "--reboothint"], timeout=120)
    except CommandFailed as exc:
        if exc.returncode != 1:
            raise Refused("Cannot determine whether a reboot is required") from exc
        return True
    return False


def maintain(config: Path, state: Path=Path("/var/lib/nebulalog/manager"), runner=run, now=None):
    require_linux_root()
    policy=json.loads(trusted_file(config).read_text())
    now=now or datetime.now(timezone.utc)
    if policy.get("automatic_os_updates") is not True:
        return {"status":"disabled"}
    if not in_maintenance_window(now,weekday=policy.get("weekday",6),start=policy.get("start","03:00"),end=policy.get("end","05:00"),zone=policy["timezone"]):
        return {"status":"outside_maintenance_window"}
    with locked(state/"transaction.lock"), locked(state/"updates/transaction.lock"):
        livepatch.require_settled(state / "updates")
        journal = state / "os-transaction.json"
        previous = json.loads(journal.read_text()) if journal.exists() else None
        if os_maintenance_pending(previous):
            raise Refused("An interrupted OS transaction or pending reboot requires recovery before another update")
        component_record = state / "updates/transaction.json"
        if component_record.exists():
            component = json.loads(component_record.read_text())
            if component.get("state") not in ("preflight_failed", "committed", "rolled_back") or (component.get("state") in ("committed", "rolled_back") and component.get("finalization") != "complete"):
                raise Refused("Component maintenance must finish before OS maintenance")
        transaction = {"state": "preflight", "started_at": datetime.now(timezone.utc).isoformat()}
        if previous and previous.get("reboot_pending") is True:
            # Planning/network failures must not erase an earlier deferred reboot.
            transaction.update(reboot_pending=True, prior_reboot_stage=previous.get("stage"))
        def record(value, **details):
            transaction.update(state=value, **details)
            atomic_json(journal, transaction)
            audit(state / "audit.jsonl", "os." + value, **details)
        if not status(runner)["host_controls_ok"]:
            raise Refused("OS updates require healthy FIPS, SELinux, firewall and auditing controls")
        for name in ("update-os-preflight", "update-os-postcheck", "update-reboot-prepare", "update-reboot-abort"):
            trusted_file(Path("/usr/libexec/nebulalog") / name)
        # The image enforces gpgcheck and repository allowlisting. Never enable a
        # repository or alter trust as part of the update transaction.
        record("preflight")
        try:
            backup = _hook("update-os-preflight", runner)
            if backup.get("postgresql") is not True or backup.get("configuration") is not True:
                raise Refused("OS maintenance requires verified metadata and configuration backups")
            stage = backup.get("stage")
            if not isinstance(stage, str) or not Path(stage).is_absolute():
                raise Refused("OS maintenance requires an operation-owned backup stage")
            boot_id = backup.get("boot_id")
            if not isinstance(boot_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
                raise Refused("OS maintenance requires the backup boot identity")
            record("planning", stage=stage, boot_id=boot_id)
            plan = os_payload.prepare(Path(stage), policy, runner=runner)
            candidate_reboot = plan.get("reboot_required") is True
            if candidate_reboot:
                record("planning", reboot_pending=True, kernel_reboot_required=True)
            no_updates = plan.get("status") == "no_updates"
            if no_updates:
                record("planning", no_updates=True, plan_sha256=None)
                reboot = _reboot_required(runner)
                if not reboot and transaction.get("reboot_pending") is not True:
                    record("complete", status="no_updates", reboot_pending=False)
                    return {"status": "no_updates", "reboot_pending": False}
                # A prior update can still require a reboot after DNF has no new
                # packages. Use this run's fresh backup and full acceptance; do
                # not replay the earlier RPM installation or its stale backup.
                record("postcheck", reboot_pending=reboot or transaction.get("reboot_pending") is True)
            else:
                record("updating", plan_sha256=plan["plan_sha256"])
                os_payload.apply(Path(stage), runner=runner)
                record("postcheck")
            if not status(runner)["host_controls_ok"]:
                raise Refused("OS update security postcondition failed; reboot blocked")
            accepted = _runtime_postcheck(runner, stage)
            record("postcheck", health=accepted["checks"])
            reboot = _reboot_required(runner) or candidate_reboot
            record("postcheck", reboot_pending=reboot)
        except Exception as exc:
            record("recovery_required" if transaction["state"] in ("updating", "postcheck") or (state / "maintenance.json").exists() else "failed",
                   recovery_phase=transaction["state"], error=type(exc).__name__)
            raise
        # Re-evaluate actual current time after a potentially long update.
        within=in_maintenance_window(datetime.now(timezone.utc),weekday=policy.get("weekday",6),start=policy.get("start","03:00"),end=policy.get("end","05:00"),zone=policy["timezone"])
        if reboot and within:
            record("reboot_preparing")
            try:
                prepared = _hook("update-reboot-prepare", runner)
                if not prepared.get("boot_id"):
                    raise Refused("Reboot preparation did not record the current boot identity")
            except Exception as exc:
                if not (state / "maintenance.json").exists():
                    # Preparation can stop and restart services before refusing.
                    # Recheck the current runtime instead of reusing its earlier proof.
                    record("postcheck", reboot_pending=True)
                    try:
                        accepted = _runtime_postcheck(runner, stage)
                    except Exception as postcheck_error:
                        record("recovery_required", recovery_phase="postcheck", error=type(postcheck_error).__name__)
                        raise Refused("Reboot preparation failed and current runtime acceptance requires recovery") from postcheck_error
                    record("complete", status="no_updates" if no_updates else "updated", reboot_pending=True, reboot_blocked=type(exc).__name__)
                    raise Refused("OS maintenance passed; reboot remains pending because unlock or preparation requirements were not met") from exc
                record("recovery_required", recovery_phase="reboot_preparing", error=type(exc).__name__)
                raise Refused("Reboot preparation failed; review appliance service and unlock state") from exc
            record("reboot_requested", boot_id=prepared["boot_id"])
            try:
                runner(["systemctl","reboot"], timeout=120)
            except Exception as exc:
                try:
                    recovered = _hook("update-reboot-abort", runner)
                    if recovered.get("recovered") is not True or any(recovered.get("health", {}).get(name) is not True for name in REQUIRED_CHECKS):
                        raise Refused("Reboot abort did not provide verified service/authentication recovery")
                    record("reboot_aborted", reboot_pending=True)
                except Exception as recovery_error:
                    record("recovery_required", error=type(recovery_error).__name__)
                    raise Refused("Reboot request failed and service recovery failed; maintenance remains active") from recovery_error
                raise Refused("Reboot request failed; appliance services and local authentication were restored and verified") from exc
            return {"status":"reboot_requested"}
        result={"status":"no_updates" if no_updates else "updated","reboot_pending":reboot}
        record("complete", **result)
        return result

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config",type=Path,default=Path("/etc/nebulalog/maintenance.json"))
    a=p.parse_args()
    try:print(json.dumps(maintain(a.config)))
    except (Refused,OSError,ValueError) as exc:raise SystemExit(str(exc))
