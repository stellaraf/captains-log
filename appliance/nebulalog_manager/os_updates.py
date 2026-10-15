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


def _runtime_postcheck(runner, stage, boot_id):
    result = _hook("update-os-postcheck", runner)
    if (result.get("stage") != stage or result.get("boot_id") != boot_id
            or any(result.get("checks", {}).get(name) is not True for name in REQUIRED_CHECKS)):
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
        resume = bool(previous and previous.get("storage_maintenance") == "held"
            and previous.get("state") in {"complete", "reboot_aborted"}
            and previous.get("finalization") == "complete" and previous.get("reboot_pending") is True
            and all(previous.get(field, "complete") in (None, "complete")
                    for field in ("kernel_finalization", "kernel_retention", "kernel_rollback")))
        if os_maintenance_pending(previous) and not resume:
            raise Refused("An interrupted OS transaction or pending reboot requires recovery before another update")
        component_record = state / "updates/transaction.json"
        if component_record.exists():
            component = json.loads(component_record.read_text())
            if component.get("state") not in ("preflight_failed", "committed", "rolled_back") or (component.get("state") in ("committed", "rolled_back") and component.get("finalization") != "complete"):
                raise Refused("Component maintenance must finish before OS maintenance")
        transaction = dict(previous) if resume else {"state": "preflight", "payload_started": False,
                                                     "started_at": datetime.now(timezone.utc).isoformat()}
        if previous and previous.get("reboot_pending") is True and not resume:
            # Planning/network failures must not erase an earlier deferred reboot.
            transaction.update(reboot_pending=True, prior_reboot_stage=previous.get("stage"))
        def record(value, **details):
            transaction.update(state=value, **details)
            atomic_json(journal, transaction)
            audit(state / "audit.jsonl", "os." + value, **details)
        def refresh():
            # Adapters own durable backup references and finalization. Preserve
            # their operation state across the subprocess boundary.
            retained = json.loads(trusted_file(journal).read_text())
            if transaction.get("stage") is not None and retained.get("stage") != transaction["stage"]:
                raise Refused("OS adapter changed the owning operation")
            transaction.update(retained)
        def finalize(**details):
            record("complete", finalization="pending", recovery_phase="postcheck", **details)
            try:
                result = _runtime_postcheck(runner, transaction["stage"], transaction["boot_id"])
                if result.get("finalized") is not True or type(result.get("storage_released")) is not bool:
                    raise Refused("OS adapter did not explicitly finalize storage maintenance")
                refresh()
                if (transaction.get("state") != "complete" or transaction.get("finalization") != "complete"
                        or transaction.get("storage_maintenance") != ("released" if result["storage_released"] else "held")):
                    raise Refused("OS finalization acknowledgement has no matching durable disposition")
            except Exception as exc:
                refresh()
                record("complete", finalization="failed", finalization_error=type(exc).__name__)
                raise
            return {"status": transaction["status"], "reboot_pending": transaction["reboot_pending"]}
        if not status(runner)["host_controls_ok"]:
            raise Refused("OS updates require healthy FIPS, SELinux, firewall and auditing controls")
        for name in ("update-os-preflight", "update-os-postcheck", "update-reboot-prepare", "update-reboot-abort"):
            trusted_file(Path("/usr/libexec/nebulalog") / name)
        # The image enforces gpgcheck and repository allowlisting. Never enable a
        # repository or alter trust as part of the update transaction.
        if resume:
            record("postcheck", finalization="pending", resuming_deferred=True)
        else:
            record("preflight")
        try:
            if resume:
                stage, boot_id = transaction["stage"], transaction["boot_id"]
                no_updates = transaction.get("no_updates") is True
                candidate_reboot = transaction.get("kernel_reboot_required") is True
            else:
                backup = _hook("update-os-preflight", runner)
                refresh()
                if backup.get("postgresql") is not True or backup.get("configuration") is not True:
                    raise Refused("OS maintenance requires verified metadata and configuration backups")
                stage = backup.get("stage")
                if not isinstance(stage, str) or not Path(stage).is_absolute():
                    raise Refused("OS maintenance requires an operation-owned backup stage")
                boot_id = backup.get("boot_id")
                if not isinstance(boot_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
                    raise Refused("OS maintenance requires the backup boot identity")
                if transaction.get("stage") not in (None, stage) or transaction.get("boot_id") not in (None, boot_id):
                    raise Refused("OS backup acknowledgement belongs to another operation")
                record("planning", stage=stage, boot_id=boot_id, storage_maintenance="held", finalization="pending")
                plan = os_payload.prepare(Path(stage), policy, runner=runner)
                candidate_reboot = plan.get("reboot_required") is True
                if candidate_reboot:
                    record("planning", reboot_pending=True, kernel_reboot_required=True)
                no_updates = plan.get("status") == "no_updates"
                if no_updates:
                    record("postcheck", no_updates=True, plan_sha256=None)
                else:
                    record("updating", plan_sha256=plan["plan_sha256"], payload_started=True)
                    os_payload.apply(Path(stage), runner=runner)
                    record("postcheck")
            if not status(runner)["host_controls_ok"]:
                raise Refused("OS update security postcondition failed; reboot blocked")
            accepted = _runtime_postcheck(runner, stage, boot_id)
            refresh()
            record("postcheck", health=accepted["checks"], health_boot_id=boot_id)
            reboot = _reboot_required(runner) or candidate_reboot
            record("postcheck", reboot_pending=reboot)
        except Exception as exc:
            refresh()
            record("recovery_required" if transaction.get("stage") is not None or (state / "maintenance.json").exists() else "failed",
                   recovery_phase=transaction["state"], error=type(exc).__name__)
            raise
        # Re-evaluate actual current time after a potentially long update.
        within=in_maintenance_window(datetime.now(timezone.utc),weekday=policy.get("weekday",6),start=policy.get("start","03:00"),end=policy.get("end","05:00"),zone=policy["timezone"])
        if reboot and within:
            record("reboot_preparing")
            try:
                prepared = _hook("update-reboot-prepare", runner)
                if prepared.get("boot_id") != boot_id:
                    raise Refused("Reboot preparation did not record the current boot identity")
            except Exception as exc:
                if not (state / "maintenance.json").exists():
                    # Preparation can stop and restart services before refusing.
                    # Recheck the current runtime instead of reusing its earlier proof.
                    record("postcheck", reboot_pending=True)
                    try:
                        accepted = _runtime_postcheck(runner, stage, boot_id)
                        refresh()
                    except Exception as postcheck_error:
                        record("recovery_required", recovery_phase="postcheck", error=type(postcheck_error).__name__)
                        raise Refused("Reboot preparation failed and current runtime acceptance requires recovery") from postcheck_error
                    finalize(status="no_updates" if no_updates else "updated", reboot_pending=True,
                             reboot_blocked=type(exc).__name__, health=accepted["checks"], health_boot_id=boot_id)
                    raise Refused("OS maintenance passed; reboot remains pending because unlock or preparation requirements were not met") from exc
                record("recovery_required", recovery_phase="reboot_preparing", error=type(exc).__name__)
                raise Refused("Reboot preparation failed; review appliance service and unlock state") from exc
            record("reboot_requested", boot_id=prepared["boot_id"])
            try:
                runner(["systemctl","reboot"], timeout=120)
            except Exception as exc:
                try:
                    recovered = _hook("update-reboot-abort", runner)
                    if (recovered.get("recovered") is not True or recovered.get("finalized") is not True
                            or recovered.get("boot_id") != boot_id or recovered.get("storage_released") is not False
                            or any(recovered.get("health", {}).get(name) is not True for name in REQUIRED_CHECKS)):
                        raise Refused("Reboot abort did not provide verified service/authentication recovery")
                    refresh()
                    record("reboot_aborted", reboot_pending=True)
                except Exception as recovery_error:
                    refresh()
                    record("recovery_required", recovery_phase="reboot_abort", error=type(recovery_error).__name__)
                    raise Refused("Reboot request failed and service recovery failed; maintenance remains active") from recovery_error
                raise Refused("Reboot request failed; appliance services and local authentication were restored and verified") from exc
            return {"status":"reboot_requested"}
        result={"status":"no_updates" if no_updates else "updated","reboot_pending":reboot}
        return finalize(**result)

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config",type=Path,default=Path("/etc/nebulalog/maintenance.json"))
    a=p.parse_args()
    try:print(json.dumps(maintain(a.config)))
    except (Refused,OSError,ValueError) as exc:raise SystemExit(str(exc))
