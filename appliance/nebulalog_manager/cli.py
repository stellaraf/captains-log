from __future__ import annotations
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from .common import Refused, trusted_file
from . import backup, security, sizing, storage, updates, enrollment


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="nebulalog", description="Captain’s Log appliance manager")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("setup", help="Run the local first-boot enrollment wizard")
    st = commands.add_parser("storage").add_subparsers(dest="action", required=True)
    for name in ("status", "plan", "grow"):
        p = st.add_parser(name)
        p.add_argument("--identity", type=Path, default=Path("/etc/nebulalog/storage.json"))
        if name == "grow":
            p.add_argument("--confirm-fingerprint", required=True)
            p.add_argument("--key-file", type=Path)
    p = st.add_parser("add-plan")
    p.add_argument("--disk", required=True)
    p = st.add_parser("add")
    p.add_argument("--identity", type=Path, default=Path("/etc/nebulalog/storage.json"))
    p.add_argument("--disk", required=True)
    p.add_argument("--confirmation", required=True)
    p.add_argument("--key-file", type=Path, required=True)
    p.add_argument("--recovery-destination", type=Path, required=True)
    p = st.add_parser("sizing")
    p.add_argument("--measurements", type=Path, required=True)
    cp = commands.add_parser("compliance").add_subparsers(dest="action", required=True)
    cp.add_parser("status")
    p = cp.add_parser("scan")
    p.add_argument("--policy", type=Path, default=Path("/etc/nebulalog/compliance.json"))
    p.add_argument("--output", type=Path, required=True)
    up = commands.add_parser("update").add_subparsers(dest="action", required=True)
    up.add_parser("status")
    up.add_parser("history")
    up.add_parser("livepatch-status", help="Observe the committed kernel patch on this boot without loading it")
    up.add_parser("livepatch-poll", help="Run the configured automatic kernel livepatch check")
    p = up.add_parser("enroll-trust", help="Enroll an explicitly authenticated publisher public key; never generates a signer")
    p.add_argument("--public-key", type=Path, required=True, help="Root-owned public SPKI PEM input")
    p.add_argument("--expected-spki-sha256", required=True, help="SHA256 obtained through an independently authenticated publisher channel")
    p.add_argument("--trust-source", required=True, help="Auditable description/reference for that independent authentication")
    up.add_parser("reboot-complete", help="Verify a changed OS boot and retry its maintenance release")
    up.add_parser("os-recover", help="Retry retained same-boot OS health and maintenance release; never reruns package updates")
    up.add_parser("kernel-retry", help="Request one bounded retry after a verified fallback to the old kernel")
    up.add_parser("kernel-rollback", help="Remove the exact failed candidate after verified fallback, or resume its recovery")
    p = up.add_parser("rollback")
    p.add_argument("--public-key", type=Path, default=Path("/etc/nebulalog/release-public.pem"))
    p = up.add_parser("finalize", help="Recheck a completed transaction and retry maintenance release")
    p.add_argument("--public-key", type=Path, default=Path("/etc/nebulalog/release-public.pem"))
    p = up.add_parser("recover", help="Restore an interrupted component update using its retained transaction")
    p.add_argument("--public-key", type=Path, default=Path("/etc/nebulalog/release-public.pem"))
    for name in ("check", "install"):
        p = up.add_parser(name)
        p.add_argument("--manifest", type=Path, required=True)
        p.add_argument("--signature", type=Path, required=True)
        p.add_argument("--bundle", type=Path, required=True)
        p.add_argument("--public-key", type=Path, default=Path("/etc/nebulalog/release-public.pem"))
    p = commands.add_parser("backup")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--include-logs", action="store_true", help="Capture a complete configuration and native log recovery set with explicit capacity/time budgets")
    mode.add_argument("--resume", metavar="UUID", help="Resume an existing full-backup transaction using retained inputs")
    mode.add_argument("--status", metavar="UUID", help="Read retained full-backup progress without starting or resuming it")
    mode.add_argument("--retire", metavar="UUID", help="Retire a settled unsuccessful full backup while preserving all recovery evidence")
    p.add_argument("--configuration", type=Path)
    p.add_argument("--recipient-certificate", type=Path)
    p.add_argument("--output", type=Path)
    for name in ("maximum-archive-bytes", "growth-reserve-bytes", "minimum-free-bytes", "deadline-seconds"):
        p.add_argument("--" + name, type=int)
    p = commands.add_parser("restore")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--apply-fresh", action="store_true", help="Recover a compatible fresh appliance after host/storage enrollment and before runtime provisioning")
    mode.add_argument("--prepare-fresh", action="store_true", help="Authenticate and review local recovery inputs without changing the runtime")
    mode.add_argument("--apply-plan", metavar="UUID", help="Apply an exact unexpired authenticated restore review")
    mode.add_argument("--resume", metavar="UUID", help="Resume the retained recovery transaction without reapplying an uncertain database restore")
    mode.add_argument("--status", action="store_true", help="Show redacted retained recovery progress without applying or resuming it")
    p.add_argument("--backup", type=Path)
    p.add_argument("--plan-digest", help="Exact review digest returned by --prepare-fresh; requires --apply-plan")
    p.add_argument("--private-key", type=Path)
    p.add_argument("--certificate", type=Path)
    p.add_argument("--media", type=Path, help="Explicit /dev/srN configuration recovery ISO; requires --apply-fresh and an interactive protected passphrase prompt")
    p.add_argument("--log-recovery-set", type=Path, help="Protected local native-log recovery set matching the configuration backup")
    p.add_argument("--log-deadline-seconds", type=int)
    p.add_argument("--log-minimum-free-bytes", type=int)
    p.add_argument("--destination", type=Path, help="New staging directory for validation-only restore")
    args = parser.parse_args(argv)
    try:
        if args.command == "setup":
            from .firstboot import main as firstboot_main
            return firstboot_main(["wizard"])
        if args.command == "storage":
            if args.action == "add-plan":
                result = enrollment.probe_blank(args.disk)
            elif args.action == "add":
                result = enrollment.add_disk(args.identity, args.disk, args.confirmation, args.key_file, args.recovery_destination)
            elif args.action == "sizing":
                values = json.loads(args.measurements.read_text())
                result = sizing.forecast(values["capacity_bytes"], values["used_bytes"],
                                         [sizing.Measurement(**s) for s in values["samples"]])
            else:
                identity = storage.Identity(**json.loads(trusted_file(args.identity).read_text()))
                if args.action == "grow":
                    result = storage.apply_growth(identity, args.confirm_fingerprint, key_file=args.key_file)
                else:
                    snapshot = storage.inspect(identity)
                    result = asdict(snapshot) if args.action == "status" else storage.growth_plan(snapshot)
        elif args.command == "compliance":
            result = security.status() if args.action == "status" else security.scan(args.policy, args.output)
        elif args.command == "update":
            manager = updates.UpdateManager()
            if args.action == "status":
                result = manager.status()
            elif args.action == "livepatch-status":
                from . import livepatch
                result = livepatch.status(manager.state, Path('/etc/nebulalog/release-public.pem'))
            elif args.action == "livepatch-poll":
                from . import livepatch
                result = livepatch.poll_configured(manager.state)
            elif args.action == "history":
                path = manager.state / "history.jsonl"
                result = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
            elif args.action == "enroll-trust":
                from .update_enrollment import UpdateEnrollment
                result = UpdateEnrollment().trust(args.public_key, args.expected_spki_sha256, args.trust_source)
            elif args.action == "rollback":
                result = manager.rollback(args.public_key)
            elif args.action == "finalize":
                result = manager.finalize(args.public_key)
            elif args.action == "recover":
                result = manager.recover(args.public_key)
            elif args.action in ("reboot-complete", "os-recover", "kernel-retry", "kernel-rollback"):
                from .common import require_linux_root
                from .os_updates import _hook
                require_linux_root()
                result = _hook("update-" + args.action, updates.run)
            elif args.action == "check":
                trusted_file(args.public_key)
                updates.enrolled_key(manager.state, args.public_key)
                current = manager.status()["current"]
                result = updates.verify_release(args.manifest, args.signature, args.public_key, args.bundle,
                                                current_sequence=current["sequence"],
                                                current_versions={k:v["version"] for k,v in current["components"].items()})
            else:
                result = manager.install(args.manifest, args.signature, args.bundle, args.public_key)
        elif args.command == "backup":
            budgets = {name: getattr(args, name) for name in ("maximum_archive_bytes", "growth_reserve_bytes", "minimum_free_bytes", "deadline_seconds")}
            if args.resume is not None or args.status is not None or args.retire is not None:
                if (any(value is not None for value in budgets.values())
                        or any(value is not None for value in (args.configuration, args.output, args.recipient_certificate))):
                    raise Refused("Full-backup status/resume/retire uses retained inputs and rejects every input or budget override")
                from .recovery_set import FullBackupManager
                manager = FullBackupManager()
                if args.retire is not None:
                    result = manager.retire(args.retire)
                elif args.resume is not None:
                    result = manager.resume(args.resume)
                else:
                    result = manager.status(args.status)
            else:
                configuration = args.configuration or Path("/var/lib/nebulalog/configuration")
                if configuration != Path("/var/lib/nebulalog/configuration"):
                    raise Refused("Backup requires the canonical appliance configuration directory")
                if not args.output or not args.recipient_certificate:
                    raise Refused("A new backup requires --output and --recipient-certificate")
                if args.include_logs:
                    if any(value is None for value in budgets.values()):
                        raise Refused("Full backup requires --maximum-archive-bytes, --growth-reserve-bytes, --minimum-free-bytes and --deadline-seconds")
                    from .recovery_set import FullBackupManager
                    result = FullBackupManager().create(args.output, args.recipient_certificate, **budgets)
                else:
                    if any(value is not None for value in budgets.values()):
                        raise Refused("Capacity/time budget flags require --include-logs")
                    result = backup.create_backup(configuration, args.output, args.recipient_certificate)
        else:
            log_options = {"log_recovery_set": args.log_recovery_set,
                           "log_restore_deadline_seconds": args.log_deadline_seconds,
                           "log_restore_minimum_free_bytes": args.log_minimum_free_bytes}
            with_logs = any(value is not None for value in log_options.values())
            if args.plan_digest and not args.apply_plan:
                raise Refused("A review digest requires --apply-plan")
            if with_logs and (not (args.apply_fresh or args.prepare_fresh) or args.media or any(value is None for value in log_options.values())):
                raise Refused("Log recovery requires all three log-set/deadline/free-space options with --apply-fresh local files; media, status, resume and validation-only do not accept them")
            if args.apply_plan:
                if not args.plan_digest or any((args.backup, args.private_key, args.certificate, args.destination, args.media)):
                    raise Refused("Apply-plan requires its exact digest and no input or destination overrides")
                from .configuration_restore import ConfigurationRestore
                result = ConfigurationRestore().apply_prepared(args.apply_plan, args.plan_digest)
            elif args.status:
                if any((args.backup, args.private_key, args.certificate, args.destination, args.media)):
                    raise Refused("Recovery status does not accept input or destination overrides")
                from .configuration_restore import ConfigurationRestore
                result = ConfigurationRestore().status()
            elif args.resume:
                if any((args.backup, args.private_key, args.certificate, args.destination, args.media)):
                    raise Refused("Resume uses its retained inputs; backup/key/certificate/destination overrides are not accepted")
                from .configuration_restore import ConfigurationRestore
                result = ConfigurationRestore().resume(args.resume)
            elif args.media:
                if not args.apply_fresh or any((args.backup, args.private_key, args.certificate, args.destination)):
                    raise Refused("Recovery media requires --apply-fresh and does not accept file or destination overrides")
                from .configuration_restore import ConfigurationRestore
                from .recovery_media import restore_from_media
                result = restore_from_media(ConfigurationRestore(), args.media,
                                            write=lambda message: print(message, file=sys.stderr))
            else:
                if not all((args.backup, args.private_key, args.certificate)):
                    raise Refused("Restore requires --backup, --private-key and --certificate")
                if args.apply_fresh or args.prepare_fresh:
                    if args.destination:
                        raise Refused("Fresh restore uses managed encrypted staging; --destination is only for validation")
                    from .configuration_restore import ConfigurationRestore
                    recovery = ConfigurationRestore()
                    action = recovery.prepare if args.prepare_fresh else recovery.start
                    result = action(args.backup, args.private_key, args.certificate, **(log_options if with_logs else {}))
                else:
                    if not args.destination:
                        raise Refused("Validation-only restore requires a new --destination, or select --apply-fresh")
                    result = backup.restore_backup(args.backup, args.private_key, args.certificate, args.destination)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError) as exc:
        # Do not include command stderr, payloads or secrets in errors.
        print(json.dumps({"error": str(exc), "status": "refused"}), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
