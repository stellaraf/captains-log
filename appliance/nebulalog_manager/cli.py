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
    p.add_argument("--configuration", type=Path, default=Path("/var/lib/nebulalog/configuration"))
    p.add_argument("--recipient-certificate", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("restore")
    p.add_argument("--backup", type=Path, required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--certificate", type=Path, required=True)
    p.add_argument("--destination", type=Path, required=True)
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
            result = backup.create_backup(args.configuration, args.output, args.recipient_certificate)
        else:
            result = backup.restore_backup(args.backup, args.private_key, args.certificate, args.destination)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError) as exc:
        # Do not include command stderr, payloads or secrets in errors.
        print(json.dumps({"error": str(exc), "status": "refused"}), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
