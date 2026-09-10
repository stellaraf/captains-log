"""Dispatch fixed installed lifecycle entrypoints; stdout is one sanitized JSON receipt."""
import json
import os
from pathlib import Path
import sys
from nebulalog_manager.common import Refused, require_linux_root
from .lifecycle import Lifecycle, load_config

STAGED = {"update-preflight": "preflight", "update-backup": "backup", "update-prepare": "prepare",
          "update-activate": "activate", "update-health": "health", "update-rollback": "rollback",
          "update-finalize": "finalize"}
HOST = {"update-os-preflight": "os_preflight", "update-os-postcheck": "os_postcheck", "update-os-recover": "os_recover", "update-reboot-prepare": "reboot_prepare", "update-reboot-abort": "reboot_abort",
        "update-boot-gate": "boot_gate", "update-reboot-complete": "reboot_complete"}


def main():
    try:
        require_linux_root()
        os.umask(0o077)
        name = Path(sys.argv[0]).name
        if name not in STAGED and name not in HOST:
            raise Refused("Unknown installed lifecycle entrypoint")
        if len(sys.argv) != (2 if name in STAGED else 1):
            raise Refused("Unexpected lifecycle arguments")
        manager = Lifecycle(load_config())
        result = getattr(manager, STAGED[name])(Path(sys.argv[1])) if name in STAGED else getattr(manager, HOST[name])()
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("ok") is True else 1
    except Exception as exc:
        # Exception strings may contain filesystem paths, URLs, tokens or driver payloads.
        print(json.dumps({"ok": False, "error": type(exc).__name__, "message": "Lifecycle operation failed; inspect its protected manager receipts."}))
        return 1
