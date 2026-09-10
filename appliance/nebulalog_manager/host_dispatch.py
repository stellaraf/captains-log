"""Pin component hooks to the accepted coordinator recorded by the manager.

The signed-release manager supplies the protected transaction and retains this
coordinator through finalization. Staging alone never grants hook execution.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

from . import host_payload as payload
from .common import Refused, require_linux_root

STATE = Path("/var/lib/nebulalog/manager/updates")
STATES = {"preflight", "preflight_failed", "preparing", "activating", "checking", "committed",
          "rolling_back", "rolled_back", "recovery_required"}
HOOK_STATES = {
    "update-preflight": {"preflight"}, "update-backup": {"preflight"}, "update-prepare": {"preparing"},
    "update-activate": {"activating"}, "update-health": {"checking", "rolling_back", "rolled_back", "committed", "recovery_required"},
    "update-rollback": {"rolling_back", "recovery_required"}, "update-finalize": {"committed", "rolled_back"},
}
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C",
               "TMPDIR": "/var/lib/nebulalog/tmp"}
MAX_OUTPUT = 1024**2
MAX_HOOK_SECONDS = 3600
# The selected generation is an argv datum, never interpolated executable code.
# -I excludes cwd, PYTHONPATH and user site; -B leaves generations read-only.
DISPATCH_CODE = """import pathlib,sys
root=pathlib.Path(sys.argv[1])
sys.path.insert(0,str(root/'lib'))
sys.argv=[sys.argv[2],sys.argv[3]]
from nebulalog_adapters.cli import main
raise SystemExit(main())
"""


def protected_json(path, maximum=1024**2):
    payload._trusted_tree(path.parent)
    return payload.strict_json(payload.read_regular(path, maximum, trusted=True))


def transaction_binding(stage: Path):
    require_linux_root()
    if (not stage.is_absolute() or stage.parent != STATE / "releases"
            or not re.fullmatch(r"[1-9][0-9]*-[A-Za-z0-9_-]{1,100}", stage.name)):
        raise Refused("Host operations require a fixed manager-owned release stage")
    payload._trusted_tree(stage)
    transaction = protected_json(STATE / "transaction.json")
    raw = payload.read_regular(stage / "manifest.json", 1024**2, trusted=True)
    manifest = payload.strict_json(raw)
    if (not isinstance(transaction, dict) or transaction.get("release") != str(stage)
            or not isinstance(transaction.get("state"), str) or transaction.get("state") not in STATES or type(transaction.get("sequence")) is not int
            or not 0 < transaction["sequence"] < 2**63 or transaction.get("manifest_sha256") != payload.digest(raw)
            or not stage.name.startswith(str(transaction["sequence"]) + "-")
            or not isinstance(manifest, dict) or manifest.get("sequence") != transaction["sequence"]
            or type(manifest.get("sequence")) is not int or manifest.get("product") != "nebulalog"
            or manifest.get("channel") != "stable" or not isinstance(manifest.get("components"), dict)):
        raise Refused("Host operation does not match the protected manager transaction")
    return transaction, manifest


def generation_info(generation: str):
    if not isinstance(generation, str) or not payload.SHA256.fullmatch(generation):
        raise Refused("Generation identity must be a digest, never a path")
    path = payload.GENERATIONS / generation
    metadata = protected_json(path / "host-payload.json", payload.MAX_METADATA)
    receipt = protected_json(path / "staging-receipt.json", payload.MAX_METADATA)
    if not isinstance(receipt, dict) or receipt.get("archive_sha256") != generation:
        raise Refused("Generation receipt differs from its selected identity")
    evidence = {"archive_sha256": generation, "metadata": metadata}
    payload.verify_generation(path, evidence)
    return {"generation": generation, "version": metadata["version"],
            "host_source_sha256": metadata["host_source_sha256"], "abi": metadata["abi"]}


def coordinator_pin(stage: Path):
    transaction, _ = transaction_binding(stage)
    previous = transaction.get("previous")
    host = (previous.get("components", {}).get("host") if isinstance(previous, dict)
            and isinstance(previous.get("components"), dict) else None)
    if (not isinstance(host, dict) or type(previous.get("sequence")) is not int
            or not 0 <= previous["sequence"] < transaction["sequence"] or type(host.get("abi")) is not int):
        raise Refused("Manager transaction lacks its previously accepted host identity")
    observed = generation_info(host.get("generation"))
    if any(host.get(key) != observed[key] for key in observed):
        raise Refused("Previous coordinator differs from its accepted component record")
    return {"schema": 1, **observed, "sequence": transaction["sequence"], "manifest_sha256": transaction["manifest_sha256"]}


def hook_command(pin, name, stage: Path):
    transaction, _ = transaction_binding(stage)
    if not isinstance(name, str) or name not in HOOK_STATES or transaction["state"] not in HOOK_STATES[name]:
        raise Refused("Component hook is not allowed in this transaction phase")
    if (not isinstance(pin, dict) or type(pin.get("schema")) is not int or type(pin.get("abi")) is not int
            or type(pin.get("sequence")) is not int or pin != coordinator_pin(stage)):
        raise Refused("The transaction coordinator pin changed")
    return ["/usr/bin/python3", "-I", "-B", "-c", DISPATCH_CODE,
            str(payload.GENERATIONS / pin["generation"]), name, str(stage)]


def _run_bounded(argv):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                               env=ENVIRONMENT, start_new_session=True)
    selector = selectors.DefaultSelector()
    deadline, output = time.monotonic() + MAX_HOOK_SECONDS, bytearray()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            if time.monotonic() > deadline:
                raise Refused("Pinned component hook exceeded its deadline")
            if not selector.select(timeout=min(1, max(0, deadline - time.monotonic()))):
                continue
            chunk = os.read(process.stdout.fileno(), min(65536, MAX_OUTPUT - len(output) + 1))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT:
                raise Refused("Pinned component hook exceeded its output bound")
        if process.wait(timeout=max(.001, deadline - time.monotonic())) != 0:
            raise Refused("Pinned component hook failed")
        return bytes(output)
    except subprocess.TimeoutExpired as exc:
        raise Refused("Pinned component hook exceeded its deadline") from exc
    finally:
        selector.close()
        process.stdout.close()
        # Only the session created for this hook is signalled. Terminating its
        # leader alone could leave a pipe-holding descendant running after error.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def run_hook(pin, name, stage: Path):
    result = payload.strict_json(_run_bounded(hook_command(pin, name, stage)))
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise Refused("Pinned component hook did not report success")
    return result
