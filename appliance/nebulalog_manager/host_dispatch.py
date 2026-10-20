"""Pin component hooks to the accepted coordinator recorded by the manager.

The signed-release manager supplies the protected transaction and retains this
coordinator through finalization. Staging alone never grants hook execution.
"""
from __future__ import annotations

import json
from datetime import datetime
import xml.etree.ElementTree as ET
import os
import stat
import uuid
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

from . import host_payload as payload
from .common import Refused, require_linux_root, trusted_file

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
    return ["/usr/bin/python3.14", "-I", "-B", "-c", DISPATCH_CODE,
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


class HookJournal:
    """Immutable lifecycle dispatch and terminal evidence, never a PID lease.

    The adapter terminates its method before publishing a terminal record. Every
    native invocation must have a successful acknowledgement first; otherwise
    even a departed hook process leaves the operation held.
    """
    MAX_HOOKS = 256
    MAX_COMMANDS = 4096
    # Only this inert literal query may acknowledge a normally returned failure.
    # Timeout/signal never reaches this exception; changed argv is a mutator.
    POSTGRES_READY = ["podman", "exec", "--user", "999:999", "nebulalog-postgresql", "psql", "-X",
        "--username=postgres", "--dbname=postgres", "--tuples-only", "--no-align",
        "--set=ON_ERROR_STOP=1", "--command", "SELECT 1"]

    def __init__(self, stage, transaction):
        self.stage = Path(stage)
        if (not self.stage.is_absolute() or self.stage.resolve() != self.stage
                or self.stage.is_symlink() or self.stage.parent.name != "releases"
                or not isinstance(transaction, dict) or transaction.get("release") != str(self.stage)
                or type(transaction.get("hook_protocol")) is not int or transaction["hook_protocol"] != 1
                or type(transaction.get("sequence")) is not int or transaction["sequence"] < 1):
            raise Refused("Component operation lacks exact hook lifetime protocol ownership")
        for directory in (self.stage, self.stage.parent, self.stage.parent.parent):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != payload._OWNER_UID or info.st_mode & 0o022:
                raise Refused("Component hook evidence is not in protected manager storage")
        raw = trusted_file(self.stage / "manifest.json").read_bytes()
        if transaction.get("manifest_sha256") != payload.digest(raw):
            raise Refused("Component hook manifest identity changed")
        self.transaction = transaction
        self.binding = {"stage": str(self.stage), "sequence": transaction["sequence"],
            "manifest_sha256": transaction["manifest_sha256"],
            "previous_sha256": payload.digest(payload.encoded(transaction.get("previous"))),
            "coordinator_sha256": payload.digest(payload.encoded(transaction.get("host_coordinator")))}

    @staticmethod
    def _encoded(value):
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

    def _read(self, path):
        raw = trusted_file(path).read_bytes()
        if len(raw) > 65536:
            raise Refused("Oversized component execution evidence")
        value = payload.strict_json(raw)
        if raw != self._encoded(value):
            raise Refused("Component execution evidence is not canonical")
        return value, payload.digest(raw)

    def _write(self, path, value):
        raw = self._encoded(value)
        if os.path.lexists(path):
            if trusted_file(path).read_bytes() != raw:
                raise Refused("Immutable component execution evidence changed")
            return payload.digest(raw)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return payload.digest(raw)

    def _path(self, token, suffix):
        return self.stage / ("component-hook-" + token + "-" + suffix + ".json")

    def _intents(self):
        tokens = set()
        for path in self.stage.glob("component-hook-*"):
            if path.name == "component-hook-lease.lock":
                continue
            match = re.fullmatch(r"component-hook-([a-f0-9]{32})-(intent|entered|terminal)\.json", path.name)
            if match is None:
                raise Refused("Unknown component hook evidence")
            tokens.add(match[1])
        if len(tokens) > self.MAX_HOOKS:
            raise Refused("Component hook evidence limit reached")
        result = {}
        for token in sorted(tokens):
            value, checksum = self._read(self._path(token, "intent"))
            if (not isinstance(value, dict) or set(value) != {"schema", "id", "name", "state", "executor_sha256", *self.binding}
                    or type(value.get("schema")) is not int or value["schema"] != 1
                    or value.get("id") != token or value.get("name") not in HOOK_STATES
                    or value.get("state") not in HOOK_STATES[value["name"]]
                    or any(value.get(key) != expected for key, expected in self.binding.items())
                    or not isinstance(value.get("executor_sha256"), str) or not payload.SHA256.fullmatch(value["executor_sha256"])):
                raise Refused("Component hook intent belongs to another operation")
            result[token] = (value, {"id": token, "sha256": checksum})
        return result

    def _commands(self, intents):
        tokens = set()
        for path in self.stage.glob("component-command-*"):
            match = re.fullmatch(r"component-command-([a-f0-9]{32})-(intent|complete|returned)\.json", path.name)
            if match is None:
                raise Refused("Unknown component native-command evidence")
            tokens.add(match[1])
        if len(tokens) > self.MAX_COMMANDS:
            raise Refused("Component native-command evidence limit reached")
        result = {token: [] for token in intents}
        for token in sorted(tokens):
            path = self.stage / ("component-command-" + token + "-intent.json")
            value, checksum = self._read(path)
            ref = value.get("hook") if isinstance(value, dict) else None
            if (not isinstance(value, dict) or set(value) != {"schema", "id", "hook", "kind", "command_sha256", "probe", "scap"}
                    or type(value.get("schema")) is not int or value["schema"] != 1 or value.get("id") != token
                    or not isinstance(ref, dict) or ref.get("id") not in intents or ref != intents[ref["id"]][1]
                    or value.get("kind") not in {"call", "capture", "feed"}
                    or not isinstance(value.get("command_sha256"), str) or not payload.SHA256.fullmatch(value["command_sha256"])
                    or value.get("probe") not in {None, "postgresql-ready-v1"}
                    or value.get("probe") == "postgresql-ready-v1" and (value["kind"] != "call"
                        or value["command_sha256"] != payload.digest(self._encoded(self.POSTGRES_READY)))):
                raise Refused("Component native command belongs to another hook")
            if value["scap"] is not None:
                self._validate_scap(value["scap"])
                if value["kind"] != "call" or value["probe"] is not None or value["command_sha256"] != payload.digest(self._encoded(self._scap_argv(value["scap"]))):
                    raise Refused("SCAP command differs from its fixed assessment authority")
            completed = self.stage / ("component-command-" + token + "-complete.json")
            if not os.path.lexists(completed):
                raise Refused("Component native command lacks successful acknowledgement; operation remains held")
            body, completed_sha = self._read(completed)
            expected = {"schema": 1, "id": token, "intent_sha256": checksum, "success": True}
            if (isinstance(body, dict) and body.get("success") is False
                    and value["probe"] == "postgresql-ready-v1" and type(body.get("returncode")) is int
                    and 0 < body["returncode"] < 128):
                expected = {**expected, "success": False, "returncode": body["returncode"]}
            if (isinstance(body, dict) and body.get("success") is False and value["scap"] is not None
                    and type(body.get("returncode")) is int and body["returncode"] == 2):
                returned, returned_sha = self._read(self.stage / ("component-command-" + token + "-returned.json"))
                if returned != {"schema": 1, "id": token, "intent_sha256": checksum, "returncode": 2} or type(returned.get("schema")) is not int or type(returned.get("returncode")) is not int:
                    raise Refused("SCAP normal exit evidence changed")
                expected = {**expected, "success": False, "returncode": 2, "returned_sha256": returned_sha,
                            "scap_result": self._scap_result(value["scap"])}
            elif os.path.lexists(self.stage / ("component-command-" + token + "-returned.json")):
                raise Refused("Unexpected native semantic completion evidence")
            if body != expected or type(body.get("schema")) is not int or type(body.get("success")) is not bool:
                raise Refused("Component native command acknowledgement changed")
            result[ref["id"]].append({"id": token, "intent_sha256": checksum, "complete_sha256": completed_sha})
        return result

    def assert_settled(self, *, allow=None):
        intents = self._intents()
        commands = self._commands(intents)
        if allow is not None and (not isinstance(allow, dict) or allow.get("id") not in intents or allow != intents[allow["id"]][1]):
            raise Refused("Active component hook reference changed")
        for token, (intent, ref) in intents.items():
            entered_path, terminal_path = self._path(token, "entered"), self._path(token, "terminal")
            if allow == ref and not os.path.lexists(terminal_path):
                if os.path.lexists(entered_path):
                    entered, _ = self._read(entered_path)
                    if entered != {"schema": 1, "hook": ref} or type(entered.get("schema")) is not int:
                        raise Refused("Active component hook entry changed")
                continue
            if not os.path.lexists(terminal_path):
                raise Refused("Component hook outcome is unresolved; operation remains held")
            entered, _ = self._read(entered_path)
            terminal, _ = self._read(terminal_path)
            if (entered != {"schema": 1, "hook": ref} or type(entered.get("schema")) is not int
                    or not isinstance(terminal, dict) or set(terminal) != {"schema", "hook", "outcome", "commands_sha256", "result_sha256"}
                    or type(terminal.get("schema")) is not int or terminal["schema"] != 1
                    or terminal.get("hook") != ref or terminal.get("outcome") not in {"success", "failed"}
                    or terminal.get("commands_sha256") != payload.digest(self._encoded(commands[token]))
                    or terminal.get("result_sha256") is not None and (not isinstance(terminal["result_sha256"], str) or not payload.SHA256.fullmatch(terminal["result_sha256"]))):
                raise Refused("Component hook terminal acknowledgement changed")
        return len(intents)

    def begin(self, name, executor):
        if self.assert_settled() >= self.MAX_HOOKS:
            raise Refused("Component hook evidence limit reached")
        if name not in HOOK_STATES or self.transaction.get("state") not in HOOK_STATES[name]:
            raise Refused("Component hook does not belong to the current phase")
        token = uuid.uuid4().hex
        intent = {"schema": 1, "id": token, "name": name, "state": self.transaction["state"],
                  "executor_sha256": payload.digest(self._encoded(executor)), **self.binding}
        return {"id": token, "sha256": self._write(self._path(token, "intent"), intent)}

    def enter(self, name):
        intents = self._intents()
        pending = [(intent, ref) for token, (intent, ref) in intents.items() if not os.path.lexists(self._path(token, "terminal"))]
        if len(pending) != 1 or pending[0][0]["name"] != name:
            raise Refused("Adapter requires exactly one matching unresolved hook dispatch")
        _, ref = pending[0]
        self.assert_settled(allow=ref)
        if os.path.lexists(self._path(ref["id"], "entered")):
            raise Refused("Component hook body was already entered; replay is forbidden")
        self._write(self._path(ref["id"], "entered"), {"schema": 1, "hook": ref})
        return ref

    def finish(self, ref, outcome, *, result=None):
        self.assert_settled(allow=ref)
        if outcome not in {"success", "failed"}:
            raise Refused("Invalid component hook terminal outcome")
        entered, _ = self._read(self._path(ref["id"], "entered"))
        if entered != {"schema": 1, "hook": ref} or type(entered.get("schema")) is not int:
            raise Refused("Component terminal belongs to another hook entry")
        commands = self._commands(self._intents())[ref["id"]]
        self._write(self._path(ref["id"], "terminal"), {"schema": 1, "hook": ref, "outcome": outcome,
            "commands_sha256": payload.digest(self._encoded(commands)),
            "result_sha256": None if result is None else payload.digest(self._encoded(result))})

    def successful_result(self, ref, result):
        self.assert_settled()
        terminal, _ = self._read(self._path(ref["id"], "terminal"))
        if terminal["outcome"] != "success" or terminal["result_sha256"] != payload.digest(self._encoded(result)):
            raise Refused("Component result lacks exact successful adapter terminal evidence")

    def command_event(self, hook, phase, kind, *, argv=None, ticket=None, returncode=None, scap=None):
        intents = self._intents()
        if (not isinstance(hook, dict) or hook.get("id") not in intents or hook != intents[hook["id"]][1]
                or kind not in {"call", "capture", "feed"} or os.path.lexists(self._path(hook["id"], "terminal"))):
            raise Refused("Native command has no active exact component hook")
        entered, _ = self._read(self._path(hook["id"], "entered"))
        if entered != {"schema": 1, "hook": hook} or type(entered.get("schema")) is not int:
            raise Refused("Native command hook entry changed")
        if phase == "dispatch":
            self.assert_settled(allow=hook)
            if len(list(self.stage.glob("component-command-*-intent.json"))) >= self.MAX_COMMANDS:
                raise Refused("Component native-command evidence limit reached")
            if scap is not None:
                self._validate_scap(scap)
                self._scap_live_sources(scap)
                if kind != "call" or argv != self._scap_argv(scap):
                    raise Refused("SCAP acknowledgement requires the exact fixed eval operation")
            token = uuid.uuid4().hex
            value = {"schema": 1, "id": token, "hook": hook, "kind": kind,
                     "command_sha256": payload.digest(self._encoded(argv)),
                     "probe": "postgresql-ready-v1" if kind == "call" and argv == self.POSTGRES_READY else None, "scap": scap}
            checksum = self._write(self.stage / ("component-command-" + token + "-intent.json"), value)
            return {"id": token, "sha256": checksum}
        if (phase not in {"complete", "failed"} or not isinstance(ticket, dict) or set(ticket) != {"id", "sha256"}
                or not isinstance(ticket.get("id"), str) or not re.fullmatch(r"[0-9a-f]{32}", ticket["id"])):
            raise Refused("Invalid component native-command acknowledgement")
        value, checksum = self._read(self.stage / ("component-command-" + ticket["id"] + "-intent.json"))
        if checksum != ticket["sha256"] or value.get("hook") != hook or value.get("kind") != kind:
            raise Refused("Native command acknowledgement belongs to another invocation")
        completion = {"schema": 1, "id": ticket["id"], "intent_sha256": checksum, "success": True}
        if phase == "failed":
            if value.get("scap") is not None and kind == "call" and type(returncode) is int and returncode == 2:
                self._write(self.stage / ("component-command-" + ticket["id"] + "-returned.json"),
                    {"schema": 1, "id": ticket["id"], "intent_sha256": checksum, "returncode": 2})
                return  # The completed result must still pass semantic validation.
            if (value.get("probe") != "postgresql-ready-v1" or kind != "call"
                    or value.get("command_sha256") != payload.digest(self._encoded(self.POSTGRES_READY))
                    or type(returncode) is not int or not 0 < returncode < 128):
                return  # A failed mutator or signal remains unresolved.
            completion.update(success=False, returncode=returncode)
        elif value.get("scap") is not None:
            self._scap_live_sources(value["scap"])
        self._write(self.stage / ("component-command-" + ticket["id"] + "-complete.json"), completion)


    @staticmethod
    def _scap_argv(value):
        argv = ["oscap", "xccdf", "eval", "--profile", value["profile"], "--results", value["xml"], "--report", value["html"]]
        if value.get("arf") is not None:
            argv += ["--results-arf", value["arf"]]
        if value["tailoring"] is not None:
            argv += ["--tailoring-file", value["tailoring"]["path"]]
        return argv + [value["datastream"]["path"]]

    @staticmethod
    def _scap_live_sources(value):
        for name in ("datastream", "tailoring"):
            ref = value[name]
            if ref is None:
                continue
            path = Path(ref["path"])
            if (not path.is_absolute() or path.resolve() != path
                    or payload.digest(payload.read_regular(path, 64 * 1024**2, trusted=True)) != ref["sha256"]):
                raise Refused("SCAP execution input changed during assessment")

    def _validate_scap(self, value):
        if (not isinstance(value, dict) or set(value) not in ({"policy", "profile", "kind", "datastream", "tailoring", "xml", "html"}, {"policy", "profile", "kind", "datastream", "tailoring", "xml", "html", "arf"})
                or value["kind"] not in {"cis", "stig"} or not isinstance(value["profile"], str) or not value["profile"].startswith("xccdf_")):
            raise Refused("Invalid fixed SCAP authority")
        for name in ("policy", "datastream", "tailoring"):
            ref = value[name]
            if name == "tailoring" and ref is None:
                continue
            if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or not isinstance(ref.get("path"), str):
                raise Refused("Invalid SCAP source reference")
            path = Path(ref["path"])
            if (not path.is_absolute() or str(path) != os.path.normpath(ref["path"])
                    or not isinstance(ref.get("sha256"), str) or not payload.SHA256.fullmatch(ref["sha256"])):
                raise Refused("Invalid SCAP source identity")
            # Installed content may later change through an authorized OS update.
            # Historical completion binds the exact retained input, not that
            # mutable pathname; the original path still binds the executed argv.
            retained = path if name == "policy" else self.stage / ("component-scap-source-" + ref["sha256"] + ".xml")
            if payload.digest(trusted_file(retained).read_bytes()) != ref["sha256"]:
                raise Refused("Bound SCAP policy or content changed")
        policy = Path(value["policy"]["path"])
        xml, html = Path(value["xml"]), Path(value["html"])
        if (not policy.is_relative_to(self.stage) or policy.name != "security-policy.json"
                or xml.resolve() != xml or html.resolve() != html or not xml.is_relative_to(policy.parent)
                or xml.parent != html.parent or xml.name != value["kind"] + ".xml" or html.name != value["kind"] + ".html"):
            raise Refused("SCAP output must belong to its retained operation policy")
        if "arf" in value:
            arf = Path(value["arf"])
            if arf.resolve() != arf or arf.parent != xml.parent or arf.name != value["kind"] + ".arf.xml":
                raise Refused("ARF output must belong to its exact retained assessment")
        body = payload.strict_json(trusted_file(policy).read_bytes())
        profiles = body.get("assessments", []) if isinstance(body, dict) else []
        matches = [profile for profile in profiles if isinstance(profile, dict) and profile.get("kind") == value["kind"]
                   and profile.get("profile_id") == value["profile"]]
        if len(matches) != 1:
            raise Refused("SCAP profile differs from its retained operation policy")
        profile = matches[0]
        expected_tailoring = None if not profile.get("tailoring") else {"path": profile["tailoring"], "sha256": profile.get("tailoring_sha256")}
        if (value["datastream"] != {"path": profile.get("datastream"), "sha256": profile.get("sha256")}
                or value["tailoring"] != expected_tailoring or profile.get("platform") != "rocky9" or profile.get("reviewed") is not True):
            raise Refused("SCAP authority does not match reviewed policy content")

    def scap_authority(self, policy_path, argv):
        policy_path = Path(policy_path)
        body = payload.strict_json(trusted_file(policy_path).read_bytes())
        if len(argv) not in (10, 12, 14) or argv[:4] != ["oscap", "xccdf", "eval", "--profile"]:
            raise Refused("Only the fixed non-remediating SCAP eval can qualify")
        matches = [profile for profile in body.get("assessments", []) if profile.get("profile_id") == argv[4]
                   and Path(argv[6]).name == profile.get("kind", "") + ".xml"]
        if len(matches) != 1:
            raise Refused("SCAP command has no exact retained profile")
        profile = matches[0]
        value = {"policy": {"path": str(policy_path), "sha256": payload.digest(policy_path.read_bytes())},
            "profile": profile["profile_id"], "kind": profile["kind"],
            "datastream": {"path": profile["datastream"], "sha256": profile["sha256"]},
            "tailoring": None if not profile.get("tailoring") else {"path": profile["tailoring"], "sha256": profile.get("tailoring_sha256")},
            "xml": argv[6], "html": argv[8]}
        if argv[9:10] == ["--results-arf"]:
            value["arf"] = argv[10]
        for name in ("datastream", "tailoring"):
            ref = value[name]
            if ref is None:
                continue
            path = Path(ref["path"])
            raw = payload.read_regular(path, 64 * 1024**2, trusted=True)
            if not path.is_absolute() or path.resolve() != path or payload.digest(raw) != ref["sha256"]:
                raise Refused("SCAP dispatch source differs from the retained policy")
            retained = self.stage / ("component-scap-source-" + payload.digest(raw) + ".xml")
            if os.path.lexists(retained):
                if trusted_file(retained).read_bytes() != raw:
                    raise Refused("Retained SCAP source changed")
            else:
                fd = os.open(retained, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                parent = os.open(self.stage, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        self._validate_scap(value)
        if argv != self._scap_argv(value) or os.path.lexists(value["xml"]) or os.path.lexists(value["html"]) or "arf" in value and os.path.lexists(value["arf"]):
            raise Refused("SCAP dispatch must create its exact fresh operation outputs")
        return value

    def _scap_result(self, authority):
        from .baseline import rule_results
        self._validate_scap(authority)
        xml, html = trusted_file(Path(authority["xml"])), trusted_file(Path(authority["html"]))
        rules = rule_results(xml, authority["profile"])
        raw = xml.read_bytes()
        root = ET.fromstring(raw)
        results = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "TestResult"]
        if len(results) != 1 or not rules:
            raise Refused("SCAP did not complete a nonempty exact assessment")
        try:
            start = datetime.fromisoformat(results[0].attrib["start-time"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(results[0].attrib["end-time"].replace("Z", "+00:00"))
            valid = start.utcoffset() is not None and end.utcoffset() is not None and end >= start
        except (ValueError, TypeError, KeyError):
            valid = False
        if not valid:
            raise Refused("SCAP result lacks a completed assessment interval")
        proof = {"xml_sha256": payload.digest(raw), "html_sha256": payload.digest(html.read_bytes()),
                 "rules_sha256": payload.digest(self._encoded(rules))}
        if "arf" in authority:
            from .baseline import ContentUpdate
            proof.update(arf_sha256=payload.digest(trusted_file(Path(authority["arf"])).read_bytes()),
                         evidence_sha256=ContentUpdate.assessment_evidence(xml.parent, authority["kind"], authority["profile"], source=self.stage / ("component-scap-source-" + authority["datastream"]["sha256"] + ".xml")))
        return proof

    def acknowledge_scap(self, hook, ticket, argv):
        if not isinstance(ticket, dict) or set(ticket) != {"id", "sha256"} or not isinstance(ticket["id"], str) or not re.fullmatch(r"[a-f0-9]{32}", ticket["id"]):
            raise Refused("SCAP completion lacks the exact native dispatch ticket")
        value, checksum = self._read(self.stage / ("component-command-" + ticket["id"] + "-intent.json"))
        if (checksum != ticket["sha256"] or value.get("hook") != hook or value.get("kind") != "call"
                or value.get("scap") is None or argv != self._scap_argv(value["scap"])
                or value.get("command_sha256") != payload.digest(self._encoded(argv))):
            raise Refused("SCAP completion differs from its exact native dispatch")
        returned, returned_sha = self._read(self.stage / ("component-command-" + ticket["id"] + "-returned.json"))
        if returned != {"schema": 1, "id": ticket["id"], "intent_sha256": checksum, "returncode": 2} or type(returned.get("schema")) is not int or type(returned.get("returncode")) is not int:
            raise Refused("SCAP completion has no normal exit-2 evidence")
        self._scap_live_sources(value["scap"])
        proof = self._scap_result(value["scap"])
        self._write(self.stage / ("component-command-" + ticket["id"] + "-complete.json"),
                    {"schema": 1, "id": ticket["id"], "intent_sha256": checksum, "success": False,
                     "returncode": 2, "returned_sha256": returned_sha, "scap_result": proof})
