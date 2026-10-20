#!/usr/bin/python3.14
"""Fixed host boot ABI 1. Standard library only until generation verification.

This file is outside updatable generations. Changing its ABI requires a separately
qualified appliance migration. It never restores data or clears maintenance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

OWNER = 0
ETC = Path("/etc/nebulalog")
SHARE = Path("/usr/share/nebulalog")
GENERATIONS = Path("/usr/lib/nebulalog/generations")
STATE = Path("/var/lib/nebulalog/manager/updates")
FIXED = {"appliance/host_boot.py": Path("/usr/libexec/nebulalog/host-boot"),
         "appliance/factory_host.py": Path("/usr/libexec/nebulalog/factory-host"),
         "appliance/factory_kernel.py": Path("/usr/libexec/nebulalog/factory-kernel")}
SHA = re.compile(r"[a-f0-9]{64}")
COMMANDS = {"nebulalog": ("cli", ()), "bootstrap-runtime": ("bootstrap", ()),
            "github-updates": ("github_updates", ()), "os-updates": ("os_updates", ()),
            "enroll-installed-release": ("update_enrollment", ()), "load-image-bundle": ("image_bundle", ()),
            "nebulalog-aide": ("aide", ()), "nebulalog-baseline": ("baseline", ()),
            "nebulalog-console": ("console", ()), "nebulalog-firstboot": ("firstboot", ("gate",)),
            "nebulalog-setup": ("firstboot", ("wizard",)), "publish-status": ("status_snapshot", ()),
            "validate-guest": ("guest_validation", ())}
STAGED = {"update-preflight", "update-backup", "update-prepare", "update-activate", "update-health",
          "update-rollback", "update-finalize"}
ADAPTERS = STAGED | {"update-os-preflight", "update-os-postcheck", "update-os-recover", "update-reboot-prepare",
                     "update-reboot-abort", "update-boot-gate", "update-reboot-complete",
                     "update-kernel-retry", "update-kernel-rollback"}
PHASES = {"preflight", "preflight_failed", "preparing", "activating", "checking", "committed",
          "rolling_back", "rolled_back", "recovery_required"}
PROBES = {"verify-selected", "probe-selected"}
PROBE_MODULES = ("nebulalog_manager.updates", "nebulalog_manager.github_updates", "nebulalog_adapters.lifecycle")


class Refused(RuntimeError):
    pass


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def tree(path):
    if not path.is_absolute(): raise Refused("Absolute protected path required")
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o022:
            raise Refused("Unsafe host dispatch ancestry")


def read(path, maximum=1024**2):
    tree(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != OWNER or before.st_nlink != 1
                or before.st_mode & 0o7022 or not 0 <= before.st_size <= maximum):
            raise Refused("Unsafe fixed host dispatch input")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in
                ("st_ino", "st_dev", "st_size", "st_mode", "st_nlink", "st_mtime_ns", "st_ctime_ns")):
            raise Refused("Host dispatch input changed")
    return raw


def unique(items):
    result = {}
    for key, value in items:
        if key in result: raise Refused("Duplicate host dispatch metadata")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite metadata")))


def js(path, maximum=1024**2): return decode(read(path, maximum))
def present(path): return path.exists() or path.is_symlink()
def digest(value): return isinstance(value, str) and SHA.fullmatch(value) is not None
def sequence(value): return type(value) is int and 0 <= value < 2**63


def identity(value):
    if (not isinstance(value, dict) or set(value) != {"generation", "version", "host_source_sha256", "abi"}
            or type(value["abi"]) is not int or value["abi"] != 1 or not digest(value["generation"])
            or not digest(value["host_source_sha256"]) or not isinstance(value["version"], str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,100})?", value["version"])):
        raise Refused("Invalid accepted host identity")
    return value


def factory():
    record = js(SHARE / "initial-host.json")
    fields = {"schema", "abi", "host", "initial_release_sha256", "source_snapshot_sha256", "catalog", "catalog_sha256", "fixed_files"}
    if (not isinstance(record, dict) or set(record) != fields or type(record["schema"]) is not int
            or record["schema"] != 1 or type(record["abi"]) is not int or record["abi"] != 1
            or not isinstance(record["catalog"], list) or not 1 <= len(record["catalog"]) <= 256
            or sha(encoded(record["catalog"])) != record["catalog_sha256"]):
        raise Refused("Factory host ABI is missing or malformed")
    identity(record["host"])
    initial_raw, source_raw = read(SHARE / "initial-release.json"), read(SHARE / "source-manifest.json", 8 * 1024**2)
    initial, source = decode(initial_raw), decode(source_raw)
    initial_fields = {"schema", "product", "sequence", "schema_revision", "source_commit", "source_dirty", "source_snapshot_sha256",
                      "bundle_manifest_sha256", "qualification_status", "publisher"}
    if (not isinstance(initial, dict) or not initial_fields <= set(initial) or set(initial) - initial_fields - {"restore_auth", "private_qualification"} or type(initial["schema"]) is not int or initial["schema"] != 1
            or initial["product"] != "nebulalog" or initial["qualification_status"] != "pending"
            or not isinstance(initial["schema_revision"], str) or not re.fullmatch(r"[1-9][0-9]{0,8}", initial["schema_revision"])
            or not isinstance(initial["source_commit"], str) or not re.fullmatch(r"[a-f0-9]{40}", initial["source_commit"])
            or type(initial["source_dirty"]) is not bool or not digest(initial["bundle_manifest_sha256"])
            or not isinstance(initial["publisher"], dict) or initial["publisher"].get("mode") not in ("factory", "private-unsealed")
            or not isinstance(source, dict) or set(source) != {"schema", "files"} or type(source.get("schema")) is not int
            or record["initial_release_sha256"] != sha(initial_raw) or record["source_snapshot_sha256"] != sha(source_raw)
            or initial.get("source_snapshot_sha256") != sha(source_raw) or not sequence(initial.get("sequence"))
            or source.get("schema") != 1 or not isinstance(source.get("files"), dict) or not 1 <= len(source["files"]) <= 10000
            or not isinstance(record["fixed_files"], dict) or set(record["fixed_files"]) != set(FIXED)):
        raise Refused("Factory dispatch provenance changed")
    private_qualification = initial.get("private_qualification") is True
    if "private_qualification" in initial and (not private_qualification or initial["schema_revision"] != "4" or "restore_auth" not in initial):
        raise Refused("Private qualification descriptor is invalid")
    if "restore_auth" in initial:
        proof = initial["restore_auth"]
        if (initial["schema_revision"] != "3" and not private_qualification or not isinstance(proof, dict)
                or set(proof) != {"schema", "contract", "version", "artifacts"}
                or type(proof["schema"]) is not int or proof["schema"] != 1 or proof["contract"] != "restored-jwt-issued-at-v1"
                or not isinstance(proof["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,100})?", proof["version"])
                or not isinstance(proof["artifacts"], dict) or set(proof["artifacts"]) != {"application-build.json", "restore-auth-behavior.json"}):
            raise Refused("Factory restored authentication descriptor is invalid")
        for name, expected in proof["artifacts"].items():
            if (not isinstance(expected, dict) or set(expected) != {"bytes", "sha256"}
                    or type(expected["bytes"]) is not int or not 0 < expected["bytes"] <= 8 * 1024**2
                    or not digest(expected["sha256"])):
                raise Refused("Factory restored authentication artifact identity is invalid")
            raw = read(SHARE / "restore-auth" / name, 8 * 1024**2)
            if len(raw) != expected["bytes"] or sha(raw) != expected["sha256"]:
                raise Refused("Factory restored authentication evidence changed")
    paths, sources = set(), {}
    for item in record["catalog"]:
        if (not isinstance(item, dict) or set(item) != {"source", "path", "mode"}
                or type(item["mode"]) is not int or item["mode"] not in (0o644, 0o755)):
            raise Refused("Malformed fixed host catalog")
        for name in (item["source"], item["path"]):
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_@.-]+(?:/[A-Za-z0-9_@.-]+)*", name) or any(p in (".", "..") for p in name.split("/")):
                raise Refused("Unsafe fixed host catalog path")
        if item["path"] in paths or item["source"] in sources or not digest(source["files"].get(item["source"])):
            raise Refused("Ambiguous fixed host catalog")
        paths.add(item["path"])
        sources[item["source"]] = source["files"][item["source"]]
    if record["host"]["host_source_sha256"] != sha(encoded(sources)):
        raise Refused("Factory host source binding changed")
    for name, path in FIXED.items():
        if (not digest(record["fixed_files"][name]) or source["files"].get(name) != record["fixed_files"][name]
                or sha(read(path, 8 * 1024**2)) != record["fixed_files"][name]):
            raise Refused("Fixed host dispatch code differs from captured factory source")
    return record, initial


def generation(host, record):
    identity(host)
    root = GENERATIONS / host["generation"]
    tree(root)
    meta = js(root / "host-payload.json")
    if (set(meta) != {"schema", "product", "component", "abi", "platform", "version", "catalog_sha256", "source_snapshot_sha256", "host_source_sha256", "files"}
            or type(meta["schema"]) is not int or meta["schema"] != 1 or meta["product"] != "captains-log"
            or meta["component"] != "host" or type(meta["abi"]) is not int or meta["abi"] != 1
            or meta["platform"] != {"os": "linux", "distribution": "rocky", "major": 9, "architecture": "x86_64"}
            or type(meta["platform"]["major"]) is not int or meta["version"] != host["version"]
            or meta["catalog_sha256"] != record["catalog_sha256"] or not digest(meta["source_snapshot_sha256"])
            or meta["host_source_sha256"] != host["host_source_sha256"] or not isinstance(meta["files"], list)
            or len(meta["files"]) != len(record["catalog"])):
        raise Refused("Selected generation metadata differs from its accepted identity")
    expected, sources, total = {}, {}, 0
    for item, fixed in zip(meta["files"], record["catalog"]):
        if (not isinstance(item, dict) or set(item) != {"source", "path", "mode", "bytes", "sha256"}
                or any(item.get(k) != v for k, v in fixed.items()) or type(item["mode"]) is not int
                or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= 8 * 1024**2 or not digest(item["sha256"])):
            raise Refused("Selected generation differs from fixed catalog")
        raw = read(root / item["path"], 8 * 1024**2)
        if len(raw) != item["bytes"] or sha(raw) != item["sha256"]:
            raise Refused("Selected generation content changed before import")
        total += len(raw)
        expected[item["path"]] = item["mode"] & ~0o222
        sources[item["source"]] = item["sha256"]
    if total > 32 * 1024**2 or sha(encoded(sources)) != host["host_source_sha256"]:
        raise Refused("Selected generation source identity changed")
    expected.update({"host-payload.json": 0o444, "staging-receipt.json": 0o444})
    receipt = {"schema": 1, "abi": 1, "archive_sha256": host["generation"], "host_source_sha256": host["host_source_sha256"],
               "source_snapshot_sha256": meta["source_snapshot_sha256"], "archive_verified": True,
               "signature_verified": False, "activated": False, "runtime_executed": False}
    if read(root / "staging-receipt.json") != encoded(receipt) or read(root / "host-payload.json") != encoded(meta):
        raise Refused("Selected generation receipt changed")
    directories = {"."}
    for name in expected: directories.update(str(parent) for parent in Path(name).parents)
    pending, seen = [root], set()
    while pending:
        path = pending.pop()
        name, info = str(path.relative_to(root)), path.lstat()
        if name in seen or len(seen) >= len(expected) + len(directories): raise Refused("Unexpected generation inventory")
        seen.add(name)
        if name in directories and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555:
            pending.extend(path.iterdir())
        elif name not in expected or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != expected[name] or info.st_nlink != 1:
            raise Refused("Generation inventory is writable, linked or unexpected")
        if info.st_uid != OWNER: raise Refused("Generation ownership changed")
    if seen != set(expected) | directories: raise Refused("Incomplete generation inventory")
    if host == record["host"] and meta["source_snapshot_sha256"] != record["source_snapshot_sha256"]:
        raise Refused("Factory generation source changed")
    return root


def current_host(current):
    if (not isinstance(current, dict) or not sequence(current.get("sequence")) or not isinstance(current.get("version"), str)
            or not isinstance(current.get("components"), dict)):
        raise Refused("Accepted current release is missing or malformed")
    return identity(current["components"].get("host"))


def import_guard(event, arguments):
    """Refuse ordinary import side effects; this is not a native-code sandbox."""
    if event == "open":
        _, mode, flags = arguments
        if (isinstance(mode, str) and any(char in mode for char in "wax+")) or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
            raise Refused("Selected module import attempted a file write")
    if (event.startswith(("subprocess.", "socket.", "ctypes.", "os.exec", "os.spawn"))
            or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.remove", "os.rename", "os.mkdir", "os.rmdir",
                         "os.chmod", "os.chown", "os.link", "os.symlink", "os.truncate", "os.utime", "os.putenv", "os.unsetenv",
                         "fcntl.fcntl", "fcntl.ioctl", "shutil.copyfile", "shutil.copymode", "shutil.copystat"}):
        raise Refused("Selected module import attempted a prohibited side effect")


def choose(record, initial, command, arguments, *, selected_probe=False):
    selected = js(ETC / "host-selection.json", 16384)
    if (not isinstance(selected, dict) or set(selected) != {"schema", "generation", "sequence"}
            or type(selected["schema"]) is not int or selected["schema"] != 1
            or not digest(selected["generation"]) or not sequence(selected["sequence"])):
        raise Refused("Invalid selected host generation")
    if not present(STATE / "current.json"):
        if (present(ETC / "configured") or present(STATE / "transaction.json")
                or selected != {"schema": 1, "generation": record["host"]["generation"], "sequence": initial["sequence"]}):
            raise Refused("Accepted state unavailable; refusing candidate import")
        return record["host"], "factory"
    current = js(STATE / "current.json")
    accepted = current_host(current)
    if not present(STATE / "transaction.json"):
        enrolled = js(STATE / "initial-enrollment.json") if present(STATE / "initial-enrollment.json") else js(STATE / "initial-pending.json")
        if (enrolled.get("current") != current or enrolled.get("initial_release_sha256") != record["initial_release_sha256"]
                or accepted != record["host"] or current["sequence"] != initial["sequence"]):
            raise Refused("Current state has no exact initial enrollment binding")
        if selected != {"schema": 1, "generation": accepted["generation"], "sequence": current["sequence"]}:
            raise Refused("Accepted selection differs from enrolled current state")
        return accepted, "accepted"
    transaction = js(STATE / "transaction.json")
    previous = transaction.get("previous")
    old = current_host(previous)
    seq, phase = transaction.get("sequence"), transaction.get("state")
    if not sequence(seq) or seq <= previous["sequence"] or phase not in PHASES or not digest(transaction.get("manifest_sha256")):
        raise Refused("Pending host transaction is malformed")
    stage = Path(transaction.get("release", ""))
    if stage.parent != STATE / "releases" or not re.fullmatch(str(seq) + r"-[A-Za-z0-9_-]{1,100}", stage.name):
        raise Refused("Pending transaction stage is outside fixed storage")
    raw = read(stage / "manifest.json")
    manifest = decode(raw)
    if (sha(raw) != transaction["manifest_sha256"] or manifest.get("sequence") != seq or type(manifest.get("sequence")) is not int
            or manifest.get("product") != "nebulalog" or manifest.get("channel") != "stable" or not isinstance(manifest.get("components"), dict)):
        raise Refused("Pending transaction manifest binding changed")
    components = {**previous["components"], **manifest["components"]}
    candidate = old
    host = manifest["components"].get("host")
    if host is not None:
        artifacts = [item for item in manifest.get("artifacts", []) if isinstance(item, dict) and item.get("name") == host.get("artifact")]
        if len(artifacts) != 1 or host.get("rollback_safe") is not True: raise Refused("Ambiguous candidate host artifact")
        candidate = identity({key: host.get(key) for key in ("version", "host_source_sha256", "abi")} | {"generation": artifacts[0].get("sha256")})
        components["host"] = candidate
    committed = {"sequence": seq, "version": manifest.get("version"), "components": components, "release": str(stage)}
    restored = {**previous, "sequence": seq}
    if current not in (previous, committed, restored): raise Refused("Current state differs from exact transaction outcomes")
    allowed = {"preflight": (previous,), "preflight_failed": (previous,), "preparing": (previous,),
               "activating": (previous,), "checking": (previous, committed), "committed": (committed,),
               "rolled_back": (restored,), "rolling_back": (previous, committed, restored),
               "recovery_required": (previous, committed, restored)}
    if current not in allowed[phase] or transaction.get("finalization") not in (None, "pending", "failed", "complete"):
        raise Refused("Current state or finalization contradicts the transaction phase")
    choices = [{"schema": 1, "generation": old["generation"], "sequence": previous["sequence"]},
               {"schema": 1, "generation": old["generation"], "sequence": seq}]
    if host is not None:
        activation = js(stage / "host-activation.json") if present(stage / "host-activation.json") else None
        if activation is not None:
            pin = {"schema": 1, **old, "sequence": seq, "manifest_sha256": transaction["manifest_sha256"]}
            if (activation.get("coordinator") != pin or activation.get("candidate") != candidate
                    or activation.get("previous_selection") != choices[0] or activation.get("sequence") != seq
                    or activation.get("manifest_sha256") != transaction["manifest_sha256"]
                    or activation.get("state") not in {"prepared", "selecting", "selected", "restoring", "restored"}):
                raise Refused("Host activation journal differs from retained coordinator")
            choices.append({"schema": 1, "generation": candidate["generation"], "sequence": seq})
    if selected not in choices: raise Refused("Selection is unrelated to the protected transaction")
    if command in STAGED and arguments != [str(stage)]: raise Refused("Hook stage differs from protected transaction")
    if phase in {"committed", "rolled_back"} and transaction.get("finalization") == "complete":
        expected = committed if phase == "committed" else restored
        if current != expected or selected != {"schema": 1, "generation": accepted["generation"], "sequence": current["sequence"]}:
            raise Refused("Finalized current and selection are inconsistent")
        return accepted, "accepted"
    if phase == "preflight_failed" and current != previous: raise Refused("Failed preflight changed accepted state")
    if selected_probe:
        return (candidate if selected["generation"] == candidate["generation"] else old), "selected"
    return old, "coordinator"


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if os.geteuid() != OWNER or not arguments or len(arguments) > 128 or sum(len(item) for item in arguments) > 65536:
            raise Refused("Protected fixed host dispatch invocation required")
        command, arguments = arguments[0], arguments[1:]
        if command not in COMMANDS and command not in ADAPTERS and command not in PROBES: raise Refused("Unknown fixed host command")
        if command in PROBES and arguments: raise Refused("Unexpected verification arguments")
        if command in ADAPTERS and len(arguments) != (1 if command in STAGED else 0): raise Refused("Unexpected fixed hook arguments")
        record, initial = factory()
        host, route = choose(record, initial, command, arguments)
        root = generation(host, record)
        # Re-read protected routing after the expensive file scan. Do not import
        # a candidate if a concurrent transaction changed the chosen authority.
        if choose(record, initial, command, arguments) != (host, route): raise Refused("Host routing changed before import")
        if command in PROBES:
            coordinator = host
            host, _ = choose(record, initial, command, arguments, selected_probe=True)
            root = generation(host, record)
            selected = js(ETC / "host-selection.json", 16384)
            if choose(record, initial, command, arguments, selected_probe=True)[0] != host or selected["generation"] != host["generation"]:
                raise Refused("Selected generation changed during verification")
            result = {"schema": 1, "abi": 1, **host, "selection_sequence": selected["sequence"], "verified": True}
            if command == "verify-selected":
                print(json.dumps(result, sort_keys=True))
                return 0
            # Explicit candidate import probe only after the retained coordinator
            # and selected generation have both passed the fixed byte verifier.
            import importlib
            import ctypes  # Load the trusted stdlib's Python handle before blocking dynamic foreign calls.
            sys.path.insert(0, str(root / "lib"))
            sys.addaudithook(import_guard)
            origins, hashes = {}, {}
            for name in PROBE_MODULES:
                module = importlib.import_module(name)
                expected = root / "lib" / (name.replace(".", "/") + ".py")
                if Path(module.__file__) != expected: raise Refused("Selected Python module origin differs")
                origins[name], hashes[name] = str(expected), sha(read(expected, 8 * 1024**2))
            print(json.dumps({**result, "coordinator_verified": True, "coordinator_generation": coordinator["generation"],
                              "origins": origins, "module_sha256": hashes, "runtime_imported": True}, sort_keys=True))
            return 0
        os.environ.update(NEBULALOG_HOST_GENERATION=host["generation"], NEBULALOG_HOST_SOURCE_SHA256=host["host_source_sha256"],
                          NEBULALOG_HOST_ABI="1", NEBULALOG_HOST_ROUTE=route)
        sys.path.insert(0, str(root / "lib"))
        if command in ADAPTERS:
            sys.argv = [command, *arguments]
            from nebulalog_adapters.cli import main as adapter_main
            return adapter_main()
        module, prefix = COMMANDS[command]
        sys.argv = [command, *prefix, *arguments]
        runpy.run_module("nebulalog_manager." + module, run_name="__main__", alter_sys=False)
        return 0
    except (Refused, OSError, ValueError, KeyError, TypeError, AttributeError):
        print('{"ok":false,"status":"refused","message":"Host generation or recovery evidence is unavailable or inconsistent; maintenance must remain active."}', file=sys.stderr)
        return 1


if __name__ == "__main__": raise SystemExit(main())
