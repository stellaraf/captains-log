"""Journal-bound host selection primitives for the signed-release manager.

Changing this selection record does not restart a service, switch an executable
launcher, accept health checks or commit an update. The manager must coordinate
those separate effects with the fixed boot dispatcher and runtime lifecycle.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from . import host_dispatch as dispatch, host_payload as payload
from .common import Refused, atomic_json, locked, require_linux_root

SELECTION = Path("/etc/nebulalog/host-selection.json")
PHASES = {"prepared", "selecting", "selected", "restoring", "restored"}


def selection():
    value = dispatch.protected_json(SELECTION, 16384)
    if (not isinstance(value, dict) or set(value) != {"schema", "generation", "sequence"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or not isinstance(value["generation"], str) or not payload.SHA256.fullmatch(value["generation"])
            or type(value["sequence"]) is not int or not 0 <= value["sequence"] < 2**63):
        raise Refused("Factory-enrolled host selection is missing or malformed")
    return value


def _record_path(stage):
    return stage / "host-activation.json"


@contextmanager
def _selection_lock():
    require_linux_root()
    payload._trusted_tree(dispatch.STATE)
    lock = dispatch.STATE / "host-selection.lock"
    if lock.exists() or lock.is_symlink():
        payload.read_regular(lock, 0, trusted=True)
    with locked(lock):
        payload.read_regular(lock, 0, trusted=True)
        yield


def _candidate_identity(manifest):
    host = manifest["components"].get("host")
    if (not isinstance(host, dict) or host.get("rollback_safe") is not True or host.get("abi") != payload.ABI
            or type(host.get("abi")) is not int or not isinstance(host.get("artifact"), str)
            or not isinstance(host.get("host_source_sha256"), str) or not payload.SHA256.fullmatch(host["host_source_sha256"])
            or not isinstance(host.get("version"), str) or not payload.VERSION.fullmatch(host["version"])
            or not isinstance(manifest.get("artifacts"), list)):
        raise Refused("Host selection requires an explicitly reversible compatible host component")
    artifacts = [item for item in manifest["artifacts"] if isinstance(item, dict) and item.get("name") == host["artifact"]]
    if len(artifacts) != 1:
        raise Refused("Host component artifact is ambiguous")
    artifact = artifacts[0]
    payload.safe_source_path(artifact["name"])
    if ("/" in artifact["name"] or not artifact["name"].endswith(".tar") or len(artifact["name"]) > 128
            or type(artifact.get("bytes")) is not int or not 0 < artifact["bytes"] <= payload.MAX_ARCHIVE
            or not isinstance(artifact.get("sha256"), str) or not payload.SHA256.fullmatch(artifact["sha256"])):
        raise Refused("Host component artifact must be a direct bounded stage member")
    return ({"generation": artifact["sha256"], "version": host["version"],
             "host_source_sha256": host["host_source_sha256"], "abi": host["abi"]}, artifact)


def _candidate(stage, manifest):
    identity, artifact = _candidate_identity(manifest)
    stream, _ = payload.open_regular(stage / artifact["name"], payload.MAX_ARCHIVE, trusted=True)
    stream.close()
    evidence = payload.verify_archive(stage / artifact["name"], expected_sha256=artifact.get("sha256"),
                                      expected_host_source_sha256=identity["host_source_sha256"])
    if evidence["archive_bytes"] != artifact["bytes"]:
        raise Refused("Host component archive differs from its manifest length")
    candidate = dispatch.generation_info(artifact["sha256"])
    if candidate != identity:
        raise Refused("Staged host generation differs from the manager release")
    return candidate


def _load(stage, *, verify_candidate=False):
    transaction, manifest = dispatch.transaction_binding(stage)
    record = dispatch.protected_json(_record_path(stage), 16384)
    fields = {"schema", "state", "sequence", "manifest_sha256", "coordinator", "previous_selection", "candidate"}
    if (not isinstance(record, dict) or set(record) != fields or type(record["schema"]) is not int or record["schema"] != 1
            or not isinstance(record["state"], str) or record["state"] not in PHASES or record["sequence"] != transaction["sequence"]
            or type(record["sequence"]) is not int or record["manifest_sha256"] != transaction["manifest_sha256"]
            or not isinstance(record["coordinator"], dict) or type(record["coordinator"].get("schema")) is not int
            or type(record["coordinator"].get("abi")) is not int or type(record["coordinator"].get("sequence")) is not int
            or record["coordinator"] != dispatch.coordinator_pin(stage) or not isinstance(record["previous_selection"], dict)):
        raise Refused("Host selection journal no longer matches its coordinator transaction")
    prior = record["previous_selection"]
    if (set(prior) != {"schema", "generation", "sequence"} or type(prior["schema"]) is not int or prior["schema"] != 1
            or prior["generation"] != record["coordinator"]["generation"] or type(prior["sequence"]) is not int
            or prior["sequence"] != transaction["previous"].get("sequence")
            or not isinstance(record["candidate"], dict) or type(record["candidate"].get("abi")) is not int
            or record["candidate"] != _candidate_identity(manifest)[0]):
        raise Refused("Host selection journal identities changed")
    # Recovery must require the retained previous generation, but must remain
    # possible when candidate files or its archive are damaged or unavailable.
    if verify_candidate and record["candidate"] != _candidate(stage, manifest):
        raise Refused("Host candidate changed after preparation")
    return transaction, record


def prepare(stage: Path):
    with _selection_lock():
        transaction, manifest = dispatch.transaction_binding(stage)
        if transaction["state"] != "preparing":
            raise Refused("Host preparation requires the manager preparing phase")
        pin = dispatch.coordinator_pin(stage)
        prior = selection()
        if prior["generation"] != pin["generation"] or prior["sequence"] != transaction["previous"].get("sequence"):
            raise Refused("Host selection differs from the previously accepted manager state")
        value = {"schema": 1, "state": "prepared", "sequence": transaction["sequence"],
                 "manifest_sha256": transaction["manifest_sha256"], "coordinator": pin,
                 "previous_selection": prior, "candidate": _candidate(stage, manifest)}
        path = _record_path(stage)
        if path.exists() or path.is_symlink():
            _, existing = _load(stage, verify_candidate=True)
            if existing != value:
                raise Refused("An existing host operation cannot be replaced")
            return existing
        atomic_json(path, value)
        return value


def _candidate_selection(record):
    return {"schema": 1, "generation": record["candidate"]["generation"], "sequence": record["sequence"]}


def _restored_selection(record):
    # Preserve the rejected release high-water sequence while restoring code.
    return {"schema": 1, "generation": record["coordinator"]["generation"], "sequence": record["sequence"]}


def select_candidate(stage: Path):
    with _selection_lock():
        transaction, record = _load(stage, verify_candidate=True)
        if transaction["state"] != "activating" or record["state"] not in {"prepared", "selecting", "selected"}:
            raise Refused("Host selection requires the manager activating phase")
        current, candidate = selection(), _candidate_selection(record)
        if current not in (record["previous_selection"], candidate) or record["state"] == "selected" and current != candidate:
            raise Refused("Host selection changed outside this operation")
        record["state"] = "selecting"
        atomic_json(_record_path(stage), record)
        atomic_json(SELECTION, candidate)
        record["state"] = "selected"
        atomic_json(_record_path(stage), record)
        return {"state": "selected", "selection": candidate, "coordinator": record["coordinator"],
                "runtime_activated": False, "committed": False}


def restore_previous(stage: Path):
    with _selection_lock():
        path = _record_path(stage)
        if not path.exists() and not path.is_symlink():
            transaction, manifest = dispatch.transaction_binding(stage)
            if transaction["state"] not in {"rolling_back", "rolled_back", "recovery_required"}:
                raise Refused("Host restoration requires the manager rollback or recovery phase")
            pin = dispatch.coordinator_pin(stage)
            prior = {"schema": 1, "generation": pin["generation"], "sequence": transaction["previous"]["sequence"]}
            if selection() != prior:
                raise Refused("Missing preparation journal cannot authorize a changed host selection")
            # Power loss or failed preparation may precede the first host journal.
            # Only the still-selected accepted previous generation can be adopted
            # for recovery; this does not authorize candidate activation.
            atomic_json(path, {"schema": 1, "state": "restoring", "sequence": transaction["sequence"],
                              "manifest_sha256": transaction["manifest_sha256"], "coordinator": pin,
                              "previous_selection": prior, "candidate": _candidate_identity(manifest)[0]})
        transaction, record = _load(stage)
        if transaction["state"] not in {"rolling_back", "rolled_back", "recovery_required"}:
            raise Refused("Host restoration requires the manager rollback or recovery phase")
        current, restored = selection(), _restored_selection(record)
        if current not in (record["previous_selection"], _candidate_selection(record), restored):
            raise Refused("An unrelated host selection cannot be overwritten during recovery")
        record["state"] = "restoring"
        atomic_json(_record_path(stage), record)
        atomic_json(SELECTION, restored)
        record["state"] = "restored"
        atomic_json(_record_path(stage), record)
        return {"state": "restored", "selection": restored, "coordinator": record["coordinator"],
                "runtime_recovered": False, "committed": False}


def advance_unchanged(stage: Path):
    """Advance accepted host high-water during an OCI-only component transaction."""
    with _selection_lock():
        transaction, manifest = dispatch.transaction_binding(stage)
        if "host" in manifest["components"] or transaction["state"] not in {"checking", "committed", "rolling_back", "rolled_back", "recovery_required"}:
            raise Refused("Unchanged host advancement requires an OCI acceptance or recovery phase")
        pin = dispatch.coordinator_pin(stage)
        previous = {"schema": 1, "generation": pin["generation"], "sequence": transaction["previous"]["sequence"]}
        accepted = {**previous, "sequence": transaction["sequence"]}
        if selection() not in (previous, accepted):
            raise Refused("Unrelated host selection cannot be advanced")
        atomic_json(SELECTION, accepted)
        return accepted


def recovery_decision(stage: Path):
    """Return a decision under lock; never clears maintenance or starts code."""
    with _selection_lock():
        transaction, record = _load(stage)
        current = selection()
        if current not in (record["previous_selection"], _candidate_selection(record), _restored_selection(record)):
            raise Refused("Host recovery requires reconciliation of an unrelated selection")
        if transaction["state"] == "committed":
            action = "verify_candidate_then_finalize" if current == _candidate_selection(record) else "reconcile_committed_selection"
        elif transaction["state"] == "rolled_back" and current == _restored_selection(record):
            action = "verify_previous_then_finalize"
        else:
            action = "restore_previous_with_pinned_coordinator"
        return {"action": action, "coordinator": record["coordinator"], "maintenance_must_remain": True,
                "runtime_recovered": False, "committed": False}
