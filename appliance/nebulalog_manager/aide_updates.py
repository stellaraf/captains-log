"""Exact authorized host changes over an immutable original AIDE enrollment.

Callers own the manager and update locks. This module takes the remaining
firstboot/runtime/baseline locks and never releases maintenance or commits a
release. --update builds a separate database; a fresh --check must pass before
the current database is replaced. Reports, old/new databases and chain entries
are retained privately on the enrolled encrypted filesystem.
"""
from __future__ import annotations

import contextlib
import contextvars
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from . import aide, host_activation, host_dispatch, host_payload
from .aide_report import parse_report, render_config
from .common import Refused
from .host_job_storage import digest, exact, strict_json
from .host_operations import digest_value, uuid_value

MAX_CHAIN = 1000
MAX_PATHS = 4096
_UNSET = object()
_LOCK_CONTEXT = contextvars.ContextVar('aide_update_lock_context', default=None)
CONFIGURATION = Path("/var/lib/nebulalog/configuration")


def _refuse(reason):
    raise Refused("aide_update_" + reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _immutable(manager, path, value, identity):
    if aide.present(path):
        if manager.records.read(path, identity) != value:
            _refuse("retained_evidence_changed")
    else:
        manager.records.write(path, value, identity)
    manager._sync(path, path.parent)


@contextlib.contextmanager
def _locked(manager):
    if _LOCK_CONTEXT.get() is not None:
        _refuse('nested_integrity_mutation')
    identity = manager.guard()
    state = identity.root / "manager/aide"
    for path in (state, state / "reports", state / "tmp"):
        manager.records.directory(path, identity)
    with contextlib.ExitStack() as stack:
        for path in manager.lock_paths(identity):
            for parent in path.parents:
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != aide.ROOT_UID or info.st_mode & 0o022:
                    _refuse("unsafe_lock")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != aide.ROOT_UID
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                _refuse("unsafe_lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _refuse("coordination_busy")
        if manager.guard() != identity:
            _refuse("identity_changed")
        token = _LOCK_CONTEXT.set((manager, state, identity))
        try:
            yield state, identity
        finally:
            _LOCK_CONTEXT.reset(token)


@contextlib.contextmanager
def _evidence_locked(manager):
    """Reuse only this context's held locks for nested read-only evidence."""
    active = _LOCK_CONTEXT.get()
    if active is not None:
        owner, state, identity = active
        if manager is not None and manager is not owner or owner.guard() != identity:
            _refuse('retained_evidence_lock_owner_changed')
        yield owner, state, identity
    else:
        owner = manager or aide.Aide()
        with _locked(owner) as (state, identity):
            yield owner, state, identity


def _metadata(path):
    """Hash Linux ACL and SELinux xattrs as well as every other xattr.

    A missing/unsupported xattr API refuses. No empty metadata fallback is used.
    ACLs are system.posix_acl_access/default and the SELinux label is
    security.selinux, all covered by the full name/value hash inventory.
    """
    before = path.lstat()
    values = {}
    for name in sorted(os.listxattr(path, follow_symlinks=False)):
        if not isinstance(name, str) or len(name) > 255 or len(values) >= 128:
            _refuse("metadata_limit")
        raw = os.getxattr(path, name, follow_symlinks=False)
        if len(raw) > 1024 * 1024:
            _refuse("metadata_limit")
        values[name] = _sha(raw)
    after = path.lstat()
    if not host_payload.same_file(before, after):
        _refuse("metadata_changed_during_read")
    return {"xattrs_sha256": digest(values), "acl_sha256": digest({key: value for key, value in values.items() if key.startswith("system.posix_acl_")}),
            "selinux_sha256": digest({key: value for key, value in values.items() if key == "security.selinux"})}


def _measure(manager, item, *, preserved=False):
    path = Path(item["path"])
    customer = preserved and path.is_relative_to(CONFIGURATION)
    if customer:
        host_payload._trusted_tree(CONFIGURATION)
        for parent in path.parents:
            if not parent.is_relative_to(CONFIGURATION):
                break
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                _refuse("unsafe_managed_path")
    else:
        host_payload._trusted_tree(path.parent)
    before = path.lstat()
    if (not customer and before.st_uid != aide.ROOT_UID) or before.st_mode & 0o7022:
        _refuse("unsafe_managed_path")
    if stat.S_ISDIR(before.st_mode):
        value = {"kind": "directory", "uid": before.st_uid, "gid": before.st_gid, "mode": stat.S_IMODE(before.st_mode)}
    elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
        if customer:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not host_payload.same_file(before, opened) or not 0 <= opened.st_size <= host_payload.MAX_FILE:
                    _refuse("managed_path_changed_during_read")
                raw = stream.read(host_payload.MAX_FILE + 1)
                if len(raw) != opened.st_size or not host_payload.same_file(opened, os.fstat(stream.fileno())):
                    _refuse("managed_path_changed_during_read")
        else:
            raw = manager.reader(path, maximum=host_payload.MAX_FILE)
        value = {"kind": "file", "uid": before.st_uid, "gid": before.st_gid, "mode": stat.S_IMODE(before.st_mode), "bytes": len(raw), "sha256": _sha(raw)}
    else:
        _refuse("unsafe_managed_path")
    metadata = _metadata(path)
    if not host_payload.same_file(before, path.lstat()):
        _refuse("managed_path_changed_during_read")
    return value, metadata


def _description(value, *, directory=False, preserved=False):
    fields = {"kind", "uid", "gid", "mode"} | (set() if directory else {"bytes", "sha256"})
    exact(value, fields)
    if (value["kind"] != ("directory" if directory else "file")
            or type(value["uid"]) is not int or not 0 <= value["uid"] < 2**32 or not preserved and value["uid"] != aide.ROOT_UID
            or type(value["gid"]) is not int or not 0 <= value["gid"] < 2**32 or not preserved and value["gid"] != 0
            or type(value["mode"]) is not int or (value["mode"] & ~0o755 if preserved else value["mode"] not in (0o444, 0o555, 0o600, 0o644))):
        _refuse("invalid_file_description")
    if not directory:
        digest_value(value["sha256"])
        if type(value["bytes"]) is not int or not 0 <= value["bytes"] <= host_payload.MAX_FILE:
            _refuse("invalid_file_description")


def _bound_plan(manager, stage, path, *, preparing):
    stage, path = Path(stage), Path(path)
    if path == stage / 'ordinary-boot-plan.json':
        from . import ordinary_boot
        return ordinary_boot.bound_integrity_plan(manager, stage, path, preparing=preparing)
    from . import kernel_boot, kernel_retention, kernel_retention_generation
    if path.parent == stage and kernel_boot.NAME.fullmatch(path.name):
        return kernel_boot.bound_integrity_plan(manager, stage, path, preparing=preparing)
    if path == stage / kernel_retention.INTEGRITY:
        return kernel_retention.bound_integrity_plan(manager, stage, path, preparing=preparing)
    if path.parent == stage and kernel_retention_generation.INTEGRITY_NAME.fullmatch(path.name):
        return kernel_retention_generation.bound_integrity_plan(manager, stage, path, preparing=preparing)
    if path.parent == stage and kernel_retention.RESUME_NAME.fullmatch(path.name):
        return kernel_retention.bound_resume_integrity_plan(manager, stage, path, preparing=preparing)
    if path == stage / "os-integrity-plan.json":
        from . import os_payload
        return os_payload.bound_integrity_plan(manager, stage, path, preparing=preparing)
    if path != stage / "host-runtime-plan.json":
        _refuse("unexpected_plan_path")
    transaction, release = host_dispatch.transaction_binding(stage)
    allowed = {"preflight"} if preparing else {"checking", "rolling_back", "rolled_back", "committed", "recovery_required"}
    if transaction["state"] not in allowed:
        _refuse("wrong_transaction_phase")
    pin = host_dispatch.coordinator_pin(stage)
    candidate, _ = host_activation._candidate_identity(release)
    host_dispatch.generation_info(candidate["generation"])
    raw = manager.reader(path, maximum=host_payload.MAX_SOURCE_MANIFEST, private=True)
    plan = strict_json(raw)
    exact(plan, {"schema", "sequence", "manifest_sha256", "coordinator_generation", "candidate_generation", "files", "generation_additions", "selection", "preserved", "migration_only"})
    if (type(plan["schema"]) is not int or plan["schema"] != 1
            or type(plan["sequence"]) is not int or plan["sequence"] != transaction["sequence"]
            or plan["manifest_sha256"] != transaction["manifest_sha256"]
            or plan["coordinator_generation"] != pin["generation"] or plan["candidate_generation"] != candidate["generation"]):
        _refuse("plan_transaction_mismatch")
    # These are the fixed ABI resource destinations, never destinations supplied
    # by a downloaded hook or generic patch list.
    targets = {str(Path("/etc/systemd/system") / name) for name in host_payload.UNITS}
    targets |= {str(Path("/usr/share/nebulalog/quadlet-templates") / name) for name in host_payload.QUADLETS}
    targets |= {"/usr/share/nebulalog/httpd/nebulalog.conf.in", "/usr/share/nebulalog/keycloak/realm.json"}
    targets |= {"/etc/containers/systemd/nebulalog-" + name + ".container" for name in ("api", "ingest", "postgresql", "clickhouse", "keycloak")}
    paths = [item.get("path") for item in plan["files"] if isinstance(item, dict)]
    if set(paths) not in (targets, targets | {"/etc/httpd/conf.d/nebulalog.conf"}) or len(paths) != len(set(paths)):
        _refuse("unexpected_runtime_destination")
    for item in plan["files"]:
        exact(item, {"path", "before", "after"})
        for phase in ("before", "after"):
            _description(item[phase])
            if item[phase]["mode"] != 0o644:
                _refuse("invalid_runtime_mode")
    selection = plan["selection"]
    exact(selection, {"path", "before", "after", "restored"})
    if selection["path"] != str(host_activation.SELECTION):
        _refuse("unexpected_selection")
    for phase, generation, sequence in (("before", pin["generation"], transaction["previous"]["sequence"]),
                                        ("after", candidate["generation"], transaction["sequence"]),
                                        ("restored", pin["generation"], transaction["sequence"])):
        encoded = (json.dumps({"schema": 1, "generation": generation, "sequence": sequence}, sort_keys=True, indent=2) + "\n").encode()
        expected = {"kind": "file", "uid": aide.ROOT_UID, "gid": 0, "mode": 0o600, "bytes": len(encoded), "sha256": _sha(encoded)}
        if selection[phase] != expected:
            _refuse("selection_description_changed")
    root = host_payload.GENERATIONS / candidate["generation"]
    additions = plan["generation_additions"]
    if (not isinstance(additions, list) or not 0 < len(additions) <= MAX_PATHS
            or {item.get("path") for item in additions} != {str(path) for path in (root, *root.rglob("*"))}):
        _refuse("generation_inventory_changed")
    for item in additions:
        _description({key: value for key, value in item.items() if key != "path"}, directory=item.get("kind") == "directory")
    migration = {"share/defaults/" + name for name in host_payload.DEFAULTS} | {"share/templates/keycloak/realm.json", "share/templates/quadlet/nebulalog.network"} | {name for name in host_payload.CATALOG_BY_PATH if name.startswith("bin/")}
    if plan["migration_only"] != sorted(migration):
        _refuse("fixed_policy_inventory_changed")
    for name in migration:
        old = manager.reader(host_payload.GENERATIONS / pin["generation"] / name, maximum=host_payload.MAX_FILE)
        new = manager.reader(root / name, maximum=host_payload.MAX_FILE)
        if old != new:
            _refuse("fixed_policy_change_requires_migration")
    if not isinstance(plan["preserved"], list) or len(plan["preserved"]) > MAX_PATHS:
        _refuse("preserved_inventory_invalid")
    for item in plan["preserved"]:
        _description({key: value for key, value in item.items() if key != "path"}, preserved=True)
    all_paths = paths + [selection["path"]] + [item["path"] for item in additions + plan["preserved"]]
    if len(all_paths) != len(set(all_paths)) or any(not isinstance(item, str) or not item.startswith("/") or str(Path(os.path.normpath(item))) != item for item in all_paths):
        _refuse("overlapping_or_invalid_paths")
    return plan, _sha(raw)


def _snapshot(manager, plan, phase, retained=None):
    if plan.get('kind') == 'ordinary-boot-v1':
        from . import ordinary_boot
        return ordinary_boot.integrity_snapshot(manager, plan, phase, retained)
    if plan.get('kind') == 'rocky-kernel-retention-resume-v1':
        from . import kernel_retention
        return kernel_retention.resume_integrity_snapshot(manager, plan, phase, retained)
    if plan.get('kind') == 'kernel-boot-v1':
        from . import kernel_boot
        return kernel_boot.integrity_snapshot(manager, plan, phase, retained)
    if plan.get('kind') == 'rocky-kernel-retention-v1':
        from . import kernel_retention
        return kernel_retention.integrity_snapshot(manager, plan, phase, retained)
    if plan.get('kind') == 'kernel-install-v1':
        from . import kernel_integrity
        return kernel_integrity.snapshot(manager, plan, phase, retained)
    if plan.get("kind") == "os-payload-v1":
        from . import os_payload
        return os_payload.integrity_snapshot(manager, plan, phase, retained)
    items = [{"path": item["path"], **item["before" if phase == "prepare" else "after" if phase == "forward" else "before"]} for item in plan["files"]]
    selection_phase = {"prepare": "before", "forward": "after", "rollback": "restored"}[phase]
    items += [{"path": plan["selection"]["path"], **plan["selection"][selection_phase]}]
    items += plan["generation_additions"] + plan["preserved"]
    values = {}
    preserved_paths = {item["path"] for item in plan["preserved"]}
    for item in items:
        description, metadata = _measure(manager, item, preserved=item["path"] in preserved_paths)
        if description != {key: value for key, value in item.items() if key != "path"}:
            _refuse("live_file_not_authorized")
        if retained is not None and retained.get(item["path"]) != metadata:
            _refuse("acl_xattrs_or_selinux_changed")
        values[item["path"]] = metadata
    return values


def _parse_update(result, database_in, database_out):
    report = strict_json(result.stdout)
    if (not isinstance(report, dict) or report.get("new_database") != str(database_out)
            or not isinstance(report.get("databases"), dict)
            or set(report["databases"]) != {str(database_in), str(database_out)}):
        _refuse("database_report_binding_failed")
    # Reuse the pinned check parser for all counts, diagnostics, grouped paths,
    # version and exit-mask validation after validating the update-only fields.
    normalized = {key: value for key, value in report.items() if key != "new_database"}
    normalized["databases"] = {str(database_in): report["databases"][str(database_in)]}
    measured = parse_report(json.dumps(normalized), result.stderr, result.code, "check", str(database_in))
    return report, measured


def _allowed_report(report, plan, phase):
    if plan.get('kind') == 'ordinary-boot-v1':
        from . import ordinary_boot
        return ordinary_boot.allowed_integrity_report(report, plan, phase)
    if plan.get('kind') == 'rocky-kernel-retention-resume-v1':
        from . import kernel_retention
        return kernel_retention.allowed_resume_integrity_report(report, plan, phase)
    if plan.get('kind') == 'kernel-boot-v1':
        from . import kernel_boot
        return kernel_boot.allowed_integrity_report(report, plan, phase)
    if plan.get('kind') == 'rocky-kernel-retention-v1':
        from . import kernel_retention
        return kernel_retention.allowed_integrity_report(report, plan, phase)
    if plan.get('kind') == 'kernel-install-v1':
        from . import kernel_integrity
        return kernel_integrity.allowed_report(report, plan, phase)
    if plan.get("kind") == "os-payload-v1":
        from . import os_payload
        return os_payload.allowed_integrity_report(report, plan, phase)
    additions = {item["path"] for item in plan["generation_additions"]}
    changes = set() if phase == "prepare" else {item["path"] for item in plan["files"]} | {plan["selection"]["path"]}
    if set(report.get("added", {})) - additions or report.get("removed") or set(report.get("changed", {})) - changes:
        _refuse("unrelated_integrity_change")


def _config(manager, state, identity, policy, token, database_in, database_out):
    path = state / "authorized/artifacts" / (token + ".conf")
    manager._write_bytes(path, render_config(policy, str(database_in), str(database_out)).encode(), identity)
    result = manager.runner(["/usr/sbin/restorecon", "-R", str(state)], tmpdir=state / "tmp")
    if result.code or result.stderr.strip():
        _refuse("labels_not_applied")
    result = manager.runner([str(aide.BINARY), "--config=" + str(path), "--config-check"], tmpdir=state / "tmp")
    if result.code or result.stderr.strip():
        _refuse("invalid_configuration")
    return path


def _scan(manager, state, identity, config, action, facts, database_in, database_out=None):
    token = str(uuid.uuid4())
    attempt = {"schema": 1, "id": str(uuid.uuid4()), "observed_at": manager.clock(), "state": "running", "report_id": None}
    manager.records.write(state / "last-attempt.json", attempt, identity)
    record = {"schema": 1, "id": token, "action": action, "observed_at": manager.clock(), "facts_sha256": digest(facts),
              "database_sha256": manager._database(database_in, identity)[1], "state": "error", "exit_code": None,
              "stdout": "", "stderr": ""}
    # Retain even invalid output before refusing it. Never include raw output in
    # an exception or in the public status surface.
    report_path = state / "reports" / (token + ".json")
    if len(list((state / "reports").iterdir())) >= aide.MAX_REPORTS:
        _refuse("report_storage_full")
    try:
        result = manager.runner([str(aide.BINARY), "--config=" + str(config), "--" + action], tmpdir=state / "tmp", timeout=3600)
        record.update(exit_code=result.code, stdout=result.stdout, stderr=result.stderr)
        raw, measured = (_parse_update(result, database_in, database_out) if action == "update"
                         else (strict_json(result.stdout), parse_report(result.stdout, result.stderr, result.code, "check", str(database_in))))
        record.update(measured)
    finally:
        record["observed_at"] = manager.clock()
        _immutable(manager, report_path, record, identity)
        # Only the caller's full context checks may publish a completed check.
        # A failure after a scan must not leave the previous clean check current.
        attempt.update(state="error", observed_at=manager.clock())
        manager.records.write(state / "last-attempt.json", attempt, identity)
    return record, raw


def _pointer(entry):
    return {"id": entry["id"], "sha256": digest(entry)}


def _chain(manager, state, identity, base, *, head_override=_UNSET, proposed=None):
    root = state / "authorized"
    head_path = root / "head.json"
    if head_override is not _UNSET:
        pointer = head_override
    elif not aide.present(head_path):
        if aide.present(root / "entries") and any((root / "entries").iterdir()):
            _refuse("chain_head_missing")
        return None, base["database_sha256"], None
    else:
        pointer = manager.records.read(head_path, identity)
    if pointer is None:
        return None, base["database_sha256"], None
    head, next_db, latest = pointer, None, None
    seen = set()
    while pointer is not None:
        exact(pointer, {"id", "sha256"})
        token, expected = uuid_value(pointer["id"]), digest_value(pointer["sha256"])
        if token in seen or len(seen) >= MAX_CHAIN:
            _refuse("baseline_chain_invalid")
        seen.add(token)
        entry_path = root / "entries" / (token + ".json")
        if proposed is not None and proposed.get("id") == token:
            entry = proposed
            if aide.present(entry_path) and manager.records.read(entry_path, identity) != entry:
                _refuse("retained_evidence_changed")
        else:
            entry = manager.records.read(entry_path, identity)
        exact(entry, {"schema", "id", "installation_id", "original_enrollment_sha256", "previous", "previous_database_sha256", "database_sha256", "input", "output", "update_report", "check_report", "prepared", "direction", "plan_sha256", "accepted_at"})
        if (type(entry["schema"]) is not int or entry["schema"] != 1 or entry["id"] != token or digest(entry) != expected
                or entry["installation_id"] != identity.installation_id or entry["original_enrollment_sha256"] != digest(base)
                or entry["direction"] not in {"forward", "rollback"} or next_db is not None and entry["database_sha256"] != next_db):
            _refuse("baseline_chain_invalid")
        for key, hash_key in (("input", "previous_database_sha256"), ("output", "database_sha256")):
            uuid_value(entry[key])
            if manager._database(root / "artifacts" / (entry[key] + ".db.gz"), identity)[1] != entry[hash_key]:
                _refuse("retained_database_changed")
        prepared = _read_bound(manager, root / "prepared", entry["prepared"], identity)
        if (prepared["plan_sha256"] != entry["plan_sha256"] or prepared["original_enrollment_sha256"] != digest(base)
                or entry["prepared"] != _pointer(prepared)):
            _refuse("prepared_plan_changed")
        preparation_report = _read_bound(manager, state / "reports", prepared["report"], identity)
        parse_report(preparation_report["stdout"], preparation_report["stderr"], preparation_report["exit_code"], "check", str(state / "aide.db.gz"))
        _allowed_report(strict_json(preparation_report["stdout"]), prepared["plan"], "prepare")
        if (preparation_report["database_sha256"] != prepared["database_sha256"]
                or preparation_report["facts_sha256"] != digest(base["facts"])):
            _refuse("retained_preparation_invalid")
        update = _read_bound(manager, state / "reports", entry["update_report"], identity)
        checked = _read_bound(manager, state / "reports", entry["check_report"], identity)
        raw, _ = _parse_update(aide.Result(update["exit_code"], update["stdout"], update["stderr"]), root / "artifacts" / (entry["input"] + ".db.gz"), root / "artifacts" / (entry["output"] + ".db.gz"))
        _allowed_report(raw, prepared["plan"], entry["direction"])
        measured = parse_report(checked["stdout"], checked["stderr"], checked["exit_code"], "check", str(root / "artifacts" / (entry["output"] + ".db.gz")))
        if (measured["state"] != "clean" or checked["database_sha256"] != entry["database_sha256"]
                or checked["facts_sha256"] != digest(base["facts"]) or update["facts_sha256"] != digest(base["facts"])
                or update["database_sha256"] != entry["previous_database_sha256"]):
            _refuse("retained_check_invalid")
        if latest is None:
            latest = entry
        next_db, pointer = entry["previous_database_sha256"], entry["previous"]
    if next_db != base["database_sha256"]:
        _refuse("original_baseline_binding_failed")
    return head, latest["database_sha256"], latest


def _read_bound(manager, directory, pointer, identity):
    exact(pointer, {"id", "sha256"})
    value = manager.records.read(directory / (uuid_value(pointer["id"]) + ".json"), identity)
    if digest(value) != digest_value(pointer["sha256"]):
        _refuse("retained_record_changed")
    return value


def _pending(manager, state, identity):
    path = state / "authorized/pending.json"
    if not aide.present(path):
        return None
    value = manager.records.read(path, identity)
    phase = value.get("state") if isinstance(value, dict) else None
    if phase == "complete":
        exact(value, {"schema", "state", "entry", "database_sha256"})
        digest_value(value["database_sha256"])
    elif phase in {"scanning", "ready"}:
        fields = {"schema", "state", "id", "prepared", "direction", "previous", "previous_database_sha256"}
        exact(value, fields | ({"entry", "proposed_entry", "database_sha256"} if phase == "ready" else set()))
        uuid_value(value["id"])
        digest_value(value["previous_database_sha256"])
        if value["direction"] not in {"forward", "rollback"}:
            _refuse("invalid_pending_journal")
    else:
        _refuse("invalid_pending_journal")
    if type(value["schema"]) is not int or value["schema"] != 1:
        _refuse("invalid_pending_journal")
    for key in ("entry", "prepared", "previous"):
        if key in value and value[key] is not None:
            exact(value[key], {"id", "sha256"})
            uuid_value(value[key]["id"])
            digest_value(value[key]["sha256"])
    return value


def active_enrollment(manager, state, identity, base_receipt):
    """Called only after Aide validates its immutable original enrollment."""
    pending = _pending(manager, state, identity)
    if pending is not None and pending.get("state") != "complete":
        _refuse("acceptance_pending_recovery_required")
    head, database_sha, _ = _chain(manager, state, identity, base_receipt)
    if pending is not None and (pending.get("entry") != head or pending.get("database_sha256") != database_sha):
        _refuse("completed_journal_changed")
    if manager._database(state / "aide.db.gz", identity)[1] != database_sha:
        _refuse("current_database_changed")
    return {**base_receipt, "database_sha256": database_sha}


def retained_plan_acceptance(stage, plan_path, *, manager=None, expected=None, historical=False):
    """Verify retained scan/database evidence for one immutable OS plan.

    Historical evidence proves its published chain prefix, never a clean live
    host. Current evidence additionally requires membership in the active chain
    and its exact live database. Neither path writes a journal or a database.
    """
    stage, plan_path = Path(stage), Path(plan_path)
    if historical and expected is None:
        _refuse('historical_acceptance_reference_required')
    if expected is not None:
        exact(expected, {'entry', 'original_enrollment_sha256', 'plan_sha256',
                         'prepared_sha256', 'database_sha256'})
        exact(expected['entry'], {'id', 'sha256'})
        uuid_value(expected['entry']['id'])
        digest_value(expected['entry']['sha256'])
        for key in ('original_enrollment_sha256', 'plan_sha256', 'prepared_sha256', 'database_sha256'):
            digest_value(expected[key])
    with _evidence_locked(manager) as (owner, state, identity):
        ordinary = stage.parent == identity.root / 'manager/boot-integrity'
        if (not stage.is_absolute() or stage.parent not in (identity.root / 'manager/os-updates', identity.root / 'manager/boot-integrity')
                or not re.fullmatch(r'[a-f0-9]{32}', stage.name) or stage.resolve() != stage
                or plan_path.parent != stage or plan_path.is_symlink()):
            _refuse('retained_acceptance_stage_changed')
        owner.records.directory(stage, identity)
        raw = owner._bytes(plan_path, identity)
        plan, plan_sha = strict_json(raw), _sha(raw)
        if ordinary and (plan_path.name != 'ordinary-boot-plan.json' or plan.get('kind') != 'ordinary-boot-v1'
                         or plan.get('stage') != str(stage)):
            _refuse('retained_acceptance_ordinary_owner_changed')
        base = owner._initial_enrollment(state, identity)
        root = state / 'authorized'
        if historical:
            pointer = expected['entry']
            # Only an actual retained entry is eligible. An uncommitted ready
            # journal's in-memory proposal cannot serve as published proof.
            owner.records.read(root / 'entries' / (pointer['id'] + '.json'), identity)
            _chain(owner, state, identity, base, head_override=pointer)
        else:
            active_enrollment(owner, state, identity, base)
            pointer, _, _ = _chain(owner, state, identity, base)
        seen = set()
        while pointer is not None:
            exact(pointer, {'id', 'sha256'})
            token = uuid_value(pointer['id'])
            if token in seen or len(seen) >= MAX_CHAIN:
                _refuse('retained_acceptance_chain_limit')
            seen.add(token)
            entry = _read_bound(owner, root / 'entries', pointer, identity)
            prepared = _read_bound(owner, root / 'prepared', entry['prepared'], identity)
            matches = (entry['direction'] == 'forward' and entry['plan_sha256'] == plan_sha
                       and prepared['release'] == str(stage) and prepared['plan'] == plan
                       and prepared['plan_sha256'] == plan_sha)
            if matches:
                proof = {'entry': pointer, 'original_enrollment_sha256': digest(base),
                         'plan_sha256': plan_sha, 'prepared_sha256': digest(prepared),
                         'database_sha256': entry['database_sha256']}
                if expected is not None and proof != expected:
                    _refuse('retained_acceptance_reference_changed')
                return proof
            if historical:
                # A historical caller names this exact accepted generation;
                # finding some older matching plan is not equivalent authority.
                break
            pointer = entry['previous']
        _refuse('retained_plan_acceptance_missing')


def accepted_plan_history(*, manager=None, allow_pending_owner=None):
    """Read verified published ancestry without converting pending work to proof.

    A normal read requires the live DB to match the completed published chain.
    An explicit ordinary-boot owner may inspect its own interrupted forward
    CAS, including a copied output, but receives the pending state separately.
    The caller must establish that owner's place in its immutable ancestry.
    This function never writes, copies a database, or reports the host clean.
    """
    with _evidence_locked(manager) as (owner, state, identity):
        base = owner._initial_enrollment(state, identity)
        pending = _pending(owner, state, identity)
        pending_prepared = None
        if pending is None or pending['state'] == 'complete':
            active_enrollment(owner, state, identity, base)
        else:
            stage = Path(allow_pending_owner) if allow_pending_owner is not None else None
            if (stage is None or not stage.is_absolute() or stage.resolve() != stage
                    or stage.parent != identity.root / 'manager/boot-integrity'
                    or not re.fullmatch(r'[a-f0-9]{32}', stage.name)):
                _refuse('history_pending_owner_required')
            owner.records.directory(stage, identity)
            prepared = _read_bound(owner, state / 'authorized/prepared', pending['prepared'], identity)
            pending_prepared = prepared
            if (prepared['release'] != str(stage) or pending['direction'] != 'forward'
                    or prepared['plan'].get('kind') != 'ordinary-boot-v1'
                    or prepared['original_enrollment_sha256'] != digest(base)
                    or pending['previous_database_sha256'] != prepared['database_sha256']):
                _refuse('history_pending_owner_changed')
            raw = owner._bytes(stage / 'ordinary-boot-plan.json', identity)
            if strict_json(raw) != prepared['plan'] or _sha(raw) != prepared['plan_sha256']:
                _refuse('history_pending_plan_changed')
            head, checksum, _ = _chain(owner, state, identity, base)
            current = owner._database(state / 'aide.db.gz', identity)[1]
            if pending['state'] == 'scanning':
                if head != pending['previous'] or checksum != pending['previous_database_sha256'] or current != checksum:
                    _refuse('history_pending_database_changed')
            elif pending['state'] == 'ready':
                entry = pending['proposed_entry']
                if (_pointer(entry) != pending['entry'] or entry['id'] != pending['id']
                        or entry['prepared'] != pending['prepared'] or entry['direction'] != 'forward'
                        or entry['previous'] != pending['previous']
                        or entry['previous_database_sha256'] != pending['previous_database_sha256']
                        or entry['database_sha256'] != pending['database_sha256']):
                    _refuse('history_pending_entry_changed')
                _chain(owner, state, identity, base, head_override=pending['entry'], proposed=entry)
                if (head not in (pending['previous'], pending['entry'])
                        or current not in (entry['previous_database_sha256'], entry['database_sha256'])
                        or head == pending['entry'] and current != entry['database_sha256']):
                    _refuse('history_pending_database_changed')
            else:
                _refuse('history_pending_state_changed')
        pointer, checksum, _ = _chain(owner, state, identity, base)
        head, rows, seen = pointer, [], set()
        while pointer is not None:
            token = uuid_value(pointer['id'])
            if token in seen or len(seen) >= MAX_CHAIN:
                _refuse('history_chain_limit')
            seen.add(token)
            entry = _read_bound(owner, state / 'authorized/entries', pointer, identity)
            prepared = _read_bound(owner, state / 'authorized/prepared', entry['prepared'], identity)
            rows.append({'entry_ref': pointer, 'entry': entry, 'prepared': prepared, 'plan': prepared['plan']})
            pointer = entry['previous']
        return {'original_enrollment': base, 'head': head, 'database_sha256': checksum,
                'current_database_sha256': owner._database(state / 'aide.db.gz', identity)[1],
                'pending': pending, 'pending_prepared': pending_prepared, 'history': list(reversed(rows))}


def _directories(manager, state, identity):
    for path in (state / "authorized", state / "authorized/artifacts", state / "authorized/entries", state / "authorized/prepared"):
        manager.records.directory(path, identity, create=True)


def _prepared(manager, state, identity, stage, plan, plan_sha):
    key = digest({"release": str(stage), "sequence": plan["sequence"], "manifest_sha256": plan["manifest_sha256"]})
    pointer_path = state / "authorized" / (key + ".json")
    if not aide.present(pointer_path):
        return pointer_path, None
    pointer = manager.records.read(pointer_path, identity)
    record = _read_bound(manager, state / "authorized/prepared", pointer, identity)
    if record["plan_sha256"] != plan_sha or record["plan"] != plan or record["release"] != str(stage):
        _refuse("prepared_plan_changed")
    return pointer_path, record


def _resume_kernel_pending(manager, state, identity, base, stage, plan_path, plan, plan_sha):
    """Resolve only historical CAS evidence owned by an exact boot resume.

    This does not copy or update a database, nor publish a clean scan. The
    following ordinary preparation and acceptance must measure the new boot's
    exact qualified GRUB change and reject all unrelated filesystem drift.
    """
    if plan.get('kind') != 'kernel-boot-v1' or plan.get('phase') not in {'postboot', 'resume'}:
        _refuse('kernel_resume_plan_required')
    from . import kernel_boot
    prior, prior_sha = kernel_boot.integrity_predecessor(stage, plan_path)
    allowed = {'postboot': {'arm'}, 'resume': {'commit', 'resume'}}
    if prior.get('kind') != 'kernel-boot-v1' or prior.get('phase') not in allowed[plan['phase']]:
        _refuse('kernel_resume_commit_required')
    _, prepared = _prepared(manager, state, identity, stage, prior, prior_sha)
    if prepared is None or prepared['original_enrollment_sha256'] != digest(base):
        _refuse('kernel_resume_preparation_required')
    pending = _pending(manager, state, identity)
    if pending is None or pending['state'] == 'complete':
        return
    if (pending.get('prepared') != _pointer(prepared) or pending.get('direction') != 'forward'
            or pending.get('previous_database_sha256') != prepared['database_sha256']):
        _refuse('kernel_resume_different_acceptance_pending')
    metadata = _snapshot(manager, plan, 'prepare')
    root = state / 'authorized'
    archive = {'schema': 1, 'resume_plan_sha256': plan_sha, 'prior_plan_sha256': prior_sha, 'pending': pending}
    _immutable(manager, root / 'artifacts' / (pending['id'] + '.' + plan_sha + '.kernel-resume.json'), archive, identity)
    if pending['state'] == 'ready':
        # The existing historical-retention helper validates every old report,
        # proposed chain link and preserved input/output database. It may only
        # retain a head for a database that was already copied before reboot.
        _retain_interrupted_forward(manager, state, identity, base, pending)
    head, checksum, _ = _chain(manager, state, identity, base)
    if (manager._database(state / 'aide.db.gz', identity)[1] != checksum
            or pending['state'] == 'scanning' and (head != pending['previous'] or checksum != pending['previous_database_sha256'])
            or _snapshot(manager, plan, 'prepare', metadata) != metadata):
        _refuse('kernel_resume_historical_database_changed')
    manager.records.write(root / 'pending.json', {'schema': 1, 'state': 'complete', 'entry': head, 'database_sha256': checksum}, identity)
    manager._sync(root / 'pending.json', root, state)


def _resume_retention_pending(manager, state, identity, base, stage, plan_path, plan, plan_sha):
    """Retain only an exact ancestor's interrupted CAS, then require new scans.

    The immutable erase authorization binds the original preparation. Compound
    ancestry also covers a reboot before an intermediate plan was prepared.
    No unpublished database is copied and no clean result is produced here.
    """
    from . import kernel_retention
    if plan.get('kind') != kernel_retention.RESUME_KIND:
        _refuse('retention_resume_plan_required')
    origin = kernel_retention.resume_origin(stage, plan_path)
    _, original = _prepared(manager, state, identity, stage, origin['integrity'], origin['integrity_sha256'])
    if (original is None or original['original_enrollment_sha256'] != digest(base)
            or digest(original) != origin['prepared_sha256']):
        _refuse('retention_resume_original_preparation_changed')
    pending = _pending(manager, state, identity)
    if pending is None or pending['state'] == 'complete':
        return
    prior, prior_sha, prior_path = plan, plan_sha, Path(plan_path)
    seen = set()
    while True:
        if prior_sha in seen or len(seen) >= MAX_CHAIN:
            _refuse('retention_resume_ancestry_limit')
        seen.add(prior_sha)
        _, prepared = _prepared(manager, state, identity, stage, prior, prior_sha)
        if prepared is not None:
            if prepared['original_enrollment_sha256'] != digest(base):
                _refuse('retention_resume_preparation_changed')
            if pending.get('prepared') == _pointer(prepared):
                break
        if prior.get('kind') != kernel_retention.RESUME_KIND:
            _refuse('retention_resume_different_acceptance_pending')
        prior, prior_sha = kernel_retention.resume_integrity_predecessor(stage, prior_path)
        if prior.get('kind') == kernel_retention.RESUME_KIND:
            prior_path = Path(stage) / ('kernel-retention-resume-' + prior['id'] + '-plan.json')
        elif prior != origin['integrity'] or prior_sha != origin['integrity_sha256']:
            _refuse('retention_resume_original_plan_changed')
    if (pending.get('direction') != 'forward'
            or pending.get('previous_database_sha256') != prepared['database_sha256']):
        _refuse('retention_resume_different_acceptance_pending')
    metadata = _snapshot(manager, plan, 'prepare')
    root = state / 'authorized'
    archive = {'schema': 1, 'resume_plan_sha256': plan_sha, 'prior_plan_sha256': prior_sha,
               'original_preparation_sha256': origin['prepared_sha256'], 'pending': pending}
    _immutable(manager, root / 'artifacts' / (pending['id'] + '.' + plan_sha + '.retention-resume.json'), archive, identity)
    if pending['state'] == 'ready':
        _retain_interrupted_forward(manager, state, identity, base, pending)
    head, checksum, _ = _chain(manager, state, identity, base)
    if (manager._database(state / 'aide.db.gz', identity)[1] != checksum
            or pending['state'] == 'scanning' and (head != pending['previous'] or checksum != pending['previous_database_sha256'])
            or _snapshot(manager, plan, 'prepare', metadata) != metadata):
        _refuse('retention_resume_historical_database_changed')
    manager.records.write(root / 'pending.json', {'schema': 1, 'state': 'complete', 'entry': head, 'database_sha256': checksum}, identity)
    manager._sync(root / 'pending.json', root, state)


def _resume_ordinary_pending(manager, state, identity, base, stage, plan_path, plan, plan_sha):
    """Resolve only this generation or an exact ordinary ancestor's old CAS."""
    from . import ordinary_boot
    if plan.get('kind') != ordinary_boot.KIND or plan.get('original_enrollment_sha256') != digest(base):
        _refuse('ordinary_boot_enrollment_changed')
    pending = _pending(manager, state, identity)
    if pending is None or pending['state'] == 'complete':
        return
    prior, prior_sha, prior_stage, prior_path = plan, plan_sha, Path(stage), Path(plan_path)
    seen = set()
    while True:
        if prior_sha in seen or len(seen) >= MAX_CHAIN:
            _refuse('ordinary_boot_ancestry_limit')
        seen.add(prior_sha)
        if prior.get('kind') != ordinary_boot.KIND or prior.get('original_enrollment_sha256') != digest(base):
            _refuse('ordinary_boot_ancestor_changed')
        _, prepared = _prepared(manager, state, identity, prior_stage, prior, prior_sha)
        if prepared is not None:
            if prepared['original_enrollment_sha256'] != digest(base):
                _refuse('ordinary_boot_preparation_changed')
            if pending.get('prepared') == _pointer(prepared):
                break
        predecessor = ordinary_boot.integrity_predecessor(prior_stage, prior_path)
        if predecessor is None:
            _refuse('ordinary_boot_different_acceptance_pending')
        prior, prior_sha = predecessor
        prior_stage = Path(prior['stage'])
        prior_path = prior_stage / ordinary_boot.PLAN
    if (pending.get('direction') != 'forward'
            or pending.get('previous_database_sha256') != prepared['database_sha256']):
        _refuse('ordinary_boot_different_acceptance_pending')
    metadata = _snapshot(manager, plan, 'prepare')
    root = state / 'authorized'
    archive = {'schema': 1, 'resume_stage': str(stage), 'resume_plan_sha256': plan_sha,
               'prior_stage': str(prior_stage), 'prior_plan_sha256': prior_sha, 'pending': pending}
    _immutable(manager, root / 'artifacts' / (pending['id'] + '.' + plan_sha + '.ordinary-boot-resume.json'), archive, identity)
    if pending['state'] == 'ready':
        _retain_interrupted_forward(manager, state, identity, base, pending)
    head, checksum, _ = _chain(manager, state, identity, base)
    if (manager._database(state / 'aide.db.gz', identity)[1] != checksum
            or pending['state'] == 'scanning' and (head != pending['previous'] or checksum != pending['previous_database_sha256'])
            or _snapshot(manager, plan, 'prepare', metadata) != metadata):
        _refuse('ordinary_boot_historical_database_changed')
    manager.records.write(root / 'pending.json', {'schema': 1, 'state': 'complete', 'entry': head, 'database_sha256': checksum}, identity)
    manager._sync(root / 'pending.json', root, state)


def prepare(manager, stage, plan_path):
    with _locked(manager) as (state, identity):
        plan, plan_sha = _bound_plan(manager, stage, plan_path, preparing=True)
        base = manager._initial_enrollment(state, identity)
        if plan.get('kind') == 'kernel-boot-v1' and plan.get('phase') in {'postboot', 'resume'}:
            manager._monitor(identity, state, base)
            _resume_kernel_pending(manager, state, identity, base, stage, plan_path, plan, plan_sha)
        if plan.get('kind') == 'rocky-kernel-retention-resume-v1':
            manager._monitor(identity, state, base)
            _resume_retention_pending(manager, state, identity, base, stage, plan_path, plan, plan_sha)
        if plan.get('kind') == 'ordinary-boot-v1':
            manager._monitor(identity, state, base)
            _resume_ordinary_pending(manager, state, identity, base, stage, plan_path, plan, plan_sha)
        enrolled = active_enrollment(manager, state, identity, base)
        policy = manager._monitor(identity, state, enrolled)
        metadata = _snapshot(manager, plan, "prepare")
        _directories(manager, state, identity)
        pointer_path, existing = _prepared(manager, state, identity, stage, plan, plan_sha)
        if existing is not None and existing["metadata"] != metadata:
            _refuse("prepared_metadata_changed")
        token = str(uuid.uuid4())
        config = _config(manager, state, identity, policy, token, state / "aide.db.gz", state / "authorized/artifacts" / (token + ".unused.db.gz"))
        report, raw = _scan(manager, state, identity, config, "check", enrolled["facts"], state / "aide.db.gz")
        _allowed_report(raw, plan, "prepare")
        if (manager._database(state / "aide.db.gz", identity)[1] != enrolled["database_sha256"]
                or _snapshot(manager, plan, "prepare", metadata) != metadata or manager._monitor(identity, state, enrolled) != policy):
            _refuse("preparation_context_changed")
        if existing is None:
            record = {"schema": 1, "id": token, "release": str(stage), "plan": plan, "plan_sha256": plan_sha,
                      "metadata": metadata, "original_enrollment_sha256": digest(base), "database_sha256": enrolled["database_sha256"],
                      "report": _pointer(report), "prepared_at": manager.clock()}
            _immutable(manager, state / "authorized/prepared" / (token + ".json"), record, identity)
            _immutable(manager, pointer_path, _pointer(record), identity)
        _publish_check(manager, state, identity, report)
        return {"ok": True, "plan_sha256": plan_sha, "baseline_changed": False}


def _replace_current(manager, state, identity, expected, content):
    """CAS under the cooperating manager/update/baseline locks; never --init."""
    path = state / "aide.db.gz"
    if manager._database(path, identity)[1] != expected:
        _refuse("current_database_cas_failed")
    fd, temporary = tempfile.mkstemp(prefix=".authorized-aide-", dir=state)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if manager._database(path, identity)[1] != expected:
            _refuse("current_database_cas_failed")
        os.replace(temporary, path)
        manager._sync(path, state)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _publish_check(manager, state, identity, record):
    summary = {key: record[key] for key in ("schema", "id", "action", "observed_at", "facts_sha256", "database_sha256", "state", "exit_code", "counts")}
    summary["report_sha256"] = digest(record)
    manager.records.write(state / "last-result.json", summary, identity)
    manager.records.write(state / "last-attempt.json", {"schema": 1, "id": str(uuid.uuid4()), "observed_at": record["observed_at"], "state": "complete", "report_id": record["id"]}, identity)


def accept(manager, stage, plan_path, *, direction="forward"):
    if direction not in ("forward", "rollback"):
        _refuse("invalid_direction")
    with _locked(manager) as (state, identity):
        plan, plan_sha = _bound_plan(manager, stage, plan_path, preparing=False)
        base = manager._initial_enrollment(state, identity)
        policy = manager._monitor(identity, state, base)
        _, prepared = _prepared(manager, state, identity, stage, plan, plan_sha)
        if prepared is None or prepared["original_enrollment_sha256"] != digest(base):
            _refuse("preparation_required")
        metadata = prepared["metadata"]
        _snapshot(manager, plan, direction, metadata)
        root = state / "authorized"
        pending_path = root / "pending.json"
        pending = _pending(manager, state, identity)
        # A ready journal may have atomically replaced the DB but not its head.
        # Resolve this exact retained entry first, never adopt an arbitrary DB.
        if pending is not None and pending.get("state") == "ready":
            if pending["prepared"] != _pointer(prepared):
                _refuse("different_acceptance_pending")
            if pending["direction"] == direction:
                _complete(manager, state, identity, base, pending, plan, metadata, policy)
            elif pending["direction"] == "forward" and direction == "rollback":
                _retain_interrupted_forward(manager, state, identity, base, pending)
            else:
                _refuse("different_acceptance_pending")
        head, database_sha, latest = _chain(manager, state, identity, base)
        if manager._database(state / "aide.db.gz", identity)[1] != database_sha:
            _refuse("current_database_changed")
        pending = _pending(manager, state, identity)
        abandoning_forward = pending is not None and pending["state"] in {"scanning", "ready"} and pending["direction"] == "forward" and direction == "rollback" and pending["prepared"] == _pointer(prepared)
        if pending is not None and pending.get("state") not in {"complete", "scanning"} and not abandoning_forward:
            _refuse("invalid_pending_journal")
        if pending is not None and pending["state"] == "complete" and (pending["entry"] != head or pending["database_sha256"] != database_sha):
            _refuse("completed_journal_changed")
        if pending is not None and pending["state"] == "scanning" and (pending.get("prepared") != _pointer(prepared) or pending.get("direction") != direction and not abandoning_forward or pending.get("previous") != head or pending.get("previous_database_sha256") != database_sha):
            _refuse("different_acceptance_pending")
        if abandoning_forward:
            _immutable(manager, root / "artifacts" / (pending["id"] + ".interrupted-forward.json"), pending, identity)
        # Idempotent repeats perform a fresh check; they never rewrite a baseline
        # or absorb new inode/ctime drift after its completed acceptance.
        if latest is not None and latest["prepared"] == _pointer(prepared) and latest["direction"] == direction:
            token = str(uuid.uuid4())
            config = _config(manager, state, identity, policy, token, state / "aide.db.gz", root / "artifacts" / (token + ".unused.db.gz"))
            report, _ = _scan(manager, state, identity, config, "check", base["facts"], state / "aide.db.gz")
            if report["state"] != "clean" or _snapshot(manager, plan, direction, metadata) != metadata or manager._monitor(identity, state, base) != policy:
                _refuse("accepted_baseline_no_longer_clean")
            if manager._database(state / "aide.db.gz", identity)[1] != database_sha:
                _refuse("current_database_changed")
            _publish_check(manager, state, identity, report)
            manager._sync(state / "aide.db.gz", root / "head.json", pending_path, root, state)
            return {"ok": True, "direction": direction, "plan_sha256": plan_sha, "database_sha256": database_sha, "baseline_changed": False}
        token, input_token, output_token = (str(uuid.uuid4()) for _ in range(3))
        pending = {"schema": 1, "state": "scanning", "id": token, "prepared": _pointer(prepared), "direction": direction,
                   "previous": head, "previous_database_sha256": database_sha}
        manager.records.write(pending_path, pending, identity)
        input_path, output_path = (root / "artifacts" / (item + ".db.gz") for item in (input_token, output_token))
        manager._write_bytes(input_path, manager._database(state / "aide.db.gz", identity)[0], identity)
        config = _config(manager, state, identity, policy, token, input_path, output_path)
        report, raw = _scan(manager, state, identity, config, "update", base["facts"], input_path, output_path)
        _allowed_report(raw, plan, direction)
        _, output_sha = manager._database(output_path, identity)
        if manager._database(input_path, identity)[1] != database_sha or _snapshot(manager, plan, direction, metadata) != metadata:
            _refuse("scan_context_changed")
        check_config = _config(manager, state, identity, policy, str(uuid.uuid4()), output_path, root / "artifacts" / (token + ".unused.db.gz"))
        checked, _ = _scan(manager, state, identity, check_config, "check", base["facts"], output_path)
        if (checked["state"] != "clean" or manager._database(output_path, identity)[1] != output_sha
                or _snapshot(manager, plan, direction, metadata) != metadata or manager._monitor(identity, state, base) != policy):
            _refuse("new_baseline_not_clean")
        entry = {"schema": 1, "id": token, "installation_id": identity.installation_id, "original_enrollment_sha256": digest(base),
                 "previous": head, "previous_database_sha256": database_sha, "database_sha256": output_sha,
                 "input": input_token, "output": output_token, "update_report": _pointer(report), "check_report": _pointer(checked),
                 "prepared": _pointer(prepared), "direction": direction, "plan_sha256": plan_sha, "accepted_at": manager.clock()}
        # Journal owns the full proposed entry before an immutable entry appears,
        # so an interruption at the first head write has unambiguous recovery.
        pending.update(state="ready", entry=_pointer(entry), proposed_entry=entry, database_sha256=output_sha)
        manager.records.write(pending_path, pending, identity)
        _complete(manager, state, identity, base, pending, plan, metadata, policy)
        return {"ok": True, "direction": direction, "plan_sha256": plan_sha, "database_sha256": output_sha, "baseline_changed": True}


def _complete(manager, state, identity, base, pending, plan, metadata, policy):
    root = state / "authorized"
    entry = pending["proposed_entry"]
    if (_pointer(entry) != pending["entry"] or entry["id"] != pending["id"] or entry["prepared"] != pending["prepared"]
            or entry["previous"] != pending["previous"] or entry["direction"] != pending["direction"]
            or entry["database_sha256"] != pending["database_sha256"] or entry["previous_database_sha256"] != pending["previous_database_sha256"]):
        _refuse("pending_entry_changed")
    head_path = root / "head.json"
    current_head = manager.records.read(head_path, identity) if aide.present(head_path) else None
    if current_head not in (entry["previous"], pending["entry"]):
        _refuse("baseline_head_cas_failed")
    # Validate the full proposed chain in memory before either a database or
    # head write, including retained original and preparation evidence.
    _chain(manager, state, identity, base, head_override=pending["entry"], proposed=entry)
    # Reparse all retained scan evidence before any recovery write. A ready
    # journal alone is not acceptance of its proposed database.
    output_path = root / "artifacts" / (uuid_value(entry["output"]) + ".db.gz")
    output_data, output_sha = manager._database(output_path, identity)
    input_path = root / "artifacts" / (uuid_value(entry["input"]) + ".db.gz")
    if output_sha != entry["database_sha256"] or manager._database(input_path, identity)[1] != entry["previous_database_sha256"]:
        _refuse("pending_database_changed")
    report = _read_bound(manager, state / "reports", entry["update_report"], identity)
    raw, _ = _parse_update(aide.Result(report["exit_code"], report["stdout"], report["stderr"]), input_path, output_path)
    _allowed_report(raw, plan, entry["direction"])
    config = _config(manager, state, identity, policy, str(uuid.uuid4()), output_path, root / "artifacts" / (str(uuid.uuid4()) + ".unused.db.gz"))
    checked, _ = _scan(manager, state, identity, config, "check", base["facts"], output_path)
    if (checked["state"] != "clean" or manager._database(output_path, identity)[1] != output_sha
            or _snapshot(manager, plan, entry["direction"], metadata) != metadata or manager._monitor(identity, state, base) != policy):
        _refuse("recovery_baseline_not_clean")
    current_sha = manager._database(state / "aide.db.gz", identity)[1]
    if current_sha not in (entry["previous_database_sha256"], output_sha):
        _refuse("current_database_cas_failed")
    if current_sha != output_sha:
        _replace_current(manager, state, identity, entry["previous_database_sha256"], output_data)
    _immutable(manager, root / "entries" / (uuid_value(entry["id"]) + ".json"), entry, identity)
    manager.records.write(head_path, pending["entry"], identity)
    # _chain fully validates the just-installed link and its entire ancestry.
    if _chain(manager, state, identity, base)[:2] != (pending["entry"], output_sha):
        _refuse("accepted_chain_changed")
    _publish_check(manager, state, identity, checked)
    complete = {"schema": 1, "state": "complete", "entry": pending["entry"], "database_sha256": output_sha}
    manager.records.write(root / "pending.json", complete, identity)
    manager._sync(state / "aide.db.gz", head_path, root / "pending.json", root, state)


def _retain_interrupted_forward(manager, state, identity, base, pending):
    """Keep historical CAS evidence while a same-plan rollback is still pending.

    This publishes no clean status/completion. If the exact proposed forward DB
    is already current, retain its historical verified chain link so the next
    --update can compare restored files against it. If CAS had not happened,
    retain the prior head. Both paths require the fresh rollback scan/check.
    """
    entry = pending["proposed_entry"]
    if (_pointer(entry) != pending["entry"] or entry["id"] != pending["id"]
            or entry["prepared"] != pending["prepared"] or entry["direction"] != "forward"
            or entry["previous"] != pending["previous"] or entry["database_sha256"] != pending["database_sha256"]
            or entry["previous_database_sha256"] != pending["previous_database_sha256"]):
        _refuse("pending_entry_changed")
    _chain(manager, state, identity, base, head_override=pending["entry"], proposed=entry)
    root = state / "authorized"
    head = manager.records.read(root / "head.json", identity) if aide.present(root / "head.json") else None
    current_sha = manager._database(state / "aide.db.gz", identity)[1]
    if head not in (pending["previous"], pending["entry"]):
        _refuse("baseline_head_cas_failed")
    if current_sha == pending["database_sha256"]:
        _immutable(manager, root / "entries" / (entry["id"] + ".json"), entry, identity)
        manager.records.write(root / "head.json", pending["entry"], identity)
    elif current_sha != pending["previous_database_sha256"] or head != pending["previous"]:
        _refuse("current_database_cas_failed")
