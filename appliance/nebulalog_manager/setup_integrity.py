"""Bounded first-boot console actions; no shell, arbitrary paths or auto-enrollment."""
from __future__ import annotations

from datetime import datetime, timezone
import re
import subprocess

from .common import Refused
from .host_job_storage import PrivateRecords, StorageIdentity, strict_json
from .host_operations import uuid_value, digest_value


class _ConsoleBoundary(Refused):
    """End the action loop if its privileged terminal/session boundary changes."""


def _private_json(path, *, device=None):
    from .aide import protected_bytes
    return strict_json(protected_bytes(path, maximum=1024 * 1024, private=True, device=device))


def _present(path):
    return path.exists() or path.is_symlink()


def _integrity_state_exists(manager):
    root = manager.paths.data / "manager"
    return _present(root / "aide") or _present(root / "aide-enrollment.json")


def resume_runtime(manager, config):
    """Reuse only installation-bound, complete runtime evidence without rewriting it.

    None means a not-yet-provisioned/owned partial runtime can use the existing
    guarded provisioning workflow. AIDE state prevents any such fallback.
    """
    from .firstboot import RUNTIME_CHECKS, _digest, validate_config
    from .aide import RUNTIME_STAGES
    validate_config(config)
    ready_path = manager.paths.bootstrap / "runtime-ready.json"
    if not _present(ready_path):
        if _integrity_state_exists(manager):
            raise Refused("Runtime readiness is missing while file-integrity state exists; automatic reprovisioning is refused")
        return None
    try:
        gate = manager.gate()
        if gate.get("host_ready") is not True or gate.get("setup_complete") is True:
            raise Refused("The unfinished installation is not ready for console resumption")
        installation = uuid_value(gate.get("installation_id"))
        identity = StorageIdentity(installation, manager.paths.data, manager.paths.data.stat().st_dev)
        PrivateRecords().directory(identity.root, identity)
        journal = _private_json(manager.journal_path)
        ready = _private_json(ready_path)
        state_path = identity.root / "configuration/bootstrap/runtime-state.json"
        state = _private_json(state_path, device=identity.device)
        setup = _private_json(identity.root / "configuration/bootstrap/setup.json", device=identity.device)
        if (type(journal) is not dict or journal.get("installation_id") != installation
                or journal.get("config_sha256") != _digest(config)
                or type(ready) is not dict or type(ready.get("schema")) is not int or ready["schema"] != 1
                or ready.get("installation_id") != installation or ready.get("state") != "runtime-ready"
                or type(ready.get("checks")) is not dict or not all(ready["checks"].get(key) is True for key in RUNTIME_CHECKS)
                or type(state) is not dict or type(state.get("schema")) is not int or state["schema"] != 1
                or state.get("installation_id") != installation or type(state.get("completed")) is not list
                or any(type(stage) is not str or stage not in RUNTIME_STAGES for stage in state["completed"])
                or len(state["completed"]) != len(set(state["completed"]))
                or state.get("active_stage") not in RUNTIME_STAGES | {None}
                or type(setup) is not dict or setup.get("installation_id") != installation
                or setup.get("hostname") != config["hostname"] or setup.get("baseline") != config["baseline"]):
            raise Refused("Saved runtime evidence does not match the current installation and settings")
        if (state.get("active_stage") is not None or set(state["completed"]) != RUNTIME_STAGES
                or state.get("identity_initialized") is not True):
            if _integrity_state_exists(manager):
                raise Refused("Runtime provisioning is incomplete while file-integrity state exists; automatic reprovisioning is refused")
            return None
        # Display only the enrolled hostname and a validated public certificate hash.
        # A saved receipt cannot inject a URL, credential or terminal escape sequence.
        url = "https://" + config["hostname"]
        if ready.get("https_url", url) != url:
            raise Refused("Saved runtime HTTPS address differs from the enrolled hostname")
        fingerprint = ready.get("tls_certificate_sha256")
        if fingerprint is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
            raise Refused("Saved runtime certificate evidence is invalid")
        result = {"schema": 1, "state": "runtime-ready", "setup_complete": False,
                  "installation_id": installation, "https_url": url}
        if fingerprint is not None:
            result["tls_certificate_sha256"] = fingerprint
        return result
    except (OSError, ValueError, TypeError, KeyError):
        raise Refused("Saved runtime evidence is unavailable or invalid; automatic reprovisioning is refused") from None


def pending_console(manager):
    from .console import local_console, sealed_state
    local_console()
    if sealed_state(manager) != "pending":
        raise Refused("Interactive file-integrity setup requires this unfinished sealed appliance console")


def prerequisites(manager):
    """Read existing reviewed selection; never invent a policy or SCAP approval."""
    from .aide import runtime_storage, sha
    from .baseline import validate_policy
    from .firstboot import BASELINES
    identity = runtime_storage()
    gate = manager.gate()
    if identity.root != manager.paths.data or gate.get("installation_id") != identity.installation_id:
        raise Refused("File-integrity runtime identity differs from setup")
    setup = _private_json(identity.root / "configuration/bootstrap/setup.json", device=identity.device)
    path = identity.root / "configuration/security-policy.json"
    from .aide import protected_bytes
    raw = protected_bytes(path, maximum=1024 * 1024, private=True, device=identity.device)
    selected = strict_json(raw)
    if (type(setup) is not dict or setup.get("baseline") not in BASELINES
            or setup.get("installation_id") != identity.installation_id or type(selected) is not dict
            or selected.get("installation_id") != identity.installation_id or selected.get("baseline") != setup["baseline"]):
        raise Refused("File integrity requires the installation's reviewed security policy")
    validate_policy(selected)
    return {"installation_id": identity.installation_id, "baseline": setup["baseline"], "policy_sha256": sha(raw)}


def _answer(read, prompt):
    value = read(prompt)
    if not isinstance(value, str) or len(value) > 128 or any(ord(char) < 32 for char in value):
        raise Refused("Enter one displayed action or the full review digest")
    return value.strip()


def _when(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise Refused("File-integrity timestamp is unavailable")
    return parsed.astimezone(timezone.utc).isoformat()


def _counts(value):
    keys = ("total", "added", "removed", "changed")
    if (type(value) is not dict or set(value) != set(keys)
            or any(type(value[key]) is not int or not 0 <= value[key] < 2**63 for key in keys)
            or not value["total"]):
        raise Refused("File-integrity counts are unavailable")
    return ", ".join(f"{key}: {value[key]}" for key in keys)


def _show_check(result, write):
    state = result.get("state")
    if state not in ("clean", "differences", "error", "interrupted"):
        raise Refused("File-integrity result is unavailable")
    observed = _when(result["observed_at"])
    identifier = uuid_value(result["id"])
    details = _counts(result["counts"]) if state in ("clean", "differences") else None
    write(f"Last completed observation: {state.upper()} at {observed}" if state in ("clean", "differences") else f"Latest attempt: {state.upper()} at {observed}")
    write("Report/attempt ID: " + identifier)
    if details:
        write(details)
    if result.get("stale"):
        write("This observation is stale. Run CHECK for fresh evidence.")
    if state == "clean":
        write("This records a clean scan at the displayed time; it is not continuous integrity or a compliance pass.")
    else:
        write("Review is required. The enrolled baseline has not been replaced; final setup cannot use this result.")


def _show_review(value, write):
    facts, report = value["facts"], value["report"]
    # Validate every displayed dynamic value before emitting any of the review.
    candidate = uuid_value(value["candidate_id"])
    confirmation = digest_value(value["confirmation"])
    database = digest_value(value["database_sha256"])
    source = digest_value(facts["source_snapshot_sha256"])
    policy = digest_value(facts["policy_sha256"])
    installation = uuid_value(facts["installation_id"])
    created = _when(value["created_at"])
    if type(facts["source_dirty"]) is not bool or type(value["enrolled"]) is not bool:
        raise Refused("File-integrity candidate identity is unavailable")
    package = facts["aide_package"]
    if not isinstance(package, str) or not re.fullmatch(r"aide-0\.19\.2-[A-Za-z0-9._+]+\.x86_64", package):
        raise Refused("File-integrity checker identity is unavailable")
    if report.get("state") != "clean" or type(report.get("exit_code")) is not int or report["exit_code"] != 0:
        raise Refused("The original candidate verification is not clean")
    observed, report_id, counts = _when(report["observed_at"]), uuid_value(report["id"]), _counts(report["counts"])
    write("\nReview initial file-integrity baseline")
    write("Installation: " + installation + "\nCandidate: " + candidate + "\nCreated: " + created)
    write("Checker: " + package + "\nCaptured source SHA-256: " + source)
    write("Captured source includes local changes: " + ("yes" if facts["source_dirty"] else "no"))
    write("AIDE policy SHA-256: " + policy + "\nDatabase SHA-256: " + database)
    write("Original clean verification: " + observed + "\nReport ID: " + report_id + "\n" + counts)
    write("Scope: boot files, system code, host settings and canonical encrypted configuration.")
    write("Live databases, container storage, logs and specifically defined mutable setup evidence are excluded.")
    write("Accept only a known, reviewed initial installation. A clean comparison does not establish that the starting system was uncompromised.")
    write("Review confirmation SHA-256: " + confirmation)
    if value["enrolled"]:
        write("This exact candidate is already enrolled. ENROLL can only verify and finish the same enrollment; it cannot replace it.")
    return confirmation


def integrity_console(manager, *, integrity=None, read=input, write=print,
                      guard=pending_console, ready=prerequisites):
    """Fixed, explicit actions on the actual lifecycle; never dispatch user input."""
    from .aide import Aide
    integrity = integrity or Aide()
    guard(manager)
    try:
        ready(manager)
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        write("File integrity is unavailable until runtime readiness and the installation's reviewed security policy are verified.")
        write("A baseline name alone is insufficient. Policy enrollment and SCAP findings review still require their qualified operator workflow; this menu cannot select or approve them.")
        return {"state": "prerequisite-unavailable"}
    write("\nFile integrity: explicit initial baseline and measured checks")
    write("PREPARE creates or resumes a private candidate and scans it. REVIEW reads its saved evidence.")
    write("ENROLL activates only the full digest you review and type. CHECK compares files against that enrolled database.")
    write("No action resets an existing baseline or approves SCAP findings.")
    reviewed = None
    while True:
        action = _answer(read, "STATUS, PREPARE, REVIEW, ENROLL, CHECK, or BACK [BACK]: ").upper() or "BACK"
        guard(manager)  # Recheck the local TTY and pending seal after every wait.
        if action == "BACK":
            return {"state": "returned"}
        if action not in ("STATUS", "PREPARE", "REVIEW", "ENROLL", "CHECK"):
            write("Choose one of the displayed actions.")
            continue
        try:
            ready(manager)
            if action == "STATUS":
                status = integrity.status()
                if status.get("baseline") not in ("enrolled", "not_enrolled"):
                    raise Refused("File-integrity enrollment status is unavailable")
                write("Baseline: " + ("ENROLLED" if status["baseline"] == "enrolled" else "NOT ENROLLED"))
                if status.get("last_check"):
                    _show_check(status["last_check"], write)
                else:
                    write("No completed routine check is recorded. PREPARE and ENROLL do not replace the final CHECK requirement.")
                write("Final setup independently requires a separate routine CHECK completed within five minutes.")
            elif action in ("PREPARE", "REVIEW"):
                if action == "PREPARE":
                    write("Preparing the explicitly requested candidate. This can take several minutes; interruption retains owned state for review.")
                    integrity.prepare()
                reviewed = _show_review(integrity.review(), write)
            elif action == "ENROLL":
                if reviewed is None:
                    write("Choose REVIEW first to inspect an existing candidate, or PREPARE to explicitly create one.")
                    continue
                confirmation = _answer(read, "Type the complete review confirmation SHA-256, or CANCEL: ")
                try:
                    guard(manager)
                except (Refused, OSError, ValueError, KeyError, TypeError):
                    raise _ConsoleBoundary("The guarded setup console is no longer available; no enrollment was performed") from None
                if confirmation == "CANCEL":
                    continue
                if not re.fullmatch(r"[0-9a-f]{64}", confirmation) or confirmation != reviewed:
                    write("The typed digest does not match the reviewed candidate. Nothing was enrolled.")
                    continue
                ready(manager)
                integrity.enroll(confirmation)
                write("The exact reviewed baseline is enrolled. Run CHECK for final-completion evidence; no database was automatically replaced.")
            else:
                write("Checking the enrolled baseline. This can take several minutes.")
                _show_check(integrity.check(), write)
        except _ConsoleBoundary:
            raise
        except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            reviewed = None
            write("The action could not be verified. Existing baseline and reports are retained; no replacement was authorized.")
            write("Check prerequisites and use STATUS or REVIEW. An incomplete, changed or older-format candidate requires qualified recovery; this menu cannot reset it.")
