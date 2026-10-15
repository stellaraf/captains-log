"""Measured host security status and OpenSCAP evaluation; no automatic remediation."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
import xml.etree.ElementTree as ET
from .common import CommandFailed, Refused, atomic_json, require_linux_root, run, trusted_file

BASELINES = ("cis-level2", "stig", "unified")


def kernel_crypto_diagnostics(result):
    """Summarize current-boot evidence without publishing raw kernel messages.

    Mode flags cannot override a reported self-test failure. Absence of a
    matching message does not prove every algorithm was tested or certified.
    """
    patterns = {
        "hkdf_self_test_failure": r"\b(?:basic (?:hdkf|hkdf) test|hkdf test with long input).*\b(?:failed|mismatch)\b",
        "crypto_algorithm_test_failure": r"\balg:.*(?:test.*fail|fail.*test)",
        "crypto_self_test_failure": r"\b(?:fips|crypto|cryptomgr)\b.*\bself[ -]?tests?\b.*\bfail(?:ed|ure)?\b",
    }
    counts = {}
    for line in result.stdout.splitlines():
        for category, pattern in patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                counts[category] = counts.get(category, 0) + 1
                break
    boot_start = bool(re.search(r"(?m)^Linux version \S+", result.stdout))
    complete = result.code == 0 and not result.stderr.strip() and boot_start
    return {"status": "failed" if counts else "no_failure_observed" if complete else "unavailable",
            "journal_exit_code": result.code, "boot_start_observed": boot_start,
            "diagnostic_counts": counts, "scope": "retained current-boot kernel journal",
            "all_algorithms_tested": "not established"}


def status(runner=run) -> dict:
    def probe(argv):
        try:
            return {"ok": True, "value": runner(argv)}
        except (OSError, Refused, subprocess.SubprocessError):
            return {"ok": False, "value": "unavailable"}
    result = {"observed_at": datetime.now(timezone.utc).isoformat()}
    try:
        result["fips_kernel"] = Path("/proc/sys/crypto/fips_enabled").read_text().strip() == "1"
    except OSError:
        result["fips_kernel"] = False
    try:
        result["module_signatures_enforced"] = Path("/sys/module/module/parameters/sig_enforce").read_text().strip() == "Y"
    except OSError:
        result["module_signatures_enforced"] = False
    result["fips_tool"] = probe(["fips-mode-setup", "--check"])
    result["crypto_policy"] = probe(["update-crypto-policies", "--show"])
    result["selinux"] = probe(["getenforce"])
    result["firewalld"] = probe(["systemctl", "is-active", "firewalld"])
    result["auditd"] = probe(["systemctl", "is-active", "auditd"])
    result["aide_timer"] = probe(["systemctl", "is-enabled", "nebulalog-aide.timer"])
    # Read the current boot only. A bounded tail that has lost its boot header
    # cannot establish complete retained evidence, even if mode flags are set.
    journal = probe(["journalctl", "-k", "--boot=0", "--no-pager", "--output=cat", "--lines=10000"])
    result["kernel_crypto_diagnostics"] = kernel_crypto_diagnostics(SimpleNamespace(
        code=0 if journal["ok"] else 1, stdout=journal["value"] if journal["ok"] else "", stderr=""))
    result["host_controls_ok"] = (result["fips_kernel"] and result["module_signatures_enforced"] and result["fips_tool"]["ok"] and
                                  result["kernel_crypto_diagnostics"]["status"] == "no_failure_observed" and
                                  result["crypto_policy"]["value"] == "FIPS" and
                                  result["selinux"]["value"] == "Enforcing" and
                                  result["firewalld"]["value"] == "active" and result["auditd"]["value"] == "active")
    result["certification"] = "not asserted"
    return result


def summarize_xccdf(path: Path) -> dict:
    # Refuse DTD/entity input, including XML external entities. Reports are local,
    # but supplied content must not produce a misleading compliance result.
    data = path.read_bytes()
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise Refused("Unsafe XML in compliance result")
    root = ET.fromstring(data)
    results = [n for n in root.iter() if n.tag.rsplit("}",1)[-1] == "rule-result"]
    counts = {}
    for node in results:
        result = next((c.text for c in node if c.tag.rsplit("}",1)[-1] == "result"), "error")
        counts[result] = counts.get(result, 0) + 1
    passed = counts.get("pass", 0)
    return {"counts": counts, "assessed": len(results), "passed": passed,
            "automated_assessment_passed": bool(results) and passed > 0 and
            all(value == "pass" for value in counts),
            "requires_review": any(value != "pass" for value in counts) or not results,
            "certification": "not asserted"}


def scan(policy_path: Path, output: Path, runner=run) -> dict:
    require_linux_root()
    trusted_file(policy_path)
    policy = json.loads(policy_path.read_text())
    if policy.get("baseline") not in BASELINES:
        raise Refused("Select cis-level2, stig, or unified")
    profiles = policy.get("assessments", [])
    required = {"cis", "stig"} if policy["baseline"] == "unified" else {"cis" if policy["baseline"] == "cis-level2" else "stig"}
    if {p.get("kind") for p in profiles} != required:
        raise Refused("Selected baseline requires explicit applicable assessment content")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    reports = []
    for profile in profiles:
        source = trusted_file(Path(profile["datastream"]))
        if hashlib.sha256(source.read_bytes()).hexdigest() != profile["sha256"]:
            raise Refused("SCAP content hash changed; review content before assessment")
        if profile.get("platform") != "rocky9" or profile.get("reviewed") is not True:
            raise Refused("SCAP applicability must be reviewed for the exact Rocky 9 build")
        profile_id = profile["profile_id"]
        if not profile_id.startswith("xccdf_"):
            raise Refused("Expected an explicit XCCDF profile ID")
        info = runner(["oscap", "info", str(source)])
        if profile.get("base_profile_id", profile_id) not in info:
            raise Refused("Requested SCAP profile is not present")
        xml = output / (profile["kind"] + ".xml")
        html = output / (profile["kind"] + ".html")
        argv = ["oscap", "xccdf", "eval", "--profile", profile_id,
                "--results", str(xml), "--report", str(html)]
        if profile.get("tailoring"):
            from .baseline import validate_tailoring
            validate_tailoring(profile, runner=runner)
            tailoring = trusted_file(Path(profile["tailoring"]))
            if hashlib.sha256(tailoring.read_bytes()).hexdigest() != profile.get("tailoring_sha256"):
                raise Refused("SCAP tailoring hash mismatch")
            argv += ["--tailoring-file", str(tailoring)]
        argv.append(str(source))
        try:
            runner(argv, timeout=3600)
        except CommandFailed as exc:
            # Only exit 2 means a completed assessment with failing rules. A
            # truncated report from an execution error must never appear passed.
            if exc.returncode != 2 or not xml.is_file():
                raise
        summary = summarize_xccdf(xml)
        reports.append({"kind": profile["kind"], "profile": profile_id,
                        "content_sha256": profile["sha256"], **summary})
    report = {"observed_at": datetime.now(timezone.utc).isoformat(), "baseline": policy["baseline"],
              "host": status(runner), "assessments": reports,
              "exceptions": policy.get("exceptions", []), "certification": "not asserted"}
    atomic_json(output / "summary.json", report)
    return report
