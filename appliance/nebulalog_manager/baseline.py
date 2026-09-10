"""Installation-bound SCAP evidence and explicit review; never auto-remediate."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
import xml.etree.ElementTree as ET

from . import security
from .common import Refused, atomic_json, audit, locked, require_linux_root, run, trusted_file

CONFIGURATION = Path("/var/lib/nebulalog/configuration")
CONTENT = Path("/usr/share/xml/scap/ssg/content")
SHA256 = re.compile(r"[0-9a-f]{64}")
RESULTS = {"pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational", "fixed"}
UNASSESSABLE = {"error", "unknown", "fixed"}


def _now():
    return datetime.now(timezone.utc)


def _sha(path):
    path = Path(path)
    _directory(path.parent)
    digest = hashlib.sha256()
    with trusted_file(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(path):
    path = Path(path)
    _directory(path.parent)
    return json.loads(trusted_file(path).read_text())


def _text(value, minimum=1, maximum=8192):
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum or "\0" in value:
        raise Refused("Review text is missing or invalid")
    return value


def _date(value):
    try:
        if isinstance(value, str) and value.endswith("Z"):
            value = value[:-1] + "+00:00"  # Python3.9 does not accept the UTC Z suffix.
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        raise Refused("Review timestamps must be ISO 8601 with a timezone") from None


def _directory(path, create=False):
    path = Path(path)
    if not path.is_absolute():
        raise Refused("Use absolute paths for baseline content and evidence")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Check every existing ancestor: a root-owned file in a writable directory
    # is not trusted evidence. Tests run with the invoking test user's ownership.
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            raise Refused("Baseline directories must be owned by root and not writable by others or symlinks")
    return path


def _xml(path):
    path = Path(path)
    _directory(path.parent)
    raw = trusted_file(path).read_bytes()
    declaration_check = raw.upper().replace(b"\0", b"")
    if len(raw) > 128 * 1024 * 1024 or b"<!DOCTYPE" in declaration_check or b"<!ENTITY" in declaration_check:
        raise Refused("Unsafe or oversized SCAP XML")
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        raise Refused("Malformed SCAP XML") from None


def _local(node):
    return node.tag.rsplit("}", 1)[-1]


def _manual_rules(path):
    """Only source-declared manual/no-check rules may receive manual evidence.

    A missing OVAL engine/result never turns an automated control into a manual
    one. Unknown check engines and mixed OCIL/OVAL rules remain fail-closed.
    """
    manual = set()
    for rule in _xml(path).iter():
        if _local(rule) != "Rule":
            continue
        checks = [node for node in rule.iter() if _local(node) == "check"]
        if not checks or all(node.get("system") == "http://scap.nist.gov/schema/ocil/2" for node in checks):
            manual.add(rule.get("id"))
    return manual


def _content(path, runner):
    path = Path(path)
    _directory(path.parent)
    digest = _sha(path)
    info = runner(["oscap", "info", str(path)])
    root = _xml(path)
    profiles = []
    benchmarks = []
    rule_ids = sorted({node.get("id") for node in root.iter() if _local(node) == "Rule" and node.get("id")})
    cpes = sorted({value for node in root.iter() for value in node.attrib.values() if value.startswith(("cpe:/", "cpe:2.3:"))})
    for node in root.iter():
        if _local(node) == "Benchmark":
            benchmarks.append({"id": node.get("id"), **{key: next((" ".join(child.itertext()).strip() for child in node if _local(child) == key), "") for key in ("title", "version")}})
        if _local(node) != "Profile":
            continue
        title = next((" ".join(child.itertext()).strip() for child in node if _local(child) == "title"), "")
        profile_id = node.get("id", "")
        if not profile_id.startswith("xccdf_") or any(p["id"] == profile_id for p in profiles):
            raise Refused("SCAP profiles must have unique explicit XCCDF identifiers")
        candidates = []
        if re.search(r"\bCIS\b", title, re.I) and re.search(r"\bLevel\s*2\b", title, re.I) and re.search(r"\bServer\b", title, re.I):
            candidates.append("cis-level2")
        if re.search(r"\bSTIG\b|Security Technical Implementation Guide", title, re.I):
            candidates.append("stig")
        profiles.append({"id": profile_id, "title": title, "candidate_for": candidates, "extends": node.get("extends"),
                         "references": [{"href": child.get("href"), "text": " ".join(child.itertext()).strip()} for child in node if _local(child) == "reference"]})
    if not profiles or _sha(path) != digest:
        raise Refused("SCAP content is empty or changed during inventory")
    return {"path": str(path), "sha256": digest, "profiles": profiles, "benchmarks": benchmarks, "platform_cpes": cpes, "rule_ids": rule_ids,
            "rocky9_cpe_present": "cpe:/o:rocky:rocky:9" in cpes,
            "oscap_info": info, "qualification": "unreviewed candidate; profile presence does not establish coverage or compliance"}


def inventory(directory=CONTENT, runner=run):
    """Inventory installed content without treating absence as an empty pass."""
    result = {"observed_at": _now().isoformat(), "directory": str(directory), "datastreams": [], "unavailable": [], "certification": "not asserted"}
    try:
        result["scanner"] = runner(["oscap", "--version"])
        result["packages"] = runner(["rpm", "-q", "openscap-scanner", "scap-security-guide"])
        _directory(directory)
    except (Refused, OSError) as exc:
        result["unavailable"].append(str(exc))
        return result
    for path in sorted(Path(directory).glob("*-ds.xml")):
        try:
            result["datastreams"].append(_content(path, runner))
        except (Refused, OSError) as exc:
            result["unavailable"].append({"path": str(path), "reason": str(exc)})
    if not result["datastreams"]:
        result["unavailable"].append("No usable installed SCAP datastream was found")
    return result


def _review_attestation(value, now):
    if not isinstance(value, dict) or value.get("approved") is not True:
        raise Refused("An explicit approved content review is required")
    for key in ("reviewer", "platform_basis", "benchmark_basis", "license_basis"):
        _text(value.get(key), 8)
    reviewed, expires = _date(value.get("reviewed_at")), _date(value.get("expires_at"))
    if reviewed > now or not now < expires <= reviewed + timedelta(days=366):
        raise Refused("Content review is expired, future-dated, or longer than one year")


def validate_policy(policy, runner=run, now=None):
    now = now or _now()
    if not isinstance(policy, dict) or policy.get("schema") != 1 or policy.get("baseline") not in security.BASELINES:
        raise Refused("A schema-1 cis-level2, stig, or unified policy is required")
    assessments = policy.get("assessments")
    required = {"cis", "stig"} if policy["baseline"] == "unified" else {"cis" if policy["baseline"] == "cis-level2" else "stig"}
    if not isinstance(assessments, list) or len(assessments) != len(required) or {p.get("kind") for p in assessments if isinstance(p, dict)} != required:
        raise Refused("Each selected baseline needs exactly one assessment of each required kind")
    rules_by_kind = {}
    for item in assessments:
        if item.get("platform") != "rocky9" or item.get("reviewed") is not True:
            raise Refused("Content applicability to Rocky9 must be explicitly reviewed")
        _review_attestation(item.get("content_review"), now)
        _text(item.get("source_url"), 8)
        _text(item.get("content_revision"), 1)
        content = _content(item.get("datastream", ""), runner)
        rules_by_kind[item["kind"]] = set(content["rule_ids"])
        if content["sha256"] != item.get("sha256") or not content["rocky9_cpe_present"]:
            raise Refused("Reviewed datastream hash or native Rocky9 platform declaration is missing")
        matches = [p for p in content["profiles"] if p["id"] == item.get("profile_id")]
        intent = "cis-level2" if item["kind"] == "cis" else "stig"
        if len(matches) != 1 or intent not in matches[0]["candidate_for"]:
            raise Refused("Choose the actual installed CIS Level 2 Server or STIG profile; profile IDs are not inferred")
        if item.get("tailoring") or item.get("tailoring_sha256"):
            raise Refused("Tailored profile assessment is unavailable until the scanner supports explicit base/effective profile validation")
    if policy["baseline"] == "unified":
        mapping = policy.get("unified_mapping", {})
        if not isinstance(mapping, dict) or not SHA256.fullmatch(str(mapping.get("sha256", ""))) or _sha(mapping.get("path", "")) != mapping["sha256"]:
            raise Refused("Unified requires a hashed reviewed control mapping and conflict register")
        register = _json(mapping["path"])
        _review_attestation(register.get("review"), now)
        if register.get("schema") != 1 or register.get("baseline") != "unified" or register.get("coverage_reviewed") is not True or not isinstance(register.get("controls"), list) or not 1 <= len(register["controls"]) <= 10000:
            raise Refused("Unified mapping must explicitly review coverage and record control decisions")
        expected = {p["kind"]: {"sha256": p["sha256"], "profile_id": p["profile_id"]} for p in assessments}
        if register.get("assessments") != expected:
            raise Refused("Unified mapping does not match the selected benchmark content")
        controls, pairs = set(), set()
        for control in register["controls"]:
            if not isinstance(control, dict) or control.get("decision") not in ("same-once", "stricter-compatible", "direct-conflict", "application-exception", "cis-only", "stig-only"):
                raise Refused("Unified control mapping has an invalid decision")
            for key in ("control", "rationale", "effective_setting"):
                _text(control.get(key), 1)
            pair = (control.get("cis_rule"), control.get("stig_rule"))
            if control["control"] in controls or pair in pairs or not any(pair):
                raise Refused("Unified mapping contains duplicate or empty control decisions")
            controls.add(control["control"])
            pairs.add(pair)
            for kind, identifier in zip(("cis", "stig"), pair):
                if identifier is not None and identifier not in rules_by_kind[kind]:
                    raise Refused("Unified mapping references a rule absent from the reviewed benchmark")
            if (control["decision"] == "cis-only" and (not pair[0] or pair[1] is not None) or
                control["decision"] == "stig-only" and (not pair[1] or pair[0] is not None) or
                control["decision"] in ("same-once", "stricter-compatible", "direct-conflict") and not all(pair)):
                raise Refused("Unified mapping decision does not match its rule references")
    return policy


def _host(runner):
    release = Path("/etc/os-release")
    values = dict(line.split("=", 1) for line in release.read_text().splitlines() if "=" in line)
    if values.get("ID", "").strip('"') != "rocky" or values.get("VERSION_ID", "").strip('"').split(".")[0] != "9":
        raise Refused("Baseline assessment requires the actual Rocky Linux9 guest")
    if runner(["uname", "-m"]) != "x86_64":
        raise Refused("Baseline assessment requires the supported x86_64 appliance")
    return {"os_release_sha256": hashlib.sha256(release.read_bytes()).hexdigest(),
            "machine_id_sha256": _sha(Path("/etc/machine-id")), "kernel": runner(["uname", "-r"]),
            "packages": runner(["rpm", "-q", "openscap-scanner", "scap-security-guide"]),
            "scanner": runner(["oscap", "--version"]), "host_controls_ok": security.status(runner)["host_controls_ok"]}


def rule_results(path, profile_id):
    root = _xml(path)
    tests = [node for node in root.iter() if _local(node) == "TestResult"]
    if len(tests) != 1:
        raise Refused("Expected exactly one XCCDF TestResult")
    selected = [node.get("idref") for node in tests[0] if _local(node) == "profile"]
    if selected != [profile_id]:
        raise Refused("XCCDF result does not match the selected profile")
    rules = []
    for node in tests[0].iter():
        if _local(node) != "rule-result":
            continue
        identifier = node.get("idref", "")
        result = [child.text for child in node if _local(child) == "result"]
        if not identifier.startswith("xccdf_") or len(result) != 1 or result[0] not in RESULTS:
            raise Refused("Malformed or unknown XCCDF rule result")
        # Complex/multi-check content can emit repeated rule IDs with instances;
        # it needs an explicit instance-aware adapter, never ambiguous waivers.
        if any(rule["rule_id"] == identifier for rule in rules):
            raise Refused("Repeated XCCDF rule instances require an instance-aware review adapter")
        rules.append({"rule_id": identifier, "result": result[0]})
    return rules


class Baseline:
    def __init__(self, configuration=CONFIGURATION, *, runner=run, scanner=security.scan, host=_host, clock=_now):
        self.configuration = Path(configuration)
        self.runner, self.scanner, self.host, self.clock = runner, scanner, host, clock
        self.policy_path = self.configuration / "security-policy.json"
        self.assessment_path = self.configuration / "baseline-assessment.json"
        self.review_path = self.configuration / "baseline-review.json"
        self.attempt_path = self.configuration / "baseline-attempt.json"

    @contextmanager
    def _attempt(self, installation_id, baseline):
        token = uuid.uuid4().hex
        record = {"scan_id": token, "installation_id": installation_id, "baseline": baseline,
                  "state": "running", "started_at": self.clock().isoformat()}
        atomic_json(self.attempt_path, record)
        try:
            yield token
            if _json(self.assessment_path).get("scan_id") != token:
                raise Refused("Scan did not publish its own assessment")
            record.update(state="complete", completed_at=self.clock().isoformat(), assessment_sha256=_sha(self.assessment_path))
            atomic_json(self.attempt_path, record)
        except Exception:
            # Preserve prior evidence for history while making it unusable for
            # acceptance after a known failed or interrupted new assessment.
            record.update(state="failed", failed_at=self.clock().isoformat())
            atomic_json(self.attempt_path, record)
            raise

    def select(self, policy_path, confirmation, installation_id, baseline):
        require_linux_root()
        _directory(self.configuration)
        with locked(self.configuration / "baseline.lock"):
            if not SHA256.fullmatch(confirmation) or _sha(policy_path) != confirmation:
                raise Refused("Policy changed since explicit review")
            policy = validate_policy(_json(policy_path), self.runner, self.clock())
            if policy["baseline"] != baseline:
                raise Refused("Policy does not match the selected first-boot baseline")
            policy["installation_id"] = str(uuid.UUID(installation_id))
            policy["selection_id"] = uuid.uuid4().hex
            atomic_json(self.policy_path, policy)
            audit(self.configuration / "baseline-audit.jsonl", "baseline.select", installation_id=installation_id,
                  baseline=baseline, policy_sha256=_sha(self.policy_path))
            return {"baseline": baseline, "policy_sha256": _sha(self.policy_path), "assessment_status": "pending", "review_status": "pending"}

    def scan(self, installation_id, baseline):
        require_linux_root()
        _directory(self.configuration)
        with locked(self.configuration / "baseline.lock"), self._attempt(installation_id, baseline) as scan_id:
            policy = validate_policy(_json(self.policy_path), self.runner, self.clock())
            if policy.get("installation_id") != installation_id or policy["baseline"] != baseline:
                raise Refused("Selected policy belongs to another installation or baseline")
            before = self.host(self.runner)
            policy_hash = _sha(self.policy_path)
            output = self.configuration / "baseline-assessments" / uuid.uuid4().hex
            _directory(output.parent, create=True)
            summary = self.scanner(self.policy_path, output, self.runner)
            artifacts = {}
            for profile in policy["assessments"]:
                kind = profile["kind"]
                xml = output / (kind + ".xml")
                rules = rule_results(xml, profile["profile_id"])
                matched = [item for item in summary["assessments"] if item["kind"] == kind]
                if len(matched) != 1:
                    raise Refused("Scanner summary does not match the required assessment set")
                matched[0]["rules"] = rules
                matched[0]["manual_only_rule_ids"] = sorted(_manual_rules(profile["datastream"]))
                for name, source in ((kind + ".xml", xml), (kind + ".html", output / (kind + ".html")),
                                     (kind + "-content.xml", Path(profile["datastream"]))):
                    if source.parent != output:
                        destination = output / name
                        destination.write_bytes(trusted_file(source).read_bytes())
                        destination.chmod(0o600)
                        source = destination
                    artifacts[name] = _sha(source)
                if artifacts[kind + "-content.xml"] != profile["sha256"]:
                    raise Refused("SCAP content changed while retaining its provenance")
                if profile.get("tailoring"):
                    destination = output / (kind + "-tailoring.xml")
                    destination.write_bytes(trusted_file(Path(profile["tailoring"])).read_bytes())
                    destination.chmod(0o600)
                    artifacts[destination.name] = _sha(destination)
            atomic_json(output / "policy.json", policy)
            artifacts["policy.json"] = _sha(output / "policy.json")
            if policy.get("unified_mapping"):
                atomic_json(output / "unified-mapping.json", _json(policy["unified_mapping"]["path"]))
                artifacts["unified-mapping.json"] = _sha(output / "unified-mapping.json")
            if before != self.host(self.runner) or _sha(self.policy_path) != policy_hash:
                raise Refused("Host or selected policy changed during assessment; rerun the scan")
            validate_policy(policy, self.runner, self.clock())
            summary.update(schema=1, installation_id=installation_id, scan_id=scan_id, policy_sha256=policy_hash,
                           provenance=before, artifact_directory=output.name, artifacts=artifacts,
                           review_status="pending", remediation_applied=False)
            atomic_json(output / "assessment.json", summary)
            atomic_json(self.assessment_path, summary)
            audit(self.configuration / "baseline-audit.jsonl", "baseline.scan", installation_id=installation_id,
                  baseline=baseline, assessment_sha256=_sha(self.assessment_path))
            return summary

    def _validated_assessment(self, installation_id, baseline):
        _directory(self.configuration)
        policy = validate_policy(_json(self.policy_path), self.runner, self.clock())
        value = _json(self.assessment_path)
        attempt = _json(self.attempt_path)
        if attempt.get("state") != "complete" or attempt.get("scan_id") != value.get("scan_id") or attempt.get("installation_id") != installation_id or attempt.get("baseline") != baseline or attempt.get("assessment_sha256") != _sha(self.assessment_path):
            raise Refused("Latest assessment attempt failed, was interrupted, or has changed")
        if value.get("schema") != 1 or value.get("installation_id") != installation_id or policy.get("installation_id") != installation_id or value.get("baseline") != baseline or policy["baseline"] != baseline:
            raise Refused("Assessment is not bound to this installation and selected baseline")
        if value.get("policy_sha256") != _sha(self.policy_path) or value.get("provenance") != self.host(self.runner):
            raise Refused("Assessment policy, content or host provenance is stale")
        name = value.get("artifact_directory", "")
        if not isinstance(name, str) or not re.fullmatch(r"[0-9a-f]{32}", name):
            raise Refused("Invalid assessment artifact directory")
        output = _directory(self.configuration / "baseline-assessments" / name)
        if _json(output / "assessment.json") != value:
            raise Refused("Assessment summary changed after the scan")
        expected = {"policy.json"}
        for profile in policy["assessments"]:
            expected.update(profile["kind"] + suffix for suffix in (".xml", ".html", "-content.xml"))
            if profile.get("tailoring"):
                expected.add(profile["kind"] + "-tailoring.xml")
        if policy.get("unified_mapping"):
            expected.add("unified-mapping.json")
        if set(value.get("artifacts", {})) != expected or any(_sha(output / name) != digest for name, digest in value["artifacts"].items()):
            raise Refused("Assessment artifacts are missing or changed")
        if _json(output / "policy.json") != policy:
            raise Refused("Assessment policy snapshot changed")
        findings = []
        assessed = value.get("host", {}).get("host_controls_ok") is True and value["provenance"].get("host_controls_ok") is True
        if len(value.get("assessments", [])) != len(policy["assessments"]):
            raise Refused("Assessment set is incomplete")
        for profile in policy["assessments"]:
            kind = profile["kind"]
            rows = [item for item in value["assessments"] if item.get("kind") == kind]
            rules = rule_results(output / (kind + ".xml"), profile["profile_id"])
            manual = _manual_rules(output / (kind + "-content.xml"))
            if len(rows) != 1 or rows[0].get("rules") != rules or rows[0].get("profile") != profile["profile_id"] or _sha(output / (kind + "-content.xml")) != profile["sha256"]:
                raise Refused("Rule evidence differs from the recorded assessment")
            if rows[0].get("manual_only_rule_ids") != sorted(manual):
                raise Refused("Manual control classification differs from the pinned benchmark")
            recomputed = security.summarize_xccdf(output / (kind + ".xml"))
            if any(rows[0].get(key) != val for key, val in recomputed.items()):
                raise Refused("Rule counts or automated result changed")
            assessed = assessed and any(rule["result"] in ("pass", "fail") for rule in rules) and not any(rule["result"] in UNASSESSABLE or rule["result"] == "notchecked" and rule["rule_id"] not in manual for rule in rules)
            findings.extend({"kind": kind, **rule, "manual_only": rule["rule_id"] in manual} for rule in rules if rule["result"] not in ("pass", "notselected"))
        return value, findings, bool(assessed)

    def review_template(self, installation_id, baseline):
        value, findings, assessed = self._validated_assessment(installation_id, baseline)
        return {"schema": 1, "installation_id": installation_id, "baseline": baseline,
                "assessment_sha256": _sha(self.assessment_path), "approved": False,
                "reviewer": "", "rationale": "", "reviewed_at": "", "expires_at": "", "selection_reviewed": False,
                "assessment_usable": assessed,
                "findings": [{**finding, "disposition": "", "reason": "", "compensating_control": "", "owner": "", "approval": "", "expires_at": "", "evidence": "", **({"manual_evidence": {"path": "", "sha256": ""}} if finding["result"] == "notchecked" else {})} for finding in findings]}

    def _validate_review(self, review, installation_id, baseline, findings):
        now = self.clock()
        if review.get("schema") != 1 or review.get("installation_id") != installation_id or review.get("baseline") != baseline or review.get("assessment_sha256") != _sha(self.assessment_path):
            raise Refused("Review does not match the current installation and assessment")
        if review.get("approved") is not True or review.get("selection_reviewed") is not True:
            raise Refused("Explicit findings and profile/tailoring review is required even when every rule passes")
        _text(review.get("reviewer"), 3)
        _text(review.get("rationale"), 12)
        reviewed, expires = _date(review.get("reviewed_at")), _date(review.get("expires_at"))
        if reviewed < _date(_json(self.assessment_path)["observed_at"]) or reviewed > now or not now < expires <= reviewed + timedelta(days=90):
            raise Refused("Assessment review must follow the scan and expire within 90 days")
        entries = review.get("findings")
        expected = {(f["kind"], f["rule_id"], f["result"]) for f in findings}
        manual = {(f["kind"], f["rule_id"], f["result"]) for f in findings if f["manual_only"]}
        if not isinstance(entries, list) or len(entries) != len(expected) or {tuple(f.get(key) for key in ("kind", "rule_id", "result")) for f in entries if isinstance(f, dict)} != expected:
            raise Refused("Every finding needs exactly one matching review; extra or missing waivers are refused")
        for finding in entries:
            result = finding["result"]
            disposition = "exception" if result == "fail" else "not-applicable" if result == "notapplicable" else "manual-pass" if result == "notchecked" else "manual-review"
            if result in UNASSESSABLE or result == "notchecked" and (finding["kind"], finding["rule_id"], result) not in manual or finding.get("disposition") != disposition:
                raise Refused("Scanner errors, unknown and unchecked controls must be resolved and rescanned")
            if result == "notchecked":
                evidence = finding.get("manual_evidence", {})
                if not isinstance(evidence, dict) or not SHA256.fullmatch(str(evidence.get("sha256", ""))) or _sha(evidence.get("path", "")) != evidence["sha256"]:
                    raise Refused("Manual-only controls require a real, unchanged evidence file and explicit manual-pass")
            for field in ("reason", "compensating_control", "owner", "approval", "evidence"):
                _text(finding.get(field), 8 if field in ("reason", "compensating_control", "evidence") else 3)
            if not now < _date(finding.get("expires_at")) <= expires:
                raise Refused("Finding exception is expired or outlives the assessment review")

    def review(self, review_path, confirmation, installation_id, baseline):
        require_linux_root()
        _directory(self.configuration)
        with locked(self.configuration / "baseline.lock"):
            _, findings, assessed = self._validated_assessment(installation_id, baseline)
            if not assessed:
                raise Refused("Empty, all-notapplicable, error, unknown or unexpectedly unchecked assessments cannot be approved")
            if confirmation != _sha(self.assessment_path):
                raise Refused("Assessment changed since explicit review")
            review = _json(review_path)
            self._validate_review(review, installation_id, baseline, findings)
            review["recorded_at"] = self.clock().isoformat()
            review["certification"] = "not asserted"
            atomic_json(self.review_path, review)
            audit(self.configuration / "baseline-audit.jsonl", "baseline.review", installation_id=installation_id,
                  baseline=baseline, assessment_sha256=confirmation, reviewer=review["reviewer"], review_sha256=_sha(self.review_path))
            return {"baseline_assessed": True, "baseline_review_complete": True, "exceptions": len(findings), "automated_result_unchanged": True}

    def checks(self, installation_id, baseline):
        result = {"baseline_assessed": False, "baseline_review_complete": False}
        try:
            _, findings, result["baseline_assessed"] = self._validated_assessment(installation_id, baseline)
            if result["baseline_assessed"]:
                self._validate_review(_json(self.review_path), installation_id, baseline, findings)
                result["baseline_review_complete"] = True
        except (Refused, OSError, ValueError, KeyError, TypeError):
            pass
        return result

    def status(self, installation_id, baseline):
        result = {"baseline": baseline, "installation_id": installation_id, "certification": "not asserted",
                  "baseline_assessed": False, "baseline_review_complete": False, "assessments": [], "exceptions": []}
        try:
            assessment, findings, assessed = self._validated_assessment(installation_id, baseline)
            result.update(baseline_assessed=assessed, last_assessment=assessment["observed_at"],
                          assessment_sha256=_sha(self.assessment_path), host=assessment["host"],
                          assessments=[{key: item[key] for key in ("kind", "profile", "counts", "automated_assessment_passed")} for item in assessment["assessments"]], findings=findings)
            if not assessed:
                result["reason"] = "Assessment contains unusable results or required host controls are unavailable"
                return result
            review = _json(self.review_path)
            self._validate_review(review, installation_id, baseline, findings)
            result.update(baseline_review_complete=True, reviewer=review["reviewer"], review_expires_at=review["expires_at"], exceptions=review["findings"])
        except (Refused, OSError, ValueError, KeyError, TypeError) as exc:
            result["reason"] = str(exc)
        return result


def firstboot_checks(configuration, installation_id, baseline, *, runner=run):
    return Baseline(configuration, runner=runner).checks(installation_id, baseline)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nebulalog-baseline")
    parser.add_argument("--configuration", type=Path, default=CONFIGURATION)
    parser.add_argument("--setup", type=Path, default=Path("/var/lib/nebulalog/configuration/bootstrap/setup.json"))
    commands = parser.add_subparsers(dest="command", required=True)
    item = commands.add_parser("inventory")
    item.add_argument("--content-directory", type=Path, default=CONTENT)
    item = commands.add_parser("select")
    item.add_argument("--policy", type=Path, required=True)
    item.add_argument("--confirm-policy-sha256", required=True)
    commands.add_parser("scan")
    commands.add_parser("status")
    commands.add_parser("review-template")
    item = commands.add_parser("review")
    item.add_argument("--review-file", type=Path, required=True)
    item.add_argument("--confirm-assessment-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        require_linux_root()
        if args.command == "inventory":
            result = inventory(args.content_directory)
        else:
            setup = _json(args.setup)
            installation_id, baseline = setup["installation_id"], setup["baseline"]
            manager = Baseline(args.configuration)
            if args.command == "select":
                result = manager.select(args.policy, args.confirm_policy_sha256, installation_id, baseline)
            elif args.command == "scan":
                result = manager.scan(installation_id, baseline)
            elif args.command == "review-template":
                result = manager.review_template(installation_id, baseline)
            elif args.command == "review":
                result = manager.review(args.review_file, args.confirm_assessment_sha256, installation_id, baseline)
            else:
                result = manager.status(installation_id, baseline)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
