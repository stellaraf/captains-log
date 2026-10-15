"""Installation-bound SCAP assessment, initial hardening and explicit review."""
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
from .common import CommandFailed, Refused, atomic_json, audit, locked, require_linux_root, run, trusted_file

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
    value_selectors = {}
    for node in root.iter():
        if node.tag != "{http://checklists.nist.gov/xccdf/1.2}Value":
            continue
        identifier = node.get("id")
        if not identifier or identifier in value_selectors:
            raise Refused("SCAP values must have unique identifiers")
        selectors = [child.get("selector") for child in node
                     if child.tag == "{http://checklists.nist.gov/xccdf/1.2}value" and child.get("selector") is not None]
        if len(selectors) != len(set(selectors)):
            raise Refused("SCAP value selectors must be unambiguous")
        value_selectors[identifier] = selectors
    group_rules = {}
    ns = "{http://checklists.nist.gov/xccdf/1.2}"
    for group in root.iter(ns + "Group"):
        identifier = group.get("id")
        if not identifier or identifier in group_rules:
            raise Refused("SCAP groups must have unique identifiers")
        group_rules[identifier] = sorted({node.get("id") for node in group.iter(ns + "Rule") if node.get("id")})
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
    return {"path": str(path), "sha256": digest, "profiles": profiles, "benchmarks": benchmarks, "platform_cpes": cpes, "rule_ids": rule_ids, "group_rules": group_rules, "value_selectors": value_selectors,
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


def validate_tailoring(item, content=None, runner=run):
    """Bind one effective profile to its reviewed base and explicit rule decisions.

    Rule selections and existing named value selectors require exact decisions.
    Group enablement requires its complete descendant inventory. Free-form values,
    group disabling, extra profiles and embedded checks/fixes are refused.
    """
    content = content or _content(item["datastream"], runner)
    path = item.get("tailoring", "")
    digest = item.get("tailoring_sha256", "")
    if not SHA256.fullmatch(str(digest)) or _sha(path) != digest:
        raise Refused("Tailoring hash is missing or changed")
    root = _xml(path)
    ns = "{http://checklists.nist.gov/xccdf/1.2}"
    if root.tag != ns + "Tailoring":
        raise Refused("Expected an XCCDF 1.2 Tailoring document")
    allowed = {ns + name for name in ("benchmark", "version", "Profile")}
    if any(child.tag not in allowed for child in root):
        raise Refused("Unsupported tailoring document element")
    benchmarks = root.findall(ns + "benchmark")
    profiles = root.findall(ns + "Profile")
    if len(benchmarks) != 1 or benchmarks[0].attrib != {"href": Path(item["datastream"]).name}:
        raise Refused("Tailoring must bind the local datastream filename")
    if len(profiles) != 1:
        raise Refused("Tailoring must contain exactly one effective profile")
    profile = profiles[0]
    base = item.get("base_profile_id")
    if base not in {p["id"] for p in content["profiles"]}:
        raise Refused("Tailoring base profile is absent from the pinned datastream")
    effective = item.get("profile_id", "")
    if (not effective.startswith("xccdf_") or effective in {p["id"] for p in content["profiles"]}
            or profile.attrib != {"id": effective, "extends": base}):
        raise Refused("Tailoring effective profile must explicitly extend the selected base")
    decisions = item.get("tailoring_decisions")
    values = item.get("tailoring_values", [])
    groups = item.get("tailoring_groups", [])
    if not isinstance(decisions, list) or not isinstance(values, list) or not isinstance(groups, list) or not (decisions or values or groups):
        raise Refused("Tailoring requires explicit reviewed rule or value decisions")
    expected = {}
    for decision in decisions:
        if not isinstance(decision, dict) or decision.get("rule_id") not in content["rule_ids"] or type(decision.get("selected")) is not bool:
            raise Refused("Tailoring decision references an invalid rule or selection")
        rule = decision["rule_id"]
        if rule in expected:
            raise Refused("Duplicate tailoring decision")
        _text(decision.get("rationale"), 8)
        _text(decision.get("effective_control"), 8)
        expected[rule] = "true" if decision["selected"] else "false"
    for decision in groups:
        if not isinstance(decision, dict):
            raise Refused("Invalid tailoring group decision")
        identifier = decision.get("group_id")
        if not isinstance(identifier, str):
            raise Refused("Invalid tailoring group identifier")
        descendants = content.get("group_rules", {}).get(identifier)
        if (not descendants or identifier in content["rule_ids"] or identifier in expected
                or decision.get("selected") is not True or decision.get("affected_rules") != descendants):
            raise Refused("Group enablement requires its exact complete rule inventory; disabling groups is refused")
        _text(decision.get("rationale"), 8)
        _text(decision.get("effective_control"), 8)
        expected[identifier] = "true"
    expected_values = {}
    for decision in values:
        if not isinstance(decision, dict):
            raise Refused("Invalid tailoring value decision")
        identifier, selector = decision.get("value_id"), decision.get("selector")
        if (not isinstance(identifier, str) or not isinstance(selector, str)
                or selector not in content["value_selectors"].get(identifier, [])):
            raise Refused("Tailoring value must select an existing named source value")
        if identifier in expected_values:
            raise Refused("Duplicate tailoring value decision")
        _text(decision.get("rationale"), 8)
        expected_values[identifier] = selector
    actual, actual_values = {}, {}
    for child in profile:
        if child.tag in (ns + "title", ns + "description") and not list(child):
            continue
        if child.tag == ns + "refine-value":
            if set(child.attrib) != {"idref", "selector"} or list(child) or child.get("idref") in actual_values:
                raise Refused("Invalid or duplicate tailoring value selection")
            actual_values[child.get("idref")] = child.get("selector")
            continue
        if child.tag != ns + "select" or set(child.attrib) != {"idref", "selected"} or list(child):
            raise Refused("Only reviewed rules, group enablement and named values are supported in tailoring")
        rule = child.get("idref")
        if rule in actual:
            raise Refused("Duplicate tailoring selection")
        actual[rule] = child.get("selected")
    if actual != expected or actual_values != expected_values or _sha(path) != digest:
        raise Refused("Tailoring does not match its reviewed rule decisions")
    return path


def _mapping_rules(path, profile_id, overrides=None):
    """Inventory explicit rule/group selection before appliance exceptions.

    This is not a general XCCDF resolver: inherited items and cluster selectors
    require resolved content and are refused instead of silently omitting rules.
    A rule participates only when it and every containing group are selected.
    """
    ns = "{http://checklists.nist.gov/xccdf/1.2}"
    root = _xml(path)
    benchmarks = [n for n in root.iter(ns + "Benchmark")
                  if any(c.tag == ns + "Profile" and c.get("id") == profile_id for c in n)]
    if len(benchmarks) != 1:
        raise Refused("Unified coverage requires one unambiguous benchmark")
    benchmark = benchmarks[0]
    profile = next(c for c in benchmark if c.tag == ns + "Profile" and c.get("id") == profile_id)
    if profile.get("extends") or profile.get("abstract", "false") not in ("false", "0"):
        raise Refused("Unified coverage requires a resolved nonabstract profile")
    selected, rules = {}, {}
    parents = {child: parent for parent in benchmark.iter() for child in parent}
    for node in benchmark.iter():
        if node.tag not in (ns + "Rule", ns + "Group"):
            continue
        identifier, enabled = node.get("id"), node.get("selected", "true")
        if not identifier or identifier in selected or node.get("extends") or enabled not in ("true", "false", "1", "0"):
            raise Refused("Unified coverage requires unique resolved rules and groups")
        selected[identifier] = enabled in ("true", "1")
        if node.tag == ns + "Rule":
            rules[identifier] = node
    seen = set()
    for choice in profile:
        if choice.tag != ns + "select":
            continue
        identifier, enabled = choice.get("idref"), choice.get("selected")
        if identifier not in selected or identifier in seen or enabled not in ("true", "false", "1", "0"):
            raise Refused("Unified coverage requires explicit unambiguous rule/group selections")
        seen.add(identifier)
        selected[identifier] = enabled in ("true", "1")
    for identifier, enabled in (overrides or {}).items():
        if identifier not in selected or type(enabled) is not bool:
            raise Refused("Unified effective selection references an unknown item")
        selected[identifier] = enabled
    result = set()
    for identifier, node in rules.items():
        enabled = selected[identifier]
        parent = parents.get(node)
        while parent is not None:
            if parent.tag == ns + "Group":
                enabled = enabled and selected[parent.get("id")]
            parent = parents.get(parent)
        if enabled:
            result.add(identifier)
    if not result:
        raise Refused("Unified coverage cannot use an empty baseline")
    return result


def assessment_binding(item):
    """Bind source and effective semantics independently of console acceptance.

    A profile ID is reusable when tailoring changes. The coverage reviewer must
    therefore approve the exact tailoring bytes and all recorded decisions, not
    just the source datastream and that label. Per-installation reviewer names,
    timestamps and absolute file paths are intentionally not selection identity.
    """
    selections = {key: sorted(item.get(key, []), key=lambda d: d[identifier])
                  for key, identifier in (("tailoring_decisions", "rule_id"),
                                          ("tailoring_values", "value_id"),
                                          ("tailoring_groups", "group_id"))}
    raw = json.dumps(selections, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return {"sha256": item["sha256"], "profile_id": item["profile_id"],
            "base_profile_id": item.get("base_profile_id", item["profile_id"]),
            "tailoring_sha256": item.get("tailoring_sha256"),
            "selection_sha256": hashlib.sha256(raw).hexdigest()}


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
        rules_by_kind[item["kind"]] = (_mapping_rules(item["datastream"], item.get("base_profile_id", item["profile_id"]))
                                           if policy["baseline"] == "unified" else set(content["rule_ids"]))
        if content["sha256"] != item.get("sha256") or not content["rocky9_cpe_present"]:
            raise Refused("Reviewed datastream hash or native Rocky9 platform declaration is missing")
        matches = [p for p in content["profiles"] if p["id"] == item.get("base_profile_id", item.get("profile_id"))]
        intent = "cis-level2" if item["kind"] == "cis" else "stig"
        if len(matches) != 1 or intent not in matches[0]["candidate_for"]:
            raise Refused("Choose the actual installed CIS Level 2 Server or STIG profile; profile IDs are not inferred")
        if item.get("tailoring") or item.get("tailoring_sha256"):
            validate_tailoring(item, content, runner)
        elif item.get("base_profile_id") or item.get("tailoring_decisions") or item.get("tailoring_values") or item.get("tailoring_groups"):
            raise Refused("Base profile and decisions require an explicit tailoring document")
    if policy["baseline"] == "unified":
        mapping = policy.get("unified_mapping", {})
        if not isinstance(mapping, dict) or not SHA256.fullmatch(str(mapping.get("sha256", ""))) or _sha(mapping.get("path", "")) != mapping["sha256"]:
            raise Refused("Unified requires a hashed reviewed control mapping and conflict register")
        register = _json(mapping["path"])
        _review_attestation(register.get("review"), now)
        if register.get("schema") != 1 or register.get("baseline") != "unified" or register.get("coverage_reviewed") is not True or not isinstance(register.get("controls"), list) or not 1 <= len(register["controls"]) <= 10000:
            raise Refused("Unified mapping must explicitly review coverage and record control decisions")
        expected = {p["kind"]: assessment_binding(p) for p in assessments}
        if register.get("assessments") != expected:
            raise Refused("Unified mapping does not match the selected benchmark content")
        controls, pairs = set(), set()
        covered = {kind: set() for kind in required}
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
                    raise Refused("Unified mapping references a rule not selected by the original reviewed benchmark")
                if identifier is not None:
                    if identifier in covered[kind]:
                        raise Refused("Unified mapping repeats a benchmark rule across decisions")
                    covered[kind].add(identifier)
            if (control["decision"] == "cis-only" and (not pair[0] or pair[1] is not None) or
                control["decision"] == "stig-only" and (not pair[1] or pair[0] is not None) or
                control["decision"] in ("same-once", "stricter-compatible", "direct-conflict") and not all(pair)):
                raise Refused("Unified mapping decision does not match its rule references")
        if covered != rules_by_kind:
            raise Refused("Unified mapping must cover every selected original benchmark rule, including exceptions")
        if policy.get("unified_remediation") is not None:
            item = policy["unified_remediation"]
            # Reuse full source, review, base/effective and tailoring validation.
            validate_policy({"schema": 1, "baseline": "stig", "assessments": [item]}, runner, now)
            stig = next(p for p in assessments if p["kind"] == "stig")
            if (not item.get("tailoring") or item.get("base_profile_id") != stig.get("base_profile_id", stig["profile_id"])
                    or any(p["sha256"] != item["sha256"] for p in assessments)):
                raise Refused("Unified remediation requires one shared datastream and an explicit merged STIG-derived profile")
            binding = {key: item[key] for key in ("sha256", "profile_id", "tailoring_sha256")}
            if register.get("remediation") != binding:
                raise Refused("Unified conflict register does not bind the exact merged remediation")
            applied = set()
            for control in register["controls"]:
                if "applied_rule" not in control:
                    raise Refused("Unified remediation needs an applied rule or explicit exception for every decision")
                rule = control["applied_rule"]
                if rule is None:
                    if control["decision"] != "application-exception":
                        raise Refused("Only an explicit application exception may omit remediation")
                elif not isinstance(rule, str) or rule not in (control.get("cis_rule"), control.get("stig_rule")):
                    raise Refused("Unified applied rule must belong to its reviewed control pair")
                else:
                    applied.add(rule)
            overrides = {d["rule_id"]: d["selected"] for d in item["tailoring_decisions"]}
            overrides.update({d["group_id"]: d["selected"] for d in item.get("tailoring_groups", [])})
            effective = _mapping_rules(item["datastream"], item["base_profile_id"], overrides)
            if effective != applied:
                raise Refused("Unified effective profile differs from its complete applied-rule register")
            _validate_unified_values(assessments, item, register)
    elif policy.get("unified_remediation") is not None:
        raise Refused("Merged remediation is only valid for a Unified policy")
    return policy


def _profile_values(path, profile_id, overrides=None):
    """Resolve existing named values without inferring which is more secure."""
    ns = "{http://checklists.nist.gov/xccdf/1.2}"
    root = _xml(path)
    profiles = [p for p in root.iter(ns + "Profile") if p.get("id") == profile_id]
    if len(profiles) != 1 or profiles[0].get("extends"):
        raise Refused("Unified values require one resolved source profile")
    values, choices = {}, {}
    for node in root.iter(ns + "Value"):
        identifier = node.get("id")
        options = [c for c in node if c.tag == ns + "value"]
        selectors = [c.get("selector") for c in options]
        if not identifier or identifier in values or len(selectors) != len(set(selectors)) or selectors.count(None) != 1:
            raise Refused("Unified values require unique source values and one default")
        values[identifier] = {c.get("selector"): "".join(c.itertext()) for c in options}
        choices[identifier] = None
    selected = set()
    for child in profiles[0]:
        if child.tag == ns + "set-value":
            raise Refused("Unified source profiles must use existing named values")
        if child.tag != ns + "refine-value":
            continue
        identifier, selector = child.get("idref"), child.get("selector")
        if (set(child.attrib) != {"idref", "selector"} or list(child)
                or identifier in selected or selector not in values.get(identifier, {})):
            raise Refused("Unified source value selection is unknown or ambiguous")
        selected.add(identifier)
        choices[identifier] = selector
    for identifier, selector in (overrides or {}).items():
        if identifier not in values or selector not in values[identifier]:
            raise Refused("Unified value override is not an existing source choice")
        choices[identifier] = selector
    return {key: {"selector": choice, "value": values[key][choice]} for key, choice in choices.items()}


def unified_value_conflicts(assessments):
    """Inventory original benchmark differences, before appliance tailoring."""
    if len(assessments) != 2 or {p.get("kind") for p in assessments} != {"cis", "stig"}:
        raise Refused("Unified values require one CIS and one STIG assessment")
    if len({p.get("sha256") for p in assessments}) != 1:
        raise Refused("Unified values require the same pinned datastream")
    for item in assessments:
        if _sha(item["datastream"]) != item["sha256"]:
            raise Refused("Unified value source changed from its pinned hash")
    values = {p["kind"]: _profile_values(p["datastream"], p.get("base_profile_id", p["profile_id"])) for p in assessments}
    for item in assessments:
        if _sha(item["datastream"]) != item["sha256"]:
            raise Refused("Unified value source changed during conflict inventory")
    if set(values["cis"]) != set(values["stig"]):
        raise Refused("Unified benchmarks have different source value inventories")
    return {key: {kind: values[kind][key] for kind in ("cis", "stig")}
            for key in sorted(values["cis"]) if values["cis"][key]["value"] != values["stig"][key]["value"]}


def _validate_unified_values(assessments, remediation, register):
    conflicts = unified_value_conflicts(assessments)
    decisions = register.get("value_decisions", [])
    if not isinstance(decisions, list):
        raise Refused("Unified value conflicts require an explicit decision list")
    overrides = {d["value_id"]: d["selector"] for d in remediation.get("tailoring_values", [])}
    effective = _profile_values(remediation["datastream"], remediation["base_profile_id"], overrides)
    seen = set()
    for decision in decisions:
        if not isinstance(decision, dict):
            raise Refused("Unified value decision is invalid")
        identifier = decision.get("value_id")
        if (not isinstance(identifier, str) or identifier not in conflicts or identifier in seen
                or decision.get("choices") != conflicts[identifier]
                or decision.get("decision") not in ("stricter-compatible", "direct-conflict", "application-exception")
                or decision.get("effective") != effective[identifier]):
            raise Refused("Unified value decision must bind its source choices and exact effective value")
        _text(decision.get("rationale"), 8)
        seen.add(identifier)
    if seen != set(conflicts):
        raise Refused("Unified mapping must resolve every original benchmark value conflict")


def factory_directory():
    generation_defaults = Path(__file__).resolve().parents[2] / "share/defaults"
    if generation_defaults.is_dir():
        return generation_defaults
    return Path("/usr/share/nebulalog/baselines")


def factory_profile(baseline, directory=None):
    """Read a shipped candidate, without inventing operator or compliance approval."""
    directory = _directory(directory or factory_directory())
    catalog = _json(directory / "baseline-catalog.json")
    if catalog.get("schema") != 1 or baseline not in ("cis-level2", "stig", "unified"):
        raise Refused("Bundled unified hardening requires a completed conflict mapping")
    profile = catalog.get("profiles", {}).get(baseline)
    if baseline == "unified" and not isinstance(profile, dict):
        raise Refused("Bundled unified hardening requires a completed conflict mapping")
    if not isinstance(profile, dict):
        raise Refused("The selected bundled baseline is unavailable")
    expected = "baseline-" + ("cis" if baseline == "cis-level2" else baseline) + ".xml"
    if profile.get("tailoring_file") != expected:
        raise Refused("Bundled tailoring must use its fixed local filename")
    if baseline == "unified":
        if (profile.get("kind") != "stig" or profile.get("mapping_file") != "baseline-unified-mapping.json"
                or not SHA256.fullmatch(str(profile.get("mapping_sha256", "")))
                or _sha(directory / profile["mapping_file"]) != profile["mapping_sha256"]):
            raise Refused("Bundled unified hardening requires its exact hashed conflict mapping")
    return catalog, profile, directory / expected


def factory_policy(baseline, reviewer, directory=None, runner=run, now=None, expected_catalog=None):
    """Create content acceptance after the console operator reviews the candidate.

    This accepts exact content for assessment/remediation, never its findings.
    Final per-installation compliance review remains a separate required action.
    """
    now = now or _now()
    _text(reviewer, 3, 200)
    catalog, profile, tailoring = factory_profile(baseline, directory)
    if expected_catalog is not None and catalog != expected_catalog:
        raise Refused("Bundled baseline changed after content was displayed; review it again")
    review = {"approved": True, "reviewer": "Initial-console operator: " + reviewer,
              "platform_basis": catalog["platform_basis"], "benchmark_basis": profile["benchmark_basis"],
              "license_basis": catalog["license_basis"], "reviewed_at": now.isoformat(),
              "expires_at": (now + timedelta(days=90)).isoformat()}
    item = {key: catalog[key] for key in ("datastream", "sha256", "source_url", "content_revision")}
    item.update({key: profile[key] for key in ("kind", "base_profile_id", "profile_id", "tailoring_sha256", "tailoring_decisions")})
    for optional in ("tailoring_values", "tailoring_groups"):
        if profile.get(optional):
            item[optional] = profile[optional]
    item.update(platform="rocky9", reviewed=True, content_review=review, tailoring=str(tailoring))
    policy = {"schema": 1, "baseline": baseline, "assessments": [item]}
    if baseline == "unified":
        # The operator accepts packaged content; this never creates or renews
        # the separate publisher's semantic coverage/conflict review.
        policy.update(assessments=[factory_policy(kind, reviewer, directory, runner, now, catalog)["assessments"][0]
                                   for kind in ("cis-level2", "stig")],
                      unified_remediation=item,
                      unified_mapping={"path": str(directory / profile["mapping_file"]), "sha256": profile["mapping_sha256"]})
    return validate_policy(policy, runner, now)


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


@contextmanager
def initial_hardening(configuration, installation_id, baseline):
    """Serialize with firstboot/AIDE and permit mutation only before enrollment."""
    from .firstboot import FirstBoot
    manager = FirstBoot()
    if Path(configuration) != manager.paths.data / "configuration":
        raise Refused("Initial hardening requires the installed encrypted configuration")
    _directory(manager.paths.data / "manager")
    with locked(manager.paths.data / "manager/transaction.lock"), locked(manager.paths.bootstrap / "firstboot.lock"), locked(configuration / "bootstrap/runtime.lock"):
        gate = manager.gate()
        setup = _json(configuration / "bootstrap/setup.json")
        if setup.get("installation_id") != installation_id or gate.get("installation_id") != installation_id or setup.get("baseline") != baseline:
            raise Refused("Initial hardening belongs to another installation")
        if (manager.paths.etc / "configured").exists() or (manager.paths.etc / "configured").is_symlink():
            raise Refused("Initial hardening cannot run on a completed appliance")
        # Never silently invalidate an enrolled integrity baseline. Subsequent
        # policy migrations need the normal authorized lifecycle workflow.
        for name in ("aide-enrollment.json", "aide"):
            path = manager.paths.data / "manager" / name
            if path.exists() or path.is_symlink():
                raise Refused("Apply initial hardening before starting file-integrity enrollment")
        yield


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

    def remediate(self, installation_id, baseline, confirmation):
        """Apply one reviewed effective profile, retaining an unapproved receipt.

        Remediation output is not a compliance scan: OpenSCAP can emit multiple
        TestResults and `fixed` statuses. A separate scan/review remains required.
        """
        from .bootloader import remediation_checkpoint, accept_remediation
        require_linux_root()
        _directory(self.configuration)
        with initial_hardening(self.configuration, installation_id, baseline), locked(self.configuration / "baseline.lock"):
            if not SHA256.fullmatch(confirmation) or _sha(self.policy_path) != confirmation:
                raise Refused("Selected hardening policy changed since confirmation")
            policy = validate_policy(_json(self.policy_path), self.runner, self.clock())
            if policy.get("installation_id") != installation_id or policy["baseline"] != baseline:
                raise Refused("Selected policy belongs to another installation or baseline")
            if baseline == "unified" and not policy.get("unified_remediation"):
                raise Refused("Unified remediation requires an executable reviewed conflict mapping; sequential profiles are not equivalent")
            before = self.host(self.runner)
            if before.get("host_controls_ok") is not True:
                raise Refused("Initial hardening requires healthy host security controls")
            bootloader_state = self.configuration / "bootstrap"
            bootloader_checkpoint = remediation_checkpoint(bootloader_state, installation_id)
            profile = policy["unified_remediation"] if baseline == "unified" else policy["assessments"][0]
            output = _directory(self.configuration / "baseline-remediations" / uuid.uuid4().hex, create=True)
            content = output / "inputs" / Path(profile["datastream"]).name
            content.parent.mkdir(mode=0o700)
            content.write_bytes(trusted_file(Path(profile["datastream"])).read_bytes())
            content.chmod(0o600)
            if _sha(content) != profile["sha256"]:
                raise Refused("Hardening content changed while capturing immutable input")
            tailoring = None
            if profile.get("tailoring"):
                tailoring = content.parent / "tailoring.xml"
                if tailoring == content:
                    raise Refused("Tailoring and content filenames collide")
                tailoring.write_bytes(trusted_file(Path(profile["tailoring"])).read_bytes())
                tailoring.chmod(0o600)
                captured = dict(profile, datastream=str(content), tailoring=str(tailoring))
                validate_tailoring(captured, runner=self.runner)
            atomic_json(output / "policy.json", policy)
            if baseline == "unified":
                mapping = output / "unified-mapping.json"
                mapping.write_bytes(trusted_file(Path(policy["unified_mapping"]["path"])).read_bytes())
                mapping.chmod(0o600)
                if _sha(mapping) != policy["unified_mapping"]["sha256"]:
                    raise Refused("Unified mapping changed while capturing remediation inputs")
            record = {"schema": 1, "installation_id": installation_id, "baseline": baseline,
                      "policy_sha256": confirmation, "content_sha256": profile["sha256"],
                      "profile_id": profile["profile_id"], "tailoring_sha256": profile.get("tailoring_sha256"), "state": "running",
                      "unified_mapping_sha256": policy.get("unified_mapping", {}).get("sha256"),
                      "started_at": self.clock().isoformat(), "provenance": before,
                      "assessment_required": True, "review_required": True}
            atomic_json(output / "remediation.json", record)
            # Invalidate any prior assessment before the first host mutation.
            atomic_json(self.attempt_path, {"state": "remediation_pending", "installation_id": installation_id,
                                           "baseline": baseline, "remediation_id": output.name})
            try:
                try:
                    argv = ["oscap", "xccdf", "eval", "--remediate", "--profile", profile["profile_id"],
                            "--results", str(output / "results.xml"), "--report", str(output / "report.html")]
                    if tailoring:
                        argv += ["--tailoring-file", str(tailoring)]
                    self.runner(argv + [str(content)], timeout=3600)
                    code = 0
                except CommandFailed as error:
                    if error.returncode != 2:
                        raise
                    code = 2  # Findings remain; never translate this into success/compliance.
                if _sha(content) != profile["sha256"] or _sha(self.policy_path) != confirmation:
                    raise Refused("Hardening inputs changed during execution")
                if tailoring and _sha(tailoring) != profile["tailoring_sha256"]:
                    raise Refused("Tailoring changed during remediation")
                if baseline == "unified" and _sha(mapping) != policy["unified_mapping"]["sha256"]:
                    raise Refused("Unified mapping changed during remediation")
                after = self.host(self.runner)
                if after.get("host_controls_ok") is not True:
                    raise Refused("Host security checks failed after hardening")
                artifact_names = ["results.xml", "report.html", "policy.json"]
                if baseline == "unified":
                    artifact_names.append("unified-mapping.json")
                record.update(state="applied_scan_required", scanner_exit_code=code,
                              completed_at=self.clock().isoformat(), postconditions=after,
                              artifacts={name: _sha(output / name) for name in artifact_names})
                record['bootloader_refresh'] = accept_remediation(
                    bootloader_state, bootloader_checkpoint, output.name, confirmation, runner=self.runner)
            except Exception as error:
                record.update(state="failed_review_required", error_type=type(error).__name__)
                atomic_json(output / "remediation.json", record)
                raise
            atomic_json(output / "remediation.json", record)
            audit(self.configuration / "baseline-audit.jsonl", "baseline.remediate", installation_id=installation_id,
                  baseline=baseline, policy_sha256=confirmation, remediation_id=output.name)
            return record

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
                    if artifacts[destination.name] != profile["tailoring_sha256"]:
                        raise Refused("Tailoring changed while retaining its provenance")
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
    item = commands.add_parser("remediate")
    item.add_argument("--confirm-policy-sha256", required=True)
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
            elif args.command == "remediate":
                result = manager.remediate(installation_id, baseline, args.confirm_policy_sha256)
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
