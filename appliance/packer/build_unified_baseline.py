#!/usr/bin/env python3
"""Prepare unapproved Unified review inputs or package an already reviewed policy.

Run with the pinned vendor datastream and OpenSCAP in the isolated build tooling.
This never chooses a security precedence, approves coverage, or remediates a host.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from nebulalog_manager import baseline as b
from nebulalog_manager.common import Refused, atomic_json, run, trusted_file


PROFILE_FIELDS = ("kind", "base_profile_id", "profile_id", "tailoring_sha256", "tailoring_decisions")
OPTIONAL_FIELDS = ("tailoring_values", "tailoring_groups")


def review_inputs(directory, datastream, runner=run):
    directory, datastream = b._directory(directory), Path(datastream)
    catalog = b._json(directory / "baseline-catalog.json")
    content = b._content(datastream, runner)
    if catalog.get("schema") != 1 or content["sha256"] != catalog.get("sha256"):
        raise Refused("Review inputs require the exact pinned factory datastream")
    items, rules = [], {}
    for name, kind in (("cis-level2", "cis"), ("stig", "stig")):
        _, profile, tailoring = b.factory_profile(name, directory)
        item = {key: profile[key] for key in PROFILE_FIELDS}
        item.update({key: profile[key] for key in OPTIONAL_FIELDS if key in profile})
        item.update(datastream=str(datastream), sha256=content["sha256"], tailoring=str(tailoring))
        if item["kind"] != kind:
            raise Refused("Factory profile has the wrong assessment kind")
        b.validate_tailoring(item, content, runner)
        rules[kind] = b._mapping_rules(datastream, item["base_profile_id"])
        items.append(item)
    conflicts = b.unified_value_conflicts(items)
    return {"schema": 1, "baseline": "unified", "coverage_reviewed": False,
            "review": {"approved": False}, "source_sha256": content["sha256"],
            "assessments": {p["kind"]: b.assessment_binding(p) for p in items},
            "controls": [{"control": rule, "cis_rule": rule if rule in rules["cis"] else None,
                          "stig_rule": rule if rule in rules["stig"] else None,
                          "decision": "pending", "rationale": "", "effective_setting": "", "applied_rule": None}
                         for rule in sorted(rules["cis"] | rules["stig"])],
            "value_decisions": [{"value_id": key, "choices": choices, "decision": "pending", "rationale": "", "effective": None}
                                for key, choices in conflicts.items()],
            "existing_factory_adaptations": {p["kind"]: {key: p.get(key, []) for key in ("tailoring_decisions", *OPTIONAL_FIELDS)} for p in items},
            "warning": "An identifier union does not prove semantic compatibility. Review cross-rule effects, every value conflict and each exception before producing a merged policy."}


def package_policy(directory, policy_path, output, runner=run, now=None):
    """Capture fixed-name files only after complete existing policy validation."""
    directory, output = b._directory(directory), Path(output)
    catalog = b._json(directory / "baseline-catalog.json")
    policy = b.validate_policy(b._json(policy_path), runner, now)
    if policy["baseline"] != "unified" or not policy.get("unified_remediation"):
        raise Refused("Factory packaging requires a reviewed executable Unified policy")
    files = {}
    for name, kind in (("cis-level2", "cis"), ("stig", "stig")):
        _, profile, tailoring = b.factory_profile(name, directory)
        item = next(p for p in policy["assessments"] if p["kind"] == kind)
        if (any(item.get(key) != catalog.get(key) for key in ("sha256", "source_url", "content_revision")) or
                any(item.get(key, []) != profile.get(key, []) for key in (*PROFILE_FIELDS, *OPTIONAL_FIELDS))):
            raise Refused("Reviewed Unified assessments must match the exact factory candidates")
        raw = trusted_file(tailoring).read_bytes()
        if hashlib.sha256(raw).hexdigest() != item["tailoring_sha256"]:
            raise Refused("Factory tailoring changed while packaging")
        files[profile["tailoring_file"]] = raw
    merged = policy["unified_remediation"]
    profile = {key: merged[key] for key in PROFILE_FIELDS}
    profile.update({key: merged[key] for key in OPTIONAL_FIELDS if key in merged})
    profile.update(tailoring_file="baseline-unified.xml", mapping_file="baseline-unified-mapping.json",
                   mapping_sha256=policy["unified_mapping"]["sha256"],
                   benchmark_basis=merged["content_review"]["benchmark_basis"])
    for name, path, digest in ((profile["tailoring_file"], merged["tailoring"], merged["tailoring_sha256"]),
                               (profile["mapping_file"], policy["unified_mapping"]["path"], profile["mapping_sha256"])):
        raw = trusted_file(Path(path)).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise Refused("Reviewed Unified content changed while packaging")
        files[name] = raw
    catalog = copy.deepcopy(catalog)
    catalog["profiles"]["unified"] = profile
    b._directory(output.parent)
    output.mkdir(mode=0o700)  # Never overwrite source or a prior package.
    for name, raw in files.items():
        target = output / name
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(0o600)
    atomic_json(output / "baseline-catalog.json", catalog)
    return {"schema": 1, "source_sha256": catalog["sha256"],
            "files": {p.name: b._sha(p) for p in sorted(output.iterdir())},
            "approval_created": False, "guest_remediation_performed": False,
            "release_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-directory", type=Path, required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    review = actions.add_parser("review-inputs")
    review.add_argument("--datastream", type=Path, required=True)
    package = actions.add_parser("package")
    package.add_argument("--policy", type=Path, required=True)
    package.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = (review_inputs(args.catalog_directory, args.datastream) if args.action == "review-inputs"
              else package_policy(args.catalog_directory, args.policy, args.output))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
