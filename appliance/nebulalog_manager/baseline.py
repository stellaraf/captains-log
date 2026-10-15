"""Installation-bound SCAP assessment, initial hardening and explicit review."""
from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import uuid
import xml.etree.ElementTree as ET

from . import security
from .common import CommandFailed, Refused, atomic_json, audit, locked, require_linux_root, run, trusted_file

CONFIGURATION = Path("/var/lib/nebulalog/configuration")
CONTENT = Path("/usr/share/xml/scap/ssg/content")
SHA256 = re.compile(r"[0-9a-f]{64}")
RESULTS = {"pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational", "fixed"}
UNASSESSABLE = {"error", "unknown", "fixed"}


class ContentUpdate:
    """Fixed content-only release format; executable scanner updates are separate.

    The archive contains data, never a hook, executable or remediation recipe.
    A signed template is publisher provenance, not installation review authority.
    """
    KIND = "captains-log-compliance-content-v1"
    ROOT = Path("/usr/share/nebulalog/compliance-content")
    MAX_FILE = 128 * 1024**2
    MAX_ARCHIVE = 384 * 1024**2
    MAX_FILES = 16
    NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}\.(?:xml|json)")
    VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?")
    COMPONENT_FIELDS = {"artifact", "version", "from_versions", "rollback_safe", "content_schema", "descriptor_sha256"}

    @staticmethod
    def encoded(value):
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

    @staticmethod
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def engine(cls, runner=run):
        nevra = runner(["rpm", "-q", "--qf", "%{NEVRA}", "openscap-scanner"]).strip()
        if not re.fullmatch(r"openscap-scanner-[A-Za-z0-9.+:~_-]+\.x86_64", nevra):
            raise Refused("Compliance content requires one exact x86_64 scanner package")
        version = runner(["oscap", "--version"])
        if not isinstance(version, str) or not 1 <= len(version) <= 65536 or "OpenSCAP" not in version:
            raise Refused("Installed scanner identity is unavailable")
        return {"scanner_nevra": nevra, "version_sha256": cls.digest(version.encode())}

    @classmethod
    def validate_component(cls, value):
        if (not isinstance(value, dict) or set(value) != cls.COMPONENT_FIELDS
                or type(value["content_schema"]) is not int or value["content_schema"] != 1
                or value["rollback_safe"] is not True or not isinstance(value["version"], str)
                or not cls.VERSION.fullmatch(value["version"])
                or not isinstance(value["descriptor_sha256"], str) or not SHA256.fullmatch(value["descriptor_sha256"])
                or not isinstance(value["artifact"], str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}\.tar", value["artifact"])
                or not isinstance(value["from_versions"], list) or not value["from_versions"]
                or any(not isinstance(v, str) or not (cls.VERSION.fullmatch(v) or re.fullmatch(r"sha256:[a-f0-9]{64}", v)) for v in value["from_versions"])
                or len(set(value["from_versions"])) != len(value["from_versions"])):
            raise Refused("Baseline content requires its exact signed component contract")
        return value

    @classmethod
    def descriptor(cls, value):
        fields = {"schema", "kind", "version", "platform", "source_url", "content_revision", "engine", "files", "policies"}
        if (not isinstance(value, dict) or set(value) != fields or type(value["schema"]) is not int or value["schema"] != 1
                or value["kind"] != cls.KIND or value["platform"] != "rocky9-x86_64"
                or not isinstance(value["version"], str) or not cls.VERSION.fullmatch(value["version"])):
            raise Refused("Unsupported compliance-content descriptor")
        _text(value["source_url"], 8, 4096); _text(value["content_revision"], 1, 256)
        engine = value["engine"]
        if (not isinstance(engine, dict) or set(engine) != {"scanner_nevra", "version_sha256"}
                or not isinstance(engine["scanner_nevra"], str) or not re.fullmatch(r"openscap-scanner-[A-Za-z0-9.+:~_-]+\.x86_64", engine["scanner_nevra"])
                or not isinstance(engine["version_sha256"], str) or not SHA256.fullmatch(engine["version_sha256"])):
            raise Refused("Content must declare the exact qualified scanner engine")
        files = value["files"]
        if not isinstance(files, dict) or not 1 <= len(files) <= cls.MAX_FILES:
            raise Refused("Content file inventory is empty or exceeds its bound")
        total = 0
        for name, item in files.items():
            if (not isinstance(name, str) or not cls.NAME.fullmatch(name) or name == "content.json"
                    or not isinstance(item, dict) or set(item) != {"bytes", "sha256"}
                    or type(item["bytes"]) is not int or not 0 < item["bytes"] <= cls.MAX_FILE
                    or not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"])):
                raise Refused("Invalid bounded compliance-content file")
            total += item["bytes"]
        if total > cls.MAX_ARCHIVE - 1024**2:
            raise Refused("Compliance content exceeds its aggregate bound")
        policies = value["policies"]
        if not isinstance(policies, dict) or set(policies) != set(security.BASELINES):
            raise Refused("A content release must supply CIS Level 2, STIG and Unified templates")
        used = set()
        for name, policy in policies.items():
            if (not isinstance(policy, dict) or type(policy.get("schema")) is not int or policy["schema"] != 1
                    or policy.get("baseline") != name or "installation_id" in policy or "selection_id" in policy
                    or "content_update" in policy):
                raise Refused("Content policy template cannot assert installation authority")
            for item in [*policy.get("assessments", []), *([policy["unified_remediation"]] if policy.get("unified_remediation") else [])]:
                if not isinstance(item, dict):
                    raise Refused("Malformed content assessment template")
                for path_key, digest_key in (("datastream", "sha256"), ("tailoring", "tailoring_sha256")):
                    if path_key not in item and path_key == "tailoring":
                        continue
                    path = item.get(path_key)
                    if not isinstance(path, str) or path not in files or files[path]["sha256"] != item.get(digest_key):
                        raise Refused("Content template references an unbound file")
                    used.add(path)
            if policy.get("unified_mapping"):
                item = policy["unified_mapping"]
                if not isinstance(item, dict) or set(item) != {"path", "sha256"} or item["path"] not in files or files[item["path"]]["sha256"] != item["sha256"]:
                    raise Refused("Unified template mapping is not inventoried")
                used.add(item["path"])
        if used != set(files):
            raise Refused("Content archive cannot carry unused files")
        return value

    @classmethod
    def verify_archive(cls, path, *, expected_sha256=None, expected_descriptor_sha256=None, expected_version=None):
        from . import host_payload
        raw = host_payload.read_regular(Path(path), cls.MAX_ARCHIVE)
        checksum = cls.digest(raw)
        if expected_sha256 is not None and checksum != expected_sha256:
            raise Refused("Signed compliance archive hash changed")
        import io
        files = {}
        end = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                for entry in archive:
                    if (len(files) >= cls.MAX_FILES + 1 or not entry.isreg() or entry.name in files
                            or not cls.NAME.fullmatch(entry.name) or entry.pax_headers
                            or entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                            or entry.uid != 0 or entry.gid != 0 or entry.mode != 0o644
                            or entry.offset != end or entry.offset_data != entry.offset + 512
                            or not 0 < entry.size <= (1024**2 if entry.name == "content.json" else cls.MAX_FILE)):
                        raise Refused("Compliance archive has an unsafe or duplicate member")
                    stream = archive.extractfile(entry)
                    body = stream.read(entry.size + 1)
                    if len(body) != entry.size:
                        raise Refused("Compliance archive member length changed")
                    files[entry.name] = body
                    end = entry.offset_data + ((entry.size + 511) // 512) * 512
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise Refused("Malformed uncompressed compliance archive") from exc
        if len(raw) - end < 1024 or len(raw) % 512 or any(raw[end:]):
            raise Refused("Compliance archive has trailing or concatenated data")
        descriptor_raw = files.pop("content.json", b"")
        descriptor = cls.descriptor(host_payload.strict_json(descriptor_raw))
        if descriptor_raw != cls.encoded(descriptor):
            raise Refused("Compliance descriptor is not canonical JSON")
        if expected_descriptor_sha256 is not None and cls.digest(descriptor_raw) != expected_descriptor_sha256:
            raise Refused("Signed compliance descriptor hash changed")
        if expected_version is not None and descriptor["version"] != expected_version:
            raise Refused("Signed compliance version changed")
        if set(files) != set(descriptor["files"]) or any({"bytes": len(body), "sha256": cls.digest(body)} != descriptor["files"][name] for name, body in files.items()):
            raise Refused("Compliance archive differs from its complete inventory")
        for policy in descriptor["policies"].values():
            for item in [*policy.get("assessments", []), *([policy["unified_remediation"]] if policy.get("unified_remediation") else [])]:
                cls.closed_datastream(files[item["datastream"]])
        return {"descriptor": descriptor, "files": files, "archive_sha256": checksum}

    @classmethod
    def xml(cls, raw):
        if not isinstance(raw, bytes) or len(raw) > cls.MAX_FILE or b"<!DOCTYPE" in raw.upper().replace(b"\0", b"") or b"<!ENTITY" in raw.upper().replace(b"\0", b""):
            raise Refused("Unsafe or oversized compliance XML")
        try:
            return ET.fromstring(raw)
        except ET.ParseError as exc:
            raise Refused("Malformed compliance XML") from exc

    @classmethod
    def closed_datastream(cls, raw):
        """Reject executable/remote checks before invoking a native XML consumer.

        This deliberately does not strip SCE. Publisher preprocessing is a new
        reviewed content artifact and cannot claim unchanged rule semantics.
        """
        root = cls.xml(raw)
        ds = "{http://scap.nist.gov/schema/scap/source/1.2}"
        xlink = "{http://www.w3.org/1999/xlink}href"
        if root.tag != ds + "data-stream-collection":
            raise Refused("Content updates require a closed SCAP source datastream")
        components, refs, names = {}, {}, {}
        for node in root.iter():
            local = _local(node)
            if local in {"script", "extended-component", "check-content", "fix"}:
                raise Refused("Executable or inline checks require a separate execution recipe")
            if node.tag == ds + "component":
                identifier = node.get("id")
                if not identifier or identifier in components or len(node) != 1:
                    raise Refused("Ambiguous SCAP component")
                components[identifier] = node
            if node.tag == ds + "component-ref":
                identifier, href = node.get("id"), node.get(xlink)
                if not identifier or identifier in refs or not isinstance(href, str) or not href.startswith("#") or len(href) < 2:
                    raise Refused("External or ambiguous SCAP component reference")
                refs[identifier] = href[1:]
            if node.tag == "{urn:oasis:names:tc:entity:xmlns:xml:catalog}uri":
                name, uri = node.get("name"), node.get("uri")
                if (not isinstance(name, str) or not name or name.startswith(("/", ".")) or ":" in name or "\\" in name
                        or not isinstance(uri, str) or not uri.startswith("#") or names.get(name, uri[1:]) != uri[1:]):
                    raise Refused("Remote or ambiguous SCAP catalog reference")
                names[name] = uri[1:]
        if not components or not refs or any(component not in components for component in refs.values()) or any(ref not in refs for ref in names.values()):
            raise Refused("SCAP component graph is not closed")
        allowed = {"http://oval.mitre.org/XMLSchema/oval-definitions-5", "http://scap.nist.gov/schema/ocil/2"}
        for node in root.iter():
            local = _local(node)
            if local == "check" and node.get("system") not in allowed:
                raise Refused("Unsupported or executable SCAP check engine")
            if local == "check-content-ref" or local == "check" and node.get("href"):
                href = node.get("href")
                if href not in names:
                    raise Refused("Check content is not an embedded authenticated component")
        return root

    @classmethod
    def policy_paths(cls, policy, root):
        result = copy.deepcopy(policy)
        for item in [*result["assessments"], *([result["unified_remediation"]] if result.get("unified_remediation") else [])]:
            for key in ("datastream", "tailoring"):
                if key in item:
                    item[key] = str(Path(root) / item[key])
        if result.get("unified_mapping"):
            result["unified_mapping"]["path"] = str(Path(root) / result["unified_mapping"]["path"])
        return result

    @classmethod
    def _choices(cls, old, new, key, identifier):
        """Existing site decisions win; missing source IDs fail full validation."""
        original, proposed = old.get(key, []), new.get(key, [])
        for values in (original, proposed):
            if (not isinstance(values, list) or any(not isinstance(v, dict) or not isinstance(v.get(identifier), str) for v in values)
                    or len({v[identifier] for v in values}) != len(values)):
                raise Refused("Ambiguous site-policy decisions")
        merged = {v[identifier]: copy.deepcopy(v) for v in proposed}
        merged.update({v[identifier]: copy.deepcopy(v) for v in original})
        return [merged[name] for name in sorted(merged)]

    @classmethod
    def _tailoring(cls, item):
        ns = "{http://checklists.nist.gov/xccdf/1.2}"
        root = ET.Element(ns + "Tailoring", {"id": "xccdf_com_captainslog_content_tailoring"})
        ET.SubElement(root, ns + "benchmark", {"href": Path(item["datastream"]).name})
        ET.SubElement(root, ns + "version", {"time": "2000-01-01T00:00:00Z"}).text = "1"
        profile = ET.SubElement(root, ns + "Profile", {"id": item["profile_id"], "extends": item["base_profile_id"]})
        for key, identifier in (("tailoring_decisions", "rule_id"), ("tailoring_groups", "group_id")):
            for entry in item.get(key, []):
                if type(entry.get("selected")) is not bool:
                    raise Refused("Site selection must be explicitly boolean")
                ET.SubElement(profile, ns + "select", {"idref": entry[identifier], "selected": str(entry["selected"]).lower()})
        for entry in item.get("tailoring_values", []):
            ET.SubElement(profile, ns + "refine-value", {"idref": entry["value_id"], "selector": entry["selector"]})
        return ET.tostring(root, encoding="utf-8", xml_declaration=True)

    @classmethod
    def derive(cls, archive, previous, generation):
        """Construct exact bytes; never write or infer a review/exception renewal."""
        descriptor = archive["descriptor"]
        selected = previous.get("baseline")
        if selected not in security.BASELINES:
            raise Refused("Installed baseline selection is unavailable")
        template = copy.deepcopy(descriptor["policies"][selected])
        policy = copy.deepcopy(previous)
        files = dict(archive["files"])
        policy.pop("content_update", None)
        def profile(old, proposed, label):
            if old.get("kind") != proposed.get("kind"):
                raise Refused("A content release cannot change the selected baseline kind")
            result = copy.deepcopy(proposed)
            # Preserve all existing site fields, including custom exception
            # metadata. Only publisher source/profile identity is replaceable.
            replace = {"datastream", "sha256", "source_url", "content_revision", "profile_id", "base_profile_id", "tailoring", "tailoring_sha256"}
            for key, value in old.items():
                if key not in replace and key not in {"tailoring_decisions", "tailoring_groups", "tailoring_values"}:
                    result[key] = copy.deepcopy(value)
            for key, identifier in (("tailoring_decisions", "rule_id"), ("tailoring_groups", "group_id"), ("tailoring_values", "value_id")):
                merged = cls._choices(old, proposed, key, identifier)
                if merged or key in old or key in proposed:
                    result[key] = merged
            if old.get("tailoring") or proposed.get("tailoring"):
                result["base_profile_id"] = proposed.get("base_profile_id", proposed["profile_id"])
                if result["profile_id"] == result["base_profile_id"]:
                    result["profile_id"] = "xccdf_com_captainslog_profile_content_" + label
                name = "site-" + label + ".xml"
                if name in files:
                    raise Refused("Signed content collides with a reserved site-policy file")
                body = cls._tailoring(result)
                files[name] = body
                result["tailoring"], result["tailoring_sha256"] = name, cls.digest(body)
            return result
        old_by_kind = {p["kind"]: p for p in previous["assessments"]}
        if set(old_by_kind) != {p.get("kind") for p in template["assessments"]}:
            raise Refused("Content update cannot replace the selected baseline coverage")
        policy["assessments"] = [profile(old_by_kind[item["kind"]], item, item["kind"]) for item in template["assessments"]]
        if previous.get("unified_remediation") or template.get("unified_remediation"):
            if not previous.get("unified_remediation") or not template.get("unified_remediation"):
                raise Refused("Unified executable selection must retain its established policy shape")
            policy["unified_remediation"] = profile(previous["unified_remediation"], template["unified_remediation"], "unified")
        if selected == "unified":
            old_mapping = _json(previous["unified_mapping"]["path"])
            new_mapping = json.loads(files[template["unified_mapping"]["path"]])
            mapping = copy.deepcopy(old_mapping)
            mapping["controls"] = cls._choices(old_mapping, new_mapping, "controls", "control")
            mapping["assessments"] = {p["kind"]: assessment_binding(p) for p in policy["assessments"]}
            if policy.get("unified_remediation"):
                item = policy["unified_remediation"]
                mapping["remediation"] = {key: item[key] for key in ("sha256", "profile_id", "tailoring_sha256")}
            if "site-unified-mapping.json" in files:
                raise Refused("Signed content collides with a reserved site mapping")
            body = cls.encoded(mapping)
            files["site-unified-mapping.json"] = body
            policy["unified_mapping"] = {"path": "site-unified-mapping.json", "sha256": cls.digest(body)}
        policy = cls.policy_paths(policy, generation)
        return policy, files

    @classmethod
    def measure(cls, policy_path, runner=run):
        from . import host_payload
        raw = host_payload.read_regular(Path(policy_path), 1024**2, trusted=True)
        policy = host_payload.strict_json(raw)
        if policy.get("baseline") not in security.BASELINES or not isinstance(policy.get("assessments"), list) or not policy["assessments"]:
            raise Refused("Installed content identity requires the selected policy")
        if (not isinstance(policy.get("installation_id"), str) or str(uuid.UUID(policy["installation_id"])) != policy["installation_id"]
                or not isinstance(policy.get("selection_id"), str) or not re.fullmatch(r"[a-f0-9]{32}", policy["selection_id"])):
            raise Refused("Installed content identity requires exact installation selection")
        validate_policy(policy, runner)
        files = {}
        for item in [*policy["assessments"], *([policy["unified_remediation"]] if policy.get("unified_remediation") else [])]:
            for key, hash_key in (("datastream", "sha256"), ("tailoring", "tailoring_sha256")):
                if key not in item and key == "tailoring":
                    continue
                path = Path(item.get(key, ""))
                body = host_payload.read_regular(path, cls.MAX_FILE, trusted=True)
                if cls.digest(body) != item.get(hash_key):
                    raise Refused("Active content differs from the selected policy")
                files[str(path)] = {"bytes": len(body), "sha256": cls.digest(body)}
        if policy.get("unified_mapping"):
            item = policy["unified_mapping"]
            body = host_payload.read_regular(Path(item["path"]), cls.MAX_FILE, trusted=True)
            if cls.digest(body) != item["sha256"]:
                raise Refused("Active Unified mapping changed")
            files[item["path"]] = {"bytes": len(body), "sha256": cls.digest(body)}
        engine = cls.engine(runner)
        generation = cls.digest(cls.encoded({"policy_sha256": cls.digest(raw), "files": files, "engine": engine}))
        # Publisher upgrade endpoints must be portable between installations;
        # local policy/selection identity remains separately bound in generation.
        source_version = cls.digest(cls.encoded(sorted({item["sha256"] for item in policy["assessments"]})))
        version = cls.selected_authority(policy)["transition"]["version"] if "content_update" in policy else "sha256:" + source_version
        return {"version": version, "generation": generation, "policy_sha256": cls.digest(raw), "engine": engine}

    @classmethod
    def bridge(cls, stage, configuration=CONFIGURATION, runner=run):
        from . import host_payload
        configuration, stage = Path(configuration), Path(stage)
        setup = _json(configuration / "bootstrap/setup.json")
        identity = str(uuid.UUID(setup["installation_id"]))
        manager = Baseline(configuration, runner=runner)
        checks = manager.checks(identity, setup["baseline"])
        if not all(checks.get(key) is True for key in ("baseline_assessed", "baseline_review_complete")):
            raise Refused("Content inventory bridge requires the accepted selected baseline and exact current review")
        measured = cls.measure(manager.policy_path, runner)
        record = {"schema": 1, "kind": "compliance-content-enrollment-v1", "installation_id": identity,
                  "baseline": setup["baseline"], "identity": measured,
                  "assessment_sha256": _sha(manager.assessment_path), "review_sha256": _sha(manager.review_path)}
        cls._retain(stage / "content-enrollment.json", cls.encoded(record))
        return record

    @classmethod
    def bridge_health(cls, stage, configuration=CONFIGURATION, runner=run):
        from . import host_payload
        record = host_payload.strict_json(host_payload.read_regular(Path(stage) / "content-enrollment.json", 65536, trusted=True))
        if record != cls.bridge(stage, configuration, runner):
            raise Refused("Content bridge authority changed during full lifecycle acceptance")
        return record["identity"]

    @classmethod
    def semantic_identity(cls, policy, reader):
        """Conservative whole-source identity, not a guessed rule equivalence.

        XML formatting is retained: false negatives require review rather than
        accidentally treating a changed OVAL expression/value as equivalent.
        """
        value = copy.deepcopy(policy)
        value.pop("content_update", None)
        for item in [*value["assessments"], *([value["unified_remediation"]] if value.get("unified_remediation") else [])]:
            source = reader(item["datastream"])
            cls.xml(source)
            item["source_bytes_sha256"] = cls.digest(source)
            for key in ("datastream", "sha256", "source_url", "content_revision", "tailoring", "tailoring_sha256", "content_review"):
                item.pop(key, None)
        if value.get("unified_mapping"):
            mapping = json.loads(reader(value["unified_mapping"]["path"]))
            for key in ("review", "assessments", "remediation"):
                mapping.pop(key, None)
            value["unified_mapping"] = mapping
        return cls.digest(cls.encoded(value))

    @classmethod
    def review_binding(cls, previous_raw, policy_raw, archive_sha256):
        previous, policy = json.loads(previous_raw), json.loads(policy_raw)
        return {"installation_id": previous["installation_id"], "baseline": previous["baseline"],
                "previous_policy_sha256": cls.digest(previous_raw), "candidate_policy_sha256": cls.digest(policy_raw),
                "archive_sha256": archive_sha256}

    @classmethod
    def validate_review(cls, value, binding, previous, now=None):
        now = now or _now()
        fields = {"schema", "binding", "approved", "control_semantics_reviewed", "reviewer", "rationale", "reviewed_at", "expires_at"}
        if (not isinstance(value, dict) or set(value) != fields or type(value["schema"]) is not int or value["schema"] != 1
                or value["binding"] != binding or value["approved"] is not True or value["control_semantics_reviewed"] is not True):
            raise Refused("The exact content transition needs explicit control-semantics review")
        _text(value["reviewer"], 3, 200); _text(value["rationale"], 16, 8192)
        reviewed, expires = _date(value["reviewed_at"]), _date(value["expires_at"])
        old_expirations = [_date(item["content_review"]["expires_at"]) for item in previous["assessments"]]
        if previous.get("unified_remediation"):
            old_expirations.append(_date(previous["unified_remediation"]["content_review"]["expires_at"]))
        if previous.get("unified_mapping"):
            old_expirations.append(_date(_json(previous["unified_mapping"]["path"])["review"]["expires_at"]))
        if reviewed > now or not now < expires <= min(*old_expirations, reviewed + timedelta(days=90)):
            raise Refused("Content review cannot renew the original authority or exception expiry")
        return value

    @classmethod
    def _retain(cls, path, raw, mode=0o600):
        from . import host_payload
        path = Path(path)
        host_payload._trusted_tree(path.parent)
        if os.path.lexists(path):
            actual = host_payload.read_regular(path, cls.MAX_FILE, trusted=True)
            info = path.lstat()
            if actual != raw or stat.S_IMODE(info.st_mode) != mode or info.st_uid != 0 or info.st_gid != 0:
                raise Refused("Retained compliance content differs; automatic replacement refused")
            return
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @classmethod
    def prepare_transition(cls, stage, release, previous_identity, configuration=CONFIGURATION, runner=run):
        """Prepare nonactive exact bytes and review authority before maintenance."""
        from . import host_payload
        stage, configuration = Path(stage), Path(configuration)
        component = cls.validate_component(release["components"]["baseline"])
        artifacts = [item for item in release["artifacts"] if item["name"] == component["artifact"]]
        if len(artifacts) != 1:
            raise Refused("Baseline archive identity is ambiguous")
        archive = cls.verify_archive(stage / component["artifact"], expected_sha256=artifacts[0]["sha256"],
                                     expected_descriptor_sha256=component["descriptor_sha256"], expected_version=component["version"])
        observed = cls.measure(configuration / "security-policy.json", runner)
        if not isinstance(previous_identity, dict) or any(previous_identity.get(key) != observed[key] for key in ("version", "generation", "policy_sha256", "engine")):
            raise Refused("Active compliance content differs from its enrolled identity")
        if archive["descriptor"]["engine"] != observed["engine"]:
            raise Refused("Scanner changes require a separate qualified engine recipe")
        previous_raw = host_payload.read_regular(configuration / "security-policy.json", 1024**2, trusted=True)
        previous = host_payload.strict_json(previous_raw)
        token = cls.digest(cls.encoded({"archive": archive["archive_sha256"], "previous_policy": cls.digest(previous_raw)}))
        generation = cls.ROOT / token
        work = stage / "content-work"
        if not work.exists():
            work.mkdir(mode=0o700)
        host_payload._trusted_tree(work)
        policy, files = cls.derive(archive, previous, generation)
        policy["content_update"] = {"schema": 1, "generation": token, "archive_sha256": archive["archive_sha256"],
                                    "previous_policy_sha256": cls.digest(previous_raw)}
        for name, raw in files.items():
            cls._retain(work / name, raw)
        # Validate every advertised baseline, then the actual site-preserving
        # candidate. Native info/validation is observable through fixed hooks.
        for template in archive["descriptor"]["policies"].values():
            validate_policy(cls.policy_paths(template, work), runner)
        candidate_for_validation = copy.deepcopy(policy)
        candidate_for_validation.pop("content_update")
        for item in [*candidate_for_validation["assessments"], *([candidate_for_validation["unified_remediation"]] if candidate_for_validation.get("unified_remediation") else [])]:
            for key in ("datastream", "tailoring"):
                if key in item:
                    item[key] = str(work / Path(item[key]).name)
        if candidate_for_validation.get("unified_mapping"):
            candidate_for_validation["unified_mapping"]["path"] = str(work / Path(candidate_for_validation["unified_mapping"]["path"]).name)
        validate_policy(candidate_for_validation, runner)
        policy_raw = cls.encoded(policy)
        binding = cls.review_binding(previous_raw, policy_raw, archive["archive_sha256"])
        before_semantic = cls.semantic_identity(previous, lambda path: host_payload.read_regular(Path(path), cls.MAX_FILE, trusted=True))
        after_semantic = cls.semantic_identity(policy, lambda path: files[Path(path).name])
        request = {"schema": 1, "binding": binding, "generation": token, "before_semantic_sha256": before_semantic,
                   "after_semantic_sha256": after_semantic, "review_required": before_semantic != after_semantic}
        cls._retain(stage / "content-review-request.json", cls.encoded(request))
        cls._retain(work / "security-policy.json", policy_raw)
        review = None
        if request["review_required"]:
            review_path = stage.parent.parent / "content-reviews" / (token + ".json")
            if not os.path.lexists(review_path):
                raise Refused("Content semantics changed; review this exact content transition before installation")
            review = cls.validate_review(host_payload.strict_json(host_payload.read_regular(review_path, 65536, trusted=True)), binding, previous)
        transition = {"schema": 1, "kind": cls.KIND, "generation": token, "binding": binding,
                      "descriptor_sha256": component["descriptor_sha256"], "version": component["version"],
                      "engine": observed["engine"], "previous_identity": previous_identity,
                      "before_semantic_sha256": before_semantic, "after_semantic_sha256": after_semantic, "review": review}
        files.update({"content.json": cls.encoded(archive["descriptor"]), "original-policy.json": previous_raw,
                      "security-policy.json": policy_raw, "transition.json": cls.encoded(transition)})
        if any(name in archive["files"] for name in {"original-policy.json", "security-policy.json", "transition.json"}):
            raise Refused("Signed content collides with fixed transaction evidence")
        for name, raw in files.items():
            cls._retain(work / name, raw)
        expected = {"schema": 1, "kind": cls.KIND, "generation": token, "root": str(generation),
                    "transition_sha256": cls.digest(files["transition.json"]),
                    "before_policy_sha256": cls.digest(previous_raw), "after_policy_sha256": cls.digest(policy_raw),
                    "files": {name: {"bytes": len(raw), "sha256": cls.digest(raw)} for name, raw in sorted(files.items())}}
        if {item.name for item in work.iterdir()} != set(files):
            raise Refused("Unrelated files appeared in content preparation")
        cls._retain(stage / "content-plan.json", cls.encoded(expected))
        return expected

    @classmethod
    def review_template(cls, stage):
        from . import host_dispatch, host_payload
        transaction, _ = host_dispatch.transaction_binding(Path(stage))
        if transaction.get("activation_started") is not False or transaction["state"] != "preflight_failed":
            raise Refused("Content review requires a settled failed preflight before activation")
        host_dispatch.HookJournal(stage, transaction).assert_settled()
        request = host_payload.strict_json(host_payload.read_regular(Path(stage) / "content-review-request.json", 65536, trusted=True))
        if request.get("review_required") is not True:
            raise Refused("This content transition does not require new semantic authority")
        return {"schema": 1, "binding": request["binding"], "approved": False, "control_semantics_reviewed": False,
                "reviewer": "", "rationale": "", "reviewed_at": _now().isoformat(), "expires_at": ""}

    @classmethod
    def approve(cls, stage, review_path, confirmation, configuration=CONFIGURATION):
        from . import host_payload
        require_linux_root()
        stage = Path(stage)
        template = cls.review_template(stage)
        raw = host_payload.read_regular(stage / "content-work/security-policy.json", 1024**2, trusted=True)
        if cls.digest(raw) != confirmation or template["binding"]["candidate_policy_sha256"] != confirmation:
            raise Refused("Candidate policy changed since explicit review")
        previous_raw = host_payload.read_regular(Path(configuration) / "security-policy.json", 1024**2, trusted=True)
        if cls.digest(previous_raw) != template["binding"]["previous_policy_sha256"]:
            raise Refused("Installed policy changed before content approval")
        value = host_payload.strict_json(host_payload.read_regular(Path(review_path), 65536, trusted=True))
        cls.validate_review(value, template["binding"], host_payload.strict_json(previous_raw))
        token = json.loads(raw)["content_update"]["generation"]
        root = stage.parent.parent / "content-reviews"
        if not root.exists():
            root.mkdir(mode=0o700)
        cls._retain(root / (token + ".json"), cls.encoded(value))
        return {"ok": True, "generation": token, "candidate_policy_sha256": confirmation,
                "findings_approved": False, "installed": False}

    @classmethod
    def publish(cls, stage, plan):
        """Publish only inactive immutable files; the active policy is untouched.

        The protected owner record precedes any covered-path creation. A partial
        publication can continue only with the identical owner/inventory, and
        an unrelated existing directory is never adopted even if bytes match.
        """
        from . import host_payload
        stage = Path(stage)
        root = cls.ROOT / plan["generation"]
        if plan["root"] != str(root):
            raise Refused("Content generation path changed")
        owners = stage.parent.parent / "content-owners"
        if not owners.exists():
            owners.mkdir(mode=0o700)
        owner = owners / (plan["generation"] + ".json")
        owner_body = cls.encoded({"schema": 1, "plan_sha256": cls.digest(cls.encoded(plan)), "plan": plan})
        existed = os.path.lexists(owner)
        if not existed and os.path.lexists(root):
            raise Refused("Existing content generation has no protected publication owner")
        cls._retain(owner, owner_body)
        if not cls.ROOT.exists():
            host_payload._trusted_tree(cls.ROOT.parent)
            cls.ROOT.mkdir(mode=0o555)
            cls.ROOT.chmod(0o555)
        host_payload._trusted_tree(cls.ROOT)
        parent_info = cls.ROOT.lstat()
        if parent_info.st_uid != 0 or parent_info.st_gid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o555:
            raise Refused("Content generation parent is not immutable root-owned storage")
        if not root.exists():
            root.mkdir(mode=0o555)
            root.chmod(0o555)
        host_payload._trusted_tree(root)
        info = root.lstat()
        if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o555:
            raise Refused("Content generation directory metadata changed")
        if {path.name for path in root.iterdir()} - set(plan["files"]):
            raise Refused("Content generation contains foreign files")
        for name, expected in plan["files"].items():
            raw = host_payload.read_regular(stage / "content-work" / name, cls.MAX_FILE, trusted=True)
            if {"bytes": len(raw), "sha256": cls.digest(raw)} != expected:
                raise Refused("Prepared content differs from its immutable plan")
            cls._retain(root / name, raw, 0o444)
        return cls.validate_plan(stage, plan)

    @classmethod
    def validate_plan(cls, stage, plan, release=None):
        from . import host_payload
        fields = {"schema", "kind", "generation", "root", "transition_sha256", "before_policy_sha256", "after_policy_sha256", "files"}
        if (not isinstance(plan, dict) or set(plan) != fields or type(plan["schema"]) is not int or plan["schema"] != 1
                or plan["kind"] != cls.KIND or not isinstance(plan["generation"], str) or not SHA256.fullmatch(plan["generation"])
                or plan["root"] != str(cls.ROOT / plan["generation"])):
            raise Refused("Malformed fixed content plan")
        root = Path(plan["root"])
        owner = host_payload.strict_json(host_payload.read_regular(Path(stage).parent.parent / "content-owners" / (plan["generation"] + ".json"), 1024**2, trusted=True))
        if owner != {"schema": 1, "plan_sha256": cls.digest(cls.encoded(plan)), "plan": plan}:
            raise Refused("Content publication ownership changed")
        def read(name):
            if not isinstance(name, str) or not cls.NAME.fullmatch(name):
                raise Refused("Unsafe immutable content filename")
            return host_payload.read_regular(root / name, cls.MAX_FILE, trusted=True)
        if not isinstance(plan["files"], dict) or not 5 <= len(plan["files"]) <= cls.MAX_FILES + 8 or {p.name for p in root.iterdir()} != set(plan["files"]):
            raise Refused("Content generation inventory changed")
        for name, info in plan["files"].items():
            raw = read(name)
            metadata = (root / name).lstat()
            if info != {"bytes": len(raw), "sha256": cls.digest(raw)} or stat.S_IMODE(metadata.st_mode) != 0o444 or metadata.st_uid != 0 or metadata.st_gid != 0:
                raise Refused("Immutable content bytes or security metadata changed")
        for path in (cls.ROOT, root):
            metadata = path.lstat()
            if stat.S_IMODE(metadata.st_mode) != 0o555 or metadata.st_uid != 0 or metadata.st_gid != 0:
                raise Refused("Immutable content directory changed")
        descriptor_raw = read("content.json")
        descriptor = cls.descriptor(host_payload.strict_json(descriptor_raw))
        transition_raw, previous_raw, policy_raw = read("transition.json"), read("original-policy.json"), read("security-policy.json")
        transition, previous, policy = map(host_payload.strict_json, (transition_raw, previous_raw, policy_raw))
        if (not isinstance(transition, dict) or set(transition) != {"schema", "kind", "generation", "binding", "descriptor_sha256", "version", "engine", "previous_identity", "before_semantic_sha256", "after_semantic_sha256", "review"}
                or type(transition.get("schema")) is not int or transition["schema"] != 1 or transition["kind"] != cls.KIND
                or cls.encoded(transition) != transition_raw or cls.encoded(descriptor) != descriptor_raw
                or cls.digest(transition_raw) != plan["transition_sha256"] or cls.digest(previous_raw) != plan["before_policy_sha256"]
                or cls.digest(policy_raw) != plan["after_policy_sha256"]
                or transition.get("binding") != cls.review_binding(previous_raw, policy_raw, transition.get("binding", {}).get("archive_sha256"))
                or transition.get("descriptor_sha256") != cls.digest(descriptor_raw) or transition.get("version") != descriptor["version"]
                or transition.get("engine") != descriptor["engine"] or transition.get("generation") != plan["generation"]):
            raise Refused("Content transition identity changed")
        archive_sha = transition["binding"]["archive_sha256"]
        if not isinstance(archive_sha, str) or not SHA256.fullmatch(archive_sha) or plan["generation"] != cls.digest(cls.encoded({"archive": archive_sha, "previous_policy": cls.digest(previous_raw)})):
            raise Refused("Content generation is not bound to its source and previous selection")
        if release is not None:
            component = cls.validate_component(release["components"]["baseline"])
            artifacts = [item for item in release["artifacts"] if item["name"] == component["artifact"]]
            if (len(artifacts) != 1 or artifacts[0]["sha256"] != archive_sha
                    or component["descriptor_sha256"] != cls.digest(descriptor_raw) or component["version"] != descriptor["version"]):
                raise Refused("Content plan differs from the signed release")
        source_files = {name: read(name) for name in descriptor["files"]}
        if any({"bytes": len(body), "sha256": cls.digest(body)} != descriptor["files"][name] for name, body in source_files.items()):
            raise Refused("Signed content source changed")
        rebuilt, derived = cls.derive({"descriptor": descriptor, "files": source_files}, previous, root)
        rebuilt["content_update"] = {"schema": 1, "generation": plan["generation"], "archive_sha256": archive_sha,
                                     "previous_policy_sha256": cls.digest(previous_raw)}
        if cls.encoded(rebuilt) != policy_raw or any(read(name) != raw for name, raw in derived.items()):
            raise Refused("Candidate policy no longer preserves its exact site authority")
        before = cls.semantic_identity(previous, lambda path: host_payload.read_regular(Path(path), cls.MAX_FILE, trusted=True))
        after = cls.semantic_identity(policy, lambda path: read(Path(path).name))
        if transition.get("before_semantic_sha256") != before or transition.get("after_semantic_sha256") != after:
            raise Refused("Content semantic identity changed")
        if before != after:
            # Plan authority is historical: expiry must not prevent restoring
            # the exact old bytes. Selecting/assessing the candidate checks live
            # expiry separately; no approval is renewed here.
            review = transition.get("review")
            cls.validate_review(review, transition["binding"], previous, now=_date(review.get("reviewed_at")) if isinstance(review, dict) else None)
        elif transition.get("review") is not None:
            raise Refused("Unexpected equivalent-content approval")
        additions = [{"path": str(path), "kind": "directory", "mode": 0o555, "uid": 0, "gid": 0} for path in (cls.ROOT, root)]
        additions.extend({"path": str(root / name), "kind": "file", "mode": 0o444, "uid": 0, "gid": 0, **info} for name, info in sorted(plan["files"].items()))
        return {"plan": plan, "additions": additions, "policy": policy, "before": previous_raw, "after": policy_raw,
                "transition": transition}

    @classmethod
    def selected_authority(cls, policy):
        from . import host_dispatch, host_payload
        selection = policy.get("content_update")
        if (not isinstance(selection, dict) or set(selection) != {"schema", "generation", "archive_sha256", "previous_policy_sha256"}
                or type(selection["schema"]) is not int or selection["schema"] != 1
                or any(not isinstance(selection[key], str) or not SHA256.fullmatch(selection[key]) for key in ("generation", "archive_sha256", "previous_policy_sha256"))):
            raise Refused("Selected content transition authority is malformed")
        owner = host_payload.strict_json(host_payload.read_regular(host_dispatch.STATE / "content-owners" / (selection["generation"] + ".json"), 1024**2, trusted=True))
        result = cls.validate_plan(host_dispatch.STATE / "releases" / "content-authority", owner.get("plan"))
        if result["policy"] != policy:
            raise Refused("Selected policy differs from its reviewed immutable transition")
        cls.current_review(result)
        return result

    @classmethod
    def current_review(cls, result):
        transition = result["transition"]
        if transition["review"] is not None:
            cls.validate_review(transition["review"], transition["binding"], json.loads(result["before"]))

    @classmethod
    def assessment_evidence(cls, directory, kind, profile, *, source=None):
        """Conservative complete ARF equality, not a rule/status waiver.

        Keep every instance, collected item, object, variable, definition result,
        source and relationship. Only generated TestResult IDs and the explicitly
        named scan/collection times are volatile. Other format differences fail
        closed; missing OVAL system characteristics never establishes equivalence.
        """
        directory = Path(directory)
        arf = cls.xml(trusted_file(directory / (kind + ".arf.xml")).read_bytes())
        if arf.tag != "{http://scap.nist.gov/schema/asset-reporting-format/1.1}asset-report-collection":
            raise Refused("Full ARF assessment evidence is required")
        xccdf = "{http://checklists.nist.gov/xccdf/1.2}"
        oval = "{http://oval.mitre.org/XMLSchema/oval-results-5}"
        system = "{http://oval.mitre.org/XMLSchema/oval-system-characteristics-5}"
        common = "{http://oval.mitre.org/XMLSchema/oval-common-5}"
        tests = list(arf.iter(xccdf + "TestResult"))
        actual = cls.xml(trusted_file(directory / (kind + ".xml")).read_bytes())
        standalone = [node for node in actual.iter() if _local(node) == "TestResult"]
        if (len(tests) != 1 or len(standalone) != 1
                or [node.get("idref") for node in tests[0] if _local(node) == "profile"] != [profile]
                or not list(arf.iter(oval + "oval_results")) or not list(arf.iter(system + "collected_objects"))):
            raise Refused("ARF lacks exact XCCDF result or collected OVAL facts")
        for result in arf.iter(oval + "oval_results"):
            systems = result.findall(oval + "results/" + oval + "system")
            if len(systems) != 1:
                raise Refused("ARF OVAL host result is missing or ambiguous")
            current = systems[0]
            characteristics = current.findall(system + "oval_system_characteristics")
            if len(characteristics) != 1:
                raise Refused("ARF OVAL collected host facts are missing")
            facts = characteristics[0]
            objects, data = facts.findall(system + "collected_objects"), facts.findall(system + "system_data")
            if len(objects) != 1 or len(data) > 1:
                raise Refused("ARF OVAL fact collection is ambiguous")
            items = list(data[0]) if data else []
            identifiers = [node.get("id") for node in items]
            object_ids = [node.get("id") for node in objects[0]]
            if (any(not value for value in identifiers + object_ids) or len(set(identifiers)) != len(identifiers)
                    or len(set(object_ids)) != len(object_ids)):
                raise Refused("ARF OVAL item or object identities are missing or duplicated")
            refs = [node.get("item_ref") for node in objects[0].iter(system + "reference")]
            tested = [node.get("item_id") for node in current.iter(oval + "tested_item")]
            if any(ref not in identifiers for ref in refs + tested) or set(identifiers) - set(refs):
                raise Refused("ARF OVAL item evidence is missing or foreign to its host")
        # Namespace-qualified XCCDF results must agree exactly before reducing
        # volatile metadata. This also binds the human-readable summary's input.
        def node_value(node, parent=None, volatile=True):
            attributes = dict(node.attrib)
            if volatile and node.tag == xccdf + "TestResult":
                if not re.fullmatch(r"xccdf_org.open-scap_testresult_[A-Za-z0-9_.:-]+", attributes.get("id", "")):
                    raise Refused("Unknown generated assessment identity")
                attributes.pop("id")
                for key in ("start-time", "end-time"):
                    _date(attributes.pop(key, None))
            elif volatile and node.tag == xccdf + "rule-result" and "time" in attributes:
                _date(attributes.pop("time"))
            text = node.text or ""
            if volatile and node.tag == common + "timestamp" and parent in (oval + "generator", system + "generator"):
                try:
                    datetime.fromisoformat(text.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    raise Refused("Invalid OVAL collection timestamp") from None
                text = "<assessment-time>"
            elif list(node) and not text.strip():
                text = ""
            tail = node.tail or ""
            if not tail.strip(): tail = ""
            return [node.tag, sorted(attributes.items()), text, tail,
                    [node_value(child, node.tag, volatile) for child in node]]
        arf_ns = "{http://scap.nist.gov/schema/asset-reporting-format/1.1}"
        requests = list(arf.iter(arf_ns + "report-request"))
        if (len(requests) != 1 or len(requests[0]) != 1 or requests[0][0].tag != arf_ns + "content"
                or len(requests[0][0]) != 1):
            raise Refused("ARF source request is missing or ambiguous")
        expected_source = cls.xml(trusted_file(Path(source) if source is not None else directory / (kind + "-content.xml")).read_bytes())
        if node_value(requests[0][0][0], volatile=False) != node_value(expected_source, volatile=False):
            raise Refused("ARF embedded source differs from the exact retained assessment content")
        # OpenSCAP embeds the same result but rewrites benchmark/check hrefs to
        # internal ARF components/reports and adds the bound target asset link.
        # Prove those references before comparing every remaining result field.
        arf_ns = "{http://scap.nist.gov/schema/asset-reporting-format/1.1}"
        def unique(tag):
            values = list(arf.iter(tag))
            ids = [node.get("id") for node in values]
            if any(not isinstance(key, str) or not key for key in ids) or len(set(ids)) != len(ids):
                raise Refused("Duplicate or missing ARF graph identity")
            return dict(zip(ids, values))
        reports = unique(arf_ns + "report")
        assets = unique(arf_ns + "asset")
        components = unique("{http://scap.nist.gov/schema/scap/source/1.2}component")
        def reference(node, values):
            href = node.get("href", "")
            if not href.startswith("#") or href.count("#") != 1 or href[1:] not in values:
                raise Refused("ARF result reference is not an exact internal fragment")
            return values[href[1:]]
        left, right = copy.deepcopy(tests[0]), copy.deepcopy(standalone[0])
        if len(list(left.iter(xccdf + "benchmark"))) != 1 or len(list(left.iter(xccdf + "target-id-ref"))) != 1:
            raise Refused("ARF assessment source or asset link is ambiguous")
        for node in left.iter():
            if node.tag == xccdf + "benchmark":
                target = reference(node, components)
                if len(target) != 1 or target[0].tag != xccdf + "Benchmark" or target[0].get("id") != node.get("id"):
                    raise Refused("ARF benchmark source reference is unresolved")
            if node.tag == xccdf + "check-content-ref":
                target = reference(node, reports)
                if (len(target) != 1 or target[0].tag != arf_ns + "content" or len(target[0]) != 1
                        or target[0][0].tag != oval + "oval_results"
                        or sum(child.get("id") == node.get("name") for child in target.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition")) != 1):
                    raise Refused("ARF check result reference is unresolved")
        for node in list(left):
            if node.tag == xccdf + "target-id-ref":
                if (set(node.attrib) != {"name", "system", "href"} or node.get("name") not in assets
                        or node.get("system") != "http://scap.nist.gov/schema/asset-identification/1.1" or node.get("href") != ""):
                    raise Refused("ARF target asset reference is unresolved")
                left.remove(node)
        for root in (left, right):
            for node in root.iter():
                if node.tag in (xccdf + "benchmark", xccdf + "check-content-ref"):
                    node.attrib.pop("href", None)
        if node_value(left, volatile=False) != node_value(right, volatile=False):
            raise Refused("ARF and standalone assessment results differ")
        return cls.digest(cls.encoded(node_value(arf)))

    @staticmethod
    def assessment_host(runner):
        value = _host(runner)
        packages = runner(["rpm", "-qa", "--qf", "%{NEVRA}\n"])
        if not packages or len(packages) > 1024**2:
            raise Refused("Content assessment package inventory is unavailable")
        value.update(boot_id=str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip())),
                     packages_sha256=hashlib.sha256("\n".join(sorted(packages.splitlines())).encode()).hexdigest())
        return value

    @classmethod
    def _assessment_owner(cls, stage, pointer, role="candidate"):
        from . import host_payload
        if role not in {"candidate", "rollback"}:
            raise Refused("Unknown content assessment direction")
        root = Path(stage).parent.parent
        fields = {"schema", "directory", "policy_sha256", "host"}
        if (not isinstance(pointer, dict) or set(pointer) != fields or type(pointer["schema"]) is not int or pointer["schema"] != 1):
            raise Refused("Malformed content assessment owner")
        directory = Path(pointer["directory"])
        if (directory.name != "content-" + role + "-assessment" or directory.parent.parent != root / "releases"
                or directory.resolve() != directory or not directory.is_absolute()):
            raise Refused("Candidate assessment belongs to another protected release")
        host_payload._trusted_tree(directory)
        token = cls.digest(cls.encoded({"policy_sha256": pointer["policy_sha256"], "host": pointer["host"], "role": role}))
        index = root / "content-assessments" / (token + ".json")
        if host_payload.read_regular(index, 65536, trusted=True) != cls.encoded(pointer):
            raise Refused("Candidate assessment owner changed")
        return directory

    @classmethod
    def candidate_assessment(cls, stage, policy_raw, runner=run, *, host=None, role="candidate"):
        """Retain an operation-owned assessment for explicit preflight review."""
        from . import host_payload
        stage = Path(stage)
        if role not in {"candidate", "rollback"}:
            raise Refused("Unknown content assessment direction")
        policy = host_payload.strict_json(policy_raw)
        host = host or cls.assessment_host
        identity = host(runner)
        token = cls.digest(cls.encoded({"policy_sha256": cls.digest(policy_raw), "host": identity, "role": role}))
        root = stage.parent.parent / "content-assessments"
        if not root.exists(): root.mkdir(mode=0o700)
        directory = stage / ("content-" + role + "-assessment")
        if not directory.exists(): directory.mkdir(mode=0o700)
        cls._retain(directory / "security-policy.json", policy_raw)
        index = root / (token + ".json")
        pointer = {"schema": 1, "directory": str(directory), "policy_sha256": cls.digest(policy_raw), "host": identity}
        if os.path.lexists(index):
            pointer = host_payload.strict_json(host_payload.read_regular(index, 65536, trusted=True))
        else:
            cls._retain(index, cls.encoded(pointer))
        cls._assessment_owner(stage, pointer, role)
        cls._retain(stage / ("content-" + role + "-assessment.json"), cls.encoded(pointer))
        manager = Baseline(directory, runner=runner, host=host, full_evidence=True)
        if not os.path.lexists(manager.attempt_path):
            manager.scan(policy["installation_id"], policy["baseline"])
        assessment, findings, assessed = manager._validated_assessment(policy["installation_id"], policy["baseline"])
        if not assessed:
            raise Refused("Candidate content produced unusable assessment results")
        try:
            continuation = cls.finding_continuation(stage, manager, runner, host=host, role=role)
        except (Refused, OSError, ValueError, KeyError, TypeError):
            raise Refused("Review the retained candidate content assessment before activation: " + pointer["directory"]) from None
        return {**pointer, "assessment_sha256": _sha(manager.assessment_path), "continuation": continuation}

    @classmethod
    def finding_continuation(cls, stage, current, runner=run, *, host=None, role="candidate", current_locked=False):
        from . import host_payload
        pointer = host_payload.strict_json(host_payload.read_regular(Path(stage) / ("content-" + role + "-assessment.json"), 65536, trusted=True))
        directory = cls._assessment_owner(stage, pointer, role)
        with ExitStack() as locks:
            if not current_locked:
                locks.enter_context(locked(current.configuration / "baseline.lock"))
            if directory != current.configuration:
                locks.enter_context(locked(directory / "baseline.lock"))
            return cls._finding_continuation_locked(stage, current, runner, host=host, role=role)

    @classmethod
    def _finding_continuation_locked(cls, stage, current, runner=run, *, host=None, role="candidate"):
        """Carry only exact observed facts; original review and expiry stay intact."""
        from . import host_payload
        stage = Path(stage)
        pointer = host_payload.strict_json(host_payload.read_regular(stage / ("content-" + role + "-assessment.json"), 65536, trusted=True))
        directory = cls._assessment_owner(stage, pointer, role)
        host = host or cls.assessment_host
        manager = Baseline(directory, runner=runner, host=host, full_evidence=True)
        policy = host_payload.strict_json(host_payload.read_regular(manager.policy_path, 1024**2, trusted=True))
        if (pointer["policy_sha256"] != _sha(manager.policy_path) or pointer["host"] != host(runner)
                or _sha(current.policy_path) != pointer["policy_sha256"]):
            raise Refused("Candidate findings belong to another policy or host")
        prior, previous_findings, assessed = manager._validated_assessment(policy["installation_id"], policy["baseline"])
        assessment, findings, current_ok = current._validated_assessment(policy["installation_id"], policy["baseline"])
        if not assessed or not current_ok or previous_findings != findings or prior["assessments"] != assessment["assessments"]:
            raise Refused("Fresh candidate outcomes changed; earlier review cannot authorize them")
        before = directory / "baseline-assessments" / prior["artifact_directory"]
        after = current.configuration / "baseline-assessments" / assessment["artifact_directory"]
        evidence = {}
        for item in policy["assessments"]:
            old = cls.assessment_evidence(before, item["kind"], item["profile_id"])
            new = cls.assessment_evidence(after, item["kind"], item["profile_id"])
            if old != new:
                raise Refused("Collected assessment facts or instance scope changed despite unchanged result status")
            evidence[item["kind"]] = new
        automated = all(item["automated_assessment_passed"] for item in assessment["assessments"])
        review = None
        if not automated:
            review = _json(manager.review_path)
            manager._validate_review(review, policy["installation_id"], policy["baseline"], findings)
        return {"schema": 1, "kind": "exact-content-findings-continuation-v1", "configuration": str(directory),
                "review_sha256": None if automated else _sha(manager.review_path),
                "reviewed_assessment_sha256": _sha(manager.assessment_path), "current_assessment_sha256": _sha(current.assessment_path),
                "policy_sha256": pointer["policy_sha256"], "evidence": evidence,
                "expires_at": None if automated else review["expires_at"], "manual_attestation_revalidated": any(f["manual_only"] for f in findings)}


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
    if "content_update" in policy:
        ContentUpdate.selected_authority(policy)
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
    def __init__(self, configuration=CONFIGURATION, *, runner=run, scanner=security.scan, host=_host, clock=_now, full_evidence=False):
        self.full_evidence = full_evidence
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
            summary = self.scanner(self.policy_path, output, self.runner, **({"full_evidence": True} if self.full_evidence else {}))
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
                if self.full_evidence:
                    ContentUpdate.assessment_evidence(output, kind, profile["profile_id"])
                    artifacts[kind + ".arf.xml"] = _sha(output / (kind + ".arf.xml"))
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
            if value.get("evidence_schema") == "arf-v1":
                expected.add(profile["kind"] + ".arf.xml")
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
            if self.full_evidence and value.get("evidence_schema") != "arf-v1":
                raise Refused("Full assessment evidence is required for content continuation")
            if value.get("evidence_schema") == "arf-v1":
                ContentUpdate.assessment_evidence(output, kind, profile["profile_id"])
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
    item = commands.add_parser("content-review-template")
    item.add_argument("--stage", type=Path, required=True)
    item = commands.add_parser("content-review")
    item.add_argument("--stage", type=Path, required=True)
    item.add_argument("--review-file", type=Path, required=True)
    item.add_argument("--confirm-candidate-policy-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        require_linux_root()
        if args.command == "inventory":
            result = inventory(args.content_directory)
        elif args.command == "content-review-template":
            result = ContentUpdate.review_template(args.stage)
        elif args.command == "content-review":
            result = ContentUpdate.approve(args.stage, args.review_file, args.confirm_candidate_policy_sha256, args.configuration)
        else:
            setup = _json(args.setup)
            installation_id, baseline = setup["installation_id"], setup["baseline"]
            role = next((role for role in ("candidate", "rollback") if args.configuration.name == "content-" + role + "-assessment"), None)
            if role:
                stage = args.configuration.parent
                pointer = _json(stage / ("content-" + role + "-assessment.json"))
                if ContentUpdate._assessment_owner(stage, pointer, role) != args.configuration or args.command not in {"review-template", "review", "status"}:
                    raise Refused("Retained content assessment permits only exact review or status")
                manager = Baseline(args.configuration, host=ContentUpdate.assessment_host, full_evidence=True)
            else:
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
