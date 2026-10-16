#!/usr/bin/env python3
"""Assemble local updater assets; verify separate native evidence before publication.

No network, image pulls, appliance changes, key generation or GitHub writes.
Cryptographic/artifact checks do not assert that native tests were performed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nebulalog_manager import host_payload as payload, image_bundle, publisher_inputs
from nebulalog_manager.image_bundle import ApplicationSchema as application_schema
from nebulalog_manager.common import Refused, run
from nebulalog_manager.baseline import ContentUpdate
from nebulalog_manager.updates import verify_release, _utc, CLICKHOUSE_VERSION, validate_clickhouse_change
from build_host_bundle import build as build_host
from prepare_provenance import application_hash

REPOSITORY = "stellaraf/captains-log"
MAX_ASSET = 2 * 1024**3 - 1
MAX_EVIDENCE = 32 * 1024**2
IMAGES = {"nebulalog": "NEBULALOG_IMAGE", "postgresql": "POSTGRESQL_IMAGE",
          "clickhouse": "CLICKHOUSE_IMAGE", "keycloak": "KEYCLOAK_FIPS_IMAGE"}
IDENTITY_GATES = {"local_password_otp", "ad_ldaps_otp", "saml_okta", "saml_entra", "saml_generic", "oidc_generic"}
NATIVE_GATES = {name: "real_rocky_vm" for name in (
    "efi_boot", "tpm_luks_reboot", "kernel_crypto", "combined_update", "selected_host_provenance",
    "authorized_aide_transition", "rollback", "interrupted_recovery", "os_update_aide", "tls_log_ingestion")}
NATIVE_GATES.update(vmware_import="real_vsphere_import", nutanix_import="real_ahv_import")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}")
COMPONENT_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,100})?")


def read_json(path, maximum=payload.MAX_METADATA):
    return payload.strict_json(payload.read_regular(path, maximum))


def file_info(path, maximum=MAX_ASSET, destination=None):
    """Stable, bounded, link-free stream with optional exclusive private copy."""
    source, before = payload.open_regular(path, maximum)
    digest = hashlib.sha256()
    written = 0
    output = destination.open("xb") if destination is not None else None
    try:
        if output is not None:
            os.fchmod(output.fileno(), 0o600)
        with source:
            while chunk := source.read(1024**2):
                written += len(chunk)
                if written > maximum:
                    raise Refused("Release asset exceeded its bounded size while reading")
                digest.update(chunk)
                if output is not None:
                    output.write(chunk)
            if written != before.st_size or not payload.same_file(before, os.fstat(source.fileno())):
                raise Refused("Release asset changed while reading")
        if output is not None:
            output.flush()
            os.fsync(output.fileno())
    finally:
        source.close()
        if output is not None:
            output.close()
    return {"bytes": written, "sha256": digest.hexdigest()}


def write_json(path, value):
    with path.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(payload.encoded(value))
        output.flush()
        os.fsync(output.fileno())


def validate_recipe(value, now=None):
    fields = {"schema", "repository", "sequence", "version", "issued_at", "expires_at", "schema_revision", "source_commit", "components", "evidence_artifacts"}
    if (not isinstance(value, dict) or not fields <= set(value) or set(value) - fields - {"database_migration", "content_enrollment"} or type(value["schema"]) is not int or value["schema"] != 1
            or value["repository"] != REPOSITORY or type(value["sequence"]) is not int or not 0 < value["sequence"] < 2**63
            or not isinstance(value["version"], str) or not payload.VERSION.fullmatch(value["version"])
            or not isinstance(value["schema_revision"], str) or not re.fullmatch(r"[1-9][0-9]{0,8}", value["schema_revision"])
            or not isinstance(value["source_commit"], str) or not re.fullmatch(r"[a-f0-9]{40}", value["source_commit"])):
        raise Refused("Release recipe identity, sequence or schema is invalid")
    migration = value.get("database_migration", "none")
    if migration not in ("none", application_schema.ADDITIVE_UPGRADE) or migration == application_schema.ADDITIVE_UPGRADE and value["schema_revision"] != "2":
        raise Refused("Release recipe has no reviewed application migration")
    now = now or datetime.now(timezone.utc)
    if not _utc(value["issued_at"]) <= now < _utc(value["expires_at"]):
        raise Refused("Release recipe must be currently valid with explicit expiration")
    changes = value["components"]
    if not isinstance(changes, dict) or not {"host", "nebulalog"} <= set(changes) <= set(IMAGES) | {"host", "baseline"}:
        raise Refused("Every release requires host plus application; only fixed OCI and compliance-content components are supported")
    if "content_enrollment" in value and (value["content_enrollment"] != "selected-baseline-v1" or "baseline" in changes):
        raise Refused("Content enrollment must explicitly select the compatible host bridge without a baseline update")
    for name, change in changes.items():
        if name == "baseline":
            if not isinstance(change, dict) or set(change) != {"version", "from_versions", "content_schema", "descriptor_sha256"}:
                raise Refused("Baseline recipe requires its exact content contract")
            ContentUpdate.validate_component({**change, "artifact": "baseline-content.tar", "rollback_safe": True})
            continue
        extra = {"family", "tested_minimum", "tested_maximum"} if name == "clickhouse" else {"qualification_artifact"} if name == "keycloak" else set()
        version_pattern = payload.VERSION if name in {"host", "nebulalog"} else CLICKHOUSE_VERSION if name == "clickhouse" else COMPONENT_VERSION
        if (not isinstance(change, dict) or set(change) != {"version", "from_versions"} | extra
                or not isinstance(change["version"], str) or not version_pattern.fullmatch(change["version"])
                or not isinstance(change["from_versions"], list) or not change["from_versions"]
                or any(not isinstance(version, str) or not version_pattern.fullmatch(version) for version in change["from_versions"])
                or len(set(change["from_versions"])) != len(change["from_versions"])):
            raise Refused("Release components require exact metadata and explicit accepted source versions")
        if name in {"host", "nebulalog"} and change["version"] != value["version"]:
            raise Refused("Host and application versions must match the release version")
        if name == "host" and change["version"] in change["from_versions"]:
            raise Refused("A versioned host bundle must advance even when code bytes are unchanged")
        if name == "postgresql" and any(version.split(".")[0] != change["version"].split(".")[0] for version in change["from_versions"]):
            raise Refused("PostgreSQL major migrations require separate qualification")
        if name == "clickhouse":
            validate_clickhouse_change(change)
    evidence = value["evidence_artifacts"]
    if (not isinstance(evidence, list) or len(evidence) > 32
            or any(not isinstance(name, str) or not NAME.fullmatch(name) or not name.endswith(".json") for name in evidence)
            or len(set(evidence)) != len(evidence)):
        raise Refused("Only explicit bounded JSON qualification artifacts may accompany components")
    return value


def verify_source(source, snapshot):
    for name, expected in snapshot["files"].items():
        if file_info(Path(source) / name, payload.MAX_FILE)["sha256"] != expected:
            raise Refused("Release source tree differs from the frozen source inventory")


def check_identity(recipe, stage, manifest):
    change = manifest["components"].get("keycloak")
    if change is None:
        if recipe["evidence_artifacts"]:
            raise Refused("Unreferenced qualification artifacts are not published")
        return
    name = change["qualification_artifact"]
    if name not in recipe["evidence_artifacts"]:
        raise Refused("Keycloak requires the explicit browser qualification artifact")
    value = read_json(stage / name)
    if (not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1 or value.get("keycloak_image") != change["image"]
            or value.get("source_commit") != recipe["source_commit"] or not isinstance(value.get("checks"), dict)):
        raise Refused("Browser qualification must match this source and Keycloak image")
    used = {name}
    for gate in IDENTITY_GATES:
        record = value["checks"].get(gate)
        if (not isinstance(record, dict) or record.get("status") != "passed" or record.get("method") != "real_browser"
                or record.get("evidence_artifact") not in recipe["evidence_artifacts"] or record["evidence_artifact"] == name):
            raise Refused("Candidate-specific real browser qualification is incomplete")
        used.add(record["evidence_artifact"])
    if used != set(recipe["evidence_artifacts"]):
        raise Refused("Unreferenced browser evidence is not published")


def assemble(source, source_manifest, image_directory, recipe_path, output, *, signing_key=None, evidence_directory=None, content_archive=None, now=None):
    source, source_manifest, image_directory, output = map(lambda path: Path(path).absolute(), (source, source_manifest, image_directory, output))
    recipe = validate_recipe(read_json(recipe_path), now)
    if ("baseline" in recipe["components"]) != (content_archive is not None):
        raise Refused("Compliance archive must be supplied exactly when baseline content is declared")
    content = None
    if content_archive is not None:
        spec = recipe["components"]["baseline"]
        content = ContentUpdate.verify_archive(content_archive,
            expected_descriptor_sha256=spec["descriptor_sha256"], expected_version=spec["version"])
    source_raw = payload.read_regular(source_manifest, payload.MAX_SOURCE_MANIFEST)
    snapshot = payload.source_manifest(source_raw)
    verify_source(source, snapshot)
    application_schema.bind_source(snapshot["files"], recipe["schema_revision"])
    if not any(name.startswith("cmd/") for name in snapshot["files"]) or "go.mod" not in snapshot["files"]:
        raise Refused("Frozen source must include the application as well as host modules")
    public_raw = payload.read_regular(source / publisher_inputs.PUBLIC_SOURCE, 16384)
    descriptor_raw = payload.read_regular(source / publisher_inputs.DESCRIPTOR_SOURCE, 16384)
    for name, raw in ((publisher_inputs.PUBLIC_SOURCE, public_raw), (publisher_inputs.DESCRIPTOR_SOURCE, descriptor_raw)):
        if snapshot["files"].get(name) != payload.digest(raw):
            raise Refused("Publisher public trust differs from the frozen source")
    descriptor = publisher_inputs.descriptor(descriptor_raw)
    publisher_inputs.public_key(public_raw, descriptor["spki_sha256"])
    pins = read_json(image_directory / "images.json")
    images = image_bundle.verify_bundle(image_directory, pins)["images"]
    app_hash = application_hash(snapshot)
    if images["NEBULALOG_IMAGE"]["application_source_sha256"] != app_hash:
        raise Refused("OCI application label differs from the frozen application source")
    if output.exists() or output.is_symlink():
        raise Refused("Release output must be a fresh directory")
    if signing_key is not None:
        signing_key = Path(signing_key).absolute()
        stream, info = payload.open_regular(signing_key, 16384)
        stream.close()
        if (info.st_mode & 0o077 or info.st_uid != os.getuid()
                or any(signing_key.is_relative_to(path) for path in (source, output, image_directory))
                or any((parent / ".git").exists() for parent in signing_key.parents)):
            raise Refused("Signing key must be owner-private and outside repository and release inputs")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".pending-release-", dir=output.parent))
    try:
        host = build_host(source, source_manifest, stage / "host.tar", version=recipe["version"])
        manifest = {"schema": 1, "product": "nebulalog", "channel": "stable", **{key: recipe[key] for key in ("sequence", "version", "issued_at", "expires_at")},
                    "components": {}, "artifacts": []}
        if "content_enrollment" in recipe:
            manifest["content_enrollment"] = recipe["content_enrollment"]
        artifacts = {"host.tar": file_info(stage / "host.tar")}
        for name, spec in sorted(recipe["components"].items()):
            component = {**spec, "rollback_safe": True}
            if name == "host":
                component.update(artifact="host.tar", abi=payload.ABI, host_source_sha256=host["metadata"]["host_source_sha256"])
            elif name == "baseline":
                filename = "baseline-content.tar"
                artifacts[filename] = file_info(Path(content_archive), ContentUpdate.MAX_ARCHIVE, stage / filename)
                ContentUpdate.verify_archive(stage / filename, expected_sha256=content["archive_sha256"],
                    expected_descriptor_sha256=spec["descriptor_sha256"], expected_version=spec["version"])
                component["artifact"] = filename
            else:
                item = images[IMAGES[name]]
                filename = item["archive"]
                if filename in artifacts or not NAME.fullmatch(filename):
                    raise Refused("Component archives must have unique fixed direct filenames")
                artifacts[filename] = file_info(image_directory / filename, destination=stage / filename)
                if artifacts[filename] != {"bytes": item["archive_bytes"], "sha256": item["archive_sha256"]}:
                    raise Refused("OCI asset changed after verification")
                migration = recipe.get("database_migration", "none") if name == "nebulalog" else "none"
                component.update(artifact=filename, image=item["reference"],
                                 **application_schema.declaration(snapshot["files"], recipe["schema_revision"], migration))
            manifest["components"][name] = component
        reserved = {"manifest.json", "manifest.sig", "source-manifest.json", "publisher-public.spki", "publisher-trust.json", "release-provenance.json"}
        for name in recipe["evidence_artifacts"]:
            if evidence_directory is None or name in artifacts or name in reserved:
                raise Refused("Qualification artifact collides with release metadata or is unavailable")
            path = Path(evidence_directory) / name
            raw = payload.read_regular(path, MAX_EVIDENCE)
            payload.strict_json(raw)
            if payload.PRIVATE_KEY.search(raw):
                raise Refused("Qualification artifact contains private key material")
            artifacts[name] = file_info(path, MAX_EVIDENCE, stage / name)
            if artifacts[name] != {"bytes": len(raw), "sha256": payload.digest(raw)}:
                raise Refused("Qualification artifact changed after its content check")
        check_identity(recipe, stage, manifest)
        manifest["artifacts"] = [{"name": name, **value} for name, value in sorted(artifacts.items())]
        write_json(stage / "manifest.json", manifest)
        for name, raw in (("source-manifest.json", source_raw), ("publisher-public.spki", public_raw), ("publisher-trust.json", descriptor_raw)):
            with (stage / name).open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if signing_key is not None:
            run(["openssl", "dgst", "-sha256", "-sign", str(signing_key), "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
                 "-out", str(stage / "manifest.sig"), str(stage / "manifest.json")])
            (stage / "manifest.sig").chmod(0o600)
            verify_release(stage / "manifest.json", stage / "manifest.sig", stage / "publisher-public.spki", stage, now=now)
        provenance = {"schema": 1, "repository": REPOSITORY, "source_commit": recipe["source_commit"],
            "source_snapshot_sha256": payload.digest(source_raw), "application_source_sha256": app_hash,
            "publisher_spki_sha256": descriptor["spki_sha256"], "host_generation": host["archive_sha256"],
            "version": recipe["version"], "sequence": recipe["sequence"], "signed": signing_key is not None,
            "qualification": "not_assessed", "assets": {path.name: file_info(path) for path in sorted(stage.iterdir())}}
        write_json(stage / "release-provenance.json", provenance)
        if payload.read_regular(source_manifest, payload.MAX_SOURCE_MANIFEST) != source_raw:
            raise Refused("Frozen source manifest changed during release assembly")
        verify_source(source, snapshot)
        payload._rename_noreplace(stage, output)
        payload._sync_directory(output.parent)
        return {"status": "assembled", "signed": signing_key is not None, "native_qualified": False,
                "version": recipe["version"], "manifest_sha256": provenance["assets"]["manifest.json"]["sha256"], "network_used": False}
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def verify_package(package, *, expected_manifest, expected_commit, source_tree=None, now=None):
    """Read-only artifact/source verification; never upgrades qualification status."""
    package = Path(package)
    record = read_json(package / "release-provenance.json")
    fields = {"schema", "repository", "source_commit", "source_snapshot_sha256", "application_source_sha256",
              "publisher_spki_sha256", "host_generation", "version", "sequence", "signed", "qualification", "assets"}
    if (not isinstance(record, dict) or set(record) != fields or type(record.get("schema")) is not int or record["schema"] != 1 or record.get("repository") != REPOSITORY
            or record.get("signed") is not True or record.get("qualification") != "not_assessed"
            or record.get("source_commit") != expected_commit or not re.fullmatch(r"[a-f0-9]{40}", expected_commit)
            or not isinstance(record.get("assets"), dict) or not payload.SHA256.fullmatch(expected_manifest)):
        raise Refused("Signed local package identity is invalid")
    if set(path.name for path in package.iterdir()) != set(record["assets"]) | {"release-provenance.json"}:
        raise Refused("Release directory contains missing or undeclared assets")
    for name, expected in record["assets"].items():
        if not NAME.fullmatch(name) or file_info(package / name) != expected:
            raise Refused("Release assets differ from their retained package inventory")
    if record["assets"].get("manifest.json", {}).get("sha256") != expected_manifest:
        raise Refused("Manifest differs from the explicitly approved SHA256")
    source = payload.source_manifest(payload.read_regular(package / "source-manifest.json", payload.MAX_SOURCE_MANIFEST))
    if source_tree is not None:
        verify_source(source_tree, source)
    description = publisher_inputs.descriptor(payload.read_regular(package / "publisher-trust.json", 16384))
    key = payload.read_regular(package / "publisher-public.spki", 16384)
    publisher_inputs.public_key(key, description["spki_sha256"])
    if (source["files"].get(publisher_inputs.PUBLIC_SOURCE) != payload.digest(key)
            or source["files"].get(publisher_inputs.DESCRIPTOR_SOURCE) != payload.digest(payload.read_regular(package / "publisher-trust.json", 16384))
            or record["source_snapshot_sha256"] != record["assets"]["source-manifest.json"]["sha256"]
            or record["publisher_spki_sha256"] != description["spki_sha256"]
            or record["application_source_sha256"] != application_hash(source)):
        raise Refused("Package public trust and source identity disagree")
    manifest = verify_release(package / "manifest.json", package / "manifest.sig", package / "publisher-public.spki", package, now=now)
    if (not {"host", "nebulalog"} <= set(manifest["components"]) <= set(IMAGES) | {"host", "baseline"}
            or manifest["version"] != record["version"] or manifest["sequence"] != record["sequence"]):
        raise Refused("Package is not a combined host and OCI release")
    referenced = {change["artifact"] for change in manifest["components"].values()}
    recipe = {"schema": 1, "repository": REPOSITORY, "source_commit": expected_commit,
        **{key: manifest[key] for key in ("version", "sequence", "issued_at", "expires_at")},
        "schema_revision": manifest["components"]["nebulalog"]["schema_revision"],
        "components": {}, "evidence_artifacts": [item["name"] for item in manifest["artifacts"] if item["name"] not in referenced]}
    recipe["database_migration"] = manifest["components"]["nebulalog"]["database_migration"]
    if "content_enrollment" in manifest:
        recipe["content_enrollment"] = manifest["content_enrollment"]
    application_schema.bind_source(source["files"], recipe["schema_revision"])
    for name, change in manifest["components"].items():
        if name == "baseline":
            ContentUpdate.validate_component(change)
            recipe["components"][name] = {key: change[key] for key in ("version", "from_versions", "content_schema", "descriptor_sha256")}
            continue
        keys = {"version", "from_versions"} | ({"family", "tested_minimum", "tested_maximum"} if name == "clickhouse" else {"qualification_artifact"} if name == "keycloak" else set())
        fixed = {"artifact", "rollback_safe"} | ({"abi", "host_source_sha256"} if name == "host" else {"image", "database_migration", "schema_revision", "schema_sha256"})
        declared = application_schema.declaration(source["files"], recipe["schema_revision"],
            recipe["database_migration"] if name == "nebulalog" else "none") if name != "host" else {}
        if set(change) != keys | fixed or change["rollback_safe"] is not True or any(change.get(key) != value for key, value in declared.items()):
            raise Refused("Release component differs from the fixed compatible publisher contract")
        recipe["components"][name] = {key: change[key] for key in keys}
    validate_recipe(recipe, now)
    check_identity(recipe, package, manifest)
    host = payload.verify_archive(package / manifest["components"]["host"]["artifact"], expected_sha256=record["host_generation"])
    if host["metadata"]["source_snapshot_sha256"] != record["source_snapshot_sha256"]:
        raise Refused("Host generation differs from the frozen package source")
    for name, change in manifest["components"].items():
        if name == "host": continue
        if name == "baseline":
            ContentUpdate.verify_archive(package / change["artifact"],
                expected_sha256=record["assets"][change["artifact"]]["sha256"],
                expected_descriptor_sha256=change["descriptor_sha256"], expected_version=change["version"])
            continue
        image = image_bundle.verify_oci_archive(package / change["artifact"], change["image"])
        if name == "nebulalog" and image["application_source_sha256"] != record["application_source_sha256"]:
            raise Refused("OCI application differs from the frozen package source")
    return {"status": "artifacts_verified", "native_qualified": False, "manifest": manifest, "provenance": record}


def verify_native(package, report_path, evidence_directory, ova, *, expected_manifest, expected_commit, source_tree, now=None):
    """Verify an independently reviewed native attestation and exact evidence bytes.

    This checks binding/completeness, not whether the attester really ran tests.
    A protected publication environment must review original native receipts.
    No helper in this file generates a passed native attestation.
    """
    package, ova = Path(package), Path(ova)
    checked = verify_package(package, expected_manifest=expected_manifest, expected_commit=expected_commit, source_tree=source_tree, now=now)
    report = read_json(report_path)
    if (not isinstance(report, dict) or set(report) != {"schema", "kind", "repository", "release_provenance_sha256", "ova", "platform", "checks"}
            or type(report["schema"]) is not int or report["schema"] != 1 or report["kind"] != "captains-log-native-release-acceptance"
            or report["repository"] != REPOSITORY or report["platform"] != payload.PLATFORM
            or report["release_provenance_sha256"] != file_info(package / "release-provenance.json")["sha256"]
            or not NAME.fullmatch(ova.name) or not ova.name.endswith(".ova")
            or report["ova"] != {"name": ova.name, **file_info(ova)}
            or not isinstance(report["checks"], dict) or set(report["checks"]) != set(NATIVE_GATES)):
        raise Refused("Native qualification must bind this exact package, x86 Rocky platform and OVA")
    for name, method in NATIVE_GATES.items():
        check = report["checks"][name]
        if (not isinstance(check, dict) or set(check) != {"status", "method", "evidence"}
                or check["status"] != "passed" or check["method"] != method
                or not isinstance(check["evidence"], list) or not 1 <= len(check["evidence"]) <= 8):
            raise Refused("Native qualification is incomplete; sealer or fixture passes cannot replace native gates")
        for item in check["evidence"]:
            if (not isinstance(item, dict) or set(item) != {"name", "bytes", "sha256"} or not isinstance(item["name"], str)
                    or type(item["bytes"]) is not int or item["bytes"] <= 0
                    or not NAME.fullmatch(item["name"]) or file_info(Path(evidence_directory) / item["name"], MAX_EVIDENCE) != {key: item[key] for key in ("bytes", "sha256")}):
                raise Refused("Native evidence is missing or changed")
    return {"status": "native_attestation_bound", "native_execution_verified_by_tool": False,
            "requires_reviewed_publication_environment": True, "version": checked["provenance"]["version"],
            "assets": sorted(checked["provenance"]["assets"]) + ["release-provenance.json"], "ova": ova.name}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("assemble")
    for name in ("source", "source-manifest", "image-directory", "recipe", "output"):
        build.add_argument("--" + name, required=True, type=Path)
    build.add_argument("--signing-key", type=Path)
    build.add_argument("--evidence-directory", type=Path)
    build.add_argument("--content-archive", type=Path)
    verify = sub.add_parser("verify-native")
    for name in ("package", "report", "evidence-directory", "ova", "source-tree"):
        verify.add_argument("--" + name, required=True, type=Path)
    verify.add_argument("--expected-manifest", required=True)
    verify.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    try:
        if args.command == "assemble":
            result = assemble(args.source, args.source_manifest, args.image_directory, args.recipe, args.output,
                              signing_key=args.signing_key, evidence_directory=args.evidence_directory, content_archive=args.content_archive)
        else:
            result = verify_native(args.package, args.report, args.evidence_directory, args.ova,
                                   expected_manifest=args.expected_manifest, expected_commit=args.expected_commit, source_tree=args.source_tree)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('{"status":"refused","message":"Release inputs, signature, artifact binding or required evidence failed verification"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
