"""Real RSA, host archives, OCI blobs and evidence hashes; no native tests or publishing."""
import copy
import io
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch

from nebulalog_manager import host_payload as payload, publisher_inputs
from nebulalog_manager.common import Refused
from nebulalog_manager.image_bundle import ApplicationSchema, RestoredAuthContract
import test_host_payload as hosts
import test_image_bundle as images
import test_manager as manager
from test_restore_auth_contract import build_receipt, behavior_receipt

PACKER = Path(__file__).resolve().parents[1] / "packer"
sys.path.insert(0, str(PACKER))
import assemble_release as release
from nebulalog_manager.baseline import ContentUpdate

NOW = datetime(2026, 9, 9, tzinfo=timezone.utc)
COMMIT = "a" * 40


def content_archive(path):
    """Synthetic closed source graph; no native policy qualification asserted."""
    raw = b'''<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2"
        xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:x="http://checklists.nist.gov/xccdf/1.2">
        <data-stream id="stream"><checklists><component-ref id="ref" xlink:href="#benchmark"/></checklists></data-stream>
        <component id="benchmark"><x:Benchmark id="fixture"><x:Rule id="fixture_rule"/></x:Benchmark></component>
        </data-stream-collection>'''
    descriptor = {"schema": 1, "kind": ContentUpdate.KIND, "version": "1.2.3", "platform": "rocky9-x86_64",
        "source_url": "https://example.invalid/synthetic", "content_revision": "synthetic-fixture-v1",
        "engine": {"scanner_nevra": "openscap-scanner-1.3.14-1.el9.x86_64", "version_sha256": "e" * 64},
        "files": {"source.xml": {"bytes": len(raw), "sha256": payload.digest(raw)}},
        "policies": {name: {"schema": 1, "baseline": name,
            "assessments": [{"datastream": "source.xml", "sha256": payload.digest(raw)}]}
            for name in ("cis-level2", "stig", "unified")}}
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in (("content.json", ContentUpdate.encoded(descriptor)), ("source.xml", raw)):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(body), 0o644
            archive.addfile(entry, io.BytesIO(body))
    return descriptor


class ReleaseTests(unittest.TestCase):
    setUpClass = classmethod(manager.SignatureTests.setUpClass.__func__)
    tearDownClass = classmethod(manager.SignatureTests.tearDownClass.__func__)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source, self.snapshot_path = hosts.fixture_source(self.root)
        snapshot = json.loads(self.snapshot_path.read_text())
        raw_public = self.public.read_bytes()
        der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(self.public), "-pubout", "-outform", "DER"], stderr=subprocess.DEVNULL)
        descriptor = {"schema": 1, "publisher": "Test fixture", "repository": release.REPOSITORY, "key_id": "fixture",
                      "algorithm": "RSA-PSS-SHA256", "spki_sha256": payload.digest(der)}
        legacy, additive, stepup = ApplicationSchema.reviewed_sql()
        # These existing tests exercise the immutable schema-2 release contract.
        # Current source migrations now describe fresh schema 3.
        migrations = {"postgres.sql": (legacy + additive).encode(), "host_stepup.sql": stepup.encode(),
                      "clickhouse.sql": (PACKER.parents[1] / "migrations/clickhouse.sql").read_bytes()}
        migrations["clickhouse.sql"] = migrations["clickhouse.sql"].replace(
            b"SETTINGS index_granularity=8192;", b"TTL expires_at DELETE\nSETTINGS index_granularity=8192;")
        self.assertEqual(payload.digest(migrations["clickhouse.sql"]), ApplicationSchema.SCHEMAS["2"]["migrations/clickhouse.sql"])
        for name, raw in ((publisher_inputs.PUBLIC_SOURCE, raw_public), (publisher_inputs.DESCRIPTOR_SOURCE, payload.encoded(descriptor)),
                          ("go.mod", b"module fixture\n"), ("cmd/nebulalog/main.go", b"package main\n"),
                          *(("migrations/" + name, raw) for name, raw in migrations.items())):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            snapshot["files"][name] = payload.digest(raw)
        self.snapshot_path.write_bytes(payload.encoded(snapshot))
        self.images = self.root / "images"
        self.pins, self.image_manifest, _ = images.fixture_bundle(self.images, application_source_sha256=release.application_hash(snapshot))
        self.recipe = {"schema": 1, "repository": release.REPOSITORY, "sequence": 2, "version": "0.1.1",
            "issued_at": "2026-09-01T00:00:00Z", "expires_at": "2027-09-01T00:00:00Z", "schema_revision": "2", "source_commit": COMMIT,
            "components": {name: {"version": "0.1.1", "from_versions": ["0.1.0"]} for name in ("host", "nebulalog")}, "evidence_artifacts": []}
        self.recipe_path = self.root / "recipe.json"
        self.output = self.root / "release"
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()

    def assemble(self, *, signed=True, content=None):
        self.recipe_path.write_bytes(payload.encoded(self.recipe))
        return release.assemble(self.source, self.snapshot_path, self.images, self.recipe_path, self.output,
            signing_key=self.private.resolve() if signed else None, evidence_directory=self.evidence, content_archive=content, now=NOW)

    def content(self):
        path = self.root / "candidate-content.tar"
        descriptor = content_archive(path)
        self.recipe["components"]["baseline"] = {"version": descriptor["version"], "from_versions": ["sha256:" + "a" * 64],
            "content_schema": 1, "descriptor_sha256": payload.digest(ContentUpdate.encoded(descriptor))}
        return path

    def test_content_package_binds_actual_archive_descriptor_and_measured_source_version(self):
        path = self.content()
        result = self.assemble(content=path)
        verified = self.verify()
        change = verified["manifest"]["components"]["baseline"]
        self.assertEqual(change, {**self.recipe["components"]["baseline"], "rollback_safe": True, "artifact": "baseline-content.tar"})
        self.assertEqual((self.output / change["artifact"]).read_bytes(), path.read_bytes())
        self.assertFalse(result["native_qualified"])

    def test_content_input_and_recipe_must_be_paired_and_standalone_content_is_refused(self):
        path = self.content()
        with self.assertRaisesRegex(Refused, "supplied exactly"): self.assemble()
        original = self.recipe["components"].pop("baseline")
        with self.assertRaisesRegex(Refused, "supplied exactly"): self.assemble(content=path)
        self.recipe["components"] = {"baseline": original}
        with self.assertRaisesRegex(Refused, "requires host"): self.assemble(content=path)
        self.assertFalse(self.output.exists())

    def test_content_declared_version_descriptor_and_inventory_tamper_refuse(self):
        path = self.content()
        original = copy.deepcopy(self.recipe["components"]["baseline"])
        for changes in ({"descriptor_sha256": "f" * 64}, {"version": "9.9.9"}, {"content_schema": True},
                        {"from_versions": ["*"]}, {"engine_update": True}):
            self.recipe["components"]["baseline"] = {**original, **changes}
            with self.subTest(changes=changes), self.assertRaises(Refused): self.assemble(content=path)
            self.assertFalse(self.output.exists())
        self.recipe["components"]["baseline"] = original
        raw = path.read_bytes().replace(b'fixture_rule', b'changed_rule')
        path.write_bytes(raw)
        with self.assertRaises(Refused): self.assemble(content=path)
        self.assertFalse(self.output.exists())

    def test_content_copy_race_is_reverified_before_release_publication(self):
        path = self.content()
        copy_asset = release.file_info
        def replace(source, *args, **kwargs):
            if Path(source) == path:
                path.write_bytes(path.read_bytes().replace(b'fixture_rule', b'changed_rule'))
            return copy_asset(source, *args, **kwargs)
        with patch.object(release, "file_info", side_effect=replace), self.assertRaises(Refused):
            self.assemble(content=path)
        self.assertFalse(self.output.exists())

    def test_signed_content_enrollment_bridge_is_explicit_and_preserved(self):
        self.recipe["content_enrollment"] = "selected-baseline-v1"
        self.assemble()
        manifest = self.verify()["manifest"]
        self.assertEqual(manifest["content_enrollment"], "selected-baseline-v1")
        self.assertNotIn("baseline", manifest["components"])

    def test_content_bridge_refuses_unsupported_or_combined_content_activation(self):
        self.recipe["content_enrollment"] = True
        with self.assertRaisesRegex(Refused, "Content enrollment"): self.assemble()
        self.recipe["content_enrollment"] = "selected-baseline-v1"
        path = self.content()
        with self.assertRaisesRegex(Refused, "Content enrollment"): self.assemble(content=path)
        self.assertFalse(self.output.exists())

    def verify(self):
        return release.verify_package(self.output, expected_manifest=release.file_info(self.output / "manifest.json")["sha256"],
                                      expected_commit=COMMIT, source_tree=self.source, now=NOW)

    def test_signed_combined_package_is_accepted_by_real_updater_and_has_no_private_material(self):
        result = self.assemble()
        self.assertTrue(result["signed"])
        self.assertFalse(result["native_qualified"])
        verified = self.verify()
        self.assertEqual(verified["status"], "artifacts_verified")
        self.assertFalse(verified["native_qualified"])
        self.assertEqual(verified["manifest"]["components"]["host"]["version"], "0.1.1")
        self.assertEqual(verified["manifest"]["components"]["nebulalog"]["image"], self.pins["NEBULALOG_IMAGE"])
        self.assertEqual(verified["provenance"]["qualification"], "not_assessed")
        for path in self.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(payload.PRIVATE_KEY.search(path.read_bytes()))
        self.assertFalse(result["network_used"])

    def restored_auth(self):
        snapshot = json.loads(self.snapshot_path.read_bytes())
        for name in RestoredAuthContract.REQUIRED_SOURCE | set(ApplicationSchema.SCHEMAS["3"]):
            raw = ((PACKER.parents[1] / name).read_bytes() if name.startswith("migrations/") else (name + " fixture\n").encode())
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            snapshot["files"][name] = payload.digest(raw)
        self.snapshot_path.write_bytes(payload.encoded(snapshot))
        shutil.rmtree(self.images)  # Only this test's generated tiny OCI fixture.
        self.pins, self.image_manifest, _ = images.fixture_bundle(self.images, application_source_sha256=release.application_hash(snapshot))
        image = release.image_bundle.verify_bundle(self.images, self.pins)["images"]["NEBULALOG_IMAGE"]
        self.recipe.update(schema_revision="3", restore_auth=RestoredAuthContract.CONTRACT,
                           evidence_artifacts=sorted(RestoredAuthContract.EVIDENCE))
        for name, value in ((RestoredAuthContract.BUILD, build_receipt(snapshot, image, self.recipe["version"])),
                            (RestoredAuthContract.BEHAVIOR, behavior_receipt(image, self.pins["NEBULALOG_IMAGE"]))):
            (self.evidence / name).write_bytes(payload.encoded(value))

    def test_restored_auth_source_and_behavior_are_signed_without_native_acceptance_claim(self):
        self.restored_auth()
        self.assemble()
        result = self.verify()
        manifest = result["manifest"]
        self.assertEqual(manifest["restore_auth"], RestoredAuthContract.declaration())
        self.assertTrue({RestoredAuthContract.SOURCE, *RestoredAuthContract.EVIDENCE} <= {item["name"] for item in manifest["artifacts"]})
        self.assertFalse(result["native_qualified"])
        self.assertFalse(RestoredAuthContract.verify(manifest, self.output)["execution_verified_by_tool"])

    def test_restored_auth_failed_behavior_and_unbound_build_refuse_before_signature(self):
        self.restored_auth()
        path = self.evidence / RestoredAuthContract.BEHAVIOR
        value = json.loads(path.read_bytes())
        value["cases"]["before_cutoff"]["http_status"] = 200
        path.write_bytes(payload.encoded(value))
        with self.assertRaisesRegex(Refused, "boundary case"): self.assemble()
        self.assertFalse(self.output.exists())
        self.restored_auth()
        path = self.evidence / RestoredAuthContract.BUILD
        value = json.loads(path.read_bytes()); value["local_image_id"] = "sha256:" + "f" * 64
        path.write_bytes(payload.encoded(value))
        with self.assertRaisesRegex(Refused, "build receipt"): self.assemble()
        self.assertFalse(self.output.exists())

    def test_unsigned_package_cannot_pass_publication_verification(self):
        result = self.assemble(signed=False)
        self.assertFalse(result["signed"])
        self.assertFalse((self.output / "manifest.sig").exists())
        with self.assertRaisesRegex(Refused, "Signed local package"): self.verify()

    def test_missing_host_wildcards_replays_and_unsupported_migrations_refuse_before_output(self):
        original = copy.deepcopy(self.recipe)
        mutations = [lambda r: r["components"].pop("host"), lambda r: r.update(sequence=True),
                     lambda r: r["components"]["host"].update(from_versions=["*"]),
                     lambda r: r["components"]["host"].update(from_versions=["0.1.1"]),
                     lambda r: r["components"]["nebulalog"].update(hook="arbitrary"),
                     lambda r: r.update(repository="other/repository"), lambda r: r.update(evidence_artifacts=["../secret.json"]),
                     lambda r: r["components"].update(postgresql={"version": "18.1", "from_versions": ["17.11"]})]
        for mutate in mutations:
            self.recipe = copy.deepcopy(original); mutate(self.recipe)
            with self.subTest(recipe=self.recipe), self.assertRaises(Refused): self.assemble()
            self.assertFalse(self.output.exists())

    def test_database_versions_use_actual_two_and_four_part_formats(self):
        self.recipe["components"].update(postgresql={"version": "17.12", "from_versions": ["17.11"]},
            clickhouse={"version": "25.3.10.1", "from_versions": ["25.3.9.100"], "family": "25.3",
                        "tested_minimum": "25.3.9.100", "tested_maximum": "25.3.10.1"})
        self.assemble()
        self.assertEqual(set(self.verify()["manifest"]["components"]), {"host", "nebulalog", "postgresql", "clickhouse"})

    def test_clickhouse_actual_altinityfips_version_retains_full_identity(self):
        self.recipe["components"]["clickhouse"] = {
            "version": "25.3.8.30001.altinityfips", "from_versions": ["25.3.8.30001.altinityfips"],
            "family": "25.3", "tested_minimum": "25.3.8.30001", "tested_maximum": "25.3.8.30001"}
        self.assemble()
        change = self.verify()["manifest"]["components"]["clickhouse"]
        self.assertEqual(change["version"], "25.3.8.30001.altinityfips")
        self.assertEqual(change["from_versions"], ["25.3.8.30001.altinityfips"])

    def test_clickhouse_vendor_changes_and_out_of_range_versions_refuse(self):
        original = copy.deepcopy(self.recipe)
        for previous, version, maximum in (
                ("25.3.8.30001", "25.3.8.30001.altinityfips", "25.3.8.30001"),
                ("25.3.8.30001.altinityfips", "25.3.8.30001", "25.3.8.30001"),
                ("25.3.8.30001.altinityfips", "25.3.9.1.altinityfips", "25.3.8.30001"),
                ("25.3.8.30001.altinityfips", "25.3.8.30001.unrecognized", "25.3.8.30001")):
            self.recipe = copy.deepcopy(original)
            self.recipe["components"]["clickhouse"] = {"version": version, "from_versions": [previous],
                "family": "25.3", "tested_minimum": "25.3.8.30001", "tested_maximum": maximum}
            with self.subTest(previous=previous, version=version), self.assertRaises(Refused):
                self.assemble()
            self.assertFalse(self.output.exists())

    def test_keycloak_requires_complete_candidate_browser_evidence(self):
        self.recipe["components"]["keycloak"] = {"version": "26.7.3", "from_versions": ["26.7.2"], "qualification_artifact": "identity.json"}
        self.recipe["evidence_artifacts"] = ["identity.json", "browser.json"]
        report = {"schema": 1, "keycloak_image": self.pins["KEYCLOAK_FIPS_IMAGE"], "source_commit": COMMIT,
                  "checks": {name: {"status": "passed", "method": "real_browser", "evidence_artifact": "browser.json"} for name in release.IDENTITY_GATES}}
        (self.evidence / "browser.json").write_bytes(payload.encoded({"fixture": True, "real_browser_performed": False}))
        report_path = self.evidence / "identity.json"
        report["checks"]["saml_entra"]["status"] = "pending"
        report_path.write_bytes(payload.encoded(report))
        with self.assertRaisesRegex(Refused, "browser qualification"): self.assemble()
        self.assertFalse(self.output.exists())
        report["checks"]["saml_entra"]["status"] = "passed"
        report_path.write_bytes(payload.encoded(report))
        self.assemble()
        verified = self.verify()
        self.assertIn("keycloak", verified["manifest"]["components"])
        self.assertFalse(verified["native_qualified"])

    def test_signing_key_must_stay_private_and_outside_source_and_repository(self):
        copied = self.source / "private.key"
        copied.write_bytes(self.private.read_bytes()); copied.chmod(0o600)
        original = self.private
        self.private = copied
        try:
            with self.assertRaisesRegex(Refused, "Signing key"): self.assemble()
            copied.unlink()
            copied = self.root / "unsafe.key"
            copied.write_bytes(original.read_bytes()); copied.chmod(0o644)
            self.private = copied
            with self.assertRaisesRegex(Refused, "Signing key"): self.assemble()
        finally:
            self.private = original
        self.assertFalse(self.output.exists())

    def test_missing_or_wrong_application_source_label_refuses(self):
        for value in (None, "b" * 64):
            shutil.rmtree(self.images)
            images.fixture_bundle(self.images, application_source_sha256=value)
            with self.assertRaisesRegex(Refused, "application label"): self.assemble()
            self.assertFalse(self.output.exists())

    def test_changed_source_or_public_trust_refuses_without_output(self):
        for name in ("cmd/nebulalog/main.go", publisher_inputs.PUBLIC_SOURCE):
            path = self.source / name
            original = path.read_bytes(); path.write_bytes(original + b"changed")
            with self.assertRaises(Refused): self.assemble()
            self.assertFalse(self.output.exists())
            path.write_bytes(original)

    def test_replaced_or_extra_asset_and_approved_hash_mismatch_refuse(self):
        self.assemble()
        with self.assertRaisesRegex(Refused, "approved SHA256"):
            release.verify_package(self.output, expected_manifest="0" * 64, expected_commit=COMMIT, now=NOW)
        unexpected = self.output / "credentials.json"
        unexpected.write_text("inert fixture")
        with self.assertRaisesRegex(Refused, "undeclared"): self.verify()
        unexpected.unlink()
        asset = self.output / self.image_manifest["images"]["NEBULALOG_IMAGE"]["archive"]
        asset.write_bytes(b"changed")
        with self.assertRaisesRegex(Refused, "inventory"): self.verify()

    def test_links_hardlinks_and_excessive_asset_size_refuse(self):
        item = self.root / "item"
        item.write_bytes(b"fixture")
        with self.assertRaises(Refused): release.file_info(item, maximum=1)
        alias = self.root / "alias"
        alias.symlink_to(item)
        with self.assertRaises(Refused): release.file_info(alias)
        alias.unlink(); os.link(item, alias)
        with self.assertRaises(Refused): release.file_info(item)

    def test_existing_or_competing_output_is_never_replaced(self):
        self.output.mkdir()
        sentinel = self.output / "customer-data"
        sentinel.write_text("unchanged")
        with self.assertRaises(Refused): self.assemble()
        self.assertEqual(sentinel.read_text(), "unchanged")
        shutil.rmtree(self.output)
        original = payload._rename_noreplace
        def race(stage, target):
            target.mkdir(); (target / "sentinel").write_text("retained")
            original(stage, target)
        with patch.object(payload, "_rename_noreplace", side_effect=race), self.assertRaises(Refused): self.assemble()
        self.assertEqual((self.output / "sentinel").read_text(), "retained")
        self.assertFalse(list(self.root.glob(".pending-release-*")))

    def test_wrong_signer_fails_real_verification_and_does_not_publish_partial_package(self):
        wrong = self.root / "wrong-private.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(wrong)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        original = self.private
        self.private = wrong
        try:
            with self.assertRaises(Refused): self.assemble()
        finally:
            self.private = original
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".pending-release-*")))

    def test_oci_mutation_after_verification_refuses_before_publication(self):
        original = release.file_info
        target = self.images / self.image_manifest["images"]["NEBULALOG_IMAGE"]["archive"]
        def race(path, *args, **kwargs):
            if path == target:
                path.write_bytes(b"changed after OCI verification")
            return original(path, *args, **kwargs)
        with patch.object(release, "file_info", side_effect=race), self.assertRaisesRegex(Refused, "OCI asset changed"):
            self.assemble()
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".pending-release-*")))

    def test_source_mutation_after_signature_still_prevents_output(self):
        original = release.run
        def race(args, **kwargs):
            result = original(args, **kwargs)
            if "-sign" in args:
                (self.source / "cmd/nebulalog/main.go").write_bytes(b"changed during signing")
            return result
        with patch.object(release, "run", side_effect=race), self.assertRaisesRegex(Refused, "source tree"):
            self.assemble()
        self.assertFalse(self.output.exists())

    def native_fixture(self):
        self.assemble()
        self.ova = self.root / "fixture.ova"
        self.ova.write_bytes(b"Not a VM: opaque artifact-binding fixture only")
        evidence = self.evidence / "fixture-receipt.json"
        evidence.write_bytes(payload.encoded({"fixture": True, "native_test_performed": False}))
        self.native = {"schema": 1, "kind": "captains-log-native-release-acceptance", "repository": release.REPOSITORY,
            "release_provenance_sha256": release.file_info(self.output / "release-provenance.json")["sha256"],
            "ova": {"name": self.ova.name, **release.file_info(self.ova)}, "platform": dict(payload.PLATFORM),
            "checks": {name: {"status": "passed", "method": method, "evidence": [{"name": evidence.name, **release.file_info(evidence)}]}
                       for name, method in release.NATIVE_GATES.items()}}
        self.native_path = self.root / "native.json"

    def verify_native(self):
        self.native_path.write_bytes(payload.encoded(self.native))
        return release.verify_native(self.output, self.native_path, self.evidence, self.ova,
            expected_manifest=release.file_info(self.output / "manifest.json")["sha256"], expected_commit=COMMIT, source_tree=self.source, now=NOW)

    def test_evidence_binding_explicitly_never_claims_native_execution(self):
        self.native_fixture()
        result = self.verify_native()
        self.assertEqual(result["status"], "native_attestation_bound")
        self.assertFalse(result["native_execution_verified_by_tool"])
        self.assertTrue(result["requires_reviewed_publication_environment"])
        self.assertNotIn("native_qualified", result)

    def test_partial_sealer_only_fixture_or_wrong_platform_claim_cannot_pass_native_gate(self):
        self.native_fixture()
        original = copy.deepcopy(self.native)
        mutations = [lambda r: r.update(kind="seal_receipt"), lambda r: r.update(schema=True),
                     lambda r: r["platform"].update(architecture="arm64"), lambda r: r["checks"].pop("os_update_aide"),
                     lambda r: r["checks"]["combined_update"].update(method="unit_test"),
                     lambda r: r["checks"]["vmware_import"].update(status="pending"),
                     lambda r: r.update(release_provenance_sha256="f" * 64), lambda r: r["ova"].update(sha256="f" * 64)]
        for mutate in mutations:
            self.native = copy.deepcopy(original); mutate(self.native)
            with self.subTest(value=self.native), self.assertRaises(Refused): self.verify_native()

    def test_missing_or_changed_evidence_and_source_are_rejected(self):
        self.native_fixture()
        evidence = self.evidence / "fixture-receipt.json"
        original = evidence.read_bytes(); evidence.write_bytes(original + b" ")
        with self.assertRaisesRegex(Refused, "evidence"): self.verify_native()
        evidence.write_bytes(original)
        (self.source / "cmd/nebulalog/main.go").write_bytes(b"different checkout")
        with self.assertRaisesRegex(Refused, "source tree"): self.verify_native()


if __name__ == "__main__":
    unittest.main()
