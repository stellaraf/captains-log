"""Real RSA, host archives, OCI blobs and evidence hashes; no native tests or publishing."""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager import host_payload as payload, publisher_inputs
from nebulalog_manager.common import Refused
import test_host_payload as hosts
import test_image_bundle as images
import test_manager as manager

PACKER = Path(__file__).resolve().parents[1] / "packer"
sys.path.insert(0, str(PACKER))
import assemble_release as release

NOW = datetime(2026, 9, 9, tzinfo=timezone.utc)
COMMIT = "a" * 40


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
        for name, raw in ((publisher_inputs.PUBLIC_SOURCE, raw_public), (publisher_inputs.DESCRIPTOR_SOURCE, payload.encoded(descriptor)),
                          ("go.mod", b"module fixture\n"), ("cmd/nebulalog/main.go", b"package main\n")):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            snapshot["files"][name] = payload.digest(raw)
        self.snapshot_path.write_bytes(payload.encoded(snapshot))
        self.images = self.root / "images"
        self.pins, self.image_manifest, _ = images.fixture_bundle(self.images, application_source_sha256=release.application_hash(snapshot))
        self.recipe = {"schema": 1, "repository": release.REPOSITORY, "sequence": 2, "version": "0.1.1",
            "issued_at": "2026-09-01T00:00:00Z", "expires_at": "2027-09-01T00:00:00Z", "schema_revision": "1", "source_commit": COMMIT,
            "components": {name: {"version": "0.1.1", "from_versions": ["0.1.0"]} for name in ("host", "nebulalog")}, "evidence_artifacts": []}
        self.recipe_path = self.root / "recipe.json"
        self.output = self.root / "release"
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()

    def assemble(self, *, signed=True):
        self.recipe_path.write_bytes(payload.encoded(self.recipe))
        return release.assemble(self.source, self.snapshot_path, self.images, self.recipe_path, self.output,
            signing_key=self.private.resolve() if signed else None, evidence_directory=self.evidence, now=NOW)

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
