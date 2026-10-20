"""Artifact/parser fixtures only; these do not perform or assert image qualification."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import shutil
import subprocess
import tempfile
import unittest

from nebulalog_manager import host_payload as payload, image_bundle
from nebulalog_manager.common import Refused
from nebulalog_manager.image_bundle import ApplicationSchema, RestoredAuthContract as Contract
import test_host_payload as hosts
import test_image_bundle as images

PACKER = Path(__file__).resolve().parents[1] / "packer"
sys.path.insert(0, str(PACKER))
from build_host_bundle import build as build_host
from prepare_provenance import application_hash
from prepare_provenance import capture


def build_receipt(snapshot, image, version):
    """Synthetic build receipt for binding tests, never a release input."""
    selected = Contract.application_files(snapshot["files"])
    return {"schema": 1, "status": "built", "tag": "nebulalog/fixture:test", "local_image_id": image["config_digest"],
            "platform": "linux/amd64", "requested_version": version,
            "application_source_sha256": Contract.application_hash(snapshot["files"]),
            "source_commit": "a" * 40, "source_dirty": True, "application_files": selected,
            "context_sha256": "b" * 64, "context_bytes": 10240, "source_bytes": 1024,
            "source_files": len(selected), "context_mode": "captured_source_tar_stdin",
            "runtime_executed": False, "signature_created": False}


def behavior_receipt(image, reference):
    """Synthetic HTTP results for parser tests; no HTTP request was performed."""
    cutoff = 1700000000
    cases = {}
    for name, status in Contract.CASES.items():
        cases[name] = {"iat": None if name == "missing_iat" else cutoff + (-1 if name == "before_cutoff" else 1 if name == "after_cutoff" else 0),
            "exp": cutoff + (9 if name == "expired" else 120), "observed_at": cutoff + 10,
            "issuer_match": name != "wrong_issuer", "audience_match": name != "wrong_audience",
            "signature_valid": name != "wrong_signature", "http_status": status,
            "api_role": "VIEWER" if status == 200 else None, "token_sha256": hashlib.sha256(name.encode()).hexdigest()}
    return {"schema": 1, "kind": "captains-log-restored-token-boundary", "method": "isolated-image-normal-api-http",
            "application_image": reference, "application_config_digest": image["config_digest"],
            "application_source_sha256": image["application_source_sha256"], "command": ["serve"],
            "http_method": "GET", "path": "/api/me", "issuer_mode": "isolated-fixture",
            "cutoff": cutoff, "observed_cutoff": cutoff, "cases": cases}


class ContractTests(unittest.TestCase):
    revision = "3"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source, snapshot_path = hosts.fixture_source(self.root)
        self.snapshot = json.loads(snapshot_path.read_bytes())
        self.revision = getattr(self, "revision", "3")
        for name in Contract.REQUIRED_SOURCE | set(ApplicationSchema.SCHEMAS[self.revision]):
            raw = ((PACKER.parents[1] / name).read_bytes() if name.startswith("migrations/") else (name + " fixture\n").encode())
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            self.snapshot["files"][name] = payload.digest(raw)
        snapshot_path.write_bytes(payload.encoded(self.snapshot))
        self.bundle = self.root / "bundle"
        self.pins, _, _ = images.fixture_bundle(self.bundle, application_source_sha256=application_hash(self.snapshot))
        verified = image_bundle.verify_bundle(self.bundle, self.pins)
        self.image = verified["images"]["NEBULALOG_IMAGE"]
        self.host = build_host(self.source, snapshot_path, self.bundle / "host.tar", version="1.0.1")
        self.manifest = {"version": "1.0.1", "restore_auth": Contract.declaration(), "components": {
            "host": {"artifact": "host.tar", "version": "1.0.1", "host_source_sha256": self.host["metadata"]["host_source_sha256"], "rollback_safe": True},
            "nebulalog": {"artifact": self.image["archive"], "image": self.pins["NEBULALOG_IMAGE"], "rollback_safe": True,
                          **ApplicationSchema.declaration(self.snapshot["files"], self.revision)}}, "artifacts": []}
        self.build = build_receipt(self.snapshot, self.image, self.manifest["version"])
        self.behavior = behavior_receipt(self.image, self.pins["NEBULALOG_IMAGE"])
        self.rewrite()

    def rewrite(self):
        for name, value in ((Contract.SOURCE, self.snapshot), (Contract.BUILD, self.build), (Contract.BEHAVIOR, self.behavior)):
            (self.bundle / name).write_bytes(payload.encoded(value))
        names = {Contract.SOURCE, Contract.BUILD, Contract.BEHAVIOR, "host.tar", self.image["archive"]}
        self.manifest["artifacts"] = [{"name": name, "bytes": (self.bundle / name).stat().st_size,
            "sha256": payload.digest((self.bundle / name).read_bytes())} for name in sorted(names)]

    def verify(self):
        return Contract.verify(self.manifest, self.bundle)

    def test_exact_real_archives_bind_without_claiming_native_or_tool_verified_execution(self):
        result = self.verify()
        self.assertEqual(result["subject"]["host_generation"], self.host["archive_sha256"])
        self.assertEqual(result["subject"]["application_config_digest"], self.image["config_digest"])
        self.assertEqual(Contract.application_hash(self.snapshot["files"]), application_hash(self.snapshot))
        self.assertEqual(result["subject"]["schema_revision"], self.revision)
        self.assertFalse(result["native_qualified"])
        self.assertFalse(result["execution_verified_by_tool"])

    def test_missing_unsigned_or_unknown_contract_refuses(self):
        for change in (None, True, {**Contract.declaration(), "qualified": True}, {**Contract.declaration(), "schema": True}):
            with self.subTest(change=change), self.assertRaises(Refused):
                Contract.verify({**self.manifest, "restore_auth": change}, self.bundle)
        original = copy.deepcopy(self.manifest)
        for name in (Contract.SOURCE, Contract.BUILD, Contract.BEHAVIOR):
            self.manifest = copy.deepcopy(original)
            self.manifest["artifacts"] = [item for item in self.manifest["artifacts"] if item["name"] != name]
            with self.subTest(name=name), self.assertRaises(Refused): self.verify()

    def test_legacy_schema_and_migrations_are_not_admitted(self):
        original = copy.deepcopy(self.manifest)
        for change in ({"schema_revision": "2"}, {"database_migration": ApplicationSchema.ADDITIVE_UPGRADE}, {"rollback_safe": False}):
            self.manifest = copy.deepcopy(original)
            self.manifest["components"]["nebulalog"].update(change)
            with self.subTest(change=change), self.assertRaises(Refused): self.verify()

    def test_changed_source_build_image_or_version_refuses(self):
        original = copy.deepcopy(self.build)
        for change in ({"local_image_id": "sha256:" + "f" * 64}, {"application_source_sha256": "f" * 64},
                       {"requested_version": "9.0.0"}, {"context_mode": "live_directory"}, {"source_files": True},
                       {"runtime_executed": True}, {"application_files": {}}, {"context_bytes": 0}):
            self.build = {**original, **change}; self.rewrite()
            with self.subTest(change=change), self.assertRaises(Refused): self.verify()
        self.build = original
        self.snapshot["files"]["internal/auth/restore.go"] = "f" * 64
        self.rewrite()
        with self.assertRaises(Refused): self.verify()

    def test_behavior_must_use_normal_api_route_exact_image_and_fixed_cutoff(self):
        original = copy.deepcopy(self.behavior)
        for change in ({"method": "go_unit_test"}, {"command": ["version"]}, {"command": ["api"]}, {"path": "/api/health"},
                       {"observed_cutoff": original["cutoff"] - 1}, {"application_config_digest": "sha256:" + "f" * 64},
                       {"application_source_sha256": "f" * 64}, {"issuer_mode": "production"}, {"cutoff": True}):
            self.behavior = {**original, **change}; self.rewrite()
            with self.subTest(change=change), self.assertRaises(Refused): self.verify()

    def test_each_case_must_pass_without_expiry_signature_or_role_confounders(self):
        original = copy.deepcopy(self.behavior)
        for name in Contract.CASES:
            self.behavior = copy.deepcopy(original)
            self.behavior["cases"][name]["http_status"] = 503
            self.rewrite()
            with self.subTest(name=name), self.assertRaises(Refused): self.verify()
        for change in ({"exp": original["cutoff"]}, {"signature_valid": False}, {"issuer_match": False}, {"audience_match": False}, {"http_status": True}):
            self.behavior = copy.deepcopy(original)
            self.behavior["cases"]["before_cutoff"].update(change); self.rewrite()
            with self.subTest(change=change), self.assertRaises(Refused): self.verify()
        self.behavior = copy.deepcopy(original)
        self.behavior["cases"]["at_cutoff"]["api_role"] = "ADMINISTRATOR"; self.rewrite()
        with self.assertRaises(Refused): self.verify()

    def test_artifact_hash_duplicate_json_and_symlinks_refuse(self):
        path = self.bundle / Contract.BEHAVIOR
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(Refused): self.verify()
        self.rewrite()
        path.write_bytes(b'{"schema":1,"schema":1}')
        for item in self.manifest["artifacts"]:
            if item["name"] == Contract.BEHAVIOR:
                item.update(bytes=path.stat().st_size, sha256=payload.digest(path.read_bytes()))
        with self.assertRaises(Refused): self.verify()
        self.rewrite()
        moved = path.with_name("moved.json"); path.rename(moved); path.symlink_to(moved)
        with self.assertRaises(Refused): self.verify()




class FactoryContractTests(unittest.TestCase):
    setUp = ContractTests.setUp
    rewrite = ContractTests.rewrite

    def factory(self):
        self.share = self.root / "share"
        self.share.mkdir()
        (self.share / "restore-auth").mkdir()
        shutil.copy2(self.bundle / Contract.SOURCE, self.share / Contract.SOURCE)
        for name in Contract.EVIDENCE:
            shutil.copy2(self.bundle / name, self.share / "restore-auth" / name)
        value = Contract.factory_capture(self.snapshot["files"], self.image,
            (self.bundle / Contract.BUILD).read_bytes(), (self.bundle / Contract.BEHAVIOR).read_bytes(),
            schema_revision=self.revision)
        self.descriptor = {"schema_revision": self.revision, "source_snapshot_sha256": payload.digest((self.share / Contract.SOURCE).read_bytes()), "restore_auth": value}
        # Factory host version is deliberately independent of the application.
        self.factory_host = build_host(self.source, self.share / Contract.SOURCE, self.root / "factory-host.tar", version="0.0.0-factory.abcdef")

    def test_factory_host_and_app_versions_are_independently_bound(self):
        self.factory()
        proof = Contract.verify_factory(self.descriptor, self.share, self.factory_host, self.image, root_owned=False)
        self.assertEqual(proof["subject"]["host_generation"], self.factory_host["archive_sha256"])
        self.assertEqual(proof["subject"]["application_image"], self.pins["NEBULALOG_IMAGE"])
        self.assertEqual(proof["subject"]["schema_revision"], self.revision)
        self.assertFalse(proof["native_qualified"])

    def test_factory_absence_loose_receipts_tamper_and_legacy_refuse(self):
        self.factory()
        for descriptor in ({}, {**self.descriptor, "schema_revision": "2"},
                           {**self.descriptor, "restore_auth": {**self.descriptor["restore_auth"], "qualified": True}}):
            with self.subTest(descriptor=descriptor), self.assertRaises(Refused):
                Contract.verify_factory(descriptor, self.share, self.factory_host, self.image, root_owned=False)
        path = self.share / "restore-auth" / Contract.BEHAVIOR
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(Refused):
            Contract.verify_factory(self.descriptor, self.share, self.factory_host, self.image, root_owned=False)

    def test_capture_places_exact_receipts_under_initial_descriptor_without_native_claim(self):
        environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        for argv in (("init", "--quiet"), ("add", "."), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")):
            subprocess.run(["git", "-C", str(self.source), *argv], env=environment, check=True, capture_output=True)
        output = self.root / "provenance"
        result = capture(self.source, self.bundle, output, sequence=1, schema_revision="3", private_unsealed=True,
                         restore_auth_evidence=self.bundle)
        descriptor = payload.strict_json((output / "initial-release.json").read_bytes())
        self.assertEqual(descriptor["restore_auth"], result["restore_auth"])
        self.assertEqual(descriptor["qualification_status"], "pending")
        self.assertFalse(result["signature_created"])
        for name in Contract.EVIDENCE:
            self.assertEqual((output / "restore-auth" / name).read_bytes(), (self.bundle / name).read_bytes())


class Schema4ContractTests(ContractTests):
    revision = "4"


class Schema4FactoryContractTests(unittest.TestCase):
    """Explicit binding only; the default packaging/admission hold stays closed."""
    revision = "4"
    setUp = ContractTests.setUp
    rewrite = ContractTests.rewrite
    factory = FactoryContractTests.factory
    test_factory_host_and_app_versions_are_independently_bound = FactoryContractTests.test_factory_host_and_app_versions_are_independently_bound
    test_factory_absence_loose_receipts_tamper_and_legacy_refuse = FactoryContractTests.test_factory_absence_loose_receipts_tamper_and_legacy_refuse

    def test_schema4_source_cannot_be_relabelled_as_same_schema3(self):
        self.factory()
        with self.assertRaises(Refused):
            Contract.verify_factory({**self.descriptor, "schema_revision": "3"},
                                    self.share, self.factory_host, self.image, root_owned=False)
