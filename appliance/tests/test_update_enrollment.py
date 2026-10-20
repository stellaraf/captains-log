"""Real OCI/hash and RSA tests; runtime service observations are isolated fixtures."""
import hashlib
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from types import SimpleNamespace
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import update_enrollment as enrollment
from nebulalog_manager import baseline, host_payload
from nebulalog_manager.common import Refused, atomic_json, run
from nebulalog_manager.image_bundle import verify_bundle
from nebulalog_manager.updates import UpdateManager
from test_image_bundle import fixture_bundle
from test_baseline import CONTENT, CIS

INSTALLATION = "458a08e3-ef3b-4cd1-83e5-b402a2c1e913"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class InstalledReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.data, self.etc, self.share = (self.root / name for name in ("data", "etc", "share"))
        for path in (self.data / "manager", self.data / "tmp", self.etc, self.share):
            path.mkdir(mode=0o700, parents=True)
        self.source_files = {"cmd/nebulalog/main.go": "a" * 64, **enrollment.application_schema.SCHEMAS["1"]}
        self.pins, self.bundle_manifest, self.images = fixture_bundle(self.share / "images", enrollment.application_source_digest(self.source_files))
        atomic_json(self.etc / "images.json", self.pins)
        atomic_json(self.data / "configuration/bootstrap/setup.json", {"installation_id": INSTALLATION, "baseline": "cis-level2"})
        self.content_path = self.share / "ssg-fixture.xml"
        self.content_path.write_text(CONTENT)
        self.content_path.chmod(0o600)
        now = datetime.now(timezone.utc)
        self.policy_path = self.data / "configuration/security-policy.json"
        self.policy = {"schema": 1, "baseline": "cis-level2", "installation_id": INSTALLATION,
            "selection_id": "a" * 32, "assessments": [{"kind": "cis", "platform": "rocky9", "reviewed": True,
                "datastream": str(self.content_path), "sha256": digest(self.content_path), "profile_id": CIS,
                "source_url": "https://example.invalid/fixture", "content_revision": "fixture-v1",
                "content_review": {"approved": True, "reviewer": "Fixture reviewer", "platform_basis": "Fixture Rocky CPE",
                    "benchmark_basis": "Fixture Level 2 profile", "license_basis": "Synthetic fixture only",
                    "reviewed_at": (now - timedelta(days=1)).isoformat(), "expires_at": (now + timedelta(days=1)).isoformat()}}]}
        atomic_json(self.data / "configuration/lifecycle.json", {"schema_revision": "1"})
        atomic_json(self.share / "source-manifest.json", {"schema": 1, "files": self.source_files})
        self.descriptor = {"schema": 1, "product": "nebulalog", "sequence": 0, "schema_revision": "1", "source_commit": "b" * 40,
                           "source_dirty": True, "source_snapshot_sha256": digest(self.share / "source-manifest.json"),
                           "bundle_manifest_sha256": digest(self.share / "images/manifest.json"), "qualification_status": "pending",
                           "publisher": {"mode": "private-unsealed"}}
        atomic_json(self.share / "initial-release.json", self.descriptor)
        loaded = {name: {"manifest_digest": image["Digest"], "config_digest": image["Id"], "architecture": "amd64", "os": "linux"}
                  for name, ref in self.pins.items() for image in [self.images[ref]]}
        atomic_json(self.data / "manager/image-bundle-receipt.json", {"schema": 1, "status": "loaded", "network_used": False, "images": loaded})
        self.versions = {"api": "0.1.0-dev.abcdef123456", "ingest": "0.1.0-dev.abcdef123456", "postgresql": "17.11",
                         "clickhouse": "25.3.9.100.altinitystable", "keycloak": "Keycloak 26.7.3"}
        self.calls, self.container_changes = [], {}
        self.firstboot = Mock()
        self.firstboot.gate.return_value = {"host_ready": True, "installation_id": INSTALLATION}
        self.manager = enrollment.UpdateEnrollment(data=self.data, etc=self.etc, share=self.share, runner=self.runner, firstboot=self.firstboot)
        # These cases isolate OCI/runtime and publisher enrollment. Full initial
        # generation bytes/selection/dispatch are exercised in test_factory_host.
        self.host = {"generation": "1" * 64, "version": "0.0.0-factory.fixture", "host_source_sha256": "2" * 64, "abi": 1}
        self.host_probe = patch.object(self.manager, "_factory_host", return_value=self.host)
        self.host_probe.start()
        self.addCleanup(self.host_probe.stop)
        self.running_host_probe = patch.object(self.manager, "_running_host")
        self.running_host_probe.start()
        self.addCleanup(self.running_host_probe.stop)
        for mocker in (patch.object(enrollment, "require_linux_root"), patch.object(enrollment, "_tree"),
                       patch.object(enrollment, "ROOT_UID", os.getuid()),
                       patch.object(host_payload, "_OWNER_UID", os.getuid()),
                       patch.object(baseline, "_directory", side_effect=lambda path: Path(path)),
                       patch.object(baseline, "trusted_file", side_effect=lambda path: Path(path)),
                       patch.object(enrollment, "verify_bundle", side_effect=lambda path, pins, **_: verify_bundle(path, pins))):
            mocker.start()
            self.addCleanup(mocker.stop)

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:2] == ["oscap", "info"]:
            return "Profiles:\nID: " + CIS
        if argv == ["oscap", "--version"]:
            return "OpenSCAP command line tool (oscap) 1.3.fixture"
        if argv == ["rpm", "-q", "--qf", "%{NEVRA}", "openscap-scanner"]:
            return "openscap-scanner-1.3.14-1.el9.x86_64"
        if argv[0] == "openssl":
            return run(argv, **kwargs)
        if argv[:3] == ["podman", "image", "exists"]:
            return ""
        if argv[:3] == ["podman", "image", "inspect"]:
            return json.dumps([self.images[argv[3]]])
        if argv[:3] == ["podman", "container", "inspect"]:
            name = argv[3].removeprefix("nebulalog-")
            component = "nebulalog" if name in ("api", "ingest") else name
            image = self.images[self.pins[enrollment.COMPONENT_IMAGES[component]]]
            return json.dumps([{**{"Id": "c" * 64, "Image": image["Id"], "State": {"Running": True}}, **self.container_changes.get(name, {})}])
        if argv[:2] == ["podman", "exec"]:
            return self.versions[argv[4].removeprefix("nebulalog-")]
        raise AssertionError("Unexpected command: " + repr(argv))

    def test_measured_versions_archive_identity_dirty_provenance_and_idempotence(self):
        result = self.manager.installed()
        self.assertTrue(result["ok"])
        self.assertEqual(result["publisher_trust"], "not_enrolled")
        self.assertEqual(result["current"]["components"]["clickhouse"]["version"], "25.3.9.100.altinitystable")
        self.assertEqual(result["current"]["components"]["postgresql"]["version"], "17.11")
        receipt = json.loads((self.manager.state / "initial-enrollment.json").read_text())
        self.assertTrue(receipt["provenance"]["source_dirty"])
        self.assertEqual(receipt["provenance"]["qualification_status"], "pending")
        before = (self.manager.state / "current.json").read_bytes()
        self.assertEqual(self.manager.installed(), result)
        self.assertEqual((self.manager.state / "current.json").read_bytes(), before)
        self.assertFalse((self.etc / "release-public.pem").exists())
        self.assertNotIn("baseline", receipt["current"]["components"])
        self.assertFalse(self.policy_path.exists())
        self.assertTrue(all(call[0] == "podman" for call in self.calls))

    def test_content_from_another_installation_or_missing_policy_is_not_adopted(self):
        for changes in ({"installation_id": "11111111-2222-4333-8444-555555555555"}, {"baseline": "stig"}):
            atomic_json(self.policy_path, {**self.policy, **changes})
            with self.subTest(changes=changes), self.assertRaisesRegex(Refused, "installation and baseline"):
                self.manager._content(INSTALLATION)
            self.assertFalse((self.manager.state / "current.json").exists())
        self.policy_path.unlink()
        with self.assertRaises(Refused): self.manager._content(INSTALLATION)
        self.assertFalse((self.manager.state / "initial-enrollment.json").exists())

    def test_content_change_during_readonly_measurement_is_refused(self):
        atomic_json(self.policy_path, self.policy)
        runner = self.manager.runner
        def changed(argv, **kwargs):
            result = runner(argv, **kwargs)
            if argv[:2] == ["oscap", "info"]:
                self.content_path.write_text(CONTENT + "\n<!-- changed during observation -->")
            return result
        self.manager.runner = changed
        with self.assertRaises(Refused): self.manager._content(INSTALLATION)
        self.assertFalse((self.manager.state / "current.json").exists())

    def test_readonly_content_measurement_binds_scanner_without_writing_enrollment(self):
        atomic_json(self.policy_path, self.policy)
        runner, versions = self.manager.runner, iter(("1.3.fixture", "1.4.changed"))
        def changed(argv, **kwargs):
            result = runner(argv, **kwargs)
            if argv == ["oscap", "--version"]:
                return "OpenSCAP command line tool (oscap) " + next(versions)
            return result
        self.manager.runner = changed
        before = self.manager._content(INSTALLATION)
        after = self.manager._content(INSTALLATION)
        self.assertEqual(before["policy_sha256"], digest(self.policy_path))
        self.assertNotEqual(before["engine"], after["engine"])
        self.assertNotEqual(before["generation"], after["generation"])
        self.assertFalse((self.manager.state / "initial-pending.json").exists())

    def test_policy_change_after_completed_initial_enrollment_is_not_reenrolled(self):
        self.manager.installed()
        before = (self.manager.state / "initial-enrollment.json").read_bytes()
        atomic_json(self.policy_path, self.policy)
        self.assertNotIn("baseline", self.manager.installed()["current"]["components"])
        measured = self.manager._content(INSTALLATION)
        self.assertEqual(measured["policy_sha256"], digest(self.policy_path))
        self.assertEqual((self.manager.state / "initial-enrollment.json").read_bytes(), before)

    def test_runtime_prepare_precedes_console_hardening_without_fabricating_initial_content(self):
        from nebulalog_manager import bootstrap, firstboot
        from nebulalog_manager.firstboot import Locations, RUNTIME_CHECKS
        paths = Locations(self.etc, self.data, self.root / "run")
        paths.bootstrap.mkdir()
        setup = {"installation_id": INSTALLATION, "hostname": "fixture.invalid", "baseline": "cis-level2"}
        atomic_json(self.data / "configuration/bootstrap/setup.json", setup)
        stages = []
        def runtime_runner(argv, **kwargs):
            self.assertEqual(argv, [str(bootstrap.ENROLL_RELEASE)])
            self.assertFalse(self.policy_path.exists())
            stages.append("installed-release")
            return json.dumps(self.manager.installed())
        runtime = bootstrap.Bootstrap(paths, runner=runtime_runner, firstboot=self.firstboot)
        runtime.setup, runtime.pins = setup, self.pins
        runtime.state = {"installation_id": INSTALLATION, "completed": []}
        evidence = {"checks": {name: True for name in RUNTIME_CHECKS}, "https_url": "https://fixture.invalid"}
        with ExitStack() as stack:
            stack.enter_context(patch.object(runtime, "_load"))
            stack.enter_context(patch.object(runtime, "_schema_revision", return_value="1"))
            stack.enter_context(patch.object(runtime, "_evidence", return_value=evidence))
            stack.enter_context(patch.object(bootstrap, "INITIAL_RELEASE", self.share / "initial-release.json"))
            stack.enter_context(patch.object(bootstrap, "trusted_file", side_effect=lambda path: Path(path)))
            stack.enter_context(patch.object(bootstrap.os, "access", return_value=True))
            stack.enter_context(patch.object(enrollment.UpdateEnrollment, "_factory_host", return_value=self.host))
            for method in ("_directories", "_storage_maintenance", "_certificates", "_images", "_environment", "_realm", "_postgres", "_migrate", "_identity", "_lifecycle", "_edge"):
                stack.enter_context(patch.object(runtime, method))
            receipt = runtime.prepare(runtime.bootstrap / "setup.json", runtime.bootstrap / "secrets.json")
        initial = (self.manager.state / "initial-enrollment.json").read_bytes()
        self.assertNotIn("baseline", json.loads(initial)["current"]["components"])
        self.assertFalse(self.policy_path.exists())
        def hardening(manager, config):
            # Only the native hardening boundary is inert; console ordering,
            # actual runtime enrollment and immutable evidence remain real.
            self.assertEqual(config, setup)
            stages.append("HARDENING")
            atomic_json(self.policy_path, self.policy)
        with patch("nebulalog_manager.setup_integrity.pending_console"), \
                patch.object(firstboot, "_answer", side_effect=["HARDENING", "LATER"]), \
                patch.object(firstboot, "_hardening_console", side_effect=hardening):
            result = firstboot._runtime_console(SimpleNamespace(paths=paths), setup, receipt)
        self.assertEqual(stages, ["installed-release", "HARDENING"])
        self.assertEqual(result["state"], "runtime-ready")
        self.assertTrue(self.policy_path.exists())
        self.assertEqual((self.manager.state / "initial-enrollment.json").read_bytes(), initial)
        self.assertNotIn("baseline", json.loads((self.manager.state / "current.json").read_text())["components"])

    def test_pristine_installer_and_sealer_verify_same_real_bundle_source_contract(self):
        value = self.manager.verify_build_inputs()
        self.assertEqual(value["descriptor"], self.descriptor)
        self.assertEqual(value["application_source_sha256"], enrollment.application_source_digest(self.source_files))
        self.assertEqual(set(value["bundle"]["images"]), set(self.pins))
        self.assertEqual(self.calls, [])
        self.firstboot.gate.assert_not_called()

    def test_pristine_build_refuses_bundle_manifest_and_application_source_mismatch(self):
        self.descriptor["bundle_manifest_sha256"] = "f" * 64
        atomic_json(self.share / "initial-release.json", self.descriptor)
        with self.assertRaisesRegex(Refused, "offline bundle"):
            self.manager.verify_build_inputs()
        self.descriptor["bundle_manifest_sha256"] = digest(self.share / "images/manifest.json")
        atomic_json(self.share / "source-manifest.json", {"schema": 1, "files": {**self.source_files, "cmd/nebulalog/main.go": "c" * 64}})
        self.descriptor["source_snapshot_sha256"] = digest(self.share / "source-manifest.json")
        atomic_json(self.share / "initial-release.json", self.descriptor)
        with self.assertRaisesRegex(Refused, "Application image"):
            self.manager.verify_build_inputs()
        self.assertEqual(self.calls, [])

    def test_missing_descriptor_refuses_before_runtime_commands(self):
        (self.share / "initial-release.json").unlink()
        with self.assertRaises(Refused):
            self.manager.installed()
        self.assertEqual(self.calls, [])
        self.assertFalse((self.manager.state / "current.json").exists())

    def test_archive_tampering_refuses_before_runtime_commands(self):
        entry = next(iter(self.bundle_manifest["images"].values()))
        with (self.share / "images" / entry["archive"]).open("r+b") as stream:
            stream.seek(1024)
            stream.write(b"tamper")
        with self.assertRaisesRegex(Refused, "SHA256"):
            self.manager.installed()
        self.assertEqual(self.calls, [])

    def test_running_image_mismatch_or_stopped_container_refuses(self):
        for changes in ({"Image": "sha256:" + "d" * 64}, {"State": {"Running": False}}, {"Id": None}):
            self.container_changes["api"] = changes
            with self.subTest(changes=changes), self.assertRaisesRegex(Refused, "Running container"):
                self.manager.installed()
            self.assertFalse((self.manager.state / "current.json").exists())

    def test_api_and_ingest_must_measure_same_version(self):
        self.versions["ingest"] = "0.1.9"
        with self.assertRaisesRegex(Refused, "different application versions"):
            self.manager.installed()

    def test_new_descriptor_or_changed_current_never_resets_enrollment(self):
        self.manager.installed()
        before = (self.manager.state / "current.json").read_bytes()
        self.descriptor["source_dirty"] = False
        atomic_json(self.share / "initial-release.json", self.descriptor)
        with self.assertRaisesRegex(Refused, "differs"):
            self.manager.installed()
        self.assertEqual((self.manager.state / "current.json").read_bytes(), before)
        self.descriptor["source_dirty"] = True
        atomic_json(self.share / "initial-release.json", self.descriptor)
        current = json.loads(before)
        current["sequence"] = 4
        atomic_json(self.manager.state / "current.json", current)
        with self.assertRaisesRegex(Refused, "differs"):
            self.manager.installed()
        self.assertEqual(json.loads((self.manager.state / "current.json").read_text())["sequence"], 4)

    def test_existing_current_is_not_adopted_or_overwritten(self):
        atomic_json(self.manager.state / "current.json", {"sequence": 1, "components": {}})
        with self.assertRaisesRegex(Refused, "differs"):
            self.manager.installed()
        self.assertFalse((self.manager.state / "initial-pending.json").exists())

    def test_interruption_after_current_write_resumes_exact_proposal(self):
        original = enrollment.atomic_json
        def interrupted(path, value):
            if path.name == "initial-enrollment.json":
                raise OSError("simulated power loss")
            original(path, value)
        with patch.object(enrollment, "atomic_json", side_effect=interrupted), self.assertRaises(OSError):
            self.manager.installed()
        self.assertTrue((self.manager.state / "current.json").exists())
        self.assertFalse((self.manager.state / "initial-enrollment.json").exists())
        self.assertTrue(self.manager.installed()["ok"])

    def test_claimed_qualification_and_unbound_source_are_refused(self):
        self.descriptor["qualification_status"] = "qualified"
        atomic_json(self.share / "initial-release.json", self.descriptor)
        with self.assertRaisesRegex(Refused, "unsupported claims"):
            self.manager.installed()
        self.descriptor["qualification_status"] = "pending"
        atomic_json(self.share / "initial-release.json", self.descriptor)
        atomic_json(self.share / "source-manifest.json", {"schema": 1, "files": {"cmd/main.go": "e" * 64}})
        with self.assertRaisesRegex(Refused, "source manifest"):
            self.manager.installed()

    def test_newer_captured_source_cannot_be_attributed_to_older_application_image(self):
        self.source_files["cmd/nebulalog/main.go"] = "e" * 64
        atomic_json(self.share / "source-manifest.json", {"schema": 1, "files": self.source_files})
        self.descriptor["source_snapshot_sha256"] = digest(self.share / "source-manifest.json")
        atomic_json(self.share / "initial-release.json", self.descriptor)
        with self.assertRaisesRegex(Refused, "source label"):
            self.manager.installed()
        self.assertEqual(self.calls, [])
        self.assertFalse((self.manager.state / "current.json").exists())

    def test_missing_source_label_refuses_before_any_runtime_command(self):
        verified = verify_bundle(self.share / "images", self.pins)
        verified["images"]["NEBULALOG_IMAGE"]["application_source_sha256"] = None
        with patch.object(enrollment, "verify_bundle", return_value=verified), self.assertRaisesRegex(Refused, "source label"):
            self.manager.installed()
        self.assertEqual(self.calls, [])

    def test_application_source_subset_hash_is_deterministic_and_ignores_host_only_changes(self):
        files = {"docs/README.md": "b" * 64, "cmd/main.go": "a" * 64, "go.mod": "c" * 64}
        expected = hashlib.sha256(b'{"cmd/main.go":"' + b'a'*64 + b'","go.mod":"' + b'c'*64 + b'"}').hexdigest()
        self.assertEqual(enrollment.application_source_digest(files), expected)
        files["appliance/nebulalog_manager/bootstrap.py"] = "d" * 64
        self.assertEqual(enrollment.application_source_digest(dict(reversed(list(files.items())))), expected)

    def test_literal_systemd_instance_path_is_valid_captured_source(self):
        self.source_files["appliance/systemd/getty@tty1.service.d/50-nebulalog-firstboot.conf"] = "e" * 64
        atomic_json(self.share / "source-manifest.json", {"schema": 1, "files": self.source_files})
        self.descriptor["source_snapshot_sha256"] = digest(self.share / "source-manifest.json")
        atomic_json(self.share / "initial-release.json", self.descriptor)
        self.assertTrue(self.manager.installed()["ok"])

    def test_reader_refuses_link_writable_file_and_nonregular_input(self):
        path = self.root / "unsafe"
        path.symlink_to(self.share / "initial-release.json")
        with self.assertRaises(Refused):
            enrollment._read(path)
        path.unlink()
        path.write_text("{}")
        path.chmod(0o666)
        with self.assertRaises(Refused):
            enrollment._read(path)
        path.unlink()
        path.mkdir()
        with self.assertRaises(Refused):
            enrollment._read(path)


@unittest.skipUnless(shutil.which("openssl"), "Real OpenSSL public-key verification required")
class FactoryRestoreProofTests(unittest.TestCase):
    from test_restore_auth_contract import FactoryContractTests as _Fixture
    setUp = _Fixture.setUp
    rewrite = _Fixture.rewrite
    factory = _Fixture.factory

    def test_initial_proof_is_bound_to_descriptor_host_source_and_exact_offline_image(self):
        self.factory()
        manager = enrollment.UpdateEnrollment(share=self.share)
        host = {"generation": self.factory_host["archive_sha256"]}
        verified = {"images": {"NEBULALOG_IMAGE": self.image}}
        with patch.object(enrollment, "ROOT_UID", os.getuid()), patch.object(enrollment, "_tree"), \
                patch.object(host_payload, "_OWNER_UID", os.getuid()), \
                patch("nebulalog_manager.host_dispatch.protected_json", return_value=self.factory_host["metadata"]):
            self.assertIsNone(manager._factory_restore_auth(self.descriptor, verified, None))
            proof = manager._factory_restore_auth(self.descriptor, verified, host)
            self.assertEqual(proof["subject"]["host_generation"], host["generation"])
            self.assertFalse(proof["native_qualified"])
            path = self.share / "restore-auth/restore-auth-behavior.json"
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaises(Refused): manager._factory_restore_auth(self.descriptor, verified, host)

    def test_absent_factory_descriptor_never_adopts_loose_receipts(self):
        self.factory()
        manager = enrollment.UpdateEnrollment(share=self.share)
        with patch.object(enrollment, "_read", side_effect=AssertionError("must not read loose evidence")):
            self.assertIsNone(manager._factory_restore_auth({}, {}, None))


class PublisherTrustTests(unittest.TestCase):
    runner = InstalledReleaseTests.runner
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.private = Path(cls.keys.name) / "test-only-private.pem"
        cls.public = Path(cls.keys.name) / "publisher.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(cls.private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(cls.private), "-pubout", "-out", str(cls.public)], check=True)
        der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(cls.public), "-pubout", "-outform", "DER"])
        cls.fingerprint = hashlib.sha256(der).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        InstalledReleaseTests.setUp(self)
        self.manager.installed()

    def enroll(self, **changes):
        return self.manager.trust(changes.get("source", self.public), changes.get("fingerprint", self.fingerprint), changes.get("trust_source", "Fixture publisher authenticated in a separate test channel"))

    def test_trust_real_spki_hash_idempotence_and_manager_key_binding(self):
        result = self.enroll()
        target = self.etc / "release-public.pem"
        self.assertEqual(result, self.enroll())
        self.assertEqual(enrollment.enrolled_key(self.manager.state, target)["spki_sha256"], self.fingerprint)
        with self.assertRaisesRegex(Refused, "changed"):
            enrollment.enrolled_key(self.manager.state, self.public)
        with target.open("ab") as stream:
            stream.write(b"\n")
        with self.assertRaisesRegex(Refused, "changed"):
            enrollment.enrolled_key(self.manager.state, target)
        with self.assertRaisesRegex(Refused, "changed"):
            self.manager.installed()

    def test_mismatched_fingerprint_and_private_input_create_no_trust(self):
        for kwargs in ({"fingerprint": "0" * 64}, {"source": self.private}):
            with self.subTest(kwargs=kwargs), self.assertRaises(Refused):
                self.enroll(**kwargs)
            self.assertFalse((self.etc / "release-public.pem").exists())
            self.assertFalse((self.manager.state / "publisher-pending.json").exists())

    def test_weak_rsa_key_refuses_before_trust_writes(self):
        private, public = self.root / "test-only-weak-private.pem", self.root / "test-only-weak-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True)
        with self.assertRaisesRegex(Refused, "3072"):
            self.enroll(source=public)
        self.assertFalse((self.manager.state / "publisher-pending.json").exists())

    def test_cli_check_cannot_substitute_another_public_key_path(self):
        from nebulalog_manager.cli import main
        self.enroll()
        with patch("nebulalog_manager.cli.updates.UpdateManager", return_value=UpdateManager(state=self.manager.state)), \
                patch("nebulalog_manager.cli.trusted_file", side_effect=lambda path: path), \
                patch("nebulalog_manager.cli.updates.verify_release") as verify, \
                patch("sys.stderr"):
            result = main(["update", "check", "--manifest", str(self.root / "manifest"), "--signature", str(self.root / "signature"),
                           "--bundle", str(self.root), "--public-key", str(self.public)])
        self.assertEqual(result, 1)
        verify.assert_not_called()

    def test_changed_trust_source_refuses_without_overwriting(self):
        self.enroll()
        before = (self.manager.state / "publisher-trust.json").read_bytes()
        with self.assertRaisesRegex(Refused, "rotation"):
            self.enroll(trust_source="A different unreviewed trust source")
        self.assertEqual((self.manager.state / "publisher-trust.json").read_bytes(), before)

    def test_changed_or_incomplete_current_refuses_before_publisher_writes(self):
        original = (self.manager.state / "current.json").read_bytes()
        mutations = (lambda value: value["components"]["postgresql"].update(version="1.0-unmeasured"),
                     lambda value: value["components"]["nebulalog"].update(image="registry.invalid/app@sha256:" + "f" * 64),
                     lambda value: value["components"].pop("clickhouse"),
                     lambda value: value.pop("version"), lambda value: value.update(sequence=4))
        for mutation in mutations:
            value = json.loads(original)
            mutation(value)
            atomic_json(self.manager.state / "current.json", value)
            with self.subTest(value=value), self.assertRaises(Refused):
                self.enroll()
            self.assertFalse((self.etc / "release-public.pem").exists())
            self.assertFalse((self.manager.state / "publisher-pending.json").exists())
            self.assertFalse(enrollment.enrollment_status(self.manager.state)["update_ready"])
        (self.manager.state / "current.json").write_bytes(original)
        self.enroll()
        value = json.loads(original)
        value["components"]["postgresql"]["version"] = "1.0-unmeasured"
        atomic_json(self.manager.state / "current.json", value)
        with self.assertRaises(Refused):
            enrollment.enrolled_key(self.manager.state, self.etc / "release-public.pem")
        self.assertFalse(enrollment.enrollment_status(self.manager.state)["update_ready"])

    def test_interruption_after_key_write_resumes_only_matching_trust(self):
        original = enrollment.atomic_json
        def interrupted(path, value):
            if path.name == "publisher-trust.json":
                raise OSError("simulated power loss")
            original(path, value)
        with patch.object(enrollment, "atomic_json", side_effect=interrupted), self.assertRaises(OSError):
            self.enroll()
        target = self.etc / "release-public.pem"
        self.assertTrue(target.exists())
        with self.assertRaisesRegex(Refused, "completed"):
            enrollment.enrolled_key(self.manager.state, target)
        self.assertTrue(self.enroll()["ok"])

    def test_all_manager_actions_refuse_missing_or_altered_enrollment_before_hooks(self):
        self.enroll()
        target = self.etc / "release-public.pem"
        runner = Mock(side_effect=AssertionError("No command should run before enrollment acceptance"))
        manager = UpdateManager(state=self.manager.state, runner=runner)
        for damage in ("missing", "modified_initial"):
            with self.subTest(damage=damage):
                if damage == "missing":
                    (self.manager.state / "publisher-trust.json").unlink()
                else:
                    self.enroll()
                    value = json.loads((self.manager.state / "initial-enrollment.json").read_text())
                    value["provenance"]["source_commit"] = "f" * 40
                    atomic_json(self.manager.state / "initial-enrollment.json", value)
                with patch("nebulalog_manager.updates.require_linux_root"), patch("nebulalog_manager.updates.trusted_file", side_effect=lambda path: path):
                    for action in (lambda: manager.install(self.root / "manifest", self.root / "sig", self.root, target),
                                   lambda: manager.finalize(target), lambda: manager.rollback(target)):
                        with self.assertRaises(Refused):
                            action()
        runner.assert_not_called()
