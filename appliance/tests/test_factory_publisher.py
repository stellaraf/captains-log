"""Disposable RSA/OpenSSL and actual provenance parsers; no guest or publisher changes."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager import publisher_inputs as public
from nebulalog_manager import update_enrollment as enrollment
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.updates import verify_release
import test_update_enrollment as fixtures
import test_stage_sources as stages
import test_archive_sources as archives
import test_provision_guard as provision


def public_descriptor(fingerprint):
    return {"schema": 1, "publisher": "Fixture Publisher", "repository": "stellaraf/captains-log",
            "key_id": "fixture-2026", "algorithm": "RSA-PSS-SHA256", "spki_sha256": fingerprint}


def serialized(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


@unittest.skipUnless(shutil.which("openssl"), "Real OpenSSL is required for public trust verification")
class FactoryPublisherTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.PublisherTrustTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.PublisherTrustTests.tearDownClass.__func__)
    runner = fixtures.InstalledReleaseTests.runner

    def setUp(self):
        fixtures.InstalledReleaseTests.setUp(self)
        self.description = public_descriptor(self.fingerprint)
        self.configure()

    def configure(self, *, key=None, description=None):
        raw = self.public.read_bytes() if key is None else key
        self.description = self.description if description is None else description
        description_raw = serialized(self.description)
        (self.share / "publisher-public.spki").write_bytes(raw)
        (self.share / "publisher-trust.json").write_bytes(description_raw)
        self.source_files.update({public.PUBLIC_SOURCE: public.digest(raw), public.DESCRIPTOR_SOURCE: public.digest(description_raw)})
        atomic_json(self.share / "source-manifest.json", {"schema": 1, "files": self.source_files})
        self.descriptor.update(source_snapshot_sha256=fixtures.digest(self.share / "source-manifest.json"),
                               publisher={"mode": "factory", "descriptor_sha256": public.digest(description_raw),
                                          "public_spki_pem_sha256": public.digest(raw),
                                          **{name: self.description.get(name) for name in ("spki_sha256", "repository", "key_id")}})
        atomic_json(self.share / "initial-release.json", self.descriptor)

    def test_factory_install_automatically_enrolls_exact_public_trust_and_is_idempotent(self):
        value = self.manager.installed()
        self.assertEqual(value["publisher_trust"], "enrolled")
        self.assertEqual(value["build_mode"], "factory")
        self.assertTrue(value["update_ready"])
        target = self.etc / "release-public.pem"
        receipt = enrollment.enrolled_key(self.manager.state, target)
        self.assertEqual(receipt["spki_sha256"], self.fingerprint)
        self.assertIn(fixtures.digest(self.share / "initial-release.json"), receipt["trust_source"])
        self.assertEqual(receipt["algorithm"], "RSA-PSS-SHA256")
        self.assertEqual(receipt["rsa_bits"], 3072)
        before = {name: (self.manager.state / name).read_bytes() for name in ("publisher-pending.json", "publisher-trust.json", "current.json")}
        self.assertEqual(self.manager.installed(), value)
        self.assertEqual(before, {name: (self.manager.state / name).read_bytes() for name in before})
        self.assertTrue(self.manager.factory_status()["update_ready"])
        self.assertFalse(any(command[0] in ("curl", "wget", "ssh") or "genpkey" in command or "genrsa" in command for command in self.calls))

    def test_factory_enrolled_key_verifies_real_pss_sha256_release(self):
        self.manager.installed()
        artifact = self.root / "app.tar"
        artifact.write_bytes(b"real signed artifact fixture")
        manifest = {"schema": 1, "product": "nebulalog", "channel": "stable", "version": "0.1.1", "sequence": 1,
                    "issued_at": "2026-09-01T00:00:00Z", "expires_at": "2026-10-01T00:00:00Z",
                    "artifacts": [{"name": "app.tar", "bytes": artifact.stat().st_size, "sha256": fixtures.digest(artifact)}],
                    "components": {"nebulalog": {"version": "0.1.1", "artifact": "app.tar", "from_versions": [self.versions["api"]], "rollback_safe": True}}}
        path, signature = self.root / "manifest.json", self.root / "manifest.sig"
        path.write_bytes(serialized(manifest))
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.private), "-sigopt", "rsa_padding_mode:pss",
                        "-sigopt", "rsa_pss_saltlen:32", "-out", str(signature), str(path)], check=True, capture_output=True)
        result = verify_release(path, signature, self.etc / "release-public.pem", self.root,
                                now=datetime(2026, 9, 9, tzinfo=timezone.utc), current_sequence=0)
        self.assertEqual(result["sequence"], 1)
        self.assertTrue(result["artifacts_verified"])

    def test_factory_interruption_after_key_write_resumes_only_exact_pending_identity(self):
        original = enrollment.atomic_json
        def interrupted(path, value):
            if path.name == "publisher-trust.json":
                raise OSError("fixture power loss after public-key installation")
            return original(path, value)
        with patch.object(enrollment, "atomic_json", side_effect=interrupted), self.assertRaises(OSError):
            self.manager.installed()
        self.assertTrue((self.etc / "release-public.pem").exists())
        self.assertTrue((self.manager.state / "publisher-pending.json").exists())
        self.assertFalse((self.manager.state / "publisher-trust.json").exists())
        self.assertFalse(enrollment.enrollment_status(self.manager.state)["update_ready"])
        self.assertIn("Retry first-boot", enrollment.enrollment_status(self.manager.state)["operator_action"])
        self.assertTrue(self.manager.installed()["update_ready"])

    def test_factory_interruption_after_initial_identity_is_resumable(self):
        with patch.object(self.manager, "trust_factory", side_effect=OSError("fixture restart")), self.assertRaises(OSError):
            self.manager.installed()
        self.assertTrue((self.manager.state / "initial-enrollment.json").exists())
        self.assertFalse((self.etc / "release-public.pem").exists())
        self.assertTrue(self.manager.installed()["update_ready"])

    def test_changed_factory_provenance_cannot_resume_an_existing_pending_key(self):
        original = enrollment.atomic_json
        def interrupted(path, value):
            if path.name == "publisher-trust.json":
                raise OSError("fixture interruption")
            return original(path, value)
        with patch.object(enrollment, "atomic_json", side_effect=interrupted), self.assertRaises(OSError):
            self.manager.installed()
        key = (self.etc / "release-public.pem").read_bytes()
        pending = (self.manager.state / "publisher-pending.json").read_bytes()
        self.configure(description={**self.description, "key_id": "changed-after-interruption"})
        with self.assertRaises(Refused):
            self.manager.installed()
        self.assertEqual((self.etc / "release-public.pem").read_bytes(), key)
        self.assertEqual((self.manager.state / "publisher-pending.json").read_bytes(), pending)
        self.assertFalse((self.manager.state / "publisher-trust.json").exists())

    def test_changed_factory_descriptor_never_adopts_or_replaces_enrolled_trust(self):
        self.manager.installed()
        target = self.etc / "release-public.pem"
        before = target.read_bytes(), (self.manager.state / "publisher-trust.json").read_bytes()
        self.configure(description={**self.description, "key_id": "different-fixture-key-id"})
        with self.assertRaises(Refused):
            self.manager.installed()
        with self.assertRaises(Refused):
            self.manager.trust_factory()
        self.assertEqual(before, (target.read_bytes(), (self.manager.state / "publisher-trust.json").read_bytes()))

    def test_existing_manual_trust_is_not_silently_relabelled_as_factory_trust(self):
        self.manager._installed()
        self.manager.trust(self.public, self.fingerprint, "Separately authenticated fixture operator trust")
        before = (self.manager.state / "publisher-trust.json").read_bytes()
        with self.assertRaisesRegex(Refused, "rotation"):
            self.manager.trust_factory()
        with self.assertRaisesRegex(Refused, "differs from packaged"):
            self.manager.factory_status()
        self.assertEqual(before, (self.manager.state / "publisher-trust.json").read_bytes())

    def test_changed_packaged_bytes_refuse_even_when_public_key_identity_is_unchanged(self):
        path = self.share / "publisher-public.spki"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(Refused, "differ from factory"):
            self.manager.installed()
        self.assertFalse((self.manager.state / "initial-enrollment.json").exists())

    def test_key_change_between_factory_verification_and_trust_write_refuses(self):
        self.manager._installed()
        original = self.manager.trust
        def change_then_trust(*args, **kwargs):
            path = self.share / "publisher-public.spki"
            path.write_bytes(path.read_bytes() + b"\n")
            return original(*args, **kwargs)
        with patch.object(self.manager, "trust", side_effect=change_then_trust), self.assertRaisesRegex(Refused, "source changed"):
            self.manager.trust_factory()
        self.assertFalse((self.manager.state / "publisher-pending.json").exists())

    def test_private_multiple_or_malformed_key_cannot_create_installed_or_trust_state(self):
        for raw in (self.private.read_bytes(), self.public.read_bytes() * 2,
                    b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"):
            with self.subTest(kind=raw.splitlines()[0]):
                self.configure(key=raw)
                with self.assertRaises(Refused):
                    self.manager.installed()
                self.assertFalse((self.manager.state / "initial-enrollment.json").exists())
                self.assertFalse((self.etc / "release-public.pem").exists())

    def test_wrong_descriptor_algorithm_repository_or_fingerprint_refuses(self):
        original = self.description
        for changes in ({"algorithm": "RSA-PKCS1-SHA256"}, {"repository": "other/repository"}, {"spki_sha256": "0" * 64},
                        {"key_id": "../escape"}, {"unexpected": "ignored"}, {"schema": True}):
            with self.subTest(changes=changes):
                self.configure(description={**original, **changes})
                with self.assertRaises(Refused):
                    self.manager.verify_build_inputs(require_factory=True)
                self.assertFalse((self.etc / "release-public.pem").exists())

    def test_missing_one_public_input_and_symlink_are_refused(self):
        path = self.share / "publisher-public.spki"
        path.unlink()
        with self.assertRaises(Refused):
            self.manager.verify_build_inputs(require_factory=True)
        path.symlink_to(self.public)
        with self.assertRaises(Refused):
            self.manager.verify_build_inputs(require_factory=True)

    def test_readonly_factory_acceptance_does_not_complete_missing_trust(self):
        self.manager._installed()
        with self.assertRaisesRegex(Refused, "completed"):
            self.manager.factory_status()
        self.assertFalse((self.etc / "release-public.pem").exists())
        self.manager.trust_factory()
        (self.etc / "release-public.pem").unlink()
        with self.assertRaises(Refused):
            self.manager.factory_status()
        self.assertFalse((self.etc / "release-public.pem").exists())

    def test_installed_entrypoint_runs_factory_enrollment_automatically(self):
        with patch.object(enrollment, "UpdateEnrollment", return_value=self.manager), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(enrollment.main([]), 0)
        self.assertTrue(json.loads(output.getvalue())["update_ready"])

    def test_ec_and_restricted_pss_keys_cannot_change_the_fixed_signature_algorithm(self):
        for algorithm, options in (("EC", ["-pkeyopt", "ec_paramgen_curve:P-256"]),
                                   ("RSA-PSS", ["-pkeyopt", "rsa_keygen_bits:3072", "-pkeyopt", "rsa_pss_keygen_md:sha512"])):
            with self.subTest(algorithm=algorithm):
                private = self.root / (algorithm + "-test-only-private")
                key = self.root / (algorithm + "-test-only-public")
                subprocess.run(["openssl", "genpkey", "-algorithm", algorithm, *options, "-out", str(private)], check=True, capture_output=True)
                subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(key)], check=True, capture_output=True)
                der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(key), "-pubout", "-outform", "DER"])
                self.configure(key=key.read_bytes(), description={**self.description, "spki_sha256": hashlib.sha256(der).hexdigest()})
                with self.assertRaises(Refused):
                    self.manager.installed()
                self.assertFalse((self.etc / "release-public.pem").exists())


class PrivatePublisherModeTests(unittest.TestCase):
    runner = fixtures.InstalledReleaseTests.runner
    setUp = fixtures.InstalledReleaseTests.setUp

    def test_explicit_private_candidate_never_claims_update_or_distribution_trust_readiness(self):
        self.assertFalse(self.manager.verify_build_inputs()["publisher"]["distribution_trust_ready"])
        value = self.manager.installed()
        self.assertEqual(value["build_mode"], "private-unsealed")
        self.assertFalse(value["update_ready"])
        self.assertEqual(value["publisher_trust"], "not_enrolled")
        with self.assertRaisesRegex(Refused, "cannot be sealed"):
            self.manager.verify_build_inputs(require_factory=True)

    def test_missing_mode_is_never_implicitly_factory_or_private(self):
        self.descriptor.pop("publisher")
        atomic_json(self.share / "initial-release.json", self.descriptor)
        with self.assertRaises(Refused):
            self.manager.verify_build_inputs()

    def test_private_mode_cannot_ignore_packaged_public_inputs(self):
        (self.share / "publisher-public.spki").write_bytes(b"unexpected")
        with self.assertRaisesRegex(Refused, "unexpected publisher inputs"):
            self.manager.verify_build_inputs()

    def test_seal_guard_refuses_private_candidate_after_build_identity_is_accepted(self):
        with patch.object(provision.guard, "build_identity", return_value=provision.IDENTITY), \
             patch.object(provision.guard, "BuildGuard"), \
             patch.object(enrollment, "UpdateEnrollment", return_value=self.manager), \
             patch("sys.argv", ["provision-guard", "verify-seal"]):
            with self.assertRaisesRegex(provision.guard.Refused, "factory publisher trust"):
                provision.guard.main()


@unittest.skipUnless(shutil.which("openssl"), "Real OpenSSL is required for public trust verification")
class FactoryBuildInputsTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.PublisherTrustTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.PublisherTrustTests.tearDownClass.__func__)
    setUp = stages.StagedSourceTests.setUp
    git = stages.StagedSourceTests.git
    write = stages.StagedSourceTests.write

    def supply_public(self):
        self.write(public.PUBLIC_SOURCE, self.public.read_bytes())
        self.write(public.DESCRIPTOR_SOURCE, serialized(public_descriptor(self.fingerprint)))

    def capture(self, **kwargs):
        return stages.capture(self.root, self.bundle, self.provenance, sequence=1, schema_revision="2", **kwargs)

    def test_missing_public_inputs_require_explicit_private_capture(self):
        with self.assertRaisesRegex(ValueError, "explicitly select --private-unsealed"):
            self.capture()
        self.assertFalse(self.provenance.exists())
        value = self.capture(private_unsealed=True)
        self.assertEqual(value["publisher"], {"mode": "private-unsealed"})
        self.assertEqual(stages.staging.stage(self.root, self.provenance, self.output)["status"], "verified")

    def test_public_factory_roundtrip_pins_capture_stage_and_full_archive(self):
        self.supply_public()
        value = self.capture()
        self.assertEqual(value["publisher"]["spki_sha256"], self.fingerprint)
        self.assertEqual(value["publisher"]["public_spki_pem_sha256"], public.digest(self.public.read_bytes()))
        staged = stages.staging.stage(self.root, self.provenance, self.output)
        self.assertEqual(staged["status"], "verified")
        self.assertEqual((self.output / public.PUBLIC_SOURCE).read_bytes(), self.public.read_bytes())
        archived = self.base / "factory-source.tar"
        self.assertEqual(archives.archiver.archive_sources(self.root, self.provenance, archived)["status"], "verified")
        self.assertEqual(archives.archiver.verify(archived, self.provenance)["status"], "verified")

    def test_partial_factory_inputs_and_private_override_are_refused(self):
        self.write(public.PUBLIC_SOURCE, self.public.read_bytes())
        with self.assertRaises(ValueError):
            self.capture()
        with self.assertRaisesRegex(Refused, "cannot ignore"):
            self.capture(private_unsealed=True)
        self.assertFalse(self.provenance.exists())

    def test_private_or_wrong_fingerprint_input_cannot_be_captured(self):
        self.supply_public()
        self.write(public.PUBLIC_SOURCE, self.private.read_bytes())
        with self.assertRaisesRegex(Refused, "Only one public"):
            self.capture()
        self.write(public.PUBLIC_SOURCE, self.public.read_bytes())
        self.write(public.DESCRIPTOR_SOURCE, serialized(public_descriptor("0" * 64)))
        with self.assertRaisesRegex(Refused, "SPKI fingerprint"):
            self.capture()
        self.assertFalse(self.provenance.exists())
