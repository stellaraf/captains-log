"""Real bounded CMS roundtrips and hostile recovery-set admission, no database/VM."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import log_recovery_set as transport
from nebulalog_manager.common import Refused, run


class LogRecoverySetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        openssl = shutil.which("openssl")
        if not openssl or not subprocess.check_output([openssl, "version"], text=True).startswith("OpenSSL 3."):
            raise unittest.SkipTest("Real authenticated CMS tests require OpenSSL 3")
        cls.keys = tempfile.TemporaryDirectory()
        cls.keyroot = Path(cls.keys.name)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Synthetic Log Recovery",
             "-keyout", str(cls.keyroot / "key.pem"), "-out", str(cls.keyroot / "cert.pem")])

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.staging, self.native, self.export = self.root / "scratch", self.root / "native", self.root / "export"
        for path in (self.staging, self.native):
            path.mkdir(mode=0o700)
        self.archive = self.native / "events.tar"
        self.payload = bytes(range(256)) * 35
        self.archive.write_bytes(self.payload)
        self.archive.chmod(0o600)
        self.cert, self.key = self.root / "cert.pem", self.root / "key.pem"
        shutil.copyfile(self.keyroot / "cert.pem", self.cert)
        shutil.copyfile(self.keyroot / "key.pem", self.key)
        self.cert.chmod(0o644)  # Public recipient certificates need not be secret.
        self.key.chmod(0o600)
        self.output = self.staging / "restored.tar"
        self.calls = []
        self.manager = transport.LogRecoverySet(self.command)
        self.metadata = {"link": {
            "source_installation_id": "a2eaf0a7-99dd-45a8-ae60-841127afc90c",
            "configuration_backup": {"sha256": "c" * 64, "bytes": 12345},
            "runtime": {"schema_revision": "3", "images": {name: "registry.example/image@sha256:" + "a" * 64 for name in transport.IMAGE_KEYS}}},
            "native": {"table": "nebulalog.events", "server_version": "25.3.8.30001.altinityfips",
                "table_uuid": "fbece678-cf26-46e5-b380-0b20bfa143dd", "backup_id": "d590273c-f410-4722-8b54-f997a58aed45",
                "query_id": "abc296fa-f921-47b3-8d15-92669a23e839", "started_at": "2026-10-19T20:00:00Z",
                "finished_at": "2026-10-19T20:00:10Z", "table_definition_sha256": "e" * 64, "retention_policy_revision": 4},
            "archive": {"format": "clickhouse-native-tar", "sha256": hashlib.sha256(self.payload).hexdigest(), "bytes": len(self.payload)}}
        # Substitute only host/mount ownership for private temporary fixtures. The
        # CMS engine, parser, hashes, permissions, links, inventory and writes run.
        for item in (patch.object(transport, "ROOT_UID", os.getuid()), patch.object(transport, "require_linux_root"),
                     patch.object(transport, "_directory", side_effect=self.directory),
                     patch.object(transport, "_encrypted_staging", side_effect=lambda path, *_: self.directory(path, private=True)),
                     patch.object(transport, "trusted_file", side_effect=self.trusted),
                     patch.object(transport, "CHUNK_BYTES", 4096), patch.object(transport, "MAX_CHUNKS", 8),
                     patch.object(transport, "MANIFEST_BYTES", 1024**2),
                     patch.object(transport.shutil, "disk_usage", return_value=Mock(free=1024**4))):
            item.start()
            self.addCleanup(item.stop)

    def directory(self, path, *, private=False):
        if not path.is_relative_to(self.root) or ".." in path.parts:
            raise Refused("Outside fixture")
        for item in (path, *path.parents):
            if item == self.root.parent:
                break
            if item.is_symlink() or not item.is_dir() or item.stat().st_mode & 0o022:
                raise Refused("Unsafe fixture directory")
        if private and path.stat().st_mode & 0o077:
            raise Refused("Not private")

    def trusted(self, path):
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o022:
            raise Refused("Untrusted fixture file")
        return path

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        return run(argv, **kwargs)

    def seal(self):
        return self.manager.seal(self.archive, self.export, self.cert, self.staging, self.metadata)

    def unseal(self, link=None):
        return self.manager.unseal(self.export, self.output, self.cert, self.key, self.staging, link or self.metadata["link"])

    def manifest(self):
        plain = self.root / "inspect.json"
        run(["openssl", "cms", "-decrypt", "-binary", "-inform", "DER", "-in", str(self.export / "manifest.cms"),
             "-recip", str(self.cert), "-inkey", str(self.key), "-out", str(plain)])
        return json.loads(plain.read_bytes())

    def replace_manifest(self, value, *, algorithm="aes-256-gcm"):
        plain = self.root / "rewrite.json"
        plain.write_text(json.dumps(value))
        target = self.export / "manifest.cms"
        target.unlink()
        run(["openssl", "cms", "-encrypt", "-binary", "-" + algorithm, "-outform", "DER",
             "-in", str(plain), "-out", str(target), str(self.cert)])
        target.chmod(0o600)

    def test_real_multichunk_roundtrip_preserves_source_and_permissions(self):
        before = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        result = self.seal()
        self.assertTrue(result["complete"])
        self.assertEqual(result["chunks"], 3)
        self.assertFalse(result["native_qualified"])
        manifest = self.manifest()
        self.assertEqual([item["bytes"] for item in manifest["chunks"]], [4096, 4096, 768])
        restored = self.unseal()
        self.assertFalse(restored["native_restored"])
        self.assertEqual(restored["metadata"], self.metadata)
        self.assertEqual(self.output.read_bytes(), self.payload)
        self.assertEqual(hashlib.sha256(self.archive.read_bytes()).hexdigest(), before)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertEqual({path.name for path in self.staging.iterdir()}, {"restored.tar"})
        self.assertTrue(all("-stream" not in args and "-indef" not in args for args in self.calls))
        for encrypted in [self.export / "manifest.cms", *sorted((self.export / "chunks").glob("*.cms"))]:
            envelope = run(["openssl", "cms", "-cmsout", "-print", "-inform", "DER", "-in", str(encrypted)])
            self.assertIn("rsaesOaep", envelope)
            self.assertIn("mgf1", envelope)
            self.assertEqual(envelope.count("OBJECT            :sha256"), 2)
            self.assertIn("aes-256-gcm", envelope)
            self.assertNotIn("rsaEncryption", envelope)

    def test_sealed_receipt_is_retained_before_publication_and_readback_needs_no_key(self):
        receipts = []
        def checkpoint(receipt):
            self.assertFalse((self.export / "manifest.cms").exists())
            self.assertTrue((self.export / ".manifest.pending").exists())
            receipts.append(copy.deepcopy(receipt))
        expected = self.manager.seal(self.archive, self.export, self.cert, self.staging,
                                     self.metadata, checkpoint=checkpoint)
        self.assertEqual(len(receipts), 1)
        self.key.unlink()
        self.calls.clear()
        actual = self.manager.inspect_sealed(self.export, receipts[0], self.metadata)
        self.assertEqual(actual, expected)
        self.assertEqual(self.calls, [])

    def test_sealed_readback_refuses_ciphertext_mutation_missing_and_extra_files(self):
        receipts = []
        self.manager.seal(self.archive, self.export, self.cert, self.staging,
                          self.metadata, checkpoint=receipts.append)
        chunk = self.export / "chunks/000000.cms"
        original = chunk.read_bytes()
        chunk.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaises(Refused):
            self.manager.inspect_sealed(self.export, receipts[0], self.metadata)
        chunk.write_bytes(original)
        chunk.unlink()
        with self.assertRaises(Refused):
            self.manager.inspect_sealed(self.export, receipts[0], self.metadata)
        chunk.write_bytes(original)
        chunk.chmod(0o600)
        (self.export / ".manifest.pending").write_bytes(b"interrupted")
        with self.assertRaises(Refused):
            self.manager.inspect_sealed(self.export, receipts[0], self.metadata)

    def test_sealed_readback_refuses_wrong_snapshot_or_chunk_order(self):
        receipts = []
        self.manager.seal(self.archive, self.export, self.cert, self.staging,
                          self.metadata, checkpoint=receipts.append)
        wrong = copy.deepcopy(self.metadata)
        wrong["archive"]["sha256"] = "a" * 64
        with self.assertRaises(Refused):
            self.manager.inspect_sealed(self.export, receipts[0], wrong)
        receipts[0]["chunks"].reverse()
        with self.assertRaises(Refused):
            self.manager.inspect_sealed(self.export, receipts[0], self.metadata)

    def test_seal_checkpoint_failure_preserves_partial_output_without_publication(self):
        def fail(receipt):
            raise OSError("Synthetic durable journal failure")
        with self.assertRaises(OSError):
            self.manager.seal(self.archive, self.export, self.cert, self.staging,
                              self.metadata, checkpoint=fail)
        self.assertFalse((self.export / "manifest.cms").exists())
        self.assertTrue((self.export / ".manifest.pending").exists())
        self.assertEqual(self.archive.read_bytes(), self.payload)

    def test_readback_reestablishes_lost_final_barrier_and_refuses_failed_barrier(self):
        receipts = []
        original = transport._fsync
        def fail_final(path):
            if path == self.export.parent:
                raise OSError("Synthetic lost final directory barrier")
            return original(path)
        with patch.object(transport, "_fsync", side_effect=fail_final):
            with self.assertRaises(OSError):
                self.manager.seal(self.archive, self.export, self.cert, self.staging,
                                  self.metadata, checkpoint=receipts.append)
        self.assertTrue((self.export / "manifest.cms").is_file())
        self.assertFalse((self.export / ".manifest.pending").exists())
        with patch.object(transport, "_fsync", side_effect=fail_final):
            with self.assertRaises(OSError):
                self.manager.inspect_sealed(self.export, receipts[0], self.metadata)
        with patch.object(transport, "_fsync", wraps=original) as barriers:
            self.assertTrue(self.manager.inspect_sealed(self.export, receipts[0], self.metadata)["complete"])
            self.assertEqual([call.args[0] for call in barriers.call_args_list][-3:],
                             [self.export / "chunks", self.export, self.export.parent])

    def test_wrong_link_refuses_before_any_log_chunk_decryption(self):
        self.seal()
        link = copy.deepcopy(self.metadata["link"])
        link["configuration_backup"]["sha256"] = "b" * 64
        self.calls.clear()
        with self.assertRaisesRegex(Refused, "different configuration"):
            self.unseal(link)
        self.assertFalse(self.output.exists())
        self.assertEqual(sum("-decrypt" in args for args in self.calls), 1)

    def test_missing_or_additional_chunk_rejected_before_payload(self):
        self.seal()
        chunk = self.export / "chunks/000002.cms"
        saved = chunk.read_bytes()
        chunk.unlink()
        with self.assertRaises(Refused):
            self.unseal()
        chunk.write_bytes(saved)
        chunk.chmod(0o600)
        (self.export / "chunks/extra").write_bytes(b"unlisted")
        with self.assertRaises(Refused):
            self.unseal()
        self.assertFalse(self.output.exists())

    def test_reordered_chunks_fail_hash_admission(self):
        self.seal()
        first, second = self.export / "chunks/000000.cms", self.export / "chunks/000001.cms"
        a, b = first.read_bytes(), second.read_bytes()
        first.write_bytes(b)
        second.write_bytes(a)
        with self.assertRaisesRegex(Refused, "differs from its manifest"):
            self.unseal()
        self.assertFalse(self.output.exists())

    def test_valid_manifest_cannot_hide_bad_gcm_tag_and_partial_plaintext(self):
        self.seal()
        manifest = self.manifest()
        path = self.export / "chunks/000001.cms"
        changed = bytearray(path.read_bytes())
        changed[-1] ^= 1
        path.write_bytes(changed)
        manifest["chunks"][1]["encrypted_sha256"] = hashlib.sha256(changed).hexdigest()
        self.replace_manifest(manifest)
        with self.assertRaises(Refused):
            self.unseal()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_reencrypted_identical_plaintext_after_preflight_is_refused(self):
        self.seal()
        original = self.manager._decrypt
        replaced = False
        def replacing(encrypted, plain, certificate, key, maximum, **kwargs):
            nonlocal replaced
            if encrypted.name == "000000.cms" and not replaced:
                replaced = True
                payload = self.root / "same-plaintext"
                payload.write_bytes(self.payload[:4096])
                self.manager._encrypt(payload, encrypted, self.cert)
            return original(encrypted, plain, certificate, key, maximum, **kwargs)
        with patch.object(self.manager, "_decrypt", side_effect=replacing):
            with self.assertRaisesRegex(Refused, "Pinned log ciphertext"):
                self.unseal()
        self.assertTrue(replaced)
        self.assertFalse(self.output.exists())

    def test_manifest_cbc_is_refused(self):
        self.seal()
        self.replace_manifest(self.manifest(), algorithm="aes-256-cbc")
        with self.assertRaisesRegex(Refused, "envelope|AES-256-GCM"):
            self.unseal()
        self.assertFalse(self.output.exists())

    def test_forged_plain_hash_and_whole_archive_hash_refused(self):
        self.seal()
        manifest = self.manifest()
        for mutate in (lambda m: m["chunks"][0].update(sha256="f" * 64),
                       lambda m: m["metadata"]["archive"].update(sha256="f" * 64)):
            changed = copy.deepcopy(manifest)
            mutate(changed)
            self.replace_manifest(changed)
            with self.assertRaises(Refused):
                self.unseal()
            self.assertFalse(self.output.exists())

    def test_symlink_hardlink_and_public_key_file_refusals(self):
        self.seal()
        chunk = self.export / "chunks/000000.cms"
        original = chunk.read_bytes()
        external = self.root / "external.cms"
        external.write_bytes(original)
        external.chmod(0o600)
        chunk.unlink()
        chunk.symlink_to(external)
        with self.assertRaises(Refused):
            self.unseal()
        chunk.unlink()
        os.link(external, chunk)
        with self.assertRaises(Refused):
            self.unseal()
        chunk.unlink()
        chunk.write_bytes(original)
        chunk.chmod(0o600)
        self.key.chmod(0o644)
        with self.assertRaisesRegex(Refused, "keys must be private"):
            self.unseal()
        self.assertFalse(self.output.exists())

    def test_export_failure_retains_ciphertext_without_completion_manifest(self):
        real = self.manager._encrypt
        def fail_second(plain, target, certificate):
            if target.name == "000001.cms":
                raise Refused("Synthetic encryption failure")
            return real(plain, target, certificate)
        with patch.object(self.manager, "_encrypt", side_effect=fail_second):
            with self.assertRaises(Refused):
                self.seal()
        self.assertTrue((self.export / "chunks/000000.cms").is_file())
        self.assertFalse((self.export / "manifest.cms").exists())
        self.assertEqual(list(self.staging.iterdir()), [])
        with self.assertRaises(Refused):
            self.seal()
        with self.assertRaises(Refused):
            self.unseal()

    def test_changed_source_never_publishes_manifest(self):
        self.metadata["archive"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(Refused, "terminal evidence"):
            self.seal()
        self.assertFalse((self.export / "manifest.cms").exists())
        self.assertEqual(self.archive.read_bytes(), self.payload)

    def test_output_collision_preserved(self):
        self.seal()
        self.output.write_bytes(b"existing recovery evidence")
        with self.assertRaises(Refused):
            self.unseal()
        self.assertEqual(self.output.read_bytes(), b"existing recovery evidence")

    def test_capacity_refuses_before_export_directory(self):
        with patch.object(transport.shutil, "disk_usage", return_value=Mock(free=0)):
            with self.assertRaisesRegex(Refused, "Insufficient space"):
                self.seal()
        self.assertFalse(self.export.exists())

    def test_metadata_rejects_mutable_image_bools_unknown_fields_and_future_schema(self):
        mutations = (
            lambda m: m["link"]["runtime"]["images"].update(NEBULALOG_IMAGE="app:latest"),
            lambda m: m["archive"].update(bytes=True),
            lambda m: m["native"].update(table="other.events"),
            lambda m: m["native"].update(retention_policy_revision=True),
            lambda m: m["native"].update(started_at="tomorrow"),
            lambda m: m["native"].update(finished_at="2026-10-19T19:00:00Z"),
            lambda m: m["link"].update(override=True),
            lambda m: m.update(schema=9),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(self.metadata)
                mutate(changed)
                with self.assertRaises(Refused):
                    transport.validate_metadata(changed)

    def test_chunk_indices_and_size_cannot_be_forged(self):
        self.seal()
        manifest = self.manifest()
        for change in ({"index": True}, {"index": 1}, {"bytes": 4097}, {"path": "../escape"}):
            changed = copy.deepcopy(manifest)
            changed["chunks"][0].update(change)
            self.replace_manifest(changed)
            with self.assertRaises(Refused):
                self.unseal()
            self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
