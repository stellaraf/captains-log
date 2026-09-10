"""Real bounded archive/filesystem tests; Linux-root guards use isolated fixtures.

No host activation, network request, service command or publisher key is involved.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager import host_payload as payload
from nebulalog_manager.common import Refused, locked

SCRIPT = Path(__file__).resolve().parents[1] / "packer/build_host_bundle.py"
SPEC = importlib.util.spec_from_file_location("build_host_bundle", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def fixture_source(root):
    source = root / "source"
    source.mkdir()
    files = {}
    for entry in payload.CATALOG:
        path = source / entry["source"]
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = ("# Inert fixture: " + entry["source"] + "\n").encode()
        path.write_bytes(raw)
        files[entry["source"]] = payload.digest(raw)
    manifest = root / "source-manifest.json"
    manifest.write_bytes(payload.encoded({"schema": 1, "files": files}))
    return source, manifest


def tar_members(path):
    with tarfile.open(path, "r:") as archive:
        return [(copy.copy(item), archive.extractfile(item).read()) for item in archive]


def write_tar(path, members):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for member, raw in members:
            archive.addfile(member, io.BytesIO(raw) if raw is not None else None)


def fixture_tree(root):
    def validate(path):
        # The production ancestry check is exercised separately. The filesystem
        # fixture owns only its temporary subtree, never the system root directory.
        if not path.is_relative_to(root):
            raise AssertionError("Fixture escaped its temporary root")
        for current in (path, *path.parents):
            if not current.is_relative_to(root):
                break
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise Refused("Fixture ancestry is not protected")
    return validate


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.root = Path(temporary.name).resolve()
        self.addCleanup(temporary.cleanup)
        self.source, self.manifest = fixture_source(self.root)
        self.archive = self.root / "host.tar"
        self.evidence = builder.build(self.source, self.manifest, self.archive, version="0.1.1")
        self.members = tar_members(self.archive)

    def verify(self):
        return payload.verify_archive(self.archive, expected_sha256=payload.digest(self.archive.read_bytes()))

    def replace_metadata(self, mutate):
        metadata = json.loads(self.members[0][1])
        mutate(metadata)
        raw = payload.encoded(metadata)
        self.members[0] = (payload.tar_header("host-payload.json", len(raw), 0o644), raw)
        write_tar(self.archive, self.members)

    def test_complete_archive_hash_catalog_and_source_binding_are_verified_without_execution(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no subprocess allowed")), patch("socket.create_connection", side_effect=AssertionError("no network allowed")):
            result = self.verify()
        self.assertTrue(result["archive_verified"])
        self.assertFalse(result["signature_verified"])
        self.assertFalse(result["runtime_executed"])
        self.assertFalse(result["activated"])
        self.assertEqual(result["metadata"]["files"], self.evidence["metadata"]["files"])
        self.assertEqual(result["metadata"]["source_snapshot_sha256"], payload.digest(self.manifest.read_bytes()))

    def test_wrong_outer_hash_and_selected_source_identity_refused(self):
        with self.assertRaisesRegex(Refused, "archive SHA256"):
            payload.verify_archive(self.archive, expected_sha256="a" * 64)
        with self.assertRaisesRegex(Refused, "source differs"):
            payload.verify_archive(self.archive, expected_sha256=payload.digest(self.archive.read_bytes()), expected_host_source_sha256="a" * 64)

    def test_inner_hash_tamper_fails_even_with_matching_outer_hash(self):
        member, raw = self.members[1]
        self.members[1] = (member, b"x" + raw[1:])
        write_tar(self.archive, self.members)
        with self.assertRaisesRegex(Refused, "file hash"):
            self.verify()

    def test_private_key_material_refused_with_self_consistent_file_hashes(self):
        raw = b"-----BEGIN PRIVATE KEY-----\nfixture only\n-----END PRIVATE KEY-----\n"
        member = self.members[1][0]
        member.size = len(raw)
        self.members[1] = member, raw
        def update(value):
            value["files"][0].update(bytes=len(raw), sha256=payload.digest(raw))
            value["host_source_sha256"] = payload.host_source_hash({item["source"]: item["sha256"] for item in value["files"]})
        self.replace_metadata(update)
        with self.assertRaisesRegex(Refused, "Private key"):
            self.verify()

    def test_unknown_metadata_abi_platform_version_or_catalog_refused(self):
        original = copy.deepcopy(self.members)
        for values in ({"abi": 2}, {"abi": True}, {"schema": True}, {"product": "other"}, {"component": "other"},
                       {"platform": {**payload.PLATFORM, "architecture": "aarch64"}},
                       {"platform": {**payload.PLATFORM, "major": 9.0}}, {"version": None}, {"execute": "arbitrary"},
                       {"catalog_sha256": "a" * 64}, {"host_source_sha256": "a" * 64}):
            with self.subTest(values=values):
                self.members = copy.deepcopy(original)
                self.replace_metadata(lambda value: value.update(values))
                with self.assertRaises(Refused):
                    self.verify()

    def test_missing_duplicate_or_altered_inventory_refused(self):
        original = copy.deepcopy(self.members)
        mutations = (lambda value: value["files"].pop(), lambda value: value["files"].append(value["files"][0]),
                     lambda value: value["files"][0].update(path="../../outside"),
                     lambda value: value["files"][0].update(source="appliance/security/publisher-public.spki"),
                     lambda value: value["files"][0].update(mode=0o4755), lambda value: value["files"][0].update(bytes=True))
        for mutate in mutations:
            self.members = copy.deepcopy(original)
            self.replace_metadata(mutate)
            with self.assertRaises(Refused):
                self.verify()

    def test_duplicate_json_keys_and_noncanonical_encoding_refused(self):
        for raw in (b'{"schema":1,"schema":1}', json.dumps(json.loads(self.members[0][1]), indent=2).encode()):
            members = copy.deepcopy(self.members)
            members[0] = (payload.tar_header("host-payload.json", len(raw), 0o644), raw)
            write_tar(self.archive, members)
            with self.assertRaises(Refused):
                self.verify()

    def test_links_devices_sparse_and_extension_headers_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE,
                     tarfile.GNUTYPE_SPARSE, tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
            members = copy.deepcopy(self.members)
            member = members[1][0]
            member.type, member.size = kind, 0
            member.linkname = "/etc/shadow" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            members[1] = member, None
            write_tar(self.archive, members)
            with self.subTest(kind=kind), self.assertRaises(Refused):
                self.verify()

    def test_traversal_absolute_duplicate_missing_extra_or_reordered_members_refused(self):
        for name in ("../outside", "/etc/shadow", "payload/../outside", "payload//bin/nebulalog", ".env", "private.key"):
            members = copy.deepcopy(self.members)
            members[1][0].name = name
            write_tar(self.archive, members)
            with self.subTest(name=name), self.assertRaises(Refused):
                self.verify()
        for members in (self.members[:-1], self.members + [self.members[-1]],
                        [self.members[1], self.members[0], *self.members[2:]]):
            write_tar(self.archive, members)
            with self.assertRaises(Refused):
                self.verify()

    def test_noncanonical_owner_mode_time_and_padding_refused(self):
        for key, value in (("uid", 1000), ("gid", 1000), ("mode", 0o666), ("mode", 0o4755), ("mtime", 1), ("uname", "root")):
            members = copy.deepcopy(self.members)
            setattr(members[1][0], key, value)
            write_tar(self.archive, members)
            with self.subTest(key=key, value=value), self.assertRaises(Refused):
                self.verify()
        write_tar(self.archive, self.members)
        raw = bytearray(self.archive.read_bytes())
        position = 512 + len(self.members[0][1])
        self.assertNotEqual(position % 512, 0)
        raw[position] = 1
        self.archive.write_bytes(raw)
        with self.assertRaisesRegex(Refused, "padding"):
            self.verify()

    def test_truncation_trailing_payload_or_excess_padding_refused(self):
        original = self.archive.read_bytes()
        for raw in (original[:511], original[:1024], original[:-512], original[:-1], original + b"x" * 10240, original + b"\0" * 10240):
            self.archive.write_bytes(raw)
            with self.assertRaises(Refused):
                self.verify()

    def test_limits_reject_before_oversized_allocation(self):
        for setting in ("MAX_ARCHIVE", "MAX_FILE", "MAX_METADATA", "MAX_TOTAL"):
            with self.subTest(setting=setting), patch.object(payload, setting, 1), self.assertRaises(Refused):
                self.verify()

    def test_archive_symlink_hardlink_fifo_and_unsafe_mode_refused(self):
        linked = self.root / "alias"
        linked.symlink_to(self.archive)
        with self.assertRaises(Refused):
            payload.verify_archive(linked, expected_sha256=self.evidence["archive_sha256"])
        linked.unlink(); os.link(self.archive, linked)
        with self.assertRaises(Refused):
            self.verify()
        linked.unlink(); self.archive.chmod(0o666)
        with self.assertRaises(Refused):
            self.verify()
        linked = self.root / "fifo"
        os.mkfifo(linked)
        with self.assertRaises(Refused):
            payload.verify_archive(linked, expected_sha256=self.evidence["archive_sha256"])


class GenerationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.root = Path(temporary.name).resolve()
        def cleanup():
            for current in (self.root, *self.root.rglob("*")):
                if current.is_dir() and not current.is_symlink():
                    current.chmod(0o700)
            temporary.cleanup()
        self.addCleanup(cleanup)
        self.source, self.manifest = fixture_source(self.root)
        self.archive = self.root / "host.tar"
        self.evidence = builder.build(self.source, self.manifest, self.archive, version="0.1.1")
        self.generations = self.root / "generations"
        self.real_tree = payload._trusted_tree
        for mocker in (patch.object(payload, "require_linux_root"), patch.object(payload, "GENERATIONS", self.generations),
                       patch.object(payload, "_OWNER_UID", os.getuid()), patch.object(payload, "_trusted_tree", side_effect=fixture_tree(self.root))):
            mocker.start(); self.addCleanup(mocker.stop)

    def stage(self):
        return payload.stage_generation(self.archive, expected_sha256=self.evidence["archive_sha256"],
                                        expected_host_source_sha256=self.evidence["metadata"]["host_source_sha256"])

    def test_stages_complete_immutable_generation_atomically_and_idempotently(self):
        with patch("subprocess.Popen", side_effect=AssertionError("staging cannot execute code")), patch("socket.create_connection", side_effect=AssertionError("staging cannot use network")):
            result = self.stage()
        generation = Path(result["generation"])
        self.assertEqual(generation.name, self.evidence["archive_sha256"])
        self.assertEqual(stat.S_IMODE(generation.stat().st_mode), 0o555)
        self.assertFalse(result["activated"])
        self.assertFalse(result["runtime_executed"])
        self.assertFalse(result["signature_verified"])
        self.assertFalse(result["already_staged"])
        for entry in payload.CATALOG:
            path = generation / entry["path"]
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), entry["mode"] & ~0o222)
            self.assertEqual(path.read_bytes(), (self.source / entry["source"]).read_bytes())
        before = {str(path.relative_to(generation)): path.stat().st_ino for path in generation.rglob("*")}
        self.assertTrue(self.stage()["already_staged"])
        self.assertEqual(before, {str(path.relative_to(generation)): path.stat().st_ino for path in generation.rglob("*")})
        self.assertFalse(list(self.generations.glob(".pending-host-*")))

    def test_existing_changed_generation_is_never_replaced_or_deleted(self):
        generation = Path(self.stage()["generation"])
        target = generation / payload.CATALOG[0]["path"]
        target.chmod(0o600); target.write_text("operator changed fixture"); target.chmod(payload.CATALOG[0]["mode"] & ~0o222)
        before = target.stat().st_ino
        with self.assertRaisesRegex(Refused, "content changed"):
            self.stage()
        self.assertEqual(target.stat().st_ino, before)
        self.assertEqual(target.read_text(), "operator changed fixture")

    def test_changed_metadata_or_receipt_bytes_are_not_adopted_even_if_json_matches(self):
        generation = Path(self.stage()["generation"])
        for name in ("host-payload.json", "staging-receipt.json"):
            path = generation / name
            raw = path.read_bytes()
            path.chmod(0o600); path.write_bytes(raw + b" "); path.chmod(0o444)
            with self.subTest(name=name), self.assertRaises(Refused):
                self.stage()
            path.chmod(0o600); path.write_bytes(raw); path.chmod(0o444)

    def test_existing_empty_directory_or_symlink_is_not_adopted(self):
        self.generations.mkdir()
        destination = self.generations / self.evidence["archive_sha256"]
        destination.mkdir()
        with self.assertRaises((Refused, OSError)):
            self.stage()
        self.assertEqual(list(destination.iterdir()), [])
        destination.rmdir(); destination.symlink_to(self.root / "source")
        with self.assertRaises(Refused):
            self.stage()
        self.assertTrue(destination.is_symlink())

    def test_existing_generation_extra_file_link_and_mode_damage_refused(self):
        generation = Path(self.stage()["generation"])
        generation.chmod(0o755)
        extra = generation / "unexpected"
        extra.write_text("extra")
        generation.chmod(0o555)
        with self.assertRaises(Refused):
            self.stage()
        generation.chmod(0o755); extra.unlink(); extra.symlink_to(self.manifest); generation.chmod(0o555)
        with self.assertRaises(Refused):
            self.stage()
        generation.chmod(0o755); extra.unlink(); generation.chmod(0o555)
        target = generation / payload.CATALOG[0]["path"]
        target.chmod(0o644)
        with self.assertRaisesRegex(Refused, "mode changed"):
            self.stage()

    def test_failed_verification_or_disk_reserve_creates_no_generation(self):
        with patch.object(payload.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1, 1, 0)), self.assertRaisesRegex(Refused, "space"):
            self.stage()
        self.assertFalse(list(self.generations.glob(".pending-host-*")))
        self.archive.write_bytes(b"changed")
        with self.assertRaises(Refused):
            self.stage()
        self.assertFalse((self.generations / self.evidence["archive_sha256"]).exists())

    def test_archive_change_between_verification_and_extraction_is_refused_and_cleaned(self):
        original = payload.verify_archive
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.archive.write_bytes(b"changed after verification")
            return result
        with patch.object(payload, "verify_archive", side_effect=changed), self.assertRaises(Refused):
            self.stage()
        self.assertFalse(list(self.generations.glob(".pending-host-*")))
        self.assertFalse((self.generations / self.evidence["archive_sha256"]).exists())

    def test_concurrent_existing_directory_is_preserved_by_native_no_replace(self):
        original = payload._rename_noreplace
        def competitor(source, destination):
            destination.mkdir()
            return original(source, destination)
        with patch.object(payload, "_rename_noreplace", side_effect=competitor), self.assertRaisesRegex(Refused, "existing target"):
            self.stage()
        destination = self.generations / self.evidence["archive_sha256"]
        self.assertTrue(destination.is_dir())
        self.assertEqual(list(destination.iterdir()), [])
        self.assertFalse(list(self.generations.glob(".pending-host-*")))

    def test_publication_failure_cleans_only_its_fresh_stage(self):
        sentinel = self.root / "customer-config"
        sentinel.write_text("untouched")
        with patch.object(payload, "_rename_noreplace", side_effect=Refused("publication failure")), self.assertRaises(Refused):
            self.stage()
        self.assertEqual(sentinel.read_text(), "untouched")
        self.assertTrue(self.archive.exists())
        self.assertFalse(list(self.generations.glob(".pending-host-*")))

    def test_parallel_staging_is_locked_before_extraction(self):
        self.generations.mkdir()
        with locked(self.generations / ".stage.lock"), self.assertRaises(Refused):
            self.stage()
        self.assertFalse(list(self.generations.glob(".pending-host-*")))

    def test_production_ancestry_checks_refuse_writable_or_symlinked_storage(self):
        directory = self.root / "unsafe"
        directory.mkdir(mode=0o777); directory.chmod(0o777)
        with self.assertRaises(Refused):
            self.real_tree(directory)
        alias = self.root / "linked"
        alias.symlink_to(self.source)
        with self.assertRaises(Refused):
            self.real_tree(alias)


class PrivilegeTests(unittest.TestCase):
    def test_production_stage_has_no_nonroot_or_nonlinux_bypass(self):
        for system, uid in (("Darwin", 0), ("Linux", 501)):
            with self.subTest(system=system, uid=uid), patch("nebulalog_manager.common.platform.system", return_value=system), patch("nebulalog_manager.common.os.geteuid", return_value=uid), patch.object(payload, "verify_archive") as verify:
                with self.assertRaisesRegex(Refused, "requires root inside the Rocky"):
                    payload.stage_generation(Path("/nonexistent"), expected_sha256="a" * 64, expected_host_source_sha256="b" * 64)
                verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
