import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager.common import CommandFailed, Refused
from nebulalog_manager.image_bundle import (ImageBundleLoader, NAMES, file_sha256,
                                           run_private, verify_bundle, verify_oci_archive)

BUILDER_PATH = Path(__file__).resolve().parents[1] / "packer/bundle_images.py"
SPEC = importlib.util.spec_from_file_location("bundle_images", BUILDER_PATH)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def archive_members(architecture="amd64", label="fixture", application_source_sha256=None):
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        body = label.encode()
        item = tarfile.TarInfo("image-content")
        item.size, item.mode = len(body), 0o644
        tar.addfile(item, io.BytesIO(body))
    layer = layer.getvalue()
    config = {"architecture": architecture, "os": "linux", "rootfs": {"type": "layers", "diff_ids": [digest(layer)]}}
    if application_source_sha256 is not None:
        config["config"] = {"Labels": {"io.nebulalog.application-source-sha256": application_source_sha256}}
    config = encoded(config)
    manifest = encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(config), "size": len(config)},
                        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest(layer), "size": len(layer)}]})
    index = encoded({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest(manifest), "size": len(manifest)}]})
    members = {"index.json": index, "oci-layout": encoded({"imageLayoutVersion": "1.0.0"})}
    for blob in (layer, config, manifest):
        members["blobs/sha256/" + digest(blob).split(":")[1]] = blob
    return members, "registry.example/nebulalog/fixture@" + digest(manifest), digest(config)


def write_archive(path, members, extras=()):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in members.items():
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(content), 0o644
            archive.addfile(item, io.BytesIO(content))
        for item, content in extras:
            archive.addfile(item, io.BytesIO(content) if content is not None else None)
    path.chmod(0o600)


def fixture_bundle(path, application_source_sha256=None):
    path.mkdir()
    pins, manifest, evidence = {}, {"schema": 1, "images": {}}, {}
    for name in sorted(NAMES):
        members, reference, config_digest = archive_members(label=name, application_source_sha256=application_source_sha256 if name == "NEBULALOG_IMAGE" else None)
        archive = builder.ARCHIVES[name]
        write_archive(path / archive, members)
        pins[name] = reference
        manifest["images"][name] = {"archive": archive, "sha256": file_sha256(path / archive), "reference": reference}
        evidence[reference] = {"Digest": reference.split("@", 1)[1], "Architecture": "amd64", "Os": "linux", "Id": config_digest}
    (path / "manifest.json").write_bytes(encoded(manifest))
    (path / "images.json").write_bytes(encoded(pins))
    return pins, manifest, evidence


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "test.oci.tar"
        self.members, self.reference, self.config = archive_members()
        write_archive(self.path, self.members)

    def test_valid_manifest_config_layers_and_archive_hash(self):
        evidence = verify_oci_archive(self.path, self.reference, expected_sha256=file_sha256(self.path))
        self.assertEqual(evidence["config_digest"], self.config)
        self.assertEqual(evidence["verified_blobs"], 3)
        self.assertEqual(evidence["architecture"], "amd64")

    def test_application_source_label_is_read_only_from_verified_config(self):
        members, reference, _ = archive_members(application_source_sha256="a" * 64)
        write_archive(self.path, members)
        self.assertEqual(verify_oci_archive(self.path, reference)["application_source_sha256"], "a" * 64)
        for invalid in ("not-a-sha256", 123, "A" * 64):
            members, reference, _ = archive_members(application_source_sha256=invalid)
            write_archive(self.path, members)
            with self.assertRaisesRegex(Refused, "source label"):
                verify_oci_archive(self.path, reference)

    def test_archive_tamper_fails_before_oci_parse(self):
        expected = file_sha256(self.path)
        with self.path.open("r+b") as stream:
            stream.seek(1024)
            stream.write(b"tampered")
        with self.assertRaisesRegex(Refused, "archive SHA256"):
            verify_oci_archive(self.path, self.reference, expected_sha256=expected)

    def test_blob_tamper_even_with_matching_outer_archive_hash(self):
        key = next(key for key, value in self.members.items() if len(value) > 5000)
        self.members[key] = b"X" + self.members[key][1:]
        write_archive(self.path, self.members)
        with self.assertRaisesRegex(Refused, "blob hash"):
            verify_oci_archive(self.path, self.reference, expected_sha256=file_sha256(self.path))

    def test_missing_referenced_blob_is_rejected(self):
        self.members.pop("blobs/sha256/" + self.config.split(":")[1])
        write_archive(self.path, self.members)
        with self.assertRaisesRegex(Refused, "descriptor"):
            verify_oci_archive(self.path, self.reference)

    def test_wrong_architecture_and_manifest_are_rejected(self):
        members, reference, _ = archive_members("arm64")
        write_archive(self.path, members)
        with self.assertRaisesRegex(Refused, "Linux amd64"):
            verify_oci_archive(self.path, reference)
        with self.assertRaisesRegex(Refused, "child-manifest"):
            verify_oci_archive(self.path, self.reference)

    def test_links_traversal_duplicates_and_extended_headers_are_rejected(self):
        cases = []
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.XHDTYPE):
            item = tarfile.TarInfo("evil")
            item.type, item.linkname = kind, "/etc/shadow"
            cases.append((item, None))
        for name in ("../outside", "/etc/shadow", "index.json"):
            item = tarfile.TarInfo(name)
            item.size = 2
            cases.append((item, b"{}"))
        for item, body in cases:
            with self.subTest(name=item.name, kind=item.type):
                write_archive(self.path, self.members, [(item, body)])
                with self.assertRaises(Refused):
                    verify_oci_archive(self.path, self.reference)

    def test_untrusted_files_and_symlinks_are_rejected(self):
        self.path.chmod(0o666)
        with self.assertRaises(Refused):
            verify_oci_archive(self.path, self.reference, root_owned=True)
        link = self.root / "alias.oci.tar"
        link.symlink_to(self.path)
        with self.assertRaises(Refused):
            verify_oci_archive(link, self.reference)

    def test_untrusted_owner_and_fifo_are_rejected_without_blocking(self):
        original = os.fstat
        def foreign_owner(fd):
            value = list(original(fd))
            value[4] = 12345
            return os.stat_result(value)
        with patch("nebulalog_manager.image_bundle.os.fstat", side_effect=foreign_owner):
            with self.assertRaises(Refused):
                verify_oci_archive(self.path, self.reference, root_owned=True)
        fifo = self.root / "pipe.oci.tar"
        os.mkfifo(fifo)
        with self.assertRaises(Refused):
            verify_oci_archive(fifo, self.reference)

    def test_duplicate_json_properties_rejected(self):
        self.members["oci-layout"] = b'{"imageLayoutVersion":"1.0.0","imageLayoutVersion":"1.0.0"}'
        write_archive(self.path, self.members)
        with self.assertRaisesRegex(Refused, "Duplicate JSON"):
            verify_oci_archive(self.path, self.reference)


class BundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = self.root / "bundle"
        self.pins, self.manifest, self.evidence = fixture_bundle(self.bundle)

    def test_pure_bundle_verification_has_no_process_or_guest_dependency(self):
        with patch("subprocess.run", side_effect=AssertionError("must not launch processes")):
            evidence = verify_bundle(self.bundle, self.pins)
        self.assertEqual(set(evidence["images"]), NAMES)

    def test_manifest_pin_and_duplicate_archive_refusal(self):
        name = sorted(NAMES)[0]
        self.manifest["images"][name]["reference"] = "registry.example/wrong@sha256:" + "a" * 64
        (self.bundle / "manifest.json").write_bytes(encoded(self.manifest))
        with self.assertRaisesRegex(Refused, "release image pins"):
            verify_bundle(self.bundle, self.pins)

    def test_builder_hardlink_reuses_verified_archives(self):
        sources = {name: {"archive": str(self.bundle / self.manifest["images"][name]["archive"]), "reference": self.pins[name]} for name in NAMES}
        output = self.root / "published"
        result = builder.build_bundle(sources, output, reuse_existing_archives=True)
        self.assertEqual(result["status"], "verified")
        for name in NAMES:
            self.assertEqual((output / builder.ARCHIVES[name]).stat().st_ino, Path(sources[name]["archive"]).stat().st_ino)
        self.assertEqual(set(verify_bundle(output, self.pins)["images"]), NAMES)

    def test_builder_failure_never_publishes_or_deletes_source(self):
        sources = {name: {"archive": str(self.bundle / self.manifest["images"][name]["archive"]), "reference": self.pins[name]} for name in NAMES}
        original = {name: Path(item["archive"]).read_bytes() for name, item in sources.items()}
        sources[sorted(NAMES)[-1]]["reference"] = "registry.example/wrong@sha256:" + "b" * 64
        output = self.root / "failed"
        with self.assertRaises(Refused):
            builder.build_bundle(sources, output, reuse_existing_archives=True)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".nebulalog-images-*")), [])
        for name, item in sources.items():
            self.assertEqual(Path(item["archive"]).read_bytes(), original[name])

    def test_builder_refuses_existing_destination(self):
        marker = self.bundle / "keep"
        marker.write_text("keep this")
        sources = {name: {"source": "local:test", "reference": self.pins[name]} for name in NAMES}
        with self.assertRaisesRegex(Refused, "new directory"):
            builder.build_bundle(sources, self.bundle)
        self.assertEqual(marker.read_text(), "keep this")


class LoaderTests(unittest.TestCase):
    def setUp(self):
        BundleTests.setUp(self)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "containers").mkdir()
        self.calls, self.installed = [], {}
        self.loader = ImageBundleLoader(bundle_dir=self.bundle, pins_path=self.bundle / "images.json", data=self.data, gate=lambda: {"host_ready": True}, runner=self.runner)

    def runner(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[:2] == ["podman", "info"]:
            return json.dumps({"store": {"graphRoot": str(self.data / "containers")}})
        if argv[0] == "findmnt":
            return json.dumps({"filesystems": [{"fstype": "xfs", "source": "/dev/mapper/nebulalog-data"}]})
        if argv[:3] == ["podman", "image", "exists"]:
            if argv[-1] not in self.installed:
                raise CommandFailed("podman", 1)
            return ""
        if argv[:3] == ["podman", "image", "inspect"]:
            return json.dumps([self.installed[argv[-1]]])
        if argv[0] == "skopeo" and "inspect" in argv:
            name = Path(argv[-1].removeprefix("oci-archive:")).name
            reference = next(item["reference"] for item in self.manifest["images"].values() if item["archive"] == name)
            return json.dumps(self.evidence[reference])
        if argv[0] == "skopeo" and "copy" in argv:
            reference = argv[-1].removeprefix("containers-storage:")
            self.installed[reference] = self.evidence[reference]
            return ""
        raise AssertionError("Unexpected command: " + repr(argv))

    def trusted_fixture(self):
        # Ownership checks have separate negative tests. This models a root-owned
        # installed fixture on the unprivileged macOS unit-test host.
        original = os.fstat
        def owned(fd):
            value = list(original(fd))
            value[4] = 0
            return os.stat_result(value)
        return patch("nebulalog_manager.image_bundle.os.fstat", side_effect=owned)

    def test_gate_failure_performs_no_container_commands(self):
        self.loader.gate = lambda: {"host_ready": False}
        with self.assertRaisesRegex(Refused, "firstboot"):
            self.loader.load()
        self.assertEqual(self.calls, [])

    def test_unencrypted_graphroot_refuses_before_copy(self):
        original_stat = Path.stat
        def owned(path, *args, **kwargs):
            value = list(original_stat(path, *args, **kwargs))
            value[4] = 0
            return os.stat_result(value)
        self.loader.runner = lambda argv, **kwargs: json.dumps({"store": {"graphRoot": "/var/lib/containers/storage"}})
        with patch.object(Path, "stat", owned):
            with self.assertRaisesRegex(Refused, "outside enrolled encrypted"):
                self.loader.load()
        self.assertEqual(self.installed, {})

    def test_tampered_bundle_refuses_before_any_copy(self):
        archive = self.bundle / self.manifest["images"][sorted(NAMES)[-1]]["archive"]
        with archive.open("ab") as stream:
            stream.write(b"tamper")
        with patch.object(self.loader, "_storage"), patch("nebulalog_manager.image_bundle._trusted_directory"), self.trusted_fixture():
            with self.assertRaisesRegex(Refused, "archive SHA256"):
                self.loader.load()
        self.assertEqual(self.calls, [])

    def test_loader_preserves_digests_and_second_run_is_read_only(self):
        with patch.object(self.loader, "_storage"), patch("nebulalog_manager.image_bundle._trusted_directory"), self.trusted_fixture():
            receipt = self.loader.load()
            copies = [call for call in self.calls if call[0] == "skopeo" and "copy" in call]
            self.assertEqual(len(copies), 4)
            self.assertTrue(all("--preserve-digests" in call and call[-2].startswith("oci-archive:") and call[-1].startswith("containers-storage:") for call in copies))
            self.calls.clear()
            self.loader.load()
        self.assertEqual(receipt["status"], "loaded")
        self.assertFalse(any("copy" in call for call in self.calls))
        self.assertFalse(any("docker://" in argument for call in self.calls for argument in call))

    def test_private_tmp_override_does_not_change_global_environment(self):
        before = os.environ.get("TMPDIR")
        with patch("subprocess.run") as command:
            command.return_value.returncode = 0
            command.return_value.stdout = b"{}"
            run_private(["skopeo", "inspect", "oci-archive:/approved"], temp=self.data / "tmp")
            self.assertEqual(command.call_args.kwargs["env"]["TMPDIR"], str(self.data / "tmp"))
        self.assertEqual(os.environ.get("TMPDIR"), before)


if __name__ == "__main__":
    unittest.main()
