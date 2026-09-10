"""Complete-source retention fixtures; never execute Packer, containers or guests."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "packer/archive_sources.py"
SPEC = importlib.util.spec_from_file_location("archive_sources", SCRIPT)
archiver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archiver)
from prepare_provenance import capture


class ArchiveSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "repo"
        self.root.mkdir()
        self.contents = {"LICENSE": b"fixture license\n", "internal/app.go": b"package app\n",
                         "web/src/App.tsx": b"export const app = 'fixture'\n",
                         "appliance/packer/recipe.hcl": b"fixture recipe\n",
                         "appliance/tests/fixture.py": b"# test source\n", "docs/example.md": b"documentation\n",
                         ".gitignore": b".local/\n.env*\nnode_modules/\n"}
        for name, raw in self.contents.items():
            self.write(name, raw)
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=Archive Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")
        self.bundle = self.base / "bundle"
        self.bundle.mkdir()
        (self.bundle / "manifest.json").write_text('{}\n')
        self.provenance = self.base / "capture"
        self.output = self.base / "complete-source.tar"

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def git(self, *args):
        environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        subprocess.run(["git", "-C", str(self.root), *args], env=environment, check=True, capture_output=True)

    def capture(self):
        return capture(self.root, self.bundle, self.provenance, sequence=1, schema_revision="1", private_unsealed=True)

    def archive(self):
        return archiver.archive_sources(self.root, self.provenance, self.output)

    def assert_unpublished(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(archiver.receipt_path(self.output).exists())
        self.assertEqual(list(self.base.glob(".nebulalog-source-archive-*")), [])

    def test_real_git_roundtrip_preserves_all_captured_bytes_and_dirty_identity(self):
        self.contents["docs/untracked.md"] = b"captured untracked source\n"
        self.write("docs/untracked.md", self.contents["docs/untracked.md"])
        original = self.capture()
        result = self.archive()
        self.assertEqual(result["source_snapshot_sha256"], original["source_snapshot_sha256"])
        self.assertEqual(result["source_commit"], original["source_commit"])
        self.assertTrue(result["source_dirty"])
        self.assertEqual(result["archive_sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertEqual(result["source_files"], len(self.contents))
        self.assertEqual(result["source_bytes"], sum(map(len, self.contents.values())))
        restored = self.base / "restored"
        restored.mkdir()
        with tarfile.open(self.output, "r:") as archive:
            members = archive.getmembers()
            self.assertEqual([item.name for item in members], sorted(self.contents))
            for item in members:
                self.assertEqual((item.type, item.uid, item.gid, item.mtime, item.mode, item.uname, item.gname),
                                 (tarfile.REGTYPE, 0, 0, 0, 0o644, "", ""))
                raw = archive.extractfile(item).read()
                self.assertEqual(raw, self.contents[item.name])
                path = restored / item.name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
        self.assertEqual({p.relative_to(restored).as_posix(): p.read_bytes() for p in restored.rglob("*") if p.is_file()}, self.contents)
        for path in (self.output, archiver.receipt_path(self.output)):
            self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            self.assertEqual(path.stat().st_nlink, 1)
        self.write("internal/app.go", b"later workspace edit\n")
        self.assertEqual(archiver.verify(self.output, self.provenance), result)
        self.assertFalse(result["runtime_executed"])
        self.assertFalse(result["signature_created"])

    def test_deterministic_bytes_ignore_uncaptured_modes_and_timestamps(self):
        self.capture()
        first = self.archive()
        original = self.output.read_bytes()
        for name in self.contents:
            path = self.root / name
            path.chmod(0o744)
            os.utime(path, (1700000000, 1700000000))
        self.git("config", "core.fileMode", "false")
        self.output = self.base / "second.tar"
        second = self.archive()
        self.assertEqual(original, self.output.read_bytes())
        self.assertEqual(first, second)

    def test_ignored_credentials_generated_files_and_git_metadata_never_enter_tar(self):
        self.write(".env.production", b"ignored credential fixture\n")
        self.write(".local/private.key", b"ignored private material\n")
        self.write("node_modules/generated.js", b"ignored build payload\n")
        self.capture()
        self.archive()
        with tarfile.open(self.output) as archive:
            self.assertEqual(archive.getnames(), sorted(self.contents))

    def test_tracked_deletion_is_preserved_as_absence(self):
        (self.root / "docs/example.md").unlink()
        self.contents.pop("docs/example.md")
        self.capture()
        self.assertTrue(self.archive()["source_dirty"])
        with tarfile.open(self.output) as archive:
            self.assertEqual(archive.getnames(), sorted(self.contents))

    def test_changed_missing_and_extra_files_refuse_before_publish(self):
        self.capture()
        path = self.root / "internal/app.go"
        for damage in ("changed", "missing", "extra"):
            path.write_bytes(self.contents["internal/app.go"])
            if damage == "changed":
                path.write_bytes(b"modified after capture\n")
            elif damage == "missing":
                path.unlink()
            else:
                self.write("new.key", b"unlisted credential\n")
            with self.subTest(damage=damage), self.assertRaises((ValueError, OSError)):
                self.archive()
            self.assert_unpublished()

    def test_linked_nonregular_and_symlink_sources_refuse(self):
        self.capture()
        path = self.root / "internal/app.go"
        for kind in ("symlink", "hardlink", "directory", "fifo"):
            path.unlink()
            outside = self.base / "outside"
            outside.write_bytes(self.contents["internal/app.go"])
            if kind == "symlink":
                path.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, path)
            elif kind == "directory":
                path.mkdir()
            else:
                os.mkfifo(path)
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                self.archive()
            self.assert_unpublished()
            path.rmdir() if kind == "directory" else path.unlink()
            path.write_bytes(self.contents["internal/app.go"])

    def test_symlink_parent_and_root_refuse(self):
        self.capture()
        directory = self.root / "internal"
        directory.rename(self.base / "outside")
        directory.symlink_to(self.base / "outside", target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.archive()
        self.assert_unpublished()
        alias = self.base / "repo-link"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            archiver.archive_sources(alias, self.provenance, self.output)

    def test_captured_credentials_generated_paths_and_unsafe_tar_names_refuse(self):
        for name in ("docs/operator.key", "docs/.aws/config", "web/dist/index.html", "docs/" + "x" * 101):
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=self.base) as temporary:
                path = self.write(name, b"fixture\n")
                provenance = Path(temporary) / "capture"
                capture(self.root, self.bundle, provenance, sequence=1, schema_revision="1", private_unsealed=True)
                with self.assertRaises(ValueError):
                    archiver.archive_sources(self.root, provenance, self.output)
                self.assert_unpublished()
                path.unlink()

    def test_private_key_content_under_an_ordinary_name_refuses(self):
        self.write("docs/operator.txt", b"-----BEGIN RSA PRIVATE KEY-----\nfixture only\n-----END RSA PRIVATE KEY-----\n")
        self.capture()
        with self.assertRaisesRegex(ValueError, "Private key"):
            self.archive()
        self.assert_unpublished()

    def test_manifest_descriptor_mismatch_and_duplicate_fields_refuse(self):
        self.capture()
        path = self.provenance / "source-manifest.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            self.archive()
        self.assert_unpublished()
        path = self.provenance / "initial-release.json"
        path.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):
            self.archive()
        self.assert_unpublished()

    def test_file_total_and_count_bounds_refuse_without_archive(self):
        self.capture()
        for setting in ("MAX_FILE", "MAX_BYTES", "MAX_FILES", "MAX_ARCHIVE"):
            with self.subTest(setting=setting), patch.object(archiver, setting, 1), self.assertRaises(ValueError):
                self.archive()
            self.assert_unpublished()

    def test_changes_during_copy_and_after_copy_refuse_including_restored_bytes(self):
        self.capture()
        original_reader = archiver.source_bytes
        for when, restore in ((1, False), (1, True), (len(self.contents) * 2, False)):
            calls = 0
            def reader(root, name, expected, observation):
                nonlocal calls
                raw = original_reader(root, name, expected, observation)
                calls += 1
                if calls == when:
                    target = self.root / ".gitignore"
                    target.write_bytes(b"changed during archive\n")
                    if restore:
                        target.write_bytes(self.contents[".gitignore"])
                return raw
            with self.subTest(when=when, restore=restore), patch.object(archiver, "source_bytes", side_effect=reader), self.assertRaises(ValueError):
                self.archive()
            self.assert_unpublished()
            (self.root / ".gitignore").write_bytes(self.contents[".gitignore"])

    def test_growth_during_protected_read_refuses(self):
        self.capture()
        original_open = archiver.open_source
        class ChangingStream:
            def __init__(self, stream, path):
                self.stream, self.path = stream, path
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def fileno(self): return self.stream.fileno()
            def read(self, size):
                raw = self.stream.read(size)
                with self.path.open("ab") as other: other.write(b"changed while read")
                return raw
        def opened(root, name):
            stream, info = original_open(root, name)
            return ChangingStream(stream, root / name), info
        with patch.object(archiver, "open_source", side_effect=opened), self.assertRaises(ValueError):
            self.archive()
        self.assert_unpublished()

    def test_existing_output_or_receipt_and_publish_race_preserve_competing_files(self):
        self.capture()
        receipt = archiver.receipt_path(self.output)
        for existing in (self.output, receipt):
            existing.write_bytes(b"preserve existing evidence")
            with self.assertRaises(ValueError):
                self.archive()
            self.assertEqual(existing.read_bytes(), b"preserve existing evidence")
            existing.unlink()
        original_link = os.link
        def race(source, destination, **kwargs):
            if destination == receipt:
                receipt.write_bytes(b"competing receipt")
            return original_link(source, destination, **kwargs)
        with patch.object(archiver.os, "link", side_effect=race), self.assertRaises(FileExistsError):
            self.archive()
        self.assertTrue(self.output.exists())  # A fully verified tar is retained without accepting the competing receipt.
        self.assertEqual(receipt.read_bytes(), b"competing receipt")
        self.assertEqual(list(self.base.glob(".nebulalog-source-archive-*")), [])
        with self.assertRaises(ValueError):
            archiver.verify(self.output, self.provenance)

    def test_changed_member_extra_member_padding_and_receipt_fail_reverification(self):
        self.capture()
        self.archive()
        original = self.output.read_bytes()
        for damage in ("member", "extra", "padding"):
            self.output.chmod(0o600)
            if damage == "member":
                self.output.write_bytes(original.replace(b"fixture license", b"altered license", 1))
            elif damage == "padding":
                self.output.write_bytes(original + b"\0" * 10240)
            else:
                with tarfile.open(self.output, "w", format=tarfile.USTAR_FORMAT) as archive:
                    for name, raw in sorted(self.contents.items()):
                        archive.addfile(archiver.tar_info(name, len(raw)), io.BytesIO(raw))
                    archive.addfile(archiver.tar_info("unlisted", 1), io.BytesIO(b"x"))
            self.output.chmod(0o400)
            with self.subTest(damage=damage), self.assertRaises(ValueError):
                archiver.verify(self.output, self.provenance)
        self.output.chmod(0o600)
        self.output.write_bytes(original)
        self.output.chmod(0o400)
        receipt = archiver.receipt_path(self.output)
        record = json.loads(receipt.read_text())
        record["archive_sha256"] = "0" * 64
        receipt.chmod(0o600)
        receipt.write_text(json.dumps(record))
        receipt.chmod(0o400)
        with self.assertRaises(ValueError):
            archiver.verify(self.output, self.provenance)

    def test_extensions_and_oversized_header_refuse_before_tar_parser_or_payload(self):
        self.capture()
        self.archive()
        for kind in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE, tarfile.SYMTYPE, tarfile.DIRTYPE):
            item = archiver.tar_info(sorted(self.contents)[0], 2**30)
            item.type = kind
            self.output.chmod(0o600)
            self.output.write_bytes(item.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 9728)
            self.output.chmod(0o400)
            with self.subTest(kind=kind), patch.object(archiver.tarfile, "open", side_effect=AssertionError("Input tar parser forbidden")), self.assertRaises(ValueError):
                archiver.verify(self.output, self.provenance)

    def test_receipt_types_are_exact_not_numeric_boolean_equivalence(self):
        self.capture()
        self.archive()
        receipt = archiver.receipt_path(self.output)
        original = json.loads(receipt.read_text())
        for field, value in (("source_dirty", 0), ("runtime_executed", 0), ("source_files", float(len(self.contents)))):
            receipt.chmod(0o600)
            receipt.write_text(json.dumps({**original, field: value}))
            receipt.chmod(0o400)
            with self.subTest(field=field), self.assertRaises(ValueError):
                archiver.verify(self.output, self.provenance)

    def test_new_file_or_provenance_edit_after_copy_refuses_publication(self):
        self.capture()
        original_reader = archiver.source_bytes
        descriptor_path = self.provenance / "initial-release.json"
        original_descriptor = descriptor_path.read_bytes()
        for change in ("inventory", "provenance"):
            calls = 0
            def reader(root, name, expected, observation):
                nonlocal calls
                raw = original_reader(root, name, expected, observation)
                calls += 1
                if calls == len(self.contents) * 2:
                    if change == "inventory":
                        self.write("new-source", b"late source")
                    else:
                        value = json.loads(original_descriptor)
                        value["sequence"] = 2
                        descriptor_path.write_text(json.dumps(value))
                return raw
            with self.subTest(change=change), patch.object(archiver, "source_bytes", side_effect=reader), self.assertRaises(ValueError):
                self.archive()
            self.assert_unpublished()
            if change == "inventory":
                (self.root / "new-source").unlink()
            descriptor_path.write_bytes(original_descriptor)

    def test_verify_cli_needs_no_source_checkout_and_executes_no_repository_commands(self):
        self.capture()
        result = self.archive()
        with patch.object(archiver, "git", side_effect=AssertionError("No Git inspection during archive verification")):
            self.assertEqual(archiver.verify(self.output, self.provenance), result)
        process = subprocess.run([sys.executable, str(SCRIPT), "--verify-only", "--output", str(self.output),
                                  "--provenance", str(self.provenance)], capture_output=True, check=True)
        self.assertEqual(json.loads(process.stdout), result)


if __name__ == "__main__":
    unittest.main()
