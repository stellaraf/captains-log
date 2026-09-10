"""Host-only staging fixtures: no Packer build, guest or container execution."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "packer"
SPEC = importlib.util.spec_from_file_location("stage_sources", SCRIPTS / "stage_sources.py")
staging = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(staging)
from prepare_provenance import capture


class StagedSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "repo"
        self.root.mkdir()
        for name in staging.REQUIRED:
            self.write(name, b"fixture source\n")
        for prefix in staging.PREFIXES:
            if not any(name.startswith(prefix) for name in staging.REQUIRED):
                self.write(prefix + "fixture", b"fixture payload\n")
        self.write("LICENSE", b"fixture license\n")
        self.write("internal/example.go", b"package example\n")
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=Source Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")
        self.bundle = self.base / "bundle"
        self.bundle.mkdir()
        (self.bundle / "manifest.json").write_text('{}\n')
        self.provenance = self.base / "provenance"
        self.output = self.base / "frozen source"

    def git(self, *arguments):
        environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        subprocess.run(["git", "-C", str(self.root), *arguments], env=environment, check=True, capture_output=True)

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def capture(self):
        return capture(self.root, self.bundle, self.provenance, sequence=1, schema_revision="1", private_unsealed=True)

    def stage(self):
        return staging.stage(self.root, self.provenance, self.output)

    def test_frozen_inputs_match_existing_capture_and_have_fixed_modes(self):
        original = self.capture()
        result = self.stage()
        self.assertEqual(result["source_snapshot_sha256"], original["source_snapshot_sha256"])
        self.assertEqual(result["application_source_sha256"], original["application_source_sha256"])
        self.assertFalse((self.output / "internal").exists())
        self.assertFalse((self.output / ".git").exists())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.output / "appliance/install-host.sh").stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((self.output / staging.REALM).stat().st_mode), 0o400)
        self.assertEqual(staging.verify(self.output), result)
        self.write("appliance/install-host.sh", b"later edit\n")
        self.assertEqual(staging.verify(self.output), result)

    def test_new_stages_have_distinct_recorded_disk_ids_stable_on_verification(self):
        self.capture()
        first = self.stage()
        first_id = first["variables"]["build_disk_id"]
        self.assertRegex(first_id, r"^[a-f0-9]{16}$")
        self.assertEqual(staging.verify(self.output)["variables"]["build_disk_id"], first_id)
        self.output = self.base / "second frozen source"
        second = self.stage()
        self.assertNotEqual(second["variables"]["build_disk_id"], first_id)
        self.assertIn('build_disk_id = "' + second["variables"]["build_disk_id"] + '"',
                      (self.output / "frozen-sources.pkrvars.hcl").read_text())

    def test_changed_source_or_new_file_after_capture_is_refused_before_output(self):
        self.capture()
        self.write("appliance/bin/later", b"later edit\n")
        with self.assertRaisesRegex(ValueError, "changed after"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_ignored_private_files_are_not_copied(self):
        self.write(".gitignore", b".local/\nappliance/secrets/\n")
        self.write(".local/private.key", b"private fixture\n")
        self.write("appliance/secrets/private.key", b"private fixture\n")
        self.capture()
        self.stage()
        self.assertFalse((self.output / ".local").exists())
        self.assertFalse((self.output / "appliance/secrets").exists())

    def test_manifest_listed_credentials_are_refused(self):
        self.write("appliance/security/operator.key", b"fixture\n")
        self.capture()
        with self.assertRaisesRegex(ValueError, "credential"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_private_key_content_under_innocent_name_is_refused(self):
        self.write("appliance/security/fixture.conf", b"-----BEGIN RSA PRIVATE KEY-----\nfixture\n")
        self.capture()
        with self.assertRaisesRegex(ValueError, "Private key"):
            self.stage()
        self.assertFalse((self.output / "staging-receipt.json").exists())

    def test_private_key_detector_source_is_not_private_key_material(self):
        detector = b'PRIVATE_KEY = re.compile(rb"(?m)^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----\\r?$")\n'
        self.write("appliance/nebulalog_manager/key_detector.py", detector)
        self.capture()
        self.stage()
        self.assertEqual((self.output / "appliance/nebulalog_manager/key_detector.py").read_bytes(), detector)

    def test_symlink_file_and_directory_after_capture_are_refused(self):
        self.capture()
        original = self.root / "appliance/install-host.sh"
        target = self.base / "outside"
        target.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(target)
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_existing_output_is_never_adopted_or_overwritten(self):
        self.capture()
        self.output.mkdir()
        sentinel = self.output / "customer"
        sentinel.write_bytes(b"retain")
        with self.assertRaisesRegex(ValueError, "exclusive"):
            self.stage()
        self.assertEqual(sentinel.read_bytes(), b"retain")

    def test_descriptor_hash_mismatch_is_refused(self):
        self.capture()
        path = self.provenance / "source-manifest.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "initial-release"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_changed_mode_hash_extra_file_and_symlink_fail_reverification(self):
        self.capture()
        self.stage()
        path = self.output / "appliance/install-host.sh"
        path.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "mode"):
            staging.verify(self.output)
        path.chmod(0o500)
        extra = self.output / "appliance/unlisted"
        extra.write_text("unlisted")
        with self.assertRaisesRegex(ValueError, "inventory"):
            staging.verify(self.output)
        extra.unlink()
        extra.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            staging.verify(self.output)
        extra.unlink()
        path.chmod(0o700)
        path.write_bytes(b"altered\n")
        path.chmod(0o500)
        with self.assertRaisesRegex(ValueError, "bytes"):
            staging.verify(self.output)

    def test_source_mutation_during_copy_leaves_no_success_receipt(self):
        self.capture()
        original = staging.read_bounded
        changed = False
        def reader(root, name, maximum):
            nonlocal changed
            raw = original(root, name, maximum)
            if root == self.root and not changed:
                changed = True
                self.write("internal/example.go", b"package changed\n")
            return raw
        with patch.object(staging, "read_bounded", side_effect=reader):
            with self.assertRaisesRegex(ValueError, "changed while staging"):
                self.stage()
        self.assertFalse((self.output / "staging-receipt.json").exists())

    def test_varfile_paths_are_absolute_and_hcl_interpolation_is_escaped(self):
        self.output = self.base / 'frozen ${path} %{if true} "quoted"'
        self.capture()
        result = self.stage()
        content = (self.output / "frozen-sources.pkrvars.hcl").read_text()
        self.assertIn("$${path}", content)
        self.assertIn("%%{if true}", content)
        self.assertTrue(Path(result["variables"]["appliance_source_directory"]).is_absolute())

    def test_omitted_runtime_file_refuses_incomplete_capture(self):
        (self.root / "appliance/bin/nebulalog-aide").unlink()
        self.capture()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_omitted_managed_aide_config_refuses_incomplete_capture(self):
        (self.root / "appliance/security/aide.conf").unlink()
        self.capture()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.stage()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
