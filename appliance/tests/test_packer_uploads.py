"""Execute the captured upload preflight against temporary local fixtures only."""
import ast
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


TEMPLATE = Path(__file__).resolve().parents[1] / "packer/nebulalog.pkr.hcl"
RECIPE = TEMPLATE.read_text()
SCRIPT = RECIPE.split("python3 - <<'PYUPLOAD'\n", 1)[1].split("\nPYUPLOAD\n", 1)[0]
# Load the actual helper without invoking its fixed /tmp guest entrypoint.
tree = ast.parse(SCRIPT)
tree.body = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
namespace = {}
exec(compile(tree, str(TEMPLATE), "exec"), namespace)
prepare_uploads = namespace["prepare_uploads"]
NAMES = ("nebulalog-appliance", "nebulalog-image-bundle")


class UploadPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def prepare(self):
        prepare_uploads(str(self.root), os.getuid(), os.getgid())

    def directory(self, name, mode=0o700):
        path = self.root / name
        path.mkdir()
        path.chmod(mode)
        return path

    def test_fresh_targets_are_private_and_empty(self):
        self.prepare()
        self.assertEqual({path.name for path in self.root.iterdir()}, set(NAMES))
        for name in NAMES:
            path = self.root / name
            info = path.lstat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (os.getuid(), os.getgid(), 0o700))
            self.assertEqual(list(path.iterdir()), [])

    def test_existing_empty_private_targets_are_not_replaced(self):
        self.prepare()
        before = {name: (self.root / name).stat().st_ino for name in NAMES}
        self.prepare()
        self.assertEqual(before, {name: (self.root / name).stat().st_ino for name in NAMES})

    def test_partial_or_unrelated_content_refuses_before_creating_other_target(self):
        target = self.directory(NAMES[1])
        evidence = target / ".partial-upload"
        evidence.write_bytes(b"retained evidence")
        with self.assertRaisesRegex(RuntimeError, "empty, packer-owned"):
            self.prepare()
        self.assertFalse((self.root / NAMES[0]).exists())
        self.assertEqual(evidence.read_bytes(), b"retained evidence")

    def test_symlink_and_regular_file_targets_are_not_adopted(self):
        outside = self.directory("outside")
        target = self.root / NAMES[1]
        for destination in (outside, self.root / "absent"):
            with self.subTest(destination=destination.name):
                target.symlink_to(destination, target_is_directory=True)
                with self.assertRaises(OSError):
                    self.prepare()
                self.assertTrue(target.is_symlink())
                self.assertFalse((self.root / NAMES[0]).exists())
                target.unlink()
        target.write_bytes(b"unrelated")
        with self.assertRaises(OSError):
            self.prepare()
        self.assertEqual(target.read_bytes(), b"unrelated")
        self.assertEqual(list(outside.iterdir()), [])

    def test_unexpected_owner_or_group_refuses_without_chown(self):
        target = self.directory(NAMES[1])
        inode = target.stat().st_ino
        fstat = os.fstat
        for field in ("st_uid", "st_gid"):
            def foreign_owner(descriptor):
                info = fstat(descriptor)
                if info.st_ino != inode:
                    return info
                value = {"st_uid": info.st_uid, "st_gid": info.st_gid, "st_mode": info.st_mode}
                value[field] += 1
                return SimpleNamespace(**value)
            with self.subTest(field=field), patch("os.fstat", side_effect=foreign_owner):
                with self.assertRaisesRegex(RuntimeError, "packer-owned"):
                    self.prepare()
            self.assertFalse((self.root / NAMES[0]).exists())
            self.assertEqual(target.stat().st_ino, inode)

    def test_unexpected_modes_are_refused_without_repair(self):
        target = self.directory(NAMES[1])
        for mode in (0o500, 0o750, 0o755, 0o777):
            with self.subTest(mode=oct(mode)):
                target.chmod(mode)
                with self.assertRaises(RuntimeError):
                    self.prepare()
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
                self.assertFalse((self.root / NAMES[0]).exists())
        target.chmod(0o700)

    def test_existing_realm_file_or_dangling_symlink_is_preserved(self):
        realm = self.root / "nebulalog-keycloak-realm.json"
        realm.write_bytes(b"previous upload")
        with self.assertRaisesRegex(RuntimeError, "realm upload"):
            self.prepare()
        self.assertEqual(realm.read_bytes(), b"previous upload")
        realm.unlink()
        realm.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(RuntimeError, "realm upload"):
            self.prepare()
        self.assertTrue(realm.is_symlink())
        self.assertEqual({path.name for path in self.root.iterdir()}, {realm.name})

    def test_creation_race_is_not_adopted(self):
        mkdir = os.mkdir
        def intervening_creation(name, mode, *, dir_fd):
            mkdir(name, mode=mode, dir_fd=dir_fd)
            raise FileExistsError("Another creator won")
        with patch("os.mkdir", side_effect=intervening_creation), self.assertRaises(FileExistsError):
            self.prepare()
        self.assertFalse((self.root / NAMES[1]).exists())

    def test_actual_entrypoint_rejects_other_users_before_preparing_paths(self):
        foreign = SimpleNamespace(pw_uid=os.getuid() + 1000, pw_gid=os.getgid())
        with patch("sys.platform", "linux"), patch("pwd.getpwnam", return_value=foreign), patch("os.open") as opened:
            with self.assertRaisesRegex(SystemExit, "disposable packer account"):
                exec(compile(SCRIPT, str(TEMPLATE), "exec"), {})
            opened.assert_not_called()

    def test_recipe_uses_precreated_targets_and_content_only_transfers(self):
        # SDK0.6.10 SCP and SFTP both omit the source basename only when source
        # ends in '/'. Destination setup must therefore precede either upload.
        self.assertLess(RECIPE.index("prepare_uploads(\"/tmp\""), RECIPE.index('provisioner "file"'))
        for variable, target in (("appliance_source_directory", NAMES[0]), ("image_bundle_directory", NAMES[1])):
            expected = 'source      = "${var.' + variable + '}/"\n    destination = "/tmp/' + target + '"'
            self.assertIn(expected, RECIPE)
        self.assertEqual(RECIPE.count('provisioner "file"'), 3)
        self.assertIn('sudo /bin/bash /tmp/nebulalog-appliance/install-host.sh', RECIPE)


if __name__ == "__main__":
    unittest.main()
