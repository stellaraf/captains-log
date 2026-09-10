"""Exercise cleanup against real fixture files, links and xattrs without a VM."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "packer/artifact_cleanup.py"
spec = importlib.util.spec_from_file_location("artifact_cleanup", SOURCE)
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


def xattr_names(path):
    if hasattr(os, "listxattr"):
        return os.listxattr(path, follow_symlinks=False)
    return subprocess.check_output(["/usr/bin/xattr", str(path)], text=True).splitlines()


def xattr_read(path, key):
    if hasattr(os, "getxattr"):
        return os.getxattr(path, key, follow_symlinks=False)
    return bytes.fromhex(subprocess.check_output(["/usr/bin/xattr", "-px", key, str(path)], text=True))


def xattr_write(path, key, value):
    if hasattr(os, "setxattr"):
        os.setxattr(path, key, value)
    else:
        subprocess.run(["/usr/bin/xattr", "-wx", key, value.hex(), str(path)], check=True)


class Tree:
    def __init__(self, root):
        self.root = root
        self.foreign = set()

    def path(self, path):
        return self.root / path.lstrip("/")

    def lstatns(self, path):
        s = self.path(path).lstat()
        return {"st_mode": s.st_mode, "st_uid": 99 if path in self.foreign else 0,
                "st_gid": 0, "st_nlink": s.st_nlink, "st_size": s.st_size}

    def exists(self, path): return self.path(path).exists()
    def is_symlink(self, path): return self.path(path).is_symlink()
    def readlink(self, path): return str(self.path(path).readlink())
    def ls(self, path): return sorted(p.name for p in self.path(path).iterdir())
    def find(self, path):
        return sorted(str(p.relative_to(self.path(path))) for p in self.path(path).rglob("*"))
    def read_file(self, path):
        p = self.path(path)
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode & 0o400: return p.read_bytes()
        p.chmod(mode | 0o400)
        try: return p.read_bytes()
        finally: p.chmod(mode)
    def checksum(self, algorithm, path):
        assert algorithm == "sha256"
        return hashlib.sha256(self.read_file(path)).hexdigest()
    def lgetxattrs(self, path):
        p = self.path(path)
        mode = stat.S_IMODE(p.stat().st_mode)
        if not mode & 0o400: p.chmod(mode | 0o400)
        try:
            return [{"attrname": k, "attrval": xattr_read(p, k)}
                    for k in xattr_names(p)]
        finally:
            if not mode & 0o400: p.chmod(mode)
    def rm(self, path): self.path(path).unlink()
    def truncate(self, path):
        with self.path(path).open("wb"): pass
    def sync(self): pass


class ArtifactCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.g = Tree(self.root)
        for path in ("/var/lib/nebulalog", "/etc/ssh", "/etc/systemd/system", "/boot/loader/entries", "/home", "/etc/sudoers.d"):
            self.g.path(path).mkdir(parents=True, exist_ok=True)
        for path, body in {
            "/etc/nebulalog/bootstrap/state": "unconfigured\n",
            "/etc/nebulalog/bootstrap/image-state": "sealed\n",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "/etc/shadow": "root:!:0:0:99999:7:::\n",
            "/etc/machine-id": "", "/etc/hostname": "captains-log\n",
            "/root/anaconda-ks.cfg": "public build settings",
            "/root/original-ks.cfg": "original settings",
            "/tmp/ks-script-one": "build public key",
            "/var/log/messages": "builder identity",
            "/var/log/anaconda/journal.log": "old journal",
            "/var/log/btmp": "login records",
            "/boot/initramfs-5.14.0.img": "normal boot image",
            "/boot/initramfs-0-rescue-template.img": "rescue boot image",
            "/boot/vmlinuz-5.14.0": "signed kernel",
            "/boot/initramfs-5.14.0kdump.img": "obsolete embedded identity",
            "/boot/loader/entries/template.conf": "linux /vmlinuz-5.14.0\ninitrd /initramfs-5.14.0.img\n",
            "/usr/lib/nebulalog/manager.py": "frozen host payload",
        }.items():
            self.put(path, body)
        self.g.path("/var/log/README").symlink_to("../../usr/share/doc/systemd/README.logs")
        self.g.path("/tmp").chmod(0o1777)
        self.g.path("/var/log/btmp").chmod(0o660)
        xattr_write(self.g.path("/var/log/messages"), "user.captains_log_test", b"preserve-label")
        self.payload = {"/usr/lib/nebulalog/manager.py": self.g.checksum("sha256", "/usr/lib/nebulalog/manager.py")}

    def put(self, path, body):
        p = self.g.path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        p.chmod(0o600)

    def test_cleanup_retains_real_log_metadata_boot_images_and_payload(self):
        plan = cleanup.create_plan(self.g, self.payload)
        result = cleanup.apply_plan(self.g, plan)
        self.assertEqual(result["actions_verified"], 7)
        self.assertFalse(self.g.exists("/root/anaconda-ks.cfg"))
        self.assertFalse(self.g.exists("/boot/initramfs-5.14.0kdump.img"))
        self.assertEqual(self.g.read_file("/var/log/messages"), b"")
        self.assertEqual(stat.S_IMODE(self.g.path("/var/log/btmp").stat().st_mode), 0o660)
        self.assertEqual(xattr_read(self.g.path("/var/log/messages"), "user.captains_log_test"), b"preserve-label")
        self.assertEqual(self.g.read_file("/boot/initramfs-5.14.0.img"), b"normal boot image")
        self.assertEqual(self.g.read_file("/boot/initramfs-0-rescue-template.img"), b"rescue boot image")
        self.assertTrue(plan["free_space_zeroing_still_required"])
        self.assertEqual(self.g.readlink("/var/log/README"), "../../usr/share/doc/systemd/README.logs")

    def test_unexpected_documentation_link_refuses_before_cleanup(self):
        self.g.path("/var/log/README").unlink()
        self.g.path("/var/log/README").symlink_to("/root/anaconda-ks.cfg")
        with self.assertRaisesRegex(ValueError, "documentation link target"):
            cleanup.create_plan(self.g, self.payload)
        self.assertTrue(self.g.exists("/root/anaconda-ks.cfg"))

    def test_deleted_builder_account_backups_are_removed_and_active_accounts_preserved(self):
        active = {path: self.g.read_file(path) for path in ("/etc/passwd", "/etc/shadow")}
        for path in cleanup.ACCOUNT_BACKUPS:
            self.put(path, "packer:synthetic-old-account-material\n")
            if "shadow" in path: self.g.path(path).chmod(0)
        plan = cleanup.create_plan(self.g, self.payload)
        cleanup.apply_plan(self.g, plan)
        self.assertTrue(all(not self.g.exists(path) for path in cleanup.ACCOUNT_BACKUPS))
        self.assertEqual({path: self.g.read_file(path) for path in active}, active)

    def test_enrollment_refuses_before_any_changes(self):
        self.put("/etc/nebulalog/configured", "configured")
        with self.assertRaisesRegex(ValueError, "enrollment"):
            cleanup.create_plan(self.g, self.payload)
        self.assertEqual(self.g.read_file("/var/log/messages"), b"builder identity")

    def test_symlink_hardlink_and_foreign_owner_refuse(self):
        for variant in ("symlink", "hardlink", "owner"):
            with self.subTest(variant=variant):
                p = self.g.path("/root/anaconda-ks.cfg")
                original = p.read_bytes()
                p.unlink()
                foreign = self.root / "untouched"
                foreign.write_bytes(original)
                if variant == "symlink": p.symlink_to(foreign)
                elif variant == "hardlink": os.link(foreign, p)
                else:
                    p.write_bytes(original)
                    self.g.foreign.add("/root/anaconda-ks.cfg")
                with self.assertRaises(ValueError): cleanup.create_plan(self.g, self.payload)
                self.assertEqual(foreign.read_bytes(), original)
                p.unlink();foreign.unlink();self.g.foreign.clear();self.put("/root/anaconda-ks.cfg", original.decode())

    def test_last_target_change_refuses_all_mutations(self):
        plan = cleanup.create_plan(self.g, self.payload)
        self.put("/var/log/messages", "changed since review")
        with self.assertRaisesRegex(ValueError, "changed after review"):
            cleanup.apply_plan(self.g, plan)
        self.assertTrue(self.g.exists("/root/anaconda-ks.cfg"))
        self.assertTrue(self.g.exists("/boot/initramfs-5.14.0kdump.img"))

    def test_enabled_or_referenced_kdump_refuses(self):
        enabled = self.g.path("/etc/systemd/system/multi-user.target.wants/kdump.service")
        enabled.parent.mkdir()
        enabled.symlink_to("/usr/lib/systemd/system/kdump.service")
        with self.assertRaisesRegex(ValueError, "enabled"): cleanup.create_plan(self.g, self.payload)
        enabled.unlink()
        self.put("/boot/loader/entries/template.conf", "initrd /initramfs-5.14.0kdump.img\n")
        with self.assertRaisesRegex(ValueError, "references"): cleanup.create_plan(self.g, self.payload)

    def test_tampered_payload_and_injected_action_refuse(self):
        with self.assertRaisesRegex(ValueError, "frozen input"):
            cleanup.create_plan(self.g, {next(iter(self.payload)): "0" * 64})
        plan = cleanup.create_plan(self.g, self.payload)
        self.put("/root/keep", "must remain")
        plan["actions"].append({**cleanup.record(self.g, "/root/keep"), "action": "unlink"})
        with self.assertRaisesRegex(ValueError, "scope changed"): cleanup.apply_plan(self.g, plan)
        self.assertEqual(self.g.read_file("/root/keep"), b"must remain")

    def test_readonly_verification_detects_reintroduced_metadata_or_boot_changes(self):
        plan = cleanup.create_plan(self.g, self.payload)
        cleanup.apply_plan(self.g, plan)
        self.put("/var/log/messages", "regenerated builder log")
        with self.assertRaisesRegex(ValueError, "preserve metadata"): cleanup.verify_plan(self.g, plan)
        self.g.truncate("/var/log/messages")
        self.put("/boot/initramfs-5.14.0.img", "changed boot image")
        with self.assertRaisesRegex(ValueError, "retained payload or boot"): cleanup.verify_plan(self.g, plan)


if __name__ == "__main__": unittest.main()
