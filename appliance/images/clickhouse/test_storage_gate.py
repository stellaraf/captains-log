"""Bounded sysfs/mountinfo fixtures; never inspect or alter host block devices."""
from pathlib import Path
import subprocess
import tempfile
import unittest


GATE = Path(__file__).with_name("storage-gate.sh")


class StorageGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "dev/block").mkdir(parents=True)
        (self.root / "devices").mkdir()

    def node(self, number, uuid=None, partition=False):
        path = self.root / "devices" / number.replace(":", "_")
        path.mkdir()
        (path / "dev").write_text(number + "\n")
        (path / "uevent").write_text("DEVTYPE=" + ("partition" if partition else "disk") + "\n")
        if partition:
            (path / "partition").write_text("1\n")
        else:
            (path / "slaves").mkdir()
        if uuid:
            (path / "dm").mkdir()
            (path / "dm/uuid").write_text(uuid + "\n")
        (self.root / "dev/block" / number).symlink_to(path, target_is_directory=True)
        return path

    def edge(self, parent, child):
        (parent / "slaves" / child.name).symlink_to(child, target_is_directory=True)

    def chain(self):
        lv = self.node("253:0", "LVM-fixture")
        crypt = self.node("253:1", "CRYPT-LUKS2-fixture")
        partition = self.node("8:1", partition=True)
        self.edge(lv, crypt)
        self.edge(crypt, partition)
        return lv, crypt, partition

    def run_gate(self, function, *args):
        return subprocess.run(
            ["bash", "-eu", "-c", 'source "$1"; shift; "$@"', "fixture", str(GATE), function, *map(str, args)],
            text=True, capture_output=True, timeout=5,
        )

    def check_tree(self, accepted, message=None):
        result = self.run_gate("_nebulalog_check_luks2_tree", self.root, "253:0")
        self.assertEqual(result.returncode == 0, accepted, result.stderr)
        if message:
            self.assertIn(message, result.stderr)

    def test_lvm_over_luks2_partition(self):
        self.chain()
        self.check_tree(True)

    def test_luks2_whole_disk(self):
        lv, crypt, partition = self.chain()
        (crypt / "slaves" / partition.name).unlink()
        self.edge(crypt, self.node("8:0"))
        self.check_tree(True)

    def test_multiple_encrypted_branches(self):
        lv, _, _ = self.chain()
        crypt = self.node("253:2", "CRYPT-LUKS2-second")
        self.edge(lv, crypt)
        self.edge(crypt, self.node("8:2", partition=True))
        self.check_tree(True)

    def test_mixed_unencrypted_branch(self):
        lv, _, _ = self.chain()
        self.edge(lv, self.node("8:2", partition=True))
        self.check_tree(False, "unencrypted")

    def test_shared_leaf_does_not_inherit_other_branch_encryption(self):
        lv, _, partition = self.chain()
        self.edge(lv, partition)
        self.check_tree(False, "unencrypted")

    def test_cycles(self):
        lv, crypt, _ = self.chain()
        self.edge(crypt, lv)
        self.check_tree(False, "cycle")

    def test_luks1_and_unknown_mapper_are_refused(self):
        _, crypt, _ = self.chain()
        for uuid in ("CRYPT-LUKS1-fixture", "unknown-fixture", "CRYPT-LUKS2-"):
            with self.subTest(uuid=uuid):
                (crypt / "dm/uuid").write_text(uuid + "\n")
                self.check_tree(False, "unsupported")

    def test_missing_metadata(self):
        _, crypt, _ = self.chain()
        (crypt / "dm/uuid").unlink()
        self.check_tree(False, "missing")

    def test_unknown_leaf_type(self):
        _, _, partition = self.chain()
        (partition / "uevent").write_text("DEVTYPE=mystery\n")
        self.check_tree(False, "unknown")

    def test_duplicate_device_type(self):
        _, _, partition = self.chain()
        (partition / "uevent").write_text("DEVTYPE=partition\nDEVTYPE=disk\n")
        self.check_tree(False, "unknown")

    def test_non_mapper_intermediate_is_refused(self):
        lv, _, _ = self.chain()
        (lv / "dm/uuid").unlink()
        (lv / "dm").rmdir()
        self.check_tree(False, "unsupported intermediate")

    def test_metadata_symlink_is_refused(self):
        _, crypt, partition = self.chain()
        (crypt / "dm/uuid").unlink()
        (crypt / "dm/uuid").symlink_to(partition / "dev")
        self.check_tree(False, "missing device-mapper UUID")

    def test_unexpected_slave_file_is_refused(self):
        _, crypt, _ = self.chain()
        (crypt / "slaves/unexpected").write_text("8:1\n")
        self.check_tree(False, "invalid slave link")

    def test_missing_partition_metadata(self):
        _, _, partition = self.chain()
        (partition / "partition").unlink()
        self.check_tree(False, "partition metadata")

    def test_empty_mapper_slaves_are_not_physical_leaf(self):
        _, crypt, partition = self.chain()
        (crypt / "slaves" / partition.name).unlink()
        self.check_tree(False, "incomplete")

    def test_inconsistent_device_index(self):
        _, crypt, partition = self.chain()
        index = self.root / "dev/block/8:1"
        index.unlink()
        index.symlink_to(crypt, target_is_directory=True)
        self.check_tree(False, "inconsistent")

    def test_sysfs_escape(self):
        self.chain()
        index = self.root / "dev/block/253:0"
        index.unlink()
        index.symlink_to(self.root.parent, target_is_directory=True)
        self.check_tree(False, "escapes")

    def test_depth_limit(self):
        last = self.node("253:0", "LVM-fixture")
        for i in range(1, 18):
            node = self.node(f"253:{i}", "CRYPT-LUKS2-fixture")
            self.edge(last, node)
            last = node
        self.edge(last, self.node("8:1", partition=True))
        self.check_tree(False, "depth limit")

    def test_branch_limit(self):
        lv, _, _ = self.chain()
        for i in range(2, 18):
            self.edge(lv, self.node(f"8:{i}", partition=True))
        self.check_tree(False, "branch limit")

    def test_node_limit(self):
        lv = self.node("253:0", "LVM-fixture")
        for branch in range(16):
            crypt = self.node(f"253:{branch + 1}", "CRYPT-LUKS2-fixture")
            self.edge(lv, crypt)
            for leaf in range(8):
                self.edge(crypt, self.node(f"8:{branch * 8 + leaf}", partition=True))
        self.check_tree(False, "node limit")

    def test_oversized_metadata(self):
        _, crypt, _ = self.chain()
        (crypt / "dm/uuid").write_text("CRYPT-LUKS2-" + "x" * 300)
        self.check_tree(False, "missing device-mapper UUID")

    def test_mountinfo_requires_exact_unique_xfs_mount(self):
        path = self.root / "mountinfo"
        valid = "30 1 253:0 /var/lib/nebulalog/clickhouse /var/lib/clickhouse rw,nosuid shared:9 - xfs /dev/mapper/data rw\n"
        cases = [
            (valid, True),
            (valid.replace(" - xfs ", " - overlay "), False),
            (valid.replace("/var/lib/clickhouse ", "/var/lib/clickhouse-extra "), False),
            (valid + valid, False),
            (valid.replace("253:0", "../8:1"), False),
            (valid.replace(" - xfs ", " xfs "), False),
            (valid + "x" * 8193 + "\n", False),
            ("30 1 8:1 / /unrelated rw - xfs /dev/sda1 rw\n" * 4097 + valid, False),
        ]
        for content, accepted in cases:
            with self.subTest(accepted=accepted, prefix=content[:90]):
                path.write_text(content)
                result = self.run_gate("_nebulalog_clickhouse_mount_device", path)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if accepted:
                    self.assertEqual(result.stdout, "253:0\n")

    def test_public_entrypoint_refuses_path_override(self):
        result = self.run_gate("nebulalog_require_encrypted_storage", self.root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("overrides", result.stderr)


if __name__ == "__main__":
    unittest.main()
