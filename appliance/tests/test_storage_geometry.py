"""Synthetic measured XFS fixtures, never real host filesystem mutations."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager.common import Refused
from nebulalog_manager.storage import Identity, Snapshot, MIB, apply_growth, growth_plan, xfs_geometry

GIB = 1024**3
BLOCK = 4096
LOG_BYTES = 64*MIB
IDENTITY = Identity("/dev/disk/by-id/synthetic-xfs", "synthetic", "/dev/disk/by-id/synthetic-xfs-part1",
                    "part", "luks", "nebulalog-data", "pv", "vg", "lv")


def info(geometry=8*GIB, log_bytes=LOG_BYTES):
    return ("meta-data=/dev/mapper/synthetic isize=512 agcount=4, agsize=524288 blks\n"
            f"data     =                       bsize={BLOCK}   blocks={geometry//BLOCK}, imaxpct=5\n"
            "         =                       sunit=0 swidth=0 blks\n"
            f"log      =internal log           bsize={BLOCK}   blocks={log_bytes//BLOCK}, version=2\n"
            "realtime =none                   extsz=4096 blocks=0, rtextents=0\n")


def snapshot(geometry=8*GIB, lv=8*GIB):
    measured = xfs_geometry(info(geometry), filesystem_bytes=geometry-LOG_BYTES, filesystem_block_size=BLOCK, lv_bytes=lv)
    return Snapshot(IDENTITY, lv+20*MIB, lv+18*MIB, MIB, lv+2*MIB, lv, lv, geometry-LOG_BYTES, 0,
                    filesystem_geometry_bytes=measured)


class GeometryTests(unittest.TestCase):
    def test_internal_log_capacity_is_not_remaining_growth(self):
        observed = snapshot()
        self.assertEqual(observed.filesystem_bytes, 8*GIB-LOG_BYTES)
        self.assertEqual(observed.geometry_bytes, 8*GIB)
        self.assertEqual(growth_plan(observed)["stages"], [])

    def test_larger_lv_requires_only_xfs_then_reaches_noop(self):
        before, after = snapshot(4*GIB), snapshot(8*GIB)
        self.assertEqual(growth_plan(before)["stages"], ["xfs"])
        with tempfile.TemporaryDirectory() as temporary, patch("nebulalog_manager.storage.require_linux_root"):
            observations = iter((before, before, after))
            commands = []
            result = apply_growth(IDENTITY, before.fingerprint, state=Path(temporary),
                                  inspector=lambda _: next(observations), runner=lambda argv: commands.append(argv))
        self.assertEqual(commands, [["xfs_growfs", IDENTITY.mount]])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["after"]["filesystem_bytes"], 8*GIB-LOG_BYTES)
        self.assertEqual(growth_plan(after)["stages"], [])

    def test_legacy_pure_fixture_without_geometry_keeps_its_meaning(self):
        legacy = replace(snapshot(), filesystem_bytes=8*GIB, filesystem_geometry_bytes=None)
        self.assertEqual(legacy.geometry_bytes, legacy.filesystem_bytes)
        self.assertEqual(growth_plan(legacy)["stages"], [])
        self.assertEqual(growth_plan(replace(legacy, filesystem_bytes=4*GIB))["stages"], ["xfs"])

    def test_multi_pv_geometry_can_exceed_designated_disk(self):
        observed = snapshot(12*GIB, 12*GIB)
        observed = replace(observed, identity=replace(IDENTITY, additional_pvs=(("pv2", "luks2"),)),
                           disk_bytes=8*GIB+20*MIB, partition_bytes=8*GIB+18*MIB,
                           mapping_bytes=8*GIB+2*MIB, pv_bytes=8*GIB)
        self.assertGreater(observed.filesystem_bytes, observed.disk_bytes)
        self.assertEqual(growth_plan(observed)["stages"], [])

    def test_rejects_missing_duplicate_malformed_or_oversized_output(self):
        original = info()
        cases = ("", original.replace("data     =", "other    ="), original + original,
                 original.replace("blocks=2097152", "blocks=-1"), original.replace("blocks=2097152", "blocks=2e9"),
                 original.replace("blocks=2097152", "blocks=184467440737095516160"), original + "\0",
                 original + "x"*65536, original.replace("imaxpct=5", "imaxpct=5 blocks=123"))
        for value in cases:
            with self.subTest(value=value[:90]), self.assertRaises(Refused):
                xfs_geometry(value, filesystem_bytes=8*GIB-LOG_BYTES, filesystem_block_size=BLOCK, lv_bytes=8*GIB)

    def test_rejects_external_log_realtime_or_wrong_block_size(self):
        for value in (info().replace("internal log", "/dev/other"), info().replace("realtime =none", "realtime =/dev/other"),
                      info().replace("blocks=0, rtextents=0", "blocks=100, rtextents=10"),
                      info().replace("bsize=4096", "bsize=8192"), info().replace("blocks=16384", "blocks=0")):
            with self.subTest(value=value[:90]), self.assertRaises(Refused):
                xfs_geometry(value, filesystem_bytes=8*GIB-LOG_BYTES, filesystem_block_size=BLOCK, lv_bytes=8*GIB)

    def test_rejects_concurrent_or_inconsistent_independent_measurements(self):
        for changes in ({"filesystem_bytes": 8*GIB}, {"filesystem_bytes": 8*GIB-LOG_BYTES-BLOCK},
                        {"lv_bytes": 4*GIB}, {"filesystem_block_size": 512}, {"filesystem_bytes": True}):
            arguments = {"filesystem_bytes": 8*GIB-LOG_BYTES, "filesystem_block_size": BLOCK, "lv_bytes": 8*GIB}
            arguments.update(changes)
            with self.subTest(changes=changes), self.assertRaises(Refused):
                xfs_geometry(info(), **arguments)

    def test_snapshot_refuses_fabricated_geometry(self):
        for geometry in (True, 0, 4*GIB, 16*GIB):
            with self.subTest(geometry=geometry), self.assertRaises(Refused):
                growth_plan(replace(snapshot(), filesystem_geometry_bytes=geometry))


if __name__ == "__main__":
    unittest.main()
