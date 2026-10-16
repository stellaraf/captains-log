import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('preserve_build',Path(__file__).resolve().parents[1]/'packer/preserve_build.py')
preserve=importlib.util.module_from_spec(spec);spec.loader.exec_module(preserve)

class RecoveryTests(unittest.TestCase):
    def test_unlink_and_compaction_replacement_preserve_both_inodes(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);source=root/'build';recovery=root/'recovery'
            links=preserve.RecoveryLinks(source,recovery)
            self.assertEqual(links.capture(),[])
            source.mkdir();disk=source/preserve.NAMES[0];disk.write_bytes(b'original')
            links.capture();disk.write_bytes(b'completed');links.capture()
            self.assertEqual(len(links.records),1)
            disk.unlink();disk.write_bytes(b'compacted');links.capture()
            disk.unlink();source.rmdir()
            records=links.capture()
            self.assertEqual([Path(r['recovery_file']).read_bytes() for r in records],[b'completed',b'compacted'])
            self.assertTrue(all(r['consistent_image_verified'] is False for r in records))

    def test_existing_recovery_and_symlink_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);source=root/'build';source.mkdir();recovery=root/'recovery'
            links=preserve.RecoveryLinks(source,recovery)
            with self.assertRaises(FileExistsError):preserve.RecoveryLinks(source,recovery)
            (source/preserve.NAMES[0]).symlink_to(root/'secret')
            with self.assertRaises(ValueError):links.capture()

    def test_unrelated_files_are_not_captured(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);source=root/'build';source.mkdir();(source/'credential').write_text('fixture')
            links=preserve.RecoveryLinks(source,root/'recovery')
            self.assertEqual(links.capture(),[])
