"""Small file-race/publication checks; no database, native runtime or CMS claim."""
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import log_recovery_set as transport
from nebulalog_manager.common import Refused


class PinnedInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.target = self.root / "input", self.root / "pinned"
        self.body = b"small synthetic input"
        self.source.write_bytes(self.body)
        self.source.chmod(0o600)
        self.original = self.source.stat()

    def test_growth_after_admission_is_refused_before_copy_or_hash(self):
        with self.source.open("ab") as stream:
            stream.write(b"x" * 128)
        with self.assertRaisesRegex(Refused, "changed before"):
            transport._copy_bounded(self.source, self.target, self.original, 1024)
        self.assertEqual(self.target.read_bytes(), b"")
        with self.assertRaisesRegex(Refused, "changed before"):
            transport._digest_bounded(self.source, self.original, 1024)

    def test_same_bytes_replacement_after_admission_is_refused(self):
        replacement = self.root / "replacement"
        replacement.write_bytes(self.body)
        replacement.chmod(0o600)
        os.replace(replacement, self.source)
        with self.assertRaisesRegex(Refused, "changed before"):
            transport._copy_bounded(self.source, self.target, self.original, 1024)
        with self.assertRaisesRegex(Refused, "changed before"):
            transport._digest_bounded(self.source, self.original, 1024)

    def test_growth_during_copy_reads_only_admitted_bytes_and_overflow_probe(self):
        fdopen = os.fdopen
        reads = []
        source = self.source
        body = self.body

        class GrowingReader:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def fileno(self):
                return self.stream.fileno()

            def read(self, count):
                reads.append(count)
                data = self.stream.read(count)
                if len(reads) == 1:
                    with source.open("ab") as output:
                        output.write(b"x" * 128)
                return data

        with patch.object(transport.os, "fdopen", side_effect=lambda fd, mode: GrowingReader(fdopen(fd, mode))):
            with self.assertRaisesRegex(Refused, "changed while"):
                transport._copy_bounded(self.source, self.target, self.original, 1024)
        self.assertEqual(reads, [len(body), 1])
        self.assertEqual(self.target.read_bytes(), body)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_atime_only_difference_is_accepted_by_copy_and_hash(self):
        # A read can advance atime without changing ctime. os.utime would also
        # change ctime, so model only that allowed filesystem observation here.
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        earlier = SimpleNamespace(**{name: getattr(self.original, name) for name in fields},
                                  st_atime=self.original.st_atime - 100,
                                  st_atime_ns=self.original.st_atime_ns - 100_000_000_000)
        transport._copy_bounded(self.source, self.target, earlier, 1024)
        self.assertEqual(self.target.read_bytes(), self.body)
        self.assertEqual(transport._digest_bounded(self.source, earlier, 1024), hashlib.sha256(self.body).hexdigest())

    def test_copy_preserves_existing_target_and_refuses_symlink_source(self):
        self.target.write_bytes(b"retained evidence")
        with self.assertRaises(FileExistsError):
            transport._copy_bounded(self.source, self.target, self.original, 1024)
        self.assertEqual(self.target.read_bytes(), b"retained evidence")
        self.source.unlink()
        self.source.symlink_to(self.target)
        with self.assertRaises(OSError):
            transport._copy_bounded(self.source, self.root / "never", self.original, 1024)
        self.assertFalse((self.root / "never").exists())

    def test_fifo_substitution_is_refused_without_blocking_before_fstat(self):
        # Run this regression in a bounded child: a missing O_NONBLOCK must
        # fail the test rather than hang the entire host test suite in open().
        code = """
import os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv[2])
from nebulalog_manager import log_recovery_set as transport
from nebulalog_manager.common import Refused
root = Path(sys.argv[1])
def deadline(*args):
    raise RuntimeError('FIFO operation blocked after imports completed')
signal.signal(signal.SIGALRM, deadline)
signal.alarm(2)
for name in ('copy', 'digest'):
    source = root / ('fifo-' + name)
    source.write_bytes(b'small synthetic source')
    original = source.stat()
    source.unlink()
    os.mkfifo(source, 0o600)
    try:
        if name == 'copy':
            transport._copy_bounded(source, root / 'never-published', original, 1024)
        else:
            transport._digest_bounded(source, original, 1024)
    except Refused:
        pass
    else:
        raise AssertionError('Substituted FIFO was accepted')
signal.alarm(0)
print('both FIFO substitutions refused before any read')
"""
        result = subprocess.run([sys.executable, "-B", "-c", code, str(self.root), str(Path(__file__).resolve().parents[1])],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("both FIFO substitutions refused", result.stdout)


class PublicationBoundaryTests(unittest.TestCase):
    def test_success_persists_set_parent_and_removes_archive_link_before_final_barriers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging, native, output = root / "scratch", root / "native", root / "export"
            staging.mkdir(mode=0o700)
            native.mkdir(mode=0o700)
            archive = native / "events.tar"
            body = b"small synthetic publication archive"
            archive.write_bytes(body)
            archive.chmod(0o600)
            link = {"source_installation_id": "a2eaf0a7-99dd-45a8-ae60-841127afc90c",
                    "configuration_backup": {"sha256": "c" * 64, "bytes": 12345},
                    "runtime": {"schema_revision": "3", "images": {name: "registry.example/image@sha256:" + "a" * 64 for name in transport.IMAGE_KEYS}}}
            metadata = {"link": copy.deepcopy(link),
                        "native": {"table": "nebulalog.events", "server_version": "25.3.8",
                                   "table_uuid": "fbece678-cf26-46e5-b380-0b20bfa143dd",
                                   "backup_id": "d590273c-f410-4722-8b54-f997a58aed45",
                                   "query_id": "abc296fa-f921-47b3-8d15-92669a23e839",
                                   "started_at": "2026-10-19T20:00:00Z", "finished_at": "2026-10-19T20:00:10Z",
                                   "table_definition_sha256": "e" * 64, "retention_policy_revision": 4},
                        "archive": {"format": "clickhouse-native-tar", "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}}
            manager = transport.LogRecoverySet(Mock(side_effect=AssertionError("No subprocess permitted")))
            events = []
            original_link, original_unlink = os.link, Path.unlink

            def linked(source, target, **kwargs):
                result = original_link(source, target, **kwargs)
                events.append(("link", source, target))
                return result

            def unlinked(path, *args, **kwargs):
                result = original_unlink(path, *args, **kwargs)
                events.append(("unlink", path))
                return result

            def copy_crypto(source, target, *args, **kwargs):
                # Exercise actual manifest/chunk validation and publication;
                # cryptographic acceptance belongs to the real CMS suite.
                target.write_bytes(source.read_bytes())
                target.chmod(0o600)

            with patch.object(transport, "ROOT_UID", os.getuid()), \
                    patch.object(transport, "_directory"), patch.object(transport, "_encrypted_staging"), \
                    patch.object(transport.shutil, "disk_usage", return_value=Mock(free=1024**4)), \
                    patch.object(manager, "_workspace"), patch.object(manager, "_credential", return_value=root / "synthetic.pem"), \
                    patch("nebulalog_manager.backup.probe_recipient") as recipient_probe, \
                    patch.object(manager, "_encrypt", side_effect=copy_crypto), \
                    patch.object(manager, "_decrypt", side_effect=copy_crypto), \
                    patch.object(transport, "_fsync", side_effect=lambda path: events.append(("fsync", path))), \
                    patch.object(transport.os, "link", side_effect=linked), patch.object(Path, "unlink", unlinked):
                sealed = manager.seal(archive, output, root / "synthetic.pem", staging, metadata)
                recipient_probe.assert_called_once()
                self.assertTrue(sealed["complete"])
                self.assertEqual(events[-3:], [("unlink", output / ".manifest.pending"),
                                               ("fsync", output), ("fsync", output.parent)])
                self.assertEqual((output / "manifest.cms").stat().st_nlink, 1)
                events.clear()
                restored = staging / "restored.tar"
                result = manager.unseal(output, restored, root / "synthetic.pem", root / "synthetic.key", staging, link)
                self.assertTrue(result["verified"])
                publication = next(index for index, event in enumerate(events)
                                   if event[0] == "link" and event[2] == restored)
                pending = events[publication][1]
                self.assertEqual(events[publication + 1:publication + 6], [
                    ("fsync", restored.parent), ("unlink", pending), ("fsync", pending.parent),
                    ("fsync", restored), ("fsync", restored.parent)])
                self.assertFalse(pending.exists())
                self.assertEqual(restored.stat().st_nlink, 1)
                self.assertEqual(restored.stat().st_mode & 0o777, 0o600)
                self.assertEqual(restored.read_bytes(), body)

    def test_crash_after_manifest_link_leaves_refused_set_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging, native, output = root / "scratch", root / "native", root / "export"
            staging.mkdir(mode=0o700)
            native.mkdir(mode=0o700)
            archive = native / "events.tar"
            body = b"synthetic archive bytes"
            archive.write_bytes(body)
            archive.chmod(0o600)
            link = {"source_installation_id": "a2eaf0a7-99dd-45a8-ae60-841127afc90c",
                    "configuration_backup": {"sha256": "c" * 64, "bytes": 12345},
                    "runtime": {"schema_revision": "3", "images": {name: "registry.example/image@sha256:" + "a" * 64 for name in transport.IMAGE_KEYS}}}
            metadata = {"link": copy.deepcopy(link),
                        "native": {"table": "nebulalog.events", "server_version": "25.3.8",
                                   "table_uuid": "fbece678-cf26-46e5-b380-0b20bfa143dd",
                                   "backup_id": "d590273c-f410-4722-8b54-f997a58aed45",
                                   "query_id": "abc296fa-f921-47b3-8d15-92669a23e839",
                                   "started_at": "2026-10-19T20:00:00Z", "finished_at": "2026-10-19T20:00:10Z",
                                   "table_definition_sha256": "e" * 64, "retention_policy_revision": 4},
                        "archive": {"format": "clickhouse-native-tar", "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}}
            manager = transport.LogRecoverySet(Mock(side_effect=AssertionError("No subprocess permitted")))
            original_unlink = Path.unlink

            def interrupted_unlink(path, *args, **kwargs):
                if path == output / ".manifest.pending":
                    raise OSError("Synthetic interruption after complete-file hardlink")
                return original_unlink(path, *args, **kwargs)

            def encrypt(plain, target, certificate):
                # Only publication ordering is under test here. Real CMS,
                # including bad-tag plaintext cleanup, has its own test suite.
                target.write_bytes(plain.read_bytes())
                target.chmod(0o600)

            with patch.object(transport, "ROOT_UID", os.getuid()), \
                    patch.object(transport, "_directory"), patch.object(transport, "_encrypted_staging"), \
                    patch.object(transport.shutil, "disk_usage", return_value=Mock(free=1024**4)), \
                    patch.object(manager, "_workspace"), patch.object(manager, "_credential", return_value=root / "synthetic.pem"), \
                    patch("nebulalog_manager.backup.probe_recipient") as recipient_probe, \
                    patch.object(manager, "_encrypt", side_effect=encrypt), \
                    patch.object(Path, "unlink", interrupted_unlink):
                with self.assertRaisesRegex(OSError, "Synthetic interruption"):
                    manager.seal(archive, output, root / "synthetic.pem", staging, metadata)
                recipient_probe.assert_called_once()
                self.assertTrue((output / "manifest.cms").is_file())
                self.assertEqual((output / "manifest.cms").stat().st_nlink, 2)
                self.assertEqual((output / ".manifest.pending").stat().st_ino, (output / "manifest.cms").stat().st_ino)
                with patch.object(manager, "_decrypt", side_effect=AssertionError("Incomplete set must fail before parsing")):
                    with self.assertRaisesRegex(Refused, "inventory budget|incomplete"):
                        manager.unseal(output, staging / "restored.tar", root / "synthetic.pem", root / "synthetic.key", staging, link)
                with self.assertRaisesRegex(Refused, "must be new"):
                    manager.seal(archive, output, root / "synthetic.pem", staging, metadata)
            self.assertEqual(archive.read_bytes(), body)
            self.assertFalse((staging / "restored.tar").exists())


if __name__ == "__main__":
    unittest.main()
