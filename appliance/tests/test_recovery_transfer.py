"""Small real filesystem fixtures; no receiver, key unlock or appliance runtime.

Only Linux/root/encrypted-volume admission and capacity observations are fixture
substitutions. Directory ownership remains checked against this process inside
its 0700 fixture; file modes, symlinks, inode identity, flock, writes and fsync are
real. Synthetic credential envelopes test structure, not cryptographic validity.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from nebulalog_manager import recovery_transfer as transfer
from nebulalog_manager.common import Refused
from test_recovery_media import encrypted_pem


def sha(value):
    return hashlib.sha256(value).hexdigest()


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "transfers"
        self.owner = transfer.Owner(str(uuid.uuid4()), sha(b"subject"), sha(b"session"))
        self.policy = transfer.Policy(64 * 1024**2, transfer.MIN_RESERVE)
        self.encrypted = Mock()
        self.commands = Mock(side_effect=AssertionError("No command may run in transfer fixtures"))
        self.capacity = SimpleNamespace(f_bavail=100 * 1024**3, f_blocks=200 * 1024**3, f_frsize=1)
        for target, replacement in (("require_linux_root", Mock()), ("ROOT_UID", os.getuid()),
                                    ("_directory", self.directory), ("_encrypted_staging", self.encrypted)):
            replacement_patch = patch.object(transfer, target, replacement)
            replacement_patch.start()
            self.addCleanup(replacement_patch.stop)
        replacement_patch = patch.object(transfer.os, "statvfs", return_value=self.capacity)
        replacement_patch.start()
        self.addCleanup(replacement_patch.stop)
        self.manager = transfer.RecoveryTransfer(self.owner, self.policy, root=self.root, commands=self.commands)
        self.inputs = {"configuration.cms": b"opaque configuration ciphertext",
                       "recipient.pem": b"-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n",
                       "recovery-key.pk8": encrypted_pem()}

    def directory(self, path, *, private=False, create=False):
        path = Path(path)
        self.assertTrue(path.is_relative_to(self.base), "Fixture must remain in owned temporary directory")
        for item in reversed((path, *[p for p in path.parents if p.is_relative_to(self.base)])):
            if create and not os.path.lexists(item): item.mkdir(mode=0o700)
            info = item.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise Refused("Unsafe fixture directory")
        if private and path.stat().st_mode & 0o077:
            raise Refused("Fixture directory is not private")

    def create(self, inputs=None, *, request=None, **overrides):
        inputs = self.inputs if inputs is None else inputs
        full = "logs/manifest.cms" in inputs
        options = dict(scope="full" if full else "configuration", chunk_count=len(inputs) - 4 if full else 0,
                       total_bytes=sum(map(len, inputs.values())))
        options.update(overrides)
        self.request = request or str(uuid.uuid4())
        result = self.manager.create(self.request, **options)
        self.identifier = result["id"]
        return result

    def declare(self, name, value, **overrides):
        metadata = dict(name=name, bytes=len(value), sha256=sha(value))
        metadata.update(overrides)
        return self.manager.declare(self.identifier, metadata)["id"]

    def append(self, object_id, value, *, offset=0, **overrides):
        options = dict(offset=offset, length=len(value), sha256=sha(value), stream=io.BytesIO(value))
        options.update(overrides)
        return self.manager.append(self.identifier, object_id, **options)

    def journal(self, object_id=None):
        path = self.root / self.identifier
        path = path / "objects" / (object_id + ".json") if object_id else path / "transfer.json"
        return json.loads(path.read_text())

    def payload(self, name="configuration.cms"):
        return self.root / self.identifier / "payload" / name

    def fill(self, inputs=None):
        objects = {}
        for name, value in (self.inputs if inputs is None else inputs).items():
            object_id = self.declare(name, value)
            objects[name] = object_id
            self.append(object_id, value)
            self.manager.finalize_object(self.identifier, object_id)
        return objects

    def test_configuration_round_trip_immutable_idempotency_and_private_modes(self):
        first = self.create()
        self.assertEqual(first, self.create(request=self.request))
        objects = self.fill()
        object_id = objects["configuration.cms"]
        self.assertEqual(self.declare("configuration.cms", self.inputs["configuration.cms"]), object_id)
        self.assertTrue(self.append(object_id, self.inputs["configuration.cms"])["retry"])
        self.manager.finalize_object(self.identifier, object_id)
        sealed = self.manager.seal(self.identifier)
        self.assertEqual(sealed, self.manager.seal(self.identifier))
        self.assertFalse(sealed["authenticated"])
        self.assertFalse(sealed["coordinator_ready"])
        self.assertEqual(self.create(request=self.request)["state"], "sealed")
        with self.assertRaises(Refused): self.append(object_id, self.inputs["configuration.cms"])
        for path in self.root.rglob("*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        self.encrypted.assert_called_with(self.base, self.commands)
        self.commands.assert_not_called()

    def test_full_inventory_pages_and_fixed_chunk_order(self):
        inputs = {**self.inputs, "logs/manifest.cms": b"opaque manifest", "logs/chunks/000000.cms": b"chunk zero",
                  "logs/chunks/000001.cms": b"chunk one"}
        self.create(inputs)
        page = self.manager.status(self.identifier, limit=2)
        self.assertEqual(page["next_cursor"], 2)
        self.assertEqual([r["state"] for r in page["objects"]], ["undeclared", "undeclared"])
        self.fill(dict(reversed(list(inputs.items()))))
        names, cursor = [], 0
        while cursor is not None:
            page = self.manager.status(self.identifier, cursor=cursor, limit=2)
            names += [row["name"] for row in page["objects"]]
            cursor = page["next_cursor"]
        self.assertEqual(names, list(inputs))
        self.assertEqual(self.manager.seal(self.identifier)["state"], "sealed")
        self.assertEqual(self.manager.status(self.identifier, cursor=6)["objects"], [])
        for options in ({"cursor": 7}, {"limit": 129}, {"limit": False}, {"cursor": "0"}):
            with self.subTest(options=options), self.assertRaises(Refused):
                self.manager.status(self.identifier, **options)

    def test_fixed_segment_grid_and_bounded_stream_reads(self):
        # Production grid is 4 MiB; shrink it only for tiny filesystem fixtures.
        data = b"abcdefghijklmnopqrst"
        inputs = {**self.inputs, "configuration.cms": data}
        self.create(inputs)
        object_id = self.declare("configuration.cms", data)
        with patch.object(transfer, "SEGMENT_BYTES", 8), patch.object(transfer, "COPY_BYTES", 3):
            for offset in (0, 8, 16):
                part = data[offset:offset + 8]
                reader = Mock(wraps=io.BytesIO(part))
                self.append(object_id, part, offset=offset, stream=reader)
                self.assertLessEqual(max(call.args[0] for call in reader.read.call_args_list), 3)
            self.assertTrue(self.append(object_id, data[8:16], offset=8)["retry"])
            for offset, value in ((1, data[1:9]), (0, data[:4]), (16, b"extra-long"), (24, b"x")):
                with self.subTest(offset=offset), self.assertRaises(Refused): self.append(object_id, value, offset=offset)
        self.assertEqual(self.payload().read_bytes(), data)
        self.manager.finalize_object(self.identifier, object_id)

    def test_fixed_names_exact_metadata_and_scalar_bounds(self):
        self.create()
        for name in ("../configuration.cms", "/configuration.cms", "logs/manifest.cms", "configuration.cms/x",
                     "configuration.cms\0", "recipient.pem ", ["configuration.cms"]):
            with self.subTest(name=name), self.assertRaises(Refused): self.declare(name, b"x")
        for changes in ({"bytes": True}, {"bytes": 0}, {"sha256": "A" * 64}, {"bytes": transfer.ARCHIVE_LIMIT + 1}, {"extra": 1}):
            with self.subTest(changes=changes), self.assertRaises(Refused): self.declare("configuration.cms", b"x", **changes)
        for options in ({"chunk_count": False}, {"scope": "invalid"}, {"total_bytes": True}, {"total_bytes": self.policy.maximum_bytes + 1}):
            with self.subTest(options=options), self.assertRaises(Refused): self.create(**options)
        with self.assertRaises(Refused): self.manager.status("../outside")
        with self.assertRaises(Refused): transfer.RecoveryTransfer({}, self.policy, root=self.root)

    def test_owner_session_policy_and_active_transfer_are_host_bindings(self):
        self.create()
        for owner, policy in ((transfer.Owner(self.owner.installation_id, self.owner.subject_sha256, sha(b"different-session")), self.policy),
                              (transfer.Owner(self.owner.installation_id, sha(b"different-subject"), self.owner.session_sha256), self.policy),
                              (self.owner, transfer.Policy(self.policy.maximum_bytes + 1, transfer.MIN_RESERVE))):
            other = transfer.RecoveryTransfer(owner, policy, root=self.root)
            with self.assertRaises(Refused): other.status(self.identifier)
        with self.assertRaises(Refused): self.create()

    def test_capacity_and_aggregate_bounds_precede_payload_effects(self):
        self.capacity.f_bavail = transfer.MIN_RESERVE
        with self.assertRaises(Refused): self.create()
        self.assertFalse(any(p.is_dir() for p in self.root.iterdir()))
        self.capacity.f_bavail = 100 * 1024**3
        self.create(total_bytes=3)
        with self.assertRaises(Refused): self.declare("configuration.cms", b"four")
        object_id = self.declare("configuration.cms", b"x")
        self.capacity.f_bavail = transfer.MIN_RESERVE
        with self.assertRaises(Refused): self.append(object_id, b"x")
        self.assertEqual(self.payload().read_bytes(), b"")
        self.assertIsNone(self.journal(object_id)["pending"])
        self.capacity.f_bavail = 100 * 1024**3
        source = io.BytesIO(b"x")
        def consumes_margin(size):
            value = source.read(size)
            if not value: self.capacity.f_bavail = transfer.MIN_RESERVE
            return value
        with self.assertRaisesRegex(Refused, "reserve"):
            self.append(object_id, b"x", stream=Mock(read=consumes_margin))
        self.assertEqual(self.payload().read_bytes(), b"")
        self.assertIsNone(self.journal(object_id)["pending"])

    def test_retained_sealed_transfers_count_toward_host_allocation(self):
        total = sum(map(len, self.inputs.values()))
        self.policy = transfer.Policy(total, transfer.MIN_RESERVE)
        self.manager = transfer.RecoveryTransfer(self.owner, self.policy, root=self.root)
        self.create()
        self.fill()
        self.manager.seal(self.identifier)
        with self.assertRaisesRegex(Refused, "allocation"): self.create()

    def test_stream_truncation_overflow_hash_and_type_fail_before_intent(self):
        self.create()
        object_id = self.declare("configuration.cms", b"four")
        for stream, checksum in ((io.BytesIO(b"bad"), sha(b"four")), (io.BytesIO(b"fours"), sha(b"four")),
                                 (io.BytesIO(b"four"), sha(b"wrong")), (Mock(read=lambda size: "text"), sha(b"four")),
                                 (Mock(read=lambda size: b"x" * (size + 1)), sha(b"four"))):
            with self.subTest(checksum=checksum), self.assertRaises(Refused):
                self.append(object_id, b"four", stream=stream, sha256=checksum)
            self.assertEqual(self.payload().read_bytes(), b"")
            self.assertIsNone(self.journal(object_id)["pending"])
            self.assertEqual(list((self.root / self.identifier / "scratch").iterdir()), [])

    def test_bad_credential_structure_never_enters_payload(self):
        for name, value in (("recipient.pem", self.inputs["recipient.pem"] + b"appended key"),
                            ("recovery-key.pk8", b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
                            ("recovery-key.pk8", encrypted_pem(iterations=2000001))):
            with self.subTest(name=name):
                # Independent root per invalid case; retained failed inputs remain immutable.
                self.root = self.base / str(uuid.uuid4())
                self.manager = transfer.RecoveryTransfer(self.owner, self.policy, root=self.root)
                self.create({**self.inputs, name: value})
                object_id = self.declare(name, value)
                with self.assertRaises(Refused): self.append(object_id, value)
                self.assertEqual(self.payload(name).read_bytes(), b"")
                self.assertIsNone(self.journal(object_id)["pending"])
                self.commands.assert_not_called()

    def test_wrong_object_hash_and_retry_content_cannot_overwrite(self):
        self.create()
        object_id = self.declare("configuration.cms", b"four", sha256=sha(b"five"))
        self.append(object_id, b"four")
        with self.assertRaises(Refused): self.manager.finalize_object(self.identifier, object_id)
        with self.assertRaises(Refused): self.append(object_id, b"five")
        with self.assertRaises(Refused): self.declare("configuration.cms", b"four")
        self.assertEqual(self.payload().read_bytes(), b"four")

    def test_declaration_checkpoint_loss_reconciles_once(self):
        self.create()
        original = self.manager._txsave
        def save(tx):
            if tx["declared_count"] == 1 and tx["pending"] is None:
                raise OSError("injected acknowledgement loss before final journal")
            original(tx)
        with patch.object(self.manager, "_txsave", side_effect=save), self.assertRaises(OSError):
            self.declare("configuration.cms", b"four")
        with self.assertRaises(Refused): self.declare("recipient.pem", b"x")
        object_id = self.declare("configuration.cms", b"four")
        self.assertEqual(self.declare("configuration.cms", b"four"), object_id)
        self.assertEqual(self.journal()["declared_count"], 1)
        self.assertEqual(self.journal()["declared_bytes"], 4)

    def test_complete_write_with_lost_checkpoint_reconciles_without_rewrite(self):
        self.create()
        object_id = self.declare("configuration.cms", b"four")
        original = transfer._save
        def save(path, value):
            if path.name == object_id + ".json" and value["offset"] == 4 and value["pending"] is None:
                raise OSError("injected checkpoint loss")
            original(path, value)
        with patch.object(transfer, "_save", side_effect=save), self.assertRaises(OSError): self.append(object_id, b"four")
        self.assertIsNotNone(self.journal(object_id)["pending"])
        self.assertEqual(self.manager.status(self.identifier)["objects"][0]["state"], "uncertain")
        with self.assertRaises(Refused): self.append(object_id, b"five")
        with patch.object(transfer.os, "pwrite", side_effect=AssertionError("No rewrite on reconciliation")):
            self.append(object_id, b"four")
        self.assertIsNone(self.journal(object_id)["pending"])
        self.assertEqual(self.journal(object_id)["offset"], 4)
        self.assertEqual(self.payload().read_bytes(), b"four")

    def test_partial_or_zero_uncertain_writes_remain_preserved(self):
        for partial in (False, True):
            with self.subTest(partial=partial):
                self.root = self.base / str(uuid.uuid4())
                self.manager = transfer.RecoveryTransfer(self.owner, self.policy, root=self.root)
                self.create()
                object_id = self.declare("configuration.cms", b"four")
                original = os.pwrite
                def failed(fd, value, offset):
                    if partial: original(fd, value[:2], offset)
                    raise OSError("injected interrupted write")
                with patch.object(transfer.os, "pwrite", side_effect=failed), self.assertRaises(OSError): self.append(object_id, b"four")
                retained = self.payload().read_bytes()
                with self.assertRaises(Refused): self.append(object_id, b"four")
                self.assertEqual(self.payload().read_bytes(), retained)
                self.assertIsNotNone(self.journal(object_id)["pending"])

    def test_retry_after_commit_ack_loss_reestablishes_metadata_directory_barrier(self):
        self.create()
        object_id = self.declare("configuration.cms", b"four")
        original = transfer._save
        def save(path, value):
            original(path, value)
            if path.name == object_id + ".json" and value["offset"] == 4:
                raise OSError("injected response loss after durable commit")
        with patch.object(transfer, "_save", side_effect=save), self.assertRaises(OSError): self.append(object_id, b"four")
        with patch.object(transfer, "_sync", wraps=transfer._sync) as synced:
            self.assertTrue(self.append(object_id, b"four")["retry"])
        self.assertIn(self.root / self.identifier / "objects", [c.args[0] for c in synced.call_args_list])

    def test_payload_durability_precedes_committed_offset(self):
        self.create()
        object_id = self.declare("configuration.cms", b"four")
        events = []
        fsync, sync, save = os.fsync, transfer._sync, transfer._save
        inode = self.payload().stat().st_ino
        def recorded_fsync(fd):
            if os.fstat(fd).st_ino == inode: events.append("data")
            return fsync(fd)
        def recorded_sync(path):
            if path == self.payload().parent: events.append("directory")
            return sync(path)
        def recorded_save(path, value):
            if path.name == object_id + ".json": events.append("intent" if value["pending"] else "commit")
            return save(path, value)
        with patch.object(transfer.os, "fsync", side_effect=recorded_fsync), patch.object(transfer, "_sync", side_effect=recorded_sync), patch.object(transfer, "_save", side_effect=recorded_save):
            self.append(object_id, b"four")
        self.assertEqual([e for e in events if e in ("intent", "data", "directory", "commit")], ["intent", "data", "directory", "commit"])

    def test_replacement_links_fifo_and_permissions_are_refused(self):
        for mutation in ("replacement", "symlink", "hardlink", "fifo", "mode"):
            with self.subTest(mutation=mutation):
                self.root = self.base / str(uuid.uuid4())
                self.manager = transfer.RecoveryTransfer(self.owner, self.policy, root=self.root)
                self.create()
                object_id = self.declare("configuration.cms", b"four")
                path = self.payload()
                other = self.base / (str(uuid.uuid4()) + ".data")
                other.write_bytes(b"")
                other.chmod(0o600)
                if mutation == "mode": path.chmod(0o644)
                else:
                    path.unlink()
                    if mutation == "symlink": path.symlink_to(other)
                    elif mutation == "hardlink": os.link(other, path)
                    elif mutation == "fifo": os.mkfifo(path, 0o600)
                    else: os.replace(other, path)
                previous = signal.signal(signal.SIGALRM, lambda *args: (_ for _ in ()).throw(RuntimeError("FIFO blocked")))
                signal.alarm(5)
                try:
                    with self.assertRaises((Refused, OSError)): self.append(object_id, b"four")
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, previous)

    def test_completed_mutation_and_unexpected_inventory_refuse_seal(self):
        self.create()
        self.fill()
        path = self.payload()
        value = path.read_bytes()
        path.write_bytes(value[:-1] + b"!")
        with self.assertRaises(Refused): self.manager.seal(self.identifier)
        path.write_bytes(value)
        # T9 may report equal timestamps for adjacent same-size writes. Force a
        # distinct timestamp to exercise identity rejection after restoring bytes.
        info = path.stat()
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
        with self.assertRaisesRegex(Refused, "changed"): self.manager.seal(self.identifier)

    def test_unexpected_object_and_payload_members_and_scratch_are_preserved(self):
        self.create()
        self.fill()
        stage = self.root / self.identifier
        for directory in ("objects", "payload", "scratch"):
            extra = stage / directory / "unexpected"
            extra.write_bytes(b"retained evidence")
            extra.chmod(0o600)
            with self.subTest(directory=directory), self.assertRaises(Refused): self.manager.seal(self.identifier)
            self.assertEqual(extra.read_bytes(), b"retained evidence")
            extra.unlink()
        self.assertEqual(self.manager.seal(self.identifier)["state"], "sealed")

    def test_retained_scratch_refuses_new_segment_without_deletion(self):
        self.create()
        object_id = self.declare("configuration.cms", b"four")
        leftover = self.root / self.identifier / "scratch" / "segment-crash"
        leftover.write_bytes(b"uncertain ciphertext")
        leftover.chmod(0o600)
        with self.assertRaisesRegex(Refused, "scratch"): self.append(object_id, b"four")
        self.assertEqual(leftover.read_bytes(), b"uncertain ciphertext")
        self.assertEqual(self.payload().read_bytes(), b"")

    def exit_child(self, action):
        """An owned local child exits without Python cleanup, like lost power."""
        pid = os.fork()
        if pid == 0:
            try: action()
            except BaseException: os._exit(99)
            os._exit(98)
        end = time.monotonic() + 10
        while time.monotonic() < end:
            observed, status = os.waitpid(pid, os.WNOHANG)
            if observed:
                self.assertEqual(os.waitstatus_to_exitcode(status), 73)
                return
            time.sleep(0.01)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        self.fail("Owned abrupt-exit child exceeded its test bound")

    def test_process_exit_with_complete_range_and_scratch_resumes_exactly(self):
        self.create()
        object_id = self.declare("configuration.cms", b"four")
        def child():
            original = transfer._save
            def save(path, value):
                if path.name == object_id + ".json" and value["offset"] == 4 and value["pending"] is None:
                    os._exit(73)
                original(path, value)
            with patch.object(transfer, "_save", side_effect=save): self.append(object_id, b"four")
        self.exit_child(child)
        scratch = self.root / self.identifier / "scratch"
        self.assertEqual(len(list(scratch.iterdir())), 1)
        self.assertEqual(self.payload().read_bytes(), b"four")
        with patch.object(transfer.os, "pwrite", side_effect=AssertionError("Never rewrite recovered bytes")):
            self.append(object_id, b"four")
        self.assertEqual(list(scratch.iterdir()), [])
        self.assertEqual(self.journal(object_id)["offset"], 4)
        self.assertIsNone(self.journal(object_id)["pending"])

    def test_process_exit_partial_scratch_is_preserved_without_data_intent(self):
        self.create()
        object_id = self.declare("configuration.cms", b"four")
        def child():
            calls = 0
            def read(size):
                nonlocal calls
                calls += 1
                if calls == 2: os._exit(73)
                return b"fo"
            with patch.object(transfer, "COPY_BYTES", 2): self.append(object_id, b"four", stream=Mock(read=read))
        self.exit_child(child)
        scratch = list((self.root / self.identifier / "scratch").iterdir())
        self.assertEqual(len(scratch), 1)
        self.assertEqual(scratch[0].read_bytes(), b"fo")
        with self.assertRaisesRegex(Refused, "scratch segment"): self.append(object_id, b"four")
        self.assertEqual(scratch[0].read_bytes(), b"fo")
        self.assertEqual(self.payload().read_bytes(), b"")
        self.assertIsNone(self.journal(object_id)["pending"])

    def test_maximum_inventory_status_is_bounded_without_object_ledger(self):
        self.create(scope="full", chunk_count=transfer.MAX_CHUNKS, total_bytes=transfer.MAX_OBJECTS)
        stage = self.root / self.identifier
        self.assertLess((stage / "transfer.json").stat().st_size, transfer.METADATA_BYTES)
        self.assertEqual(list((stage / "objects").iterdir()), [])
        page = self.manager.status(self.identifier)
        self.assertEqual(len(page["objects"]), transfer.PAGE_LIMIT)
        final = self.manager.status(self.identifier, cursor=transfer.MAX_OBJECTS - 1)
        self.assertEqual(final["objects"], [{"name": "logs/chunks/262143.cms", "state": "undeclared"}])
        for name in ("logs/chunks/262144.cms", "logs/chunks/0000000.cms", "logs/chunks/../000001.cms"):
            with self.subTest(name=name), self.assertRaises(Refused): self.declare(name, b"x")

    def test_creation_ack_loss_before_active_publication_blocks_second_open(self):
        original = transfer._save
        def failed(path, value):
            if path.name == "active.json": raise OSError("injected loss before active publication")
            return original(path, value)
        with patch.object(transfer, "_save", side_effect=failed), self.assertRaises(OSError): self.create()
        request = self.request
        retained = [path for path in self.root.iterdir() if path.is_dir()]
        self.assertEqual(len(retained), 1)
        self.assertFalse((self.root / "active.json").exists())
        with self.assertRaisesRegex(Refused, "unfinished retained"): self.create()
        self.assertEqual([path for path in self.root.iterdir() if path.is_dir()], retained)
        self.assertEqual(self.create(request=request)["id"], retained[0].name)
        self.assertEqual(json.loads((self.root / "active.json").read_text()), {"id": retained[0].name})

    def test_new_declaration_and_finalize_do_not_allocate_below_reserve(self):
        self.create()
        self.capacity.f_bavail = transfer.MIN_RESERVE
        with self.assertRaisesRegex(Refused, "reserve"): self.declare("configuration.cms", b"four")
        self.assertEqual(self.journal()["declared_count"], 0)
        self.assertIsNone(self.journal()["pending"])
        self.assertEqual(list((self.root / self.identifier / "objects").iterdir()), [])
        self.assertFalse(self.payload().exists())
        self.capacity.f_bavail = 100 * 1024**3
        object_id = self.declare("configuration.cms", b"four")
        self.append(object_id, b"four")
        self.capacity.f_bavail = transfer.MIN_RESERVE
        # Exact existing declaration only performs readback/directory barriers.
        self.assertEqual(self.declare("configuration.cms", b"four"), object_id)
        with self.assertRaisesRegex(Refused, "reserve"): self.manager.finalize_object(self.identifier, object_id)
        self.assertEqual(self.journal(object_id)["state"], "receiving")


if __name__ == "__main__":
    unittest.main()
