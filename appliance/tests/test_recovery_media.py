"""Small optical-delivery fixtures; no device, mount, guest or service operation."""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import recovery_media as media
from nebulalog_manager.common import CommandFailed, Refused


def tlv(tag, value):
    length = bytes([len(value)]) if len(value) < 128 else bytes([0x82]) + len(value).to_bytes(2, "big")
    if len(value) >= 128 and len(value) < 256:
        length = bytes([0x81, len(value)])
    return bytes([tag]) + length + value


def encrypted_pem(iterations=100000, salt=b"s" * 16, prf="2a864886f70d0209", cipher="60864801650304012a"):
    oid = lambda value: tlv(6, bytes.fromhex(value))
    sequence = lambda value: tlv(0x30, value)
    integer = iterations.to_bytes((iterations.bit_length() + 7) // 8 or 1, "big")
    if integer[0] & 128:
        integer = b"\0" + integer
    work = sequence(tlv(4, salt) + tlv(2, integer) + sequence(oid(prf) + tlv(5, b"")))
    parameters = sequence(sequence(oid("2a864886f70d01050c") + work)
                          + sequence(oid(cipher) + tlv(4, b"i" * 16)))
    data = sequence(sequence(oid("2a864886f70d01050d") + parameters) + tlv(4, b"x" * 32))
    return b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + base64.b64encode(data) + b"\n-----END ENCRYPTED PRIVATE KEY-----\n"


class FileBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "media"
        self.source.mkdir()
        for name in media.INPUTS:
            (self.source / name).write_bytes(b"small synthetic bytes")
        self.descriptor = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.descriptor)

    def test_exact_inventory_and_private_hash_copy(self):
        inventory = media._inventory(self.descriptor)
        target = self.root / "pinned"
        digest = media._copy(self.descriptor, "backup.cms", inventory["backup.cms"], target)
        self.assertEqual(digest, hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_extra_missing_link_special_and_oversize_files_are_refused(self):
        extra = self.source / "unexpected"
        extra.write_text("x")
        with self.assertRaises(Refused): media._inventory(self.descriptor)
        extra.unlink()
        path = self.source / "backup.cms"
        path.unlink()
        with self.assertRaises(Refused): media._inventory(self.descriptor)
        path.symlink_to(self.source / "recipient.pem")
        with self.assertRaises(Refused): media._inventory(self.descriptor)
        path.unlink()
        os.link(self.source / "recipient.pem", path)
        with self.assertRaises(Refused): media._inventory(self.descriptor)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(Refused): media._inventory(self.descriptor)
        path.unlink()
        path.write_bytes(b"x" * 20)
        with patch.dict(media.INPUTS, {"backup.cms": 10}), self.assertRaises(Refused):
            media._inventory(self.descriptor)

    def test_growth_replacement_and_fifo_after_admission_are_refused(self):
        path = self.source / "backup.cms"
        for mutation in ("growth", "replacement", "fifo"):
            with self.subTest(mutation=mutation):
                if path.exists(): path.unlink()
                path.write_bytes(b"original")
                info = path.stat()
                if mutation == "growth":
                    path.write_bytes(b"original plus unexpected bytes")
                else:
                    replacement = self.root / "new-source"
                    if mutation == "fifo": os.mkfifo(replacement)
                    else: replacement.write_bytes(b"original")
                    os.replace(replacement, path)
                previous = signal.signal(signal.SIGALRM, lambda *args: (_ for _ in ()).throw(RuntimeError("FIFO open blocked")))
                signal.alarm(10)
                try:
                    with self.assertRaisesRegex(Refused, "changed before"):
                        media._copy(self.descriptor, "backup.cms", info, self.root / mutation)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, previous)

    def test_existing_destination_is_never_overwritten(self):
        target = self.root / "retained"
        target.write_bytes(b"retained evidence")
        with self.assertRaises(FileExistsError):
            media._copy(self.descriptor, "backup.cms", (self.source / "backup.cms").stat(), target)
        self.assertEqual(target.read_bytes(), b"retained evidence")


class KeyAdmissionTests(unittest.TestCase):
    def test_strict_pbes2_cost_and_algorithm_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "encrypted.pem"
            path.write_bytes(encrypted_pem())
            media.encrypted_key_parameters(path)
            invalid = [encrypted_pem(iterations=99999), encrypted_pem(iterations=2000001),
                       encrypted_pem(salt=b"s" * 8), encrypted_pem(prf="2a864886f70d0207"),
                       encrypted_pem(cipher="608648016503040102"),
                       b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
                       encrypted_pem() + b"extra", encrypted_pem().replace(b"eHh4", b"!Hh4", 1)]
            for value in invalid:
                with self.subTest(prefix=value[:30]), self.assertRaises(Refused):
                    path.write_bytes(value)
                    media.encrypted_key_parameters(path)

    def test_passphrase_prompt_has_no_echo_fallback(self):
        with patch.object(media.sys, "stdin", Mock(isatty=lambda: False)), self.assertRaises(Refused):
            media.read_passphrase()

    def test_invalid_secret_input_is_refused_without_quoting_or_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            commands = Mock()
            inputs = media.ImportedInputs(Path(temporary), "a" * 64, commands)
            for secret in ("short-secret", "synthetic-secret\nmore", "synthetic-secret\udcff", "x" * 1025, None):
                with self.subTest(kind=type(secret).__name__), self.assertRaises(Refused) as caught:
                    inputs.unlock(secret)
                self.assertNotIn("synthetic-secret", str(caught.exception))
                self.assertFalse((inputs.directory / "private-key.pem").exists())
            commands.assert_not_called()
        with patch.object(media.sys, "stdin", Mock(isatty=lambda: True)), \
                patch.object(media.sys, "stderr", Mock(isatty=lambda: True)), \
                patch.object(media.resource, "setrlimit"), \
                patch.object(media.getpass, "getpass", side_effect=media.getpass.GetPassWarning("secret")), self.assertRaises(Refused):
            media.read_passphrase()


class MountPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.mount = self.root / "mount"
        self.mount.mkdir()
        self.device = Path("/dev/sr0")
        self.info = SimpleNamespace(st_rdev=os.makedev(11, 0))
        self.evidence = {"target": str(self.mount), "source": str(self.device), "fstype": "iso9660",
                         "options": ",".join(sorted(media.OPTIONS)), "maj:min": "11:0"}
        self.manager = media.RecoveryMedia(Mock(), data=self.root, mount=self.mount)

    def test_exact_device_filesystem_and_protected_mount_options(self):
        with patch.object(self.manager, "_mount_info", return_value=self.evidence):
            self.manager._verify_mount(self.device, self.info)
        for key, value in (("source", "/dev/sda"), ("target", "/elsewhere"), ("fstype", "udf"),
                           ("options", "ro,nodev,nosuid,noexec"), ("options", self.evidence["options"] + ",rw"),
                           ("maj:min", "11:1")):
            with self.subTest(key=key), patch.object(self.manager, "_mount_info", return_value={**self.evidence, key: value}), self.assertRaises(Refused):
                self.manager._verify_mount(self.device, self.info)

    def test_mount_cleanup_runs_on_input_failure_and_never_uses_force(self):
        device_file = self.root / "device-fixture"
        device_file.write_bytes(b"inert")
        real_stat = device_file.stat()
        attributes = {name: getattr(real_stat, name) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
        fake = SimpleNamespace(**{**attributes, "st_mode": stat.S_IFBLK | 0o600, "st_uid": media.ROOT_UID}, st_rdev=os.makedev(11, 0))
        original_open, original_fstat, original_lstat = os.open, os.fstat, Path.lstat
        opened, calls = [], []
        mounted = False

        def open_fixture(path, flags, *args, **kwargs):
            if path == self.device:
                self.assertTrue(flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW)
                result = original_open(device_file, flags)
                opened.append(result)
                return result
            return original_open(path, flags, *args, **kwargs)

        def command(argv, **kwargs):
            nonlocal mounted
            calls.append(argv)
            if argv[0] == "findmnt":
                if not mounted: raise CommandFailed("findmnt", 1)
                return json.dumps({"filesystems": [self.evidence]})
            if argv[0] == "mount": mounted = True
            elif argv[0] == "umount": mounted = False
            else: raise AssertionError("Unexpected command")
            return ""

        self.manager.cmd = command
        with patch.object(media, "_directory"), patch.object(Path, "lstat", lambda path: fake if path == self.device else original_lstat(path)), \
                patch.object(media.os, "open", side_effect=open_fixture), \
                patch.object(media.os, "fstat", side_effect=lambda fd: fake if fd in opened else original_fstat(fd)):
            with self.assertRaisesRegex(Refused, "synthetic input failure"):
                with self.manager._mounted(self.device):
                    raise Refused("synthetic input failure")
        self.assertFalse(mounted)
        mount = next(call for call in calls if call[0] == "mount")
        self.assertEqual(set(mount[mount.index("--options") + 1].split(",")), media.OPTIONS)
        self.assertIn(["umount", "--", str(self.mount)], calls)
        with self.assertRaises(OSError): original_fstat(opened[0])

    def test_no_automatic_device_selection_or_reuse_of_existing_mount(self):
        for device in (Path("/dev/sda"), Path("/dev/cdrom"), Path("relative"), Path("/dev/sr0;id")):
            with self.subTest(device=device), self.assertRaises(Refused):
                with self.manager._mounted(device): self.fail("must not yield")
        self.manager.cmd.assert_not_called()


class RealCryptoDeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which("openssl")
        if not cls.openssl or "-saltlen" not in subprocess.run([cls.openssl, "pkcs8", "-help"], capture_output=True, text=True).stderr:
            raise unittest.SkipTest("OpenSSL with explicit PKCS#8 salt length is unavailable")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.key, cls.certificate = cls.root / "original.key", cls.root / "recipient.pem"
        cls.passphrase = "synthetic fixture passphrase only"

        def command(argv, input=None):
            proc = subprocess.run([cls.openssl, *argv], input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if proc.returncode: raise AssertionError("Synthetic OpenSSL fixture generation failed")
            return proc.stdout
        command(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cls.key), "-out", str(cls.certificate), "-subj", "/CN=synthetic-recovery", "-days", "1"])
        command(["pkcs8", "-topk8", "-in", str(cls.key), "-out", str(cls.root / "recovery-key.pk8"), "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-iter", "100000", "-saltlen", "16", "-passout", "stdin"], input=cls.passphrase.encode() + b"\n")
        plain = cls.root / "synthetic.txt"
        plain.write_bytes(b"synthetic configuration envelope; no restore is performed")
        command(["cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER", "-in", str(plain), "-out", str(cls.root / "backup.cms"), str(cls.certificate)])
        for path in cls.root.iterdir(): path.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temporary"): cls.temporary.cleanup()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.source = self.work / "media"
        self.source.mkdir()
        for name in media.INPUTS: shutil.copyfile(self.root / name, self.source / name)
        self.calls = []

    def commands(self, argv, *, input=None, timeout=120):
        self.calls.append((argv, input))
        # Host prlimit is substituted only in this macOS crypto fixture. The
        # production argv still carries its file-size and core-dump bounds.
        real = argv[argv.index("--") + 1:] if argv[0] == "prlimit" else argv
        if real[0] != "openssl": raise AssertionError("No mount or runtime command is permitted")
        proc = subprocess.run([self.openssl, *real[1:]], input=input, capture_output=True, timeout=timeout)
        if proc.returncode: raise CommandFailed("openssl", proc.returncode)
        return proc.stdout.decode().strip()

    @contextmanager
    def mounted_fixture(self, device):
        descriptor = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        try: yield descriptor
        finally: os.close(descriptor)

    @contextmanager
    def imported(self):
        manager = media.RecoveryMedia(self.commands, data=self.work, mount=self.work / "mount")
        def directory(path, **kwargs): path.mkdir(mode=0o700, parents=True, exist_ok=True)
        with patch.object(media, "require_linux_root"), patch.object(media, "_encrypted_staging"), \
                patch.object(media, "_directory", side_effect=directory), patch.object(media, "ROOT_UID", os.getuid()), \
                patch.object(manager, "_mounted", side_effect=self.mounted_fixture):
            with manager.staged(Path("/dev/sr0")) as result: yield result

    def test_real_encrypted_key_and_cms_admission_then_cleanup(self):
        with self.imported() as inputs:
            directory = inputs.directory
            self.assertEqual(inputs.backup_sha256, hashlib.sha256((self.source / "backup.cms").read_bytes()).hexdigest())
            key = inputs.unlock(self.passphrase)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertTrue(key.exists())
        self.assertFalse(directory.exists())
        key_command, secret = next((argv, value) for argv, value in self.calls if "pkcs8" in argv)
        self.assertEqual(secret, self.passphrase.encode() + b"\n")
        self.assertNotIn(self.passphrase, " ".join(key_command))
        self.assertIn("--fsize=65536", key_command)
        self.assertEqual(set(path.name for path in self.source.iterdir()), set(media.INPUTS))

    def test_wrong_passphrase_removes_private_scratch(self):
        with self.assertRaises(CommandFailed):
            with self.imported() as inputs:
                directory = inputs.directory
                inputs.unlock("a wrong fixture passphrase")
        self.assertFalse(directory.exists())

    def test_capacity_refusal_occurs_before_any_key_operation(self):
        with patch.object(media.shutil, "disk_usage", return_value=SimpleNamespace(free=0)), self.assertRaisesRegex(Refused, "Insufficient encrypted scratch"):
            with self.imported(): self.fail("No imported inputs may be published")
        self.assertEqual(self.calls, [])
        self.assertEqual(set(path.name for path in self.source.iterdir()), set(media.INPUTS))

    def test_certificate_file_cannot_smuggle_an_appended_private_key(self):
        with (self.source / "recipient.pem").open("ab") as stream:
            stream.write(self.key.read_bytes())
        with self.assertRaisesRegex(Refused, "one certificate PEM block"):
            with self.imported(): self.fail("Combined certificate/key media must be refused")
        self.assertEqual(self.calls, [])

    def test_decrypted_key_must_match_the_certificate(self):
        with self.imported() as inputs:
            command = inputs.commands

            def mismatched(argv, **kwargs):
                return "different public key" if argv[:2] == ["openssl", "x509"] and "-pubkey" in argv else command(argv, **kwargs)

            inputs.commands = mismatched
            with self.assertRaisesRegex(Refused, "does not match"):
                inputs.unlock(self.passphrase)
            self.assertFalse((inputs.directory / "private-key.pem").exists())

    def test_downstream_failure_removes_private_scratch(self):
        with self.assertRaisesRegex(Refused, "synthetic downstream failure"):
            with self.imported() as inputs:
                directory = inputs.directory
                inputs.unlock(self.passphrase)
                raise Refused("synthetic downstream failure")
        self.assertFalse(directory.exists())


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.recovery = Mock()
        self.recovery.status.return_value = {"state": "not_started"}
        self.operation = "11111111-2222-4333-8444-555555555555"
        self.recovery.prepare.return_value = {"id": self.operation, "scope": "configuration", "source_installation_id": self.operation,
            "target_installation_id": self.operation, "archive_sha256": "a" * 64, "expires_at": 1800000300, "review_digest": "b" * 64}
        self.inputs = Mock(backup_sha256="a" * 64, backup=Path("/private/backup.cms"), certificate=Path("/private/recipient.pem"))
        self.inputs.unlock.return_value = Path("/private/key.pem")
        self.importer = Mock()
        self.importer.staged.return_value.__enter__ = Mock(return_value=self.inputs)
        self.importer.staged.return_value.__exit__ = Mock(return_value=False)
        self.secret, self.guard = Mock(return_value="synthetic passphrase"), Mock()
        self.output = []

    def invoke(self, answers, **kwargs):
        return media.restore_from_media(self.recovery, Path("/dev/sr0"), importer=self.importer,
                                        read=Mock(side_effect=answers), write=self.output.append,
                                        secret=self.secret, guard=self.guard, **kwargs)

    def test_receipt_precedes_secret_and_authenticated_review_precedes_apply(self):
        self.invoke(["IMPORT " + "a" * 64, "RESTORE logs.example.test"], target_confirmation="RESTORE logs.example.test")
        self.recovery.prepare.assert_called_once_with(self.inputs.backup, self.inputs.unlock.return_value, self.inputs.certificate)
        self.recovery.apply_prepared.assert_called_once_with(self.operation, "b" * 64)
        self.recovery.start.assert_not_called()
        self.assertIn("Authenticated recovery review", " ".join(self.output))
        self.assertIn("independently retained", " ".join(self.output))
        self.assertIn("alone does not establish", " ".join(self.output))
        self.assertNotIn("synthetic passphrase", " ".join(self.output))
        self.assertEqual(self.guard.call_count, 4)

    def test_cancel_after_authentication_never_applies(self):
        result = self.invoke(["IMPORT " + "a" * 64, "CANCEL"])
        self.assertFalse(result["applied"])
        self.recovery.prepare.assert_called_once()
        self.recovery.apply_prepared.assert_not_called()

    def test_root_media_cli_also_requires_exact_apply_identity(self):
        self.invoke(["IMPORT " + "a" * 64, "APPLY " + self.operation])
        self.recovery.apply_prepared.assert_called_once_with(self.operation, "b" * 64)

    def test_importer_secret_scratch_closes_before_review_wait_and_apply(self):
        def read(prompt):
            if "IMPORT " in prompt:
                self.importer.staged.return_value.__exit__.assert_not_called()
                return "IMPORT " + "a" * 64
            self.importer.staged.return_value.__exit__.assert_called_once()
            return "APPLY " + self.operation
        def applied(*args):
            self.importer.staged.return_value.__exit__.assert_called_once()
            return {"state": "synthetic"}
        self.recovery.apply_prepared.side_effect = applied
        media.restore_from_media(self.recovery, Path("/dev/sr0"), importer=self.importer,
            read=read, write=self.output.append, secret=self.secret, guard=self.guard)

    def test_cancellation_retained_owner_and_changed_guard_never_start_restore(self):
        result = self.invoke(["CANCEL"])
        self.assertFalse(result["applied"])
        self.secret.assert_not_called()
        self.recovery.start.assert_not_called()
        self.recovery.apply_prepared.assert_not_called()
        self.recovery.status.return_value = {"state": "recovery_required"}
        self.importer.reset_mock()
        with self.assertRaises(Refused): self.invoke([])
        self.importer.staged.assert_not_called()
        self.recovery.status.return_value = {"state": "not_started"}
        self.guard.side_effect = [None, None, Refused("changed terminal")]
        with self.assertRaisesRegex(Refused, "changed terminal"): self.invoke(["IMPORT " + "a" * 64])
        self.inputs.unlock.assert_not_called()
        self.recovery.start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
