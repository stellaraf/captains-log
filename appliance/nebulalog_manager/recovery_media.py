"""Explicit optical-media delivery for fresh configuration recovery.

Only encrypted backup/key inputs cross the media boundary. This is not a log
recovery-set importer, a media automounter, or a replacement restore engine.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import sys
import tempfile
import warnings

from .backup import DATA, _directory, _encrypted_staging
from .common import CommandFailed, Refused, locked, require_linux_root, run
from .configuration_restore import ARCHIVE_LIMIT, authenticated_cms

ROOT_UID = 0
MOUNT = Path("/run/nebulalog/recovery-media")
INPUTS = {"backup.cms": ARCHIVE_LIMIT, "recipient.pem": 65536, "recovery-key.pk8": 65536}
OPTIONS = {"ro", "nodev", "nosuid", "noexec", "nosymfollow"}
COPY_BYTES = 1024**2
RESERVE_BYTES = 1024**3


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _inventory(descriptor):
    names = set()
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(names) == len(INPUTS):
                raise Refused("Recovery media must contain only the three named configuration recovery files")
            names.add(entry.name)
    if names != set(INPUTS):
        raise Refused("Recovery media requires backup.cms, recipient.pem and encrypted recovery-key.pk8 only")
    result = {}
    device = os.fstat(descriptor).st_dev
    for name, maximum in INPUTS.items():
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_dev != device
                or not 0 < info.st_size <= maximum):
            raise Refused("Recovery media files must be bounded regular files without links or nested mounts")
        result[name] = info
    return result


def _copy(descriptor, name, original, target):
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    digest = hashlib.sha256()
    with os.fdopen(source, "rb") as incoming, target.open("xb") as outgoing:
        os.fchmod(outgoing.fileno(), 0o600)
        if _identity(os.fstat(incoming.fileno())) != _identity(original):
            raise Refused("Recovery media changed before copy")
        remaining = original.st_size
        while remaining:
            value = incoming.read(min(remaining, COPY_BYTES))
            if not value:
                raise Refused("Recovery media was truncated during copy")
            outgoing.write(value)
            digest.update(value)
            remaining -= len(value)
        if (incoming.read(1) or _identity(os.fstat(incoming.fileno())) != _identity(original)
                or _identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) != _identity(original)):
            raise Refused("Recovery media changed during copy")
        outgoing.flush()
        os.fsync(outgoing.fileno())
    return digest.hexdigest()


class _DER:
    """Small strict reader for bounded recovery credential DER."""
    def __init__(self, data):
        self.data, self.position = data, 0

    def item(self, tag):
        start = self.position
        if start + 2 > len(self.data) or self.data[start] != tag:
            raise Refused("Unsupported recovery credential structure")
        length, start = self.data[start + 1], start + 2
        if length & 128:
            count = length & 127
            raw = self.data[start:start + count]
            if not 1 <= count <= 4 or len(raw) != count or raw[0] == 0:
                raise Refused("Unsupported recovery credential length")
            length, start = int.from_bytes(raw, "big"), start + count
            if length < 128:
                raise Refused("Noncanonical recovery credential length")
        if start + length > len(self.data):
            raise Refused("Truncated recovery credential input")
        self.position = start + length
        return self.data[start:self.position]

    def sequence(self):
        return _DER(self.item(0x30))

    def oid(self, value):
        if self.item(6) != bytes.fromhex(value):
            raise Refused("Recovery keys require PBES2/PBKDF2-SHA256/AES-256-CBC encryption")

    def integer(self):
        value = self.item(2)
        if (not 0 < len(value) <= 4 or value[0] & 128
                or len(value) > 1 and value[0] == 0 and not value[1] & 128):
            raise Refused("Invalid encrypted PKCS#8 work factor")
        return int.from_bytes(value, "big")

    def end(self):
        if self.position != len(self.data):
            raise Refused("Unexpected recovery credential parameters or trailing data")


def encrypted_key_parameters(path):
    """Refuse plaintext/legacy keys and excessive KDF work before OpenSSL."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= INPUTS["recovery-key.pk8"]:
        raise Refused("Encrypted recovery key exceeds its input budget")
    value = path.read_bytes()  # A private pinned copy, already bounded at admission.
    match = re.fullmatch(rb"-----BEGIN ENCRYPTED PRIVATE KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END ENCRYPTED PRIVATE KEY-----\r?\n?", value)
    if not match:
        raise Refused("Media must contain an encrypted PKCS#8 PEM key, never an unencrypted private key")
    try:
        data = base64.b64decode(match[1].replace(b"\r", b"").replace(b"\n", b""), validate=True)
    except ValueError:
        raise Refused("Invalid encrypted PKCS#8 encoding") from None
    container = _DER(data)
    outer = container.sequence()
    container.end()
    algorithm = outer.sequence()
    algorithm.oid("2a864886f70d01050d")  # PBES2
    parameters = algorithm.sequence()
    algorithm.end()
    kdf = parameters.sequence()
    kdf.oid("2a864886f70d01050c")  # PBKDF2
    work = kdf.sequence()
    kdf.end()
    if not 16 <= len(work.item(4)) <= 64:
        raise Refused("Encrypted recovery keys require a 16–64 byte PBKDF2 salt")
    iterations = work.integer()
    if not 100000 <= iterations <= 2000000:
        raise Refused("Encrypted recovery key PBKDF2 work must be between 100000 and 2000000 iterations")
    if work.position < len(work.data) and work.data[work.position] == 2:
        if work.integer() != 32:
            raise Refused("Encrypted recovery key must use a 256-bit derived key")
    prf = work.sequence()
    prf.oid("2a864886f70d0209")  # HMAC-SHA256; SHA1 default is not accepted.
    if prf.position < len(prf.data) and prf.item(5) != b"":
        raise Refused("Invalid PBKDF2 PRF parameters")
    prf.end()
    work.end()
    encryption = parameters.sequence()
    encryption.oid("60864801650304012a")  # AES-256-CBC, the PKCS#8 envelope.
    if len(encryption.item(4)) != 16:
        raise Refused("Invalid encrypted recovery key IV")
    encryption.end()
    parameters.end()
    ciphertext = outer.item(4)
    if not ciphertext or len(ciphertext) % 16:
        raise Refused("Invalid encrypted recovery key ciphertext")
    outer.end()


def certificate_envelope(path):
    # OpenSSL x509 otherwise accepts the first certificate and ignores suffixes,
    # which could accidentally include an unencrypted escrowed key on the ISO.
    value = path.read_bytes()  # Private pinned copy; inventory capped it at 64 KiB.
    match = re.fullmatch(rb"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\r?\n?", value)
    if not match:
        raise Refused("Recovery media requires one certificate PEM block without appended content")
    try:
        encoded = base64.b64decode(match[1].replace(b"\r", b"").replace(b"\n", b""), validate=True)
    except ValueError:
        raise Refused("Invalid recovery certificate encoding") from None
    outer = _DER(encoded)
    outer.sequence()
    outer.end()


def read_passphrase():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise Refused("Recovery media requires a protected interactive terminal for its key passphrase")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass("Encrypted recovery key passphrase (not echoed): ")
        except getpass.GetPassWarning:
            raise Refused("A hidden terminal passphrase prompt is unavailable") from None


@dataclass
class ImportedInputs:
    directory: Path
    backup_sha256: str
    commands: object

    @property
    def backup(self):
        return self.directory / "backup.cms"

    @property
    def certificate(self):
        return self.directory / "recipient.pem"

    def unlock(self, passphrase):
        try:
            encoded = passphrase.encode("utf-8") if isinstance(passphrase, str) else b""
        except UnicodeError:
            raise Refused("The encrypted recovery key passphrase must be valid UTF-8") from None
        if (not isinstance(passphrase, str) or len(passphrase) < 14 or len(encoded) > 1024
                or any(value in passphrase for value in ("\n", "\r", "\0"))):
            raise Refused("The encrypted recovery key passphrase must contain 14 or more characters without line breaks")
        key = self.directory / "private-key.pem"
        with key.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
        try:
            self.commands(["prlimit", "--core=0", "--fsize=65536", "--", "openssl", "pkcs8", "-in",
                           str(self.directory / "recovery-key.pk8"), "-passin", "stdin", "-out", str(key)],
                          input=encoded + b"\n", timeout=30)
            info = key.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1
                    or info.st_mode & 0o077 or not 0 < info.st_size <= 65536):
                raise Refused("Recovered private key is invalid")
            public = self.commands(["openssl", "pkey", "-in", str(key), "-pubout"], timeout=10)
            certificate = self.commands(["openssl", "x509", "-in", str(self.certificate), "-pubkey", "-noout"], timeout=10)
            if not public or public != certificate:
                raise Refused("The recovery key does not match the media certificate")
            return key
        except BaseException:
            key.unlink(missing_ok=True)
            raise


class RecoveryMedia:
    def __init__(self, commands=run, *, data=DATA, mount=MOUNT):
        self.cmd, self.data, self.mount = commands, data, mount

    def _mount_info(self, *, absent=False):
        try:
            raw = self.cmd(["findmnt", "--json", "--mountpoint", str(self.mount),
                            "--output", "TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN"], timeout=10)
        except CommandFailed as error:
            if absent and error.returncode == 1:
                return None
            raise
        if len(raw) > 16384:
            raise Refused("Recovery media mount evidence exceeds its budget")
        entries = json.loads(raw).get("filesystems")
        if not isinstance(entries, list) or len(entries) != 1:
            raise Refused("Recovery media mount is ambiguous")
        return entries[0]

    def _verify_mount(self, device, info):
        mount = self._mount_info()
        if (mount.get("target") != str(self.mount) or mount.get("source") != str(device)
                or mount.get("fstype") != "iso9660" or not OPTIONS <= set(mount.get("options", "").split(","))
                or "rw" in mount.get("options", "").split(",")
                or mount.get("maj:min") != f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"):
            raise Refused("Recovery media must remain on the selected read-only protected ISO9660 mount")

    @contextmanager
    def _mounted(self, device):
        if not isinstance(device, Path) or not re.fullmatch(r"/dev/sr[0-9]{1,3}", str(device)):
            raise Refused("Select an attached optical device by its exact /dev/srN path")
        info = device.lstat()
        if not stat.S_ISBLK(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o002 or os.major(info.st_rdev) != 11:
            raise Refused("Recovery media requires a root-owned optical block device")
        _directory(self.mount.parent, private=True, create=True)
        if self._mount_info(absent=True) is not None:
            raise Refused("A previous recovery media mount remains; reboot before retrying this import")
        _directory(self.mount, private=True, create=True)
        if any(self.mount.iterdir()):
            raise Refused("Recovery media mountpoint must be empty")
        descriptor = os.open(device, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        mounted = False
        try:
            opened = os.fstat(descriptor)
            if _identity(opened) != _identity(info) or opened.st_rdev != info.st_rdev:
                raise Refused("Selected recovery device changed")
            self.cmd(["mount", "--no-canonicalize", "--types", "iso9660", "--options",
                      ",".join(sorted(OPTIONS)), "--", str(device), str(self.mount)], timeout=30)
            mounted = True
            self._verify_mount(device, info)
            if _identity(device.lstat()) != _identity(info):
                raise Refused("Selected recovery device changed during mount")
            directory = os.open(self.mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                yield directory
                self._verify_mount(device, info)
                if _identity(device.lstat()) != _identity(info):
                    raise Refused("Selected recovery device changed during import")
            finally:
                os.close(directory)
        finally:
            try:
                if mounted:
                    self.cmd(["umount", "--", str(self.mount)], timeout=30)
                    if self._mount_info(absent=True) is not None:
                        raise Refused("Recovery media did not unmount; imported inputs will not be used")
            finally:
                os.close(descriptor)

    @contextmanager
    def staged(self, device):
        require_linux_root()
        _directory(self.data)
        _encrypted_staging(self.data, self.cmd)
        scratch = self.data / "manager/recovery-inputs"
        _directory(scratch, private=True, create=True)
        with locked(scratch / "import.lock"):
            with tempfile.TemporaryDirectory(prefix="media-", dir=scratch) as temporary:
                work = Path(temporary)
                with self._mounted(device) as directory:
                    inventory = _inventory(directory)
                    if shutil.disk_usage(work).free < sum(value.st_size for value in inventory.values()) + 65536 + RESERVE_BYTES:
                        raise Refused("Insufficient encrypted scratch for recovery media inputs")
                    hashes = {name: _copy(directory, name, original, work / name) for name, original in inventory.items()}
                    if {name: _identity(value) for name, value in _inventory(directory).items()} != {name: _identity(value) for name, value in inventory.items()}:
                        raise Refused("Recovery media inventory changed during import")
                authenticated_cms(work / "backup.cms")
                encrypted_key_parameters(work / "recovery-key.pk8")
                certificate_envelope(work / "recipient.pem")
                self.cmd(["openssl", "x509", "-in", str(work / "recipient.pem"), "-noout"], timeout=10)
                yield ImportedInputs(work, hashes["backup.cms"], self.cmd)


def restore_from_media(recovery, device, *, importer=None, read=input, write=print,
                       secret=read_passphrase, guard=lambda: None, target_confirmation=None):
    """The console and root CLI share confirmation and existing restore routing."""
    guard()
    if recovery.status()["state"] != "not_started":
        raise Refused("A retained restore owns this target; media cannot replace its inputs")
    recovery.runtime.guard_fresh()
    with (importer or RecoveryMedia()).staged(device) as inputs:
        write("Configuration backup SHA256: " + inputs.backup_sha256)
        write("Compare this digest with your independently retained backup receipt. Repeating the displayed digest alone does not establish its origin.")
        write("This media imports configuration and identity only. Optional full log-data recovery uses a separate recovery set.")
        confirmation = "IMPORT " + inputs.backup_sha256
        if read("After verifying your known backup receipt, type " + confirmation + " (or CANCEL): ") != confirmation:
            return {"state": "cancelled", "applied": False}
        guard()
        passphrase = secret()
        guard()
        key = inputs.unlock(passphrase)
        del passphrase
        recovery.runtime.guard_fresh()
        review = recovery.prepare(inputs.backup, key, inputs.certificate)
    # prepare owns authenticated copies. Drop importer-owned plaintext key and
    # media scratch before a human wait or any runtime effects; never remove a
    # caller's original media or local-path recovery key.
    from .configuration_restore import review_text
    write(review_text(review))
    confirmation = target_confirmation or "APPLY " + review["id"]
    if read("After reviewing this recovery, isolating the source and exporting target disk recovery material, type " + confirmation + ": ") != confirmation:
        return {"state": "cancelled", "applied": False}
    guard()
    return recovery.apply_prepared(review["id"], review["review_digest"])
