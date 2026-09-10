#!/usr/bin/env python3
"""Private Packer provisioning guard. There is no customer-repair or bypass mode."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import struct
import subprocess
import sys
import tempfile


class Refused(RuntimeError):
    pass


PRIVATE_MARKER = b"NebulaLog private Packer build; not distributable\n"
CONTEXTS = {
    "/run/nebulalog-public(/.*)?": "httpd_var_run_t",
    "/run/nebulalog-status(/.*)?": "container_file_t",
    "/var/lib/nebulalog/configuration/tls(/.*)?": "container_file_t",
    "/var/lib/nebulalog/configuration/edge-tls(/.*)?": "httpd_config_t",
    "/var/lib/nebulalog/manager/aide(/.*)?": "aide_db_t",
}
EQUIVALENCE = ("/var/lib/nebulalog/containers", "/var/lib/containers/storage")
# Rocky's distribution policy substitutes /run with /var/run before file-context
# lookup. seobject.add() requires the latter spelling; runtime paths stay /run.
RUNTIME_EQUIVALENCE = ("/run", "/var/run")
RUNTIME_CONTEXTS = {
    "/run/nebulalog-public(/.*)?": "/var/run/nebulalog-public(/.*)?",
    "/run/nebulalog-status(/.*)?": "/var/run/nebulalog-status(/.*)?",
}


def present(path):
    return path.exists() or path.is_symlink()


def private_file(path, *, uid=0, gid=0, mode=0o600, maximum=4096):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink) != (uid, gid, mode, 1) or not 0 < info.st_size <= maximum:
        raise Refused("A required build file is not protected, regular and within its size limit")
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) != info.st_size:
        raise Refused("Build file changed during verification")
    return value


def private_dir(path, uid=0, gid=0):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, 0o700):
        raise Refused("A build directory must be private, owned by its expected identity and not a symlink")


def rsa_key_digest(value):
    """Parse public SSH wire data; never invoke a key generator or print key material."""
    fields = value.decode("ascii").strip().split()
    if b"\n" in value.rstrip(b"\n") or len(fields) < 2 or fields[0] != "ssh-rsa":
        raise Refused("The disposable build requires one RSA public key")
    try:
        wire = base64.b64decode(fields[1], validate=True)
        parts = []
        while wire:
            length = struct.unpack(">I", wire[:4])[0]
            if length == 0 or length > len(wire) - 4:
                raise ValueError()
            parts.append(wire[4:4 + length])
            wire = wire[4 + length:]
        if len(parts) != 3 or parts[0] != b"ssh-rsa" or parts[1][0] & 0x80 or parts[2][0] & 0x80:
            raise ValueError()
        exponent, modulus = int.from_bytes(parts[1], "big"), int.from_bytes(parts[2], "big")
        if exponent < 3 or exponent % 2 != 1 or modulus.bit_length() < 3072 or modulus % 2 != 1:
            raise ValueError()
    except (ValueError, IndexError, struct.error) as exc:
        raise Refused("The disposable build requires a valid RSA public key of at least 3072 bits") from exc
    return hashlib.sha256((fields[0] + " " + fields[1]).encode()).hexdigest()


def checked(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise Refused("A required private-build host probe failed")
    return result.stdout.strip()


def build_identity(*, require_sudo=True):
    if os.geteuid() != 0 or sys.platform != "linux":
        raise Refused("Provisioning requires root inside the disposable Linux build VM")
    virtual = checked(["systemd-detect-virt", "--vm"])
    if not virtual or virtual == "none":
        raise Refused("Provisioning requires an actual virtual machine")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release.get("ID", "").strip('"') != "rocky" or release.get("VERSION_ID", "").strip('"').split(".")[0] != "9" or Path("/proc/sys/crypto/fips_enabled").read_text().strip() != "1" or checked(["getenforce"]) != "Enforcing":
        raise Refused("The actual Rocky 9 FIPS kernel and SELinux Enforcing are required")
    account = pwd.getpwnam("packer")
    if account.pw_uid == 0 or account.pw_dir != "/home/packer":
        raise Refused("The disposable Packer identity is invalid")
    if require_sudo and (os.environ.get("SUDO_USER"), os.environ.get("SUDO_UID")) != ("packer", str(account.pw_uid)):
        raise Refused("Run the provisioner through the disposable packer sudo session")
    sudoers = private_file(Path("/etc/sudoers.d/nebulalog-build"), mode=0o440)
    if sudoers != b"packer ALL=(ALL) NOPASSWD: ALL\n":
        raise Refused("The disposable build sudo policy is missing or changed")
    private_dir(Path("/home/packer/.ssh"), account.pw_uid, account.pw_gid)
    key = private_file(Path("/home/packer/.ssh/authorized_keys"), uid=account.pw_uid, gid=account.pw_gid, maximum=16384)
    machine = Path("/etc/machine-id")
    info = machine.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 64:
        raise Refused("The build VM machine identity is invalid")
    value = machine.read_text().strip()
    if not re.fullmatch("[0-9a-f]{32}", value) or value == "0" * 32:
        raise Refused("The build VM machine identity is missing")
    root_status = checked(["passwd", "--status", "root"]).split()
    if len(root_status) < 2 or root_status[0] != "root" or root_status[1] not in {"L", "LK"}:
        raise Refused("The disposable build requires the locked root account")
    if "nebulalog" in checked(["vgs", "--noheadings", "--options", "vg_name"]).split():
        raise Refused("An enrolled Captain’s Log volume group exists")
    return {"machine_sha256": hashlib.sha256(value.encode()).hexdigest(), "build_key_sha256": rsa_key_digest(key)}


def data_is_mounted(mountinfo):
    if not mountinfo.strip() or len(mountinfo) > 8 * 1024 * 1024:
        raise Refused("Mount inventory exceeds its safety bound")
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise Refused("Cannot verify the mount inventory")
        target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
        if target == "/var/lib/nebulalog" or target.startswith("/var/lib/nebulalog/"):
            return True
    return False


class BuildGuard:
    """The filesystem root/owner parameters are fixture seams; CLI has no overrides."""
    def __init__(self, root=Path("/"), uid=0, gid=0):
        self.root, self.uid, self.gid = root, uid, gid
        self.base = root / "etc/nebulalog"
        self.bootstrap = self.base / "bootstrap"
        self.receipt = self.bootstrap / "private-build.json"

    def read(self, path):
        return private_file(path, uid=self.uid, gid=self.gid)

    def directory(self, path):
        private_dir(path, self.uid, self.gid)

    def factory_host(self):
        """Validate only the fixed shim measured by this factory source, never candidate imports."""
        import importlib.util
        share = self.root / "usr/share/nebulalog"
        source_raw = private_file(share / "source-manifest.json", uid=self.uid, gid=self.gid, maximum=8 * 1024**2)
        initial_raw = private_file(share / "initial-release.json", uid=self.uid, gid=self.gid, maximum=65536)
        source, initial = json.loads(source_raw), json.loads(initial_raw)
        if initial.get("source_snapshot_sha256") != hashlib.sha256(source_raw).hexdigest():
            raise Refused("Factory host source is not bound to initial release")
        shim = self.root / "usr/libexec/nebulalog/host-boot"
        raw = private_file(shim, uid=self.uid, gid=self.gid, mode=0o755, maximum=8 * 1024**2)
        if source.get("files", {}).get("appliance/host_boot.py") != hashlib.sha256(raw).hexdigest():
            raise Refused("Fixed factory host verifier differs from captured source")
        # The verifier is a fixed source-measured stdlib-only file. Its loader
        # does not import the selected generation or any downloaded module.
        from importlib.machinery import SourceFileLoader
        spec = importlib.util.spec_from_loader("fixed_factory_host_guard", SourceFileLoader("fixed_factory_host_guard", str(shim)))
        module = importlib.util.module_from_spec(spec)
        exec(compile(raw, str(shim), "exec"), module.__dict__)
        module.OWNER, module.ETC, module.SHARE = self.uid, self.base, share
        module.GENERATIONS = self.root / "usr/lib/nebulalog/generations"
        module.FIXED = {name: self.root / str(path).lstrip("/") for name, path in module.FIXED.items()}
        # Fixture roots remain protected by this guard's owner/mode checks.
        if self.root != Path("/"):
            def fixture_tree(path):
                for parent in (path, *path.parents):
                    if not parent.is_relative_to(self.root): break
                    info = parent.lstat()
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o022:
                        raise Refused("Unsafe factory fixture ancestry")
            module.tree = fixture_tree
        record, descriptor = module.factory()
        module.generation(record["host"], record)
        expected = {"schema": 1, "generation": record["host"]["generation"], "sequence": descriptor["sequence"]}
        if module.js(self.base / "host-selection.json") != expected:
            raise Refused("Guarded image selection differs from measured initial generation")

    def inspect(self, identity, *, complete=False):
        if data_is_mounted((self.root / "proc/self/mountinfo").read_text()):
            raise Refused("The appliance data path is mounted; provisioning is forbidden")
        for relative in ("dev/mapper/nebulalog-data", "dev/nebulalog"):
            if present(self.root / relative):
                raise Refused("An appliance storage mapping exists")
        data = self.root / "var/lib/nebulalog"
        if present(data):
            self.directory(data)
            if any(data.iterdir()):
                raise Refused("The appliance data directory is not empty")
        for relative in ("etc/crypttab", "etc/fstab"):
            path = self.root / relative
            if present(path) and any("nebulalog" in line for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")):
                raise Refused("Appliance boot-storage enrollment exists")
        if present(self.base):
            self.directory(self.base)
            if set(p.name for p in self.base.iterdir()) - {"bootstrap", "trust.json", "images.json", "github-updates.json", "host-selection.json"}:
                raise Refused("Configured, enrolled or unexpected appliance state exists")
            if present(self.base / "host-selection.json"):
                self.factory_host()
        if present(self.bootstrap):
            self.directory(self.bootstrap)
            if set(p.name for p in self.bootstrap.iterdir()) - {"private-build.json", "unsealed-build", "state"}:
                raise Refused("Sealed, enrolled or unexpected bootstrap state exists")
        if present(self.receipt):
            record = json.loads(self.read(self.receipt))
            expected = {"schema": 1, "purpose": "private-packer-build", **identity}
            if not isinstance(record, dict) or type(record.get("schema")) is not int or set(record) != set(expected) | {"phase"} or any(record.get(k) != v for k, v in expected.items()) or record["phase"] not in {"provisioning", "installed"}:
                raise Refused("The protected build receipt does not match this VM and build key")
            if complete and record["phase"] != "installed":
                raise Refused("Provisioning has not completed; sealing is forbidden")
            for name, value in (("state", b"unconfigured\n"), ("unsealed-build", PRIVATE_MARKER)):
                path = self.bootstrap / name
                if present(path):
                    if self.read(path) != value:
                        raise Refused("The appliance is not an unconfigured private build")
                elif record["phase"] == "installed" or complete:
                    raise Refused("A completed private build marker is missing")
            return record
        # Only a truly fresh destination, including directories left before the
        # first receipt's durable creation, can start a new private transaction.
        if complete or present(self.base) and any(p.name != "bootstrap" for p in self.base.iterdir()) or present(self.bootstrap) and any(self.bootstrap.iterdir()):
            raise Refused("Existing appliance state has no guarded private-build receipt")
        for relative in ("usr/local/bin/nebulalog", "usr/lib/nebulalog", "usr/libexec/nebulalog", "usr/share/nebulalog", "etc/systemd/system/nebulalog-firstboot.service"):
            if present(self.root / relative):
                raise Refused("An earlier appliance payload exists without a guarded build receipt")
        return None

    def write(self, path, content):
        fd, temporary = tempfile.mkstemp(prefix=".provision-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def begin(self, identity):
        self.inspect(identity)
        for directory in (self.base, self.bootstrap):
            directory.mkdir(mode=0o700, exist_ok=True)
            self.directory(directory)
            parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        record = {"schema": 1, "purpose": "private-packer-build", **identity, "phase": "provisioning"}
        self.write(self.receipt, (json.dumps(record, sort_keys=True) + "\n").encode())
        for name, value in (("unsealed-build", PRIVATE_MARKER), ("state", b"unconfigured\n")):
            path = self.bootstrap / name
            if not present(path):
                self.write(path, value)

    def finish(self, identity):
        record = self.inspect(identity)
        if record is None:
            raise Refused("The private provisioning receipt is missing")
        record["phase"] = "installed"
        self.write(self.receipt, (json.dumps(record, sort_keys=True) + "\n").encode())


def policy_contexts(distribution_equiv):
    """Resolve only the two reviewed names under the exact distribution alias."""
    if distribution_equiv.get(RUNTIME_EQUIVALENCE[0]) == RUNTIME_EQUIVALENCE[1]:
        return {RUNTIME_CONTEXTS.get(expression, expression): label for expression, label in CONTEXTS.items()}
    return dict(CONTEXTS)


def context_plan(all_records, local_records, local_equiv, distribution_equiv):
    """Only the exact fixed local rules are acceptable in this private build."""
    contexts = policy_contexts(distribution_equiv)
    for key, context in local_records.items():
        if key[0] not in contexts or key[1] != "all files" or context != ("system_u", "object_r", contexts[key[0]], "s0"):
            raise Refused("Unexpected local SELinux file-context policy; it will not be overwritten")
    if any((target, source) != EQUIVALENCE for target, source in local_equiv.items()):
        raise Refused("Unexpected local SELinux equivalence; it will not be overwritten")
    planned = []
    # Reject differing exact policy on either spelling, even when the logical
    # /run spelling is not the effective registration under the standard alias.
    for expression, label in {**CONTEXTS, **contexts}.items():
        matching = {key: value for key, value in all_records.items() if key[0] == expression}
        expected = {(expression, "all files"): ("system_u", "object_r", label, "s0")}
        if matching and matching != expected:
            raise Refused("A fixed SELinux file-context expression has an unexpected existing policy")
        if expression in contexts and not matching:
            planned.append(("-a", "-t", label, expression))
    target, source = EQUIVALENCE
    owned_paths = [target] + [value.removesuffix("(/.*)?") for value in sorted({*CONTEXTS, *RUNTIME_CONTEXTS.values()})]
    for mapping, distribution in ((local_equiv, False), (distribution_equiv, True)):
        for existing, substitute in mapping.items():
            if distribution and (existing, substitute) == RUNTIME_EQUIVALENCE:
                continue
            for own in owned_paths:
                if existing == own or existing.startswith(own + "/") or own.startswith(existing + "/"):
                    if (existing, substitute) != EQUIVALENCE:
                        raise Refused("An existing SELinux equivalence overlaps a fixed appliance path: " + own)
    if target not in local_equiv and target not in distribution_equiv:
        planned.append(("-a", "-e", source, target))
    return planned


def ensure_context(arguments):
    valid = {("-a", "-t", label, expression) for expression, label in CONTEXTS.items()} | {("-a", "-e", EQUIVALENCE[1], EQUIVALENCE[0])}
    rule = tuple(arguments)
    if rule not in valid:
        raise Refused("Only fixed appliance SELinux rules may be registered")
    import seobject  # Supplied by Rocky policycoreutils-python-utils; no policy edits on import.
    records = seobject.fcontextRecords()
    plan = context_plan(records.get_all(), records.get_all(True), records.equiv, records.equiv_dist)
    contexts = policy_contexts(records.equiv_dist)
    registered_rule = rule
    if rule[1] == "-t" and rule[3] not in contexts:
        registered_rule = (*rule[:3], RUNTIME_CONTEXTS[rule[3]])
    if registered_rule in plan:
        if registered_rule[1] == "-e":
            records.add_equal(registered_rule[3], registered_rule[2])
        else:
            records.add(registered_rule[3], registered_rule[2], "a", "s0", "system_u")
    # Re-read committed state. Never treat a failed registration as a successful retry.
    records = seobject.fcontextRecords()
    remaining = context_plan(records.get_all(), records.get_all(True), records.equiv, records.equiv_dist)
    if policy_contexts(records.equiv_dist) != contexts:
        raise Refused("The distribution SELinux runtime alias changed during registration")
    if registered_rule in remaining:
        raise Refused("The fixed SELinux rule was not registered")


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {"begin", "finish", "verify-seal", "fcontext"}:
        raise Refused("Unsupported provisioner guard action")
    action = sys.argv[1]
    if action != "fcontext" and len(sys.argv) != 2:
        raise Refused("The provisioner guard accepts no override arguments")
    identity = build_identity(require_sudo=action != "verify-seal")
    guard = BuildGuard()
    if action == "begin":
        guard.begin(identity)
    elif action == "finish":
        guard.finish(identity)
    elif action == "verify-seal":
        guard.inspect(identity, complete=True)
        sys.path.insert(0, "/usr/lib/nebulalog")
        from nebulalog_manager.update_enrollment import UpdateEnrollment
        try:
            UpdateEnrollment().verify_build_inputs(require_factory=True)
        except Exception:
            raise Refused("Measured build inputs and packaged factory publisher trust are required before sealing") from None
    else:
        if guard.inspect(identity) is None:
            raise Refused("SELinux registration requires an existing protected build receipt")
        ensure_context(sys.argv[2:])


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, Refused) else "Required private-build evidence is missing or invalid"
        print("Captain’s Log provisioning refused: " + message, file=sys.stderr)
        raise SystemExit(78)
