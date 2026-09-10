"""Remove private build networking before sealing; never a customer repair tool."""
from pathlib import Path
import os
import stat
import subprocess
import sys

from .common import Refused


SETUP_PROFILE = b"""[connection]
id=Captain's Log setup
type=ethernet
autoconnect=true

[ethernet]

[ipv4]
method=auto

[ipv6]
method=auto
addr-gen-mode=stable-privacy
"""


def sanitize(root=Path("/"), *, uid=0):
    """The alternate root/owner are fixture seams; the CLI has no path override."""
    root = Path(root)
    remove = []
    directories = []
    total = 0

    def inspect(path, *, directory=False):
        nonlocal total
        for parent in path.parents:
            if parent == root.parent:
                break
            before = parent.lstat()
            if not stat.S_ISDIR(before.st_mode) or before.st_uid != uid or before.st_mode & 0o022:
                raise Refused("Build network ancestors must remain protected directories")
        info = path.lstat()
        if info.st_uid != uid or info.st_mode & 0o022:
            raise Refused("Build network paths must remain owned and protected")
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                raise Refused("Build network directory cannot be a link or other object")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Refused("Build network file cannot be a link or other object")
        else:
            total += info.st_size
            if total > 32 * 1024**2 or len(remove) >= 512:
                raise Refused("Build network state exceeds its bounded cleanup inventory")

    def tree(path):
        if not path.exists() and not path.is_symlink():
            return
        inspect(path, directory=True)
        for child in sorted(path.iterdir()):
            if child.is_dir() and not child.is_symlink():
                tree(child)
                directories.append(child)
            else:
                inspect(child)
                remove.append(child)

    # These trees only contain generated NetworkManager profile, lease and host
    # identity state. Stop NetworkManager before invoking this function.
    for name in ("etc/NetworkManager/system-connections", "run/NetworkManager/system-connections",
                 "var/lib/NetworkManager", "var/lib/dhclient"):
        tree(root / name)
    legacy = root / "etc/sysconfig/network-scripts"
    if legacy.exists() or legacy.is_symlink():
        inspect(legacy, directory=True)
        for path in sorted(legacy.iterdir()):
            if path.name != "ifcfg-lo" and path.name.startswith(("ifcfg-", "route-", "route6-", "rule-", "rule6-", "keys-")):
                inspect(path)
                remove.append(path)
    replacements = {
        "etc/hostname": b"captains-log\n",
        "etc/hosts": b"127.0.0.1 localhost localhost.localdomain\n::1 localhost localhost.localdomain\n",
        "etc/sysconfig/network": b"NETWORKING=yes\n",
        "etc/resolv.conf": b"# NetworkManager supplies DNS after first boot.\n",
    }
    for name in replacements:
        path = root / name
        inspect(path.parent, directory=True)
        if name == "etc/resolv.conf" and path.is_symlink():
            if path.lstat().st_uid != uid or os.readlink(path) not in (
                    "/run/NetworkManager/resolv.conf", "../run/NetworkManager/resolv.conf"):
                raise Refused("Unexpected resolver link in the private build")
        elif path.exists() or path.is_symlink():
            inspect(path)
    profile_directory = root / "etc/NetworkManager/system-connections"
    inspect(profile_directory, directory=True)
    # Complete validation precedes deletion, so unexpected state preserves all
    # build network evidence and cannot produce a partly sanitized success.
    for path in remove:
        path.unlink()
    for path in directories:
        path.rmdir()
    for name, value in replacements.items():
        path = root / name
        if path.exists() or path.is_symlink():
            path.unlink()
        with path.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    profile = profile_directory / "captains-log-setup.nmconnection"
    with profile.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(SETUP_PROFILE)
        stream.flush()
        os.fsync(stream.fileno())
    return {"build_network_files_removed": len(remove), "generic_ethernet_profile": True}


def main():
    if len(sys.argv) != 1 or sys.platform != "linux" or os.geteuid() != 0:
        raise Refused("Network sealing requires the private Linux build guest")
    base = Path("/etc/nebulalog/bootstrap")
    if ((base / "state").read_bytes() != b"unconfigured\n" or
            not (base / "unsealed-build").is_file() or (base / "image-state").exists()):
        raise Refused("Cannot sanitize an enrolled or sealed appliance")
    state = subprocess.run(["systemctl", "show", "--property=ActiveState", "--value", "NetworkManager.service"],
                           check=True, text=True, capture_output=True, timeout=30).stdout.strip()
    if state != "inactive":
        raise Refused("NetworkManager must finish stopping before network sealing")
    sanitize()


if __name__ == "__main__":
    main()
