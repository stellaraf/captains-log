#!/usr/bin/env python3
"""Read-only static audit of the finalized x86 Rocky UEFI system QCOW2.

Requires the distro python3-libguestfs package on a Linux packaging host.
libguestfs starts its own isolated inspection appliance, with networking off,
one explicit read-only disk, and no execution of binaries from that disk.
This validates disk structure, not Secure Boot signatures or actual VM boot.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess

ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
UUID = re.compile(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}")
EFI_FILES = ("/boot/efi/EFI/rocky/shimx64.efi", "/boot/efi/EFI/rocky/grubx64.efi",
             "/boot/efi/EFI/BOOT/BOOTX64.EFI", "/boot/efi/EFI/BOOT/fbx64.efi")


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            digest.update(block)
    return digest.hexdigest()


def pe_x64(raw):
    """Require a bounded AMD64 PE32+ EFI application; never execute it."""
    if len(raw) < 256 or raw[:2] != b"MZ":
        raise ValueError("EFI binary lacks a PE header")
    offset = struct.unpack_from("<I", raw, 60)[0]
    if offset < 64 or offset + 24 + 112 > len(raw) or raw[offset:offset + 4] != b"PE\0\0":
        raise ValueError("EFI binary has an invalid PE offset")
    machine, sections = struct.unpack_from("<HH", raw, offset + 4)
    optional_size = struct.unpack_from("<H", raw, offset + 20)[0]
    optional = offset + 24
    if (machine != 0x8664 or not 1 <= sections <= 96 or optional_size < 112
            or optional + optional_size + sections * 40 > len(raw)
            or struct.unpack_from("<H", raw, optional)[0] != 0x20b
            or struct.unpack_from("<H", raw, optional + 68)[0] != 10):
        raise ValueError("Require an x86_64 PE32+ EFI application")


def read(g, path, maximum=1024**2):
    if not g.is_file(path, followsymlinks=False) or not 0 < g.filesize(path) <= maximum:
        raise ValueError("Firmware audit requires a bounded regular guest file: " + path)
    raw = g.read_file(path)
    if len(raw) > maximum:
        raise ValueError("Guest file grew during firmware inspection")
    return raw


def check_stub(raw, boot_uuid):
    """Accept Rocky's forwarding stub, not an unrelated UUID or custom script."""
    lines = [line.strip() for line in raw.decode("ascii").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    expected_search = rf"search --no-floppy (?:--root-dev-only )?--fs-uuid --set=dev {re.escape(boot_uuid)}"
    if (len(lines) != 4 or not re.fullmatch(expected_search, lines[0])
            or lines[1] not in ("set prefix=($dev)/grub2", "set prefix=($dev)'/grub2'", 'set prefix="($dev)/grub2"')
            or lines[2] not in ("export $prefix", "export prefix")
            or lines[3] not in ("configfile $prefix/grub.cfg", 'configfile "$prefix/grub.cfg"')):
        raise ValueError("Rocky EFI forwarding stub does not bind to the inspected /boot UUID")


def inspect(g):
    devices, roots = g.list_devices(), g.inspect_os()
    if len(devices) != 1 or len(roots) != 1:
        raise ValueError("UEFI audit requires exactly one system disk and one installed OS")
    disk, root = devices[0], roots[0]
    if (g.inspect_get_type(root) != "linux" or g.inspect_get_arch(root) != "x86_64"
            or g.part_get_parttype(disk) != "gpt"):
        raise ValueError("UEFI appliance must be x86_64 Linux on GPT")
    mounts = g.inspect_get_mountpoints(root)
    if mounts.get("/") != root or not {"/boot", "/boot/efi"} <= mounts.keys():
        raise ValueError("UEFI requires separate /boot and /boot/efi mounts")
    boot, esp = mounts["/boot"], mounts["/boot/efi"]
    if boot == esp or any(g.part_to_dev(device) != disk for device in (boot, esp)):
        raise ValueError("Boot and ESP partitions must belong to the system disk")
    esps = [part for part in g.list_partitions()
            if g.part_get_gpt_type(disk, g.part_to_partnum(part)).lower() == ESP_TYPE]
    if esps != [esp] or g.vfs_type(esp) != "vfat" or g.vfs_type(boot) != "xfs":
        raise ValueError("Require one GPT FAT ESP and the appliance XFS /boot")
    boot_uuid, root_uuid = g.vfs_uuid(boot), g.vfs_uuid(root)
    if not UUID.fullmatch(boot_uuid) or not UUID.fullmatch(root_uuid):
        raise ValueError("Boot and root filesystem UUIDs are invalid")
    for path in ("/", "/boot", "/boot/efi"):
        g.mount_ro(mounts[path], path)
    # /etc/os-release is normally a symlink on Rocky; inspect the fixed vendor
    # file rather than following arbitrary guest-controlled symlink chains.
    release = read(g, "/usr/lib/os-release", 8192).decode("ascii")
    if not re.search(r'^ID="?rocky"?$', release, re.M) or not re.search(r'^VERSION_ID="?9(?:\.[0-9]+)?"?$', release, re.M):
        raise ValueError("Require Rocky Linux 9 installed root")
    digests = {}
    for path in EFI_FILES:
        raw = read(g, path, 16 * 1024**2)
        pe_x64(raw)
        digests[path] = hashlib.sha256(raw).hexdigest()
    # Fresh VM NVRAM must find the distro shim through the standard x64 path.
    if digests[EFI_FILES[0]] != digests[EFI_FILES[2]]:
        raise ValueError("Removable-media boot path must contain the exact Rocky shim")
    csv = read(g, "/boot/efi/EFI/rocky/BOOTX64.CSV", 16384).decode("utf-16-le")
    csv_lines = csv.lstrip("\ufeff").splitlines()
    if (len(csv_lines) != 1 or len(csv_lines[0].split(",")) != 4
            or csv_lines[0].split(",")[0] != "shimx64.efi"
            or csv_lines[0].split(",")[2] != ""):
        raise ValueError("Rocky fallback loader CSV does not select shimx64.efi")
    stub = read(g, "/boot/efi/EFI/rocky/grub.cfg", 16384)
    check_stub(stub, boot_uuid)
    config = read(g, "/boot/grub2/grub.cfg").decode("utf-8")
    if not re.search(r"^\s*blscfg\s*$", config, re.M):
        raise ValueError("The inspected /boot GRUB configuration lacks BLS loading")
    entries = g.ls("/boot/loader/entries")
    if not 1 <= len(entries) <= 128:
        raise ValueError("A bounded BLS kernel inventory is required")
    kernels = []
    for name in entries:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.conf", name):
            raise ValueError("Unexpected BLS entry name")
        body = read(g, "/boot/loader/entries/" + name, 65536).decode("utf-8")
        fields = {}
        for line in body.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            key, _, value = line.partition(" ")
            if key in ("linux", "initrd", "options"):
                if key in fields:
                    raise ValueError("Duplicate BLS boot field")
                fields[key] = value.strip()
        if set(fields) != {"linux", "initrd", "options"}:
            raise ValueError("BLS entry lacks fixed kernel, initramfs or options")
        for key in ("linux", "initrd"):
            if not re.fullmatch(r"/[A-Za-z0-9_.+-]+", fields[key]) or not g.is_file("/boot" + fields[key], followsymlinks=False):
                raise ValueError("BLS boot files must exist on the inspected /boot partition")
        options = fields["options"].split()
        roots = [token for token in options if token.startswith("root=")]
        root_options = {"root=UUID=" + root_uuid}
        if root in ("/dev/mapper/system-root", "/dev/system/root"):
            root_options.update(("root=/dev/mapper/system-root", "root=/dev/system/root"))
        if (len(roots) != 1 or roots[0] not in root_options
                or [token for token in options if token.startswith("fips=")] != ["fips=1"]
                or [token for token in options if token.startswith("module.sig_enforce=")] != ["module.sig_enforce=1"]):
            raise ValueError("BLS options must bind this root and enforce FIPS and signed modules")
        kernels.append(fields["linux"])
    return {"architecture": "x86_64", "partition_table": "gpt", "esp_type": ESP_TYPE,
            "boot_uuid": boot_uuid, "root_uuid": root_uuid, "efi_file_sha256": digests,
            "efi_stub_sha256": hashlib.sha256(stub).hexdigest(), "kernels": sorted(kernels),
            "fallback_shim_matches": True, "boot_configuration_bound": True}


def audit(system):
    if system.is_symlink() or not stat.S_ISREG(system.stat().st_mode):
        raise ValueError("Firmware audit accepts a regular system image only")
    system = system.resolve()
    info = json.loads(subprocess.check_output(["qemu-img", "info", "-f", "qcow2", "--output=json", str(system)]))
    if info.get("backing-filename") or info.get("snapshots") or info.get("encrypted"):
        raise ValueError("Firmware audit requires a standalone QCOW2")
    before = sha(system)
    try:
        import guestfs
    except ImportError as error:
        raise RuntimeError("UEFI packaging requires the Linux python3-libguestfs package") from error
    g = guestfs.GuestFS(python_return_dict=True)
    try:
        g.set_network(False)
        g.add_drive_opts(str(system), format="qcow2", readonly=True)
        g.launch()
        result = inspect(g)
    finally:
        g.close()
    if sha(system) != before:
        raise ValueError("System disk changed during firmware audit")
    return {"schema": 1, "firmware": "efi", "system_qcow2_sha256": before,
            "static_disk_audit_verified": True, "boot_validated": False,
            "secure_boot_validated": False, "efi_signatures_verified": False,
            "tpm_enrolled": False, **result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-image", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.system_image), indent=2))
