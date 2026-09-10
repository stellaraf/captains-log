#!/usr/bin/env python3
"""Clean a new standalone sealed-system copy and zero free space before packaging.

Run on a disposable Linux builder with distro libguestfs/virt-sparsify. The
original must additionally be bind-mounted read-only by the build supervisor.
Never point this at a host device, running VM, enrolled appliance, or data disk.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import time

from artifact_cleanup import apply_plan, create_plan, verify_plan

GIB = 1024**3


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024**2), b""):
            result.update(block)
    return result.hexdigest()


def inspect_header(path):
    """Reject dependencies before QEMU can open a backing or external data file.

    Offsets follow QEMU's documented qcow2 v2/v3 header and extension format.
    Only the small first cluster is read here; qemu-img check validates the
    remaining image after this dependency gate passes.
    """
    with path.open("rb") as stream:
        header = stream.read(104)
        if len(header) < 72 or header[:4] != b"QFI\xfb":
            raise ValueError("Require a QCOW2 header")
        version = struct.unpack_from(">I", header, 4)[0]
        bits = struct.unpack_from(">I", header, 20)[0]
        if version not in (2, 3) or not 9 <= bits <= 21:
            raise ValueError("Unsupported QCOW2 header")
        if (struct.unpack_from(">Q", header, 8)[0] or struct.unpack_from(">I", header, 16)[0]
                or struct.unpack_from(">I", header, 32)[0] or struct.unpack_from(">I", header, 60)[0]
                or struct.unpack_from(">Q", header, 64)[0]):
            raise ValueError("QCOW2 backing files, encryption and snapshots are forbidden")
        if struct.unpack_from(">Q", header, 24)[0] != 80 * GIB:
            raise ValueError("Require an 80GiB system image")
        length = 72
        if version == 3:
            if len(header) < 104:
                raise ValueError("Truncated QCOW2 v3 header")
            incompatible = struct.unpack_from(">Q", header, 72)[0]
            autoclear = struct.unpack_from(">Q", header, 88)[0]
            if incompatible & ~0x18 or autoclear & 2:
                raise ValueError("Dirty, corrupt, external-data or unknown QCOW2 features are forbidden")
            length = struct.unpack_from(">I", header, 100)[0]
            if length < 104 or length % 8:
                raise ValueError("Invalid QCOW2 header length")
        cluster_size = 1 << bits
        if length + 8 > cluster_size:
            raise ValueError("QCOW2 header extensions exceed the first cluster")
        stream.seek(0)
        cluster = stream.read(cluster_size)
        position = length
        while position + 8 <= len(cluster):
            kind, size = struct.unpack_from(">II", cluster, position)
            if kind in (0x44415441, 0xE2792ACA, 0x0537BE77):
                raise ValueError("QCOW2 dependency or encryption extension is forbidden")
            if kind == 0:
                if size:
                    raise ValueError("Invalid QCOW2 extension terminator")
                return
            position += 8 + ((size + 7) // 8) * 8
        raise ValueError("Truncated QCOW2 header extensions")


def disk_info(path):
    inspect_header(path)
    row = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", "-f", "qcow2", str(path)]))
    features = row.get("format-specific", {}).get("data", {})
    if (row.get("backing-filename") or row.get("snapshots") or features.get("data-file")
            or row.get("encrypted") or row["virtual-size"] != 80 * GIB):
        raise ValueError("Require one standalone 80GiB system QCOW2 without snapshots")
    subprocess.run(["qemu-img", "check", "-q", "-f", "qcow2", str(path)], check=True)
    return row


def open_image(path, readonly):
    import guestfs
    g = guestfs.GuestFS(python_return_dict=True)
    try:
        g.set_backend("direct")
        g.set_memsize(512)
        g.set_network(False)
        g.set_autosync(False)
        g.add_drive_opts(str(path), format="qcow2", readonly=readonly)
        g.launch()
        if g.list_devices() != ["/dev/sda"] or g.blockdev_getsize64("/dev/sda") != 80 * GIB:
            raise ValueError("Unexpected inspection device")
        if readonly:
            g.blockdev_setro("/dev/sda")
        parts = g.list_partitions()
        boots = [p for p in parts if g.vfs_type(p) == "xfs"]
        esps = [p for p in parts if g.vfs_type(p) == "vfat"]
        pvs = g.pvs()
        if len(boots) != 1 or len(esps) > 1 or len(pvs) != 1 or pvs[0] not in parts or g.vgs() != ["system"]:
            raise ValueError("Unexpected sealed system layout")
        expected = {"/dev/system/" + name for name in ("root", "var", "log", "audit", "home", "tmp", "swap")}
        if set(g.lvs()) != expected:
            raise ValueError("Unexpected logical volumes")
        g.vg_activate(False, ["system"])
        g.lvm_set_filter(pvs)
        g.vg_activate(False, ["system"])
        g.debug("sh", ["lvm lvchange -ay system/root system/var system/log system/audit system/home system/tmp"])
        g.debug("sh", ["test ! -e /dev/mapper/system-swap"])
        mounts = [("/dev/system/root", "/"), (boots[0], "/boot"), ("/dev/system/var", "/var"),
                  ("/dev/system/home", "/home"), ("/dev/system/tmp", "/tmp"),
                  ("/dev/system/log", "/var/log"), ("/dev/system/audit", "/var/log/audit")]
        for device, target in mounts:
            if readonly:
                g.blockdev_setro(device)
            g.mount_options("ro,norecovery" if readonly else "rw", device, target)
        if esps:
            if readonly:
                g.blockdev_setro(esps[0])
            g.mount_options("ro" if readonly else "rw", esps[0], "/boot/efi")
        if len(g.debug("sh", ["cat /proc/swaps"]).strip().splitlines()) != 1:
            raise ValueError("Swap must remain inactive")
        return g
    except BaseException:
        g.close()
        raise


def close_image(g):
    try:
        g.umount_all()
        g.shutdown()
    finally:
        g.close()


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Darwin may report EPERM for an unreaped process. Treat it as present;
        # never turn an inability to signal/probe into successful cleanup.
        return True


def stop_group(process, grace_seconds=2):
    """Signal the owned group even if its leader has already exited."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        process.poll()  # Reap our direct child before probing its group.
        if not group_exists(process.pid):
            break
        time.sleep(0.05)
    if group_exists(process.pid):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait()
    # Descendants are covered by the supervisor's private systemd cgroup too.
    # Reap any other children in this group if the caller is a subreaper.
    while True:
        try:
            if os.waitpid(-process.pid, os.WNOHANG)[0] == 0:
                break
        except ChildProcessError:
            break


def run_guarded(command, work, minimum_free, timeout, log_name, env=None):
    """Terminate only this newly spawned process group on a resource failure."""
    started = time.monotonic()
    with (work / log_name).open("x") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True, env=env)
        try:
            while process.poll() is None:
                if shutil.disk_usage(work).free < minimum_free:
                    raise RuntimeError("Scratch free-space guard reached")
                if time.monotonic() - started > timeout:
                    raise RuntimeError("Bounded build operation timed out")
                time.sleep(2)
            if process.returncode:
                raise RuntimeError("Build operation failed; private log retained")
            if group_exists(process.pid):
                raise RuntimeError("Build operation left background descendants")
        except BaseException:
            stop_group(process)
            raise


def protected_parent(path):
    """Refuse symlink traversal and writable output/work directory chains."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Build paths must be absolute and canonical")
    parents = list(reversed(path.parents))
    for parent in parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()):
            raise ValueError("Build path has an untrusted parent directory")
        writable = info.st_mode & 0o022
        sticky_ancestor = parent != path.parent and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if writable and not sticky_ancestor:
            raise ValueError("Build path parent is writable by another account")


def publish_verified(pending, output):
    """Atomically publish verified bytes without replacing any existing path."""
    protected_parent(pending)
    protected_parent(output)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    source_fd = os.open(pending.parent, flags)
    try:
        target_fd = os.open(output.parent, flags)
        try:
            info = os.stat(pending.name, dir_fd=source_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise ValueError("Pending output must be one owned regular file")
            # link is atomic and fails with EEXIST even for a dangling symlink.
            os.link(pending.name, output.name, src_dir_fd=source_fd, dst_dir_fd=target_fd, follow_symlinks=False)
            os.fsync(target_fd)
            os.unlink(pending.name, dir_fd=source_fd)
            os.fsync(source_fd)
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--payload-manifest", type=Path, required=True)
    parser.add_argument("--approved-plan", type=Path)
    parser.add_argument("--minimum-free-gib", type=int, default=16)
    args = parser.parse_args()
    os.umask(0o077)
    if not re.fullmatch("[0-9a-f]{64}", args.expected_sha256) or args.minimum_free_gib < 16:
        parser.error("An exact source SHA256 and at least16GiB scratch reserve are required")
    source = args.input.absolute()
    output = args.output.absolute()
    work = args.work_dir.absolute()
    if args.input.is_symlink() or not source.is_file() or output.exists() or output.is_symlink() or work.exists():
        parser.error("Require regular immutable input and new output/work paths")
    for path in (source, output, work):
        protected_parent(path)
    source_stat = source.lstat()
    if source_stat.st_nlink != 1 or source_stat.st_uid not in (0, os.geteuid()):
        parser.error("Original must be one trusted regular file")
    if source == output or source.is_relative_to(work) or output.is_relative_to(work):
        parser.error("Original and final output must be outside the transient workspace")
    if not output.parent.is_dir() or not work.parent.is_dir() or output.parent.stat().st_dev != work.parent.stat().st_dev:
        parser.error("Output and workspace must share the bounded scratch filesystem")
    if not os.statvfs(source).f_flag & os.ST_RDONLY:
        raise ValueError("Original image must be bind-mounted read-only by the build supervisor")
    before = sha(source)
    if before != args.expected_sha256:
        raise ValueError("Source image SHA256 mismatch")
    info = disk_info(source)
    reserve = args.minimum_free_gib * GIB
    if shutil.disk_usage(work.parent).free < 2 * info["virtual-size"] + reserve:
        raise ValueError("Insufficient scratch capacity for copy-mode sparsification")
    raw = json.loads(args.payload_manifest.read_text())["files"]
    expected = {path: row["sha256"] for path, row in raw.items()}
    work.mkdir(mode=0o700)
    (work / "source-receipt.json").write_text(json.dumps({"path": str(source), "sha256": before,
        "virtual_bytes": info["virtual-size"], "original_readonly_binding_verified": True}, indent=2) + "\n")
    copy = work / "cleanup-copy.qcow2"
    run_guarded(["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", str(source), str(copy)], work, reserve, 900, "copy.log")
    subprocess.run(["qemu-img", "compare", "-q", "-f", "qcow2", "-F", "qcow2", str(source), str(copy)], check=True)
    g = open_image(copy, False)
    try:
        plan = create_plan(g, expected)
        if args.approved_plan:
            approved = json.loads(args.approved_plan.read_text())
            actual = sorted((x["path"], x["action"], x["bytes"], x["sha256"]) for x in plan["actions"])
            wanted = sorted((x["path"], x["action"], x["expected_bytes"], x["expected_sha256"]) for x in approved["actions"])
            if approved["source_sha256"] != before or actual != wanted:
                raise ValueError("Observed cleanup differs from the exact reviewed derivation")
        (work / "cleanup-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
        result = apply_plan(g, plan)
        (work / "cleanup-result.json").write_text(json.dumps(result, indent=2) + "\n")
    finally:
        close_image(g)
    copy.chmod(0o400)
    pending = work / "pending-sanitized.qcow2"
    (work / "sparsify-tmp").mkdir(mode=0o700)
    run_guarded(["virt-sparsify", "--format", "qcow2", "--convert", "qcow2", "--check-tmpdir=fail",
                 "--tmp", str(work / "sparsify-tmp"), str(copy), str(pending)], work, reserve, 3600, "sparsify.log")
    disk_info(pending)
    pending.chmod(0o400)
    output_before_audit = sha(pending)
    g = open_image(pending, True)
    try:
        final = verify_plan(g, plan)
    finally:
        close_image(g)
    if sha(pending) != output_before_audit or sha(source) != before:
        raise ValueError("Read-only inspection changed an image")
    with pending.open("rb") as stream:
        os.fsync(stream.fileno())
    publish_verified(pending, output)
    receipt = {"schema": 1, "source_sha256": before, "cleanup_copy_sha256": sha(copy),
               "output_sha256": output_before_audit, "output_bytes": output.stat().st_size,
               "virtual_bytes": info["virtual-size"], "source_unchanged": True,
               "copy_mode_sparsification": True, "minimum_free_gib": args.minimum_free_gib,
               "cleanup_actions_verified": final["actions_verified"], "controls_verified": final["controls_verified"],
               "final_readonly_audit_unchanged": True, "native_tool_fixture_qualification_required": True,
               "firmware_and_boot_acceptance_still_required": True}
    (work / "sanitization-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
