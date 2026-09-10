"""Identity-bound expansion of the single supported LUKS2/LVM/XFS topology.

The pure planner accepts fixture snapshots for tests. The apply path ONLY obtains
snapshots from the Linux inspector and never executes commands from plan JSON.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable
from .common import Refused, audit, locked, require_linux_root, run, trusted_file

MIB = 1024**2

@dataclass(frozen=True)
class Identity:
    disk: str
    serial: str
    partition: str
    partuuid: str
    luks_uuid: str
    mapper: str
    pv_uuid: str
    vg_uuid: str
    lv_uuid: str
    vg: str = "nebulalog"
    lv: str = "/dev/nebulalog/data"
    mount: str = "/var/lib/nebulalog"
    partition_number: int = 1
    additional_pvs: tuple = ()  # (PV UUID, LUKS UUID) pairs enrolled by the manager

    def validate(self) -> None:
        if not self.disk.startswith("/dev/disk/by-id/") or ".." in self.disk or "\n" in self.disk:
            raise Refused("Data disk requires a stable /dev/disk/by-id identity")
        if not re.fullmatch(r"[A-Za-z0-9_./:-]+", self.disk):
            raise Refused("Invalid disk identity")
        if self.partition_number != 1 or self.partition != self.disk + "-part1":
            raise Refused("Only the dedicated first/final data partition is supported")
        if self.vg != "nebulalog" or self.lv != "/dev/nebulalog/data" or self.mount != "/var/lib/nebulalog":
            raise Refused("Unexpected storage pool or mount")
        if not re.fullmatch(r"nebulalog-data[0-9]*", self.mapper):
            raise Refused("Unexpected encryption mapping name")
        if not all((self.serial, self.partuuid, self.luks_uuid, self.pv_uuid, self.vg_uuid, self.lv_uuid)):
            raise Refused("Missing persistent storage identity")

@dataclass(frozen=True)
class Snapshot:
    identity: Identity
    disk_bytes: int
    partition_bytes: int
    partition_start: int
    mapping_bytes: int
    pv_bytes: int
    lv_bytes: int
    filesystem_bytes: int
    vg_free_bytes: int
    sector_size: int = 512
    luks_version: int = 2
    filesystem: str = "xfs"
    mounted: bool = True
    read_only: bool = False
    removable: bool = False
    system_disk: bool = False
    last_partition: bool = True
    linear: bool = True
    # statvfs capacity excludes the XFS internal journal. Only geometry is
    # comparable to LV length; None retains compatibility with pure old fixtures.
    filesystem_geometry_bytes: int | None = None

    @property
    def geometry_bytes(self) -> int:
        return self.filesystem_bytes if self.filesystem_geometry_bytes is None else self.filesystem_geometry_bytes

    def validate(self) -> None:
        self.identity.validate()
        if self.system_disk or self.read_only or self.removable:
            raise Refused("Refusing system, read-only, or removable storage")
        if self.luks_version != 2 or self.filesystem != "xfs" or not self.mounted or not self.linear:
            raise Refused("Expected mounted XFS on a linear LVM LV inside LUKS2")
        if not self.last_partition or self.sector_size not in (512, 4096):
            raise Refused("Unsupported partition geometry")
        sizes = (self.disk_bytes, self.partition_bytes, self.mapping_bytes, self.pv_bytes, self.lv_bytes, self.filesystem_bytes)
        if min(sizes) <= 0 or self.vg_free_bytes < 0 or self.partition_start < MIB:
            raise Refused("Invalid observed storage sizes")
        if self.partition_start + self.partition_bytes > self.disk_bytes:
            raise Refused("Presented disk is smaller than partition; shrinking is prohibited")
        if self.mapping_bytes > self.partition_bytes or self.pv_bytes > self.mapping_bytes + MIB:
            raise Refused("Inconsistent encrypted storage geometry")
        if self.filesystem_bytes > self.lv_bytes + MIB:
            raise Refused("Filesystem exceeds logical volume")
        if self.filesystem_geometry_bytes is not None and (type(self.filesystem_geometry_bytes) is not int or
                not self.filesystem_bytes <= self.filesystem_geometry_bytes <= self.lv_bytes):
            raise Refused("Measured filesystem geometry is inconsistent with usable capacity or logical volume")

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def growth_plan(snapshot: Snapshot) -> dict:
    snapshot.validate()
    unused = snapshot.disk_bytes - snapshot.partition_start - snapshot.partition_bytes
    # GPT backup header and allocation alignment are intentionally not consumed.
    stages = []
    if unused > 4*MIB:
        stages.append("partition")
    if stages or snapshot.partition_bytes - snapshot.mapping_bytes > 32*MIB:
        stages.append("luks")
    if stages or snapshot.mapping_bytes - snapshot.pv_bytes > 4*MIB:
        stages.append("pv")
    if stages or snapshot.vg_free_bytes >= 4*MIB:
        stages.append("lv")
    if stages or snapshot.lv_bytes - snapshot.geometry_bytes > 4*MIB:
        stages.append("xfs")
    return {"operation": "grow", "fingerprint": snapshot.fingerprint,
            "disk": snapshot.identity.disk, "serial": snapshot.identity.serial,
            "current_bytes": snapshot.filesystem_bytes,
            "presented_bytes": snapshot.disk_bytes,
            "unallocated_disk_bytes": max(0, unused), "stages": stages,
            "requires_unlock_credential": "luks" in stages,
            "warning": "Growth is irreversible; snapshot/backup and recovery key must be available"}


def xfs_geometry(text: str, *, filesystem_bytes: int, filesystem_block_size: int, lv_bytes: int) -> int:
    """Parse only the supported internal-log/no-realtime XFS geometry, read-only.

    Linux XFS statfs reports sb_dblocks minus internal sb_logblocks. Comparing
    statvfs directly to the LV therefore invents an unconsumed journal-sized gap.
    Both independent measurements must agree; concurrent/unsupported changes refuse.
    """
    if not isinstance(text, str) or len(text) > 65536 or any(ord(char) < 32 and char not in "\n\r\t" for char in text):
        raise Refused("Invalid or oversized XFS geometry output")
    def section(name, expression):
        lines = [line for line in text.splitlines() if re.match(r"^\s*" + name + r"\s*=", line)]
        match = re.fullmatch(expression, lines[0]) if len(lines) == 1 else None
        if not match:
            raise Refused("Missing, ambiguous or unsupported XFS geometry section")
        return tuple(int(value) for value in match.groups())
    block_size, blocks = section("data", r"\s*data\s*=\s*bsize=([0-9]{1,5})\s+blocks=([0-9]{1,19}),\s*imaxpct=[0-9]{1,3}\s*")
    log_size, log_blocks = section("log", r"\s*log\s*=internal log\s+bsize=([0-9]{1,5})\s+blocks=([0-9]{1,19}),\s*version=2\s*")
    section("realtime", r"\s*realtime\s*=none\s+extsz=[0-9]{1,10}\s+blocks=0,\s*rtextents=0\s*")
    if any(type(value) is not int or not 0 < value < 2**63 for value in (filesystem_bytes, filesystem_block_size, lv_bytes)):
        raise Refused("Invalid independently measured XFS capacity")
    geometry = blocks * block_size
    if block_size not in (512, 1024, 2048, 4096) or block_size != log_size or block_size != filesystem_block_size or not 0 < log_blocks < blocks or geometry > lv_bytes:
        raise Refused("Inconsistent or unsupported XFS block geometry")
    if (blocks - log_blocks) * block_size != filesystem_bytes:
        raise Refused("XFS geometry and usable capacity disagree; refresh the observation")
    return geometry


def _flatten(items: list[dict]) -> list[dict]:
    result = []
    for item in items:
        result.append(item)
        result.extend(_flatten(item.get("children", [])))
    return result


def inspect(identity: Identity, runner: Callable = run) -> Snapshot:
    identity.validate()
    disk = os.path.realpath(identity.disk)
    part = os.path.realpath(identity.partition)
    if not stat.S_ISBLK(os.stat(disk).st_mode) or not stat.S_ISBLK(os.stat(part).st_mode):
        raise Refused("Configured data paths are not block devices")
    all_devices = json.loads(runner(["lsblk", "--bytes", "--json", "--paths", "--output",
                                   "NAME,TYPE,SIZE,PKNAME,FSTYPE,UUID,PARTUUID,MOUNTPOINTS,RO,RM,SERIAL"]))["blockdevices"]
    nodes = _flatten(all_devices)
    one = lambda name: next((n for n in nodes if n["name"] == name), None)
    d, p = one(disk), one(part)
    mapping = one("/dev/mapper/" + identity.mapper)
    if not d or not p or not mapping or d["type"] != "disk" or p["pkname"] != disk:
        raise Refused("Configured partition no longer belongs to designated disk")
    if str(d.get("serial") or "").strip() != identity.serial:
        raise Refused("Disk serial changed")
    if p.get("partuuid") != identity.partuuid or p.get("uuid") != identity.luks_uuid:
        raise Refused("Partition or LUKS identity changed")
    if mapping.get("pkname") != part or mapping.get("type") != "crypt":
        raise Refused("Encryption mapping is not backed by the designated partition")
    runner(["cryptsetup", "isLuks", "--type", "luks2", identity.partition])
    partition_table = json.loads(runner(["sfdisk", "--json", identity.disk]))["partitiontable"]
    if partition_table["label"] != "gpt" or len(partition_table["partitions"]) != 1:
        raise Refused("Data disk must have exactly one GPT partition")
    partition_data = partition_table["partitions"][0]
    if os.path.realpath(partition_data["node"]) != part:
        raise Refused("Unexpected partition table target")
    physical = json.loads(runner(["pvs", "--reportformat", "json", "--units", "b", "--nosuffix", "-o",
                                 "pv_name,pv_uuid,vg_uuid,pv_size,vg_name"]))["report"][0]["pv"]
    pool_pvs = [r for r in physical if r["vg_uuid"] == identity.vg_uuid]
    expected_pvs = {identity.pv_uuid: identity.luks_uuid, **dict(identity.additional_pvs)}
    if len(expected_pvs) != 1 + len(identity.additional_pvs) or {r["pv_uuid"] for r in pool_pvs} != set(expected_pvs):
        raise Refused("Volume group members do not match the enrolled encryption registry")
    for member in pool_pvs:
        member_node = next((n for n in nodes if os.path.realpath(n["name"]) == os.path.realpath(member["pv_name"])), None)
        parent = one(member_node.get("pkname")) if member_node else None
        if not member_node or member_node["type"] != "crypt" or not parent or parent.get("uuid") != expected_pvs[member["pv_uuid"]]:
            raise Refused("A pool member is not backed by its enrolled LUKS container")
        runner(["cryptsetup", "isLuks", "--type", "luks2", parent["name"]])
    physical = next((r for r in physical if r["pv_uuid"] == identity.pv_uuid), None)
    if not physical or os.path.realpath(physical["pv_name"]) != os.path.realpath("/dev/mapper/" + identity.mapper):
        raise Refused("PV is not backed by the verified encryption mapping")
    if physical["vg_uuid"] != identity.vg_uuid or physical["vg_name"] != identity.vg:
        raise Refused("PV has changed storage pool")
    logical = json.loads(runner(["lvs", "--reportformat", "json", "--units", "b", "--nosuffix", "-o",
                                "lv_uuid,lv_path,vg_uuid,lv_size,segtype", identity.lv]))["report"][0]["lv"]
    if len(logical) != 1 or logical[0]["lv_uuid"] != identity.lv_uuid or logical[0]["vg_uuid"] != identity.vg_uuid:
        raise Refused("Logical volume identity changed")
    mount = json.loads(runner(["findmnt", "--json", "--mountpoint", identity.mount]))["filesystems"]
    if len(mount) != 1 or os.path.realpath(mount[0]["source"]) != os.path.realpath(identity.lv):
        raise Refused("Data filesystem is not mounted from designated LV")
    groups = json.loads(runner(["vgs", "--reportformat", "json", "--units", "b", "--nosuffix", "-o",
                               "vg_uuid,vg_free", identity.vg]))["report"][0]["vg"]
    if len(groups) != 1 or groups[0]["vg_uuid"] != identity.vg_uuid:
        raise Refused("Volume group identity changed")
    # System mounts are checked on all descendants of the disk, not only its own node.
    system_disk = any(m in ("/", "/boot", "/boot/efi", "/usr", "/var", "/home")
                      for n in _flatten([d]) for m in (n.get("mountpoints") or []))
    fsstat = os.statvfs(identity.mount)
    lv_bytes = int(float(logical[0]["lv_size"]))
    filesystem_bytes = fsstat.f_blocks*fsstat.f_frsize
    geometry = xfs_geometry(runner(["xfs_info", identity.mount], timeout=5), filesystem_bytes=filesystem_bytes,
                            filesystem_block_size=fsstat.f_frsize, lv_bytes=lv_bytes)
    result = Snapshot(identity, int(d["size"]), int(p["size"]),
                      int(partition_data["start"])*int(partition_table["sectorsize"]), int(mapping["size"]),
                      int(float(physical["pv_size"])), lv_bytes,
                      filesystem_bytes, int(float(groups[0]["vg_free"])),
                      sector_size=int(partition_table["sectorsize"]), filesystem=mount[0]["fstype"],
                      read_only=bool(d["ro"] or p["ro"] or "ro" in mount[0]["options"].split(",")),
                      removable=bool(d["rm"]), system_disk=system_disk,
                      linear=logical[0]["segtype"] == "linear", filesystem_geometry_bytes=geometry)
    result.validate()
    return result


def apply_growth(identity: Identity, expected_fingerprint: str, *, key_file: Path | None = None,
                 state: Path = Path("/var/lib/nebulalog/manager"),
                 inspector: Callable = inspect, runner: Callable = run) -> dict:
    require_linux_root()
    with locked(state / "transaction.lock"):
        before = inspector(identity)
        plan = growth_plan(before)
        if plan["fingerprint"] != expected_fingerprint:
            raise Refused("Storage changed since review; refresh and confirm a new plan")
        if "luks" in plan["stages"]:
            if key_file is None:
                raise Refused("LUKS2 resize requires a secure runtime unlock credential")
            trusted_file(key_file)
            if key_file.stat().st_mode & 0o077:
                raise Refused("Unlock credential must be readable only by root")
            # Verify before touching partition geometry; do not expose key bytes or argv secrets.
            runner(["cryptsetup", "open", "--test-passphrase", "--key-file", str(key_file), identity.partition])
        audit(state / "audit.jsonl", "storage.grow.begin", fingerprint=expected_fingerprint,
              disk=identity.disk, stages=plan["stages"])
        try:
            for stage in plan["stages"]:
                current = inspector(identity)
                if current.identity != before.identity or current.disk_bytes != before.disk_bytes:
                    raise Refused("Disk identity or presented capacity changed mid-transaction")
                if stage == "partition":
                    runner(["growpart", identity.disk, "1"])
                    runner(["udevadm", "settle"])
                    after_partition = inspector(identity)
                    if after_partition.partition_bytes <= current.partition_bytes:
                        raise Refused("Kernel partition geometry did not grow; controlled reboot required")
                elif stage == "luks":
                    runner(["cryptsetup", "resize", "--key-file", str(key_file), identity.mapper])
                elif stage == "pv":
                    runner(["pvresize", "/dev/mapper/" + identity.mapper])
                elif stage == "lv":
                    current = inspector(identity)
                    if current.vg_free_bytes >= 4*MIB:
                        runner(["lvextend", "--extents", "+100%FREE", identity.lv])
                elif stage == "xfs":
                    runner(["xfs_growfs", identity.mount])
                audit(state / "audit.jsonl", "storage.grow.stage", stage=stage)
            after = inspector(identity)
            if growth_plan(after)["stages"]:
                raise Refused("Storage layers did not reach expected capacity; inspect transaction before retry")
            audit(state / "audit.jsonl", "storage.grow.complete", filesystem_bytes=after.filesystem_bytes)
            return {"before": asdict(before), "after": asdict(after), "status": "complete"}
        except Exception as exc:
            audit(state / "audit.jsonl", "storage.grow.failed", reason=type(exc).__name__)
            raise


def blank_disk_plan(disk: str, serial: str, size: int, signatures: list, children: list,
                    holders: list, mounted: bool, read_only: bool, removable: bool) -> dict:
    """Review-only enrollment plan; unknown disks are never selected automatically."""
    if not disk.startswith("/dev/disk/by-id/") or not serial or size < 1024**3:
        raise Refused("A persistent identity and at least 1 GiB are required")
    if signatures or children or holders or mounted or read_only or removable:
        raise Refused("Disk is not blank, unmounted, writable and exclusively available")
    evidence = {"disk": disk, "serial": serial, "bytes": size}
    return {"operation": "add-disk", **evidence,
            "confirmation": hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest(),
            "destructive": True, "steps": ["GPT", "LUKS2", "recovery-key enrollment", "PV", "VG extension", "LV", "XFS"]}
