"""Explicitly confirmed blank-disk enrollment; never select disks by enumeration."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import re
import stat
from .common import Refused, atomic_json, audit, locked, require_linux_root, run, trusted_file
from .storage import Identity, blank_disk_plan, inspect


def probe_blank(disk: str, runner=run) -> dict:
    if not re.fullmatch(r"/dev/disk/by-id/[A-Za-z0-9_.:-]+",disk):
        raise Refused("A stable whole-disk /dev/disk/by-id path is required")
    device=Path(disk).resolve()
    if not stat.S_ISBLK(device.stat().st_mode):
        raise Refused("Target is not a block device")
    listing=json.loads(runner(["lsblk","--json","--bytes","--paths","--output","NAME,TYPE,SIZE,SERIAL,RO,RM,MOUNTPOINTS",str(device)]))["blockdevices"]
    if len(listing)!=1 or listing[0]["type"]!="disk":
        raise Refused("Target is not an exclusive whole disk")
    item=listing[0]
    signatures=json.loads(runner(["wipefs","--json","--no-act",str(device)])).get("signatures",[])
    holders=list((Path("/sys/class/block")/device.name/"holders").iterdir())
    return blank_disk_plan(disk,str(item.get("serial") or "").strip(),int(item["size"]),signatures,
                           item.get("children",[]),holders,any(item.get("mountpoints") or []),bool(item["ro"]),bool(item["rm"]))


def add_disk(identity_path: Path, disk: str, confirmation: str, key_file: Path,
             recovery_destination: Path, *, state: Path=Path("/var/lib/nebulalog/manager"),
             runner=run, inspector=inspect, prober=probe_blank) -> dict:
    require_linux_root()
    trusted_file(identity_path)
    trusted_file(key_file)
    if key_file.stat().st_mode & 0o077:
        raise Refused("Unlock credential must be root-only")
    if recovery_destination.parent != Path("/run/nebulalog") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", recovery_destination.name) or recovery_destination.exists() or recovery_destination.is_symlink():
        raise Refused("Recovery key output must be a new root-only /run/nebulalog file")
    with locked(state/"transaction.lock"):
        identity=Identity(**json.loads(identity_path.read_text()))
        before=inspector(identity)
        blank=prober(disk)
        if blank["confirmation"] != confirmation or Path(disk).resolve()==Path(identity.disk).resolve():
            raise Refused("New disk confirmation is stale or targets an existing member")
        # The passphrase must already unlock the existing pool, proving an
        # operator possesses recovery material before extending its failure domain.
        runner(["cryptsetup","open","--test-passphrase","--key-file",str(key_file),identity.partition])
        mapping="nebulalog-data"+str(len(identity.additional_pvs)+2)
        partition=disk+"-part1"
        recovery_destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        directory_stat=recovery_destination.parent.lstat()
        if not stat.S_ISDIR(directory_stat.st_mode) or directory_stat.st_uid != 0 or directory_stat.st_mode & 0o077:
            raise Refused("Runtime recovery directory must be private and root-owned")
        fd=os.open(recovery_destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),0o600)
        with os.fdopen(fd,"wb") as output:
            output.write(os.urandom(64));output.flush();os.fsync(output.fileno())
        audit(state/"audit.jsonl","storage.add.begin",disk=disk,serial=blank["serial"],bytes=blank["bytes"],confirmation=confirmation)
        try:
            # Last signature/geometry refresh immediately before destructive GPT creation.
            if prober(disk)["confirmation"] != confirmation:
                raise Refused("New disk changed before initialization")
            runner(["sfdisk","--label","gpt",disk],input=b"label: gpt\nstart=2048, type=L\n")
            runner(["udevadm","settle"])
            runner(["cryptsetup","luksFormat","--batch-mode","--type","luks2","--pbkdf","pbkdf2",
                    "--cipher","aes-xts-plain64","--key-size","512","--hash","sha256","--key-file",str(key_file),partition])
            runner(["cryptsetup","luksAddKey","--pbkdf","pbkdf2","--key-file",str(key_file),partition,str(recovery_destination)])
            runner(["cryptsetup","open","--test-passphrase","--key-file",str(recovery_destination),partition])
            runner(["cryptsetup","open","--key-file",str(key_file),partition,mapping])
            runner(["pvcreate","/dev/mapper/"+mapping])
            pv=json.loads(runner(["pvs","--reportformat","json","-o","pv_uuid","/dev/mapper/"+mapping]))["report"][0]["pv"]
            if len(pv)!=1:raise Refused("New PV identity could not be established")
            luks_uuid=runner(["cryptsetup","luksUUID",partition]).strip()
            updated=replace(identity,additional_pvs=tuple(identity.additional_pvs)+((pv[0]["pv_uuid"],luks_uuid),))
            # Persist the intended registry before VG mutation. If interrupted here,
            # strict status refuses mismatched registry until the recovery journal is reviewed.
            atomic_json(state/"pending-enrollment.json",{"identity":asdict(updated),"disk":disk,"state":"before_vg_extension"})
            runner(["vgextend",identity.vg,"/dev/mapper/"+mapping])
            atomic_json(identity_path,asdict(updated))
            # Ensure restart can activate all pool members; console passphrase is
            # intentional unless qualified TPM enrollment is configured later.
            crypttab=Path("/etc/crypttab")
            existing=crypttab.read_text() if crypttab.exists() else ""
            if any(line.split() and line.split()[0]==mapping for line in existing.splitlines()):
                raise Refused("Encryption mapping name already exists in crypttab")
            fd=os.open(crypttab,os.O_WRONLY|os.O_APPEND|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600)
            with os.fdopen(fd,"a") as out:
                out.write(f"{mapping} UUID={luks_uuid} none luks\n");out.flush();os.fsync(out.fileno())
            runner(["systemctl","daemon-reload"])
            inspector(updated)
            runner(["lvextend","--extents","+100%FREE",identity.lv])
            runner(["xfs_growfs",identity.mount])
            after=inspector(updated)
            if after.filesystem_bytes<=before.filesystem_bytes:
                raise Refused("New storage did not increase filesystem capacity")
            atomic_json(state/"pending-enrollment.json",{"disk":disk,"state":"complete"})
            audit(state/"audit.jsonl","storage.add.complete",disk=disk,filesystem_bytes=after.filesystem_bytes)
            return {"status":"complete","filesystem_bytes":after.filesystem_bytes,"recovery_key_path":str(recovery_destination),
                    "recovery_action":"Export to protected off-appliance escrow, verify, then remove runtime copy"}
        except Exception as exc:
            audit(state/"audit.jsonl","storage.add.failed",disk=disk,reason=type(exc).__name__)
            # Never remove created LUKS/PV data or recovery material during rollback.
            raise
