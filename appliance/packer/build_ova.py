#!/usr/bin/env python3
"""Package a built QCOW2 system disk plus blank data disk as an OVA.

This packages artifacts; it does not assert guest boot or hypervisor validation.
Runs qemu-img on explicit input files only, never host block devices.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
import firmware_audit

OVF = "http://schemas.dmtf.org/ovf/envelope/1"
RASD = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
VSSD = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
VMW = "http://www.vmware.com/schema/ovf"
for prefix, uri in (("ovf",OVF),("rasd",RASD),("vssd",VSSD),("xsi",XSI),("vmw",VMW)):
    ET.register_namespace(prefix,uri)

def child(parent, tag, text=None, **attrs):
    elem=ET.SubElement(parent, f"{{{OVF}}}{tag}", {f"{{{OVF}}}{k}":str(v) for k,v in attrs.items()})
    if text is not None: elem.text=str(text)
    return elem

def field(parent,namespace,tag,text):
    ET.SubElement(parent,f"{{{namespace}}}{tag}").text=str(text)

def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024**2),b""):h.update(chunk)
    return h.hexdigest()

def build_descriptor(disks, firmware="bios"):
    """Render the transport descriptor without running tools or a guest."""
    if firmware not in ("bios", "efi"):
        raise ValueError("Supported appliance firmware is bios or efi")
    root=ET.Element(f"{{{OVF}}}Envelope")
    refs=child(root,"References")
    dsection=child(root,"DiskSection");child(dsection,"Info","Captain’s Log disks")
    for index,(path,size) in enumerate(disks,1):
        child(refs,"File",id=f"file{index}",href=path.name,size=path.stat().st_size)
        child(dsection,"Disk",diskId=f"disk{index}",fileRef=f"file{index}",capacity=size,
              capacityAllocationUnits="byte",format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized")
    nets=child(root,"NetworkSection");child(nets,"Info","Appliance network")
    net=child(nets,"Network",name="Captain’s Log");child(net,"Description","Management and Syslog network")
    vm=child(root,"VirtualSystem",id="nebulalog");child(vm,"Info","Captain’s Log Rocky Linux 9 appliance");child(vm,"Name","Captain’s Log")
    ossec=child(vm,"OperatingSystemSection",id=107);child(ossec,"Info","Rocky Linux 9 x86_64")
    hardware=child(vm,"VirtualHardwareSection");child(hardware,"Info","Default appliance hardware")
    systemitem=child(hardware,"System")
    for tag,value in (("ElementName","Virtual Hardware Family"),("InstanceID",0),("VirtualSystemIdentifier","Captain’s Log"),("VirtualSystemType","vmx-19")):
        field(systemitem,VSSD,tag,value)
    def item(instance,kind,name,fields=()):
        entry=child(hardware,"Item")
        for tag,value in (("ElementName",name),("InstanceID",instance),("ResourceType",kind),*fields):field(entry,RASD,tag,value)
    item(1,3,"4 virtual CPUs",(("VirtualQuantity",4),("AllocationUnits","hertz * 10^6")))
    item(2,4,"8192 MB memory",(("VirtualQuantity",8192),("AllocationUnits","byte * 2^20")))
    item(3,6,"VMware paravirtual SCSI controller",(("ResourceSubType","VirtualSCSI"),("Address",0)))
    item(4,17,"System disk",(("HostResource","ovf:/disk/disk1"),("Parent",3),("AddressOnParent",0)))
    item(5,17,"Encrypted data disk (enroll at first boot)",(("HostResource","ovf:/disk/disk2"),("Parent",3),("AddressOnParent",1)))
    item(6,10,"Network adapter",(("ResourceSubType","VMXNET3"),("Connection","Captain’s Log"),("AutomaticAllocation","true")))
    # Expose each VMDK's own persistent SCSI identifier to Linux. Never bake
    # shared serials into the OVF. Other importers may ignore this extension;
    # firstboot still requires actual unique by-id/serial evidence.
    ET.SubElement(hardware, f"{{{VMW}}}ExtraConfig", {
        f"{{{OVF}}}required": "false", f"{{{VMW}}}key": "disk.EnableUUID", f"{{{VMW}}}value": "true"})
    if firmware == "efi":
        # Use VMware's firmware configuration element, not an ExtraConfig hint.
        # An importer that cannot honor this must refuse rather than boot BIOS.
        ET.SubElement(hardware, f"{{{VMW}}}Config", {
            f"{{{OVF}}}required": "true", f"{{{VMW}}}key": "firmware", f"{{{VMW}}}value": "efi"})
    return root

def package(system:Path,data:Path,output:Path,firmware="bios"):
    if firmware not in ("bios", "efi"):
        raise ValueError("Supported appliance firmware is bios or efi")
    if output.exists() or output.is_symlink():raise ValueError("Output already exists")
    for path in (system,data):
        if not path.is_file() or path.is_symlink():raise ValueError("Image inputs must be regular files")
    system, data = system.resolve(), data.resolve()
    if system == data or os.path.samefile(system, data):
        raise ValueError("System and data images must be distinct files")
    output = output.absolute()
    infos = []
    for path in (system, data):
        # Explicit format and absolute file paths prevent protocol/format guessing.
        # Never force-share: QEMU must refuse an image owned by a running writer.
        info=json.loads(subprocess.check_output(["qemu-img","info","-f","qcow2","--output=json",str(path)]))
        if info.get("backing-filename") or info.get("snapshots") or info.get("encrypted"):
            raise ValueError("Package only standalone images without backing files or snapshots")
        if not isinstance(info.get("virtual-size"), int) or info["virtual-size"] <= 0:
            raise ValueError("Image has an invalid virtual capacity")
        subprocess.run(["qemu-img","check","-q","-f","qcow2",str(path)],check=True)
        infos.append(info)
    # Reinspect the actual finalized image here. A supplied JSON receipt alone
    # cannot authorize relabeling a BIOS disk as an EFI appliance.
    audit = firmware_audit.audit(system) if firmware == "efi" else None
    # Conversion and archive coexist until verified publication. This is an
    # allocation estimate, not a request to allocate the virtual 1 TiB data disk.
    reserve = 2 * sum(info.get("actual-size", path.stat().st_size) for info,path in zip(infos,(system,data))) + 2*1024**3
    if shutil.disk_usage(output.parent).free < reserve:
        raise ValueError("Insufficient free space for conversion, archive and working reserve")
    with tempfile.TemporaryDirectory(prefix="nebulalog-ova-",dir=output.parent) as temp:
        work=Path(temp)
        blank=work/"blank-data.qcow2"
        subprocess.run(["qemu-img","create","-q","-f","qcow2",str(blank),str(infos[1]["virtual-size"])],check=True)
        comparison=subprocess.run(["qemu-img","compare","-q","-f","qcow2","-F","qcow2",str(data),str(blank)])
        if comparison.returncode:
            raise ValueError("Data disk must be entirely blank; never distribute initialized data or encryption keys")
        disks=[]
        for index,(source,info) in enumerate(zip((system,data),infos)):
            target=work/f"nebulalog-disk{index+1}.vmdk"
            subprocess.run(["qemu-img","convert","-f","qcow2","-O","vmdk","-o","subformat=streamOptimized",str(source),str(target)],check=True)
            subprocess.run(["qemu-img","compare","-q","-f","qcow2","-F","vmdk",str(source),str(target)],check=True)
            disks.append((target,info["virtual-size"]))
        if audit and sha(system) != audit["system_qcow2_sha256"]:
            raise ValueError("System disk changed after its firmware audit")
        root=build_descriptor(disks, firmware)
        descriptor=work/"nebulalog.ovf"
        ET.ElementTree(root).write(descriptor,encoding="utf-8",xml_declaration=True)
        manifest=work/"nebulalog.mf"
        manifest.write_text("".join(f"SHA256({path.name})= {sha(path)}\n" for path in (descriptor,*(x[0] for x in disks))))
        # Descriptor is first as required by OVA transport convention.
        candidate=work/"candidate.ova"
        with tarfile.open(candidate,"x",format=tarfile.USTAR_FORMAT) as tar:
            for path in (descriptor,manifest,*(x[0] for x in disks)):
                member=tar.gettarinfo(str(path),arcname=path.name)
                member.uid=member.gid=0
                member.uname=member.gname="root"
                member.mode=0o644
                with path.open("rb") as source:
                    tar.addfile(member,source)
        # Read the finished transport back before making the output visible.
        expected={path.name:(path.stat().st_size,sha(path)) for path in (descriptor,manifest,*(x[0] for x in disks))}
        with tarfile.open(candidate,"r:") as tar:
            members=tar.getmembers()
            if [m.name for m in members] != list(expected) or any(not m.isfile() for m in members):
                raise ValueError("OVA member order or type is invalid")
            for member in members:
                digest=hashlib.sha256()
                with tar.extractfile(member) as source:
                    for chunk in iter(lambda:source.read(1024**2),b""):digest.update(chunk)
                if (member.size,digest.hexdigest()) != expected[member.name]:
                    raise ValueError("OVA member verification failed")
        with candidate.open("rb") as stream:os.fsync(stream.fileno())
        # Atomic no-replacement publication. A failed build leaves no partial OVA.
        os.link(candidate,output,follow_symlinks=False)
        descriptor_fd=os.open(output.parent,os.O_RDONLY)
        try:os.fsync(descriptor_fd)
        finally:os.close(descriptor_fd)
    return {"output":str(output),"sha256":sha(output),"disk_conversion_verified":True,
            "blank_data_disk_verified":True,"archive_verified":True,
            "boot_validated":False,"publisher_signature_verified":False,
            "firmware":firmware,"firmware_audit":audit}

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-image",type=Path,required=True)
    parser.add_argument("--data-image",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--firmware",choices=("bios","efi"),default="bios")
    args=parser.parse_args()
    print(json.dumps(package(args.system_image,args.data_image,args.output,args.firmware),indent=2))
