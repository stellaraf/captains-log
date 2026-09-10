"""Pure recipe/OVF checks; no QEMU process, VM or image build is started."""
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET


PACKER = Path(__file__).resolve().parents[1] / "packer"
SPEC = importlib.util.spec_from_file_location("ova_identity", PACKER / "build_ova.py")
ova = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ova)


class DiskIdentityRecipeTests(unittest.TestCase):
    def test_qcow2_artifacts_skip_intermediate_compaction_and_compression(self):
        text = (PACKER / "nebulalog.pkr.hcl").read_text()
        self.assertRegex(text, r'qemu\s*=\s*\{\s*version\s*=\s*"= 1\.1\.6"')
        source = text.split('source "qemu" "rocky9" {', 1)[1].split('\n}\n', 1)[0]
        settings = re.findall(
            r'(?m)^\s*(format|skip_compaction|disk_compression)\s*=\s*("[^"]*"|true|false)\s*$',
            source)
        self.assertEqual(len(settings), 3)
        # In plugin 1.1.6, compression would still run qemu-img convert even
        # when skip_compaction is true. Both settings define this space budget.
        self.assertEqual(dict(settings), {"format": '"qcow2"', "skip_compaction": "true",
                                         "disk_compression": "false"})

    def test_qemu_frontends_have_distinct_bounded_serials_and_keep_backends(self):
        text = (PACKER / "nebulalog.pkr.hcl").read_text()
        self.assertRegex(text, r'disk_interface\s*=\s*"virtio-scsi"')
        self.assertRegex(text, r'disk_size\s*=\s*"80G"')
        self.assertRegex(text, r'disk_additional_size\s*=\s*\["1T"\]')
        self.assertNotIn('["-drive"', text)
        self.assertNotIn('["-global"', text)
        devices = re.findall(r'\["-device", "([^"]+)"\]', text)
        self.assertEqual(len(devices), 3)
        os_disk, data_disk, nic = devices
        self.assertEqual(nic, "virtio-net,netdev=user.0")
        self.assertIn("virtio-blk-pci,id=nebulalog-os,drive=drive0,", os_disk)
        self.assertIn("virtio-blk-pci,id=nebulalog-data,drive=drive1,", data_disk)
        rendered = [item.split("serial=", 1)[1].replace("${var.build_disk_id}", "0123456789abcdef")
                    for item in (os_disk, data_disk)]
        self.assertEqual(rendered, ["NL0123456789abcdefOS", "NL0123456789abcdefDT"])
        self.assertTrue(all(len(value) == 20 for value in rendered))
        self.assertIn('hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22', text)

    def test_build_identity_is_required_and_does_not_have_a_shared_default(self):
        text = (PACKER / "nebulalog.pkr.hcl").read_text()
        block = text.split('variable "build_disk_id" {', 1)[1].split('\n}\n', 1)[0]
        self.assertNotIn("default", block)
        self.assertIn('regex("^[0-9a-f]{16}$", var.build_disk_id)', block)

    def test_ovf_exposes_vmdk_uuids_without_embedding_shared_serials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            disks = []
            for index, capacity in enumerate((80 * 1024**3, 1024**4), 1):
                path = root / f"nebulalog-disk{index}.vmdk"
                path.write_bytes(b"descriptor fixture")
                disks.append((path, capacity))
            rendered = ET.fromstring(ET.tostring(ova.build_descriptor(disks)))
        vm = rendered.find(f"{{{ova.OVF}}}VirtualSystem")
        self.assertEqual(vm.attrib[f"{{{ova.OVF}}}id"], "nebulalog")
        self.assertEqual(vm.find(f"{{{ova.OVF}}}Name").text, "Captain’s Log")
        self.assertEqual(vm.find(f"{{{ova.OVF}}}Info").text, "Captain’s Log Rocky Linux 9 appliance")
        hardware = vm.find(f"{{{ova.OVF}}}VirtualHardwareSection")
        self.assertEqual(hardware.find(f"{{{ova.OVF}}}System/{{{ova.VSSD}}}VirtualSystemIdentifier").text, "Captain’s Log")
        extras = hardware.findall(f"{{{ova.VMW}}}ExtraConfig")
        self.assertEqual(len(extras), 1)
        self.assertEqual(extras[0].attrib, {f"{{{ova.OVF}}}required": "false",
                         f"{{{ova.VMW}}}key": "disk.EnableUUID", f"{{{ova.VMW}}}value": "true"})
        items = hardware.findall(f"{{{ova.OVF}}}Item")
        fields = [{child.tag.removeprefix("{" + ova.RASD + "}"): child.text for child in item} for item in items]
        disk_fields = [item for item in fields if item["ResourceType"] == "17"]
        self.assertEqual([(item["HostResource"], item["Parent"], item["AddressOnParent"]) for item in disk_fields],
                         [("ovf:/disk/disk1", "3", "0"), ("ovf:/disk/disk2", "3", "1")])
        self.assertEqual(fields[2]["ResourceSubType"], "VirtualSCSI")
        self.assertEqual(fields[5]["ResourceSubType"], "VMXNET3")
        network = rendered.find(f"{{{ova.OVF}}}NetworkSection/{{{ova.OVF}}}Network")
        self.assertEqual(network.attrib[f"{{{ova.OVF}}}name"], "Captain’s Log")
        self.assertEqual(fields[5]["Connection"], network.attrib[f"{{{ova.OVF}}}name"])
        self.assertNotIn("serial", ET.tostring(rendered).decode().lower())


if __name__ == "__main__":
    unittest.main()
