"""Actual qemu image/transport checks; these deliberately do not boot a guest."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location("build_ova",Path(__file__).parents[1]/"packer/build_ova.py")
ova=importlib.util.module_from_spec(spec)
spec.loader.exec_module(ova)


@unittest.skipUnless(shutil.which("qemu-img") and shutil.which("qemu-io"),"QEMU image tools are required")
class OVATest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)
        self.system,self.data=self.path/"system.qcow2",self.path/"data.qcow2"
        for path in (self.system,self.data):
            subprocess.run(["qemu-img","create","-q","-f","qcow2",str(path),"16M"],check=True)
        subprocess.run(["qemu-io","-f","qcow2","-c","write -P 0x5a 0 4096",str(self.system)],check=True,stdout=subprocess.DEVNULL)

    def test_real_conversion_manifest_and_atomic_transport(self):
        output=self.path/"candidate.ova"
        result=ova.package(self.system,self.data,output)
        self.assertTrue(result["disk_conversion_verified"])
        self.assertTrue(result["blank_data_disk_verified"])
        self.assertFalse(result["boot_validated"])
        with tarfile.open(output,"r:") as archive:
            self.assertEqual(archive.getnames(),["nebulalog.ovf","nebulalog.mf","nebulalog-disk1.vmdk","nebulalog-disk2.vmdk"])
            manifest=archive.extractfile("nebulalog.mf").read().decode()
            self.assertEqual(len(manifest.splitlines()),3)
            self.assertTrue(all(line.startswith("SHA256(") for line in manifest.splitlines()))
        with self.assertRaises(ValueError):ova.package(self.system,self.data,output)

    def test_initialized_data_is_refused_without_output(self):
        subprocess.run(["qemu-io","-f","qcow2","-c","write -P 0x5a 8192 4096",str(self.data)],check=True,stdout=subprocess.DEVNULL)
        output=self.path/"candidate.ova"
        with self.assertRaisesRegex(ValueError,"entirely blank"):
            ova.package(self.system,self.data,output)
        self.assertFalse(output.exists())

    def test_backing_chain_and_aliased_disk_are_refused(self):
        overlay=self.path/"overlay.qcow2"
        subprocess.run(["qemu-img","create","-q","-f","qcow2","-F","qcow2","-b",str(self.system),str(overlay)],check=True)
        with self.assertRaisesRegex(ValueError,"standalone"):
            ova.package(overlay,self.data,self.path/"chain.ova")
        with self.assertRaisesRegex(ValueError,"distinct"):
            ova.package(self.system,self.system,self.path/"alias.ova")

    def test_efi_packaging_requires_fresh_actual_image_audit_before_publication(self):
        output=self.path/"efi-refused.ova"
        with patch.object(ova.firmware_audit,"audit",side_effect=ValueError("Missing GPT ESP")) as audit:
            with self.assertRaisesRegex(ValueError,"Missing GPT ESP"):
                ova.package(self.system,self.data,output,firmware="efi")
            audit.assert_called_once_with(self.system.resolve())
        self.assertFalse(output.exists())

    def test_efi_package_binds_audit_to_conversion_and_preserves_unqualified_state(self):
        # Only transport wiring is exercised here; the synthetic disk is not a
        # bootable appliance. Static firmware parsing has independent fixtures.
        result_fixture={"system_qcow2_sha256":ova.sha(self.system),"static_disk_audit_verified":True,
                        "boot_validated":False,"secure_boot_validated":False}
        output=self.path/"efi-fixture.ova"
        with patch.object(ova.firmware_audit,"audit",return_value=result_fixture) as audit:
            result=ova.package(self.system,self.data,output,firmware="efi")
            audit.assert_called_once_with(self.system.resolve())
        self.assertEqual(result["firmware"],"efi")
        self.assertEqual(result["firmware_audit"],result_fixture)
        self.assertFalse(result["boot_validated"])
        with tarfile.open(output,"r:") as archive:
            descriptor=ova.ET.fromstring(archive.extractfile("nebulalog.ovf").read())
            self.assertEqual(descriptor.find(".//{"+ova.VMW+"}Config").attrib["{"+ova.VMW+"}value"],"efi")
            self.assertEqual(len(archive.getmembers()),4)  # No NVRAM or TPM member.

    def test_efi_audit_for_other_disk_cannot_authorize_output(self):
        output=self.path/"wrong-firmware-binding.ova"
        with patch.object(ova.firmware_audit,"audit",return_value={"system_qcow2_sha256":"0"*64}):
            with self.assertRaisesRegex(ValueError,"changed after its firmware audit"):
                ova.package(self.system,self.data,output,firmware="efi")
        self.assertFalse(output.exists())


if __name__=="__main__":unittest.main()
