"""Static firmware fixtures; no inspection appliance or product VM is launched."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest.mock import patch


PACKER = Path(__file__).resolve().parents[1] / "packer"


def module(name):
    spec = importlib.util.spec_from_file_location(name, PACKER / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


firmware = module("firmware_audit")
prepare = module("prepare_uefi")
ova = module("build_ova")
BOOT_UUID = "11111111-2222-3333-4444-555555555555"
ROOT_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def pe():
    result = bytearray(1024)
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 60, 64)
    result[64:68] = b"PE\0\0"
    struct.pack_into("<HH", result, 68, 0x8664, 1)
    struct.pack_into("<H", result, 84, 112)
    struct.pack_into("<H", result, 88, 0x20b)
    struct.pack_into("<H", result, 156, 10)
    return bytes(result)


class Guest:
    def __init__(self):
        self.files = {name: pe() for name in firmware.EFI_FILES}
        self.files.update({
            "/usr/lib/os-release": b'ID="rocky"\nVERSION_ID="9.8"\n',
            "/boot/efi/EFI/rocky/BOOTX64.CSV": "shimx64.efi,Rocky Linux,,Boot Rocky\n".encode("utf-16-le"),
            "/boot/efi/EFI/rocky/grub.cfg": ("search --no-floppy --fs-uuid --set=dev " + BOOT_UUID +
                "\nset prefix=($dev)/grub2\nexport $prefix\nconfigfile $prefix/grub.cfg\n").encode(),
            "/boot/grub2/grub.cfg": b"insmod blscfg\nblscfg\n",
            "/boot/loader/entries/fixture.conf": ("title Rocky Linux\nlinux /vmlinuz-fixture.x86_64\n"
                "initrd /initramfs-fixture.x86_64.img\noptions root=UUID=" + ROOT_UUID + " ro fips=1 module.sig_enforce=1\n").encode(),
            "/boot/vmlinuz-fixture.x86_64": b"fixture kernel",
            "/boot/initramfs-fixture.x86_64.img": b"fixture initramfs"})
        self.mounts = {"/": "/dev/system/root", "/boot": "/dev/sda2", "/boot/efi": "/dev/sda1"}
        self.mounted = []
        self.symlinks = set()
    def list_devices(self): return ["/dev/sda"]
    def inspect_os(self): return ["/dev/system/root"]
    def inspect_get_type(self, root): return "linux"
    def inspect_get_arch(self, root): return "x86_64"
    def part_get_parttype(self, disk): return "gpt"
    def inspect_get_mountpoints(self, root): return self.mounts
    def part_to_dev(self, part): return part[:-1]
    def list_partitions(self): return ["/dev/sda1", "/dev/sda2", "/dev/sda3"]
    def part_to_partnum(self, part): return int(part[-1])
    def part_get_gpt_type(self, disk, num): return firmware.ESP_TYPE if num == 1 else "not-an-esp"
    def vfs_type(self, part): return "vfat" if part.endswith("1") else "xfs"
    def vfs_uuid(self, part): return BOOT_UUID if part == self.mounts["/boot"] else ROOT_UUID
    def mount_ro(self, device, mount): self.mounted.append((device, mount))
    def is_file(self, path, *, followsymlinks):
        assert followsymlinks is False
        return path in self.files and path not in self.symlinks
    def filesize(self, path): return len(self.files[path])
    def read_file(self, path): return self.files[path]
    def ls(self, path):
        assert path == "/boot/loader/entries"
        return [name.rsplit("/", 1)[1] for name in self.files if name.startswith(path + "/")]


class StaticFirmwareTests(unittest.TestCase):
    def test_real_structure_fixture_binds_esp_boot_root_and_fallback(self):
        guest = Guest()
        result = firmware.inspect(guest)
        self.assertEqual(result["boot_uuid"], BOOT_UUID)
        self.assertEqual(result["root_uuid"], ROOT_UUID)
        self.assertTrue(result["boot_configuration_bound"])
        self.assertEqual([path for _, path in guest.mounted], ["/", "/boot", "/boot/efi"])
        self.assertEqual(result["efi_file_sha256"][firmware.EFI_FILES[0]], hashlib.sha256(pe()).hexdigest())

    def test_mislabeled_bios_arm_missing_wrong_or_duplicate_esp_refused(self):
        mutations = [
            ("part_get_parttype", lambda disk: "msdos"),
            ("inspect_get_arch", lambda root: "aarch64"),
            ("part_get_gpt_type", lambda disk, num: "wrong"),
            ("part_get_gpt_type", lambda disk, num: firmware.ESP_TYPE),
            ("vfs_type", lambda part: "xfs"),
            ("list_devices", lambda: ["/dev/sda", "/dev/sdb"])]
        for name, replacement in mutations:
            with self.subTest(name=name):
                guest = Guest()
                setattr(guest, name, replacement)
                with self.assertRaises(ValueError): firmware.inspect(guest)
        for path in ("/boot", "/boot/efi"):
            guest = Guest()
            del guest.mounts[path]
            with self.assertRaises(ValueError): firmware.inspect(guest)
        guest = Guest()
        guest.mounts["/boot/efi"] = "/dev/sdb1"
        with self.assertRaisesRegex(ValueError, "system disk"): firmware.inspect(guest)

    def test_wrong_arch_truncation_and_non_efi_pe_refused(self):
        for offset, value in ((68, 0xaa64), (88, 0x10b), (156, 3), (84, 1)):
            with self.subTest(offset=offset):
                raw = bytearray(pe())
                struct.pack_into("<H", raw, offset, value)
                with self.assertRaises(ValueError): firmware.pe_x64(raw)
        for raw in (b"no", pe()[:100], pe().replace(b"MZ", b"NO", 1)):
            with self.assertRaises(ValueError): firmware.pe_x64(raw)
        raw = bytearray(pe())
        struct.pack_into("<I", raw, 60, 0xffffffff)
        with self.assertRaises(ValueError): firmware.pe_x64(raw)

    def test_boot_uuid_configuration_and_root_binding_refused_on_changes(self):
        cases = [("/boot/efi/EFI/rocky/grub.cfg", BOOT_UUID.encode(), ROOT_UUID.encode()),
                 ("/boot/efi/EFI/rocky/grub.cfg", b"/grub2", b"/evil"),
                 ("/boot/loader/entries/fixture.conf", ROOT_UUID.encode(), BOOT_UUID.encode()),
                 ("/boot/loader/entries/fixture.conf", b"fips=1", b"fips=0"),
                 ("/boot/loader/entries/fixture.conf", b"fips=1", b"fips=1 fips=0"),
                 ("/boot/loader/entries/fixture.conf", b"/vmlinuz-fixture.x86_64", b"/../vmlinuz"),
                 ("/boot/loader/entries/fixture.conf", b"module.sig_enforce=1", b""),
                 ("/boot/loader/entries/fixture.conf", b"module.sig_enforce=1", b"module.sig_enforce=0"),
                 ("/boot/loader/entries/fixture.conf", b"module.sig_enforce=1", b"module.sig_enforce=1 module.sig_enforce=0"),
                 ("/boot/grub2/grub.cfg", b"blscfg", b"disabled")]
        for path, old, new in cases:
            with self.subTest(path=path, old=old):
                guest = Guest()
                guest.files[path] = guest.files[path].replace(old, new)
                with self.assertRaises(ValueError): firmware.inspect(guest)

    def test_missing_kernel_fallback_or_symlink_is_not_accepted(self):
        for path in (firmware.EFI_FILES[2], "/boot/initramfs-fixture.x86_64.img"):
            guest = Guest()
            del guest.files[path]
            with self.assertRaises(ValueError): firmware.inspect(guest)
        guest = Guest()
        guest.files[firmware.EFI_FILES[2]] += b"changed shim"
        with self.assertRaisesRegex(ValueError, "exact Rocky shim"): firmware.inspect(guest)
        guest = Guest()
        guest.symlinks.add(firmware.EFI_FILES[0])
        with self.assertRaisesRegex(ValueError, "regular guest file"): firmware.inspect(guest)

    def test_wrapper_only_opens_readonly_offline_disk_and_never_claims_boot(self):
        guest = Guest()
        calls = []
        guest.set_network = lambda value: calls.append(("network", value))
        guest.add_drive_opts = lambda path, **options: calls.append(("disk", path, options))
        guest.launch = lambda: calls.append(("inspection",))
        guest.close = lambda: calls.append(("closed",))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "system.qcow2"
            path.write_bytes(b"fixture image bytes, never launched")
            with patch.dict("sys.modules", {"guestfs": types.SimpleNamespace(GuestFS=lambda **kw: guest)}), \
                    patch.object(firmware.subprocess, "check_output", return_value=b"{}"):
                result = firmware.audit(path)
            self.assertEqual(result["system_qcow2_sha256"], firmware.sha(path))
            self.assertEqual(calls[0], ("network", False))
            self.assertEqual(calls[1][2], {"format": "qcow2", "readonly": True})
            self.assertEqual(calls[-1], ("closed",))
            for field in ("boot_validated", "secure_boot_validated", "efi_signatures_verified", "tpm_enrolled"):
                self.assertIs(result[field], False)

    def test_wrapper_refuses_chain_and_changed_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "system.qcow2"
            path.write_bytes(b"fixture")
            with patch.object(firmware.subprocess, "check_output", return_value=b'{"backing-filename":"other"}'):
                with self.assertRaisesRegex(ValueError, "standalone"): firmware.audit(path)
            guest = Guest()
            guest.set_network = lambda value: None
            guest.add_drive_opts = lambda *args, **kw: None
            guest.launch = lambda: None
            guest.close = lambda: path.write_bytes(b"modified")
            with patch.dict("sys.modules", {"guestfs": types.SimpleNamespace(GuestFS=lambda **kw: guest)}), \
                    patch.object(firmware.subprocess, "check_output", return_value=b"{}"):
                with self.assertRaisesRegex(ValueError, "changed"): firmware.audit(path)


class FirmwareInputsTests(unittest.TestCase):
    def test_verified_snapshots_are_new_readonly_pinned_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            code, variables = directory / "code.fd", directory / "vars.fd"
            for path, byte in ((code, b"C"), (variables, b"V")):
                raw = bytearray(byte * (64 * 1024))
                raw[40:44] = b"_FVH"
                path.write_bytes(raw)
            output = directory / "snapshot"
            pins = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (code, variables)]
            record = prepare.prepare(code, variables, *pins, output)
            values = json.loads((output / "uefi.pkrvars.json").read_text())["uefi"]
            self.assertEqual(Path(values["code"]).read_bytes(), code.read_bytes())
            self.assertEqual(record["code_sha256"], pins[0])
            self.assertEqual((output / "OVMF_CODE.fd").stat().st_mode & 0o777, 0o400)
            self.assertFalse(record["tpm_created"])
            with self.assertRaises(FileExistsError): prepare.prepare(code, variables, *pins, output)
            with self.assertRaises(ValueError): prepare.prepare(code, variables, "0" * 64, pins[1], directory / "wrong")
            with self.assertRaises(ValueError): prepare.prepare(code, code, pins[0], pins[0], directory / "alias")
            symlink = directory / "link.fd"
            symlink.symlink_to(code)
            with self.assertRaises(OSError): prepare.prepare(symlink, variables, *pins, directory / "link-output")

    def test_uefi_kickstart_is_only_the_documented_derivative_of_bios(self):
        bios = (PACKER / "http/nebulalog.ks").read_text()
        expected = bios.replace("# Installer/build recipe.", "# Opt-in UEFI installer/build recipe.")
        expected = expected.replace("clearpart --all --initlabel --drives=vda", "clearpart --all --initlabel --disklabel=gpt --drives=vda")
        expected = expected.replace("part biosboot --fstype=biosboot --size=1 --ondisk=vda", "part /boot/efi --fstype=efi --size=600 --ondisk=vda")
        expected = expected.replace('set -euo pipefail\ntest "$(cat /proc/sys/crypto/fips_enabled)" = 1',
                                    'set -euo pipefail\ntest -d /sys/firmware/efi\ntest "$(uname -m)" = x86_64\ntest "$(cat /proc/sys/crypto/fips_enabled)" = 1', 1)
        expected = expected.replace("xfsprogs\n", "xfsprogs\nshim-x64\ngrub2-efi-x64\ngrub2-efi-x64-modules\nefibootmgr\ndosfstools\n", 1)
        self.assertEqual((PACKER / "http/nebulalog-uefi.ks").read_text(), expected)

    def test_bios_descriptor_preserved_and_efi_is_required_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "fixture.vmdk"
            disk.write_bytes(b"fixture")
            bios = ova.build_descriptor([(disk, 1024)])
            efi = ova.build_descriptor([(disk, 1024)], "efi")
        self.assertEqual(bios.findall(".//{" + ova.VMW + "}Config"), [])
        config = efi.find(".//{" + ova.VMW + "}Config")
        self.assertEqual(config.attrib, {"{" + ova.OVF + "}required": "true",
                         "{" + ova.VMW + "}key": "firmware", "{" + ova.VMW + "}value": "efi"})
        with self.assertRaises(ValueError): ova.build_descriptor([], "arm")


if __name__ == "__main__": unittest.main()
