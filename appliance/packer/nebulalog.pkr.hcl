packer {
  required_plugins {
    qemu = { version = "= 1.1.6", source = "github.com/hashicorp/qemu" }
  }
}

variable "iso_url" { type = string }
variable "iso_checksum" {
  type = string
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.iso_checksum))
    error_message = "Supply the independently verified Rocky 9 x86_64 ISO SHA256."
  }
}
variable "build_ssh_private_key" {
  type        = string
  sensitive   = true
  description = "Per-build ephemeral RSA >=3072 private key path; never bake it into an image."
}
variable "output_directory" {
  type    = string
  default = "output/nebulalog-rocky9"
}
variable "accelerator" {
  type    = string
  default = "kvm"
}
variable "build_cpus" {
  type    = number
  default = 4
}
variable "build_memory" {
  type    = number
  default = 8192
}
variable "ssh_timeout" {
  type    = string
  default = "90m"
}
variable "seal_image" {
  type        = bool
  default     = true
  description = "False retains an unsealed, private build guest for provisioning tests; never distribute that image."
}
variable "build_serial_log" {
  type    = string
  default = "output/installer-serial.log"
}
variable "build_qmp_socket" {
  type        = string
  default     = "output/nebulalog-build.qmp"
  description = "Unique short socket path for this build; Unix socket paths have a strict length limit."
}
variable "build_disk_id" {
  type        = string
  description = "Unique per-build 16 lowercase hex digits; stage_sources.py records this nonsecret ID. Retain it when rebooting the same private disks."
  validation {
    condition     = can(regex("^[0-9a-f]{16}$", var.build_disk_id))
    error_message = "Supply a new 16-hex build disk identity; never share one identity between builds."
  }
}
variable "image_bundle_directory" {
  type        = string
  default     = "output/image-bundle"
  description = "Verified offline bundle from bundle_images.py. An empty directory is allowed only for a private unsealed base build."
}
variable "appliance_source_directory" {
  type        = string
  default     = "appliance"
  description = "Captured installer/runtime source directory from stage_sources.py for a reproducible build."
}
variable "keycloak_realm_template" {
  type        = string
  default     = "deploy/keycloak/realm.json"
  description = "Captured credential-free Keycloak realm template."
}
variable "kickstart_directory" {
  type        = string
  default     = "appliance/packer/http"
  description = "Captured HTTP directory containing the verified nebulalog.ks."
}

# Opt in only with a separately verified OVMF CODE + pristine VARS template.
# prepare_uefi.py verifies the ordinary SHA256 pins and snapshots those inputs.
# Packer lacks filesha256; its second check hashes the exact base64 encoding.
variable "uefi" {
  type    = object({ code = string, vars = string, code_base64_sha256 = string, vars_base64_sha256 = string })
  default = null
  validation {
    condition = var.uefi == null ? true : try(
      var.uefi.code != var.uefi.vars &&
      can(regex("^[a-f0-9]{64}$", var.uefi.code_base64_sha256)) &&
      can(regex("^[a-f0-9]{64}$", var.uefi.vars_base64_sha256)) &&
      sha256(filebase64(var.uefi.code)) == var.uefi.code_base64_sha256 &&
    sha256(filebase64(var.uefi.vars)) == var.uefi.vars_base64_sha256, false)
    error_message = "UEFI requires the exact separately verified OVMF CODE and pristine VARS snapshots from prepare_uefi.py."
  }
}

source "qemu" "rocky9" {
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = var.output_directory
  vm_name          = "nebulalog-rocky9.qcow2"
  format           = "qcow2"
  # build_ova.py validates these disks and converts directly to streamOptimized
  # VMDK. Avoid Packer's redundant temporary QCOW2 copy after guest shutdown.
  skip_compaction   = true
  disk_compression  = false
  accelerator       = var.accelerator
  machine_type      = var.uefi == null ? "pc" : "q35"
  efi_boot          = var.uefi != null
  efi_firmware_code = var.uefi == null ? null : var.uefi.code
  efi_firmware_vars = var.uefi == null ? null : var.uefi.vars
  efi_drop_efivars  = true
  # A deployed VM gets its own vTPM. Never export a build TPM or NVRAM identity.
  vtpm                 = false
  headless             = true
  cpus                 = var.build_cpus
  memory               = var.build_memory
  disk_size            = "80G"
  disk_additional_size = ["1T"]
  # qemu1.1.6 exposes separate if=none,id=drive0/drive1 backends only through
  # this layout. Explicit virtio-blk devices below keep guest names vda/vdb.
  disk_interface       = "virtio-scsi"
  net_device           = "virtio-net"
  http_directory       = var.kickstart_directory
  ssh_username         = "packer"
  ssh_private_key_file = var.build_ssh_private_key
  ssh_timeout          = var.ssh_timeout
  # The sealer verifies the per-build key against its protected receipt before
  # removing the build account and all keys. Packer must not erase it first.
  ssh_clear_authorized_keys = false
  qmp_enable                = true
  qmp_socket_path           = var.build_qmp_socket
  boot_wait                 = "15s"
  boot_command = var.uefi == null ? [
    "<up><tab> inst.text inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/nebulalog.ks fips=1 console=ttyS0,115200n8 PACKER_AUTHORIZED_KEY={{ .SSHPublicKey | urlquery }}<enter>"
    ] : [
    "c<wait>",
    "search --no-floppy --file --set=root /images/pxeboot/vmlinuz<enter>",
    "linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=Rocky-9-8-x86_64-dvd inst.text inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/nebulalog-uefi.ks fips=1 console=ttyS0,115200n8 PACKER_AUTHORIZED_KEY={{ .SSHPublicKey | urlquery }}<enter>",
    "initrdefi /images/pxeboot/initrd.img<enter>",
    "boot<enter>"
  ]
  qemuargs = [
    ["-cpu", "max"],
    ["-serial", "file:${var.build_serial_log}"],
    ["-device", "virtio-blk-pci,id=nebulalog-os,drive=drive0,serial=NL${var.build_disk_id}OS"],
    ["-device", "virtio-blk-pci,id=nebulalog-data,drive=drive1,serial=NL${var.build_disk_id}DT"],
    ["-device", "virtio-net,netdev=user.0"],
    ["-netdev", "user,id=user.0,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22"]
  ]
  shutdown_timeout = "15m"
  shutdown_command = var.seal_image ? "sudo /usr/local/sbin/nebulalog-seal" : "sudo /usr/sbin/shutdown -P now"
}

build {
  sources = ["source.qemu.rocky9"]
  provisioner "shell" {
    inline = [<<-UPLOAD
python3 - <<'PYUPLOAD'
import os
import pwd
import stat
import sys

def prepare_uploads(directory, uid, gid):
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    names = ("nebulalog-appliance", "nebulalog-image-bundle")
    def inspect(name):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, 0o700) or os.listdir(descriptor):
                raise RuntimeError("Upload destinations must be empty, packer-owned directories with mode 0700")
        finally:
            os.close(descriptor)
    try:
        try:
            os.stat("nebulalog-keycloak-realm.json", dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("An existing realm upload will not be overwritten")
        missing = []
        for name in names:
            try:
                inspect(name)
            except FileNotFoundError:
                missing.append(name)
        for name in missing:
            # An intervening creation is an error, never an object to adopt.
            os.mkdir(name, mode=0o700, dir_fd=parent)
        for name in names:
            inspect(name)
    finally:
        os.close(parent)

if sys.platform != "linux":
    raise SystemExit("Upload preparation requires the disposable Linux build guest")
account = pwd.getpwnam("packer")
if account.pw_uid == 0 or (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (account.pw_uid, account.pw_uid, account.pw_gid, account.pw_gid):
    raise SystemExit("Upload preparation must run as the disposable packer account")
os.umask(0o077)
prepare_uploads("/tmp", account.pw_uid, account.pw_gid)
PYUPLOAD
UPLOAD
    ]
  }
  provisioner "file" {
    source      = var.keycloak_realm_template
    destination = "/tmp/nebulalog-keycloak-realm.json"
  }
  provisioner "file" {
    source      = "${var.appliance_source_directory}/"
    destination = "/tmp/nebulalog-appliance"
  }
  provisioner "file" {
    source      = "${var.image_bundle_directory}/"
    destination = "/tmp/nebulalog-image-bundle"
  }
  provisioner "shell" {
    inline = [
      var.uefi == null ? "test ! -d /sys/firmware/efi" : "test -d /sys/firmware/efi && test \"$(uname -m)\" = x86_64 && mountpoint -q /boot/efi",
      "sudo /bin/bash /tmp/nebulalog-appliance/install-host.sh"
    ]
  }
  post-processor "manifest" {
    output     = "output/packer-manifest.json"
    strip_path = true
  }
}
