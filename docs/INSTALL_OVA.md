# OVA installation and build status

**No validated Captain’s Log OVA release is available from this source checkout.** The Rocky recipe, guarded first-installation wizard, bootstrap helpers and packager are implemented. Local tests and an installer-kernel probe do not establish an installed, sealed or imported appliance. See [current evidence and outstanding gates](APPLIANCE_VALIDATION.md).

## Build in an isolated Linux builder

Use a dedicated disposable Linux builder with Packer, the pinned QEMU plugin and QEMU/KVM for x86_64 guests. Linux-hosted QEMU TCG is the slower development fallback; it is not a supported deployment-platform claim. Native macOS QEMU failed the pinned installer's kernel FIPS self-tests and is not the qualified route.

Obtain pinned Rocky Linux 9 x86_64 media from Rocky and independently verify the published checksum/signature. The current recipe selects Rocky 9.8 repositories. Supply exact media SHA-256, a unique temporary RSA build key of at least 3072 bits, unique output/log/socket paths and a verified offline bundle. Never use a production SSH key. The system image is 80 GiB and the sparse blank data image is 1 TiB; binary units are intentional (see [storage](STORAGE.md)).

Build all four exact Linux/amd64 archives with [the offline bundle helper](IMAGE_BUNDLE.md). Final bundle and initial-release metadata must identify the same source snapshot and manifests. A private unsealed base may omit runtime images while candidates are qualified; never distribute it.

Run the following phases from the repository root under a build supervisor
that enforces [development storage and post-run cleanup](DEVELOPMENT.md).
Allocate unique scratch/cache paths on the build volume, require at least
150 GiB free before dispatch, and keep output disks, recovery links and logs
outside those paths. These raw Packer commands do not provide that supervision:

```sh
packer init appliance/packer/nebulalog.pkr.hcl
packer validate -var-file=/build/private/nebulalog.pkrvars.hcl appliance/packer/nebulalog.pkr.hcl
packer build -var-file=/build/private/nebulalog.pkrvars.hcl appliance/packer/nebulalog.pkr.hcl
```

The private variable file supplies `iso_url`, `iso_checksum` (`sha256:` plus 64 hex digits), `build_ssh_private_key`, `image_bundle_directory`, `output_directory`, `build_serial_log`, `build_qmp_socket` and a unique 16-lowercase-hex `build_disk_id`. Use the [frozen-source staging procedure](../appliance/PROVISIONING.md#frozen-source-inputs-for-a-clean-build) for a clean build: it supplies captured source paths and records that public disk identity automatically. The QEMU OS/data serials are distinct and retain the guest's `vda`/`vdb` layout; keep the same serials when rebooting those private disks. `seal_image` defaults to true; false retains a private build guest. Choose KVM where supported; TCG is a fallback. Retain exact inputs and successful provisioning evidence.

Validate the BIOS boot sequence against the selected ISO. Never run the Kickstart on an existing server: it clears the disposable VM's designated system disk. The data disk remains blank. FIPS is requested on the installer command line and checked before provisioning. Root stays locked; the temporary build account and SSH access are removed or disabled at sealing.

After successful pristine-base sealing, package the two completed disk outputs:

```sh
python3 appliance/packer/build_ova.py --system-image <sealed-system.qcow2> \
  --data-image <sealed-blank-data.qcow2> --output <new-nebulalog.ova>
```

The packager converts to stream-optimized VMDK and writes OVF with VMware paravirtual SCSI (`VirtualSCSI`), SHA-256 manifest and OVA tar. It refuses existing output, non-regular/aliased/backing/snapshot inputs and a nonblank data disk, compares converted content and reads the archive back before atomic publication. Reserve scratch space. The image installs a non-host-only initramfs configuration with VMware paravirtual SCSI, VMXNET3 and VirtIO drivers and checks their presence; sealing regenerates the initramfs. Actual hypervisor boot still requires proof. SHA manifests detect corruption; publisher authenticity requires the trusted release signature and build evidence. Disposable packager fixtures are not release artifacts.

The OVF includes `vmw:ExtraConfig` with `disk.EnableUUID=true`, exposing each VMDK's persistent identifier to Linux on VMware instead of embedding shared disk serials. VMware documents this setting for matching guest SCSI IDs to VMDK UUIDs. [VMware disk identity procedure](https://knowledge.broadcom.com/external/article/418101/mapping-a-linux-guest-os-disk-to-its-cor.html), [OVF ExtraConfig contract](https://developer.broadcom.com/xapis/vcloud-suite-api/latest/structures/com/vmware/vcenter/ovf/extra_config-structure.html).

The VMware extension is optional in the OVF so other hypervisors can ignore it. An importer may also filter additional configuration: verify the resulting VMware VM setting before power-on and inspect distinct whole-disk `/dev/disk/by-id` paths and nonempty serials inside the guest before enrollment. On other platforms, configure their supported persistent disk identifiers and perform the same guest check. Missing or changed identity remains a firstboot refusal, not a reason to substitute `/dev/sdX` or relax the guard. Preserve identifiers when moving an enrolled appliance; a new blank deployment needs its own distinct disk identities. Actual import, reboot persistence and clone behavior remain platform acceptance gates.

## Implemented first-installation flow

Once a signed artifact passes release gates, import both disks, select the management network and ensure physical datastore headroom. Thin virtual capacity does not reserve physical space. Enlarge the **data** disk before first boot if desired; reviewed enrollment consumes its presented capacity.

Open the VM's graphical console. A sealed unfinished image presents **Captain’s Log appliance console** on tty1; press Enter to start or resume without a Linux login. The wizard checks host security, lists eligible blank disks, collects network/hostname/DNS/NTP, administrator, baseline, maintenance and retention settings, and requires the full disk serial before initialization. It uses unique unlock/recovery material, then provisions local services.

Store the displayed disk recovery passphrase in an off-appliance vault. Compare the printed certificate SHA-256 fingerprint before trusting HTTPS. Sign in, enroll MFA/account recovery codes, configure forwarding and complete assessment/review. Return to console verification and prove the saved disk recovery passphrase. Only successful current evidence writes the completed-installation receipt. See [first-boot instructions](FIRST_BOOT.md).

`nebulalog-firstboot.service` is the measured host/storage gate, separate from the interactive console. `host-ready` releases containers so browser enrollment can proceed; it is not completed setup. Default disk unlock prompts through the hypervisor console at reboot. vTPM/unattended unlock remains separate qualification work.

The wizard and guards are implemented and unit-tested. Complete behavior in the final imported guest—including keyboard interaction, SELinux certificate access, cold boot/unlock, browser enrollment and recovery—still awaits acceptance. Do not bypass receipts or controls to represent this checkout as a deployable OVA.

## Validation matrix

| Platform | Packaging route | Current evidence |
|---|---|---|
| VMware vSphere | OVF/OVA import; paravirtual SCSI VMDK | Packager implementation; final import/boot/growth unverified |
| Nutanix AHV | Supported image format through Image Service | Unverified; do not assume direct OVA support |
| Proxmox / KVM | QCOW2 import, preserving both disks | Recipe and limited installer-kernel probe; final deployment/growth unverified |
| Hyper-V | Appropriate VHDX and supported generation | Unvalidated; not advertised as supported |

Guest tools (`open-vm-tools`, `qemu-guest-agent`) are included where packaged. Nutanix Guest Tools require the vendor's supported procedure and are not bundled. Tools do not substitute for identity checks or backups. See [appliance research](research/APPLIANCE.md).
