# Storage expansion

The implemented host manager creates an identity-bound plan and applies only the fixed supported grow sequence. It will not execute a command list supplied by a browser. The UI bridge and initial first-boot auto-grow/enrollment are not yet release-qualified.

For a qualified appliance, the intended administrator flow is: enlarge the virtual **data** disk in the hypervisor, wait for “Additional Storage Capacity Detected”, review current/presented capacity, and choose **Expand Storage**. A pre-boot enlarged designated disk should be consumed automatically after unique encryption enrollment; that first-boot flow still requires integration validation.

## Hypervisor side

- **VMware vSphere:** identify the data disk by virtual controller/unit and the guest's recorded serial, open VM **Edit Settings**, select that disk, and increase capacity. Snapshot/controller restrictions may prevent online changes. Follow the version-specific VMware procedure; do not remove/recreate the disk.
- **Nutanix AHV:** identify the data vDisk in Prism, use the VM disk update/resize operation supported by the installed AOS/AHV version, and preserve its identity. Prism versions differ; this workflow is not yet validated for Captain’s Log.
- **Proxmox:** select VM **Hardware**, select the data disk, then **Disk Action → Resize** and enter the additional capacity. Confirm controller support before online resize.
- **KVM/libvirt:** enlarge the backing image/block volume with the storage backend's supported tool, then use the domain disk resize operation so the running guest sees the larger virtual block device. A qcow2 file's host allocation size is not its virtual size.
- **Hyper-V:** not validated for this release; do not assume online resizing or OVA import compatibility.

These are administrative workflow descriptions, not tested version-specific deployment support claims. Hypervisor expansion does not expand the encrypted guest stack. Never shrink a disk or reuse an attached disk containing retained logs.

## Guest manager / recovery-console procedure

On an enrolled disposable appliance:

```sh
nebulalog storage plan
nebulalog storage grow --confirm-fingerprint <reviewed-fingerprint> \
  --key-file /run/nebulalog/unlock-key
nebulalog storage status
```

The credential file must be root-owned, regular, mode 0600; use a private runtime tmpfs file supplied through a secure console, never command-line key text. The manager verifies the credential before any partition mutation, refreshes identity under a transaction lock, grows partition → LUKS → PV → LV → XFS and re-inspects. A stale confirmation, failed kernel geometry refresh, unsupported topology or unavailable credential stops the transaction. Growth is irreversible; a failed partial operation is audited and must be re-inspected before retry. No blind rollback/shrink is attempted.

## Additional disk

Adding a blank disk is destructive to that **new** disk and requires separate confirmation:

```sh
nebulalog storage add-plan --disk /dev/disk/by-id/<new-disk>
nebulalog storage add --disk /dev/disk/by-id/<new-disk> \
  --confirmation <reviewed-confirmation> --key-file /run/nebulalog/unlock-key \
  --recovery-destination /run/nebulalog/new-disk-recovery.key
```

The code rejects signatures, partitions, holders, mounts, removable/read-only devices and absent stable serials. It refreshes blankness immediately before creating GPT/LUKS2; enrolls and tests a new recovery key; creates the PV; records intended membership; extends the VG/LV/XFS; and adds the encryption mapping to crypttab. Export the recovery material to protected off-appliance escrow, verify recovery in a maintenance test, then remove the runtime copy. Never rely on a lost `/run` file as the sole recovery method.

This guarded path has **not** been executed on real or loopback Linux disks. Abrupt interruption after VG extension/crypttab changes and LVM devices-file behavior require VM tests before use on retained data. An enrollment journal mismatch intentionally stops further automation. A multi-disk pool increases capacity without adding redundancy.
