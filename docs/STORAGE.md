# Storage

The appliance design separates an 80 GiB system disk from a default 1 TiB data disk. Packer units are binary (1 TiB = 1,099,511,627,776 bytes); UI measurements should state whether displayed units are decimal TB or binary TiB. A virtual thin disk advertises capacity without allocating it all on the host. Guest free space and datastore free space must both be monitored.

The supported data stack is:

```text
stable disk identity → single GPT partition → LUKS2 → LVM PV
                                                     ↓
                                             nebulalog VG
                                                     ↓
                                                  data LV
                                                     ↓
                                       XFS /var/lib/nebulalog
```

Persistent ClickHouse data, ingest spool, PostgreSQL metadata, Keycloak data, exports, application secrets/configuration, backup scratch and update staging belong on this mount. Container startup requires the mount and first-boot gate. An unavailable or locked data disk must stop the data path rather than fall back to the root filesystem.

The host manager stores exact disk serial, PARTUUID, LUKS UUID, PV UUID, VG UUID and LV UUID in root-owned `/etc/nebulalog/storage.json`. It refuses arbitrary `/dev/sdX` identities, the system disk, removable/read-only media, unsupported filesystems, unexpected pool membership and shrink operations. Added PVs are tracked by PV and LUKS UUID and must be encrypted. Growing one designated disk does not implicitly initialize other disks.

A linear LVM pool is not RAID. Adding a disk extends the failure domain: losing either disk can lose the combined filesystem. Hypervisor redundancy and independent backups remain necessary. XFS growth is supported by the platform; XFS shrink is not. Do not reduce a virtual disk after use.

Use roughly 15% filesystem free space as operational reserve for merges, exports, ingest and maintenance. Thresholds are 70% information, 80% warning, 90% critical, 95% emergency. The application must audit configured emergency retention decisions; a capacity forecast alone does not delete data. Multi-terabyte log-data backups are separate from configuration backups.

The collector independently checks the filesystem of its open WAL file before each new append on Linux and macOS. Admission preserves a fixed 256 MiB of space available to an unprivileged writer, plus 64 KiB of metadata headroom and the next record rounded to a filesystem allocation block. The configured spool byte cap remains an additional limit. Insufficient or unverifiable free space holds TCP/TLS admission with backpressure and records an error; rejected UDP datagrams increment the drop counter. Already durable records can still drain and checkpoint, and pressure never silently acknowledges or deletes queued records. Admission resumes when space is verifiably available. This check is not a filesystem quota or a guarantee against concurrent space consumption by other processes; the emergency controller, export limits, and operational free-space reserve remain necessary.

Current evidence: growth plans/refusals/resumption are unit tested; no host disks were changed. Rocky LUKS/XFS growth, initial enrollment, UI-to-manager authorization and hypervisor restart recovery must pass appliance acceptance before release.
