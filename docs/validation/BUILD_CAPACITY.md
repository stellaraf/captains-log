# Scoped appliance-build cache reclamation

Observed September 8, 2026 UTC on the shared development host. Cleanup covered reviewed old NebulaLog BuildKit records only. Application data, logs, images, volumes, Docker's disk file, other projects and frozen candidate inputs were preserved.

A read-only Buildx/Engine audit identified **61 old private cache records** with an exact accounting size of **4,404,117,656 bytes**. Two Go 1.25 build trees were linked through retained historical records to explicit NebulaLog compilation commands. The older Keycloak runtime tree matched this repository's exact recipe. Each selected tree was closed over its current children. The 13 protected records, including the current v7 record and its ancestors, were excluded, as were generic upstream layers without sufficient ownership evidence. All selected records were unused, immutable, private, regular and more than an hour old when reviewed.

The first exact-ID prune at **10:50:59 UTC** removed 15 leaves, accounting for **4,005,984 bytes**, and retained their parents. BuildKit updated each newly exposed parent's last-used time and usage count when releasing the child reference. A repeated age-filtered request would not complete that tree deletion.

The reviewed continuation kept the original 61-record scope. Every pass selected only currently exposed leaves and checked the actual child removed in the preceding successful pass, exact metadata, the expected usage-count/time transition, absence of foreign children, unused/private status and the protected records. Unexpected changes, uncertain command outcomes or no progress stop the process. This did not change the appliance's capacity guard or apply a global recent-cache prune.

Eleven bounded continuation passes completed at **10:55:48 UTC**. All 61 selected records were absent afterward, all protected records remained, no image IDs were removed, and the four development-service container identities and runtime state were preserved. The Packer container retained its identity and exited independently because of the [SELinux provisioning refusal](ROCKY_INSTALLER.md). Final host free space was approximately **9.73 GB** at that observation. Packer also removed its unfinished disks during this interval, and the host was active; the full free-space change is not a measured attribution to cache cleanup alone. BuildKit accounting is separate from immediate APFS physical reclamation.

Private receipts include:

- `.local/appliance-build/cache-subgraph-review-20260908T104728Z.json`
- `.local/appliance-build/cache-subgraph-prune-20260908-{start,result}.json`
- `.local/appliance-build/cache-postprune-investigation-20260908T105404Z.json`
- `.local/appliance-build/cache-parent-continuation-20260908-{start,result}.json` and the individual pass receipts

The unchanged clean-build thresholds remain 10 GiB free before launch and a 5 GiB running floor. Bundle upload and installed archive copies coexist, so a successful installation needs more headroom than its final disk size alone. These observations do not supply the much larger space required by the mandatory 100M-event benchmark.

The source recipe now sets `skip_compaction=true` and `disk_compression=false`. With the pinned [QEMU plugin 1.1.6](https://github.com/hashicorp/packer-plugin-qemu/blob/v1.1.6/builder/qemu/step_convert_disk.go), this skips the temporary second OS QCOW2 that the failed clean3 recipe would have created after shutdown. Disk names, guest contents and virtual capacities are preserved; the retained QCOW2 can occupy more host space.

`appliance/packer/build_ova.py` converts the standalone QCOW2 inputs directly to `streamOptimized` VMDK. Its existing `qemu-img info` and consistency checks, blank-data comparison, converted-content comparisons, archive verification and capacity guard remain unchanged. Packaging still requires free space of at least twice the inputs' actual allocation plus 2 GiB for conversion, the coexisting OVA and working reserve. A larger uncompacted input can increase that requirement; skipping Packer compaction does not establish packaging capacity, guest qualification or release acceptance.
