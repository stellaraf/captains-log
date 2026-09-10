# Appliance research — 2026-09-07

These findings guide the build; they are not evidence that a NebulaLog OVA has passed acceptance. Target Rocky Linux 9 x86_64. All citations below are upstream or standards-owner sources.

## FIPS installation and scope

- Rocky's release table identifies 9.8 as the current Rocky 9 minor release, with security support through May 2032. Release inputs must pin an ISO checksum and package provenance rather than assume an unversioned download remains identical. [Rocky releases](https://docs.rockylinux.org/latest/releases/)
- RHEL 9 documents booting the **installer** with `fips=1`, followed by verification after boot with `fips-mode-setup --check`. Setting only the system crypto policy is insufficient; the initramfs and kernel boot argument matter. Application keys must be generated after FIPS activation. This is the compatible platform mechanism selected for Rocky 9, subject to testing on the exact Rocky image. [RHEL 9 FIPS installation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/switching-rhel-to-fips-mode_security-hardening)
- Since RHEL 9.6, choosing a STIG installer profile does **not** itself activate FIPS. The installer command line must explicitly contain `fips=1`. [RHEL installation boot requirements](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/interactively_installing_rhel_from_installation_media/booting-the-installer-from-local-media_rhel-installer)
- NIST lists active certificate **5116**, Rocky Linux 9 OpenSSL FIPS Provider, and a specific security policy. This does not certify arbitrary Rocky packages, a container's bundled OpenSSL, Python, Keycloak/JVM, or the whole appliance. The released build must map exact package/module versions, approved modes, operating environment, and crypto boundaries against their certificates. [CMVP 5116](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5116), [module security policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5116.pdf)

## CIS, STIG, and OpenSCAP

- CIS's current Rocky benchmark listing is **Rocky Linux 9 v3.0.0**. The separately listed Build Kit is v2.0.0; those versions must not be conflated. CIS download/licensing terms apply; NebulaLog links to benchmark material and does not copy or redistribute restricted benchmark content. [CIS Rocky Linux benchmark](https://www.cisecurity.org/benchmark/rocky_linux)
- Use installed `openscap-scanner` and `scap-security-guide`, inventory the actual datastream with `oscap info`, record its SHA-256 and profile IDs, and retain machine-readable results plus HTML. RHEL's STIG profile ID is `xccdf_org.ssgproject.content_profile_stig`; this must not be assumed to assess Rocky successfully without the product/platform applicability checks. A scan returning `notapplicable`, `notchecked`, or `error` is not compliance. [RHEL security hardening](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/index), [Red Hat STIG guidance](https://access.redhat.com/compliance/disa-stig)
- Product decision: CIS, STIG, and Unified are selectable policy intents. A released Unified tailoring must maintain a control-by-control conflict/exception register and report CIS and STIG separately. Never report a merged profile or alignment badge merely because the selection was saved. Fail closed when licensed/current/applicable content has not been supplied and reviewed.

## Podman Quadlet

Use rootful systemd to supervise containers running non-root UIDs, isolated networks, no exposed database ports, `NoNewPrivileges`, capability drops and SELinux-labelled encrypted bind mounts. Place distribution Quadlets under `/usr/share/containers/systemd/`; administrator overrides belong under `/etc/containers/systemd/`. Quadlet is a generator, and cgroup v2 is required. Validate against the actual installed Podman version using the generator `--dryrun`: new documentation can contain unsupported keys. Never use container image auto-update tags; NebulaLog's signed release owns digest changes. [Podman Quadlet manual](https://docs.podman.io/en/stable/markdown/podman-systemd.unit.5.html)

## Storage design and growth

Selected stack: designated data disk → final GPT partition → LUKS2 → LVM PV → dedicated `nebulalog` VG → linear `data` LV → mounted XFS. Use stable disk identity plus stored PARTUUID/LUKS UUID/PV UUID/VG UUID/LV UUID, never `/dev/sdb` alone. The system disk and unknown disks are excluded. Different stacks require separate validated plans.

`cryptsetup resize` changes only the active mapping, deriving usable space from its backing device if no size is given. It does not grow a partition or filesystem. For LUKS2 it may require retrieving a token or entering a passphrase again; online growth cannot promise to be unattended without a validated unlock mechanism. [Upstream cryptsetup resize manual](https://gitlab.com/cryptsetup/cryptsetup/-/raw/main/man/cryptsetup-resize.8.adoc)

The full grow order is partition → kernel partition reread → LUKS mapping → PV → LV → XFS. Re-inspect every layer after each action; when the kernel cannot reread a busy partition, stop and require an appliance-controlled reboot rather than proceed on stale geometry. LVM device visibility must be constrained and identity verified. XFS growth is online; shrinking XFS is not supported. [RHEL LVM administration](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_managing_logical_volumes/index)

Operational reserve is filesystem free space, not unallocated LVM extents. A 15% target reserve is deducted in measured capacity projections. Adding a linear PV increases capacity but provides no redundancy: loss of either virtual disk can lose the pool. Unknown disks require an explicit administrator confirmation bound to identity and geometry; detect signatures/partitions/holders/mounts immediately before any destructive operation. Do not auto-enroll raw disks by size or enumeration order.

## Release gates

This research does not substitute for installing a disposable Rocky VM and proving FIPS/SELinux, LUKS and reboot recovery, supported hypervisor disk growth, signed updates and rollback, OpenSCAP applicability, MFA/authentication, database health and durable ingestion. Hardware-specific TPM2/vTPM unlock, Nutanix Guest Tools, VMware/Hyper-V imports and OVA packaging remain acceptance tests, not assumed features.
