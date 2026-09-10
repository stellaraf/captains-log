# Rocky clean4 build and installed-guest observations

Evidence date: **2026-09-09**. Target: **Rocky Linux 9.8 x86_64**. The ARM64 host is development tooling only; all four images in the frozen appliance bundle are Linux/amd64.

Packer completed at **17:28:14 UTC** with exit 0 and `seal_image=false`. Offline QEMU integrity checks passed for both standalone QCOW2 files. The data disk matched a blank reference. A separate overlay boot reached the installed guest, collected observations and shut down cleanly; full base hashes remained unchanged.

| Artifact | Identity |
| --- | --- |
| Frozen v9 source snapshot | `5d9960f9eb02c61377e89d4e0bca8a7d0548868f96a50e0244e23344e752f4c0` |
| Source archive SHA-256 | `716926d10a380f0ef47946c7effe227e214af42695cf6250212febe0dba302a1` |
| OS disk | 80 GiB virtual; 5,670,240,256 file bytes; SHA-256 `9b0c7cbb2513e879211d351ecd4ff082fd43c643ce2539e0f5046d96e1304696` |
| Data disk | 1 TiB virtual; 212,992 file bytes; SHA-256 `aff06a546faabbf67123b750dfd8d49e0406d576730050a229c094a45ed40ec3` |
| Observed running kernel | `5.14.0-687.45.1.el9_8.x86_64` |

The guest had the expected private, unsealed build identity, locked root, no enrollment artifacts, and an unmounted empty data directory. SELinux Enforcing and expected path labels were observed. Core systemd files passed syntax/dependency verification. The firstboot gate was failed on this unenrolled private guest; application container units had not yet been generated or started. These observations do not establish firstboot/runtime success.

## Findings that remain open

- FIPS mode and policy were enabled and the OpenSSL FIPS provider was active, but the kernel emitted `basic hdkf test(hmac(sha256-avx2)): hkdf_extract failed with -22`. Exact Rocky `.44.1` and `.45.1` source comparison confirms the test's 13-byte salt conflicts with the FIPS HMAC minimum of 14 bytes. This is an HKDF library self-test failure before digest computation. Generic HMAC/SHA self-test success and enabled mode flags do not clear it; it does not establish an AVX2 arithmetic error or failure of the separate whole kernel algorithm self-test path. [Red Hat reports the same symptom](https://access.redhat.com/solutions/7134366). No verified vendor fix or cryptographic qualification has been established.
- VMware `vmw_pvscsi` and `vmxnet3` modules were available for the running kernel but absent from its current initramfs. VirtIO modules were present. The unsealed build installs the dracut configuration; the sealer explicitly regenerates the initramfs with these drivers. Actual post-seal contents and boot must be verified.
- Sealing has not run. A fresh pristine copy must lose its temporary build account, SSH host keys, machine identity and random seed before distribution. Actual post-shutdown state must be checked, including whether systemd recreates a seed while stopping.
- VMware and Nutanix are both required test targets. Actual import, firstboot, storage identity, recovery and runtime acceptance await test-cluster access and a sealed candidate.

The private harness needed an SSH client UID correction and a corrected `journalctl -k` invocation. Its original failed launcher receipt and the successful manual observation receipt remain separate. Neither correction changed the guest's security policy or the base disks.

Current source now includes more explicit kernel self-test reporting, lifecycle compliance review/retry, and public syslog-CA download wiring. Those changes are **not** in the frozen v9 disks. Their source/runtime tests must not be attributed to this appliance image. Full provisioning, updates, restore, scale and release gates remain in [RELEASE_ACCEPTANCE](../RELEASE_ACCEPTANCE.md).
