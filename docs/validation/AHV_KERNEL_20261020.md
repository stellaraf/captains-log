# AHV native kernel diagnostic — October 20, 2026

**The private diagnostic guest imported and booted on AHV, but the kernel
cryptographic gate failed. No OVA or production appliance is accepted.**

This test used a separately owned copy of the recorded Rocky 9.8 x86_64
diagnostic base, with public vendor kernel
`5.14.0-687.58.1.el9_8.x86_64`. It did not install or qualify the latest
four-image application bundle. Existing qualification guests and recovery
disks were preserved.

## Executed checks

| Check | Observed result |
| --- | --- |
| Source preparation | Recorded source disk hashes matched. Independent disks were flattened and content-compared. The exported QCOW2 was compared with the prepared disk. |
| Temporary access | A unique RSA build key authenticated; the previous build key was refused. The guest received a unique SSH host key and machine ID. |
| Image Service | The upload completed with HTTP 200. The server-reported SHA-256 matched the local export, and the 80 GiB virtual disk was placed on the intended cluster. |
| VM configuration | AHV 11.2.0.2; Q35, Secure Boot, 4 vCPUs, 16 GiB RAM, separate 80 GiB system and 1 TiB blank data disks, SCSI controllers and VirtIO networking. Configuration was read back before power-on. |
| Native identity and network | Pinned SSH host identity and the prepared machine ID matched. The guest DMI UUID matched the created VM. The assigned static address, gateway, DNS and 6-second duplicate-address detection setting were read back. |
| OS security | x86_64, Secure Boot enabled, kernel FIPS flag `1`, crypto policy `FIPS`, SELinux Enforcing, module signature enforcement `Y`, kernel taint `0`, audit and firewall active. |
| Vendor kernel integrity | Verification of the installed kernel-core, kernel-modules-core and kernel-modules packages returned success with no differences. |
| Kernel crypto self-test | **Failed**, as shown below. |
| Captain’s Log enrollment | **Refused** with firstboot exit status `1` because the current boot reports a kernel cryptographic self-test failure. |
| Final resource state | The diagnostic VM was shut down gracefully and its NIC disconnected; both states were read back. Current diagnostic disks, image and private access material are retained for subsequent vendor testing. The local preparation container was removed. |

The native kernel journal contains:

```text
basic hdkf test(hmac(sha256-ni)): hkdf_extract failed with -22
```

The firstboot service reported:

```text
Enrollment blocked: the current boot reports a kernel cryptographic self-test failure
```

This reproduces the earlier VMware failure on a second native hypervisor.
The public Rocky repository was rechecked during the run and still listed
`687.58.1` as the newest kernel-core build. The related vendor issue remains
a separate upstream dependency. [Rocky package index](https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/k/),
[vendor issue](https://access.redhat.com/solutions/7134366).

## Import behavior learned

The first image-creation task rejected a client-supplied UUID. Its terminal
failure and absence of the proposed image were verified before a corrected
request let the server assign the UUID.

The first VM-creation task rejected a boot-disk container that differed from
the uploaded image's container. Its terminal failure and VM absence were
verified before retrying with the image's container for the boot disk.
The separate data disk used the selected data container. Neither failed
request was treated as a completed import.

For this tested Image Service route, bind server-assigned identities to the
owned request, wait for asynchronous outcomes, verify the uploaded checksum
and cluster placement, and keep the boot disk in its image's container.
These observations do not establish direct OVA import support.

## Acceptance limits

No kernel, crypto implementation or enrollment gate was bypassed. FIPS
enablement checks passed; the cryptographic self-test failed. This is not
composite FIPS certification.

The latest application images, sealed factory metadata, graphical enrollment,
encrypted data setup, real identity-provider sign-in, automated OS/application/
log-system updates, reboot/rollback, full restore and performance acceptance
remain separate requirements. All 154 original acceptance rows remain in
scope. This diagnostic result does not close final AHV appliance acceptance,
VMware acceptance or user sign-off.
