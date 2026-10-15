# FIPS mode and cryptographic boundaries

Captain’s Log does not claim whole-product FIPS certification. A kernel flag or crypto-policy setting is not such certification.

The September 9 native VMware installation of Rocky 9.8 x86_64, running `5.14.0-687.45.1.el9_8.x86_64`, reproduced the HKDF library self-test warning previously seen in the local build. It is not specific to ARM emulation. The public [Red Hat issue](https://access.redhat.com/solutions/7134366) describes the same symptom and is marked in progress; no vendor fix has been verified for this appliance. Native boot and enabled mode flags do not close cryptographic qualification.

Current source shares one kernel-diagnostic classifier between guest qualification and runtime host health. A reported crypto self-test failure makes `host_controls_ok` false, which also blocks lifecycle preflight and successful update health checks. Unavailable or incomplete retained current-boot journal evidence cannot count as healthy. Diagnostic summaries contain categories and counts, not raw kernel messages; absence of a matching warning is recorded only as “no failure observed,” never as certification. Frozen earlier candidates retain their original captured checks.

The image installer is booted with `fips=1` before generating guest build credentials. The Kickstart preflight checks `/proc/sys/crypto/fips_enabled`, and guest provisioning verifies `fips-mode-setup --check`, the `FIPS` crypto policy and SELinux Enforcing. Every deployed appliance must generate new TLS/database/authentication/encryption secrets only after those checks pass. Merely choosing a STIG profile does not enable FIPS on newer RHEL 9 installations. [Official installation mechanism](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/switching-rhel-to-fips-mode_security-hardening)

NIST certificate 5116 covers a specific Rocky Linux 9 OpenSSL FIPS Provider in an approved mode and operating environment. It does not cover arbitrary current Rocky packages or Captain’s Log containers. [CMVP certificate 5116](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5116)

## October 15 vendor-kernel qualification

The isolated Rocky x86_64 guest installed the four signed vendor kernel packages
for `5.14.0-687.57.1.el9_8` and booted that exact kernel. The previous kernel and
an independently hashed offline copy of both disks and firmware were retained.
No custom kernel or diagnostic module was used for this boot.

The new kernel reproduced `hkdf_extract failed with -22` in its current-boot
journal. First boot refused enrollment and exited with status 1. Kernel FIPS
was `1`, the crypto policy was `FIPS`, SELinux was Enforcing, audit/firewall
services were active, module-signature enforcement was `Y`, and the kernel
taint value was zero. Verification of the three kernel payload RPMs found no
modified payload files. Secure Boot remained disabled in this qualification VM.

This is a failed native qualification of the newer vendor kernel. It does not
establish successful automatic OS updating, appliance enrollment, encrypted
unattended reboot, or VMware/Nutanix acceptance. The product decision remains
vendor-supplied Rocky kernels; the self-test gate has not been bypassed.

Retained evidence in the private T9 build root:

- `outputs/vendor-kernel-687.57.1/qualification-result.json`
- `outputs/vendor-kernel-687.57.1/native-qualification.json`
- `outputs/vendor-kernel-687.57.1/kernel-journal.log`
- `outputs/vendor-kernel-687.57.1/recovery-original/`

## October 12 local qualification evidence

The new T9 build booted Rocky 9.8 kernel
`5.14.0-687.56.1.el9_8.x86_64` and reproduced the HKDF extraction failure in
its current-boot kernel journal. The journal includes the boot header and the
shared classifier records one `hkdf_self_test_failure`. The kernel configuration
hash matched the exact input used by the self-built livepatch qualification.
This newer vendor kernel does not resolve the observed release gate.

The guest reported kernel FIPS enabled, successful `fips-mode-setup --check`,
FIPS crypto policy, SELinux Enforcing, and active firewall/auditing. Its host
OpenSSL 3.5.8 returned the known SHA-256 empty-input digest under both default
properties and `fips=yes`; default MD5 fetch failed as unsupported. These
positive userspace observations do not override the kernel failure or establish
container/application boundaries. Secure Boot was disabled and module signature
enforcement was `N`. New source requires `module.sig_enforce=1`, independently
checks runtime enforcement, and rejects boot entries missing that setting.

Evidence retained under the private T9 build root
`/Volumes/T9/StellarBuilds/CaptainsLog/build-20261012`:

- `outputs/installed-security-001.json`
- `outputs/installed-kernel-crypto-001.json` and `logs/installed-kernel-boot-001.log`
- `outputs/native-openssl-fetch-001.json`
- `logs/guest-module-trust-probe.log` and `logs/guest-keyrings-and-provisioning.log`

The original candidate finished provisioning, but Packer failed its manifest
post-processor and removed its VM output directory. Those disks were not retained;
the diagnostic files, input images and source archives were retained. The
replacement build uses committed source `2bcc6c2`, no post-processor, and
independent live recovery links. The links are not consistent snapshots while
the builder writes.

### Replacement guest early observations

The replacement has now booted the same exact vendor kernel and accepted SSH.
Its early provisioning-time probes report module signature enforcement `Y`,
kernel FIPS `1`, successful FIPS mode verification, FIPS crypto policy, SELinux
Enforcing, and active firewall/audit services. The kernel image and configuration
hashes match the first candidate. The SHA-256/default-MD5 provider checks also
pass again. This closes the earlier missing module-enforcement setting for this
boot; it does not close appliance qualification.

The replacement again reports one HKDF self-test failure. The retained early
journal lacks the boot header, so it cannot independently prove complete boot
coverage; the failure itself is sufficient to reject a healthy result. The
serial capture also records the failure on the installed boot. Secure Boot is
disabled, firmware is in Setup Mode, and the `.machine` keyring is empty. The
disposable qualification certificate has not been enrolled or used to load a
module. Trust enrollment and loading must be tested on the independent guest
copy after the builder exits, not on live recovery links.

Additional retained evidence under the same T9 root:

- `outputs/installed-security-v2-early.json`
- `outputs/native-openssl-fetch-v2-early.json`
- `outputs/installed-kernel-crypto-v2-early.json`
- `logs/installed-kernel-boot-v2-early.log`
- `outputs/installed-boot-serial-v2-early.json`
- `logs/replacement-guest-keyrings.log`

These are early observations while provisioning is active. Final installed
payload, first-boot setup, application crypto, hardening scans, encrypted storage,
signed patch loading and reboot acceptance remain unverified.

## October 12 qualification repair and livepatch evidence

The independent replacement guest was reprovisioned through the normal private
build guard from commit `1e9cec6`. Packer previously omitted the separately
staged source and release provenance, preventing factory host enrollment. The
repair uploads both inputs before installation. Native `verify-selected` now
passes for host generation
`e15d3c53d0a81e750599e8901f8505728aa03472956f456f48889e8f94f1c22a`.
First boot reaches the security check and refuses enrollment because the kernel
crypto self-test fails. This is not a successful setup or appliance acceptance.
Evidence: `logs/qualification-reprovision-validation.log` in the T9 build root.

A disposable signed livepatch was loaded on the exact replacement kernel with
module signature enforcement enabled. Its transition completed and its
qualification-only `/proc/meminfo` marker appeared within the same boot. The
module fixes no vulnerability. It does not prove application health, FIPS
qualification, automatic delivery, or reboot reapplication. Evidence:
`logs/qualification-native-load-003.log`; signed module SHA-256:
`7754d77c7efc4c3ea61d785516bcd0ccff82a6353f7a1a0e84428947a466f61c`.

The qualification CA was enrolled through firmware and the kernel accepted its
leaf signer into the secondary trusted keyring. Production trust provisioning
and persistence remain acceptance requirements; the qualification VM's firmware
variables are not a portable OVA trust-enrollment solution.

A fresh Rocky repository query on October 12 still lists
`5.14.0-687.56.1.el9_8` as the newest available kernel, matching the installed
candidate. No newer vendor kernel was available in that query to test as a fix.
Evidence: `logs/kernel-availability-networked.log`.

## HKDF failure investigation

The project specification requires FIPS mode during installation, the FIPS
crypto policy, delayed appliance-secret generation, and accurate module/version,
operating-environment and exception records. It explicitly disclaims automatic
whole-product certification. These requirements do not turn an observed kernel
self-test failure into a successful qualification result.

The upstream [November 2025 discussion](https://lists.openwall.net/linux-kernel/2025/11/27/162)
identifies the same failure: HKDF passes its salt to HMAC's key-setting API,
while the generic HMAC implementation rejects lengths below 14 bytes in FIPS
mode. The HKDF input keying material, rather than its salt, contains the secret.
This agrees with the retained Rocky source review: the first HKDF test uses a
13-byte salt and the HMAC code enforces the 14-byte minimum. The upstream reply
notes different behavior after the SHA-256 implementation changed in Linux 6.17;
that is not evidence of a fix in this Rocky 5.14 vendor kernel.

A proposed salt-padding RFC was discussed, not established here as an accepted
Rocky backport. Neither importing that proposal, modifying the test vector, nor
filtering its diagnostic is a qualified release repair. Any custom kernel change
would need its own exact-source build, signing/trust, boot and crypto tests,
module-boundary documentation, and a fresh livepatch target. No such change has
been applied. The public [vendor issue](https://access.redhat.com/solutions/7134366)
was rechecked on October 12 and still reports a solution in progress, updated
September 14, 2026. Subscriber-only guidance was not accessed.

## Required release evidence

| Boundary | Required evidence | Current status |
|---|---|---|
| Host kernel and cryptsetup/LUKS | Exact RPMs, module certificates/security policies, approved operating mode | Unverified |
| Host OpenSSL/Python manager | Exact OpenSSL provider/module loading; SHA256/RSA-PSS and CMS AES-GCM tests in that mode | Rocky SHA-256/default-MD5 policy probes passed; complete manager algorithms and approved operating environment unverified |
| Go API/ingestion | Frozen `GOFIPS140=v1.0.0` build plus runtime FIPS check, exact module operating environment | CMVP 5247 upstream; exact Captain’s Log build/OE still requires validation |
| Keycloak/JVM | Qualified JDK plus approved Bouncy Castle FIPS providers; strict Keycloak configuration | Requires qualified image and authentication tests |
| PostgreSQL/ClickHouse images | TLS libraries, algorithms and provider mode on actual image digests | Unverified |

A strict Keycloak command-line flag without matching provider jars does not produce a working FIPS identity service. Build failure is preferable to disabling FIPS. TLS interoperability must include older PAN-OS clients, TLS 1.2 Extended Master Secret constraints, LDAPS and SAML/OIDC signatures. Do not weaken system crypto policy to conceal an interoperability failure.

The packaged checks implement build gates. Partial guest measurements are recorded above; the full cryptographic bill of materials, approved operating environments and appliance acceptance remain unqualified.

Go documents the frozen v1.0.0 module as CMVP certificate 5247. The release build pins that module and requires its runtime FIPS mode rather than assuming the host kernel activates Go cryptography. This does not certify the surrounding application or prove the exact binary/image operating environment. [Go FIPS documentation](https://go.dev/doc/security/fips140)

## Pinned Keycloak image candidate

The [Keycloak image recipe](../appliance/images/keycloak-fips/README.md) now pins Keycloak 26.7.3, UBI9 Red Hat OpenJDK 21.0.12.1+1, and the release's exact four BC-FIPS dependencies with image digests and JAR SHA-256 checks. It enables strict FIPS and supported passkey/recovery-code capabilities without creating accounts or keys during the build. Its entry point refuses credential-bearing operations unless the actual host kernel is in FIPS mode and the JVM exposes the required NSS-FIPS/XMLDSig providers.

This is a build/qualification candidate, not a certified runtime. NIST certificate 4943 currently lists BC-FJA 2.1.1; the compatible Keycloak dependency is patched 2.1.2. That difference and the exact Rocky/UBI/JVM operating environment must be resolved in the release cryptographic boundary assessment. Do not call all four JARs separately certified or imply a non-FIPS development build proves guest FIPS. [Versioned Keycloak dependencies](https://github.com/keycloak/keycloak/blob/26.7.3/pom.xml), [NIST certificate 4943](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4943).

## PostgreSQL image candidate

The [PostgreSQL recipe](../appliance/images/postgresql-fips/README.md) pins PGDG PostgreSQL 17.11 for Rocky 9.8, the amd64 RESF base manifest, signed RPM inputs and matched system OpenSSL 3.5.5 libraries/provider. It checks the actual FIPS kernel, native system crypto policy, approved default properties and provider selection before reading the initialization secret or invoking `initdb`. The isolated development checks establish build identity, system-library linkage and non-FIPS refusal without initializing a database.

Actual guest initialization, SCRAM, backup/restore, provider use and complete module/OE qualification remain unverified. The current internal database transport is unencrypted and has no TLS acceptance claim. NIST certificate 5116 identifies a different exact Rocky provider package/version; it does not establish certification of the public 3.5.5 package or this image. [Certificate 5116](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5116), [security policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5116.pdf).

## ClickHouse boundary and vendor candidate

The [ClickHouse assessment and implementation plan](../appliance/images/clickhouse/README.md) records read-only inspection of the pinned upstream 25.8.33.6 image and an Altinity 25.3.8.30001 FIPS candidate. The upstream binary embeds OpenSSL 3.5.7 and has no inspected FIPS provider. Host crypto policy or a TLS proxy cannot qualify its internal cryptography. Its current plaintext XML service account compares password bytes directly; SHA256/SCRAM hashing findings apply to separately selected account methods, not that account.

The Altinity artifact reports `FIPS_CLICKHOUSE=1` and `AWS-LC-FIPS-2.0.0`, but remains unqualified for Captain’s Log. The derived candidate now supplies fixed TLS-only transports, a SHA256 account, FIPS/storage gates and a protected initializer for fresh encrypted data. Positive guest testing, application/schema compatibility, maintained provenance and exact module/operating-environment evidence remain required. The vendor source retains separate Poco SHA1 and conditional bcrypt paths; the candidate excludes those account methods instead of trusting its FIPS build label alone. No existing ClickHouse service or datastore was replaced. See the assessment for pinned digests, runtime contracts, primary sources, reproduction and explicit release gates.

The fixed candidate configuration includes 14-day part metadata retention for measured storage sizing, with no SQL query-log table. Its pre-engine ownership record permits retry of this installation's interrupted initialization only after all crypto gates and a matching version/credential check; unrelated or malformed data remains refused. [Runtime logging, recovery contract and limitations](../appliance/images/clickhouse/README.md#part-metadata-and-measured-sizing) distinguish these controls from pending real-guest part-log, recovery and FIPS acceptance evidence.

## Isolated HKDF repair diagnostic, October 12, 2026

The [experimental probe](../appliance/experiments/README.md) reproduced the
original failure and passed all 15 unchanged vendor vectors with short public
salts zero-padded before HMAC. FIPS mode, module signature enforcement and the
generic HMAC short-key rejection remained active. The modules export no symbols
and do not replace the installed implementation. Firstboot still refuses the
original kernel self-test failure. This is diagnostic evidence for a candidate
repair, not a repaired or FIPS-qualified kernel or a release acceptance result.
