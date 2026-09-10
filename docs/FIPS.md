# FIPS mode and cryptographic boundaries

Captain’s Log does not claim whole-product FIPS certification. A kernel flag or crypto-policy setting is not such certification.

The September 9 native VMware installation of Rocky 9.8 x86_64, running `5.14.0-687.45.1.el9_8.x86_64`, reproduced the HKDF library self-test warning previously seen in the local build. It is not specific to ARM emulation. The public [Red Hat issue](https://access.redhat.com/solutions/7134366) describes the same symptom and is marked in progress; no vendor fix has been verified for this appliance. Native boot and enabled mode flags do not close cryptographic qualification.

Current source shares one kernel-diagnostic classifier between guest qualification and runtime host health. A reported crypto self-test failure makes `host_controls_ok` false, which also blocks lifecycle preflight and successful update health checks. Unavailable or incomplete retained current-boot journal evidence cannot count as healthy. Diagnostic summaries contain categories and counts, not raw kernel messages; absence of a matching warning is recorded only as “no failure observed,” never as certification. Frozen earlier candidates retain their original captured checks.

The image installer is booted with `fips=1` before generating guest build credentials. The Kickstart preflight checks `/proc/sys/crypto/fips_enabled`, and guest provisioning verifies `fips-mode-setup --check`, the `FIPS` crypto policy and SELinux Enforcing. Every deployed appliance must generate new TLS/database/authentication/encryption secrets only after those checks pass. Merely choosing a STIG profile does not enable FIPS on newer RHEL 9 installations. [Official installation mechanism](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/switching-rhel-to-fips-mode_security-hardening)

NIST certificate 5116 covers a specific Rocky Linux 9 OpenSSL FIPS Provider in an approved mode and operating environment. It does not cover arbitrary current Rocky packages or Captain’s Log containers. [CMVP certificate 5116](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5116)

## Required release evidence

| Boundary | Required evidence | Current status |
|---|---|---|
| Host kernel and cryptsetup/LUKS | Exact RPMs, module certificates/security policies, approved operating mode | Unverified |
| Host OpenSSL/Python manager | Exact OpenSSL provider/module loading; SHA256/RSA-PSS and CMS AES-GCM tests in that mode | Algorithm tests passed on development OpenSSL; Rocky provider unverified |
| Go API/ingestion | Frozen `GOFIPS140=v1.0.0` build plus runtime FIPS check, exact module operating environment | CMVP 5247 upstream; exact Captain’s Log build/OE still requires validation |
| Keycloak/JVM | Qualified JDK plus approved Bouncy Castle FIPS providers; strict Keycloak configuration | Requires qualified image and authentication tests |
| PostgreSQL/ClickHouse images | TLS libraries, algorithms and provider mode on actual image digests | Unverified |

A strict Keycloak command-line flag without matching provider jars does not produce a working FIPS identity service. Build failure is preferable to disabling FIPS. TLS interoperability must include older PAN-OS clients, TLS 1.2 Extended Master Secret constraints, LDAPS and SAML/OIDC signatures. Do not weaken system crypto policy to conceal an interoperability failure.

The packaged checks are an implementation of the build gates. No booted Rocky VM or complete module/certificate bill of materials has been validated in this checkout.

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
