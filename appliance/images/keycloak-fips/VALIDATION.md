# Keycloak 26.8.1 candidate verification — 2026-10-20 UTC

The Linux/amd64 candidate was built with Keycloak **26.8.1**, the current pinned
Red Hat UBI9 Java 21 image, and the exact Bouncy Castle dependency versions in
Keycloak's release POM: **bc-fips 2.1.3**, **bctls-fips 2.1.25**,
**bcpkix-fips 2.1.13** and **bcutil-fips 2.1.8**.

- Local tag: `nebulalog/keycloak-fips:26.8.1-20261020`.
- Manifest: `sha256:1515f912b7d0dee9fb3bd0d0d7028839c35007e41c3df3d468fcd2ac85383d03`.
- Configuration: `sha256:9e50faec14b7331a25b0da6fbcf965180ad234fe32e3950f1e218c1e0792bd7d`.
- Verified OCI archive: **519,958,016 bytes**, SHA-256
  `59232de0e2e209337a76858e38c4c3305dc199a81c1cf27ab1c423b9fa0bf84c`.
- Actual runtime: **21.0.12.1+1-LTS**, RPM
  `java-21-openjdk-headless-21.0.12.1.1-1.2.el9.x86_64`. The newly resolved base
  image digest differs from the older recipe; the Java version is unchanged.
- All four detached Maven signatures verified against the vendor-linked key,
  fingerprint `7B121B76A7ED6CE6E60AD51784E913A8E3A748C0`. The provider SHA-256
  also matched the vendor's checksum list. The image retained original JARs,
  their internal signatures and license material; packaged checksums passed.
- Optimized augmentation completed with PostgreSQL, health/metrics,
  FIPS, recovery-codes and passkeys. The actual generated `initCrypto` method
  invokes both `setCryptoProvider(STRICT)` and `configureTruststore(STRICT)`.
- Six source verifier tests passed using the real generated class as a fixture:
  the original passed; changed mode, provider method, truststore method,
  invocation instructions with intact constants, and truncation were rejected.
- Normal startup on the actual non-FIPS development host returned **78** before
  service startup. UID/GID **1000:1000**, readonly root, network isolation,
  dropped capabilities and no privilege escalation were used for diagnostics.

The older verifier initially refused the renamed generated recorder. Reviewing
26.8.1's processor/recorder source and actual class instructions established the
new layout; the check now requires both strict operations. It was not replaced
with a string-only or environment-only assertion. All temporary verification
containers were removed, including the failed attempt. The owned build cache
was removed after build/export, preserving this image and previous archives.

This is build/artifact and negative-startup evidence. It does not establish
positive native FIPS operation, production PostgreSQL/TLS integration, login,
MFA/recovery/passkeys, external identity providers, native update/rollback or
whole-appliance acceptance. NIST certificate 4943 still lists module 2.1.1;
patched 2.1.3 and this operating environment have not been established as
certified. Complete SBOM/vulnerability and module/environment review remain open.

## Previous candidate evidence

### September candidate verification

Recorded **2026-09-08 04:47 UTC** (2026-09-07 in the development host's America/Phoenix timezone). These are container build and artifact checks on Docker Desktop; no FIPS guest, database or authentication service was started for this verification.

## Artifact identity

| Item | Observed result |
| --- | --- |
| Local tag | `nebulalog/keycloak-fips:26.7.3-1` |
| Local OCI index / Docker image ID | `sha256:10c23255e63a0e3078fa5fa6825a406908312acc86f9664063e7c0c92b2dc36a` |
| linux/amd64 manifest | `sha256:3461effbf37fa74d8c06a317e0422181824926b1f6a4538bd62fa319ec664ee2` |
| Platform | `linux/amd64` |
| Effective image user | `1000:1000` |
| Keycloak | `26.7.3` |
| Runtime | Red Hat OpenJDK `21.0.12.1+1-LTS` |
| Build | Optimized augmentation completed successfully with explicit strict-FIPS/features arguments |
| Provider integrity | All four original JARs passed the pinned SHA-256 checks |
| Optimized configuration | PostgreSQL, health/metrics, FIPS, recovery-codes and passkeys recorded |
| Recorded crypto startup | Generated method invokes `KeycloakRecorder.setCryptoProvider(FipsMode.STRICT)` |
| Development host | Docker LinuxKit; `/proc/sys/crypto/fips_enabled` unavailable |
| Default production start | Refused with exit 78 because the actual host kernel is not FIPS enabled |

The local tag has not been published to a registry. The two immutable parent image manifests and dependency versions are in `BOM.json`; build output identity can change on a fresh augmentation. A release must retain its own final OCI digest after export/import or registry publication.

## Verification scope

`verify_image.py` inspected the actual built image using readonly disposable containers with networking disabled, all capabilities dropped and privilege escalation disabled. It ran `--version`, `show-config`, integrity inspection and the expected default-start refusal. The verifier extracted `generated-bytecode.jar` from an unstarted disposable container and checked the actual crypto startup instructions, not only environment values or a string match. Temporary containers were removed.

The bytecode checker accepted the real strict recorder and rejected three negative variants: changed mode, changed crypto method and a truncated class. Recipe shell syntax, Python compilation and scoped whitespace checks also passed. Local detailed receipts are under `.local/keycloak-fips/`; they contain no appliance credentials and are intentionally outside the release artifact.

## Required before release acceptance

- Boot this exact image on the actual install-time-FIPS Rocky9 guest. Prove inherited NSS-FIPS and XMLDSig providers, BC approved mode and `FIPS-JVM: enabled`; exercise the failure gates on that guest.
- Prove PEM leaf/CA-chain plus RSA PKCS8 loading, HTTPS, PostgreSQL creation/migration and restart using the real readonly mount/group arrangement. BCFKS is the alternative file-keystore contract; it has not been needed or tested here.
- Verify the generated realm's local login, mandatory MFA, recovery enrollment and reuse rejection, WebAuthn/passkeys, SAML, OIDC, AD/LDAPS, role boundaries and bundled Stellar theme in real browsers and providers.
- Review an exhaustive SBOM and current vulnerability findings for the final image, including both runtime RPMs and Keycloak Java/transitive dependencies. The component lock and RPM license inventory are not an exhaustive vulnerability scan.
- Resolve the exact BC-FJA module revision and operating-environment mapping: the reviewed NIST certificate lists 2.1.1, while the Keycloak-compatible provider here is 2.1.2. No claim that the composite image or Rocky/UBI operating environment is certified follows from these checks.
- Exercise image upgrade/database migration, supported recovery/rollback, backup/restore and all appliance host security requirements. Production acceptance belongs to the complete appliance evidence matrix.
