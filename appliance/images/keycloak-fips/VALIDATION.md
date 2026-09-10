# Local candidate verification

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
