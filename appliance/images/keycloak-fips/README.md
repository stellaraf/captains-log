# Keycloak strict-FIPS image candidate

This recipe builds **linux/amd64 Keycloak 26.8.1** with the exact BC-FIPS dependency set in its release POM and Red Hat OpenJDK **21.0.12.1+1** on UBI9. It is a production-oriented candidate, not an accepted/certified appliance image. Current Keycloak recommends Java 21 for its FIPS integration; using the current upstream container's newer Java runtime would not meet that recommendation. [Versioned Keycloak guide](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/fips.adoc), [release dependencies](https://github.com/keycloak/keycloak/blob/26.8.1/pom.xml).

No realm, account, password, encryption material or certificate is generated in the build. First boot supplies those only after the guest's required security checks. The existing development Keycloak and database are not modified by this recipe.

26.8.1 was released on October 13, 2026 and includes security fixes. Community Keycloak fixes vulnerabilities in its current or following minor release according to severity; this pinned image has no long-term support entitlement. NebulaLog must qualify patched image replacements and database migrations regularly. Using UBI does not turn community Keycloak into the separately supported Red Hat build. [Release notes](https://www.keycloak.org/2026/10/keycloak-2681-released), [upstream security policy](https://www.keycloak.org/security).

## Immutable inputs and licensing

The original Captain’s Log entrypoint and theme code are AGPL-3.0-only; the
project license is copied to `/opt/nebulalog/LICENSE-NEBULALOG`. Keycloak and the
inherited enrollment template retain Apache-2.0, and fonts retain their own
licenses. See the [theme README](../../../deploy/keycloak/themes/nebulalog/README.md).

`BOM.json` records exact amd64 image manifests, Java RPM and dependency versions. `bc-fips.sha256` pins original JAR bytes, checked both during URL download and inside the image. The provider checksum was independently matched to Bouncy Castle's published checksum list. All four Maven Central artifacts also passed detached-signature verification against the vendor-linked public key, whose fingerprint and file checksum are recorded in the BOM. A pinned checksum is not a publisher signature or a license grant. [Vendor downloads and checksums](https://www.bouncycastle.org/download/bouncy-castle-java-fips/).

Keycloak's distribution and its third-party license material are retained. The runtime preserves UBI/RPM license files and writes the exact package/version/license inventory to `/opt/nebulalog/rpm-bom.tsv`. Bouncy Castle's original signed JARs are unmodified, and the license text from the utility JAR is separately bundled as `LICENSE-BOUNCY-CASTLE.txt`; do not unpack/repack or strip JAR signatures. Bouncy Castle uses its MIT-style license; UBI comprises individually licensed packages under Red Hat's redistribution terms. The composite image must not be represented as Apache-2.0-only. [Bouncy Castle license](https://www.bouncycastle.org/license.html), [UBI terms](https://www.redhat.com/en/about/red-hat-universal-base-image-end-user-license-agreement).

The NIST certificate currently identifies BC-FJA **2.1.1**, whereas this Keycloak release requires patched **2.1.3**. Record the exact security-module revision and approved operating-environment assessment before any compliance claim. Do not downgrade the dependency to obtain a convenient certificate number. [CMVP 4943](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4943).

## Build and non-guest checks

Use mounted build storage and an owned builder/cache lifecycle as described in
[development storage rules](../../../docs/DEVELOPMENT.md). Remove the exact
owned cache and temporary containers after success or failure, preserving the
output image and rollback archives. From the repository root:

```sh
docker build --platform linux/amd64 \
  -f appliance/images/keycloak-fips/Containerfile \
  -t nebulalog/keycloak-fips:26.8.1-1 .
python3 appliance/images/keycloak-fips/verify_image.py \
  --image nebulalog/keycloak-fips:26.8.1-1 \
  --output .local/keycloak-fips/verification.json
```

The build augments Keycloak for PostgreSQL, health/metrics, strict FIPS and supported recovery-codes/passkeys features; augmentation does not require a live database or generate production account secrets. Provider timestamps are normalized before augmentation so `start --optimized` can verify the prebuilt provider state. The image bundles the Stellar login theme rebased to the 26.8.1 parent. Its enrollment and login flows passed against the non-FIPS 26.8.1 vendor image; this strict-FIPS image still requires its own positive guest/browser qualification. [Container build procedure](https://www.keycloak.org/server/containers).

The verification script starts only isolated, network-disabled, readonly disposable containers. It verifies versions/settings/hashes, nonroot UID and default refusal on the current non-FIPS development kernel. It does **not** substitute a fake FIPS flag, disable a gate, start a database or claim guest startup/login.

The verifier also checks the optimized startup bytecode actually invokes both `setCryptoProvider(FipsMode.STRICT)` and `configureTruststore(FipsMode.STRICT)`. In this release `kc.fips-mode` is omitted from the persisted-properties listing, so `show-config` alone cannot establish the recorded mode. The `initCrypto` recorder combines these operations in 26.8.1. Its bytecode check deliberately targets this pinned release and fails if the generated method layout changes; review it when upgrading. The mode is recorded by the upstream [Keycloak processor](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/deployment/src/main/java/org/keycloak/quarkus/deployment/KeycloakProcessor.java). The current local build receipt and remaining boundaries are in [VALIDATION.md](VALIDATION.md).

## Guest runtime contract

- UID/GID **1000:1000**; readonly root; drop all capabilities; no privilege escalation; private writable `/opt/keycloak/data` and bounded writable `/tmp`; persistent data on the appliance's LUKS2 filesystem. Do not expose the container engine socket.
- Default command **`start --optimized`**. The image already fixes `KC_FEATURES=fips,recovery-codes,passkeys`, `KC_FIPS_MODE=strict`, `KC_DB=postgres`, health/metrics, HTTP disabled and HTTPS 8443. Do not add `--fips-mode`/feature overrides in Quadlets. Single-appliance cache mode is local; clustering requires a separately qualified design.
- Actual host `/proc/sys/crypto/fips_enabled=1` and inherited FIPS JVM configuration are mandatory. Entry point also requires `SunPKCS11-NSS-FIPS` and `XMLDSig` provider names before operations that can create/read credentials. Host-kernel mode alone does not establish the remaining crypto boundary. `--version`, `--help`, and `show-config` are available for build diagnostics.
- Supply a stable public HTTPS `KC_HOSTNAME`, `KC_DB_URL`, `KC_DB_USERNAME`, `KC_DB_PASSWORD`, and enrolled TLS material. Use `KC_HTTPS_KEY_STORE_FILE`, `KC_HTTPS_KEY_STORE_TYPE=BCFKS`, and `KC_HTTPS_KEY_STORE_PASSWORD` for a BCFKS keystore. Generate/store passwords through the privileged first-boot secret workflow, not shell arguments or image layers.
- Alternatively supply `KC_HTTPS_CERTIFICATE_FILE` (PEM leaf plus chain) and `KC_HTTPS_CERTIFICATE_KEY_FILE` (matching RSA PKCS8 PEM). Keycloak supports an in-memory keystore from these files; the on-disk Java-keystore restrictions do not establish a PEM prohibition. The guest must still prove successful strict-mode TLS/chain loading. Shared mode-0640 material owned by root/group 20001 needs that supplementary group granted to container UID1000. [Versioned TLS guide](https://github.com/keycloak/keycloak/blob/26.8.1/docs/guides/server/enabletls.adoc).
- Default ports: **8443 HTTPS**, **9000 management health/metrics**. Keep management private. If behind a proxy, explicitly qualify its HTTPS-to-Keycloak transport, trusted proxy/header settings, public path and callback/issuer URLs. Do not enable public HTTP to solve setup problems.
- Use `KC_BOOTSTRAP_ADMIN_USERNAME`/`KC_BOOTSTRAP_ADMIN_PASSWORD` only for the initial bootstrap if that mechanism is chosen; generate a unique secret, provision the durable administrator, then remove bootstrap credentials from persistent runtime environment. Do not copy development accounts into the appliance.
- The image includes BC provider JARs in the server and required CLI library locations. The host manager owns realm import/bootstrap and encrypted truststore material. It must not invoke unsupported arbitrary shell commands from untrusted UI input.

## Authentication capabilities and required tests

WebAuthn, passkeys and recovery codes are supported/default features in 26.8.1; this image explicitly enables the latter two with FIPS. Feature availability alone does not create enrollment or a correct mandatory-MFA browser flow. [Versioned feature definitions](https://github.com/keycloak/keycloak/blob/26.8.1/common/src/main/java/org/keycloak/common/Profile.java).

The realm bootstrap must set `hashAlgorithm(pbkdf2-sha512)` before users are created and require at least 14-character passwords. Keep RSA keys at least 2048 bits (NebulaLog can use 3072), long random client secrets and the approved keystore form. Avoid importing Argon2-hashed development passwords. SAML requires XMLDSig; AD/LDAPS remains usable, whereas Kerberos/SPNEGO is not an accepted part of this FIPS recipe. [Strict-mode constraints](https://www.keycloak.org/server/fips).

Root-owned realm templates must provide mandatory initial TOTP and recovery-code enrollment, single-use recovery, optional WebAuthn/passkey enrollment with a stable HTTPS RP ID, and a local break-glass path. Real browser tests must cover enroll → fresh login → credential loss/recovery → reuse rejection → revocation for each supported factor, plus wrong-origin/user-verification WebAuthn cases. Do not silently turn mandatory MFA into password-only authentication when recovery or passkeys are added.

## Guest qualification still required

1. Boot the exact image on the install-time-FIPS Rocky9 guest, confirm inherited JVM provider configuration, and retain actual `Approved Mode` plus `FIPS-JVM: enabled` Keycloak crypto startup evidence. Keep security-provider tracing limited to qualification and review logs for secrets before retention.
2. Exercise real PostgreSQL initialization/migration, HTTPS/BCFKS loading, health, browser issuer/callbacks, local login/MFA/recovery/passkeys, RBAC and the Stellar theme.
3. Exercise real AD/LDAPS, SAML, OIDC, signing-key/IdP-certificate rollover and rejection/recovery paths; no non-FIPS algorithm/provider fallback.
4. Test readonly mounts, restart/power failure, backup/restore, supported Keycloak upgrade/rollback and all host security postconditions.
5. Record final OCI digest, SBOM/vulnerability review and exact cryptographic module/OE mapping. A built optimized image or module self-test is not full FIPS qualification.
