# ClickHouse cryptographic boundary and candidate plan

Assessment date: 2026-09-07. **No ClickHouse artifact is qualified for the NebulaLog FIPS release gate yet.** This directory contains a narrowly scoped [candidate Containerfile](Containerfile), fixed TLS/account configuration, startup gates and the remaining qualification plan. It is for a fresh encrypted guest datastore only. Existing development services and data were not changed.

## Artifact evidence

The original Captain’s Log wrapper and fixed configuration are AGPL-3.0-only,
with the project license at `/opt/nebulalog/LICENSE-NEBULALOG`. ClickHouse retains
Apache-2.0; AWS-LC and vendor distribution components retain their own licenses.
The component boundaries are recorded in `BOM.json` and the bundled license files.

Both artifacts were inspected in isolated, unprivileged, network-disabled Linux amd64 containers on the development Mac. `clickhouse local` queried only `system.build_options` using temporary storage. No server, accounts, certificates, or persistent databases were initialized by those identity inspections. The observations are reproducible using [inspect_image.py](inspect_image.py); successful inspection is not FIPS approval.

| Property | Current upstream artifact | Vendor FIPS candidate |
|---|---|---|
| Repository | `clickhouse/clickhouse-server` | `altinity/clickhouse-server` |
| Version | `25.8.33.6` | `25.3.8.30001.altinityfips` |
| Pinned Linux amd64 manifest | `sha256:4ff0d6c199a9ebb906af75ae406496e8a96edd0187afdc16d51c0fb77ffca588` | `sha256:6254bc404966150468130d2b5b02ebdf7238f21d2d85fbde77bc76c7181447df` |
| Source commit reported by binary | `65eaf18b4a939f3e02aad50b7fbb2711b09495a0` | `0ec342e4405683c138a412d0191897013d6867cd` |
| Binary SHA-256 | `6a96266c0f00897225f9bb2ab0f965111298da75d7ec1b67465c6c9d5cf5ae81` | `080dce0336607e1d38e4deb9c9b95bfca34f587bdfd0613d8584fdce6bf8ee21` |
| Container distribution | Ubuntu 22.04.5 LTS | Ubuntu 22.04.5 LTS |
| `OPENSSL_VERSION` | `3.5.7` | `AWS-LC-FIPS-2.0.0` |
| `FIPS_CLICKHOUSE` | No reported build option | `1` |
| Dynamic TLS/crypto dependency | None in `ldd`; embedded crypto | None in `ldd`; embedded crypto |
| Guest FIPS, TLS, authentication acceptance | Not performed | Not performed |

The candidate's public multi-platform index is `sha256:db25d4c333914380f2e43943098651886ed85cf335e3e91059ec0f3dc23ce06a`. Only its amd64 image was pulled. Its approximately 181 MiB of compressed layers require no source compilation; the small derived image uses those existing layers. See [VALIDATION.md](VALIDATION.md) for the built candidate identity and checks.

Run after obtaining the exact images through the normal artifact verification process:

```sh
python3 appliance/images/clickhouse/inspect_image.py upstream .local/ch-upstream-inspection
python3 appliance/images/clickhouse/inspect_image.py altinity-fips .local/ch-fips-inspection
```

The script refuses an existing output directory and uses `--pull=never`. Its report records source/version, executable hash, actual repository identity, raw evidence hashes and the explicit unqualified result. It creates no release acceptance receipt.

## Why the current image is unqualified

The exact upstream build embeds OpenSSL 3.5.7. Its source disables OpenSSL configuration loading unless `OPENSSL_CONF` is set and explicitly loads default and legacy providers. The image has no FIPS provider or FIPS module configuration at the inspected module locations. Rocky host crypto policy cannot replace this embedded implementation. `USE_SSL=1`, an approved algorithm name, or a FIPS kernel flag is insufficient evidence. [Initializer](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/src/Common/Crypto/OpenSSLInitializer.cpp#L47), [OpenSSL version](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/contrib/openssl-cmake/common/include/openssl/opensslv.h).

Upstream exposes `ENABLE_OPENSSL_DYNAMIC`, defaulting off for amd64. This is a custom-build avenue, not an attestation that a system OpenSSL provider is used or that the official artifact is qualified. The exact build configuration also contains generated-source comments mentioning `enable-fips`; comments do not establish a built, installed or active FIPS module. [Root build option](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/CMakeLists.txt#L467), [crypto build configuration](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/contrib/openssl-cmake/CMakeLists.txt).

The live upstream security policy inspected on the assessment date marks all `25.*` releases unsupported, while listing 26.3 and 26.6–26.8 as supported. This is a separate release-maintenance issue. A recent image build date does not extend branch support. Refresh this policy for every release; third-party lifecycle tables may disagree. [Upstream security policy](https://github.com/ClickHouse/ClickHouse/security).

## Actual appliance authentication versus optional crypto

The original development setup supplied `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD` to the inspected upstream entrypoint, which writes a plaintext `<password>` XML element. That selects `PLAINTEXT_PASSWORD`; ordinary HTTP Basic/header and native authentication compare stored bytes directly. **That inspected account does not invoke SHA256 or SCRAM password hashing.** Native credentials and HTTP headers are unencrypted on its original internal ports. The new appliance candidate has the different TLS/SHA256 contract below; it does not alter the running development service. [XML account loading](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/src/Access/UsersConfigAccessStorage.cpp#L158), [authentication dispatch](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/src/Access/Authentication.cpp#L173), [comparison](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/src/Access/Authentication.cpp#L34).

Other paths remain within the cryptographic assessment:

| Enabled behavior or account method | Implementation in exact upstream source | Required treatment |
|---|---|---|
| SHA256 password creation/verification | OpenSSL SHA256; SQL creation can use `RAND_bytes` salt | Qualify the selected provider and generation path |
| SCRAM-SHA256 | OpenSSL PBKDF2/HMAC/SHA256 | Qualify provider, parameters and protocol use |
| Double-SHA1 password / MySQL challenge | Bundled Poco SHA1 implementation | Exclude from the appliance account/interface allowlist |
| bcrypt | Separate bcrypt/Blowfish library | Exclude unless separately justified; not covered by an OpenSSL certificate |
| SQL encryption and SHA2 functions | OpenSSL EVP | Review available operations and approved parameters, even if TLS is disabled |
| Replication, external object stores, LDAP, other database protocols | Additional authentication/TLS/nonce paths | Keep unneeded integrations disabled and review before enabling |

[Password implementation](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/src/Access/AuthenticationData.cpp), [EVP helpers](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/src/Common/OpenSSLHelpers.cpp), [SQL encryption](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/src/Functions/FunctionsAES.h), [Poco SHA1](https://github.com/ClickHouse/ClickHouse/blob/v25.8.33.6-lts/base/poco/Foundation/src/SHA1Engine.cpp).

A system TLS proxy can protect a connection only up to that proxy. It cannot change ClickHouse's password or SQL cryptographic implementations. Local Podman bridge traffic can remain inside one VM, but it is not automatically loopback-only: the actual network membership, namespace, routing, listeners and host firewall must demonstrate that boundary. The current plaintext authentication path is not a reason to weaken storage or transport to avoid cryptography. It also does not prove the entire server crypto-free.

## Supported vendor path and remaining gates

Altinity lists `25.3.8.30001.altinityfips` as supported and publishes its source, build report and container. The observed binary reports AWS-LC FIPS 2.0.0. The release changes encrypted codec formats and removes some integrations; it cannot be assumed interchangeable with an existing 25.8 installation. [Vendor release](https://github.com/Altinity/ClickHouse/releases/tag/v25.3.8.30001.altinityfips), [vendor lifecycle table](https://docs.altinity.com/altinitystablebuilds/).

The vendor deployment instructions require secure HTTPS/native listeners and disabling plaintext interfaces; they also document startup self-tests and crypto test harnesses. Follow the complete vendor procedure and use CA/hostname verification. Example output elsewhere showing port 9000 is not authorization to retain an insecure listener. [Vendor configuration and verification](https://docs.altinity.com/altinitystablebuilds/fips-compatible-altinity-builds/).

NIST certificate 4816 covers the AWS-LC **static module**, in approved mode. Its policy identifies specific Ubuntu/Amazon Linux and processor environments, not this Rocky guest on every required hypervisor. It also places entropy-strength responsibilities on the calling environment. The certificate does not cover all of ClickHouse. Module self-tests alone do not establish approved use by every enabled feature. [Certificate](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4816), [security policy, sections 2.2, 2.4 and 2.8](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4816.pdf).

The exact Altinity source still includes Poco double-SHA1 and conditional bcrypt account methods. Its FIPS label therefore needs a separate account-method allowlist and privileges that prevent application accounts creating arbitrary users. [Altinity authentication](https://github.com/Altinity/ClickHouse/blob/v25.3.8.30001.altinityfips/src/Access/Authentication.cpp), [Altinity password implementations](https://github.com/Altinity/ClickHouse/blob/v25.3.8.30001.altinityfips/src/Access/AuthenticationData.cpp).

Implementation and qualification sequence:

1. **Select the maintained branch and provenance.** Prefer the vendor FIPS artifact over inventing an upstream provider substitution. Archive source/module/build provenance, a full image/dependency SBOM, licenses, security advisory assessment and a pinned artifact receipt. Confirm access to security updates through the appliance support lifetime. Altinity lists extended support to July 2028, while AWS currently lists FIPS 2.0 support ending April 2027; a module upgrade/backport plan is required before the earlier deadline. [AWS maintenance policy](https://github.com/aws/aws-lc/blob/main/VERSIONING.md).
2. **Use a fresh candidate datastore.** Run the NebulaLog schema and application acceptance suite against 25.3. Test every function, type, TTL, partition, query and backup operation used by NebulaLog. Never start 25.3 on existing 25.8 files. Existing data needs a separately tested export/import or vendor-supported migration with counts, event integrity, retention, settings, rollback and disk-capacity evidence. No migration is authorized by this document.
3. **Replace insecure initializer behavior.** Both vendor entrypoints write plaintext user XML, use password command arguments during initialization, and skip certificate checks in their HTTPS probes. The candidate now bypasses them with the NebulaLog wrapper described below. Its positive guest behavior remains unverified. Generate per-install secrets only on the FIPS guest.
4. **Move every internal client to TLS.** Set API/ingest to `https://clickhouse:8443`, add `clickhouse` to the server certificate SAN, mount the per-install CA into the Go client trust path, and configure the maintenance client for port 9440 with secure mode and strict hostname verification. Keep these ports unpublished outside the appliance. Mount the private key with access limited to the ClickHouse service identity. Secure or disable interserver traffic; no replication is currently required.
5. **Constrain the server.** Disable HTTP/native plaintext, MySQL, PostgreSQL, PROXY, bridges, unauthenticated metrics and unused integration listeners. Apply the vendor's approved TLS protocol/cipher configuration. Use only reviewed password methods through the selected module; deny application account-management privileges. Review SQL crypto/storage codecs and outbound integrations as part of the same boundary.
6. **Qualify the exact runtime.** Record image/module/source identity, approved-service use, startup KAT/integrity results, kernel FIPS state, entropy path and Rocky/hypervisor operating-environment disposition. Run the vendor TLS/ACVP harnesses plus successful/failed authentication, CA/hostname rejection, protocol/cipher rejection, plaintext-port rejection, restart, ingestion, search, retention, backup/restore and lifecycle tests in the guest. Docker build-option inspection is not any of these guest tests.

A custom current-upstream build is the alternative if branch or migration constraints make the vendor candidate unsuitable. That would require its own exact module integration, non-approved-path exclusions, source/build provenance, security patch maintenance and operating-environment assessment; changing the base image or setting an environment variable is insufficient. No heavy source compilation was attempted during this audit.

## Candidate runtime contract

Build from the repository root; the derived image needs no new network packages or source compilation:

```sh
docker buildx build --platform linux/amd64 --network=none --load \
  -t nebulalog/clickhouse-fips:25.3.8.30001-1 \
  -f appliance/images/clickhouse/Containerfile .
python3 appliance/images/clickhouse/verify_development.py \
  --output .local/clickhouse-boundary/candidate-verification.json
python3 -m unittest discover -s appliance/images/clickhouse -p 'test_storage_gate.py'
docker run --rm --pull=never --platform linux/amd64 --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --tmpfs /run/nebulalog-clickhouse:rw,nosuid,nodev,size=256m,mode=0700,uid=101,gid=101 \
  --mount "type=bind,src=$PWD/appliance/images/clickhouse/test_data_state.sh,dst=/opt/nebulalog/test_data_state.sh,readonly" \
  --entrypoint /bin/bash nebulalog/clickhouse-fips:25.3.8.30001-1 \
  /opt/nebulalog/test_data_state.sh
```

Use the resulting immutable image digest in the appliance's offline bundle and lifecycle configuration. The runtime manager must verify that digest. The wrapper checks the vendor module's own integrity tests and build identity; it does not invoke the unrelated Ubuntu OpenSSL CLI or `sha256sum` for runtime security operations. The image's inherited EXPOSE metadata may mention upstream ports; only the two ports present in the fixed server configuration are opened.

| Runtime input | Required value |
|---|---|
| Identity | UID/GID `101:101`, supplementary group `20001` for TLS key access |
| Command | `server`; `health` is a read-only readiness command; arbitrary server flags are refused |
| Kernel/policy | Actual `/proc/sys/crypto/fips_enabled` must be `1`; host `/etc/crypto-policies/config` mounted read-only at the same path must contain `FIPS` |
| Data | Bind mount at `/var/lib/clickhouse`, UID/GID 101, mode 0700, XFS entirely backed by LUKS2 |
| Runtime files | Dedicated tmpfs `/run/nebulalog-clickhouse`, UID/GID 101, mode 0700; allow at least 256 MiB for probe state and private generated configuration |
| Password | Podman secret `nebulalog-ch-password` at `/run/secrets/nebulalog-ch-password`, UID101 mode0400, exactly 64 lowercase hex characters from firstboot's per-install `token_hex(32)` |
| Optional env | `CLICKHOUSE_PASSWORD_FILE=/run/secrets/nebulalog-ch-password`, `CLICKHOUSE_USER=nebulalog`, `CLICKHOUSE_DB=nebulalog`; these are also defaults |
| Forbidden env | Inline `CLICKHOUSE_PASSWORD`, account-management enablement, alternate crypto/library/initializer configuration |
| TLS | Read-only `/etc/nebulalog/tls/server.crt`, `server.key`, `ca.crt`; key must be root:20001 mode0640; RSA3072 server certificate must include `clickhouse`, `localhost` and `127.0.0.1` SANs |
| External application client | `CH_URL=https://clickhouse:8443`; its CA bundle must trust the per-install CA and verify the `clickhouse` hostname |
| Maintenance client | Keep canonical `/etc/nebulalog/clickhouse-client.xml` if needed; render the same strict secure/port9440/CA/hostname settings as [client.xml.in](client.xml.in) |
| Ports | HTTPS 8443 and native TLS 9440 inside the appliance network; publish neither externally |
| Server configuration | Immutable `/opt/nebulalog/server.xml`; `/etc/clickhouse-server/config.d` is unused and must not be mounted as a customization interface |

The wrapper's storage gate reads only mount metadata and the kernel sysfs block graph. It follows the XFS/LVM/LUKS2 chain and requires every raw backing branch to cross a `CRYPT-LUKS2-` device; mixed, unknown, cyclic or excessively large graphs fail. It does not require privileged mode, a block device mount, or a broad host sysfs mount. If Podman masks necessary metadata, investigate the exact denial before exposing any additional path. Firstboot's actual LUKS header/device verification remains authoritative; the container topology check does not replace it.

On each startup the wrapper checks host/storage prerequisites, then queries the fixed vendor binary's module identity. It creates a temporary **loopback-only TLS** probe using an unused public dummy account hash. The probe must report full KAT and integrity success, accept an authenticated TLS query with CA/hostname checking, and terminate cleanly with exit zero within a bounded period. Only then does the wrapper read the actual account password and compute its SHA256 using the vendor binary's AWS-LC-backed SQL implementation, passing the secret solely over standard input. It generates protected XML in tmpfs, configures only a SHA256 account, and starts the persistent TLS-only server. The service account has privileges for `nebulalog.*` and SELECT on `system.*`; no account-management grants or mutable SQL user directory exist.

### Part metadata and measured sizing

The fixed server configuration explicitly enables `system.part_log`; an external `config.d` fragment cannot enable it for this candidate. Daily partitions have a 14-day TTL, allowing the sizing query's eight-day lookback. The queue is limited to 65,536 rows, reserves 1,024 rows, requests a flush at 32,768 rows, and otherwise flushes every 7.5 seconds. Expired whole parts are eligible for deletion during TTL processing, with a one-hour minimum interval between TTL merges. This is time-based retention and a bounded row queue, **not a hard disk-byte limit or a guaranteed deletion deadline**. Stalled merges and a full queue can affect evidence; monitor them. The exact pinned version supports these fields. [System-log configuration parser](https://github.com/Altinity/ClickHouse/blob/v25.3.8.30001.altinityfips/src/Interpreters/SystemLog.cpp#L204), [MergeTree TTL settings](https://github.com/Altinity/ClickHouse/blob/v25.3.8.30001.altinityfips/src/Storages/MergeTree/MergeTreeSettings.cpp).

Part records include operation type, timestamps, row/byte counts, query identifiers and error metadata; no SQL query-text field exists in the pinned part-log schema. `query_log` and `text_log` remain unconfigured, and the service profile keeps `log_queries=false`. Part/error metadata is still protected operational data on encrypted storage. The sizing query counts successful `NewPart` bytes for `nebulalog.events`; it must not substitute merged-part sizes or fabricate historical observations. The table may be absent until the first MergeTree insertion is logged. Verify an actual insert, subsequent successful `NewPart` record, configured TTL and API sizing response in the FIPS guest. [Pinned part-log schema](https://github.com/Altinity/ClickHouse/blob/v25.3.8.30001.altinityfips/src/Interpreters/PartLog.cpp), [part-log behavior](https://clickhouse.com/docs/reference/system-tables/part_log).

### Interrupted first initialization and recovery

The entrypoint locks the data-directory inode without creating a lock file. After host/storage/module/TLS preflight and credential verification, an empty datastore receives `.nebulalog-fips-owner` before any persistent engine write. This single-link regular file is UID/GID101 mode0600 and contains the fixed format/version plus the already computed SHA256 digest of this installation's 256-bit service password. Exclusive creation and a filesystem sync precede engine startup. The record is an installation-consistency check, **not a MAC, tamper-proof attestation or compliance receipt**; a privileged operator can modify it.

Fresh data receives `.nebulalog-fips-format` only after authenticated server readiness. Its exact content is `nebulalog-clickhouse-fips:1:25.3.8.30001.altinityfips`, also UID/GID101 mode0600 and single-link. The private temporary file and final rename are synchronized. After a crash before readiness, automatic retry is allowed only when the valid owner record matches the current version and installation credential. ClickHouse must recover its own existing metadata and pass authenticated readiness. The wrapper does not delete parts, create a readiness marker early, or claim that engine recovery has succeeded merely because the owner record matches.

Recovery handling is conservative:

- **Valid matching owner, no ready marker:** restart normally after resolving the protected engine diagnostic. The startup message identifies owned initialization; subsequent health stays unavailable until recovery and TLS readiness succeed. A stale private pending-marker file is preserved and never followed or overwritten.
- **Nonempty data without a valid owner, malformed owner, linked/wrong-permission records, different credential/version, or invalid ready marker:** startup refuses. Preserve the datastore and diagnostics for explicit review. Do not fabricate either record, relabel foreign files as owned, or rerun an empty-datastore initializer on those files. Restore the original verified credential if it was replaced accidentally, or provision a separate fresh encrypted datastore and use a reviewed restore/migration process.
- **Crash during owner creation or failed sync:** no persistent engine write follows the failed claim. A complete matching owner can be re-synchronized and retried; an incomplete record requires review. The wrapper never repairs an incomplete record automatically.
- **Planned credential rotation or version upgrade:** requires a coordinated, verified record/credential transition or migration. The current initializer intentionally refuses an uncoordinated change; this version-bound record is not an upgrade or rotation framework.

`health` requires host/storage gates, valid owner and recognized format records, current-process readiness state and a successful native TLS query. It returns a runtime observation with `guest_qualification: pending`; neither this output nor the records are a compliance approval. The wrapper's generated private client configuration is `/run/nebulalog-clickhouse/client.xml`, independent of the separately maintained canonical maintenance client file.

Actual FIPS guest startup, clean preflight termination, HTTPS ingestion, certificate rejection, account privilege denials, schema/retention/backups and supported-platform evidence remain required. An earlier no-listener diagnostic emitted successful KAT/integrity followed by ClickHouse's `NO_ELEMENTS_IN_CONFIG` exception code139; **that nonzero run is not accepted by the candidate readiness gate**. The implemented preflight requires a clean loopback TLS run instead.
