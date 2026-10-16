# Initial software identity and update publisher trust

The first signed update must declare an upgrade path from the software actually installed in the appliance. First boot therefore enrolls measured component versions and immutable image identities, then automatically enrolls the packaged publisher public key. Appliance owners do not need a manual trust command. The trust boundary is the initial appliance image obtained through a trusted distribution process; downloading a key and its checksum together does not independently authenticate that image. The appliance never generates or ships a release signing private key.

## Publisher identity in the build

The publisher supplies two public source inputs: `appliance/security/publisher-public.spki` and `appliance/security/publisher-trust.json`. The descriptor has exactly these fields:

```json
{
  "schema": 1,
  "publisher": "Stellar Technologies",
  "repository": "stellaraf/captains-log",
  "key_id": "captains-log-2026-01",
  "algorithm": "RSA-PSS-SHA256",
  "spki_sha256": "cf342e7a27f5355abd1f5f07ef750922ab4a55e513b332fec334f1fa090e7371"
}
```

This project key is 4,096-bit RSA. Its private key is held outside the repository and appliance build; only the public inputs ship. Local key validation and a real RSA-PSS/SHA-256 signature check have passed. Configuring the protected GitHub release signer, publishing a qualified release and testing that release on a guest are separate remaining steps. This document does not establish an independent trust channel for the key.

The source capture utility checks the public inputs and binds their exact file hashes and DER-SPKI fingerprint into `initial-release.json`. The installer, source stager, archive verifier and sealer validate the same binding. Missing, weak, private, malformed or altered inputs prevent distribution. The public files are installed under `/usr/share/nebulalog/`; first boot never fetches a key from the network. Signatures use RSA-PSS/SHA-256 with MGF1-SHA-256 and a 32-byte salt.

An explicit `prepare_provenance.py --private-unsealed` mode is available only when both public trust source files are absent. It marks the initial descriptor as `publisher: {"mode":"private-unsealed"}`, keeps update readiness false and cannot pass the distribution sealer. Earlier frozen private qualification candidates retain their captured contract and do not acquire factory trust from later source edits.

## Build inputs and initial enrollment

Install these protected, root-owned regular files before sealing the image:

| Path | Content |
| --- | --- |
| `/etc/nebulalog/images.json` | The four immutable Linux/amd64 platform image references. |
| `/usr/share/nebulalog/images/manifest.json` and its OCI archives | The [verified offline bundle](IMAGE_BUNDLE.md). |
| `/usr/share/nebulalog/source-manifest.json` | Captured source snapshot: `{"schema":1,"files":{"relative/source/path":"64-lowercase-hex-sha256"}}`. |
| `/usr/share/nebulalog/initial-release.json` | Explicit initial sequence, schema and provenance, shown below. |
| `/usr/share/nebulalog/publisher-public.spki` and `publisher-trust.json` | The captured public publisher identity and exact descriptor. |

The source manifest is a deterministic, reviewed inventory of tracked and relevant untracked source files. Use sorted keys and a stable encoding when producing it. Exclude credentials, `.local`, `.git`, dependencies such as `node_modules`, build output and packaged artifacts. Paths must be safe repository-relative names; each value hashes the exact source file bytes. Enrollment validates this inventory's structure and exact packaged hash. It does not reconstruct source from container layers or prove that a build was reproducible.

The application image must also carry `io.nebulalog.application-source-sha256` in its OCI configuration labels, supplied as build argument `APPLICATION_SOURCE_SHA256`. Its value hashes the UTF-8 JSON encoding of a subset of `source-manifest.files`, with sorted keys and compact `,`/`:` separators. Select paths under `cmd/`, `internal/`, `web/` and `migrations/`, plus the exact paths `go.mod`, `go.sum`, `appliance/images/application/Containerfile` and `LICENSE`. Generated `web/dist` and `node_modules` must already be excluded from the captured inventory. The pure helper `application_source_digest(files)` defines this calculation. The OCI verifier obtains the label from hash-verified configuration bytes; enrollment requires equality with the captured source subset. A missing label or a newer source snapshot paired with an older application image refuses enrollment. This prevents attributing changed application source to an earlier build while allowing separately captured host-only changes.

The initial descriptor has exactly these fields (placeholder hash values are descriptive, not valid inputs):

```json
{
  "schema": 1,
  "product": "nebulalog",
  "sequence": 0,
  "schema_revision": "2",
  "source_commit": "40-lowercase-hex-base-commit",
  "source_dirty": true,
  "source_snapshot_sha256": "sha256-of-exact-source-manifest.json-bytes",
  "bundle_manifest_sha256": "sha256-of-exact-images/manifest.json-bytes",
  "qualification_status": "pending",
  "publisher": {
    "mode": "factory",
    "descriptor_sha256": "sha256-of-exact-publisher-trust.json-bytes",
    "public_spki_pem_sha256": "sha256-of-exact-publisher-public.spki-bytes",
    "spki_sha256": "cf342e7a27f5355abd1f5f07ef750922ab4a55e513b332fec334f1fa090e7371",
    "repository": "stellaraf/captains-log",
    "key_id": "captains-log-2026-01"
  }
}
```

Sequence is an explicit nonnegative integer below `2^63`; zero is appropriate for the unreleased development candidate. The first signed update must have a strictly higher sequence. `source_commit` identifies the base commit when `source_dirty` is true; it must not be presented as the complete source identity. A promoted signed release requires a clean, tested commit and retained artifact qualification. This initial enrollment interface accepts only `qualification_status: pending`; it makes no production qualification claim.

After encrypted storage, the offline loader, databases, API/ingestion, Keycloak and lifecycle configuration are ready, bootstrap invokes:

```text
/usr/libexec/nebulalog/enroll-installed-release
```

The fixed hook accepts no arguments. It requires the actual first-boot host/storage gate and matching installation UUID. It revalidates all OCI archive/manifest/config/layer hashes, the protected load receipt, immutable installed images and every running container's image ID. It measures both app instances with `nebulalog version`, PostgreSQL with a read-only `server_version` query, ClickHouse with `SELECT version()`, and Keycloak with `kc.sh --version`. API and ingestion versions must match. Container identity is inspected before and after each measurement. Component versions are never inferred from repository tags or hardcoded defaults.

The hook takes the global appliance transaction lock and the updater lock. It writes a durable exact proposal, `current.json`, then `initial-enrollment.json` under encrypted `/var/lib/nebulalog/manager/updates`, all mode `0600`. The receipt binds the installation UUID, build descriptor hash, source and bundle provenance, application source subset hash, actual component versions, image manifest/config digests and archive hashes. An interrupted write resumes only with identical evidence. Changed source, pins, runtime versions, current state or an existing update transaction refuse re-enrollment; the hook cannot reset a release sequence.

The success receipt contains `schema:1`, `ok:true`, `status:"enrolled"`, `installation_id`, `initial_release_sha256`, `current` (sequence, application version and four component records), `publisher_trust` and `qualification_status:"pending"`. Bootstrap must validate that receipt against its installation and protected descriptor, rather than treating exit status alone as proof. Allow a bounded 1,800 seconds for complete archive rehashing and runtime version commands. Each subprocess also has its own shorter timeout. No service is started, stopped or changed by enrollment.

## Automatic first-boot trust enrollment

After software identity enrollment succeeds, `enroll-installed-release` calls the fixed factory-trust operation. It revalidates the captured public inputs and initial installation identity, then uses the same durable, exact-only trust journal described below. Runtime preparation and final setup acceptance independently check that factory enrollment remains valid. Missing or changed trust cannot be counted as ready or silently repaired. Existing trust is never replaced by this step; an interrupted enrollment resumes only when all original inputs still match.

The installed verification key is `/etc/nebulalog/release-public.pem`. The encrypted receipt records the factory provenance reference, installation identity and public fingerprint. An owner can inspect `nebulalog update status` without enrolling any additional key. A signed ordinary software release cannot change publisher trust; key rotation requires a separately designed and tested authorized transition.

## Manual enrollment for legacy private installations

The existing manual command remains available for legacy private installations. It is not an owner step for factory images and cannot be silently adopted as factory enrollment. Obtain the publisher's **public SPKI PEM** and authenticate its **SHA-256 fingerprint of DER-encoded SubjectPublicKeyInfo** through an independent trusted channel. Record the reference used. Fetching the key and its checksum from the same untrusted download does not establish trust.

For comparison, the following prints the SPKI fingerprint of a public key; calculating it locally does not authenticate the key:

```sh
openssl pkey -pubin -in publisher-public.pem -pubout -outform DER | openssl dgst -sha256
```

On the appliance's root console, place the authenticated public key in a protected regular file beneath a protected root-owned directory, then run:

```sh
nebulalog update enroll-trust \
  --public-key /run/nebulalog/publisher-public.pem \
  --expected-spki-sha256 <independently-authenticated-64-lowercase-hex> \
  --trust-source '<reference identifying the independent publisher authentication>'
nebulalog update status
```

Only one RSA SPKI public PEM is accepted, with a key size from 3,072 through 8,192 bits. Private keys, certificates, additional PEM objects, fingerprint mismatches, symlinks, writable ancestors and unsafe file ownership/permissions are refused. OpenSSL validates and canonicalizes the public key. Temporary files remain under encrypted `/var/lib/nebulalog/tmp`; no private key is handled by this workflow.

The canonical public key is installed as `/etc/nebulalog/release-public.pem`, mode `0600`. Its public-key hash, DER SPKI fingerprint, RSA size, installation UUID, exact initial-enrollment hash and operator-provided trust reference are recorded in encrypted `publisher-trust.json`. `publisher-pending.json` makes a power-loss retry exact and recoverable. Identical enrollment is idempotent. A different key, trust reference, existing key or receipt is refused; this command does not rotate trust or erase updater state.

`nebulalog update status` reports `enrollment.installed_release`, `enrollment.publisher_trust`, `enrollment.update_ready` and an actionable enrollment/recovery instruction. Readiness means the local enrollment records and key bytes agree. It does not mean a release is available, downloaded, signed or qualified. The public API status bridge may expose a subset of this local diagnostic record.

Appliance `check`, `install`, `rollback` and `finalize` verify that their public-key path and exact key bytes match completed enrollment. Passing a different `--public-key` cannot bypass the enrolled publisher. Signed updates continue to require RSA-PSS/SHA-256, a 32-byte salt, expiry and sequence checks, supported measured `from_versions`, artifact integrity and lifecycle acceptance.

## Qualification and recovery boundaries

Tests use real disposable OCI archives and OpenSSL RSA verification; runtime inspection is simulated by isolated fixtures. They cover changed images/versions/provenance, interrupted initial and factory/manual trust writes, unknown preexisting state, mismatched fingerprints, private keys, unsafe paths and all manager action gates. No signing private key from a test is packaged. Installed Rocky execution, real first signed update/rollback, protected automated signing and delivery, and a reviewed key-rotation procedure remain release acceptance gates. A recovery operator must investigate changed trust; deleting records to force re-enrollment is not a supported rotation process.
