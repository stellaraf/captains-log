# Backup and restore

Configuration backups include separate `pg_dump` custom archives for the `nebulalog` and `keycloak` databases plus the canonical encrypted `/var/lib/nebulalog/configuration` directory. They include **no ClickHouse log data**. The root CLI supports validation-only staging and a separate fresh-appliance recovery workflow. Source tests and isolated PostgreSQL compatibility tests exist; native Rocky appliance recovery qualification remains pending.

The transport uses the running `nebulalog-postgresql` container and verifies that its image matches the installed immutable PostgreSQL Quadlet pin. Database tools execute as container UID/GID `999:999`; each dump connects as its own fixed, unprivileged database owner through `/var/run/postgresql`. The installed socket mount is accessible only to UID 999. Connection options are explicit, password prompting is disabled, and the child environment is cleared. No host `pg_service.conf`, host PostgreSQL tools, password argument or password environment variable is required. Catalog inspection reads database ownership/privileges, sizes and server version; it does not read password hashes. Every dump must pass the same container's `pg_restore --list` before packaging. [PostgreSQL 17 pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html), [Podman exec](https://docs.podman.io/en/stable/markdown/podman-exec.1.html)

```sh
nebulalog backup --recipient-certificate /etc/nebulalog/backup-recipient.pem \
  --output /var/lib/nebulalog/backups/configuration.cms
```

The recipient public certificate must be a root-controlled, unexpired regular file; keep its private recovery key off appliance. The CLI accepts only a new destination under root-controlled directories, outside the live configuration and scratch directories. Scratch is root-only on the mounted XFS data filesystem with verified LUKS ancestry. Actual first-boot enrollment, storage identity, FIPS/SELinux and host-control gates are rechecked under the operation locks. An unconfigured appliance cannot use this command.

The tar is encrypted with OpenSSL CMS AES-256-GCM authenticated enveloped data and atomically published with mode 0600 without overwriting an existing file. Key transport explicitly uses RSA-OAEP with SHA-256 for both OAEP and MGF1. A public-only encryption probe checks recipient/provider compatibility before configuration capture pauses services; there is no fallback to legacy RSA padding or another provider. Log exports use the same profile for their manifest and every chunk. The recipient's private recovery key stays off the source appliance. This compatibility check does not prove key possession or qualify the native Rocky FIPS module. [OpenSSL CMS](https://docs.openssl.org/3.5/man1/openssl-cms/), [OpenSSL RSA key transport](https://docs.openssl.org/3.5/man7/EVP_ASYM_CIPHER-RSA/)

Output includes the ciphertext SHA-256/length and a transaction UUID. Inside the encrypted manifest are per-file hashes/lengths, source file permissions/owners, installation identity, PostgreSQL image/version/owners and capture times. CMS authentication protects archive integrity; this workflow does not create a detached publisher signature. Both staging-only and fresh restore require authenticated AES-256-GCM envelopes before decryption and validate the tag before unpacking. CBC envelopes are refused. Copy the result and receipt off the appliance; a backup stored on the same failed disk is not recovery.

## Consistency and service impact

The CLI acquires the shared manager transaction lock, first-boot lock, runtime bootstrap lock and baseline lock, in that order. All are nonblocking: a competing operation is refused before maintenance starts. Pending OS/component transactions and existing maintenance also block capture. It calls only lifecycle primitives that do not reacquire these locks.

The edge enters maintenance while **only API and Keycloak are stopped**. PostgreSQL, ClickHouse and ingestion remain running. Each database has its own consistent `pg_dump` snapshot; their capture timestamps are recorded separately. Configuration and identity writers are quiesced across both dumps, but this is **not one atomic cross-database snapshot**. Ingest continues its volatile firewall-inventory updates, so inventory reflects the `nebulalog` dump's snapshot time. New logs continue entering ClickHouse and are excluded from this backup. The configuration copy is hashed before and after copying; an unexpected change, link or special file refuses publication. [PostgreSQL snapshot behavior](https://www.postgresql.org/docs/17/app-pgdump.html)

API/Keycloak are restarted and local API/database health plus ingest service activity are checked before maintenance is released and encryption starts. This does not claim a fresh user MFA session or log-delivery probe. A failed capture attempts the same runtime recovery. Restart/health failure keeps the maintenance gate and a redacted `recovery_required` journal under `/var/lib/nebulalog/manager/backups/<UUID>/transaction.json`; no backup success is reported.

To recover **only an interrupted standalone backup's service pause**, run this fixed action from the protected appliance administrator console. Use the exact transaction UUID reported by the failed operation:

```sh
PYTHONPATH=/usr/lib/nebulalog python3 -m nebulalog_manager.backup recover --id <transaction-uuid>
```

It rechecks host/storage gates and locks, validates installation/transaction/maintenance ownership, starts API/Keycloak, checks health, and releases only that backup's maintenance gate. Its successful result is `recovered_without_backup`, never a completed backup or an applied restore. It refuses unrelated maintenance and completed transactions. A process/power failure can leave private scratch on the encrypted filesystem; this runtime recovery action does not delete unreviewed leftover files or resume an interrupted encryption operation.

The configuration archive budget is 20 GiB expanded, with a 1 MiB manifest limit. Free-space estimates reserve three times the measured configuration/database size plus 1 GiB before pausing writers. The dump output receives a per-process `prlimit --fsize` bound based on that reserve; the second dump uses the remaining budget. Dump/archive verification commands have deadlines. These checks do not reserve filesystem capacity against concurrent log ingestion; live exhaustion and timeout behavior still need guest qualification. [util-linux prlimit](https://man7.org/linux/man-pages/man1/prlimit.1.html)

## Staged recovery

```sh
nebulalog restore --backup /recovery/configuration.cms \
  --private-key /run/nebulalog/backup-recovery.pem \
  --certificate /recovery/backup-recipient.pem \
  --destination /var/lib/nebulalog/recovery/restored-configuration
```

Staged restore requires an enrolled, healthy appliance with its qualified PostgreSQL container running. It takes the same locks and refuses pending maintenance/updates but does not pause any service. The recovery key must be a root-only regular file. Restore bounds input/plaintext size and reserves scratch capacity, then decrypts on encrypted private scratch. It only unpacks after decryption succeeds, rejects traversal, links, devices, duplicate/unexpected files and excessive expanded size, verifies every manifest hash/length, and validates both PostgreSQL archives using the installed container. Failed database-archive validation removes only the new staging destination. Destination must be new and outside live configuration. This mode does **not** apply databases or activate configuration.

## Recover onto a fresh appliance

Use a new x86_64 Rocky appliance running the **same four immutable application, PostgreSQL, ClickHouse and Keycloak images and application schema revision** recorded in the backup. New backups include this measured runtime provenance; older backups without it can still be staged, but cannot be automatically applied. A restore is not a database downgrade or release-upgrade procedure.

This workflow requires an appliance generation that includes the restore implementation. Qualification currently targets fresh schema 3 installations. At the 2026-10-19 development review, no public release or tag had been published; older schema 2 development appliances are prototypes, and their migration bridges are not part of the first supported release baseline. They continue to refuse incompatible generations. Supported-release update, rollback and failure-recovery testing remains mandatory, including on restored appliances. Do not copy recovery modules into an installed appliance or edit its boot authority to make them load. Restored appliances must retain their token issuance cutoff across future upgrades and rollbacks.

Component installation, rollback and component recovery currently refuse a restore-owned target before selecting software. A matching database schema does not prove that an application image enforces the cutoff. Automatic component updates on restored targets remain an acceptance requirement, pending qualification of an exact compatible host/image pair and its rollback. Keep the retained restore markers; deleting them is not a supported way to enable updates. This restriction does not change the separate OS update path.

1. Keep the source appliance offline before reusing its hostname or address. Preserve the original encrypted backup and recovery key off the appliance.
2. Enroll the target's blank data disk and network through the guarded graphical console wizard (or the root firstboot `plan` and `apply` actions). At `host-ready`, select `RESTORE`; do not select `NEW` or call `provision`. Use the source hostname, local administrator username and baseline selection. Its restored server certificate must cover the target addresses and remain valid. The target keeps its own installation UUID, disk encryption keys and physical storage identity.
3. Export and verify the **new target's** disk recovery credential. Place the encrypted backup/certificate in root-controlled directories and the private backup recovery key in a root-only file. Keep secret contents out of command arguments and shell history.
4. Authenticate and review the backup, then explicitly apply that review:

The console supports local paths through `RESTORE`, or an explicitly selected optical recovery ISO through `MEDIA`. Both authenticate into private encrypted staging, verify target compatibility, and display the authenticated source/target identities, ciphertext digest, review digest and expiry before asking for the final target confirmation. `CANCEL` or `LATER` leaves runtime provisioning unrequested; prepared evidence remains retained. Neither path resets restored account passwords or MFA. The media path copies only `backup.cms`, `recipient.pem` and an encrypted `recovery-key.pk8` to protected encrypted scratch. Compare the displayed configuration digest with your independently retained receipt before confirming import; the key passphrase uses a hidden terminal prompt. The ISO path is configuration-only. There is no pre-runtime browser upload, automatic media selection, SSH enablement, URL fetch or pasted-key input. See [FIRST_BOOT.md](FIRST_BOOT.md#configuration-recovery-from-the-console) for media preparation and import instructions.

```sh
nebulalog restore --prepare-fresh \
  --backup /recovery/configuration.cms \
  --private-key /run/nebulalog/backup-recovery.pem \
  --certificate /recovery/backup-recipient.pem

nebulalog restore --apply-plan <review-uuid> --plan-digest <complete-review-digest>
```

Preparation accepts only a fresh, host-enrolled target: existing runtime data, accepted integrity state, completed setup and unrelated host operations are refused. It retains authenticated input under `/var/lib/nebulalog/manager/restores/<UUID>/` on encrypted storage, without installing the restore ownership pointer or starting services. It admits only authenticated CMS AES-256-GCM envelopes, validates the archive, and checks source compatibility against the measured factory code, offline image bundle and schema. It verifies the restored TLS keys, hostname/address coverage and validity before any runtime change. Configuration recovery retains its conservative reserve of three maximum-size archives plus 1 GiB (about 62 GiB); full recovery additionally inspects native archive metadata and checks its copy/data/filesystem reserves. These are capacity guards, not a measured PostgreSQL expansion ratio or duration estimate.

The review is valid for five minutes after authentication and inspection finish. Apply requires the exact UUID/digest, forbids replacement inputs, and records admission before repeating input hashes, factory compatibility, fresh-target and free-space checks. Verification admitted before expiry may continue beyond it for large recovery sets. Only after those checks does apply install the durable pointer `/var/lib/nebulalog/manager/restore.json` and enter runtime recovery. A repeated exact apply reads retained status; use the explicit resume command to continue. If admission is interrupted before the pointer exists, prepare a new review from the original inputs; the prior evidence is preserved and never silently adopted. An expired preview also requires a new review. The root-only `--apply-fresh` convenience remains available and performs the same prepare/apply sequence in one invocation.

Before creating startable services, the workflow installs persistent boot conditions holding Keycloak, API, ingest and HTTPS. It creates fresh database credentials and empty databases, then runs each archive as its fixed unprivileged database owner with `pg_restore --single-transaction --exit-on-error --no-owner --no-privileges`. The databases commit separately. No database drop, overwrite, clean or superuser restore is performed.

Accounts, subject IDs, passwords, MFA/recovery credentials, role mappings, identity providers, saved filters, layouts, inventory and retention settings come from the restored databases. The restored CA/server identity and appliance service credentials are retained. Only appliance-owned installation attributes are rebound to the new target. Old login sessions and host authorizations are invalidated; the API enforces a persisted token issuance cutoff as well as normal signature/issuer/audience/expiry checks. New login is required. Export records are marked unavailable because exported files are not included; source-host storage observations and pending operations are quarantined before ingestion starts. The original records remain recoverable from the retained encrypted backup.

The target does not inherit the source's disk identity, update acceptance or file-integrity approval. Runtime health is checked, and success reports `runtime_ready` with `setup_complete: false`. Sign in with the restored account and its existing MFA, check roles/settings/filters, reconnect log forwarding, review the target baseline, enroll/check its integrity database, and finish firstboot with its newly exported disk recovery credential. Verify a new firewall event at the API and UI before accepting recovery.

If recovery fails, preserve the reported UUID, stage and protected transaction. The workflow attempts to hold its listeners and records whether that hold was verified. PostgreSQL/ClickHouse and restored data are retained. Resume only through:

```sh
nebulalog restore --resume <transaction-uuid>
```

The unfinished appliance console also offers `STATUS`, `RESUME`, and `LATER` for its retained operation; `RESUME` requires the exact displayed UUID and accepts no replacement input paths. The root CLI provides `nebulalog restore --status` for the same read-only, redacted progress projection. Recorded database acknowledgements, runtime stage and listener-hold evidence are distinct from current service health. An uncertain action disables console dispatch and remains refused by the coordinator. A `runtime_ready` record enables `CONTINUE` in the console, which revalidates complete runtime evidence before the existing final setup workflow. Neither a status record nor returning from restore marks setup complete.

Resume verifies the retained manifest and operation ownership. It skips durably acknowledged database restores. An interrupted database or runtime action with an uncertain outcome is **not automatically replayed**; use a new fresh target or a separately reviewed recovery procedure. A failed health check after completed activation can be rechecked without applying the databases again. Normal firstboot provisioning refuses a restore-owned target so it cannot seed a replacement realm or reset restored credentials. Never delete the transaction/fence files to force progress.

## Full log-data backup

The source CLI now provides an explicit full-backup mode and local-path fresh recovery of its linked log set. This workflow is under qualification; it has not passed native Rocky recovery acceptance and is not a published supported release. The default configuration backup continues to exclude event rows. Do not copy live ClickHouse data directories or take an uncoordinated snapshot and treat it as a consistent backup.

The source implementation uses the pinned ClickHouse native `BACKUP` operation for the fixed `nebulalog.events` table. Its recovery set consists of `configuration.cms` and a separately encrypted `logs/` snapshot, bound together by the configuration ciphertext hash, source installation, exact image pins/schema, table identity, policy revision and actual capture times. Configuration capture records the policy while API/identity writers are paused; native dispatch checks that exact revision and policy content under its deletion hold. A policy change refuses the combined capture. The databases have separate consistency points; the set does not claim a single atomic cross-database snapshot. Native restore targets a precreated empty compatible table while the fresh appliance's listeners remain held. The destination retains its own table UUID and storage identity.

For a qualification deployment built from this source, select explicit budgets in bytes and seconds. The following numbers are examples, not a sizing recommendation; free-space reserve must be at least 10 GiB and 10% of the data filesystem. Allow space for the native snapshot, encrypted export, incoming logs and restore copies. The current CLI validates these budgets but does not yet provide measured duration estimates.

```sh
nebulalog backup --include-logs \
  --recipient-certificate /root/offline-recipient.pem \
  --output /var/lib/nebulalog/recovery-export-001 \
  --maximum-archive-bytes 10737418240 \
  --growth-reserve-bytes 5368709120 \
  --minimum-free-bytes 107374182400 \
  --deadline-seconds 3600
nebulalog backup --status <operation-uuid>
nebulalog backup --resume <operation-uuid>
```

The operation returns its UUID and may report `running`. Resume observes that same native job; it does not redispatch an uncertain backup or recapture a completed configuration child. Status only projects the retained journal. Resume also completes encryption and verifies every exported ciphertext against a protected seal receipt before releasing the retention hold. A failed or ambiguous child retains its journals, archive and any hold for recovery; starting another full backup cannot bypass it. Copy both `configuration.cms` and the complete `logs/` directory off the appliance, retaining their returned digests and the private key separately.

An unsuccessful operation can be retired explicitly after its configuration and native work are proven settled:

```sh
nebulalog backup --retire <operation-uuid>
```

Retirement reports `retired_without_backup` with `complete: false`. It preserves every archive, partial or complete output, child journal and original recovery record; it does not delete files or claim a usable backup. After the coordinator records successful retirement, a new backup may use a new operation UUID and output directory. `--retire`, `--resume`, `--status` and `--include-logs` are mutually exclusive. Retirement uses only retained inputs and rejects all configuration, certificate, output and budget overrides.

Retirement checks exact operation and installation ownership, recovers only supported configuration failures, and requires positive evidence that native work was never dispatched or that the original job has settled as failed or cancelled. A native snapshot that succeeded before its encrypted export failed can also be abandoned explicitly as an unsuccessful full backup: the native archive and partial ciphertext remain preserved. A running job, missing status row, expired deadline, changed server identity or uncertain outcome cannot authorize retirement. This command neither cancels nor replays native work. Lost acknowledgements are reconciled against the original child evidence; never delete transaction or hold files to force a new backup. These recovery transitions are implemented in source and still require native Rocky interruption testing.

On a compatible fresh target with those files already placed in protected local directories:

```sh
nebulalog restore --apply-fresh \
  --backup /root/recovery/configuration.cms \
  --certificate /root/recovery/recipient.pem \
  --private-key /root/recovery/private-key.pem \
  --log-recovery-set /root/recovery/logs \
  --log-deadline-seconds 3600 \
  --log-minimum-free-bytes 107374182400
nebulalog restore --status
nebulalog restore --resume <operation-uuid>
```

The authenticated configuration and log set must match before database effects start. Recovery records native restore intent once, observes the exact job, checks restored rows/parts and table integrity, then binds the target table to the restored retention policy before listener activation. Resume preserves normalization already completed for that target. An ambiguous database effect is never retried automatically. The configuration-only optical importer does not deliver the full log set; protected large-set delivery and browser workflow remain unfinished.

The log transport uses fixed 256 MiB chunks, each protected by CMS AES-256-GCM, and an encrypted manifest containing their order, sizes and hashes. This bounds individual OpenSSL input size without changing the definite DER envelope format used by configuration recovery. OpenSSL's `-stream` option uses indefinite BER encoding; it is deliberately not used by this format. The source format bounds the manifest to 64 MiB and the archive to 262,144 chunks (64 TiB); these are admission limits, not a capacity or performance qualification. See the [OpenSSL CMS documentation](https://docs.openssl.org/3.5/man1/openssl-cms/) and [ClickHouse native local backups](https://clickhouse.com/docs/concepts/features/backup-restore/local-disk).

Plaintext archives, keys, chunks and manifests are handled only on verified encrypted scratch. Ciphertext chunks are written first and the encrypted manifest is published last. A complete publication can be recovered after a lost acknowledgement only by matching the coordinator's private seal receipt and reestablishing filesystem durability barriers. Partial exports remain preserved and are never overwritten. A crash during final publication can leave a pending manifest link, which admission refuses. A manifest filename alone is not proof of a usable recovery set. Recovery requires the complete fixed inventory, authenticated decryption and every per-chunk and whole-archive check before publishing a native archive for the database coordinator. Transport verification alone does not establish a restored table.

The remaining product work includes browser selection, useful capacity/time estimates, protected full-set delivery, cancellation of running native work, and native roundtrip/interruption qualification of capture, retirement and recovery. Explicit retirement supports only proven settled outcomes; unresolved work keeps its hold. Keep the private recovery key separately from encrypted backup files and preserve the original recovery set during testing. No full-log recovery acceptance is claimed by source or transport tests.

Focused tests cover archive admission, actual OpenSSL3 GCM round-trip/tamper/CBC rejection, fixed container/role transport, partial database failure, ownership and lock boundaries, retained intent, recovery status and token cutoff. Console/media fixtures cover explicit optical selection, protected copies, encrypted-key admission and hidden-passphrase handling, cancellation, retained-owner routing and preservation of existing MFA language. Full-backup fixtures cover lost acknowledgements, no redispatch, partial ciphertext retention and release only after exact readback. The isolated PostgreSQL17 compatibility harness additionally exercises real owner-role restores and transaction rollback; its host architecture and synthetic Keycloak fixtures do not establish native appliance acceptance. Encrypted backup capture, active-ingest continuity, real optical import, restart/power-loss recovery and complete account/MFA/RBAC/configuration/certificate/API/ingest parity still require end-to-end qualification on Rocky x86_64.
