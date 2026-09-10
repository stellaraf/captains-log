# Backup and restore

Configuration backups include separate `pg_dump` custom archives for the `nebulalog` and `keycloak` databases plus the canonical encrypted `/var/lib/nebulalog/configuration` directory. They include **no ClickHouse log data**. The root CLI is implemented and unit-tested; actual appliance backup/restore qualification remains pending.

The transport uses the running `nebulalog-postgresql` container and verifies that its image matches the installed immutable PostgreSQL Quadlet pin. Database tools execute as container UID/GID `999:999`; each dump connects as its own fixed, unprivileged database owner through `/var/run/postgresql`. The installed socket mount is accessible only to UID 999. Connection options are explicit, password prompting is disabled, and the child environment is cleared. No host `pg_service.conf`, host PostgreSQL tools, password argument or password environment variable is required. Catalog inspection reads database ownership/privileges, sizes and server version; it does not read password hashes. Every dump must pass the same container's `pg_restore --list` before packaging. [PostgreSQL 17 pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html), [Podman exec](https://docs.podman.io/en/stable/markdown/podman-exec.1.html)

```sh
nebulalog backup --recipient-certificate /etc/nebulalog/backup-recipient.pem \
  --output /var/lib/nebulalog/backups/configuration.cms
```

The recipient public certificate must be a root-controlled, unexpired regular file; keep its private recovery key off appliance. The CLI accepts only a new destination under root-controlled directories, outside the live configuration and scratch directories. Scratch is root-only on the mounted XFS data filesystem with verified LUKS ancestry. Actual first-boot enrollment, storage identity, FIPS/SELinux and host-control gates are rechecked under the operation locks. An unconfigured appliance cannot use this command.

The tar is encrypted with OpenSSL CMS AES-256-GCM authenticated enveloped data and atomically published with mode 0600 without overwriting an existing file. Output includes the ciphertext SHA-256/length and a transaction UUID. Inside the encrypted manifest are per-file hashes/lengths, source file permissions/owners, installation identity, PostgreSQL image/version/owners and capture times. CMS authentication protects archive integrity; this workflow does not create a detached publisher signature. Copy the result and receipt off the appliance; a backup stored on the same failed disk is not recovery. [OpenSSL CMS](https://docs.openssl.org/3.5/man1/openssl-cms/)

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

Staged restore currently requires an enrolled, healthy appliance with its qualified PostgreSQL container running. It takes the same locks and refuses pending maintenance/updates but does not pause any service. The recovery key must be a root-only regular file. Restore bounds input/plaintext size and reserves scratch capacity, then authenticates/decrypts on encrypted private scratch. It only unpacks after authentication succeeds, rejects traversal, links, devices, duplicate/unexpected files and excessive expanded size, verifies every manifest hash/length, and validates both PostgreSQL archives using the installed container. Failed database-archive validation removes only the new staging destination. Destination must be new and outside live configuration; restore does **not** overwrite live databases or configuration. A fresh-appliance restore flow is not implemented yet.

Applying staged recovery still requires a separately reviewed implementation that provisions **empty compatible-version** databases, restores each matching archive transactionally, reconstructs scoped roles and credentials, and activates configuration. Review source installation identity, role ownership, TLS names and Keycloak realm/client URLs before switching configuration. Validate local break-glass login, MFA, RBAC, saved filters, inventory, API and ingest. Do not use a PostgreSQL major-version downgrade as rollback. The current CLI deliberately supplies no database-application command.

## Full log-data backup

Use ClickHouse's supported native backup/restore workflow for the pinned release, or a documented quiesced storage backup. Include the schema/retention policy, backup consistency point, encryption material and restore test. Copying live ClickHouse data directories or taking an uncoordinated snapshot is not evidence of a consistent database backup. Multi-terabyte backups are an explicit administrator choice with storage/time estimates.

`appliance/tests/test_backup.py` currently has 27 passing tests covering fixed container/role transport, immutable-image mismatch, host/storage/setup gates, all four real lock-contention paths, changed configuration and invalid dumps, ingestion-preserving recovery, foreign maintenance, failed health/restart, output collision, space refusal, staged-only restore and actual OpenSSL 3 CMS round-trip/tamper rejection. PostgreSQL, systemd, FIPS and mount measurements are simulated in these tests; only files, locks and the dedicated CMS test use real local mechanisms. The 64 manager/lifecycle regression tests also pass. Encrypted backup capture, active-ingest continuity, restart/power-loss recovery and restored database/application parity must still be exercised end-to-end inside the qualified Rocky appliance. The full browser recovery wizard is not complete.
