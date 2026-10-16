# Retention

Administration → Storage stores a global and per-category expiry policy in
PostgreSQL. Values are 1–3,650 days. The collector loads it for each batch and
stamps expiry relative to ingestion time. Policy changes affect **new arrivals**;
existing records retain their original expiry. Retroactive expiry changes are
not implemented. PostgreSQL failures retain delivery work in the durable spool.

ClickHouse TTL merges remove expired data asynchronously. An expired event can
remain present until merge work occurs. Do not manually remove database files.

## Emergency storage protection

The emergency policy is **enabled by default**. It starts at **95% used** and
continues until **90% used or less** on the verified ClickHouse data disk. This
can permanently remove eligible logs **before their normal expiry**. Defaults
protect Traffic for one day, URL for seven days, and the other supported physical
categories for thirty days. These are emergency-deletion minimum ages only:
a shorter normal expiry can still delete data sooner. Raising an emergency
minimum does not extend existing expiry or restore deleted data.

The worker observes capacity every 15 seconds, with at most 45 seconds per
attempt. Observations older than two minutes are stale. Percentages use
ClickHouse's usable total and unreserved space, including ongoing reservations;
its configured keep-free reserve is already excluded and is not subtracted a
second time. This is a log-disk measurement, not a whole-appliance health claim.
See [ClickHouse disk measurements](https://clickhouse.com/docs/reference/system-tables/disks)
and the [vendor local-disk implementation](https://github.com/ClickHouse/ClickHouse/blob/v25.8.1.5101-lts/src/Disks/DiskLocal.cpp).

Administrators can change enablement, the trigger (90–99%), recovery threshold
(70% to below the trigger), and category minimums (1–3,650 whole days). The UI
requires confirmation that the policy permits permanent deletion. A save uses
an expected revision and atomically records old/new policy in the audit trail;
a stale revision or unresolved removal returns HTTP 409. There is no manual
purge or force-unblock endpoint. Read access requires authentication; writes
require the Administrator role. Disabling emergency cleanup does not cancel an
already dispatched or uncertain removal.

Selection proceeds as follows:

1. Verify the existing nonzero Atomic table UUID, exact `MergeTree` engine,
   `(log_type, toDate(ingested_at))` partition scheme, default storage policy,
   one local writable default disk, and exact table/disk paths.
2. Consider complete UTC category/day partitions. The day's **end** must be
   strictly older than its minimum-age cutoff. Current/incomplete days cannot
   qualify. Traffic is considered first, oldest first; other eligible categories
   follow oldest first. A cycle inspects at most 65,536 active parts and checks
   at most 128 eligible candidates, refusing additional removal when that bound
   cannot prove a candidate safe.
3. Exclude unknown/unsupported categories and every partition containing any
   parse status other than `parsed`. A failed or partial Traffic parse protects
   the **whole mixed partition**. Parsing, Unified and Alarms are virtual UI
   views, not separate storage categories. Alarms use the System minimum.
4. Exclude partitions covered by an unresolved insertion reservation. Under the
   shared application coordination lock, each delivery attempt commits its
   table UUID, category/day set and query ID before sending the INSERT. This
   reservation survives loss of the PostgreSQL session while ClickHouse may
   still be executing. A successful response clears it; an ambiguous attempt
   retains it for review. Up to 4,096 outstanding attempts are retained; reaching
   that bound holds further delivery. The UI exposes the reservation count,
   which is **not** a unique partition count.
5. Recheck capacity, table identity, exact active-part evidence, row counts and
   parse protection. Stop if capacity recovered during planning. Commit the
   exact policy revision, table UUID, partition, part names, observed rows/bytes
   and unique query ID with an audit intent **before** one `DROP PARTITION ID`.
   Values are bound parameters. All later state transitions are also audited.
6. Require an actual successful response, then wait until **all active and
   inactive parts** for that partition disappear and a positive net free-space
   observation is recorded. Only then may another cycle select a partition.
   Observed rows/part bytes are pre-action estimates, not attributed reclaimed
   bytes. TTL merges and concurrent filesystem activity can change those values.

The worker persists hysteresis and one global unresolved removal across
restarts. The advisory lock coordinates policy changes, delivery and planning;
the durable intent remains the destructive fence after lock loss. Each cycle
releases its connection rather than holding one during the cleanup interval.
The first verified table/disk identity is persisted and audited. Table or disk
replacement is a migration requiring operator review, not automatic adoption.
Privileged external INSERT/DDL operations do not participate in this application
coordination protocol and must not run concurrently with the controller.

ClickHouse marks dropped parts inactive before deleting their files; normal
physical cleanup can take approximately ten minutes. See [DROP PARTITION](https://clickhouse.com/docs/reference/statements/alter/partition)
and [system.parts](https://clickhouse.com/docs/reference/system-tables/parts).
While a removal or capacity emergency is unresolved, the collector holds delivery
and retains its bounded WAL. TCP/TLS senders experience backpressure; UDP cannot
provide delivery guarantees and spool-pressure drops remain counted. A later WAL
batch can recreate an old category/day after a completed removal; it is a new
insertion generation, never silently discarded by a permanent tombstone.

## Host maintenance coordination

Host update/backup/rollback uses the same exclusive PostgreSQL advisory lock
(`4850182995969828167`) to install an operation-owned durable gate before work.
`settings.storage_emergency_maintenance` has the exact shape
`{schema:1, held:boolean, delivery_held:boolean, operation:null|64-lowercase-hex}`.
The host also publishes the same exact gate to
`/var/lib/nebulalog/manager/storage-maintenance/gate.json`, mounted read-only at
`/run/nebulalog-storage-maintenance/gate.json` in both API and ingestion. Running
FIPS-required roles require that fixed `STORAGE_MAINTENANCE_PATH`; only local
development with no configured path may omit the host file. The one-shot
`migrate` and `version` commands do not run controllers or delivery.

The Go consumer requires root-owned, nonsymlink, non-writable ancestry, a regular
file at most 4 KiB, no group/world write permissions, an actually unwritable
parent directory for its process identity, and stable no-follow file reads.
It reads the host gate before acquiring the database lock and again under that
lock. Host and database holds combine conservatively; simultaneous held owners
must match. Restoring an idle PostgreSQL snapshot cannot release a retained host
hold. Duplicate JSON keys, unknown fields and malformed owners are refused.

The operation is SHA-256 of the canonical protected host-stage path. A released
gate requires both flags false and a null operation; a held gate requires the
operation digest. Missing or malformed evidence holds work. Migration preserves
an existing gate, and there is no expiry or application-side clear endpoint.

`held` suppresses every new destructive intent while still allowing observation
and acknowledged cleanup. `delivery_held` additionally holds new INSERTs. The
host can resume healthy delivery for canary checks while keeping removal paused;
it must stop/quiesce all old writers and verify no pending removal or unresolved
insertion before backup or rollback. Old application versions do not implement
this protocol. Gate ownership, protected host recovery evidence and metadata
restore ordering are part of the separately qualified lifecycle migration;
a PostgreSQL restore must not silently erase the only maintenance authority.
The API exposes gate state as read-only maintenance status. An uncertain
removal remains held regardless of maintenance flags.

## Held outcomes and operator recovery

Missing/invalid measurement, policy, audit storage, identity, or protection
proof authorizes no removal. No eligible partition produces a visible blocked
state. Adding capacity or reducing other usage may allow a later observation
to recover normally. Metadata or mixed-diagnostic partitions remain protected.

A durable `prepared` action was never authorized for dispatch; after interruption
it is cancelled with an audit record, and a future cycle plans afresh. An
`executing` or `uncertain` action is **never automatically retried or resolved
from absent parts alone**. HTTP requests may continue after a lost connection,
and a paused executor might not have sent its request yet. A query ID is tracing
identity, not permanent deduplication. See the [ClickHouse HTTP interface](https://clickhouse.com/docs/concepts/features/interfaces/http).

For uncertainty, preserve the action, policy, table/part evidence, audit rows,
insertion reservations, ClickHouse query logs and application logs. Stop and
account for all original application executors before any recovery decision.
Establish the exact query's terminal outcome from trustworthy server evidence;
absence from `system.processes` or an empty partition is insufficient. Recheck
identity, active/inactive parts, capacity and any retained WAL attempts. Recovery
requires a reviewed database repair/migration with backup and new audit evidence;
there is intentionally no automatic SQL recipe or UI button that discards this
fence. Do not delete action or reservation rows merely to resume traffic.

An acknowledged removal stays held if physical cleanup is incomplete. After
30 minutes this becomes an explicit blocked cleanup observation. If parts are
gone but concurrent usage masks net free-space gain, after two minutes the
status explicitly requests capacity/operator review and issues no further
removal. Later proven cleanup and positive free space can complete the same
acknowledged action without replay. These holds preserve evidence; they are not
claims of successful automatic recovery.

## Installation and qualification boundary

The PostgreSQL migration creates the emergency policy, singleton observation,
removal ledger and insertion reservations. It is idempotent and must run before
starting this application version. Fresh appliance bootstrap runs the image's
`migrate` command before API/ingestion services. Existing installations need a
qualified schema migration release: the current automatic updater accepts only
same-schema, migration-free component updates. Starting this image against the
old schema holds delivery rather than bypassing the new coordination protocol.
Do not label this change a migration-free release.

The isolated backend tests use dedicated PostgreSQL 17.6 and ClickHouse 25.8
fixtures with a separate destructive-test opt-in, never the existing read-only
ClickHouse test endpoint. They cover real partition selection/removal, retained
protected rows, physical part disappearance, nonzero keep-free semantics, late
WAL insertion, lost acknowledgement, and PostgreSQL session loss during a
delayed diagnostic INSERT. Pressure is injected into the measurement seam;
these tests do **not** qualify a full appliance under actual disk exhaustion,
production throughput, native guest FIPS, or an automatic schema upgrade.
