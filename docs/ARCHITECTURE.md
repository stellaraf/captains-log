# Captain’s Log architecture

Status: implementation design, 2026-09-07. The release acceptance gates in
SPECIFICATION.md remain authoritative; a working developer deployment is not a
validated appliance release.

## Runtime boundaries

Rocky Linux 9 x86_64 runs Podman Quadlets, Keycloak, PostgreSQL, ClickHouse,
and a Go Captain’s Log binary. The binary supports separate `serve` and `ingest`
roles; `all` combines these for a small installation. A bounded DNS worker pool
is independent of searches and ingestion. The host appliance manager is a
separate, narrowly privileged process: the web container has no host shell,
block devices, Podman socket, or root privileges.

React/TypeScript provides a dense, route-backed Monitor-style application.
Keycloak's JavaScript adapter uses authorization code with PKCE; access and
refresh tokens remain in memory. The API verifies issuer, signature, expiration,
audience and roles using an established OIDC implementation. No auth bypass is
provided. ADMINISTRATOR controls settings; ANALYST can export and save searches;
VIEWER can only read. Authentication and all metadata persist in PostgreSQL,
with separate Keycloak and application databases and database owners.

## Durable ingest

UDP, TCP, and TLS listeners preserve original bytes and sender metadata. TCP
supports RFC 6587 octet-counting and newline framing. Each accepted message is
committed to a bounded disk spool before it becomes eligible for a batch insert.
The collector acknowledges spool work only after ClickHouse acknowledges a
synchronous insert. Database outages retry with backoff; spool survives restart.
TCP applies backpressure. UDP cannot guarantee delivery: overflow, socket errors,
and failed persistence must be counted and logged. There is no exactly-once
claim across an ambiguous database commit; stable event IDs permit diagnosis of
replay duplicates. Spool is located on the encrypted data volume.

PAN-OS CSV schemas are registered by wire family and documented schema revision.
Version cannot be reliably inferred from a field count. Original CSV fields and
raw event are retained, optional trailing fields are tolerated, and unsupported
or malformed records are stored with parser diagnostics. UI categories sharing
the THREAT format use documented subtype/category mappings.

## Event database

ClickHouse exclusively owns firewall events. A MergeTree table partitions by
log family and UTC day, sorts by family/time/device/event ID, and uses typed
normalized columns plus raw evidence. Low-cardinality dimensions and ZSTD
compression constrain storage. Address skipping indexes are measured before
being promoted to production recommendations. Retention uses per-row expiry
computed from the administrator's family policy and ClickHouse TTL merges.
Changes to policy explicitly state whether they affect future records or
retained data; no surprise destructive rewrite. High-cardinality device IDs are
never partition keys. Queries always have a bounded time range and result size.

The filter engine is a lexer, recursive-descent parser, typed AST validator,
and compiler. Identifiers come only from an allowlist. Values are ClickHouse
typed parameters, including IP and CIDR operands. No user SQL is accepted.
Cursor loading uses deterministic sort plus event ID. Export streams rows to
a private temporary file with an owner-bound job and explicit lifecycle.

## Host security and lifecycle

FIPS is enabled during image installation before appliance secrets are generated.
The data stack is partition → LUKS2 → LVM → XFS. First boot consumes only the
designated data disk. Later expansion requires an administrator request; unknown
disks always require explicit confirmation. Storage plans bind device identity
and observed topology, and revalidate before mutation. SELinux remains enforcing.
Host security status is measured, never inferred from the development host.

Signed release manifests constrain hashes, supported component versions, and
upgrade paths. Update transactions require health checks, backups and security
postconditions. Database rollback is not assumed safe after a format migration.
No shipping signing private key or universal appliance secret is included.

## Evidence and limits

Unit tests, real-container integration, browser verification, crash/outage tests,
VM boot/security tests, and performance benchmarks are separate gates. The local
macOS machine can validate application behavior; it cannot prove Rocky FIPS,
LUKS, SELinux, vTPM, hypervisor expansion, or hardware performance. The available
workspace has about 62 GiB free at implementation start: large benchmarks must
check a disk budget and may not consume the host operational reserve.

Official-source research is recorded in research/. No screenshots were supplied
with the specification. See MILESTONES.md and ACCEPTANCE.md for release status.
