# Implementation milestones

Each milestone requires build, automated tests, startup/log inspection,
persistence/failure checks, and UI checks for user-visible changes. Evidence is
recorded in ACCEPTANCE.md. Unexecuted acceptance tests stay unverified.

1. Research and architecture: canonical PAN-OS field descriptions; Rocky/CIS/STIG,
   Keycloak FIPS and ClickHouse research; ADRs and interface contracts.
2. Durable data path: Go binary, real PostgreSQL/ClickHouse deployment, migrations,
   versioned parsers, spool, UDP/TCP/TLS listeners and outage/restart tests.
3. Search workflow: real filter compiler, authenticated API, dense virtualized
   viewer, graphical/click filters, layouts, saved filters and streaming CSV.
4. Operational application: documented log families, inventory, DNS cache,
   diagnostics, retention, measured storage sizing and health metrics.
5. Identity: Keycloak realm and PKCE, mandatory local MFA, role enforcement,
   external provider guidance and provider integration acceptance matrix.
6. Appliance: Rocky image recipe, install-time FIPS, encrypted storage, guarded
   growth/add-disk manager, Quadlets, first boot, security/compliance evidence.
7. Lifecycle: signed manifests, controlled updates and rollback, OS maintenance,
   configuration/full-data backups with restore validation.
8. Release gates: reference workload and bursts, 10M/100M scale benchmarks,
   real OVA build/boot/security and hypervisor tests, release documentation.

The initial implementation proceeds in this order, with independent packages
developed concurrently after research. Packaging recipes are not release proof.
