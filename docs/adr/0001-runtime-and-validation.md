# ADR 0001: Go data plane, React client, separate host manager

Accepted 2026-09-07.

Use Go for bounded concurrent syslog ingestion, an explicit query compiler, and
the HTTP API; React/TypeScript for the browser; Python standard library for the
host manager's inspectable privileged storage/update operations. This keeps the
specified service responsibilities while allowing the application processes to
share one binary and schema. PostgreSQL and ClickHouse remain mandatory.

Development Compose uses loopback-published services and unique generated secrets.
It is explicitly a development deployment and cannot claim the appliance's FIPS,
LUKS or SELinux baseline. Production fails closed without identity configuration.
Do not generate fake log records to populate screens; fixture senders are explicit
testing tools and their synthetic firewall identity must be visible.

Release evidence is incremental. No checked acceptance box may rely only on a
configuration file, mock implementation, successful compilation, or an unrun test.
