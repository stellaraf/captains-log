# PostgreSQL

Separate `nebulalog` and `keycloak` databases have separate owner credentials;
PUBLIC database access is revoked. PostgreSQL owns saved filters, per-user
layouts, inventory metadata, retention policy, export jobs, measured storage
samples, administrative audit and Keycloak state. No SQLite dependency exists.

The application uses pgx and SQL parameters. Saved filters/layouts/export jobs
are scoped by the verified Keycloak subject. Administrative metadata writes and
audit entries use a transaction where policy state changes. Database migrations
are idempotent initialization for the development schema; released upgrades need
ordered versioned migrations and backup/rollback compatibility evidence.

Production should use separate migration and runtime privileges and encrypted
transport whenever traffic crosses an untrusted boundary. The development
Compose network and loopback publication are explicitly not production TLS proof.
