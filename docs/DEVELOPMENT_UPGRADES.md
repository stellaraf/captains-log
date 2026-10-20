# Updating an existing Docker development deployment

The development Compose stack and the Rocky appliance have separate update
paths. This procedure covers the development PostgreSQL and Keycloak services.
It does not qualify the appliance updater, strict FIPS mode, an OS upgrade, or
a PostgreSQL major-version migration.

Use a maintenance window. Stop every application, collector and Keycloak
process using these databases, including native processes or separately named
containers outside Compose. Account for interrupted firewall delivery before
stopping the collector. Do not regenerate `.local/dev.env`, run `dev-init.py`
against existing volumes, or delete volumes with `down -v`.

## Preserve the running version before changing the checkout

Keep a private backup directory on the development drive. Capture the current
source revision, Compose files and overrides, image digests, theme, environment
file, and any custom identity providers or configuration. Retain the old images
or exported image archives so rollback does not depend on a mutable tag.

The examples assume the standard project and `.local/dev.env`. If your deployment
uses a different project name, env file or Compose override, use those same
inputs for every command. A changed project name can silently select new volumes.
The pinned targets are Linux x86-64. The in-place test covers x86-64 on both
sides; an existing ARM database requires a separately verified logical
dump/restore migration rather than assuming its volume is interchangeable.

```sh
umask 077
backup_dir="$(mktemp -d .local/pre-upgrade-XXXXXXXX)"
cp .local/dev.env "$backup_dir/dev.env"
cp docker-compose.yml "$backup_dir/docker-compose.yml"
cp -R deploy/keycloak/themes/nebulalog "$backup_dir/theme-before"
git rev-parse HEAD > "$backup_dir/source-revision.txt"
docker compose --env-file .local/dev.env images \
  > "$backup_dir/images.txt"
docker compose --env-file .local/dev.env --profile application stop app keycloak
```

The `images` listing is an inventory aid, not an image backup or an immutable
digest lock. Inspect the actual container image IDs and preserve their archives
before removing any old images. Protect backups: they include identity signing
keys, password hashes and MFA credentials.

With all writers stopped, leave PostgreSQL running and dump both databases:

```sh
docker compose --env-file .local/dev.env exec -T postgres \
  pg_dump -U postgres --format=custom --dbname=nebulalog \
  > "$backup_dir/nebulalog.dump"
docker compose --env-file .local/dev.env exec -T postgres \
  pg_dump -U postgres --format=custom --dbname=keycloak \
  > "$backup_dir/keycloak.dump"
docker compose --env-file .local/dev.env exec -T postgres \
  pg_restore --list < "$backup_dir/nebulalog.dump" \
  > "$backup_dir/nebulalog.contents"
docker compose --env-file .local/dev.env exec -T postgres \
  pg_restore --list < "$backup_dir/keycloak.dump" \
  > "$backup_dir/keycloak.contents"
```

Check each command's exit status before proceeding. Record checksums and perform
a restore rehearsal into a separate empty PostgreSQL volume. A readable archive
directory alone does not prove restore succeeds. These two database dumps do
not back up ClickHouse logs, the collector spool, exports or TLS files; preserve
those separately before changing their software or storage.

## Upgrade and validate

1. Review the target release's migration notes and update the source while
   retaining the captured rollback materials.
2. Pull the digest-pinned PostgreSQL and Keycloak images from Compose.
3. Stop PostgreSQL and recreate only that service against its existing volume.
   PostgreSQL 17.6 → 17.11 is a minor update within major version 17. Verify
   `SHOW server_version;`, database availability and preserved application data.
4. Start the new Keycloak against the existing `keycloak` database and wait for
   its schema migration and realm discovery endpoint to finish. Do not run old
   and new Keycloak servers against this database concurrently.
5. Start the application. Verify `/api/health`, a fresh password/MFA login,
   existing roles, saved filters, layouts, retention settings, and a known log.
   Enroll a disposable user's new authenticator and confirm invalid-code
   rejection and a subsequent fresh MFA login. Check any configured external
   identity provider separately.
6. Resume collection and compare fresh firewall-native events with stored logs.
   Keep the pre-upgrade backups and old images until the upgrade is accepted.

Re-importing `realm.json` is not a database migration or a restoration of
existing users. Keep the realm/client identifiers, issuer, credentials and
existing MFA factors intact.

## Roll back by restoring the pre-upgrade databases

Stop the upgraded application and Keycloak, then PostgreSQL. Preserve the
upgraded volume for diagnosis; do not erase it. Create a separate empty volume
for the old PostgreSQL image, and use the captured environment and initialization
script to create the original database owners and empty databases.

Restore each original dump to its corresponding empty database using the old
PostgreSQL server and `pg_restore -U postgres --dbname=<database>
--single-transaction --exit-on-error`. Verify the dump checksum before restore.
Start the old Keycloak image with its captured old theme and configuration only
after the old database has been restored. Finally start the matching application
and repeat fresh password/MFA login, settings, role and log checks.

Do **not** point the old Keycloak image at the database migrated by the newer
version. Changing its image tag alone is not rollback. Restoring the pre-upgrade
backup also discards identity and application-setting changes made since that
backup; reconcile those changes before reopening the deployment. Keep restored
and preserved upgraded databases isolated from one another.

See the [Keycloak upgrade guide](https://www.keycloak.org/docs/latest/upgrading/index.html)
and [PostgreSQL versioning policy](https://www.postgresql.org/support/versioning/).
Current project-specific evidence and its limits are recorded in
[runtime validation](validation/RUNTIME_REFRESH.md).
