# Identity maintenance authority and session cutoff

`identity_sessions.invalidate_realm_sessions` operates through an authenticated,
realm-relative Keycloak Admin REST adapter. It checks installation ownership,
validates the cutoff, and refuses an existing floor newer than the persisted
caller intent. The caller must persist a revised intent before retrying. It
writes the requested boundary and verifies readback before logout.

Keycloak 26.8.1's `logout-all` replaces `notBefore` with its server clock; see
[the vendor implementation](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/managers/ResourceAdminManager.java).
The helper reads the resulting boundary. A newer floor becomes the returned
API cutoff. A lower floor, caused by clock skew or a future-dated policy, is
repaired and verified while maintenance remains held. Therefore the exact
requested epoch is not necessarily the final epoch. The first live run with
an exact-equality assertion caught this vendor behavior; that failed run is
not passing qualification evidence.

The caller must durably record its requested issuance boundary before dispatch,
serialize identity changes, and keep external access fenced across the entire
operation, including failures and uncertain acknowledgements. It must persist
the returned effective floor before starting the API or exposing any service.
The vendor operation can temporarily lower its own policy during this fenced
interval; no failure authorizes removing the fence. A newer observed floor requires persisting a revised intent before a retry;
otherwise a subsequent lost logout response could discard a boundary that
existed only in process memory. The helper does not grant itself administration.

## Two enforcement points

Keycloak's realm/session boundary prevents old refresh sessions from producing
new tokens. The application verifies access-token signatures locally and also
needs `OIDC_TOKEN_NOT_BEFORE`. Its existing verifier rejects tokens issued before
that epoch even when their signature and expiration remain valid.

The helper's result therefore explicitly reports `api_cutoff_required: true`
and `locally_verified_tokens_revoked: false`. A successful REST return must not
be interpreted as complete appliance session invalidation. The API must be
started with the recorded effective floor and tested with both an older valid token and
a fresh password/MFA login.

## Temporary authority

The normal appliance inspector cannot change client configuration; the
identity-provider manager cannot do so either. The original bootstrap user
must remain disabled.

Keycloak's documented
[bootstrap-admin service command](https://www.keycloak.org/server/bootstrap-admin-recovery)
can create a temporary administrator service while all identity-server nodes
are stopped. The private secret must be supplied through an environment-backed
configuration, not command-line text. The command must use the actual server
database settings. The production optimized image additionally requires its
optimized mode and intact strict-FIPS entrypoint checks.

After the maintenance work, delete the temporary client and verify that its
service user is absent, its secret cannot obtain a token, and its already-issued
administration token cannot access the realm. Persisted intent must allow
reconciliation after a lost creation or deletion acknowledgement without
adopting an unrelated account or re-enabling the original bootstrap user.

## Executed validation

The final source-bound Linux/amd64 fixture used PostgreSQL 17.11, Keycloak
26.8.1 and the actual application API. The session helper executed under public
Rocky Python 3.14.8. All **89 focused tests** passed across session boundaries,
browser scope reconciliation, host packaging and update enrollment.

All **10 live authority/token checks** passed. A refresh exchange and API access
worked before maintenance. With the sole identity server stopped, the vendor
bootstrap-admin service command created temporary administration. The original
bootstrap user stayed disabled. Browser reconciliation and session invalidation
ran under that temporary service. Its client and service user were then removed;
both new grants with its secret and administration using its issued token were
refused. The old refresh token and still-unexpired access token were rejected,
with the API configured to use the returned effective cutoff.

Six browser regressions passed before and six after maintenance. Four actual
password/TOTP role-permission cases, fresh authenticator enrollment, invalid-code
rejection and fresh-context login passed. Independent database readback verified
scope configuration. Application-realm users, credentials, attributes, required
actions, stored grants, role definitions and signing-key material retained
identical snapshots. This fixture does not seed external identity providers or
the production manager/inspector service clients, so it does not qualify their
migration under this temporary authority.

The fixture used the standard vendor development-mode identity image and
loopback HTTP. It did not bypass the production strict-FIPS entrypoint. Native
TLS/FIPS execution and production optimized-image recovery are separate gates.
The earlier failed exact-equality run remains failure evidence, not a pass.

## Durable cutoff journal

`SessionCutoffJournal` retains a root-owned, mode-0600 record in a private manager
state directory outside the database and customer-configuration backup. It
binds the installation, realm ID, operation, canonical API environment path,
non-cutoff configuration hash, phase and greatest recorded issuance floor.

Before any realm mutation, it durably writes and reads back an intent containing
the maximum of the requested, retained, API and realm floors. After session
invalidation it persists the effective floor before replacing the API's cutoff
line. Both the record and environment writes fsync the file and parent directory.
The receipt requires fresh-login verification and explicitly does not authorize
releasing maintenance.

Retries require the same non-cutoff API configuration. A distinct authorized
operation can bind legitimate changed settings after the prior operation reached
the API phase; it still retains the maximum cutoff. Foreign realm/installation
identity, ambiguous environment keys, duplicate JSON fields, unsafe modes,
symlinks, hardlinks, lost fencing and an unfinished different operation are
refused. Recovering with a missing journal refuses instead of silently starting
at an older floor. First initialization is explicit and must be authorized by
the factory/update coordinator; existence checks alone are insufficient to
re-authorize initialization after loss.

The caller must provide an operation-bound fence check, verify the directory is
on encrypted manager storage, and keep the API stopped throughout reconciliation.
The journal does not create temporary administration, stop services, authorize
initialization, or invoke itself from the updater. It must be combined with the
coordinator's configuration-preservation checks. A rollback must not overwrite
the database while a newer observed boundary remains unpersisted after an I/O
failure; that remains a held recovery condition.

All **106 focused tests** passed under Rocky Python 3.14.8, including 17 journal
tests using real private files. Faults cover lost logout/write acknowledgements,
durable-intent failure before REST mutation, fence loss, changed configuration,
restored older floors, record loss and ownership/format violations. These file
and injected-REST tests are separate from the live database-restore fixture.

### Live database and configuration rollback

The final source-bound fixture passed **12 authority/token/rollback checks**
against PostgreSQL 17.11 and Keycloak 26.8.1. It took a real SQL backup containing
the original browser session, applied session invalidation, and confirmed that
the old refresh token failed. With the API still stopped, it stopped Keycloak,
restored the actual database backup with its original owners and permissions,
and restarted the identity server. The old refresh session worked again,
demonstrating that database rollback alone revives previously revoked sessions.

A new Rocky Python 3.14.8 process reused the same private journal volume and
reconciled the restored older API environment and identity database. The retained
record matched the first process's final record; its floor was preserved or
increased. The revived refresh token then failed, and the actual API rejected
both original and newly revived, still-unexpired access tokens with HTTP 401.
The host fixture's API environment hash matched the journal's resulting file.

All six browser regressions passed before and six after the operation. Four
role-permission cases, fresh authenticator enrollment, invalid-code rejection
and fresh-context password/TOTP login passed. Identity/credential/grant and
signing-key snapshots stayed equal. Temporary administration was removed and
its credentials and issued token were refused; the original bootstrap account
remained disabled.

The SQL backup deliberately included the fixture's temporary administrator so
the restored server could be administered without introducing a second recovery
identity. Therefore this test does **not** qualify durable temporary-administrator
creation/deletion recovery. The fixture supplied the fence-admission callback
from its API-stopped observation; production maintenance admission, encrypted
host-storage verification, full lifecycle rollback, native TLS/FIPS and failure
between a remote mutation and persistence remain separate gates.

## Rollback and integration limits

Both helpers are catalogued libraries, not an automatic migration entrypoint.
The new factory host catalog contains 136 files. Existing 134-file factory
catalogs cannot automatically accept it: catalog/boot migration and rollback
must be qualified separately. A verified new archive is not installed or
activated merely because its source and archive hashes pass.
The retained update coordinator still refuses unqualified changes to identity
templates and preserved customer configuration.

A database/configuration rollback must not lower the authentication boundary.
It must reconcile the realm/session floor and API configuration before exposing
the restored service. Simply restoring an older database can revive sessions;
simply restoring an older API environment can remove local JWT rejection.
The recovery path must also remove temporary administration and retain the
original bootstrap account's disabled state.

Automatic transaction integration, durable temporary-authority recovery,
full lifecycle rollback, native TLS/FIPS execution and full appliance acceptance
remain open. The isolated SQL/configuration rollback above does not release
those production gates.
