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

The earlier journal-only fixture's SQL backup deliberately included its temporary administrator so
the restored server could be administered without introducing a second recovery
identity. Therefore this test does **not** qualify durable temporary-administrator
creation/deletion recovery. The fixture supplied the fence-admission callback
from its API-stopped observation; production maintenance admission, encrypted
host-storage verification, full lifecycle rollback, native TLS/FIPS and failure
between a remote mutation and persistence remain separate gates.

## Durable temporary-authority controller

`TemporaryIdentityAuthority` records the installation, target realm, disabled
bootstrap identity, maintenance operation, random temporary client name, secret,
observed client/service-user IDs and current phase in a private manager journal.
It persists intent before invoking the vendor recovery command. Its trusted
backend must stop the sole identity server and reconcile any still-running owned
recovery process before it observes or creates the account.

| Phase | Recovery rule |
| --- | --- |
| `intent` | No account may exist yet; persist `creating` before dispatch. |
| `creating` | Observe the vendor temporary marker, exact account shape and service user; prove the persisted secret works before adoption. A known bound identity that disappears is not silently recreated. |
| `ready` | Verify administration of the owned realm, run the fixed scope/session workflow, and persist its bounded receipt. |
| `removing` | Skip completed work; delete only the bound client, verify client and service-user absence, and check that its secret and issued token are refused. |
| `removed` | Retain the receipt with secret and token erased. Reuse requires live settled-state readback; a new recovery operation uses new credentials. |

The backend must positively verify the external maintenance fence at each
boundary. Untracked clients in the appliance's temporary-account namespace,
orphan service users, an enabled original bootstrap identity, foreign token
subject/client claims, changed account IDs and unsafe records are refused.
Failed work or uncertain responses retain the private recovery record; they do
not authorize resuming service or falsely claim that administration was removed.
A removed account that reappears requires explicit recovery instead of adoption.

The work callback accepts the fixed session-journal receipt shape, preventing
arbitrary callback data or credentials from being copied into completion
metadata. A successful return still requires fresh login and never releases
maintenance. Repeating a completed operation requires the backend to verify the
live realm, API environment and required scope state. Database rollback uses a
distinct authorized recovery operation so that reconciliation runs again.

All **124 focused tests** passed on Rocky Python 3.14.8, including 18 authority
state-machine tests. These cover response loss after committed creation and
deletion, interrupted work, credential erasure, stale completion, foreign
identity/token state, missing records, invalid receipts, fencing and durable-write
failure. Live vendor-command and database-restore evidence is recorded separately.

### Live temporary-authority recovery

The source-bound recovery fixture passed **13 live authority/token/rollback
checks**. The actual controller ran in four separate Rocky Python 3.14.8
Linux/amd64 processes against PostgreSQL 17.11 and Keycloak 26.8.1:

1. The vendor recovery command created one account, then the fixture injected a
   lost response after the command committed. The journal retained its secret
   and `creating` intent.
2. A new process observed and authenticated that same account, without creating
   another one. It reconciled browser scopes and the session journal, then lost
   the response after actual client deletion. The durable phase was `removing`.
3. A new process skipped completed work, verified client/service-user absence
   and refusal of the retained secret and administration token, then durably
   erased both credentials. It neither recreated nor deleted another account.
4. The fixture restored an actual database backup taken before any temporary
   account existed. The original refresh session worked again. A distinct
   recovery operation created fresh vendor authority, reconciled the retained
   session journal and restored API environment, and removed that new account.
   The revived refresh token and both still-unexpired API access tokens were
   rejected afterward.

The original bootstrap account remained disabled. Identity/credential/grant and
signing-key snapshots matched. Six browser regressions passed before and six
after the sequence, alongside four role-permission cases, authenticator
enrollment, invalid-code rejection and fresh-context password/TOTP login.

The fixture backend used narrowly checked Docker Engine operations on its owned
containers, real SQL observations and loopback Admin REST. It checked that its
API container stayed stopped. It did not implement or qualify the production
Podman/systemd backend, external edge-maintenance admission, encrypted native
storage, service-client migration, strict-FIPS execution, or interruption while
the vendor command itself was still writing. The two injected failures occurred
after committed real operations; they are not a claim of arbitrary power-loss
coverage. No production updater entrypoint invokes this controller yet.

## Production maintenance HTTPS transport

`MaintenanceIdentityAPI` supplies the local HTTPS connection for the pending
production recovery backend. It connects to the fixed Keycloak Quadlet listener
at `127.0.0.1:8443` while checking the configured issuer's certificate hostname
and explicit, root-owned appliance CA. It does not depend on the public edge
being available. System proxy settings and redirects cannot send recovery
credentials elsewhere.

Every request requires a positive maintenance-fence callback. Client credentials
are sent only in the token request body, and error diagnostics omit response
bodies. The product-realm callback refuses other realms, traversal, encoded
paths and arbitrary query parameters. The separate master-realm deletion
method validates the client-ID format; the authority controller remains
responsible for supplying only its previously bound client identity.
Transport failures, unexpected status codes, HTML responses and malformed JSON
cannot prove that an account or token was revoked. A secret requires an explicit
OAuth client denial; a token requires a JSON HTTP 401. Neither check by itself
replaces the controller's database/account-absence observations.

All **178 focused tests** passed on Rocky Python **3.14.8**, Linux/amd64.
Fourteen new transport cases use an actual loopback TLS server with disposable
certificates. They exercise CA and hostname rejection, SNI/Host preservation,
proxy isolation, all five redirect statuses, per-request fencing, bounded and
strict JSON, disconnections, explicit revocation outcomes, and credential-safe
errors. The protocol responses in those cases are synthetic. The initial test
CA lacked its key-usage extension and was rejected by Python's strict verifier;
the fixture was corrected to match the appliance certificate generator.
Certificate validation was not relaxed.
The appliance's actual certificate generator also passed a TLS 1.3 handshake
using Python's default strict verifier and its generated CA/server chain.

The same production transport subsequently passed against actual vendor
Keycloak **26.8.1** over HTTPS. The vendor `bootstrap-admin service` command
created a temporary account with the server stopped. A separate Rocky Python
3.14 process authenticated it, checked the owned realm, reconciled browser
scopes, advanced the realm cutoff and logged out sessions, deleted the account,
and verified that its secret and previously accepted token were rejected.
There was no TLS proxy or fabricated identity response in this check.

That fixture used disposable `dev-file` storage and an isolated network
namespace with no published ports; its fence callback was synthetic.
It does not qualify PostgreSQL persistence, production service control, the
complete authority journal, strict FIPS, native encrypted storage, or browser
login over production TLS. Its first attempt rejected a host-generated leaf
certificate missing an authority-key identifier. The disposable fixture added
explicit key identifiers; the product verifier and certificate generator were
unchanged. Both attempts removed their owned containers, database volumes and
private files.

This transport does not yet control Podman, verify the live maintenance fence,
or connect the controller to update activation and rollback. A separate
[native backend](IDENTITY_NATIVE_BACKEND.md) now implements the fixed host
boundaries but is not yet invoked by lifecycle entrypoints or qualified natively.
Those remain required before automatic identity maintenance can be accepted.

## Rollback and integration limits

These maintenance primitives are catalogued libraries, not an automatic migration entrypoint.
The new factory host catalog contains 137 files. Existing 134- and 136-file factory
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

Automatic transaction integration, production temporary-authority admission,
full lifecycle rollback, native TLS/FIPS execution and full appliance acceptance
remain open. The isolated controller and SQL/configuration rollback fixtures do
not release those production gates.

## API security metadata during cutoff replacement

The completed-database rollback coordinator now invokes the composed identity
workflow; its integration evidence and remaining limits are recorded in
[IDENTITY_NATIVE_BACKEND](IDENTITY_NATIVE_BACKEND.md). Forward activation and
native appliance acceptance remain open.

API cutoff replacement previously created a new 0600 file without copying the
original ACLs or extended attributes. That could discard customer metadata or
a SELinux label even when all unrelated configuration bytes were preserved,
and contradict the recovery integrity proof.

The replacement now retains the original owner/group and exact extended
attribute values, including Linux POSIX ACLs and SELinux labels. It verifies
the temporary file before rename and checks that the original inode and
metadata have not changed during preparation. A denied, unsupported or
unacknowledged metadata operation fails before replacement, leaving the
session journal at the recoverable realm phase. The private temporary file is
removed on failure. New temporary-authority credential files continue to use
the separate default 0600 creation behavior.

Validation passed **724 regression tests without skips** on public Rocky
Python **3.14.8**, Linux/amd64, using a disposable Docker volume with POSIX ACL
support. The six added cases exercise an actual named-user ACL, binary xattrs,
group ownership, retry, denied writes, ignored writes, unavailable metadata
and a concurrent metadata change. All six fail against the preceding
implementation (four assertion failures and two missing-attribute errors).
Both isolated test containers and volumes were removed after terminal results.

Those container results alone do not establish native SELinux policy
permission, FIPS acceptance, or a complete appliance restore. The subsequent
native metadata/scanner result below has a separate, bounded scope.

## Native Rocky ACL, SELinux and AIDE validation

Ten tests passed without failures or skips on the retained Nutanix AHV
diagnostic guest using public Rocky Python **3.14.8** and
`aide-0.19.2-5.el9_8.1.x86_64`. SELinux stayed **Enforcing**. The tests ran
through a transient systemd service in
`system_u:system_r:unconfined_service_t:s0`, using the actual atomic API writer,
vendor AIDE scanner, database parser and retained-history validator.

The positive metadata case created a named-user POSIX ACL, a binary user xattr
and a custom `system_u:object_r:etc_t:s0` label before preparing the baseline.
After atomic replacement, all attributes were identical and the inode was new.
AIDE accepted the intended cutoff change and subsequently reported a clean
state. Other cases exercised interrupted database replacement, retained
authorization, forward/rollback lineage, altered proofs, unrelated changes,
and rejection of changed xattrs or API bytes. The synthetic database-row
mutation case remains in the container regression suite; it is excluded from
the native runner because its fake-scanner injection does not apply to real
AIDE output.

The first transient service failed at standard-output setup before Python
executed: systemd could not open a file under the fixture's private temporary
directory. The second service used journal output and completed successfully.
No SELinux policy, enforcement setting or appliance enrollment gate was changed.

The older diagnostic guest needed four additional vendor packages:
`python3.14`, `python3.14-libs`, `python3.14-pip-wheel` and `mpdecimal`.
DNF used the public BaseOS/AppStream repositories with package signature
checking enabled. No installed package was replaced, including the kernel and
system Python. Vendor non-configuration files verified without differences;
the sole full-package verification difference, `/etc/aide.conf`, exactly
matched the repository's managed configuration. Tests used their own explicit
temporary AIDE policies.

All 226 transferred source inputs were hash-verified before and after testing.
Receipts, scanner databases and journals were collected before removing test
scratch and the dedicated DNF cache, reclaiming **122,925,056 allocated bytes**
on the guest. The four new runtime packages remain for later qualification.
The guest was shut down gracefully and its NIC disconnected; the final VM
specification matched the pre-test specification on independent API readback.

This closes the bounded native metadata/scanner test, not appliance acceptance.
Restore admission, storage identity and source/plan admission are still fixture
boundaries. The guest still reports the known kernel HKDF self-test failure
despite its enabled FIPS flag. Complete native restore/update integration,
strict cryptographic acceptance, VMware parity and the final OVA remain open.

## Pre-restore capture includes interrupted session work

Keycloak logout can replace the realm cutoff with its current clock. If the
logout response is lost before the higher intended cutoff is repaired, that
higher value may exist only in `session-cutoff.json`; the API environment may
still have its older value. Reading only the live realm and API before
database replacement can therefore miss a durable rejection boundary.

The capture path now validates the retained session record and includes its
floor in the maximum, for `intent`, `realm` and completed `api` phases. The
installation, API path, record shape and realm must match. Incomplete work
also requires the same non-cutoff API configuration. A changed journal during
observation is refused rather than silently adopting an incomplete snapshot.
The same record validator serves session reconciliation.

Database-replacement resume still requires the original bound capture and
does not query a partially restored database or require the API file to exist.
It refuses a journal from another realm or a journal floor above that capture.
Capture leaves the session journal untouched and grants no permission to take
over an unfinished operation or release maintenance.

Validation passed **735 regression tests without skips** on Rocky Python
**3.14.8**, Linux/amd64. Eleven added cases cover lost logout acknowledgement,
failed API writes, completed records after database/configuration rollback,
resume without a live API/database, malformed or foreign state, changed
configuration, concurrent journal changes, unsafe journal files and the
adapter's capture boundary. All eleven failed against the prior module
(18 failed assertions including subtests). The adapter case uses actual
private files with injected native commands/SQL observations; it is not a live
database or complete update test. Six owned test containers/volumes were
independently confirmed absent afterward.

Forward migration remains unconnected. Safe retirement of its interrupted
temporary authority and session operation, forward integrity authorization,
and complete update/rollback execution remain required.
