# Identity maintenance backend

`IdentityMaintenanceBackend` implements the fixed host boundaries needed by
`TemporaryIdentityAuthority`. It is included in the **137-file** factory host
catalog. No lifecycle entrypoint invokes it yet; inclusion in a verified archive
does not authorize activation or migrate an installed catalog.

## Admission and external access

The backend binds a canonical release stage, activation/rollback direction,
installation UUID, manifest, immutable Keycloak image, and protected setup,
database environment, Quadlet and CA inputs. Native use requires the active
lifecycle hook lease and durable activation admission.

The caller must first stop API and ingestion writers and establish the exact
transaction's private/public maintenance markers and delivery hold. `hold()`
then stops the host Apache edge and verifies its inactive state. Every subsequent
operation rechecks those fences, bound inputs, encrypted storage, and the
encrypted Podman graph root. Success never starts Apache or releases maintenance.

## Vendor command and interruption recovery

Before creating a container, the backend stores the credential environment on
encrypted storage and persists its hash with the operation and command intent.
It runs the installed immutable image with its original entrypoint and
`bootstrap-admin service --optimized`. Strict FIPS remains enabled. Credentials
are passed through the private environment file, not command arguments; the
original bootstrap password is not copied.

The command has an operation/attempt-derived container name and ownership
labels. Inspection must match its exact ID, image, creation arguments,
environment, user, capability restrictions and read-only root. The temporary
data directory is a tmpfs: the command does not mount or relabel the server's
persistent Keycloak data. Only the appliance CA is mounted from the TLS tree.
See the vendor's [container inspection fields](https://docs.podman.io/en/stable/markdown/podman-container-inspect.1.html).

An uncertain create response leaves intent that can identify the exact owned
container. Recovery persists that identity before stopping or removing it.
An uncertain start/wait cannot authorize server startup. Quiescing checks the
actual server container as well as systemd, removes only the owned command, and
requires all Keycloak database-writer connections to be gone. Command retries
are bounded and require the previous attempt to have been fenced and removed.
A lost removal response is reconciled by inspection before deleting the private
credential file. Foreign containers and changed recipes are refused.

## Identity and completion evidence

The SQL observer reads the installation/realm identity, disabled `nlbootstrap`
account, vendor temporary-client marker, service-user link, administrative role,
and account protocol flags. It also detects other recovery clients and orphaned
recovery service users. It performs no account or role mutation.

The HTTPS connection uses the previously qualified local TLS transport. Server
readiness additionally requires discovery to advertise the configured issuer.
Empty HTTP 201 responses to POST are supported because actual Keycloak creation
endpoints use that response; callers still verify the resulting entity.

`record_work()` is called only after scope reconciliation and session journaling.
It checks the private journal, actual realm ID/installation/cutoff, and the exact
API environment. It stores a digest of product-realm clients, scopes, mappers,
role definitions/composites, service users and grants. Only the digest is retained,
not raw database credential values. `settled()` repeats those reads, so deleting
the master-realm recovery account cannot hide changed product authorization or
revived authentication state.

Completion also requires a persisted removed command, an absent private
credential file, and no reappeared recovery container. A retained work receipt
cannot override an unfinished command cleanup.

## Executed validation — 2026-10-20

All **195 focused tests passed** under public Rocky Python **3.14.8** on
Linux/amd64, with no skips. These include 16 backend cases covering command
ownership, interrupted create/start/remove, input and storage fences, actual
server-state observations, bounded retries, and completion readback. The
systemd, Podman, SQL and encrypted-storage boundaries in these tests are fixtures.

A separate isolated fixture passed **19 checks** against actual PostgreSQL
**17.11** and Keycloak **26.8.1** over verified HTTPS. It executed the backend's
SQL ownership/authorization observations and session/work completion readback;
verified the two managed service clients' token roles; detected foreign temporary
clients, orphan service users, bootstrap re-enablement and role-definition drift;
and verified logout cutoff, recovery-account deletion, and refusal of the deleted
account's credentials and issued token. An initial run exposed Keycloak's empty
HTTP 201 creation response; the transport was corrected and the final run passed.

This fixture injects lifecycle/storage fencing and the native command-cleanup
gate. It does not execute the production Podman recipe or establish native FIPS
acceptance. Its disabled bootstrap user is created after the vendor recovery
command, so this fixture alone does not prove preservation of a pre-existing
bootstrap identity. The separate interruption-recovery evidence remains required.

## Acceptance boundary

### Composed post-restore session recovery

`IdentityMaintenanceBackend.restore_sessions()` composes the retained temporary
authority, session journal and completion observer. It requires rollback
direction, verified completed database restoration, the exact pre-restore
capture, and the original API environment from the verified recovery set.
Before creating authority it persists an operation-bound admission recording
whether first-use authority/session initialization is permitted. Retries reject
changed admission, changed customer bytes and missing admission with existing
work.

The operation retains maintenance while obtaining the vendor recovery account,
reconciling the captured cutoff over HTTPS, writing the API cutoff, and removing
the recovery account. Completion requires the controller's persisted removed
state, erased secret/token, live SQL/session readback and removed command
containers. Its receipt explicitly leaves maintenance held. A lost completion
acknowledgement can reuse the exact receipt without creating a second account
or repeating completed session work. New state-directory entries are fsynced
before subsequent durable work.

The composed operation is not yet invoked automatically by lifecycle service
startup. Host resource preservation now verifies the exact completed restore
transformation described below. AIDE still requires the original API environment
hash and needs retained historical authorization before this operation can be
connected without failing integrity acceptance. The completed-restore retry path must also
preserve the new cutoff rather than recopying the old configuration. Those checks
remain enforced; this work does not exempt the API environment from integrity
monitoring or claim full appliance rollback acceptance.

Validation passed **314 focused tests** under Rocky Python **3.14.8**, with no
skips. The composed-operation cases cover lost creation, logout, deletion,
admission and completion acknowledgements; changed customer configuration or
capture; missing admission; and idempotent completion.

A real PostgreSQL **17.11** / Keycloak **26.8.1** HTTPS fixture passed the
**20 identity checks**, **six database capture/restore checks**, and **15
post-restore workflow checks**. Three separate Rocky Python processes lost the
vendor-command creation response, resumed through session repair and lost the
account-deletion response, then completed cleanup and repeated completion.
The workflow created one recovery account, performed session work once, and
verified its removal and credential erasure. The retained cutoff and all other
API environment bytes remained correct after actual database replacement.

This fixture executes the production composition, SQL observations, HTTPS
transport, session journal and authority controller. Its command boundary uses
owned Docker containers for the real vendor CLI and server, with injected native
Podman journaling, lifecycle admission and encrypted-storage checks. It does not
qualify those native boundaries, AIDE acceptance, or the full appliance lifecycle.

### Host preservation after session recovery

Rollback host reconciliation can authorize the single changed
`runtime/api.env` inventory entry through
`verify_restore_api_preservation()`. Forward activation, backup and preparation
retain their exact original-file checks. Every other customer/trust inventory
entry must still match, with no added, removed or reordered entries.

The read-only verifier binds the original protected API descriptor to the
verified recovery copy, requires completed database replacement and the exact
pre-restore capture, and validates the operation's admission/completion records,
installation identity, immutable image pin and retained input hashes. It
compares all non-cutoff bytes directly, requires the canonical final cutoff line
and a nondecreasing floor, checks the completed session journal and removed
temporary-authority record, then remeasures both API files. Files must retain
root ownership, private mode and protected ancestry. The returned evidence
contains hashes and metadata, never credential values; it does not release
maintenance or assert current database/server health.

The focused Rocky Python **3.14.8** run passed **348 tests** without skips,
including changed customer values, lowered cutoffs, wrong plan descriptors,
changed recovery copies, foreign or incomplete operations, missing admission,
unremoved authority, concurrent file modification, and forward-use refusal.
Existing AIDE tests still reject unrelated byte/metadata changes. The test
container's private scratch mount has protected ancestry; the first attempt
correctly refused fixtures beneath a world-writable scratch parent.

The repeated PostgreSQL **17.11** / Keycloak **26.8.1** HTTPS fixture passed
**20 identity checks**, **six database capture/restore checks**, and **19
workflow/preservation checks** across three separate recovery processes.
The new verifier accepted the actual restored API cutoff, refused a wrong
preimage, returned no customer credential value and did not authorize releasing
maintenance. Creation, session work and deletion each occurred once despite
lost creation/deletion acknowledgements. Native admission, command journaling
and encrypted-storage checks remain injected as described above.

This host check does not grant an AIDE exception. Historical authorization,
completed-restore resume ordering and lifecycle invocation remain required.

### Pre-restore cutoff capture

Failed-activation rollback now calls `capture_before_database_restore()` after
stopping application/identity writers and before publishing destructive database
restore intent. It repeats the capture immediately before replacement. The
capture binds the verified backup/restore context and installation, and records
the greatest current clock, API cutoff, live identity-database cutoff and
previously captured cutoff in encrypted manager state outside the recovery set.

The boundary requires matching private/public maintenance markers, a delivery
hold, inactive units, absent or stopped writer containers, no retained recovery
command and no Keycloak database-writer connections. An orphan recovery command
must be reconciled before database replacement; this boundary never deletes it.
Interrupted restore requires the exact retained capture and does not query a
possibly absent or already replaced identity database. Missing or foreign
capture evidence stops recovery.

`SessionCutoffJournal.reconcile()` consumes that retained floor and verifies
the realm identity before mutation. Capture is not session invalidation: the
complete post-restore authority/session workflow must still be connected before
this can qualify a full appliance rollback. Historical image-only rollback
does not replace the database and does not use this capture boundary.

The final source passed **308 focused tests** on Rocky Python **3.14.8**,
Linux/amd64, with no skips. These include capture persistence/failure, exact
restore-resume ownership, parent-directory durability, rollback ordering and
stale-completion rejection. The host-resource fixture uses injected native
identity admission; it does not establish an actual host restore.

The real PostgreSQL **17.11** / Keycloak **26.8.1** HTTPS fixture passed
**20 identity checks** and **11 additional restore checks**. It took a real
database dump, raised the live realm cutoff, captured that newer floor, removed
the database, and exercised retry with the database absent. Removing the retained
capture caused refusal. Restoring the dump demonstrably restored the older
database cutoff; subsequent HTTPS session reconciliation retained the higher
captured floor in both the realm and API environment, preserving other API
configuration bytes. A recreated fixture administration account was removed and
its credentials/token were refused.

The fixture stopped its actual Keycloak container before replacement, but injects
the production systemd/Podman inventory and encrypted-storage admission. It
invokes capture and reconciliation explicitly across the restore; it does not
run complete production lifecycle activation/rollback. This evidence does not
close that integration gate or native FIPS/hypervisor acceptance.

The native-boundary tests inject systemd, Podman, SQL and encrypted-storage
responses. They exercise command journaling and interruption recovery but cannot
establish actual Podman behavior, SELinux labeling, encrypted mount admission or
strict-FIPS execution.

Remaining work includes connecting this backend to the full authority/session
workflow and service-client migration; preserving the authentication cutoff
before database replacement; reconciling the API environment with host-update
configuration preservation; and exercising actual activation, rollback and
interruption on both hypervisors. All prerelease external identity-provider
qualification gates remain in force. The public Rocky kernel's native crypto
self-test blocker and final OVA acceptance remain separate unresolved gates.
