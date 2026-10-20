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
