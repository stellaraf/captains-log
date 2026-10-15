# Appliance updates

Captain’s Log owns component versions. Podman auto-update tags are not used. A signed release specifies supported upgrade paths and explicit component versions; ClickHouse additionally names its family and tested minimum/maximum. PostgreSQL major upgrades and irreversible format migrations require a controlled recovery procedure, not automatic image replacement.

**Current status:** OS maintenance, GitHub release discovery/download and the signed component transaction engine are implemented in source, but complete self-updating has not passed appliance acceptance. AIDE renewal for exact host and supported RPM payload changes is integrated in source; actual OS reboot and complete component upgrade/rollback acceptance remain open. Current source adds operation-bound compliance review/retry for health checks; this does not complete initial component-install recovery from a review-required failure. The logging system (ingestion and ClickHouse), application, and managed PostgreSQL/Keycloak versions all remain in the update scope.

## GitHub automatic updates

The default repository is [`stellaraf/captains-log`](https://github.com/stellaraf/captains-log). The installed `nebulalog-app-update.timer` checks at minutes **00, 15, 30 and 45** of every hour, with a persistent missed-run check after startup. This 15-minute schedule supersedes the original daily-check specification at the product owner's request. Stable, compatible releases install automatically; there is no separate application maintenance-window approval. Rocky package updates and reboots retain their separate maintenance policy below.

The policy lives in root-owned `/etc/nebulalog/github-updates.json` and defaults to `automatic_updates: true`, `poll_interval_seconds: 900`. The service requires completed first boot and the encrypted data mount. Public GitHub releases need no GitHub credential. A private fork may use a root-only read token at the fixed encrypted path `/var/lib/nebulalog/configuration/github-read-token`; neither the token nor private download URLs appear in status or audit output.

Each published stable `vMAJOR.MINOR.PATCH` release must contain `manifest.json`, `manifest.sig`, and every OCI artifact named in the signed manifest. The version must match the GitHub tag. Downloads use GitHub's numeric asset API; redirects are restricted to GitHub's HTTPS asset hosts, and API credentials are never forwarded to them. The signature, expiry, supported versions, rollback policy and available space are checked before large artifact downloads. Exact byte counts and SHA-256 hashes are verified before the existing transaction engine can activate anything. Release assets cannot choose a command, publisher key, external download origin or installation hook.

A known, fully terminated failed health check rolls back and keeps the release sequence high-water mark, so the next 15-minute check cannot repeatedly reinstall the failed release. Pending recovery or incomplete maintenance release blocks new installation. Network errors and missing releases are recorded for subsequent checks. Checks do not overlap; OS, storage and component mutations remain serialized by the manager's existing transaction lock. A long-running update is allowed to finish instead of starting another at the next timer tick.

Administration → System → Updates reports the repository, configured policy, timer enabled/active observations, publisher enrollment, last/next check and freshness. Automatic operation is reported only when those observations support it; stale, blocked or unenrolled channels do not appear healthy. The development Docker stack has no host timer and continues to report the channel as not connected.

**Release readiness:** the GitHub repository is connected, but no qualified stable release or production publisher enrollment has been published yet. Source tests cover the downloader, real TLS and signatures, rollback and status reporting. A real GitHub asset-to-guest upgrade, two observed timer intervals, OS/kernel reboot, data retention, and VMware/Nutanix imports remain required. A passing source test is not appliance acceptance.

## Signed release verifier

The manager verifies an exact JSON manifest with a trusted out-of-band RSA public key using RSA-PSS/SHA-256 with a 32-byte salt. It rejects invalid signatures, altered bytes, duplicate JSON keys, expired/future metadata, replay/downgrade sequences, unsafe/symlink paths, unexpected components, missing hashes/lengths and unsupported upgrade paths. No signing private key is present in the repository or appliance recipe.

```sh
nebulalog update status
nebulalog update check --manifest <manifest.json> --signature <manifest.sig> --bundle <download-directory>
nebulalog update history
nebulalog update rollback
nebulalog update finalize
nebulalog update reboot-complete
nebulalog update os-recover
```

Signature verification is only as trustworthy as the installed verification key and root filesystem. Release infrastructure must establish an offline protected signing key, documented public-key enrollment/rotation and signed channel metadata. A bare SHA-256 checksum from the download server is insufficient.

First boot records the measured versions and immutable OCI identities of the installed application, PostgreSQL, ClickHouse and Keycloak, then automatically enrolls the publisher public key packaged in the trusted initial appliance image. Appliance owners do not run a separate key-enrollment command. The initial sequence, captured source and exact public trust inputs are bound by build provenance; an uncommitted source snapshot is labeled as such. See [initial identity and publisher enrollment](UPDATE_ENROLLMENT.md) for the build contract, crash recovery and trust boundaries. The project public identity is configured in source; the protected GitHub release signer and real-release guest acceptance remain outstanding. `update status` exposes missing or invalid enrollment; an arbitrary `--public-key` cannot bypass established trust.

## Transaction mechanism and current gate

`nebulalog update install` uses the same manifest/signature/bundle options. It verifies supported versions and disk reserve, copies/reverifies immutable staging files, records a durable transaction journal and invokes **fixed locally installed root-owned adapters**, never a downloaded hook name. Preflight and PostgreSQL/configuration backups precede component activation. Postchecks require API, Web, ClickHouse, PostgreSQL, Keycloak, local auth, ingestion, FIPS, SELinux, LUKS, firewall and compliance. Failure invokes rollback and repeats health checks; any failed recovery is recorded as `recovery_required`. A release sequence high-water mark survives rollback.

The [installed lifecycle adapters](../appliance/adapters/README.md) implement these operations using bounded systemd, Podman/Skopeo, PostgreSQL and ClickHouse commands. They accept same-schema, explicitly reversible immutable OCI changes. Current development source also implements the fixed schema-1-to-2 transition described below; other schema changes and database major upgrades remain refused. The reviewed content-only baseline transaction and its required capability/enrollment sequence are described in [Compliance content updates](COMPLIANCE_CONTENT_UPDATES.md); scanner RPM/engine changes remain a separate qualified recipe. Keycloak changes also require signed, candidate-bound real browser evidence for local MFA, AD/LDAPS+MFA, Okta/Entra/generic SAML and generic OIDC. The routine health probe independently proves fresh local password+OTP with PKCE and authenticated VIEWER access; it does not substitute for remote-provider browser evidence.

Emergency storage protection introduces application schema **2**. Build provenance,
factory enrollment and release assembly now bind the declared revision to the
complete, reviewed set of PostgreSQL, ClickHouse and step-up migration file hashes.
Changed or additional SQL cannot be labelled as a schema-1 update. The source
includes a persistent host storage gate, a matching database gate and a tested
PostgreSQL lock barrier. They distinguish pausing destructive cleanup from pausing
log delivery, and retain the host hold when database acknowledgement is lost.

The fixed schema-1-to-2 executor and component lifecycle integration are implemented
and undergoing native qualification. The executor compares the complete catalog
against reviewed SQL, records an immutable operation before dispatch and verifies
the actual committed catalog and marker in a separate transaction. A lost
acknowledgement never authorizes replay. Recovery removes the exact client container
and terminates its tagged PostgreSQL execution before any metadata restore.

Existing installations need a compatible coordinator update before a migration
release: lifecycle hooks run through the previously accepted host generation.
That bridge must retain the old schema-1 application and its Quadlet templates;
it must not claim schema 1 for the new schema-2 source. A later operator application
rollback preserves the additive database schema, users and current data. Actual
schema provenance is stored separately from the installation's lifecycle settings
and remains bound to the original migration receipt and verified backup. Preserve
that entire release stage while the provenance references it. An interrupted
immediate restore resumes only from its exact backup and continuous host hold;
a completed restore is not replayed after writers have resumed.

Real PostgreSQL and coordinator interruption tests have passed. Native
Podman/systemd transport, combined release installation and OS hold finalization
are still being qualified; these changes are not deployed or accepted as a complete
self-update path. A fresh schema-2 install or successful package assembly does not
prove the existing-installation upgrade/rollback path.

Metadata backups and all credentials remain on the encrypted data mount. API/identity writers are quiesced. A verified gate-aware collector continues receiving into durable WAL with database delivery paused; a legacy or unverified collector is stopped for a consistent backup. A failed activation restores validated metadata/configuration and original image pins; a later operator rollback preserves post-commit users/configuration/data and changes only the release's image pins. ClickHouse log history and WAL are not rewound by metadata restore. Unresolved ClickHouse removal or insertion evidence blocks metadata changes. An unrecovered backup failure records `recovery_required` and retains maintenance.

Component completion is durable before `update-finalize` releases maintenance. If release fails, the accepted software remains installed; status exposes pending finalization and blocks new work. `nebulalog update finalize` repeats retained signature/exact transaction hash checks and current health, then retries only maintenance release. Installation expiry may have elapsed for this recovery-only action, which never activates software or restores data. The operator rollback command also re-verifies retained metadata and requires a reversible release plus complete health; expired metadata remains refused for rollback/new installation, and altered metadata is always refused. **Adapter and engine unit coverage is implemented; installed-guest upgrade/rollback qualification is still pending.** GitHub delivery is implemented in source and still requires real-release guest acceptance.

## OS and maintenance

Ordinary reboots also require integrity reconciliation. Newly enrolled images
retain an immutable boot-state root; the maintenance gate compares each boot
with that root and accepted update history, then requires AIDE and all runtime
checks before reopening access. The boot verifier also runs periodically to
handle the vendor's later boot-success flag and interrupted verification.
Unknown changes and foreign pending operations remain held. This workflow is
implemented in source and still requires native appliance qualification; see
[ordinary boot recovery](OS_UPDATE_QUALIFICATION.md#ordinary-boots-and-late-boot-success-flags).

The image configures RPM signature checks and retains the current kernel plus two prior kernels (`installonly_limit=3`). The OS manager runs only inside the configured timezone/day/time window, with default intent Sunday 03:00–05:00 local. It downloads Rocky 9 update candidates and requires an exact supported RPM/file plan before any package mutation. The current executor supports a narrow scriptless payload replacement; unsupported scripts, triggers, kernel/checker transitions and generated files are refused. It checks security postconditions, asks `dnf needs-restarting`, and rechecks the window before requesting a reboot. Complete automatic Rocky security/minor/kernel support remains unfinished; see [OS update qualification](OS_UPDATE_QUALIFICATION.md). It never changes image-pinned ClickHouse/Keycloak versions independently.

The local OS adapters enforce enrolled Rocky repository keys, healthy databases, encrypted backups, durable ingestion preparation and explicit unlock readiness. Console-only unlock cannot claim unattended reboot readiness: updated packages retain a pending reboot. A rejected reboot request invokes the fixed abort adapter and requires real service/API/local-MFA recovery evidence. The boot gate restores the nonsecret Apache maintenance marker from encrypted state before external mutations are accepted. Reboot completion requires a changed boot ID and full runtime/security checks, and can be retried with `nebulalog update reboot-complete`. A request accepted by systemd is not successful reboot evidence. These paths require actual guest qualification before unattended operation is claimed.

OS package changes now require all 12 runtime/security checks even when no reboot is needed, or when a reboot must wait. A failed check retains its operation-owned backup and blocks further automatic changes. `nebulalog update os-recover` retries the exact same-boot postcheck operation after the underlying issue or compliance review is resolved; it verifies the retained backup and fresh health, and completes the journal before releasing maintenance. It does not repeat RPM/DNF installation or restore databases/logs. An interrupted apply can recover only if the retained exact package/file result and its AIDE acceptance pass; a partial or unplanned package transaction remains blocked for investigation.

A deferred reboot is checked again at the next maintenance window even if there are no newer RPMs to download. That attempt takes a fresh backup, binds the unchanged package inventory to the current boot, runs an ordinary AIDE check without replacing its baseline, and rechecks runtime health and the maintenance window. A failed package query, unknown reboot hint, or failed health check cannot silently clear the pending reboot.

If the process is interrupted while preparing to reboot, `nebulalog update os-recover` can restore the operation's services on the same boot. It verifies the retained backup and package/AIDE state before starting services, then requires all runtime checks before releasing maintenance. It neither installs packages again nor requests a reboot. A transaction that already requested a reboot follows the separate new-boot completion path; the recovery command cannot reinterpret it as an interrupted preparation.

For an interrupted component transaction, `nebulalog update recover` verifies the retained release signature and transaction, restores through the previous host coordinator, and requires fresh health checks before releasing maintenance. This command can restore configuration and release pins from the interrupted operation; completed transactions use `finalize` instead. Pending OS recovery must finish first. The appliance status publishes the applicable fixed recovery command.

If backup or preparation stopped before activation, recovery uses the durable
preactivation journal and the original protected backup intent to verify that
configuration, permissions, image pins and actual database schema are unchanged.
It settles the storage barrier and restarts the previous services without
restoring partial database dumps. Incomplete backup files remain available for
diagnosis. Any candidate migration/activation evidence, changed runtime, foreign
maintenance owner or unresolved storage action refuses this path. Full health
checks and durable transaction completion still precede maintenance release.
Every new component transaction also uses hook lifetime protocol 1. The manager
publishes an immutable dispatch intent before launching each fixed hook. The
adapter records entry once and publishes a terminal outcome only after its method
and cleanup paths have ended and every native invocation has a durable success
acknowledgement. Exact stage, manifest, sequence, coordinator, command digest and
result bindings are retained. A returned JSON success alone is insufficient.
Known Python/health failures with settled native work can use recovery; timeout,
interruption, missing terminal evidence or an unresolved native command keeps the
operation held before host selection, rollback, fresh health or gate release.
Status reports `hook_outcome_unsettled` and `recovery_blocked_by:hook_outcome`.
An available process lock or absent client PID never settles delegated work.

Two fixed observational commands have narrow completion rules. The exact
PostgreSQL readiness `SELECT 1` probe may acknowledge a normally returned nonzero
result, with its argv digest and probe identifier bound in the journal. OpenSCAP
evaluation may acknowledge normal exit 2 only after validating the exact retained
policy, inputs, profile and completed XML/HTML reports. Original source bytes are
checked before and after execution; retained copies preserve historical evidence
across later authorized content changes. Findings still fail health until the
existing assessment review requirements are met. Changed operations, signals,
timeouts and malformed reports retain the hold; no failed mutation is waived.
Direct host AIDE operations also have durable compound dispatch evidence and
require the complete authorized operation to return exact success. OS, livepatch
and ordinary-boot admission apply the same settled-hook guard before beginning
their work.
A missing preactivation snapshot may be recaptured only before the first hook
was ever dispatched. Unknown attempts are not replayed. Native schema transport
recovery has separate exact executor fencing, but the new outer hook guard still
holds unknown dispatches before entering that recovery. Earlier native schema
fault tests do not qualify integrated recovery through this new protocol.

An older already committed and finalized release remains an accepted starting
point for a new installation after exact retained signature/current/history and
maintenance checks. This bridge does not retroactively claim hook evidence. Any
mixed new-protocol artifacts refuse the legacy allowance, and interrupted,
failed-preflight or pending-finalization legacy transactions stay held. Legacy
rollback history remains readable; it cannot authorize effects without qualified
hook terminal authority. An older pinned coordinator without protocol support
fails the initial preflight before backup or service changes. These source rules
still require installed-guest upgrade/recovery acceptance.

Native x86_64 UEFI/Secure Boot build work is present; tested vTPM enrollment and unattended encrypted-storage reboot on both selected hypervisors remain required. The GitHub transaction also carries compatible management-software generations with exact AIDE renewal; the new reviewed content-only baseline path remains unaccepted on a native appliance, and checker/engine changes and broad OS package recipes remain separate unfinished work. These are explicit candidate limitations, not accepted all-software update coverage.

The first-boot maintenance configuration, scheduled GitHub delivery, UI status bridge, controlled database migration/rollback and OS kernel reboot still require installed-guest acceptance. The source tests do not change host packages or services. A separate disposable native guest has executed a real signed inert-RPM upgrade and refusal tests; that result does not establish full appliance acceptance.

### Vendor kernel updates and retained live-patch tooling

The October 13, 2026 product decision retains vendor-supplied Rocky kernels.
Automatic package maintenance and controlled reboots are the release path.
New factory installations set `automatic_livepatch: false` in
`/etc/nebulalog/github-updates.json` and do not enable
`nebulalog-livepatch.timer`. This leaves application `automatic_updates: true`
and its 15-minute schedule unchanged. Existing installations are not silently
rewritten; an already enabled live-patch policy requires explicit operator review.

Self-built live-patch tooling is retained for isolated qualification. Its
disabled-by-default timer, when explicitly enabled with an opted-in policy,
runs two minutes after boot and at minutes 07, 22, 37 and 52.
`nebulalog update livepatch-poll` enforces the same policy before network access
or module loading; `nebulalog update livepatch-status` observes retained state
and the current kernel without loading a module.

A committed patch is reauthenticated and reapplied to the identical kernel on a
new boot before contacting GitHub. The feed uses the exact tag
`livepatch-<kernel-release>` and requires signed metadata and matching artifacts.
Publish these releases with `make_latest=false` so they do not replace the
application release channel. A missing publication means no published patch,
not security coverage. A saved sequence alone never proves an active patch.
Interrupted loads require recovery; automation does not force a transition,
unload a patch, bypass failing FIPS checks, or enroll an untrusted module signer.

The retained timer and transaction integration have source tests, but they are
not an enabled release feature or a substitute for the vendor kernel update
tests. A qualification marker patch is not a security fix. Reintroducing live
patching would require an explicit scope decision and native qualification.
