# Internal host plan and job primitives

This is the **journal core**, not completed appliance management. The subsequent **post-v7 [read-only storage plan slice](HOST_READ_ONLY_PLANS.md)** exposes capabilities, plan creation and owner-bound lookup through a protected local socket and Administrator API source. Its foreground CLI is opt-in and has no installer/boot integration. Acceptance/cancellation primitives below remain unexposed; there is no systemd dispatcher, executor, storage mutation or progress stream. All advertised capabilities return `execution_available:false`; core default capabilities report `executor_not_registered` and the unconfigured manager refuses acceptance. Missing storage, initialization or observation can refuse earlier. These sources have not been qualified in a running appliance.

Sources: [typed operations](../appliance/nebulalog_manager/host_operations.py), [private storage](../appliance/nebulalog_manager/host_job_storage.py), [plans and jobs](../appliance/nebulalog_manager/host_jobs.py). The [integration audit](HOST_CONTROL_INTEGRATION.md) remains the implementation roadmap. Nothing here closes a [release acceptance](RELEASE_ACCEPTANCE.md) gate.

## Fixed data contracts

Only the exact fields in `host_operations.SCHEMAS` are accepted. Unknown operations, missing/extra fields, paths, arbitrary commands, environment variables and service names are refused. UUIDs below are opaque references; accepting UUID syntax alone does not prove that a resource exists or is safe. The new read-only service resolves `storage.grow` against an explicitly enrolled installation/disk/VG/LV pool registry and rejects multi-PV identities. Other resource/artifact registries and every eventual qualified executor still require implementation and verification.

| Operation | Exact parameters |
| --- | --- |
| `storage.grow` | `pool_id` UUID |
| `storage.add_disk` | `pool_id`, `disk_id` UUIDs |
| `updates.check` | `channel:"stable"` |
| `updates.install` | `release_id` UUID |
| `updates.rollback`, `updates.finalize`, `reboot.complete` | `transaction_id` UUID |
| `updates.schedule` | `weekday` integer 0–6, `start`/`end` HH:MM, IANA `timezone`, separate Boolean `automatic_os_updates` and `automatic_application_updates` |
| `os.apply` | `policy_revision` lowercase SHA256 |
| `backup.create` | `recipient_id` UUID, `scope:"configuration"` |
| `restore.apply` | `backup_id` UUID |
| `baseline.scan` | `selection_id` UUID |
| `baseline.review` | `assessment_id`, `review_id` UUIDs |
| `baseline.select` | `policy_id` UUID, `baseline` = `cis-level2`, `stig` or `unified` |
| `settings.network` | `network_configuration_id` UUID; no unvalidated network document or path |
| `settings.time` | 1–8 unique single-token `ntp_servers`, IANA `timezone` |
| `certificates.activate` | `certificate_id` UUID, `target` = `https`, `syslog` or `internal` |

Registration describes a request; it does not enable the operation, prove a recovery path, or override existing host preconditions. Network checkpoints, publisher enrollment, secret/artifact upload, full restore, baseline remediation and external grant policy still need dedicated implementations. Secret values are not schema fields. Certificate/private-key material, credentials and disk recovery keys must never be passed through these ordinary records.

`HostJobs.plan(operation, values, Actor(...))` requires an injected read-only host observer. It returns and durably stores a random host-issued UUID, installation UUID, exact normalized operation/parameters, subject/session, SHA256 resource revision, integer UTC issue/expiry times and canonical SHA256 plan digest. Lifetime is 30–300 seconds. Observation must be at most 30 seconds old, with at most five seconds of forward clock tolerance. No observer means `host_observation_unavailable`, not a fabricated plan. Plans are immutable; changing a setting or revision requires another plan. This primitive is not yet a complete user-facing effects/downtime/data-loss review document.

`HostJobs.get_plan(plan_id, plan_digest, Actor(...))` is an owner-bound read under the same private-record lock. It checks identity/digest and expiry before observation, reinspects the resource revision, and checks final expiry/freshness before returning a copy. It changes no journal or audit record and calls no executor/grant/acceptance/cancellation path. The read-only service supplies issuer/client/subject/session-domain hashes from the verified API session and a sanitized storage review; that API peer assertion is not independent host verification of the human or a mutation grant. See [the exact trust and wire contract](HOST_READ_ONLY_PLANS.md).

## Trusted integration and authorization boundaries

The constructor's callbacks are trusted Python integration dependencies. They are not request parameters, plugin dispatch points or JSON claims. The fixed local plan-service factory does not allow callers to choose them.

- `observer(operation, validated_parameters) -> Observation(resource_revision, observed_at)` must perform bounded read-only inspection and bind the digest to all relevant state: disk identities, configuration, artifact contents and prerequisite revisions. A Boolean feature flag is not observation.
- `executor_probe(operation) -> ExecutorEvidence(operation, adapter_revision, qualification_revision, observed_at)` must independently verify a fixed installed adapter and its actual qualification evidence. The evidence must be at most 60 seconds old and bound to this exact operation. Its presence enables only **internal acceptance**. This module has no executor call and still reports dispatch unavailable. Production code must not wire a constant success callback to enable a button.
- `grant_verifier(proof, expected_binding) -> VerifiedGrant` must independently validate signature, configured issuer/audience/client, Administrator authorization, active subject/session, action and recent MFA under an explicit reviewed assurance policy. It must be bounded and **side-effect-free**. The ledger, not a remote verifier side effect, atomically consumes the grant ID. The core does not implement JWT validation, session introspection or MFA, and a constructed dataclass is not authentication evidence outside this trusted boundary.

`GrantBinding` contains installation UUID, full `Actor(subject, session_id)`, `job.accept` or `job.cancel`, operation, plan UUID/digest, canonical request digest and resource revision. The verifier must return these exact bindings. `VerifiedGrant` additionally contains a canonical one-use UUID, issue/expiry times, authentication time and the assurance-policy SHA256. Grant lifetime is at most 120 seconds; authentication is at most 300 seconds old, with five seconds of forward tolerance. These times and observation/executor freshness are checked again after callbacks before acceptance. Real issuer policy may be stricter. No client-supplied `mfa:true`, role flag or generic service token is accepted as a substitute.

New acceptance checks current plan/body/actor, expiry, absence of a pending job, a freshly matching resource revision and qualified executor availability **before calling the verifier**. An unavailable executor creates no job and consumes no grant. The successful internal state is exactly `accepted_pending_dispatch`, with `execution_started:false` and `dispatch_available:false`; it is not queued to an implemented worker and is never presented as completed work.

Idempotency keys are canonical UUIDs scoped to the full subject/session. The same key and exact body returns the original job after fresh authorization verification; a different body is refused. A retry can read the original acceptance after plan expiry or executor unavailability, because it performs no new acceptance. A consumed grant may authorize only the identical retry with its original immutable evidence. An expired grant requires a new valid bound grant for that read; the new read-only retry does not consume another grant. Reusing a consumed ID for new work, another action or altered evidence is refused.

Cancellation requires a separately verified `job.cancel` grant. Only `accepted_pending_dispatch` can transition to `cancelled`; retry returns the existing cancellation. There is no generic subprocess termination, cancellation of running mutations, or accepted external `running`/`completed` status. Unknown stored lifecycle states fail validation. Subject/session ownership is strict: **a new login session, even for the same subject, cannot read or cancel an old job through these methods**. A separately reviewed cross-session recovery authorization and root console recovery interface are required before production dispatch; do not fabricate the old session or weaken ownership to implement them.

## Encrypted records, serialization and recovery

The default storage guard calls `FirstBoot.gate()` and requires the sealed setup to be complete, including actual encrypted storage inspection and foundation controls. It verifies root-owned protected ancestry, then checks every private directory and record has the same filesystem device as the encrypted data mount. A nested different filesystem is refused. Tests inject a private temporary storage identity; this injection must never become an operator-supplied “encrypted” assertion or path.

Canonical persistent layout:

```text
/var/lib/nebulalog/manager/transaction.lock
/var/lib/nebulalog/manager/host-jobs-identity.json
/var/lib/nebulalog/manager/jobs/initial-pending.json
/var/lib/nebulalog/manager/jobs/ledger.json
```

The read-only storage service additionally retains sealed `manager/host-plan-pool.json` and `manager/jobs/host-plan-pool-genesis.json`. Requests never enroll or repair these records. Explicit recovery of interrupted enrollment is limited to an entirely pristine journal: revision zero and empty plans/jobs/audit/grants/idempotency. Existing history or a surviving conflicting/missing binding refuses reenrollment; full details and root-rollback limits are in [HOST_READ_ONLY_PLANS](HOST_READ_ONLY_PLANS.md).

Directories are root-owned `0700`; records and the existing shared lock are regular root-owned `0600` with a single hard link. Symlinks, wrong owners/modes, unsafe ancestors, changed files and oversized records are refused. No public snapshot or container mount contains this journal. The default guard must succeed **before** any journal directory, lock or temporary file is created. File and directory barriers include the encrypted root so a retry also flushes a previously uncertain new manager-directory entry.

One nonblocking exclusive global `manager/transaction.lock` protects each inspection/plan/journal transaction. Within this store, at most one pending accepted job exists. After restart it remains pending and blocks another acceptance; status reports that it requires verified cancellation or a future dispatcher integration. Existing storage/update managers use the same short-held lock, but they **do not yet inspect this pending-job ledger**. A future executor coordinator must integrate those pending-work and recovery checks and define one lock owner before exposing any mutation. This core does not reserve the entire appliance while an inert pending record exists.

The single authoritative ledger contains plans, jobs, idempotency entries, consumed grant receipts and a hash-linked audit sequence. Each acceptance or cancellation replaces that ledger atomically after validating all cross-references. It fsyncs the new file and parent directory. There is no separate authoritative JSONL/database write that could leave a consumed grant without its job or duplicate an accepted operation. Audit entries contain actor/session, action, operation, IDs, request digest and time; they contain neither the proof nor parameter values. Callback exception text is suppressed with stable refusal codes. Any future PostgreSQL mirror must be a replayable projection of this ledger.

Explicit initialization first writes a durable empty genesis proposal, then the identical genesis ledger, then the permanent identity marker **outside the jobs directory**. Interrupted initialization can only finish that exact genesis. Missing or changed marker/ledger/genesis after use is refused; deletion of the whole jobs directory cannot initialize a new registry while the outside marker survives. Orphan `.pending-*` files are never promoted. Acceptance/cancellation reply loss is reconciled through the original idempotency/cancellation record, including another durability barrier before a retry acknowledgement. Corruption, incomplete indices, invalid audit chains, clock rollback and unknown schema/states fail closed; the module never automatically resets uncertain work.

Hard limits are 8 MiB per authoritative record, 4,096 retained plans, 1,024 jobs, 2,048 consumed grants and 4,096 audit events. Generic `HostJobs.plan` callers keep the original 1,024-total-plan admission limit. The fixed read-only storage service explicitly opts into `read_only_admission=True`: its 1,024 charged slots exclude only expired `storage.grow` plans for the exact enrolled pool with no reference from any job. Accepted/cancelled plans, other pools/operations and live reviews remain charged. Full prior plans, audit entries, grants and idempotency records remain intact. This is admission reclamation, not physical compaction; the new plan and audit event are still one atomic durable write under the existing lock.

Admission requires validated history and time at least as recent as its last audit event, then refuses backward time or a forward jump over 30 seconds during the bounded read-only observation. It does not prove externally trusted wall time. No wire field controls this trusted integration policy. Older readers that reject more than 1,024 retained plans fail closed; do not downgrade/reset the journal. There is intentionally no silent history deletion, rotation or compaction. Record/audit exhaustion still refuses new work; reviewed bounded archival/compaction with preserved replay protection is required before sustained production use. SHA256 checks detect corruption and inconsistent state; they do not provide tamper-proof history or rollback protection against root, whole-disk snapshot restoration or deletion of all external anchors. Those require a separate recovery/trust design.

## Validation and remaining integration

Run the isolated tests with:

```sh
PYTHONPATH=appliance python3 -m unittest discover -s appliance/tests -p 'test_host_*.py' -v
```

The tests cover all operation schemas; command/path/unknown-field and IPv6-scope token injection; unavailable executors; missing or invalid verifier evidence; binding/session/expiry/replay failures; changed resource revisions; acceptance/cancellation retries before and after uncertain commits; every initialization write boundary; parent-fsync retry; lost journal directory/anchors; corrupt/duplicate/truncated JSON and audit/index inconsistencies; global lock contention; nested filesystem and permission/link failures; capacity limits and proof/error redaction. The post-v7 host suite totals **110 passing tests**, including local socketpairs and admission from 1,024 to 1,025 retained reviews with unchanged history, accepted/cancelled retry preservation and forward/backward clock refusal. They run no appliance disks or executors. The separate Linux UID/GID Python/Go round trip and unauthorized-peer tests passed after capacity recovery, using synthetic geometry and a private temporary journal; this proves neither real encrypted storage nor guest installation. See [the retained verification boundary](HOST_READ_ONLY_PLANS.md#integration-status-and-verification).

Next work must provide real independently verified authorization, a resource/artifact registry, qualified fixed executors, dispatch/recovery coordination, durable compaction, authenticated cross-session recovery, narrowly scoped maintenance access and role-tested browser/API workflows. Installing or exposing this core alone must not enable a management button.
