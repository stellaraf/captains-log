# Read-only host storage plans

Source checkpoint: **September 8, 2026, working tree after frozen candidate v7**. This slice implements protected local capability discovery, storage-plan creation and owner-bound lookup. It creates review records, not storage changes. It is absent from frozen v7 artifacts, and this document records no new application deployment, live UI result or installed-guest qualification.

The implementation consists of the [Go client](../internal/hostcontrol/client.go), [Linux peer verification](../internal/hostcontrol/peer_linux.go), [Administrator HTTP handlers](../internal/api/host_plans.go), [Python planner](../appliance/nebulalog_manager/host_plans.py), [socket service](../appliance/nebulalog_manager/host_plan_socket.py) and [`HostJobs.get_plan`](../appliance/nebulalog_manager/host_jobs.py). The existing [job primitives](HOST_JOB_PRIMITIVES.md) remain separate from any dispatch workflow. Every capability and plan reports `execution_available:false`.

## HTTP and identity boundary

All three routes require the authenticated application's **Administrator** role and a private verified application session. Viewer and Analyst cannot use them. The session must match the configured issuer's verified token, current user, authorized application client and audience, `Bearer` token kind, nonempty session identifier and valid issue/not-before/expiry bounds. A role string, unverified request identity, duplicate Authorization header or browser-supplied actor cannot establish this context.

| Route | Contract |
| --- | --- |
| `GET /api/appliance/capabilities` | No query parameters. Returns the single enrolled pool and current read-only `storage.grow` planning availability. |
| `POST /api/appliance/plans` | Exact JSON `{"operation":"storage.grow","parameters":{"pool_id":"<UUID>"}}`; returns `201` with an immutable review. No other operation is exposed. |
| `GET /api/appliance/plans/{id}?digest=<SHA256>` | Exactly one digest query value and a canonical plan UUID; returns the same owner's currently valid, freshly reinspected plan. |

Creation additionally requires one exact `Origin` matching `NEBULALOG_PUBLIC_ORIGIN`, configured as an HTTPS origin without credentials, path, query or fragment. An empty configuration keeps creation unavailable; an invalid nonempty value fails application startup. If present, `Sec-Fetch-Site` must be one `same-origin` or `none` value. Bodies require a single `application/json` content type, strict bounded UTF-8 JSON, exact case-sensitive field names, no duplicate keys, no trailing document and at most 16 KiB. Origin protection does not replace bearer-token authorization. Requests reaching the plan handler receive `Cache-Control: no-store` and `Referrer-Policy: no-referrer`; authentication/role denials can occur earlier in middleware.

Only the API derives the private actor, using lowercase hex SHA256 over the following JSON arrays encoded by Go's `encoding/json`:

```text
subject_hash = SHA256(["nebulalog.host-plan.subject.v1", issuer, client_id, subject])
session_hash = SHA256(["nebulalog.host-plan.session.v1", subject_hash, session_id])
```

These domains bind ownership to the verified issuer, application client, subject and exact original login session. Another login for the same subject cannot retrieve the old session's plan. The Go actor is opaque, redacts formatting and refuses ordinary JSON serialization; only its private wire encoder emits the two hashes. Raw subject/session identifiers and bearer tokens are not sent to the host service or included in plan responses.

The host trusts the authenticated **API process** to assert these hashes for read ownership. It does not independently verify the human, fresh MFA, active-session revocation or a host-control token. The current signed application session is sufficient only for this read-only review scope. A plan, its digest and this actor are **not authorization grants**. The [step-up coordinator](HOST_STEP_UP_TRANSACTIONS.md) remains unwired, and no route accepts a job, consumes a grant, invokes an executor, cancels work or applies storage changes.

## Protected local protocol

The fixed endpoint is `/run/nebulalog-control/plans.sock`; there is no network address or request-selected path.

| Boundary | Required state |
| --- | --- |
| Directory | `/run/nebulalog-control`, root-owned, group **20002**, mode **0750** |
| Socket | Root-owned, group **20002**, mode **0660** |
| API caller | Linux `SO_PEERCRED` UID **10001**, primary GID **10001**, positive PID; supplementary group **20002** provides filesystem access |
| Host server | Go verifies connected Linux `SO_PEERCRED` UID **0**, primary GID **0**, positive PID |
| Ancestry | Real root-owned directories without group/world write; symlinks and incorrect socket type/owner/group/mode refuse |

The server never adopts or removes a preexisting file/socket. It pins the parent directory, checks identity around binding/serving and removes only its own socket inode on orderly cleanup. The Go client checks the protected path and the connected peer; path ownership alone is insufficient. Non-Linux production clients return unavailable. Group 20002 is a dedicated control-access group, separate from the API's primary group and public status directory.

Each AF_UNIX connection carries exactly one four-byte big-endian unsigned length followed by strict UTF-8 JSON. Request bodies are 1–16,384 bytes; response bodies are 1–65,536 bytes. The client must half-close its write side; the server requires EOF immediately after the one request, before dispatch. The server sends one framed response and closes; the Go client requires immediate EOF after that response. Truncation, trailing bytes/frames, duplicate keys, excessive nesting, malformed types, null/missing required fields and unknown fields are refused.

The Go client admits at most four concurrent calls, each with a total **10-second** budget including connection/queue waiting. The Python foreground service handles connections serially with backlog eight; its separate **10-second** deadline starts after accepting a connection, not while that connection waits in the kernel backlog. `StorageObserver` uses an **8-second** planning budget and caps its commands at the lesser of five seconds and remaining time. The default `PrivateRecords` guard also inspects real host state through `FirstBoot.gate()`; those guard commands use their existing runner and are bounded by the outer main-thread alarm, not the observer's per-command cap. Fully exhausted connections close without extending the deadline to deliver an error; Go does not accept late responses. Observer command output bounds are checked before using the result. These are refusal/resource limits, not latency or load qualification.

Exact request envelopes are:

```json
{"schema":1,"action":"capabilities","actor":{"subject":"<SHA256>","session_id":"<SHA256>"}}
{"schema":1,"action":"plan.create","actor":{"subject":"<SHA256>","session_id":"<SHA256>"},"operation":"storage.grow","parameters":{"pool_id":"<UUID>"}}
{"schema":1,"action":"plan.lookup","actor":{"subject":"<SHA256>","session_id":"<SHA256>"},"plan_id":"<UUID>","plan_digest":"<SHA256>"}
```

Success is exactly `{"schema":1,"status":"ok","data":...}`. Refusal is exactly `{"schema":1,"status":"unavailable","reason":"<code>"}`. Allowed codes are `invalid_request`, `peer_not_authorized`, `request_timeout`, `host_unavailable`, `plan_unavailable`, `plan_expired`, `resource_changed`, `manager_busy` and `journal_full`. Unknown internal exceptions become generic unavailability; no exception text or host command output is returned.

For received host refusal codes, HTTP maps `invalid_request` to 400, `plan_unavailable` to 404, `plan_expired` to 410 and `resource_changed` to 409. Busy, full-journal and generic host/peer/transport/deadline failures return 503. Some internal observer failures, including detected registry changes, are deliberately masked to generic unavailability and therefore return 503. This host-error path returns fixed redacted `error`, `code` and `execution_available:false` fields. Earlier HTTP authentication, role, Origin, JSON, content-type and query validation failures use the existing `{"error":...}` response shape. A browser must invalidate prior success on any failed refresh.

## Pool enrollment and review integrity

The initial slice supports only the **single designated encrypted data disk** and rejects an identity containing additional PVs. It does not discover or initialize unknown disks and makes no aggregate multi-disk capacity claim. The pool UUID is stable UUID5 with the installation UUID as namespace and `nebulalog.storage.data.v1` as name.

Explicit initialization binds that pool and installation to the enrolled `storage.Identity` digest, including disk/serial/partition/LUKS/PV/VG/LV identity. Two root-private sealed records retain the binding:

```text
/var/lib/nebulalog/manager/host-plan-pool.json
/var/lib/nebulalog/manager/jobs/host-plan-pool-genesis.json
```

The existing journal marker, genesis and ledger remain required. Records use the default `PrivateRecords` encrypted-storage guard: completed first boot and foundation controls, protected root ancestry, same mounted filesystem device, root **0700** private directories and regular single-link root **0600** records. This is storage on the verified encrypted filesystem, not an additional per-record encryption format. Requests never initialize or repair missing enrollment.

Explicit initialization may resume an interrupted first enrollment only at **pristine journal genesis**: revision zero and empty plans, jobs, audit, grants and idempotency indexes. An existing pool record must match exactly before its missing genesis copy can be written. A missing main record is refused if the genesis copy survives or the journal has any history. Once plans exist, losing either or both pool records cannot trigger reenrollment. Boolean/float schema substitutions, changed seals, identities, files or storage evidence refuse. Loss/rollback of every anchor while the journal still appears pristine cannot be distinguished from a first enrollment; this code does not protect against malicious root or whole-disk rollback.

Capabilities, create and lookup use the existing manager transaction lock. Both registry copies are checked before **and after** physical inspection under that same lock. The production observer calls the existing read-only `storage.inspect` and `storage.growth_plan`; it does not call an executor, grant verifier or mutation routine. Injected observers/runners are trusted Python dependencies, not sandboxed capabilities or public request inputs. Library callers also face a nonblocking per-service admission guard to prevent concurrent reuse of observer state.

A capability response contains `control:"read_only"`, the pool UUID and one operation with `planning_available:true`, `execution_available:false`, `reason:"execution_not_qualified"`. A plan response contains exactly:

- `id`, `installation_id`, `operation:"storage.grow"`, `parameters:{pool_id}`, `resource_revision`, `issued_at`, `expires_at`, `digest` and `execution_available:false`.
- `review:{current_bytes,presented_bytes,unallocated_disk_bytes,stages,requires_unlock_credential,irreversible:true}`.

`current_bytes` is usable XFS filesystem capacity, not the LV geometry or free bytes. `presented_bytes` and unallocated bytes describe the designated disk. Stages retain the supported partition → LUKS → PV → LV → XFS order; an empty list is a no-op review, not evidence that another disk has no capacity. Unlock-credential necessity is descriptive; this protocol receives no credential. Responses include no raw device paths, serials, private actor or bearer tokens.

The resource revision hashes the installation/pool, actual snapshot fingerprint, sanitized review and a revision derived from the fixed `host_plans.py`, `storage.py` and `host_jobs.py` source bytes. Source or resource changes invalidate existing plans. The plan digest seals its immutable identity, private actor, operation/parameters, resource revision and times. Go independently recomputes that actor-bound digest and validates response sizes, fields, stages, lifetime and disabled execution. These SHA256 values detect inconsistency; they are not publisher signatures or qualification evidence.

The transport creates plans with a **300-second** lifetime; the underlying primitive permits 30–300 seconds. `get_plan` checks exact owner/digest and current time before inspection, reinspects resource identity, then checks final expiry/freshness. It modifies no journal/audit record and invokes no execution callbacks. Wrong-owner, missing and wrong-digest plans share the same refusal. There is no cross-session recovery exception.

Creation durably adds an immutable plan and `plan.created` audit entry. Repeated creation makes another plan; it has no idempotency key. A lost response can therefore leave a valid inaccessible-to-the-client plan consuming quota, but cannot start work.

The fixed storage service explicitly uses **read-only admission reclamation**, preserving every full plan and audit entry. Its **1,024 admission slots** exclude only validated, expired `storage.grow` reviews for this exact enrolled pool that **no job references**. Unexpired reviews, another operation/pool, and all accepted or cancelled job plans remain charged. A 1,025th review can therefore be created after 1,024 unused reviews expire, without deleting their identity, parameters, resource revisions, digests or history. The trusted `HostJobs.plan(..., read_only_admission=True)` keyword is fixed by service code and is not accepted on the wire. Other primitive callers retain the original 1,024-total-plan admission policy.

Eligibility is computed after complete journal validation under the same manager lock as observation and the atomic/fsynced new-plan commit. Current time must not precede the latest audit event; backward time or a forward jump exceeding 30 seconds during this bounded planning call refuses without a write. These checks do not independently establish correct wall time before the call. There is no deletion, tombstone, schema migration or separate uncertain maintenance commit. Every job/grant/idempotency linkage and acceptance/cancellation retry remains unchanged. Older source that refuses a ledger containing more than 1,024 plans must not be used to downgrade or reset that ledger.

Hard limits remain **4,096 retained plans**, **4,096 audit events**, **8 MiB per authoritative record**, 1,024 jobs and 2,048 grant receipts. Admission credits do not free record bytes or audit capacity. Exhaustion returns `journal_full`; durable archival/compaction and broader admission/rate policy remain prerequisites for sustained deployment. No request can reset the ledger to bypass these limits.

## Integration status and verification

The Python entry point is an **opt-in foreground** `python3 -m nebulalog_manager.host_plan_socket serve`. Its real factory requires a preinitialized journal and the real encrypted-storage guard. The explicit initialization library entry exists for future reviewed enrollment integration. Neither is wired into installation, first boot or a systemd service. No control directory/group provisioning, API socket mount, SELinux policy, boot-time journal enrollment or maintenance recovery exception was added. The new Go application source constructs the fixed client; missing service/configuration stays unavailable. Do not enable this path by mounting the private journal or exposing a Podman socket.

Completed local checks for this source checkpoint:

| Evidence | Result and scope |
| --- | --- |
| Python `test_host_*.py` | **110 passed** after admission reclamation. Includes real local socketpairs/private file/flock behavior, mocked Linux peer predicates, strict framing/EOF, deadlines, same-lock registry checks, ownership/expiry/resource changes, no execution, initialization loss and fixture shutdown. New checks create review 1,025 from 1,024 expired reviews while retaining full history, preserve accepted/cancelled retries, and refuse clock discontinuities and hard limits. Independent review separately passed nine focused regressions. Portable tests are not Linux kernel/SELinux/LUKS qualification. |
| Full Python appliance discovery | **542 passed** with `PYTHONPATH=appliance:appliance/adapters`, `PYTHONDONTWRITEBYTECODE=1`, `python3 -m unittest discover -s appliance/tests -q`. The final run completed in 18.9 seconds after capacity recovery and correct adapter-path configuration; earlier failed attempts remain recorded below. |
| Go API/auth focused checks | **12 top-level API/authentication tests passed**, with role, session, request and error subcases. They include signed synthetic token verification, exact actor bindings, Origin/JSON bounds and no execution/step-up routes. Auth/API/client race checks passed locally. Synthetic signing does not prove real fresh MFA. |
| Go Unix fixture-client checks | Passed local framing, cancellation/admission, response validation, actor/plan digest and fixed-refusal tests. They use a controlled socket endpoint; Linux ownership and connected peer verification require the separate Linux run. |
| Full Go source and local integration suite | `go test -p 1 -json -count=1 ./...` passed **130 top-level tests and 442 subtests**, with **zero skips or failures**. The explicit local run includes actual ClickHouse-backed calculations, an owned disabled Keycloak broker round trip, and isolated PostgreSQL/synthetic-TLS step-up transactions. This supersedes the earlier 124/418 source run with six skipped integrations. It establishes neither an installed guest nor external-provider sign-in/fresh MFA. |
| Cross-language Linux fixture | **Two top-level tests passed on the final admission source**: real Python/Go capability/create/lookup/ownership round trip and untrusted-server peer rejection. One subprocess-only helper skips when invoked as a standalone top-level test; the parent tests execute its dropped-UID children. Linux arm64, real `SO_PEERCRED`/permissions/flock, synthetic storage only; no LUKS, SELinux or installed-guest proof. |
| Source browser workflow | **23 cases passed**, with zero browser errors or unexpected network requests and unchanged source hashes. The actual `Admin` and `HostStoragePlan` components used synthetic API/session fixtures; eight desktop/mobile light/dark screenshots were retained in `.local/qa-host-plans/`, alongside `results.json`. Cases cover role/session loss, expiry, manual revalidation, stale responses and unavailable/error states. This proves neither real identity/host storage nor deployment. |

An earlier full Python run attempted 533 tests and passed 530, with capacity failures in `test_image_bundle.BundleTests.test_builder_hardlink_reuses_verified_archives` (insufficient scratch space), `test_ova.OVATest.test_real_conversion_manifest_and_atomic_transport` (conversion/archive working-reserve guard), and `test_ova.OVATest.test_initialized_data_is_refused_without_output` (reserve guard before the expected “entirely blank” validation). All three passed on a separate retest after capacity recovery and again in the final full run. An initial post-admission invocation also omitted the lifecycle-adapter import path, causing 25 setup/import errors; the corrected full invocation above passed. Neither source tests nor space guards were weakened.

Private receipts are retained at `.local/host-plan-python-admission-source-tests-v2-20260908.json`, `.local/host-plan-linux-runtime-admission-tests-20260908.json` and `.local/host-plan-go-live-integration-tests-20260908.json`. The earlier Go run remains in `host-plan-go-source-tests-20260908.json`; failed/retest Python receipts remain alongside it: `host-plan-python-source-tests-20260908.json`, `host-plan-python-capacity-retest-20260908.json` and `host-plan-python-admission-source-tests-20260908.json`. The initial Linux attempt was blocked before container creation at 3,662,987,264 then 3,464,798,208 bytes free; capacity later fell to 2,083,352,576 bytes and heavy work paused. After recovery, the final full Python run measured **15,433,572,352 bytes free before and 15,420,760,064 after**. These are dated observations, not current capacity guarantees. HTTP 200 from the older `44e2eb1` development application is separate evidence and does not establish deployment of these sources.

The [Python fixture](../appliance/tests/host_plan_linux_fixture.py) requires `NEBULALOG_HOST_PLAN_FIXTURE=1` and Linux root. It creates a new private temporary journal and the protected fixed socket, emits `READY`, and cleans up on SIGTERM. Its storage identity and geometry are explicitly synthetic; it performs no disk inspection or mutation. The [Go Linux tests](../internal/hostcontrol/peer_linux_test.go), gated by `NEBULALOG_HOST_PEER_TEST=1`, ran in a disposable no-network container with read-only root/source, `/run` and `/tmp` tmpfs, one CPU, 256 MiB memory and a 64-process limit. They exercised real UID/GID transitions, supplementary control-group access, Python/Go round trips and unauthorized peer refusal. The final receipt records source hashes, binary SHA256 `8e63ebea59fd8232ebebdc14da1223fb570a884847ce69956e22c524aeca8314` and image digest `sha256:c31315ac2d5a3e36c7d40958a01f303a4dadd423710bb2cd62d1bab5220fac75`.

An initial Linux test expected a typed denial after an unauthorized caller had queued a request; Linux connection reset instead produced the Go client's generic unavailability. The corrected test separately verifies an explicit peer-denial frame without sending a request, and retains the production client's fail-closed assertion. The server's authentication/framing behavior was not weakened to make the test pass.

Future acceptance requires protected installation and SELinux integration, real encrypted-guest inspection/enrollment/restart tests and retained browser/API evidence. Any mutation additionally requires qualified fresh step-up, independent host authorization, one-use action-bound grants, fixed executors, global coordination, durable recovery and failure testing. This slice closes none of the [storage-growth or privileged-management release gates](RELEASE_ACCEPTANCE.md).
