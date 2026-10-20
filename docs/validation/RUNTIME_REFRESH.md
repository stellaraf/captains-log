# Appliance runtime refresh — 2026-10-20 UTC

New x86-64 appliance builds install Rocky's public `python3.14` package alongside
the system interpreter. Captain's Log host launchers, fixed dispatch, console,
provisioning, sealing and lifecycle hooks explicitly invoke Python 3.14. The
qualification fixture used Rocky `python3.14-3.14.8-1.el9_8.x86_64`.

The operating system's Python remains unchanged. The kernel dependency solver
continues to invoke `/usr/bin/python3` because Rocky's DNF bindings belong to that
interpreter. Versioned Python packages are classified as migration-required OS
payloads, just like the original system Python package. This change does not
authorize an automatic runtime replacement on an existing appliance.

The application compiler is Go 1.27.2, pinned to official Linux/amd64 manifest
`sha256:55395706e9703db746cc507abfc4eb2aea75918f8a8024e4848e2cb81004f5ad`.
The frozen Go cryptographic module remains `GOFIPS140=v1.0.0`. Node 24 remains
the LTS web-build input. The PostgreSQL image's Python wrapper has subsequently been rebuilt with the
same public Python 3.14.8 runtime; see [its image validation](../../appliance/images/postgresql-fips/VALIDATION.md). Positive native database qualification remains open.

## Executed validation

- **693 Python tests passed** under the actual public Rocky Python 3.14.8
  x86-64 runtime, with no skips. The selected suites cover restore,
  configuration recovery, host dispatch/update orchestration, AIDE, kernel
  updates, OS payload policy, factory inputs, console, GitHub polling,
  Kickstart key validation, sealing and the host-runtime adapter.
- Actual `FreshRestoreRuntime` review/preparation passed for schemas 3 and 4
  on Python 3.14.8. Both cases used the complete nine-file configuration
  inventory, real Linux ownership checks, OpenSSL certificate/key/SAN
  verification, persistent listener fences and idempotent preparation.
  All 16 negative cases passed, including foreign CA, mismatched key, missing
  target SAN, changed configuration, premature activation and uncertain
  action replay.
- `go test -count=1 -json ./...` passed in an isolated Linux/amd64 Go 1.27.2
  container: **225 passing top-level tests, 1,147 passes including subtests,
  zero failures** across all 11 packages. **37 test/subtest skips** remain,
  including 16 top-level tests requiring external services or explicit
  fixture conditions. `go vet ./...` also passed.
- The Linux gate-permission test now places its child executable in its
  owned fixture. This lets the unprivileged child run when Go's compiler
  scratch directory is private to root; product ownership checks are
  unchanged. All 11 permission scenarios ran successfully.
- Factory publisher fixtures now declare the schema actually represented
  by their migration inputs. Production schema-mismatch rejection remains
  intact.

The preparation fixture substitutes host-ready/encrypted-staging admission,
factory binding and service/image/database startup boundaries. It does not
perform database restore, final enrollment, full activation, or native FIPS
qualification. Go integration skips are not passing integration evidence.

## Subsequent database authentication qualification

The complete `internal/auth` package subsequently passed with the PostgreSQL
integration opt-in enabled: **55 top-level tests, 491 passes including subtests,
zero failures and zero skips**. The client used Go 1.27.2 on macOS/arm64; the
isolated server used the pinned official PostgreSQL 17.11 Linux/amd64 image.
This is application/database integration evidence, not an ARM appliance build
or native Rocky/FIPS qualification.

The previously skipped `TestPostgresStepUpAtomicIntegration` and
`TestStepUpTLSPostgresIntegration` both executed. Coverage includes exact
transaction binding, replay refusal, 24 concurrent consumers with one success,
database constraints, bounded retention, and the actual TLS/PAR/token/JWKS
client flow against a synthetic HTTPS issuer. It does not prove a real
Keycloak, Okta, or Entra login.

The fixture now pins PostgreSQL 17.11 instead of the stale 17.6 guard. In
addition to the existing bind-mount fixture, it accepts an explicitly selected,
uniquely named and labelled local Docker volume. Container/image identity,
loopback port, resource limits, mount identity, volume ownership labels and
database system identity remain mandatory. This accommodates Docker Desktop
bind-mount ownership behavior without relaxing production database checks.
Both temporary schemas were removed; the container, volume, private fixture
credentials and build caches were independently confirmed absent afterward.

## Subsequent Linux peer qualification

Both opt-in Linux host-planning socket tests passed using the Go 1.27.2
Linux/amd64 test executable and public Rocky Python 3.14.8, with networking
disconnected. The dedicated API UID could create and retrieve a plan. Root
was rejected as an API caller, a different session could not retrieve the plan,
and an untrusted server received no request bytes even after its socket's
filesystem ownership was made to look trusted. The kernel `SO_PEERCRED`
checks, framing and private journals were real; disk geometry was synthetic
and no storage operation was executed.

The first run exposed a fixture teardown defect: Go context cancellation
killed Python before its journal cleanup ran. The test now requests and checks
graceful shutdown before canceling the context, and explicitly runs Python
3.14. Both integration cases and all three Python fixture-safety tests then
passed. An independent in-container check confirmed that the socket, control
directory and temporary journals were absent. The container and host compile
caches were subsequently removed and their absence verified. This does not
qualify native host-authority enrollment, privileged execution or recovery.

## Subsequent constrained-filesystem qualification

`TestSpoolHeadroomConstrainedFilesystem` passed on a real, initially empty
320 MiB Linux tmpfs using the Go 1.27.2 Linux/amd64 test executable. Actual
filesystem pressure refused admission at 268,496,896 available bytes while
preserving the 268,435,456-byte reserve. The test verified the exact retained
WAL record across restart, continued refusal after restart, acknowledgement
and draining under pressure, and resumed admission after space was recovered.
It ran without network access and with all container capabilities dropped.
The tmpfs was empty afterward; the container and host compile caches were
independently confirmed absent. Physical disk failures, native encrypted
storage and full appliance recovery remain separate acceptance gates.

## Subsequent retention and ClickHouse qualification

Twelve selected integration tests passed with **41 passes including subtests,
zero failures and zero skips** against disposable PostgreSQL 17.11 and the
pinned Altinity `25.3.8.30001.altinityfips` Linux/amd64 server. The client was
Go 1.27.2 on macOS/arm64. Tests covered:

- Emergency-policy HTTP revision conflicts and signed-actor audit records.
- Emergency intent, admission, maintenance holds and recovery behavior.
- Actual partition removal and physical cleanup, protection of diagnostic
  records, a delayed INSERT during PostgreSQL lock loss, and uncertainty after
  a successful DROP whose response was lost.
- Normal retention policy changes over existing rows, late-delivery fencing,
  legacy TTL removal only under an owned migration hold, and uncertain dispatch.
- Complete wide-row reads at 1, 200 and 1,000 rows; ascending/descending cursor
  sorting over one million inline records; threat/DNS category membership;
  inventory time-window and storage write-demand calculations.

Pressure observations and selected transport failures were injected; the
PostgreSQL transactions and ClickHouse INSERT, ALTER and DROP effects were real.
The SQL fixtures used temporary credentials, loopback-only published ports,
a private PostgreSQL volume and a bounded 1 GiB ClickHouse tmpfs. They do not
qualify production TLS, native FIPS operation or large-estate performance.
No temporary PostgreSQL schemas remained afterward. Both containers, the
volume, credentials and host compile caches were independently confirmed absent.

## Subsequent identity-provider qualification

The full `internal/identity` package passed with its live fixture enabled:
**16 top-level tests, 54 passes including subtests, zero failures and zero
skips**. Go 1.27.2 on macOS/arm64 exercised pinned Keycloak 26.7.3 on Linux/amd64.
Both Okta and Entra defaults completed disabled-provider creation, configuration
and mapper readback, validation, group-mapping update and independent removal.
The service account had exactly `manage-identity-providers`,
`view-identity-providers` and `view-realm`; the broker flow had one required OTP
execution. Both aliases were absent after testing.

An explicit private fixture descriptor now binds the test to a running,
labelled container, immutable image ID and loopback port. An invalid selected
fixture cannot fall back to the development login service. Descriptor admission
rejects the development port, mutable image/name references, missing ownership,
short/missing secrets, readable credential files, symlinks and oversized input.
The test-only Docker inspection deadline is bounded at 30 seconds to accommodate
host load; identity checks remain mandatory.

This used disposable Keycloak development-mode storage and HTTP on loopback.
Neither provider was enabled, and no upstream authentication was attempted.
Actual tenant sign-in, production PostgreSQL-backed Keycloak, TLS and strict
FIPS operation remain separate acceptance gates. Both fixture attempts,
temporary credentials, downloaded fixture image and compile caches were removed.

## Integration skip reconciliation

Of the 37 skipped test/subtest entries in the earlier Linux Go run, **36 now
have passing execution evidence** in the separate fixtures above. One entry is
the Linux child helper exercised by its two parent tests. The final two
`TestEmergencyObservationControllerIsolated` cases passed against PostgreSQL
17.11 with injected ClickHouse observations. Inconsistent capacity data was
resampled and refused, including immediately before dispatch, without creating
deletion actions or prepared/executing audit authority. Later coherent readings
restored normal status without deleting anything. Temporary schemas and the
database fixture were removed. All 59 Go
production-source/module files in the earlier source manifest still match.
This reconciliation does not claim one combined full-environment run or native
appliance acceptance.

## Development build alignment

The development Dockerfile now uses the same pinned Go 1.27.2 and Node 24
manifests as the appliance build. Compose explicitly selects `linux/amd64` for
the application, preventing a host-default architecture from selecting a
different final runtime on Apple Silicon.

A complete development image build passed, including the TypeScript/Vite
frontend. The resulting binary's build information confirmed Go 1.27.2,
`GOARCH=amd64` and `GOFIPS140=v1.0.0`. Its normal entrypoint successfully ran
`version` with `REQUIRE_FIPS=true`, UID 10001, networking disabled, a read-only
root and all capabilities dropped. The frontend index and exact project
license were present. Compose configuration parsed with synthetic credentials.
This is a development-image build/startup check, not a live database,
browser-login or native appliance FIPS qualification.

The owned BuildKit container/cache volume, temporary image, probe container,
private Buildx configuration, source copy and extracted binary were removed.
Independent readback confirmed absence and preserved all four current release
archives.

A read-only check of the official npm registry's stable dist-tags also found
pending upgrades: React/React DOM 19.3.1, Playwright 1.64.1, Lucide 1.60.0,
TypeScript 7.0.2, Vite 8.3.4, its React plugin 6.1.2 and Vitest 5.0.5.
The corresponding React type packages also have newer versions. This
observation is dated 2026-10-20 UTC; availability does not establish migration
compatibility. These updates, the older development database/identity images,
and transitive/OS dependency review remain open. The development build's
`npm ci` reported zero known vulnerabilities at execution time.

## Remaining acceptance

Existing-appliance interpreter installation and fixed-host migration,
native PostgreSQL initialization, complete dependency review, real host-authority and
browser recovery, final factory packaging, VMware/Nutanix boot, OS/application/
log-system automatic updates and rollback, and the complete release acceptance
inventory remain separate gates. The last native public Rocky kernel check
failed its crypto self-test. This checkpoint does not establish an accepted
OVA, a deployed runtime upgrade, or whole-product FIPS certification.
