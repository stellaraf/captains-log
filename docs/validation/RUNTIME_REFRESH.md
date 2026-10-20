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

## Remaining acceptance

Existing-appliance interpreter installation and fixed-host migration,
native PostgreSQL initialization, complete dependency review, real host-authority and
browser recovery, final factory packaging, VMware/Nutanix boot, OS/application/
log-system automatic updates and rollback, and the complete release acceptance
inventory remain separate gates. The last native public Rocky kernel check
failed its crypto self-test. This checkpoint does not establish an accepted
OVA, a deployed runtime upgrade, or whole-product FIPS certification.
