# Development

Read SPECIFICATION.md, ARCHITECTURE.md, API.md and the relevant ADR before making
architecture changes. Go owns ingestion/query/API; `web/` owns React/TypeScript;
`appliance/` owns privileged host operations. Keep secrets and raw captures under
permission-restricted `.local/`, never source control.

Before local builds or tests, confirm the dedicated development volume is
mounted. Keep the checkout, output, temporary files and developer caches on
that volume. For Wayne's workstation this is T9, including the mounted
`/Volumes/OrionOSWork` workspace; do not create a replacement workspace on the
internal disk when the volume is absent.

Use an exclusively created directory per run for `TMPDIR`, `GOCACHE`,
`GOMODCACHE`, npm's cache and `PACKER_CACHE_DIR`, as applicable. Check available
space before dispatch; local image, container and native appliance runs require
at least 150 GiB free on the actual backing storage. Keep logs, receipts and
deliverables outside temporary directories. Once the exact child processes and
containers have exited, remove that run's scratch and caches on both success and
failure and record the cleanup result. Interrupted or uncertain ownership must
be inspected before removal. Preserve source, credentials, VM disks, current
releases, rollback copies and recovery evidence. Age alone does not authorize
deletion. Never use a blanket Docker image, volume or system prune.

The commands below are validation steps inside that managed run. They do not
provide storage admission or post-run cleanup by themselves. Container builds
also require a verified builder with its backing storage on the development
volume and an owned cache lifecycle; setting host `TMPDIR` does not relocate
Docker's cache. `build_application.py` uses a unique buildx builder and labelled
cache volume with private configuration/scratch under the receipt directory.
Pass an explicit `--storage-root` (on this workstation `/Volumes/T9`),
`--docker-context`, and cached immutable `--buildkit-image`; independently verify
the daemon's backing storage. It settles its exact owned container and removes
its cache after success, failure, timeout or CLI interruption, while preserving
loaded images and private outcome evidence. It never prunes shared caches.
Incomplete cleanup fails the invocation and must be reconciled before another
image build; SIGKILL and power loss cannot guarantee immediate cleanup. See
[the release instructions](../appliance/packer/RELEASING.md) for the command and
ownership/cleanup contract. These guarantees apply to this helper; other build
entrypoints still require their own equivalent bounded cleanup.

```sh
go test -race ./...
go vet ./...
go build -o bin/nebulalog ./cmd/nebulalog
cd web
npm ci
npm test
npm run build
```

Go1.25+ and Node24+ are the baseline toolchains. The runtime dependencies are
locked by go.sum and package-lock.json. See INSTALL_DOCKER.md for a real local
stack. Schema initialization uses `nebulalog migrate`; no SQLite/memory metadata
fallback exists.

The parser fixture directory uses reserved documentation address ranges and
synthetic identities. New fixtures must retain CSV field count, quoting, framing,
and subtype semantics while removing organization-specific values. Native
capture validation and generated fixture tests are distinct evidence.

Useful validation layers: pure compiler/parser tests, TCP/TLS socket tests,
spool restart/outage tests, real-database integration, authenticated browser
tests, reference workload generation, then appliance VM boot and lifecycle tests.

If automated browser tests have enrolled the development `administrator`
account, create a separate human operator rather than sharing its OTP seed:

```sh
python3 scripts/dev-auth.py --create-operator stellar-admin
```

This creates a unique administrator credential, requires the person's own first
login OTP enrollment, and writes the operator's login to private `.local/login.txt`.
It leaves the test identity's enrolled MFA unchanged. Rerunning bootstrap does
not reset an existing operator password or enrollment.

The local Keycloak theme inherits the installed26.3.3 templates and bundles
Stellar assets/fonts without remote requests. The single OTP template override
corrects two label/input associations; compare it against the exact parent
when upgrading. See `deploy/keycloak/themes/nebulalog/README.md`.
Do not run destructive host manager operations on a workstation. Use disposable
VMs and explicit device identities for storage acceptance.

The browser test harness keeps TOTP and session artifacts in `.local/`. Those
credentials are test evidence, not a second universal password. Do not include
browser traces with secrets or real log payloads in public CI artifacts.
