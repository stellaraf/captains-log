# Development

Read SPECIFICATION.md, ARCHITECTURE.md, API.md and the relevant ADR before making
architecture changes. Go owns ingestion/query/API; `web/` owns React/TypeScript;
`appliance/` owns privileged host operations. Keep secrets and raw captures under
permission-restricted `.local/`, never source control.

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
