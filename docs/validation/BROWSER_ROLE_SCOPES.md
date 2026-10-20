# Browser token roles

New realms disable full scope on the `nebulalog` browser client. Its explicit
role-scope mappings name `ADMINISTRATOR`, `ANALYST` and `VIEWER`. Its default
identity scopes are `basic`, `profile`, `email` and `acr`; it has no optional
client scopes.

Keycloak 26.8.1 also includes the requesting client's own assigned roles when
resolving roles with full scope disabled. Therefore scope mappings alone do not
exclude additional roles in the `nebulalog` namespace. A real browser negative
test detected this behavior: an assigned `UNRELATED` role appeared in the first
candidate's token. The vendor's
[role-resolution implementation](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/TokenManager.java)
also documents that behavior.

The browser client now uses three built-in role-name mappers to project only
its supported roles into the `captains-log-token-roles` projection namespace.
A client-role mapper emits that selected set at
`resource_access.nebulalog.roles`. The general `roles` client scope is not
attached to this browser client. Audience, subject, username, profile and
authentication-context claims remain available.

An enabled, bearer-only `captains-log-token-roles` client supplies that namespace.
Its interactive, password and service-account grants are disabled. Keycloak
requires an enabled client for projected roles to participate in token
construction. Role assignments remain on the real `nebulalog` client. SAML/AD
role mappings continue to target its existing roles. The projection client is
not an identity-provider role-assignment target. Role projection does not
change stored user grants.

## Repeatable browser permission check

Install the locked web dependencies, then run:

```sh
ROLE_FIXTURE=/path/to/private-fixture.json node scripts/qualify-browser-roles.mjs
```

The opt-in script requires a disposable application and identity realm on an
ephemeral `http://127.0.0.1` port. It rejects the standard shared development
ports. It performs real password/TOTP logins, creates and removes temporary
saved filters, and tests the administrator-only DNS-cache action.

The configuration must be an owner-only regular file (mode `0600`) containing
`origin`, an existing private `evidence` directory (mode `0700`), and a `users`
array. Each entry supplies `username`, `password`, a 32-byte SHA-256 TOTP secret
encoded as 64 lowercase hexadecimal characters in `otpHex`, and `role`.
Use distinct usernames beginning with `scope-` for these four cases:

| Case | Stored Captain's Log roles | Expected application access |
| --- | --- | --- |
| `ADMINISTRATOR` | `ADMINISTRATOR`, `VIEWER` | Read, analyst writes, administrator action |
| `ANALYST` | `ANALYST` | Read and analyst writes; administrator action denied |
| `VIEWER` | `VIEWER` | Read; both write classes denied |
| `UNASSIGNED` | None of the three supported roles | Application requests denied |

In the disposable realm, also assign every test user an `UNRELATED` role on
`nebulalog`, `ADMINISTRATOR` on a separate `scope-decoy` client, and
`realm-admin` on `realm-management`. These deliberately excessive fixture
grants test exclusion from application tokens; provision them only in the
disposable realm. All four users must already have their supplied authenticator
enrolled.

The script checks the exact emitted role set, audience, subject, username and
real API results. Mixed administrator/viewer grants must retain administrator
precedence. It writes a result file and screenshots without persisting access
tokens. The fixture owner must remove its users, containers, credentials and
temporary data afterward.

## Executed qualification — 2026-10-20

The current application image was exercised against actual PostgreSQL 17.11,
Keycloak 26.8.1 and ClickHouse 25.3.8.30001 services on Linux/amd64. Chromium
performed real password/TOTP authentication.

- All four role cases in the table passed. Unrelated application, foreign-client
  and realm-administration grants were absent from application tokens. The
  administrator/viewer combination retained administrator access.
- All six existing browser regressions passed with no skips, failures or flaky
  retries. A synthetic PAN-OS event reached the real TCP collector and database.
- Fresh authenticator enrollment, invalid-code rejection, a fresh-context login
  in the next TOTP interval, label/focus checks and the 390px enrollment layout
  passed.
- The projection client refused browser authorization with HTTP 403 and
  Keycloak recorded `not_allowed`.
- The affected appliance bootstrap, host-identity and schema4-bootstrap suites
  passed 67 tests under actual public Rocky Python 3.14.8 on Linux/amd64.

The qualification uncovered two configuration issues before the passing
browser run: scope mappings alone retained additional same-client roles, and
the first projection lacked the enabled bearer-only client required by
Keycloak's role resolver. A test expectation was then corrected from HTTP 400
to the observed HTTP 403 refusal. Authentication and role checks were not
weakened to accommodate these findings.

The fixture uses development-mode Keycloak and loopback HTTP. It does not prove
native FIPS/TLS operation or external tenant authentication. The shared local
deployment was not changed.

## Migration limits

This realm template applies to new realm creation. Keycloak does not overwrite
an existing realm when importing this template again. Existing-appliance and
existing-development-realm migration must separately preserve users, MFA,
signing keys, provider mappings and active-session policy, and account for
previously issued tokens. Do not delete or re-import a live realm as a shortcut.

Native TLS/FIPS operation, external Okta/Entra/AD authentication and the complete
appliance update/rollback and recovery matrix remain separate acceptance gates.
