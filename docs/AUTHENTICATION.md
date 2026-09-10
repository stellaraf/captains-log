# Authentication and roles

Keycloak is the sole interactive identity provider. Captain’s Log uses authorization
code with S256 PKCE, exact redirect origins, and memory-only browser tokens.
The Go API verifies issuer, signature, expiry and the `nebulalog` audience with
go-oidc; it reads client-scoped roles, not arbitrary realm-role names.

| Role | Permissions |
|---|---|
| ADMINISTRATOR | Search, export, saved filters, inventory/retention/DNS administration |
| ANALYST | Search, export, own saved filters and preferences |
| VIEWER | Read/search and own display preferences |

All API routes require authentication except bootstrap public config, minimal
health and single-use expiring download capabilities. Export jobs and saved
filters are scoped to the authenticated subject. A job ID is not authorization.

`deploy/keycloak/realm.json` supplies a local browser flow with required password
and OTP executions, PKCE client and roles. `scripts/dev-auth.py` creates a unique
development administrator requiring CONFIGURE_TOTP. The realm uses SHA256 TOTP,
six digits and a30-second period. Password policy requires at least14 characters
and mixed character classes. No direct password grant is enabled on the app.

Local TOTP enrollment and a subsequent fresh password+TOTP login have separate
browser acceptance checks. WebAuthn/passkeys and recovery-code enrollment are
required release work; they are not claimed merely because Keycloak supports
them. Preserve a local break-glass administrator before configuring federation.

Production strict FIPS requires the qualified JVM/provider bundle and measured
startup evidence in FIPS.md. The development Keycloak container does not make
that claim. External provider setup currently uses Keycloak administration;
the appliance's simplified provider wizard remains a release gate.

Source: [Keycloak administration](https://www.keycloak.org/docs/latest/server_admin/)
and [JavaScript adapter](https://www.keycloak.org/securing-apps/javascript-adapter).
