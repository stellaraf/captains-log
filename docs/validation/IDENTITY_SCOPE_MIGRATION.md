# Existing-realm scope migration

`appliance/nebulalog_manager/browser_scopes.py` is a maintenance helper with
isolated configuration qualification. It and the session-invalidation helper
are included in the host source catalog. Neither is invoked automatically by
bootstrap or the updater; catalog inclusion is not installation or activation.

The caller must supply authenticated administration, the trusted realm template
and the expected installation ID. The helper checks the realm's installation
attribute before changing clients. It refuses unexpected authentication grants,
missing PKCE, custom direct protocol mappers, custom client scopes, role-bearing
identity scopes, changed role definitions and conflicting projection clients.

The helper disables the application client, reconciles its supported scopes and
role mappers, checks REST readback and then re-enables it. An interrupted
configuration must remain in maintenance until a retry completes. It does not
write user accounts, passwords, OTP credentials, realm signing keys, external
providers, redirect addresses or authentication-flow bindings.

Keycloak 26.8.1 import materializes the legacy audience mapper's introspection
and user-info settings. The comparison recognizes exactly `true` and `false`,
respectively, when those fields are omitted; explicit conflicting values and
unknown settings remain differences. The reviewed legacy scope links are:

| Link | Accepted legacy names |
| --- | --- |
| Default | `basic`, `profile`, `email`, `acr`, `roles`, `web-origins` |
| Optional | `address`, `phone`, `offline_access`, `organization`, `microprofile-jwt` |

After reconciliation, only `basic`, `profile`, `email` and `acr` remain linked,
all as defaults. Global scope definitions are unchanged. Missing required
identity scopes, unknown links and links in an unexpected category are refused.

## Executed configuration qualification — 2026-10-20

Seven boundary tests passed under actual public Rocky Python 3.14.8 on
Linux/amd64. A disposable PostgreSQL 17.11 / Keycloak 26.8.1 realm imported
the previous application's configuration and exercised nine checks:
foreign/missing ownership, a custom mapper, a custom scope, a lost mapper-write
acknowledgement, recovery, repeat reconciliation, a lost final-enable
acknowledgement and another reconciliation under Rocky Python 3.14.8.

Database hashes were unchanged for users, user attributes, credentials,
required actions, role definitions/grants, provider definitions/configuration/
mappers and key components/configuration. The public signing-key set and the
browser client's redirects, origins, PKCE attributes and flow bindings also
matched. The fixture included a disabled synthetic external provider; it did
not perform external authentication.

A lost mapper-write acknowledgement left the application client disabled and
retry completed. A lost final-enable acknowledgement left the client enabled
with the verified configuration, while the helper reported an error. The next
call reconciled successfully. Therefore the caller must keep its independent
maintenance hold until uncertain outcomes are resolved.

The initial attempts exposed two legacy representation differences before any
migration write: the audience defaults and optional `organization` scope.
Read-only probes captured the vendor configuration before the comparison and
legacy-link policy were corrected. Custom mapper and scope rejection remained
in the subsequent execution.

Six real browser regressions passed before migration and all six passed again
afterward, with no failures, skips or flaky retries. Four fresh password/TOTP
role cases then verified exact token roles and read/write/administrator API
permissions. Fresh authenticator enrollment, invalid-code rejection and a
fresh-context login in a new TOTP interval also passed. The real collector
persisted a synthetic PAN-OS event.

These checks used the same Keycloak version on both sides of the configuration
migration, development-mode identity and loopback HTTP. They do not establish
an identity-server version upgrade, production TLS/FIPS, token revocation,
automatic migration authority or native appliance acceptance. The isolated
fixture and its temporary credentials were removed; shared development and
native appliances were unchanged.

## Authority and transaction requirements

An initialized appliance has disabled its temporary bootstrap administrator.
The normal inspector and identity-provider manager deliberately lack the
permissions needed to migrate browser clients. Do not re-enable the old
bootstrap user or expand the application's permanent service-account grants.

Keycloak documents a
[temporary administrator service account](https://www.keycloak.org/server/bootstrap-admin-recovery)
created by `bootstrap-admin service`. All Keycloak nodes must be stopped before
that command runs. The command must use the server's database/runtime settings,
and optimized distributions should use `--optimized`. The temporary account
must subsequently be removed. This mechanism still requires appliance-specific
qualification; the helper does not create it.

Automatic activation requires all of the following:

- Bind the exact migration and installed realm to the authorized release and
  persistent maintenance transaction.
- Back up identity/configuration state and verify a usable rollback.
- Stop the API and identity writers, establish temporary administration through
  the qualified vendor mechanism, and retain recovery state on encrypted storage.
- Apply browser and service-scope changes without replacing the realm.
- Set and verify the API's token cutoff and identity-session policy. Disabling
  a client or changing its scopes does not prove old access tokens are rejected.
- Verify fresh local password/MFA login, intended role access, health identity,
  provider mappings and cleanup of temporary administration before releasing
  maintenance.
- Exercise interruption and rollback at each durable boundary, including
  uncertain REST writes and interrupted temporary-account removal.

The [session cutoff and temporary-authority validation](IDENTITY_SESSION_CUTOFF.md)
tracks the additional token and administration boundaries.

Existing-realm configuration reconciliation, automatic updater integration,
native TLS/FIPS operation and release acceptance are separate evidence scopes.
