# Explicit service-account scopes — 2026-10-20

Appliance enrollment and local development provisioning now disable each owned
service client while configuring it, turn off full role scope, and configure
explicit role-scope mappings before enabling it. The shared implementation is
included in the host payload catalog.

| Identity | Assigned roles in `realm-management` | Effective token roles |
| --- | --- | --- |
| `nebulalog-identity-manager` | `manage-identity-providers`, `view-identity-providers`, `view-realm` | Those three roles |
| `nebulalog-appliance-inspector` | `view-users`, `view-clients`, `view-realm` | Those three roles plus `query-users`, `query-groups`, `query-clients` |

The inspector's query permissions are children of Keycloak's vendor-defined
read roles. The implementation checks their exact names and ownership, and
refuses new children or further composites. It does not automatically accept
expanded permissions after an identity-server upgrade.

Only the `roles` default client scope is linked to these clients. Optional
client scopes are removed from these clients, and the shared `roles` scope
must not contain additional role-scope mappings. Realm-wide scopes and browser
clients are not modified. Keycloak 26.8.1 automatically attaches a
`service_account` scope when creating service accounts; the provisioner
reconciles client-scope links through their dedicated REST endpoints rather
than relying on `ClientRepresentation` updates.

Effective administration grants, interactive application roles, explicit role
scopes and inherited scope mappings are checked. Unexpected privileges cause
refusal; they are not silently removed. An interruption during scope assignment
leaves the owned client disabled. A retry can complete provisioning after the underlying problem is
resolved. Foreign clients are refused before mutation.

This follows Keycloak's separation between assigned service-account roles and
the roles a client may include in tokens. See the
[vendor administration guide](https://www.keycloak.org/docs/26.8.1/server_admin/).

## Validation scope

The focused Python, bootstrap, host-payload, bundle and update-enrollment suites
passed **111 tests** on Linux/amd64 using public Rocky Python **3.14.8**. This
includes actual deterministic host archive creation, isolated staging and
importing the packaged modules, plus refusal of unexpected composite-role
expansion and incomplete scope-write readback.

An isolated official Keycloak **26.8.1** Linux/amd64 server exercised the actual
appliance service provisioner. Twenty-two checks covered exact token role
sets, required inspection reads, forbidden user/provider writes, exclusion of
extra assigned application/realm-admin privileges from new tokens, refusal of
polluted grants and scopes, interrupted provisioning, retry, narrowing an
owned broad client, and refusing a foreign client without modifying it.

The initial live attempt exposed Keycloak's automatic `service_account` link.
Subsequent readback identified the vendor inspector-role composites. Both
behaviors were incorporated explicitly before repeating the checks.

The complete Go identity package then passed **54 tests/subtests**, with no
failures or skips, against these scoped credentials and the same Keycloak
server. Actual disabled Okta and Entra providers were created, read, updated,
checked and deleted. This verifies provider configuration operations, not
upstream tenant authentication. The Go client ran on macOS/arm64; the identity
server ran on Linux/amd64.

A fresh server repeated the 22 appliance checks and ran the unchanged
`scripts/dev-auth.py` twice, for creation and retry. Only its fixed loopback
destination was routed to the isolated server; REST responses were real.
Both runs verified exact token roles, only the `roles` default scope, no optional
scopes, required broker OTP, and the human administrator's pending OTP
enrollment. Retry preserved the administrator ID and password credential ID.
This did not exercise an already-enrolled human's browser login.

All three identity fixtures and the Python test containers were removed.
Private credentials, source copies and compile caches were removed after
their processes completed; current appliance artifacts and native VM disks
were retained.

## Deployment and migration limits

This changes new enrollment and explicit development reprovisioning. The
already-initialized appliance path does not rerun service provisioning, so this
is **not an automatic migration of existing appliance realms**.

Disabling a client prevents new token issuance; it does not establish revocation
of already-issued access tokens. Existing-appliance migration must account for
their validity period and verify revocation/expiry behavior before acceptance.
The browser client's role scopes remain a separate review item.

These tests use disposable development-mode storage and loopback HTTP. They do
not qualify native FIPS/TLS operation, real Okta/Entra/AD sign-in, existing
appliance migration, complete browser recovery, automatic updates or the OVA.
The shared development deployment and existing native guests were not changed.
