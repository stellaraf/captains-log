# Authentication and database research

Reviewed 2026-09-07 against current official documentation. These findings define implementation requirements; they do not certify a built appliance.

## Keycloak FIPS

Keycloak's default distribution includes ordinary Bouncy Castle; enabling the feature alone is insufficient. The current guide requires compatible BCFIPS provider jars and a FIPS-enabled OS/JVM. It recommends OpenJDK 21 for compliance even though integration is tested on 25. Current listed provider versions are bc-fips 2.1.2, bctls-fips 2.1.22, bcpkix-fips 2.1.10, and bcutil-fips 2.1.5. Pin the whole tested bundle, obtain artifacts with provenance, and recheck compatibility before an upgrade. Run `--features=fips --fips-mode=strict`; verify startup reports Approved Mode and FIPS JVM enabled. Strict mode uses BCFKS keystores, requires RSA keys at least 2048 bits, and constrains password/key lengths. Choose a minimum 14-character password policy. Do not turn on non-approved compatibility algorithms to make federation pass. [Official FIPS guide](https://www.keycloak.org/server/fips), [configuration reference](https://www.keycloak.org/server/all-config).

An appliance's FIPS-enabled status is separate from a CMVP validation claim. Maintain module/version/operating-environment evidence for the actual packaged build; an untested container is not an approved appliance.

## Identity and MFA design

Use Keycloak's local user store, LDAP/AD federation, and OIDC/SAML identity brokers. LDAPS requires a trusted directory certificate chain. Configure LDAP as read-only initially and map directory groups into explicit appliance roles. Keycloak provides OTP, WebAuthn, and recovery-code authenticators; recovery codes are single-use backup factors. Required actions enroll credentials, while authentication-flow requirements enforce their use. Configure a required second-factor subflow, including federated directory users, and test that users without enrolled factors cannot bypass it. [Server administration guide](https://www.keycloak.org/docs/latest/server_admin/).

NebulaLog design decisions: authorization code flow with PKCE; no passwords handled by the application; exact redirect URIs; token issuer, audience, signature and expiry validation at the API; least-privilege role checks on every route. Preserve a local break-glass administrator. External IdP configuration changes must prove a new login and retain local access. Document strict-FIPS passkey, SAML signature, and AD certificate compatibility as acceptance tests, not assumptions.

## Ingestion and storage

ClickHouse recommends batching at least 1,000 rows, ideally 10,000–100,000, to reduce part creation and merge overhead. Use bounded client batches with a latency-triggered flush at lower rates. If server asynchronous inserts are used, require `async_insert=1, wait_for_async_insert=1`; fire-and-forget acknowledges memory buffering and can hide failed persistence. The release's deduplication behavior must be verified with ambiguous retry tests, including the configured non-replicated deduplication window. [Insert strategy](https://clickhouse.com/docs/concepts/best-practices/selecting-an-insert-strategy).

NebulaLog design decisions: retain durable spool batches until confirmed insert, use stable event and batch identities, expose failed insert retries, and document at-least-once semantics where bounded deduplication cannot eliminate all retry duplicates. Keep raw messages in ClickHouse and all configuration in PostgreSQL. Separate keycloak/nebulalog PostgreSQL databases and credentials; no public database listener.

## Retention and queries

ClickHouse TTL deletion happens during background merges, not exactly at the expiration timestamp. Default delete-TTL merge delay is four hours. Conditional TTL supports different event retention. Align partitions with retention periods so complete expired parts can be removed cheaply, and avoid routine `OPTIMIZE FINAL`. [TTL guide](https://clickhouse.com/docs/concepts/features/operations/delete/ttl).

NebulaLog design decisions: use low-cardinality log family and daily/monthly time partitioning selected by measured merge load; never partition by IP/device. Use a measured sort-key and index plan before claiming billion-row performance. Enforce read timeouts, memory limits, page limits and selected-column allowlists; stream exports through bounded disk jobs.

ClickHouse supports typed `{name:Type}` query parameters with values passed separately, including `param_name` for HTTP. Parameters are not arbitrary SQL substitutions. [SQL syntax reference](https://clickhouse.com/docs/reference/syntax).

NebulaLog's filter compiler must therefore emit SQL solely from validated AST nodes and fixed field/operator maps, binding every user literal. Validate addresses and CIDRs as typed inputs. Keep database error details in protected server logs and return useful parser errors with character positions to the browser.

## Browser integration

Initialize the official `keycloak-js` adapter before mounting route state. Use its standard authorization-code flow, S256 PKCE, and a public client with exact redirect and web-origin allowlists. Refresh through `updateToken` before authenticated calls. Access/refresh tokens remain in memory and must not be persisted in browser storage. [Keycloak JavaScript adapter](https://www.keycloak.org/securing-apps/javascript-adapter).

The web implementation uses React, TypeScript and Vite with semantic HTML controls, native modal dialogs, scoped design tokens and a bounded virtual table. Keep operational values exclusively API-derived. [React documentation](https://react.dev/learn), [Vite guide](https://vite.dev/guide/), [HTML dialog reference](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/dialog).
