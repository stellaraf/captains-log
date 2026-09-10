# Downloadable syslog trust certificate

Evidence date: **2026-09-09**. This records source validation and the running local Docker application. Rocky first-boot execution and a sealed OVA remain separate acceptance gates.

## Implemented behavior

Administrators can use **Administration → Diagnostics → Encrypted log forwarding → Download Syslog CA Certificate**. The panel shows the CA fingerprint, expiry dates, covered names and addresses, and Palo Alto configuration instructions. Download requests require an authenticated Administrator session and the exact reviewed certificate ETag. The browser checks the downloaded certificate's DER SHA-256 fingerprint. Downloads are recorded in PostgreSQL before certificate bytes are returned.

The download contains one public CA certificate. The API validates the configured CA, server certificate and chain, refuses unsafe or private-key PEM input, and exports no private keys. Production first-boot code generates a unique RSA-3072 CA and server certificate on encrypted appliance storage. The CA key has root-only permissions. The production API mounts only public certificate files; the separate collector receives the server key it needs. Static management addresses are included in the server certificate SANs. Existing credentials and certificates are not silently rotated.

The local development initializer creates a separate CA and server certificate for the local runtime. Its signing key is outside all application mounts. This is a development fixture, not a certificate baked into a distributable appliance.

## Local validation

- The actual pinned development Go toolchain passed the API and command race tests: 44 top-level tests and 185 subtests. Three unrelated ClickHouse integration tests were skipped because their integration URL was unset. All eight new certificate tests and their 61 subtests ran.
- All 79 web tests and the TypeScript/Vite build passed. Appliance certificate wiring passed 49 focused bootstrap, first-boot and service tests, including real OpenSSL chain and identity checks.
- A normal password-and-OTP Administrator login downloaded the public PEM through the real browser UI. Its bytes matched the local public CA; its DER fingerprint matched both displayed metadata and the response ETag. An independent PostgreSQL read confirmed the matching download audit event.
- Live connections to the running TLS listener succeeded with the downloaded CA over both TLS 1.2 and TLS 1.3. The TLS 1.2 cipher was `ECDHE-RSA-AES128-GCM-SHA256`. Wrong-CA and wrong-name checks failed as expected. These local socket checks sent no syslog payloads.
- Light and dark desktop and mobile views were inspected. Browser errors were zero. The two newly created QA sessions were removed and verified absent; existing accounts, passwords and OTP credentials were preserved.
- Independent runtime inspection confirmed the expected deployed image and that the CA signing key was not mounted into the development app.

The deployed development version is `0.1.0-dev.syslog-ca-e48de217b92e`, image `sha256:c2f0f35039f7dd9e0b10264c4c2d913f09aa69cd125f207156ad75633d775f89`. Private receipts are under `.local/qa-syslog-ca-20260909/`, `.local/syslog-cert-download-20260909/revision-2/`, and `.local/public-ca-appliance-20260909/`. Initial harness failures and their separate corrected runs are preserved.

## Native Palo Alto encrypted forwarding

The authorized PA-1410 running PAN-OS **12.1.4-h8** successfully imported the same public CA downloaded through the application. The imported certificate's DER fingerprint matched; no private key was transferred. The candidate contained exactly one new public CA object, one trusted-root membership and the existing owned syslog destination's TCP-to-SSL and 5514-to-6514 changes. Existing rules, other destinations, logging assignments and validation settings were preserved.

Commit **46864** reached **FIN / OK**, with the final running/candidate identity verified at **20:00:50 UTC** and no pending edits. Only one commit request was sent. Owned configuration and commit locks were removed and verified. The first staging attempt had refused a duplicated lock-view alias before any certificate/profile write; its separate receipt and the narrowly corrected guard tests are retained.

A complete **68.879-second** observation from **20:03:36 to 20:04:45 UTC** recorded 212 firewall-to-collector TCP 6514 data packets, including 100 TLS application-record-prefix matches. The old TCP 5514 connections remained idle: eight headers and no data. Both observers exited successfully, their parsed counts matched tcpdump's final counts, and kernel capture drops were zero. Capture was restricted to this endpoint pair with 54-byte Ethernet snapshots; no log payloads were saved. The first observation preserved positive TLS evidence but was marked incomplete because the helper rejected tcpdump's shutdown blank line; a separate corrected helper and passing follow-up observation supersede its completeness claim.

The corresponding bounded database window contained **358** newly ingested native firewall records, including **352** whose device-generated and collector-ingested times both fell within the window. All parsed successfully across Traffic, System, DNS Security, URL Filtering and Data Filtering. These are persisted rows, not a uniqueness or lossless-delivery guarantee. The event schema has no per-event transport field; the evidence combines the exact committed SSL configuration, endpoint-specific TLS traffic and freshly persisted native records.

The firewall continued to report `enforce` for its existing connection, CRL, OCSP and EKU validation settings. A bounded native System-log query found no TLS failure markers; its medium event was a certificate/configuration deprecation advisory before commit completion, without a reference to this destination or CA. The global forwarding drop counter increased by one between the broader before/after snapshots; this cannot be attributed to this destination, and no zero-loss claim is made.

Private evidence is under `.local/palo-syslog-tls-20260909/` and `.local/palo-network-proof-20260909/`. The aggregate migration observation receipt has SHA-256 `1b6d650931bbc8702fdafcd6fe019364acb0bbf5f2b9c15bb53764850b0491cb`.

## Scope

Certificate metadata describes configured files. Native forwarding evidence above is specific to this tested firewall and local deployment. Automatic certificate renewal, mutual TLS client authentication, final Rocky first-boot execution and sealed OVA qualification are separate acceptance gates. See the [configuration instructions](../SYSLOG.md#download-appliance-trust-for-palo-alto).
