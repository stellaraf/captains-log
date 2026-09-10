# Development validation and release gates

Evidence date: 2026-09-07. This is a working development implementation running
locally in Docker. **Version 1 is not complete.** A Docker application, a package
recipe and unit-tested host tooling do not establish a qualified Rocky appliance.

## September 8 development update

The [wide Traffic search correction](validation/TRAFFIC_QUERY_MEMORY.md) records a real one-day/seven-day HTTP503 defect, bounded ClickHouse event reads, full Go verification and the exact development backend deployment. It preserves the earlier frontend and does not qualify the frozen Rocky candidate. Historical counts below belong to the September7 checkpoint; the full release contract remains [RELEASE_ACCEPTANCE](RELEASE_ACCEPTANCE.md).

## Observed application and data path

| Area | Observed result | Evidence and limits |
|---|---|---|
| Real PAN-OS forwarding | PA-1410, PAN-OS12.1.4-h8 forwards native Syslog into the collector | [Real firewall validation](validation/PALO_REAL.md). Scoped forwarding commit45239 finished successfully. Existing unrelated forwarding and policy behavior were preserved. |
| Record accuracy | Sampled Traffic and DNS/THREAT fields match independent firewall XML API records | Serial, addresses, ports, application, rule, action, counters, session and timestamps checked. Sanitized fixtures are retained; private raw receipts are excluded from source. |
| UDP/TCP/TLS | Real sockets receive, normalize and persist test records | TLS test verified certificate and hostname. Production trust/certificate enrollment is a separate gate. |
| Durable recovery | 527 stable event IDs present in the fsynced spool before app restart were all recovered as527 unique records | This specific test observed no duplicates. Transport is documented at-least-once, not universally exactly-once. |
| Complete dependency outage at startup | Isolated `ingest` and `all` processes stayed alive and accepted durable UDP data with databases/Keycloak unreachable | Authentication stayed closed. Only test child processes were terminated. |
| Malformed/unknown data | Original payloads and diagnostics persist and are searchable | Invalid UTF-8 has a separate base64 representation. Unknown native formats remain visibly unsupported, not guessed. |
| Local identity | Real Keycloak password+mandatory SHA256 TOTP enrollment and a separate fresh MFA login passed | The app uses OIDC authorization-code/S256 PKCE; backend signature, issuer, audience, expiry and client-role checks are independent. |
| Authorization | Real administrator, analyst and viewer API checks passed | Forged signed claims denied; viewer cannot save/export; analyst cannot change retention/DNS; ownership boundaries enforced. Temporary test clients removed. |
| Search | Manual/compiler, graphical and click-generated filters query retained data | IPv4, IPv6, CIDR, nested Boolean, quoted strings, invalid SQL identifiers and cursor isolation tested. No regex SQL substitution. |
| Persistence | Saved queries, favorite/sort preferences and column layouts survive reload | Data lives in PostgreSQL. Role/owner restrictions are enforced by API. |
| Explorer | Cursor pagination, stable raw-event/firewall detail routes, DNS enrichment, auto-refresh pause, inventory and native CSV downloads passed browser checks | The browser uses real services without route interception or sample-data fallback. Stellar Light/Dark themes and compact/comfortable density persist in PostgreSQL. |
| SAML configuration | Real scoped Keycloak create/update/inspect/configuration-check with a disabled synthetic provider passed | The browser metadata review/save/reload path also passed. No external IdP login occurred. Required broker OTP and seven explicit role/profile/username mappers were checked. |
| Export | Disk-backed matching exports and single-use native browser downloads work | Output512MiB/job, two concurrent jobs, retained2GiB; memory and temporary database-sort disk bounded. Oversize jobs fail visibly. |
| Retention | Global/per-category policy persists and controls expiry for new arrivals | ClickHouse TTL cleanup tested on an isolated table. Changing existing records' expiry is not yet implemented. |
| Storage | Actual ClickHouse capacity, active bytes/event and periodic growth samples are measured | Predictions require at least one hour of positive net growth and remain estimates after merges/TTL. Guest/LUKS capacity and complete multi-window/peak EPS sizing still need integration. |

The Docker Desktop transport may report its gateway as sender IP. Firewall serial
and device name preserve device identity; the observed peer must not be labeled
as the verified management address. See [Docker deployment](INSTALL_DOCKER.md).

## Performance scope

[Ingest benchmark](INGEST_BENCHMARK.md) records a real TCP/parser/WAL/database path:

- 265 EPS for60seconds:15,900 sent and15,900 distinct stored records.
- 2,650 EPS for10seconds:26,500 sent and26,500 distinct stored records; queue drained
  afterward. Full persistence averaged1,905.73 EPS over the complete13.9054seconds.
- Both runs reported zero dropped events. These are short reference-load and
  burst checks, not a multi-day soak or an indefinite2,650 EPS capacity claim.

[Query benchmark](BENCHMARKS.md) records realistic full-payload synthetic data in
an isolated table, including raw/base64/130-field representations. Ten million
records were measured under a3CPU/3GiB ClickHouse container cap and512MiB query
budget. The100M projection exceeded the development scratch-space budget and was
not inserted. The1B preference is also untested. Exact data shape, query columns,
time distribution, repetitions, resource failures, export limits and cleanup
receipts belong to that report; a small result query does not prove every broad
raw export has the same latency.

## Automated and browser checks

Run the source checks with:

```sh
go test -race ./...
go vet ./...
PYTHONPATH=appliance:appliance/adapters python3 -m unittest discover -s appliance/tests -v
cd web
npm ci
npm test
npm run build
```

`scripts/api-integration.py` checks a running real stack with a privately stored,
browser-issued token. Browser tests also use actual Keycloak and enrolled MFA;
see [WEB.md](WEB.md). Test credentials, cookies, bearer tokens, screenshots and
raw firewall evidence are stored under ignored/private `.local/`, not in source.

The host-manager suite has39 tests covering storage guards and resume plans,
compliance result semantics, genuine OpenSSL RSA3072/PSS signing and rejection,
safe archive extraction, update gates/high-water marks and rollback logic.
[Appliance validation](APPLIANCE_VALIDATION.md) gives exact tested boundaries.

The runtime npm dependency audit reported zero known vulnerabilities. Go's
vulnerability checker found a reachable normalization issue in the original
`golang.org/x/text` dependency; it was upgraded to0.39.0, with the required
`x/sync` update, and regression tests passed. See
[GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970). A current clean scan is
recorded separately from correctness and appliance qualification; dependency
audits cannot prove absence of unknown defects. Both the final source scan and
the built Linux binary scan reported no known vulnerabilities after the fix.

Final local check:37 real API/RBAC checks,16 frontend unit tests,4 live browser
tests,40 viewport/theme/page checks,39 appliance tests and8 benchmark guard tests
passed. The current-state disable API was separately exercised against the
disabled synthetic Okta fixture, with invalid-body rejection and both audit
intent/completion rows verified. The fixture was removed and both provider
entries independently reported unconfigured afterward. A final snapshot observed
the real PA-1410 still receiving with10,961 events recorded that day and no
collector-reported drops since the final app restart. Counts are snapshot
evidence, not a permanent total or proof against UDP loss outside the collector.

## Security and appliance release blockers

| Version1 gate | Current boundary |
|---|---|
| OVA builds and Rocky boots | OVA packaging smoke uses disposable blank disks. No installed Rocky guest image has been built/booted and accepted. |
| Host FIPS, LUKS2, SELinux, auditd, firewalld, AIDE | Recipes/gates exist; no qualified guest measurement. UI reports host security unverified. |
| Application cryptography | Frozen Go FIPS module is enabled in the running development binary and its fail-closed startup gate is tested. That does not certify the application, container OS, JVM or full appliance. |
| CIS/Unified/STIG selectable and assessed | Assessment plumbing exists. Licensed/current content, reviewed Unified tailoring, exceptions and real remediation/scan evidence are unqualified. |
| First-boot experience | Security/storage gate exists; complete administrator/MFA/recovery/network/baseline/maintenance enrollment is incomplete. |
| Disk deployment/growth/addition | Guarded plans and transaction tests exist. Real GPT/LUKS/PV/LV/XFS growth, reboot recovery, blank-disk enrollment and vTPM unlock are unexecuted. Unknown disks are never automatically consumed. |
| External authentication | Okta/Entra guides and provider configuration are development work. External tenant login, negative assertions, rollover and recovery remain unverified. AD/LDAPS+MFA and additional OIDC federation are not accepted. |
| Recovery codes/passkeys | Required production enrollment/recovery tests remain incomplete. |
| Emergency disk policy | Threshold reporting and bounded spool exist. Automatic destructive emergency purge is not implemented; UI says so explicitly. |
| Managed updates | Real signature/hash/sequence/path validation and transaction tooling exist. No qualified activation/health/rollback adapters, live signed release channel, OS/kernel reboot or database/Keycloak upgrade acceptance. |
| Backup/restore | Encrypted archive/integrity and safe extraction tooling tested. Full live metadata/authentication restore and optional ClickHouse recovery require a separate test. |
| Hypervisors | VMware/Nutanix/Proxmox/Hyper-V imported boot, guest integration, HTTPS edge and storage tests are unexecuted. |
| Production scale |100M benchmark, longer265EPS soak, sustained overload/disk-full recovery and suitably sized hardware qualification remain open. |

Do not distribute this development stack as the completed, hardened appliance.
Closing a gate requires retained measurements on the target environment and a
reviewed release artifact, not changing an on-screen status or checking a box.
