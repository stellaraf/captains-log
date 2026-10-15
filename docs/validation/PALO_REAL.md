# Real PA-1410 forwarding and parsing validation

Initial evidence date: **2026-09-07**. This records a real firewall/application test, not complete version 1 appliance acceptance. The subsequent **2026-09-09** public-CA import and native encrypted forwarding test is recorded in [Syslog TLS certificate validation](SYSLOG_TLS_CA.md#native-palo-alto-encrypted-forwarding). Private source logs, credentials, firewall addresses, serial numbers, and policy names are deliberately excluded from this public document.

## Environment and authorized change

- Hardware: **Palo Alto Networks PA-1410**.
- PAN-OS: **12.1.4-h8**.
- Firewall timezone: **US/Pacific**; the collector used the matching timezone for legacy timestamps.
- Destination: local NebulaLog developer runtime, TCP 5514, backed by real Docker-hosted PostgreSQL, ClickHouse, and Keycloak. The initial receiving process was the actual Go application, not a mock or synthetic log screen.
- Configuration change: one additive NebulaLog Syslog profile, one data-plane Log Forwarding profile, **ten** existing explicitly session-end-logged security/default-rule attachments, and **six** management categories: System, Configuration, GlobalProtect, HIP Match, User-ID, IP-Tag.
- No policy match criteria, allow/deny/reset actions, or session logging flags changed. A rule without explicit logging was left alone. Existing forwarding destinations were preserved, including an existing System destination. If old and new destinations converge on one collector, System events can arrive more than once; the collector does not silently discard them.

The running/candidate comparison initially showed no pending administrator changes. Configuration was guarded by a shared config lock, changed through **18 additive set operations**, and checked against **54 expected leaf additions** before commit. The candidate contained exactly the planned changes. Commit job **45239** reached **FIN / OK**. Independent running configuration matched the prepared expected fingerprint; the post-commit candidate had **zero differences**. The lock was released. Credentials and full configuration values were not included in the receipts.

## Persisted event evidence

At **22:40:14 UTC**, ClickHouse contained the following events from the validated firewall during this test window:

| Display category | Native type | Persisted events | Parse result |
| --- | --- | ---: | --- |
| Traffic | TRAFFIC | 1,323 | All parsed |
| DNS Security, threat-derived | THREAT | 170 | All parsed |
| System | SYSTEM | 24 | All parsed |
| Data Filtering | THREAT | 8 | All parsed |
| URL Filtering | THREAT | 5 | All parsed |
| **Total** | | **1,530** | **Zero parser failures for this firewall** |

The first persisted firewall event arrived at 22:34:33 UTC. The observed source receive times began earlier than that. Subsequent events continued arriving with current timestamps. Firewall external forwarding counters independently showed traffic/threat sends with zero reported forwarding drops and an empty forwarding queue during inspection. These are point-in-time observations, not a lossless-network or sustained throughput benchmark.

A separate device was already sending non-PAN-OS BSD messages to the listener. Those messages were correctly retained in Parsing diagnostics with their original raw text and sender. Their presence initially made the aggregate failure percentage misleading; grouping by sender and serial established that the PA-1410 records were parsed successfully.

## Follow-up category audit

At **2026-09-08 02:15:59 UTC**, the same firewall had **47,259 Traffic**, **1,679 DNS-related Threat**, **672 URL Filtering**, **208 Data Filtering**, and **933 System** records persisted. All **50,751** parsed successfully. The Threat view now includes the same DNS-related event IDs as DNS Security; this overlap does not duplicate stored events.

A bounded, read-only native XML log query independently found no retained records in the firewall's HIP Match, User-ID, GlobalProtect, IP-Tag, Authentication, Decryption, Tunnel or WildFire databases. Its latest Configuration event occurred before forwarding activation. Empty views for those families were therefore consistent with the source during this inspection, rather than evidence of another category-name mismatch. No firewall changes or generated threat traffic were needed for this audit. The firmware's XML log API did not accept the dedicated `dns-security` log-type value, so no native DNS-database absence is claimed.

The UI now explains category scope, defaults to a clearly selected time range, offers an explicit 30-day search from supported empty views, and labels Tunnel parsing as unavailable. System alerts is explicitly a high/critical System view; native PAN-OS Alarm ingestion is not claimed. An additional parser regression covers documented Advanced DNS Security `adns-*` categories using controlled fixture variations; no live `adns-*` capture was observed during this audit.

At **2026-09-08 08:30:37 UTC**, a bounded read-only database audit found **168,098 native PAN-OS records**, all parsed: **159,555 Traffic**, **4,097 DNS-related Threat**, **1,494 URL Filtering**, **623 Data Filtering**, and **2,329 System**. The same snapshot contained **345,741 unknown records** with no PAN-OS wire type or serial and the diagnostic `PAN-OS common header requires at least 7 fields`. Sender/envelope grouping and five privately retained samples identified unrelated BSD switch telemetry; the samples contained one to four CSV fields and fan-controller event tokens. These records do not establish a PAN-OS parser failure or an unsupported native DNS/Tunnel layout. No new native wire family was observed, no parser mapping was changed, and the original messages remain retained. This is a persisted-data snapshot; it does not establish uninterrupted delivery during the preceding local runtime outage.

At **2026-09-08 10:44:47 UTC**, a fresh normal password/OTP development check passed all 19 category API requests, the Threat/DNS shared-event comparison, wide Traffic pagination/detail and the existing refresh/application browser suites. A real one-day/seven-day Traffic memory failure was corrected by the [bounded event-read profile](TRAFFIC_QUERY_MEMORY.md). Configuration remained empty in the tested period with correct guidance; this check neither changed the firewall nor established support for unobserved native families. Fresh native Traffic, DNS/THREAT and System ingestion was independently observed after deployment.

## Complete WildFire verdict logging follow-up

On **2026-09-14**, the PA-1410's WildFire runtime counters showed **12 files forwarded** and **12 benign verdicts received**, while its native WildFire log query completed with **zero entries**. Benign and grayware reporting were not explicitly enabled; both default to disabled. Captain’s Log likewise contained zero WildFire submission rows, with no PAN-OS parser failures. Authenticated browser/API checks returned HTTP 200 and zero rows for both the last hour and the last 30 days. This identified a source logging gap, not an application filter failure.

The existing forwarding profile already selected **All Logs** for WildFire and sent them through the verified **TLS/6514** destination. With user authorization, only `report-benign-file` and `report-grayware-file` were set to `yes`. The live PAN-OS schema exposed both fields. The candidate diff contained exactly those two leaf additions; commit **50955** completed **FIN / OK**, the running configuration matched the expected change, and no candidate differences or configuration locks remained. File-submission rules, security actions, destinations, and transport were preserved.

Four source package test suites passed. A separate isolated full-parser check passed five controlled cases: benign, grayware, malware, and phishing `THREAT/wildfire` events remained WildFire Submissions; `THREAT/wildfire-virus` remained Threat. These were synthetic variations of a sanitized native Threat fixture, **not real WildFire captures**, and none were injected into the collector or event database.

The reporting settings apply to future qualifying events; they do not backfill earlier unlogged submissions. At this September checkpoint, a subsequent native WildFire event had not yet been matched to its stored record. Follow the [complete forwarding setup](../FIREWALL_SETUP.md), including the [required WildFire reporting settings](../FIREWALL_SETUP.md#5-include-benign-and-grayware-wildfire-files), instead of treating upload or verdict counters as log-delivery evidence.

### October 15 historical WildFire comparison

A read-only audit at **2026-10-15 19:05 UTC** found **1,495 parsed
`THREAT/wildfire` records** in the preceding 30 days. Nine native firewall
submissions from October 3 matched stored events by serial and sequence across
**17 fields each, with all 153 comparisons matching**. Those comparisons include
the verdict/category, file digest/type, addresses and ports, rule/action, and
session. This is actual historical submission evidence, not generated fixtures.

The running firewall still enabled benign and grayware reporting, forwarded
WildFire with **All Logs** over **TLS/6514**, and used an analysis profile covering
any supported file type/application in both directions on the associated rules.
Existing inspection-bypass rules had no WildFire Analysis association; session
logging on those rules does not establish file-inspection coverage. The audit
did not change inspection policy, upload samples, or generate alerts.

The latest native submission was October 13. The default one-hour query correctly
returned zero; the equivalent 30-day query returned the 1,495 historical records.
Twenty newer native records in the latest 100 were absent from the collector,
and no category had stored arrivals during October 9–14. This is consistent with
a collection gap, but the audit did not independently establish historical
runtime uptime or the cause of every missing record. It is not evidence of
uninterrupted or lossless delivery.

The private audit receipt has SHA-256
`4d180c1d350e54c88c4df63da6e56ef426fe8b445353c08cc2a5ad67a452f4f7`.
Raw data and configuration remain outside Git. A fresh post-reconnection
WildFire submission, authenticated category UI, and CSV export still need
verification. This advances historical native parsing/delivery evidence only;
it does not close the complete appliance release gate.

## Field correctness beyond the parse flag

1. **Twenty-five** actual stored Traffic rows were compared to their preserved native CSV values across **fourteen normalized fields**. The native layout contained **130 CSV fields**. No mismatches were found.
2. A stored Traffic record was matched by its exact sequence number to the firewall's independently fetched **XML API Traffic log**. **Sixteen fields** matched, including original source/destination IPs, ports, application, action, rule, device/serial, session ID, subtype, byte/packet counters, and generated time.
3. A stored DNS-related Threat record was matched by exact sequence to the firewall's **XML API Threat log**. **Twelve fields** matched, including addresses, ports, application, action, rule, device identity, session/subtype, and generated time. No mismatches were found.
4. Native Traffic and Threat layouts were converted into thoroughly sanitized regression fixtures preserving their **130-field** and **140-field** structures. All customer-identifying values and unknown suffix values were replaced or cleared. Tests verify timestamps with timezone offsets, IPv4/IPv6, ports, application, action, subtype/category, counters, threat metadata, and appended-field handling.

Private audit and comparison receipts are held under the developer workspace's ignored `.local/firewall/` directory. Raw captures and session credentials are not repository fixtures.

## Automated checks

`go test -race ./internal/panos ./internal/ingest` passed, including native-layout regressions, UDP, real TCP/TLS sockets, server-certificate validation, fragmented/coalesced frames, raw malformed evidence, outage/restart replay IDs, WAL acknowledgment and corruption handling, bounded capacity, and five-second rate expiration.

## Limits and remaining gates

This exercise validates native **TCP** forwarding and the observed families on one PAN-OS release. Configuration forwarding was configured but no post-activation Configuration event was claimed as observed in the counts above. Dedicated new native DNS Security, GlobalProtect, HIP, User-ID, Authentication, Decryption, and Tunnel data were not claimed as hardware-tested here.

The real firewall was not switched to TLS during the initial September 7 test. Its later [September 9 encrypted forwarding test](SYSLOG_TLS_CA.md#native-palo-alto-encrypted-forwarding) independently verifies that transition. Neither test establishes production OVA boot, Rocky FIPS/CMVP status, LUKS, SELinux, compliance profiles, storage expansion, production authentication federation, signed update behavior, or 100-million-event performance acceptance.
