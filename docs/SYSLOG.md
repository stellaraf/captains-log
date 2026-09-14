# Syslog ingestion and parser support

Captain’s Log accepts configurable UDP, TCP, and TLS listeners. Appliance defaults are UDP 514, TCP 514, and TLS 6514. Deployment port mappings may differ. Standard PAN-OS CSV is accepted without a custom format.

Follow the [complete firewall setup guide](FIREWALL_SETUP.md) to enable event generation and forward every available category with **All Logs**, including informational events. A running listener and an attached forwarding profile cannot create logs that PAN-OS suppressed. In particular, enable both **Report Benign Files** and **Report Grayware Files** for complete eligible WildFire file reporting; the [WildFire setup step](FIREWALL_SETUP.md#5-include-benign-and-grayware-wildfire-files) explains defaults, email-link exclusions, and why earlier unlogged submissions are not backfilled.

## Download appliance trust for Palo Alto

An Administrator can open **Administration → Diagnostics → Encrypted log forwarding** to inspect the configured certificates and choose **Download Syslog CA Certificate**. First boot generates a unique RSA-3072 CA and server certificate on the appliance after the host security gates pass. The CA signing key stays on encrypted appliance storage with root-only permissions. The API receives read-only mounts of public certificates and the public trust bundle; it does not receive the CA or server private key.

Compare the displayed **CA SHA-256 fingerprint** with the CA fingerprint on the trusted VM console before trusting the download. HTTPS uses a separate server-certificate fingerprint, also shown on that console. The PEM download contains only the public CA certificate. It requires an authenticated Administrator and the exact fingerprint reviewed in the UI; a changed certificate requires refreshing and reviewing again. The browser independently checks the downloaded certificate's SHA-256 fingerprint. Metadata describes configured files, not a proven active TLS connection.

On PAN-OS, import that PEM under **Device → Certificate Management → Certificates**, using **Custom Certificates** on 12.1 and later or **Device Certificates** on earlier versions. Import without a private key and mark the CA as a **Trusted Root CA**. In **Device → Server Profiles → Syslog**, choose **SSL** (the PAN-OS label for TLS), TCP port **6514**, and a reachable server name or IP address included in the displayed certificate SANs. The appliance includes its configured hostname and, for static addressing, its configured management IP. A DHCP address is not guessed or silently added; use the configured DNS name.

The **Certificate for Secure Syslog** checkbox selects a firewall *client* certificate for mutual TLS. It is not part of importing this public CA. This download configures server trust and encrypted transport; client-certificate authentication is a separate feature. Assign the syslog server profile to the relevant forwarding profiles and log settings, commit, and verify fresh events and firewall TLS errors. Never work around an expired certificate, name mismatch or untrusted issuer by disabling verification. [PAN-OS syslog and TLS configuration](https://docs.paloaltonetworks.com/ngfw/help/12-2/configure-syslog-monitoring)

The development setup uses `python3 scripts/dev-init.py` to create its own unique CA and server certificate covering the configured `SYSLOG_BIND_IP`. Its CA key is outside application mounts. This is a development fixture; production certificates are generated during appliance first boot and are never included in an OVA. Certificate download support does not establish automatic certificate renewal. The local deployment has a separate [real Palo Alto TLS delivery validation](validation/SYSLOG_TLS_CA.md#native-palo-alto-encrypted-forwarding).

## Transport and framing

UDP preserves datagram boundaries; the collector reads a full-size datagram buffer to avoid truncating normal UDP payloads. UDP offers no delivery acknowledgment, and network or kernel losses cannot be recovered by the application. Do not describe application drop counters as a complete measurement of upstream UDP loss.

TCP supports newline/CRLF and octet-counted framing. A frame length counts **bytes**, including multibyte UTF-8, rather than characters. Fragmented socket reads and several messages in one read are handled. TLS uses the same bounded frame reader and requires a configured server certificate with TLS 1.2 or later. RFC 5425 senders should use octet counting. Native BSD and RFC 5424 envelopes are parsed independently from their CSV bodies.

Defaults are a 1 MiB maximum message, 128 simultaneous stream connections, a two-minute stream read timeout, batches of 1,000, and a one-second flush interval in the collector package. The supplied application sets a two-second flush interval. A partial stream message at disconnect/timeout is retained with a framing error. An oversized stream frame closes the connection, retains the captured bounded prefix as a diagnostic, and increments the drop counter; unread bytes beyond the bound are not claimed as retained. Limits can be configured through the collector API; deployment environment exposure is documented in the runtime configuration.

Standards: [RFC 3164](https://www.rfc-editor.org/rfc/rfc3164), [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424), [RFC 6587](https://www.rfc-editor.org/rfc/rfc6587), and [RFC 5425](https://www.rfc-editor.org/rfc/rfc5425).

## Durable buffering

Before a message is locally accepted, its original bytes, sender, local ingestion timestamp, and stable ID are appended to a bounded disk spool and fsynced. The spool uses checksummed, append-only segments, private permissions, and a process ownership lock. It must reside on the encrypted data volume for production.

Delivery retries a stable batch during database outages. Acknowledgment is persisted atomically only after the database acknowledges insertion; acknowledged segments are reclaimed. After a crash between database insertion and spool acknowledgment, a batch can replay with the same event IDs. This is **at-least-once** delivery, not an exactly-once promise. Checkpoint corruption, partial WAL records, or checksum failures stop spool startup visibly instead of silently skipping evidence. Preserve the spool for investigation; do not delete it to clear an error.

A terminal WAL read/write/acknowledgment error stops admission, marks listeners failed, and retains the spool for recovery. A single record larger than the entire configured spool capacity is rejected immediately. When temporarily full, TCP waits for capacity and applies backpressure. UDP cannot pause its sender: failed persistence increments the drop counter and records an error. Database outage, connection limits, framing failures, and full-spool states must be visible in diagnostics. The disk capacity limit counts WAL payload files; filesystem metadata requires additional reserve.

## Schemas and categories

A registry revision identifies a documented field mapping, not the firewall's software release. Field count is never used to infer PAN-OS version. Core fields are validated while missing optional suffixes and new trailing columns are tolerated. Original CSV field values and unrecognized suffixes remain available, alongside raw evidence. Invalid typed fields produce a partial parse instead of invented values.

| Native wire family | Display category | Current parser behavior |
| --- | --- | --- |
| TRAFFIC | Traffic | Dedicated mapping, original/NAT addresses, counters, session and device metadata |
| THREAT, subtype url | URL Filtering | Threat layout |
| THREAT, subtype wildfire | WildFire Submissions | Threat layout; wildfire-virus remains Threat |
| THREAT, subtype data/file/dlp | Data Filtering | Threat layout |
| THREAT, recognized dns-* or adns-* threat category | DNS Security | Threat layout, original wire type retained; also included in the Threat view |
| THREAT, other subtypes | Threat | Threat layout |
| SYSTEM | System | Dedicated mapping |
| CONFIG | Configuration | Default and before/after-detail layouts; ambiguous layouts remain diagnostic |
| AUTHENTICATION | Authentication | Dedicated mapping |
| USERID | User-ID | Dedicated mapping |
| GLOBALPROTECT | GlobalProtect | Dedicated mapping |
| HIP-MATCH | HIP Match | Dedicated mapping |
| IPTAG | IP-Tag | Dedicated mapping |
| DECRYPTION | Decryption | Dedicated mapping |
| Unverified native families, including dedicated new DNS Security, Tunnel, GTP, SCTP, and Correlation | Parsing diagnostics | Raw retained until the exact wire schema is verified |

Unified searches across categories. No `UNIFIED` or `ALARMS` wire format is invented. Alarms availability must be described as a derived/application capability rather than parser support.

DNS categorization recognizes both request-analysis `dns-*` categories and Advanced DNS Security response-analysis `adns-*` categories, as described in [Palo Alto's Advanced DNS Security instructions](https://docs.paloaltonetworks.com/dns-security/activation-and-onboarding/enable-advanced-dns-security/enable-advanced-dns-security-pan-os-11-2). This applies to incoming Threat records; previously stored classifications are not rewritten. It does not establish support for the separate native DNS Security CSV layout.

Default CSV escaping follows the dedicated Palo Alto reference: quoted comma-containing values and doubled embedded quotes. Backslashes in usernames remain literal. A custom field order is not automatically supported.

Legacy timestamps without timezone offsets use the configured device/site timezone and record that assumption. High-resolution receive timestamps honor their supplied offsets. Local ingestion time is always recorded independently. The firewall management-plane receive time, original generated time, and collector time have different meanings. Configure `PANOS_TIMEZONE` to match the sender for the single-timezone runtime; mixed-timezone fleets need explicit per-device timezone configuration before authoritative generated-time claims.

See [canonical research and known documentation ambiguities](research/PANOS.md).

## Diagnostics and measurement

When API and ingestion run as separate Quadlet services, ingestion atomically publishes a short-lived observation at `COLLECTOR_STATUS_PATH` every two seconds. The encrypted runtime directory is mounted writable only in the collector and read-only in the API. The API rejects missing, malformed, externally writable, symlinked, future-dated or older-than-ten-second observations; health and metrics return unavailable instead of an empty success. A normal collector shutdown removes its observation. This file is telemetry, not an event journal or proof of delivery. An inability to publish telemetry does not stop durable ingestion.

Stats expose received, parsed, failed, inserted, queue depth, spool bytes, dropped, last received, listener state, and last error. Current events/sec and bytes/sec use **50 completed 100 ms buckets divided by five**, including idle intervals. This represents a full five-second window ending at the most recent 100 ms boundary, with at most 100 ms display latency. Excluding the partial bucket avoids a periodic rate underestimate. Lifetime averages are exposed separately as `average_events_per_second` and `average_bytes_per_second`; `rate_window_seconds` reports five. Counts restart with the collector process; pending WAL work survives. Parsed/inserted counters can include replayed work accepted by an earlier process and therefore need not be less than this process's received count. Stats are concurrent snapshots, not a transactionally consistent accounting ledger.

A listener may receive non-PAN-OS devices on a shared port. Such messages remain in Parsing diagnostics with their sender and original payload. Investigate error counts by sender and serial before attributing them to a firewall parser defect. Restrict incoming senders at the host/network firewall for a dedicated production deployment.

For an empty log category, first confirm a matching event exists in the firewall's native log database. Then follow the [per-category delivery checks](FIREWALL_SETUP.md#7-commit-and-verify-each-category) through forwarding, receipt, parsing, database insertion, and UI filters. File upload counts, WildFire analysis verdict counts, established TLS connections, and collector health each describe different stages; none alone proves a specific log reached storage.

Tests cover real UDP/TCP/TLS sockets, certificates, fragmented/coalesced messages, outage/restart replay identity, raw failures, WAL corruption, capacity backpressure, and parser field correctness. The PA-1410's native 130-field Traffic and 140-field Threat layouts have sanitized regression fixtures; see [hardware evidence](validation/PALO_REAL.md).
