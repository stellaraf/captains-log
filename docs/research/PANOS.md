# PAN-OS syslog research

Verified against official documentation on 2026-09-07. This is an implementation decision record, not a claim of hardware compatibility certification. Palo Alto's current documentation navigation includes PAN-OS 12.2, 12.1, 11.2, 11.1, and 10.2. Versioned documentation and sanitized captures from each supported release must accompany parser compatibility claims.

## Canonical sources

- [Current syslog field descriptions](https://docs.paloaltonetworks.com/ngfw/help/12-2/syslog-field-descriptions)
- [PAN-OS 11.1 syslog field descriptions](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions)
- [Traffic](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields)
- [Threat](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields)
- [System](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/system-log-fields)
- [Configuration](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/config-log-fields)
- [Authentication](https://docs.paloaltonetworks.com/ngfw/help/12-2/authentication-log-fields)
- [GlobalProtect](https://docs.paloaltonetworks.com/ngfw/help/12-2/globalprotect-log-fields)
- [User-ID](https://docs.paloaltonetworks.com/ngfw/help/12-2/user-id-log-fields)
- [CSV escaping](https://docs.paloaltonetworks.com/ngfw/help/12-2/escape-sequences)
- [Forwarding configuration](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring)
- [DNS Security collection](https://docs.paloaltonetworks.com/dns-security/administration/dns-security-data-collection-and-logging)

## Wire families versus views

Keep the original wire type and subtype independent from the display category. URL Filtering is `THREAT/url`; WildFire Submissions is `THREAT/wildfire`. Other malware detected by Antivirus remains Threat, including `wildfire-virus`. Data Filtering can select the documented threat subtypes `data`, `file`, and `dlp` where the specific schema supports them. Do not invent `URL`, `WILDFIRE`, or `DATA` wire schemas because a sidebar contains these labels. [Threat reference](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields).

PAN-OS 12.1.2 introduced a dedicated DNS Security log type with external forwarding; see [12.1 content inspection release notes](https://docs.paloaltonetworks.com/ngfw/release-notes/12-1/features-introduced-in-pan-os/content-inspection-features). Its exact native CSV layout must be verified separately because the generic index does not list it. Malicious DNS can also be present in threat logs. A DNS Security view selects recognized `dns-*` and `adns-*` threat categories, preserving the original type. Palo Alto documents `dns-*` for request analysis and `adns-*` for Advanced DNS Security response analysis, including benign response categories; classification alone is not a malicious verdict. [Advanced DNS Security instructions](https://docs.paloaltonetworks.com/dns-security/activation-and-onboarding/enable-advanced-dns-security/enable-advanced-dns-security-pan-os-11-2). Strata Logging Service has separate DNS schemas and is not evidence that an on-premises firewall exports that same wire layout. Unknown DNS layouts must remain raw/diagnostic until supported by a specific schema and fixture. [DNS collection](https://docs.paloaltonetworks.com/dns-security/administration/dns-security-data-collection-and-logging).

`TRAFFIC`, `SYSTEM`, `CONFIG`, `USERID`, `GLOBALPROTECT`, and `AUTHENTICATION` have distinct documented layouts. HIP Match, IP-Tag, Decryption, Tunnel Inspection, SCTP, Correlated Events, GTP, and Audit also have dedicated references under the canonical index; parse them only with their own layouts. Unified is an application cross-category view. The current syslog index does not establish an `ALARMS` wire family; an Alarms view must be an explicitly documented derived view or unavailable, never an invented parser.

## Core field mapping

Indices below are zero-based CSV positions after stripping the syslog envelope. They are not a global schema. The registry keeps per-family revision IDs and source URLs, permits appended fields, checks the common prefix, and never assigns a PAN-OS release based on field count alone.

Common envelope for the named standard families: receive timestamp at 1, firewall serial at 2, wire family at 3, subtype at 4, generated timestamp at 6. Position 5 is reserved, **not reliably a PAN-OS version**. Preserve it as an original field. Local ingestion time and transport sender are independently recorded.

| Family | Normalized fields and CSV indices |
| --- | --- |
| TRAFFIC | src/dst 7/8; NAT src/dst 9/10; rule 11; src/dst user 12/13; app 14; VSYS 15; src/dst zone 16/17; session 22; src/dst port 24/25; protocol 29; action 30; bytes/sent/received 31/32/33; packets 34; sequence 39; session end reason 46; device 52 |
| THREAT | Same network prefix through action 30; misc 31; threat identifier 32; category 33; severity 34; sequence 36; device 59; threat category 69 |
| SYSTEM | VSYS 7; event ID 8; object 9; module 12; severity 13; description 14; sequence 15; device 22 |
| AUTHENTICATION | VSYS 7; src 8; user 9; policy 12; description 18; event/result 20; sequence 22; device 29 |
| USERID | VSYS 7; src 8; user 9; data source 10; event ID 11; sequence 18; device 25 |
| GLOBALPROTECT | VSYS 7; event ID 8; stage 9; user 12; public IPv4/IPv6 15/16; description 27; result 28; sequence 34; device 47 |

Source tables above are linked individually in Canonical sources. Missing optional values remain empty/nullable, not fabricated. Validate present IP addresses and numbers; preserve raw and flag a partial parse if any typed value is invalid. Extended field positions are interpreted only by a registered layout.

## Configuration ambiguity

The [Configuration reference](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/config-log-fields) lists before/after-change detail in its format sequence, but its field descriptions explicitly state those fields occur only in custom logs. Consequently a default configuration layout uses host 7, VSYS 8, command 9, admin 10, client 11, result 12, path 13, sequence 14, device 21. The custom-inclusive layout shifts sequence to 16 and device to 23. Detect a candidate using numeric sequence and timestamp anchors; require explicit schema selection when ambiguous. Retain all fields and original text in either case. Full device-capture validation remains a release gate.

## Escaping, timestamps, and provenance

Use a real CSV reader: comma or quote-containing fields are quoted and embedded quotes are doubled. Backslashes in usernames must remain literal. The dedicated [escape-sequence reference](https://docs.paloaltonetworks.com/ngfw/help/12-2/escape-sequences) governs standard CSV, even though the general current index discusses custom escaping broadly.

Firewall receive time means management-plane receipt; generated time represents the original event. A high-resolution timestamp, when available, improves receive-time precision and includes an offset. Legacy timestamps omit zone information: parse using configured device/site timezone, and label the assumption. Never silently claim UTC was on the wire. Keep nullable typed times and original field values. The parser's registry ID, parser software version, configured firewall PAN-OS version, and confidence/warnings are separate provenance fields.

## Framing and durability decisions

- [RFC 3164](https://www.rfc-editor.org/rfc/rfc3164) covers BSD envelopes; [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424) covers versioned envelopes and structured data. Header parsing must not mistake commas in a header for CSV start.
- [RFC 6587](https://www.rfc-editor.org/rfc/rfc6587) documents octet counting and delimiter framing. Implement both for TCP; lengths count bytes, and a single socket read is not a message boundary. Support coalesced and fragmented frames. Bounds and incomplete frames require explicit diagnostics.
- [RFC 5425](https://www.rfc-editor.org/rfc/rfc5425) specifies TLS syslog with octet-counted frames and port 6514. TLS listener configuration should use a certificate and restricted minimum protocol; integration tests must verify real TLS traffic.
- UDP preserves datagram boundaries but provides no end-to-end delivery guarantee. TCP acknowledgment is also not application/database acknowledgment. Document kernel/network loss limits.
- Append a full original event plus sender, ingestion timestamp, and stable event ID to a bounded, fsynced spool before treating it as locally accepted. Batch delivery to ClickHouse; advance a durable spool acknowledgment only after database success. Crash before acknowledgment can replay a batch: provide stable IDs and document at-least-once semantics.
- When full, stop accepting TCP work and expose spool/capacity errors. UDP overflow/drop counters and errors must be visible. Do not rotate away undelivered spool records. Every malformed/unrecognized accepted message follows the same durable path to diagnostics.

## Additional registered native families

The parser also uses separate layouts for [HIP Match](https://docs.paloaltonetworks.com/ngfw/help/12-2/hip-match-log-fields), [IP-Tag](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/ip-tag-log-fields), and [Decryption](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/decryption-log-fields). Their native wire types are HIP-MATCH, IPTAG, and DECRYPTION. Display IDs are hip, iptag, and decryption. CONFIG and AUTHENTICATION display IDs are configuration and authentication. The [Tunnel reference](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/tunnel-inspection-log-fields) currently describes its Type field as START/END, inconsistent with the type/subtype convention. Native tunnel captures are needed before declaring support.

Rechecked on 2026-09-07 during the blank-category audit: the [12.2 Help reference](https://docs.paloaltonetworks.com/ngfw/help/12-2/tunnel-inspection-log-fields) repeats that Tunnel Type-field ambiguity. The [networking guide](https://docs.paloaltonetworks.com/ngfw/networking/tunnel-content-inspection/view-tunnel-information-in-logs) establishes a Tunnel log type for matching inspection rules but does not provide a native CSV example resolving position 3. Do not select the Traffic layout just because the first network fields match: Tunnel's severity and counter positions differ. Keep unverified Tunnel wire records in parsing diagnostics with their full raw evidence until a native capture resolves the discriminator. Existing VPN status events can be System logs and are not evidence of a Tunnel Inspection record.
