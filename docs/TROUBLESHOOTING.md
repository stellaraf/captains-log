# Troubleshooting

Start with the exact sender, listener, time range, and error. Separate firewall forwarding, network receipt, durable buffering, parsing, database insertion, and browser filtering.

## No firewall events

1. In **Diagnostics → Syslog**, check the actual listener address/port and received count. A listener bound to `127.0.0.1` cannot receive a remote firewall.
2. Confirm **Device → Server Profiles → Syslog** has the correct address, transport, port, and standard format. A profile alone does not forward Traffic.
3. Confirm **Objects → Log Forwarding** references the Syslog profile and that applicable **Policies → Security → Actions** reference the forwarding profile.
4. Confirm **Log at Session End** is enabled where intended. Existing long-lived sessions may not produce a new final event immediately.
5. Confirm management categories separately in **Device → Log Settings**.
6. Verify **Commit** completed successfully, not merely queued. Do not commit somebody else's pending candidate changes to troubleshoot forwarding.
7. Check PAN-OS **Device → Setup → Services → Service Route Configuration** and the actual route/source interface used for Syslog. Do not change service routes without understanding existing traffic and log destinations.
8. Inspect transport reachability and host firewalld rules. For a configured TCP port, a workstation test such as `nc -vz <NEBULALOG-IP> 514` proves a listener is reachable from that workstation, not from the firewall.

On the appliance, a narrowly scoped passive capture can verify arrival:

```sh
sudo tcpdump -ni any -c 20 'host <FIREWALL-IP> and (udp port 514 or tcp port 514 or tcp port 6514)'
```

Use the actual mapped ports. Payload captures contain sensitive logs; keep them private, limit their duration and size, and do not attach unsanitized raw data to public issues. Avoid `-A` on a shared screen.

PAN-OS operational commands useful for read-only diagnosis include `debug log-receiver statistics` and `show jobs id <JOB-ID>`. External Syslog forwarding counters are more relevant than Panorama connection status for a standalone Syslog destination. Firewall "sent" counters do not prove database persistence. A TCP connection can be established while firewall buffers await flushing.

## Received events but none inserted

Check **Queue Depth**, **Spool Usage**, **Events Inserted**, and **Last Error**. A growing queue with database errors means durable buffering is active. Verify ClickHouse credentials, network reachability, schema migrations, and available storage. Verify PostgreSQL inventory/metadata writes as well when they are part of delivery completion. Never remove undelivered WAL files or reset the database simply to clear an error.

Check free space on the encrypted data volume and the configured spool limit. TCP intentionally waits when the spool is full. UDP persistence failures are counted but cannot backpressure the source. Restarting with a corrupt/checkpoint-inconsistent spool fails visibly to protect evidence; preserve the directory and investigate before recovery.

## Parsing failures

Open **Administration → Diagnostics → Parsing**, inspect sender and suspected type, then view raw evidence privately.

- A different vendor on a shared Syslog port is not a malformed PAN-OS firewall record.
- Confirm the firewall uses standard CSV, not a custom field order or CEF/LEEF.
- Include the PAN-OS software release, native type/subtype, parser version, schema ID, and exact error in a bug report. Supply a thoroughly sanitized sample only.
- New native families or changed layouts are retained rather than guessed. The new dedicated DNS Security type introduced in PAN-OS 12.1.2 is distinct from older DNS-related Threat records.
- Compare the same sequence/session against PAN-OS Monitor or an XML API log record. Verify actual values, not just `parse_status=parsed`.

## Logs exist but searches are empty

Check category, time range, filter, and timezone. Clear the filter and try Unified with a recent range. High-resolution receive timestamps include their offset; legacy generated timestamps require the configured firewall timezone. A browser's local display timezone is separate from UTC database storage.

Use **Add Filter** or query validation to locate syntax errors. Quoted rule names must remain quoted, for example `( rule eq "Default Outbound" )`. The query compiler supports IPv4 and IPv6; a hostname resolution result never replaces the original IP address.

## TLS failures

Verify the Syslog profile uses **SSL**, the server port matches the TLS listener, the listener has its certificate/key, the firewall trusts the issuing CA, the certificate's SAN matches the configured destination, and the clocks are correct. If client certificates are required, verify the firewall's secure Syslog certificate selection and the collector's client-CA policy.

From an appropriate diagnostic host:

```sh
openssl s_client -connect <NEBULALOG-HOST>:6514 -servername <CERTIFICATE-HOSTNAME> -CAfile <TRUSTED-CA.pem> -verify_return_error
```

A successful TLS handshake does not prove the sender uses the correct Syslog framing or forwards events. Do not disable certificate verification or SELinux to make a test pass. See [TLS](TLS.md) and [Syslog framing](SYSLOG.md).

## Search or DNS seems slow

Compare query duration, database health, result count, and disk usage. Use a bounded time range and a selective field filter. DNS runs asynchronously and cannot block event ingestion/search. Pending or negative hostname resolution results can reflect configured resolver reachability and timeout limits. Large exports should be monitored as jobs; avoid opening multi-gigabyte CSV files in a browser.

For security, storage, update, or authentication failures, record observed status and relevant component versions. Do not present development-container status as proof of Rocky FIPS, LUKS, SELinux, or compliance certification.
