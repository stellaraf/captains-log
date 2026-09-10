# Forward PAN-OS logs to Captain’s Log

These instructions use the firewall's standard CSV syslog format. Do not configure a custom message format. Captain’s Log is independent of Palo Alto Networks.

## Before configuration

Open Captain’s Log **Administration → Diagnostics → Syslog** and confirm the intended listener is running. Use the appliance's reachable address, not localhost. Production defaults are UDP 514, TCP 514, and TLS 6514; community/developer deployments can map other ports, such as TCP 5514. Match the port in both places. Prefer TLS across networks where log confidentiality matters; TCP provides transport backpressure but does not encrypt messages.

For TLS, use **Encrypted log forwarding → Download Syslog CA Certificate** in Diagnostics. Compare its CA fingerprint with the trusted appliance console, import the public PEM on the firewall as a Trusted Root CA without a private key, and select **SSL / 6514** in the syslog server profile. Use a reachable server name/IP covered by the certificate. See the [certificate download and trust instructions](SYSLOG.md#download-appliance-trust-for-palo-alto), including the distinction from an optional firewall client certificate.

Allow the selected transport through intermediate firewalls and the appliance firewall. For an appliance using a public certificate, the firewall must trust its issuer and validate the hostname. See [TLS](TLS.md). Confirm that firewall and appliance clocks use reliable NTP. Configure Captain’s Log’s PAN-OS timezone to match the firewall when legacy generated timestamps do not include an offset.

Read the firewall's pending configuration before making changes. A commit can activate unrelated candidate changes. Preserve existing forwarding profiles and destinations; additive forwarding is usually the safest migration path.

## 1. Create the syslog destination

In PAN-OS, select **Device → Server Profiles → Syslog → Add**.

1. Name the profile **Captain’s Log**.
2. Add a server and enter the reachable Captain’s Log IP or hostname.
3. Select **UDP**, **TCP**, or **SSL**. PAN-OS calls TLS transport **SSL** in this field.
4. Enter the matching listener port: normally 514 for UDP/TCP or 6514 for TLS.
5. Use **BSD** or **IETF**, as supported by your forwarding requirements. Both envelope formats are supported. BSD over TCP normally uses newline framing; IETF can use octet counting.
6. Select the desired facility. Leave **Custom Log Format** unchanged.

Creating a Syslog Server Profile alone **does not cause Traffic logs to forward**. Continue with the forwarding profile and security rules.

## 2. Create the data-plane forwarding profile

Select **Objects → Log Forwarding → Add**, name the profile **Captain’s Log**, and create match-list entries for the categories you need. Choose the Captain’s Log Syslog profile in each entry. A match filter of **All Logs** forwards that category without additional filtering.

Available categories depend on PAN-OS release and licenses. Common choices are Traffic, Threat, URL Filtering, WildFire, Data Filtering, Authentication, Decryption, and Tunnel Inspection. PAN-OS 12.1.2 and later also expose DNS Security forwarding. A category being forwardable does not prove that Captain’s Log has a verified native parser for every release; unsupported messages are retained in Parsing diagnostics. See [Syslog support](SYSLOG.md).

If a security rule already references a forwarding profile, preserve its destinations. Add a Captain’s Log match to a verified copy of that profile or extend the existing profile deliberately; replacing the rule's profile with a new empty profile would remove previous forwarding.

## 3. Attach the profile to security rules

Select **Policies → Security**, edit each applicable rule, and open **Actions**.

- Set **Log Forwarding** to the prepared Captain’s Log profile.
- Recommend **Log at Session End** for useful final byte counts and session-end reasons.
- Enabling **Log at Session Start** can generate an additional record before final application identification; use it only when needed.

Do not change traffic actions, address/service/application matches, or security profiles merely to enable logging. If logging is currently disabled, enabling it is a separate, deliberate change. Review default security-rule logging as well if denied interzone traffic is required.

## 4. Configure management-plane forwarding

Select **Device → Log Settings** and configure the relevant categories, such as **System**, **Configuration**, **User-ID**, **HIP Match**, **GlobalProtect**, and **IP-Tag**. Add a match-list entry referencing the Captain’s Log syslog profile. Preserve existing entries and destinations.

These settings are separate from Objects → Log Forwarding. Security-rule forwarding does not automatically cover management-plane events.

## 5. Commit and verify

Review the candidate diff, then **Commit**. Wait for the commit job to finish successfully; an enqueued job is not proof the configuration is active.

In Captain’s Log:

1. Open **Administration → Firewalls**. Verify the firewall serial, device name, sender address, and Last Seen time.
2. Open **Logs → Traffic**, choose a recent time range, and allow existing sessions to end or generate ordinary permitted traffic.
3. Apply a known filter, such as `( app eq dns-base )` or `( port.dst eq 443 )`.
4. Open a row's details and compare raw message fields with PAN-OS Monitor → Logs for the same event/session.
5. Check **Administration → Diagnostics → Parsing** for unsupported or malformed messages, and **Diagnostics → Syslog** for queue, spool, insertion, and error status.

A connection can be established before the firewall flushes its forwarding buffers. Distinguish firewall events sent, collector messages received, and database events inserted. Do not treat a healthy web page as proof of log delivery.

## Validated device and limits

A PA-1410 running PAN-OS **12.1.4-h8** was configured additively and tested against a real local deployment. Traffic, DNS-related Threat, System, URL Filtering, and Data Filtering events were stored and parsed; selected fields were independently checked against firewall XML API records. See [the recorded evidence](validation/PALO_REAL.md). This is not a claim that every PAN-OS family/version or a production OVA has passed acceptance.

Official references: [Configure Syslog Monitoring](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring), [Configure Log Forwarding](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/configure-log-forwarding/configure-log-forwarding-pan-os), and [standard syslog fields](https://docs.paloaltonetworks.com/ngfw/help/12-2/syslog-field-descriptions).
