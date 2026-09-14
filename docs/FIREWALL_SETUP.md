# Forward PAN-OS logs to Captain’s Log

These instructions use the firewall's standard CSV syslog format. Do not configure a custom message format. Captain’s Log is independent of Palo Alto Networks.

For complete available logging, configure both **event generation** and **forwarding**. An **All Logs** forwarding filter only sends records the firewall actually creates. It cannot recover events suppressed by a security profile or a disabled reporting option. Complete this guide for each firewall and virtual system, including inherited policies.

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

## 2. Forward every available data-plane category

Select **Objects → Log Forwarding → Add**, name the profile **Captain’s Log**, and add one match-list entry for **each available Log Type**. Select **All Logs** and add the Captain’s Log Syslog profile to every entry. Do not restrict the filter to high severity, blocked actions, malware verdicts, or selected rules.

Include **Traffic, Threat, URL Filtering, WildFire, Data Filtering, Authentication, Decryption, Tunnel Inspection, DNS Security, GTP, and SCTP** wherever the installed release, model, and licenses expose them. Compare this list with the firewall's actual Log Type selector; unavailable features do not need invented entries. PAN-OS 12.1.2 and later expose dedicated DNS Security forwarding. [PAN-OS forwarding profile fields](https://docs.paloaltonetworks.com/ngfw/help/12-1/objects/objects-log-forwarding)

A forwardable category may not have a verified Captain’s Log parser. Unverified native DNS Security, Tunnel, GTP, SCTP, and other unsupported wire families remain raw records in Parsing diagnostics. Keep forwarding them and consult the [parser support table](SYSLOG.md#schemas-and-categories); a dedicated UI category is not a promise of support for every wire format.

If a security rule already references a forwarding profile, preserve its destinations. Add a Captain’s Log match to a verified copy of that profile or extend the existing profile deliberately; replacing the rule's profile with a new empty profile would remove previous forwarding.

## 3. Cover every applicable rule and zone

In **Policies → Security → Actions**, enable **Log at Session End** and select the prepared forwarding profile on every applicable rule, including allow, deny, drop, exception, and bypass rules. Check local rules and Panorama pre/post rules. A rule that intentionally skips inspection still needs session logging and forwarding; record that inspection gap explicitly.

Select **intrazone-default** and **interzone-default**, use **Override** where required, and enable session-end logging and forwarding while preserving their traffic actions. These defaults otherwise leave same-zone permitted traffic and unmatched interzone denies unlogged. [Default-rule logging](https://docs.paloaltonetworks.com/best-practices/10-2/data-center-best-practices/data-center-best-practice-security-policy/log-and-monitor-data-center-traffic/what-data-center-traffic-to-log-and-monitor)

Session-end logging supplies final counters. Also enable **Log at Session Start** where immediate visibility into long-lived sessions is required; it adds an early record with incomplete counters and potentially incomplete application identification. Apply forwarding to applicable **Authentication**, **DoS Protection**, and **Network → Zones → Log Setting** configurations too. These associations are separate from Security rules. [Policy and zone forwarding](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/configure-log-forwarding/configure-log-forwarding-pan-os)

Keep traffic actions and address/service/application matches unchanged when setting up logging. If a rule or zone remains excluded, record its name and the resulting visibility gap instead of declaring coverage complete.

## 4. Enable the profiles that generate events

Review **Policies → Security → Actions → Profile Settings** for each allowed traffic path. Attach the appropriate Security Profiles or Security Profile Group and verify the matching profile rules, subscriptions, and content updates. A forwarding profile by itself does not perform inspection.

| Event family | Generation requirements |
| --- | --- |
| Threat and DNS detections | Applicable Antivirus, Anti-Spyware/DNS Security, Vulnerability Protection, or other inspection profiles must be attached and match the traffic. Check exceptions and disabled engines. Profile/signature actions of `allow` can suppress detection logs; use `alert` where traffic should remain permitted but the detection should be recorded. Preserve existing block/reset protections. [Security profile actions](https://docs.paloaltonetworks.com/ngfw/help/11-2/objects/objects-security-profiles/actions-in-security-profiles) |
| URL Filtering | Attach a URL Filtering profile. Set permitted categories to **alert** when their access must be logged: **allow** permits access without a URL log. Retain existing block, continue, and override decisions. [URL category actions](https://docs.paloaltonetworks.com/ngfw/help/10-2/objects/objects-security-profiles-url-filtering/url-filtering-categories) |
| Data Filtering and File Blocking | Attach the relevant profiles and review application/file type/direction matches and data-pattern thresholds. Use File Blocking **alert** to record permitted matching files, preserving existing blocking rules. Data Filtering is not an inventory of every transferred file. [File Blocking profiles](https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-profiles/security-profile-file-blocking) |
| WildFire Submissions | Attach a WildFire Analysis profile with the intended applications, supported file types, both transfer directions where required, and analysis destination. Verify cloud connectivity and completed analysis. Enable both verdict-reporting settings in step 5. [WildFire sample forwarding](https://docs.paloaltonetworks.com/advanced-wildfire/administration/configure-advanced-wildfire-analysis/forward-files-for-advanced-wildfire-analysis) |
| Decryption | In each applicable **Policies → Decryption → Options**, select logging for **successful and unsuccessful SSL/TLS handshakes** and the Log Forwarding profile. Successful handshake logging is disabled by default. Keep existing decrypt/no-decrypt decisions; some protocols and handshake outcomes do not produce Decryption records. Account for the added volume in log quotas. [Decryption logging](https://docs.paloaltonetworks.com/network-security/decryption/administration/monitoring-decryption/configure-decryption-logging) |
| Authentication, GlobalProtect, HIP Match, User-ID, IP-Tag, Tunnel, GTP, and SCTP | The corresponding feature must be deployed and an event must occur. Check its policy/zone forwarding or Device Log Settings association. A category can correctly remain empty when the feature is unused. |

Encrypted payloads outside the firewall's inspection coverage cannot produce the same file, URL, or threat detail as inspected traffic. Review inspection coverage separately; enabling syslog does not enable TLS decryption or authorize changing an inspection exception.

## 5. Include benign and grayware WildFire files

Open **Device → Setup → WildFire → General Settings** and enable **both**:

- **Report Benign Files**
- **Report Grayware Files**

Both are disabled by default. Without them, successful file submissions and benign verdicts can coexist with an empty **Monitor → Logs → WildFire Submissions** page. Keep the WildFire forwarding match at **All Logs**, including informational and low severity. PAN-OS does not log email links with benign or grayware verdicts even with these settings enabled. [Benign and grayware logging](https://docs.paloaltonetworks.com/advanced-wildfire/administration/monitor-wildfire-activity/configure-wildfire-submissions-log-settings/enable-logging-for-benign-and-grayware-samples)

These settings apply to future qualifying events after commit. They do not backfill submissions that were never logged. A file-submission counter or a verdict received from WildFire is not proof that a submission log was created or delivered to Captain’s Log.

## 6. Configure management-plane forwarding

Select **Device → Log Settings** and configure every available category, including **System**, **Configuration**, **User-ID**, **HIP Match**, **GlobalProtect**, and **IP-Tag**, plus Correlation where available. Add an **All Logs** match referencing the Captain’s Log syslog profile for each category. Include every severity, particularly **informational**; a warning-or-higher System filter omits normal administrative and service activity. Preserve existing destinations. [Management log forwarding](https://docs.paloaltonetworks.com/ngfw/help/12-1/device/device-log-settings/select-log-forwarding-destinations)

These settings are separate from Objects → Log Forwarding. Security-rule forwarding does not automatically cover management-plane events.

## 7. Commit and verify each category

Review the candidate diff, then **Commit**. With Panorama, commit and push the relevant device-group/template changes to the intended firewalls. Wait for successful completion and inspect the resulting running configuration; an enqueued job is not proof the settings are active.

Record the commit time. For each category, first find a fresh event in the firewall's own **Monitor → Logs** or native XML API log database. Use ordinary permitted activity that exercises the configured feature. For WildFire, wait for analysis to finish and verify the file's verdict in **WildFire Submissions**; submission/analysis counters alone are insufficient.

In Captain’s Log:

1. Open **Administration → Firewalls**. Verify the firewall serial, device name, sender address, and Last Seen time.
2. Open the corresponding **Logs** category, select the firewall, choose a time range after the commit, and clear old search/severity/verdict filters. For Traffic, allow the session to end before expecting final counters.
3. Apply a known filter, such as `( app eq dns-base )` or `( port.dst eq 443 )`.
4. Open a row's details and match the firewall serial, generated time, session/sequence ID, and relevant fields with the same native firewall event. For WildFire, also compare the file hash/name and verdict where present.
5. Check **Administration → Diagnostics → Parsing** for unsupported or malformed messages, and **Diagnostics → Syslog** for queue, spool, insertion, and error status.

A connection can be established before the firewall flushes its forwarding buffers. Distinguish firewall events sent, collector messages received, and database events inserted. Do not treat a healthy web page as proof of log delivery.

| Observation | Next check |
| --- | --- |
| No record in the firewall's own log database | Generation settings, matched rule/profile, license, feature activity, and analysis completion. For benign/grayware WildFire files, check both reporting flags. |
| Native record exists, collector receives nothing | Running forwarding associations and All Logs filters, service route, certificate trust/name, selected port, and firewall forwarding errors. |
| Collector receives the message but category is empty | Parsing diagnostics, raw wire type/subtype, insertion/spool errors, selected firewall, time range, and search filters. WildFire submissions use `THREAT` subtype `wildfire`; `wildfire-virus` belongs to Threat. |
| Feature is unused or its format is unverified | Record the category as inactive or unverified. Preserve received raw messages; do not mark end-to-end delivery passed without a matching stored event. |

Keep a per-category acceptance record with the native event identifier and the corresponding Captain’s Log event. Recheck coverage after adding rules, changing profiles, or upgrading PAN-OS.

## Validated device and limits

A PA-1410 running PAN-OS **12.1.4-h8** was configured additively and tested against a real local deployment. Traffic, DNS-related Threat, System, URL Filtering, and Data Filtering events were stored and parsed; selected fields were independently checked against firewall XML API records. See [the recorded evidence](validation/PALO_REAL.md). This is not a claim that every PAN-OS family/version or a production OVA has passed acceptance.

Official references: [Configure Syslog Monitoring](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring), [Configure Log Forwarding](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/configure-log-forwarding/configure-log-forwarding-pan-os), and [standard syslog fields](https://docs.paloaltonetworks.com/ngfw/help/12-2/syslog-field-descriptions).
