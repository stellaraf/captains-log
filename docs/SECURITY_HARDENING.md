# Security hardening

## October 12 native baseline assessment

The unconfigured Rocky qualification guest completed read-only assessments with
the pinned bundled appliance tailoring. CIS reported 188 pass, 186 fail and 21
not applicable; STIG reported 183 pass, 241 fail, 31 not applicable and 9 not
checked. These are pre-remediation observations, not release acceptance. The
unselected-rule counts are excluded from those totals. Both scans returned the
OpenSCAP findings exit code, and no remediation was requested.

Reports, result XML, command logs and file digests are retained in
`outputs/native-baselines-001/` under the T9 build root. `triage.json` intersects
native failures with the generated scripts' missing-remediation rules.

Five CIS failures lack packaged Bash fixes: separate `/var/tmp`, GRUB password,
root recovery password, SSH access restrictions, and the journald/rsyslog choice.
The installer recipes now allocate a 4 GiB XFS `/var/tmp` with
`nodev,nosuid,noexec`; both pass the Rocky RHEL9 Kickstart validator, but the new
layout still requires installation and boot verification. The initial console
now includes GRUB recovery enrollment; native enrollment/reboot acceptance is pending.
Build-only SSH/account findings must be reassessed after sealing.

STIG additionally exposes controls concerning authorized local users, time and
DNS configuration, bootloader administrator identity, supported OS evidence,
sudo SELinux context, certificate mapping and user namespaces. Some require
deployment configuration or manual assessment. None is waived by this record;
their applicability and final effective behavior remain release requirements.

## Architecture and release gates

The initial HARDENING action enrolls a separate GRUB recovery identity before
running baseline remediation. The operator chooses a non-default username and
password and acknowledges storing both off the appliance. Enrollment uses the
vendor PBKDF2 tool with 100,000 iterations. Plaintext goes through standard input,
never command arguments or the transaction journal. The encrypted setup directory
retains the original configuration and planned password hash for resumption.

The initial-hardening locks and host security gate apply, and changes are refused
after AIDE enrollment or setup completion. Unknown existing credentials and
unexpected boot-file changes require explicit recovery review. Regeneration must
pass GRUB syntax checking and match the planned recovery identity. The comparison
permits only unchanged, unique `fips=` and `boot=` arguments to move, as observed
with native FIPS tooling; other argument order remains significant. The installed
configuration retains the original argument order. Interrupted enrollment
can resume the retained transaction without generating a different credential.
These source guarantees still require native configured-guest and reboot tests.

Baseline remediation binds the completed GRUB enrollment receipt before making
changes. After verifying its captured inputs, result artifacts and host security,
it may refresh the expected GRUB configuration hash under the same hardening
locks. The recovery template, credential and authentication block must remain
intact, and the resulting configuration must pass GRUB syntax checking. The
receipt records the policy, remediation identity and previous/current hashes.
This permits a later hardening attempt after legitimate GRUB regeneration;
missing or changed recovery authentication, incomplete enrollment and unrelated
receipt changes remain refusals. A failed remediation does not authorize refresh.

Native tooling probes generated the expected PBKDF2 format and a syntax-valid
GRUB configuration. The comparison accepted the observed FIPS argument movement
and rejected a changed `fips=` value. Evidence: `logs/native-grub-tool-probe.log`
and `logs/native-grub-comparison-final.log` in the T9 build root. These probes did
not perform appliance credential enrollment or prove reboot authentication.

The production architecture requires install-time FIPS, encrypted application persistence, SELinux Enforcing, firewalld default deny, auditd, file integrity monitoring, authenticated access and least-privilege containers. These are release gates, not claims inferred from a developer Compose deployment.

The image recipe supplies minimum kernel/sysctl controls, separate host log/audit/tmp filesystems, audit watches, a daily AIDE check timer, SSH-disabled sealing and public-key-only build SSH. [AIDE preparation and explicit enrollment](AIDE.md) bind the initial database to a sealed appliance's static runtime configuration and captured host source, before its final SCAP assessment/review and setup completion. Final completion requires a recent enrolled clean check. The timer reports missing enrollment as failure, and findings never reset the baseline. This console workflow and actual SELinux/timer execution still require guest qualification; normal Administrator UI management is not yet connected. Full CIS/STIG remediation is not accomplished by the supplied minimum controls.

Quadlets use immutable image references rendered from approved release metadata, no privileged flag, no container socket, no public database ports, non-root container UIDs and dropped capabilities. UID ownership, image entrypoints, read-only roots and SELinux contexts must be tested on the actual images. The host manager has narrow fixed operations; no endpoint accepts arbitrary shell or SQL.

Inbound production defaults are TCP 443 only. Configured Syslog can open UDP/TCP 514 and TLS 6514; restrict senders by network and firewall where possible. SSH stays disabled unless an administrator explicitly enables a documented recovery mode. Use host firewall rules and inspect effective Podman network rules: port publication can introduce rules whose interaction must be verified. Database administration remains on the private container network.

Application tokens, database passwords, TLS keys, export files, retained raw logs, manager journals and backup scratch are sensitive. The encrypted data mount must be required before service startup. Audit captures administrative actions, retention changes, authentication configuration, updates and storage operations without logging secrets.

The first-boot wizard, HTTPS edge configuration, module validation, audited manager/UI bridge, baseline remediation and a complete host assessment are not yet release-qualified. Do not disable an enforcement check to make an incomplete image appear ready. See [FIPS](FIPS.md), [SELinux](SELINUX.md), [compliance](COMPLIANCE.md) and [updates](UPDATES.md).

### Unified coverage gate

A Unified control register must cover every rule selected by each original
reviewed CIS/STIG profile, including rules later excluded by appliance tailoring.
Each benchmark rule appears in exactly one decision; omissions, repeated rule
references, and references to unselected rules are refused. This prevents a
partial register from claiming complete coverage. The inventory supports the
vendor content's explicit rule and group selections, including disabled parent
groups. Inherited profiles, cluster selectors, and unresolved item inheritance require resolved content
and are refused rather than guessed. This is a coverage check, not approval of
the decision's technical merits or proof of compliance.

The bundled Unified conflict mapping and native combined remediation remain
pending. Separate CIS/STIG remediation is not treated as equivalent to Unified.
Selection semantics follow the [NIST XCCDF 1.2 specification](https://csrc.nist.gov/pubs/ir/7275/r4/upd1/final).

### Native algorithm-policy observation

The guest collector exercises OpenSSL's active fetch policy: SHA-256 with default
properties and with `fips=yes` must both produce the known empty-input digest;
a default MD5 fetch must fail as unsupported. A missing command or incorrect
digest does not count as successful enforcement. This checks the host OpenSSL
CLI only. Application/container crypto boundaries and kernel self-test diagnostics
remain separate requirements.

### Reviewed parent-group enablement

Combining profiles requires respecting parent groups: enabling a child rule does
not activate it when its parent remains disabled. Tailoring may now enable a
named source group only with an explicit rationale, effective control, and the
exact sorted inventory of every descendant rule. Duplicate, unknown, incomplete,
and disabling group decisions are refused. The setup console displays the group
and its affected-rule count alongside the other tailoring decisions.

A native Rocky OpenSCAP fix-generation check against pinned content
`769e4de0ee8ee67334745f97088043591d97694f3f494d07d9d0fa44fed02a51`
confirmed that selecting `service_fapolicyd_enabled` under the CIS profile alone
did not emit that fix; explicitly enabling its reviewed parent group did. Both
XML documents passed XSD validation, and generated shell passed syntax checking.
No generated fix was executed. This establishes selection behavior, not
application compatibility or completion of the Unified conflict mapping.

### Single-pass Unified remediation contract

A reviewed policy may now supply `unified_remediation`: one explicit tailored
profile derived from the same pinned STIG datastream used by both assessments.
The complete conflict register must bind its content, effective profile and
exact tailoring hash. Every control records `applied_rule`, selecting a rule from
that control's CIS/STIG pair, or null only for an explicit application exception.
The validator resolves the merged rule/group selections and requires exact
agreement with the applied-rule set. It refuses missing decisions, additional
selected rules, omitted rules and mismatched content. Value selections remain
bound to the reviewed XML and named source selectors.

Remediation invokes that effective profile once and retains the exact conflict
register with its input hashes. Changed evidence during execution fails acceptance.
The resulting receipt still requires separate CIS and STIG assessments and review;
it is not a compliance approval. Source tests cover this execution contract. A
complete bundled conflict register, application-compatible settings, and native
combined remediation remain pending before Unified can be offered out of the box.

### Container bridge forwarding exception

Both bundled profiles exclude their host IPv4 forwarding-disable remediation:
CIS `sysctl_net_ipv4_ip_forward` and STIG
`sysctl_net_ipv4_conf_all_forwarding`. The shipped Quadlets use the rootful
`nebulalog` bridge and publish ingestion ports 514/TCP, 514/UDP and 6514/TCP.
Turning off host forwarding conflicts with those paths. Netavark's
[pinned bridge implementation](https://github.com/containers/netavark/blob/v1.16.1/src/network/bridge.rs#L562-L578)
explicitly enables forwarding for non-internal bridges. This source review does
not establish the installed Netavark version or prove guest reachability.

The catalog discloses the exception during content acceptance. It does not add
an unrestricted firewall policy or claim benchmark compliance. Native acceptance
must test allowed ingestion and management, denied transit between external
interfaces, denial of unpublished database ports, and reboot persistence.
IPv6 forwarding and redirect protections remain selected. Independent CIS/STIG
findings and the required exception review remain release gates.

Rocky OpenSCAP 1.3.14 against the pinned datastream passed XSD validation and
shell syntax checking for both revised profiles. Fix generation included each
forwarding-disable rule in its stock profile and omitted it in its tailored
profile, while retaining `sysctl_net_ipv4_conf_all_accept_redirects`. No fix was
executed. Thirty focused factory, tailoring and remediation tests also passed.
