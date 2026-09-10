# AIDE checks in the inspected Rocky SCAP content

This is a source inspection, **not a passing guest assessment**. On 2026-09-07 the official `scap-security-guide-0.1.81-1.el9_8.rocky.1.1.noarch.rpm` was downloaded and its `ssg-rl9-ds.xml` extracted without installing it. The datastream's SHA-256 is `716e6b620d990079b1159d3cf4fcb9fe61d42a0cdd3820645f4528aafee4ff3b`, matching the content recorded in [COMPLIANCE.md](COMPLIANCE.md). The findings below come from that exact compiled XCCDF/OVAL content, rather than the current upstream branch. [Official Rocky RPM](https://download.rockylinux.org/pub/rocky/9.8/AppStream/x86_64/os/Packages/s/scap-security-guide-0.1.81-1.el9_8.rocky.1.1.noarch.rpm)

## Recognized configuration

All the configuration checks below read `/etc/aide.conf`. They do not follow an appliance-specific `--config` invocation or expand arbitrary AIDE includes and rule groups.

| Rule suffix | Selected profiles | What the exact OVAL checks |
| --- | --- | --- |
| `package_aide_installed` | CIS and STIG | RPM package `aide` exists. |
| `aide_build_database` | CIS and STIG | Installed package plus existence of a path assembled from `DBDIR` and the database filename in `/etc/aide.conf`. It does not prove a successful check or reviewed enrollment. |
| `aide_check_audit_tools` | CIS and STIG | Seven explicit tool rules with a fixed literal attribute sequence in `/etc/aide.conf`. Broad `/usr` coverage and group references do not satisfy the text checks. |
| `aide_periodic_cron_checking` | CIS | A recognizable direct `/usr/sbin/aide --check` cron command. There is no systemd timer alternative in this datastream. |
| `aide_scan_notification` | STIG | A cron line containing `/usr/sbin/aide --check` piped to `/bin/mail -s` with a recipient resembling an email address. It does not measure delivery. |
| `aide_use_fips_hashes` | STIG | Every matching uppercase group definition contains `sha512`, and no matching group contains the listed rejected hash names. |
| `aide_verify_acls` | STIG | Every matching uppercase group except `ALLXTRAHASHES` contains `acl`. |
| `aide_verify_ext_attributes` | STIG | Every matching uppercase group except `ALLXTRAHASHES` contains `xattrs`. |

The full rule ID is `xccdf_org.ssgproject.content_rule_` followed by the suffix. The inspected CIS Server Level 2 profile is `xccdf_org.ssgproject.content_profile_cis`; STIG is `xccdf_org.ssgproject.content_profile_stig`. These retain the benchmark/version qualifications documented in [COMPLIANCE.md](COMPLIANCE.md).

### Database path

`oval:ssg-object_aide_build_database_dirpath:obj:1` extracts `DBDIR` from:

```text
^@@define[\s]DBDIR[\s]+(/.*)$
```

`oval:ssg-object_aide_operational_database_filename:obj:1` extracts only the final filename from:

```text
^database(?:_in)?=file:(?:@@{DBDIR})?/(?:[a-z.]+/)*([a-z.]+)$
```

`oval:ssg-variable_aide_operational_database_absolute_path:var:1` concatenates the first extracted value, `/`, and that filename. Therefore a literal absolute `database_in` path alone is insufficient: the checked configuration also needs the matching `DBDIR` definition. Spaces around `=` are not recognized by this pattern. For the appliance's active database, a consistent managed header is:

```text
@@define DBDIR /var/lib/nebulalog/manager/aide
database_in=file:@@{DBDIR}/aide.db.gz
```

The manager may render a matching literal input path instead, provided `DBDIR` still agrees. The real database must already have passed the manager's explicit enrollment and integrity checks; the SCAP file-existence test does not replace them. The managed default configuration must be installed before the initial AIDE snapshot and remain byte-identical across later checks. It must be verified as an intentional managed package configuration, separately from unmodified packaged binaries.

### Audit tools and attribute groups

The seven tool objects match explicit paths ending in `auditctl`, `auditd`, `ausearch`, `aureport`, `autrace`, `rsyslogd`, and `augenrules`, under `/sbin` or `/usr/sbin`. Their shared state, `oval:ssg-state_aide_check_attributes:ste:1`, accepts only:

```text
^p\+i\+n\+u\+g\+s\+b\+acl(|\+selinux)\+xattrs\+sha512$
```

The appliance's broader typed rules and additional metadata attributes can provide coverage without matching that textual form. Any change to specific tool rules must retain the intended real coverage and be verified with AIDE; do not remove stronger attributes merely to change the scanner result.

The STIG group checks also interpret a directory-only metadata group as if it needed a content hash. An explicit directory group without `sha512` consequently fails this content's `aide_use_fips_hashes` check. Preserve the original finding and document the exact policy and file-type behavior in review; a text match is not evidence of cryptographic module qualification.

### Scheduling and notifications

The periodic rule's four alternatives inspect `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron/root`, and `/etc/cron.daily` or `/etc/cron.weekly`. They do not inspect `nebulalog-aide.timer`, its last execution, the manager's receipt, or its guards. The notification rule inspects cron files for a direct mail pipeline. A private report and a failed systemd unit are not delivered administrator notifications.

Do not add comments, dummy cron jobs, or a second unmanaged invocation to manufacture a pass. Retain the actual failed rule and review the timer's measured operation as a compensating control where authorized. Notification delivery remains a separate functional gap until implemented and tested. Any future reviewed SCAP tailoring must retain provenance and must not silently convert the original automated result into a pass.

## Remaining runtime evidence

The exact installed scanner must evaluate the selected datastream in the sealed, configured Rocky guest. Required evidence includes the managed configuration's parser check, access to the encrypted database under enforcing SELinux, explicit database enrollment, a clean real check, timer execution and failure reporting, actual SCAP results, and installation-bound findings review. Source patterns alone establish none of these runtime outcomes. The pre-finalization AIDE phase must use measured host/runtime readiness; requiring an already completed setup would place AIDE initialization after the baseline review that needs it.
