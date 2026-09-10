# Host file-integrity baseline and checks

The appliance has an explicit AIDE preparation/enrollment/check lifecycle with actions in the guarded first-boot virtual console. No Linux login or developer root shell is needed to use that menu. The timer invokes the manager and fails visibly if no database has been enrolled; it no longer silently skips a missing distribution database. This next-candidate console integration is not an in-app Administrator workflow, a compliance result or guest qualification. No build-time baseline is generated.

The inspected Rocky 9.8 package is `aide-0.19.2-5.el9_8.1.x86_64`. It supplies AIDE and its configuration, but no packaged check service/timer. Its configuration uses `database_in`, while the older `database=` directive is removed. The manager deliberately supports the observed 0.19.2 interface and records the exact package and executable hash; another version requires review. [Official Rocky package](https://download.rockylinux.org/pub/rocky/9.8/AppStream/x86_64/os/Packages/a/aide-0.19.2-5.el9_8.1.x86_64.rpm)

AIDE normally initializes a new database and activates it separately. System changes must be reviewed before updating that trusted baseline. Captain’s Log implements the separate review explicitly and never invokes `--update` or promotes findings automatically. [RHEL 9 AIDE lifecycle](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/checking-integrity-with-aide_security-hardening)

## Initial enrollment before final setup completion

First finish the sealed appliance's static settings, runtime provisioning and initial software enrollment, then select its security baseline. The AIDE-specific gate requires `FirstBoot.gate()` to pass the actual FIPS kernel/tool, FIPS policy, SELinux Enforcing, firewall/audit and enrolled LUKS/XFS checks. The protected `runtime-ready.json` must identify this installation and all runtime checks; the encrypted runtime journal must have all eleven stages complete, initialized identity and no active stage. Final setup may still be incomplete. The general host-job storage gate continues to require completed setup; this narrowly scoped AIDE phase does not weaken that gate.

The sequence is **static runtime configuration and selected security policy → AIDE prepare/review/enroll/clean check → SCAP assessment and findings review → final setup completion**. Administrator MFA/recovery enrollment, verified disk-recovery export and received Syslog also remain mandatory before final completion. This order permits the real AIDE database to exist for the assessment without first waiving its missing-database rule. Merely installing AIDE, enabling its timer or providing a version string does not establish readiness.

Preparation additionally requires `/etc/nebulalog/bootstrap/image-state` to contain `sealed`, absence of the disposable `packer` account/home/sudo policy and private build markers, and completed initial software enrollment. The initial component state must still match that enrollment. The captured source manifest must match the actual installed manager/adapters Python source and AIDE helper/policy/default configuration/units. It binds the runtime-ready receipt and encrypted setup/runtime-state hashes; the selected policy must belong to this installation and match the setup baseline. A later edit cannot be attributed to an older captured source simply because its base Git commit matches. Candidate provenance records `source_dirty` without converting it into a clean-release claim.

On the unfinished sealed appliance's graphical console, resume setup and select **FILE INTEGRITY**. The menu verifies runtime identity/readiness and the already enrolled, reviewed security policy before allowing lifecycle actions. A recorded baseline name alone does not qualify. If that policy is absent, invalid or expired, the menu states the prerequisite and returns without creating a candidate. Policy content enrollment and SCAP findings review still require their separate qualified operator workflow; this menu neither implements nor invents those approvals.

| Console action | Effect |
| --- | --- |
| `STATUS` | Reads enrollment and the latest measured check or interrupted/error state. |
| `PREPARE` | Explicitly creates or resumes the owned candidate, scans it, then displays validated review evidence. It does not activate a database. |
| `REVIEW` | Reads an existing prepared candidate and its original verified report without initialization, another scan, or writes. |
| `ENROLL` | Requires a candidate displayed in this console session and the complete confirmation SHA-256 typed by the operator. It activates only that exact reviewed candidate after the backend rechecks it. `CANCEL` leaves it unchanged. |
| `CHECK` | Performs a real comparison against the enrolled database and displays safe counts, time, state and report ID. It never initializes or replaces a baseline. |
| `BACK` | Returns to the setup menu without completing setup. |

The review shows the installation/candidate identities, captured source and policy hashes, exact database digest, checker version, original clean report counts/time, monitored scope and confirmation digest. It does not print raw reports, filenames or command diagnostics. Known incomplete or changed state is retained for qualified recovery. Interrupting a prompt or operation returns through the guarded console's retry handling; reviewing a saved candidate does not call `prepare()` implicitly.

Every user wait is followed by a fresh local-terminal and unfinished-sealed-image check. The complete typed digest is passed to `Aide.enroll()` rather than automatically substituting the displayed value. Existing enrolled candidates can only retry that same verified enrollment. There is no reset, arbitrary path, policy body, command entry or shell fallback.

For qualified automation or an operator already using an authorized root console, the underlying fixed helper remains available:

```sh
/usr/libexec/nebulalog/nebulalog-aide prepare
```

This creates a private candidate database, validates its compressed stream, then performs a real filesystem comparison against it. A positive entry count, complete supported JSON report, no diagnostics, unchanged candidate bytes and fresh host/monitor checks are required. The result contains the candidate UUID, exact database SHA256, source/package/policy identities, verification report UUID and a `confirmation` SHA256. It does **not** activate the baseline.

Review the approved installation provenance, monitored scope, candidate record and private report on this trusted appliance. The fixed policy is `/usr/share/nebulalog/aide/policy.conf`; the proposal is `/var/lib/nebulalog/manager/aide/candidate.json`; reports are under the same private directory's `reports/` child. The candidate database contains file metadata and checksums, not a proof that the initial machine was uncompromised. Accept only a known, reviewed initial state.

Then supply the exact returned confirmation:

```sh
/usr/libexec/nebulalog/nebulalog-aide enroll --confirmation=<reviewed-confirmation-sha256>
/usr/libexec/nebulalog/nebulalog-aide status
/usr/libexec/nebulalog/nebulalog-aide check
```

Enrollment verifies the bound original review report before new scan/configuration writes, rechecks the candidate against the current filesystem, and revalidates both host/source identity and the original report before copying the exact reviewed bytes into the active database. It stores a durable commit proposal and permanent enrollment receipt. The receipt includes the installation UUID, candidate confirmation, database hash, source/monitor evidence, verification report UUID and enrollment time. Subsequent enrolled-state checks also require the intact original report; a newer clean report cannot conceal its loss or alteration. This is local root authorization; it does not invent an application actor, session or MFA assertion.

After the separate SCAP assessment and review, final setup calls the read-only `aide.firstboot_checks(installation_id)` integration. It requires an explicitly completed routine check, an enrolled matching database, intact report/receipt hashes, the current installation and checker identity, positive monitored entries and a clean exit. The completed observation must be no more than **300 seconds old** and not in the future. If assessment/review took longer, run `nebulalog-aide check` again immediately before final completion. Newer failed or interrupted attempts invalidate an earlier clean result.

The integration returns exactly `aide_enrolled: true` and `aide_checked_clean: true` only when those conditions hold. It takes the existing manager lock nonblocking while its caller already owns firstboot/runtime locks; it does not reacquire those locks, write state, initialize a database or start another filesystem scan. Errors leave final setup incomplete. The receipt describes a recorded completed scan, not continuous filesystem integrity.

The helper CLI has only `prepare`, `enroll`, `check` and `status`; the first-boot menu also uses the internal read-only `Aide.review()` method. They accept no caller-selected path, command, arbitrary AIDE flag or policy body. A future typed host job integration can invoke the lifecycle behind independently verified action grants and an application review UI. No host-job operation or public endpoint currently enables it.

## Monitored scope and exclusions

[The fixed policy](../appliance/security/aide-policy.conf) covers `/boot`, `/usr`, `/etc`, `/root`, `/home`, `/var/spool/cron` and canonical encrypted `/var/lib/nebulalog/configuration`. That includes installed host code, units, executables, authentication/TLS configuration and appliance settings. Files use explicit file type, permission, ownership, link, inode, size/time, ACL, SELinux/xattr and SHA-512 attributes. The separate directory rule keeps type, permission, inode, ownership, ACL, SELinux and xattrs, while omitting size/timestamps/link count so creation of an intentionally excluded report does not dirty its parent. It does not use broad hash groups containing nonapproved algorithms. Offline image archives under `/usr/share/nebulalog/images` remain within `/usr` coverage; their scan cost must be measured on the actual appliance.

The precise planned setup transitions excluded from coverage are `/etc/nebulalog/configured`, the bootstrap audit journal and firstboot/runtime locks, and the baseline lock, assessment/review/attempt receipts, audit journal and `baseline-assessments` output directory. These allow the final assessment and completion markers to follow initial enrollment. The selected `security-policy.json`, SCAP content, encrypted setup/runtime configuration, TLS material and other static configuration remain covered. Changing those inputs after enrollment remains a real difference.

Live PostgreSQL/ClickHouse contents, container storage, WAL, temporary data, manager records and logs are excluded. Kernel runtime trees and a few explicitly named interactive history/cache files are also excluded. The monitor does not hash the AIDE database, reports or its own changing journal as monitored inputs. This is host/configuration coverage, not integrity validation of retained log contents or all application volumes. Runtime root symlinks under `/etc` do not replace coverage of the canonical encrypted configuration tree.

The manager renders complete fixed configurations for initialization, candidate verification and routine checks. Input/output databases always differ. There are no executable includes or stock-configuration overrides. Report settings precede `report_url=stdout`, because AIDE captures them when the destination is parsed. `database_attrs=sha512` controls reported database hashes separately from selection-rule file hashes; those reported hashes cover uncompressed database content. The manager's own SHA256 binds the exact compressed artifact bytes. [Upstream 0.19.2 report implementation](https://raw.githubusercontent.com/aide/aide/v0.19.2/src/report.c), [JSON fields](https://raw.githubusercontent.com/aide/aide/v0.19.2/src/report_json.c)

The source-owned `/etc/aide.conf` contains the same policy and active encrypted database, with `@@define DBDIR /var/lib/nebulalog/manager/aide` and `database_in=file:@@{DBDIR}/aide.db.gz`. This allows the pinned SCAP database-existence rule to inspect the real managed database. Its recognized size/hash/mtime difference from the distribution's stock configuration is accepted only alongside the separately verified captured configuration hash; binary or other package changes still refuse. Other pinned SCAP checks do not recognize this timer or all stronger policy rules. Those findings remain visible and require truthful review; no dummy cron entry or weakened rule is installed. See [the exact SCAP inspection](AIDE_SCAP_REVIEW.md).

## Periodic results and failures

`nebulalog-aide.timer` requests a daily check with up to one hour of random delay and a persistent missed-run trigger. Its service requires first boot and the encrypted mount, then invokes only `nebulalog-aide check`. It has a bounded runtime and no `ConditionPathExists` or `SuccessExitStatus` that would conceal missing enrollment or differences. `ProtectSystem=full` protects system configuration/code while preserving the real writable data-mount view required by the storage gate. Actual systemd/SELinux execution remains a guest test.

For `--check`, AIDE's exit bits are 1 added, 2 removed and 4 changed; combinations 1–7 represent findings, not operational success. The parser checks these bits against positive JSON counts and listed entries. Exit 0 requires a positive total and a complete clean report. Operational exits, warnings, malformed/missing reports, mismatched database identity and unsupported versions become errors. [Official Rocky manuals in the package](https://download.rockylinux.org/pub/rocky/9.8/AppStream/x86_64/os/Packages/a/aide-0.19.2-5.el9_8.1.x86_64.rpm)

The helper preserves clean/finding exit codes 0–7 and returns 78 for refused/invalid operations. Its JSON distinguishes `clean`, `differences` and `error`; systemd sees nonzero findings as a failed check needing review. The full bounded report stays encrypted. Only counts, state, timestamps, hashes and report IDs reach ordinary helper output; raw command diagnostics and filenames are never copied into error messages or the system journal.

Each routine check durably records its start before inspecting the monitor and records completion only after a second baseline hash/host/monitor check. A failed precondition supersedes an old clean result. An unfinished attempt is shown as interrupted after restart. Status validates active database bytes, monitor identity and report/summary correspondence; a report older than 48 hours, or dated in the future, is marked stale. A clean result describes the completed scan at its timestamp, not continuous proof of integrity.

Ordinary monitored file changes are still scanned against the original baseline, including legitimate configuration or software changes. Altered AIDE package/binary identity or policy instead blocks execution pending review of the checker itself. Findings and errors never replace the active database. A qualified baseline renewal/acknowledgment workflow, including authorized updates, is **not yet implemented**; do not delete receipts or run the distribution's `aide --update` to hide a difference. Preserve the report and original database for investigation and future reviewed reconciliation.

## Storage, retries and installation contract

All sensitive persistent state is on the verified encrypted data filesystem:

```text
/var/lib/nebulalog/manager/aide-enrollment.json
/var/lib/nebulalog/manager/aide/candidate.json
/var/lib/nebulalog/manager/aide/candidate.db.gz
/var/lib/nebulalog/manager/aide/aide.db.gz
/var/lib/nebulalog/manager/aide/commit-pending.json
/var/lib/nebulalog/manager/aide/{init,candidate,enrolled}.conf
/var/lib/nebulalog/manager/aide/last-attempt.json
/var/lib/nebulalog/manager/aide/last-result.json
/var/lib/nebulalog/manager/aide/reports/<host-issued-uuid>.json
/var/lib/nebulalog/manager/aide/tmp/
```

Directories are root-owned `0700`, records `0600`. Symlinks, hard-linked files, unsafe ancestors, different nested filesystems, changed artifacts and oversized input are refused. A shared manager transaction lock serializes scanning with supported storage/update operations. Initial preparation, enrollment and routine checks take coordination locks in manager → firstboot → runtime → baseline order and refuse concurrent work. Temporary files and child `TMPDIR` use the encrypted AIDE state. Each child is bounded to one hour, output is bounded, database writes are limited to 128 MiB and decompression to 512 MiB. A report is bounded to 8 MiB; reaching 1,000 retained reports refuses further checks rather than silently deleting evidence. Reviewed report retention and baseline renewal remain necessary before sustained production service.

Repeated preparation returns the same verified proposal; it never changes a prepared database. The candidate confirmation now also binds the original verification report's SHA256, allowing `REVIEW` to validate it even after later reports have been written. Older candidate records missing that binding are refused; there is no silent schema conversion or replacement. An interrupted initialization can resume only the owned candidate and must prove a clean comparison before presenting it for review. An interrupted enrollment can finish only its exact durable proposal. Active database/receipt loss or a mismatching hash fails closed. The permanent enrollment anchor is outside the replaceable AIDE directory, so deleting that directory cannot make the appliance appear never enrolled. Successful retries flush the database, receipt and all relevant directory entries, including an uncertain newly created manager directory. No automatic reset or initial-baseline replacement exists.

The first-boot wizard resumes a completed runtime only after independently checking the actual host foundation, installation/configuration digest, private receipt and complete encrypted runtime journal. It then avoids rewriting credentials, settings, journals or the runtime-ready receipt. An owned partial runtime can use guarded provisioning only while no AIDE state exists. Missing or inconsistent readiness alongside any candidate/enrollment refuses automatic reprovisioning. The host apply/provision methods enforce the same refusal before writes and again under their coordination lock.

Install these fixed artifacts:

- [Helper](../appliance/bin/nebulalog-aide) → `/usr/libexec/nebulalog/nebulalog-aide`, mode `0755`.
- [Policy](../appliance/security/aide-policy.conf) → `/usr/share/nebulalog/aide/policy.conf`, mode `0644`.
- [Default configuration](../appliance/security/aide.conf) → `/etc/aide.conf`, root-owned mode `0600`, followed by `restorecon`; install before the initial snapshot.
- [Manager](../appliance/nebulalog_manager/aide.py) and [pure parser](../appliance/nebulalog_manager/aide_report.py) through the existing manager-module installer.
- [Service](../appliance/systemd/nebulalog-aide.service) and [timer](../appliance/systemd/nebulalog-aide.timer) through the existing unit installer.

Persist the exact SELinux mapping `/var/lib/nebulalog/manager/aide(/.*)?` → `aide_db_t`; do not relabel the entire manager or data tree. The helper applies `restorecon` to its private tree before invoking AIDE. It captures stdout and writes reports itself, so no direct AIDE log destination is configured. The default distribution database directory has `aide_db_t`; default direct log paths have `aide_log_t`. [Rocky SELinux policy documentation](https://download.rockylinux.org/pub/rocky/9.8/BaseOS/x86_64/os/Packages/s/selinux-policy-doc-38.1.75-2.el9_8.noarch.rpm)

SHA256 bindings and protected local records detect corruption and inconsistent state. They do not provide an external trust anchor against privileged root tampering or rollback of all encrypted state. Off-appliance evidence retention, renewal authorization, management UI, monitoring alerts and actual guest crash/tamper/SELinux/timer qualification remain open. [Release acceptance S09](RELEASE_ACCEPTANCE.md) remains unverified until those real guest checks pass.

Validation:

```sh
PYTHONPATH=appliance:appliance/adapters python3 -m unittest discover -s appliance/tests -p 'test_aide*.py' -v
```

The tests use private temporary files and fixed command fixtures. They exercise all finding masks, invalid JSON/diagnostics, explicit enrollment, source/build-user gates, changed candidate bytes, failed/interrupted checks, summary tampering, lost anchors and crash/retry durability. Any escaped real subprocess fails the lifecycle fixtures; no appliance or development-host AIDE service was executed.
