# OS update qualification

Automatic Rocky 9 security, minor-version and kernel updates remain a required, unfinished deliverable. The current executable slice proves a narrow real RPM transaction; it does not establish complete unattended OS updating.

## Implemented transaction

`os_payload.py` resolves downloads before mutation, retains exact RPM bytes outside the DNF cache, verifies signatures against an isolated keyring containing only the enrolled Rocky 9 key, and records the complete installed package inventory. The private signature database receives the existing system RPM database SELinux label; no policy or global keyring is changed.

The initial compatible transaction replaces existing Rocky 9 x86_64/noarch packages whose regular-file and directory paths remain unchanged. Package file hashes, size, mode and ownership must match the installed signed payload before mutation. New payloads must use SHA-256 file digests. Applicable installed package/file triggers, package scripts, config/ghost files, links, capabilities, privileged files and unqualified boot/checker/package-manager changes are refused before package installation. Shared regular files are refused. Excluded documentation remains absent; directory metadata remains unchanged.

Application uses `rpm --upgrade` with the retained package paths, after an exact `--test` pass. No solver is rerun and no dependency, signature, scriptlet, conflict or version check is disabled. The durable apply intent prevents automatic repeated installation after interruption. Recovery checks the actual installed package set and payload bytes without rerunning RPM.

The OS integrity plan has its own schema and operation/boot identity. It uses the existing retained AIDE `--update` database chain, including fresh checks, metadata preservation and compare-and-swap recovery. Only the exact planned regular files may change; additions, removals, unrelated paths and ACL/xattr/SELinux changes are refused. The original enrollment and original database remain immutable. A kernel or AIDE checker replacement cannot silently rewrite those original facts.

## Measured native result

On the disposable Rocky 9.8 x86_64 VMware guest, the signed `linux-firmware-whence` package was set to `20260707-161.1.el9_8` as an explicit test fixture, then upgraded by the exact executor to `20260804-161.2.el9_8`. The latter was the original installed version. This changes the real `/usr/share/licenses/linux-firmware-whence/WHENCE` payload. Both versions were downloaded from the official Rocky 9 BaseOS repository and verified against the enrolled Rocky key.

The live Rocky repository query reported **zero currently available upgrades** on this guest; the retained older signed package was therefore needed to exercise a real forward update. The installed inventory contained 451 packages. Header classification found only 8 candidates eligible for further inert-payload checks; most packages require additional metadata, scriptlet/trigger or migration recipes. This is a measurement of the current coverage gap, not a supported-package guarantee.

The real transaction passed, restored the original current package, and verified the new file hash. Corrupt retained RPM bytes, installed-file drift and a repeated transaction were each refused. The first native attempt exposed a private RPM key-database labeling problem; copying the existing RPM database label resolved it with SELinux still Enforcing. No package mutation occurred in that failed first attempt.

The joint real-RPM/full-host-AIDE test also passed on the native guest: a private baseline covered 35,328 entries, the signed RPM update changed exactly the expected WHENCE file with zero added or removed entries, and the subsequent full-host check was clean. All native AIDE commands had empty diagnostic output. The original database remained byte-identical and the installed appliance policy was not replaced. FIPS remained enabled and SELinux remained Enforcing.

The first full-policy attempt exposed an AIDE 0.19.2 compatibility defect: underscores in the two group aliases generated deprecation diagnostics, which the strict manager correctly refused. The source policy and generated default configuration now use alphanumeric aliases. Reversing those two literal replacements reproduces the original files byte-for-byte; monitored paths, attributes, rule order and exclusions are unchanged. The successful run used this corrected policy from a separate protected test directory. The original failed receipt and exact current-package restoration were retained. Existing frozen appliance candidates still contain the old policy and need a rebuilt baseline; no warning suppression or in-place policy migration was used.

The independent source tests cover the OS-specific AIDE chain, unrelated drift, metadata rejection and recovery after a database swap interruption. The native joint test exercises the real RPM executor and full-policy scans, not the production enrollment, timer or healthy-host acceptance path. Full appliance OS runtime acceptance remains unqualified. A private scan baseline is not production enrollment.

## Kernel lifecycle implementation and evidence limits

The kernel recipe plans the exact four signed Rocky kernel packages, resolves
their dependencies offline, and retains their bytes and vendor-script identities.
Installation preserves the running kernel and its persistent boot selection.
The recipe permits a fourth complete kernel set temporarily; another kernel
installation is refused until accepted retention returns the inventory to three.
Mixed kernel and unrelated package transactions remain unsupported.

The temporary kernel-default protection setting is published by an atomic,
same-directory replacement with exact owner, mode, ACL/xattr and SELinux
metadata. Immutable preimages, postimages and temporary-file identities bind
interruption recovery. A separate durable RPM-command sentinel distinguishes a
new schema-2 operation that never started RPM from an attempted command. Only
the former can perform its first execution after recovery; sentinel-present,
partial-inventory and legacy ambiguous operations remain held. Focused tests
exercise failures before and after replacement, changed identities and the
once-only execution boundary. Native interruption acceptance remains pending.

Before requesting a reboot, lifecycle verifies the retained backup, local
authentication and the intended candidate initramfs's encrypted-storage unlock
configuration. It stops services, syncs storage and arms one boot of the new
kernel. The old kernel remains the persistent default until the actual candidate
boot, full runtime/security checks and a separate measured promotion all pass.
GRUB changes use the original AIDE enrollment's authorized-change chain. Exact
abort restores the prior environment bytes. Interrupted arming, promotion and
subsequent boot observations retain their original intent and proof records;
they do not rewrite the original operation's boot identity.

Final acceptance uses immutable `kernel-acceptance-<boot UUID>.json` generations
and an atomic current pointer. A later boot links the prior acceptance digest
instead of replacing its evidence. `promotion_sha256` identifies the original
promotion plan; the recursive boot proof distinguishes a completed promotion
from an interrupted prepared intent. The optional `resume_sha256` identifies a
separately accepted later-boot transition. Candidate cleanup retains the first
acceptance and original pending reference, including when interrupted after
unlinking the pending pointer.

Retention requires that current acceptance, a fresh verified backup and all
runtime checks before removing only the oldest unprotected kernel. Its four
original signed RPMs must be retained in an owned transaction stage or the
factory provenance bundle; installed RPM database headers alone are insufficient.
An erase intent is never replayed automatically. Missing provenance and partial
erasure retain maintenance and recovery evidence. A refreshed backup keeps the
original operation's maintenance gate active and publishes an immutable intent
before updating its two journal references.

A later boot after an exactly completed erase now has a separate recovery
path. It revalidates the signed retained plan, exact remaining inventory,
protected kernels and qualified GRUB transition. A compound AIDE plan allows
only the original deletions, their permitted parent-directory metadata changes
and the measured GRUB environment change. Its authority links the original
erase intent and preparation, current backup and immutable boot-plan ancestry.
Recovery can retain a database already copied before interruption; it never
copies an unpublished historical database or reruns RPM. Fresh full scans must
pass before a new acceptance is published. A second reboot traverses only that
explicit ancestry, including an intermediate plan that was never prepared.

The optional `retention_integrity_sha256` acceptance field binds the published
compound AIDE evidence. Older immutable acceptances retain their original bytes
and provide no such authority. Runtime checks, final current-boot acceptance,
retention completion and another runtime postcheck precede maintenance release.
Kernel acceptance records establish the verified kernel and runtime checks;
they do not establish appliance-wide finalization. The operation journal and
maintenance gate remain pending until retention and its postcheck complete,
including when a crash leaves a new kernel acceptance already published.
Source tests cover the real AIDE report/database chain and lifecycle ordering;
native interrupted-erase recovery remains unqualified. A retained plan with no
erase intent from an earlier boot requires a new execution-generation workflow,
which is not yet implemented. An attempted but unchanged or partial inventory
remains held rather than automatically repeating the erase.

Factory builds now capture the exact installed four-package kernel set, its
signed RPM bytes and installed inventory. Sealing and initial AIDE enrollment
verify that retained bundle offline; enrollment records immutable manifest and
inventory digests. The verifier measures its original runtime dependencies
before importing them. Native capture, sealing and first enrollment remain
unqualified, and existing enrollments require an explicit migration. See the
[factory build instructions](../appliance/packer/RELEASING.md).

The source suites include real private-file transitions and a combined
boot/AIDE dispatcher, snapshot and retained-database chain. Their native host
identity, GRUB renderer and scanner inputs are controlled fixtures. A separate
native Rocky test established the real GRUB tool's 1024-byte format and exact
set/unset restoration on disposable private files, leaving live `/boot`
unchanged. A subsequent isolated VM, using separate disk overlays and copied
firmware state, exercised the exact `kernel_boot._replace` helper on its live
XFS `/boot`. The replacement changed the inode, preserved the exact bytes,
ownership, mode and SELinux/xattr metadata, and survived a real reboot. GRUB
consumed the one-time selection while retaining the persistent default. Both
selections identified the existing vendor kernel; this was a bootloader
mechanism test, not a new-kernel promotion or unattended unlock acceptance.
A second controlled boot confirmed the vendor reset of `boot_success=1` and
`boot_indeterminate=1` to zero while preserving the replaced inode and security
metadata. This also demonstrates why ordinary-boot flag reconciliation is
required; the native fixture did not authorize those changes through AIDE.
The original qualification VM and recovery disks were unchanged. None of these
results establishes a complete installed-appliance kernel update.

## Ordinary boots and late boot-success flags

Source now includes a separate ordinary-boot integrity owner. Initial AIDE
enrollment binds an immutable snapshot of the installed RPM inventory, boot
artifacts, kernel modules, GRUB configuration and qualified vendor flag writers.
Later observations are compared with that root plus the verified chronological
AIDE change chain. Capturing the running machine never grants authority to
replace the baseline. Existing enrollments without this root require explicit
migration; they are not silently re-enrolled.

An ordinary reboot or the vendor user-session success timer can create a new,
immutable integrity generation. It permits only the qualified GRUB flag-byte
transition, preserving the kernel/default selection, other environment entries,
boot artifacts and security metadata. An accepted package/kernel/retention
transaction is reduced through its retained typed evidence before comparison.
Metadata not recorded in an older payload receipt requires a full AIDE check
against the already accepted database before a new checkpoint can be published.

The boot maintenance gate runs before the public edge. Reconciliation,
full runtime/security checks and current-boot finalization precede gate release.
Interrupted ordinary generations retain exact ancestry; recovery can retain an
already copied database but cannot copy an unpublished historical result. An
unrelated pending update or unexplained drift remains held. No OS update journal
is invented or reopened to represent an ordinary boot.

If periodic observation fails before a valid generation exists, a separate
installation-bound failure receipt can retain maintenance without granting any
baseline authority. Recovery requires valid original evidence, a fresh full
AIDE check and all runtime checks, including retries after gate-release failure.
Incomplete or mismatched OS journal pairs cannot be claimed by this owner.

New installations enable `nebulalog-reboot-verify.timer`: an initial check after
three minutes and another fifteen minutes after the previous verification ends.
This covers a vendor success flag written after a later user login and retries
interrupted verification. Source tests exercise these boundaries; production
enrollment, native reboot/timer recovery and hypervisor acceptance remain open.

On October 15, a read-only capture on the original Rocky x86_64 qualification
guest measured all 456 installed package identities, 6,253 protected artifacts
and the 1,024-byte GRUB environment twice with matching results. Native testing
found and corrected two source assumptions: RPM's `gpg-pubkey` pseudo-package
omits its architecture tag, and the qualified GRUB packages have epoch `1`.
Key records remain in the inventory using an explicit `none` pseudo-architecture;
ordinary packages still require a valid architecture. The same ten writer-file
hashes passed with the corrected exact package identities. This verifies capture
and layout compatibility, not AIDE enrollment, reboot recovery or a healthy
appliance. The guest and its existing baseline were not changed.

The following cases remain explicit qualification or implementation gaps:

- Interruption between the GRUB temporary-file creation and replacement, and
  the complete candidate-kernel boot/promotion path on a configured appliance.
- Native qualification of later-boot exact-erasure recovery and its earlier
  acceptance generations; supported recovery for partial erasure and an
  unattempted plan from an earlier boot remains unfinished.
- Native qualification of ordinary-reboot integrity reconciliation before the
  first kernel update, after completed update/retention, and after a late vendor
  boot-success timer change. Drift during a measured phase must retain its
  maintenance gate and recover through a new qualified generation.
- Native interruption qualification of atomic kernel-default protection and
  its once-only RPM-command boundary.
- Retry or rollback of an unaccepted candidate after a verified fallback boot.
  That state is reported as `kernel_recovery_required` with retry held; it must
  not become an endless automatic reboot loop or a successful-update claim.
- The complete general vendor update transaction, critical packages and their
  service/generated-file migrations, and native VMware/AHV acceptance.

## Required next work

- Inspect the real currently available Rocky update transaction and classify every resolved package before mutation. Unsupported packages must be reported by name and reason; an all-or-refuse transaction is an interim constraint, not the final automatic-update behavior.
- Add explicit recipes for RPM scriptlets and installed triggers, with exact qualified outputs. The `hwdata` test candidate was rejected because its `/usr/lib/modprobe.d` payload would invoke a glibc file trigger; a package name alone is not a safe exemption.
- Qualify systemd-generated files, loader caches, SELinux labeling changes and other generated outputs. Preserve unrelated customer configuration and demonstrate failed/interrupted execution recovery.
- Implement and verify the AIDE/checker monitor-facts transition using independently verified replacement tools while retaining the prior checker and baseline chain.
- Qualify the implemented kernel, initramfs, BLS/EFI and encrypted-storage unlock binding by cold-booting the exact update on VMware and Nutanix. Secure Boot PCR 7 alone does not authenticate all initramfs/command-line inputs.
- Test real unattended OS updates, service recovery, reboot/unlock, retained log data, local authentication and recovery after failures on fully configured appliances. The present kernel crypto self-test warning still blocks normal healthy-host acceptance; it has not been bypassed for these tests.

`nebulalog update os-recover` can accept an interrupted operation only when the retained exact RPM result and fresh integrity/runtime checks pass. It does not claim that `dnf history undo` can reverse arbitrary scripts or persistent application data.

## Kernel vendor evidence

On October 15, the isolated native Rocky x86_64 guest installed and booted the
newer signed vendor kernel `5.14.0-687.57.1.el9_8`. The same HKDF self-test
failure recurred and the first-boot gate refused enrollment. The previous
kernel and offline recovery disks/firmware were retained. This manual vendor
transaction provides real package/boot evidence for developing the kernel
recipe; it is not acceptance of the automatic update manager. See the dated
measurements in [FIPS qualification](FIPS.md#october-15-vendor-kernel-qualification).

The earlier September qualification used `5.14.0-687.45.1.el9_8.x86_64`;
the configured repositories provided no newer x86_64 kernel at that time.
[RHSA-2026:64808](https://access.redhat.com/errata/RHSA-2026:64808), issued
September 8, ships that version for other listed security fixes. The October
qualification above supersedes that earlier package-availability observation.

On October 15, source analysis of the signed `687.56.1` and `687.57.1` Rocky
source RPMs found byte-identical `crypto/hkdf.c` and `crypto/hmac.c`: the first
HKDF vector's 13-byte salt reaches a generic HMAC FIPS minimum of 14 bytes,
which returns `-EINVAL` before SHA driver computation. The public
[Red Hat knowledgebase entry 7134366](https://access.redhat.com/solutions/7134366)
matches this failure class, was updated September 14, and still showed
“Solution In Progress” when checked October 15. Subscriber-only guidance was
not accessed, and no supported vendor fix or CPU-setting remedy was verified.
The signed-source comparison and references are retained in
`outputs/vendor-hkdf-analysis-20261015/vendor-remedy-analysis.json` in the
private T9 build root; this analysis does not relax any acceptance gate.
