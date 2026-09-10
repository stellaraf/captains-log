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

## Required next work

- Inspect the real currently available Rocky update transaction and classify every resolved package before mutation. Unsupported packages must be reported by name and reason; an all-or-refuse transaction is an interim constraint, not the final automatic-update behavior.
- Add explicit recipes for RPM scriptlets and installed triggers, with exact qualified outputs. The `hwdata` test candidate was rejected because its `/usr/lib/modprobe.d` payload would invoke a glibc file trigger; a package name alone is not a safe exemption.
- Qualify systemd-generated files, loader caches, SELinux labeling changes and other generated outputs. Preserve unrelated customer configuration and demonstrate failed/interrupted execution recovery.
- Implement and verify the AIDE/checker monitor-facts transition using independently verified replacement tools while retaining the prior checker and baseline chain.
- Bind kernel, initramfs, BLS/EFI configuration and encrypted-storage unlock to the planned new kernel, then cold-boot that kernel on VMware and Nutanix. Secure Boot PCR 7 alone does not authenticate all initramfs/command-line inputs.
- Test real unattended OS updates, service recovery, reboot/unlock, retained log data, local authentication and recovery after failures on fully configured appliances. The present kernel crypto self-test warning still blocks normal healthy-host acceptance; it has not been bypassed for these tests.

`nebulalog update os-recover` can accept an interrupted operation only when the retained exact RPM result and fresh integrity/runtime checks pass. It does not claim that `dnf history undo` can reverse arbitrary scripts or persistent application data.

## Kernel vendor evidence

The public [Red Hat knowledgebase entry 7134366](https://access.redhat.com/solutions/7134366) recognizes the same HKDF extraction failure class during FIPS boot in RHEL 9/10 and remains labeled “Solution In Progress.” Its full subscriber-only guidance was not accessed. The installed Rocky kernel is `5.14.0-687.45.1.el9_8.x86_64`; the live [Rocky 9 BaseOS package index](https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/k/) and the configured repositories provided no newer x86_64 kernel during this qualification. [RHSA-2026:64808](https://access.redhat.com/errata/RHSA-2026:64808), issued September 8, 2026, ships this same kernel version for other listed security fixes. No supported fixed Rocky package for the observed HKDF failure was verified. This does not exclude subscriber-only guidance or a later vendor fix.
