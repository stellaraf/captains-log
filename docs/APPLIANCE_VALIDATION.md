# Appliance implementation evidence — 2026-09-09

**No completed, imported and end-to-end validated OVA release is available.** The clean4 Rocky 9.8 x86_64 build completed, and both disks passed offline integrity checks. An isolated installed-guest observation boot completed and shut down with the original disk hashes unchanged. The base is deliberately unsealed; sealing, OVA packaging, VMware/Nutanix imports and full runtime acceptance remain pending. See the [clean4 evidence](validation/ROCKY_CLEAN4.md). A completed build is distinct from a deployable release.

## Implemented and locally checked

| Area | Evidence and limits |
|---|---|
| First installation | Guarded disk review and durable GPT/LUKS2/LVM/XFS enrollment, network/hostname/DNS/NTP inputs, unique secrets/recovery material, staged provisioning and final evidence checks. Transaction/safety tests use command models; no host disks are changed. |
| Accessible console | Sealed unfinished VMs enter a guarded tty1 wizard without Linux login. Private builds and completed installations cannot reenter it. Fifteen tests cover terminal boundaries, retry/interruption, completion and direct-TTY output. Actual graphical-console handoff and reboot remain guest gates. |
| Runtime bootstrap | Immutable image inputs, encrypted configuration, separate database identities, strict MFA policy, admin creation without password reset, package-trust enrollment and actual OpenSSL CA/server name/key tests. The final container set still requires guest startup and fresh browser MFA verification. |
| Offline bundle | Builder/verifier check archive hashes, referenced OCI blobs, platform and exact manifests. Candidate v6 contains the captured-source application plus PostgreSQL, ClickHouse and Keycloak FIPS candidates: 973,066,752 archive bytes, all Linux/amd64. The application source hash is bound to its OCI configuration. The cancelled second installer used separately frozen v5 inputs (973,055,488 bytes); its result cannot qualify v6 changes. Actual guest Skopeo/Podman loading and runtime qualification remain separate. |
| Host status | Bounded, allowlisted observations are published atomically through a dedicated read-only mount; private journals and credentials are omitted and failed sections become unavailable. Tests include permission/size/symlink refusal and label failure preserving the prior snapshot. Guest access/UI freshness remain live checks. |
| Administrator step-up | Post-v6 source adds an inactive dedicated Keycloak definition/read-back and a server transaction with confidential PAR, S256, signed nonce/token-pair validation, original-session/action binding and atomic PostgreSQL consumption. Signed synthetic, HTTPS and isolated PostgreSQL integration/race checks pass. The combined test uses a synthetic issuer; browser MFA, Keycloak flow behavior, live revocation, host grants and UI dispatch remain unqualified. See [transaction evidence](HOST_STEP_UP_TRANSACTIONS.md). |
| Ordering and SELinux paths | Static tests check an acyclic declared graph, the storage gate, maintenance-before-HTTPS, reboot verification and separate Apache/status paths. Apache receives exact canonical certificate copies in encrypted edge-tls; actual OpenSSL copy/key/retry tests pass. These are not installed systemd generator or SELinux enforcement tests. |
| Security baseline | Assessment/review workflow binds scan provenance and explicit review to the installation and selected policy. Parser and refusal tests pass. Selection alone does not establish passing controls, approved exceptions or a qualified CIS/STIG deployment. |
| File integrity | Explicit AIDE prepare/review/enroll/check uses an encrypted database and protected receipts. Next-candidate tty1 actions support this workflow and preserve runtime configuration on resume; changing a reviewed report refuses enrollment and later verification. Final setup requires a verified clean check within 300 seconds. Managed configuration, parser, refusal and completion integration tests pass. Actual guest scans, SELinux/timer behavior, notifications, renewal, normal-admin policy selection/SCAP review and in-app management remain open. |
| Source retention | Complete-source archival binds canonical USTAR bytes to the original captured manifest and descriptor, with independent verification and a read-only receipt. Nineteen isolated fixtures and independent review cover source/metadata races, hostile headers and competing output preservation. This is unsigned source-byte retention; it does not reproduce a completed guest or reconstruct Git history/modes. |
| Lifecycle updates | Fixed adapters implement preflight, writer quiescing/backups, digest-pinned activation, fresh password+OTP/PKCE health, rollback and retained finalization/reboot recovery. Unit coverage is implemented; installed-guest upgrade/rollback/reboot qualification remains pending. |
| Backup handling | Archive integrity/rejection and OpenSSL signing/tamper checks are covered. Live encrypted backup, PostgreSQL recovery and complete appliance restore remain guest gates. |
| OVA packager | Three actual QEMU fixture tests cover conversion/readback, refusing backing/snapshot/aliased inputs and nonblank data, content comparison and atomic publication. OVF uses VMware paravirtual SCSI. These disposable inputs contain no installed appliance OS. |

Run the current checks from the repository root:

```sh
PYTHONPATH=appliance:appliance/adapters python3 -m unittest discover -s appliance/tests -q
PYTHONPATH=appliance:appliance/adapters python3 -m unittest discover -s appliance/adapters/tests -q
python3 -m compileall -q appliance
bash -n appliance/install-host.sh appliance/bin/nebulalog-seal
```

The latest appliance suite passed **457 tests**, followed by **19 additional full-source archive tests** and independent review; the lifecycle adapter suite passed **25 tests**. The application checkpoint passed all Go package checks, auth/API race checks, 35 web unit tests, TypeScript and 12 isolated browser lifecycle cases. Browser cases use synthetic API observations and establish expiry/failed-refresh/race behavior, not live host or identity qualification. Candidate v6 passed actual isolated FIPS-enabled startup, disabled/malformed-policy refusal, read-only execution and build-identity checks. Its Linux/amd64 manifest is `546874a4a1d114ac424aa7657d13f9464084682e14a7768f03140ce4856d3fa4`; application source hash is `05bf5f6b2381afde5f63c966f714cdb6ec11da23dd109ef949311e95340d3c21`. Earlier test-count reports are superseded. Retain exact test outputs/review records with the candidate source snapshot; changed code or a rebuilt candidate requires its own applicable checks. These checks do not demonstrate guest throughput or production crypto operating-environment qualification.

## Isolated boot evidence

The September 9 [clean4 build and installed-guest observations](validation/ROCKY_CLEAN4.md) supersede the earlier build status described below. Earlier test counts and candidate identifiers remain historical checkpoints, not current-release acceptance.

The first Linux-hosted Rocky 9.8 x86_64 installation passed installer FIPS crypto self-tests and installed 410 packages, but its post script rejected Packer's terminal newline in the build public key. A narrowly scoped manual recovery reached installed-kernel boot with FIPS enabled; incomplete installer finalization left SELinux labels and core services broken. That candidate was stopped and rejected. The second, clean build used the corrected decoder and frozen v5 inputs but was cancelled during package 339/410 when free host space reached 4.94 GiB. Packer removed its interrupted disks; its logs/receipts remain. Candidate v6 source/archive and verified bundle are ready for another build with adequate capacity. See [ROCKY_INSTALLER](validation/ROCKY_INSTALLER.md) for both outcomes. The native macOS QEMU kernel failure was also retained. None of these observations establishes clean installed-host provisioning or appliance qualification.

Ignored `.local/appliance-build/` holds boot-probe serial logs and exact bundle receipts. Build keys and enrollment credentials are private inputs and must not enter published evidence.

The installed [read-only guest collector](../appliance/validation/README.md) produces redacted stage-by-stage JSON for the first authorized Rocky VM run. Its local parsing/guard tests are complete; creation of the collector is not a collected guest result. It records a boot identity, measured FIPS/provider/RPM/driver/label/unit evidence, pristine disk observations and enrolled runtime health when available, with overall acceptance always pending.

## Gates still required before release

1. Complete the isolated Rocky installation and retain source/ISO/package/image identities. Run the exact Podman Quadlet generator and `systemd-analyze verify`; inspect installed dependencies, cycles and failed jobs.
2. Seal a pristine base: remove disposable identity and SSH access, verify the blank data disk and release metadata/bundle, and prove no installation secrets or universal encryption keys remain.
3. Import the artifact and exercise graphical first boot, reviewed disk selection/full capacity, hidden credentials, recovery export, interruption/resume and actual LUKS recovery verification. Reboot through console unlock with root still locked.
4. Prove the final containers start under SELinux Enforcing with expected UIDs/groups, TLS verification and FIPS settings. Verify Apache's encrypted certificate access and API access to sanitized status, while private host configuration remains inaccessible. Investigate precise AVCs without a blanket allow policy.
5. Complete human MFA/recovery enrollment, fresh local health authentication, real PAN-OS receipt, assessed/reviewed baseline and the final installation receipt. Test each advertised remote identity method against real provider fixtures.
6. Exercise online growth, added-disk enrollment, identity mismatch refusal, crash/reboot recovery, LVM devices-file behavior and disk exhaustion. vTPM unlock remains separately qualified.
7. Exercise live backup/restore, supported component activation/rollback/finalization, OS preflight and a real kernel reboot. Durable maintenance must be restored before public HTTPS; failed new-boot health must preserve it.
8. Qualify baseline content/tailoring, approved exceptions, remediation and the crypto-module/CMVP operating-environment mapping. Enabling FIPS does not certify the appliance.
9. Validate advertised hypervisor routes, workload/retention sizing and high-volume ingestion/query behavior. Publish only the exact signed candidate supported by this evidence and a trusted verification key/channel.

These unit/model checks do not mutate development-host disks, packages or networks. The isolated guest build has separate outcomes, which must be recorded before release claims.
