# Appliance update execution

The September 10 test run uses a disposable VMware clone and a private GitHub
delivery repository. Version 0.2.0 to 0.2.1 is a deliberate small application
change with an independently measured host bundle. These are test versions, not
published production releases. The existing local collector and original build
checkpoints are preserved.

This table is an execution checklist, not a passing attestation. A result becomes
passed only after its native evidence exists; source tests remain separate.

| Test | Required evidence | Current result |
|---|---|---|
| Initial host readiness | Rocky x86_64, Secure Boot, FIPS, SELinux, current-boot diagnostics | Native mode/service checks passed; HKDF diagnostic failed the strict health gate |
| First-boot enrollment | Blank data disk, new LUKS identity, local administrator and real MFA | Unmodified host gate refused enrollment; data disk remains blank |
| Small application update | Actual 0.2.0 to 0.2.1 API/UI change, selected host provenance, complete transaction | Signed B package built; both application versions executed in isolated amd64 containers; installed native verifier accepted B; activation pending |
| GitHub automatic delivery | Real HTTPS assets, observed 900-second timer, signature/hash verification, automatic commit | Private release published; unmodified downloader retrieved all eight assets over HTTPS and verified hashes/signature on the Mac; native timer and automatic commit pending |
| Log continuity | Known event IDs before/during/after update, durable recovery and searchable records | Native isolated ClickHouse replacement/rollback preserved exact records; complete ingestion/API continuity pending running test appliance |
| Update rollback | Previous code restored, later logs and configuration preserved, fresh health | Pending update execution |
| Interrupted update | Real interruption, retained transaction, recovery command, fresh integrity and health | Pending update execution |
| Rejected updates | Wrong signer, modified asset, unsupported path, sequence replay; installed state unchanged | Native verifier passed valid B plus eight refusals: signature/manifest corruption, replay, unsupported path, expiry, host corruption, OCI truncation, and symlinked artifact; separate wrong-key test pending |
| Integrity transition | Real AIDE scanner, metadata preservation, unrelated-drift refusal, database-CAS recovery | Six tests passed on Rocky's installed AIDE 0.19.2 with actual SELinux restorecon; storage/source/plan remain fixture inputs |
| OS package update | Exact signed RPM transaction, planned file changes, authorized integrity acceptance, runtime health | Native exact Rocky-signed WHENCE RPM forward transaction, three refusals, and full-policy AIDE delta/clean-check passed using a private baseline; enrolled OS transaction and broad OS/security/minor/kernel recipes unfinished |
| Kernel update and reboot | New kernel boot, intact LUKS unlock, services and logs recovered | Pending; vTPM qualification unresolved |
| PostgreSQL, ClickHouse, Keycloak updates | Supported real patch changes, preserved data, required authentication and rollback checks | Native ClickHouse metadata-only replacement/rollback passed with encrypted storage and authenticated TLS; assembler/runtime version-range bug fixed; real binary patch transitions and PostgreSQL/Keycloak lifecycle tests remain pending |
| OVA VMware/Nutanix import | Exact packaged artifact imported, first boot, unique identities and functional tests | Pending final image cleanup and packaging |

The existing kernel reports `hkdf_extract failed with -22` in its HKDF library
self-test. Red Hat documents this symptom as an unresolved issue. Upstream
discussion links it to the FIPS HMAC minimum key-length check applied to HKDF salt;
that discussion does not establish a supported fix in the installed Rocky kernel.
The appliance currently refuses enrollment and successful update health when this
diagnostic is present. The test must retain that refusal rather than suppress the
message or substitute a healthy result.

At 02:37 UTC on September 10, the disposable native VMware clone reproduced
the strict first-boot refusal. A separate read-only kernel HMAC diagnostic used
public RFC vectors: the original 13-byte salt was rejected with errno 22;
the equivalent zero-padded HMAC key and a separate 20-byte HMAC key both produced
the expected results. This narrows the symptom to the observed short-key policy
rejection; it does not clear the failed library self-test or certify the kernel.
The enabled Rocky repositories reported no kernel newer than the installed
`5.14.0-687.45.1.el9_8.x86_64` at that observation.

An explicit exception for the disposable test build has been proposed to the
operator to permit positive functional tests. It has not been applied. Production
health gates and the public stable release channel remain unchanged.

The exact A2 installer also completed on the native guest. Its installed fixed
launcher verified factory host generation
`6453e8b103c3fd9776ebc5b99dc7f05a3acf01152141b9583aec65b868cad3f9`.
Its host version is `0.0.0-factory.130fb74761a6c2c9`, which exactly matches B's
declared supported starting version. Generation hashes and version strings serve
different purposes and are not interchangeable.

Private GitHub release `v0.2.1` (release ID `385970937`) contains the measured
manifest `1738c446d8dc637b344a5d3de937669b0eba0627fd9cdf4106f516838e7515af`.
The downloaded signed payload contains 98,409,984 bytes. The delivery test used
the existing local CLI credential in process memory; no GitHub credential was
copied into the guest. It establishes real release delivery, not automatic
installation. The public `stellaraf/captains-log` channel was not modified.

The native package test replaced `linux-firmware-whence` version
`20260707-161.1` with `20260804-161.2`, checking the signature, complete package
inventory, and actual installed file digest. An older signed package was needed
to exercise a real forward transition because the native repository query
reported no pending upgrades. Corrupted retained RPM bytes, installed-file drift,
and repeated execution were refused. The final package version again matches the
guest's original current version. This exercises the exact RPM executor and does
not establish general OS update, full appliance health, or reboot support.

Native testing exposed a confined RPM database label failure. The implementation
now applies the existing system RPM database SELinux label to its own temporary
signature-verification database; SELinux remains Enforcing and no policy is
disabled. Installed-package classification shows that most real system packages
still require additional qualified update recipes. See `docs/UPDATES.md` for
the supported scope and remaining implementation work.

The unmodified ClickHouse component entrypoint also completed on the native guest
using a separate 2 GiB LUKS2/XFS test volume. The base image stored two uniquely
tagged rows, the metadata-only replacement preserved them and accepted a third,
and rollback to the base image retained all three with an identical final content
hash. Each start passed its own AWS-LC FIPS known-answer/integrity checks and
authenticated TLS readiness. The binary version remained
`25.3.8.30001.altinityfips`: this is an image replacement and persistence test,
not a ClickHouse binary patch qualification or complete updater transaction.
The owned containers were intentionally stopped, the test mapping/loop closed,
and the encrypted fixture retained privately. Product storage remained blank.

That test exposed unsupported `uid`/`gid` tmpfs options in both the ClickHouse
and PostgreSQL Quadlets. The templates now use Podman's supported `U` ownership
option. The native Quadlet generator and generated mounts verified service
owners `101:101` and `999:999`, mode `0700`, and `noexec,nosuid,nodev` on real
tmpfs. A2's frozen installed host source was preserved; a fresh base must include
the fix before full first-boot qualification.

The joint RPM/AIDE test then scanned 35,328 entries under the complete selected
host policy. The real forward package transaction changed exactly
`/usr/share/licenses/linux-firmware-whence/WHENCE`, with no added or removed paths;
the subsequent full check was clean. It used the production RPM executor,
report parser and allowed-change validator with a private test baseline. It did
not create a production enrollment or complete the enrolled OS maintenance flow.
The initial database and installed policy were preserved.

The first attempt exposed deprecated underscore-containing group aliases in
the original policy. Strict production handling correctly refused AIDE's
warnings. Source now uses `NEBULALOGSTATIC` and `NEBULALOGDIRECTORY`; reversing
those two substitutions reproduces the original policy bytes exactly. Paths,
attributes, ordering and exclusions are unchanged. The corrected policy passed
native configuration checks and all scans with empty stderr. Existing frozen
candidates retain the old policy and require rebuilding before first-boot
qualification. Detailed scope is in `docs/OS_UPDATE_QUALIFICATION.md`.

Sources: [Red Hat issue](https://access.redhat.com/solutions/7134366),
[upstream crypto discussion](https://www.spinics.net/lists/kernel/msg5946981.html).

Private execution receipts are retained under `.local/native-update-test-20260909/`,
`.local/update-smoke-release-20260909-a/`, and `.local/update-execution-20260910/`.
They are not release assets and may contain infrastructure identifiers.
