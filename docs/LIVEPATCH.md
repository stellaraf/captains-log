# Self-built Rocky kernel live patches

The October 13, 2026 product decision selects vendor-supplied Rocky kernels and
automatic vendor package updates with controlled reboots. Self-built live
patching is not enabled in the factory policy or timer installation. This
document preserves the isolated experimental tooling and its qualification
requirements; it does not describe an enabled release feature. No security
patch has been published or demonstrated in the appliance guest.

## Build inputs and toolchain

`appliance/images/livepatch-builder/Containerfile` builds an x86_64 Rocky 9
build-only image from the pinned Rocky base and upstream kpatch commit with explicit Rocky support
`74ac9ffe96df2704eb6f141bc7e680a7f449503e`. The image retains its source and
package inventory. Kernel source preparation requires dependencies from the exact vendor source
RPM. Resolve them from its extracted SPEC in a derived build image before the
network-disabled patch build. For this kernel-only build, the SPEC supports
`_without_perf 1` and `_without_tools 1`; these omit separate userspace package
dependencies and do not alter the pinned kernel configuration. The compiler must match the original kernel.

`appliance/packer/build_livepatch.py` accepts a schema-1 JSON recipe containing:

- `kernel_release`: exact Rocky 9 x86_64 release from the qualification guest.
- `module_name`: a unique `livepatch_` name using lowercase letters, digits and underscores.
- `source_rpm`, `config`, `vmlinux`: objects with absolute `path` and SHA-256 `sha256`.
- `patches`: ordered list of source patch objects with the same path/hash fields.
- `security_fixes`: explicit security fix references, or a clearly identified qualification-only purpose.

Use the running kernel's unstripped vmlinux, original configuration and vendor
source RPM. The builder captures the exact bytes into an exclusive new output
directory, verifies Rocky source-RPM signing and identity, checks required kernel
options, and invokes kpatch-build with its compiler checks and atomic replacement
mode retained. It verifies the resulting module's target kernel and identity.
Caches and scratch files are scoped to the output directory. Failed builds retain
their inputs, logs and receipt; rerun in a new directory.

Run the builder in a network-disabled container with signed inputs mounted
read-only and a dedicated native Linux filesystem for writable kernel build
space. On this Mac, Docker stores that volume on T9; RPM source extraction on
the macOS bind mount failed while the native-volume probe passed. Mount source
code read-only at `/source` and export resulting artifacts to the T9 build folder. For example,
after creating an actual pinned recipe under that build root:

```sh
python3 /source/appliance/packer/build_livepatch.py \
  --manifest /build/inputs/livepatch-recipe.json \
  --output /build/outputs/livepatch-candidate-001
```

The resulting receipt says `candidate_requires_signing_and_guest_validation`.
It is not a signed update manifest and cannot establish native patch safety.
This builder does not load modules or include private signing keys in its image.

## Kernel module trust

Before loading a verified module, the guarded transaction loads its exact signed
leaf certificate into `.secondary_trusted_keys` using `keyctl padd`. The kernel
must already trust the signing chain; this operation cannot enroll a new root,
modify firmware trust, or disable signature enforcement. The installer includes
`keyutils`. Signer loading runs again after reboot because leaf keys are volatile.
The transaction records the certificate digest and key serial before `insmod`;
rejection leaves recovery evidence and prevents the module load.

On October 12, the helper accepted the qualification leaf and the native Rocky
kernel rejected an unrelated self-signed certificate. The earlier certificate
used for a negative probe shared the already trusted public key and was correctly
accepted; it was not a valid untrusted-signer test. Retained evidence is
`logs/native-signer-helper-unrelated.log` in the T9 build root. This proves the
helper's kernel interaction, not the entire automatic appliance transaction.
The observed kernel FIPS failure still prevents that transaction's health gate
from passing. Production CA enrollment and portable OVA trust remain unqualified.

Both installer recipes request `module.sig_enforce=1`. Host provisioning requires
that the running kernel reports `Y` for its signature-enforcement parameter.
The static UEFI audit checks every retained boot entry for the explicit flag and
rejects missing, disabled, or conflicting options. Runtime health and guest
qualification independently read the running kernel's enforcement state; a
configured boot option alone does not establish enforcement.

This does not enroll a livepatch certificate or establish Secure Boot. A custom
patch still requires a signer trusted by the guest kernel and actual load and
transition qualification. The initial private guest built before this change
reported `N`; it must be updated and rechecked before livepatch acceptance.

## Authenticated candidate verification

`nebulalog_manager.livepatch.verify_bundle` verifies a captured local bundle
against the already enrolled publisher key. Its RSA-PSS SHA-256 manifest binds
an increasing sequence, validity window, exact kernel image/configuration hashes,
module bytes, a pinned DER module signer certificate, and the publisher's
qualification assertion. Fixed artifact names and bounded protected regular
files prevent unsigned path selection. A detached CMS check authenticates the
Linux module signature against the pinned certificate; module metadata must
identify an x86_64 live patch for the same kernel with a SHA-256-or-stronger
signature digest.

Certificate pinning here authenticates bytes; it does not enroll the certificate
in the kernel. `authenticated_candidate` deliberately returns `applied: false`,
`kernel_trust_verified: false`, and `native_transition_verified: false`. The
qualification report is a publisher assertion, not a measurement of this host.
The trusted caller must supply measured kernel identities and durable sequence
state. This API does not advance sequence state, download a feed, load a module,
or provide automatic delivery. Those integration gates remain open.

Tests exercise real RSA-PSS and detached CMS verification, including republished
but cryptographically damaged modules, a different pinned certificate, expiry,
replay, wrong kernel hashes, incomplete qualification, and changed enrollment.
Native `modinfo` and kernel transition checks remain guest acceptance work.

## Retained candidate staging

`livepatch.stage_bundle` copies only the five fixed, bounded bundle files into
an exclusive protected candidate directory and flushes them before verifying
the retained bytes. The verification and capture receipts are durable; failure
retains evidence with `authenticated: false`. Tests mutate the incoming module
after staging and verify that retained bytes are independent, and confirm that
failed captures cannot produce a verified receipt.

Directory existence or an old verification receipt never authorizes loading.
The transaction controller must reverify captured bytes against current trust,
measured kernel identity, expiry and durable sequence state immediately before
loading. Staging neither advances the sequence nor loads a module. The automatic
feed and transaction/reboot integration remain pending.

## Kernel transition observation

`livepatch.wait_for_transition` reads the running kernel release, boot ID,
signature-enforcement state, module init state, and livepatch enabled/transition
attributes. It requires two consecutive enabled, completed observations within a
bounded monotonic timeout. Reversed transitions, missing or malformed attributes,
changed boot identity, and disabled signature enforcement are refused. It never
writes the force attribute, signals tasks, reverses a patch, or unloads a module.

This follows the [kernel transition interface](https://docs.kernel.org/livepatch/livepatch.html#consistency-model).
The result is a sysfs observation, not authentication of the loaded bytes or
proof of service/FIPS health. The transaction controller must bind it to
the captured authenticated module it loaded under its lock, retain crash/replay
state, and perform post-load health checks. Fixture tests cover completion,
stalled/reversed transitions, changed boot identity and unsafe/missing attributes;
no native patch has yet been loaded. Automatic delivery remains incomplete.

## Guarded application transaction

`livepatch.apply_bundle` is an internal application API, not yet connected to a
CLI, feed timer or reboot service. It takes the shared appliance transaction lock,
refuses unfinished component/OS maintenance and prior interrupted livepatch work,
and runs the existing lifecycle service checks by default, plus independent host
security and enrolled AIDE integrity checks. It measures the running release and boot ID, verifies installed
kernel RPM files, and hashes the exact boot image/configuration. It stages and
reverifies the signed bundle before recording the intended load durably.

The API loads only the captured module, observes the enabled transition, and
requires unchanged kernel identity, healthy host/application checks, and unchanged
publisher trust before recording `applied`. Failure after the durable preparation
boundary records `recovery_required`; retry is refused. It does not force a
transition, automatically unload, or silently reuse the interrupted transaction.
A subsequent candidate must have a higher sequence. Tests use real publisher and
CMS signatures but mock kernel loading and host observations; no native apply
claim follows from these tests.

Component install, rollback, recovery and finalization, plus automatic OS
maintenance, check the livepatch journal under their existing transaction locks.
They refuse prepared, loading, failed or malformed livepatch state before running
maintenance hooks. A completed entry also requires its post-load health flag.

Remaining integration includes automatic feed delivery,
operator recovery, reboot-service wiring and cumulative-patch policy.
The API must not be exposed as an enabled automatic service until those paths and
native acceptance are complete. An RPM check and boot-file digest are provenance
checks under the trusted boot/host boundary, not runtime kernel attestation.

## Integrity checks within the patch transaction

Pre-load and post-load acceptance now run an enrolled AIDE check using the live
manager-lock descriptor owned by the patch transaction. The checker verifies the
descriptor matches the protected manager lock, takes the existing subordinate
coordination locks, and uses the same enrolled-database and report checks as an
ordinary scan. It never initializes, accepts or replaces an integrity baseline.
An unrelated or closed descriptor is refused. Tests prove a scan can complete
under the existing lock while a separately acquired ordinary scan refuses, and
that the enrolled database remains byte-identical. Dirty integrity prevents
module loading; post-load failure retains the recovery boundary.

## Same-kernel reboot reapplication

The internal application API accepts `reapply=True` only with no incoming
bundle. It retrieves the previously completed transaction's retained candidate,
requires a new boot ID and identical kernel release/image/configuration, and
reverifies signatures, validity, qualification and publisher trust. Sequence
equality is allowed only for that exact committed manifest and publisher identity;
ordinary candidate verification still rejects equal or older sequences.

Reapplication uses the same durable load/transition/health checks and does not
advance the sequence. Same-boot retry, changed kernel targets, changed committed
identity and incomplete prior health records are refused. This is transaction
logic tested with mocked kernel loads, not proof of a native reboot. The boot
service is still pending, and an expired
patch remains refused after reboot until a qualified current candidate is supplied.

## Default application health adapter

Without a test-injected callback, the patch transaction invokes the active host
code's lifecycle health implementation. This checks API/web responses, both
databases, fresh local password/OTP authentication, Keycloak strict FIPS mode,
application crypto status, encrypted storage, actual ingestion canaries, and
current compliance results. It requires every existing lifecycle acceptance
check; an aggregate `ok` flag cannot hide a missing or false check.

Evidence is retained under `updates/livepatch-health/<boot-id>`. Pre/post checks
and retries within the same boot reuse that directory, so explicit review of
retained compliance findings remains possible. The existing assessment binding
and fresh-outcome checks still apply. The adapter refuses stages outside its
protected health parent and does not pretend to be a component-release update.
Tests cover retained finding review, current service failure, directory refusal,
and incomplete acceptance checks. These are fixtures, not native service proof.

## Per-kernel delivery

`inspect_publication` authenticates the bounded manifest/signature against the
enrolled publisher before payload transfer. `fetch_candidate` uses the existing
HTTPS GitHub transport and the exact stable tag `livepatch-<kernel-release>`.
It rejects drafts, prereleases, wrong tags, duplicate/incomplete assets, excessive
sizes, and mismatched signed lengths/hashes. No asset-supplied URL is followed;
asset IDs are fetched through the fixed repository API and the existing approved
CDN redirect policy. Captures and failure receipts remain in protected storage.

A publication contains the fixed `livepatch.json`, `livepatch.sig`, `module.ko`,
`module-signer.der`, and `qualification.json` assets. The publisher must publish
this separate tag with GitHub's latest-release selection disabled so it does not
replace the ordinary semantic-version application release feed. No livepatch
release has been published. Qualification-only marker modules must not be
represented as security-fix coverage.

After metadata authentication, equal/older sequences return `not_newer` without
payload transfer; this is not a claim that the currently running kernel is
patched. Newer candidates undergo complete module/CMS/qualification verification
and still return `applied: false`. The application transaction must reverify them
at execution. Tests use real signatures and an in-memory transport to exercise
forged metadata, tampered modules, wrong release metadata and bounded downloads.
The periodic/boot entry points and native delivery proof remain pending.

## Remaining release requirements

1. Build a real candidate against the exact installed vendor kernel, including
   preserved patch source and the original/patched function comparison.
2. Review the patch's consistency, state and data-layout constraints; a successful
   compilation does not prove a patch is safe to apply live.
3. Sign the final module using a protected key trusted by the guest kernel, and
   bind its final bytes to the appliance publisher's signed update metadata.
   Do not disable Secure Boot or signature checks to make it load.
4. Verify exact-kernel matching, expiration and rollback/replay protection in the
   delivery path; apply only authenticated, qualified patches automatically.
5. Observe the kernel livepatch transition completing, with service continuity,
   retained FIPS diagnostics, health checks, and recovery evidence. Never force
   a stuck transition merely to report success.
6. Prove automatic reapplication after reboot into the same kernel, and correct
   handling of replacement kernels and cumulative patches.
7. Publish accurate patch coverage and unsupported-fix status. Some fixes require
   a conventional kernel update and reboot; never report those as live-patched.

Upstream kpatch is in maintenance mode for older kernels; its replacement
`klp-build` targets newer upstream kernels. Rocky 9 uses its vendor-maintained
5.14 kernel, so compatibility must be proven on that exact vendor release.

References: [kpatch source and limitations](https://github.com/dynup/kpatch),
[patch-author guide](https://github.com/dynup/kpatch/blob/master/doc/patch-author-guide.md),
[kernel transition model](https://docs.kernel.org/livepatch/livepatch.html), and
[module signing](https://docs.kernel.org/admin-guide/module-signing.html).
