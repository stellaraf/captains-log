# Release assembly and guarded prerelease publication

`assemble_release.py` produces local assets compatible with Captain's Log's existing signed updater. It has no network or GitHub operations. An assembled package is always `qualification: not_assessed`, including when its signature and all archives verify. The GitHub workflow is disabled until its explicit repository variable is enabled, and can publish only a prerelease.

## Inputs and assembly

Use one immutable source tree and `source-manifest.json` captured by `prepare_provenance.py`. The assembler checks every captured file, the complete fixed host ABI catalog, and the public factory publisher inputs. The application OCI configuration must contain `io.nebulalog.application-source-sha256` matching that same captured application source. The offline image directory must pass `image_bundle.verify_bundle`; it supplies immutable Linux/amd64 references and actual checked archive bytes.

The recipe explicitly records the publisher-approved release sequence, timestamps, source commit, current schema revision and supported prior versions:

```json
{
  "schema": 1,
  "repository": "stellaraf/captains-log",
  "sequence": 2,
  "version": "0.1.1",
  "issued_at": "2026-09-09T00:00:00Z",
  "expires_at": "2026-12-09T00:00:00Z",
  "source_commit": "<40-character published source commit>",
  "schema_revision": "1",
  "components": {
    "host": {"version": "0.1.1", "from_versions": ["0.1.0"]},
    "nebulalog": {"version": "0.1.1", "from_versions": ["0.1.0"]}
  },
  "evidence_artifacts": []
}
```

These values are illustrative, not a current qualified release. Include the actual measured factory host version in `from_versions` when supporting that factory image. Every release includes both host and application assets. The host version must advance, even when only OCI bytes change. Database changes may additionally select `postgresql`, `clickhouse`, and `keycloak`; unselected database images remain installed. PostgreSQL major changes are refused. ClickHouse requires `family`, `tested_minimum`, and `tested_maximum`, with both old and new versions inside that range. Preserve the full measured ClickHouse version, such as `25.3.8.30001.altinityfips`, in `version` and `from_versions`; range bounds are numeric, such as `25.3.8.30001`. Both the publisher and appliance verifier reject family changes, vendor suffix changes and endpoints outside that range. Automatic schema migrations are not accepted.

Keycloak additionally requires `qualification_artifact` naming a JSON report with the existing lifecycle schema: exact image, source commit, and successful `real_browser` observations for local password/OTP, AD LDAPS/OTP, Okta SAML, Entra SAML, generic SAML and generic OIDC. Every referenced browser evidence artifact must be listed explicitly in `evidence_artifacts` and supplied in `--evidence-directory`. Only the selected, bounded JSON files are copied. Those browser artifacts become public release assets; supply reviewed, sanitized reports containing no tokens, cookies, passwords, private keys or personal data. The assembler checks schema and binding, not the truth of browser assertions or complete content redaction.

```sh
python3 appliance/packer/assemble_release.py assemble \
  --source /protected/frozen-source \
  --source-manifest /protected/provenance/source-manifest.json \
  --image-directory /protected/offline-images \
  --recipe /protected/release-recipe.json \
  --signing-key /protected/publisher-private.key \
  --output /protected/candidate/package
```

Omit `--signing-key` for an unsigned local inspection package; unsigned packages cannot pass the publication gate. The signing key must be owner-private, outside every repository and release input/output tree. The tool never creates a key or copies a private key into an artifact. It signs `manifest.json` with RSA-PSS, SHA-256, and a 32-byte salt, then uses the appliance verifier and captured factory public key to verify the actual signature. Wrong signing keys fail without publishing a partial output directory.

The output includes `manifest.json`, `manifest.sig` when signed, `host.tar`, selected OCI archives, declared browser JSON evidence, `source-manifest.json`, the two public publisher inputs, and `release-provenance.json`. Provenance binds exact asset lengths/hashes, source snapshot, application source, host generation, sequence and version. Fresh output directories publish atomically without overwriting an existing or competing output.

## Independent native acceptance

Native acceptance is a separate attestation. Neither the assembler nor workflow creates a passing native report. An authorized reviewer must inspect actual guest and hypervisor receipts and write a report with exactly:

- `schema: 1`, `kind: captains-log-native-release-acceptance`, `repository: stellaraf/captains-log`.
- `release_provenance_sha256`: exact SHA-256 of this package's `release-provenance.json`.
- `ova`: `{name, bytes, sha256}` for the actual OVA being distributed.
- `platform`: `{os: linux, distribution: rocky, major: 9, architecture: x86_64}`.
- `checks`: all the gates below, each `{status: passed, method, evidence: [{name, bytes, sha256}]}`.

| Gate | Required observation method |
| --- | --- |
| `efi_boot`, `tpm_luks_reboot`, `kernel_crypto` | `real_rocky_vm` |
| `combined_update`, `selected_host_provenance`, `authorized_aide_transition` | `real_rocky_vm` |
| `rollback`, `interrupted_recovery`, `os_update_aide`, `tls_log_ingestion` | `real_rocky_vm` |
| `vmware_import` | `real_vsphere_import` |
| `nutanix_import` | `real_ahv_import` |

Evidence filenames are direct bounded files under a separate private evidence directory. They are hash-checked and are never uploaded by this workflow. A sealer pass, unit tests, package hashes, scanner fixture or the read-only guest collector's pending report cannot substitute for these observations. OS RPM/AIDE acceptance remains its own required gate.

`verify-native` rechecks the source tree, signature, OCI blobs, host archive, package inventory, OVA hash, complete attestation schema and all referenced evidence bytes. Its result is `native_attestation_bound` with `native_execution_verified_by_tool: false`. This means the evidence is complete and bound, not that a JSON parser observed a VM boot. The protected publication review provides the human assessment of the original evidence.

All individual GitHub assets must be smaller than 2 GiB. The current gate refuses a larger OVA or OCI archive; multipart OVA distribution is not implemented in this slice. Do not silently omit, truncate or publish a placeholder for a rejected large artifact. [GitHub release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)

## Workflow readiness

`.github/workflows/release-candidate.yml` is manual-only, restricted to this repository's `main` branch, and guarded by `CAPTAINS_LOG_ENABLE_PRERELEASE_PUBLICATION == true`. Keep that variable unset until all native gates pass and the publication environment is configured.

Configure a dedicated trusted Linux x86_64 runner with the `captains-log-publisher` label, Python 3, OpenSSL and GitHub CLI. Configure the `captains-log-prerelease` environment with required reviewers, prevent self-review, and restrict it to the protected `main` branch. Keep the publisher staging directory protected against other workloads. The runner needs no publisher signing key: signing happens separately before staging. Use the workflow's short-lived `github.token`; no personal API credential belongs in source or release assets.

Stage these exact paths for a version:

```text
/srv/captains-log/releases/<version>/package/
/srv/captains-log/releases/<version>/native-qualification.json
/srv/captains-log/releases/<version>/private-evidence/
/srv/captains-log/releases/<version>/captains-log-<version>-rocky9-x86_64.ova
```

Supply the independently reviewed manifest SHA256 when dispatching. The workflow checks that every frozen source file matches the checked-out commit, verifies the evidence gate, uploads only the explicit package assets and OVA to a new draft prerelease, and compares GitHub's uploaded asset lengths/SHA256 digests and actual tag commit. It rechecks local evidence before publishing with `prerelease: true` and `latest: false`. Missing GitHub digest evidence, an existing release, upload failure or any mismatch leaves publication unfinished; no overwrite, deletion or automatic partial-draft reuse is attempted.

The appliance's 15-minute stable GitHub poller excludes prereleases. Stable publication and promotion require a separately reviewed process and are deliberately absent here. The workflow source has local fixture validation only until it is installed and run against the configured repository/runner/environment.

## Preserve builder disks independently

The October 12 private build completed provisioning but its manifest
post-processor failed because the relative output directory was absent. Packer
then removed the input artifact despite `-on-error=abort`. That flag is not an
artifact-retention guarantee. The template now returns builder outputs directly,
without a post-processor. Write receipt files outside Packer after it exits.

A local build supervisor can use `preserve_build.RecoveryLinks` to retain the
three known disk/firmware files in a separate recovery directory on the same
filesystem. Call `capture()` throughout the build and after the writer exits;
replacement inodes receive separate links. These links share live writes and
must never be treated as crash-consistent snapshots or opened by a second VM
while the original writer runs. After exit, verify image consistency before use.
They are recovery evidence and must be preserved independently of Packer output
cleanup. This does not protect against physical filesystem/drive failure.

## Retain factory kernel provenance

`install-host.sh` invokes the captured `factory_kernel.py` helper during guarded
private image provisioning. It requires exactly one complete installed Rocky
9.8 x86_64 kernel set, equal to the running kernel and persistent boot default.
It downloads the exact installed NEVRAs for `kernel`, `kernel-core`,
`kernel-modules`, and `kernel-modules-core` from the fixed Rocky BaseOS HTTPS
repository. This step downloads bytes only: it cannot install an update or
substitute a newer package when the exact vendor version is unavailable.

The helper checks installed payloads, downloaded payload/script headers, and signatures
against an isolated keyring containing only the pinned Rocky key. It preserves
four SHA256-named RPMs, `installed-inventory.xml`, `capture.json`, and the
completion marker `manifest.json` under
`/usr/share/nebulalog/kernel-provenance`. Protected files are retained unchanged
across exact retries; partial or conflicting evidence is never silently replaced.
The sealer verifies the bundle offline. Initial AIDE enrollment verifies the
source-measured helper and retains the manifest and installed-inventory digests.
The existing `/usr` policy covers all seven files; there is no provenance
exclusion. Later checks preserve the original enrollment facts, including after
the factory kernel is eventually pruned by an accepted retention transaction.

Missing exact vendor RPMs, extra installed kernel versions, changed signatures
or payloads, and incomplete provenance stop the build/enrollment. Existing
appliances whose AIDE enrollment lacks these factory facts require an explicitly
qualified migration; the helper does not create a replacement baseline. Source
tests cover capture, refusal, and retry boundaries. The actual download command,
SELinux labels, offline seal/first-enrollment verification, and later native
four-to-three retention still require a rebuilt Rocky guest qualification.
