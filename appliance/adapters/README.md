# Installed lifecycle adapters

These are the local, root-owned implementation of the manager hooks described in
[UPDATES.md](../../docs/UPDATES.md). Unit tests inject command runners and do not
operate host services. An installed Rocky guest must still qualify image loading,
backup/restore, FIPS providers, all authentication flows, ingestion, SCAP and actual
reboot survival. Passing a simulated transaction is not that qualification.

## Installation and paths

Install `nebulalog_adapters/` alongside `nebulalog_manager/` under
`/usr/lib/nebulalog`, root-owned without group/world write. Install every file in
`bin/` as root0755 under `/usr/libexec/nebulalog`. Hooks are fixed executable names;
a release cannot provide shell commands, service names, volume mounts or hooks.

The five container names, systemd units and Quadlets are `nebulalog-api`,
`nebulalog-ingest`, `nebulalog-postgresql`, `nebulalog-clickhouse` and
`nebulalog-keycloak`. Quadlets reside in `/etc/containers/systemd` and each has one
`Image=repository@sha256:<manifest digest>` line. Keep previous image digests until
their retained transaction is no longer eligible for rollback. The Apache edge is
a host service and remains running to enforce the maintenance gate.

`/var/lib/nebulalog` must be the LUKS-backed XFS data mount. Runtime configuration,
TLS keys, identity credentials, Podman graphroot, backups and manager state all
reside on that encrypted filesystem. Adapter subprocesses use the fixed private
`TMPDIR=/var/lib/nebulalog/tmp`, checked root0700. They do not inherit arbitrary
proxy or command environment variables. Fixed command arguments never contain
database passwords. PostgreSQL is addressed over its container Unix socket as
uid999/role `postgres`; the two databases are `nebulalog` and `keycloak`. ClickHouse
uid101 reads `/etc/nebulalog/clickhouse-client.xml` inside its container.

The fixed additive application migration uses a separately identified Podman
client supervised by systemd. It shares the PostgreSQL container's network,
authenticates over loopback SCRAM using the existing `nebulalog-pg-password`
secret mounted uid999/mode0400, and uses the exact image ID resolved from the
protected PostgreSQL Quadlet. The password is read inside that client and never
appears in host arguments or receipts. Native execution of this path is still
under qualification.

## Runtime configuration

First boot writes `/var/lib/nebulalog/configuration/lifecycle.json` as root0600.
The JSON below is a schema example, not a usable account or enrollment file.
Generate unique random health credentials for each appliance; never place them in
an image, source repository, unencrypted `/etc`, command line or status receipt.

```json
{
  "schema": 1,
  "schema_revision": "2",
  "api_url": "http://127.0.0.1:8080",
  "issuer": "https://logs.example.test/realms/nebulalog",
  "ca_file": "/var/lib/nebulalog/configuration/tls/ca.crt",
  "compliance_policy": "/var/lib/nebulalog/configuration/security-policy.json",
  "rocky_key_sha256": "SHA256_OF_THE_OUT_OF_BAND_VERIFIED_ROCKY_9_PUBLIC_KEY",
  "unattended_reboot": false,
  "auth_probe": {
    "client_id": "nebulalog",
    "redirect_uri": "https://logs.example.test/health-oidc",
    "username": "nebulalog-health",
    "password": "GENERATE_A_UNIQUE_RANDOM_PASSWORD",
    "totp_secret": "GENERATE_A_UNIQUE_BASE32_OTP_SECRET",
    "totp_algorithm": "SHA256",
    "totp_digits": 6,
    "totp_period": 30
  }
}
```

The client uses authorization code with PKCE and an exact registered redirect URI.
The health account has only VIEWER and a pre-enrolled SHA256 TOTP credential. The
probe creates a fresh session and completes actual password and OTP browser forms,
validates callback state, exchanges the code, then requires authenticated
`/api/me` to return VIEWER. Password-only login, service tokens, direct grants and
external redirects cannot satisfy `local_auth`. HTTPS connections use the real
issuer Host/SNI with certificate/CA verification, connecting to loopback so the
edge can distinguish the actual local peer. The web health gate also fetches the
UI through this HTTPS edge.

Do not set `edge_service` for the host Apache deployment. Optional `data_root`,
`manager_state` and `quadlet_dir` overrides must equal the fixed installed paths;
relocation is not supported by this adapter. The compliance policy must be the
installed trusted policy consumed by `nebulalog compliance scan`. Enroll the Rocky
key fingerprint only after independent key verification. Unattended reboot stays
false until current TPM unlock and actual candidate-kernel boot survival are
qualified; the adapter never creates an unlock key or enables a weaker method.

## Component transaction contract

All seven component hooks accept exactly one argument: a direct child of
`/var/lib/nebulalog/manager/updates/releases`. The staged manifest hash must match
the durable verified transaction. Success writes a root0600 JSON receipt in that
directory and emits JSON with `ok:true`; failure returns nonzero with a sanitized
error type. Inspect protected receipts for details.

| Hook | Required effect and evidence |
| --- | --- |
| `update-preflight` | Verify encrypted paths, immutable previous pins, host controls, running services, real local MFA, supported versions and reserve. |
| `update-backup` | Publish host/database storage holds; stop API/Keycloak writers; dump and validate both PostgreSQL databases; preserve schema provenance, config permissions/ownership and original Quadlets; hash the inventory. Keep ingest receiving into WAL only if its running image is bound to the gate-aware release; otherwise stop it. On failure restore writers or retain maintenance with an explicit failed recovery receipt. |
| `update-prepare` | Import signed OCI archives with `skopeo copy --preserve-digests`; require exact inspected RepoDigest; stage only changed `Image=` lines. |
| `update-activate` | Stop known writers, verify the live schema, sync encrypted data and replace prepared Quadlets. Run only the reviewed schema transition if declared and required; verify its committed receipt before starting candidate writers. Resume delivery for health checks while destructive cleanup remains held. |
| `update-health` | Require API, HTTPS UI, PostgreSQL, ClickHouse, fresh local password+OTP, Keycloak, FIPS signals, SELinux, LUKS, firewall and policy SCAP checks; send a unique TCP514 canary and prove it persisted in ClickHouse. |
| `update-rollback` | Before activation: require a durable preactivation journal, original unchanged-runtime backup intent and a settled storage barrier; restart old services without restoring partial dumps. Failed activation: fence the retained migration executor, validate backups and record restore intent before restoring configuration/pins and both PostgreSQL databases. Reconcile actual schema provenance before publishing restore completion and resuming writers. A completed restore cannot replay. Later operator rollback preserves the current additive schema, users, metadata and config while restoring changed image pins. ClickHouse log data and WAL are never rewound from a metadata backup. |
| `update-finalize` | Require durable `committed`/`rolled_back` and complete health receipt, then release maintenance. |

The shared manager transaction lock serializes storage, OS and component work;
component work additionally takes its updater lock. A finalizer failure preserves
successfully committed software. `nebulalog update finalize` re-verifies retained
signed release metadata, reruns health and retries only gate release. It never
activates images or restores a database. Pending finalization blocks subsequent
updates. Retained metadata must still pass signature and exact transaction hash
checks. Its installation expiry may have elapsed for this access-recovery action;
expiry still blocks new installs and operator rollback activation.

Supported automatic changes are explicitly reversible, same-schema OCI releases
with `database_migration:"none"` and the installed `schema_revision`. PostgreSQL
must stay within its major version; ClickHouse must stay within its declared
major/minor family. Baseline/SCAP artifacts and schema/major database migrations
require separate qualified adapters and are refused here. Bounded database dump
and restore commands allow 600 seconds per database; archive validation allows
120 seconds, service operations 180 seconds, and each health SCAP command at most
900 seconds. An outer hook timeout remains a failure requiring journal recovery.

## External identity release evidence

A Keycloak change additionally names `qualification_artifact` in its signed
component definition. That JSON and each referenced browser evidence archive must
be artifacts in the same hash/length-verified signed release. Its schema is:

```json
{
  "schema": 1,
  "source_commit": "EXACT_SOURCE_COMMIT_HEX",
  "keycloak_image": "EXACT_CANDIDATE_REPOSITORY_AT_SHA256_DIGEST",
  "checks": {
    "local_password_otp": {"status":"passed", "method":"real_browser", "evidence_artifact":"identity-browser-evidence.tar"},
    "ad_ldaps_otp": {"status":"passed", "method":"real_browser", "evidence_artifact":"identity-browser-evidence.tar"},
    "saml_okta": {"status":"passed", "method":"real_browser", "evidence_artifact":"identity-browser-evidence.tar"},
    "saml_entra": {"status":"passed", "method":"real_browser", "evidence_artifact":"identity-browser-evidence.tar"},
    "saml_generic": {"status":"passed", "method":"real_browser", "evidence_artifact":"identity-browser-evidence.tar"},
    "oidc_generic": {"status":"passed", "method":"real_browser", "evidence_artifact":"identity-browser-evidence.tar"}
  }
}
```

This is a signed release attestation checked for candidate binding and completeness;
the installed updater cannot independently repeat sign-in at remote customer
providers. Release reviewers must inspect real candidate-specific success,
rejection, MFA and role evidence under the full acceptance matrix before signing.
Placeholder, simulated or service-token evidence must never be attested as passed.
Routine appliance health proves local MFA separately on the actual installed host.

## Lifecycle compliance review and retry

Lifecycle health retains its own assessment under the exact component or OS
transaction directory. `adapter-compliance.json` identifies its `configuration`,
assessment SHA256 and status. The assessment is bound to the installation,
selected policy/setup, current boot, installed RPM inventory, running image IDs
and Quadlet bytes. It does not copy a prior installation review. An unchanged
unreviewed assessment is retained across retries so an operator can review it.

An entirely passing automated assessment retains the existing automatic health
path. Other usable results require the existing explicit review of every finding,
including approved exceptions, not-applicable decisions and evidence for manual
controls. Errors or unexpectedly unchecked controls cannot be approved. Review
does not change the underlying failed-rule counts. Every accepted retry runs a
fresh bounded scan and requires identical rule outcomes, current host controls,
unchanged policy/runtime identities and an unexpired exact review. Changed rule
outcomes require a new assessment/review; no approval is silently carried forward.

On an authorized guest root console, use the `configuration` path printed in the
private transaction receipt as `<assessment-directory>`:

```sh
/usr/libexec/nebulalog/nebulalog-baseline --configuration <assessment-directory> \
  --setup /var/lib/nebulalog/configuration/bootstrap/setup.json review-template
/usr/libexec/nebulalog/nebulalog-baseline --configuration <assessment-directory> \
  --setup /var/lib/nebulalog/configuration/bootstrap/setup.json \
  review --review-file <root-owned-reviewed-findings.json> \
  --confirm-assessment-sha256 <exact-assessment-sha256>
```

The reviewer must inspect the retained content/reports and provide the complete
review, evidence and expiry fields; a template is not approval. Keep those files
on the encrypted filesystem. Use the same helper's `scan` command only when a
failed assessment needs a deliberate new attempt, then review its new exact hash.
Do not edit binding records or copy another assessment's approval.

For a pending OS new-boot transaction, retry `nebulalog update reboot-complete`;
maintenance remains active until every health check passes. For an already
committed or rolled-back component transaction awaiting finalization, retry
`nebulalog update finalize`. These commands preserve their existing signature,
transaction and boot gates. **Initial component installation still immediately
rolls back on health refusal; its `recovery_required` state has no public
review/resume command yet.** Reviewing an assessment does not repair that engine
gap, automatically commit an update or authorize removing maintenance manually.
This bounded recovery mechanism is not unattended update qualification, AIDE
baseline renewal, or a browser workflow. It requires installed-guest acceptance.

## OS reboot and boot ordering

The host hooks take no arguments. `update-os-preflight` verifies the enrolled Rocky
key and enabled signed repositories, checks runtime/security and captures encrypted
metadata backups, then resumes writers. `update-reboot-prepare` checks recent
backup integrity, encrypted-member TPM token unlock, selected-kernel initramfs
crypttab and fresh local MFA before draining/stopping services. It records the
current boot ID. `update-reboot-abort` recovers only that prepared operation,
restarts services, verifies API/local MFA, and returns `recovered:true` with
`health.api:true` and `health.local_auth:true` before the manager records recovery.
A failed or incomplete receipt retains `recovery_required`.

Install a root oneshot invoking `update-boot-gate` after the encrypted data mount
and completed first boot, **before** the HTTPS edge starts. Use
`RequiresMountsFor=/var/lib/nebulalog` and
`ConditionPathExists=/var/lib/nebulalog/configuration/lifecycle.json`. The edge must
require successful gate initialization. The encrypted authoritative marker is
`/var/lib/nebulalog/manager/maintenance.json` (root0600). Its nonsecret public copy
is `/run/nebulalog-public/maintenance.json` (root0644, parent0755 and
`httpd_var_run_t`). `/run/nebulalog` remains0700 for secret recovery material.
Boot gate recreates the public marker from encrypted state/unfinished journals
before the edge can accept external mutations.

Install a second root oneshot invoking `update-reboot-complete` after all five
runtime services and the HTTPS edge start, with the same mount/config conditions
and `TimeoutStartSec=3600`. The edge remains accessible to actual loopback peers
and enforces maintenance for external mutating API/auth requests; never authorize
loopback access from a caller-supplied forwarding header. Completion requires a
different observed boot ID and every real runtime health gate. It durably records
OS completion before removing maintenance. Failure preserves the gate and exposes
retry via `nebulalog update reboot-complete`. A successful `systemctl reboot`
request alone is never recorded as verified reboot survival.

## Local validation

```sh
PYTHONPATH=appliance:appliance/adapters python3 -m unittest discover -s appliance/adapters/tests -v
PYTHONPATH=appliance:appliance/adapters python3 -m unittest discover -s appliance/tests -v
```

These tests cover protocol and failure contracts with fake command runners. Real
qualification must retain signed candidate/image identity, encrypted storage and
service evidence, real auth/browser receipts, persisted canary, successful and
failed update recovery, later rollback preserving post-commit data, marker release
failure/retry and actual reboot/change-of-boot-ID proof.
