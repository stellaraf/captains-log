# First installation and enrollment

The first-boot engine initializes the explicitly reviewed blank data disk in a Rocky Linux 9 virtual appliance. Its automated checks and command models are tested on the development host; actual guest installation, disk operations, console interaction and reboot recovery require the retained guest acceptance results. A successful unit test or `host-ready` receipt does not establish a completed appliance.

## Console workflow

Open the imported VM's graphical console. On an unfinished sealed image, **Captain’s Log appliance console** appears automatically on the first virtual terminal (`/dev/tty1`). Press Enter to start or resume setup; no Linux username, password or shell command is needed. The root account stays locked. An administrator already working through an authorized appliance console can also invoke `nebulalog-setup`.

The wizard:

1. Checks the Rocky image marker, VM environment, active kernel/tool FIPS, FIPS crypto policy, SELinux Enforcing, firewalld and auditd.
2. Lists only blank, writable, unused disks with stable `/dev/disk/by-id` identities and nonempty serials. Select the designated data disk. It never chooses an unknown disk automatically.
3. Collects hostname, an existing management connection, DHCP or static IPv4/IPv6, DNS, NTP, a local administrator, security baseline, maintenance window and initial retention.
4. Shows the exact disk path, serial, actual capacity and configuration review. Typing the complete serial authorizes initialization. An expanded disk is fully allocated at its presented capacity.
5. Prompts twice for a unique disk unlock passphrase and a separate administrator password. Prompts are hidden; credentials are not command arguments, status output or journal data.
6. Creates GPT → LUKS2 → LVM PV/VG/LV → XFS, verifies persistent identities, mounts `/var/lib/nebulalog`, and installs boot entries. Encryption uses the selected console passphrase and an independently generated recovery passphrase. No plaintext persistent unlock key is written to the system disk.
7. Displays the disk recovery passphrase **only on the interactive console**. Store and check it in an off-appliance vault, then acknowledge `STORED`. Account recovery codes are separate. Do not record or share this console screen.
8. At `host-ready`, choose `NEW`, `MEDIA`, `RESTORE`, `STATUS`, or `LATER`. `NEW` requires an explicit second confirmation, then prepares application services and prints the verified HTTPS URL and certificate SHA-256 fingerprint. Sign in through the browser and complete mandatory MFA/recovery-code enrollment and forwarding setup. `MEDIA` imports a configuration recovery ISO; `RESTORE` uses already protected local files. Both enter the fresh-appliance recovery flow below before ordinary provisioning can create a new realm. `LATER` leaves host enrollment intact; returning to the console offers the same choice without repeating disk initialization or credential collection.
9. After the installation's reviewed security policy has been enrolled, choose `FILE INTEGRITY`. Its bounded console menu offers `STATUS`, explicit `PREPARE`, read-only `REVIEW`, full-digest-confirmed `ENROLL`, `CHECK` and `BACK`. Review the displayed installation, source/policy/database hashes and original verification evidence before typing the full confirmation. The menu never initializes automatically, resets an enrolled database or opens a shell. See [AIDE.md](AIDE.md).
10. Complete the separate SCAP assessment and findings review. Policy enrollment and findings approval still require their qualified operator workflow; this first-boot menu does not provide or fabricate them. If no valid reviewed policy exists, the file-integrity menu explains the prerequisite and creates nothing. A baseline name selected in step 3 is not evidence of approval.
11. Select `VERIFY` and re-enter the disk recovery passphrase from your vault. The engine tests it against the actual LUKS container, then requests live application verification. An explicit enrolled clean AIDE check must have completed within five minutes; choose `FILE INTEGRITY` → `CHECK` again if the intervening review took longer. Missing checks leave setup incomplete. Choose `LATER` to return and complete the remaining steps later.

The bootstrap administrator is created once. A retry must never reset a user's password or replace enrolled MFA. Once actual host identity, the private runtime-ready receipt and complete encrypted runtime journal have been verified, the wizard resumes at the completion menu without rerunning storage/configuration/application provisioning or recreating credential files. A state string or file's existence is insufficient. An interrupted partial runtime can resume guarded provisioning only before any AIDE state exists; later missing/inconsistent readiness requires qualified recovery, not automatic reprovisioning. Optional external identity configuration follows local enrollment and must preserve local break-glass access.

## Configuration recovery from the console

Choose `MEDIA` or `RESTORE` after enrolling a fresh target's blank disk and network and exporting its new disk recovery material. Use the backup source's hostname, administrator username and baseline, and isolate the source before reusing its address. The target must run the same immutable release and application schema recorded in the backup. The host-enrollment bootstrap password is temporary target input; applying a backup retains the source account password and existing MFA/recovery credentials. Do not enroll replacement MFA to bypass recovery.

`MEDIA` provides delivery before application services exist. Prepare an ISO9660 recovery image on a protected administrator workstation, using the authenticated encrypted configuration backup, its recipient certificate and its separately escrowed recovery key. The image root must contain **exactly** `backup.cms`, `recipient.pem` and `recovery-key.pk8`; no directories, links, scripts or additional files. The private key on media must be encrypted PKCS#8 using PBES2, PBKDF2-HMAC-SHA256 (100,000–2,000,000 iterations, 16–64 byte salt) and AES-256-CBC. The configuration backup itself must retain its authenticated CMS AES-256-GCM format. A plaintext or legacy-encrypted private key is refused.

For example, in a new private directory on the workstation, using OpenSSL with explicit `-saltlen` support and an installed ISO authoring tool:

```sh
umask 077
mkdir recovery-media
cp /protected/known-backup.cms recovery-media/backup.cms
cp /protected/recipient.pem recovery-media/recipient.pem
openssl pkcs8 -topk8 -in /protected/escrowed-recovery.key \
  -out recovery-media/recovery-key.pk8 -v2 aes-256-cbc \
  -v2prf hmacWithSHA256 -iter 600000 -saltlen 16
xorriso -as mkisofs -iso-level 3 -R -V CAPTAINS_LOG_RECOVERY \
  -o configuration-recovery.iso recovery-media
```

OpenSSL prompts for a new encryption passphrase without putting it in the command line. Use at least 14 characters and retain it separately from the ISO. Keep the original backup, original escrowed key and previously recorded backup SHA256 receipt off appliance. The ISO contains the encrypted private key; protect the ISO and do not place the passphrase beside it. ISO level 3 permits configuration backups larger than a single 4 GiB ISO9660 extent; the importer still limits `backup.cms` to 20 GiB + 256 MiB and each credential file to 64 KiB. Virtual optical capacity and large multi-extent images require qualification on the selected hypervisor.

Attach the ISO as a virtual optical drive through the hypervisor, then choose `MEDIA` and enter the explicit `/dev/srN` device, such as `/dev/sr0`. Nothing is selected or mounted automatically. The importer mounts only ISO9660 at its fixed private location with `ro,nodev,nosuid,noexec,nosymfollow`, verifies the device and mount options, copies bounded files into root-only scratch on the verified encrypted data filesystem, and unmounts before requesting secrets or applying recovery. It neither starts SSH nor downloads inputs or executes media content.

Compare the displayed configuration backup SHA256 with your **independently retained backup receipt**, then enter `IMPORT <complete-sha256>`. Typing the displayed value without that comparison does not establish the backup's origin. Enter the key passphrase at the hidden prompt; it travels to OpenSSL through stdin, never argv or journal output. The key must match the certificate. The coordinator then authenticates the backup and verifies compatibility without starting application services. Review the displayed source/target identities, scope, backup digest and expiring review digest. Confirm `RESTORE <enrolled-hostname>` only after checking that review, source isolation and the target's recovery export. The root media CLI instead requires `APPLY <review-uuid>`. `CANCEL` or a mismatched confirmation applies nothing; authenticated staged evidence remains protected on encrypted storage.

The importer reserves space for its copied inputs and scratch; the restore coordinator separately requires its complete encrypted restore reserve. Media copies and the temporary decrypted key are removed when the operation returns, including ordinary failures; original media files remain unchanged. A process or power interruption can retain root-only scratch on the encrypted data disk. If an interrupted mount remains, reboot before repeating import. Once the restore journal exists, use its `STATUS`/`RESUME` flow rather than importing again; it no longer needs the media key. Remove the virtual ISO after use. Cleanup is unlinking encrypted scratch, not a claim of secure physical erasure.

An authorized root CLI uses the same import and fingerprint/passphrase flow:

```sh
nebulalog restore --apply-fresh --media /dev/sr0
```

`RESTORE` remains available for three already protected **local file paths**: encrypted configuration backup, recipient certificate and private recovery key. Place the backup/certificate in root-controlled directories and the private key in a root-only file, preferably volatile `/run/nebulalog`, through an independently protected administrator workflow. The console accepts no pasted key contents, URLs or shell expansions.

This optical delivery path covers configuration recovery. Optional full log-data recovery can exceed optical-media capacity and still requires its separate complete recovery set, coordinator and protected delivery workflow. Multi-volume recovery media and a pre-runtime browser upload are not implemented by this path. The source and small fixtures do not establish real Rocky optical mounts, FIPS operation, power-loss survival or end-to-end recovery acceptance.

The local-file path also authenticates and displays its review before the final target confirmation. A review expires five minutes after preparation; an expired review must be prepared again. Apply repeats input and fresh-target checks and records ownership before runtime changes. If apply admission is interrupted before ownership is recorded, prepare another explicit review from the original inputs; the earlier evidence remains preserved. A failure returns to the guarded console without opening a shell. Once the durable restore pointer exists, retained recovery takes precedence over ordinary provisioning: `STATUS`, `RESUME`, and `LATER` are available. Status shows the operation UUID, allowlisted recorded stages and database acknowledgements; it does not expose credentials or raw diagnostics and is not a live health check. `RESUME` requires the complete UUID and uses retained inputs. An uncertain database/runtime action has no automatic replay; preserve the target for review or use a new fresh target. `NEW` and replacement inputs are unavailable once a restore owns the target.

After recovery reports `runtime_ready`, choose `CONTINUE`. The console validates the complete installed runtime evidence before opening the existing hardening, file-integrity and final-verification menu. Sign in with the restored account and existing MFA, verify roles/settings and new log receipt, review this target's security baseline, and verify its exported disk recovery credential. Recovery alone does not complete setup. See [BACKUP_RESTORE.md](BACKUP_RESTORE.md) for scope, failure handling and remaining native qualification.

The default unlock method prompts for the disk passphrase at boot through the hypervisor console. vTPM enrollment remains a separately qualified option. Losing both the console passphrase and recovery material can make the data unrecoverable.

If a checked prerequisite fails or you interrupt a prompt, the console reports a controlled error and waits for Enter to retry. It retains the installation journal and recovery material. Closing the terminal input or an unexpected implementation error ends the setup process without opening a root shell; restart the appliance and reopen its graphical console to resume. Complete browser enrollment before returning to final verification.

The automatic console accepts only Linux root with stdin, stdout and stderr attached directly to `/dev/tty1`. SSH sessions, pseudo-terminals and redirected output are refused. The service sends both output streams to that TTY, never to the journal, and disables core dumps. Recovery material can still appear in a hypervisor screenshot or console recording; keep this screen private.

| Image state | Local virtual console |
|---|---|
| Private build with `/etc/nebulalog/bootstrap/unsealed-build` | Automatic enrollment is disabled; the normal protected getty remains available. |
| Sealed image with unfinished enrollment | The root-owned `image-state` must say `sealed`; Enter starts the guarded wizard. |
| Valid completed enrollment | Automatic privileged setup ends; the normal protected getty and HTTPS management instructions remain. |
| Invalid completion receipt | Privileged setup refuses to restart; a marker alone cannot reopen enrollment. |

The installer enables `nebulalog-console.service`, installs `/usr/libexec/nebulalog/nebulalog-console`, and installs the `getty@tty1.service.d/50-nebulalog-firstboot.conf` drop-in. The drop-in uses OR conditions to allow the ordinary getty during private builds or after setup. There is no root autologin, shell fallback, or unconditional getty conflict. Service ordering places the console before getty; it queues the normal getty only after independently checking the completed installation receipt. The exact guest must still pass `systemd-analyze verify` and graphical-console acceptance, including unfinished, interrupted, resumed, completed and rebooted states.

## Setup states and service ordering

| State | Meaning |
|---|---|
| `unconfigured` | No disk initialization has started. |
| `in-progress` | A durable installation journal exists; its current stage may need resuming. |
| `host-ready` | Measured host controls, encrypted storage, unique runtime secrets and host configuration are ready. Containers may start. |
| `runtime-ready` | Live databases, Keycloak, HTTPS, initial administrator and required MFA policy are verified. Interactive enrollment is still outstanding. |
| `setup-complete` | Live MFA/recovery enrollment, Syslog receipt, assessed/reviewed security baseline, recent enrolled clean AIDE evidence and the disk recovery test have all passed. |

`nebulalog-firstboot.service` runs the measured `gate` command. It fails if the enrolled mount or host controls are absent. Its purpose is to release the containers after `host-ready`; requiring browser enrollment first would create a startup cycle. The final `/etc/nebulalog/configured` receipt is written only by successful final verification. A bare marker file or a unit-test result is insufficient.

## Automation interface

For the image build harness, the same engine has a noninteractive interface:

```sh
python3 -m nebulalog_manager.firstboot plan --config /etc/nebulalog/bootstrap/setup-input.json
python3 -m nebulalog_manager.firstboot apply --config /etc/nebulalog/bootstrap/setup-input.json --confirmation <reviewed-plan-sha256>
python3 -m nebulalog_manager.firstboot provision
python3 -m nebulalog_manager.firstboot complete --recovery-key-file /run/nebulalog/restored-recovery.key
python3 -m nebulalog_manager.firstboot status
```

These are guest commands. Do not execute them on an existing server. Mutations require Linux root, the installed appliance marker, Rocky 9 and VM detection. Configuration and credential inputs must be root-owned, root-only regular files. Passphrase files reside directly under `/run/nebulalog` and contain the exact credential bytes, without an appended newline. The engine rejects unknown JSON fields, arbitrary device paths, inline passwords and stale confirmation fingerprints.

Example input (contains paths only, no secrets):

```json
{
  "schema": 1,
  "disk": "/dev/disk/by-id/virtio-nebulalog-data",
  "unlock_key_file": "/run/nebulalog/setup-disk-passphrase",
  "hostname": "logs.example.com",
  "network": {
    "connection_uuid": "11111111-2222-4333-8444-555555555555",
    "ipv4": {"method": "auto"},
    "ipv6": {"method": "auto"},
    "dns": []
  },
  "ntp": ["ntp.example.com"],
  "administrator": {
    "username": "appliance-admin",
    "password_file": "/run/nebulalog/setup-administrator-password"
  },
  "baseline": "unified",
  "maintenance": {"weekday": 6, "start": "03:00", "end": "05:00", "timezone": "America/Phoenix"},
  "retention_days": 90
}
```

Static IP configuration uses `method: "manual"`, `addresses: ["192.0.2.10/24"]` and an optional `gateway`. DNS entries must be literal IPv4/IPv6 addresses; an empty list retains network-provided DNS. NTP entries are written to a managed Chrony source file. Baseline selection records intent; it never fabricates an assessment or silently waives failed controls.

## Runtime adapter protocol

The engine invokes only the installed, root-owned executable `/usr/libexec/nebulalog/bootstrap-runtime`:

```text
bootstrap-runtime prepare --setup /var/lib/nebulalog/configuration/bootstrap/setup.json --secrets /var/lib/nebulalog/configuration/bootstrap/secrets.json
bootstrap-runtime verify --setup /var/lib/nebulalog/configuration/bootstrap/setup.json
```

The encrypted setup JSON preserves validated configuration, adds `installation_id` and `required_actions: ["CONFIGURE_TOTP", "CONFIGURE_RECOVERY_AUTHN_CODES"]`, points `administrator.password_file` to the encrypted bootstrap directory, and removes `unlock_key_file`. `secrets.json` contains independent generated credentials named `postgresql_admin`, `postgresql_app`, `postgresql_keycloak`, `clickhouse`, `keycloak_bootstrap` and `identity_service`. The adapter must preserve these values across retries and delete the temporary administrator-password copy only after verified account creation.

Successful preparation returns:

```json
{
  "schema": 1,
  "installation_id": "the-exact-setup-uuid",
  "state": "runtime-ready",
  "checks": {
    "postgresql": true,
    "clickhouse": true,
    "keycloak": true,
    "https": true,
    "administrator_created": true,
    "administrator_mfa_required": true,
    "local_breakglass": true
  },
  "https_url": "https://logs.example.com",
  "tls_certificate_sha256": "64-hex-characters"
}
```

Final verification returns `state: "setup-complete"`, all preparation checks, and true checks named `administrator_mfa_enrolled`, `administrator_recovery_enrolled`, `syslog_received`, `baseline_assessed`, `baseline_review_complete`, `aide_enrolled` and `aide_checked_clean`. These must come from current service/credential/receipt evidence. File-integrity completion requires an explicitly enrolled AIDE database and a verified clean check no older than five minutes; final verification never initializes or replaces that baseline. Enroll file integrity after runtime provisioning and selected security policy, before baseline assessment/review, and run another clean check before completion if needed. The current pre-release console procedure is documented in [AIDE.md](AIDE.md); its browser management integration remains unfinished. The engine independently adds `disk_recovery_verified` after an actual cryptsetup test. Unknown adapter fields are not persisted; missing, false or mismatched checks refuse completion.

The installed runtime implementation is `nebulalog_manager.bootstrap`. It reads release-selected image digests from `/etc/nebulalog/images.json`, renders the sealed Quadlet and HTTPS templates, creates separate PostgreSQL databases/roles, runs application migrations, and provisions Keycloak identities. A declared offline image bundle at `/usr/share/nebulalog/images/manifest.json` must load through the installed verification helper; a missing expected digest does not fall back to a registry pull. Rootful Podman's graphroot must already be `/var/lib/nebulalog/containers`, so environment metadata and Podman secrets stay inside LUKS.

Canonical environment and lifecycle credential files remain under `/var/lib/nebulalog/configuration`; only Podman environment-file symlinks are placed under `/etc/nebulalog`. The server certificate/key and local CA are generated per installation. The shared server key is `root:20001` mode `0640`, the CA private key remains root-only, and application containers receive the supplemental TLS group. The ClickHouse lifecycle client config is `root:101` mode `0640` and mounted read-only.

The canonical certificate covers the selected hostname, `localhost`, `keycloak`, `clickhouse`, `127.0.0.1` and `::1`. Every required name and IP is checked on retries; an older certificate missing one is refused instead of silently replaced. ClickHouse uses HTTPS 8443 and secure native 9440 with the local CA. Its server password is a Podman-mounted secret; the application and initial migration receive the read-only CA mount and supplemental TLS group. The final image must prove these paths under its actual FIPS/SELinux runtime.

Host Apache receives exact copies of the same server certificate, server key and public CA in encrypted `configuration/edge-tls`, separate from the container TLS mount's SELinux label. That directory is root-only mode `0700`; its server key is `root:root` mode `0600`. The installer supplies an `httpd_config_t` file-context rule, which bootstrap restores before Apache starts. No CA private key is copied, no second TLS identity is generated, and a differing existing edge identity stops a retry. Bootstrap verifies the copied chain, hostname and key match before rendering Apache's paths.

The initial Keycloak master bootstrap administrator is disabled after scoped service identities are established, and the disabled state is independently checked. Runtime verification uses a fresh browser authorization-code flow with PKCE, password and SHA-256 TOTP through a dedicated local **VIEWER** health account. This does not substitute for human administrator enrollment. The human administrator is never given the health seed or automatically enrolled by the appliance.

Before HTTPS starts, bootstrap writes the encrypted lifecycle configuration so the required maintenance boot gate can inspect durable transactions. Missing lifecycle configuration must fail that gate, never become a skipped condition permitting HTTPS. After services start, the fixed `enroll-installed-release` helper measures the installed component inventory. Bootstrap validates its receipt against the protected initial-release descriptor's explicit sequence/hash, installation ID and exact runtime image pins. Missing metadata is refused. Candidate inventory enrollment does not enroll publisher trust or mark release qualification complete.

The OTP credential uses the pinned Keycloak model's explicit `BASE32` encoding; omitting it changes the key bytes. The required second-factor flow permits either OTP or an enrolled recovery code. See the upstream [OTP credential model](https://github.com/keycloak/keycloak/blob/26.7.3/server-spi/src/main/java/org/keycloak/models/credential/OTPCredentialModel.java), [recovery-code authenticator](https://github.com/keycloak/keycloak/blob/26.7.3/services/src/main/java/org/keycloak/authentication/authenticators/browser/RecoveryAuthnCodesFormAuthenticatorFactory.java), and [Keycloak FIPS guidance](https://www.keycloak.org/server/fips).

Local validation includes firstboot transaction/safety tests, runtime-bootstrap tests with actual OpenSSL CA/server generation, name/key verification, identity preservation and package-trust enrollment/refusal, plus 15 console boundary, retry, completion and service-contract tests. These checks run without modifying host disks or development containers; live guest Podman/Keycloak provisioning and full console/reboot acceptance are separate evidence.

## Interrupted installation

The journal is `/etc/nebulalog/bootstrap/firstboot.json`. It records configuration and review fingerprints, installation UUID, expected GPT/partition/LUKS/filesystem UUIDs, observed LVM identities and the active/completed stages. It contains no passphrases. Effects are journaled before execution and observed again on retry. A crash after volume-group creation can resume by verifying that the group contains only the enrolled PV; it does not create or format that disk again.

Resume with the **same configuration and disk identity**. Supply the same console disk passphrase if `/run` was lost at reboot. A changed serial, capacity during an in-progress transaction, foreign partition table, replaced LUKS header, conflicting volume group or unexpected filesystem causes refusal. Never delete the journal to force setup to continue; inspect retained evidence and recover the known installation.

If interruption occurs while adding a recovery slot and its generated runtime file is lost, restore that exact file before resuming. The engine will not silently generate a new recovery credential whose slot state is uncertain. No automatic rollback deletes GPT, LUKS, PV, LV, filesystem or recovery material.

The implementation follows the upstream [cryptsetup formatting options](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup-luksFormat.8.adoc) and [NetworkManager connection settings](https://networkmanager.dev/docs/api/latest/nm-settings-nmcli.html). Command support and security policy must still be verified in the exact qualified Rocky guest build.
