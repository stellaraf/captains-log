# Conditional qualification plan after clean3

Prepared **September 8, 2026** from the current collector/firstboot/console code, the matching frozen v7 copies, and the private clean3 launch recipe. **Clean3 was still building when this plan was prepared. No completed image, diagnostic boot, enrollment or sealing is asserted here. No command below was executed as part of preparing this document.**

The next result sought is narrow: a clean installed Rocky guest can boot from preserved private build artifacts with FIPS and SELinux intact, and its default data disk remains eligible for deliberate first enrollment. The later post-v7 host-plan source and its local integration tests are not part of this frozen guest candidate.

## Required input identity and completion gate

Private control files are under `.local/appliance-build/linux-clean-3/`: `plan.json`, `launch.py`, `README.md`, `attempts/.../result.json`, `output/packer-manifest.json`, and the private logs. Do not rerun `launch.py --start` against existing output, modify its inputs or adopt another build's files.

| Input | Pinned value |
| --- | --- |
| Builder image | `sha256:ba3c6acdd5dcff9af9da8abdc2d47c1fcef9361322847ea3193549c3dbdec0d9` |
| Repository source snapshot | `8ce5348245fb76c754b60a28251d76e9ca73a713bedbaedc21c393ae91e168c0` |
| Application source | `92aefc4a574364b13e63d6642fb89191b143bc50ae47aca712d7481e00385b4f` |
| Bundle manifest | `eb47ad560304c03982c38bf56698bd1ca212338d36a98312214e8ea46defe9d8` |
| Disk identity | `59ac86ef04924681`; OS serial `NL59ac86ef04924681OS`, data serial `NL59ac86ef04924681DT` |
| Build policy | `seal_image:false`; x86_64 QEMU/TCG, two guest CPUs, 4 GiB guest RAM |
| Output directory | `.local/appliance-build/linux-clean-3/output/rocky9/` |

The directory currently contains names `nebulalog-rocky9.qcow2` and `nebulalog-rocky9.qcow2-1`; these were observed during construction, not accepted as final artifacts. After completion, resolve roles again from the final manifest, recorded device wiring and measured virtual capacities. Expected capacities are **85,899,345,920 bytes (80 GiB)** for OS and **1,099,511,627,776 bytes (1 TiB)** for blank data. Never select an image merely because its filename looks right.

Before reading final image metadata or preparing overlays, require all of:

1. The exact attempt's `result.json` says `status:"completed"`, `reason:"packer_exited"`, `exit_code:0`, with the recorded image/attempt/container identities. A stopped, failed, missing or `stop_unconfirmed` result is not completion.
2. The recorded full container ID is stopped with exit zero, and no remaining process owns the output images. Preserve the launcher outcome and Packer manifest together; do not use `qemu-img --force-share` to inspect a still-owned image.
3. The frozen source/bundle/ISO/staging receipts still match. Hash completed output files only after their writer has stopped. Record file identity, byte length, allocated size, SHA256, tool versions and original input references in a new private receipt. No hash of a changing image is acceptance evidence.
4. The next diagnostic attempt has its own private directory, unique owner token/container ID, explicit image/overlay list and capacity guard. Keep the clean3 rule of **at least 10 GiB free before create/start**, two-second observation and a **5 GiB stop floor**. Bound the diagnostic boot attempt to 30 minutes, preserve outputs on timeout and stop only its proven container ID. An owned process that cannot be confirmed stopped blocks reuse of its overlays.

The existing clean3 launcher is a **Packer builder**, not a diagnostic-boot launcher. Prepare/review the guarded boot wrapper before executing the command specifications below. It must not restart the builder, mount the whole development workspace or select containers by a broad name pattern.

## Preserve the bases and prepare disposable overlays

Use the pinned Linux builder image for QEMU tools; the native macOS TCG probe previously failed the FIPS jitter-entropy requirement. No host device, Docker socket, host network, published host port, ISO or development environment file is needed for this boot.

The later diagnostic container's mount contract is:

| Container path | Source and access |
| --- | --- |
| `/in/base` | Exact completed clean3 `output/rocky9` directory, **read-only** |
| `/in/build-rsa` | Exact private build-access key file, **read-only**, kept private; never copied into `/work` receipts |
| `/work` | New attempt-owned private directory, the only persistent writable mount |
| `/tmp` | Bounded private tmpfs; container root filesystem read-only |

Use `--network=none`, `--restart=no`, `--init`, three Docker CPUs, 6 GiB memory, a process bound, dropped capabilities and `no-new-privileges`. Match the existing proved builder's file access; if the key or work directory is inaccessible, stop rather than relaxing source permissions. Capture exact arguments, mounts and Docker image/container/attempt identity before start.

The following are **future commands inside that isolated tool environment**, after the completion gate. Every destination must be absent; set private umask and exclusive output handling in the wrapper. Preserve command exit status separately from stdout/stderr.

```sh
qemu-img info -f qcow2 --output=json /in/base/nebulalog-rocky9.qcow2
qemu-img info -f qcow2 --output=json /in/base/nebulalog-rocky9.qcow2-1
qemu-img check -q -f qcow2 /in/base/nebulalog-rocky9.qcow2
qemu-img check -q -f qcow2 /in/base/nebulalog-rocky9.qcow2-1
qemu-img create -q -f qcow2 /work/reference-blank.qcow2 1099511627776
qemu-img compare -q -f qcow2 -F qcow2 /in/base/nebulalog-rocky9.qcow2-1 /work/reference-blank.qcow2
qemu-img create -q -f qcow2 -F qcow2 -b /in/base/nebulalog-rocky9.qcow2 /work/os-overlay.qcow2
qemu-img create -q -f qcow2 -F qcow2 -b /in/base/nebulalog-rocky9.qcow2-1 /work/data-overlay.qcow2
qemu-img info -f qcow2 --backing-chain --output=json /work/os-overlay.qcow2
qemu-img info -f qcow2 --backing-chain --output=json /work/data-overlay.qcow2
```

Require standalone original QCOW2 files, no unexpected backing chain/snapshots/encryption wrapper, matching capacities and zero comparison. The synthetic blank reference is sparse and does not initialize the guest disk. Never run repair, commit, rebase or resize against the original files. The two overlays must point to exactly the read-only bases. QEMU documents offline-image checks and explicitly formatted backing-file creation; these operations do not establish a bootable or encrypted appliance. [QEMU 7.2 image utility](https://raw.githubusercontent.com/qemu/qemu/v7.2.0/docs/tools/qemu-img.rst).

## First private boot and access

The guarded wrapper should invoke this QEMU argument set, preserving the build's OS/data device order and serials. It must first create a fresh private `/work/boot-1` directory exclusively and place this boot's stdout/stderr and command/collector receipts there. This is a command specification, not an instruction to start a VM during plan preparation:

```sh
qemu-system-x86_64 \
  -machine pc,accel=tcg -cpu max -smp 2 -m 4096 \
  -display none -boot order=c \
  -drive file=/work/os-overlay.qcow2,if=none,id=drive0,format=qcow2 \
  -drive file=/work/data-overlay.qcow2,if=none,id=drive1,format=qcow2 \
  -device virtio-blk-pci,id=nebulalog-os,drive=drive0,serial=NL59ac86ef04924681OS \
  -device virtio-blk-pci,id=nebulalog-data,drive=drive1,serial=NL59ac86ef04924681DT \
  -device virtio-net,netdev=user.0 \
  -netdev user,id=user.0,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22 \
  -serial file:/work/boot-1/installed-boot-serial.log \
  -qmp unix:/work/boot-1/boot.qmp,server=on,wait=off
```

There is no installer CD or replacement kernel command line: boot the installed disk and verify its actual FIPS state. QEMU's restricted user network blocks guest routing to host/outside except explicitly defined forwarding; the SSH forward above exists only on the isolated container's loopback. It is not a Docker-published port. [QEMU 7.2 network options](https://raw.githubusercontent.com/qemu/qemu/v7.2.0/qemu-options.hx).

Use the existing private `packer` build identity for this unsealed diagnostic stage. Pin its SSH host key in the new private attempt's `known_hosts` file. If this is the first connection, a new key may be enrolled only through this proven isolated container/owned-QEMU loopback path; preserve that trust receipt and require strict matching on subsequent connections. Never use global `StrictHostKeyChecking=no`, agent forwarding, raw key output or inherited credential/environment files.

From within that same container, after host-key pinning, the collection command is:

```sh
ssh -T -p 2222 -i /in/build-rsa \
  -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/work/known_hosts -o ConnectTimeout=10 \
  packer@127.0.0.1 'sudo -n /usr/libexec/nebulalog/validate-guest'
```

Capture stdout to a fresh host-private receipt through the wrapper; do not persist the collector report in the guest. Use the installed frozen helper, not a file copied from current source. Its internal five-minute budget and bounded subprocess output apply. Root's [read-only collector contract](../../appliance/validation/README.md) explains each section; exit zero means collection completed and may still contain failures/pending/unavailable results.

## Checkpoints before any enrollment

| Evidence | Required interpretation before proceeding |
| --- | --- |
| Host and image identity | Rocky 9 in the recognized VM; fresh boot ID; `image_state.image:"unsealed_private_build"`; `pristine_observation:true`; root locked; expected disposable build account/SSH may remain. |
| Foundation crypto | `fips.status:"passed"`: kernel FIPS `1`, successful `fips-mode-setup --check`, policy `FIPS`, actual active OpenSSL FIPS provider. No credential generation or setup on a failed/unavailable result. Exact RPM/module/OE qualification remains separate. |
| SELinux | `selinux.mode:"Enforcing"`, no failed observed labels. Paths requiring enrollment may be pending. Preserve bounded AVC diagnostics if needed; no permissive mode, blanket allow policy or repair/relabel action in this stage. |
| Installed boot | FIPS dracut module and required running-kernel drivers pass. No rescue/emergency/panic or recurrence of the rejected build's incomplete labels/services. A successful installer kernel alone is insufficient. |
| Units | Installed unit verification passes without diagnostics; auditd, firewalld, D-Bus and NetworkManager are active. Container generation/runtime readiness may remain pending before enrollment. No service start/reload/image loading merely to make a read-only check pass. |
| Blank data | Exact data serial/size maps to a distinct stable whole-disk by-id path; no child partitions, signatures, holders, mounts, read-only/removable flags. The initial offline zero comparison and guest signature/usage observation are separate evidence. OS disk must never be eligible. |
| Enrollment | No `firstboot.json`, `storage.json` or `configured` marker; data directory empty and unmounted; `enrolled_runtime` pending because enrollment has not begun. An encrypted-storage gate cannot legitimately pass yet. |
| Listening boundary | No exposed private DB/Keycloak ports. Private build SSH is expected here and must be removed by later sealing; socket inventory alone does not verify firewalld reachability. |

Additional exact read-only guest commands may be run through the same pinned SSH connection, retaining their exit status and sanitized/private output:

```sh
sudo -n env PYTHONPATH=/usr/lib/nebulalog python3 -m nebulalog_manager.firstboot status
sudo -n passwd -S root
sudo -n systemctl show nebulalog-console.service getty@tty1.service nebulalog-firstboot.service -p ActiveState -p SubState -p Result -p ConditionResult
sudo -n systemctl is-active auditd firewalld dbus NetworkManager
sudo -n cat /proc/sys/crypto/fips_enabled
sudo -n fips-mode-setup --check
sudo -n update-crypto-policies --show
sudo -n getenforce
sudo -n lsblk --json --bytes --paths --output NAME,TYPE,SIZE,SERIAL,RO,RM,MOUNTPOINTS
```

The unsealed console service is normally **skipped**, because its systemd conditions require a sealed marker and absence of `unsealed-build`. Therefore an “unsealed” banner is not required. `firstboot status` should report `unconfigured` and `setup_complete:false`, but by itself proves only journal absence. Calling the console helper over SSH/PTY refuses the local-tty guard and is not a graphical console test.

**Do not invoke `nebulalog-setup`, `wizard`, `apply`, `provision` or `complete` as readiness probes.** The unsealed marker blocks automatic console enrollment, not direct `FirstBoot.apply` or wizard calls. Those paths can create storage and secrets or alter networking. Do not create/delete state markers, initialize AIDE, run a sealer or load containers during this first observation stage.

## Clean shutdown, repeat boot and later branches

After the initial report, request guest shutdown through the existing private build session using `sudo -n /usr/sbin/shutdown -P now`. The expected SSH disconnect is not sufficient: confirm the exact QEMU/container stopped, retain its exit/serial/QMP evidence and perform image checks only after it stops. Rehash original base files and require byte identity with the preboot receipt. Preserve overlays, reports and command results; do not commit overlays into bases or remove evidence automatically.

A second bounded boot of these same overlays, with identical serials and pinned SSH identity, should show a changed boot ID, stable device identities/capacities, persistent FIPS/Enforcing state and continued absence of enrollment. Create a fresh private `/work/boot-2` directory exclusively and change both QEMU log/socket paths above to that directory; give stdout/stderr and every command/collector receipt fresh paths there too. Reuse only the exact overlay files and pinned `known_hosts`, never the first boot's log or receipt destinations. A forced-stop overlay is retained as a failed/interrupted attempt, not silently relabeled a clean second boot.

Only after those observations are reviewed should a separate branch begin:

1. A **read-only first-install plan** may use a newly prepared root-private configuration with the observed whole-disk by-id and existing NetworkManager UUID. `sudo -n env PYTHONPATH=/usr/lib/nebulalog python3 -m nebulalog_manager.firstboot plan --config /run/nebulalog/firstboot-review.json` validates the configuration and blank candidate; its output contains private identity/network metadata and a confirmation digest. Credential fields are distinct paths under `/run/nebulalog`; the plan does not read credential contents. Do not create passwords/unlock material merely to run this review. `destructive:true` describes future effects, not completed writes. Stop before `apply`.
2. **Sealing qualification** uses a new pristine branch of the preserved unsealed base before any enrollment. The real sealer must verify the completed protected build receipt, remove the build identity/material and stop the guest. Do not simulate sealing by changing markers. The sealer explicitly refuses an enrolled or populated appliance, so an enrollment experiment must never become a release base.
3. **Actual graphical first boot** starts from a separate sealed branch with blank data and a protected local `/dev/tty1` console, not this SSH-only diagnostic boot. Test default 1 TiB enrollment, later a separate sparse 5 TiB presentation, exact disk selection, hidden credentials, recovery handling, interruption/resume, real LUKS recovery and reboot. Such work needs its own capacity/network/secret-capture policy and receipts. No enrollment, FIPS operating-environment, SELinux runtime, MFA, hypervisor import or signed-release acceptance follows automatically from this readiness plan.

The current firstboot, console and collector modules were compared read-only with the frozen v7 copies and matched when this plan was written. The private source/launch receipts are still the authority for clean3; do not update frozen inputs to pick up unrelated current-tree work. Raw console/SSH/plan evidence and every image containing disposable or future installation identity remain private. Never publish private-key bytes, setup environments, password/token files or recovery-passphrase screens.
