# Read-only installed-guest evidence

The collector is `/usr/libexec/nebulalog/validate-guest` (Python module `nebulalog_manager.guest_validation`). It accepts no arguments and runs only as root in a recognized Rocky Linux 9 VM with the protected installed NebulaLog marker. The parent build operator executes it inside the specifically authorized disposable guest. Do not run it on a development host or an unrelated server.

It emits a single JSON document on stdout. During the private build, the operator can capture that stream through the existing authorized SSH session into a private evidence file on the build host. The collector has no output-file option and does not persist a report in the guest. After sealing, do not reenable SSH for this tool; use the separately authorized guest acceptance path.

## Scope

The collector reads:

- Kernel FIPS state, `fips-mode-setup --check`, crypto policy and the actually active OpenSSL provider inventory. Exact relevant RPM versions are recorded; missing optional/differently packaged components are explicit.
- SELinux mode, expected host/container path labels and ownership/modes. Label matches do not prove successful service access or absence of AVCs.
- The running kernel, required driver availability, actual initramfs archive members and the FIPS dracut module. Existence of an initramfs file alone cannot pass these checks.
- Installed NebulaLog unit verification and bounded unit state properties. It does not invoke the Quadlet/systemd generators, reload the manager, start/stop units or read environment values. A diagnostic on successful `systemd-analyze verify` exit is still a failed verification result.
- Protected unsealed/sealed markers, root-lock/build-account/SSH state and whether storage enrollment artifacts or a mounted/populated data path exist. This is a pristine-state observation, not proof of universal-secret absence.
- Whole-disk metadata and signature/holder/mount observations using `wipefs --no-act`. It neither selects a disk nor authorizes initialization. Serial values are hashed. No complete zero scan is performed.
- Listener protocol, port and loopback/wildcard/non-loopback class. Literal addresses and process/command lines are omitted. A listening socket does not prove firewall reachability.
- After actual enrolled-storage validation succeeds, a CA/name-verified GET of local HTTPS health. It does not authenticate, enroll users, request tokens, mutate databases or perform repair. A validated stored completion receipt is reported separately from fresh interactive acceptance.

Commands have per-call deadlines and a combined five-minute budget. Output pipes are bounded; command stderr, environment files, journal bodies, credentials, certificate/private-key contents and raw diagnostic lines are never emitted. Child tools receive `TMPDIR=/run`; tools such as `lsinitrd` may allocate and clean private transient diagnostic scratch there. No appliance configuration or persistent report is written. Timeout cleanup stops only collector-owned child processes.

## Receipt semantics

The top-level contract is `schema: 1`, `collector: "nebulalog-guest-validation"`, `observed_at`, verified `host`, `read_only: true`, `qualification: "pending"`, and separate sections `image_state`, `fips`, `packages`, `selinux`, `boot_drivers`, `systemd`, `data_disks`, `listeners`, `enrolled_runtime` and `acceptance`.

| Section status | Meaning |
|---|---|
| `passed` | That bounded measured check met its stated conditions. |
| `failed` | The measurement completed but an expected condition was absent or contradicted. |
| `observed` | An inventory or observation; no broader qualification is claimed. |
| `pending` | The required installation/runtime stage has not been reached or needs separate acceptance. |
| `unavailable` | A probe failed, timed out or returned unrecognized/unsafe data. No previous result is reused. |

Exit zero means a structured collection completed, including any failed/pending/unavailable sections. Exit two means the collector could not enter the protected guest workflow; it returns a generic refusal without raw exception text. **Neither exit zero nor every locally measured check passing is a release signoff.** Human MFA/recovery, real forwarding/workload, reviewed baseline, storage recovery, upgrade/rollback/reboot, imported hypervisor behavior and signed release qualification remain explicit pending gates.

Thirteen local tests cover parsing/redaction, exact package versions, listening boundaries, driver/archive proof, host/VM refusal, resource budgets, preservation of encrypted-gate evidence when HTTPS is unavailable and the absence of inferred overall acceptance. These tests do not execute guest probes on the development host.

The diagnostic calls follow upstream [systemd verification options](https://github.com/systemd/systemd/blob/v252/man/systemd-analyze.xml) and [dracut's read/list modes](https://github.com/dracutdevs/dracut/blob/master/lsinitrd.sh). Actual command compatibility and results still require the installed Rocky guest.
