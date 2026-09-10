# SELinux

Production acceptance requires `getenforce` to return `Enforcing`. The first-boot gate refuses any other result. SELinux must not be disabled to make a container start.

Quadlet bind mounts use `:Z` for private container data and `:z` for deliberately shared TLS, collector IPC and sanitized status. TLS and status are read-only in their consumers; the collector alone writes its shared observation file. Sensitive persistence stays under encrypted `/var/lib/nebulalog`. Image-specific UIDs own their data directories. Never relabel `/`, all of `/etc`, or broad unrelated host paths for container access.

## Separated host and container paths

| Path | Expected label/access |
|---|---|
| `/var/lib/nebulalog` and its `configuration` directory | Root-only parent directories with the distribution's `var_lib_t` label; no broad Apache/container relabel. Verify the actual mounted filesystem's labels. |
| `configuration/tls` | Persistent `container_file_t` rule for shared read-only mounts. Directory `root:20001` mode `0750`; server key `root:20001` mode `0640`; public CA/cert `0644`; CA private key stays root-only. TLS consumers receive group 20001. |
| `configuration/edge-tls` | Separate `httpd_config_t` rule. Root-only `0700` directory and `0600` server key; public cert/CA `0644`. Exact copies of the canonical identity, with no copied CA private key. No container mounts this tree. |
| `/run/nebulalog-public` | `httpd_var_run_t`, root-controlled `0755`; Apache's durable-maintenance projection only. |
| `/run/nebulalog-status` | Separate `container_file_t`, root-controlled `0755`; bounded sanitized status `0644`, mounted read-only by the API. New inodes are relabeled before atomic publication. |
| `/var/lib/nebulalog/containers` | File-context equivalence to the normal rootful Podman graphroot; persistent container metadata and extraction temporary space remain encrypted. |

The reviewed [Apache policy](https://github.com/fedora-selinux/selinux-policy/blob/899a51a9e626f54ce051be22aa7e62616baf887a/policy/modules/contrib/apache.te) invokes `files_var_lib_filetrans` and permits reading `httpd_config_t`. Its [files interface](https://github.com/fedora-selinux/selinux-policy/blob/899a51a9e626f54ce051be22aa7e62616baf887a/policy/modules/kernel/files.if) and [file-transition pattern](https://github.com/fedora-selinux/selinux-policy/blob/899a51a9e626f54ce051be22aa7e62616baf887a/policy/support/file_patterns.spt) provide directory traversal for `var_lib_t`. This supports retaining ordinary parent labels; it does not prove the policy package and labels installed in the final guest. No parent-wide `httpd_config_t` rule is added.

Apache's master starts as root to initialize TLS. Verify startup, reload and proxied TLS after worker privilege drop with the existing root-only directory permissions; do not widen them speculatively. The installer enables `httpd_can_network_connect` for the fixed reverse-proxy upstreams. Firewall rules and loopback bindings remain separate controls.

Bootstrap retries restore labels only on the host mountpoint and newly created directory inodes. They must never recursively restore all existing container data: that can remove a running private mount's MCS categories. The shared TLS and host edge-TLS trees have explicit persistent rules, so their bounded restores preserve the intended consumer type.

## Service ordering and exact-guest checks

The interactive console does not depend on the measured runtime gate; it must initialize storage before that gate can pass. Every application container requires the gate and encrypted mount. The maintenance gate then runs before public HTTPS, and reboot verification follows all runtime services and the edge. A missing lifecycle file fails maintenance restoration; it is not a condition that can silently skip the required service. This distinction follows [systemd's dependency and condition semantics](https://github.com/systemd/systemd/blob/v252/man/systemd.unit.xml).

The local suite checks the declared dependency graph and these contracts. In the actual guest, run the exact Quadlet generator and `systemd-analyze verify`, then inspect installed unit dependencies and `systemctl --failed`. Check path metadata with `ls -Zd`, `namei -l` and `matchpathcon -V` for each directory above; do not print private key or credential contents. If available, query the installed policy with `sesearch` for `httpd_t` directory search on `var_lib_t` and file read on `httpd_config_t`.

On a disposable appliance, inspect AVC records with `ausearch -m AVC,USER_AVC -ts recent`, correlate the precise service/access/path, and fix expected contexts and least-privilege policy. Do not blindly feed all denials to `audit2allow`. Port publication and the HTTPS edge also require explicit policy/firewall validation.

The image recipe includes `container-selinux` and targeted persistent file-context rules. Complete booted-policy acceptance remains pending; no blanket custom allow policy is shipped. Retain startup, retry, status freshness, maintenance reboot and AVC evidence from the exact candidate. A rendered Quadlet or source-policy review is insufficient.
