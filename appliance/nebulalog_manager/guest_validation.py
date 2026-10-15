"""Read-only, redacted evidence collection inside the authorized Rocky appliance.

No initialization, repair, service changes, image loading or credential probes.
Run on the guest and retain stdout outside it; there is no guest output file.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import ssl
import stat
import subprocess
import time
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from .common import CommandFailed, Refused, require_linux_root, trusted_file
from .firstboot import FirstBoot
from .storage import inspect
from .security import kernel_crypto_diagnostics

VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_:~-]{0,159}")
VMS = {"kvm", "qemu", "vmware", "microsoft", "xen", "oracle", "amazon", "google", "bochs", "uml", "bhyve", "parallels", "apple", "acrn", "powervm"}
DRIVERS = ("vmw_pvscsi", "vmxnet3", "virtio_blk", "virtio_scsi", "virtio_net")
PACKAGES = ("rocky-release", "kernel-core", "kernel-modules-core", "kernel-modules", "kernel-modules-extra",
            "openssl", "openssl-libs", "openssl-fips-provider", "crypto-policies", "crypto-policies-scripts",
            "libgcrypt", "gnutls", "nss", "nss-softokn", "nss-softokn-freebl", "selinux-policy", "selinux-policy-targeted",
            "container-selinux", "systemd", "podman", "skopeo", "cryptsetup", "cryptsetup-libs", "lvm2", "xfsprogs",
            "dracut", "dracut-fips", "audit", "firewalld", "httpd", "mod_ssl", "python3", "openscap-scanner", "scap-security-guide", "aide")
CORE_UNITS = ("nebulalog-firstboot.service", "nebulalog-console.service", "nebulalog-edge.service",
              "nebulalog-maintenance-gate.service", "nebulalog-reboot-verify.service", "nebulalog-status.service", "nebulalog-status.timer")
CONTAINERS = ("postgresql", "clickhouse", "keycloak", "api", "ingest")
LABELS = {"/var/lib/nebulalog": "var_lib_t", "/var/lib/nebulalog/configuration": "var_lib_t",
          "/var/lib/nebulalog/configuration/tls": "container_file_t", "/var/lib/nebulalog/configuration/edge-tls": "httpd_config_t",
          "/run/nebulalog-public": "httpd_var_run_t", "/run/nebulalog-status": "container_file_t",
          "/var/lib/nebulalog/containers": "container_var_lib_t"}


@dataclass
class Result:
    code: int
    stdout: str = ""
    stderr: str = ""


def command(argv, *, timeout=30, maximum=16 * 1024 * 1024):
    """Bound both output pipes without temporary files or inherited stdin."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={**os.environ, "LC_ALL": "C", "TMPDIR": "/run"}, start_new_session=True)
    streams, size = {"stdout": bytearray(), "stderr": bytearray()}, 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise Refused("Read-only validation command exceeded its deadline")
                for key, _ in selector.select(min(left, 1)):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(data)
                    if size > maximum:
                        raise Refused("Read-only validation command exceeded its output budget")
                    streams[key.data].extend(data)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return Result(code, streams["stdout"].decode("utf-8", "replace"), streams["stderr"].decode("utf-8", "replace"))
    finally:
        if process.poll() is None:
            # Stop only this collector's child; never a service or existing task.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()
        process.stderr.close()


def small_file(path, maximum=65536, *, protected=False):
    if protected:
        trusted_file(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise Refused("Expected a regular validation input")
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise Refused("Validation input exceeds its budget")
    return data.decode("utf-8", "strict")


def package_inventory(text):
    values = {name: [] for name in PACKAGES}
    for row in text.splitlines():
        fields = row.split("\t")
        if len(fields) == 2 and fields[0] in values and VERSION.fullmatch(fields[1]):
            values[fields[0]].append(fields[1])
    return {name: {"status": "observed" if versions else "unavailable", "nevra": sorted(set(versions))} for name, versions in values.items()}


def provider_inventory(text):
    result, current = {}, None
    for line in text.splitlines():
        match = re.fullmatch(r"  ([A-Za-z][A-Za-z0-9_-]{0,40})", line)
        if match:
            current = match[1]
            result[current] = {"status": "unavailable"}
        elif current:
            match = re.fullmatch(r"    (version|status): ([A-Za-z0-9.+_-]{1,80})", line)
            if match and (match[1] == "version" or match[2] in {"active", "inactive"}):
                result[current][match[1]] = match[2]
    return result


def listener_summary(text):
    observed = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in {"tcp", "udp"}:
            raise Refused("Unrecognized listening-socket output")
        endpoint = fields[4]
        address, separator, port = endpoint.rpartition(":")
        if not separator or not port.isdigit() or not 0 <= int(port) <= 65535:
            raise Refused("Unrecognized listening endpoint")
        address = address.strip("[]").split("%", 1)[0]
        if address == "*":
            scope, family = "wildcard", "unspecified"
        else:
            ip = ipaddress.ip_address(address)
            scope = "loopback" if ip.is_loopback else "wildcard" if ip.is_unspecified else "non_loopback"
            family = "ipv" + str(ip.version)
        observed.add((fields[0], int(port), scope, family))
    return [{"protocol": protocol, "port": port, "scope": scope, "family": family} for protocol, port, scope, family in sorted(observed)]


def verification_diagnostics(result, known):
    """Never emit raw systemd diagnostics: invalid directives may quote secrets."""
    categories, implicated = {}, set()
    for line in (result.stdout + "\n" + result.stderr).splitlines():
        if not line.strip():
            continue
        lower = line.lower()
        category = next((name for needle, name in (("cycle", "ordering_cycle"), ("not executable", "missing_executable"),
                        ("unknown key", "unknown_directive"), ("unknown lvalue", "unknown_directive"),
                        ("failed to parse", "invalid_setting"), ("dependency", "dependency")) if needle in lower), "other_diagnostic")
        categories[category] = categories.get(category, 0) + 1
        implicated.update(name for name in known if name in line)
    return {"status": "passed" if result.code == 0 and not categories else "failed", "exit_code": result.code,
            "diagnostic_counts": categories, "implicated_units": sorted(implicated)}


class Collector:
    def __init__(self, *, runner=command, firstboot=None, clock=lambda: datetime.now(timezone.utc)):
        self.runner, self.clock = runner, clock
        self.firstboot = firstboot or FirstBoot(runner=self.checked, inspector=lambda identity: inspect(identity, self.checked))
        self.deadline = None

    def call(self, argv, *, timeout=30):
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                raise Refused("Guest evidence collection deadline exceeded")
        return self.runner(argv, timeout=timeout)

    def checked(self, argv, *, timeout=30):
        result = self.call(argv, timeout=timeout)
        if result.code:
            raise CommandFailed(Path(argv[0]).name, result.code)
        return result.stdout.strip()

    def guard(self):
        require_linux_root()
        release_path = Path("/etc/os-release").resolve()
        if release_path not in {Path("/etc/os-release"), Path("/usr/lib/os-release")}:
            raise Refused("Unsupported operating-system release path")
        release = dict(line.split("=", 1) for line in small_file(release_path, protected=True).splitlines() if "=" in line)
        if release.get("ID", "").strip('"') != "rocky" or release.get("VERSION_ID", "").strip('"').split(".")[0] != "9":
            raise Refused("Validation runs only inside the authorized Rocky 9 appliance VM")
        if small_file(Path("/etc/nebulalog/bootstrap/state"), 128, protected=True).strip() != "unconfigured":
            raise Refused("Installed appliance identity marker is missing or invalid")
        virtual = self.checked(["systemd-detect-virt", "--vm"])
        if virtual not in VMS:
            raise Refused("Validation requires a recognized virtual machine")
        boot_id = small_file(Path("/proc/sys/kernel/random/boot_id"), 64).strip()
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", boot_id):
            raise Refused("Current boot identity is unavailable")
        return {"os": "rocky", "major_version": 9, "virtualization": virtual, "boot_id": boot_id}

    def section(self, operation):
        try:
            return operation()
        except (OSError, Refused, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            return {"status": "unavailable", "reason": "measured probe unavailable or rejected; no repair attempted"}

    def collect(self):
        self.deadline = time.monotonic() + 300
        host = self.guard()  # No inventory probes run if host/VM identity fails.
        result = {"schema": 1, "collector": "nebulalog-guest-validation", "observed_at": self.clock().isoformat(),
                  "host": host, "read_only": True, "qualification": "pending", "certification": "not asserted"}
        for name, operation in (("image_state", self.markers), ("fips", self.fips), ("module_signatures", self.module_signatures), ("algorithm_policy", self.algorithm_policy), ("packages", self.packages),
                                ("selinux", self.selinux), ("boot_drivers", self.drivers), ("systemd", self.systemd),
                                ("data_disks", self.disks), ("listeners", self.listeners), ("enrolled_runtime", self.runtime)):
            result[name] = self.section(operation)
        result["acceptance"] = {"status": "pending", "requires": ["interactive console and disk recovery", "human MFA and recovery enrollment",
            "provider integration", "PAN-OS receipt and workload", "baseline assessment and explicit review", "upgrade backup rollback and real reboot", "hypervisor import and signed release"]}
        return result

    def markers(self):
        base = Path("/etc/nebulalog/bootstrap")
        unsealed, sealed = base / "unsealed-build", base / "image-state"
        private_build = unsealed.exists() or unsealed.is_symlink()
        if private_build:
            small_file(unsealed, 1024, protected=True)
        sealed_marker = sealed.exists() or sealed.is_symlink()
        sealed_valid = small_file(sealed, 128, protected=True).strip() == "sealed" if sealed_marker else False
        if private_build and sealed_marker or sealed_marker and not sealed_valid:
            raise Refused("Conflicting or invalid image state markers")
        enrollment_artifacts = any(path.exists() or path.is_symlink() for path in (base / "firstboot.json", Path("/etc/nebulalog/storage.json"), Path("/etc/nebulalog/configured")))
        data = Path("/var/lib/nebulalog")
        info = data.lstat()
        root_directory = stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077
        mounted = os.path.ismount(data)
        empty = not any(data.iterdir())
        root_lock = self.checked(["passwd", "--status", "root"]).split()
        try:
            pwd.getpwnam("packer")
            build_user = True
        except KeyError:
            build_user = False
        ssh = self.call(["systemctl", "is-active", "sshd.service"])
        ssh_enabled = self.call(["systemctl", "is-enabled", "sshd.service"])
        lock_observed = len(root_lock) >= 2 and root_lock[0] == "root" and root_lock[1] in {"L", "LK"}
        return {"status": "observed", "image": "unsealed_private_build" if private_build else "sealed" if sealed_valid else "marker_missing",
                "pristine_observation": root_directory and not enrollment_artifacts and not mounted and empty,
                "enrollment_artifacts_present": enrollment_artifacts, "data_mounted": mounted, "data_directory_empty": empty,
                "root_locked": lock_observed, "build_account_present": build_user,
                "sshd_active": ssh.stdout.strip() == "active", "sshd_enabled": ssh_enabled.stdout.strip() == "enabled",
                "sealed_identity_checks": "passed" if sealed_valid and lock_observed and not build_user and ssh.stdout.strip() == "inactive" and ssh_enabled.stdout.strip() == "disabled" else "pending" if private_build else "failed",
                "universal_secret_absence": "not established by this observation"}

    def algorithm_policy(self):
        """Exercise default fetch policy; provider presence alone is insufficient."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        default = self.call(["openssl", "dgst", "-sha256", "/dev/null"])
        explicit = self.call(["openssl", "dgst", "-propquery", "fips=yes", "-sha256", "/dev/null"])
        prohibited = self.call(["openssl", "dgst", "-md5", "/dev/null"])
        def matches(result):
            return (result.code == 0 and not result.stderr.strip()
                    and re.fullmatch(r"(?:SHA256|SHA2-256)\(/dev/null\)= " + expected, result.stdout.strip()) is not None)
        refused = (prohibited.code != 0 and not prohibited.stdout.strip()
                   and "inner_evp_generic_fetch:unsupported" in prohibited.stderr)
        checks = {"default_sha256_known_digest": matches(default), "explicit_fips_sha256_known_digest": matches(explicit),
                  "default_md5_fetch_refused": refused}
        return {"status": "passed" if all(checks.values()) else "failed", **checks,
                "scope": "three OpenSSL CLI fetch/digest probes; does not establish every application cryptographic boundary"}

    def module_signatures(self):
        enforced = small_file(Path("/sys/module/module/parameters/sig_enforce"), 16).strip() == "Y"
        return {"status": "passed" if enforced else "failed", "enforced": enforced,
                "scope": "running kernel module signature enforcement; livepatch signer trust requires separate qualification"}

    def fips(self):
        kernel = small_file(Path("/proc/sys/crypto/fips_enabled"), 16).strip()
        mode = self.call(["fips-mode-setup", "--check"])
        policy = self.checked(["update-crypto-policies", "--show"])
        providers = provider_inventory(self.checked(["openssl", "list", "-providers", "-verbose"]))
        provider_active = providers.get("fips", {}).get("status") == "active"
        diagnostics = kernel_crypto_diagnostics(self.call(["journalctl", "-k", "--boot=0", "--no-pager", "--output=cat"]))
        mode_ok = kernel == "1" and mode.code == 0 and policy == "FIPS" and provider_active
        measured = "failed" if not mode_ok or diagnostics["status"] == "failed" else "passed" if diagnostics["status"] == "no_failure_observed" else "unavailable"
        return {"status": measured,
                "kernel_enabled": kernel == "1", "tool_check_exit_code": mode.code,
                "crypto_policy": policy if policy in {"FIPS", "DEFAULT", "LEGACY", "FUTURE"} else "unrecognized",
                "openssl_providers": providers, "active_fips_provider_observed": provider_active,
                "kernel_crypto_diagnostics": diagnostics,
                "cmvp_operating_environment": "pending qualification"}

    def packages(self):
        result = self.call(["rpm", "-q", "--queryformat", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n", *PACKAGES])
        inventory = package_inventory(result.stdout)
        return {"status": "observed", "query_exit_code": result.code, "packages": inventory,
                "note": "Unavailable entries may be absent optional or differently packaged components; no certification inferred"}

    def selinux(self):
        mode = self.checked(["getenforce"])
        labels = {}
        for name, expected in LABELS.items():
            path = Path(name)
            if not path.exists():
                labels[name] = {"status": "pending", "expected_type": expected}
                continue
            info = path.lstat()
            context = self.checked(["stat", "--format=%C", "--", name])
            parts = context.split(":", 3)
            if len(parts) != 4 or not all(re.fullmatch(r"[A-Za-z0-9_,:.-]{1,100}", item) for item in parts):
                raise Refused("Unrecognized SELinux label")
            labels[name] = {"status": "passed" if parts[2] == expected and not path.is_symlink() else "failed",
                            "type": parts[2], "range": parts[3], "expected_type": expected, "uid": info.st_uid,
                            "gid": info.st_gid, "mode": format(stat.S_IMODE(info.st_mode), "04o")}
        return {"status": "passed" if mode == "Enforcing" and not any(value["status"] == "failed" for value in labels.values()) else "failed",
                "mode": mode if mode in {"Enforcing", "Permissive", "Disabled"} else "unrecognized", "labels": labels,
                "actual_service_access_and_avcs": "pending runtime acceptance"}

    def drivers(self):
        kernel = self.checked(["uname", "--kernel-release"])
        if not VERSION.fullmatch(kernel):
            raise Refused("Unrecognized running kernel identity")
        image = Path("/boot") / ("initramfs-" + kernel + ".img")
        trusted_file(image)
        listing = self.checked(["lsinitrd", str(image)], timeout=90)
        modules = self.checked(["lsinitrd", "-m", str(image)], timeout=90)
        values = {}
        for name in DRIVERS:
            modinfo = self.call(["modinfo", "--set-version", kernel, "--field=filename", name])
            builtin = modinfo.code == 0 and modinfo.stdout.strip() == "(builtin)"
            pattern = r"(?:^|/)" + re.escape(name).replace("_", "[-_]") + r"\.ko(?:\.(?:xz|gz|zst))?(?:\s|$)"
            in_image = bool(re.search(pattern, listing))
            values[name] = {"status": "passed" if modinfo.code == 0 and (builtin or in_image) else "failed",
                            "available_for_running_kernel": modinfo.code == 0, "built_in": builtin, "module_in_initramfs": in_image}
        fips_module = bool(re.search(r"(?m)^\s*fips\s*$", modules))
        return {"status": "passed" if fips_module and all(value["status"] == "passed" for value in values.values()) else "failed",
                "running_kernel": kernel, "drivers": values, "fips_dracut_module_observed": fips_module,
                "hypervisor_boot": "pending imported-guest acceptance"}

    def systemd(self):
        installed = {}
        for directory in (Path("/etc/systemd/system"), Path("/run/systemd/generator")):
            for path in sorted(directory.glob("nebulalog-*")):
                if path.suffix not in {".service", ".timer"} or not re.fullmatch(r"nebulalog-[a-z0-9-]+\.(service|timer)", path.name):
                    continue
                trusted_file(path)
                installed[path.name] = str(path)
        missing = sorted(set(CORE_UNITS) - set(installed))
        if len(installed) > 128:
            raise Refused("Installed Captain’s Log unit inventory exceeds its budget")
        if not installed:
            return {"status": "failed", "missing_core_units": missing}
        # Do not enable generators or manual-page checks: this inspects installed
        # output without running generators/hooks or changing manager state.
        verification = verification_diagnostics(self.call(["systemd-analyze", "verify", "--man=no", "--recursive-errors=yes", *installed.values()], timeout=90), installed)
        services = {}
        for name in (*CORE_UNITS, *("nebulalog-" + component + ".service" for component in CONTAINERS)):
            result = self.call(["systemctl", "show", "--property=LoadState,ActiveState,SubState,Result", "--", name])
            values = dict(row.split("=", 1) for row in result.stdout.splitlines() if "=" in row)
            observed = {key: value for key, value in values.items() if key in {"LoadState", "ActiveState", "SubState", "Result"} and re.fullmatch(r"[a-z][a-z0-9-]{0,40}", value)}
            services[name] = {"status": "observed" if result.code == 0 and observed.get("LoadState") == "loaded" else "pending" if observed.get("LoadState") == "not-found" else "unavailable", **observed}
        generated = all("nebulalog-" + name + ".service" in installed for name in CONTAINERS)
        return {"status": "passed" if verification["status"] == "passed" and not missing else "failed", "verification": verification,
                "missing_core_units": missing, "unit_states": services, "container_units_generated": generated,
                "generator_execution": "observed_installed_output" if generated else "pending first runtime preparation",
                "actual_startup_reboot_order": "pending acceptance"}

    def disks(self):
        listing = json.loads(self.checked(["lsblk", "--json", "--bytes", "--paths", "--output", "NAME,TYPE,SIZE,SERIAL,RO,RM,MOUNTPOINTS"]))
        rows = listing["blockdevices"]
        if not isinstance(rows, list) or len(rows) > 64:
            raise Refused("Unexpected block-device inventory")
        result = []
        identities = list(Path("/dev/disk/by-id").glob("*"))[:1024]
        for item in rows:
            if item.get("type") != "disk":
                continue
            name = item.get("name", "")
            if not re.fullmatch(r"/dev/[A-Za-z0-9_-]{1,80}", name) or not stat.S_ISBLK(Path(name).stat().st_mode):
                raise Refused("Unexpected whole-disk identity")
            children = bool(item.get("children"))
            mounted = any(item.get("mountpoints") or [])
            candidate = not children and not mounted and not item.get("ro") and not item.get("rm")
            signatures = json.loads(self.checked(["wipefs", "--json", "--no-act", name])).get("signatures") if candidate else None
            if candidate and not isinstance(signatures, list):
                raise Refused("Signature observation is incomplete")
            holders = bool(list((Path("/sys/class/block") / Path(name).name / "holders").iterdir()))
            stable = any(path.resolve() == Path(name).resolve() and not path.name.endswith("-part1") for path in identities)
            serial = str(item.get("serial") or "").strip()
            result.append({"device": name, "bytes": int(item["size"]), "has_children": children, "mounted": mounted,
                           "read_only": bool(item["ro"]), "removable": bool(item["rm"]), "holders_present": holders,
                           "stable_identity_available": stable, "serial_present": bool(serial),
                           "serial_sha256": hashlib.sha256(serial.encode()).hexdigest() if serial else None,
                           "signature_count": len(signatures) if signatures is not None else None,
                           "blank_observation": "signature_free_unused_candidate" if candidate and not holders and not signatures and stable and serial else "not_confirmed_blank"})
        return {"status": "observed", "disks": result, "authorization": "observation only; no disk selected or initialization authorized",
                "full_disk_zero_scan": "not performed"}

    def listeners(self):
        values = listener_summary(self.checked(["ss", "--no-header", "--listening", "--numeric", "--tcp", "--udp"]))
        exposed = [row for row in values if row["scope"] != "loopback" and row["port"] in {5432, 8123, 9000, 8443, 9440}]
        return {"status": "failed" if exposed else "observed", "sockets": values, "public_database_or_private_identity_ports": exposed,
                "external_connectivity_and_firewall_rules": "not established by socket inventory"}

    def runtime(self):
        journal = Path("/etc/nebulalog/bootstrap/firstboot.json")
        if not journal.exists():
            if any(path.exists() or path.is_symlink() for path in (Path("/etc/nebulalog/storage.json"), Path("/etc/nebulalog/configured"))):
                raise Refused("Enrollment evidence exists without its required journal")
            return {"status": "pending", "reason": "storage enrollment has not begun; no runtime probes attempted"}
        gate = self.firstboot.gate()
        if gate.get("host_ready") is not True:
            raise Refused("Measured encrypted-storage gate did not pass")
        health = self.section(self.runtime_health)
        return {"status": health["status"], "encrypted_host_gate": "passed", "stored_completion_receipt_valid": gate.get("setup_complete") is True,
                "https_health": health, "human_mfa_and_recovery": "not probed", "fresh_authentication": "pending separate interactive acceptance"}

    def runtime_health(self):
        ca = trusted_file(Path("/var/lib/nebulalog/configuration/tls/ca.crt"))
        context = ssl.create_default_context(cafile=str(ca))
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
        with opener.open(Request("https://localhost/api/health"), timeout=10) as response:
            if response.status != 200:
                raise Refused("HTTPS health did not succeed")
            data = response.read(65537)
        if len(data) > 65536:
            raise Refused("Oversized runtime health response")
        health = json.loads(data)
        fields = {name: health.get(name) if health.get(name) in {"ok", "degraded", "unavailable", "unconfigured", "configured"} else "unrecognized" for name in ("status", "application", "postgresql", "clickhouse", "auth")}
        return {"status": "passed" if all(fields[name] == "ok" for name in ("status", "application", "postgresql", "clickhouse")) else "failed",
                "https_ca_and_name_verified": True, "health": fields}


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        result = Collector().collect()
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except Exception:
        print(json.dumps({"schema": 1, "status": "refused", "reason": "Requires the authorized root Rocky 9 appliance VM and protected installed marker; no repairs attempted"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
