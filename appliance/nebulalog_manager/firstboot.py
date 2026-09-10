"""Identity-bound first installation. This module never selects an unknown disk.

`plan` is read-only. `apply` requires the complete plan fingerprint, a Rocky VM,
active security controls and private runtime credentials. Storage effects are
preceded by a durable journal; uncertain effects are verified before reuse.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import uuid
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .common import CommandFailed, Refused, atomic_json, audit, locked, require_linux_root, run, trusted_file
from .enrollment import probe_blank
from .security import BASELINES, status as security_status
from .storage import Identity, inspect


@dataclass(frozen=True)
class Locations:
    etc: Path = Path("/etc/nebulalog")
    data: Path = Path("/var/lib/nebulalog")
    runtime: Path = Path("/run/nebulalog")
    crypttab: Path = Path("/etc/crypttab")
    fstab: Path = Path("/etc/fstab")
    chrony: Path = Path("/etc/chrony.d/nebulalog.sources")
    chrony_config: Path = Path("/etc/chrony.conf")

    @property
    def bootstrap(self):
        return self.etc / "bootstrap"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


RUNTIME_CHECKS = ("postgresql", "clickhouse", "keycloak", "https", "administrator_created", "administrator_mfa_required", "local_breakglass")
FINAL_CHECKS = RUNTIME_CHECKS + ("administrator_mfa_enrolled", "administrator_recovery_enrolled", "syslog_received", "baseline_assessed", "baseline_review_complete", "aide_enrolled", "aide_checked_clean")
HOST_STAGES = ("partition", "encryption", "recovery", "mapping", "physical-volume", "volume-group", "logical-volume", "filesystem", "mount", "settings", "network")
RUNTIME_ADAPTER = Path("/usr/libexec/nebulalog/bootstrap-runtime")


def _exact(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise Refused("Setup configuration has missing or unknown properties")


def validate_config(value: dict) -> dict:
    """Pure validation; passwords and keys are paths, never inline JSON values."""
    _exact(value, ("schema", "disk", "hostname", "network", "ntp", "administrator", "baseline", "maintenance", "retention_days", "unlock_key_file"))
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise Refused("Unsupported setup configuration schema")
    if not isinstance(value["disk"], str) or not re.fullmatch(r"/dev/disk/by-id/[A-Za-z0-9_.:-]+", value["disk"]) or value["disk"].endswith("-part1"):
        raise Refused("Select a stable whole-disk /dev/disk/by-id path")
    hostname = value["hostname"]
    if not isinstance(hostname, str) or len(hostname) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in hostname.split(".")):
        raise Refused("Enter a valid DNS hostname")
    network = value["network"]
    _exact(network, ("connection_uuid", "ipv4", "ipv6", "dns"))
    try:
        if str(uuid.UUID(network["connection_uuid"])) != network["connection_uuid"]:
            raise ValueError()
        for family in (4, 6):
            item = network["ipv" + str(family)]
            _exact(item, ("method",), ("addresses", "gateway"))
            if item["method"] not in ("auto", "manual", "disabled"):
                raise ValueError()
            addresses = item.get("addresses", [])
            if not isinstance(addresses, list) or len(addresses) > 8:
                raise ValueError()
            if item["method"] == "manual" and not addresses or item["method"] != "manual" and (addresses or item.get("gateway")):
                raise ValueError()
            for address in addresses:
                if ipaddress.ip_interface(address).version != family:
                    raise ValueError()
            if item.get("gateway") and ipaddress.ip_address(item["gateway"]).version != family:
                raise ValueError()
            if any("%" in address for address in addresses) or "%" in item.get("gateway", ""):
                raise ValueError()
        if all(network["ipv" + str(f)]["method"] == "disabled" for f in (4, 6)):
            raise ValueError()
        if not isinstance(network["dns"], list) or len(network["dns"]) > 8:
            raise ValueError()
        for address in network["dns"]:
            ipaddress.ip_address(address)
            if "%" in address:
                raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Refused("Invalid NetworkManager connection, IP address, gateway or DNS configuration") from None
    if not isinstance(value["ntp"], list) or not 1 <= len(value["ntp"]) <= 8 or any(not isinstance(n, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", n) for n in value["ntp"]):
        raise Refused("Supply one to eight NTP hostnames or addresses")
    admin = value["administrator"]
    _exact(admin, ("username", "password_file"))
    if not isinstance(admin["username"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{2,63}", admin["username"]):
        raise Refused("Administrator username must contain 3 to 64 permitted characters")
    if admin["username"].lower() in ("nebulalog-health", "nlbootstrap") or admin["username"].lower().startswith("service-account-"):
        raise Refused("This username is reserved for an internal appliance identity")
    for key in (value["unlock_key_file"], admin["password_file"]):
        if not isinstance(key, str) or Path(key).parent != Path("/run/nebulalog") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", Path(key).name):
            raise Refused("Credentials must be private files directly under /run/nebulalog")
    if value["unlock_key_file"] == admin["password_file"]:
        raise Refused("Disk unlock and administrator credentials must be separate")
    if value["baseline"] not in BASELINES:
        raise Refused("Select cis-level2, unified, or stig")
    if type(value["retention_days"]) is not int or not 1 <= value["retention_days"] <= 3650:
        raise Refused("Initial retention must be 1 to 3650 days")
    window = value["maintenance"]
    _exact(window, ("weekday", "start", "end", "timezone"))
    if type(window["weekday"]) is not int or not 0 <= window["weekday"] <= 6 or any(not isinstance(window[k], str) or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", window[k]) for k in ("start", "end")) or window["start"] == window["end"]:
        raise Refused("Supply a valid maintenance day and nonempty HH:MM window")
    try:
        ZoneInfo(window["timezone"])
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        raise Refused("Supply an installed IANA time zone") from None
    return value


def _private_file(path: Path, *, minimum=1, maximum=16384) -> bytes:
    trusted_file(path)
    info = path.stat()
    if info.st_mode & 0o077 or not minimum <= info.st_size <= maximum:
        raise Refused("Credential/configuration file must be root-only and within its size limits")
    return path.read_bytes()


def _private_dir(path: Path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise Refused("Setup directory must be private, root-owned and not a symlink")


def _write_bytes(path: Path, content: bytes, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise Refused("Refusing a symlink configuration destination")
    fd, name = tempfile.mkstemp(prefix=".setup-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _append_unique(path: Path, row: str, key: str):
    if path.exists():
        trusted_file(path)
    existing = path.read_text() if path.exists() else ""
    matching = [line for line in existing.splitlines() if line.strip() and not line.lstrip().startswith("#") and key in line.split()]
    if matching and matching != [row]:
        raise Refused("Existing boot storage entry conflicts with the enrolled identity")
    if not matching:
        _write_bytes(path, (existing.rstrip("\n") + "\n" + row + "\n").encode())


class FirstBoot:
    def __init__(self, paths=Locations(), *, runner=run, prober=probe_blank, inspector=inspect, security=security_status):
        self.paths, self.runner, self.prober, self.inspector, self.security = paths, runner, prober, inspector, security
        self.journal_path = paths.bootstrap / "firstboot.json"

    def _host(self):
        require_linux_root()
        trusted_file(self.paths.bootstrap / "state")
        release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
        if release.get("ID", "").strip('"') != "rocky" or release.get("VERSION_ID", "").strip('"').split(".")[0] != "9":
            raise Refused("Initial installation requires the Rocky Linux 9 appliance image")
        self.runner(["systemd-detect-virt", "--vm"])
        security = self.security(self.runner)
        if not security["host_controls_ok"]:
            diagnostic = security.get("kernel_crypto_diagnostics", {}).get("status")
            if diagnostic == "failed":
                raise Refused("Enrollment blocked: the current boot reports a kernel cryptographic self-test failure; inspect nebulalog compliance status and the kernel journal")
            if diagnostic == "unavailable":
                raise Refused("Enrollment blocked: complete current-boot kernel cryptographic diagnostics are unavailable")
            raise Refused("FIPS, SELinux Enforcing, firewalld and auditd must be active before enrollment")

    def config(self, path: Path) -> dict:
        return validate_config(json.loads(_private_file(path, maximum=65536)))

    def plan(self, config: dict) -> dict:
        validate_config(config)
        self._host()
        if self.journal_path.exists():
            journal = json.loads(trusted_file(self.journal_path).read_text())
            if journal["config_sha256"] != _digest(config):
                raise Refused("A different setup transaction exists; review its journal before changing configuration")
            return {**journal["plan"], "resume": True, "completed_stages": journal["completed"]}
        if (self.paths.etc / "storage.json").exists() or (self.paths.etc / "configured").exists():
            raise Refused("Appliance already has enrolled storage or completed configuration")
        if any(row["vg_name"] == "nebulalog" for row in self._lvm("vgs", "vg_name", "vg")):
            raise Refused("A Captain’s Log volume group already exists without an installation journal")
        if Path("/dev/mapper/nebulalog-data").exists() or self.paths.data.is_symlink() or self.paths.data.exists() and any(self.paths.data.iterdir()):
            raise Refused("Initial encryption mapping or unencrypted data directory is already in use")
        blank = self.prober(config["disk"])
        # The existing connection UUID is reviewed before disk changes as well.
        if self.runner(["nmcli", "--get-values", "connection.uuid", "connection", "show", "uuid", config["network"]["connection_uuid"]]) != config["network"]["connection_uuid"]:
            raise Refused("The selected network connection does not exist")
        plan = {"schema": 1, "operation": "first-install", "disk": blank["disk"], "serial": blank["serial"],
                "bytes": blank["bytes"], "blank_confirmation": blank["confirmation"], "config_sha256": _digest(config),
                "hostname": config["hostname"], "network": config["network"], "baseline": config["baseline"],
                "administrator": config["administrator"]["username"], "retention_days": config["retention_days"],
                "maintenance": config["maintenance"], "destructive": True,
                "warning": "The reviewed blank disk will be initialized and fully allocated; console network changes may disconnect clients"}
        return {**plan, "confirmation": _digest(plan)}

    def _save(self, journal):
        journal["updated_at"] = datetime.now(timezone.utc).isoformat()
        atomic_json(self.journal_path, journal)

    def _step(self, journal, name, effect):
        # Effects perform their own observed-state checks even after a completed
        # checkpoint. This supports interruption without trusting a stale flag.
        journal["active_stage"] = name
        self._save(journal)
        result = effect()
        if name not in journal["completed"]:
            journal["completed"].append(name)
        journal["active_stage"] = None
        self._save(journal)
        audit(self.paths.bootstrap / "audit.jsonl", "firstboot.stage", installation_id=journal["installation_id"], stage=name)
        return result

    def _blkid(self, device):
        try:
            raw = self.runner(["blkid", "--probe", "--output", "export", device])
        except CommandFailed as exc:
            if exc.returncode == 2:
                return {}
            raise
        return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)

    def _lvm(self, command, columns, kind):
        return json.loads(self.runner([command, "--reportformat", "json", "-o", columns]))["report"][0][kind]

    def _disk_unchanged(self, journal):
        disk = journal["plan"]["disk"]
        item = json.loads(self.runner(["lsblk", "--json", "--bytes", "--output", "NAME,TYPE,SERIAL,SIZE,RO,RM", disk]))["blockdevices"]
        if len(item) != 1 or item[0]["type"] != "disk" or str(item[0].get("serial") or "").strip() != journal["plan"]["serial"] or int(item[0]["size"]) != journal["plan"]["bytes"] or item[0]["ro"] or item[0]["rm"]:
            raise Refused("Reviewed disk identity or capacity changed during setup")

    def _storage(self, config, journal):
        disk, partition = config["disk"], config["disk"] + "-part1"
        mapping, mapper, lv = "nebulalog-data", "/dev/mapper/nebulalog-data", "/dev/nebulalog/data"
        key = config["unlock_key_file"]
        recovery = self.paths.runtime / ("luks-recovery-" + journal["installation_id"] + ".key")
        ids = journal["identities"]

        def partition_disk():
            self._disk_unchanged(journal)
            signatures = json.loads(self.runner(["wipefs", "--json", "--no-act", disk])).get("signatures", [])
            if not signatures:
                if self.prober(disk)["confirmation"] != journal["plan"]["blank_confirmation"]:
                    raise Refused("Blank disk review changed before GPT initialization")
                self.runner(["sfdisk", "--label", "gpt", disk], input=("label: gpt\nlabel-id: " + ids["gpt_uuid"] + "\nstart=2048, type=L, uuid=" + ids["partuuid"] + "\n").encode())
                self.runner(["udevadm", "settle"])
            table = json.loads(self.runner(["sfdisk", "--json", disk]))["partitiontable"]
            parts = table.get("partitions", [])
            if table.get("label") != "gpt" or table.get("id", "").lower() != ids["gpt_uuid"] or len(parts) != 1 or parts[0].get("uuid", "").lower() != ids["partuuid"] or os.path.realpath(parts[0]["node"]) != os.path.realpath(partition):
                raise Refused("Existing partition table does not match this installation's journal")
        self._step(journal, "partition", partition_disk)

        def encrypt():
            observed = self._blkid(partition)
            if not observed.get("TYPE"):
                self.runner(["cryptsetup", "luksFormat", "--batch-mode", "--type", "luks2", "--uuid", ids["luks_uuid"], "--pbkdf", "pbkdf2", "--cipher", "aes-xts-plain64", "--key-size", "512", "--hash", "sha256", "--key-file", key, partition], timeout=600)
                observed = self._blkid(partition)
            if observed.get("TYPE") != "crypto_LUKS" or observed.get("UUID") != ids["luks_uuid"]:
                raise Refused("Data partition does not contain this installation's LUKS identity")
            self.runner(["cryptsetup", "isLuks", "--type", "luks2", partition])
            self.runner(["cryptsetup", "open", "--test-passphrase", "--key-file", key, partition])
        self._step(journal, "encryption", encrypt)

        def enroll_recovery():
            if not recovery.exists():
                if "recovery" in journal["completed"]:
                    # An exported runtime copy is intentionally absent after a
                    # reboot; never rotate a verified recovery slot implicitly.
                    return
                if journal.get("recovery_key_sha256"):
                    raise Refused("Interrupted recovery enrollment lost its runtime key; restore the exact saved key before resuming")
                _write_bytes(recovery, secrets.token_hex(48).encode())
                journal["recovery_key_sha256"] = hashlib.sha256(recovery.read_bytes()).hexdigest()
                self._save(journal)
            secret = _private_file(recovery, minimum=32)
            if hashlib.sha256(secret).hexdigest() != journal["recovery_key_sha256"]:
                raise Refused("Recovery credential changed since generation")
            try:
                self.runner(["cryptsetup", "open", "--test-passphrase", "--key-file", str(recovery), partition])
            except CommandFailed as exc:
                if exc.returncode != 2:
                    raise
                self.runner(["cryptsetup", "luksAddKey", "--pbkdf", "pbkdf2", "--key-file", key, partition, str(recovery)], timeout=600)
                self.runner(["cryptsetup", "open", "--test-passphrase", "--key-file", str(recovery), partition])
        self._step(journal, "recovery", enroll_recovery)

        def open_mapping():
            if not Path(mapper).exists():
                self.runner(["cryptsetup", "open", "--key-file", key, partition, mapping])
            output = self.runner(["cryptsetup", "status", mapping])
            backing = next((line.split(":", 1)[1].strip() for line in output.splitlines() if line.strip().startswith("device:")), None)
            if not backing or os.path.realpath(backing) != os.path.realpath(partition):
                raise Refused("Existing encryption mapping targets another partition")
        self._step(journal, "mapping", open_mapping)

        def physical_volume():
            observed = self._blkid(mapper)
            if not observed.get("TYPE"):
                self.runner(["pvcreate", mapper])
            elif observed.get("TYPE") != "LVM2_member":
                raise Refused("Encryption mapping contains an unexpected filesystem")
            rows = [row for row in self._lvm("pvs", "pv_name,pv_uuid,vg_name,vg_uuid", "pv") if os.path.realpath(row["pv_name"]) == os.path.realpath(mapper)]
            if len(rows) != 1 or rows[0]["vg_name"] not in ("", "nebulalog") or ids.get("pv_uuid", rows[0]["pv_uuid"]) != rows[0]["pv_uuid"]:
                raise Refused("PV identity or ownership does not match setup")
            ids["pv_uuid"] = rows[0]["pv_uuid"]
        self._step(journal, "physical-volume", physical_volume)

        def volume_group():
            members = [r for r in self._lvm("pvs", "pv_name,pv_uuid,vg_name,vg_uuid", "pv") if r["vg_name"] == "nebulalog"]
            if not members:
                self.runner(["vgcreate", "nebulalog", mapper])
                members = [r for r in self._lvm("pvs", "pv_name,pv_uuid,vg_name,vg_uuid", "pv") if r["vg_name"] == "nebulalog"]
            if len(members) != 1 or members[0]["pv_uuid"] != ids["pv_uuid"] or ids.get("vg_uuid", members[0]["vg_uuid"]) != members[0]["vg_uuid"]:
                raise Refused("Volume group contains storage outside this installation")
            ids["vg_uuid"] = members[0]["vg_uuid"]
        self._step(journal, "volume-group", volume_group)

        def logical_volume():
            tag = "nebulalog.install." + journal["installation_id"]
            rows = [r for r in self._lvm("lvs", "lv_path,lv_uuid,vg_uuid,lv_tags,segtype", "lv") if r["vg_uuid"] == ids["vg_uuid"]]
            if not rows:
                self.runner(["lvcreate", "--name", "data", "--extents", "100%FREE", "--addtag", tag, "nebulalog"])
                rows = [r for r in self._lvm("lvs", "lv_path,lv_uuid,vg_uuid,lv_tags,segtype", "lv") if r["vg_uuid"] == ids["vg_uuid"]]
            if len(rows) != 1 or rows[0]["lv_path"] != lv or tag not in rows[0]["lv_tags"].split(",") or rows[0]["segtype"] != "linear" or ids.get("lv_uuid", rows[0]["lv_uuid"]) != rows[0]["lv_uuid"]:
                raise Refused("Logical volume does not match the journaled installation")
            ids["lv_uuid"] = rows[0]["lv_uuid"]
        self._step(journal, "logical-volume", logical_volume)

        def filesystem():
            observed = self._blkid(lv)
            if not observed.get("TYPE"):
                self.runner(["mkfs.xfs", "-m", "uuid=" + ids["filesystem_uuid"], lv], timeout=600)
                observed = self._blkid(lv)
            if observed.get("TYPE") != "xfs" or observed.get("UUID") != ids["filesystem_uuid"]:
                raise Refused("Filesystem does not match this installation's identity")
        self._step(journal, "filesystem", filesystem)

        def mount():
            self.paths.data.mkdir(mode=0o700, exist_ok=True)
            try:
                self.runner(["mountpoint", "--quiet", str(self.paths.data)])
            except CommandFailed as exc:
                if exc.returncode != 32:
                    raise
                if any(self.paths.data.iterdir()):
                    raise Refused("Unencrypted data mountpoint is not empty; refusing to hide existing files")
                self.runner(["mount", "--options", "nodev,nosuid", lv, str(self.paths.data)])
            identity = Identity(disk, journal["plan"]["serial"], partition, ids["partuuid"], ids["luks_uuid"], mapping, ids["pv_uuid"], ids["vg_uuid"], ids["lv_uuid"])
            self.inspector(identity)
            atomic_json(self.paths.etc / "storage.json", asdict(identity))
            _append_unique(self.paths.crypttab, f"{mapping} UUID={ids['luks_uuid']} none luks", mapping)
            _append_unique(self.paths.fstab, f"UUID={ids['filesystem_uuid']} /var/lib/nebulalog xfs defaults,nodev,nosuid 0 2", "/var/lib/nebulalog")
            self.runner(["systemctl", "daemon-reload"])
        self._step(journal, "mount", mount)
        return recovery

    def _settings(self, config, journal):
        root = self.paths.data / "configuration"
        _private_dir(root)
        _private_dir(root / "bootstrap")
        setup = {**config, "installation_id": journal["installation_id"], "required_actions": ["CONFIGURE_TOTP", "CONFIGURE_RECOVERY_AUTHN_CODES"]}
        # Runtime adapter reads the administrator password from this encrypted
        # file, then deletes it after verified idempotent account creation.
        setup["administrator"] = {**config["administrator"], "password_file": str(root / "bootstrap" / "administrator-password")}
        setup.pop("unlock_key_file")
        secret_path = root / "bootstrap" / "administrator-password"
        if "settings" not in journal["completed"]:
            _write_bytes(secret_path, _private_file(Path(config["administrator"]["password_file"]), minimum=14))
        atomic_json(root / "bootstrap" / "setup.json", setup)
        secret_bundle = root / "bootstrap" / "secrets.json"
        if not secret_bundle.exists():
            if "settings" in journal["completed"]:
                raise Refused("Previously generated installation secrets are missing")
            atomic_json(secret_bundle, {name: secrets.token_hex(32) for name in ("postgresql_admin", "postgresql_app", "postgresql_keycloak", "clickhouse", "keycloak_bootstrap", "identity_service")})
        else:
            _private_file(secret_bundle)
        atomic_json(self.paths.etc / "maintenance.json", {**config["maintenance"], "automatic_os_updates": True, "automatic_application_updates": True})
        atomic_json(root / "initial-retention.json", {"global_days": config["retention_days"]})
        atomic_json(root / "baseline-selection.json", {"baseline": config["baseline"], "assessment_status": "pending"})
        self.runner(["restorecon", "-RF", str(self.paths.data), str(self.paths.etc)])

    def _network(self, config):
        self.runner(["hostnamectl", "set-hostname", config["hostname"]])
        self.runner(["timedatectl", "set-timezone", config["maintenance"]["timezone"]])
        network = config["network"]
        argv = ["nmcli", "connection", "modify", "uuid", network["connection_uuid"]]
        for family in (4, 6):
            prefix, item = "ipv" + str(family), network["ipv" + str(family)]
            dns = [s for s in network["dns"] if ipaddress.ip_address(s).version == family]
            argv += [prefix + ".method", item["method"], prefix + ".addresses", ",".join(item.get("addresses", [])), prefix + ".gateway", item.get("gateway", ""), prefix + ".dns", ",".join(dns), prefix + ".ignore-auto-dns", "yes" if network["dns"] else "no"]
        self.runner(argv)
        self.runner(["nmcli", "--wait", "60", "connection", "up", "uuid", network["connection_uuid"]], timeout=90)
        self.paths.chrony.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        _write_bytes(self.paths.chrony, "".join("server " + host + " iburst\n" for host in config["ntp"]).encode(), 0o644)
        _append_unique(self.paths.chrony_config, "sourcedir /etc/chrony.d", "/etc/chrony.d")
        self.runner(["restorecon", str(self.paths.chrony)])
        self.runner(["systemctl", "restart", "chronyd"])

    def apply(self, config: dict, confirmation: str) -> dict:
        validate_config(config)
        self._host()
        from .setup_integrity import _integrity_state_exists
        if _integrity_state_exists(self):
            raise Refused("File-integrity state already exists; automatic host reconfiguration is refused")
        _private_dir(self.paths.bootstrap)
        _private_dir(self.paths.runtime)
        # Input passphrases must remain recoverable from the physical console.
        # Never keep the LUKS unlock key on the unencrypted system disk.
        _private_file(Path(config["unlock_key_file"]), minimum=14)
        with locked(self.paths.bootstrap / "firstboot.lock"):
            if _integrity_state_exists(self):
                raise Refused("File-integrity state already exists; automatic host reconfiguration is refused")
            plan = self.plan(config)
            if not secrets.compare_digest(plan["confirmation"], confirmation):
                raise Refused("Setup review is stale or confirmation does not match")
            if self.journal_path.exists():
                journal = json.loads(trusted_file(self.journal_path).read_text())
            else:
                _private_file(Path(config["administrator"]["password_file"]), minimum=14)
                journal = {"schema": 1, "installation_id": str(uuid.uuid4()), "config_sha256": _digest(config), "plan": plan,
                           "completed": [], "active_stage": None,
                           "identities": {key: str(uuid.uuid4()) for key in ("gpt_uuid", "partuuid", "luks_uuid", "filesystem_uuid")}}
                self._save(journal)
            try:
                recovery = self._storage(config, journal)
                self._step(journal, "settings", lambda: self._settings(config, journal))
                self._step(journal, "network", lambda: self._network(config))
                self._host()
                marker = {"schema": 1, "installation_id": journal["installation_id"], "config_sha256": journal["config_sha256"], "state": "host-ready", "setup_complete": False}
                atomic_json(self.paths.bootstrap / "host-ready.json", marker)
                return {**marker, "recovery_key_path": str(recovery), "next": "Export and verify disk recovery material, provision runtime, enroll administrator MFA and recovery codes, then verify Syslog and baseline"}
            except Exception as exc:
                audit(self.paths.bootstrap / "audit.jsonl", "firstboot.failed", installation_id=journal["installation_id"], stage=journal["active_stage"], reason=type(exc).__name__)
                raise

    def gate(self):
        self._host()
        marker = json.loads(trusted_file(self.paths.bootstrap / "host-ready.json").read_text())
        journal = json.loads(trusted_file(self.journal_path).read_text())
        if marker.get("state") != "host-ready" or marker.get("installation_id") != journal.get("installation_id") or marker.get("config_sha256") != journal.get("config_sha256") or set(HOST_STAGES) - set(journal.get("completed", [])) or journal.get("active_stage"):
            raise Refused("Firstboot host-ready receipt does not match the installation journal")
        identity = Identity(**json.loads(trusted_file(self.paths.etc / "storage.json").read_text()))
        self.inspector(identity)
        return {"host_ready": True, "setup_complete": self._completed(journal), "installation_id": journal["installation_id"]}

    def _completed(self, journal):
        path = self.paths.etc / "configured"
        if not path.exists():
            return False
        marker = json.loads(trusted_file(path).read_text())
        return marker.get("schema") == 1 and marker.get("installation_id") == journal["installation_id"] and marker.get("state") == "setup-complete" and all(marker.get("checks", {}).get(key) is True for key in FINAL_CHECKS + ("disk_recovery_verified",))

    def _runtime_receipt(self, action, installation_id):
        trusted_file(RUNTIME_ADAPTER)
        if not os.access(RUNTIME_ADAPTER, os.X_OK):
            raise Refused("Runtime provisioning adapter is not executable")
        argv = [str(RUNTIME_ADAPTER), action, "--setup", str(self.paths.data / "configuration/bootstrap/setup.json")]
        if action == "prepare":
            argv += ["--secrets", str(self.paths.data / "configuration/bootstrap/secrets.json")]
        receipt = json.loads(self.runner(argv, timeout=5400 if action == "prepare" else 900))
        checks = RUNTIME_CHECKS if action == "prepare" else FINAL_CHECKS
        state = "runtime-ready" if action == "prepare" else "setup-complete"
        if receipt.get("schema") != 1 or receipt.get("installation_id") != installation_id or receipt.get("state") != state or not all(receipt.get("checks", {}).get(key) is True for key in checks):
            raise Refused("Runtime verification is incomplete; setup has not been marked complete")
        # Retain only the protocol's nonsecret evidence, never arbitrary adapter
        # output such as bootstrap credentials, tokens or provider configuration.
        result = {"schema": 1, "installation_id": installation_id, "state": state, "checks": {key: True for key in checks}, "verified_at": datetime.now(timezone.utc).isoformat()}
        if "https_url" in receipt:
            parsed = urlparse(receipt["https_url"])
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise Refused("Runtime returned an invalid public HTTPS URL")
            result["https_url"] = receipt["https_url"]
        for field in ("tls_certificate_sha256", "tls_ca_certificate_sha256"):
            if field in receipt:
                if not isinstance(receipt[field], str) or not re.fullmatch(r"[0-9a-fA-F]{64}", receipt[field]):
                    raise Refused("Runtime returned an invalid certificate fingerprint")
                result[field] = receipt[field].lower()
        return result

    def provision(self):
        gate = self.gate()
        from .setup_integrity import _integrity_state_exists
        if _integrity_state_exists(self):
            raise Refused("File-integrity state already exists; automatic runtime reprovisioning is refused")
        with locked(self.paths.bootstrap / "firstboot.lock"):
            if _integrity_state_exists(self):
                raise Refused("File-integrity state already exists; automatic runtime reprovisioning is refused")
            receipt = self._runtime_receipt("prepare", gate["installation_id"])
            atomic_json(self.paths.bootstrap / "runtime-ready.json", receipt)
            audit(self.paths.bootstrap / "audit.jsonl", "firstboot.runtime-ready", installation_id=gate["installation_id"])
            return {**receipt, "setup_complete": False, "next": "Sign in, enroll MFA and recovery codes, configure forwarding, explicitly enroll and check file integrity, review baseline findings, and verify exported disk recovery material"}

    def complete(self, recovery_key_file: Path):
        gate = self.gate()
        with locked(self.paths.bootstrap / "firstboot.lock"):
            journal = json.loads(trusted_file(self.journal_path).read_text())
            recovery = _private_file(recovery_key_file, minimum=32)
            if hashlib.sha256(recovery).hexdigest() != journal.get("recovery_key_sha256"):
                raise Refused("Provide the recovery credential exported for this installation")
            partition = journal["plan"]["disk"] + "-part1"
            self.runner(["cryptsetup", "open", "--test-passphrase", "--key-file", str(recovery_key_file), partition])
            receipt = self._runtime_receipt("verify", gate["installation_id"])
            receipt["checks"]["disk_recovery_verified"] = True
            atomic_json(self.paths.etc / "configured", receipt)
            audit(self.paths.bootstrap / "audit.jsonl", "firstboot.complete", installation_id=gate["installation_id"])
            return {**receipt, "setup_complete": True}

    def status(self):
        require_linux_root()
        if not self.journal_path.exists():
            return {"state": "unconfigured", "setup_complete": False}
        journal = json.loads(trusted_file(self.journal_path).read_text())
        complete = self._completed(journal)
        state = "setup-complete" if complete else "runtime-ready" if (self.paths.bootstrap / "runtime-ready.json").exists() else "host-ready" if (self.paths.bootstrap / "host-ready.json").exists() else "in-progress"
        return {"state": state, "setup_complete": complete, "installation_id": journal["installation_id"], "completed_stages": journal["completed"], "active_stage": journal["active_stage"]}


def _answer(prompt, default=None):
    value = input(prompt + (" [" + str(default) + "]" if default is not None else "") + ": ").strip()
    return value or default or ""


def _password_file(path: Path, prompt: str):
    first = getpass.getpass(prompt + ": ")
    if len(first) < 14 or len(first.encode()) > 1024 or any(c in first for c in ("\n", "\r", "\0")):
        raise Refused("Use a passphrase of 14 or more characters without line breaks")
    if first != getpass.getpass("Repeat " + prompt.lower() + ": "):
        raise Refused("Passphrases do not match")
    _write_bytes(path, first.encode())


def _console_recovery(manager, prepared):
    """Display only on the explicitly interactive console, never in JSON output."""
    if not sys.stdout.isatty():
        raise Refused("Recovery display requires a local interactive console")
    path = Path(prepared["recovery_key_path"])
    if not path.exists():
        print("The original runtime recovery copy is absent. Use the off-appliance copy you exported earlier.")
        return
    value = _private_file(path, minimum=32).decode("ascii")
    print("\nStore this disk recovery passphrase in your protected off-appliance vault.\nIt unlocks the encrypted disk; it is separate from administrator account recovery codes.\n")
    print(value)
    print()
    if _answer("Type STORED after saving and checking the complete passphrase") != "STORED":
        raise Refused("Disk recovery export has not been acknowledged; setup can be resumed")
    atomic_json(manager.paths.bootstrap / "recovery-export.json", {"installation_id": prepared["installation_id"], "acknowledged_at": datetime.now(timezone.utc).isoformat(), "status": "operator-acknowledged; recovery test still required"})


def _runtime_console(manager, config, receipt):
    """Resume completion actions without rewriting already prepared runtime files."""
    from .setup_integrity import integrity_console, pending_console
    pending_console(manager)
    print("\nOpen " + receipt.get("https_url", "https://" + config["hostname"]))
    if receipt.get("tls_certificate_sha256"):
        print("TLS certificate SHA-256: " + receipt["tls_certificate_sha256"])
    if receipt.get("tls_ca_certificate_sha256"):
        print("TLS CA certificate SHA-256: " + receipt["tls_ca_certificate_sha256"])
    print("Sign in with your local administrator, enroll MFA and recovery codes, and configure PAN-OS forwarding.")
    print("File integrity requires the installation's reviewed security policy. Enroll and check it before final security assessment and findings review.")
    while True:
        action = _answer("FILE INTEGRITY, VERIFY final setup, or LATER", "LATER").upper()
        pending_console(manager)
        if action == "LATER":
            return {"state": "runtime-ready", "setup_complete": False, "https_url": receipt.get("https_url", "https://" + config["hostname"])}
        if action == "FILE INTEGRITY":
            integrity_console(manager)
            continue
        if action != "VERIFY":
            print("Choose FILE INTEGRITY, VERIFY, or LATER.")
            continue
        # No stored-key acknowledgment substitutes for reading the off-appliance
        # recovery material back and testing it against the real LUKS container.
        restored = manager.paths.runtime / "setup-recovery-verification"
        try:
            _password_file(restored, "Disk recovery passphrase from your off-appliance vault")
            pending_console(manager)
            return manager.complete(restored)
        finally:
            restored.unlink(missing_ok=True)


def setup_connections(runner):
    """Allow static firstboot setup when the new Ethernet profile has no lease."""
    candidates = runner(["nmcli", "--get-values", "UUID", "connection", "show"]).splitlines()
    if len(candidates) > 128:
        raise Refused("Too many network profiles are present for appliance setup")
    connections = []
    for connection in dict.fromkeys(candidates):
        if not re.fullmatch(r"[0-9a-f-]{36}", connection):
            continue
        kind = runner(["nmcli", "--get-values", "connection.type", "connection", "show", "uuid", connection])
        if kind in {"802-3-ethernet", "ethernet"}:
            connections.append(connection)
    if not connections:
        raise Refused("No Ethernet NetworkManager profile is available for management setup")
    return connections


def wizard(manager=None):
    """Local console workflow; credential text never enters argv or the journal."""
    manager = manager or FirstBoot()
    manager._host()
    from .console import local_console
    local_console()
    print("Captain’s Log appliance setup\nUnique encrypted storage, mandatory MFA, and measured security checks.")
    current = manager.status()
    if current.get("setup_complete"):
        print("Initial setup is already complete. Use the appliance administration pages for changes.")
        return current
    config_path = manager.paths.bootstrap / "setup-input.json"
    from .setup_integrity import resume_runtime, _integrity_state_exists
    if not manager.journal_path.exists() and _integrity_state_exists(manager):
        raise Refused("File-integrity state exists without its setup journal; automatic setup cannot restart")
    if manager.journal_path.exists():
        config = manager.config(config_path)
        print("Resuming the existing installation; disk and configuration selections are locked to its journal.")
    else:
        _private_dir(manager.paths.runtime)
        _private_dir(manager.paths.bootstrap)
        candidates, seen = [], set()
        for path in sorted(Path("/dev/disk/by-id").glob("*")):
            try:
                target = path.resolve()
                if target in seen:
                    continue
                candidate = manager.prober(str(path))
                seen.add(target)
                candidates.append(candidate)
            except (OSError, Refused, ValueError, KeyError):
                continue
        if not candidates:
            raise Refused("No blank, writable, unused disk with a stable serial is available. Attach the designated data disk and restart setup.")
        print("\nBlank data disks (system and existing data disks are excluded):")
        for index, candidate in enumerate(candidates, 1):
            print(f"  {index}. {candidate['disk']} | serial {candidate['serial']} | {candidate['bytes'] / 1024**3:.2f} GiB")
        selection = int(_answer("Select designated data disk number", "1"))
        if not 1 <= selection <= len(candidates):
            raise Refused("Select one of the listed disks")
        disk = candidates[selection - 1]
        connections = setup_connections(manager.runner)
        print("\nNetwork connections:")
        for index, connection in enumerate(connections, 1):
            label = manager.runner(["nmcli", "--get-values", "connection.id", "connection", "show", "uuid", connection])
            print(f"  {index}. {label} ({connection})")
        selected = int(_answer("Select management network", "1"))
        if not 1 <= selected <= len(connections):
            raise Refused("Select one of the listed network connections")
        hostname = _answer("Hostname", "nebulalog")
        method = _answer("IPv4 mode: auto, manual, or disabled", "auto")
        ipv4 = {"method": method}
        if method == "manual":
            ipv4["addresses"] = _answer("IPv4 address/prefix, for example 192.0.2.10/24").split(",")
            ipv4["gateway"] = _answer("IPv4 gateway (empty for none)")
        ipv6 = {"method": _answer("IPv6 mode: auto, manual, or disabled", "auto")}
        if ipv6["method"] == "manual":
            ipv6["addresses"] = _answer("IPv6 address/prefix").split(",")
            ipv6["gateway"] = _answer("IPv6 gateway (empty for none)")
        config = {"schema": 1, "disk": disk["disk"], "hostname": hostname,
                  "network": {"connection_uuid": connections[selected - 1], "ipv4": ipv4, "ipv6": ipv6,
                              "dns": [s.strip() for s in _answer("DNS servers, comma separated (empty uses network DNS)").split(",") if s.strip()]},
                  "ntp": [s.strip() for s in _answer("NTP servers, comma separated", "pool.ntp.org").split(",")],
                  "administrator": {"username": _answer("Local administrator username", "administrator"), "password_file": "/run/nebulalog/setup-administrator-password"},
                  "unlock_key_file": "/run/nebulalog/setup-disk-passphrase",
                  "baseline": _answer("Security baseline: cis-level2, unified, or stig", "unified"),
                  "maintenance": {"weekday": int(_answer("Maintenance weekday: Monday 0 through Sunday 6", "6")), "start": _answer("Maintenance start HH:MM", "03:00"), "end": _answer("Maintenance end HH:MM", "05:00"), "timezone": _answer("IANA time zone", "UTC")},
                  "retention_days": int(_answer("Initial retention days", "90"))}
        validate_config(config)
        atomic_json(config_path, config)
    receipt = resume_runtime(manager, config)
    if receipt is not None:
        print("Verified the existing installation and completed runtime journal. Resuming completion actions without reprovisioning.")
        return _runtime_console(manager, config, receipt)
    _private_dir(manager.paths.runtime)
    _private_dir(manager.paths.bootstrap)
    plan = manager.plan(config)
    print(f"\nReview: {plan['hostname']} · {plan['baseline']} · {plan['retention_days']} days retention")
    print(f"Data disk: {plan['disk']}\nSerial: {plan['serial']}\nCapacity: {plan['bytes'] / 1024**3:.2f} GiB\n{plan['warning']}")
    if _answer("Type the complete data disk serial to confirm") != plan["serial"]:
        raise Refused("Disk initialization was not confirmed")
    _password_file(Path(config["unlock_key_file"]), "Disk unlock passphrase (needed at reboot)")
    if not manager.journal_path.exists() or "settings" not in json.loads(manager.journal_path.read_text())["completed"]:
        _password_file(Path(config["administrator"]["password_file"]), "Administrator password")
    print("\nEnrolling the reviewed disk and applying configuration. Interrupted work retains its journal.")
    prepared = manager.apply(config, plan["confirmation"])
    _console_recovery(manager, prepared)
    print("Encrypted storage and host configuration are ready. Preparing application services...")
    manager.runner(["systemctl", "start", "nebulalog-firstboot.service"], timeout=180)
    receipt = manager.provision()
    return _runtime_console(manager, config, receipt)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("plan", "apply"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        if name == "apply":
            command.add_argument("--confirmation", required=True)
    commands.add_parser("status")
    commands.add_parser("gate")
    commands.add_parser("provision")
    commands.add_parser("wizard")
    command = commands.add_parser("complete")
    command.add_argument("--recovery-key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    manager = FirstBoot()
    try:
        if args.action in ("plan", "apply"):
            config = manager.config(args.config)
            result = manager.plan(config) if args.action == "plan" else manager.apply(config, args.confirmation)
        elif args.action == "wizard":
            result = wizard(manager)
        elif args.action == "complete":
            result = manager.complete(args.recovery_key_file)
        else:
            result = getattr(manager, args.action)()
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (Refused, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
