"""Streamable encrypted configuration backups with safe staged restore.

PostgreSQL metadata is explicit; multi-terabyte ClickHouse data is not included.
Backup staging must reside on the appliance's mounted encrypted data filesystem.
CMS AES-256-GCM authenticates ciphertext; no plaintext passphrase is written.
"""
from __future__ import annotations
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
import uuid
from contextlib import ExitStack
from datetime import datetime, timezone
from .common import Refused, atomic_json, locked, require_linux_root, run, trusted_file
from .updates import digest_file


def _encrypted_staging(directory: Path, runner=run):
    # Inspect the existing ancestor before creating anything. A missing data mount
    # must not leave plaintext staging directories on the OS disk.
    if directory.is_symlink():
        raise Refused("Backup staging refuses symlinks")
    ancestor = directory
    while not ancestor.exists():
        ancestor = ancestor.parent
    result = json.loads(runner(["findmnt", "--json", "--target", str(ancestor)]))["filesystems"]
    if len(result) != 1 or result[0]["target"] != "/var/lib/nebulalog" or result[0]["fstype"] != "xfs":
        raise Refused("Plaintext backup staging must be on the mounted Captain’s Log XFS data filesystem")
    tree = json.loads(runner(["lsblk", "--json", "--inverse", "--output", "NAME,TYPE,FSTYPE", result[0]["source"]]))
    def walk(items):
        return [n for item in items for n in ([item] + walk(item.get("children", [])))]
    if not any(n.get("fstype") == "crypto_LUKS" for n in walk(tree["blockdevices"])):
        raise Refused("Cannot establish encrypted ancestry for backup staging")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)


DATABASES = ("nebulalog", "keycloak")
WRITERS = ("api", "keycloak")
DATA = Path("/var/lib/nebulalog")
ROOT_UID = 0
MAX_BYTES = 20 * 1024**3


def _now():
    return datetime.now(timezone.utc).isoformat()


def _directory(path, *, private=False, create=False):
    """Reject symlink and writable ancestors before creating private state."""
    if not path.is_absolute() or ".." in path.parts:
        raise Refused("Backup paths must be absolute and normalized")
    for item in reversed((path, *path.parents)):
        if not item.exists() and not item.is_symlink():
            if not create:
                raise Refused("Required backup directory is missing")
            item.mkdir(mode=0o700)
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise Refused("Backup directories must be root-controlled without writable or linked ancestors")
    if private and path.stat().st_mode & 0o077:
        raise Refused("Backup scratch and transaction directories must be root-only")


def _pg(arguments, *, interactive=False):
    # Clear inherited container environment as well as the host runner's environment.
    # Local socket trust is restricted to UID 999 by the installed 0700 socket mount.
    return ["podman", "exec", *(["--interactive"] if interactive else []), "--user", "999:999",
            "nebulalog-postgresql", "env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C",
            "PGCONNECT_TIMEOUT=15", "TMPDIR=/tmp", *arguments]


class ConfigurationBackup:
    """One lock owner, fixed runtime operations, and a durable maintenance recovery path."""
    def __init__(self, lifecycle=None, gate=None, *, data=DATA,
                 bootstrap=Path("/etc/nebulalog/bootstrap"), public=Path("/run/nebulalog-public/maintenance.json")):
        # Lifecycle imports _encrypted_staging; defer this import until invocation.
        from nebulalog_adapters.lifecycle import Lifecycle, load_config
        from .firstboot import FirstBoot
        self.lifecycle = lifecycle or Lifecycle(load_config())
        self.cmd = self.lifecycle.cmd
        self.gate = gate or FirstBoot().gate
        self.data, self.bootstrap, self.public = data, bootstrap, public
        self.configuration = data / "configuration"
        self.manager = data / "manager"
        self.marker = self.manager / "maintenance.json"

    def _guard(self):
        require_linux_root()
        evidence = self.gate()  # Actual host controls + installed LUKS/LVM/XFS identity.
        if evidence.get("host_ready") is not True or evidence.get("setup_complete") is not True:
            raise Refused("Configuration backup requires completed appliance enrollment")
        if str(uuid.UUID(evidence.get("installation_id", ""))) != evidence["installation_id"]:
            raise Refused("Invalid installation identity")
        self.lifecycle.encrypted()
        _directory(self.configuration)
        _directory(self.manager, private=True)
        return evidence["installation_id"]

    def _locks(self, stack):
        # All four use LOCK_NB. Never call an adapter entry point that reacquires
        # transaction.lock while holding it. Existing firstboot owns outer->runtime.
        for path in (self.manager / "transaction.lock", self.bootstrap / "firstboot.lock",
                     self.configuration / "bootstrap/runtime.lock", self.configuration / "baseline.lock"):
            _directory(path.parent)
            stack.enter_context(locked(path))

    def _active(self, names):
        for name in names:
            if self.cmd(["systemctl", "show", "--property=ActiveState", "--value", "nebulalog-" + name + ".service"]) != "active":
                raise Refused("Backup requires its expected runtime services to be active")

    def _pending(self, owned_stage=None):
        if owned_stage is not None:
            self._owned_marker(owned_stage, missing=True)
        elif any(path.exists() or path.is_symlink() for path in (self.marker, self.public)):
            raise Refused("Existing maintenance must be recovered before another backup")
        for path, terminal in ((self.manager / "os-transaction.json", ("complete", "failed", "reboot_aborted")),
                               (self.manager / "updates/transaction.json", ("preflight_failed", "committed", "rolled_back"))):
            if path.exists() or path.is_symlink():
                value = json.loads(trusted_file(path).read_text())
                finalization = value.get("finalization", None if value.get("state") in ("committed", "rolled_back") else "complete")
                if value.get("state") not in terminal or finalization != "complete":
                    raise Refused("An incomplete appliance transaction requires recovery before backup")

    def _metadata(self):
        from nebulalog_adapters.lifecycle import image_from_quadlet
        pin = image_from_quadlet(trusted_file(self.lifecycle.quadlets / "nebulalog-postgresql.container").read_text())
        image_id = self.cmd(["podman", "image", "inspect", "--format", "{{.Id}}", pin])
        actual_id = self.cmd(["podman", "container", "inspect", "--format", "{{.Image}}", "nebulalog-postgresql"])
        repos = json.loads(self.cmd(["podman", "image", "inspect", "--format", "{{json .RepoDigests}}", pin]))
        if not re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", image_id) or image_id.removeprefix("sha256:") != actual_id.removeprefix("sha256:") or pin not in repos:
            raise Refused("Running PostgreSQL does not match the installed immutable image")
        query = """SELECT json_build_object('server_version', current_setting('server_version'),
          'databases', (SELECT json_object_agg(d.datname, json_build_object('owner', r.rolname,
          'can_login', r.rolcanlogin, 'superuser', r.rolsuper, 'create_role', r.rolcreaterole,
          'create_database', r.rolcreatedb, 'bytes', pg_database_size(d.oid)))
          FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba
          WHERE d.datname IN ('nebulalog','keycloak')))"""
        value = json.loads(self.cmd(_pg(["psql", "-X", "--no-password", "--host=/var/run/postgresql",
                         "--username=postgres", "--dbname=postgres", "--tuples-only", "--no-align",
                         "--set=ON_ERROR_STOP=1", "--command", query])))
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?: \([^\n]{1,150}\))?", value.get("server_version", "")) or set(value.get("databases", {})) != set(DATABASES):
            raise Refused("Unexpected PostgreSQL version/database inventory")
        for name, row in value["databases"].items():
            if row.get("owner") != name or row.get("can_login") is not True or any(row.get(flag) is not False for flag in ("superuser", "create_role", "create_database")) or type(row.get("bytes")) is not int or row["bytes"] <= 0:
                raise Refused("Database owners must be the fixed unprivileged appliance roles")
        return {"image": pin, **value}

    def _owned_marker(self, stage, *, missing=False):
        found = False
        for path in (self.marker, self.public):
            if path.exists() or path.is_symlink():
                value = json.loads(trusted_file(path).read_text())
                if value.get("active") is not True or value.get("release") != str(stage):
                    raise Refused("Maintenance belongs to another appliance operation")
                found = True
        if not found and not missing:
            raise Refused("Backup maintenance marker is missing")

    def _resume(self, stage):
        self._owned_marker(stage, missing=True)
        self.lifecycle.service("start", ("keycloak", "api"))
        self.lifecycle.api_ready()
        self._active(("ingest",))
        self._owned_marker(stage, missing=True)
        self.lifecycle.maintenance(False, stage)

    def _snapshot(self, work, installation_id, metadata, budget):
        from nebulalog_adapters.lifecycle import inventory
        started = _now()
        original = inventory(self.configuration)
        if any((self.configuration / item["path"]).stat().st_nlink != 1 for item in original):
            raise Refused("Configuration backup refuses hard-linked files")
        remaining = budget - sum(item["bytes"] for item in original)
        entries, databases = [], {}
        for name in DATABASES:
            target = work / (name + ".dump")
            before = _now()
            if remaining <= 0:
                raise Refused("Database dumps exceed the encrypted scratch budget")
            self.cmd.capture(["prlimit", "--core=0", "--fsize=" + str(remaining), "--", *_pg([
                "pg_dump", "--no-password", "--host=/var/run/postgresql", "--username=" + name,
                "--dbname=" + name, "--format=custom", "--lock-wait-timeout=30000"])], target, timeout=3600)
            if target.is_symlink() or not target.is_file() or not 0 < target.stat().st_size <= MAX_BYTES:
                raise Refused("Database dump is missing, empty or exceeds the restore budget")
            self.cmd.feed(_pg(["pg_restore", "--list"], interactive=True), target, timeout=3600)
            entries.append({"path": target.name, "sha256": digest_file(target), "bytes": target.stat().st_size})
            remaining -= target.stat().st_size
            databases[name] = {"started_at": before, "finished_at": _now(), "owner": name, "archive_verified": True}
        copied = work / "configuration"
        shutil.copytree(self.configuration, copied, symlinks=True)
        observed = inventory(copied)
        keys = ("path", "bytes", "sha256", "mode")
        if inventory(self.configuration) != original or [{k: i[k] for k in keys} for i in observed] != [{k: i[k] for k in keys} for i in original]:
            raise Refused("Configuration changed during the paused-writer snapshot")
        for item in original:
            entries.append({**item, "path": "configuration/" + item["path"]})
        if sum(item["bytes"] for item in entries) > MAX_BYTES - 1024*1024:
            raise Refused("Configuration backup exceeds the restore budget")
        manifest = {"schema": 1, "product": "nebulalog", "kind": "configuration", "includes_logs": False,
                    "installation_id": installation_id, "files": entries, "postgresql": metadata,
                    "snapshot": {"started_at": started, "finished_at": _now(), "databases": databases,
                                 "paused_writers": list(WRITERS), "ingestion_paused": False,
                                 "cross_database_atomic": False, "volatile_inventory": "per-nebulalog-dump snapshot"}}
        if len(json.dumps(manifest).encode()) > 1024*1024:
            raise Refused("Backup manifest exceeds the restore budget")
        atomic_json(work / "backup.json", manifest)
        archive = work / "backup.tar"
        with tarfile.open(archive, "w") as tar:
            tar.add(work / "backup.json", arcname="backup.json", recursive=False)
            for name in DATABASES:
                tar.add(work / (name + ".dump"), arcname=name + ".dump", recursive=False)
            tar.add(copied, arcname="configuration", recursive=True)
        archive.chmod(0o600)
        return archive

    def create(self, config, output, recipient_certificate, staging):
        installation_id = self._guard()
        if config != self.configuration or config.is_symlink():
            raise Refused("Backups include only the installed canonical configuration directory")
        if output.exists() or output.is_symlink() or not output.name or output.is_relative_to(config) or output.is_relative_to(staging):
            raise Refused("Backup output must be new and outside configuration/scratch")
        _directory(output.parent, create=True)
        trusted_file(recipient_certificate)
        _directory(recipient_certificate.parent)
        if not 0 < recipient_certificate.stat().st_size <= 65536:
            raise Refused("Invalid backup recipient certificate size")
        self.cmd(["openssl", "x509", "-in", str(recipient_certificate), "-noout", "-checkend", "0"])
        with ExitStack() as stack:
            self._locks(stack)
            if self._guard() != installation_id:
                raise Refused("Installation changed before backup lock acquisition")
            self._pending()
            self._active(("postgresql", "clickhouse", "keycloak", "api", "ingest"))
            self.cmd(["prlimit", "--version"])
            metadata = self._metadata()
            _encrypted_staging(staging, self.cmd)
            _directory(staging, private=True)
            from nebulalog_adapters.lifecycle import inventory
            required = sum(item["bytes"] for item in inventory(config)) + sum(row["bytes"] for row in metadata["databases"].values())
            free = shutil.disk_usage(staging).free
            if required > MAX_BYTES or free < 3 * required + 1024**3:
                raise Refused("Insufficient encrypted staging reserve or configuration exceeds backup budget")
            budget = min(MAX_BYTES - 1024*1024, (free - 1024**3) // 3)
            identifier = str(uuid.uuid4())
            stage = self.manager / "backups" / identifier
            _directory(stage, private=True, create=True)
            transaction = {"schema": 1, "kind": "configuration-backup", "id": identifier,
                           "installation_id": installation_id, "started_at": _now(), "state": "prepared"}
            def record(state, **details):
                transaction.update(state=state, observed_at=_now(), **details)
                atomic_json(stage / "transaction.json", transaction)
            record("prepared")
            with tempfile.TemporaryDirectory(prefix="backup-", dir=staging) as temporary:
                work = Path(temporary)
                # Pin recipient bytes before quiescence; never use an operator path
                # again after validation. The certificate contains only a public key.
                certificate = work / "recipient.pem"
                certificate.write_bytes(recipient_certificate.read_bytes())
                certificate.chmod(0o600)
                self.cmd(["openssl", "x509", "-in", str(certificate), "-noout", "-checkend", "0"])
                paused = False
                try:
                    record("pausing")
                    paused = True  # maintenance can fail after writing its private half.
                    self.lifecycle.maintenance(True, stage)
                    self.lifecycle.service("stop", WRITERS)
                    record("capturing")
                    archive = self._snapshot(work, installation_id, metadata, budget)
                    record("resuming")
                    self._resume(stage)
                    paused = False
                    record("encrypting")
                    descriptor, name = tempfile.mkstemp(prefix="." + output.name + "-", suffix=".pending", dir=output.parent)
                    os.close(descriptor)
                    pending = Path(name)
                    try:
                        self.cmd(["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER",
                                  "-in", str(archive), "-out", str(pending), str(certificate)], timeout=3600)
                        if pending.stat().st_size == 0:
                            raise Refused("Encrypted backup was empty")
                        with pending.open("rb") as stream:
                            os.fsync(stream.fileno())
                        # link() publishes atomically and refuses an output created
                        # concurrently; replace() would silently overwrite it.
                        os.link(pending, output)
                        parent = os.open(output.parent, os.O_RDONLY)
                        try:
                            os.fsync(parent)
                        finally:
                            os.close(parent)
                    finally:
                        pending.unlink(missing_ok=True)
                    receipt = {"ok": True, "id": identifier, "path": str(output), "sha256": digest_file(output),
                               "bytes": output.stat().st_size, "postgresql": True, "configuration": True,
                               "includes_logs": False, "encryption": "CMS AES-256-GCM", "ingestion_paused": False}
                    record("complete", result=receipt)
                    return receipt
                except BaseException as exc:
                    recovered = not paused
                    if paused:
                        try:
                            self._resume(stage)
                            recovered = True
                        except BaseException:
                            pass
                    record("failed" if recovered else "recovery_required", error=type(exc).__name__)
                    raise Refused("Configuration backup failed; transaction " + identifier +
                                  (" has restored runtime services" if recovered else " requires backup recovery; inspect maintenance and service state")) from None

    def recover(self, identifier):
        installation_id = self._guard()
        if str(uuid.UUID(identifier)) != identifier:
            raise Refused("Backup recovery requires an exact transaction UUID")
        with ExitStack() as stack:
            self._locks(stack)
            if self._guard() != installation_id:
                raise Refused("Installation changed before recovery lock acquisition")
            stage = self.manager / "backups" / identifier
            _directory(stage, private=True)
            path = trusted_file(stage / "transaction.json")
            value = json.loads(path.read_text())
            if value.get("schema") != 1 or value.get("kind") != "configuration-backup" or value.get("id") != identifier or value.get("installation_id") != installation_id or value.get("state") not in ("pausing", "capturing", "resuming", "recovery_required"):
                raise Refused("Backup transaction has no supported interrupted runtime stage")
            # A crash can occur between verified service recovery/marker removal
            # and journaling completion. Refuse other transactions/foreign markers,
            # but safely recheck this owned runtime stage when its marker is gone.
            self._pending(stage)
            self._active(("postgresql", "clickhouse", "ingest"))
            self._resume(stage)
            value.update(state="recovered_without_backup", observed_at=_now())
            atomic_json(path, value)
            return {"ok": True, "id": identifier, "state": value["state"], "backup_created": False}


def create_backup(config: Path, output: Path, recipient_certificate: Path,
                  *, pg_services: tuple[str, str] = DATABASES,
                  staging: Path = DATA / "backup-staging", runtime=None) -> dict:
    require_linux_root()
    if pg_services != DATABASES:
        raise Refused("Backup database scope is fixed to configuration and identity")
    return (runtime or ConfigurationBackup()).create(config, output, recipient_certificate, staging)


def unpack_backup(archive: Path, destination: Path, *, max_bytes: int = 20*1024**3) -> dict:
    """Safely unpack a successfully authenticated tar to a new private directory."""
    if destination.exists() or destination.is_symlink():
        raise Refused("Restore destination must not exist")
    with tarfile.open(archive, "r:") as tar:
        members = tar.getmembers()
        names = set()
        total = 0
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.name in names or not (member.isdir() or member.isfile()):
                raise Refused("Unsafe or duplicate archive member")
            if member.name not in ("backup.json", "nebulalog.dump", "keycloak.dump", "configuration") and not member.name.startswith("configuration/"):
                raise Refused("Unexpected archive content")
            names.add(member.name)
            total += member.size
        if total > max_bytes or "backup.json" not in names:
            raise Refused("Backup exceeds restore budget or lacks a manifest")
        content = tar.extractfile("backup.json")
        if content is None or tar.getmember("backup.json").size > 1024*1024:
            raise Refused("Invalid backup manifest")
        manifest = json.load(content)
        if manifest.get("schema") != 1 or manifest.get("product") != "nebulalog" or manifest.get("kind") != "configuration":
            raise Refused("Unsupported backup format")
        expected = {f["path"] for f in manifest["files"]}
        actual = {m.name for m in members if m.isfile() and m.name != "backup.json"}
        if actual != expected or len(expected) != len(manifest["files"]):
            raise Refused("Backup file inventory mismatch")
        destination.mkdir(parents=True, mode=0o700)
        try:
            for member in members:
                target = destination / member.name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    source = tar.extractfile(member)
                    with target.open("xb") as sink:
                        os.chmod(target, 0o600)
                        shutil.copyfileobj(source, sink, 1024*1024)
            for item in manifest["files"]:
                path = destination / item["path"]
                if path.stat().st_size != item["bytes"] or digest_file(path) != item["sha256"]:
                    raise Refused("Restored file integrity mismatch")
        except Exception:
            shutil.rmtree(destination)
            raise
    return manifest


def restore_backup(backup: Path, private_key: Path, certificate: Path, destination: Path,
                   *, staging: Path = DATA / "backup-staging", runtime=None) -> dict:
    require_linux_root()
    runtime = runtime or ConfigurationBackup()
    installation_id = runtime._guard()
    if destination.exists() or destination.is_symlink() or destination.is_relative_to(runtime.configuration):
        raise Refused("Staged restore requires a new directory outside live configuration")
    for path in (backup, private_key, certificate):
        trusted_file(path)
        _directory(path.parent)
    if private_key.stat().st_mode & 0o077:
        raise Refused("Restore private key must be root-only")
    archive_limit = MAX_BYTES + 256 * 1024**2  # Includes bounded tar/member overhead.
    if not 0 < backup.stat().st_size <= archive_limit:
        raise Refused("Encrypted backup exceeds the staged restore budget")
    with ExitStack() as stack:
        runtime._locks(stack)
        if runtime._guard() != installation_id:
            raise Refused("Installation changed before restore lock acquisition")
        runtime._pending()
        runtime._active(("postgresql",))
        runtime._metadata()
        _encrypted_staging(staging, runtime.cmd)
        _encrypted_staging(destination.parent, runtime.cmd)
        _directory(staging, private=True)
        _directory(destination.parent, private=True)
        if shutil.disk_usage(staging).free < 2 * archive_limit + 1024**3:
            raise Refused("Insufficient encrypted staged restore reserve")
        with tempfile.TemporaryDirectory(prefix="restore-", dir=staging) as temporary:
            archive = Path(temporary) / "restored.tar"
            # OpenSSL can output plaintext before tag validation: it stays private
            # on encrypted scratch, and unpacking only follows successful auth.
            runtime.cmd(["prlimit", "--core=0", "--fsize=" + str(archive_limit), "--", "openssl", "cms", "-decrypt", "-binary", "-inform", "DER", "-in", str(backup),
                         "-recip", str(certificate), "-inkey", str(private_key), "-out", str(archive)], timeout=3600)
            manifest = unpack_backup(archive, destination)
        try:
            for service in DATABASES:
                runtime.cmd.feed(_pg(["pg_restore", "--list"], interactive=True), destination / (service + ".dump"))
        except BaseException:
            shutil.rmtree(destination)
            raise Refused("Staged PostgreSQL archive validation failed; no database was changed") from None
    return {"ok": True, "staged": str(destination), "manifest": manifest,
            "database_restore": "not applied; restore to empty databases during recovery"}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Recover only an interrupted standalone backup's service pause")
    sub = parser.add_subparsers(dest="operation", required=True)
    recover = sub.add_parser("recover")
    recover.add_argument("--id", required=True)
    args = parser.parse_args(argv)
    try:
        require_linux_root()
        result = ConfigurationBackup().recover(args.id)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, KeyError):
        print(json.dumps({"ok": False, "error": "Backup recovery refused; inspect its protected transaction and host/runtime gates"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
