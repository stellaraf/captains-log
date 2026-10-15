"""Bounded OCI bundle verification and offline loading into encrypted storage."""
from __future__ import annotations

import hashlib
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile

from .common import CommandFailed, Refused, atomic_json, locked, run, trusted_file
from .firstboot import FirstBoot

NAMES = {"NEBULALOG_IMAGE", "POSTGRESQL_IMAGE", "CLICKHOUSE_IMAGE", "KEYCLOAK_FIPS_IMAGE"}
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MAX_ARCHIVE_BYTES = 8 * 1024**3
MAX_BUNDLE_BYTES = 24 * 1024**3
MAX_JSON_BYTES = 4 * 1024**2
MAX_MEMBERS = 100000
BUNDLE_DIRECTORY = Path("/usr/share/nebulalog/images")
PINS_PATH = Path("/etc/nebulalog/images.json")
DATA_DIRECTORY = Path("/var/lib/nebulalog")


class ApplicationSchema:
    """Reviewed source identities; declarations never authorize live SQL.

    Keep this namespace in the existing image-bundle module so a bridge release
    remains verifiable by the previous generation's fixed host file catalog.
    """

    LEGACY_REVISION = "1"
    CURRENT_REVISION = "2"
    ADDITIVE_UPGRADE = "postgres-emergency-storage-1-to-2"
    SCHEMAS = {
        "1": {
            "migrations/postgres.sql": "122e2791afa29563db6f80aa248d604f87428e06e70818f2bf467aa58d07eefa",
            "migrations/clickhouse.sql": "fd84d9a576b8e850e0a33625c13f422901736d23475b8b97c4b71840ef1d91ce",
            "migrations/host_stepup.sql": "b78e4e65ca8dc35593803fb89cfe1af76521495ca8cabdf9a174c86be6936b56",
        },
        "2": {
            "migrations/postgres.sql": "90af76769233c482f186b6d7827abe0eab84e44192afbf81dfe48aeb71d7c217",
            "migrations/clickhouse.sql": "fd84d9a576b8e850e0a33625c13f422901736d23475b8b97c4b71840ef1d91ce",
            "migrations/host_stepup.sql": "b78e4e65ca8dc35593803fb89cfe1af76521495ca8cabdf9a174c86be6936b56",
        },
    }

    # Fixed host-installed SQL; never load a release-provided SQL path or hook.
    LEGACY_POSTGRES_SQL = 'CREATE TABLE IF NOT EXISTS saved_filters (\n id uuid PRIMARY KEY, owner_id text NOT NULL, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),\n description text NOT NULL DEFAULT \'\', query text NOT NULL, log_type text NOT NULL DEFAULT \'traffic\',\n columns jsonb NOT NULL DEFAULT \'[]\', time_range text NOT NULL DEFAULT \'1h\', sort text NOT NULL DEFAULT \'received_at\',\n favorite boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()\n);\nCREATE INDEX IF NOT EXISTS saved_filters_owner ON saved_filters(owner_id);\nCREATE TABLE IF NOT EXISTS layouts (owner_id text NOT NULL, log_type text NOT NULL, layout jsonb NOT NULL, PRIMARY KEY(owner_id,log_type));\nCREATE TABLE IF NOT EXISTS firewalls (\n serial text PRIMARY KEY, device_name text NOT NULL DEFAULT \'\', sender_ip text NOT NULL DEFAULT \'\',\n friendly_name text NOT NULL DEFAULT \'\', site text NOT NULL DEFAULT \'\', tags jsonb NOT NULL DEFAULT \'[]\', notes text NOT NULL DEFAULT \'\',\n panos_version text NOT NULL DEFAULT \'\', first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now()\n);\nCREATE TABLE IF NOT EXISTS settings (key text PRIMARY KEY, value jsonb NOT NULL);\nINSERT INTO settings(key,value) VALUES(\'retention\',\'{"global_days":90,"per_type":{"traffic":60,"threat":365,"url":90,"authentication":365,"configuration":365,"system":365}}\') ON CONFLICT DO NOTHING;\nCREATE TABLE IF NOT EXISTS audit_events(id bigserial PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL, action text NOT NULL, target text NOT NULL, detail jsonb NOT NULL DEFAULT \'{}\');\nCREATE TABLE IF NOT EXISTS export_jobs (\n id uuid PRIMARY KEY, owner_id text NOT NULL, status text NOT NULL, rows bigint NOT NULL DEFAULT 0, bytes bigint NOT NULL DEFAULT 0,\n error text NOT NULL DEFAULT \'\', request jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval \'24 hours\'\n);\nCREATE TABLE IF NOT EXISTS storage_samples(sampled_at timestamptz NOT NULL DEFAULT now(), database_bytes bigint NOT NULL, events bigint NOT NULL, PRIMARY KEY(sampled_at));\n\nALTER TABLE saved_filters ADD COLUMN IF NOT EXISTS sort_order text NOT NULL DEFAULT \'desc\' CHECK(sort_order IN (\'asc\',\'desc\'));\n\nCREATE TABLE IF NOT EXISTS user_preferences (\n owner_id text PRIMARY KEY,\n theme text NOT NULL DEFAULT \'system\' CHECK(theme IN (\'system\',\'light\',\'dark\')),\n density text NOT NULL DEFAULT \'compact\' CHECK(density IN (\'compact\',\'comfortable\')),\n rail_collapsed boolean NOT NULL DEFAULT false,\n updated_at timestamptz NOT NULL DEFAULT now()\n);\n'
    ADDITIVE_POSTGRES_SQL = '\n-- Emergency retention is separate from expiry assigned to future arrivals.\nINSERT INTO settings(key,value) VALUES(\'storage_emergency\',\'{"revision":1,"enabled":true,"trigger_percent":95,"recover_percent":90,"minimum_days":{"traffic":1,"url":7,"threat":30,"wildfire":30,"dns":30,"data":30,"hip":30,"globalprotect":30,"iptag":30,"userid":30,"decryption":30,"tunnel":30,"configuration":30,"system":30,"authentication":30}}\') ON CONFLICT DO NOTHING;\nINSERT INTO settings(key,value) VALUES(\'storage_emergency_maintenance\',\'{"schema":1,"held":false,"delivery_held":false,"operation":null}\') ON CONFLICT DO NOTHING;\nCREATE TABLE IF NOT EXISTS storage_emergency_state (\n singleton boolean PRIMARY KEY CHECK(singleton), value jsonb NOT NULL\n);\nINSERT INTO storage_emergency_state(singleton,value) VALUES(true,\'{"state":"not_observed","observed_at":null,"message":"Waiting for the first verified ClickHouse disk observation","emergency_active":false,"insert_exclusions":0}\') ON CONFLICT DO NOTHING;\nCREATE TABLE IF NOT EXISTS storage_emergency_actions (\n id uuid PRIMARY KEY, state text NOT NULL CHECK(state IN (\'prepared\',\'executing\',\'uncertain\',\'awaiting_cleanup\',\'completed\',\'cancelled\')),\n plan jsonb NOT NULL, message text NOT NULL DEFAULT \'\', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz\n);\nCREATE UNIQUE INDEX IF NOT EXISTS storage_emergency_one_pending ON storage_emergency_actions((true)) WHERE completed_at IS NULL;\nCREATE TABLE IF NOT EXISTS storage_emergency_inserts (\n id uuid PRIMARY KEY, table_uuid uuid NOT NULL, partitions jsonb NOT NULL, query_id uuid NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now()\n);\n'
    HOST_STEPUP_SQL = "-- Short-lived server-only OAuth transactions. State is SHA-256 hashed before\n-- insertion; nonce and PKCE verifier are never copied to audit/job records.\nCREATE TABLE IF NOT EXISTS host_stepup_pending (\n state_hash text PRIMARY KEY CHECK (state_hash ~ '^[a-f0-9]{64}$'),\n nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{43,128}$'),\n pkce_verifier text NOT NULL CHECK (pkce_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'),\n policy_digest text NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),\n actor_issuer text NOT NULL CHECK (octet_length(actor_issuer) BETWEEN 1 AND 2048 AND actor_issuer !~ '[[:cntrl:]]'),\n actor_subject text NOT NULL CHECK (octet_length(actor_subject) BETWEEN 1 AND 512 AND actor_subject !~ '[[:cntrl:]]'),\n actor_client_id text NOT NULL CHECK (octet_length(actor_client_id) BETWEEN 1 AND 512 AND actor_client_id !~ '[[:cntrl:]]'),\n actor_session_digest text NOT NULL CHECK (actor_session_digest ~ '^[a-f0-9]{64}$'),\n installation_id text NOT NULL CHECK (installation_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),\n operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_.]{0,127}$'),\n plan_id text NOT NULL CHECK (plan_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),\n plan_digest text NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),\n resource_revision text NOT NULL CHECK (resource_revision ~ '^[a-f0-9]{64}$'),\n binding_expires_at timestamptz NOT NULL CHECK (isfinite(binding_expires_at)),\n created_at timestamptz NOT NULL CHECK (isfinite(created_at) AND created_at >= '1970-01-01T00:00:00Z'),\n expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),\n CHECK (expires_at > created_at AND expires_at <= created_at + interval '120 seconds'),\n CHECK (expires_at <= binding_expires_at)\n);\nCREATE INDEX IF NOT EXISTS host_stepup_pending_expiry ON host_stepup_pending (expires_at, state_hash);\n"

    @staticmethod
    def reviewed_sql():
        legacy = ApplicationSchema.LEGACY_POSTGRES_SQL
        additive = ApplicationSchema.ADDITIVE_POSTGRES_SQL
        stepup = ApplicationSchema.HOST_STEPUP_SQL
        expected = ApplicationSchema.SCHEMAS
        for body, digest in ((legacy, expected["1"]["migrations/postgres.sql"]),
                             (legacy + additive, expected["2"]["migrations/postgres.sql"]),
                             (stepup, expected["2"]["migrations/host_stepup.sql"])):
            if hashlib.sha256(body.encode()).hexdigest() != digest:
                raise Refused("Installed migration SQL differs from its reviewed source identity")
        return legacy, additive, stepup

    @staticmethod
    def schema_digest(revision):
        if not isinstance(revision, str) or revision not in ApplicationSchema.SCHEMAS:
            raise Refused("Application schema revision has no reviewed source contract")
        return hashlib.sha256(json.dumps(ApplicationSchema.SCHEMAS[revision], sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @staticmethod
    def source_revision(files):
        if not isinstance(files, dict) or any(not isinstance(name, str) for name in files):
            raise Refused("Application schema needs a complete source inventory")
        migrations = {name: value for name, value in files.items() if name.startswith("migrations/")}
        for revision, expected in ApplicationSchema.SCHEMAS.items():
            if migrations == expected:
                return revision
        raise Refused("Migration source differs from every reviewed application schema; qualify a new revision")

    @staticmethod
    def bind_source(files, revision):
        observed = ApplicationSchema.source_revision(files)
        if revision != observed:
            raise Refused("Declared application schema revision differs from the actual migration source")
        return ApplicationSchema.schema_digest(observed)

    @staticmethod
    def declaration(files, revision, migration="none"):
        digest = ApplicationSchema.bind_source(files, revision)
        if migration not in ("none", ApplicationSchema.ADDITIVE_UPGRADE) or migration == ApplicationSchema.ADDITIVE_UPGRADE and revision != ApplicationSchema.CURRENT_REVISION:
            raise Refused("Application migration is not a reviewed fixed transition")
        return {"schema_revision": revision, "schema_sha256": digest, "database_migration": migration}

    @staticmethod
    def transition(change, installed_revision):
        """Validate only the declaration; this does not authorize SQL or activation."""
        target = change.get("schema_revision")
        digest = ApplicationSchema.schema_digest(target)
        if change.get("schema_sha256") != digest:
            # Retained schema-1 releases predate the fingerprint field. Their legacy
            # same-schema path is needed to install the migration-capable coordinator.
            if not (target == installed_revision == ApplicationSchema.LEGACY_REVISION and "schema_sha256" not in change):
                raise Refused("Release schema fingerprint differs from its reviewed source contract")
        migration = change.get("database_migration")
        if migration == "none" and target == installed_revision:
            return "none"
        if (migration == ApplicationSchema.ADDITIVE_UPGRADE and installed_revision == ApplicationSchema.LEGACY_REVISION
                and target == ApplicationSchema.CURRENT_REVISION and change.get("rollback_safe") is True):
            return ApplicationSchema.ADDITIVE_UPGRADE
        raise Refused("Application schema change requires a supported explicit migration")


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refused("Duplicate JSON property in image metadata")
        value[key] = item
    return value


def strict_json(data):
    try:
        return json.loads(data, object_pairs_hook=_object, parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite JSON value")))
    except (ValueError, UnicodeError) as exc:
        raise Refused("Invalid image metadata JSON") from exc


def _regular(path, *, root_owned=False, maximum=MAX_ARCHIVE_BYTES):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise Refused("Image input is unavailable or is a symbolic link") from exc
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= maximum or root_owned and (info.st_uid != 0 or info.st_mode & 0o022):
        os.close(fd)
        raise Refused("Image input must be a bounded regular file with trusted ownership/permissions")
    return os.fdopen(fd, "rb"), info


def _json_file(path, root_owned=False):
    stream, _ = _regular(path, root_owned=root_owned, maximum=MAX_JSON_BYTES)
    with stream:
        return strict_json(stream.read())


def _same_file(before, after):
    return all(getattr(before, key) == getattr(after, key) for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))


def file_sha256(path, *, root_owned=False):
    stream, before = _regular(path, root_owned=root_owned)
    with stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024**2), b""):
            digest.update(chunk)
        if not _same_file(before, os.fstat(stream.fileno())):
            raise Refused("Image archive changed while it was being verified")
        return digest.hexdigest()


def validate_pins(pins):
    if not isinstance(pins, dict) or set(pins) != NAMES or any(not isinstance(value, str) or not REFERENCE.fullmatch(value) for value in pins.values()):
        raise Refused("Exactly four immutable component image references are required")
    return pins


def _bounded_tar_headers(stream, archive_bytes):
    """Reject metadata extensions before tarfile can allocate their payloads."""
    stream.seek(0)
    count = 0
    while stream.tell() + 512 <= archive_bytes:
        raw = stream.read(512)
        if raw == b"\0" * 512:
            remaining = archive_bytes - stream.tell()
            if remaining < 512:
                raise Refused("Truncated OCI archive end marker")
            for chunk in iter(lambda: stream.read(1024**2), b""):
                if any(chunk):
                    raise Refused("Unexpected trailing content after the OCI archive")
            stream.seek(0)
            return
        try:
            member = tarfile.TarInfo.frombuf(raw, "utf-8", "strict")
        except (tarfile.HeaderError, UnicodeError) as exc:
            raise Refused("Invalid OCI archive header") from exc
        count += 1
        if count > MAX_MEMBERS or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) or member.size < 0 or member.isdir() and member.size != 0:
            raise Refused("OCI archive contains unsupported extensions or excessive entries")
        padded = (member.size + 511) // 512 * 512
        if padded > archive_bytes - stream.tell():
            raise Refused("OCI archive entry exceeds the available file bytes")
        stream.seek(padded, os.SEEK_CUR)
    raise Refused("OCI archive has no complete end marker")


def verify_oci_archive(path: Path, reference: str, *, expected_sha256=None, root_owned=False):
    """Read every OCI blob, without extracting paths or invoking container tools."""
    if not isinstance(reference, str) or not REFERENCE.fullmatch(reference):
        raise Refused("Expected an immutable repository@sha256 reference")
    expected_manifest = reference.split("@", 1)[1]
    stream, before = _regular(path, root_owned=root_owned)
    with stream:
        archive_hash = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024**2), b""):
            archive_hash.update(chunk)
        archive_sha = archive_hash.hexdigest()
        if expected_sha256 is not None and archive_sha != expected_sha256:
            raise Refused("Offline image archive SHA256 mismatch")
        stream.seek(0)
        _bounded_tar_headers(stream, before.st_size)
        try:
            archive = tarfile.open(fileobj=stream, mode="r:")
            with archive:
                members = {}
                total = 0
                for item in archive:
                    name = item.name.rstrip("/") if item.isdir() else item.name
                    if len(members) >= MAX_MEMBERS or name in members or PurePosixPath(name).as_posix() != name or name.startswith("/") or ".." in PurePosixPath(name).parts:
                        raise Refused("Ambiguous, unsafe or excessive OCI archive entries")
                    allowed = name in ("index.json", "oci-layout", "manifest.json") or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name)
                    if item.isdir():
                        if name not in ("blobs", "blobs/sha256"):
                            raise Refused("Unexpected OCI archive directory")
                    elif not item.isfile() or not allowed or item.size < 0:
                        raise Refused("OCI archive contains links, special files or unexpected paths")
                    total += item.size
                    if total > before.st_size:
                        raise Refused("OCI archive payload exceeds its bounded file size")
                    members[name] = item

                def metadata(name):
                    item = members.get(name)
                    if not item or not item.isfile() or item.size > MAX_JSON_BYTES:
                        raise Refused("Missing or oversized OCI metadata")
                    return strict_json(archive.extractfile(item).read())

                layout = metadata("oci-layout")
                index = metadata("index.json")
                if layout != {"imageLayoutVersion": "1.0.0"} or index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
                    raise Refused("Bundle archives must contain exactly one OCI image")
                descriptor = index["manifests"][0]
                if descriptor.get("digest") != expected_manifest or descriptor.get("mediaType") not in ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"):
                    raise Refused("OCI image manifest differs from the selected child-manifest digest")
                platform = descriptor.get("platform", {})
                if platform and (platform.get("architecture") != "amd64" or platform.get("os") != "linux" or platform.get("variant") not in (None, "")):
                    raise Refused("OCI descriptor does not target Linux amd64")
                blobs = {}
                for name, item in members.items():
                    if not name.startswith("blobs/sha256/") or not item.isfile():
                        continue
                    digest = hashlib.sha256()
                    content = archive.extractfile(item)
                    for chunk in iter(lambda: content.read(1024**2), b""):
                        digest.update(chunk)
                    if digest.hexdigest() != name.rsplit("/", 1)[1]:
                        raise Refused("OCI content blob hash mismatch")
                    blobs["sha256:" + digest.hexdigest()] = item.size

                def checked_descriptor(value):
                    if not isinstance(value, dict) or not isinstance(value.get("digest"), str) or not DIGEST.fullmatch(value["digest"]) or type(value.get("size")) is not int or value.get("size") != blobs.get(value["digest"]) or value.get("urls") or value.get("data"):
                        raise Refused("OCI descriptor is missing, external or inconsistent with its blob")
                    return "blobs/sha256/" + value["digest"].split(":", 1)[1]

                manifest = metadata(checked_descriptor(descriptor))
                if manifest.get("schemaVersion") != 2 or not isinstance(manifest.get("layers"), list) or not manifest["layers"] or len(manifest["layers"]) > 1024 or manifest.get("subject"):
                    raise Refused("Unsupported OCI runtime manifest")
                config = metadata(checked_descriptor(manifest.get("config")))
                for layer in manifest["layers"]:
                    checked_descriptor(layer)
                if config.get("architecture") != "amd64" or config.get("os") != "linux" or config.get("variant") not in (None, ""):
                    raise Refused("OCI configuration does not target Linux amd64")
                rootfs = config.get("rootfs", {})
                if rootfs.get("type") != "layers" or not isinstance(rootfs.get("diff_ids"), list) or len(rootfs["diff_ids"]) != len(manifest["layers"]) or any(not isinstance(value, str) or not DIGEST.fullmatch(value) for value in rootfs["diff_ids"]):
                    raise Refused("OCI root filesystem metadata does not match the manifest layers")
                config_digest = manifest["config"]["digest"]
                labels = (config.get("config") or {}).get("Labels") or {}
                if not isinstance(labels, dict):
                    raise Refused("OCI configuration labels must be an object")
                application_source = labels.get("io.nebulalog.application-source-sha256")
                if application_source is not None and (not isinstance(application_source, str) or not re.fullmatch(r"[a-f0-9]{64}", application_source)):
                    raise Refused("OCI application source label must be a lowercase SHA256")
        except (tarfile.TarError, EOFError, KeyError, TypeError, AttributeError) as exc:
            raise Refused("Invalid or truncated OCI image archive") from exc
        if not _same_file(before, os.fstat(stream.fileno())):
            raise Refused("Image archive changed during OCI verification")
    return {"archive_sha256": archive_sha, "archive_bytes": before.st_size, "manifest_digest": expected_manifest,
            "config_digest": config_digest, "architecture": "amd64", "os": "linux", "verified_blobs": len(blobs),
            "application_source_sha256": application_source}


def _trusted_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Refused("Installed image bundle directory must be root-owned and protected")


def verify_bundle(bundle_dir: Path, pins: dict, *, root_owned=False):
    """Pure installer/seal verifier. No gate, Podman, extraction or network calls."""
    validate_pins(pins)
    if root_owned:
        _trusted_directory(bundle_dir)
    manifest = _json_file(bundle_dir / "manifest.json", root_owned)
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "images"} or type(manifest["schema"]) is not int or manifest["schema"] != 1 or not isinstance(manifest["images"], dict) or set(manifest["images"]) != NAMES:
        raise Refused("Invalid offline image bundle manifest")
    total, archives, evidence = 0, set(), {}
    # Validate the complete bundle before the loader can mutate container storage.
    for name in sorted(NAMES):
        item = manifest["images"][name]
        if not isinstance(item, dict) or set(item) != {"archive", "sha256", "reference"} or item.get("reference") != pins[name]:
            raise Refused("Offline bundle differs from the installed release image pins")
        if not isinstance(item["archive"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,100}\.oci\.tar", item["archive"]) or item["archive"] in archives or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise Refused("Invalid, duplicate or unsafe offline image archive entry")
        archives.add(item["archive"])
        observed = verify_oci_archive(bundle_dir / item["archive"], item["reference"], expected_sha256=item["sha256"], root_owned=root_owned)
        total += observed["archive_bytes"]
        if total > MAX_BUNDLE_BYTES:
            raise Refused("Offline bundle exceeds the appliance image budget")
        evidence[name] = {**item, **observed}
    return {"schema": 1, "images": evidence, "total_archive_bytes": total}


def run_private(argv, *, temp: Path, input=None, timeout=120):
    """Subprocess-local temp override; do not mutate the caller's environment."""
    proc = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                          env={**os.environ, "LC_ALL": "C", "TMPDIR": str(temp)}, check=False)
    if proc.returncode:
        raise CommandFailed(Path(argv[0]).name, proc.returncode)
    return proc.stdout.decode("utf-8", "strict").strip()


class ImageBundleLoader:
    def __init__(self, *, bundle_dir=BUNDLE_DIRECTORY, pins_path=PINS_PATH, data=DATA_DIRECTORY, gate=None, runner=None):
        self.bundle, self.pins_path, self.data = bundle_dir, pins_path, data
        self.gate = gate or FirstBoot().gate
        self.temp = data / "tmp"
        self.runner = runner or (lambda argv, **kwargs: run_private(argv, temp=self.temp, **kwargs))

    def _storage(self):
        gate = self.gate()
        if gate.get("host_ready") is not True:
            raise Refused("Image loading requires the measured firstboot host/storage gate")
        if self.temp.is_symlink():
            raise Refused("Image extraction temporary directory is a symlink")
        self.temp.mkdir(mode=0o700, exist_ok=True)
        info = self.temp.stat()
        if info.st_uid != 0 or info.st_mode & 0o077:
            raise Refused("Image extraction temporary directory must be private and root-owned")
        podman = strict_json(self.runner(["podman", "info", "--format", "json"]))
        if Path(podman["store"]["graphRoot"]) != self.data / "containers":
            raise Refused("Podman graphroot is outside enrolled encrypted storage")
        graph = self.data / "containers"
        graph_info = graph.lstat()
        if not stat.S_ISDIR(graph_info.st_mode) or graph_info.st_uid != 0 or graph_info.st_mode & 0o022:
            raise Refused("Encrypted Podman graphroot must be a protected root-owned directory")
        mounts = []
        for path in (self.data, self.data / "containers", self.temp):
            result = strict_json(self.runner(["findmnt", "--json", "--target", str(path)]))["filesystems"]
            if len(result) != 1 or result[0]["fstype"] != "xfs":
                raise Refused("Container image or temporary storage is not on the encrypted XFS mount")
            mounts.append(result[0]["source"].split("[")[0])
        if len(set(mounts)) != 1:
            raise Refused("Image storage and extraction temp do not share the enrolled data filesystem")

    def _inspect_installed(self, reference, expected):
        self.runner(["podman", "image", "exists", reference])
        images = strict_json(self.runner(["podman", "image", "inspect", reference]))
        if not isinstance(images, list) or len(images) != 1:
            raise Refused("Installed image identity is ambiguous")
        image = images[0]
        image_id = image.get("Id", "")
        if image.get("Digest") != expected["manifest_digest"] or image.get("Architecture") != "amd64" or image.get("Os") != "linux" or image_id.removeprefix("sha256:") != expected["config_digest"].removeprefix("sha256:"):
            raise Refused("Installed image does not match its verified manifest, configuration and architecture")
        return {"manifest_digest": image["Digest"], "config_digest": expected["config_digest"], "architecture": image["Architecture"], "os": image["Os"]}

    def load(self):
        self._storage()
        with locked(self.data / "manager/image-bundle.lock"):
            pins = _json_file(self.pins_path, root_owned=True)
            evidence = verify_bundle(self.bundle, pins, root_owned=True)
            free = os.statvfs(self.data)
            if free.f_bavail * free.f_frsize < evidence["total_archive_bytes"] * 4 + 1024**3:
                raise Refused("Insufficient encrypted free space for bounded offline image extraction and storage")
            installed = {}
            for name, item in evidence["images"].items():
                reference = item["reference"]
                try:
                    installed[name] = self._inspect_installed(reference, item)
                    continue
                except CommandFailed as exc:
                    if exc.returncode != 1:
                        raise
                archive = self.bundle / item["archive"]
                if file_sha256(archive, root_owned=True) != item["archive_sha256"]:
                    raise Refused("Offline image changed after bundle preflight")
                source = "oci-archive:" + str(archive)
                observed = strict_json(self.runner(["skopeo", "--override-os", "linux", "--override-arch", "amd64", "inspect", source], timeout=600))
                if observed.get("Digest") != item["manifest_digest"] or observed.get("Architecture") != "amd64" or observed.get("Os") != "linux":
                    raise Refused("Skopeo selected a different image than the verified OCI manifest")
                self.runner(["skopeo", "--override-os", "linux", "--override-arch", "amd64", "copy", "--preserve-digests", source, "containers-storage:" + reference], timeout=1800)
                installed[name] = self._inspect_installed(reference, item)
            receipt = {"schema": 1, "status": "loaded", "images": installed, "network_used": False}
            atomic_json(self.data / "manager/image-bundle-receipt.json", receipt)
            return receipt


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        print(json.dumps(ImageBundleLoader().load(), sort_keys=True, indent=2))
        return 0
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc) if isinstance(exc, Refused) else "Offline image verification/loading failed"}), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
