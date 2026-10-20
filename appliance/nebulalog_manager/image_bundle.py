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
    EMERGENCY_REVISION = "2"
    CURRENT_REVISION = "3"
    # Source identities do not qualify factory images, migration or packaging.
    HOST_CHALLENGE_REVISION = "4"
    RETENTION_REVISIONS = frozenset(("3", "4"))
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
        "3": {
            "migrations/postgres.sql": "32c37b73769156897a679f0216c7995561963875bfce74775d27abe5defc4de2",
            "migrations/clickhouse.sql": "f3a6610f55eee8469769f9c9def9a99c76ff64ed8f76fcf3a9b0196091a3628d",
            "migrations/host_stepup.sql": "b78e4e65ca8dc35593803fb89cfe1af76521495ca8cabdf9a174c86be6936b56",
        },
        "4": {
            "migrations/postgres.sql": "32c37b73769156897a679f0216c7995561963875bfce74775d27abe5defc4de2",
            "migrations/clickhouse.sql": "f3a6610f55eee8469769f9c9def9a99c76ff64ed8f76fcf3a9b0196091a3628d",
            "migrations/host_stepup.sql": "b78e4e65ca8dc35593803fb89cfe1af76521495ca8cabdf9a174c86be6936b56",
            "migrations/host_stepup_v2.sql": "4bc9481081be77b0aeaf26f162a633f3b2c1d5bb26c0bbbd1172df32a6260cfd",
        },
    }

    # Fixed host-installed SQL; never load a release-provided SQL path or hook.
    LEGACY_POSTGRES_SQL = 'CREATE TABLE IF NOT EXISTS saved_filters (\n id uuid PRIMARY KEY, owner_id text NOT NULL, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),\n description text NOT NULL DEFAULT \'\', query text NOT NULL, log_type text NOT NULL DEFAULT \'traffic\',\n columns jsonb NOT NULL DEFAULT \'[]\', time_range text NOT NULL DEFAULT \'1h\', sort text NOT NULL DEFAULT \'received_at\',\n favorite boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()\n);\nCREATE INDEX IF NOT EXISTS saved_filters_owner ON saved_filters(owner_id);\nCREATE TABLE IF NOT EXISTS layouts (owner_id text NOT NULL, log_type text NOT NULL, layout jsonb NOT NULL, PRIMARY KEY(owner_id,log_type));\nCREATE TABLE IF NOT EXISTS firewalls (\n serial text PRIMARY KEY, device_name text NOT NULL DEFAULT \'\', sender_ip text NOT NULL DEFAULT \'\',\n friendly_name text NOT NULL DEFAULT \'\', site text NOT NULL DEFAULT \'\', tags jsonb NOT NULL DEFAULT \'[]\', notes text NOT NULL DEFAULT \'\',\n panos_version text NOT NULL DEFAULT \'\', first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now()\n);\nCREATE TABLE IF NOT EXISTS settings (key text PRIMARY KEY, value jsonb NOT NULL);\nINSERT INTO settings(key,value) VALUES(\'retention\',\'{"global_days":90,"per_type":{"traffic":60,"threat":365,"url":90,"authentication":365,"configuration":365,"system":365}}\') ON CONFLICT DO NOTHING;\nCREATE TABLE IF NOT EXISTS audit_events(id bigserial PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL, action text NOT NULL, target text NOT NULL, detail jsonb NOT NULL DEFAULT \'{}\');\nCREATE TABLE IF NOT EXISTS export_jobs (\n id uuid PRIMARY KEY, owner_id text NOT NULL, status text NOT NULL, rows bigint NOT NULL DEFAULT 0, bytes bigint NOT NULL DEFAULT 0,\n error text NOT NULL DEFAULT \'\', request jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval \'24 hours\'\n);\nCREATE TABLE IF NOT EXISTS storage_samples(sampled_at timestamptz NOT NULL DEFAULT now(), database_bytes bigint NOT NULL, events bigint NOT NULL, PRIMARY KEY(sampled_at));\n\nALTER TABLE saved_filters ADD COLUMN IF NOT EXISTS sort_order text NOT NULL DEFAULT \'desc\' CHECK(sort_order IN (\'asc\',\'desc\'));\n\nCREATE TABLE IF NOT EXISTS user_preferences (\n owner_id text PRIMARY KEY,\n theme text NOT NULL DEFAULT \'system\' CHECK(theme IN (\'system\',\'light\',\'dark\')),\n density text NOT NULL DEFAULT \'compact\' CHECK(density IN (\'compact\',\'comfortable\')),\n rail_collapsed boolean NOT NULL DEFAULT false,\n updated_at timestamptz NOT NULL DEFAULT now()\n);\n'
    ADDITIVE_POSTGRES_SQL = '\n-- Emergency retention is separate from expiry assigned to future arrivals.\nINSERT INTO settings(key,value) VALUES(\'storage_emergency\',\'{"revision":1,"enabled":true,"trigger_percent":95,"recover_percent":90,"minimum_days":{"traffic":1,"url":7,"threat":30,"wildfire":30,"dns":30,"data":30,"hip":30,"globalprotect":30,"iptag":30,"userid":30,"decryption":30,"tunnel":30,"configuration":30,"system":30,"authentication":30}}\') ON CONFLICT DO NOTHING;\nINSERT INTO settings(key,value) VALUES(\'storage_emergency_maintenance\',\'{"schema":1,"held":false,"delivery_held":false,"operation":null}\') ON CONFLICT DO NOTHING;\nCREATE TABLE IF NOT EXISTS storage_emergency_state (\n singleton boolean PRIMARY KEY CHECK(singleton), value jsonb NOT NULL\n);\nINSERT INTO storage_emergency_state(singleton,value) VALUES(true,\'{"state":"not_observed","observed_at":null,"message":"Waiting for the first verified ClickHouse disk observation","emergency_active":false,"insert_exclusions":0}\') ON CONFLICT DO NOTHING;\nCREATE TABLE IF NOT EXISTS storage_emergency_actions (\n id uuid PRIMARY KEY, state text NOT NULL CHECK(state IN (\'prepared\',\'executing\',\'uncertain\',\'awaiting_cleanup\',\'completed\',\'cancelled\')),\n plan jsonb NOT NULL, message text NOT NULL DEFAULT \'\', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz\n);\nCREATE UNIQUE INDEX IF NOT EXISTS storage_emergency_one_pending ON storage_emergency_actions((true)) WHERE completed_at IS NULL;\nCREATE TABLE IF NOT EXISTS storage_emergency_inserts (\n id uuid PRIMARY KEY, table_uuid uuid NOT NULL, partitions jsonb NOT NULL, query_id uuid NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now()\n);\n'
    HOST_STEPUP_SQL = "-- Short-lived server-only OAuth transactions. State is SHA-256 hashed before\n-- insertion; nonce and PKCE verifier are never copied to audit/job records.\nCREATE TABLE IF NOT EXISTS host_stepup_pending (\n state_hash text PRIMARY KEY CHECK (state_hash ~ '^[a-f0-9]{64}$'),\n nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{43,128}$'),\n pkce_verifier text NOT NULL CHECK (pkce_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'),\n policy_digest text NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),\n actor_issuer text NOT NULL CHECK (octet_length(actor_issuer) BETWEEN 1 AND 2048 AND actor_issuer !~ '[[:cntrl:]]'),\n actor_subject text NOT NULL CHECK (octet_length(actor_subject) BETWEEN 1 AND 512 AND actor_subject !~ '[[:cntrl:]]'),\n actor_client_id text NOT NULL CHECK (octet_length(actor_client_id) BETWEEN 1 AND 512 AND actor_client_id !~ '[[:cntrl:]]'),\n actor_session_digest text NOT NULL CHECK (actor_session_digest ~ '^[a-f0-9]{64}$'),\n installation_id text NOT NULL CHECK (installation_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),\n operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_.]{0,127}$'),\n plan_id text NOT NULL CHECK (plan_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),\n plan_digest text NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),\n resource_revision text NOT NULL CHECK (resource_revision ~ '^[a-f0-9]{64}$'),\n binding_expires_at timestamptz NOT NULL CHECK (isfinite(binding_expires_at)),\n created_at timestamptz NOT NULL CHECK (isfinite(created_at) AND created_at >= '1970-01-01T00:00:00Z'),\n expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),\n CHECK (expires_at > created_at AND expires_at <= created_at + interval '120 seconds'),\n CHECK (expires_at <= binding_expires_at)\n);\nCREATE INDEX IF NOT EXISTS host_stepup_pending_expiry ON host_stepup_pending (expires_at, state_hash);\n"

    # Separately reviewed identity; never appended to the legacy step-up SQL.
    HOST_STEPUP_V2_SQL = "-- Explicit version 2 migration, applied separately from immutable application\n-- schema 1/2/3. The existing host_stepup_pending table stays inert; never copy\n-- its rows or infer missing host challenges. Invalidation clears both tables.\n-- Short-lived server-only OAuth transactions with mandatory host authority\n-- bindings. State is hashed; nonce/verifier/tokens never enter audit/job JSON.\n-- No default schema or challenge values can promote legacy inserts.\nCREATE TABLE IF NOT EXISTS host_stepup_pending_v2 (\n record_schema integer NOT NULL CHECK (record_schema = 2),\n state_hash text PRIMARY KEY CHECK (state_hash ~ '^[a-f0-9]{64}$'),\n nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),\n pkce_verifier text NOT NULL CHECK (pkce_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'),\n policy_digest text NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),\n actor_issuer text NOT NULL CHECK (octet_length(actor_issuer) BETWEEN 1 AND 2048 AND actor_issuer !~ '[[:cntrl:]]'),\n actor_subject text NOT NULL CHECK (octet_length(actor_subject) BETWEEN 1 AND 512 AND actor_subject !~ '[[:cntrl:]]'),\n actor_client_id text NOT NULL CHECK (octet_length(actor_client_id) BETWEEN 1 AND 512 AND actor_client_id !~ '[[:cntrl:]]'),\n actor_session_digest text NOT NULL CHECK (actor_session_digest ~ '^[a-f0-9]{64}$'),\n installation_id text NOT NULL CHECK (installation_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),\n operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_.]{0,127}$'),\n plan_id text NOT NULL CHECK (plan_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),\n plan_digest text NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),\n resource_revision text NOT NULL CHECK (resource_revision ~ '^[a-f0-9]{64}$'),\n binding_expires_at timestamptz NOT NULL CHECK (isfinite(binding_expires_at)),\n created_at timestamptz NOT NULL CHECK (isfinite(created_at) AND created_at >= '1970-01-01T00:00:00Z'),\n expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),\n challenge_schema integer NOT NULL CHECK (challenge_schema = 1),\n challenge_id text NOT NULL CHECK (challenge_id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),\n challenge_subject_digest text NOT NULL CHECK (challenge_subject_digest ~ '^[a-f0-9]{64}$'),\n challenge_operation_schema integer NOT NULL CHECK (challenge_operation_schema = 1),\n challenge_action text NOT NULL CHECK (challenge_action IN ('job.accept', 'job.cancel')),\n challenge_request_digest text NOT NULL CHECK (challenge_request_digest ~ '^[a-f0-9]{64}$'),\n challenge_policy_generation text NOT NULL CHECK (challenge_policy_generation ~ '^[a-f0-9]{64}$'),\n challenge_issued_at bigint NOT NULL CHECK (challenge_issued_at BETWEEN 1 AND 253402300799),\n challenge_expires_at bigint NOT NULL CHECK (challenge_expires_at BETWEEN 1 AND 253402300799),\n CHECK (expires_at > created_at AND expires_at <= created_at + interval '120 seconds'),\n CHECK (expires_at <= binding_expires_at),\n CHECK (challenge_expires_at > challenge_issued_at AND challenge_expires_at <= challenge_issued_at + 120),\n CHECK (created_at >= to_timestamp(challenge_issued_at)),\n CHECK (expires_at <= to_timestamp(challenge_expires_at) AND to_timestamp(challenge_expires_at) <= binding_expires_at)\n);\nCREATE INDEX IF NOT EXISTS host_stepup_pending_v2_expiry ON host_stepup_pending_v2 (expires_at, state_hash);\n"

    # Catalog construction only; this suffix does not authorize a 2-to-3 migration.
    RETENTION_POSTGRES_SQL = '\n-- The engine remains unavailable until the explicit migration verifies the\n-- events table identity and absence of legacy TTL. No event rows are rewritten.\nINSERT INTO settings(key,value) VALUES(\'retention_engine\',\'{"schema":1,"mode":"uninitialized"}\') ON CONFLICT DO NOTHING;\nINSERT INTO settings(key,value) VALUES(\'retention_status\',\'{"state":"not_observed","message":"Waiting for retention engine verification"}\') ON CONFLICT DO NOTHING;\nCREATE TABLE IF NOT EXISTS retention_actions (\n id uuid PRIMARY KEY, state text NOT NULL CHECK(state IN (\'prepared\',\'executing\',\'uncertain\',\'awaiting_cleanup\',\'completed\',\'cancelled\')),\n plan jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz\n);\nCREATE UNIQUE INDEX IF NOT EXISTS retention_one_pending ON retention_actions((true)) WHERE completed_at IS NULL;\n'

    @staticmethod
    def reviewed_retention_sql():
        legacy, additive, _ = ApplicationSchema.reviewed_sql()
        suffix = ApplicationSchema.RETENTION_POSTGRES_SQL
        if hashlib.sha256((legacy + additive + suffix).encode()).hexdigest() != ApplicationSchema.SCHEMAS["3"]["migrations/postgres.sql"]:
            raise Refused("Installed retention SQL differs from its reviewed source identity")
        return suffix

    @staticmethod
    def reviewed_host_stepup_v2_sql():
        """Fixed catalog construction only; never authority for a live upgrade."""
        body = ApplicationSchema.HOST_STEPUP_V2_SQL
        expected = ApplicationSchema.SCHEMAS[ApplicationSchema.HOST_CHALLENGE_REVISION]
        if hashlib.sha256(body.encode()).hexdigest() != expected["migrations/host_stepup_v2.sql"]:
            raise Refused("Installed host challenge SQL differs from its reviewed source identity")
        return body

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
        if migration not in ("none", ApplicationSchema.ADDITIVE_UPGRADE) or migration == ApplicationSchema.ADDITIVE_UPGRADE and revision != ApplicationSchema.EMERGENCY_REVISION:
            raise Refused("Application migration is not a reviewed fixed transition")
        return {"schema_revision": revision, "schema_sha256": digest, "database_migration": migration}

    @staticmethod
    def transition(change, installed_revision):
        """Validate only the declaration; this does not authorize SQL or activation."""
        if not isinstance(change, dict):
            raise Refused("Application schema transition requires an explicit declaration")
        ApplicationSchema.schema_digest(installed_revision)
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
        if target in ApplicationSchema.RETENTION_REVISIONS or installed_revision in ApplicationSchema.RETENTION_REVISIONS:
            raise Refused("Schemas 3 and 4 support only fresh installation or same-schema updates; a cross-schema compatibility bridge is not qualified")
        if (migration == ApplicationSchema.ADDITIVE_UPGRADE and installed_revision == ApplicationSchema.LEGACY_REVISION
                and target == ApplicationSchema.EMERGENCY_REVISION and change.get("rollback_safe") is True):
            return ApplicationSchema.ADDITIVE_UPGRADE
        raise Refused("Application schema change requires a supported explicit migration")


class RestoredAuthContract:
    """Source and HTTP behavior binding for the first supported restored runtime.

    The caller must authenticate the enclosing release (or the factory's existing
    measured provenance). This is not a new trust root and does not execute tests.
    A publisher must review the original exact-image test run before signing its
    report. Native restore/update/rollback acceptance remains a promotion gate;
    requiring that result here would prevent executing the qualification itself.
    """

    CONTRACT = "restored-jwt-issued-at-v1"
    SOURCE = "source-manifest.json"
    BUILD = "application-build.json"
    BEHAVIOR = "restore-auth-behavior.json"
    EVIDENCE = frozenset((BUILD, BEHAVIOR))
    MAX_RECEIPT = 8 * 1024**2
    REQUIRED_SOURCE = frozenset(("go.mod", "go.sum", "LICENSE", "appliance/images/application/Containerfile",
                                 "cmd/nebulalog/main.go", "internal/auth/auth.go", "internal/auth/restore.go"))
    CASES = {"before_cutoff": 401, "at_cutoff": 200, "after_cutoff": 200,
             "missing_iat": 401, "wrong_issuer": 401, "wrong_audience": 401,
             "wrong_signature": 401, "expired": 401}

    @classmethod
    def declaration(cls):
        return {"schema": 1, "contract": cls.CONTRACT, "source_artifact": cls.SOURCE,
                "build_artifact": cls.BUILD, "behavior_artifact": cls.BEHAVIOR}

    @staticmethod
    def application_files(files):
        return {name: sha for name, sha in files.items()
                if name in ("go.mod", "go.sum", "LICENSE", "appliance/images/application/Containerfile")
                or name.startswith(("cmd/", "internal/", "web/", "migrations/"))}

    @classmethod
    def application_hash(cls, files):
        return hashlib.sha256(json.dumps(cls.application_files(files), sort_keys=True,
                                         separators=(",", ":")).encode()).hexdigest()

    @classmethod
    def factory_descriptor(cls, value):
        """Validate an optional immutable factory descriptor, never enroll it."""
        from . import host_payload
        if (not isinstance(value, dict) or set(value) != {"schema", "contract", "version", "artifacts"}
                or type(value["schema"]) is not int or value["schema"] != 1 or value["contract"] != cls.CONTRACT
                or not isinstance(value["version"], str) or not host_payload.VERSION.fullmatch(value["version"])
                or not isinstance(value["artifacts"], dict) or set(value["artifacts"]) != cls.EVIDENCE):
            raise Refused("Factory restored authentication lacks its measured proof inventory")
        for item in value["artifacts"].values():
            if (not isinstance(item, dict) or set(item) != {"bytes", "sha256"}
                    or type(item["bytes"]) is not int or not 0 < item["bytes"] <= cls.MAX_RECEIPT
                    or not isinstance(item["sha256"], str) or not host_payload.SHA256.fullmatch(item["sha256"])):
                raise Refused("Factory restored authentication artifact identity is invalid")
        return value

    @classmethod
    def factory_capture(cls, files, image, build_raw, behavior_raw):
        """Package already reviewed image evidence, with no native acceptance claim."""
        from . import host_payload
        if any(not isinstance(raw, bytes) or not 0 < len(raw) <= cls.MAX_RECEIPT for raw in (build_raw, behavior_raw)):
            raise Refused("Factory restored authentication receipts exceed their bounds")
        build = host_payload.strict_json(build_raw)
        version = build.get("requested_version") if isinstance(build, dict) else None
        ApplicationSchema.bind_source(files, "3")
        cls._build(build, files, {"version": version}, image)
        cls._behavior(host_payload.strict_json(behavior_raw), {"image": image.get("reference")}, image, cls.application_hash(files))
        return cls.factory_descriptor({"schema": 1, "contract": cls.CONTRACT, "version": version,
            "artifacts": {name: {"bytes": len(raw), "sha256": host_payload.digest(raw)}
                          for name, raw in ((cls.BUILD, build_raw), (cls.BEHAVIOR, behavior_raw))}})

    @classmethod
    def verify_factory(cls, descriptor, share, host, image, *, root_owned=True):
        """Use only after the existing measured factory host/image verification.

        The initial-host record hashes initial-release.json, which in turn hashes
        these two receipts and source-manifest.json. No loose receipt is adopted.
        """
        from . import host_payload
        factory = cls.factory_descriptor(descriptor.get("restore_auth"))
        if descriptor.get("schema_revision") != "3":
            raise Refused("Factory restored authentication requires the supported fresh schema 3 baseline")
        share = Path(share)
        source_raw = host_payload.read_regular(share / cls.SOURCE, cls.MAX_RECEIPT, trusted=root_owned)
        if host_payload.digest(source_raw) != descriptor.get("source_snapshot_sha256"):
            raise Refused("Factory restored authentication source no longer matches its descriptor")
        raw = {}
        for name, expected in factory["artifacts"].items():
            raw[name] = host_payload.read_regular(share / "restore-auth" / name, cls.MAX_RECEIPT, trusted=root_owned)
            if {"bytes": len(raw[name]), "sha256": host_payload.digest(raw[name])} != expected:
                raise Refused("Factory restored authentication receipt changed")
        subject = cls._subject(source_raw, raw[cls.BUILD], raw[cls.BEHAVIOR], host, image, factory["version"],
                               host_version=host.get("metadata", {}).get("version"))
        return {"schema": 1, "contract": cls.CONTRACT, "subject": subject,
                "proof_artifacts": factory["artifacts"], "native_qualified": False, "execution_verified_by_tool": False}

    @classmethod
    def _subject(cls, source_raw, build_raw, behavior_raw, host, image, version, *, host_version=None):
        from . import host_payload
        files = host_payload.source_manifest(source_raw)["files"]
        ApplicationSchema.bind_source(files, "3")
        metadata = host_payload.validate_metadata(host.get("metadata"))
        generation = host.get("archive_sha256")
        if (not isinstance(generation, str) or not host_payload.SHA256.fullmatch(generation)
                or metadata["version"] != (version if host_version is None else host_version)
                or metadata["source_snapshot_sha256"] != host_payload.digest(source_raw)
                or metadata["host_source_sha256"] != host_payload.host_source_hash(files)
                or {item["source"]: item["sha256"] for item in metadata["files"]}
                   != {name: files[name] for name in host_payload.CATALOG_BY_SOURCE}):
            raise Refused("Restored authentication host generation differs from its source snapshot")
        reference = image.get("reference")
        if (not isinstance(reference, str) or not REFERENCE.fullmatch(reference)
                or image.get("manifest_digest") != reference.rsplit("@", 1)[-1]
                or image.get("architecture") != "amd64" or image.get("os") != "linux"
                or not isinstance(image.get("config_digest"), str) or not DIGEST.fullmatch(image["config_digest"])):
            raise Refused("Restored authentication image lacks its verified OCI identity")
        cls._build(host_payload.strict_json(build_raw), files, {"version": version}, image)
        source_hash = cls.application_hash(files)
        cls._behavior(host_payload.strict_json(behavior_raw), {"image": reference}, image, source_hash)
        return {"source_snapshot_sha256": host_payload.digest(source_raw),
                "application_source_sha256": source_hash, "host_source_sha256": metadata["host_source_sha256"],
                "host_generation": generation, "catalog_sha256": metadata["catalog_sha256"],
                "application_image": reference, "application_config_digest": image["config_digest"],
                "schema_revision": "3", "schema_sha256": ApplicationSchema.schema_digest("3")}

    @classmethod
    def validate_metadata(cls, manifest):
        """Eligibility only; declaration presence cannot authorize installation."""
        from . import host_payload
        declaration = manifest.get("restore_auth")
        if (declaration != cls.declaration() or type(declaration.get("schema")) is not int):
            raise Refused("Restored authentication requires the fixed source and behavior contract")
        components = manifest.get("components", {})
        if not {"host", "nebulalog"} <= set(components):
            raise Refused("Restored authentication requires a combined host and application release")
        application = components["nebulalog"]
        if (application.get("schema_revision") != "3" or application.get("database_migration") != "none"
                or application.get("schema_sha256") != ApplicationSchema.schema_digest("3")
                or any(components[name].get("rollback_safe") is not True for name in ("host", "nebulalog"))):
            raise Refused("Restored authentication starts with fresh schema 3; legacy prototypes require a separate qualified bridge")
        artifacts = {}
        for item in manifest.get("artifacts", []):
            if (not isinstance(item, dict) or set(item) != {"name", "sha256", "bytes"}
                    or not isinstance(item["name"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}", item["name"])
                    or item["name"] in artifacts or type(item["bytes"]) is not int or item["bytes"] <= 0
                    or not isinstance(item["sha256"], str) or not host_payload.SHA256.fullmatch(item["sha256"])):
                raise Refused("Restored authentication artifact inventory is invalid")
            artifacts[item["name"]] = item
        if not {cls.SOURCE, cls.BUILD, cls.BEHAVIOR} <= set(artifacts):
            raise Refused("Restored authentication proof must be covered by signed artifact hashes")
        if any(artifacts[name]["bytes"] > cls.MAX_RECEIPT for name in (cls.SOURCE, cls.BUILD, cls.BEHAVIOR)):
            raise Refused("Restored authentication proof exceeds its bounded size")
        return artifacts

    @classmethod
    def _build(cls, value, files, manifest, image):
        from . import host_payload
        fields = {"schema", "status", "tag", "local_image_id", "platform", "requested_version", "application_source_sha256",
                  "source_commit", "source_dirty", "application_files", "context_sha256", "context_bytes", "source_bytes",
                  "source_files", "context_mode", "runtime_executed", "signature_created"}
        selected = cls.application_files(files)
        if (not isinstance(value, dict) or set(value) != fields or type(value["schema"]) is not int or value["schema"] != 1
                or value["status"] != "built" or value["platform"] != "linux/amd64"
                or value["context_mode"] != "captured_source_tar_stdin"
                or value["runtime_executed"] is not False or value["signature_created"] is not False
                or type(value["source_dirty"]) is not bool
                or not isinstance(value["source_commit"], str) or not re.fullmatch(r"[a-f0-9]{40}", value["source_commit"])
                or not isinstance(value["tag"], str) or not re.fullmatch(r"nebulalog/[a-z0-9]+(?:[._-][a-z0-9]+)*:[a-z0-9][a-z0-9._-]{0,100}", value["tag"])
                or value["requested_version"] != manifest["version"]
                or value["application_files"] != selected or not cls.REQUIRED_SOURCE <= set(selected)
                or value["application_source_sha256"] != cls.application_hash(files)
                or image.get("application_source_sha256") != value["application_source_sha256"]
                or value["local_image_id"] != image.get("config_digest")
                or type(value["source_files"]) is not int or value["source_files"] != len(selected)
                or any(type(value[key]) is not int for key in ("context_bytes", "source_bytes"))
                or not 0 < value["source_bytes"] <= value["context_bytes"] <= 512 * 1024**2
                or not isinstance(value["context_sha256"], str) or not host_payload.SHA256.fullmatch(value["context_sha256"])):
            raise Refused("Application build receipt does not bind the exact captured source and OCI configuration")

    @classmethod
    def _behavior(cls, value, application, image, source_hash):
        from . import host_payload
        fields = {"schema", "kind", "method", "application_image", "application_config_digest",
                  "application_source_sha256", "command", "http_method", "path", "issuer_mode", "cutoff", "observed_cutoff", "cases"}
        if (not isinstance(value, dict) or set(value) != fields or type(value["schema"]) is not int or value["schema"] != 1
                or value["kind"] != "captains-log-restored-token-boundary"
                or value["method"] != "isolated-image-normal-api-http"
                or value["application_image"] != application["image"]
                or value["application_config_digest"] != image.get("config_digest")
                or value["application_source_sha256"] != source_hash or value["command"] != ["serve"]
                or value["http_method"] != "GET" or value["path"] != "/api/me" or value["issuer_mode"] != "isolated-fixture"
                or type(value["cutoff"]) is not int or not 1577836800 <= value["cutoff"] < 2**31
                or type(value["observed_cutoff"]) is not int or value["observed_cutoff"] != value["cutoff"]
                or not isinstance(value["cases"], dict) or set(value["cases"]) != set(cls.CASES)):
            raise Refused("Restored authentication behavior must bind the exact normal API image and fixed cutoff")
        cutoff = value["cutoff"]
        for name, status in cls.CASES.items():
            case = value["cases"][name]
            fields = {"iat", "exp", "observed_at", "issuer_match", "audience_match", "signature_valid", "http_status", "api_role", "token_sha256"}
            expected_iat = None if name == "missing_iat" else cutoff + (-1 if name == "before_cutoff" else 1 if name == "after_cutoff" else 0)
            if (not isinstance(case, dict) or set(case) != fields
                    or (case["iat"] is not None and type(case["iat"]) is not int) or case["iat"] != expected_iat
                    or any(type(case[key]) is not int for key in ("exp", "observed_at", "http_status"))
                    or not cutoff + 1 <= case["observed_at"] < 2**31 or case["http_status"] != status
                    or case["api_role"] != ("VIEWER" if status == 200 else None)
                    or any(case[key] is not expected for key, expected in (
                        ("issuer_match", name != "wrong_issuer"), ("audience_match", name != "wrong_audience"),
                        ("signature_valid", name != "wrong_signature")))
                    or not isinstance(case["token_sha256"], str) or not host_payload.SHA256.fullmatch(case["token_sha256"])
                    or not (cutoff <= case["exp"] < case["observed_at"] if name == "expired"
                            else case["observed_at"] + 30 <= case["exp"] < 2**31)):
                raise Refused("Restored authentication HTTP boundary case is missing, confounded or unsuccessful: " + name)

    @classmethod
    def verify(cls, manifest, bundle, *, host=None, image=None, root_owned=False):
        """Verify bytes under caller-authenticated metadata; no adoption or writes."""
        from . import host_payload
        artifacts = cls.validate_metadata(manifest)
        bundle = Path(bundle)
        raw = {}
        for name in (cls.SOURCE, cls.BUILD, cls.BEHAVIOR):
            raw[name] = host_payload.read_regular(bundle / name, cls.MAX_RECEIPT, trusted=root_owned)
            if len(raw[name]) != artifacts[name]["bytes"] or host_payload.digest(raw[name]) != artifacts[name]["sha256"]:
                raise Refused("Restored authentication proof differs from its signed artifact identity")
        source = host_payload.source_manifest(raw[cls.SOURCE])
        files = source["files"]
        application = manifest["components"]["nebulalog"]
        ApplicationSchema.bind_source(files, "3")
        host_change = manifest["components"]["host"]
        if host_change.get("artifact") not in artifacts or application.get("artifact") not in artifacts:
            raise Refused("Restored authentication component artifacts are absent")
        host_artifact = artifacts[host_change["artifact"]]
        if host is None:
            host = host_payload.verify_archive(bundle / host_change["artifact"], expected_sha256=host_artifact["sha256"],
                                               expected_host_source_sha256=host_change["host_source_sha256"])
        metadata = host.get("metadata", {})
        if (host.get("archive_sha256") != host_artifact["sha256"] or host.get("archive_bytes") != host_artifact["bytes"]
                or metadata.get("version") != host_change["version"]
                or metadata.get("source_snapshot_sha256") != host_payload.digest(raw[cls.SOURCE])
                or metadata.get("host_source_sha256") != host_change["host_source_sha256"]
                or metadata.get("host_source_sha256") != host_payload.host_source_hash(files)
                or metadata.get("catalog_sha256") != host_payload.CATALOG_SHA256
                or {item["source"]: item["sha256"] for item in metadata.get("files", [])}
                   != {name: files[name] for name in host_payload.CATALOG_BY_SOURCE}):
            raise Refused("Restored authentication host generation differs from its source snapshot")
        if image is None:
            image = verify_oci_archive(bundle / application["artifact"], application["image"])
        image_artifact = artifacts[application["artifact"]]
        if (image.get("archive_sha256") != image_artifact["sha256"] or image.get("archive_bytes") != image_artifact["bytes"]
                or image.get("manifest_digest") != application["image"].rsplit("@", 1)[-1]
                or image.get("architecture") != "amd64" or image.get("os") != "linux"
                or not isinstance(image.get("config_digest"), str) or not DIGEST.fullmatch(image["config_digest"])):
            raise Refused("Restored authentication image differs from its signed OCI identity")
        subject = cls._subject(raw[cls.SOURCE], raw[cls.BUILD], raw[cls.BEHAVIOR], host,
                               {**image, "reference": application["image"]}, manifest["version"])
        return {"schema": 1, "contract": cls.CONTRACT,
                "subject": subject,
                "proof_artifacts": {name: artifacts[name] for name in (cls.SOURCE, cls.BUILD, cls.BEHAVIOR)},
                "native_qualified": False, "execution_verified_by_tool": False}


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
