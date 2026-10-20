"""Fixed schema-4 PostgreSQL initialization primitive; not an activation path.

The firstboot coordinator must own its protected runtime journal and lock, bind
the supplied factory identity to installed provenance, and persist checkpoints
before calling this primitive. A dictionary is not authorization. This module
has no CLI, default runtime hook, or authority to release maintenance or start
services. ClickHouse/retention, restore and native qualification remain separate.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid

from .common import Refused
from .image_bundle import ApplicationSchema, strict_json

# Matches the exact PGDG release in images/postgresql-fips/{BOM.json,Containerfile}.
# A different server version requires explicit profile review, not a fallback.
POSTGRES_SERVER_VERSION = 170011


def _binding(value):
    fields = {"installation_id", "source_snapshot_sha256", "image", "schema_revision", "schema_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise Refused("Fresh database initialization requires exact factory provenance")
    try:
        canonical = str(uuid.UUID(value["installation_id"]))
    except (ValueError, TypeError, AttributeError):
        raise Refused("Fresh database initialization requires a canonical installation") from None
    if (canonical != value["installation_id"] or canonical == str(uuid.UUID(int=0))
            or value["schema_revision"] != ApplicationSchema.HOST_CHALLENGE_REVISION
            or value["schema_sha256"] != ApplicationSchema.schema_digest("4")
            or not isinstance(value["source_snapshot_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", value["source_snapshot_sha256"])
            or not isinstance(value["image"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}", value["image"])):
        raise Refused("Fresh database provenance is unsupported or incomplete")
    return copy.deepcopy(value)


def _database(value):
    if (not isinstance(value, dict) or set(value) != {"system_identifier", "database_oid", "database", "owner", "server_version"}
            or value["database"] != "nebulalog" or value["owner"] != "nebulalog"
            or not isinstance(value["system_identifier"], str)
            or not re.fullmatch(r"[1-9][0-9]{0,19}", value["system_identifier"])
            or type(value["database_oid"]) is not int or not 1 <= value["database_oid"] < 2**32
            or type(value["server_version"]) is not int or value["server_version"] != POSTGRES_SERVER_VERSION):
        raise Refused("Fresh database identity is outside the fixed PostgreSQL 17.11 profile")
    return copy.deepcopy(value)


# These checks precede even the disposable catalog probe. The fixed connection
# is the appliance's local administrative socket; DDL runs as the unprivileged
# owner below. No caller-selected database, user, SQL file or endpoint exists.
_PREFLIGHT = """
 PERFORM pg_advisory_xact_lock(__STORAGE_LOCK__);
 IF current_database()<>'nebulalog' OR current_user<>'postgres'
  OR current_setting('server_version_num')<>'__POSTGRES_SERVER_VERSION__'
  OR (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()) IS DISTINCT FROM 'nebulalog'
 THEN RAISE EXCEPTION 'Unexpected factory database identity'; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='nebulalog' AND rolcanlogin
   AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
  OR EXISTS(SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='nebulalog'))
 THEN RAISE EXCEPTION 'Unexpected application role authority'; END IF;
 IF EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid())
  OR EXISTS(SELECT FROM pg_prepared_xacts WHERE database=current_database())
 THEN RAISE EXCEPTION 'Factory database is not exclusively idle'; END IF;
 IF EXISTS(SELECT FROM pg_event_trigger) OR EXISTS(SELECT FROM pg_default_acl)
  OR EXISTS(SELECT FROM pg_extension WHERE extname<>'plpgsql')
  OR EXISTS(SELECT FROM pg_foreign_server)
  OR EXISTS(SELECT FROM pg_namespace WHERE nspname NOT IN ('public','pg_catalog','information_schema')
    AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%')
 THEN RAISE EXCEPTION 'Unqualified factory database objects or DDL hooks'; END IF;
 IF (SELECT nspowner FROM pg_namespace WHERE nspname='public') IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname='pg_database_owner')
  OR (SELECT count(*) FROM aclexplode((SELECT nspacl FROM pg_namespace WHERE nspname='public'))) != 3
  OR EXISTS(SELECT FROM aclexplode((SELECT nspacl FROM pg_namespace WHERE nspname='public')) a
    WHERE a.is_grantable OR a.grantor<>(SELECT oid FROM pg_roles WHERE rolname='pg_database_owner')
    OR NOT (a.grantee=(SELECT oid FROM pg_roles WHERE rolname='pg_database_owner') AND a.privilege_type IN ('CREATE','USAGE')
      OR a.grantee=0 AND a.privilege_type='USAGE'))
 THEN RAISE EXCEPTION 'Unqualified public namespace privileges'; END IF;
"""

_IDENTITY = """jsonb_build_object('system_identifier',(SELECT system_identifier::text FROM pg_control_system()),
 'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'database',current_database(),'owner','nebulalog','server_version',current_setting('server_version_num')::integer)"""


def _catalogs():
    # The installed host catalog owns both modules. Expected catalog is rebuilt
    # from hash-checked fixed SQL, never learned from an existing database.
    from nebulalog_adapters.lifecycle import Lifecycle
    return Lifecycle._schema_catalog, Lifecycle._schema_literal


def _preflight():
    from nebulalog_adapters.lifecycle import STORAGE_LOCK
    return (_PREFLIGHT.replace("__STORAGE_LOCK__", str(STORAGE_LOCK))
            .replace("__POSTGRES_SERVER_VERSION__", str(POSTGRES_SERVER_VERSION)))


def probe_sql():
    catalog, _ = _catalogs()
    return f"""SET LOCAL search_path=pg_catalog;
SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s';
DO $fresh$ BEGIN {_preflight()} END $fresh$;
SELECT jsonb_build_object('database',{_IDENTITY},'empty',
 NOT EXISTS(SELECT FROM pg_class WHERE relnamespace='public'::regnamespace)
 AND NOT EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace)
 AND NOT EXISTS(SELECT FROM pg_type WHERE typnamespace='public'::regnamespace)
 AND (SELECT (value->>'extra_objects')::bigint=0 FROM ({catalog('public')}) q(value)))::text;
"""


def initialize_sql(database, *, complete=False):
    database = _database(database)
    if type(complete) is not bool:
        raise Refused("Invalid fresh database phase")
    catalog, literal = _catalogs()
    legacy, additive, stepup = ApplicationSchema.reviewed_sql()
    fixed = legacy + additive + ApplicationSchema.reviewed_retention_sql() + stepup + ApplicationSchema.reviewed_host_stepup_v2_sql()
    expected = literal(catalog("captainslog_fresh_probe"))
    actual = literal(catalog("public"))
    identity = literal(json.dumps(database, sort_keys=True, separators=(",", ":"))) + "::jsonb"
    return f"""SET LOCAL search_path=pg_catalog;
SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='90s';
CREATE TEMP TABLE captainslog_fresh_result(value jsonb) ON COMMIT DROP;
DO $fresh$
DECLARE expected jsonb; actual jsonb; empty_catalog jsonb; item record;
BEGIN
 {_preflight()}
 IF {_IDENTITY} IS DISTINCT FROM {identity}
 THEN RAISE EXCEPTION 'Factory database identity changed after admission'; END IF;
 -- Any public executable function is refused before fixed SQL or defaults run.
 IF EXISTS(SELECT FROM pg_proc WHERE pronamespace='public'::regnamespace)
 THEN RAISE EXCEPTION 'Unqualified public functions'; END IF;
 FOR item IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname LOOP
  EXECUTE format('LOCK TABLE public.%I IN ACCESS EXCLUSIVE MODE',item.relname);
 END LOOP;
 CREATE SCHEMA captainslog_fresh_probe AUTHORIZATION nebulalog;
 SET LOCAL ROLE nebulalog;
 EXECUTE {expected} INTO empty_catalog;
 SET LOCAL search_path=captainslog_fresh_probe,pg_catalog;
 EXECUTE {literal(fixed)};
 SET LOCAL search_path=pg_catalog;
 EXECUTE {expected} INTO expected;
 DROP SCHEMA captainslog_fresh_probe CASCADE;
 EXECUTE {actual} INTO actual;
 IF actual=empty_catalog AND NOT {str(complete).lower()} THEN
  SET LOCAL search_path=public,pg_catalog;
  EXECUTE {literal(fixed)};
  SET LOCAL search_path=pg_catalog;
  EXECUTE {actual} INTO actual;
 END IF;
 IF actual IS DISTINCT FROM expected
 THEN RAISE EXCEPTION 'Factory database is neither owned empty work nor exact schema 4'; END IF;
 RESET ROLE;
 INSERT INTO pg_temp.captainslog_fresh_result VALUES(jsonb_build_object('database',{_IDENTITY},
  'revision','4','profile','host-stepup-v2','catalog',actual));
END $fresh$;
SELECT value::text FROM pg_temp.captainslog_fresh_result;
"""


class FreshPostgres:
    """Caller owns the protected host journal/lock; this does not grant authority."""

    def __init__(self, commands):
        self.cmd = commands

    def _query(self, sql):
        result = self.cmd(["podman", "exec", "-i", "--user", "999:999", "nebulalog-postgresql",
            "psql", "-X", "--no-password", "--host=/var/run/postgresql", "--username=postgres",
            "--dbname=nebulalog", "--single-transaction", "--quiet", "--tuples-only", "--no-align",
            "--set=ON_ERROR_STOP=1"], input=sql.encode(), timeout=120)
        if not isinstance(result, str) or not 1 <= len(result.encode()) <= 256 * 1024:
            raise Refused("Invalid factory database readback")
        return strict_json(result.encode())

    def initialize(self, binding, transaction, checkpoint):
        binding = _binding(binding)
        if not isinstance(transaction, dict) or not callable(checkpoint):
            raise Refused("Fresh database initialization requires a protected coordinator journal")
        prior = transaction.get("fresh_postgres")
        if "fresh_postgres" in transaction:
            if (not isinstance(prior, dict) or set(prior) != {"schema", "binding", "database", "phase"}
                    or type(prior["schema"]) is not int or prior["schema"] != 1
                    or prior["binding"] != binding or prior["phase"] not in ("intent", "complete")):
                raise Refused("Fresh database journal is foreign or incomplete")
            _database(prior["database"])
        observed = self._query(probe_sql())
        if not isinstance(observed, dict) or set(observed) != {"database", "empty"} or type(observed["empty"]) is not bool:
            raise Refused("Invalid factory database admission readback")
        database = _database(observed["database"])
        if prior is None:
            if observed["empty"] is not True:
                raise Refused("First initialization requires an empty database; existing catalogs cannot grant resume authority")
            admitted = {"schema": 1, "binding": binding, "database": database, "phase": "intent"}
            transaction["fresh_postgres"] = copy.deepcopy(admitted)
            try:
                checkpoint()
            except BaseException:
                # No SQL dispatched: do not retain an unacknowledged in-memory
                # admission. The coordinator must reload its durable journal.
                transaction.pop("fresh_postgres", None)
                raise
            if transaction.get("fresh_postgres") != admitted:
                raise Refused("Fresh database checkpoint changed the admitted identity")
            prior = transaction["fresh_postgres"]
        if prior["database"] != database:
            raise Refused("Fresh database identity differs from its retained intent")
        # A lost acknowledgement retains intent. The single transaction can
        # only leave empty or exact4; a later attempt reads back before deciding.
        result = self._query(initialize_sql(database, complete=prior["phase"] == "complete"))
        if (not isinstance(result, dict) or set(result) != {"database", "revision", "profile", "catalog"}
                or result["database"] != database or result["revision"] != "4"
                or result["profile"] != "host-stepup-v2" or not isinstance(result["catalog"], dict)
                or set(result["catalog"]) != {"relations", "columns", "constraints", "indexes", "sequences",
                    "triggers", "rules", "policies", "inheritance", "extra_objects", "functions", "extra_types", "extensions"}
                or any(result["catalog"][key] != 0 for key in ("extra_objects", "functions", "extra_types", "extensions"))
                or any(not isinstance(result["catalog"][key], list) for key in ("relations", "columns", "constraints",
                    "indexes", "sequences", "triggers", "rules", "policies", "inheritance"))):
            raise Refused("Fresh database completion readback differs; retained intent requires recovery")
        transaction["fresh_postgres"] = {**prior, "phase": "complete"}
        checkpoint()
        return {"revision": "4", "database": database,
                "catalog_sha256": hashlib.sha256(json.dumps(result["catalog"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
