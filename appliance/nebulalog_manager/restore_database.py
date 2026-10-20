"""Fixed, unprivileged database application for configuration recovery.

This module never drops a database and never retries an ambiguous restore. Each
archive is applied in its own PostgreSQL transaction; the two databases are not
claimed to commit atomically. The coordinator persists intent before dispatch.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from .backup import DATABASES, _pg
from .common import Refused, trusted_file
from .updates import digest_file


def _uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise Refused("Recovery identifiers must be canonical UUIDs")
    return value


def _connection(name, operation, *, interactive=False):
    if name not in DATABASES:
        raise Refused("Recovery database is outside the fixed appliance scope")
    # No inherited credentials, shell, TCP endpoint or superuser is accepted.
    return _pg(["PGAPPNAME=captainslog-restore-" + _uuid(operation), "psql", "-X",
                "--no-password", "--host=/var/run/postgresql", "--username=" + name,
                "--dbname=" + name, "--tuples-only", "--no-align",
                "--set=ON_ERROR_STOP=1"], interactive=interactive)


EMPTY_SQL = """SELECT json_build_object(
 'database', current_database(), 'user', current_user,
 'owner', (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()),
 'privileged', (SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=current_user),
 'memberships', (SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)),
 'sessions', (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()),
 'objects', (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')
          + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema'))
          + (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('public','pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%')
          + (SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql')
          + (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')
          + (SELECT count(*) FROM pg_event_trigger)
          + (SELECT count(*) FROM pg_foreign_server));"""


class RestoreDatabases:
    def __init__(self, commands):
        self.cmd = commands

    def empty(self, name, operation):
        value = json.loads(self.cmd(_connection(name, operation) + ["--command", EMPTY_SQL]))
        if (set(value) != {"database", "user", "owner", "privileged", "memberships", "sessions", "objects"}
                or any(value.get(key) != name for key in ("database", "user", "owner"))
                or value.get("privileged") is not False
                or any(type(value.get(key)) is not int or value[key] != 0
                       for key in ("memberships", "sessions", "objects"))):
            raise Refused("Recovery requires an empty, idle database owned by its unprivileged appliance role")
        return value

    def apply(self, name: str, archive: Path, entry: dict, transaction: dict, checkpoint):
        """Apply once; checkpoint is a durable callback owned by the coordinator."""
        operation = _uuid(transaction["id"])
        if name not in DATABASES or entry.get("path") != name + ".dump":
            raise Refused("Archive does not match the recovery database")
        trusted_file(archive)
        if (archive.is_symlink() or archive.stat().st_nlink != 1 or archive.stat().st_mode & 0o077
                or type(entry.get("bytes")) is not int or entry["bytes"] <= 0
                or archive.stat().st_size != entry["bytes"]
                or not isinstance(entry.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
                or digest_file(archive) != entry["sha256"]):
            raise Refused("Recovery archive differs from its authenticated inventory")
        databases = transaction.get("databases", {})
        previous = databases.get(name)
        if previous is not None:
            # A durable completion is sufficient to skip this phase only while
            # the coordinator also owns and validates the target transaction.
            if previous == {"state": "restored", "archive_sha256": entry["sha256"]}:
                return
            raise Refused("An interrupted database restore is ambiguous; retained data was not overwritten")
        self.empty(name, operation)
        self.cmd.feed(_pg(["pg_restore", "--list"], interactive=True), archive, timeout=3600)
        transaction["databases"] = databases
        databases[name] = {"state": "restoring", "archive_sha256": entry["sha256"]}
        checkpoint()
        try:
            self.cmd.feed(_pg(["PGAPPNAME=captainslog-restore-" + operation, "pg_restore",
                              "--no-password", "--host=/var/run/postgresql", "--username=" + name,
                              "--dbname=" + name, "--single-transaction", "--exit-on-error",
                              "--no-owner", "--no-privileges"], interactive=True), archive, timeout=3600)
        except BaseException:
            # A disconnected client cannot establish whether COMMIT reached the
            # server. Preserve intent even for an ordinary nonzero exit; never
            # convert uncertainty into permission to retry or clean a database.
            raise Refused("Database recovery did not finish with a durable acknowledgement; services remain fenced") from None
        databases[name] = {"state": "restored", "archive_sha256": entry["sha256"]}
        checkpoint()

    def quarantine_source_operations(self, transaction: dict):
        """Keep settings/accounts/history, invalidate work bound to the old host.

        All changed source rows remain in the retained authenticated archive.
        This transaction and its audit marker are atomic and idempotent.
        """
        operation = _uuid(transaction["id"])
        source = _uuid(transaction["source_installation_id"])
        target = _uuid(transaction["target_installation_id"])
        if any(transaction.get("databases", {}).get(name, {}).get("state") != "restored" for name in DATABASES):
            raise Refused("Both database restores must finish before host-bound operations are quarantined")
        # Every interpolated value is a canonical UUID, never arbitrary SQL.
        sql = """BEGIN;
LOCK TABLE audit_events, export_jobs, storage_samples, storage_emergency_actions,
 storage_emergency_inserts, storage_emergency_state, settings IN ACCESS EXCLUSIVE MODE;
DO $restore$
DECLARE prior jsonb; counts jsonb; affected bigint; transient bigint := 0;
BEGIN
 SELECT detail INTO prior FROM audit_events
  WHERE action='appliance.restore.configuration' AND target='%s';
 IF FOUND THEN
  IF prior->>'source_installation_id'<>'%s' OR prior->>'target_installation_id'<>'%s' THEN
   RAISE EXCEPTION 'Recovery audit identity mismatch';
  END IF;
  RETURN;
 END IF;
 counts := jsonb_build_object('exports', (SELECT count(*) FROM export_jobs),
  'storage_samples', (SELECT count(*) FROM storage_samples),
  'pending_storage_actions', (SELECT count(*) FROM storage_emergency_actions WHERE completed_at IS NULL),
  'insertion_reservations', (SELECT count(*) FROM storage_emergency_inserts));
 IF to_regclass('public.host_stepup_pending') IS NOT NULL THEN
  EXECUTE 'DELETE FROM public.host_stepup_pending';
  GET DIAGNOSTICS transient = ROW_COUNT;
 END IF;
 IF to_regclass('public.host_stepup_pending_v2') IS NOT NULL THEN
  EXECUTE 'DELETE FROM public.host_stepup_pending_v2';
  GET DIAGNOSTICS affected = ROW_COUNT;
  transient := transient + affected;
 END IF;
 UPDATE export_jobs SET status='failed', error='Configuration restored without exported files';
 DELETE FROM storage_samples;
 UPDATE storage_emergency_actions SET state='cancelled', completed_at=now(), updated_at=now(),
  message='Source-host operation quarantined during configuration restore'
  WHERE completed_at IS NULL;
 DELETE FROM storage_emergency_inserts;
 UPDATE storage_emergency_state SET value='{"state":"not_observed","observed_at":null,"message":"Configuration restored; waiting for this host storage observation","emergency_active":false,"insert_exclusions":0}'::jsonb WHERE singleton=true;
 GET DIAGNOSTICS affected = ROW_COUNT;
 IF affected<>1 THEN RAISE EXCEPTION 'Missing storage state'; END IF;
 UPDATE settings SET value='{"schema":1,"held":false,"delivery_held":false,"operation":null}'::jsonb WHERE key='storage_emergency_maintenance';
 GET DIAGNOSTICS affected = ROW_COUNT;
 IF affected<>1 THEN RAISE EXCEPTION 'Missing storage maintenance setting'; END IF;
 IF to_regclass('public.retention_actions') IS NOT NULL THEN
  EXECUTE 'LOCK TABLE public.retention_actions IN ACCESS EXCLUSIVE MODE';
  EXECUTE $retention$UPDATE public.retention_actions SET state='cancelled',
   plan=jsonb_set(plan, '{state}', '"cancelled"'::jsonb), completed_at=now(), updated_at=now()
   WHERE completed_at IS NULL$retention$;
  GET DIAGNOSTICS affected = ROW_COUNT;
  counts := counts || jsonb_build_object('pending_retention_actions', affected);
  UPDATE settings SET value='{"schema":1,"mode":"uninitialized"}'::jsonb WHERE key='retention_engine';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected<>1 THEN RAISE EXCEPTION 'Missing retention engine setting'; END IF;
  UPDATE settings SET value='{"state":"not_observed","message":"Configuration restored; waiting for target retention table initialization"}'::jsonb WHERE key='retention_status';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected<>1 THEN RAISE EXCEPTION 'Missing retention status setting'; END IF;
 END IF;
 INSERT INTO audit_events(actor,action,target,detail) VALUES ('appliance-recovery',
  'appliance.restore.configuration','%s', counts || jsonb_build_object(
   'source_installation_id','%s','target_installation_id','%s',
   'expired_host_authorizations',transient,'logs_restored',false));
END $restore$;
COMMIT;
""" % (operation, source, target, operation, source, target)
        self.cmd(_connection("nebulalog", operation, interactive=True), input=sql.encode(), timeout=300)
        query = "SELECT count(*) FROM audit_events WHERE action='appliance.restore.configuration' AND target='" + operation + "' AND detail->>'source_installation_id'='" + source + "' AND detail->>'target_installation_id'='" + target + "';"
        if self.cmd(_connection("nebulalog", operation) + ["--command", query]).strip() != "1":
            raise Refused("Recovery quarantine did not produce its exact audit receipt")
