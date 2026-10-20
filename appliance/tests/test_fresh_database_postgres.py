"""Opt-in actual PostgreSQL 17.11 SQL qualification, never a native FIPS claim.

The harness must explicitly supply CAPTAINSLOG_FRESH_POSTGRES_FIXTURE_CONFIG, a
private JSON file describing one already-created, uniquely labelled disposable
container. This test never creates a service, selects a host endpoint, or falls
back to a development database. Only its admitted container's fixed `nebulalog`
database is reset. The harness owns terminal cleanup and retains small receipts.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
import uuid

from nebulalog_manager.common import Refused
from nebulalog_manager.fresh_database import FreshPostgres, initialize_sql, probe_sql
from nebulalog_manager.image_bundle import ApplicationSchema
from nebulalog_adapters.lifecycle import Lifecycle

ENV = "CAPTAINSLOG_FRESH_POSTGRES_FIXTURE_CONFIG"
IMAGE = "sha256:66aafa11cf15800a3c94763f7e11d1e7b2e37e5e84bc4ce027cb6e1e4bfaf4df"
IMAGE_REF = "docker.io/library/postgres@" + IMAGE
LABEL = "captainslog.fixture.fresh-postgres"
FLOOR = 150 * 1024**3
LIMIT = 2 * 1024**3
# The disposable named volume is inside the verified T9-backed Docker disk.
# Production UID999 and the exact SQL administrative identity are preserved.
FIXTURE_USER = "999:999"
FIXTURE_COMMAND = ["postgres", "-c", "listen_addresses=", "-c", "max_connections=8",
                   "-c", "shared_buffers=32MB", "-c", "work_mem=1MB", "-c", "temp_file_limit=16MB",
                   "-c", "max_wal_size=64MB", "-c", "min_wal_size=32MB", "-c", "lock_timeout=5s",
                   "-c", "statement_timeout=90s", "-c", "idle_in_transaction_session_timeout=30s"]
BINDING = {"installation_id": "e16d8648-38f2-49e4-8a09-15c5ca9d5480", "source_snapshot_sha256": "a" * 64,
           "image": "local/qualification@sha256:" + "b" * 64, "schema_revision": "4",
           "schema_sha256": ApplicationSchema.schema_digest("4")}
PRODUCT_COMMAND = ["podman", "exec", "-i", "--user", "999:999", "nebulalog-postgresql",
                   "psql", "-X", "--no-password", "--host=/var/run/postgresql", "--username=postgres",
                   "--dbname=nebulalog", "--single-transaction", "--quiet", "--tuples-only", "--no-align",
                   "--set=ON_ERROR_STOP=1"]


def _run(argv, *, data=None, timeout=120):
    if argv[0] == "docker":
        argv = ["docker", "--context", "desktop-linux", *argv[1:]]
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if len(result.stdout) > 512 * 1024 or len(result.stderr) > 512 * 1024:
        raise RuntimeError("Fixture output exceeded its fixed evidence bound")
    if result.returncode:
        raise RuntimeError("Fixture command refused: " + result.stderr.decode(errors="replace")[:4096])
    return result.stdout.decode().strip()


def _private_json(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Fixture:
    def __init__(self, config):
        config = Path(config)
        if not config.is_absolute() or config.resolve() != config:
            raise RuntimeError("Fixture config must be canonical and nonsymlink")
        info = config.lstat()
        parent = config.parent.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 8192 or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700):
            raise RuntimeError("Fixture config and run directory must be private and owned")
        self.value = json.loads(config.read_bytes())
        fields = {"schema", "run_id", "container_id", "container_name", "image_id", "run_root", "volume_name", "volume_mountpoint", "volume_created_at", "data_identity"}
        v = self.value
        if (set(v) != fields or type(v["schema"]) is not int or v["schema"] != 1
                or str(uuid.UUID(v["run_id"])) != v["run_id"]
                or not re.fullmatch(r"[a-f0-9]{64}", v["container_id"])
                or v["container_name"] != "captainslog-fresh-pg-" + v["run_id"][:8]
                or v["volume_name"] != v["container_name"] + "-data"
                or v["image_id"] != IMAGE or v["run_root"] != str(config.parent)):
            raise RuntimeError("Fixture config differs from exact qualification identity")
        self.root = config.parent
        if (not str(self.root).startswith("/Volumes/T9/StellarBuilds/CaptainsLog/build-20261012/outputs/fresh-database-postgres-")
                or self.root.stat().st_dev != Path("/Volumes/T9").stat().st_dev
                or not os.path.ismount("/Volumes/T9")):
            raise RuntimeError("Fixture must be on the mounted owned T9 output root")
        endpoint = json.loads(_run(["docker", "context", "inspect", "desktop-linux"]))[0]["Endpoints"]["docker"]["Host"]
        if endpoint != "unix:///Users/stellarwayne/.docker/run/docker.sock":
            raise RuntimeError("Fixture must use the verified local Docker endpoint")
        self.guard()

    def guard(self, *, full=True):
        v = self.value
        volume = json.loads(_run(["docker", "volume", "inspect", v["volume_name"]]))[0]
        if (volume["Name"] != v["volume_name"] or volume["Driver"] != "local" or volume["Scope"] != "local"
                or volume["Mountpoint"] != v["volume_mountpoint"] or volume["CreatedAt"] != v["volume_created_at"] or volume["Options"]
                or volume["Labels"].get(LABEL) != v["run_id"]):
            raise RuntimeError("Fixture named-volume identity changed")
        image = json.loads(_run(["docker", "image", "inspect", IMAGE]))[0]
        if (image["Id"] != IMAGE or image["Architecture"] != "amd64" or image["Os"] != "linux"
                or "PG_VERSION=17.11-1.pgdg12+2" not in image["Config"]["Env"]):
            raise RuntimeError("Fixture image is not the pinned official amd64 PostgreSQL 17.11")
        current = json.loads(_run(["docker", "inspect", v["container_id"]]))[0]
        host = current["HostConfig"]
        mounts = current["Mounts"]
        bindings = {m["Destination"]: (m["Source"], m["RW"]) for m in mounts if m["Type"] == "bind"}
        # The fixed local Docker Desktop daemon exposes this host bind through
        # its /host_mnt translation. No arbitrary alternate source is accepted.
        expected = {"/run/secrets/fixture-password": ("/host_mnt" + str(self.root / "password"), False)}
        volumes = [m for m in mounts if m["Type"] == "volume"]
        if (len(volumes) != 1 or volumes[0]["Name"] != v["volume_name"] or not volumes[0]["RW"]
                or volumes[0]["Source"] != v["volume_mountpoint"]
                or volumes[0]["Destination"] != "/var/lib/postgresql/data"):
            raise RuntimeError("Fixture data volume was substituted")
        if (current["Id"] != v["container_id"] or current["Name"] != "/" + v["container_name"]
                or current["Image"] != IMAGE or current["Config"]["Labels"].get(LABEL) != v["run_id"]
                or current["Config"]["User"] != "" or current["Config"]["Cmd"] != FIXTURE_COMMAND
                or current["State"]["Running"] is not True or host["NetworkMode"] != "none"
                or host["PortBindings"] or any(current["NetworkSettings"].get("Ports", {}).values())
                or host["ReadonlyRootfs"] is not True or host["Privileged"] or host["RestartPolicy"]["Name"] != "no"
                or host["Memory"] != 384 * 1024**2 or host["NanoCpus"] != 10**9
                or host["PidsLimit"] != 64 or bindings != expected
                or any(m["Type"] not in ("bind", "tmpfs", "volume") for m in mounts)):
            raise RuntimeError("Fixture ownership, mounts, network, or resource bounds changed")
        if shutil.disk_usage(self.root).free < FLOOR:
            raise RuntimeError("Fixture refused below 150 GiB host reserve")
        receipt = {"container_id": v["container_id"], "image_id": IMAGE,
                   "free_bytes": shutil.disk_usage(self.root).free}
        if full:
            identity = _run(["docker", "exec", "--user", FIXTURE_USER, v["container_id"], "stat", "-c", "%d:%i:%u:%g:%a", "/var/lib/postgresql/data"])
            if identity != v["data_identity"] or not identity.endswith(":999:999:700"):
                raise RuntimeError("Fixture volume directory identity changed")
            attached = _run(["docker", "ps", "-aq", "--no-trunc", "--filter", "volume=" + v["volume_name"]]).splitlines()
            if attached != [v["container_id"]]:
                raise RuntimeError("Fixture volume has another container owner")
            total = int(_run(["docker", "exec", "--user", FIXTURE_USER, v["container_id"], "du", "-sb", "/var/lib/postgresql/data"]).split()[0])
            if total > LIMIT:
                raise RuntimeError("Fixture data exceeded 2 GiB bound")
            receipt["data_bytes"] = total
        return receipt

    def sql(self, sql, *, database="nebulalog", transaction=True):
        if database not in ("nebulalog", "postgres"):
            raise RuntimeError("Fixture database outside fixed test scope")
        self.guard(full=False)
        argv = ["docker", "exec", "-i", "--user", FIXTURE_USER, self.value["container_id"], "psql", "-X",
                "--no-password", "--host=/var/run/postgresql", "--username=postgres", "--dbname=" + database,
                "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1"]
        if transaction:
            argv.append("--single-transaction")
        return _run(argv, data=sql.encode())

    def command(self, argv, *, input, timeout):
        if argv != PRODUCT_COMMAND or timeout != 120 or not isinstance(input, bytes) or len(input) > 512 * 1024:
            raise RuntimeError("Unexpected product command at SQL fixture boundary")
        return self.sql(input.decode())

    def reset(self):
        self.sql("DROP DATABASE IF EXISTS nebulalog;", database="postgres", transaction=False)
        self.sql("DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='nebulalog') THEN CREATE ROLE nebulalog LOGIN; END IF; END $$;"
                 "ALTER ROLE nebulalog NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS LOGIN;", database="postgres")
        self.sql("CREATE DATABASE nebulalog OWNER nebulalog TEMPLATE template0;", database="postgres", transaction=False)

    def observed(self):
        return json.loads(self.sql(probe_sql()))

    def catalog(self):
        # Match the initializer's transaction-local visibility. PostgreSQL's
        # pg_get_indexdef/pg_get_expr text otherwise depends on search_path.
        return json.loads(self.sql("SET LOCAL search_path=pg_catalog;\n" + Lifecycle._schema_catalog("public") + ";"))


@unittest.skipUnless(os.environ.get(ENV), "explicit protected disposable PostgreSQL 17.11 fixture required")
class FreshDatabasePostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = Fixture(os.environ[ENV])
        version = cls.fixture.sql("SELECT current_setting('server_version_num');", database="postgres")
        if version != "170011":
            raise RuntimeError("Actual server is not exact PostgreSQL 17.11")

    def setUp(self):
        self.fixture.guard()
        self.fixture.reset()
        self.state = {}
        self.case = Path(tempfile.mkdtemp(prefix=self.id().rsplit(".", 1)[-1] + "-", dir=self.fixture.root))
        self.journal = self.case / "journal.json"
        self.initial_identity = self.fixture.observed()["database"]
        self.manager = FreshPostgres(self.fixture.command)

    def tearDown(self):
        _private_json(self.case / "readback.json", {"initial_database": self.initial_identity,
            "guard": self.fixture.guard(), "probe_schema_exists": self.fixture.sql(
                "SELECT EXISTS(SELECT FROM pg_namespace WHERE nspname='captainslog_fresh_probe');")})

    def checkpoint(self):
        _private_json(self.journal, self.state)

    def initialize(self):
        return self.manager.initialize(BINDING, self.state, self.checkpoint)

    def retain_intent(self):
        self.state = {"fresh_postgres": {"schema": 1, "binding": copy.deepcopy(BINDING),
                      "database": copy.deepcopy(self.initial_identity), "phase": "intent"}}
        self.checkpoint()

    def assert_no_probe(self):
        self.assertEqual(self.fixture.sql("SELECT count(*) FROM pg_namespace WHERE nspname='captainslog_fresh_probe';"), "0")

    def schema3(self):
        legacy, additive, stepup = ApplicationSchema.reviewed_sql()
        self.fixture.sql("SET LOCAL ROLE nebulalog; SET LOCAL search_path=public,pg_catalog;" + legacy + additive
                         + ApplicationSchema.reviewed_retention_sql() + stepup)

    def test_empty_to_exact_four_and_same_intent_retry(self):
        result = self.initialize()
        catalog = self.fixture.catalog()
        default_catalog = json.loads(self.fixture.sql(Lifecycle._schema_catalog("public") + ";"))
        digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        _private_json(self.case / "catalog-observer.json", {"production_sha256": result["catalog_sha256"],
            "pg_catalog_observer_sha256": digest(catalog), "default_observer_sha256": digest(default_catalog),
            "different_fields": [key for key in catalog if catalog[key] != default_catalog[key]],
            "transaction": "Both observers use actual psql --single-transaction; fixed observer sets SET LOCAL search_path=pg_catalog"})
        self.assertEqual(result["database"], self.initial_identity)
        self.assertEqual(result["catalog_sha256"], digest(catalog))
        self.assertNotEqual(digest(catalog), digest(default_catalog))
        names = {row[0] for row in catalog["relations"]}
        self.assertTrue({"host_stepup_pending", "host_stepup_pending_v2", "retention_actions"} <= names)
        self.assertTrue(all(row[3] == "nebulalog" for row in catalog["relations"]))
        self.assertEqual(self.fixture.sql("SELECT value->>'mode' FROM settings WHERE key='retention_engine';"), "uninitialized")
        self.fixture.sql("INSERT INTO audit_events(actor,action,target) VALUES('fixture','sentinel','retained');")
        self.state = json.loads(self.journal.read_bytes())
        self.assertEqual(self.initialize(), result)
        self.assertEqual(self.fixture.sql("SELECT count(*) FROM audit_events WHERE actor='fixture';"), "1")
        self.assert_no_probe()

    def test_durable_intent_before_dispatch_survives_checkpoint_ack_loss(self):
        def checkpoint():
            self.checkpoint()
            raise OSError("simulated lost durable-intent acknowledgement")
        with self.assertRaises(OSError):
            self.manager.initialize(BINDING, self.state, checkpoint)
        self.assertEqual(self.state, {})
        self.assertTrue(self.fixture.observed()["empty"])
        self.state = json.loads(self.journal.read_bytes())
        self.assertEqual(self.state["fresh_postgres"]["phase"], "intent")
        self.initialize()
        self.assertEqual(self.state["fresh_postgres"]["phase"], "complete")

    def test_lost_ack_after_actual_commit_reuses_durable_intent(self):
        def lost_ack(argv, **kwargs):
            result = self.fixture.command(argv, **kwargs)
            if b"CREATE TEMP TABLE captainslog_fresh_result" in kwargs["input"]:
                raise TimeoutError("simulated transport loss after committed actual SQL")
            return result
        with self.assertRaises(TimeoutError):
            FreshPostgres(lost_ack).initialize(BINDING, self.state, self.checkpoint)
        self.assertFalse(self.fixture.observed()["empty"])
        self.fixture.sql("INSERT INTO audit_events(actor,action,target) VALUES('fixture','sentinel','retained');")
        self.state = json.loads(self.journal.read_bytes())
        self.assertEqual(self.state["fresh_postgres"]["phase"], "intent")
        self.initialize()
        self.assertEqual(self.fixture.sql("SELECT count(*) FROM audit_events WHERE actor='fixture';"), "1")
        self.assert_no_probe()

    def test_completion_checkpoint_failure_reloads_durable_intent(self):
        def checkpoint():
            if self.state["fresh_postgres"]["phase"] == "complete":
                raise OSError("simulated completion persistence failure")
            self.checkpoint()
        with self.assertRaises(OSError):
            self.manager.initialize(BINDING, self.state, checkpoint)
        self.state = json.loads(self.journal.read_bytes())
        self.assertEqual(self.state["fresh_postgres"]["phase"], "intent")
        self.initialize()
        self.assertEqual(self.state["fresh_postgres"]["phase"], "complete")

    def test_completed_journal_cannot_rebuild_emptied_same_database(self):
        self.initialize()
        self.fixture.sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION pg_database_owner; GRANT USAGE ON SCHEMA public TO PUBLIC;")
        self.assertEqual(self.fixture.observed()["database"], self.initial_identity)
        with self.assertRaisesRegex(RuntimeError, "neither owned empty work nor exact schema 4"):
            self.initialize()
        self.assertTrue(self.fixture.observed()["empty"])
        self.assert_no_probe()

    def test_exact_four_without_intent_does_not_grant_adoption(self):
        self.initialize()
        self.state = {}
        with self.assertRaisesRegex(Refused, "empty database"):
            self.initialize()
        self.assertEqual(self.state, {})

    def test_foreign_partial_and_three_without_intent_refuse_unchanged(self):
        for kind in ("foreign", "partial", "three"):
            with self.subTest(kind=kind):
                self.fixture.reset(); self.state = {}
                if kind == "three":
                    self.schema3()
                else:
                    sql = "CREATE TABLE foreign_fixture(id integer);" if kind == "foreign" else ApplicationSchema.reviewed_sql()[0]
                    self.fixture.sql("SET LOCAL ROLE nebulalog; SET LOCAL search_path=public,pg_catalog;" + sql)
                before = self.fixture.catalog()
                with self.assertRaisesRegex(Refused, "empty database"):
                    self.initialize()
                self.assertEqual(self.fixture.catalog(), before)
                self.assertEqual(self.state, {})
                self.assert_no_probe()

    def test_retained_intent_cannot_promote_foreign_partial_or_three(self):
        for kind in ("foreign", "partial", "three"):
            with self.subTest(kind=kind):
                self.fixture.reset(); self.initial_identity = self.fixture.observed()["database"]
                self.retain_intent()
                if kind == "three":
                    self.schema3()
                else:
                    sql = "CREATE TABLE foreign_fixture(id integer);" if kind == "foreign" else ApplicationSchema.reviewed_sql()[0]
                    self.fixture.sql("SET LOCAL ROLE nebulalog; SET LOCAL search_path=public,pg_catalog;" + sql)
                before = self.fixture.catalog()
                with self.assertRaisesRegex(RuntimeError, "neither owned empty work nor exact schema 4"):
                    self.initialize()
                self.assertEqual(self.fixture.catalog(), before)
                self.assertEqual(self.state["fresh_postgres"]["phase"], "intent")
                self.assert_no_probe()

    def test_actual_database_recreation_changes_oid_and_refuses_intent(self):
        self.retain_intent()
        self.fixture.reset()
        changed = self.fixture.observed()["database"]
        self.assertNotEqual(changed["database_oid"], self.initial_identity["database_oid"])
        self.assertEqual(changed["system_identifier"], self.initial_identity["system_identifier"])
        with self.assertRaisesRegex(Refused, "differs from its retained intent"):
            self.initialize()
        self.assertTrue(self.fixture.observed()["empty"])

    def test_sql_rechecks_system_identifier_and_oid_before_any_schema_effect(self):
        for field in ("database_oid", "system_identifier"):
            with self.subTest(field=field):
                wrong = copy.deepcopy(self.initial_identity)
                wrong[field] = wrong[field] + 1 if field == "database_oid" else str(int(wrong[field]) + 1)
                with self.assertRaisesRegex(RuntimeError, "identity changed after admission"):
                    self.fixture.sql(initialize_sql(wrong))
                self.assertTrue(self.fixture.observed()["empty"])
                self.assert_no_probe()

    def test_foreign_factory_binding_cannot_execute_sql(self):
        self.retain_intent()
        calls = []
        def observed_command(*args, **kwargs):
            calls.append(True)
            return self.fixture.command(*args, **kwargs)
        manager = FreshPostgres(observed_command)
        for field, value in (("installation_id", str(uuid.uuid4())), ("source_snapshot_sha256", "c" * 64),
                             ("image", "other/image@sha256:" + "d" * 64), ("schema_revision", "3")):
            with self.subTest(field=field), self.assertRaises(Refused):
                manager.initialize({**BINDING, field: value}, self.state, self.checkpoint)
            self.assertEqual(calls, [])
            self.assertTrue(self.fixture.observed()["empty"])

    def test_actual_transaction_rolls_back_all_ddl_after_late_failure(self):
        self.retain_intent()
        with self.assertRaisesRegex(RuntimeError, "injected late transaction failure"):
            self.fixture.sql(initialize_sql(self.initial_identity) + "\nDO $$ BEGIN RAISE EXCEPTION 'injected late transaction failure'; END $$;")
        self.assertTrue(self.fixture.observed()["empty"])
        self.assert_no_probe()
        self.state = json.loads(self.journal.read_bytes())
        self.initialize()

    def test_unqualified_namespace_acl_and_role_authority_refuse_before_intent(self):
        for mutation in ("REVOKE USAGE ON SCHEMA public FROM PUBLIC;", "ALTER ROLE nebulalog CREATEDB;",
                         "ALTER DATABASE nebulalog OWNER TO postgres;", "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC;"):
            with self.subTest(mutation=mutation):
                self.fixture.reset(); self.state = {}
                self.fixture.sql(mutation)
                with self.assertRaises(RuntimeError):
                    self.initialize()
                self.assertEqual(self.state, {})
                self.assert_no_probe()

    def test_untrusted_public_function_is_never_executed(self):
        self.retain_intent()
        self.fixture.sql("SET LOCAL ROLE nebulalog; CREATE FUNCTION public.untrusted_fixture() RETURNS integer LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'untrusted body executed'; END $$;")
        with self.assertRaisesRegex(RuntimeError, "Unqualified public functions"):
            self.initialize()
        self.assertEqual(self.fixture.sql("SELECT count(*) FROM pg_proc WHERE pronamespace='public'::regnamespace;"), "1")
        self.assert_no_probe()


if __name__ == "__main__":
    unittest.main()
