"""Actual PG17 initialization readbacks in the explicitly admitted disposable DB.

ClickHouse metadata and systemd status are injected only in the ready-boundary
case. This suite neither starts services nor qualifies a native Rocky appliance.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_adapters import lifecycle
from nebulalog_manager.fresh_database import FreshPostgres
from nebulalog_manager.image_bundle import ApplicationSchema
from test_fresh_database_postgres import BINDING, ENV, Fixture, _private_json

OPERATION = "a" * 64
COMMAND = ["podman", "exec", "-i", "--user", "999:999", "nebulalog-postgresql",
           "psql", "-X", "--username=postgres", "--dbname=nebulalog", "--single-transaction",
           "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1"]


@unittest.skipUnless(os.environ.get(ENV), "explicit protected disposable PostgreSQL 17.11 fixture required")
class InitializationCatalogPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = Fixture(os.environ[ENV])
        if cls.fixture.sql("SELECT current_setting('server_version_num');", database="postgres") != "170011":
            raise RuntimeError("Actual server is not exact PostgreSQL 17.11")

    def setUp(self):
        self.fixture.reset()
        self.state = {}
        self.case = Path(tempfile.mkdtemp(prefix=self.id().rsplit(".", 1)[-1] + "-", dir=self.fixture.root))
        self.calls = []

    def tearDown(self):
        _private_json(self.case / "readback.json", {"guard": self.fixture.guard(),
            "probe_count": self.fixture.sql("SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'captainslog_probe_%';"),
            "catalog": self.fixture.catalog()})

    def command(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:2] == ["systemctl", "show"]:
            return "inactive"
        if argv != COMMAND or kwargs.get("timeout") != 150 or set(kwargs) != {"timeout", "input"}:
            raise AssertionError("Unexpected initialization observer command")
        return self.fixture.sql(kwargs["input"].decode())

    def initialize(self):
        return FreshPostgres(self.fixture.command).initialize(
            BINDING, self.state, lambda: _private_json(self.case / "journal.json", self.state))

    def schema3(self):
        old, additive, stepup = ApplicationSchema.reviewed_sql()
        self.fixture.sql("SET LOCAL ROLE nebulalog; SET LOCAL search_path=public,pg_catalog;" +
                         old + additive + ApplicationSchema.reviewed_retention_sql() + stepup)

    def observe(self, revision):
        return lifecycle._observe_fixed_pg_catalog(self.command, revision, OPERATION)

    def test_fresh_four_independently_matches_initializer_catalog_and_database(self):
        initial = self.initialize()
        observed = self.observe("4")
        self.assertEqual(observed["database"], initial["database"])
        self.assertEqual(observed["catalog_sha256"], initial["catalog_sha256"])
        self.assertEqual(observed["profile"], "host-stepup-v2")

    def test_same_three_observation_preserves_restored_settings_and_policy(self):
        self.schema3()
        self.fixture.sql("INSERT INTO settings(key,value) VALUES('restored-fixture','{\"preserve\":true}'::jsonb);"
                         "UPDATE settings SET value='{\"global_days\":27,\"revision\":91}'::jsonb WHERE key='retention';")
        before = self.fixture.sql("SELECT jsonb_object_agg(key,value)::text FROM settings;")
        observed = self.observe("3")
        self.assertEqual(observed["schema_revision"], "3")
        self.assertEqual(self.fixture.sql("SELECT jsonb_object_agg(key,value)::text FROM settings;"), before)

    def test_cross_profile_observation_refuses_without_altering_database(self):
        self.schema3()
        before = self.fixture.catalog()
        with self.assertRaises(RuntimeError):
            self.observe("4")
        self.assertEqual(self.fixture.catalog(), before)
        self.fixture.reset()
        self.initialize()
        before = self.fixture.catalog()
        with self.assertRaises(RuntimeError):
            self.observe("3")
        self.assertEqual(self.fixture.catalog(), before)

    def test_foreign_namespace_or_migration_marker_is_never_adopted(self):
        self.initialize()
        self.fixture.sql("CREATE SCHEMA foreign_fixture;")
        with self.assertRaisesRegex(RuntimeError, "Unqualified fixed application database objects"):
            self.observe("4")
        self.assertEqual(self.fixture.sql("SELECT count(*) FROM pg_namespace WHERE nspname='foreign_fixture';"), "1")
        self.fixture.sql("DROP SCHEMA foreign_fixture;"
                         "INSERT INTO settings(key,value) VALUES('application_schema_migration:foreign','{}');")
        with self.assertRaisesRegex(RuntimeError, "unowned migration evidence"):
            self.observe("4")
        self.assertEqual(self.fixture.sql("SELECT count(*) FROM settings WHERE key='application_schema_migration:foreign';"), "1")

    def test_settled_pg_readback_preserves_policy_and_binds_injected_physical_table(self):
        self.initialize()
        gate = {"schema": 1, "held": True, "delivery_held": True, "operation": OPERATION}
        table = "777e3820-f194-49f8-b20c-bc3487eeebba"
        engine = {"schema": 1, "mode": "partition", "table_uuid": table}
        self.fixture.sql("UPDATE settings SET value='" + json.dumps(gate) +
            "'::jsonb WHERE key='storage_emergency_maintenance';"
            "UPDATE settings SET value='" + json.dumps(engine) + "'::jsonb WHERE key='retention_engine';")
        before = self.fixture.sql("SELECT value::text FROM settings WHERE key='retention';")
        host = self.case / "data/manager/storage-maintenance/gate.json"
        host.parent.mkdir(parents=True)
        host.write_text(json.dumps(gate))
        physical = {"uuid": table, "engine": "MergeTree", "partition_key": "(log_type, toDate(ingested_at))",
                    "create_table_query": "synthetic physical table metadata"}
        with patch.object(lifecycle, "trusted_file", side_effect=lambda p: p), \
             patch.object(lifecycle.Lifecycle, "ch", return_value=json.dumps(physical)):
            proof = lifecycle._observe_ready_application_catalog(
                self.command, "4", OPERATION, data=self.case / "data", configuration=self.case / "configuration")
        self.assertEqual(proof["retention"]["table_uuid"], table)
        self.assertEqual(proof["retention"]["ddl_sha256"], hashlib.sha256(physical["create_table_query"].encode()).hexdigest())
        self.assertEqual(self.fixture.sql("SELECT value::text FROM settings WHERE key='retention';"), before)
        self.assertEqual(json.loads(host.read_text()), gate)
