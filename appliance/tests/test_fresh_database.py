"""Protocol and generated-SQL tests; real PostgreSQL qualification is separate."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import Mock

from nebulalog_manager.common import Refused
from nebulalog_manager.fresh_database import FreshPostgres, POSTGRES_SERVER_VERSION, initialize_sql, probe_sql
from nebulalog_manager.image_bundle import ApplicationSchema
from nebulalog_adapters.lifecycle import STORAGE_LOCK

BINDING = {"installation_id": "e16d8648-38f2-49e4-8a09-15c5ca9d5480", "source_snapshot_sha256": "a" * 64,
           "image": "local/application@sha256:" + "b" * 64, "schema_revision": "4",
           "schema_sha256": ApplicationSchema.schema_digest("4")}
DATABASE = {"database": "nebulalog", "owner": "nebulalog", "system_identifier": "7418965244561873853",
            "database_oid": 16384, "server_version": 170011}
CATALOG = {**{key: [] for key in ("relations", "columns", "constraints", "indexes", "sequences",
                                "triggers", "rules", "policies", "inheritance")},
           **{key: 0 for key in ("extra_objects", "functions", "extra_types", "extensions")}}
RESULT = {"database": DATABASE, "revision": "4", "profile": "host-stepup-v2", "catalog": CATALOG}


class FreshDatabaseTests(unittest.TestCase):
    def runner(self, empty=True, result=None):
        return Mock(side_effect=[json.dumps({"database": DATABASE, "empty": empty}), json.dumps(result or RESULT)])

    def prior(self, phase="intent"):
        return {"fresh_postgres": {"schema": 1, "binding": copy.deepcopy(BINDING), "database": copy.deepcopy(DATABASE), "phase": phase}}

    def test_intent_is_durable_before_any_initialization_and_receipt_before_complete(self):
        state, checkpoints, events = {}, [], []
        def checkpoint():
            checkpoints.append(copy.deepcopy(state)); events.append("checkpoint:" + state["fresh_postgres"]["phase"])
        def command(argv, **kwargs):
            self.assertIn("--single-transaction", argv)
            self.assertIn("--host=/var/run/postgresql", argv)
            self.assertNotIn("--command", argv)
            if not events:
                events.append("probe")
                return json.dumps({"database": DATABASE, "empty": True})
            self.assertEqual(events[-1], "checkpoint:intent")
            events.append("initialize")
            return json.dumps(RESULT)
        result = FreshPostgres(command).initialize(BINDING, state, checkpoint)
        self.assertEqual(events, ["probe", "checkpoint:intent", "initialize", "checkpoint:complete"])
        self.assertEqual([c["fresh_postgres"]["phase"] for c in checkpoints], ["intent", "complete"])
        self.assertEqual(result["revision"], "4")
        self.assertEqual(len(result["catalog_sha256"]), 64)

    def test_missing_intent_cannot_adopt_any_existing_database(self):
        runner, state = self.runner(empty=False), {}
        with self.assertRaisesRegex(Refused, "empty database"):
            FreshPostgres(runner).initialize(BINDING, state, Mock())
        self.assertEqual(state, {})
        self.assertEqual(runner.call_count, 1)

    def test_failed_initial_checkpoint_cannot_dispatch_sql_or_mint_memory_authority(self):
        runner, state = self.runner(), {}
        with self.assertRaises(OSError):
            FreshPostgres(runner).initialize(BINDING, state, Mock(side_effect=OSError("fsync")))
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(state, {})

    def test_lost_commit_ack_retains_exact_intent_then_reads_back(self):
        runner, state = self.runner(), {}
        runner.side_effect = [json.dumps({"database": DATABASE, "empty": True}), TimeoutError("unobserved commit")]
        with self.assertRaises(TimeoutError):
            FreshPostgres(runner).initialize(BINDING, state, Mock())
        self.assertEqual(state, self.prior())
        retry = self.runner(empty=False)
        FreshPostgres(retry).initialize(BINDING, state, Mock())
        self.assertEqual(state, self.prior("complete"))

    def test_checkpoint_cannot_substitute_admission(self):
        runner, state = self.runner(), {}
        def checkpoint():
            state["fresh_postgres"]["database"]["database_oid"] = 999
        with self.assertRaisesRegex(Refused, "checkpoint changed"):
            FreshPostgres(runner).initialize(BINDING, state, checkpoint)
        self.assertEqual(runner.call_count, 1)

    def test_completed_retry_cannot_recreate_a_database_with_same_oid(self):
        runner = self.runner(empty=False)
        state = self.prior("complete")
        FreshPostgres(runner).initialize(BINDING, state, Mock())
        sql = runner.call_args.kwargs["input"].decode()
        self.assertIn("IF actual=empty_catalog AND NOT true THEN", sql)

    def test_changed_factory_binding_or_database_identity_refuses(self):
        for field, value in (("source_snapshot_sha256", "c" * 64), ("image", "other/app@sha256:" + "c" * 64),
                             ("installation_id", "e16d8648-38f2-49e4-8a09-15c5ca9d5481")):
            with self.subTest(field=field):
                state, runner = self.prior(), self.runner()
                with self.assertRaises(Refused):
                    FreshPostgres(runner).initialize({**BINDING, field: value}, state, Mock())
                runner.assert_not_called()
        for field, value in (("database_oid", 16385), ("system_identifier", "7418965244561873854")):
            with self.subTest(field=field):
                state, runner = self.prior(), self.runner()
                runner.side_effect = [json.dumps({"database": {**DATABASE, field: value}, "empty": False})]
                with self.assertRaises(Refused):
                    FreshPostgres(runner).initialize(BINDING, state, Mock())
                self.assertEqual(runner.call_count, 1)

    def test_malformed_or_legacy_authority_refuses_before_probe(self):
        for field, value in (("installation_id", "' malicious"), ("installation_id", "00000000-0000-0000-0000-000000000000"),
                             ("schema_revision", "3"), ("schema_sha256", "f" * 64), ("image", "app:latest"),
                             ("source_snapshot_sha256", True)):
            with self.subTest(field=field):
                runner = Mock()
                with self.assertRaises(Refused):
                    FreshPostgres(runner).initialize({**BINDING, field: value}, {}, Mock())
                runner.assert_not_called()
        for value in (None, {}, {**self.prior()["fresh_postgres"], "phase": "unknown"},
                      {**self.prior()["fresh_postgres"], "schema": True}):
            runner = Mock()
            with self.subTest(value=value), self.assertRaises(Refused):
                FreshPostgres(runner).initialize(BINDING, {"fresh_postgres": value}, Mock())
            runner.assert_not_called()

    def test_malformed_database_probe_does_not_create_intent(self):
        for database in ({**DATABASE, "database_oid": True}, {**DATABASE, "server_version": 170006},
                         {**DATABASE, "server_version": 170012},
                         {**DATABASE, "owner": "postgres"}, {**DATABASE, "system_identifier": "1;DROP"}):
            state = {}
            runner = Mock(return_value=json.dumps({"database": database, "empty": True}))
            with self.subTest(database=database), self.assertRaises(Refused):
                FreshPostgres(runner).initialize(BINDING, state, Mock())
            self.assertEqual(state, {})

    def test_wrong_completion_remains_intent(self):
        for result in ({**RESULT, "revision": "3"}, {**RESULT, "profile": "host-stepup"},
                       {**RESULT, "database": {**DATABASE, "database_oid": 42}},
                       {**RESULT, "catalog": {}}, {**RESULT, "catalog": {**CATALOG, "functions": 1}}):
            state = {}
            with self.subTest(result=result), self.assertRaises(Refused):
                FreshPostgres(self.runner(result=result)).initialize(BINDING, state, Mock())
            self.assertEqual(state, self.prior())

    def test_sql_is_fixed_atomic_owner_scoped_and_compares_before_completion(self):
        sql = initialize_sql(DATABASE)
        self.assertIn("pg_advisory_xact_lock(" + str(STORAGE_LOCK) + ")", sql)
        self.assertIn("SET LOCAL ROLE nebulalog", sql)
        self.assertIn("IF actual=empty_catalog AND NOT false THEN", sql)
        self.assertLess(sql.index("Factory database identity changed"), sql.index("CREATE SCHEMA"))
        self.assertLess(sql.index("pg_event_trigger"), sql.index("CREATE SCHEMA"))
        self.assertLess(sql.index("actual IS DISTINCT FROM expected"), sql.index("INSERT INTO pg_temp"))
        legacy, additive, stepup = ApplicationSchema.reviewed_sql()
        fixed = legacy + additive + ApplicationSchema.reviewed_retention_sql() + stepup + ApplicationSchema.reviewed_host_stepup_v2_sql()
        self.assertEqual(sql.count(fixed.encode().hex()), 2)
        self.assertNotIn("application_schema_migration:", sql)
        self.assertNotIn("CREATE SCHEMA", probe_sql())
        self.assertNotIn("__STORAGE_LOCK__", sql)

    def test_fixed_version_matches_all_production_postgresql_rpm_pins(self):
        root = Path(__file__).resolve().parents[1] / "images" / "postgresql-fips"
        bom = json.loads((root / "BOM.json").read_text())
        containerfile = (root / "Containerfile").read_text()
        self.assertEqual(POSTGRES_SERVER_VERSION, 170011)
        self.assertEqual(bom["postgresql_version"], "17.11-1PGDG.rhel9.8")
        pins = [rpm for rpm in bom["rpms"] if rpm["name"].startswith("postgresql17")]
        self.assertEqual(len(pins), 3)
        for rpm in pins:
            self.assertIn("-17.11-1PGDG.rhel9.8.x86_64.rpm", rpm["name"])
            self.assertIn(rpm["url"], containerfile)
            self.assertIn(rpm["sha256"], containerfile)
        self.assertIn("server_version_num')<>'170011'", probe_sql())
        self.assertNotIn("__POSTGRES_SERVER_VERSION__", initialize_sql(DATABASE))


if __name__ == "__main__":
    unittest.main()
