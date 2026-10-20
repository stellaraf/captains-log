"""Connected schema4 orchestration with inert native boundaries and real journals.

Root ownership/host tools are fixture adapters only. These tests do not claim
native service, FIPS or database qualification.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import bootstrap, fresh_database
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.firstboot import Locations, RUNTIME_CHECKS
from nebulalog_manager.image_bundle import ApplicationSchema
from nebulalog_adapters import lifecycle
from test_bootstrap import SETUP, RUNTIME


class ConnectedFreshTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.paths = Locations(self.root / "etc", self.root / "data", self.root / "run")
        self.paths.etc.mkdir()
        self.calls = []
        gate = SimpleNamespace(gate=lambda: {"host_ready": True, "setup_complete": False, "installation_id": SETUP["installation_id"]})
        self.b = bootstrap.Bootstrap(self.paths, runner=self.command, firstboot=gate)
        self.b.bootstrap.mkdir(parents=True)
        self.b.systemd = self.root / "systemd"
        self.b.systemd.mkdir()
        self.b.setup, self.b.runtime = copy.deepcopy(SETUP), copy.deepcopy(RUNTIME)
        self.b.state = {"schema": 1, "installation_id": SETUP["installation_id"], "completed": []}
        self.pins = {name: "fixture/" + name.lower() + "@sha256:" + "a" * 64 for name in bootstrap.IMAGES}
        self.binding = {"schema": 1, "installation_id": SETUP["installation_id"], "initial_release_sha256": "b" * 64,
            "source_snapshot_sha256": "c" * 64, "schema_revision": "4", "schema_sha256": ApplicationSchema.schema_digest("4"),
            "bundle_manifest_sha256": "d" * 64, "host": {"generation": "e" * 64}, "host_catalog_sha256": "f" * 64, "images": self.pins}
        self.factory = {"binding": self.binding, "bundle": {"images": {k: {"config_digest": "sha256:" + "a" * 64} for k in self.pins}}}
        self.enrollment = Mock()
        self.enrollment.verify_initialization_inputs.side_effect = lambda: copy.deepcopy(self.factory)
        self.enrollment._container.return_value = "a" * 64
        self.enrollment._version.side_effect = lambda component: "17.11" if component == "postgresql" else "25.3.8.30001.altinityfips"
        for change in (patch.object(self.b, "_enrollment", return_value=self.enrollment),
                patch.object(self.b, "_read", side_effect=lambda p: json.loads(p.read_text())),
                patch("nebulalog_manager.update_enrollment._tree"),
                patch.object(bootstrap, "trusted_file", side_effect=lambda p: Path(p)),
                patch.object(bootstrap, "_private_file", side_effect=lambda p, **kw: Path(p).read_bytes())):
            change.start(); self.addCleanup(change.stop)
        self.database = {"system_identifier": "123456789", "database_oid": 16384, "database": "nebulalog", "owner": "nebulalog", "server_version": 170011}
        self.canonical = "CREATE TABLE nebulalog.events (fixture String) ENGINE = MergeTree"
        self.pg_proof = {"revision": "4", "database": self.database, "catalog_sha256": "9" * 64}
        self.ch_started = "2026-10-20T01:00:00Z"
        self.existing_table = "0"
        self.lost_storage_ack = False

    def admit(self):
        self.b._factory_inputs()
        self.assertEqual(json.loads(self.b.state_path.read_text())["factory_binding"], self.binding)

    def command(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:3] == ["systemctl", "show", "--property=ActiveState"]:
            return "inactive"
        if argv[:3] == ["podman", "container", "inspect"]:
            return json.dumps([{"State": {"Running": True, "Paused": False, "Restarting": False, "StartedAt": self.ch_started}, "RestartCount": 0}])
        if argv[-1:] == ["initialize-storage"]:
            journal = json.loads(self.b.state_path.read_text())["fresh_storage"]
            self.assertEqual(journal["phase"], "intent")
            self.assertTrue(journal["absent_observed"])
            self.assertNotIn("migrate", argv)
            self.assertIn("STORAGE_INITIALIZATION_TABLE_UUID=" + journal["table_uuid"], argv)
            if self.lost_storage_ack:
                raise TimeoutError("isolated lost acknowledgement")
            return json.dumps({key: journal[key] for key in ("operation", "table_uuid", "schema_sql_sha256", "database_query_id", "table_query_id")} | {
                "schema": 1, "state": "initialized", "ddl_sha256": hashlib.sha256(self.canonical.encode()).hexdigest(), "retention_policy_sha256": "8" * 64})
        return ""

    def initialize(self, binding, state, checkpoint):
        expected = {key: self.binding[key] for key in ("installation_id", "source_snapshot_sha256", "schema_revision", "schema_sha256")}
        expected["image"] = self.pins["NEBULALOG_IMAGE"]
        self.assertEqual(binding, expected)
        state["fresh_postgres"] = {"schema": 1, "binding": binding, "database": self.database, "phase": "intent"}
        checkpoint()
        state["fresh_postgres"]["phase"] = "complete"
        checkpoint()
        return copy.deepcopy(self.pg_proof)

    def ready(self, commands, revision, operation, **kwargs):
        self.assertEqual(revision, "4")
        self.assertEqual(operation, self.b.state["operation"])
        storage = self.b.state["fresh_storage"]
        return {"schema_revision": "4", "schema_sha256": self.binding["schema_sha256"], "profile": "host-stepup-v2",
            "catalog_sha256": self.pg_proof["catalog_sha256"], "database": self.database, "markers": [],
            "retention": {"mode": "partition", "ttl": False, "table_uuid": storage["table_uuid"], "ddl_sha256": hashlib.sha256(self.canonical.encode()).hexdigest()}}

    def ch(self, sql):
        if "SELECT count()" in sql:
            return self.existing_table
        if "formatQuerySingleLine" in sql:
            return self.canonical
        raise AssertionError(sql)

    def pg(self, sql):
        return json.dumps({"operation": self.b.state["operation"], "table_uuid": self.b.state["fresh_storage"]["table_uuid"]})

    def schema_context(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.object(fresh_database.FreshPostgres, "initialize", side_effect=self.initialize))
        stack.enter_context(patch.object(self.b, "_storage_hold"))
        stack.enter_context(patch.object(self.b, "_fresh_policy"))
        stack.enter_context(patch.object(self.b, "_fresh_ch", side_effect=self.ch))
        stack.enter_context(patch.object(self.b, "_fresh_pg", side_effect=self.pg))
        stack.enter_context(patch.object(lifecycle, "_observe_ready_application_catalog", side_effect=self.ready))
        return stack

    def test_factory_identity_persisted_before_any_native_effect_and_changed_binding_refuses(self):
        self.admit()
        self.assertEqual(self.calls, [])
        self.factory["binding"]["source_snapshot_sha256"] = "0" * 64
        with self.assertRaisesRegex(Refused, "factory identity"):
            self.b._factory_inputs()
        self.assertEqual(self.calls, [])

    def test_missing_factory_proof_and_unowned_data_refuse_without_adoption(self):
        self.enrollment.verify_initialization_inputs.side_effect = Refused("missing measured proof")
        with self.assertRaises(Refused): self.b._factory_inputs()
        self.assertFalse(self.b.state_path.exists())
        self.enrollment.verify_initialization_inputs.side_effect = lambda: self.factory
        (self.paths.data / "postgresql").mkdir()
        (self.paths.data / "postgresql/PG_VERSION").write_text("17")
        with self.assertRaisesRegex(Refused, "unowned"):
            self.b._factory_inputs()
        self.assertFalse(self.b.state_path.exists())

    def test_fences_are_persistent_before_quadlets_and_foreign_fence_is_preserved(self):
        self.admit()
        self.b._hold_listeners()
        for name in bootstrap.LISTENERS:
            path = self.b.systemd / ("nebulalog-" + name + ".service.d/80-nebulalog-bootstrap.conf")
            phase = "identity" if name == "keycloak" else "listeners"
            self.assertIn(str(self.b.bootstrap / (phase + "-ready.json")), path.read_text())
        self.assertFalse(list(self.b.bootstrap.glob("*-ready.json")))
        path.write_text("foreign")
        with self.assertRaisesRegex(Refused, "another operation"): self.b._listener_fence()
        self.assertEqual(path.read_text(), "foreign")

    def test_foreign_token_is_not_unlinked_and_listener_stop_requires_positive_readback(self):
        self.admit()
        path = self.b.bootstrap / "identity-ready.json"
        atomic_json(path, {**self.b._token_proof("identity"), "operation": "0" * 64})
        with self.assertRaisesRegex(Refused, "token differs"): self.b._hold_listeners()
        self.assertTrue(path.exists())
        path.unlink()
        with patch.object(self.b, "runner", return_value="active"), self.assertRaisesRegex(Refused, "did not stop"):
            self.b._hold_listeners()

    def test_real_journal_connects_pg_storage_and_independent_observer(self):
        self.admit()
        with self.schema_context(): self.b._fresh_schema()
        state = json.loads(self.b.state_path.read_text())
        self.assertEqual(state["fresh_postgres"]["phase"], "complete")
        self.assertEqual(state["fresh_storage"]["phase"], "initialized")
        self.assertEqual(state["schema_proof"]["database"], self.database)
        self.assertEqual(state["schema_proof"]["retention"]["ddl_sha256"], state["fresh_storage"]["result"]["ddl_sha256"])
        self.assertEqual(sum(argv[-1:] == ["initialize-storage"] for argv, _ in self.calls), 1)

    def test_lost_storage_ack_retains_exact_uuid_and_retry_never_adopts_other_table(self):
        self.admit(); self.lost_storage_ack = True
        with self.schema_context(), self.assertRaises(TimeoutError): self.b._fresh_schema()
        intent = copy.deepcopy(json.loads(self.b.state_path.read_text())["fresh_storage"])
        self.assertEqual(intent["phase"], "intent")
        self.b.state = json.loads(self.b.state_path.read_text())
        self.lost_storage_ack = False
        with self.schema_context(): self.b._fresh_schema()
        self.assertEqual(self.b.state["fresh_storage"]["table_uuid"], intent["table_uuid"])
        self.assertEqual(self.b.state["fresh_storage"]["table_query_id"], intent["table_query_id"])
        self.assertEqual(self.b.state["fresh_storage"]["phase"], "initialized")

    def test_existing_ch_table_without_intent_and_changed_instance_refuse(self):
        self.admit(); self.existing_table = "1"
        with self.schema_context(), self.assertRaisesRegex(Refused, "unowned existing"): self.b._fresh_schema()
        self.assertFalse(any(argv[-1:] == ["initialize-storage"] for argv, _ in self.calls))
        self.existing_table = "0"; self.lost_storage_ack = True
        with self.schema_context(), self.assertRaises(TimeoutError): self.b._fresh_schema()
        self.ch_started = "2026-10-21T01:00:00Z"
        with self.schema_context(), self.assertRaisesRegex(Refused, "server or retained intent"): self.b._fresh_schema()

    def test_independent_catalog_or_engine_disagreement_prevents_ready_proof(self):
        self.admit()
        with self.schema_context(), patch.object(lifecycle, "_observe_ready_application_catalog", side_effect=Refused("structural mismatch")), self.assertRaises(Refused):
            self.b._fresh_schema()
        self.assertNotIn("schema_proof", self.b.state)
        self.assertFalse(list(self.b.bootstrap.glob("*-ready.json")))

    def test_completed_schema_reobserves_without_pg_initializer_or_storage_dispatch(self):
        self.admit()
        with self.schema_context(): self.b._fresh_schema()
        self.b.state["completed"].append("migrations")
        count = len(self.calls)
        with self.schema_context(), patch.object(fresh_database.FreshPostgres, "initialize", side_effect=AssertionError("DDL replay")):
            self.b._fresh_schema()
        self.assertFalse(any(argv[-1:] == ["initialize-storage"] for argv, _ in self.calls[count:]))

    def test_policy_uses_owned_transaction_marker_not_repeated_unconditional_update(self):
        self.admit()
        observed = []
        with patch.object(self.b, "_fresh_pg", side_effect=lambda sql: observed.append(sql) or "fresh-policy-bound"):
            self.b._fresh_policy(); self.b._fresh_policy()
        self.assertEqual(observed[0], observed[1])
        self.assertIn("IF prior IS NULL THEN", observed[0])
        self.assertIn("pg_advisory_xact_lock", observed[0])
        self.assertIn("bootstrap_retention:" + self.b.state["operation"], observed[0])
        self.assertIn("retention_policy_intent", json.loads(self.b.state_path.read_text()))

    def test_prepare_completed_state_only_verifies_without_stages_or_new_secrets(self):
        from nebulalog_manager.aide import RUNTIME_STAGES
        self.admit(); self.b.state.update(completed=sorted(RUNTIME_STAGES), active_stage=None)
        expected = {"checks": {key: True for key in RUNTIME_CHECKS}}
        with patch.object(self.b, "_load"), patch.object(self.b, "_schema_revision", return_value="4"), \
             patch.object(self.b, "_verify_prepared", return_value=expected) as verify, \
             patch.object(self.b, "_stage", side_effect=AssertionError("completed effect")), \
             patch.object(self.b, "_hold_listeners", side_effect=AssertionError("completed stop")):
            self.assertEqual(self.b.prepare(self.b.bootstrap / "setup.json", self.b.bootstrap / "secrets.json"), expected)
        verify.assert_called_once()

    def test_prepare_order_releases_identity_only_after_schema_and_holds_on_failure(self):
        self.admit(); order=[]
        def stage(name, action):
            order.append(name)
            if name == "migrations":
                self.assertFalse((self.b.bootstrap / "identity-ready.json").exists())
                raise Refused("fixed catalog failure")
            self.b.state["completed"].append(name)
        with patch.object(self.b, "_load"), patch.object(self.b, "_schema_revision", return_value="4"), \
             patch.object(self.b, "_stage", side_effect=stage), patch.object(self.b, "_hold_listeners") as hold:
            with self.assertRaisesRegex(Refused, "fixed catalog"):
                self.b.prepare(self.b.bootstrap / "setup.json", self.b.bootstrap / "secrets.json")
        self.assertEqual(hold.call_count,2)
        self.assertNotIn("identity",order)
        self.assertNotIn("edge",order)
        self.assertTrue(self.b.state["failure_fence"]["stopped"])

    def test_dependency_version_mismatch_precedes_role_creation(self):
        self.admit()
        self.b.secret={"postgresql_app":"a"*64,"postgresql_keycloak":"b"*64}
        self.enrollment._version.return_value="17.6"
        self.enrollment._version.side_effect=None
        with self.assertRaisesRegex(Refused,"fixed version"): self.b._postgres()
        self.assertFalse(any("CREATE ROLE" in kw.get("input",b"").decode() for _,kw in self.calls))

    def test_clickhouse_dependency_accepts_the_packaged_vendor_version(self):
        self.admit()
        bom = json.loads((Path(__file__).resolve().parents[1] / "images/clickhouse/BOM.json").read_text())
        vendor_version = next(c["version"] for c in bom["components"] if c["name"] == "Altinity ClickHouse")
        self.enrollment._version.side_effect = None
        self.enrollment._version.return_value = vendor_version
        self.assertEqual(self.b._dependency("clickhouse")["version"], vendor_version)

    def test_standard_clickhouse_version_cannot_substitute_for_packaged_fips_build(self):
        self.admit()
        self.enrollment._version.side_effect = None
        self.enrollment._version.return_value = "25.3.9.100.altinitystable"
        with self.assertRaisesRegex(Refused, "fixed version"):
            self.b._dependency("clickhouse")

    def test_query_uuid_matches_fixed_domain_and_phase_separation(self):
        operation="a"*64
        ids=[bootstrap._storage_query_id(operation,phase) for phase in ("database","table")]
        self.assertNotEqual(*ids)
        import uuid
        for value in ids: self.assertEqual(str(uuid.UUID(value)),value)
