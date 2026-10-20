"""Initialization readback boundaries with injected database/host transports.

The payloads below are synthetic catalog responses. These tests verify the
coordinator boundary; actual catalog SQL still requires the isolated PG17 suite.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_adapters import lifecycle
from nebulalog_manager.common import Refused
from nebulalog_manager.image_bundle import ApplicationSchema


OPERATION = "a" * 64
TABLE_UUID = "11111111-2222-4333-8444-555555555555"


def catalog():
    return {
        **{key: [] for key in ("relations", "columns", "constraints", "indexes",
                              "sequences", "triggers", "rules", "policies", "inheritance")},
        **{key: 0 for key in ("extra_objects", "functions", "extra_types", "extensions")},
    }


def structure(revision):
    return {
        "revision": revision, "profile": "host-stepup-v2" if revision == "4" else "host-stepup",
        "catalog": catalog(),
        "database": {"system_identifier": "7654321098765432101", "database_oid": 16384,
                     "database": "nebulalog", "owner": "nebulalog", "server_version": 170011},
    }


class StructuralObservationTests(unittest.TestCase):
    def observe(self, value, revision="4"):
        command = Mock(return_value=json.dumps(value))
        proof = lifecycle._observe_fixed_pg_catalog(command, revision, OPERATION)
        self.assertEqual(command.call_count, 1)
        argv = command.call_args.args[0]
        self.assertEqual(argv[:6], ["podman", "exec", "-i", "--user", "999:999", "nebulalog-postgresql"])
        self.assertIn("--single-transaction", argv)
        self.assertIn("--set=ON_ERROR_STOP=1", argv)
        self.assertEqual(command.call_args.kwargs["timeout"], 150)
        return proof

    def test_each_fixed_profile_binds_database_and_catalog(self):
        for revision in ("3", "4"):
            with self.subTest(revision=revision):
                value = structure(revision)
                proof = self.observe(value, revision)
                self.assertEqual(proof["schema_revision"], revision)
                self.assertEqual(proof["schema_sha256"], ApplicationSchema.schema_digest(revision))
                self.assertEqual(proof["database"], value["database"])
                self.assertEqual(proof["profile"], value["profile"])
                self.assertEqual(proof["catalog_sha256"], lifecycle._fixed_catalog_digest(value["catalog"]))

    def test_unknown_revision_and_operation_refuse_before_transport(self):
        command = Mock(side_effect=AssertionError("unexpected transport"))
        for revision in ("1", "2", "5", 4, [], None):
            with self.subTest(revision=revision), self.assertRaises(Refused):
                lifecycle._observe_fixed_pg_catalog(command, revision, OPERATION)
        for operation in ("", "a" * 63, "A" * 64, OPERATION + "\n", None):
            with self.subTest(operation=operation), self.assertRaises(Refused):
                lifecycle._observe_fixed_pg_catalog(command, "4", operation)
        command.assert_not_called()

    def test_cross_profile_and_unknown_result_fields_refuse(self):
        original = structure("4")
        for field, value in (("revision", "3"), ("profile", "host-stepup"), ("extra", 1)):
            with self.subTest(field=field), self.assertRaises(Refused):
                self.observe({**original, field: value})

    def test_wrong_database_identity_and_boolean_integer_values_refuse(self):
        for field, value in (
            ("system_identifier", "0"), ("system_identifier", 7654321098765432101),
            ("database_oid", True), ("database_oid", 0), ("database_oid", 2**32),
            ("database", "postgres"), ("owner", "postgres"),
            ("server_version", True), ("server_version", 160011), ("unexpected", 1),
        ):
            observed = structure("4")
            observed["database"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Refused):
                self.observe(observed)

    def test_unrecognized_catalog_and_nonzero_counters_refuse(self):
        for field, value in (("relations", {}), ("functions", 1), ("extensions", True),
                             ("extra_objects", -1), ("unexpected", [])):
            observed = structure("4")
            observed["catalog"][field] = value
            with self.subTest(field=field), self.assertRaises(Refused):
                self.observe(observed)

    def test_oversized_or_duplicate_json_is_not_catalog_evidence(self):
        for raw in ("x" * (256 * 1024 + 1), "", '{"revision":"4","revision":"3"}'):
            with self.subTest(length=len(raw)), self.assertRaises(Refused):
                lifecycle._observe_fixed_pg_catalog(Mock(return_value=raw), "4", OPERATION)


class ReadyObservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.gate = self.root / "manager/storage-maintenance/gate.json"
        self.gate.parent.mkdir(parents=True)
        self.hold = {"schema": 1, "held": True, "delivery_held": True, "operation": OPERATION}
        self.gate.write_text(json.dumps(self.hold))
        self.structure = structure("4")
        self.settled = {key: copy.deepcopy(self.structure[key]) for key in ("revision", "profile", "catalog")}
        self.settled.update(marker=None, markers=[])
        self.engine = {"schema": 1, "mode": "partition", "table_uuid": TABLE_UUID}
        self.physical = {"uuid": TABLE_UUID, "engine": "MergeTree",
            "partition_key": "(log_type, toDate(ingested_at))",
            "create_table_query": "CREATE TABLE nebulalog.events ENGINE = MergeTree PARTITION BY (log_type, toDate(ingested_at))"}
        self.service = "inactive"
        self.calls = []
        self.responses = None
        trusted = patch.object(lifecycle, "trusted_file", side_effect=lambda path: path)
        trusted.start()
        self.addCleanup(trusted.stop)

    def command(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:2] == ["systemctl", "show"]:
            return self.service
        if "psql" in argv:
            return json.dumps(next(self.responses))
        if "clickhouse-client" in argv:
            self.assertIn("show_table_uuid_in_table_create_query_if_not_nil=0", argv[argv.index("--query") + 1])
            return json.dumps(self.physical)
        self.fail("Unexpected native effect: " + repr(argv))

    def observe(self, responses=None):
        self.responses = iter(responses or (self.structure, self.settled, self.engine, self.engine))
        return lifecycle._observe_ready_application_catalog(
            self.command, "4", OPERATION, data=self.root, configuration=self.root / "configuration")

    def test_settled_readback_binds_raw_ddl_and_preserves_hold(self):
        before = self.gate.read_bytes()
        result = self.observe()
        self.assertEqual(result["markers"], [])
        self.assertEqual(result["retention"], {
            "table_uuid": TABLE_UUID, "mode": "partition", "ttl": False,
            "ddl_sha256": hashlib.sha256(self.physical["create_table_query"].encode()).hexdigest(),
        })
        self.assertEqual(self.gate.read_bytes(), before)
        self.assertEqual(sum(argv[:2] == ["systemctl", "show"] for argv, _ in self.calls), 6)
        self.assertFalse(any(argv[:2] in (["systemctl", "start"], ["systemctl", "stop"], ["podman", "run"])
                             for argv, _ in self.calls))

    def test_foreign_host_hold_refuses_before_database_reads(self):
        self.gate.write_text(json.dumps({**self.hold, "operation": "b" * 64}))
        with self.assertRaises(Refused):
            self.observe()
        self.assertEqual(self.calls, [])

    def test_live_writer_refuses_before_database_reads(self):
        self.service = "active"
        with self.assertRaises(Refused):
            self.observe()
        self.assertTrue(self.calls)
        self.assertTrue(all(argv[:2] == ["systemctl", "show"] for argv, _ in self.calls))

    def test_settled_catalog_change_and_migration_markers_refuse(self):
        original = copy.deepcopy(self.settled)
        for field, value in (("catalog", {**catalog(), "relations": ["changed"]}),
                             ("marker", {"foreign": True}), ("markers", ["foreign"])):
            self.settled = {**original, field: value}
            with self.subTest(field=field), self.assertRaises(Refused):
                self.observe()
            self.assertEqual(json.loads(self.gate.read_text()), self.hold)

    def test_physical_uuid_or_ttl_change_refuses_and_preserves_hold(self):
        original = copy.deepcopy(self.physical)
        for field, value in (("uuid", "22222222-2222-4333-8444-555555555555"),
                             ("create_table_query", original["create_table_query"] + " TTL now()")):
            self.physical = {**original, field: value}
            with self.subTest(field=field), self.assertRaises(Refused):
                self.observe()
            self.assertEqual(json.loads(self.gate.read_text()), self.hold)

    def test_engine_change_during_physical_readback_refuses(self):
        with self.assertRaises(Refused):
            self.observe((self.structure, self.settled, self.engine,
                          {**self.engine, "table_uuid": "22222222-2222-4333-8444-555555555555"}))
        self.assertEqual(json.loads(self.gate.read_text()), self.hold)
