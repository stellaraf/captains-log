"""Source/release schema fences; no claim of live migration or SQL acceptance."""
import copy
import hashlib
from pathlib import Path
import unittest

from nebulalog_manager.image_bundle import ApplicationSchema as schema
from nebulalog_manager.common import Refused


class ApplicationSchemaTests(unittest.TestCase):
    def test_current_source_bytes_bind_to_revision_two(self):
        root = Path(__file__).resolve().parents[2]
        files = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in (root / "migrations").rglob("*") if path.is_file()}
        self.assertEqual(schema.source_revision(files), "2")
        self.assertEqual(schema.bind_source(files, "2"), schema.schema_digest("2"))
        with self.assertRaisesRegex(Refused, "actual migration source"):
            schema.bind_source(files, "1")

    def test_missing_changed_or_extra_migration_is_not_same_schema(self):
        for mutation in ("changed", "missing", "extra", "renamed"):
            files = copy.deepcopy(schema.SCHEMAS["2"])
            if mutation == "changed": files["migrations/postgres.sql"] = "a" * 64
            if mutation == "missing": del files["migrations/host_stepup.sql"]
            if mutation == "extra": files["migrations/extra.sql"] = "b" * 64
            if mutation == "renamed": files["migrations/renamed.sql"] = files.pop("migrations/clickhouse.sql")
            with self.subTest(mutation=mutation), self.assertRaises(Refused):
                schema.bind_source(files, "2")

    def test_bridge_legacy_same_schema_remains_explicit(self):
        self.assertEqual(schema.transition({"database_migration": "none", "schema_revision": "1"}, "1"), "none")
        with self.assertRaises(Refused):
            schema.transition({"database_migration": "none", "schema_revision": "2"}, "2")

    def test_only_fixed_additive_transition_accepts_source_and_target(self):
        change = {**schema.declaration(schema.SCHEMAS["2"], "2", schema.ADDITIVE_UPGRADE), "rollback_safe": True}
        self.assertEqual(schema.transition(change, "1"), schema.ADDITIVE_UPGRADE)
        for altered, installed in (({**change, "database_migration": "none"}, "1"),
                                   ({**change, "rollback_safe": False}, "1"),
                                   ({**change, "schema_sha256": "f" * 64}, "1"), (change, "2"), (change, "3")):
            with self.subTest(change=altered, installed=installed), self.assertRaises(Refused):
                schema.transition(altered, installed)

    def test_no_implicit_downgrade_or_unknown_schema(self):
        with self.assertRaises(Refused):
            schema.transition(schema.declaration(schema.SCHEMAS["1"], "1"), "2")
        for revision in (None, 2, True, "3", {}, "2\n"):
            with self.subTest(revision=revision), self.assertRaises(Refused):
                schema.schema_digest(revision)

    def test_declaration_cannot_select_a_path_or_sql_as_migration(self):
        for migration in ("/tmp/upgrade.sql", "DROP TABLE events", {}, None):
            with self.subTest(migration=migration), self.assertRaises(Refused):
                schema.declaration(schema.SCHEMAS["2"], "2", migration)


if __name__ == "__main__":
    unittest.main()
