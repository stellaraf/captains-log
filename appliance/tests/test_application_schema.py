"""Source/release schema fences; no claim of live migration or SQL acceptance."""
import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from nebulalog_manager.image_bundle import ApplicationSchema as schema
from nebulalog_manager.common import Refused


class ApplicationSchemaTests(unittest.TestCase):
    def test_historical_schema_identities_are_unchanged(self):
        self.assertEqual({revision: schema.SCHEMAS[revision] for revision in ("1", "2", "3")}, {
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
        })
        self.assertEqual(schema.CURRENT_REVISION, "3")
        self.assertEqual(schema.HOST_CHALLENGE_REVISION, "4")

    def test_host_challenge_migration_cannot_impersonate_revision_three(self):
        root = Path(__file__).resolve().parents[2]
        files = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in (root / "migrations").rglob("*") if path.is_file()}
        # Recognition of the exact new source is separate from qualification
        # of an image, factory initializer, migration or rollback.
        self.assertIn("migrations/host_stepup_v2.sql", files)
        old = {name: value for name, value in files.items() if name != "migrations/host_stepup_v2.sql"}
        self.assertEqual(old, schema.SCHEMAS["3"])
        self.assertEqual(schema.source_revision(old), "3")
        self.assertEqual(schema.bind_source(old, "3"), schema.schema_digest("3"))
        self.assertEqual(files, schema.SCHEMAS["4"])
        self.assertEqual(schema.source_revision(files), "4")
        self.assertEqual(schema.bind_source(files, "4"),
                         "aa1cde39f32000e161af4d5deb13985c4917089bc6964b422591bfe36137b53f")
        for revision in ("1", "2", "3"):
            with self.subTest(revision=revision), self.assertRaisesRegex(Refused, "Declared application schema revision differs"):
                schema.bind_source(files, revision)
        with self.assertRaises(Refused):
            schema.bind_source(old, "4")

    def test_reviewed_v2_sql_has_separate_exact_identity_and_keeps_legacy_tuple(self):
        root = Path(__file__).resolve().parents[2]
        reviewed = schema.reviewed_sql()
        self.assertIsInstance(reviewed, tuple)
        self.assertEqual(len(reviewed), 3)
        self.assertEqual(reviewed[2].encode(), (root / "migrations/host_stepup.sql").read_bytes())
        self.assertEqual(schema.reviewed_host_stepup_v2_sql().encode(),
                         (root / "migrations/host_stepup_v2.sql").read_bytes())
        self.assertNotIn("host_stepup_pending_v2", reviewed[2])
        for body in (schema.HOST_STEPUP_V2_SQL + "\n", schema.HOST_STEPUP_V2_SQL.replace("record_schema = 2", "record_schema = 1")):
            with self.subTest(body_changed=True), patch.object(schema, "HOST_STEPUP_V2_SQL", body):
                with self.assertRaisesRegex(Refused, "host challenge SQL differs"):
                    schema.reviewed_host_stepup_v2_sql()
                self.assertEqual(schema.reviewed_sql(), reviewed)
        self.assertEqual(schema.SCHEMAS["4"]["migrations/postgres.sql"], schema.SCHEMAS["3"]["migrations/postgres.sql"])
        self.assertEqual(schema.SCHEMAS["4"]["migrations/clickhouse.sql"], schema.SCHEMAS["3"]["migrations/clickhouse.sql"])

    def test_missing_changed_or_extra_migration_is_not_same_schema(self):
        for revision in ("1", "2", "3", "4"):
            for name in schema.SCHEMAS[revision]:
                for mutation in ("changed", "missing", "extra", "renamed"):
                    files = copy.deepcopy(schema.SCHEMAS[revision])
                    if mutation == "changed": files[name] = "a" * 64
                    if mutation == "missing": del files[name]
                    if mutation == "extra": files["migrations/extra.sql"] = "b" * 64
                    if mutation == "renamed": files["migrations/renamed.sql"] = files.pop(name)
                    with self.subTest(revision=revision, name=name, mutation=mutation), self.assertRaises(Refused):
                        schema.bind_source(files, revision)

    def test_source_identity_requires_exact_revision_without_executing_sql(self):
        for revision in ("1", "2", "3", "4"):
            files = {**schema.SCHEMAS[revision], "cmd/nebulalog/main.go": "a" * 64}
            self.assertEqual(schema.source_revision(files), revision)
            self.assertEqual(schema.declaration(files, revision), {
                "schema_revision": revision, "schema_sha256": schema.schema_digest(revision), "database_migration": "none"})
            for other in ("1", "2", "3", "4"):
                if other != revision:
                    with self.subTest(revision=revision, declared=other), self.assertRaises(Refused):
                        schema.declaration(files, other)
        for files in (None, [], {1: "a" * 64}, {}):
            with self.subTest(files=files), self.assertRaises(Refused):
                schema.source_revision(files)

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
        for revision in (None, 2, True, "5", {}, "2\n"):
            with self.subTest(revision=revision), self.assertRaises(Refused):
                schema.schema_digest(revision)

    def test_complete_transition_matrix_has_only_one_explicit_bridge(self):
        for installed in ("1", "2", "3", "4"):
            for target in ("1", "2", "3", "4"):
                for migration in ("none", schema.ADDITIVE_UPGRADE, "postgres-host-stepup-3-to-4"):
                    for rollback_safe in (True, False, 1):
                        change = {"schema_revision": target, "schema_sha256": schema.schema_digest(target),
                                  "database_migration": migration, "rollback_safe": rollback_safe}
                        allowed = (migration == "none" and installed == target or
                                   migration == schema.ADDITIVE_UPGRADE and installed == "1" and target == "2" and rollback_safe is True)
                        with self.subTest(installed=installed, target=target, migration=migration, rollback_safe=rollback_safe):
                            if allowed:
                                self.assertEqual(schema.transition(change, installed), migration)
                            else:
                                with self.assertRaises(Refused):
                                    schema.transition(change, installed)

    def test_retention_bridge_fence_is_independent_of_current_revision(self):
        self.assertEqual(schema.RETENTION_REVISIONS, frozenset(("3", "4")))
        with patch.object(schema, "CURRENT_REVISION", "4"):
            for installed, target in (("1", "3"), ("2", "3"), ("3", "1"), ("3", "2"), ("3", "4"), ("4", "3")):
                change = schema.declaration(schema.SCHEMAS[target], target)
                with self.subTest(installed=installed, target=target), self.assertRaisesRegex(Refused, "compatibility bridge"):
                    schema.transition(change, installed)

    def test_transition_rejects_unknown_installed_revision_and_bad_declaration(self):
        change = schema.declaration(schema.SCHEMAS["4"], "4")
        for installed in (None, True, 4, {}, "5"):
            with self.subTest(installed=installed), self.assertRaises(Refused):
                schema.transition(change, installed)
        for declaration in (None, [], "4"):
            with self.subTest(declaration=declaration), self.assertRaises(Refused):
                schema.transition(declaration, "4")
        for fingerprint in (None, "a" * 64, schema.schema_digest("3")):
            with self.subTest(fingerprint=fingerprint), self.assertRaises(Refused):
                schema.transition({**change, "schema_sha256": fingerprint}, "4")

    def test_three_accepts_only_exact_same_schema_and_preserves_old_transition(self):
        change = schema.declaration(schema.SCHEMAS["3"], "3")
        self.assertEqual(schema.transition(change, "3"), "none")
        for source in ("1", "2"):
            with self.subTest(source=source), self.assertRaisesRegex(Refused, "compatibility bridge"):
                schema.transition(change, source)
        for target in ("1", "2"):
            with self.subTest(target=target), self.assertRaisesRegex(Refused, "compatibility bridge"):
                schema.transition(schema.declaration(schema.SCHEMAS[target], target), "3")
        with self.assertRaises(Refused):
            schema.declaration(schema.SCHEMAS["3"], "3", schema.ADDITIVE_UPGRADE)
        self.assertEqual(schema.EMERGENCY_REVISION, "2")
        old = schema.declaration(schema.SCHEMAS["2"], "2", schema.ADDITIVE_UPGRADE)
        self.assertEqual(schema.transition({**old, "rollback_safe": True}, "1"), schema.ADDITIVE_UPGRADE)

    def test_declaration_cannot_select_a_path_or_sql_as_migration(self):
        for migration in ("/tmp/upgrade.sql", "DROP TABLE events", {}, None):
            with self.subTest(migration=migration), self.assertRaises(Refused):
                schema.declaration(schema.SCHEMAS["2"], "2", migration)


if __name__ == "__main__":
    unittest.main()
