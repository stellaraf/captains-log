"""Control-flow fixtures only; no real initdb invocation or FIPS substitution."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("pg_fips_entrypoint", HERE / "entrypoint.py")
entrypoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entrypoint)


class EntrypointTests(unittest.TestCase):
    def test_gate_failure_precedes_credentials_and_initialization(self):
        with patch.object(sys, "argv", ["entrypoint", "postgres"]), patch.object(entrypoint, "require_fips", side_effect=RuntimeError("fixture FIPS refusal")), patch.object(entrypoint, "initialize") as initialize:
            with self.assertRaisesRegex(RuntimeError, "FIPS refusal"):
                entrypoint.main()
            initialize.assert_not_called()

    def test_arbitrary_commands_cannot_bypass_gate(self):
        for args in (["bash"], ["initdb"], ["postgres", "-c", "password_encryption=md5"]):
            with self.subTest(args=args), patch.object(sys, "argv", ["entrypoint", *args]), patch.object(entrypoint, "initialize") as initialize, self.assertRaises(RuntimeError):
                entrypoint.main()
            initialize.assert_not_called()

    def test_version_diagnostic_does_not_initialize_database(self):
        with patch.object(sys, "argv", ["entrypoint", "--version"]), patch.object(entrypoint.os, "execv", side_effect=SystemExit), patch.object(entrypoint, "initialize") as initialize, self.assertRaises(SystemExit):
            entrypoint.main()
        initialize.assert_not_called()

    def test_inline_password_and_changed_auth_contract_refused(self):
        for values in ({"POSTGRES_PASSWORD": "fixture-only"}, {"POSTGRES_INITDB_ARGS": "--auth-host=trust"}, {"POSTGRES_USER": "other"}, {"PGDATA": "/tmp/elsewhere"}):
            with self.subTest(values=values), patch.dict(entrypoint.os.environ, values, clear=True), patch.object(entrypoint.os, "getuid", return_value=999), patch.object(entrypoint.os, "getgid", return_value=999), patch.object(entrypoint.subprocess, "run") as execute, self.assertRaises(RuntimeError):
                entrypoint.initialize()
            execute.assert_not_called()

    def test_partial_initialization_requires_recovery_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "PG_VERSION").write_text("17\n")
            with patch.object(entrypoint, "DATA", directory), patch.object(entrypoint, "READY", directory / ".nebulalog-initialized.json"), patch.object(entrypoint, "private_directory"), patch.dict(entrypoint.os.environ, {}, clear=True), patch.object(entrypoint.os, "getuid", return_value=999), patch.object(entrypoint.os, "getgid", return_value=999), patch.object(entrypoint.subprocess, "run") as execute, self.assertRaisesRegex(RuntimeError, "nonempty"):
                entrypoint.initialize()
            execute.assert_not_called()

    def test_nonroot_identity_required(self):
        with patch.object(entrypoint.os, "getuid", return_value=0), self.assertRaisesRegex(RuntimeError, "nonroot"):
            entrypoint.initialize()

    def test_persisted_system_overrides_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "postgresql.auto.conf"
            path.write_text("# Automatic configuration\n")
            with patch.object(entrypoint, "DATA", directory), patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o100600, st_uid=999)):
                entrypoint.verify_no_persisted_overrides()
                path.write_text("# retained prior setting\npassword_encryption = 'md5'\n")
                with self.assertRaisesRegex(RuntimeError, "ALTER SYSTEM"):
                    entrypoint.verify_no_persisted_overrides()


if __name__ == "__main__":
    unittest.main()
