"""Recovery coordinator failure boundaries and real CMS algorithm validation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock

from nebulalog_manager import configuration_restore as recovery
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.firstboot import Locations
from test_restore_database import OP, SOURCE, TARGET


class RecoveryStatusCLITests(unittest.TestCase):
    def test_status_dispatches_only_read_only_projection(self):
        import io
        from nebulalog_manager.cli import main
        with patch.object(recovery, "ConfigurationRestore") as factory, patch("sys.stdout", io.StringIO()) as output:
            factory.return_value.status.return_value = {"state": "not_started", "setup_complete": False}
            self.assertEqual(main(["restore", "--status"]), 0)
            factory.return_value.status.assert_called_once_with()
            factory.return_value.start.assert_not_called()
            factory.return_value.resume.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["state"], "not_started")

    def test_status_rejects_input_overrides_without_instantiating_runtime(self):
        import io
        from nebulalog_manager.cli import main
        with patch.object(recovery, "ConfigurationRestore") as factory, patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["restore", "--status", "--private-key", "/run/nebulalog/key"]), 1)
            factory.assert_not_called()


class CMSBoundaryTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
    def test_real_authenticated_envelope_and_plain_cbc_rejection(self):
        openssl = shutil.which("openssl")
        if not subprocess.check_output([openssl, "version"], text=True).startswith("OpenSSL 3."):
            self.skipTest("OpenSSL3 authenticated CMS required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key, cert, plain = root / "key.pem", root / "certificate.pem", root / "plain"
            plain.write_bytes(b"Synthetic recovery evidence, no production data.")
            def run(args):
                return subprocess.run([openssl, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            result = run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Synthetic Restore",
                          "-keyout", str(key), "-out", str(cert)])
            self.assertEqual(result.returncode, 0)
            for algorithm in ("aes-256-gcm", "aes-256-cbc"):
                encrypted = root / (algorithm + ".cms")
                result = run(["cms", "-encrypt", "-binary", "-" + algorithm, "-outform", "DER", "-in", str(plain), "-out", str(encrypted), str(cert)])
                self.assertEqual(result.returncode, 0)
                if algorithm.endswith("cbc"):
                    with self.assertRaises(Refused):
                        recovery.authenticated_cms(encrypted)
                else:
                    recovery.authenticated_cms(encrypted)
                    data = encrypted.read_bytes()
                    for altered in (data[:-1], data + b"suffix", b"\x30\x80" + data[2:]):
                        invalid = root / "invalid.cms"
                        invalid.write_bytes(altered)
                        with self.assertRaises(Refused):
                            recovery.authenticated_cms(invalid)
                    # Algorithm admission does not replace OpenSSL's GCM tag
                    # verification. Changing the MAC must still fail decryption.
                    changed = bytearray(data)
                    changed[-1] ^= 1
                    encrypted.write_bytes(changed)
                    result = run(["cms", "-decrypt", "-binary", "-inform", "DER", "-in", str(encrypted),
                                  "-recip", str(cert), "-inkey", str(key), "-out", str(root / "output")])
                    self.assertNotEqual(result.returncode, 0)


class FakeRuntime:
    def __init__(self, paths):
        self.paths = paths
        self.calls = []
        self.fail_verify = False

    def guard_fresh(self, transaction=None):
        return TARGET

    def prepare(self, source, manifest, tx, checkpoint):
        self.calls.append("prepare")
        tx["runtime"]["completed"] = ["directories", "storage-maintenance", "certificates", "images", "environment", "postgresql"]
        checkpoint()

    def activate(self, source, manifest, tx, checkpoint):
        self.calls.append("activate")
        if not tx.get("operational_normalized"):
            raise AssertionError("Activation before normalization")
        checkpoint()

    def verify_restored_catalog(self, source, manifest, tx, checkpoint):
        self.calls.append("catalog")
        if any(tx["databases"].get(name, {}).get("state") != "restored" for name in ("nebulalog", "keycloak")):
            raise AssertionError("Catalog observation before both database restores")
        checkpoint()

    def finish_enrollment(self, source, manifest, tx, checkpoint):
        self.calls.append("enrollment")
        # This operation must be outside all four coordination locks.
        from nebulalog_manager.common import locked
        for path in (self.paths.data / "manager/transaction.lock", self.paths.bootstrap / "firstboot.lock",
                     self.paths.data / "configuration/bootstrap/runtime.lock", self.paths.data / "configuration/baseline.lock"):
            with locked(path):
                pass
        checkpoint()

    def verify(self, source, manifest, tx):
        self.calls.append("verify")
        if self.fail_verify:
            raise Refused("Synthetic private health diagnostic")
        return {"state": "runtime-ready", "setup_complete": False}

    def fence_failure(self, tx):
        return {"verified": True, "listeners_stopped": True}


class FakeCommands:
    def __init__(self):
        self.calls = []
        self.fail_database = None
        self.nonempty_database = None

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[-1] == "SHOW server_version":
            return "17.11"
        if "--command" in argv:
            if argv[-1].startswith("SELECT count(*) FROM audit_events"):
                return "1"
            name = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--dbname="))
            return json.dumps({"database": name, "user": name, "owner": name, "privileged": False,
                               "objects": 1 if name == self.nonempty_database else 0, "memberships": 0, "sessions": 0})
        return ""

    def feed(self, argv, source, **kwargs):
        self.calls.append((argv, {"source": source}))
        if "--single-transaction" in argv and "--dbname=" + str(self.fail_database) in argv:
            raise TimeoutError("Synthetic private database diagnostic")


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.paths = Locations(self.root / "etc", self.root / "data", self.root / "run")
        self.runtime = FakeRuntime(self.paths)
        self.commands = FakeCommands()
        self.manager = recovery.ConfigurationRestore(self.runtime, self.commands)
        self.stage = self.paths.data / "manager/restores" / OP
        source = self.stage / "source"
        for directory in (self.paths.bootstrap, self.paths.data / "configuration/bootstrap", source):
            directory.mkdir(parents=True, mode=0o700)
        entries = []
        for name in ("nebulalog", "keycloak"):
            path = source / (name + ".dump")
            path.write_bytes(b"PGDMP " + name.encode())
            path.chmod(0o600)
            entries.append({"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size})
        manifest = {"schema": 1, "product": "nebulalog", "kind": "configuration", "includes_logs": False,
                    "installation_id": SOURCE, "files": entries, "postgresql": {"server_version": "17.11", "image": "synthetic-pin"},
                    "runtime": {"images": {"POSTGRESQL_IMAGE": "synthetic-pin"}}}
        atomic_json(source / "backup.json", manifest)
        self.tx = {"schema": 1, "kind": "configuration-restore", "id": OP, "stage": str(self.stage),
                   "source_installation_id": SOURCE, "target_installation_id": TARGET,
                   "manifest_sha256": hashlib.sha256((source / "backup.json").read_bytes()).hexdigest(),
                   "archive_sha256": "a" * 64, "state": "prepared", "databases": {}, "runtime": {}}
        def trusted(path):
            if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o022:
                raise Refused("Untrusted test file")
            return path
        def directory(path, *, create=False, private=False):
            if create:
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not path.is_relative_to(self.root) or path.is_symlink() or not path.is_dir():
                raise Refused("Untrusted test directory")
        for guard in (patch.object(recovery, "require_linux_root"), patch.object(recovery, "_directory", side_effect=directory),
                      patch.object(recovery, "trusted_file", side_effect=trusted),
                      patch("nebulalog_manager.restore_database.trusted_file", side_effect=trusted)):
            guard.start()
            self.addCleanup(guard.stop)
        self.manager._save(self.tx)

    def with_logs(self):
        from nebulalog_manager import log_recovery_set as transport
        patcher = patch.object(transport, "ROOT_UID", os.getuid())
        patcher.start()
        self.addCleanup(patcher.stop)
        source = self.stage / "source"
        manifest = json.loads((source / "backup.json").read_text())
        manifest["runtime"] = {"schema_revision": "3", "images": {
            name: "registry.example/image@sha256:" + "a" * 64 for name in transport.IMAGE_KEYS}}
        manifest["postgresql"]["image"] = manifest["runtime"]["images"]["POSTGRESQL_IMAGE"]
        manifest["snapshot"] = {"retention_policy": {"revision": 7}}
        atomic_json(source / "backup.json", manifest)
        self.tx["manifest_sha256"] = hashlib.sha256((source / "backup.json").read_bytes()).hexdigest()
        encrypted = self.stage / "backup.cms"
        encrypted.write_bytes(b"synthetic ciphertext fixture")
        encrypted.chmod(0o600)
        self.tx["archive_sha256"] = hashlib.sha256(encrypted.read_bytes()).hexdigest()
        directory = self.stage / "logs"
        directory.mkdir(mode=0o700)
        archive = directory / "events.tar"
        archive.write_bytes(b"synthetic native archive fixture")
        archive.chmod(0o600)
        evidence = {"path": str(archive), "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "bytes": archive.stat().st_size}
        self.tx["logs"] = {"schema": 1, "state": "authenticated", "archive": evidence, "native": {},
            "plan": {"maximum_archive_bytes": evidence["bytes"], "deadline_seconds": 300, "minimum_free_bytes": 10*1024**3},
            "metadata": {"link": {"source_installation_id": SOURCE,
                "configuration_backup": {"sha256": self.tx["archive_sha256"], "bytes": encrypted.stat().st_size}, "runtime": manifest["runtime"]},
                "native": {"table": "nebulalog.events", "server_version": "25.3.8.30001.altinityfips", "table_uuid": SOURCE,
                    "backup_id": OP, "query_id": TARGET, "started_at": "2026-10-19T20:00:00Z", "finished_at": "2026-10-19T20:00:10Z",
                    "table_definition_sha256": "b" * 64, "retention_policy_revision": 7},
                "archive": {"format": "clickhouse-native-tar", "sha256": evidence["sha256"], "bytes": evidence["bytes"]}}}
        self.manager._save(self.tx)
        self.native_adapter = Mock()
        patcher = patch("nebulalog_manager.log_backup.LogBackupAdapter.for_restore", return_value=self.native_adapter)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.native_running = True
        def prepare(source, manifest, tx, *, checkpoint):
            self.runtime.calls.append("logs-prepare")
            if not tx["logs"]["native"]:
                tx["logs"]["native"]["state"] = "table_ready"
                checkpoint()
        def plan(runtime, source, manifest, tx, *, checkpoint, **budgets):
            tx["logs"]["native"]["state"] = "planned"
            checkpoint()
        def start(runtime, source, manifest, tx, *, checkpoint):
            tx["logs"]["native"].update(state="running", dispatched_at="2026-10-19T20:00:00Z")
            checkpoint()
        def observe(runtime, source, manifest, tx, *, checkpoint):
            state = "running" if self.native_running else "restored"
            tx["logs"]["native"]["state"] = state
            checkpoint()
            return {"state": state}
        def complete(source, manifest, tx, *, checkpoint):
            self.runtime.calls.append("logs-complete")
            tx["logs"]["native"]["state"] = "bound"
            tx["logs"]["state"] = "restored"
            checkpoint()
        self.runtime.prepare_log_restore = prepare
        self.runtime.complete_log_restore = complete
        self.native_adapter.plan_restore.side_effect = plan
        self.native_adapter.start_restore.side_effect = start
        self.native_adapter.observe_restore.side_effect = observe

    def test_optional_logs_remain_fenced_until_observed_and_never_reapply_databases(self):
        self.with_logs()
        first = self.manager.resume(OP)
        self.assertEqual(first["state"], "restoring_logs")
        self.assertFalse(first["setup_complete"])
        self.assertNotIn("activate", self.runtime.calls)
        self.assertEqual(self.manager.status()["logs"]["phase"], "running")
        normalized = (self.stage / "normalization.json").read_bytes()
        self.native_running = False
        second = self.manager.resume(OP)
        self.assertEqual(second["state"], "runtime_ready")
        self.assertEqual(sum("--single-transaction" in cmd for cmd, _ in self.commands.calls), 2)
        self.assertEqual((self.stage / "normalization.json").read_bytes(), normalized)
        self.native_adapter.plan_restore.assert_called_once()
        self.native_adapter.start_restore.assert_called_once()
        self.assertLess(self.runtime.calls.index("logs-complete"), self.runtime.calls.index("activate"))

    def test_optional_log_archive_tamper_refuses_before_database_or_listener_effects(self):
        self.with_logs()
        Path(self.tx["logs"]["archive"]["path"]).write_bytes(b"tampered")
        with self.assertRaises(Refused):
            self.manager.resume(OP)
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(self.runtime.calls, [])
        self.native_adapter.start_restore.assert_not_called()

    def test_optional_log_policy_mismatch_refuses_before_database_effects(self):
        self.with_logs()
        self.tx["logs"]["metadata"]["native"]["retention_policy_revision"] += 1
        self.manager._save(self.tx)
        with self.assertRaises(Refused):
            self.manager.resume(OP)
        self.assertEqual(self.commands.calls, [])
        self.native_adapter.start_restore.assert_not_called()

    def test_log_resume_does_not_repeat_operational_normalization(self):
        self.with_logs()
        self.manager.resume(OP)
        with patch.object(recovery.RestoreDatabases, "quarantine_source_operations", side_effect=AssertionError("Must not renormalize")):
            self.manager.resume(OP)
        self.native_adapter.start_restore.assert_called_once()

    def test_log_resume_refuses_missing_normalization_receipt(self):
        self.with_logs()
        self.manager.resume(OP)
        (self.stage / "normalization.json").unlink()
        with self.assertRaises(Refused):
            self.manager.resume(OP)
        self.native_adapter.observe_restore.assert_called_once()
        self.assertNotIn("activate", self.runtime.calls)

    def test_log_budget_requires_explicit_log_set_before_host_access(self):
        with patch.object(self.runtime, "guard_fresh") as guard:
            with self.assertRaises(Refused):
                self.manager.start(Path("backup"), Path("key"), Path("cert"), log_restore_deadline_seconds=300)
            with self.assertRaises(Refused):
                self.manager.start(Path("backup"), Path("key"), Path("cert"), log_recovery_set=Path("logs"))
            guard.assert_not_called()

    def test_log_status_rejects_malformed_progress_without_runtime_calls(self):
        for logs in ([], {"native": []}, {"native": {"state": []}}):
            self.tx["logs"] = logs
            self.manager._save(self.tx)
            with self.assertRaises(Refused):
                self.manager.status()
        self.assertEqual(self.commands.calls, [])

    def test_status_is_allowlisted_read_only_and_marks_uncertain_actions(self):
        self.tx.update(state="recovery_required", error="private diagnostic", payload="secret")
        self.tx["databases"] = {"nebulalog": {"state": "restored", "archive_sha256": "a" * 64},
                                "keycloak": {"state": "restoring", "archive_sha256": "b" * 64}}
        self.tx["runtime"] = {"active_stage": "edge", "completed": ["directories"], "secret": "hidden"}
        self.tx["failure_fence"] = {"held": True, "error": "private"}
        self.manager._save(self.tx)
        before = (self.stage / "transaction.json").read_bytes()
        result = self.manager.status()
        self.assertTrue(result["resume_blocked"])
        self.assertTrue(result["listener_hold_recorded"])
        self.assertEqual(result["databases"]["keycloak"], "restoring")
        for excluded in ("private", "hidden", "secret", "archive_sha256"):
            self.assertNotIn(excluded, json.dumps(result))
        self.assertEqual((self.stage / "transaction.json").read_bytes(), before)
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(self.runtime.calls, [])

    def test_status_rejects_invalid_progress_and_foreign_pointer(self):
        for change in ({"state": "unexpected"}, {"state": []}, {"databases": {"other": {"state": "restored"}}},
                       {"databases": {"nebulalog": {"state": []}}},
                       {"runtime": {"active_stage": "secret-injected-stage"}}):
            tx = copy.deepcopy(self.tx)
            tx.update(change)
            self.manager._save(tx)
            with self.assertRaises(Refused):
                self.manager.status()
        self.manager._save(self.tx)
        atomic_json(self.manager.pointer, {"schema": 2, "id": SOURCE, "stage": str(self.stage)})
        with self.assertRaises((Refused, FileNotFoundError)):
            self.manager.status()
        self.assertEqual(self.commands.calls, [])

    def test_status_no_pointer_does_not_create_operation(self):
        self.manager.pointer.unlink()
        result = self.manager.status()
        self.assertEqual(result, {"state": "not_started", "setup_complete": False})
        self.assertFalse(self.manager.pointer.exists())
        self.assertEqual(self.commands.calls, [])

    def test_resume_restores_two_databases_before_activation_and_keeps_setup_incomplete(self):
        result = self.manager.resume(OP)
        self.assertEqual(result["state"], "runtime_ready")
        self.assertFalse(result["setup_complete"])
        self.assertEqual(self.runtime.calls, ["prepare", "catalog", "activate", "enrollment", "verify"])
        observed = self.manager._load(OP)
        self.assertEqual({row["state"] for row in observed["databases"].values()}, {"restored"})
        self.assertEqual(sum("--single-transaction" in cmd for cmd, _ in self.commands.calls), 2)
        self.assertFalse((self.paths.etc / "configured").exists())

    def test_partial_database_failure_never_activates_or_replays(self):
        self.commands.fail_database = "keycloak"
        with self.assertRaises(Refused) as caught:
            self.manager.resume(OP)
        self.assertNotIn("private", str(caught.exception))
        state = self.manager._load(OP)
        self.assertEqual(state["state"], "recovery_required")
        self.assertEqual(state["databases"]["nebulalog"]["state"], "restored")
        self.assertEqual(state["databases"]["keycloak"]["state"], "restoring")
        self.assertEqual(self.runtime.calls, ["prepare"])
        count = len(self.commands.calls)
        with self.assertRaises(Refused):
            self.manager.resume(OP)
        self.assertEqual(len(self.commands.calls), count)
        self.assertTrue((self.stage / "source/keycloak.dump").exists())

    def test_nonempty_second_database_refuses_before_either_archive_is_dispatched(self):
        self.commands.nonempty_database = "keycloak"
        with self.assertRaises(Refused):
            self.manager.resume(OP)
        self.assertFalse(any("pg_restore" in command for command, _ in self.commands.calls))
        self.assertEqual(self.manager._load(OP)["databases"], {})
        self.assertEqual(self.runtime.calls, ["prepare"])

    def test_health_failure_can_recheck_without_database_reapplication(self):
        self.runtime.fail_verify = True
        with self.assertRaises(Refused):
            self.manager.resume(OP)
        self.runtime.fail_verify = False
        result = self.manager.resume(OP)
        self.assertEqual(result["state"], "runtime_ready")
        self.assertEqual(self.runtime.calls.count("prepare"), 1)
        self.assertEqual(sum("--single-transaction" in cmd for cmd, _ in self.commands.calls), 2)

    def test_archive_tamper_and_foreign_pointer_refuse_before_runtime_effects(self):
        path = self.stage / "source/keycloak.dump"
        original = path.read_bytes()
        path.write_bytes(b"tampered")
        with self.assertRaises(Refused):
            self.manager.resume(OP)
        self.assertEqual(self.runtime.calls, [])
        path.write_bytes(original)
        pointer = json.loads(self.manager.pointer.read_text())
        pointer["id"] = SOURCE
        atomic_json(self.manager.pointer, pointer)
        with self.assertRaises(Refused):
            self.manager.resume(OP)
        self.assertEqual(self.runtime.calls, [])

    def test_completed_resume_does_not_reapply_or_claim_final_setup(self):
        self.manager.resume(OP)
        self.commands.calls.clear()
        self.runtime.calls.clear()
        result = self.manager.resume(OP)
        self.assertFalse(result["setup_complete"])
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(self.runtime.calls, [])

    def test_checkpoint_updates_one_authoritative_file_and_preserves_pointer(self):
        pointer_bytes = self.manager.pointer.read_bytes()
        original = recovery.atomic_json
        writes = []
        def record(path, value):
            writes.append(path)
            original(path, value)
        self.tx["state"] = "preparing"
        with patch.object(recovery, "atomic_json", side_effect=record):
            self.manager._save(self.tx)
        self.assertEqual(writes, [self.stage / "transaction.json"])
        self.assertEqual(self.manager.pointer.read_bytes(), pointer_bytes)
        self.assertEqual(self.manager._load(OP)["state"], "preparing")

    def test_failed_checkpoint_leaves_previous_loadable_journal(self):
        previous = self.manager._load(OP)
        changed = copy.deepcopy(previous)
        changed["state"] = "restoring"
        with patch.object(recovery, "atomic_json", side_effect=OSError("Synthetic full disk")):
            with self.assertRaises(OSError):
                self.manager._save(changed)
        self.assertEqual(self.manager._load(OP), previous)
        self.assertEqual(self.commands.calls, [])


if __name__ == "__main__":
    unittest.main()
