"""Coordinator crash/ownership tests with fake databases and crypto transport.

Real crypto and native command admission have separate suites. These fixtures
exercise durable parent/child transitions and refusal to replay lost effects.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import recovery_set as module
from nebulalog_manager import log_recovery_set as transport
from nebulalog_manager.common import Refused, atomic_json

IDENTITY = "6aaee62c-0318-46ba-bbce-2eb520ff98fc"


class RecoverySetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        self.manager = self.data / "manager"
        self.manager.mkdir(parents=True, mode=0o700)
        self.certificate = self.root / "cert.pem"
        self.certificate.write_bytes(b"synthetic public certificate")
        self.certificate.chmod(0o600)
        self.output = self.root / "export"
        self.config = Mock(data=self.data, manager=self.manager, configuration=self.data / "configuration")
        self.config._guard.return_value = IDENTITY
        self.config.create_for_log_set.side_effect = self.capture
        self.config.settle_for_log_set.side_effect = self.settle_configuration
        self.native, self.transport = Mock(), Mock()
        self.native.plan.side_effect = self.plan
        self.native.start_backup.side_effect = self.start_native
        self.native.observe.side_effect = self.observe
        self.native.release.side_effect = self.release
        self.native.recover_backup.side_effect = self.recover_native
        self.transport._credential.side_effect = self.credential
        self.transport.seal.side_effect = self.seal
        self.transport.inspect_sealed.side_effect = self.inspect
        self.subject = module.FullBackupManager(self.config, self.native, self.transport)
        self.budgets = {"maximum_archive_bytes": 1024**3, "growth_reserve_bytes": 1024**3,
                        "minimum_free_bytes": 10 * 1024**3, "deadline_seconds": 300}
        self.policy = {"revision": 5, "raw_policy_sha256": "f" * 64, "normalization": "stored"}
        self.native_running = True
        self.crash = None
        for item in (patch.object(module, "require_linux_root"),
                     patch.object(module, "_directory", side_effect=self.directory),
                     patch.object(module, "_encrypted_staging"), patch.object(transport, "ROOT_UID", os.getuid()),
                     patch.object(module, "owned_stage", side_effect=lambda stage, data: module._read(stage / "native.json"))):
            item.start()
            self.addCleanup(item.stop)

    def directory(self, path, *, private=False, create=False):
        if not path.is_relative_to(self.root) or ".." in path.parts:
            raise Refused("Outside fixture")
        if create:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink() or not path.is_dir() or private and path.stat().st_mode & 0o077:
            raise Refused("Unsafe fixture directory")

    def credential(self, source, stage, name, **kwargs):
        target = stage / name
        target.write_bytes(source.read_bytes())
        target.chmod(0o600)
        return target

    def capture(self, output, certificate, identifier):
        output.write_bytes(b"synthetic completed configuration ciphertext")
        output.chmod(0o600)
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        link = {"source_installation_id": IDENTITY,
                "configuration_backup": {"sha256": digest, "bytes": output.stat().st_size},
                "runtime": {"schema_revision": "3", "images": {name: "registry.example/image@sha256:" + "a" * 64 for name in transport.IMAGE_KEYS}}}
        result = {"id": identifier, "path": str(output), "sha256": digest, "bytes": output.stat().st_size,
                  "log_link": link, "configuration_capture": {"retention_policy": self.policy}}
        atomic_json(self.manager / "backups" / identifier / "transaction.json", {"schema": 1,
            "kind": "configuration-backup", "id": identifier, "installation_id": IDENTITY,
            "state": "complete", "result": result})
        if self.crash == "configuration_ack":
            raise OSError("Synthetic lost parent acknowledgement")
        return result

    def plan(self, stage, *, mode, linked_metadata, **plan):
        stage.mkdir(parents=True, mode=0o700)
        value = {"state": "planned", "link": linked_metadata, "plan": plan}
        atomic_json(stage / "native.json", value)
        if self.crash == "plan_ack":
            raise OSError("Synthetic lost parent acknowledgement")
        return value

    def start_native(self, stage, **expected):
        self.assertEqual(expected, {"expected_policy_revision": self.policy["revision"],
            "expected_raw_policy_sha256": self.policy["raw_policy_sha256"]})
        value = module._read(stage / "native.json")
        value.update(state="dispatching" if self.crash == "dispatch_ack" else "running", policy=self.policy)
        atomic_json(stage / "native.json", value)
        if self.crash == "dispatch_ack":
            raise OSError("Synthetic lost dispatch acknowledgement")
        return {"state": "running"}

    def observe(self, stage):
        if self.native_running:
            return {"state": "running"}
        value = module._read(stage / "native.json")
        archive = self.data / "clickhouse/backup-staging" / stage.name / "events.tar"
        archive.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        archive.write_bytes(b"synthetic native archive")
        archive.chmod(0o600)
        evidence = {"path": str(archive), "bytes": archive.stat().st_size,
                    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        metadata = {"link": value["link"], "native": {"table": "nebulalog.events",
            "server_version": "25.3.8.30001.altinityfips", "table_uuid": IDENTITY,
            "backup_id": stage.name, "query_id": IDENTITY, "started_at": "2026-10-19T20:00:00Z",
            "finished_at": "2026-10-19T20:00:10Z", "table_definition_sha256": "b" * 64,
            "retention_policy_revision": self.policy["revision"]},
            "archive": {"format": "clickhouse-native-tar", "sha256": evidence["sha256"], "bytes": evidence["bytes"]}}
        result = {"archive": evidence, "metadata": metadata}
        value.update(state="succeeded", result=result)
        atomic_json(stage / "native.json", value)
        return result

    def seal(self, archive, output, recipient, staging, metadata, *, checkpoint):
        output.mkdir(mode=0o700)
        if self.crash == "partial_seal":
            raise OSError("Synthetic partial export")
        checkpoint({"fixture": True, "metadata": metadata})
        (output / "manifest.cms").write_bytes(b"synthetic sealed manifest")
        if self.crash == "seal_ack":
            raise OSError("Synthetic lost seal acknowledgement")

    def inspect(self, output, receipt, metadata):
        if receipt != {"fixture": True, "metadata": metadata} or (output / "manifest.cms").read_bytes() != b"synthetic sealed manifest":
            raise Refused("Synthetic ciphertext mismatch")
        return {"complete": True, "manifest_sha256": "c" * 64}

    def release(self, stage):
        self.assertTrue((self.output / "logs/manifest.cms").exists())
        value = module._read(stage / "native.json")
        value["state"] = "released"
        atomic_json(stage / "native.json", value)
        if self.crash == "release_ack":
            raise OSError("Synthetic lost release acknowledgement")

    def create(self):
        return self.subject.create(self.output, self.certificate, **self.budgets)

    def settle_configuration(self, identifier, output):
        child_path = self.manager / "backups" / identifier / "transaction.json"
        if child_path.exists():
            child = module._read(child_path)
            if child.get("state") != "complete":
                raise Refused("Synthetic unsettled configuration")
        else:
            admission = module._read(self.manager / "backup-admissions" / identifier / "admission.json")
            if admission.get("state") != "preflight_failed":
                raise Refused("Synthetic ambiguous preflight")
        return {"id": identifier, "installation_id": IDENTITY, "settled": True}

    def recover_native(self, stage, *, abandon_export):
        self.assertTrue(abandon_export)
        value = module._read(stage / "native.json")
        if value["state"] not in {"planned", "failed", "succeeded", "recovered"}:
            raise Refused("Synthetic active native job cannot retire")
        value["state"] = "recovered"
        atomic_json(stage / "native.json", value)
        if self.crash == "recovery_ack":
            raise OSError("Synthetic recovery acknowledgement lost")
        return {"id": stage.name, "settled": True, "holds_released": True, "backup_complete": False,
                "outcome": "unsuccessful_export"}

    def current(self):
        return self.subject._current()

    def test_async_resume_completes_without_recapture_or_redispatch(self):
        initial = self.create()
        self.assertEqual(initial["state"], "running")
        self.native.release.assert_not_called()
        self.native_running = False
        completed = self.subject.resume(initial["id"])
        self.assertTrue(completed["complete"])
        self.assertFalse(completed["native_qualified"])
        self.assertFalse(completed["cross_database_atomic"])
        self.config.create_for_log_set.assert_called_once()
        self.native.start_backup.assert_called_once()
        self.transport.inspect_sealed.assert_called_once()
        self.native.release.assert_called_once()
        self.subject.resume(initial["id"])
        self.native.release.assert_called_once()

    def test_complete_config_child_is_read_back_after_parent_ack_lost(self):
        self.crash = "configuration_ack"
        with self.assertRaises(Refused):
            self.create()
        identifier = self.current()["id"]
        self.crash = None
        self.assertEqual(self.subject.resume(identifier)["state"], "running")
        self.config.create_for_log_set.assert_called_once()

    def test_planned_child_readback_and_dispatch_once_after_parent_ack_lost(self):
        self.crash = "plan_ack"
        with self.assertRaises(Refused):
            self.create()
        self.crash = None
        self.subject.resume(self.current()["id"])
        self.native.plan.assert_called_once()
        self.native.start_backup.assert_called_once()

    def test_lost_dispatch_ack_is_observed_never_reissued(self):
        self.crash = "dispatch_ack"
        with self.assertRaises(Refused):
            self.create()
        self.crash = None
        self.subject.resume(self.current()["id"])
        self.native.start_backup.assert_called_once()

    def test_published_seal_readback_after_lost_ack_releases_once(self):
        self.crash, self.native_running = "seal_ack", False
        with self.assertRaises(Refused):
            self.create()
        self.native.release.assert_not_called()
        self.crash = None
        self.assertTrue(self.subject.resume(self.current()["id"])["complete"])
        self.transport.seal.assert_called_once()
        self.native.release.assert_called_once()

    def test_partial_seal_is_preserved_without_reencrypt_or_release(self):
        self.crash, self.native_running = "partial_seal", False
        with self.assertRaises(Refused):
            self.create()
        self.crash = None
        with self.assertRaises(Refused):
            self.subject.resume(self.current()["id"])
        self.transport.seal.assert_called_once()
        self.native.release.assert_not_called()
        self.assertTrue((self.output / "logs").is_dir())

    def test_altered_configuration_blocks_native_and_preserves_capture(self):
        result = self.create()
        (self.output / "configuration.cms").write_bytes(b"changed")
        with self.assertRaises(Refused):
            self.subject.resume(result["id"])
        self.native.observe.assert_called_once()
        self.native.release.assert_not_called()

    def test_wrong_native_binding_cannot_be_observed_or_released(self):
        result = self.create()
        path = self.manager / "log-backups" / result["id"] / "native.json"
        value = module._read(path)
        value["link"]["configuration_backup"]["sha256"] = "e" * 64
        atomic_json(path, value)
        with self.assertRaises(Refused):
            self.subject.resume(result["id"])
        self.native.observe.assert_called_once()
        self.native.release.assert_not_called()

    def test_active_pointer_prevents_second_capture(self):
        self.create()
        with self.assertRaises(Refused):
            self.subject.create(self.root / "second", self.certificate, **self.budgets)
        self.config.create_for_log_set.assert_called_once()
        self.assertFalse((self.root / "second").exists())

    def test_invalid_budget_refused_before_any_runtime_access(self):
        for key in self.budgets:
            values = {**self.budgets, key: True}
            with self.assertRaises(Refused):
                self.subject.create(self.output, self.certificate, **values)
        self.config._guard.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_status_projects_no_certificate_paths_policy_or_runtime_calls(self):
        result = self.create()
        self.config.reset_mock()
        self.native.reset_mock()
        status = self.subject.status(result["id"])
        self.assertEqual(status["phase"], "native")
        self.assertNotIn("recipient", json.dumps(status))
        self.assertNotIn("raw_policy", json.dumps(status))
        self.config._guard.assert_not_called()
        self.assertFalse(self.native.mock_calls)

    def test_missing_config_child_never_replays_capture(self):
        self.config.create_for_log_set.side_effect = OSError("Synthetic child failure")
        with self.assertRaises(Refused):
            self.create()
        with self.assertRaises(Refused):
            self.subject.resume(self.current()["id"])
        self.config.create_for_log_set.assert_called_once()
        self.native.plan.assert_not_called()

    def test_damaged_sealed_output_never_releases(self):
        self.crash, self.native_running = "seal_ack", False
        with self.assertRaises(Refused):
            self.create()
        (self.output / "logs/manifest.cms").write_bytes(b"changed")
        with self.assertRaises(Refused):
            self.subject.resume(self.current()["id"])
        self.native.release.assert_not_called()

    def test_top_level_export_barrier_failure_retains_hold_and_resume_repeats_it(self):
        self.native_running = False
        original = module._fsync
        def fail_parent(path):
            if path == self.output.parent:
                raise OSError("Synthetic export-directory durability failure")
            return original(path)
        with patch.object(module, "_fsync", side_effect=fail_parent):
            with self.assertRaises(Refused):
                self.create()
        self.native.release.assert_not_called()
        with patch.object(module, "_fsync", wraps=original) as barriers:
            self.assertTrue(self.subject.resume(self.current()["id"])["complete"])
            self.assertEqual([call.args[0] for call in barriers.call_args_list][-2:],
                             [self.output, self.output.parent])
        self.transport.seal.assert_called_once()
        self.native.release.assert_called_once()

    def test_partial_export_can_retire_unsuccessfully_without_deleting_or_replaying(self):
        self.crash, self.native_running = "partial_seal", False
        with self.assertRaises(Refused):
            self.create()
        tx = self.current()
        archive = Path(tx["native_result"]["archive"]["path"])
        preserved = {p: p.read_bytes() for p in (archive, self.output / "configuration.cms")}
        original_tx = copy.deepcopy(tx)
        self.crash = None
        retired = self.subject.retire(tx["id"])
        self.assertEqual(retired["state"], "retired_without_backup")
        self.assertTrue(retired["retired"])
        self.assertFalse(retired["complete"])
        self.assertEqual(module._read(Path(tx["stage"]) / "retirement-intent.json")["parent"], original_tx)
        self.assertTrue((self.output / "logs").is_dir())
        for path, content in preserved.items():
            self.assertEqual(path.read_bytes(), content)
        with self.assertRaises(Refused):
            self.subject.resume(tx["id"])
        self.assertEqual(self.subject.retire(tx["id"]), retired)
        self.native.recover_backup.assert_called_once()
        self.native.release.assert_not_called()
        self.transport.seal.assert_called_once()
        self.native.start_backup.assert_called_once()
        self.native_running = True
        second = self.subject.create(self.root / "second", self.certificate, **self.budgets)
        self.assertNotEqual(second["id"], tx["id"])
        self.assertTrue((Path(tx["stage"]) / "retirement.json").exists())

    def test_running_unknown_or_missing_children_never_retire_or_redispatch(self):
        tx = self.create()
        with self.assertRaises(Refused):
            self.subject.retire(tx["id"])
        self.assertEqual(self.current()["state"], "retiring")
        with self.assertRaises(Refused):
            self.subject.create(self.root / "second", self.certificate, **self.budgets)
        self.native.start_backup.assert_called_once()
        self.native.release.assert_not_called()
        self.assertFalse((self.root / "second").exists())

    def test_lost_native_recovery_ack_is_reconciled_without_repeating_capture(self):
        self.crash = "plan_ack"
        with self.assertRaises(Refused):
            self.create()
        identifier = self.current()["id"]
        self.crash = "recovery_ack"
        with self.assertRaises(OSError):
            self.subject.retire(identifier)
        self.crash = None
        self.assertTrue(self.subject.retire(identifier)["retired"])
        self.native.start_backup.assert_not_called()
        self.config.create_for_log_set.assert_called_once()
        self.native.plan.assert_called_once()

    def test_retirement_commit_failure_recovers_receipt_without_overwriting_it(self):
        self.crash = "plan_ack"
        with self.assertRaises(Refused):
            self.create()
        identifier = self.current()["id"]
        self.crash = None
        original = self.subject._save
        def fail_terminal(tx):
            if tx["state"] == "retired_without_backup":
                raise OSError("Synthetic parent commit failure")
            original(tx)
        with patch.object(self.subject, "_save", side_effect=fail_terminal):
            with self.assertRaises(OSError):
                self.subject.retire(identifier)
        path = Path(self.current()["stage"]) / "retirement.json"
        content = path.read_bytes()
        self.assertTrue(self.subject.retire(identifier)["retired"])
        self.assertEqual(path.read_bytes(), content)
        self.native.start_backup.assert_not_called()

    def test_missing_config_journal_is_not_no_effect_proof(self):
        self.config.create_for_log_set.side_effect = OSError("Synthetic interrupted preflight")
        with self.assertRaises(Refused):
            self.create()
        with self.assertRaises((Refused, FileNotFoundError)):
            self.subject.retire(self.current()["id"])
        self.native.recover_backup.assert_not_called()
        self.config.create_for_log_set.assert_called_once()

    def test_positive_preflight_failure_retires_without_invoking_native(self):
        def failed(output, certificate, identifier):
            atomic_json(self.manager / "backup-admissions" / identifier / "admission.json",
                        {"state": "preflight_failed"})
            raise Refused("Synthetic observed sizing refusal")
        self.config.create_for_log_set.side_effect = failed
        with self.assertRaises(Refused):
            self.create()
        self.assertTrue(self.subject.retire(self.current()["id"])["retired"])
        self.native.plan.assert_not_called()
        self.native.recover_backup.assert_not_called()

    def test_altered_intent_or_receipt_prevents_retirement_and_new_capture(self):
        self.crash = "plan_ack"
        with self.assertRaises(Refused):
            self.create()
        identifier = self.current()["id"]
        self.crash = None
        self.subject.retire(identifier)
        path = Path(self.current()["stage"]) / "retirement-intent.json"
        value = module._read(path)
        value["parent"]["error"] = "altered"
        atomic_json(path, value)
        with self.assertRaises(Refused):
            self.subject.retire(identifier)
        with self.assertRaises(Refused):
            self.subject.create(self.root / "second", self.certificate, **self.budgets)
        self.config.create_for_log_set.assert_called_once()

    def test_old_uuid_cannot_retire_current_operation(self):
        tx = self.create()
        with self.assertRaises(Refused):
            self.subject.retire(IDENTITY)
        self.assertEqual(self.current()["state"], tx["state"])
        self.config.settle_for_log_set.assert_not_called()

    def test_pending_retirement_rejects_changed_original_evidence_before_child_action(self):
        tx = self.create()
        with self.assertRaises(Refused):
            self.subject.retire(tx["id"])
        path = Path(self.current()["stage"]) / "retirement-intent.json"
        value = module._read(path)
        value["parent"]["state"] = "synthetic alteration"
        atomic_json(path, value)
        self.native.reset_mock()
        self.config.reset_mock()
        with self.assertRaisesRegex(Refused, "intent changed"):
            self.subject.retire(tx["id"])
        self.native.recover_backup.assert_not_called()
        self.config.settle_for_log_set.assert_not_called()

    def test_lost_intent_ack_requires_exact_original_parent(self):
        tx = self.create()
        original = self.subject._save
        def fail_retiring(value):
            if value["state"] == "retiring":
                raise OSError("Synthetic intent acknowledgement lost")
            original(value)
        with patch.object(self.subject, "_save", side_effect=fail_retiring), self.assertRaises(OSError):
            self.subject.retire(tx["id"])
        self.assertEqual(self.current()["state"], "running")
        path = Path(self.current()["stage"]) / "retirement-intent.json"
        value = module._read(path)
        value["parent"]["state"] = "synthetic alteration"
        atomic_json(path, value)
        with self.assertRaisesRegex(Refused, "Unacknowledged retirement intent"):
            self.subject.retire(tx["id"])
        self.config.settle_for_log_set.assert_not_called()


if __name__ == "__main__":
    unittest.main()
