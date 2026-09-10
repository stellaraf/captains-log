"""Isolated filesystem/crash tests, with inert staged source and root fixture seams.

No installed launcher, service, customer configuration or boot path is changed.
"""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager import host_activation as activation, host_dispatch as dispatch, host_payload as payload
from nebulalog_manager.common import Refused, atomic_json, locked
import test_host_payload as fixtures


class HostFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.root = Path(temporary.name).resolve()
        self.addCleanup(temporary.cleanup)
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        self.generations = self.root / "generations"
        self.state = self.root / "updates"
        self.stage = self.state / "releases/10-fixture"
        self.stage.mkdir(parents=True, mode=0o700)
        self.selection = self.root / "configuration/host-selection.json"
        self.selection.parent.mkdir(mode=0o700)
        for target, name, value in ((payload, "GENERATIONS", self.generations), (dispatch, "STATE", self.state),
                                    (activation, "SELECTION", self.selection), (payload, "_OWNER_UID", os.getuid())):
            contexts.enter_context(patch.object(target, name, value))
        for module in (payload, dispatch, activation):
            contexts.enter_context(patch.object(module, "require_linux_root"))
        contexts.enter_context(patch.object(payload, "_trusted_tree", side_effect=fixtures.fixture_tree(self.root)))
        self.old = self.make_generation("old", "0.1.0")
        self.new = self.make_generation("new", "0.1.1")
        self.addCleanup(self.writable_fixture)
        self.manifest = {"product": "nebulalog", "channel": "stable", "sequence": 10,
            "components": {"host": {"artifact": "host.tar", "version": self.new["version"], "abi": 1,
                "host_source_sha256": self.new["host_source_sha256"], "rollback_safe": True}},
            "artifacts": [{"name": "host.tar", "sha256": self.new["generation"], "bytes": (self.root / "new/host.tar").stat().st_size}]}
        (self.stage / "host.tar").write_bytes((self.root / "new/host.tar").read_bytes())
        self.transaction = {"release": str(self.stage), "state": "preparing", "sequence": 10,
            "previous": {"sequence": 9, "components": {"host": self.old}}}
        self.bind_manifest()
        atomic_json(self.selection, {"schema": 1, "generation": self.old["generation"], "sequence": 9})
        self.maintenance = self.state.parent / "maintenance.json"
        self.maintenance.write_bytes(b"maintenance fixture remains active\n")

    def writable_fixture(self):
        for path in (self.generations, *self.generations.rglob("*")):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)

    def make_generation(self, name, version):
        base = self.root / name
        base.mkdir()
        source, manifest = fixtures.fixture_source(base)
        first = source / payload.CATALOG[0]["source"]
        first.write_text("# inert generation " + name + "\n")
        manifest_value = json.loads(manifest.read_text())
        manifest_value["files"][payload.CATALOG[0]["source"]] = payload.digest(first.read_bytes())
        manifest.write_bytes(payload.encoded(manifest_value))
        archive = base / "host.tar"
        evidence = fixtures.builder.build(source, manifest, archive, version=version)
        payload.stage_generation(archive, expected_sha256=evidence["archive_sha256"],
                                 expected_host_source_sha256=evidence["metadata"]["host_source_sha256"])
        return dispatch.generation_info(evidence["archive_sha256"])

    def bind_manifest(self):
        raw = payload.encoded(self.manifest)
        (self.stage / "manifest.json").write_bytes(raw)
        self.transaction["manifest_sha256"] = payload.digest(raw)
        self.save_transaction()

    def save_transaction(self, state=None):
        if state: self.transaction["state"] = state
        atomic_json(self.state / "transaction.json", self.transaction)

    def prepare_and_select(self):
        activation.prepare(self.stage)
        self.save_transaction("activating")
        return activation.select_candidate(self.stage)

    def corrupt_generation(self, identity):
        path = self.generations / identity["generation"] / payload.CATALOG[0]["path"]
        path.chmod(0o644)
        path.write_bytes(b"corrupt fixture\n")
        path.chmod(0o444)


class ActivationTests(HostFixture):
    def test_prepare_is_idempotent_and_pins_previous_without_runtime_effects(self):
        with patch("subprocess.Popen", side_effect=AssertionError("must not execute")):
            first = activation.prepare(self.stage)
            self.assertEqual(activation.prepare(self.stage), first)
        self.assertEqual(first["coordinator"]["generation"], self.old["generation"])
        self.assertEqual(first["candidate"], self.new)
        self.assertEqual(activation.selection()["generation"], self.old["generation"])
        self.assertEqual(self.transaction["state"], "preparing")
        self.assertTrue(self.maintenance.exists())

    def test_missing_selection_is_never_silently_enrolled(self):
        self.selection.unlink()
        with self.assertRaises(Refused): activation.prepare(self.stage)
        self.assertFalse(self.selection.exists())
        self.assertFalse((self.stage / "host-activation.json").exists())

    def test_wrong_preparation_phase_or_previous_sequence_is_refused(self):
        for state in ("preflight", "checking", "committed", "rolled_back"):
            self.save_transaction(state)
            with self.assertRaises(Refused): activation.prepare(self.stage)
        self.save_transaction("preparing")
        for sequence in (8, True, 10):
            atomic_json(self.selection, {"schema": 1, "generation": self.old["generation"], "sequence": sequence})
            with self.assertRaises(Refused): activation.prepare(self.stage)

    def test_selection_and_dispatch_remain_bound_to_old_coordinator(self):
        result = self.prepare_and_select()
        self.assertEqual(activation.selection(), {"schema": 1, "generation": self.new["generation"], "sequence": 10})
        self.assertFalse(result["runtime_activated"])
        self.assertFalse(result["committed"])
        self.assertEqual(result["coordinator"]["generation"], self.old["generation"])
        self.assertEqual(activation.select_candidate(self.stage), result)
        command = dispatch.hook_command(result["coordinator"], "update-activate", self.stage)
        self.assertEqual(command[-3], str(self.generations / self.old["generation"]))
        self.assertEqual(self.maintenance.read_bytes(), b"maintenance fixture remains active\n")

    def test_candidate_corruption_or_archive_removal_prevents_selection_but_not_recovery(self):
        activation.prepare(self.stage)
        self.corrupt_generation(self.new)
        self.save_transaction("activating")
        with self.assertRaises(Refused): activation.select_candidate(self.stage)
        (self.stage / "host.tar").unlink()
        self.save_transaction("recovery_required")
        self.assertEqual(activation.recovery_decision(self.stage)["action"], "restore_previous_with_pinned_coordinator")
        result = activation.restore_previous(self.stage)
        self.assertEqual(result["selection"], {"schema": 1, "generation": self.old["generation"], "sequence": 10})
        self.assertFalse(result["runtime_recovered"])
        self.assertFalse(result["committed"])
        self.assertTrue(self.maintenance.exists())

    def test_corrupt_previous_generation_cannot_authorize_dispatch_or_restoration(self):
        self.prepare_and_select()
        self.corrupt_generation(self.old)
        self.save_transaction("recovery_required")
        before = self.selection.read_bytes()
        with self.assertRaises(Refused): activation.restore_previous(self.stage)
        with self.assertRaises(Refused): dispatch.coordinator_pin(self.stage)
        self.assertEqual(self.selection.read_bytes(), before)

    def test_unrelated_selection_is_preserved_during_activation_and_rollback(self):
        activation.prepare(self.stage)
        unrelated = {"schema": 1, "generation": "a" * 64, "sequence": 12}
        atomic_json(self.selection, unrelated)
        self.save_transaction("activating")
        with self.assertRaises(Refused): activation.select_candidate(self.stage)
        self.save_transaction("rolling_back")
        with self.assertRaises(Refused): activation.restore_previous(self.stage)
        with self.assertRaises(Refused): activation.recovery_decision(self.stage)
        self.assertEqual(activation.selection(), unrelated)

    def test_rollback_is_idempotent_preserves_sequence_and_requires_manager_phase(self):
        self.prepare_and_select()
        for state in ("activating", "checking", "committed", "preflight"):
            self.save_transaction(state)
            with self.assertRaises(Refused): activation.restore_previous(self.stage)
        self.save_transaction("rolling_back")
        result = activation.restore_previous(self.stage)
        self.assertEqual(activation.restore_previous(self.stage), result)
        self.save_transaction("rolled_back")
        decision = activation.recovery_decision(self.stage)
        self.assertEqual(decision["action"], "verify_previous_then_finalize")
        self.assertTrue(decision["maintenance_must_remain"])
        self.assertEqual(activation.selection()["sequence"], 10)

    def test_crash_at_each_selection_write_is_retryable(self):
        activation.prepare(self.stage)
        self.save_transaction("activating")
        initial_record = (self.stage / "host-activation.json").read_bytes()
        initial_selection = self.selection.read_bytes()
        for fail_at in (1, 2, 3):
            (self.stage / "host-activation.json").write_bytes(initial_record)
            self.selection.write_bytes(initial_selection)
            count = 0
            def fail_write(path, value):
                nonlocal count
                count += 1
                if count == fail_at: raise OSError("injected durable write failure")
                atomic_json(path, value)
            with patch.object(activation, "atomic_json", side_effect=fail_write), self.assertRaises(OSError):
                activation.select_candidate(self.stage)
            decision = activation.recovery_decision(self.stage)
            self.assertTrue(decision["maintenance_must_remain"])
            self.assertEqual(activation.select_candidate(self.stage)["selection"]["generation"], self.new["generation"])

    def test_crash_at_each_restoration_write_is_retryable(self):
        self.prepare_and_select()
        self.save_transaction("rolling_back")
        initial_record = (self.stage / "host-activation.json").read_bytes()
        initial_selection = self.selection.read_bytes()
        for fail_at in (1, 2, 3):
            (self.stage / "host-activation.json").write_bytes(initial_record)
            self.selection.write_bytes(initial_selection)
            count = 0
            def fail_write(path, value):
                nonlocal count
                count += 1
                if count == fail_at: raise OSError("injected durable write failure")
                atomic_json(path, value)
            with patch.object(activation, "atomic_json", side_effect=fail_write), self.assertRaises(OSError):
                activation.restore_previous(self.stage)
            self.assertEqual(activation.restore_previous(self.stage)["selection"]["generation"], self.old["generation"])
            self.assertTrue(self.maintenance.exists())

    def test_committed_recovery_never_silently_selects_or_restores(self):
        self.prepare_and_select()
        self.save_transaction("committed")
        self.assertEqual(activation.recovery_decision(self.stage)["action"], "verify_candidate_then_finalize")
        atomic_json(self.selection, {"schema": 1, "generation": self.old["generation"], "sequence": 9})
        before = self.selection.read_bytes()
        self.assertEqual(activation.recovery_decision(self.stage)["action"], "reconcile_committed_selection")
        self.assertEqual(self.selection.read_bytes(), before)
        with self.assertRaises(Refused): activation.restore_previous(self.stage)

    def test_host_manifest_identity_negatives_refuse_before_selection(self):
        original = copy.deepcopy(self.manifest)
        cases = (("abi", True), ("abi", 2), ("rollback_safe", False), ("version", "bad"),
                 ("host_source_sha256", "x" * 64), ("artifact", "../host.tar"), ("artifact", "manifest.json"))
        for key, value in cases:
            self.manifest = copy.deepcopy(original)
            self.manifest["components"]["host"][key] = value
            self.bind_manifest()
            with self.subTest(key=key), self.assertRaises(Refused): activation.prepare(self.stage)
        for key, value in (("bytes", True), ("bytes", -1), ("bytes", payload.MAX_ARCHIVE + 1), ("sha256", "bad")):
            self.manifest = copy.deepcopy(original)
            self.manifest["artifacts"][0][key] = value
            self.bind_manifest()
            with self.subTest(key=key), self.assertRaises(Refused): activation.prepare(self.stage)
        self.manifest = copy.deepcopy(original)
        self.manifest["artifacts"].append(copy.deepcopy(self.manifest["artifacts"][0]))
        self.bind_manifest()
        with self.assertRaises(Refused): activation.prepare(self.stage)
        self.assertFalse((self.stage / "host-activation.json").exists())

    def test_changed_host_journal_and_manifest_are_never_replaced(self):
        activation.prepare(self.stage)
        path = self.stage / "host-activation.json"
        original = json.loads(path.read_text())
        for key, value in (("sequence", 11), ("state", []), ("schema", True), ("candidate", self.old),
                           ("coordinator", {}), ("manifest_sha256", "a" * 64)):
            changed = {**original, key: value}
            atomic_json(path, changed)
            with self.subTest(key=key), self.assertRaises(Refused): activation.prepare(self.stage)
            self.assertEqual(json.loads(path.read_text()), changed)
        atomic_json(path, original)
        self.manifest["components"]["host"]["version"] = "0.1.2"
        self.bind_manifest()
        with self.assertRaises(Refused): activation.prepare(self.stage)
        self.assertEqual(json.loads(path.read_text()), original)

    def test_protected_selection_symlink_hardlink_and_mode_refused(self):
        original = self.selection.read_bytes()
        other = self.root / "unrelated.json"
        other.write_bytes(original)
        self.selection.unlink()
        for kind in ("symlink", "hardlink", "writable"):
            if kind == "symlink": self.selection.symlink_to(other)
            elif kind == "hardlink": os.link(other, self.selection)
            else:
                self.selection.write_bytes(original)
                self.selection.chmod(0o666)
            with self.subTest(kind=kind), self.assertRaises(Refused): activation.prepare(self.stage)
            self.selection.unlink()
        self.assertEqual(other.read_bytes(), original)

    def test_lock_is_exclusive_and_unsafe_lock_is_refused(self):
        lock = self.state / "host-selection.lock"
        with locked(lock), self.assertRaises(Refused): activation.prepare(self.stage)
        lock.unlink()
        target = self.root / "unrelated.lock"
        target.write_bytes(b"")
        os.link(target, lock)
        with self.assertRaises(Refused): activation.prepare(self.stage)
        self.assertEqual(target.stat().st_nlink, 2)


if __name__ == "__main__":
    unittest.main()
