"""Real signed archives/journals with fixture lifecycle evidence, never live hooks.

These tests verify orchestration and failure gates; evidence-producing runtime
reconciliation still needs separate adapter and Rocky guest acceptance.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from nebulalog_manager import host_activation as activation, host_dispatch as dispatch, host_payload as payload, updates
from nebulalog_manager import github_updates as github
from nebulalog_manager.common import Refused, atomic_json, run
from test_host_activation import HostFixture
import test_manager as fixtures
import test_github_updates as github_fixtures


class PowerLoss(BaseException):
    pass


class HostUpdateFixture(HostFixture):
    setUpClass = classmethod(fixtures.SignatureTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.SignatureTests.tearDownClass.__func__)

    def setUp(self):
        super().setUp()
        self.bundle = self.root / "release"
        self.bundle.mkdir()
        (self.bundle / "host.tar").write_bytes((self.root / "new/host.tar").read_bytes())
        (self.bundle / "app.tar").write_bytes(b"inert OCI fixture")
        self.manifest.update(schema=1, version="0.1.1", issued_at="2026-09-01T00:00:00Z", expires_at="2027-09-01T00:00:00Z")
        self.manifest["components"]["host"]["from_versions"] = ["0.1.0"]
        self.manifest["components"]["nebulalog"] = {"artifact": "app.tar", "version": "0.1.1", "from_versions": ["0.1.0"], "rollback_safe": True}
        raw = (self.bundle / "app.tar").read_bytes()
        self.manifest["artifacts"].append({"name": "app.tar", "bytes": len(raw), "sha256": payload.digest(raw)})
        self.sign()
        (self.state / "transaction.json").unlink()
        self.initial = {"sequence": 9, "version": "0.1.0", "components": {"host": self.old, "nebulalog": {"version": "0.1.0"}}}
        self.initial["components"].update(postgresql={"version": "17.11"}, clickhouse={"version": "25.3.9.100"}, keycloak={"version": "26.7.3"})
        atomic_json(self.state / "current.json", self.initial)
        atomic_json(self.state / "initial-enrollment.json", {"schema": 1, "state": "enrolled", "installation_id": "458a08e3-ef3b-4cd1-83e5-b402a2c1e913", "current": self.initial})
        atomic_json(self.state / "publisher-trust.json", {"schema": 1, "state": "enrolled", "installation_id": "458a08e3-ef3b-4cd1-83e5-b402a2c1e913", "algorithm": "RSA-PSS-SHA256", "rsa_bits": 3072,
                    "public_key": str(self.public), "spki_sha256": "a" * 64, "pem_sha256": payload.digest(self.public.read_bytes()),
                    "initial_enrollment_sha256": payload.digest((self.state / "initial-enrollment.json").read_bytes())})
        for mocker in (patch.object(updates, "require_linux_root"), patch.object(updates, "trusted_file", side_effect=lambda value: value),
                       patch("nebulalog_manager.update_enrollment._tree"), patch("nebulalog_manager.update_enrollment.ROOT_UID", os.getuid()),
                       patch.object(dispatch, "run_hook", side_effect=self.hook)):
            mocker.start(); self.addCleanup(mocker.stop)
        self.maintenance.unlink()
        self.calls = []
        self.fail = None
        self.crash = None
        self.omit_host = False
        self.fail_evidence = None
        self.manager = updates.UpdateManager(self.state, self.root / "unused-hooks", self.runner)

    def sign(self):
        (self.bundle / "manifest.json").write_bytes(payload.encoded(self.manifest))
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.private), "-sigopt", "rsa_padding_mode:pss",
                        "-sigopt", "rsa_pss_saltlen:32", "-out", str(self.bundle / "manifest.sig"), str(self.bundle / "manifest.json")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def runner(self, argv, **kwargs):
        if argv[0] == "openssl": return run(argv, **kwargs)
        # Legacy OCI-only hooks are inert fixtures, also covered independently by
        # the existing manager tests. Host tests must use pinned dispatch instead.
        name = Path(argv[0]).name
        result = {"ok": True}
        self.calls.append((name, "legacy", None))
        if name == "update-backup": result.update(postgresql=True, configuration=True)
        if name == "update-health": result["checks"] = {key: True for key in updates.REQUIRED_CHECKS}
        if self.fail == name: raise Refused("fixture failure")
        return json.dumps(result)

    def hook(self, pin, name, stage):
        command = dispatch.hook_command(pin, name, stage)
        tx, manifest = dispatch.transaction_binding(stage)
        self.calls.append((name, pin["generation"], tx["state"]))
        self.assertEqual(command[-3], str(self.generations / self.old["generation"]))
        if self.crash == name: raise PowerLoss()
        if self.fail == name: raise Refused("fixture hook failure")
        result = {"ok": True}
        plan_path = stage / "host-runtime-plan.json"
        if not plan_path.exists():
            atomic_json(plan_path, {"fixture": "lifecycle evidence only", "sequence": tx["sequence"]})
        if name == "update-backup":
            atomic_json(self.maintenance, {"active": True})
            result.update(postgresql=True, configuration=True)
        if name == "update-health": result["checks"] = {key: True for key in updates.REQUIRED_CHECKS}
        selected = activation.selection()
        identity = self.new if selected["generation"] == self.new["generation"] else self.old
        checks = {key: True for key in updates.HOST_PHASE_CHECKS[name]}
        if self.fail_evidence == name and tx["state"] not in {"rolling_back", "rolled_back", "recovery_required"}:
            checks[next(iter(checks))] = False
        if not self.omit_host:
            result["host"] = {"schema": 1, "abi": 1, "generation": identity["generation"],
                "host_source_sha256": identity["host_source_sha256"], "coordinator_generation": self.old["generation"],
                "candidate_generation": self.new["generation"], "checks": checks,
                "plan_sha256": payload.digest(plan_path.read_bytes())}
        if name == "update-finalize": self.maintenance.unlink(missing_ok=True)
        return result

    def install(self):
        return self.manager.install(self.bundle / "manifest.json", self.bundle / "manifest.sig", self.bundle, self.public)

    def retained(self):
        return Path(self.manager.status()["transaction"]["release"])


class HostSignatureTests(HostUpdateFixture):
    def verify(self, **kwargs):
        return updates.verify_release(self.bundle / "manifest.json", self.bundle / "manifest.sig", self.public, self.bundle,
            current_sequence=9, current_versions={"host": "0.1.0", "nebulalog": "0.1.0"}, now=datetime(2026, 9, 9, tzinfo=timezone.utc), **kwargs)

    def test_signed_host_bundle_and_metadata_only_contract(self):
        self.assertTrue(self.verify()["artifacts_verified"])
        (self.bundle / "host.tar").unlink()
        self.assertFalse(self.verify(metadata_only=True)["artifacts_verified"])
        with self.assertRaises(Refused): self.verify()

    def test_strict_host_contract_refuses_extra_hooks_abi_paths_and_source_mismatch(self):
        original = copy.deepcopy(self.manifest)
        for field, value in (("hook", "arbitrary"), ("abi", True), ("abi", 2), ("rollback_safe", False),
                             ("artifact", "manifest.json"), ("host_source_sha256", "a" * 64),
                             ("version", "0.1.2"), ("from_versions", [True])):
            self.manifest = copy.deepcopy(original)
            self.manifest["components"]["host"][field] = value
            self.sign()
            with self.subTest(field=field), self.assertRaises(Refused): self.verify()
        self.manifest = copy.deepcopy(original)
        self.manifest["components"]["nebulalog"]["artifact"] = "host.tar"
        self.sign()
        with self.assertRaises(Refused): self.verify()

    def test_signature_and_inner_archive_tamper_are_refused(self):
        (self.bundle / "manifest.json").write_bytes((self.bundle / "manifest.json").read_bytes() + b" ")
        with self.assertRaises(Refused): self.verify()
        self.sign()
        raw = bytearray((self.bundle / "host.tar").read_bytes()); raw[-1] = 1
        (self.bundle / "host.tar").write_bytes(raw)
        self.manifest["artifacts"][0]["sha256"] = payload.digest(raw)
        self.sign()
        with self.assertRaises(Refused): self.verify()


class HostEngineTests(HostUpdateFixture):
    def test_status_recovery_action_tracks_durable_state_and_prioritizes_os_recovery(self):
        for state in ("preflight", "preparing", "activating", "checking", "rolling_back", "recovery_required", "committed", "rolled_back", "preflight_failed"):
            for finalization in ("pending", "complete"):
                transaction = {"state": state, "finalization": finalization}
                atomic_json(self.state / "transaction.json", transaction)
                expected = None if state == "preflight_failed" else "nebulalog update finalize" if state in {"committed", "rolled_back"} and finalization != "complete" else None if state in {"committed", "rolled_back"} else "nebulalog update recover"
                with self.subTest(state=state, finalization=finalization):
                    self.assertEqual(self.manager.status()["recovery_action"], expected)
                    atomic_json(self.state.parent / "os-transaction.json", {"state": "reboot_requested"})
                    status = self.manager.status()
                    self.assertIsNone(status["recovery_action"])
                    self.assertEqual(status["recovery_blocked_by"], "os_update" if expected else None)
                    (self.state.parent / "os-transaction.json").unlink()

    def test_only_bound_allowlisted_host_refusal_is_retained_without_exception_text(self):
        expected = {"schema": 1, "reason": "qualified_migration_required", "resource": "bin/nebulalog",
                    "sequence": 10, "manifest_sha256": payload.digest((self.bundle / "manifest.json").read_bytes())}
        def refuse(pin, name, stage):
            atomic_json(stage / "host-refusal.json", expected)
            raise Refused("private fixture exception must never enter transaction")
        with patch.object(dispatch, "run_hook", side_effect=refuse), self.assertRaises(Refused): self.install()
        transaction = self.manager.status()["transaction"]
        self.assertEqual(transaction["host_refusal"], expected)
        self.assertNotIn("private fixture", json.dumps(transaction))
        self.assertEqual(transaction["state"], "preflight_failed")
        self.assertEqual(activation.selection()["generation"], self.old["generation"])
        for change in ({"resource": "/etc/shadow"}, {"reason": "private fixture"}, {"extra": "private fixture"},
                       {"sequence": True}, {"sequence": 9}, {"manifest_sha256": "0" * 64}, {"schema": True}):
            invalid = {**expected, **change}
            atomic_json(self.retained() / "host-refusal.json", invalid)
            observed = {key: value for key, value in transaction.items() if key != "host_refusal"}
            self.manager._retain_host_refusal(observed, self.retained())
            self.assertNotIn("host_refusal", observed)

    def test_combined_update_commits_normalized_generation_after_all_host_evidence(self):
        result = self.install()
        self.assertEqual(result["state"], "committed")
        self.assertEqual(result["finalization"], "complete")
        self.assertEqual(self.manager.status()["current"]["components"]["host"], self.new)
        self.assertEqual(activation.selection(), {"schema": 1, "generation": self.new["generation"], "sequence": 10})
        self.assertTrue(all(pin == self.old["generation"] for _, pin, _ in self.calls))
        self.assertEqual([name for name, _, _ in self.calls], list(updates.HOST_PHASE_CHECKS)[:4] + ["update-health", "update-finalize"])
        self.assertFalse(self.maintenance.exists())

    def test_missing_preflight_host_capability_refuses_before_backup_and_selection(self):
        self.omit_host = True
        with self.assertRaisesRegex(Refused, "measured runtime"): self.install()
        self.assertEqual([name for name, _, _ in self.calls], ["update-preflight"])
        self.assertEqual(self.manager.status()["transaction"]["state"], "preflight_failed")
        self.assertEqual(activation.selection()["generation"], self.old["generation"])
        self.assertEqual(self.manager.status()["current"], self.initial)

    def test_failed_runtime_provenance_restores_old_generation_and_rejects_replay(self):
        self.fail_evidence = "update-health"
        with self.assertRaisesRegex(Refused, "previous application restored"): self.install()
        status = self.manager.status()
        self.assertEqual(status["transaction"]["state"], "rolled_back")
        self.assertEqual(status["transaction"]["finalization"], "complete")
        self.assertEqual(status["current"], {**self.initial, "sequence": 10})
        self.assertEqual(activation.selection(), {"schema": 1, "generation": self.old["generation"], "sequence": 10})
        calls = list(self.calls)
        with self.assertRaisesRegex(Refused, "Replay"): self.install()
        self.assertEqual(self.calls, calls)

    def test_finalization_failure_never_rolls_back_committed_host_and_retry_pins_old(self):
        self.fail = "update-finalize"
        with self.assertRaisesRegex(Refused, "maintenance release failed"): self.install()
        self.assertNotIn("update-rollback", [name for name, _, _ in self.calls])
        self.assertEqual(self.manager.status()["current"]["components"]["host"], self.new)
        self.assertTrue(self.maintenance.exists())
        self.fail = None
        before = len(self.calls)
        self.assertEqual(self.manager.finalize(self.public)["finalization"], "complete")
        self.assertEqual([name for name, _, _ in self.calls[before:]], ["update-health", "update-finalize"])
        self.assertTrue(all(pin == self.old["generation"] for _, pin, _ in self.calls))

    def test_interrupted_activation_recovers_without_candidate_archive_or_code(self):
        self.crash = "update-activate"
        with self.assertRaises(PowerLoss): self.install()
        self.assertEqual(self.manager.status()["transaction"]["state"], "activating")
        self.assertEqual(activation.selection()["generation"], self.new["generation"])
        self.corrupt_generation(self.new)
        (self.retained() / "host.tar").unlink()
        self.crash = None
        result = self.manager.recover(self.public)
        self.assertEqual(result["state"], "rolled_back")
        self.assertEqual(result["finalization"], "complete")
        self.assertEqual(self.manager.status()["current"], {**self.initial, "sequence": 10})
        self.assertEqual(activation.selection()["generation"], self.old["generation"])

    def test_crash_before_host_preparation_journal_recovers_still_selected_previous(self):
        with patch.object(activation, "prepare", side_effect=PowerLoss), self.assertRaises(PowerLoss): self.install()
        self.assertFalse((self.retained() / "host-activation.json").exists())
        self.assertEqual(self.manager.status()["transaction"]["state"], "preparing")
        self.assertEqual(self.manager.recover(self.public)["state"], "rolled_back")
        self.assertEqual(activation.selection()["sequence"], 10)

    def test_failed_rollback_retains_recovery_gate_until_verified_recovery(self):
        self.fail_evidence = "update-health"
        self.fail = "update-rollback"
        with self.assertRaisesRegex(Refused, "recovery is required"): self.install()
        self.assertEqual(self.manager.status()["transaction"]["state"], "recovery_required")
        self.assertTrue(self.maintenance.exists())
        with self.assertRaisesRegex(Refused, "requires recovery"): self.install()
        self.fail = self.fail_evidence = None
        self.assertEqual(self.manager.recover(self.public)["state"], "rolled_back")

    def test_operator_rollback_restores_host_and_preserves_high_water(self):
        self.install()
        self.assertEqual(self.manager.rollback(self.public)["state"], "rolled_back")
        self.assertEqual(self.manager.status()["current"], {**self.initial, "sequence": 10})
        self.assertEqual(activation.selection(), {"schema": 1, "generation": self.old["generation"], "sequence": 10})

    def test_corrupted_previous_generation_never_executes_hooks_or_changes_selection(self):
        self.corrupt_generation(self.old)
        with self.assertRaises(Refused): self.install()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.manager.status()["current"], self.initial)

    def test_recovery_refuses_committed_state_and_tampered_retained_signature(self):
        self.install()
        with self.assertRaisesRegex(Refused, "No interrupted"): self.manager.recover(self.public)
        tx = self.manager.status()["transaction"]
        tx["state"] = "recovery_required"
        atomic_json(self.state / "transaction.json", tx)
        path = self.retained() / "manifest.sig"
        path.write_bytes(b"invalid fixture")
        calls = list(self.calls)
        with self.assertRaises(Refused): self.manager.recover(self.public)
        self.assertEqual(self.calls, calls)

    def test_oci_only_host_enrolled_release_is_refused_before_any_hook_or_selection_write(self):
        self.manifest["components"].pop("host")
        self.manifest["artifacts"] = self.manifest["artifacts"][1:]
        self.sign()
        before = self.selection.read_bytes()
        with self.assertRaisesRegex(Refused, "versioned host bundle"): self.install()
        self.assertEqual(self.selection.read_bytes(), before)
        self.assertEqual(self.manager.status()["current"], self.initial)
        self.assertEqual(self.calls, [])
        self.assertIsNone(self.manager.status()["transaction"])

    def test_legacy_no_host_oci_release_retains_existing_update_behavior(self):
        self.manifest["components"].pop("host")
        self.manifest["artifacts"] = self.manifest["artifacts"][1:]
        self.sign()
        self.initial["components"].pop("host")
        atomic_json(self.state / "current.json", self.initial)
        enrolled = json.loads((self.state / "initial-enrollment.json").read_text())
        enrolled["current"] = self.initial
        atomic_json(self.state / "initial-enrollment.json", enrolled)
        trust = json.loads((self.state / "publisher-trust.json").read_text())
        trust["initial_enrollment_sha256"] = payload.digest((self.state / "initial-enrollment.json").read_bytes())
        atomic_json(self.state / "publisher-trust.json", trust)
        self.assertEqual(self.install()["state"], "committed")
        self.assertTrue(all(pin == "legacy" for _, pin, _ in self.calls))
        self.assertNotIn("host", self.manager.status()["current"]["components"])

    def test_power_loss_after_current_write_before_commit_journal_recovers_previous(self):
        def write(path, value):
            if path == self.state / "transaction.json" and value.get("state") == "committed":
                raise PowerLoss()
            atomic_json(path, value)
        with patch.object(updates, "atomic_json", side_effect=write), self.assertRaises(PowerLoss): self.install()
        self.assertEqual(self.manager.status()["current"]["components"]["host"], self.new)
        self.assertEqual(self.manager.status()["transaction"]["state"], "checking")
        self.assertEqual(self.manager.recover(self.public)["state"], "rolled_back")
        self.assertEqual(self.manager.status()["current"], {**self.initial, "sequence": 10})

    def test_rollback_finalization_does_not_require_damaged_candidate_bytes(self):
        self.fail_evidence = "update-health"
        self.fail = "update-finalize"
        with self.assertRaisesRegex(Refused, "maintenance release failed"): self.install()
        self.assertEqual(self.manager.status()["transaction"]["state"], "rolled_back")
        (self.retained() / "host.tar").unlink()
        self.corrupt_generation(self.new)
        self.fail = None
        self.assertEqual(self.manager.finalize(self.public)["finalization"], "complete")


class HostGitHubTests(HostUpdateFixture):
    poll = github_fixtures.PollTests.poll

    def setUp(self):
        super().setUp()
        self.policy = {"schema": 1, "repository": "stellaraf/captains-log", "automatic_updates": True, "poll_interval_seconds": 900}
        self.now = datetime(2026, 9, 9, 20, 11, tzinfo=timezone.utc)
        for mocker in (patch.object(github, "require_linux_root"), patch.object(github, "_tree")):
            mocker.start(); self.addCleanup(mocker.stop)
        self.release = {"id": 123, "draft": False, "prerelease": False, "tag_name": "v0.1.1", "assets": []}
        self.bodies = {}
        for identity, name in enumerate(("manifest.json", "manifest.sig", "host.tar", "app.tar"), 1):
            self.bodies[identity] = (self.bundle / name).read_bytes()
            self.release["assets"].append({"id": identity, "name": name, "state": "uploaded", "size": len(self.bodies[identity])})

    def test_github_downloads_signed_combined_release_and_does_not_reactivate_current(self):
        self.assertEqual(self.poll()["status"], "installed")
        self.assertEqual(self.manager.status()["current"]["components"]["host"], self.new)
        self.assertEqual(self.poll()["status"], "up_to_date")
        self.assertEqual(sum(name == "update-activate" for name, _, _ in self.calls), 1)
        self.assertEqual(len(self.transport_calls.requests), 3)

    def test_rolled_back_host_release_is_not_automatically_retried(self):
        self.fail_evidence = "update-health"
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(self.manager.status()["transaction"]["state"], "rolled_back")
        self.assertEqual(self.poll()["reason"], "release_rolled_back")
        self.assertEqual(sum(name == "update-activate" for name, _, _ in self.calls), 1)
        self.assertEqual(len(self.transport_calls.requests), 3)

    def test_missing_host_enrollment_version_refuses_before_artifact_download(self):
        current = {**self.initial, "sequence": 10, "components": {**self.initial["components"]}}
        current["components"].pop("host")
        atomic_json(self.state / "current.json", current)
        self.manifest["sequence"] = 11
        self.sign()
        for item in self.release["assets"][:2]:
            self.bodies[item["id"]] = (self.bundle / item["name"]).read_bytes()
            item["size"] = len(self.bodies[item["id"]])
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(len(self.transport_calls.requests), 3)
        self.assertEqual(self.calls, [])

    def test_host_enrolled_oci_only_github_release_refuses_before_artifact_download(self):
        self.manifest["components"].pop("host")
        self.manifest["artifacts"] = self.manifest["artifacts"][1:]
        self.sign()
        for item in self.release["assets"][:2]:
            self.bodies[item["id"]] = (self.bundle / item["name"]).read_bytes()
            item["size"] = len(self.bodies[item["id"]])
        self.assertEqual(self.poll()["status"], "blocked")
        self.assertEqual(len(self.transport_calls.requests), 3)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.manager.status()["current"], self.initial)


if __name__ == "__main__":
    unittest.main()
