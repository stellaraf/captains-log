"""Guarded console tests use private fixtures; no host service or AIDE execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import firstboot, host_job_storage, setup_integrity
from nebulalog_manager.aide import RUNTIME_STAGES
from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager.host_job_storage import StorageIdentity
import test_aide_lifecycle as lifecycle
import test_firstboot as firstboot_fixtures
from test_firstboot import CONFIG


class IntegrityConsoleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = lifecycle.AideLifecycleTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.output = []
        self.guard = Mock()
        self.ready = Mock(return_value={"installation_id": lifecycle.INSTALLATION})

    def invoke(self, actions, **kwargs):
        answers = iter(actions)
        def read(prompt):
            answer = next(answers)
            if answer == "MATCHING_DIGEST":
                return self.fixture.record("candidate.json")["confirmation"]
            if isinstance(answer, BaseException):
                raise answer
            return answer
        return setup_integrity.integrity_console(object(), integrity=self.fixture.manager, read=read,
                                                write=self.output.append, guard=self.guard, ready=self.ready, **kwargs)

    def test_back_or_missing_prerequisite_never_initializes(self):
        self.invoke(["BACK"])
        self.assertFalse(self.fixture.state.exists())
        self.ready.side_effect = Refused("PRIVATE prerequisite detail")
        result = self.invoke(["PREPARE"])
        self.assertEqual(result["state"], "prerequisite-unavailable")
        self.assertEqual(self.fixture.calls, [])
        self.assertFalse(self.fixture.state.exists())
        self.assertNotIn("PRIVATE", "\n".join(self.output))

    def test_explicit_prepare_review_full_digest_enroll_and_check_use_real_methods(self):
        self.invoke(["PREPARE", "REVIEW", "ENROLL", "MATCHING_DIGEST", "CHECK", "STATUS", "BACK"])
        self.assertTrue(self.fixture.marker.exists())
        self.assertEqual(sum(call[-1] == "--init" for call in self.fixture.calls), 1)
        self.assertEqual(self.fixture.manager.firstboot_checks(lifecycle.INSTALLATION),
                         {"aide_enrolled": True, "aide_checked_clean": True})
        output = "\n".join(self.output)
        for expected in ("Review confirmation SHA-256", "Database SHA-256", "Original clean verification", "CLEAN", "total:"):
            self.assertIn(expected, output)
        self.assertNotIn(lifecycle.SECRET, output)
        self.assertNotIn('"stdout"', output)

    def test_enroll_requires_review_in_this_console_and_exact_typed_digest(self):
        self.fixture.manager.prepare()
        with patch.object(self.fixture.manager, "enroll", wraps=self.fixture.manager.enroll) as enroll:
            self.invoke(["ENROLL", "REVIEW", "ENROLL", "0" * 64, "ENROLL", "CANCEL", "BACK"])
            enroll.assert_not_called()
        self.assertFalse(self.fixture.marker.exists())
        self.assertIn("Choose REVIEW first", "\n".join(self.output))

    def test_review_resumes_existing_candidate_without_initializing_and_check_never_rebaselines(self):
        candidate = self.fixture.manager.prepare()
        self.fixture.calls.clear()
        with patch.object(self.fixture.manager, "prepare", side_effect=AssertionError("REVIEW must not initialize")):
            self.invoke(["REVIEW", "ENROLL", "MATCHING_DIGEST", "BACK"])
        before = (self.fixture.state / "aide.db.gz").read_bytes()
        self.fixture.check_code = 4
        self.invoke(["CHECK", "BACK"])
        self.assertEqual((self.fixture.state / "aide.db.gz").read_bytes(), before)
        self.assertEqual(self.fixture.record("candidate.json")["confirmation"], candidate["confirmation"])
        self.assertFalse(any(call[-1] == "--init" for call in self.fixture.calls))
        self.assertIn("DIFFERENCES", "\n".join(self.output))

    def test_candidate_change_after_review_refuses_enrollment(self):
        self.fixture.manager.prepare()
        checks = 0
        def ready(_):
            nonlocal checks
            checks += 1
            if checks == 4:  # After REVIEW, ENROLL selection and its digest prompt.
                self.fixture.values["runtime_ready_sha256"] = "f" * 64
        self.ready.side_effect = ready
        self.invoke(["REVIEW", "ENROLL", "MATCHING_DIGEST", "BACK"])
        self.assertFalse(self.fixture.marker.exists())
        self.assertIn("could not be verified", "\n".join(self.output))

    def test_interrupt_during_confirmation_preserves_candidate_without_enrollment(self):
        self.fixture.manager.prepare()
        before = (self.fixture.state / "candidate.json").read_bytes()
        with self.assertRaises(KeyboardInterrupt):
            self.invoke(["REVIEW", "ENROLL", KeyboardInterrupt()])
        self.assertEqual((self.fixture.state / "candidate.json").read_bytes(), before)
        self.assertFalse(self.fixture.marker.exists())
        self.invoke(["REVIEW", "ENROLL", "MATCHING_DIGEST", "BACK"])
        self.assertTrue(self.fixture.marker.exists())

    def test_unknown_commands_and_private_errors_are_not_dispatched_or_echoed(self):
        self.invoke(["/bin/sh", "rm -rf /", "BACK"])
        self.assertEqual(self.fixture.calls, [])
        with patch.object(self.fixture.manager, "prepare", side_effect=ValueError(lifecycle.SECRET)):
            self.invoke(["PREPARE", "BACK"])
        self.assertNotIn(lifecycle.SECRET, "\n".join(self.output))
        self.assertNotIn("/bin/sh", "\n".join(self.output))

    def test_completed_or_nonlocal_console_cannot_enroll_after_wait(self):
        self.fixture.manager.prepare()
        count = 0
        def guard(_):
            nonlocal count
            count += 1
            if count == 4:
                raise Refused("Setup is no longer pending")
        self.guard.side_effect = guard
        with self.assertRaises(Refused):
            self.invoke(["REVIEW", "ENROLL", "MATCHING_DIGEST"])
        self.assertFalse(self.fixture.marker.exists())

    def test_malformed_review_values_never_reach_terminal(self):
        self.fixture.manager.prepare()
        review = self.fixture.manager.review()
        review["facts"]["aide_package"] = "\x1b[2J" + lifecycle.SECRET
        with patch.object(self.fixture.manager, "review", return_value=review):
            self.invoke(["REVIEW", "BACK"])
        self.assertNotIn(lifecycle.SECRET, "\n".join(self.output))
        self.assertNotIn("\x1b", "\n".join(self.output))


class RuntimeResumeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.paths = firstboot.Locations(self.root / "etc", self.root / "data", self.root / "run")
        for directory in (self.paths.bootstrap, self.paths.data / "configuration/bootstrap", self.paths.runtime):
            directory.mkdir(parents=True, mode=0o700)
        self.paths.data.chmod(0o700)
        self.config = copy.deepcopy(CONFIG)
        self.gate = {"host_ready": True, "setup_complete": False, "installation_id": lifecycle.INSTALLATION}
        self.journal = {"installation_id": lifecycle.INSTALLATION, "config_sha256": firstboot._digest(self.config)}
        self.receipt = {"schema": 1, "state": "runtime-ready", "installation_id": lifecycle.INSTALLATION,
                        "https_url": "https://" + self.config["hostname"], "tls_certificate_sha256": "a" * 64,
                        "checks": dict.fromkeys(firstboot.RUNTIME_CHECKS, True)}
        self.state = {"schema": 1, "installation_id": lifecycle.INSTALLATION, "completed": sorted(RUNTIME_STAGES),
                      "active_stage": None, "identity_initialized": True}
        self.setup = {"installation_id": lifecycle.INSTALLATION, "hostname": self.config["hostname"], "baseline": self.config["baseline"]}
        self.manager = SimpleNamespace(paths=self.paths, journal_path=self.paths.bootstrap / "journal.json", gate=Mock(side_effect=lambda: self.gate))
        for target, value in (("nebulalog_manager.host_job_storage.ROOT_UID", os.getuid()),
                              ("nebulalog_manager.setup_integrity._private_json", self.read)):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch("subprocess.Popen", side_effect=AssertionError("No host commands"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.save()

    def save(self):
        for path, value in ((self.manager.journal_path, self.journal),
                            (self.paths.bootstrap / "runtime-ready.json", self.receipt),
                            (self.paths.data / "configuration/bootstrap/runtime-state.json", self.state),
                            (self.paths.data / "configuration/bootstrap/setup.json", self.setup)):
            atomic_json(path, value)

    def read(self, path, *, device=None):
        self.assertTrue(path.is_relative_to(self.root))
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise Refused("unsafe fixture file")
        if path.is_relative_to(self.paths.data):
            self.assertEqual(device, self.paths.data.stat().st_dev)
        return json.loads(path.read_bytes())

    def snapshot(self):
        return {str(path): (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
                for path in self.root.rglob("*") if path.is_file()}

    def test_complete_runtime_is_verified_and_reused_without_writes(self):
        before = self.snapshot()
        result = setup_integrity.resume_runtime(self.manager, self.config)
        self.assertEqual(result["https_url"], self.receipt["https_url"])
        self.assertEqual(result["installation_id"], lifecycle.INSTALLATION)
        self.assertEqual(self.snapshot(), before)
        self.manager.gate.assert_called_once()

    def test_receipt_presence_does_not_replace_actual_foundation_or_identity(self):
        self.gate["host_ready"] = False
        with self.assertRaises(Refused):
            setup_integrity.resume_runtime(self.manager, self.config)
        self.gate["host_ready"] = True
        self.receipt["installation_id"] = "4fa9e372-985d-47eb-85e7-bf7010903a13"
        self.save()
        with self.assertRaises(Refused):
            setup_integrity.resume_runtime(self.manager, self.config)

    def test_partial_runtime_resumes_only_without_any_integrity_state(self):
        self.state.update(active_stage="edge", completed=["directories"])
        self.save()
        self.assertIsNone(setup_integrity.resume_runtime(self.manager, self.config))
        (self.paths.data / "manager/aide").mkdir(parents=True, mode=0o700)
        before = self.snapshot()
        with self.assertRaisesRegex(Refused, "automatic reprovisioning is refused"):
            setup_integrity.resume_runtime(self.manager, self.config)
        self.assertEqual(self.snapshot(), before)

    def test_missing_runtime_receipt_cannot_restart_aide_initialization(self):
        (self.paths.bootstrap / "runtime-ready.json").unlink()
        self.assertIsNone(setup_integrity.resume_runtime(self.manager, self.config))
        (self.paths.data / "manager").mkdir(mode=0o700)
        (self.paths.data / "manager/aide-enrollment.json").symlink_to(self.root / "absent")
        with self.assertRaisesRegex(Refused, "automatic reprovisioning is refused"):
            setup_integrity.resume_runtime(self.manager, self.config)

    def test_changed_configuration_unsafe_receipt_or_unknown_stage_is_not_reprovisioned(self):
        for change in (lambda: self.journal.update(config_sha256="0" * 64),
                       lambda: self.state.update(completed=["unknown-stage"]),
                       lambda: self.receipt.update(https_url="https://secret@example.test"),
                       lambda: self.receipt.update(tls_certificate_sha256="\x1b[2JPRIVATE")):
            original = copy.deepcopy((self.journal, self.state, self.receipt))
            change()
            self.save()
            before = self.snapshot()
            with self.assertRaises(Refused):
                setup_integrity.resume_runtime(self.manager, self.config)
            self.assertEqual(self.snapshot(), before)
            self.journal, self.state, self.receipt = original
        self.save()
        (self.paths.bootstrap / "runtime-ready.json").chmod(0o644)
        with self.assertRaises(Refused):
            setup_integrity.resume_runtime(self.manager, self.config)

    def test_wizard_runtime_resume_never_reapplies_or_reprovisions(self):
        self.manager._host = Mock()
        self.manager.status = Mock(return_value={"setup_complete": False, "state": "runtime-ready"})
        self.manager.config = Mock(return_value=self.config)
        self.manager.plan = self.manager.apply = self.manager.provision = self.manager.runner = Mock(side_effect=AssertionError("Resume must not mutate runtime"))
        with patch("nebulalog_manager.console.local_console"), patch.object(firstboot, "_runtime_console", return_value={"state": "runtime-ready"}) as console, \
                patch.object(firstboot, "_private_dir", side_effect=AssertionError("Resume must not create directories")), \
                patch.object(firstboot, "_password_file", side_effect=AssertionError("Resume must not recreate credentials")), patch("builtins.print"):
            self.assertEqual(firstboot.wizard(self.manager), {"state": "runtime-ready"})
        console.assert_called_once()
        self.manager.runner.assert_not_called()


class FirstbootIntegrityMutationGuardTests(unittest.TestCase):
    def setUp(self):
        self.fixture = firstboot_fixtures.TransactionTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.apply()
        (self.fixture.paths.data / "manager/aide").mkdir(parents=True, mode=0o700)

    def test_apply_and_provision_refuse_before_writes_or_commands(self):
        manager = self.fixture.manager
        with patch.object(firstboot, "_private_dir", side_effect=AssertionError("No mkdir before refusal")), \
                patch.object(firstboot, "locked", side_effect=AssertionError("No new lock before refusal")), \
                patch.object(manager, "runner", side_effect=AssertionError("No commands")), \
                patch.object(manager, "gate", return_value={"installation_id": lifecycle.INSTALLATION}), \
                patch.object(firstboot, "atomic_json", side_effect=AssertionError("No record writes")):
            with self.assertRaisesRegex(Refused, "File-integrity state already exists"):
                manager.apply(CONFIG, "0" * 64)
            with self.assertRaisesRegex(Refused, "File-integrity state already exists"):
                manager.provision()

    def test_integrity_created_after_early_check_is_rechecked_under_lock(self):
        manager = self.fixture.manager
        (self.fixture.paths.data / "manager/aide").rmdir()
        with patch.object(setup_integrity, "_integrity_state_exists", side_effect=[False, True]), \
                patch.object(manager, "_runtime_receipt", side_effect=AssertionError("No adapter after concurrent AIDE")), \
                patch.object(manager, "gate", return_value={"installation_id": lifecycle.INSTALLATION}):
            with self.assertRaisesRegex(Refused, "File-integrity state already exists"):
                manager.provision()


class PolicyPrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RuntimeResumeTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.identity = StorageIdentity(lifecycle.INSTALLATION, self.fixture.paths.data, self.fixture.paths.data.stat().st_dev)
        self.path = self.identity.root / "configuration/security-policy.json"
        self.policy = {"schema": 1, "installation_id": lifecycle.INSTALLATION, "baseline": self.fixture.config["baseline"]}
        atomic_json(self.path, self.policy)
        self.validator = Mock(return_value=self.policy)
        patches = [patch("nebulalog_manager.aide.runtime_storage", return_value=self.identity),
                   patch("nebulalog_manager.aide.protected_bytes", side_effect=self.read),
                   patch("nebulalog_manager.baseline.validate_policy", self.validator)]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def read(self, path, **kwargs):
        self.assertTrue(kwargs["private"])
        return json.dumps(self.fixture.read(path, device=kwargs.get("device"))).encode()

    def test_existing_installation_policy_is_actually_validated_without_writes(self):
        before = self.fixture.snapshot()
        value = setup_integrity.prerequisites(self.fixture.manager)
        self.assertEqual(value["installation_id"], lifecycle.INSTALLATION)
        self.assertEqual(value["baseline"], self.policy["baseline"])
        self.validator.assert_called_once_with(self.policy)
        self.assertEqual(self.fixture.snapshot(), before)

    def test_missing_mismatched_or_unreviewed_policy_cannot_be_substituted_by_baseline_name(self):
        self.policy["installation_id"] = "4fa9e372-985d-47eb-85e7-bf7010903a13"
        atomic_json(self.path, self.policy)
        with self.assertRaises(Refused):
            setup_integrity.prerequisites(self.fixture.manager)
        self.validator.assert_not_called()
        self.policy["installation_id"] = lifecycle.INSTALLATION
        atomic_json(self.path, self.policy)
        self.validator.side_effect = Refused("Content review not approved")
        with self.assertRaises(Refused):
            setup_integrity.prerequisites(self.fixture.manager)
        self.path.unlink()
        with self.assertRaises(OSError):
            setup_integrity.prerequisites(self.fixture.manager)


class RuntimeConsoleDispatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.manager = SimpleNamespace(paths=SimpleNamespace(runtime=self.path), complete=Mock(return_value={"setup_complete": True}))
        self.receipt = {"https_url": "https://logs.example.test", "tls_certificate_sha256": "a" * 64}
        self.config = {"hostname": "logs.example.test"}

    def test_wizard_menu_dispatches_integrity_and_returns_without_finalizing(self):
        with patch.object(firstboot, "_answer", side_effect=["FILE INTEGRITY", "LATER"]), patch("builtins.print"), \
                patch.object(setup_integrity, "pending_console"), patch.object(setup_integrity, "integrity_console") as menu:
            result = firstboot._runtime_console(self.manager, self.config, self.receipt)
        menu.assert_called_once_with(self.manager)
        self.assertFalse(result["setup_complete"])
        self.manager.complete.assert_not_called()
        self.assertEqual(list(self.path.iterdir()), [])

    def test_final_verification_uses_fixed_private_input_and_always_removes_it(self):
        def password(path, prompt):
            self.assertEqual(path, self.path / "setup-recovery-verification")
            path.write_bytes(b"private test recovery value")
        for error in (None, Refused("Final checks incomplete"), KeyboardInterrupt()):
            self.manager.complete.side_effect = error
            with patch.object(firstboot, "_answer", return_value="VERIFY"), patch("builtins.print"), \
                    patch.object(setup_integrity, "pending_console"), patch.object(firstboot, "_password_file", side_effect=password):
                if error:
                    with self.assertRaises(type(error)):
                        firstboot._runtime_console(self.manager, self.config, self.receipt)
                else:
                    self.assertEqual(firstboot._runtime_console(self.manager, self.config, self.receipt), {"setup_complete": True})
            self.assertEqual(list(self.path.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
