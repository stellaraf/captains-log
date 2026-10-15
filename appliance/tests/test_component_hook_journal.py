"""Real private execution journals and inert child commands; no service mutation."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager.common import Refused, atomic_json
from nebulalog_manager import host_dispatch as dispatch, host_payload as payload
from nebulalog_adapters.commands import Commands
from nebulalog_adapters.lifecycle import Lifecycle


class HookJournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stage = self.root / "updates/releases/2-fixture"
        self.stage.mkdir(parents=True, mode=0o700)
        atomic_json(self.stage / "manifest.json", {"sequence": 2, "components": {}})
        self.transaction = {"hook_protocol": 1, "sequence": 2, "state": "preflight",
            "release": str(self.stage), "previous": {"sequence": 1, "components": {}},
            "manifest_sha256": payload.digest((self.stage / "manifest.json").read_bytes())}
        atomic_json(self.stage.parent.parent / "transaction.json", self.transaction)
        # Linux acceptance runs as root. This seam permits pure journal tests on
        # macOS while retaining exact record bytes/hashes/path validation.
        for mocker in (patch.object(payload, "_OWNER_UID", os.getuid()),
                       patch.object(dispatch, "trusted_file", side_effect=lambda path: path)):
            mocker.start(); self.addCleanup(mocker.stop)
        self.journal = dispatch.HookJournal(self.stage, self.transaction)

    def enter(self, name="update-preflight"):
        ref = self.journal.begin(name, {"fixture": "fixed trusted dispatcher"})
        self.assertEqual(self.journal.enter(name), ref)
        return ref

    def test_dispatch_without_terminal_is_never_settled_or_reentered(self):
        ref = self.enter()
        for operation in (self.journal.assert_settled,
                          lambda: self.journal.begin("update-backup", {}),
                          lambda: self.journal.enter("update-preflight"),
                          lambda: self.journal.successful_result(ref, {"ok": True})):
            with self.subTest(operation=operation), self.assertRaises(Refused):
                operation()

    def test_exact_success_and_known_failed_terminal_allow_next_hook(self):
        first = self.enter()
        result = {"ok": True, "checks": {"fixture": True}}
        self.journal.finish(first, "success", result=result)
        self.journal.successful_result(first, result)
        with self.assertRaises(Refused):
            self.journal.successful_result(first, {"ok": True})
        second = self.enter("update-backup")
        self.journal.finish(second, "failed")
        self.assertEqual(self.journal.assert_settled(), 2)
        with self.assertRaises(Refused):
            self.journal.successful_result(second, {"ok": True})

    def test_unknown_native_command_cannot_be_hidden_by_terminal_or_json_success(self):
        ref = self.enter()
        self.journal.command_event(ref, "dispatch", "call", argv=["fixed", "synthetic-private-value"])
        with self.assertRaisesRegex(Refused, "native command lacks"):
            self.journal.finish(ref, "success", result={"ok": True})
        with self.assertRaisesRegex(Refused, "native command lacks"):
            self.journal.command_event(ref, "dispatch", "call", argv=["must-not-run"])
        self.assertFalse(self.journal._path(ref["id"], "terminal").exists())
        for path in self.stage.glob("component-command-*"):
            self.assertNotIn(b"synthetic-private-value", path.read_bytes())

    def test_native_completion_binds_hook_kind_hash_and_terminal_digest(self):
        ref = self.enter()
        ticket = self.journal.command_event(ref, "dispatch", "capture", argv=["fixed"])
        for invalid in ({**ticket, "sha256": "0" * 64}, {**ticket, "id": "0" * 32}):
            with self.assertRaises((Refused, OSError)):
                self.journal.command_event(ref, "complete", "capture", ticket=invalid)
        with self.assertRaises(Refused):
            self.journal.command_event(ref, "complete", "call", ticket=ticket)
        self.journal.command_event(ref, "complete", "capture", ticket=ticket)
        self.journal.finish(ref, "success", result={"ok": True})
        with self.assertRaisesRegex(Refused, "no active"):
            self.journal.command_event(ref, "dispatch", "call", argv=["late"])
        completed = self.stage / ("component-command-" + ticket["id"] + "-complete.json")
        body = json.loads(completed.read_text()); body["success"] = 1
        completed.write_bytes(self.journal._encoded(body))
        with self.assertRaises(Refused):
            self.journal.assert_settled()

    def test_changed_owner_manifest_previous_and_coordinator_refuse(self):
        ref = self.enter()
        self.journal.finish(ref, "success", result={"ok": True})
        for field, value in (("sequence", 3), ("previous", {"sequence": 0}),
                             ("host_coordinator", {"generation": "a" * 64}),
                             ("hook_protocol", None), ("hook_protocol", True)):
            changed = {**self.transaction, field: value}
            with self.subTest(field=field), self.assertRaises(Refused):
                dispatch.HookJournal(self.stage, changed).assert_settled()
        (self.stage / "manifest.json").write_bytes(b"{}\n")
        with self.assertRaises(Refused):
            dispatch.HookJournal(self.stage, self.transaction)

    def test_torn_or_noncanonical_and_extra_evidence_refuse(self):
        ref = self.enter()
        self.journal.finish(ref, "success", result={"ok": True})
        terminal = self.journal._path(ref["id"], "terminal")
        original = terminal.read_bytes()
        terminal.write_bytes(original + b" ")
        with self.assertRaises(Refused): self.journal.assert_settled()
        terminal.write_bytes(original)
        unknown = self.stage / "component-hook-unrecognized.json"
        unknown.write_bytes(b"{}")
        with self.assertRaises(Refused): self.journal.assert_settled()
        unknown.unlink()
        self.journal._path(ref["id"], "entered").unlink()
        with self.assertRaises(OSError): self.journal.assert_settled()

    def test_limits_hold_before_another_dispatch(self):
        ref = self.enter()
        self.journal.finish(ref, "success", result={"ok": True})
        with patch.object(self.journal, "MAX_HOOKS", 1), self.assertRaises(Refused):
            self.journal.begin("update-backup", {})
        ref = self.enter("update-backup")
        with patch.object(self.journal, "MAX_COMMANDS", 0), self.assertRaises(Refused):
            self.journal.command_event(ref, "dispatch", "call", argv=["fixed"])

    def test_exact_readiness_nonzero_can_retry_but_changed_sql_signal_and_unknown_cannot(self):
        ref = self.enter()
        first = self.journal.command_event(ref, "dispatch", "call", argv=self.journal.POSTGRES_READY)
        self.journal.command_event(ref, "failed", "call", ticket=first, returncode=2)
        second = self.journal.command_event(ref, "dispatch", "call", argv=self.journal.POSTGRES_READY)
        self.journal.command_event(ref, "complete", "call", ticket=second)
        self.journal.finish(ref, "success", result={"ok": True})
        for label, argv, returncode in (("changed-query", self.journal.POSTGRES_READY[:-1] + ["DELETE FROM settings"], 2),
                                       ("signal", self.journal.POSTGRES_READY, -9),
                                       ("timeout", self.journal.POSTGRES_READY, None)):
            with self.subTest(case=label):
                # Separate private stage for each unresolved outcome.
                stage = self.stage.parent / ("2-" + label)
                stage.mkdir(mode=0o700)
                (stage / "manifest.json").write_bytes((self.stage / "manifest.json").read_bytes())
                journal = dispatch.HookJournal(stage, {**self.transaction, "release": str(stage)})
                hook = journal.begin("update-preflight", {})
                journal.enter("update-preflight")
                ticket = journal.command_event(hook, "dispatch", "call", argv=argv)
                if returncode is not None:
                    journal.command_event(hook, "failed", "call", ticket=ticket, returncode=returncode)
                with self.assertRaisesRegex(Refused, "native command lacks"):
                    journal.finish(hook, "failed")

    def lifecycle(self):
        manager = Lifecycle({}, Commands(), data=self.root, state=self.stage.parent.parent, guard=lambda: None)
        manager.release = lambda stage: ({"components": {}}, self.transaction)
        return manager

    def scap(self):
        directory = self.stage / "compliance-fixture"
        directory.mkdir(mode=0o700)
        output = directory / "results"
        output.mkdir(mode=0o700)
        source = self.root / "content.xml"
        source.write_text("<synthetic-content/>")
        source.chmod(0o600)
        profile = "xccdf_fixture_profile_stig"
        policy = directory / "security-policy.json"
        atomic_json(policy, {"assessments": [{"kind": "stig", "profile_id": profile,
            "datastream": str(source), "sha256": payload.digest(source.read_bytes()),
            "platform": "rocky9", "reviewed": True}]})
        argv = ["oscap", "xccdf", "eval", "--profile", profile, "--results", str(output / "stig.xml"),
                "--report", str(output / "stig.html"), str(source)]
        return policy, argv

    def test_scap_authority_refuses_remediation_changed_options_and_existing_output(self):
        policy, argv = self.scap()
        for invalid in (argv + ["--remediate"], argv[:5] + ["--report"] + argv[6:],
                        argv[:7] + ["--results"] + argv[8:]):
            with self.subTest(argv=invalid), self.assertRaises(Refused):
                self.journal.scap_authority(policy, invalid)
        Path(argv[6]).write_text("retained output cannot be replaced")
        with self.assertRaises(Refused):
            self.journal.scap_authority(policy, argv)

    def test_scap_semantic_ack_requires_actual_normal_return_record(self):
        policy, argv = self.scap()
        ref = self.enter()
        authority = self.journal.scap_authority(policy, argv)
        ticket = self.journal.command_event(ref, "dispatch", "call", argv=argv, scap=authority)
        Path(argv[6]).write_text('<Benchmark><TestResult start-time="2026-10-15T12:00:00Z" '
            'end-time="2026-10-15T12:00:01Z"><profile idref="' + argv[4] + '"/>'
            '<rule-result idref="xccdf_fixture_rule"><result>fail</result></rule-result>'
            '</TestResult></Benchmark>')
        Path(argv[8]).write_text("<html>synthetic findings</html>")
        with self.assertRaises((OSError, Refused)):
            self.journal.acknowledge_scap(ref, ticket, argv)
        self.assertFalse((self.stage / ("component-command-" + ticket["id"] + "-complete.json")).exists())
        self.journal.command_event(ref, "failed", "call", ticket=ticket, returncode=2)
        def private_directory(path):
            value = Path(path)
            self.assertTrue(value.is_relative_to(self.root))
            for ancestor in (value, *value.parents):
                info = ancestor.lstat()
                self.assertTrue(stat.S_ISDIR(info.st_mode))
                self.assertEqual(info.st_uid, os.geteuid())
                self.assertFalse(info.st_mode & 0o022)
                if ancestor == self.root: break
            return value
        # /tmp is writable by design in the isolated test container; actual
        # parser, exact report bytes and private subtree remain validated.
        with patch('nebulalog_manager.baseline._directory', side_effect=private_directory):
            self.journal.acknowledge_scap(ref, ticket, argv)
            self.journal.finish(ref, "failed")
            self.assertEqual(self.journal.assert_settled(), 1)

    def test_livepatch_admission_refuses_unknown_component_before_native_probe(self):
        from nebulalog_manager import livepatch
        self.enter()
        transaction = {**self.transaction, "state": "preflight_failed", "finalization": "complete"}
        atomic_json(self.stage.parent.parent / "transaction.json", transaction)
        calls = []
        with patch.object(livepatch, "require_linux_root"), patch.object(livepatch, "_tree"), \
                patch('nebulalog_manager.update_enrollment._tree'), \
                self.assertRaisesRegex(Refused, "unresolved"):
            livepatch.apply_bundle(self.root / "unused", self.stage.parent.parent,
                                   self.root / "unused.pem", runner=lambda argv, **kw: calls.append(argv))
        self.assertEqual(calls, [])
        self.assertFalse((self.stage.parent.parent / "livepatch-transaction.json").exists())

    def test_wrapper_terminal_follows_known_python_failure_finally(self):
        ref = self.journal.begin("update-preflight", {})
        manager = self.lifecycle()
        seen = []
        def body(stage):
            try:
                raise Refused("known fixture condition")
            finally:
                seen.append(self.journal._path(ref["id"], "terminal").exists())
        manager.preflight = body
        with self.assertRaisesRegex(Refused, "known fixture"):
            manager.component_hook("update-preflight", self.stage)
        self.assertEqual(seen, [False])
        self.assertEqual(self.journal.assert_settled(), 1)
        self.assertEqual(json.loads(self.journal._path(ref["id"], "terminal").read_text())["outcome"], "failed")

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "actual root-owned native command fixture")
    def test_actual_inert_readiness_client_can_fail_once_then_retry_to_success(self):
        ref = self.journal.begin("update-preflight", {})
        manager = self.lifecycle()
        directory = self.root / "bin"
        directory.mkdir()
        counter = self.root / "probe-count"
        client = directory / "podman"
        client.write_text("#!/usr/bin/python3\nfrom pathlib import Path\nimport sys\np=Path(" + repr(str(counter))
            + ")\nn=int(p.read_text())+1 if p.exists() else 1\np.write_text(str(n))\n"
            + "if n==1: raise SystemExit(2)\nprint('1')\n")
        client.chmod(0o700)
        def body(stage):
            manager.pg_ready(timeout=2)
            return {"ok": True}
        manager.preflight = body
        native_run = subprocess.run
        def inert_client(argv, **kwargs):
            self.assertEqual(argv, self.journal.POSTGRES_READY)
            # Preserve the fixed production command at the journal boundary;
            # execute a real inert client through Python so a noexec /tmp is
            # supported. No Podman or PostgreSQL process runs in this fixture.
            return native_run([sys.executable, str(client)], **kwargs)
        with patch("nebulalog_adapters.commands.subprocess.run", side_effect=inert_client), \
                patch("nebulalog_adapters.lifecycle.time.sleep", return_value=None):
            self.assertEqual(manager.component_hook("update-preflight", self.stage), {"ok": True})
        self.assertEqual(counter.read_text(), "2")
        self.journal.successful_result(ref, {"ok": True})
        completions = [json.loads(path.read_text()) for path in self.stage.glob("component-command-*-complete.json")]
        self.assertEqual(len(completions), 2)
        self.assertEqual(sum(value["success"] is False for value in completions), 1)
        self.assertEqual(next(value for value in completions if value["success"] is False)["returncode"], 2)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "actual root-owned native command fixture")
    def test_wrapper_actual_native_command_ack_and_failed_command_hold(self):
        ref = self.journal.begin("update-preflight", {})
        manager = self.lifecycle()
        def body(stage):
            manager.cmd([sys.executable, "-c", "print('fixture success')"])
            return {"ok": True}
        manager.preflight = body
        self.assertEqual(manager.component_hook("update-preflight", self.stage), {"ok": True})
        self.journal.successful_result(ref, {"ok": True})
        second = self.journal.begin("update-backup", {})
        manager.backup = lambda stage: manager.cmd([sys.executable, "-c", "raise SystemExit(7)"])
        with self.assertRaisesRegex(Refused, "native command lacks"):
            manager.component_hook("update-backup", self.stage)
        self.assertFalse(self.journal._path(second["id"], "terminal").exists())
        with self.assertRaises(Refused): self.journal.assert_settled()
