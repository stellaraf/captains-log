"""Pinned-dispatch validation and inert local subprocess output/timeout tests.

Actual installed lifecycle hooks, services and appliance state are never invoked.
"""
import copy
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from nebulalog_manager import host_activation as activation, host_dispatch as dispatch, host_payload as payload
from nebulalog_manager.common import Refused, atomic_json
from test_host_activation import HostFixture


class BindingTests(HostFixture):
    def test_only_fixed_hook_names_and_matching_transaction_phases_are_allowed(self):
        pin = dispatch.coordinator_pin(self.stage)
        for hook, allowed in dispatch.HOOK_STATES.items():
            for state in dispatch.STATES:
                self.save_transaction(state)
                if state in allowed:
                    command = dispatch.hook_command(pin, hook, self.stage)
                    self.assertEqual(command[:5], ["/usr/bin/python3.14", "-I", "-B", "-c", dispatch.DISPATCH_CODE])
                    self.assertEqual(command[-3:], [str(self.generations / self.old["generation"]), hook, str(self.stage)])
                else:
                    with self.subTest(hook=hook, state=state), self.assertRaises(Refused):
                        dispatch.hook_command(pin, hook, self.stage)
        for name in ("../update-health", "update-os-preflight", "sh", [], None):
            with self.assertRaises(Refused): dispatch.hook_command(pin, name, self.stage)

    def test_false_pin_or_unenrolled_previous_host_cannot_authorize_hook(self):
        self.save_transaction("preparing")
        pin = dispatch.coordinator_pin(self.stage)
        for key, value in (("generation", self.new["generation"]), ("sequence", 11), ("manifest_sha256", "a" * 64),
                           ("schema", True), ("abi", True)):
            with self.assertRaises(Refused): dispatch.hook_command({**pin, key: value}, "update-prepare", self.stage)
        original = copy.deepcopy(self.transaction)
        for previous in ({}, {"sequence": 9, "components": {}}, {"sequence": 10, "components": {"host": self.old}},
                         {"sequence": True, "components": {"host": self.old}},
                         {"sequence": 9, "components": {"host": {**self.old, "abi": True}}}):
            self.transaction = {**original, "previous": previous}
            self.save_transaction()
            with self.assertRaises(Refused): dispatch.coordinator_pin(self.stage)

    def test_only_protected_fixed_stage_and_matching_manifest_transaction_are_accepted(self):
        for path in (Path("relative"), self.root, self.stage.parent / "0-unsafe", self.stage.parent / "10-a/../10-fixture"):
            with self.assertRaises(Refused): dispatch.transaction_binding(path)
        original = copy.deepcopy(self.transaction)
        for key, value in (("release", str(self.root)), ("state", []), ("state", "unknown"), ("sequence", True),
                           ("sequence", 0), ("sequence", 2**63), ("manifest_sha256", "a" * 64)):
            self.transaction = {**original, key: value}
            self.save_transaction()
            with self.subTest(key=key), self.assertRaises(Refused): dispatch.transaction_binding(self.stage)
        self.transaction = original
        self.save_transaction()
        (self.stage / "manifest.json").write_bytes((self.stage / "manifest.json").read_bytes() + b" ")
        with self.assertRaises(Refused): dispatch.transaction_binding(self.stage)

    def test_bad_manifest_shape_or_sequence_is_refused(self):
        original = copy.deepcopy(self.manifest)
        for key, value in (("sequence", True), ("sequence", 11), ("product", "other"), ("channel", "preview"), ("components", [])):
            self.manifest = {**original, key: value}
            self.bind_manifest()
            with self.subTest(key=key), self.assertRaises(Refused): dispatch.transaction_binding(self.stage)
        self.manifest = {**original, "sequence": 11}
        self.transaction["sequence"] = 11
        self.bind_manifest()
        with self.assertRaises(Refused): dispatch.transaction_binding(self.stage)

    def test_generation_identity_is_digest_only_and_protected_receipt_required(self):
        for value in ("../escape", str(self.generations / self.old["generation"]), "a" * 63, None):
            with self.assertRaises(Refused): dispatch.generation_info(value)
        path = self.generations / self.old["generation"] / "staging-receipt.json"
        path.chmod(0o644)
        path.write_bytes(b'{"archive_sha256":"wrong"}')
        path.chmod(0o444)
        with self.assertRaises(Refused): dispatch.coordinator_pin(self.stage)

    def test_json_success_requires_boolean_and_never_exposes_failure_payload(self):
        pin = dispatch.coordinator_pin(self.stage)
        with patch.object(dispatch, "_run_bounded", return_value=b'{"ok":true,"checks":{"fixture":true}}'):
            self.assertEqual(dispatch.run_hook(pin, "update-prepare", self.stage)["checks"], {"fixture": True})
        for raw in (b'{"ok":1}', b'{"ok":false,"secret":"private fixture"}', b'[]', b'private fixture',
                    b'{"ok":true,"ok":true}', b'{"ok":NaN}'):
            with patch.object(dispatch, "_run_bounded", return_value=raw), self.assertRaises(Refused) as error:
                dispatch.run_hook(pin, "update-prepare", self.stage)
            self.assertNotIn("private fixture", str(error.exception))


class BoundedProcessTests(unittest.TestCase):
    def command(self, source):
        return [sys.executable, "-I", "-B", "-c", source]

    def test_real_inert_child_receives_fixed_environment_and_no_parent_secret(self):
        source = "import json,os;print(json.dumps({'ok':True,'leaked':'CAPTAINS_LOG_FIXTURE_SECRET' in os.environ,'path':os.environ['PATH']}))"
        with patch.dict(os.environ, {"CAPTAINS_LOG_FIXTURE_SECRET": "inert fixture"}):
            value = payload.strict_json(dispatch._run_bounded(self.command(source)))
        self.assertFalse(value["leaked"])
        self.assertEqual(value["path"], dispatch.ENVIRONMENT["PATH"])
        self.assertNotIn("PYTHONPATH", dispatch.ENVIRONMENT)

    def test_fixed_dispatch_code_imports_only_the_explicit_inert_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = root / "generation"
            package = generation / "lib/nebulalog_adapters"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("")
            (package / "cli.py").write_text("import json,sys\ndef main():\n print(json.dumps({'ok':True,'arguments':sys.argv,'origin':__file__}));return 0\n")
            poison = root / "untrusted/nebulalog_adapters"
            poison.mkdir(parents=True)
            (poison / "__init__.py").write_text("raise RuntimeError('untrusted import must not execute')")
            argv = [sys.executable, "-I", "-B", "-c", dispatch.DISPATCH_CODE, str(generation), "update-health", str(root / "stage")]
            with patch.dict(os.environ, {"PYTHONPATH": str(poison.parent)}):
                result = payload.strict_json(dispatch._run_bounded(argv))
            self.assertEqual(result["arguments"], ["update-health", str(root / "stage")])
            self.assertEqual(result["origin"], str(package / "cli.py"))
            self.assertFalse(list(generation.rglob("__pycache__")))

    def test_real_child_failure_redacts_stdout_and_stderr(self):
        with self.assertRaises(Refused) as error:
            dispatch._run_bounded(self.command("import sys;print('private fixture');print('private fixture',file=sys.stderr);sys.exit(9)"))
        self.assertEqual(str(error.exception), "Pinned component hook failed")

    def test_real_child_output_boundary_and_deadline_are_enforced(self):
        with patch.object(dispatch, "MAX_OUTPUT", 128):
            self.assertEqual(len(dispatch._run_bounded(self.command("import sys;sys.stdout.write('x'*128)"))), 128)
            with self.assertRaisesRegex(Refused, "output bound"):
                dispatch._run_bounded(self.command("import sys;sys.stdout.write('x'*129)"))
        start = time.monotonic()
        with patch.object(dispatch, "MAX_HOOK_SECONDS", .1), self.assertRaisesRegex(Refused, "deadline"):
            dispatch._run_bounded(self.command("import time;time.sleep(30)"))
        self.assertLess(time.monotonic() - start, 3)

    def test_timeout_terminates_only_owned_pipe_holding_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant-survived"
            child = "import pathlib,time;time.sleep(1);pathlib.Path(" + repr(str(marker)) + ").write_text('unexpected')"
            source = "import os,sys,time\nif os.fork()==0:\n exec(" + repr(child) + ")\nelse:\n time.sleep(30)\n"
            with patch.object(dispatch, "MAX_HOOK_SECONDS", .1), self.assertRaisesRegex(Refused, "deadline"):
                dispatch._run_bounded(self.command(source))
            time.sleep(1.1)
            self.assertFalse(marker.exists())


class PrivilegeTests(unittest.TestCase):
    def test_production_operations_refuse_non_linux_or_non_root_before_state_access(self):
        for platform, uid in (("Darwin", 0), ("Linux", 501)):
            with patch("nebulalog_manager.common.platform.system", return_value=platform), patch("nebulalog_manager.common.os.geteuid", return_value=uid):
                for function in (dispatch.transaction_binding, activation.prepare, activation.select_candidate,
                                 activation.restore_previous, activation.recovery_decision):
                    with patch.object(payload, "_trusted_tree", side_effect=AssertionError("must refuse before paths")), self.assertRaises(Refused):
                        function(Path("/unused"))


if __name__ == "__main__":
    unittest.main()
