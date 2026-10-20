"""Recovery commands route only to their corresponding guarded manager API."""
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import cli
from nebulalog_manager.common import Refused


class UpdateRecoveryCliTests(unittest.TestCase):
    def test_kernel_recovery_commands_use_fixed_root_lifecycle_hooks(self):
        for action in ("kernel-retry", "kernel-rollback"):
            with self.subTest(action=action), patch("nebulalog_manager.common.require_linux_root") as root, \
                    patch("nebulalog_manager.os_updates._hook", return_value={"ok": True}) as hook, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["update", action]), 0)
                root.assert_called_once_with()
                hook.assert_called_once_with("update-" + action, cli.updates.run)

    def test_interrupted_recovery_routes_enrolled_key_without_install_or_finalize(self):
        manager = Mock()
        manager.recover.return_value = {"state": "rolled_back"}
        output = io.StringIO()
        with patch.object(cli.updates, "UpdateManager", return_value=manager), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(["update", "recover"]), 0)
        manager.recover.assert_called_once_with(Path("/etc/nebulalog/release-public.pem"))
        manager.install.assert_not_called()
        manager.rollback.assert_not_called()
        manager.finalize.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), {"state": "rolled_back"})

    def test_recovery_refusal_does_not_fall_through_to_another_action(self):
        manager = Mock()
        manager.recover.side_effect = Refused("No interrupted component transaction is available for recovery")
        error = io.StringIO()
        with patch.object(cli.updates, "UpdateManager", return_value=manager), contextlib.redirect_stderr(error):
            self.assertEqual(cli.main(["update", "recover", "--public-key", "/etc/nebulalog/custom-public.pem"]), 1)
        manager.recover.assert_called_once_with(Path("/etc/nebulalog/custom-public.pem"))
        manager.install.assert_not_called()
        manager.finalize.assert_not_called()
        self.assertEqual(json.loads(error.getvalue())["status"], "refused")
