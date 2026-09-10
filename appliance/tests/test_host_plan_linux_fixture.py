"""Portable fixture safety checks; real Linux integration runs separately."""
import contextlib
import io
import os
import signal
import unittest
from unittest.mock import Mock, patch

import host_plan_linux_fixture as fixture
from nebulalog_manager.common import Refused


class FixtureGateTests(unittest.TestCase):
    def test_exact_opt_in_is_required_before_root_check_or_any_writes(self):
        for value in (None, "", "true", "0", "01"):
            environment = {} if value is None else {"NEBULALOG_HOST_PLAN_FIXTURE": value}
            with self.subTest(value=value), patch.dict(os.environ, environment, clear=True), \
                 patch.object(fixture, "require_linux_root") as root_check, \
                 patch.object(fixture.tempfile, "TemporaryDirectory") as temporary, \
                 patch.object(fixture, "control_directory") as directory, \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fixture.main(), 1)
                root_check.assert_not_called()
                temporary.assert_not_called()
                directory.assert_not_called()

    def test_explicit_opt_in_still_requires_linux_root_before_writes(self):
        with patch.dict(os.environ, {"NEBULALOG_HOST_PLAN_FIXTURE": "1"}, clear=True), \
             patch.object(fixture, "require_linux_root", side_effect=Refused("requires_linux_root")), \
             patch.object(fixture.tempfile, "TemporaryDirectory") as temporary, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(fixture.main(), 1)
            temporary.assert_not_called()

    def test_sigterm_unwinds_the_server_and_owned_contexts(self):
        events = []
        @contextlib.contextmanager
        def context(name, value=None):
            events.append(name + ".enter")
            try:
                yield value
            finally:
                events.append(name + ".exit")
        temporary = lambda **_: context("temporary", "/tmp/nebulalog-host-plan-fixture-test")
        directory = lambda: context("directory")
        server = Mock()
        server.bind.return_value = server
        server.serve.side_effect = lambda: fixture.stop_fixture(signal.SIGTERM, None)
        server.close.side_effect = lambda: events.append("server.close")
        previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
        output = io.StringIO()
        with patch.object(fixture, "require_opt_in"), patch.object(fixture.tempfile, "TemporaryDirectory", temporary), \
             patch.object(fixture.Path, "chmod"), patch.object(fixture, "control_directory", directory), \
             patch.object(fixture, "fixture_service"), patch.object(fixture, "PlanSocket", return_value=server), \
             contextlib.redirect_stdout(output):
            self.assertEqual(fixture.main(), 0)
        self.assertEqual(output.getvalue(), "READY\n")
        self.assertEqual(events, ["temporary.enter", "directory.enter", "server.close", "directory.exit", "temporary.exit"])
        self.assertEqual({number: signal.getsignal(number) for number in previous}, previous)


if __name__ == "__main__":
    unittest.main()
