"""Execute workflow publication Python with fake GitHub responses; no GitHub writes."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packer"))
import assemble_release as release

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/release-candidate.yml"
COMMIT = "a" * 40


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        text = WORKFLOW.read_text()
        body = text.split("          python3 - <<'PY'\n", 1)[1].rsplit("          PY", 1)[0]
        self.code = compile(textwrap.dedent(body), str(WORKFLOW), "exec")
        self.commands = []
        self.remote_hash = "b" * 64
        self.remote_commit = COMMIT
        self.final_prerelease = True
        self.fail_create = False
        self.asset_names = ["host.tar", "manifest.json", "manifest.sig", "captains-log-0.1.1-rocky9-x86_64.ova"]
        env = {"RELEASE_VERSION": "0.1.1", "APPROVED_MANIFEST": "c" * 64,
               "GITHUB_SHA": COMMIT, "RUNNER_TEMP": temporary.name}
        for mocker in (
            patch.dict(os.environ, env),
            patch.object(release, "verify_native", return_value={"version": "0.1.1", "assets": self.asset_names[:-1]}),
            patch.object(release, "file_info", return_value={"bytes": 10, "sha256": "b" * 64}),
            patch.object(subprocess, "run", side_effect=self.fake_run),
            patch.object(subprocess, "check_output", side_effect=self.output),
        ):
            mocker.start(); self.addCleanup(mocker.stop)

    def fake_run(self, args, **kwargs):
        self.commands.append(args)
        if args[:3] == ["gh", "release", "create"]:
            if self.fail_create: raise subprocess.CalledProcessError(1, args)
        elif args[:3] != ["gh", "release", "edit"]:
            raise AssertionError("Unexpected external command")
        return subprocess.CompletedProcess(args, 0)

    def output(self, args, **kwargs):
        self.commands.append(args)
        if args[:2] != ["gh", "api"]: raise AssertionError("Unexpected external command")
        if "/git/ref/tags/" in args[-1]:
            return json.dumps({"object": {"type": "commit", "sha": self.remote_commit}}).encode()
        if "/releases/tags/" not in args[-1]: raise AssertionError("Unexpected external API")
        final = any(command[:3] == ["gh", "release", "edit"] for command in self.commands)
        return json.dumps({"draft": not final, "prerelease": self.final_prerelease if final else True,
            "tag_name": "v0.1.1", "html_url": "https://github.com/stellaraf/captains-log/releases/tag/v0.1.1",
            "assets": [{"name": name, "size": 10, "state": "uploaded", "digest": "sha256:" + self.remote_hash} for name in self.asset_names]}).encode()

    def execute(self):
        with redirect_stdout(io.StringIO()):
            exec(self.code, {"__name__": "__main__"})

    def test_only_after_hash_and_tag_checks_draft_becomes_prerelease(self):
        self.execute()
        mutations = [args for args in self.commands if args[:2] == ["gh", "release"]]
        self.assertEqual(len(mutations), 2)
        self.assertIn("--draft", mutations[0])
        self.assertIn("--draft=false", mutations[1])
        for args in mutations:
            self.assertIn("--prerelease", args)
            self.assertIn("--latest=false", args)
            self.assertNotIn("--clobber", args)
        self.assertEqual(release.verify_native.call_count, 2)

    def test_wrong_remote_hash_or_tag_keeps_draft_unpublished(self):
        for kind in ("hash", "tag"):
            self.commands.clear()
            self.remote_hash = "d" * 64 if kind == "hash" else "b" * 64
            self.remote_commit = "d" * 40 if kind == "tag" else COMMIT
            with self.subTest(kind=kind), self.assertRaises(SystemExit): self.execute()
            self.assertFalse(any(args[:3] == ["gh", "release", "edit"] for args in self.commands))

    def test_existing_release_failure_does_not_clobber_reuse_or_delete(self):
        self.fail_create = True
        with self.assertRaises(subprocess.CalledProcessError): self.execute()
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(self.commands[0][:3], ["gh", "release", "create"])

    def test_lost_final_prerelease_state_is_reported_as_failure(self):
        self.final_prerelease = False
        with self.assertRaisesRegex(SystemExit, "Final prerelease"): self.execute()


if __name__ == "__main__":
    unittest.main()
