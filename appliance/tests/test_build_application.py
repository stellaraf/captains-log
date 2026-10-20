import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "packer/build_application.py"
SPEC = importlib.util.spec_from_file_location("build_application", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class ContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        contents = {name: (name + " fixture\n").encode() for name in builder.REQUIRED}
        contents.update({"internal/app.go": b"package app\n", "web/src/App.tsx": b"export const app = 'fixture'\n",
                         "migrations/001.sql": b"SELECT 1;\n", "docs/host-only.md": b"host-only input\n"})
        self.manifest = {"schema": 1, "files": {}}
        for name, content in contents.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            self.manifest["files"][name] = hashlib.sha256(content).hexdigest()
        self.selected = builder.selected_files(self.manifest)
        self.receipt = self.root / "build.json"
        self.snapshot = patch.object(builder, "source_snapshot", return_value=(self.manifest, "a" * 40, True))
        self.snapshot.start()
        self.addCleanup(self.snapshot.stop)
        self.commands, self.context_members, self.stages = [], [], []
        self.image_id = "sha256:" + "b" * 64

    def runner(self, argv, **kwargs):
        self.commands.append(argv)
        if argv[:2] == ["docker", "build"]:
            stage = Path(argv[argv.index("--iidfile") + 1]).parent
            self.assertEqual(stage.parent, self.receipt.parent)
            self.stages.append(stage)
            self.assertEqual(argv[-1], "-")
            self.assertEqual(argv[argv.index("--file") + 1], builder.CONTAINERFILE)
            stream = kwargs["stdin"]
            self.assertEqual(os.fstat(stream.fileno()).st_mode & 0o777, 0o600)
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                members = archive.getmembers()
                self.context_members = [item.name for item in members]
                self.assertEqual(self.context_members, sorted(self.selected))
                for item in members:
                    self.assertTrue(item.isfile())
                    self.assertEqual((item.uid, item.gid, item.mtime, item.mode), (0, 0, 0, 0o644))
                    self.assertEqual(hashlib.sha256(archive.extractfile(item).read()).hexdigest(), self.selected[item.name])
            self.assertIn("APPLICATION_SOURCE_SHA256=" + builder.application_hash(self.manifest), argv)
            Path(argv[argv.index("--iidfile") + 1]).write_text(self.image_id)
            return subprocess.CompletedProcess(argv, 0)
        self.assertEqual(argv, ["docker", "image", "inspect", self.image_id])
        return subprocess.CompletedProcess(argv, 0, json.dumps([{"Id": self.image_id, "Architecture": "amd64", "Os": "linux",
            "Config": {"Labels": {"io.nebulalog.application-source-sha256": builder.application_hash(self.manifest)}}}]).encode())

    def test_exact_private_stdin_context_excludes_uncaptured_secrets_and_host_files(self):
        for name in ("web/.env", "web/private.key", "web/node_modules/injected.js", "web/dist/stale.js", ".dockerignore"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("uncaptured fixture, must not reach Docker")
        result = builder.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertEqual(result["local_image_id"], self.image_id)
        self.assertFalse(result["runtime_executed"])
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.commands), 2)
        self.assertNotIn("docs/host-only.md", self.context_members)
        self.assertEqual(json.loads(self.receipt.read_text()), result)
        self.assertTrue(self.stages)
        self.assertTrue(all(not stage.exists() for stage in self.stages))

    def test_failed_build_removes_only_its_owned_context(self):
        previous = self.receipt.parent / "nebulalog-application-build-previous"
        previous.mkdir()
        retained = previous / "keep.txt"
        retained.write_text("previous run evidence")
        stages = []

        def failed(argv, **kwargs):
            stage = Path(argv[argv.index("--iidfile") + 1]).parent
            self.assertEqual(stage.parent, self.receipt.parent)
            self.assertTrue((stage / "context.tar").is_file())
            stages.append(stage)
            raise subprocess.CalledProcessError(1, argv)

        with self.assertRaises(subprocess.CalledProcessError):
            builder.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=failed)
        self.assertEqual(len(stages), 1)
        self.assertFalse(stages[0].exists())
        self.assertEqual(retained.read_text(), "previous run evidence")
        self.assertFalse(self.receipt.exists())

    def test_archive_is_deterministic_despite_live_modes_and_mtimes(self):
        first, second = self.root / "first.tar", self.root / "second.tar"
        builder.write_context(self.source, self.selected, first)
        for name in self.selected:
            path = self.source / name
            path.chmod(0o777)
            os.utime(path, (1700000000, 1700000000))
        builder.write_context(self.source, self.selected, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_changed_or_missing_source_never_invokes_docker(self):
        target = self.source / "web/src/App.tsx"
        for damage in ("modified", "deleted"):
            if damage == "modified":
                target.write_text("modified after snapshot")
            else:
                target.unlink()
            runner = Mock()
            with self.subTest(damage=damage), self.assertRaises((ValueError, OSError)):
                builder.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=runner)
            runner.assert_not_called()
            self.assertFalse(self.receipt.exists())

    def test_symlink_leaf_and_parent_and_nonregular_source_refused(self):
        target = self.source / "web/src/App.tsx"
        target.unlink()
        target.symlink_to(self.source / "go.mod")
        with self.assertRaises(OSError):
            builder.write_context(self.source, self.selected, self.root / "leaf.tar")
        target.unlink()
        target.mkdir()
        with self.assertRaises(ValueError):
            builder.write_context(self.source, self.selected, self.root / "directory.tar")
        target.rmdir()
        (self.source / "web/src").rmdir()
        (self.source / "web/src").symlink_to(self.source / "internal", target_is_directory=True)
        with self.assertRaises(OSError):
            builder.write_context(self.source, self.selected, self.root / "parent.tar")

    def test_captured_sensitive_generated_unsafe_or_missing_required_inputs_refused(self):
        for name in ("web/.env.production", "web/.npmrc", "web/private.pem", "web/keys.p12", "web/node_modules/x.js", "web/dist/index.html", "web/../escape"):
            value = {"files": {**self.manifest["files"], name: "c" * 64}}
            with self.subTest(name=name), self.assertRaises(ValueError):
                builder.selected_files(value)
        value = {"files": {**self.manifest["files"]}}
        value["files"].pop("web/package-lock.json")
        with self.assertRaises(ValueError):
            builder.selected_files(value)

    def test_limits_refuse_before_docker(self):
        for setting in ("MAX_FILE", "MAX_CONTEXT", "MAX_FILES"):
            runner = Mock()
            with patch.object(builder, setting, 1), self.subTest(setting=setting), self.assertRaises(ValueError):
                builder.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=runner)
            runner.assert_not_called()

    def test_failed_build_missing_iid_and_mismatched_label_publish_no_receipt(self):
        for failure in ("build", "iid", "label"):
            def failed(argv, **kwargs):
                if failure == "build":
                    raise subprocess.CalledProcessError(1, argv)
                if failure == "iid":
                    return subprocess.CompletedProcess(argv, 0)
                result = self.runner(argv, **kwargs)
                if argv[:3] == ["docker", "image", "inspect"]:
                    value = json.loads(result.stdout)
                    value[0]["Config"]["Labels"]["io.nebulalog.application-source-sha256"] = "0" * 64
                    result.stdout = json.dumps(value).encode()
                return result
            with self.subTest(failure=failure), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                builder.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=failed)
            self.assertFalse(self.receipt.exists())

    def test_bad_tag_version_and_existing_receipt_refused_before_capture(self):
        for tag, version in (("--push", "0.2.0"), ("registry.invalid/app:test", "0.2.0"),
                             ("nebulalog/app:test", "0.2.0;touch /tmp/bad"), ("nebulalog/app:test", "$(id)")):
            runner = Mock()
            with self.subTest(tag=tag, version=version), self.assertRaises(ValueError):
                builder.build(self.source, tag, self.receipt, version=version, runner=runner)
            runner.assert_not_called()
        self.receipt.write_text("preserve")
        with self.assertRaises(ValueError):
            builder.build(self.source, "nebulalog/app:test", self.receipt, runner=Mock())
        self.assertEqual(self.receipt.read_text(), "preserve")

    def test_actual_git_capture_keeps_ignored_credentials_out_of_context(self):
        self.snapshot.stop()
        (self.source / ".gitignore").write_text(".env*\n*.key\nnode_modules/\ndist/\n")
        for name in ("web/.env.production", "web/private.key", "web/node_modules/ignored.js"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("unit-test ignored credential fixture")
        subprocess.run(["git", "init", "--quiet", str(self.source)], check=True)
        subprocess.run(["git", "-C", str(self.source), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=Isolated Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "Temporary test fixture"], check=True)
        result = builder.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertFalse(result["source_dirty"])
        self.assertEqual(result["application_files"], self.selected)
        self.assertFalse(any(".env" in path or path.endswith(".key") or "node_modules" in path for path in self.context_members))
