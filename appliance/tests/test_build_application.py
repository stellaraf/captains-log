import hashlib
import importlib.util
import io
import json
import os
import signal
import sys
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "packer/build_application.py"
SPEC = importlib.util.spec_from_file_location("build_application", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
sys.path.insert(0, str(SCRIPT.parents[1]))
from nebulalog_manager.image_bundle import RestoredAuthContract


class ContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        contents = {name: (name + " fixture\n").encode() for name in builder.REQUIRED}
        contents.update({"internal/app.go": b"package app\n", "web/src/App.tsx": b"export const app = 'fixture'\n",
                         "internal/auth/auth.go": b"package auth\n", "internal/auth/restore.go": b"package auth\n",
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
        self.config_raw = json.dumps({"architecture": "amd64", "os": "linux", "config": {"Labels": {
            "io.nebulalog.application-source-sha256": builder.application_hash(self.manifest)}}}).encode()
        self.config_id = "sha256:" + hashlib.sha256(self.config_raw).hexdigest()
        self.manifest_raw = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": self.config_id, "size": len(self.config_raw)}, "layers": []}).encode()
        self.image_id = "sha256:" + hashlib.sha256(self.manifest_raw).hexdigest()
        self.export_patch_original = builder.export_identity
        export = patch.object(builder, "export_identity", side_effect=self.export_identity)
        export.start()
        self.addCleanup(export.stop)
        self.buildkit_image = "moby/buildkit@sha256:" + "c" * 64
        self.buildkit_id = "sha256:" + "d" * 64
        self.cid = "e" * 64
        self.volume = self.container = None
        self.container_exists = self.volume_exists = False
        self.running = False
        self.build_failure = None
        self.remove_failure = False
        admission = patch.object(builder, "storage_admission")
        admission.start()
        self.addCleanup(admission.stop)

    def build(self, *args, **kwargs):
        return builder.build(*args, docker_context="fixture", buildkit_image=self.buildkit_image, storage_root=self.root, **kwargs)

    def outcome(self):
        paths = list(self.root.glob("application-build-evidence-*/outcome.json"))
        self.assertEqual(len(paths), 1)
        return json.loads(paths[0].read_text())

    def image_tar(self, *, reverse=False):
        stream = io.BytesIO()
        members = [("blobs/sha256/" + self.config_id.split(":")[1], self.config_raw),
                   ("blobs/sha256/" + self.image_id.split(":")[1], self.manifest_raw)]
        if reverse:
            members.reverse()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in members:
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        return stream.getvalue()

    def export_identity(self, owner, binding, source_sha, storage_root):
        self.assertEqual(owner.parent, self.receipt.parent)
        self.assertEqual(binding["docker_image_id"], self.image_id)
        return builder.save_identity(io.BytesIO(self.image_tar()).read, binding["descriptor"], source_sha)

    def runner(self, argv, **kwargs):
        self.commands.append(argv)
        config = Path(kwargs["env"]["BUILDX_CONFIG"])
        self.assertEqual(config.parent.parent, self.root)
        self.assertEqual(config.stat().st_mode & 0o777, 0o700)
        self.assertNotIn("--use", argv)
        self.assertNotIn("prune", argv)
        self.assertLessEqual(kwargs["timeout"], 3600)
        def output(value=b""):
            if not isinstance(value, bytes):
                value = json.dumps(value).encode()
            return subprocess.CompletedProcess(argv, 0, value, b"")
        if argv[:3] == ["docker", "context", "inspect"]:
            return output([{"Endpoints": {"docker": {"Host": "unix:///fixture/docker.sock"}}}])
        self.assertEqual(argv[:3], ["docker", "--host", "unix:///fixture/docker.sock"])
        args = argv[3:]
        if args[:2] == ["image", "inspect"]:
            if args[2] == self.buildkit_image:
                return output([{"Id": self.buildkit_id, "Os": "linux"}])
            self.assertEqual(args[2], self.image_id)
            return output([{"Id": self.image_id, "Architecture": "amd64", "Os": "linux",
                "Config": {"Labels": {"io.nebulalog.application-source-sha256": builder.application_hash(self.manifest)}}}])
        if args[:2] in (["container", "ls"], ["volume", "ls"]):
            if "volume=" in " ".join(args):
                return output((self.cid + "\n").encode() if self.container_exists else b"")
            exists = self.container_exists if args[0] == "container" else self.volume_exists
            name = self.container if args[0] == "container" else self.volume
            return output((name + "\n").encode() if exists else b"")
        if args[:2] == ["volume", "create"]:
            self.volume, self.volume_exists = args[-1], True
            self.label = args[args.index("--label") + 1].split("=", 1)[1]
            return output((self.volume + "\n").encode())
        if args[:2] == ["volume", "inspect"]:
            self.assertTrue(self.volume_exists)
            return output([{"Name": self.volume, "Driver": "local", "Scope": "local", "Options": None,
                "CreatedAt": "2026-10-20T00:00:00Z", "Mountpoint": "/fixture/volumes/" + self.volume,
                "Labels": {"io.nebulalog.application-build": self.label}}])
        if args[:2] == ["buildx", "create"]:
            self.name = args[args.index("--name") + 1]
            node = args[args.index("--node") + 1]
            self.container = "buildx_buildkit_" + node
            self.assertEqual(self.volume, self.container + "_state")
            self.assertIn("image=" + self.buildkit_image, args)
            self.assertIn("env.NEBULALOG_APPLICATION_BUILD=" + self.label, args)
            return output((self.name + "\n").encode())
        if args[:3] == ["buildx", "inspect", "--bootstrap"]:
            self.container_exists = self.running = True
            return output(b"fixture bootstrap")
        if args[:2] == ["container", "inspect"]:
            self.assertTrue(self.container_exists)
            return output([{"Id": self.cid, "Name": "/" + self.container, "Image": self.buildkit_id,
                "Config": {"Image": self.buildkit_image, "Env": ["NEBULALOG_APPLICATION_BUILD=" + self.label]},
                "Mounts": [{"Type": "volume", "Name": self.volume, "Destination": "/var/lib/buildkit", "RW": True}],
                "State": {"Running": self.running, "Pid": 7 if self.running else 0,
                          "Status": "running" if self.running else "exited"}}])
        if args[:2] == ["container", "stop"]:
            self.assertEqual(args[-1], self.cid)
            self.running = False
            return output()
        if args[:2] == ["container", "rm"]:
            self.assertEqual(args[-1], self.cid)
            self.assertFalse(self.running)
            self.container_exists = False
            return output()
        if args[:2] == ["volume", "rm"]:
            self.assertFalse(self.container_exists)
            if self.remove_failure:
                raise subprocess.CalledProcessError(1, argv)
            self.volume_exists = False
            return output()
        self.assertEqual(args[:2], ["buildx", "build"])
        stage = Path(argv[argv.index("--iidfile") + 1]).parent
        self.assertEqual(stage.parent, self.receipt.parent)
        self.stages.append(stage)
        self.assertEqual(argv[argv.index("--builder") + 1], self.name)
        self.assertIn("--load", argv)
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
        if self.build_failure:
            raise self.build_failure
        Path(argv[argv.index("--iidfile") + 1]).write_text(self.image_id)
        Path(argv[argv.index("--metadata-file") + 1]).write_text(json.dumps({
            "containerimage.config.digest": self.config_id, "containerimage.digest": self.image_id,
            "containerimage.descriptor": {"digest": self.image_id, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": len(self.manifest_raw), "annotations": {"config.digest": self.config_id}}}))
        return output()

    def test_exact_private_stdin_context_excludes_uncaptured_secrets_and_host_files(self):
        for name in ("web/.env", "web/private.key", "web/node_modules/injected.js", "web/dist/stale.js", ".dockerignore"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("uncaptured fixture, must not reach Docker")
        result = self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertEqual(result["local_image_id"], self.config_id)
        self.assertFalse(result["runtime_executed"])
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.container_exists)
        self.assertFalse(self.volume_exists)
        self.assertEqual(self.outcome()["cleanup"], "complete")
        self.assertFalse(list(self.root.glob("application-build-evidence-*/buildx")))
        self.assertFalse(any("image" in cmd and "rm" in cmd for cmd in self.commands))
        self.assertNotIn("docs/host-only.md", self.context_members)
        self.assertEqual(json.loads(self.receipt.read_text()), result)
        self.assertTrue(self.stages)
        self.assertTrue(all(not stage.exists() for stage in self.stages))

    def test_failed_build_removes_only_its_owned_context(self):
        previous = self.receipt.parent / "nebulalog-application-build-previous"
        previous.mkdir()
        retained = previous / "keep.txt"
        retained.write_text("previous run evidence")
        self.build_failure = subprocess.CalledProcessError(1, ["fixture-build"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertEqual(len(self.stages), 1)
        self.assertFalse(self.stages[0].exists())
        self.assertEqual(self.outcome()["build_error"], "CalledProcessError")
        self.assertEqual(self.outcome()["cleanup"], "complete")
        self.assertFalse(self.volume_exists)
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
                self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=runner)
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
                self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=runner)
            runner.assert_not_called()

    def test_missing_iid_publishes_no_success_receipt_but_cleans(self):
        def missing(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if "--iidfile" in argv:
                Path(argv[argv.index("--iidfile") + 1]).unlink()
            return result
        with self.assertRaises(ValueError):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=missing)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.outcome()["cleanup"], "complete")

    def test_mismatched_source_label_refuses_after_cleanup(self):
        def mismatch(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if argv[-3:] == ["image", "inspect", self.image_id]:
                value = json.loads(result.stdout)
                value[0]["Config"]["Labels"]["io.nebulalog.application-source-sha256"] = "0" * 64
                result.stdout = json.dumps(value).encode()
            return result
        with self.assertRaises(ValueError):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=mismatch)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.outcome()["cleanup"], "complete")

    def test_timeout_settles_backend_then_removes_cache(self):
        self.build_failure = subprocess.TimeoutExpired(["fixture-build"], 3600)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        operations = [cmd[3:5] for cmd in self.commands]
        self.assertLess(operations.index(["container", "stop"]), operations.index(["container", "rm"]))
        self.assertLess(operations.index(["container", "rm"]), operations.index(["volume", "rm"]))
        self.assertEqual(self.outcome()["build_error"], "TimeoutExpired")
        self.assertEqual(self.outcome()["cleanup"], "complete")
        self.assertFalse(self.receipt.exists())

    def test_cleanup_failure_preserves_config_and_no_success_receipt(self):
        self.remove_failure = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertTrue(self.volume_exists)
        self.assertFalse(self.container_exists)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.outcome()["cleanup"], "incomplete")
        self.assertIsNone(self.outcome()["build_error"])
        self.assertTrue(list(self.root.glob("application-build-evidence-*/buildx")))

    def test_cleanup_failure_does_not_replace_primary_timeout(self):
        self.remove_failure = True
        self.build_failure = subprocess.TimeoutExpired(["fixture-build"], 3600)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertEqual(self.outcome()["build_error"], "TimeoutExpired")
        self.assertEqual(self.outcome()["cleanup_error"], "CalledProcessError")

    def test_outcome_write_failure_preserves_primary_exception(self):
        actual = builder.write_receipt
        self.build_failure = subprocess.TimeoutExpired(["fixture-build"], 3600)
        def full_disk(path, value):
            if path.name == "outcome.json":
                raise OSError("fixture ENOSPC")
            return actual(path, value)
        with patch.object(builder, "write_receipt", side_effect=full_disk), self.assertRaises(subprocess.TimeoutExpired):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.container_exists)
        self.assertFalse(self.volume_exists)

    def test_bootstrap_ack_loss_cleans_only_owned_resources(self):
        def lost_ack(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if argv[3:6] == ["buildx", "inspect", "--bootstrap"]:
                raise subprocess.TimeoutExpired(argv, 120)
            return result
        with self.assertRaises(subprocess.TimeoutExpired):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=lost_ack)
        self.assertEqual(self.outcome()["cleanup"], "complete")
        self.assertFalse(self.container_exists)
        self.assertFalse(self.volume_exists)
        self.assertFalse(self.receipt.exists())

    def test_unconfirmed_volume_removal_is_not_success(self):
        def unconfirmed(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if argv[3:5] == ["volume", "rm"]:
                self.volume_exists = True
            return result
        with self.assertRaisesRegex(ValueError, "not confirmed"):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=unconfirmed)
        self.assertEqual(self.outcome()["cleanup"], "incomplete")
        self.assertFalse(self.receipt.exists())

    def test_success_receipt_waits_for_cleanup_outcome(self):
        actual = builder.write_receipt
        def observe(path, value):
            if path == self.receipt:
                self.assertFalse(self.container_exists)
                self.assertFalse(self.volume_exists)
                self.assertFalse(any(stage.exists() for stage in self.stages))
                self.assertEqual(self.outcome()["cleanup"], "complete")
            return actual(path, value)
        with patch.object(builder, "write_receipt", side_effect=observe):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)

    def test_success_receipt_preserves_existing_exact_provenance_schema(self):
        result = self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        RestoredAuthContract._build(result, self.manifest["files"], {"version": result["requested_version"]},
            {"config_digest": self.config_id, "application_source_sha256": builder.application_hash(self.manifest)})
        self.assertEqual(self.outcome()["cleanup"], "complete")

    def test_metadata_disagreement_ambiguous_index_and_duplicates_refuse(self):
        for damage in ("config", "descriptor", "index", "iid", "duplicate", "symlink", "oversized"):
            def damaged(argv, **kwargs):
                result = self.runner(argv, **kwargs)
                if "--metadata-file" in argv:
                    path = Path(argv[argv.index("--metadata-file") + 1])
                    value = json.loads(path.read_text())
                    if damage == "config":
                        value["containerimage.config.digest"] = "sha256:" + "0" * 64
                    elif damage == "descriptor":
                        value["containerimage.descriptor"]["digest"] = "sha256:" + "0" * 64
                    elif damage == "index":
                        value["containerimage.descriptor"]["mediaType"] = "application/vnd.oci.image.index.v1+json"
                    elif damage == "iid":
                        value["containerimage.digest"] = value["containerimage.descriptor"]["digest"] = "sha256:" + "0" * 64
                    path.write_text(json.dumps(value))
                    if damage == "duplicate":
                        path.write_text('{"containerimage.digest":"a","containerimage.digest":"b"}')
                    elif damage == "symlink":
                        path.unlink()
                        path.symlink_to(self.source / "go.mod")
                    elif damage == "oversized":
                        path.write_bytes(b"x" * (1024**2 + 1))
                return result
            with self.subTest(damage=damage), self.assertRaises((ValueError, OSError)):
                self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=damaged)
            self.assertFalse(self.receipt.exists())
            self.assertFalse(self.volume_exists)
            self.assertFalse(self.container_exists)
        retained = list(self.root.glob("application-build-evidence-*/build-metadata.json"))
        self.assertEqual(len(retained), 5)  # Symlink and oversized input never admitted.
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in retained))
        self.assertTrue(any(p.read_text() == '{"containerimage.digest":"a","containerimage.digest":"b"}' for p in retained))

    def test_actual_load_profile_without_config_hints_uses_hashed_export(self):
        def no_hints(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if "--metadata-file" in argv:
                path = Path(argv[argv.index("--metadata-file") + 1])
                value = json.loads(path.read_text())
                value.pop("containerimage.config.digest")
                value["containerimage.descriptor"]["annotations"].pop("config.digest")
                path.write_text(json.dumps(value))
            return result
        result = self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=no_hints)
        self.assertEqual(result["local_image_id"], self.config_id)
        RestoredAuthContract._build(result, self.manifest["files"], {"version": result["requested_version"]},
            {"config_digest": self.config_id, "application_source_sha256": builder.application_hash(self.manifest)})

    def test_stream_identity_accepts_both_metadata_orders(self):
        descriptor = {"digest": self.image_id, "size": len(self.manifest_raw), "mediaType": "application/vnd.oci.image.manifest.v1+json"}
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                proof = builder.save_identity(io.BytesIO(self.image_tar(reverse=reverse)).read, descriptor, builder.application_hash(self.manifest))
                self.assertEqual(proof["config_digest"], self.config_id)

    def test_stream_refuses_truncation_tail_hash_source_and_total_limit(self):
        descriptor = {"digest": self.image_id, "size": len(self.manifest_raw), "mediaType": "application/vnd.oci.image.manifest.v1+json"}
        raw = self.image_tar()
        for damaged in (raw[:511], raw[:-1] + b"x", raw.replace(self.config_raw, self.config_raw.replace(b"amd64", b"arm64"))):
            with self.subTest(bytes=len(damaged)), self.assertRaises(ValueError):
                builder.save_identity(io.BytesIO(damaged).read, descriptor, builder.application_hash(self.manifest))
        with self.assertRaises(ValueError):
            builder.save_identity(io.BytesIO(raw).read, descriptor, "0" * 64)
        with patch.object(builder, "MAX_IMAGE_STREAM", 511), self.assertRaises(ValueError):
            builder.save_identity(io.BytesIO(raw).read, descriptor, builder.application_hash(self.manifest))

    def test_stream_refuses_pax_link_and_duplicate_before_payload_read(self):
        descriptor = {"digest": self.image_id, "size": len(self.manifest_raw), "mediaType": "application/vnd.oci.image.manifest.v1+json"}
        for kind in (tarfile.XHDTYPE, tarfile.SYMTYPE):
            member = tarfile.TarInfo("metadata")
            member.type, member.size = kind, 1024**3
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                builder.save_identity(io.BytesIO(member.tobuf(format=tarfile.USTAR_FORMAT)).read, descriptor, builder.application_hash(self.manifest))
        header = tarfile.TarInfo("duplicate").tobuf(format=tarfile.USTAR_FORMAT)
        with self.assertRaises(ValueError):
            builder.save_identity(io.BytesIO(header + header).read, descriptor, builder.application_hash(self.manifest))

    def test_export_cli_failure_after_complete_tar_is_not_success(self):
        import base64
        raw = base64.b64encode(self.image_tar()).decode()
        command = [sys.executable, "-c", "import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.argv[1]));sys.stdout.flush();sys.exit(7)", raw]
        def child(argv, **kwargs):
            return subprocess.Popen(command, **kwargs)
        owner = SimpleNamespace(prefix=["fixture-docker"], env=dict(os.environ), parent=self.root)
        binding = {"docker_image_id": self.image_id, "descriptor": {"digest": self.image_id, "size": len(self.manifest_raw), "mediaType": "application/vnd.oci.image.manifest.v1+json"}}
        # Call the unpatched production export function, with only the child command adapted.
        original = self.export_patch_original
        with patch.object(builder.os, "killpg") as kill, self.assertRaises(subprocess.CalledProcessError) as raised:
            original(owner, binding, builder.application_hash(self.manifest), self.root, popen=child)
        self.assertEqual(raised.exception.returncode, 7)
        kill.assert_not_called()

    def test_unreaped_export_preserves_failure_and_marks_cleanup_unsafe(self):
        process = Mock(pid=12345, returncode=None)
        process.poll.return_value = None
        process.communicate.side_effect = subprocess.TimeoutExpired(["fixture"], 10)
        process.stdout.close.side_effect = OSError("fixture close failure")
        original = ValueError("fixture parser refusal")
        owner = SimpleNamespace(prefix=["fixture-docker"], env={}, parent=self.root)
        with patch.object(builder, "save_identity", side_effect=original), patch.object(builder.os, "killpg"):
            with self.assertRaises(ValueError) as raised:
                self.export_patch_original(owner, {"docker_image_id": self.image_id, "descriptor": {}}, "0" * 64, self.root,
                                           popen=Mock(return_value=process))
        self.assertIs(raised.exception, original)
        self.assertTrue(original.command_unsettled)
        process.wait.assert_not_called()

    def test_bounded_runner_reaps_actual_timed_out_local_child(self):
        pid_file = self.root / "child.pid"
        command = [sys.executable, "-c", "import os,pathlib,time; pathlib.Path(__import__('sys').argv[1]).write_text(str(os.getpid())); time.sleep(60)", str(pid_file)]
        with self.assertRaises(subprocess.TimeoutExpired):
            builder.bounded_run(command, timeout=2, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertTrue(pid_file.exists(), "local child must have started before this timeout assertion")
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)

    def test_unreaped_cli_preserves_original_error_without_implicit_wait(self):
        process = Mock(pid=12345, returncode=None)
        original = KeyboardInterrupt()
        process.communicate.side_effect = [original, subprocess.TimeoutExpired(["fixture"], 10)]
        with patch.object(builder.subprocess, "Popen", return_value=process), patch.object(builder.os, "killpg") as kill:
            with self.assertRaises(KeyboardInterrupt) as raised:
                builder.bounded_run(["fixture"], timeout=30)
        self.assertIs(raised.exception, original)
        self.assertTrue(original.command_unsettled)
        self.assertEqual(original.command_pid, 12345)
        kill.assert_called_once_with(12345, signal.SIGKILL)
        process.wait.assert_not_called()

    def test_unknown_cli_settlement_holds_all_daemon_cleanup(self):
        self.build_failure = subprocess.TimeoutExpired(["fixture"], 3600)
        self.build_failure.command_unsettled = True
        self.build_failure.command_pid = 12345
        with self.assertRaises(subprocess.TimeoutExpired):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertTrue(self.container_exists)
        self.assertTrue(self.volume_exists)
        self.assertFalse(any(cmd[3:5] in (["container", "stop"], ["container", "rm"], ["volume", "rm"]) for cmd in self.commands))
        self.assertEqual(self.outcome()["cleanup"], "incomplete")
        self.assertEqual(self.outcome()["unsettled_command_pid"], 12345)
        self.assertTrue(list(self.root.glob("application-build-evidence-*/buildx")))

    def test_foreign_container_mount_is_never_stopped_or_removed(self):
        def foreign(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if argv[3:5] == ["container", "inspect"]:
                value = json.loads(result.stdout)
                value[0]["Mounts"][0]["Name"] = "foreign-volume"
                result.stdout = json.dumps(value).encode()
            return result
        with self.assertRaises(ValueError):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=foreign)
        self.assertTrue(self.container_exists)
        self.assertTrue(self.volume_exists)
        self.assertFalse(any(cmd[3:5] in (["container", "stop"], ["container", "rm"], ["volume", "rm"]) for cmd in self.commands))
        self.assertEqual(self.outcome()["cleanup"], "incomplete")

    def test_keyboard_interrupt_cleans_and_propagates(self):
        self.build_failure = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertEqual(self.outcome()["cleanup"], "complete")
        self.assertFalse(self.receipt.exists())

    def test_cli_sigterm_enters_cleanup_and_restores_callers_handler(self):
        original = signal.getsignal(signal.SIGTERM)
        def terminate(argv, **kwargs):
            if "--iidfile" in argv:
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return self.runner(argv, **kwargs)
        actual_build = builder.build
        def injected(*args, **kwargs):
            return actual_build(*args, runner=terminate, **kwargs)
        with patch.object(builder, "build", side_effect=injected), self.assertRaises(SystemExit) as raised:
            builder.main(["--source", str(self.source), "--tag", "nebulalog/appliance-app:test",
                          "--receipt", str(self.receipt), "--docker-context", "fixture",
                          "--buildkit-image", self.buildkit_image, "--storage-root", str(self.root)])
        self.assertEqual(raised.exception.code, 143)
        self.assertEqual(signal.getsignal(signal.SIGTERM), original)
        self.assertEqual(self.outcome()["cleanup"], "complete")

    def test_bad_tag_version_and_existing_receipt_refused_before_capture(self):
        for tag, version in (("--push", "0.2.0"), ("registry.invalid/app:test", "0.2.0"),
                             ("nebulalog/app:test", "0.2.0;touch /tmp/bad"), ("nebulalog/app:test", "$(id)")):
            runner = Mock()
            with self.subTest(tag=tag, version=version), self.assertRaises(ValueError):
                self.build(self.source, tag, self.receipt, version=version, runner=runner)
            runner.assert_not_called()
        self.receipt.write_text("preserve")
        with self.assertRaises(ValueError):
            self.build(self.source, "nebulalog/app:test", self.receipt, runner=Mock())
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
        result = self.build(self.source, "nebulalog/appliance-app:test", self.receipt, runner=self.runner)
        self.assertFalse(result["source_dirty"])
        self.assertEqual(result["application_files"], self.selected)
        self.assertFalse(any(".env" in path or path.endswith(".key") or "node_modules" in path for path in self.context_members))
