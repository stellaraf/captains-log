"""Factory generation/filesystem and fixed-shim subprocess tests; no real host changes."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import host_payload as payload, host_dispatch, update_enrollment as enrollment
from nebulalog_manager.common import Refused, atomic_json
from test_host_payload import builder, fixture_source, fixture_tree

APPLIANCE = Path(__file__).resolve().parents[1]


def bounded_fixture(command, *, env, startup_timeout=45, operation_timeout=30):
    """Separate test interpreter/import readiness from the actual fixed operation.

    The child writes one R byte immediately before entering the fixed main.
    These are fixture watchdogs; no production timeout or trust guard changes.
    """
    read_fd, write_fd = os.pipe()
    started = time.monotonic()
    process = None
    phase = "startup"
    try:
        process = subprocess.Popen([*command, str(write_fd)], env=env, pass_fds=(write_fd,),
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(write_fd); write_fd = None
        if not select.select([read_fd], [], [], startup_timeout)[0]:
            raise subprocess.TimeoutExpired(command, startup_timeout)
        if os.read(read_fd, 1) != b"R":
            out, err = process.communicate(timeout=operation_timeout)
            raise AssertionError("Fixed fixture failed before readiness: " + err + out)
        ready = time.monotonic()
        phase = "fixed operation"
        out, err = process.communicate(timeout=operation_timeout)
        result = subprocess.CompletedProcess(command, process.returncode, out, err)
        result.fixture_timing = {"startup_seconds": ready-started,
                                 "operation_seconds": time.monotonic()-ready}
        return result
    except subprocess.TimeoutExpired as exc:
        process.kill()
        out, err = process.communicate()
        raise AssertionError(f"Fixed fixture {phase} exceeded its {exc.timeout}s bound; stdout={out!r}; stderr={err!r}") from exc
    finally:
        os.close(read_fd)
        if write_fd is not None: os.close(write_fd)
        if process is not None:
            if process.poll() is None:
                process.kill(); process.communicate()
            for stream in (process.stdout, process.stderr):
                if stream is not None: stream.close()


class FixtureWatchdogTests(unittest.TestCase):
    def test_startup_and_operation_are_distinguished_and_reaped(self):
        # A sleeping child could finish while a loaded host deschedules this
        # parent. Block until killed so the expected timeout has no such race.
        for phase, code in (("startup", "import signal;signal.pause()"),
                            ("fixed operation", "import os,sys,signal;os.write(int(sys.argv[1]),b'R');signal.pause()")):
            with self.subTest(phase=phase):
                children = []
                original = subprocess.Popen
                def spawn(*args, **kwargs):
                    child = original(*args, **kwargs)
                    children.append(child)
                    return child
                with patch.object(subprocess, "Popen", side_effect=spawn), self.assertRaisesRegex(AssertionError, phase):
                    bounded_fixture([sys.executable, "-I", "-B", "-c", code], env={"PATH":"/usr/bin:/bin"},
                                    startup_timeout=45 if phase=="fixed operation" else .05, operation_timeout=.05)
                self.assertEqual(len(children), 1)
                child = children[0]
                self.assertIsNotNone(child.poll())
                self.assertTrue(child.stdout.closed and child.stderr.closed)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(child.pid, os.WNOHANG)

    def test_ready_operation_preserves_output_and_measures_both_stages(self):
        result = bounded_fixture([sys.executable, "-I", "-B", "-c",
            "import os,sys;os.write(int(sys.argv[1]),b'R');print('done')"], env={"PATH":"/usr/bin:/bin"})
        self.assertEqual((result.returncode,result.stdout),(0,"done\n"))
        self.assertEqual(set(result.fixture_timing),{"startup_seconds","operation_seconds"})


def load(name):
    spec = importlib.util.spec_from_file_location(name, APPLIANCE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


factory = load("factory_host")
boot = load("host_boot")


class FactoryHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.fixture_invocations = []
        self.root = Path(temporary.name).resolve()
        def cleanup():
            for current, directories, files in os.walk(self.root):
                Path(current).chmod(0o700)
            temporary.cleanup()
        self.addCleanup(cleanup)
        self.source, source_manifest = fixture_source(self.root)
        self.etc, self.share = self.root / "etc/nebulalog", self.root / "usr/share/nebulalog"
        self.generations, self.state = self.root / "usr/lib/nebulalog/generations", self.root / "data/manager/updates"
        for path in (self.etc, self.share, self.generations.parent, self.state): path.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.fixed = {name: self.root / str(path).lstrip("/") for name, path in boot.FIXED.items()}
        snapshot = json.loads(source_manifest.read_bytes())
        for name, installed in self.fixed.items():
            raw = (APPLIANCE / Path(name).name).read_bytes()
            (self.source / name).write_bytes(raw)
            installed.parent.mkdir(parents=True, exist_ok=True)
            installed.write_bytes(raw)
            installed.chmod(0o755)
            snapshot["files"][name] = payload.digest(raw)
        # The actual subprocess will import only tiny inert fixture modules.
        for name, raw in (("appliance/nebulalog_manager/cli.py", b'import json,os\nprint(json.dumps({"loaded":"factory","generation":os.environ["NEBULALOG_HOST_GENERATION"]}))\n'),):
            (self.source / name).write_bytes(raw)
            snapshot["files"][name] = payload.digest(raw)
        snapshot["files"]["cmd/nebulalog/main.go"] = "a" * 64
        snapshot["files"].update(enrollment.application_schema.SCHEMAS["1"])
        for entry in payload.CATALOG:
            if not entry["path"].startswith("bin/"): continue
            name = Path(entry["path"]).name
            special = {"nebulalog": "usr/local/bin/nebulalog", "nebulalog-setup": "usr/local/sbin/nebulalog-setup",
                       "nebulalog-seal": "usr/local/sbin/nebulalog-seal"}
            installed = self.root / special.get(name, "usr/libexec/nebulalog/" + name)
            installed.parent.mkdir(parents=True, exist_ok=True)
            installed.write_bytes((self.source / entry["source"]).read_bytes())
            installed.chmod(0o755)
        self.source_manifest = self.share / "source-manifest.json"
        self.source_manifest.write_bytes(payload.encoded(snapshot))
        self.source_manifest.chmod(0o600)
        self.descriptor = {"schema": 1, "product": "nebulalog", "sequence": 0, "schema_revision": "1", "source_commit": "b" * 40,
                           "source_dirty": True, "qualification_status": "pending", "publisher": {"mode": "private-unsealed"},
                           "bundle_manifest_sha256": "c" * 64, "source_snapshot_sha256": payload.digest(self.source_manifest.read_bytes())}
        atomic_json(self.share / "initial-release.json", self.descriptor)
        self.manager = Mock()
        self.manager.verify_build_inputs.return_value = {"descriptor": self.descriptor, "descriptor_sha256": payload.digest((self.share / "initial-release.json").read_bytes())}
        self.enroller = enrollment.UpdateEnrollment(data=self.root / "data", etc=self.etc, share=self.share, runner=Mock())
        patches = [patch.object(factory, "guard"), patch.object(factory, "ETC", self.etc), patch.object(factory, "SHARE", self.share),
                   patch.object(factory, "FIXED", self.fixed), patch.object(payload, "GENERATIONS", self.generations),
                   patch.object(payload, "_OWNER_UID", os.getuid()), patch.object(payload, "_trusted_tree", fixture_tree(self.root)),
                   patch.object(payload, "require_linux_root"), patch.object(enrollment, "_tree", fixture_tree(self.root)),
                   patch.object(enrollment, "ROOT_UID", os.getuid()), patch.object(enrollment, "FIXED_HOST_FILES", self.fixed),
                   patch.object(enrollment, "FIXED_HOST_ROOT", self.root),
                   patch.object(boot, "OWNER", os.getuid()), patch.object(boot, "ETC", self.etc), patch.object(boot, "SHARE", self.share),
                   patch.object(boot, "GENERATIONS", self.generations), patch.object(boot, "STATE", self.state),
                   patch.object(boot, "FIXED", self.fixed), patch.object(boot, "tree", fixture_tree(self.root))]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def enroll(self):
        return factory.enroll(self.source / "appliance", self.source / "deploy/keycloak/realm.json", self.manager)

    def test_fixed_boot_verifier_binds_optional_factory_auth_receipts(self):
        from nebulalog_manager.image_bundle import RestoredAuthContract
        (self.share / "restore-auth").mkdir(mode=0o700)
        artifacts = {}
        for name in RestoredAuthContract.EVIDENCE:
            raw = b'{"fixed_boot_transfer_fixture":true}\n'
            path = self.share / "restore-auth" / name
            path.write_bytes(raw); path.chmod(0o600)
            artifacts[name] = {"bytes": len(raw), "sha256": payload.digest(raw)}
        self.descriptor.update(schema_revision="3", restore_auth={"schema": 1, "contract": RestoredAuthContract.CONTRACT,
            "version": "1.0.0", "artifacts": artifacts})
        atomic_json(self.share / "initial-release.json", self.descriptor)
        self.manager.verify_build_inputs.return_value = {"descriptor": self.descriptor,
            "descriptor_sha256": payload.digest((self.share / "initial-release.json").read_bytes())}
        self.enroll()
        _, descriptor = boot.factory()
        self.assertEqual(descriptor["restore_auth"], self.descriptor["restore_auth"])
        path.write_bytes(raw + b" ")
        with self.assertRaisesRegex(boot.Refused, "authentication evidence changed"):
            boot.factory()

    def accepted(self, host):
        current = {"sequence": 0, "version": "0.1.0", "components": {"host": host}}
        record = {"current": current, "initial_release_sha256": payload.digest((self.share / "initial-release.json").read_bytes())}
        atomic_json(self.state / "current.json", current)
        atomic_json(self.state / "initial-enrollment.json", record)
        return current

    def candidate(self, code=None, modules=None):
        current = json.loads(self.source_manifest.read_bytes())
        candidate = self.root / "candidate-source"
        shutil.copytree(self.source, candidate)
        if code is None: code = b'import json,os\nprint(json.dumps({"loaded":"candidate","generation":os.environ["NEBULALOG_HOST_GENERATION"]}))\n'
        name = "appliance/nebulalog_manager/cli.py"
        (candidate / name).write_bytes(code)
        current["files"][name] = payload.digest(code)
        for name, raw in (modules or {}).items():
            (candidate / name).write_bytes(raw)
            current["files"][name] = payload.digest(raw)
        manifest = self.root / "candidate-source.json"
        manifest.write_bytes(payload.encoded(current))
        archive = self.root / "candidate.tar"
        evidence = builder.build(candidate, manifest, archive, version="0.1.1")
        payload.stage_generation(archive, expected_sha256=evidence["archive_sha256"], expected_host_source_sha256=evidence["metadata"]["host_source_sha256"])
        return {"generation": evidence["archive_sha256"], "version": "0.1.1", "host_source_sha256": evidence["metadata"]["host_source_sha256"], "abi": 1}

    def transaction(self, old, new, phase="checking", finalization=None):
        previous = self.accepted(old)
        stage = self.state / "releases/1-fixture"
        stage.mkdir(parents=True, mode=0o700)
        change = {key: new[key] for key in ("version", "host_source_sha256", "abi")}
        manifest = {"schema": 1, "product": "nebulalog", "channel": "stable", "sequence": 1, "version": "0.1.1",
                    "components": {"host": {**change, "artifact": "host.tar", "rollback_safe": True}},
                    "artifacts": [{"name": "host.tar", "sha256": new["generation"], "bytes": 1}]}
        atomic_json(stage / "manifest.json", manifest)
        digest = payload.digest((stage / "manifest.json").read_bytes())
        transaction = {"state": phase, "sequence": 1, "previous": previous, "release": str(stage), "manifest_sha256": digest}
        if finalization is not None: transaction["finalization"] = finalization
        atomic_json(self.state / "transaction.json", transaction)
        atomic_json(stage / "host-activation.json", {"schema": 1, "state": "selected", "sequence": 1, "manifest_sha256": digest,
                    "coordinator": {"schema": 1, **old, "sequence": 1, "manifest_sha256": digest}, "candidate": new,
                    "previous_selection": {"schema": 1, "generation": old["generation"], "sequence": 0}})
        atomic_json(self.etc / "host-selection.json", {"schema": 1, "generation": new["generation"], "sequence": 1})
        committed = {"sequence": 1, "version": "0.1.1", "components": {"host": new}, "release": str(stage)}
        if phase == "committed": atomic_json(self.state / "current.json", committed)
        return transaction, committed

    def invoke(self, command="nebulalog"):
        # There are no path/UID overrides in the production CLI. This isolated
        # launcher injects fixture constants before calling the real fixed main.
        setup = """import importlib.util,json,pathlib,os,sys,stat
spec=importlib.util.spec_from_file_location('fixed_boot_fixture',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
root=pathlib.Path(sys.argv[2]); m.OWNER=os.getuid(); m.ETC=root/'etc/nebulalog';m.SHARE=root/'usr/share/nebulalog';m.GENERATIONS=root/'usr/lib/nebulalog/generations';m.STATE=root/'data/manager/updates'
m.FIXED={name:root/str(path).lstrip('/') for name,path in m.FIXED.items()}
def protected(path):
 for p in (path,*path.parents):
  if not p.is_relative_to(root): break
  s=p.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o022: raise m.Refused('fixture ancestry')
m.tree=protected
os.write(int(sys.argv[4]),b'R');os.close(int(sys.argv[4]))
raise SystemExit(m.main([sys.argv[3]]))
"""
        result = bounded_fixture([sys.executable, "-I", "-B", "-c", setup, str(APPLIANCE / "host_boot.py"), str(self.root), command],
                                 env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "/untrusted/ignored"})
        self.fixture_invocations.append({"command":command,**result.fixture_timing})
        return result

    def test_factory_matches_canonical_builder_and_verifies_without_runtime(self):
        result = self.enroll()
        expected = self.root / "canonical.tar"
        evidence = builder.build(self.source, self.source_manifest, expected, version=result["host"]["version"])
        self.assertEqual(evidence["archive_sha256"], result["host"]["generation"])
        self.assertFalse(result["runtime_qualified"])
        self.assertEqual(self.enroller._factory_host(self.descriptor), result["host"])
        self.assertEqual(self.enroll(), result)
        record, initial = boot.factory()
        self.assertEqual(boot.generation(result["host"], record), self.generations / result["host"]["generation"])
        self.assertEqual(boot.choose(record, initial, "nebulalog", []), (result["host"], "factory"))

    def test_changed_captured_bytes_and_unproposed_selection_refuse(self):
        source = self.source / payload.CATALOG[0]["source"]
        source.write_bytes(b"changed")
        with self.assertRaisesRegex(Refused, "captured source"): self.enroll()
        self.assertFalse((self.share / "initial-host-pending.json").exists())

    def test_initial_aide_mapping_checks_all_fixed_wrappers_and_source_modules(self):
        host = self.enroll()["host"]
        result = self.enroller.verify_initial_host_installation()
        self.assertTrue(result["verified"])
        self.assertEqual(result["host"], host)
        self.assertEqual(result["source_mappings"]["appliance/nebulalog_manager/aide.py"],
                         str(self.generations / host["generation"] / "lib/nebulalog_manager/aide.py"))
        path = self.root / "usr/libexec/nebulalog/nebulalog-aide"
        path.write_text("unexpected wrapper substitution\n")
        with self.assertRaisesRegex(Refused, "fixed entrypoint"): self.enroller.verify_initial_host_installation()

    def test_build_guard_validates_only_source_measured_initial_selection(self):
        self.enroll()
        guard = load("provision_guard")
        checker = guard.BuildGuard(self.root, os.getuid(), os.getgid())
        checker.factory_host()
        atomic_json(self.etc / "host-selection.json", {"schema": 1, "generation": "f" * 64, "sequence": 0})
        with self.assertRaisesRegex(guard.Refused, "selection differs"): checker.factory_host()

    def test_partial_factory_enrollment_resumes_only_exact_pending_identity(self):
        original = factory._same_or_write
        def interrupted(path, value):
            if path.name == "host-selection.json": raise OSError("power loss")
            return original(path, value)
        with patch.object(factory, "_same_or_write", side_effect=interrupted), self.assertRaises(OSError): self.enroll()
        self.assertTrue((self.share / "initial-host-pending.json").exists())
        self.assertFalse((self.etc / "host-selection.json").exists())
        result = self.enroll()
        self.assertEqual(self.enroller._factory_host(self.descriptor), result["host"])
        (self.share / "initial-host-pending.json").unlink()
        with self.assertRaisesRegex(Refused, "durable factory proposal"): self.enroll()

    def test_fixed_shim_and_generation_tampering_refuse_before_import(self):
        host = self.enroll()["host"]
        self.accepted(host)
        path = self.generations / host["generation"] / "lib/nebulalog_manager/cli.py"
        path.chmod(0o644)
        path.write_text('raise SystemExit("UNSAFE IMPORT")\n')
        path.chmod(0o444)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("UNSAFE IMPORT", result.stderr + result.stdout)
        self.assertIn("refused", result.stderr)

    def test_fresh_accepted_and_pending_subprocess_routes_use_measured_authority(self):
        old = self.enroll()["host"]
        self.accepted(old)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["loaded"], "factory")
        new = self.candidate()
        transaction, committed = self.transaction(old, new)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["generation"], old["generation"])
        # Candidate current can be durable before committed phase is written.
        atomic_json(self.state / "current.json", committed)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["loaded"], "factory")
        transaction.update(state="committed", finalization="failed")
        atomic_json(self.state / "transaction.json", transaction)
        self.assertEqual(json.loads(self.invoke().stdout)["loaded"], "factory")
        transaction["finalization"] = "complete"
        atomic_json(self.state / "transaction.json", transaction)
        self.assertEqual(json.loads(self.invoke().stdout)["loaded"], "candidate")

    def test_pending_damaged_candidate_archive_not_needed_but_old_generation_required(self):
        old = self.enroll()["host"]
        new = self.candidate()
        self.transaction(old, new)
        # No candidate archive was installed in the stage at all.
        candidate_file = self.generations / new["generation"] / "lib/nebulalog_manager/cli.py"
        candidate_file.chmod(0o644)
        candidate_file.write_text("corrupt candidate")
        candidate_file.chmod(0o444)
        self.assertEqual(self.invoke().returncode, 0)
        self.assertNotEqual(self.invoke("verify-selected").returncode, 0)
        old_file = self.generations / old["generation"] / "lib/nebulalog_manager/cli.py"
        old_file.chmod(0o644)
        old_file.write_text("corrupt old")
        old_file.chmod(0o444)
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_ambiguous_corrupt_or_linked_journal_cannot_import_candidate(self):
        old, new = self.enroll()["host"], self.candidate()
        transaction, _ = self.transaction(old, new)
        path = self.state / "transaction.json"
        for replacement in ({**transaction, "manifest_sha256": "0" * 64}, {**transaction, "release": str(self.root)},
                            {**transaction, "sequence": True}, {**transaction, "previous": {"sequence": 0, "components": {}}}):
            atomic_json(path, replacement)
            self.assertNotEqual(self.invoke().returncode, 0)
        atomic_json(path, transaction)
        target = self.root / "journal.json"
        path.rename(target)
        path.symlink_to(target)
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_readonly_selected_probe_has_exact_identity_without_candidate_cli(self):
        old, new = self.enroll()["host"], self.candidate()
        self.transaction(old, new)
        result = self.invoke("verify-selected")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"schema": 1, **new, "selection_sequence": 1, "verified": True})
        result = self.invoke("probe-selected")
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value["runtime_imported"])
        self.assertTrue(value["coordinator_verified"])
        self.assertEqual(value["coordinator_generation"], old["generation"])
        self.assertEqual(set(value["origins"]), set(boot.PROBE_MODULES))

    def test_import_side_effect_guard_denies_network_subprocess_and_file_writes(self):
        for event, args in (("socket.__new__", ()), ("subprocess.Popen", ()), ("os.remove", ()),
                            ("open", ("file", "w", os.O_WRONLY)), ("open", ("file", None, os.O_RDWR)), ("ctypes.dlopen", ("lib",))):
            with self.subTest(event=event), self.assertRaises(boot.Refused): boot.import_guard(event, args)
        boot.import_guard("open", ("file", "r", os.O_RDONLY))

    def test_real_probe_import_refuses_file_creation_before_candidate_hook(self):
        old = self.enroll()["host"]
        target = self.root / "must-not-exist"
        raw = ("from pathlib import Path\nPath(" + repr(str(target)) + ").write_text('unsafe')\n").encode()
        new = self.candidate(modules={"appliance/nebulalog_manager/updates.py": raw})
        self.transaction(old, new)
        result = self.invoke("probe-selected")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists())
        self.assertIn("refused", result.stderr)

    def test_real_probe_import_refuses_subprocess_start(self):
        old = self.enroll()["host"]
        raw = b"import subprocess\nsubprocess.run(['/usr/bin/true'],check=True)\n"
        new = self.candidate(modules={"appliance/nebulalog_manager/updates.py": raw})
        self.transaction(old, new)
        result = self.invoke("probe-selected")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refused", result.stderr)

    def test_wrappers_and_timer_units_enter_fixed_isolated_dispatch(self):
        for name in set(boot.COMMANDS) - {"github-updates", "os-updates"}:
            self.assertIn('/usr/bin/python3.14 -I -B /usr/libexec/nebulalog/host-boot ' + name + ' "$@"', (APPLIANCE / "bin" / name).read_text())
        for name in boot.ADAPTERS:
            self.assertIn('/usr/bin/python3.14 -I -B /usr/libexec/nebulalog/host-boot ' + name + ' "$@"', (APPLIANCE / "adapters/bin" / name).read_text())
        for unit, command in (("nebulalog-app-update.service", "github-updates"), ("nebulalog-os-update.service", "os-updates")):
            text = (APPLIANCE / "systemd" / unit).read_text()
            self.assertIn("ExecStart=/usr/bin/python3.14 -I -B /usr/libexec/nebulalog/host-boot " + command, text)
            self.assertNotIn("PYTHONPATH", text)


if __name__ == "__main__": unittest.main()
