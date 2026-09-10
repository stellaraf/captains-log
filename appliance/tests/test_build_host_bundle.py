"""Frozen source/build tests; generation extraction is inert and never installed."""
import ast
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager import host_payload as payload
from nebulalog_manager.common import Refused
import test_host_payload as fixtures


class BuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.root = Path(temporary.name).resolve()
        self.addCleanup(temporary.cleanup)
        self.source, self.manifest = fixtures.fixture_source(self.root)
        self.output = self.root / "host.tar"

    def build(self):
        return fixtures.builder.build(self.source, self.manifest, self.output, version="0.1.1")

    def change_manifest(self, function):
        value = json.loads(self.manifest.read_text())
        function(value)
        self.manifest.write_bytes(payload.encoded(value))

    def test_deterministic_archive_despite_mtime_and_allowed_source_mode_changes(self):
        first = self.build()
        raw = self.output.read_bytes()
        self.output = self.root / "second.tar"
        for entry in payload.CATALOG:
            path = self.source / entry["source"]
            path.chmod(0o755)
            os.utime(path, (1000000000, 1000000000))
        second = self.build()
        self.assertEqual(raw, self.output.read_bytes())
        self.assertEqual(first["archive_sha256"], second["archive_sha256"])
        self.assertFalse(second["signature_created"])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_uncaptured_files_and_captured_public_trust_never_enter_payload(self):
        for name in ("appliance/security/publisher-public.spki", "appliance/security/publisher-trust.json", "appliance/security/trust.json"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"public trust fixture")
            self.change_manifest(lambda value: value["files"].update({name: payload.digest(path.read_bytes())}))
        secret = self.source / ".local/credentials.json"
        secret.parent.mkdir(); secret.write_text("uncaptured fixture")
        result = self.build()
        selected = {item["source"] for item in result["metadata"]["files"]}
        self.assertFalse(any("trust" in name or name.endswith(".spki") or ".local" in name for name in selected))
        self.assertEqual(selected, payload.CATALOG_BY_SOURCE.keys())

    def test_missing_or_changed_frozen_source_refuses_publication(self):
        target = self.source / payload.CATALOG[0]["source"]
        for mutation in (lambda: target.write_text("changed"), lambda: target.unlink()):
            mutation()
            with self.assertRaises((Refused, OSError)):
                self.build()
            self.assertFalse(self.output.exists())

    def test_missing_required_or_uncataloged_runtime_file_refuses(self):
        original = self.manifest.read_bytes()
        for mutate in (lambda value: value["files"].pop(payload.CATALOG[0]["source"]),
                       lambda value: value["files"].update({"appliance/nebulalog_manager/new_runtime.py": "a" * 64})):
            self.manifest.write_bytes(original)
            self.change_manifest(mutate)
            with self.assertRaises(Refused):
                self.build()
            self.assertFalse(self.output.exists())

    def test_generated_credential_traversal_or_invalid_manifest_refuses(self):
        original = self.manifest.read_bytes()
        for name in (".env", ".local/credentials.json", "appliance/private.key", "appliance/private.pem", "appliance/output/disk.qcow2", "web/node_modules/module.js", "appliance/../escape", "/outside"):
            self.manifest.write_bytes(original)
            self.change_manifest(lambda value: value["files"].update({name: "a" * 64}))
            with self.subTest(name=name), self.assertRaises(Refused):
                self.build()
        for raw in (b'{"schema":1,"schema":1}', b'{"schema":true,"files":{}}'):
            self.manifest.write_bytes(raw)
            with self.assertRaises(Refused):
                self.build()
        self.assertFalse(self.output.exists())

    def test_source_links_fifo_and_writable_or_setuid_mode_refused(self):
        target = self.source / payload.CATALOG[0]["source"]
        original = target.read_bytes()
        alias = self.root / "source-copy"
        alias.write_bytes(original)
        for kind in ("symlink", "hardlink", "fifo", "writable", "setuid"):
            target.unlink()
            if kind == "symlink": target.symlink_to(alias)
            elif kind == "hardlink": os.link(alias, target)
            elif kind == "fifo": os.mkfifo(target)
            else:
                target.write_bytes(original)
                target.chmod(0o666 if kind == "writable" else 0o4644)
            with self.subTest(kind=kind), self.assertRaises(Refused):
                self.build()
            self.assertFalse(self.output.exists())

    def test_parent_symlink_and_manifest_hardlink_refused(self):
        original = self.source / "appliance/nebulalog_manager"
        moved = self.root / "manager"
        original.rename(moved)
        original.symlink_to(moved)
        with self.assertRaises(Refused): self.build()
        original.unlink(); moved.rename(original)
        os.link(self.manifest, self.root / "manifest-alias")
        with self.assertRaises(Refused): self.build()

    def test_private_key_marker_is_refused_even_when_frozen_hash_matches(self):
        name = payload.CATALOG[0]["source"]
        target = self.source / name
        target.write_bytes(b"-----BEGIN PRIVATE KEY-----\nfixture only\n-----END PRIVATE KEY-----\n")
        self.change_manifest(lambda value: value["files"].update({name: payload.digest(target.read_bytes())}))
        with self.assertRaisesRegex(Refused, "Private key"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_competing_output_is_preserved_and_only_temporary_output_is_removed(self):
        original = payload.verify_archive
        sentinel = self.root / "customer-config"
        sentinel.write_text("unchanged")
        def compete(*args, **kwargs):
            result = original(*args, **kwargs)
            self.output.write_text("another publisher owns this path")
            return result
        with patch.object(payload, "verify_archive", side_effect=compete), self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(self.output.read_text(), "another publisher owns this path")
        self.assertEqual(sentinel.read_text(), "unchanged")
        self.assertFalse(list(self.root.glob(".pending-host-bundle-*")))

    def test_source_or_frozen_manifest_mutation_during_build_prevents_publication(self):
        original = payload.tar_header
        source = self.source / payload.CATALOG[0]["source"]
        source_before, manifest_before = source.read_bytes(), self.manifest.read_bytes()
        for target in (source, self.manifest):
            changed = False
            def race(*args, **kwargs):
                nonlocal changed
                if not changed:
                    changed = True
                    target.write_bytes(target.read_bytes() + b" ")
                return original(*args, **kwargs)
            with self.subTest(target=target.name), patch.object(payload, "tar_header", side_effect=race), self.assertRaises(Refused):
                self.build()
            self.assertFalse(self.output.exists())
            self.assertFalse(list(self.root.glob(".pending-host-bundle-*")))
            source.write_bytes(source_before); self.manifest.write_bytes(manifest_before)

    def test_existing_output_refused_without_touching_it(self):
        self.output.write_text("existing artifact")
        with self.assertRaises(Refused): self.build()
        self.assertEqual(self.output.read_text(), "existing artifact")

    def test_source_and_metadata_limits_refuse_before_output(self):
        for setting in ("MAX_FILE", "MAX_TOTAL", "MAX_SOURCE_MANIFEST"):
            with patch.object(payload, setting, 1), self.subTest(setting=setting), self.assertRaises(Refused):
                self.build()
            self.assertFalse(self.output.exists())

    def test_catalog_covers_current_runtime_files_and_relative_import_dependencies(self):
        repository = Path(__file__).resolve().parents[2]
        source_files = {str(path.relative_to(repository)) for prefix in payload.MANAGED_PREFIXES
                        for path in (repository / prefix).rglob("*") if path.is_file() and "__pycache__" not in path.parts}
        self.assertEqual(source_files, {source for source in payload.CATALOG_BY_SOURCE if source.startswith(payload.MANAGED_PREFIXES)})
        modules = {"nebulalog_manager": set(payload.MANAGER_MODULES), "nebulalog_adapters": set(payload.ADAPTER_MODULES)}
        for source in payload.CATALOG_BY_SOURCE:
            if not source.endswith(".py"): continue
            package = "nebulalog_adapters" if "/nebulalog_adapters/" in source else "nebulalog_manager"
            tree = ast.parse((repository / source).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level == 1 and node.module:
                        self.assertIn(node.module.split(".")[0] + ".py", modules[package])
                    elif node.module and node.module.split(".")[0] in modules and "." in node.module:
                        module_package, module = node.module.split(".", 1)
                        self.assertIn(module.split(".")[0] + ".py", modules[module_package])

    def test_actual_host_modules_import_from_isolated_staged_tree_without_actions(self):
        repository = Path(__file__).resolve().parents[2]
        files = {}
        for entry in payload.CATALOG:
            raw = (repository / entry["source"]).read_bytes()
            target = self.source / entry["source"]
            target.write_bytes(raw)
            files[entry["source"]] = payload.digest(raw)
        self.manifest.write_bytes(payload.encoded({"schema": 1, "files": files}))
        evidence = self.build()
        generations = self.root / "generations"
        with patch.object(payload, "GENERATIONS", generations), patch.object(payload, "require_linux_root"), patch.object(payload, "_OWNER_UID", os.getuid()), patch.object(payload, "_trusted_tree", side_effect=fixtures.fixture_tree(self.root)):
            result = payload.stage_generation(self.output, expected_sha256=evidence["archive_sha256"],
                                              expected_host_source_sha256=evidence["metadata"]["host_source_sha256"])
        generation = Path(result["generation"])
        def cleanup():
            for path in (generation, *generation.rglob("*")):
                if path.is_dir() and not path.is_symlink(): path.chmod(0o700)
        self.addCleanup(cleanup)
        modules = [package + "." + name.removesuffix(".py") for package, names in
                   (("nebulalog_manager", payload.MANAGER_MODULES), ("nebulalog_adapters", payload.ADAPTER_MODULES))
                   for name in names if name != "__init__.py"]
        script = '''import importlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0,str(root))
def deny_actions(event,args):
    if event.startswith("subprocess.") or event in {"os.system","os.posix_spawn","socket.connect","socket.bind","os.mkdir","os.remove","os.rename"}:
        raise RuntimeError("Module import attempted a forbidden action")
sys.addaudithook(deny_actions)
names=json.loads(sys.argv[2])
for name in names:
    module=importlib.import_module(name)
    if not pathlib.Path(module.__file__).resolve().is_relative_to(root):
        raise RuntimeError("Module imported outside the staged payload")
print(json.dumps({"imported_modules":len(names),"actions_executed":False}))
'''
        checked = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(generation / "lib"), json.dumps(modules)],
                                 check=True, capture_output=True, text=True, timeout=30)
        self.assertEqual(json.loads(checked.stdout), {"imported_modules": len(modules), "actions_executed": False})


if __name__ == "__main__":
    unittest.main()
