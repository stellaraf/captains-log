"""Deterministic filesystem/scan transaction fixtures, never real host updates."""
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from nebulalog_manager import aide, aide_updates as updates, host_payload
from nebulalog_manager.common import Refused
from nebulalog_manager.host_job_storage import digest
import test_aide_lifecycle as lifecycle_fixture


class AuthorizedAideTests(unittest.TestCase):
    # Reuse only fixture helpers; enrollment regression remains in its own suite.
    for _name in ("write_private", "reader", "facts", "monitor", "fresh", "run_fixture", "enrolled"):
        locals()[_name] = getattr(lifecycle_fixture.AideLifecycleTests, _name)

    def setUp(self):
        lifecycle_fixture.AideLifecycleTests.setUp(self)

    def authorized_fixture(self):
        self.runtime = self.root / "managed.conf"
        self.selection = self.root / "host-selection.json"
        self.unrelated = self.root / "unrelated.conf"
        for path, raw in ((self.runtime, b"old managed\n"), (self.selection, b"old selection\n"), (self.unrelated, b"preserved\n")):
            self.write_private(path, raw)
        self.monitored = [self.runtime, self.selection, self.unrelated]
        # This macOS Python has no os xattr API. Inject empty Linux metadata
        # evidence only in this fixture; production refuses unsupported hosts.
        metadata = patch.object(updates, "_metadata", return_value={"xattrs_sha256": digest({}), "acl_sha256": digest({}), "selinux_sha256": digest({})})
        metadata.start()
        self.addCleanup(metadata.stop)
        self.manager.runner = self.scan_runner
        self.scan_hook = None
        self.scan_calls = []
        self.candidate, self.base = self.enrolled()
        self.original = {path: path.read_bytes() for path in (self.marker, self.state / "candidate.json", self.state / "candidate.db.gz", self.state / "commit-pending.json")}
        self.initial_db = (self.state / "aide.db.gz").read_bytes()
        self.generation = self.root / ("d" * 64)
        self.generation.mkdir(mode=0o555)
        self.generation.chmod(0o755)
        self.code = self.generation / "module.py"
        self.code.write_bytes(b"candidate inert code\n")
        self.code.chmod(0o444)
        self.generation.chmod(0o555)
        self.monitored.extend([self.generation, self.code])
        self.plan = {"schema": 1, "sequence": 2, "manifest_sha256": "b" * 64, "coordinator_generation": "c" * 64,
                     "candidate_generation": "d" * 64, "files": [{"path": str(self.runtime), "before": self.desc(self.runtime), "after": self.desc(self.runtime, b"new managed\n")}],
                     "selection": {"path": str(self.selection), "before": self.desc(self.selection), "after": self.desc(self.selection, b"new selection\n"), "restored": self.desc(self.selection, b"restored selection highwater\n")},
                     "generation_additions": [{"path": str(path), **self.desc(path)} for path in (self.generation, self.code)],
                     "preserved": [{"path": str(self.unrelated), **self.desc(self.unrelated)}], "migration_only": []}
        self.stage = self.root / "release"
        self.stage.mkdir(mode=0o700)
        self.plan_path = self.stage / "host-runtime-plan.json"
        self.write_private(self.plan_path, json.dumps(self.plan).encode())
        self.bound = patch.object(updates, "_bound_plan", side_effect=lambda *_args, **_kwargs: (copy.deepcopy(self.plan), hashlib.sha256(self.plan_path.read_bytes()).hexdigest()))
        self.bound.start()
        self.addCleanup(self.bound.stop)
        tree = patch.object(host_payload, "_trusted_tree", side_effect=self.trusted_tree)
        tree.start()
        self.addCleanup(tree.stop)

    def trusted_tree(self, path):
        self.assertTrue(path.is_relative_to(self.root))
        for item in [path, *list(path.parents)[:len(path.relative_to(self.root).parts)]]:
            info = item.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or info.st_uid != os.getuid():
                raise Refused("unsafe_fixture_ancestry")

    def desc(self, path, raw=None):
        info = path.lstat()
        value = {"kind": "directory" if path.is_dir() else "file", "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
        if value["kind"] == "file":
            raw = path.read_bytes() if raw is None else raw
            value.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        return value

    def snapshot_files(self):
        value = {}
        for path in self.monitored:
            if path.exists():
                info = path.lstat()
                value[str(path)] = {**self.desc(path), "inode": info.st_ino, "mtime": info.st_mtime_ns,
                                    "ctime": info.st_ctime_ns, "metadata": updates._metadata(path)}
        return value

    def scan_runner(self, argv, *, tmpdir, **kwargs):
        self.assertEqual(Path(tmpdir), self.state / "tmp")
        if argv[0] == "/usr/sbin/restorecon":
            return aide.Result(0)
        self.assertEqual(argv[0], "/usr/sbin/aide")
        config = Path(argv[1].split("=", 1)[1])
        options = dict(line.split("=", 1) for line in config.read_text().splitlines() if "=" in line and not line.startswith("#"))
        source, output = [Path(options[key].removeprefix("file:")) for key in ("database_in", "database_out")]
        action = argv[-1].removeprefix("--")
        if action == "config-check":
            return aide.Result(0)
        self.scan_calls.append(action)
        current = self.snapshot_files()
        initializing = action == "init"
        old = {} if initializing else json.loads(gzip.decompress(source.read_bytes()))
        if action in ("init", "update"):
            self.assertFalse(output.exists(), "scan must never overwrite retained output")
            self.write_private(output, gzip.compress(json.dumps(current, sort_keys=True).encode(), mtime=0))
        added, removed = set(current) - set(old), set(old) - set(current)
        changed = {path for path in set(current) & set(old) if current[path] != old[path]}
        code = 0 if initializing else int(bool(added)) + 2 * int(bool(removed)) + 4 * int(bool(changed))
        report = {"aide_version": "0.19.2", "start_time": self.now, "end_time": self.now, "run_time_seconds": 0,
                  "outline": "Measured fixture filesystem report", "number_of_entries": {"total": len(current)},
                  "databases": {str(output if initializing else source): {"sha512": "b" * 128}}}
        if not initializing:
            for name, paths in (("added", added), ("removed", removed), ("changed", changed)):
                report["number_of_entries"][name] = len(paths)
                if paths:
                    report[name] = {path: "f ... fixture" for path in sorted(paths)}
        if action in ("init", "update"):
            report["new_database"] = str(output)
            report["databases"][str(output)] = {"sha512": "c" * 128}
        if self.scan_hook:
            self.scan_hook(action, source, output)
        return aide.Result(code, json.dumps(report))

    def prepare_update(self):
        return updates.prepare(self.manager, self.stage, self.plan_path)

    def activate(self):
        self.runtime.write_bytes(b"new managed\n")
        self.selection.write_bytes(b"new selection\n")

    def accept_update(self, direction="forward"):
        return updates.accept(self.manager, self.stage, self.plan_path, direction=direction)

    def assert_original(self):
        for path, raw in self.original.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_authorized_prepare_allows_only_exact_additions_without_changing_baseline(self):
        self.authorized_fixture()
        self.assertTrue(self.prepare_update()["ok"])
        self.assertTrue(self.prepare_update()["ok"])
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)
        self.assertEqual(self.scan_calls.count("init"), 1)
        self.assertEqual(self.scan_calls.count("update"), 0)
        self.assert_original()

    def test_authorized_forward_and_rollback_preserve_original_and_publish_fresh_checks(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        forward = self.accept_update()
        self.assertTrue(forward["ok"])
        self.assertNotEqual(forward["database_sha256"], self.base["database_sha256"])
        self.assertEqual(self.manager.status()["last_check"]["state"], "clean")
        self.assertEqual(self.manager.check()["state"], "clean")
        self.assertFalse(self.accept_update()["baseline_changed"])
        self.assertEqual(self.scan_calls.count("update"), 1)
        self.runtime.write_bytes(b"old managed\n")
        self.selection.write_bytes(b"restored selection highwater\n")
        self.assertTrue(self.accept_update("rollback")["ok"])
        self.assertEqual(self.manager.check()["state"], "clean")
        self.assertTrue(self.code.exists())
        self.assertEqual(len(list((self.state / "authorized/entries").glob("*.json"))), 2)
        self.assert_original()

    def test_authorized_preparation_refuses_preexisting_drift_even_in_allowed_file(self):
        self.authorized_fixture()
        # A same-byte rewrite changes inode/ctime evidence. Preflight must not
        # authorize it merely because that filename is an eventual target.
        self.runtime.write_bytes(self.runtime.read_bytes())
        with self.assertRaisesRegex(Refused, "unrelated_integrity_change"):
            self.prepare_update()
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)

    def test_authorized_update_refuses_unrelated_race_in_fresh_check(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        self.scan_hook = lambda action, *_: self.unrelated.write_bytes(b"intrusion\n") if action == "update" else None
        with self.assertRaises(Refused):
            self.accept_update()
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)
        with self.assertRaisesRegex(Refused, "pending_recovery"):
            self.manager.status()
        self.assert_original()

    def test_authorized_update_refuses_unrelated_report_and_never_runs_init(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        extra = self.root / "extra.conf"
        self.write_private(extra, b"unexpected\n")
        self.monitored.append(extra)
        with self.assertRaisesRegex(Refused, "unrelated_integrity_change"):
            self.accept_update()
        self.assertEqual(self.scan_calls.count("init"), 1)
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)

    def test_authorized_preserved_metadata_change_is_refused(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        original = updates._metadata
        def changed(path):
            value = original(path)
            if path == self.runtime:
                value["acl_sha256"] = "e" * 64
            return value
        with patch.object(updates, "_metadata", side_effect=changed), self.assertRaisesRegex(Refused, "acl_xattrs_or_selinux"):
            self.accept_update()
        self.assertEqual(self.scan_calls.count("update"), 0)

    def test_authorized_plan_mutation_and_candidate_corruption_are_refused(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        self.plan_path.write_bytes(self.plan_path.read_bytes() + b" ")
        with self.assertRaisesRegex(Refused, "prepared_plan_changed"):
            self.accept_update()
        self.plan_path.write_bytes(json.dumps(self.plan).encode())
        self.code.chmod(0o644)
        self.code.write_bytes(b"bad\n")
        self.code.chmod(0o444)
        with self.assertRaisesRegex(Refused, "live_file_not_authorized"):
            self.accept_update()

    def test_authorized_crash_after_database_cas_recovers_exact_entry(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        replace = updates._replace_current
        def crash(*args):
            replace(*args)
            raise OSError("injected power loss after database rename")
        with patch.object(updates, "_replace_current", side_effect=crash), self.assertRaises(OSError):
            self.accept_update()
        self.assertNotEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)
        with self.assertRaisesRegex(Refused, "pending_recovery"):
            self.manager.status()
        self.assertTrue(self.accept_update()["ok"])
        self.assertEqual(self.scan_calls.count("update"), 1)
        self.assertEqual(self.manager.check()["state"], "clean")
        self.assert_original()

    def test_authorized_scanning_crash_retries_new_output_without_reinitializing(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        def crash(action, *_):
            if action == "update":
                raise OSError("injected interrupted scan")
        self.scan_hook = crash
        with self.assertRaises(OSError):
            self.accept_update()
        self.scan_hook = None
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)
        self.assertTrue(self.accept_update()["ok"])
        self.assertEqual(self.scan_calls.count("init"), 1)
        self.assertEqual(self.scan_calls.count("update"), 2)

    def test_authorized_chain_corruption_and_current_db_replacement_refuse_monitoring(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        self.accept_update()
        head = json.loads((self.state / "authorized/head.json").read_text())
        path = self.state / "authorized/entries" / (head["id"] + ".json")
        original = path.read_bytes()
        value = json.loads(original)
        value["previous_database_sha256"] = "0" * 64
        self.write_private(path, json.dumps(value).encode())
        with self.assertRaisesRegex(Refused, "baseline_chain_invalid"):
            self.manager.status()
        self.write_private(path, original)
        self.write_private(self.state / "aide.db.gz", self.initial_db)
        with self.assertRaisesRegex(Refused, "current_database_changed"):
            self.manager.status()

    def test_authorized_same_direction_repeat_refuses_new_ctime_drift(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        self.accept_update()
        self.runtime.write_bytes(self.runtime.read_bytes())
        with self.assertRaisesRegex(Refused, "no_longer_clean"):
            self.accept_update()
        self.assertEqual(self.scan_calls.count("update"), 1)

    def test_authorized_update_parser_requires_both_exact_databases(self):
        report = {"aide_version": "0.19.2", "start_time": self.now, "end_time": self.now, "run_time_seconds": 0,
                  "outline": "update fixture", "number_of_entries": {"total": 3, "added": 0, "removed": 0, "changed": 1},
                  "changed": {"/etc/managed": "f ..."}, "new_database": "/private/output.db.gz",
                  "databases": {"/private/input.db.gz": {}, "/private/output.db.gz": {}}}
        _, measured = updates._parse_update(aide.Result(4, json.dumps(report)), Path("/private/input.db.gz"), Path("/private/output.db.gz"))
        self.assertEqual(measured["counts"]["changed"], 1)
        del report["databases"]["/private/input.db.gz"]
        with self.assertRaises(Refused):
            updates._parse_update(aide.Result(4, json.dumps(report)), Path("/private/input.db.gz"), Path("/private/output.db.gz"))

    def test_authorized_rollback_from_interrupted_forward_scan(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        def crash(action, *_):
            if action == "update":
                raise OSError("interrupted before ready journal")
        self.scan_hook = crash
        with self.assertRaises(OSError):
            self.accept_update()
        self.scan_hook = None
        self.runtime.write_bytes(b"old managed\n")
        self.selection.write_bytes(b"restored selection highwater\n")
        self.assertTrue(self.accept_update("rollback")["ok"])
        self.assertEqual(self.manager.check()["state"], "clean")
        self.assertEqual(self.scan_calls.count("init"), 1)
        self.assert_original()

    def test_authorized_rollback_from_interrupted_forward_cas(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        replace = updates._replace_current
        def crash(*args):
            replace(*args)
            raise OSError("interrupted after CAS before head")
        with patch.object(updates, "_replace_current", side_effect=crash), self.assertRaises(OSError):
            self.accept_update()
        self.runtime.write_bytes(b"old managed\n")
        self.selection.write_bytes(b"restored selection highwater\n")
        self.assertTrue(self.accept_update("rollback")["ok"])
        self.assertEqual(self.manager.check()["state"], "clean")
        self.assertEqual(len(list((self.state / "authorized/entries").glob("*.json"))), 2)
        self.assert_original()

    def test_authorized_corrupt_retained_evidence_refuses_recovery_before_cas(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        with patch.object(updates, "_replace_current", side_effect=OSError("before CAS")), self.assertRaises(OSError):
            self.accept_update()
        pending = json.loads((self.state / "authorized/pending.json").read_text())
        report = self.state / "reports" / (pending["proposed_entry"]["check_report"]["id"] + ".json")
        value = json.loads(report.read_text())
        value["stdout"] = "corrupted evidence"
        self.write_private(report, json.dumps(value).encode())
        with self.assertRaisesRegex(Refused, "retained_record_changed"):
            self.accept_update()
        self.assertEqual((self.state / "aide.db.gz").read_bytes(), self.initial_db)

    def test_authorized_crash_after_entry_before_head_is_resumable(self):
        self.authorized_fixture()
        self.prepare_update()
        self.activate()
        write = self.manager.records.write
        def crash(path, value, identity):
            if path == self.state / "authorized/head.json":
                raise OSError("head write interrupted")
            return write(path, value, identity)
        with patch.object(self.manager.records, "write", side_effect=crash), self.assertRaises(OSError):
            self.accept_update()
        self.assertTrue(self.accept_update()["ok"])
        self.assertEqual(self.scan_calls.count("update"), 1)

    def test_linux_metadata_hash_covers_acl_selinux_and_other_xattrs(self):
        path = self.root / "metadata-file"
        path.write_bytes(b"metadata fixture")
        values = {"system.posix_acl_access": b"acl", "system.posix_acl_default": b"default", "security.selinux": b"label", "user.product": b"xattr"}
        with patch.object(os, "listxattr", return_value=list(values), create=True), patch.object(os, "getxattr", side_effect=lambda _path, name, **_: values[name], create=True):
            observed = updates._metadata(path)
            hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in values.items()}
            self.assertEqual(observed["xattrs_sha256"], digest(hashes))
            self.assertEqual(observed["acl_sha256"], digest({name: value for name, value in hashes.items() if name.startswith("system.posix_acl_")}))
            self.assertEqual(observed["selinux_sha256"], digest({"security.selinux": hashes["security.selinux"]}))

    def test_linux_metadata_read_failure_never_becomes_empty_metadata(self):
        path = self.root / "metadata-file"
        path.write_bytes(b"metadata fixture")
        with patch.object(os, "listxattr", side_effect=OSError("xattr unavailable"), create=True), self.assertRaises(OSError):
            updates._metadata(path)

    def bound_fixture(self):
        self.authorized_fixture()
        self.bound.stop()
        transaction = {"state": "preflight", "sequence": 2, "manifest_sha256": "b" * 64, "previous": {"sequence": 1}}
        pin = {"generation": "c" * 64}
        candidate = {"generation": "d" * 64}
        paths = {str(Path("/etc/systemd/system") / name) for name in host_payload.UNITS}
        paths |= {str(Path("/usr/share/nebulalog/quadlet-templates") / name) for name in host_payload.QUADLETS}
        paths |= {"/usr/share/nebulalog/httpd/nebulalog.conf.in", "/usr/share/nebulalog/keycloak/realm.json"}
        paths |= {"/etc/containers/systemd/nebulalog-" + name + ".container" for name in ("api", "ingest", "postgresql", "clickhouse", "keycloak")}
        description = {"kind": "file", "uid": os.getuid(), "gid": 0, "mode": 0o644, "bytes": 4, "sha256": hashlib.sha256(b"same").hexdigest()}
        self.plan["files"] = [{"path": path, "before": dict(description), "after": dict(description)} for path in sorted(paths)]
        self.plan["selection"]["path"] = str(updates.host_activation.SELECTION)
        for phase, generation, sequence in (("before", "c" * 64, 1), ("after", "d" * 64, 2), ("restored", "c" * 64, 2)):
            raw = (json.dumps({"schema": 1, "generation": generation, "sequence": sequence}, sort_keys=True, indent=2) + "\n").encode()
            self.plan["selection"][phase] = {**description, "mode": 0o600, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        self.plan["preserved"] = []
        for item in self.plan["generation_additions"]:
            item["gid"] = 0
        self.plan["migration_only"] = sorted({"share/defaults/" + name for name in host_payload.DEFAULTS} | {"share/templates/keycloak/realm.json", "share/templates/quadlet/nebulalog.network"} | {name for name in host_payload.CATALOG_BY_PATH if name.startswith("bin/")})
        self.source_changed = None
        def reader(path, **_):
            if path == self.plan_path:
                return json.dumps(self.plan).encode()
            if self.source_changed and path == self.generation / self.source_changed:
                return b"changed"
            return b"same"
        for patched in (patch.object(updates.host_dispatch, "transaction_binding", return_value=(transaction, {})),
                        patch.object(updates.host_dispatch, "coordinator_pin", return_value=pin),
                        patch.object(updates.host_dispatch, "generation_info", return_value=candidate),
                        patch.object(updates.host_activation, "_candidate_identity", return_value=(candidate, None)),
                        patch.object(host_payload, "GENERATIONS", self.root), patch.object(self.manager, "reader", side_effect=reader)):
            patched.start()
            self.addCleanup(patched.stop)
        return transaction

    def test_plan_binds_exact_transaction_selection_inventory_and_policy(self):
        transaction = self.bound_fixture()
        observed, _ = updates._bound_plan(self.manager, self.stage, self.plan_path, preparing=True)
        self.assertEqual(observed, self.plan)
        transaction["sequence"] = 3
        with self.assertRaisesRegex(Refused, "plan_transaction_mismatch"):
            updates._bound_plan(self.manager, self.stage, self.plan_path, preparing=True)
        transaction["sequence"] = 2
        self.source_changed = "bin/nebulalog"
        with self.assertRaisesRegex(Refused, "fixed_policy_change_requires_migration"):
            updates._bound_plan(self.manager, self.stage, self.plan_path, preparing=True)

    def test_plan_refuses_arbitrary_destination_missing_generation_and_wrong_phase(self):
        transaction = self.bound_fixture()
        original = self.plan["files"][0]["path"]
        self.plan["files"][0]["path"] = "/etc/sudoers"
        with self.assertRaisesRegex(Refused, "unexpected_runtime_destination"):
            updates._bound_plan(self.manager, self.stage, self.plan_path, preparing=True)
        self.plan["files"][0]["path"] = original
        self.plan["generation_additions"].pop()
        with self.assertRaisesRegex(Refused, "generation_inventory_changed"):
            updates._bound_plan(self.manager, self.stage, self.plan_path, preparing=True)
        transaction["state"] = "committed"
        with self.assertRaisesRegex(Refused, "wrong_transaction_phase"):
            updates._bound_plan(self.manager, self.stage, self.plan_path, preparing=True)

    def test_preserved_customer_descriptions_allow_service_owners_but_not_writes_elsewhere(self):
        item = {"kind": "file", "uid": 999, "gid": 101, "mode": 0o640, "bytes": 6, "sha256": hashlib.sha256(b"secret").hexdigest()}
        updates._description(item, preserved=True)
        with self.assertRaises(Refused):
            updates._description(item)
        with self.assertRaises(Refused):
            updates._description({**item, "mode": 0o666}, preserved=True)
