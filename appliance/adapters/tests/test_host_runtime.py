"""Real fixed-resource filesystem reconciliation with fixture service/probe/AIDE responses.

No system service, real integrity database or appliance command is executed.
"""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_adapters import host_runtime as runtime
from nebulalog_adapters.lifecycle import Lifecycle
from nebulalog_manager import aide, host_activation as activation, host_dispatch as dispatch, host_payload as payload
from nebulalog_manager.common import Refused, atomic_json
import test_host_payload as archives
from test_host_activation import HostFixture

IMAGE = "registry.example/nebulalog@sha256:" + "a" * 64
NEW_IMAGE = "registry.example/nebulalog@sha256:" + "b" * 64


class RuntimeFixture(HostFixture):
    def setUp(self):
        repository = Path(__file__).resolve().parents[3]
        self.resources = {item["path"]: (repository / item["source"]).read_bytes()
                          for item in payload.CATALOG if item["path"].startswith("share/")}
        super().setUp()
        for module, name, value in ((runtime, "OWNER_UID", os.getuid()), (runtime, "OWNER_GID", os.getgid()),
                                    (runtime, "SYSTEMD", self.root / "systemd"), (runtime, "SHARE", self.root / "share"),
                                    (runtime, "ETC", self.root / "etc"), (runtime, "EDGE", self.root / "httpd/edge.conf"),
                                    (runtime, "SHIM", self.root / "bin/host-boot")):
            mocker = patch.object(module, name, value); mocker.start(); self.addCleanup(mocker.stop)
        self.integrity_calls = []
        def prepare(_, stage, plan):
            self.integrity_calls.append(("prepare", stage, plan)); return {"ok": True}
        def accept(_, stage, plan, *, direction):
            self.integrity_calls.append((direction, stage, plan)); return {"ok": True}
        for name, callback in (("authorized_update_prepare", prepare), ("authorized_update_accept", accept)):
            mocker = patch.object(aide.Aide, name, callback, create=True); mocker.start(); self.addCleanup(mocker.stop)
        configuration = self.root / "customer"
        configuration.mkdir()
        (configuration / "credentials.json").write_text("inert secret fixture, never exported")
        quadlets = self.root / "quadlets"; quadlets.mkdir()
        self.commands = []
        self.bad_probe = False
        self.inactive_service = False
        config = {"issuer": "https://fixture.example/realms/nebulalog", "edge_service": "nebulalog-edge.service"}
        self.lifecycle = Lifecycle(config, self.command, state=self.state, data=self.root, configuration=configuration, quadlets=quadlets, guard=lambda: None)
        self.manifest["components"]["nebulalog"] = {"version": "0.1.1", "artifact": "app.tar", "image": NEW_IMAGE, "rollback_safe": True}
        self.bind_manifest(); self.save_transaction("preflight")
        self.host = runtime.HostRuntime(self.lifecycle, self.stage)
        for name, path in self.host.fixed_targets().items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.host.source(self.host.old_root, name)); path.chmod(0o644)
        for service in runtime.IMAGE_KEYS:
            path = quadlets / ("nebulalog-" + service + ".container")
            path.write_bytes(self.host._render_quadlet(self.host.old_root, service, IMAGE)); path.chmod(0o644)
        runtime.EDGE.parent.mkdir(); runtime.EDGE.write_bytes(self.host._render_edge(self.host.old_root)); runtime.EDGE.chmod(0o644)
        runtime.SHIM.parent.mkdir(); runtime.SHIM.write_bytes(b"inert fixture fixed shim"); runtime.SHIM.chmod(0o755)
        for base, names in ((runtime.ETC, ("trust.json", "release-public.pem", "github-updates.json", "images.json", "bootstrap/setup.json")),
                            (runtime.SHARE, ("publisher-public.spki", "publisher-trust.json", "initial-release.json", "source-manifest.json", "initial-host.json")),
                            (self.state, ("publisher-trust.json", "initial-enrollment.json"))):
            for name in names:
                path = base / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"protected fixture " + name.encode()); path.chmod(0o600)

    def make_generation(self, name, version):
        base = self.root / name; base.mkdir()
        source, manifest = archives.fixture_source(base)
        files = json.loads(manifest.read_text())["files"]
        for item in payload.CATALOG:
            path = source / item["source"]
            if item["path"] in self.resources:
                raw = self.resources[item["path"]]
                if name == "new" and item["path"] in {"share/templates/systemd/nebulalog-status.service", "share/templates/httpd/nebulalog.conf.in", "share/templates/quadlet/nebulalog-api.container.in"}:
                    raw += b"\n# qualified inert fixture change\n"
                path.write_bytes(raw)
            elif name == "new" and item["path"].startswith("lib/"):
                path.write_bytes(path.read_bytes() + b"# candidate code fixture\n")
            files[item["source"]] = payload.digest(path.read_bytes())
        manifest.write_bytes(payload.encoded({"schema": 1, "files": files}))
        archive = base / "host.tar"
        evidence = archives.builder.build(source, manifest, archive, version=version)
        payload.stage_generation(archive, expected_sha256=evidence["archive_sha256"], expected_host_source_sha256=evidence["metadata"]["host_source_sha256"])
        return dispatch.generation_info(evidence["archive_sha256"])

    def command(self, argv, **kwargs):
        self.commands.append(argv)
        if argv[:4] == ["/usr/bin/python3.14", "-I", "-B", str(runtime.SHIM)]:
            selection = activation.selection()
            identity = self.new if selection["generation"] == self.new["generation"] else self.old
            value = {"schema": 1, "abi": 1, **identity, "selection_sequence": selection["sequence"], "verified": not self.bad_probe}
            if argv[4] == "probe-selected":
                value.update(coordinator_verified=True, coordinator_generation=self.old["generation"], runtime_imported=True,
                    origins={name: str(self.generations / identity["generation"] / "lib" / (name.replace(".", "/") + ".py")) for name in runtime.ORIGIN_MODULES})
                value["module_sha256"] = {name: payload.digest(Path(path).read_bytes()) for name, path in value["origins"].items()}
            return json.dumps(value)
        if "--property=ActiveState" in argv:
            return "inactive" if self.inactive_service else "active"
        return ""

    def prepare(self):
        self.host.preflight(); self.host.backup()
        self.save_transaction("preparing"); activation.prepare(self.stage)
        self.prepared = self.stage / "prepared-quadlets"; self.prepared.mkdir()
        runtime.HostRuntime(self.lifecycle, self.stage).prepare(self.prepared)

    def select_and_apply(self):
        self.prepare()
        self.save_transaction("activating"); activation.select_candidate(self.stage)
        self.host = runtime.HostRuntime(self.lifecycle, self.stage)
        self.host.apply()


class HostRuntimeTests(RuntimeFixture):
    def interrupted_preflight_plan(self, after_write):
        write = runtime.atomic_json
        before = {path: path.read_bytes() for path in self.host._target_paths()}
        def interrupted(path, value):
            if path != self.host.plan_path: return write(path, value)
            if after_write: write(path, value)
            raise OSError("interrupted host plan publication")
        with patch.object(runtime, "atomic_json", side_effect=interrupted), self.assertRaises(OSError):
            self.host.preflight()
        retained = self.host.plan_path.read_bytes() if self.host.plan_path.exists() else None
        self.assertEqual(activation.selection()["sequence"], self.transaction["previous"]["sequence"])
        self.assertTrue(self.host.preflight()["checks"]["dispatcher_ready"])
        if retained is not None: self.assertEqual(self.host.plan_path.read_bytes(), retained)
        for path, raw in before.items(): self.assertEqual(path.read_bytes(), raw)
        self.assertFalse(self.host.root.exists())

    def test_preflight_retries_before_plan_publication_without_touching_runtime(self):
        self.interrupted_preflight_plan(False)

    def test_preflight_retries_after_plan_publication_without_replacing_plan(self):
        self.interrupted_preflight_plan(True)

    def test_preflight_binds_exact_fixed_resources_generation_additions_and_preserved_hashes(self):
        result = self.host.preflight()
        plan = self.host.checked_plan()
        self.assertEqual(result["plan_sha256"], payload.digest(self.host.plan_path.read_bytes()))
        self.assertEqual({item["path"] for item in plan["files"]}, {str(path) for path in self.host._target_paths()})
        self.assertEqual(plan["candidate_generation"], self.new["generation"])
        self.assertGreater(len(plan["generation_additions"]), len(payload.CATALOG))
        self.assertNotIn("inert secret fixture", self.host.plan_path.read_text())
        self.assertEqual(self.integrity_calls[0][0], "prepare")
        self.assertFalse(self.host.root.exists())

    def test_real_resource_activation_and_restoration_match_old_and_new_plan(self):
        self.select_and_apply()
        plan = self.host.checked_plan()
        self.assertTrue(all(runtime.checked_file(Path(item["path"]))[1] == item["after"] for item in plan["files"]))
        self.assertIn(NEW_IMAGE.encode(), (self.lifecycle.quadlets / "nebulalog-api.container").read_bytes())
        self.save_transaction("checking")
        proof = runtime.HostRuntime(self.lifecycle, self.stage).runtime_evidence("update-health", accept_integrity=True)
        self.assertTrue(proof["checks"]["runtime_processes"])
        self.assertEqual(self.integrity_calls[-1][0], "forward")
        self.save_transaction("rolling_back"); activation.restore_previous(self.stage)
        host = runtime.HostRuntime(self.lifecycle, self.stage); host.apply(rollback=True)
        host.runtime_evidence("update-health", accept_integrity=True)
        self.assertTrue(all(runtime.checked_file(Path(item["path"]))[1] == item["before"] for item in plan["files"]))
        self.assertEqual(self.integrity_calls[-1][0], "rollback")
        self.assertTrue(all(path.exists() for path in (self.host.old_root, self.host.new_root)))

    def test_local_resource_drift_refuses_before_backup_or_write(self):
        target = runtime.SYSTEMD / "nebulalog-status.service"
        target.write_bytes(target.read_bytes() + b"local override")
        before = target.read_bytes()
        with self.assertRaisesRegex(Refused, "local changes"): self.host.preflight()
        self.assertEqual(target.read_bytes(), before)
        self.assertFalse(self.host.root.exists())

    def test_preactivation_recovery_can_capture_unchanged_host_files_after_partial_backup(self):
        self.host.preflight()
        write = self.host._write_retained
        count = 0
        def interrupted(path, raw):
            nonlocal count
            count += 1
            if count == 2: raise OSError("interrupted host backup")
            return write(path, raw)
        with patch.object(self.host, "_write_retained", side_effect=interrupted), self.assertRaises(OSError):
            self.host.backup()
        first = (self.host.root / "old/0").read_bytes()
        self.transaction["activation_started"] = False
        self.save_transaction("rolling_back"); activation.restore_previous(self.stage)
        host = runtime.HostRuntime(self.lifecycle, self.stage)
        host.backup(preactivation_recovery=True)
        self.assertEqual((host.root / "old/0").read_bytes(), first)
        host.runtime_evidence("update-health", accept_integrity=True)
        self.assertEqual(self.integrity_calls[-1][0], "rollback")

    def test_preactivation_host_backup_recovery_refuses_changed_live_file(self):
        self.host.preflight()
        self.transaction["activation_started"] = False
        self.save_transaction("rolling_back"); activation.restore_previous(self.stage)
        target = runtime.SYSTEMD / "nebulalog-status.service"
        target.write_bytes(target.read_bytes() + b"unrelated change")
        with self.assertRaisesRegex(Refused, "changed before"):
            runtime.HostRuntime(self.lifecycle, self.stage).backup(preactivation_recovery=True)
        self.assertTrue(target.read_bytes().endswith(b"unrelated change"))

    def test_explicit_policy_identity_network_migration_refusal_is_precise(self):
        original = self.host.source
        for name in runtime.MIGRATION_ONLY:
            def source(root, path):
                raw = original(root, path)
                return raw + b"changed" if root == self.host.new_root and path == name else raw
            with self.subTest(name=name), patch.object(self.host, "source", side_effect=source), self.assertRaisesRegex(Refused, "qualified.*migration") as error:
                self.host.preflight()
            self.assertIn(name, str(error.exception))
            refusal = self.stage / "host-refusal.json"
            self.assertEqual(json.loads(refusal.read_text()), {"schema": 1, "reason": "qualified_migration_required",
                "resource": name, "sequence": self.host.transaction["sequence"], "manifest_sha256": self.host.transaction["manifest_sha256"]})
            self.assertEqual(refusal.stat().st_mode & 0o777, 0o600)
            refusal.unlink()
        self.assertFalse(self.host.root.exists())

    def test_customer_or_trust_changes_never_get_overwritten_or_accepted(self):
        self.prepare()
        self.save_transaction("activating"); activation.select_candidate(self.stage)
        path = self.lifecycle.configuration / "credentials.json"
        path.write_text("changed private fixture")
        with self.assertRaisesRegex(Refused, "Customer configuration"): self.host.apply()
        self.assertEqual(path.read_text(), "changed private fixture")
        path.write_text("inert secret fixture, never exported")
        trust = runtime.ETC / "release-public.pem"; trust.write_text("changed public fixture")
        with self.assertRaisesRegex(Refused, "enrolled trust"): self.host.apply()
        self.assertEqual(trust.read_text(), "changed public fixture")

    def test_plan_destination_tamper_and_backup_content_tamper_refuse(self):
        self.prepare()
        self.save_transaction("activating"); activation.select_candidate(self.stage)
        raw = self.host.plan_path.read_bytes()
        value = json.loads(raw); value["files"][0]["path"] = str(self.root / "unrelated")
        atomic_json(self.host.plan_path, value)
        with self.assertRaisesRegex(Refused, "unexpected destination"): self.host.apply()
        self.host.plan_path.write_bytes(raw)
        (self.host.root / "old/0").write_bytes(b"changed backup fixture")
        self.save_transaction("rolling_back"); activation.restore_previous(self.stage)
        with self.assertRaisesRegex(Refused, "backup content"): self.host.apply(rollback=True)

    def test_partial_activation_can_be_retried_or_rolled_back_without_unrelated_writes(self):
        self.prepare(); self.save_transaction("activating"); activation.select_candidate(self.stage)
        from nebulalog_adapters import lifecycle
        original = lifecycle.atomic_file
        count = 0
        def fail(path, raw, *args):
            nonlocal count
            count += 1
            if count == 2: raise OSError("injected write failure")
            return original(path, raw, *args)
        with patch.object(lifecycle, "atomic_file", side_effect=fail), self.assertRaises(OSError): self.host.apply()
        plan = self.host.checked_plan()
        self.assertTrue(all(runtime.checked_file(Path(item["path"]))[1] in (item["before"], item["after"]) for item in plan["files"]))
        self.host.apply()
        self.save_transaction("rolling_back"); activation.restore_previous(self.stage)
        self.host.apply(rollback=True)
        self.assertTrue(all(runtime.checked_file(Path(item["path"]))[1] == item["before"] for item in plan["files"]))

    def test_bad_import_provenance_or_inactive_services_prevent_integrity_promotion(self):
        self.select_and_apply(); before = len(self.integrity_calls)
        self.save_transaction("checking")
        self.bad_probe = True
        with self.assertRaisesRegex(Refused, "dispatcher"): self.host.runtime_evidence("update-health", accept_integrity=True)
        self.bad_probe = False; self.inactive_service = True
        with self.assertRaisesRegex(Refused, "services"): self.host.runtime_evidence("update-health", accept_integrity=True)
        self.assertEqual(len(self.integrity_calls), before)

    def test_integrity_failure_prevents_success_and_immutable_plan_is_retained(self):
        self.select_and_apply()
        self.save_transaction("checking")
        raw = self.host.plan_path.read_bytes()
        with patch.object(aide.Aide, "authorized_update_accept", side_effect=Refused("unrelated drift"), create=True), self.assertRaisesRegex(Refused, "unrelated drift"):
            self.host.runtime_evidence("update-health", accept_integrity=True)
        self.assertEqual(self.host.plan_path.read_bytes(), raw)

    def test_unrelated_live_file_drift_blocks_forward_and_restore_without_clobber(self):
        self.prepare()
        self.save_transaction("activating"); activation.select_candidate(self.stage)
        path = runtime.SYSTEMD / "nebulalog-status.service"
        path.write_text("unrelated current runtime")
        for rollback in (False, True):
            if rollback:
                self.save_transaction("rolling_back"); activation.restore_previous(self.stage)
            with self.assertRaisesRegex(Refused, "unrelated runtime"): self.host.apply(rollback=rollback)
            self.assertEqual(path.read_text(), "unrelated current runtime")



class LifecycleHostTests(RuntimeFixture):
    """Actual lifecycle methods with filesystem resources and fixture host commands."""
    def setUp(self):
        super().setUp()
        from unittest.mock import Mock
        from nebulalog_adapters import lifecycle
        import test_lifecycle as service_fixtures
        base = service_fixtures.Commands()
        base.calls = self.commands
        owner = self
        class FixtureCommands:
            capture = base.capture
            feed = base.feed
            def __call__(self, argv, **kwargs):
                if str(runtime.SHIM) in argv:
                    return owner.command(argv, **kwargs)
                if argv[:2] == ["podman", "info"]:
                    owner.commands.append(argv); return str(owner.root / "containers")
                if argv[:3] == ["podman", "inspect", "--format"] and ".Config.Env" in argv[3]:
                    owner.commands.append(argv); return json.dumps(["KC_FIPS_MODE=strict"])
                if "--query" in argv and argv[argv.index("--query") + 1] == "SELECT 1":
                    owner.commands.append(argv); return "1"
                return base(argv, **kwargs)
        self.lifecycle.cmd = FixtureCommands()
        self.lifecycle.config["schema_revision"] = "1"
        self.lifecycle.encrypted = Mock(return_value=None)
        # Host-resource tests inject database/storage execution. Dedicated
        # PostgreSQL suites exercise those barriers and exact catalog checks.
        self.lifecycle.storage_maintenance = Mock()
        self.lifecycle.application_schema_catalog = Mock(return_value={"schema_revision": "1"})
        self.lifecycle.api_ready = Mock()
        self.lifecycle.canary = lambda: {"persisted": True, "fixture": True}
        self.lifecycle.compliance = lambda stage: {"passed": True, "fixture": True}
        self.lifecycle.get = lambda path, token=None: json.dumps({"status": "ok", "application_crypto_fips_enabled": True}).encode()
        self.lifecycle.web = lambda: b'<div id="root"></div>'
        self.lifecycle.maintenance = lambda enabled, stage: atomic_json(self.maintenance, {"active": True, "release": str(stage)}) if enabled else self.maintenance.unlink(missing_ok=True)
        self.maintenance.unlink(missing_ok=True)
        self.manifest["components"]["nebulalog"].update(database_migration="none", schema_revision="1")
        self.transaction["previous"]["components"]["nebulalog"] = {"version": "0.1.0", "image": IMAGE}
        self.bind_manifest()
        for mocker in (patch.object(lifecycle, "trusted_file", side_effect=lambda path: path),
                       patch.object(lifecycle, "local_auth", return_value=("synthetic token", {"fixture": True})),
                       patch.object(lifecycle, "security_status", return_value={"host_controls_ok": True, "selinux": {"value": "Enforcing"}, "firewalld": {"value": "active"}})):
            mocker.start(); self.addCleanup(mocker.stop)

    def test_partial_database_backup_recovers_unchanged_host_and_finalizes_after_health(self):
        self.transaction["activation_started"] = False
        self.save_transaction("preflight")
        self.lifecycle.preflight(self.stage)
        capture = self.lifecycle.cmd.capture
        def interrupted(argv, target, **kwargs):
            if "--dbname=keycloak" in argv: raise OSError("injected backup interruption")
            return capture(argv, target, **kwargs)
        self.lifecycle.api_ready.side_effect = Refused("restart interrupted")
        with patch.object(self.lifecycle.cmd, "capture", side_effect=interrupted), self.assertRaises(Refused):
            self.lifecycle.backup(self.stage)
        partial = (self.stage / "recovery/nebulalog.dump").read_bytes()
        self.assertFalse((self.stage / "adapter-backup.json").exists())
        self.lifecycle.api_ready.side_effect = None
        self.save_transaction("rolling_back"); activation.restore_previous(self.stage)
        start = len(self.commands)
        result = self.lifecycle.rollback(self.stage)
        self.assertTrue(result["unchanged_runtime_recovered"])
        self.assertTrue(result["host"]["checks"]["runtime_files"])
        self.assertFalse(any(set(call) & {"dropdb", "createdb", "pg_restore"} for call in self.commands[start:]))
        self.assertEqual((self.stage / "recovery/nebulalog.dump").read_bytes(), partial)
        self.assertTrue(self.maintenance.exists())
        self.assertTrue(self.lifecycle.health(self.stage)["ok"])
        self.save_transaction("rolled_back")
        self.lifecycle.finalize(self.stage)
        self.assertFalse(self.maintenance.exists())

    def activate_lifecycle(self):
        first = self.lifecycle.preflight(self.stage)
        self.assertTrue(first["host"]["checks"]["dispatcher_ready"])
        backup = self.lifecycle.backup(self.stage)
        self.assertTrue(backup["host"]["checks"]["backup_verified"])
        self.assertFalse((self.stage / "recovery/quadlets/nebulalog-edge.container").exists())
        self.save_transaction("preparing"); activation.prepare(self.stage)
        prepared = self.lifecycle.prepare(self.stage)
        self.assertTrue(prepared["host"]["checks"]["prepared_files"])
        self.save_transaction("activating"); activation.select_candidate(self.stage)
        active = self.lifecycle.activate(self.stage)
        self.assertTrue(active["host"]["checks"]["runtime_files"])

    def test_actual_lifecycle_methods_reconcile_host_plus_oci_and_finalize_after_integrity(self):
        self.activate_lifecycle()
        self.save_transaction("checking")
        health = self.lifecycle.health(self.stage)
        self.assertTrue(health["ok"], health)
        self.assertEqual(self.integrity_calls[-1][0], "forward")
        self.save_transaction("committed")
        result = self.lifecycle.finalize(self.stage)
        self.assertTrue(result["host"]["checks"]["maintenance_released"])
        self.assertFalse(self.maintenance.exists())
        self.assertIn(["systemctl", "start", "nebulalog-edge.service"], self.commands)

    def test_actual_lifecycle_rollback_uses_old_resources_without_candidate_archive(self):
        self.activate_lifecycle()
        self.save_transaction("rolling_back"); activation.restore_previous(self.stage)
        (self.stage / "host.tar").unlink()
        restored = self.lifecycle.rollback(self.stage)
        self.assertTrue(restored["host"]["checks"]["runtime_files"])
        self.assertEqual(self.lifecycle.health(self.stage)["ok"], True)
        self.assertEqual(self.integrity_calls[-1][0], "rollback")
        self.save_transaction("rolled_back")
        self.assertTrue(self.lifecycle.finalize(self.stage)["host"]["checks"]["maintenance_released"])

    def test_integrity_or_application_health_failure_keeps_maintenance_closed(self):
        self.activate_lifecycle(); self.save_transaction("checking")
        with patch.object(aide.Aide, "authorized_update_accept", side_effect=Refused("unrelated drift"), create=True):
            result = self.lifecycle.health(self.stage)
        self.assertFalse(result["ok"])
        self.assertFalse(result["checks"]["host"])
        self.assertTrue(self.maintenance.exists())
        self.save_transaction("committed")
        with self.assertRaisesRegex(Refused, "runtime acceptance"): self.lifecycle.finalize(self.stage)
        self.assertTrue(self.maintenance.exists())


if __name__ == "__main__":
    unittest.main()
