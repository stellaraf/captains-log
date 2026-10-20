"""Default AIDE trust gates and installed unit contract; no host commands run."""
import hashlib
import json
import os
import re
from pathlib import Path
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import aide
from nebulalog_manager.common import Refused
from nebulalog_manager.host_job_storage import StorageIdentity

INSTALLATION = "458a08e3-ef3b-4cd1-83e5-b402a2c1e913"
IDENTITY = StorageIdentity(INSTALLATION, Path("/var/lib/nebulalog"), 42)
APPLIANCE = Path(__file__).resolve().parents[1]


class AideGuardTests(unittest.TestCase):
    def setUp(self):
        self.content = b"reviewed installed source\n"
        self.descriptor = {"source_snapshot_sha256": "a" * 64, "source_dirty": True}
        source_paths = ("appliance/nebulalog_manager/aide.py", "appliance/security/aide-policy.conf", "appliance/security/aide.conf", "appliance/bin/nebulalog-aide",
                        "appliance/systemd/nebulalog-aide.service", "appliance/systemd/nebulalog-aide.timer", "appliance/factory_kernel.py")
        source = {"schema": 1, "files": {name: aide.sha(self.content) for name in source_paths}}
        self.files = {"/etc/nebulalog/bootstrap/image-state": b"sealed\n",
                      "/etc/nebulalog/bootstrap/runtime-ready.json": json.dumps({"installation_id": INSTALLATION}).encode(),
                      "/var/lib/nebulalog/configuration/bootstrap/setup.json": json.dumps({"installation_id": INSTALLATION, "baseline": "cis-level2"}).encode(),
                      "/var/lib/nebulalog/configuration/bootstrap/runtime-state.json": json.dumps({"installation_id": INSTALLATION}).encode(),
                      "/var/lib/nebulalog/configuration/security-policy.json": json.dumps({"installation_id": INSTALLATION, "baseline": "cis-level2"}).encode(),
                      "/usr/share/nebulalog/source-manifest.json": json.dumps(source).encode()}
        current = {"sequence": 0, "components": {}}
        enrolled = {"installation_id": INSTALLATION, "initial_release_sha256": "b" * 64, "provenance": self.descriptor, "current": current}
        self.enrolled, self.current = enrolled, current
        patches = [patch.object(aide, "protected_bytes", side_effect=lambda path, **_: self.files.get(str(path), self.content)),
                   patch.object(aide, 'initial_boot_snapshot', return_value={'ordinary_boot_snapshot_sha256': 'f' * 64}),
                   patch.object(aide.pwd, "getpwnam", side_effect=KeyError("no build user")),
                   patch.object(Path, "exists", return_value=False), patch.object(Path, "is_symlink", return_value=False),
                   patch("nebulalog_manager.update_enrollment.UpdateEnrollment._descriptor", return_value=(self.descriptor, "b" * 64, "c" * 64)),
                   patch("nebulalog_manager.update_enrollment._installed_state", side_effect=lambda _: (b"receipt", self.enrolled, self.current)),
                   patch.object(aide.subprocess, "Popen", side_effect=AssertionError("No host command may execute"))]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.runner = Mock(side_effect=self.command)

    def command(self, argv, **kwargs):
        if argv == ['/usr/bin/python3.14', '-I', '-B', '/usr/libexec/nebulalog/factory-kernel', '--verify']:
            return aide.Result(0, json.dumps({'schema': 1, 'verified': True, 'kernel': '5.14.0-687.57.1.el9_8.x86_64',
                                              'manifest_sha256': aide.sha(self.content), 'inventory_sha256': aide.sha(self.content)}))
        if argv[:2] == ["/usr/bin/rpm", "--query"]:
            return aide.Result(0, "aide-0.19.2-5.el9_8.1.x86_64\n")
        if argv == ["/usr/bin/rpm", "--verify", "aide"]:
            return aide.Result(0)
        if argv == ["/usr/sbin/aide", "--version"]:
            return aide.Result(0, "AIDE 0.19.2\nCompile-time options: ...\n")
        raise AssertionError("Unexpected command")

    def facts(self):
        return aide.default_facts(IDENTITY, aide.POLICY, self.runner, IDENTITY.root / "manager/aide/tmp")

    def test_sealed_runtime_ready_initial_identity_and_actual_host_source_bound(self):
        value = self.facts()
        self.assertEqual(set(value), aide.FACTS)
        self.assertEqual(value["installation_id"], INSTALLATION)
        self.assertEqual(value["source_snapshot_sha256"], "a" * 64)
        self.assertTrue(value["source_dirty"])
        self.assertEqual(value["aide_binary_sha256"], hashlib.sha256(self.content).hexdigest())
        self.assertEqual(self.runner.call_count, 4)
        self.assertEqual(value['factory_kernel_manifest_sha256'], aide.sha(self.content))
        self.assertEqual(value['factory_kernel_inventory_sha256'], aide.sha(self.content))
        self.assertEqual(value['ordinary_boot_snapshot_sha256'], 'f' * 64)

    def test_initial_factory_provenance_missing_changed_or_unverified_refuses(self):
        self.files['/usr/libexec/nebulalog/factory-kernel'] = b'changed helper'
        with self.assertRaisesRegex(Refused, 'factory_kernel_helper_changed'): self.facts()
        del self.files['/usr/libexec/nebulalog/factory-kernel']
        self.files['/usr/share/nebulalog/kernel-provenance/manifest.json'] = b'changed manifest'
        with self.assertRaisesRegex(Refused, 'factory_kernel_provenance_changed'): self.facts()
        del self.files['/usr/share/nebulalog/kernel-provenance/manifest.json']
        previous = self.runner.side_effect
        self.runner.side_effect = lambda argv, **kwargs: aide.Result(1, '', 'unverified RPM') if '--verify' in argv and 'factory-kernel' in ' '.join(argv) else previous(argv, **kwargs)
        with self.assertRaisesRegex(Refused, 'factory_kernel_provenance_not_verified'): self.facts()

    def test_unsealed_marker_or_build_account_refuses_before_any_aide_command(self):
        self.files["/etc/nebulalog/bootstrap/image-state"] = b"unsealed\n"
        with self.assertRaisesRegex(Refused, "aide_requires_sealed_image"):
            self.facts()
        self.files["/etc/nebulalog/bootstrap/image-state"] = b"sealed\n"
        with patch.object(aide.pwd, "getpwnam", return_value=object()), self.assertRaisesRegex(Refused, "aide_refuses_build_identity"):
            self.facts()
        self.runner.assert_not_called()

    def test_build_marker_and_dangling_build_artifact_refuse(self):
        for name in ("/etc/nebulalog/bootstrap/unsealed-build", "/etc/nebulalog/bootstrap/private-build.json", "/home/packer", "/etc/sudoers.d/nebulalog-build"):
            with self.subTest(name=name), patch.object(Path, "is_symlink", lambda path: str(path) == name), self.assertRaisesRegex(Refused, "aide_refuses_build_identity"):
                self.facts()

    def test_factory_generation_uses_verified_initial_installation_before_baseline(self):
        host = {"generation": "d" * 64, "version": "0.0.0-factory.test", "host_source_sha256": "e" * 64, "abi": 1}
        self.current = {"sequence": 0, "components": {"host": host}}
        self.enrolled["current"] = self.current
        proof = {"schema": 1, "verified": True, "host": host,
                 "source_snapshot_sha256": self.descriptor["source_snapshot_sha256"],
                 "initial_release_sha256": "b" * 64,
                 "source_mappings": {"appliance/nebulalog_manager/aide.py": "/usr/lib/nebulalog/generations/fixture/lib/nebulalog_manager/aide.py"}}
        with patch.object(Path, "exists", lambda path: str(path) == "/usr/share/nebulalog/initial-host.json"), \
                patch("nebulalog_manager.update_enrollment.UpdateEnrollment.verify_initial_host_installation", return_value=proof) as verified:
            self.assertEqual(self.facts()["installation_id"], INSTALLATION)
            verified.assert_called_once_with()
            self.files["/etc/aide.conf"] = b"unreviewed policy replacement"
            with self.assertRaisesRegex(Refused, "aide_installed_source_mismatch"):
                self.facts()

    def test_factory_proof_mismatch_refuses_before_scanner_or_package_commands(self):
        host = {"generation": "d" * 64, "version": "0.0.0-factory.test", "host_source_sha256": "e" * 64, "abi": 1}
        self.current = {"sequence": 0, "components": {"host": host}}
        self.enrolled["current"] = self.current
        valid = {"schema": 1, "verified": True, "host": host,
                 "source_snapshot_sha256": self.descriptor["source_snapshot_sha256"],
                 "initial_release_sha256": "b" * 64,
                 "source_mappings": {"appliance/nebulalog_manager/aide.py": "/verified/aide.py"}}
        for key, value in (("schema", True), ("verified", False), ("host", {}),
                           ("source_snapshot_sha256", "f" * 64), ("initial_release_sha256", "f" * 64),
                           ("source_mappings", {})):
            with self.subTest(key=key), patch.object(Path, "exists", lambda path: str(path) == "/usr/share/nebulalog/initial-host.json"), \
                    patch("nebulalog_manager.update_enrollment.UpdateEnrollment.verify_initial_host_installation", return_value={**valid, key: value}), \
                    self.assertRaisesRegex(Refused, "aide_initial_host_identity_changed"):
                self.facts()
        self.runner.assert_not_called()
        self.runner.assert_not_called()

    def test_changed_installed_code_or_unenrolled_versions_cannot_be_baselined(self):
        self.files["/usr/lib/nebulalog/nebulalog_manager/aide.py"] = b"later unreviewed changes"
        with self.assertRaisesRegex(Refused, "aide_installed_source_mismatch"):
            self.facts()
        del self.files["/usr/lib/nebulalog/nebulalog_manager/aide.py"]
        self.current = {"sequence": 1}
        with self.assertRaisesRegex(Refused, "aide_initial_release_changed"):
            self.facts()
        self.runner.assert_not_called()

    def test_package_verify_warning_or_unsupported_binary_cannot_establish_trust(self):
        for failed_command, result in (("--verify", aide.Result(1, "changed packaged file")),
                                       ("--query", aide.Result(0, "aide-0.16-1.el9.x86_64")),
                                       ("--version", aide.Result(0, "AIDE 0.20.0\n"))):
            runner = lambda argv, **kw: result if failed_command in argv else self.command(argv, **kw)
            with self.subTest(command=failed_command), self.assertRaisesRegex(Refused, "aide_package_not_verified"):
                aide.default_monitor(IDENTITY, aide.POLICY, runner, IDENTITY.root / "manager/aide/tmp")

    def test_only_expected_managed_configuration_rpm_differences_are_permitted(self):
        for differences in ("S.5....T.  c /etc/aide.conf\n", "..5......  c /etc/aide.conf\n"):
            runner = lambda argv, **kw: aide.Result(1, differences) if "--verify" in argv else self.command(argv, **kw)
            self.assertEqual(self.facts()["aide_version"], "0.19.2")
            self.assertEqual(aide.default_monitor(IDENTITY, aide.POLICY, runner, IDENTITY.root / "manager/aide/tmp")["default_config_sha256"], aide.sha(self.content))
        for differences in ("S.5....T.  c /etc/aide.conf\nS.5....T. /usr/sbin/aide\n", "SM5....T.  c /etc/aide.conf", "missing c /etc/aide.conf", ".....U...  c /etc/aide.conf"):
            runner = lambda argv, **kw: aide.Result(1, differences) if "--verify" in argv else self.command(argv, **kw)
            with self.subTest(differences=differences), self.assertRaisesRegex(Refused, "aide_package_not_verified"):
                aide.default_monitor(IDENTITY, aide.POLICY, runner, IDENTITY.root / "manager/aide/tmp")
        self.files["/etc/aide.conf"] = b"unreviewed replacement"
        with self.assertRaisesRegex(Refused, "aide_installed_source_mismatch"):
            self.facts()

    def test_selected_security_policy_must_precede_preparation(self):
        for selected in ({"installation_id": INSTALLATION, "baseline": "stig"},
                         {"installation_id": "different", "baseline": "cis-level2"}):
            self.files["/var/lib/nebulalog/configuration/security-policy.json"] = json.dumps(selected).encode()
            with self.assertRaisesRegex(Refused, "aide_baseline_policy_not_selected"):
                self.facts()

    def test_real_storage_gate_failure_precedes_writes_and_commands(self):
        guard = Mock(side_effect=Refused("not encrypted or not complete"))
        with patch.object(Path, "mkdir") as mkdir, self.assertRaises(Refused):
            aide.Aide(storage_guard=guard, runner=self.runner).prepare()
        mkdir.assert_not_called()
        self.runner.assert_not_called()

    def test_systemd_does_not_silently_skip_missing_database(self):
        # These are repository artifacts, never service execution.
        service = (APPLIANCE / "systemd/nebulalog-aide.service").read_text()
        timer = (APPLIANCE / "systemd/nebulalog-aide.timer").read_text()
        self.assertNotIn("ConditionPathExists", service)
        self.assertIn("Requires=nebulalog-firstboot.service", service)
        self.assertIn("RequiresMountsFor=/var/lib/nebulalog", service)
        self.assertIn("ExecStart=/usr/libexec/nebulalog/nebulalog-aide check", service)
        self.assertNotIn("SuccessExitStatus", service)
        self.assertIn("ProtectSystem=full", service)
        self.assertIn("OnCalendar=daily", timer)
        self.assertIn("Persistent=true", timer)

    def test_default_configuration_matches_managed_database_and_policy(self):
        from nebulalog_manager.aide_report import render_default_config
        policy = (APPLIANCE / "security/aide-policy.conf").read_text()
        config = (APPLIANCE / "security/aide.conf").read_text()
        self.assertEqual(config, render_default_config(policy))
        self.assertIn("@@define DBDIR /var/lib/nebulalog/manager/aide\ndatabase_in=file:@@{DBDIR}/aide.db.gz\n", config)
        # Only expected phase-transition evidence is omitted; selected static policy remains covered.
        self.assertIn("-/etc/nebulalog/configured$", policy)
        self.assertIn("-/var/lib/nebulalog/configuration/baseline-assessments(/.*)?", policy)
        self.assertNotIn("-/var/lib/nebulalog/configuration/security-policy", policy)
        self.assertIn("/var/lib/nebulalog/configuration(/.*)? f,l,p,s,c,b NEBULALOGSTATIC", policy)
        # Native AIDE 0.19.2 warns on underscores in group names. Warnings remain
        # errors in the manager, so shipped aliases must use its current syntax.
        groups = re.findall(r"(?m)^([A-Z][A-Z0-9_]*)\s*=", policy)
        self.assertTrue(groups)
        self.assertTrue(all(re.fullmatch(r"[A-Za-z0-9]+", name) for name in groups))


class AideRuntimeStorageTests(unittest.TestCase):
    def setUp(self):
        from nebulalog_manager.firstboot import RUNTIME_CHECKS
        self.ready = {"schema": 1, "state": "runtime-ready", "installation_id": INSTALLATION,
                      "checks": dict.fromkeys(RUNTIME_CHECKS, True)}
        self.state = {"schema": 1, "installation_id": INSTALLATION, "identity_initialized": True,
                      "active_stage": None, "completed": sorted(aide.RUNTIME_STAGES)}
        self.gate = {"host_ready": True, "setup_complete": False, "installation_id": INSTALLATION}
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_dev=42)
        patches = [patch.object(aide, "require_linux_root"),
                   patch("nebulalog_manager.firstboot.FirstBoot.gate", side_effect=lambda: self.gate),
                   patch.object(Path, "lstat", return_value=directory), patch.object(Path, "stat", return_value=directory),
                   patch.object(aide, "protected_bytes", side_effect=self.read),
                   patch.object(aide.subprocess, "Popen", side_effect=AssertionError("No host commands"))]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def read(self, path, **kwargs):
        if str(path) == "/etc/nebulalog/bootstrap/runtime-ready.json":
            self.assertTrue(kwargs["private"])
            return json.dumps(self.ready).encode()
        self.assertEqual(path, aide.DATA / "configuration/bootstrap/runtime-state.json")
        self.assertEqual(kwargs["device"], 42)
        self.assertTrue(kwargs["private"])
        return json.dumps(self.state).encode()

    def test_actual_host_and_runtime_ready_can_precede_final_setup(self):
        self.assertEqual(aide.runtime_storage(), IDENTITY)
        self.gate["setup_complete"] = True
        self.assertEqual(aide.runtime_storage(), IDENTITY)

    def test_incomplete_live_foundation_is_never_substituted_by_runtime_flags(self):
        self.gate["host_ready"] = False
        with self.assertRaisesRegex(Refused, "aide_host_not_ready"):
            aide.runtime_storage()
        with patch("nebulalog_manager.firstboot.FirstBoot.gate", side_effect=Refused("Actual FIPS/SELinux/LUKS probe failed")), self.assertRaises(Refused):
            aide.runtime_storage()

    def test_malformed_or_incomplete_runtime_state_refuses(self):
        for key, value in (("schema", True), ("completed", []), ("completed", [None]),
                           ("completed", [{"invalid": "stage"}]), ("active_stage", "edge"),
                           ("identity_initialized", False), ("installation_id", "different")):
            original = self.state[key]
            self.state[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(Refused, "aide_runtime_configuration_incomplete"):
                aide.runtime_storage()
            self.state[key] = original
        self.ready["checks"] = {"https": True}
        with self.assertRaisesRegex(Refused, "aide_runtime_configuration_incomplete"):
            aide.runtime_storage()

    def test_wrong_device_or_unsafe_mount_ancestry_refuses(self):
        with patch.object(aide, "protected_bytes", side_effect=Refused("unsafe_aide_file")), self.assertRaises(Refused):
            aide.runtime_storage()
        unsafe = SimpleNamespace(st_mode=stat.S_IFLNK | 0o700, st_uid=0, st_dev=42)
        with patch.object(Path, "lstat", return_value=unsafe), self.assertRaisesRegex(Refused, "aide_unsafe_storage_ancestry"):
            aide.runtime_storage()


if __name__ == "__main__":
    unittest.main()
