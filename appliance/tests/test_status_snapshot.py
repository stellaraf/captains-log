from datetime import datetime, timezone
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager.common import CommandFailed, Refused, atomic_json
from nebulalog_manager.status_snapshot import Collector, history, publish, public_directory
from nebulalog_manager.storage import Identity, Snapshot, MIB


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.now = datetime(2026, 9, 7, 10, 30, tzinfo=timezone.utc)
        self.configuration = self.path / "configuration"
        self.state = self.path / "manager"
        self.policy = self.path / "maintenance-policy.json"
        atomic_json(self.configuration / "bootstrap/setup.json", {"installation_id": "synthetic-installation", "baseline": "unified", "private_secret": "NEVER_PUBLISH_SECRET"})
        atomic_json(self.path / "storage.json", {"disk": "synthetic"})
        atomic_json(self.policy, {"automatic_os_updates": True})
        self.host = {"fips_kernel": True, "fips_tool": {"ok": True, "value": "NEVER_PUBLISH_SECRET"},
                     "crypto_policy": {"ok": True, "value": "FIPS"}, "selinux": {"ok": True, "value": "Enforcing"},
                     "firewalld": {"ok": True, "value": "active"}, "auditd": {"ok": True, "value": "active"}, "host_controls_ok": True,
                     "kernel_crypto_diagnostics": {"status": "no_failure_observed"}}
        self.baseline = Mock(return_value=SimpleNamespace(status=lambda *_: {"baseline_assessed": True, "baseline_review_complete": True,
                          "reviewer": "NEVER_PUBLISH_SECRET", "reason": "NEVER_PUBLISH_SECRET", "exceptions": [{"evidence": "NEVER_PUBLISH_SECRET"}],
                          "assessments": [{"counts": {"pass": 42, "secret": "NEVER_PUBLISH_SECRET"}}]}))
        self.current = {"current": {"sequence": 7, "components": {"nebulalog": {"version": "0.1.0", "password": "NEVER_PUBLISH_SECRET"}}},
                        "transaction": {"state": "committed", "sequence": 7, "finalization": "failed", "error": "NEVER_PUBLISH_SECRET"},
                        "maintenance_release_pending": True, "os_transaction": {"state": "reboot_requested"}}
        self.updates = Mock(return_value=SimpleNamespace(status=lambda: self.current))
        self.runner = Mock(return_value="enabled")
        self.storage_identity = Identity("/dev/disk/by-id/synthetic-private", "NEVER_PUBLISH_SECRET", "/dev/disk/by-id/synthetic-private-part1",
                                         "part", "luks", "nebulalog-data", "pv", "vg", "lv")
        self.inspector = Mock(return_value=Snapshot(self.storage_identity, 2048*MIB, 1024*MIB, MIB,
                                                   1008*MIB, 1008*MIB, 1000*MIB, 1000*MIB, 8*MIB))
        self.collector = Collector(configuration=self.configuration, state=self.state, identity=self.path / "storage.json", maintenance=self.policy,
                                   github_policy=self.path / "github-updates.json",
                                   runner=self.runner, host=lambda _: self.host, inspect=self.inspector, baseline_factory=self.baseline,
                                   update_factory=self.updates, clock=lambda: self.now)
        self.trust = patch("nebulalog_manager.status_snapshot.trusted_file", side_effect=lambda path: path)
        self.identity = patch("nebulalog_manager.status_snapshot.storage.Identity", return_value=SimpleNamespace(additional_pvs=()))
        self.trust.start(); self.identity.start()
        self.addCleanup(self.trust.stop); self.addCleanup(self.identity.stop)

    def test_publishes_only_allowlisted_measured_fields(self):
        self.current["os_transaction"] = {}
        value = self.collector.collect()
        self.assertNotIn("NEVER_PUBLISH_SECRET", json.dumps(value))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["baseline"]["counts"], {"pass": 42})
        self.assertTrue(value["storage"]["luks2_verified"])
        self.assertEqual(value["storage"]["growth"], {"presented_disk_bytes": 2048*MIB,
                         "unallocated_disk_bytes": 1023*MIB, "required_stages": ["partition", "luks", "pv", "lv", "xfs"], "expansion_needed": True})
        self.assertNotIn("/dev/", json.dumps(value))
        self.assertNotIn("fingerprint", json.dumps(value))
        self.assertTrue(value["updates"]["maintenance_release_pending"])
        self.assertEqual(value["updates"]["recovery_action"], "nebulalog update finalize")
        self.assertNotIn("automatic_updates", value["updates"])

    def test_kernel_crypto_failure_is_visible_without_raw_diagnostics(self):
        for status in ("failed", "unavailable", "NEVER_PUBLISH_SECRET"):
            with self.subTest(status=status):
                self.host["kernel_crypto_diagnostics"] = {"status": status, "raw": "NEVER_PUBLISH_SECRET"}
                value = self.collector.security()
                self.assertFalse(value["host_controls_ok"])
                self.assertEqual(value["kernel_crypto_status"], "failed" if status == "failed" else "unavailable")
                self.assertNotIn("NEVER_PUBLISH_SECRET", json.dumps(value))

    def test_component_recovery_hint_requires_interrupted_transaction_and_completed_os_work(self):
        self.current.update(maintenance_release_pending=False, os_transaction={})
        for state in ("preflight", "preparing", "activating", "checking", "rolling_back", "recovery_required"):
            self.current["transaction"] = {"state": state}
            self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "nebulalog update recover")
        self.current["os_transaction"] = {"state": "recovery_required", "recovery_phase": "updating"}
        self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "")
        self.current["os_transaction"] = {"state": "recovery_required", "recovery_phase": "postcheck", "boot_id": "boot"}
        self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "nebulalog update os-recover")
        self.current["os_transaction"] = {}
        for state in ("committed", "rolled_back", "preflight_failed"):
            self.current["transaction"] = {"state": state, "finalization": "complete"}
            self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "")

    def test_host_migration_refusal_is_bound_and_contains_no_adapter_diagnostics(self):
        receipt = {"schema": 1, "reason": "qualified_migration_required", "resource": "share/defaults/aide-policy.conf",
                   "sequence": 8, "manifest_sha256": "a" * 64}
        self.current["transaction"] = {"state": "preflight_failed", "sequence": 8, "manifest_sha256": "a" * 64,
                                       "host_refusal": receipt, "error": "NEVER_PUBLISH_SECRET"}
        value = self.collector.collect()["updates"]
        self.assertEqual(value["host_refusal"], {key: receipt[key] for key in ("reason", "resource", "sequence")})
        self.assertNotIn("NEVER_PUBLISH_SECRET", json.dumps(value))
        for mutation in ({"resource": "/etc/nebulalog/private-secret"}, {"sequence": 9}, {"sequence": True},
                         {"manifest_sha256": "b" * 64}, {"diagnostics": "NEVER_PUBLISH_SECRET"}):
            with self.subTest(mutation=mutation):
                self.current["transaction"]["host_refusal"] = {**receipt, **mutation}
                self.assertEqual(self.collector.collect()["updates"], {"status": "unavailable"})

    def github_fixture(self):
        atomic_json(self.collector.github_policy, {"schema": 1, "repository": "stellaraf/captains-log", "automatic_updates": True, "poll_interval_seconds": 900})
        record = {"schema": 1, "repository": "stellaraf/captains-log", "status": "up_to_date", "automatic_updates": True,
                  "checked_at": self.now.isoformat(), "next_check_at": self.now.replace(minute=45).isoformat(),
                  "token": "NEVER_PUBLISH_SECRET", "error": "NEVER_PUBLISH_SECRET"}
        atomic_json(self.state / "updates/github-status.json", record)
        self.current.update(enrollment={"update_ready": True}, maintenance_release_pending=False,
                            transaction={"state": "committed", "finalization": "complete"}, os_transaction={})
        self.runner.side_effect = lambda argv, **_: "active" if argv[1] == "is-active" else "enabled"
        return record

    def test_os_postcheck_recovery_hint_is_separate_from_interrupted_package_changes(self):
        self.current["maintenance_release_pending"] = False
        self.current["os_transaction"] = {"state": "recovery_required", "recovery_phase": "postcheck", "boot_id": "old-boot"}
        self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "nebulalog update os-recover")
        self.current["os_transaction"] = {"state": "recovery_required", "recovery_phase": "updating"}
        self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "")

    def test_github_observation_requires_live_timer_enrollment_and_fresh_check(self):
        self.github_fixture()
        value = self.collector.collect()["updates"]["github"]
        self.assertTrue(value["automatic_updates"])
        self.assertEqual(value["poll_interval_seconds"], 900)
        self.assertNotIn("NEVER_PUBLISH_SECRET", json.dumps(value))
        self.current["enrollment"] = {"update_ready": False}
        value = self.collector.collect()["updates"]["github"]
        self.assertFalse(value["automatic_updates"])
        self.assertEqual(value["status"], "awaiting_enrollment")

    def test_github_stale_or_blocked_check_cannot_claim_automatic_operation(self):
        record = self.github_fixture()
        for changes, expected in (({"checked_at": "2026-09-07T08:00:00Z"}, "stale"),
                                  ({"checked_at": "2026-09-07T11:00:00Z"}, "stale"),
                                  ({"status": "blocked"}, "blocked")):
            atomic_json(self.state / "updates/github-status.json", {**record, **changes})
            value = self.collector.collect()["updates"]["github"]
            self.assertEqual(value["status"], expected)
            self.assertFalse(value["automatic_updates"])

    def test_github_stopped_timer_policy_change_and_pending_recovery_are_visible(self):
        self.github_fixture()
        self.runner.side_effect = lambda argv, **_: "inactive" if argv[1] == "is-active" else "enabled"
        self.assertEqual(self.collector.collect()["updates"]["github"]["status"], "disabled")
        self.github_fixture()
        self.current["maintenance_release_pending"] = True
        self.assertEqual(self.collector.collect()["updates"]["github"]["status"], "blocked")
        self.github_fixture()
        atomic_json(self.collector.github_policy, {"schema": 1, "repository": "stellaraf/renamed", "automatic_updates": True, "poll_interval_seconds": 900})
        value = self.collector.collect()["updates"]["github"]
        self.assertEqual(value, {"status": "unavailable", "automatic_updates": False})

    def test_kernel_recovery_blocks_advertised_automatic_updates_after_healthy_fallback(self):
        self.github_fixture()
        for field in ("kernel_finalization", "kernel_retention", "kernel_rollback"):
            for phase in ("pending", "failed", "recovery_required", "unknown"):
                with self.subTest(field=field, phase=phase):
                    self.current["os_transaction"] = {"state": "complete", "finalization": "complete", field: phase}
                    result = self.collector.collect()["updates"]
                    self.assertEqual(result["github"]["status"], "blocked")
                    self.assertFalse(result["github"]["automatic_updates"])

    def test_kernel_recovery_hint_prioritizes_owned_work_over_component_release(self):
        self.github_fixture()
        self.current["maintenance_release_pending"] = True
        self.current["os_transaction"] = {"state": "complete", "finalization": "complete",
            "kernel_finalization": "recovery_required", "kernel_outcome": "recovery", "kernel_retry": "held"}
        self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "nebulalog update kernel-rollback")
        self.current["os_transaction"].update(state="reboot_requested", kernel_retry="requested", boot_id="old-boot")
        self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "nebulalog update reboot-complete")
        self.current["os_transaction"].update(kernel_rollback="failed")
        self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "nebulalog update kernel-rollback")
        self.current["os_transaction"] = {"state": "complete", "finalization": "complete", "kernel_retention": "pending"}
        self.assertEqual(self.collector.collect()["updates"]["recovery_action"], "nebulalog update reboot-complete")


    def test_fully_grown_disk_reports_measured_false(self):
        self.inspector.return_value = Snapshot(self.storage_identity, 1024*MIB, 1022*MIB, MIB,
                                               1006*MIB, 1006*MIB, 1006*MIB, 1006*MIB, 0)
        value = self.collector.collect()["storage"]
        self.assertEqual(value["growth"]["required_stages"], [])
        self.assertFalse(value["growth"]["expansion_needed"])

    def test_multi_pv_pool_capacity_is_not_designated_disk_capacity(self):
        identity = replace(self.storage_identity, additional_pvs=(("additional-pv", "additional-luks"),))
        self.inspector.return_value = Snapshot(identity, 1024*MIB, 1022*MIB, MIB,
                                               1006*MIB, 1006*MIB, 1500*MIB, 1500*MIB, 8*MIB)
        with patch("nebulalog_manager.status_snapshot.storage.Identity", return_value=identity):
            value = self.collector.collect()["storage"]
        self.assertEqual(value["status"], "observed")
        self.assertEqual(value["encrypted_members"], 2)
        self.assertEqual(value["capacity_bytes"], 1500*MIB)
        self.assertEqual(value["growth"]["presented_disk_bytes"], 1024*MIB)
        self.assertEqual(value["growth"]["required_stages"], ["lv", "xfs"])
        self.assertEqual(value["growth"]["unallocated_disk_bytes"], MIB)
        self.assertNotIn("additional-pv", json.dumps(value))

    def test_xfs_usable_capacity_and_geometry_are_published_separately(self):
        self.inspector.return_value = Snapshot(self.storage_identity, 1024*MIB, 1022*MIB, MIB,
                                               1006*MIB, 1006*MIB, 1006*MIB, 942*MIB, 0,
                                               filesystem_geometry_bytes=1006*MIB)
        value = self.collector.collect()["storage"]
        self.assertEqual(value["capacity_bytes"], 942*MIB)
        self.assertEqual(value["filesystem_geometry_bytes"], 1006*MIB)
        self.assertEqual(value["logical_volume_bytes"], 1006*MIB)
        self.assertEqual(value["growth"]["required_stages"], [])
        self.assertFalse(value["growth"]["expansion_needed"])

    def test_section_failure_never_reuses_previous_success(self):
        self.inspector.side_effect = Refused("NEVER_PUBLISH_SECRET")
        self.baseline.side_effect = Refused("NEVER_PUBLISH_SECRET")
        value = self.collector.collect()
        self.assertEqual(value["storage"], {"status": "unavailable"})
        self.assertEqual(value["baseline"], {"status": "unavailable"})
        self.assertNotIn("NEVER_PUBLISH_SECRET", json.dumps(value))

    def test_disabled_timer_does_not_hide_other_update_evidence(self):
        self.runner.side_effect = CommandFailed("systemctl", 1)
        value = self.collector.collect()["updates"]
        self.assertEqual(value["status"], "observed")
        self.assertFalse(value["os_timer_enabled"])
        self.assertEqual(value["os_timer_status"], "disabled")

    def test_command_deadline_is_bounded(self):
        self.collector.collect()
        self.assertLessEqual(self.runner.call_args.kwargs["timeout"], 5)
        self.collector.deadline = 0
        with self.assertRaises(Refused): self.collector.command(["systemctl", "is-enabled", "nebulalog-os-update.timer"])

    def test_history_is_bounded_and_strips_private_details(self):
        path = self.path / "history.jsonl"
        path.write_text("\n".join(json.dumps({"timestamp": self.now.isoformat(), "action": "update.committed", "sequence": n, "error": "NEVER_PUBLISH_SECRET"}) for n in range(2000)))
        result = history((path,))
        self.assertEqual(len(result), 20)
        self.assertEqual(result[-1]["sequence"], 1999)
        self.assertNotIn("NEVER_PUBLISH_SECRET", json.dumps(result))

    def test_atomic_publication_and_size_link_permission_safety(self):
        path = self.path / "public/status.json"
        path.parent.mkdir(mode=0o700)
        relabel = Mock(return_value="")
        with patch("nebulalog_manager.status_snapshot.public_directory"):
            publish(self.collector.collect(), path, runner=relabel)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(json.loads(path.read_text())["schema"], 1)
            self.assertEqual(relabel.call_args_list[0].args[0], ["restorecon", str(path.parent)])
            self.assertEqual(relabel.call_args_list[1].args[0][0], "restorecon")
            self.assertEqual(Path(relabel.call_args_list[1].args[0][1]).parent, path.parent)
            with self.assertRaises(Refused): publish({"oversized": "x" * 65536}, path, runner=relabel)
            path.unlink(); path.symlink_to(self.policy)
            with self.assertRaises(Refused): publish({"schema": 1}, path, runner=relabel)
        unsafe = self.path / "unsafe"
        unsafe.mkdir(mode=0o777); unsafe.chmod(0o777)
        with self.assertRaises(Refused): public_directory(unsafe)

    def test_failed_inode_relabel_preserves_previous_snapshot(self):
        path = self.path / "public/status.json"
        path.parent.mkdir(mode=0o755)
        path.write_text('{"schema":1,"observed_at":"previous"}\n')
        previous = path.read_bytes()
        def relabel(argv):
            if argv[1] != str(path.parent):
                raise Refused("Could not restore the installed status label")
        with patch("nebulalog_manager.status_snapshot.public_directory"), self.assertRaises(Refused):
            publish({"schema": 1, "observed_at": "new"}, path, runner=relabel)
        self.assertEqual(path.read_bytes(), previous)
        self.assertEqual(list(path.parent.iterdir()), [path])


if __name__ == "__main__": unittest.main()
