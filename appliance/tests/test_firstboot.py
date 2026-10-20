"""Safety and restart behavior; these tests do not claim real guest disk proof."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager.common import CommandFailed, Refused, atomic_json
from nebulalog_manager.firstboot import (FirstBoot, Locations, FINAL_CHECKS, HOST_STAGES,
                                        RUNTIME_CHECKS, _append_unique, _private_file,
                                        _runtime_console, _write_bytes, validate_config)
from nebulalog_manager.storage import blank_disk_plan


CONFIG = {
    "schema": 1, "disk": "/dev/disk/by-id/virtio-nebulalog-data", "hostname": "logs.example.test",
    "unlock_key_file": "/run/nebulalog/disk-passphrase",
    "network": {"connection_uuid": "11111111-2222-4333-8444-555555555555", "ipv4": {"method": "auto"}, "ipv6": {"method": "disabled"}, "dns": ["192.0.2.53"]},
    "ntp": ["ntp.example.test"], "administrator": {"username": "appliance-admin", "password_file": "/run/nebulalog/admin-password"},
    "baseline": "unified", "maintenance": {"weekday": 6, "start": "03:00", "end": "05:00", "timezone": "UTC"}, "retention_days": 90,
}


class ConfigTests(unittest.TestCase):
    def test_valid_static_dual_stack(self):
        config = copy.deepcopy(CONFIG)
        config["network"]["ipv4"] = {"method": "manual", "addresses": ["192.0.2.10/24"], "gateway": "192.0.2.1"}
        config["network"]["ipv6"] = {"method": "manual", "addresses": ["2001:db8::10/64"], "gateway": "2001:db8::1"}
        self.assertEqual(validate_config(config), config)

    def test_refuse_shell_and_path_injection(self):
        for key, value in (("hostname", "a;reboot"), ("disk", "/dev/sda"), ("disk", "/dev/disk/by-id/../../sda"), ("disk", "/dev/disk/by-id/data\n"), ("unlock_key_file", "/etc/private.key"), ("ntp", ["server\ncmd"]), ("baseline", "none")):
            config = copy.deepcopy(CONFIG)
            config[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(Refused):
                validate_config(config)

    def test_refuse_unknown_inline_secret_fields(self):
        config = copy.deepcopy(CONFIG)
        config["administrator"]["password"] = "never allowed inline"
        with self.assertRaises(Refused):
            validate_config(config)

    def test_refuse_invalid_network(self):
        for patch_value in ({"ipv4": {"method": "manual"}}, {"ipv4": {"method": "auto", "addresses": ["192.0.2.1/24"]}}, {"ipv4": {"method": "manual", "addresses": ["::1/128"]}}, {"ipv4": {"method": "disabled"}}, {"dns": ["$(reboot)"]}, {"connection_uuid": "--help"}):
            config = copy.deepcopy(CONFIG)
            config["network"].update(patch_value)
            with self.subTest(patch_value=patch_value), self.assertRaises(Refused):
                validate_config(config)

    def test_refuse_invalid_maintenance_and_retention(self):
        for key, value in (("weekday", True), ("weekday", 7), ("start", "25:00"), ("start", "05:00"), ("timezone", "../UTC")):
            config = copy.deepcopy(CONFIG)
            config["maintenance"][key] = value
            with self.subTest(key=key), self.assertRaises(Refused):
                validate_config(config)
        for value in (0, 3651, True, 1.5):
            config = copy.deepcopy(CONFIG)
            config["retention_days"] = value
            with self.assertRaises(Refused):
                validate_config(config)


class PrivateFileTests(unittest.TestCase):
    def test_secret_permissions_and_destination_symlink(self):
        with tempfile.TemporaryDirectory() as directory, patch("nebulalog_manager.firstboot.trusted_file", lambda path: path):
            path = Path(directory) / "secret"
            _write_bytes(path, b"private example")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.chmod(0o640)
            with self.assertRaises(Refused):
                _private_file(path)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(Refused):
                _write_bytes(link, b"must not overwrite")

    def test_boot_entries_idempotent_and_conflicts_refused(self):
        with tempfile.TemporaryDirectory() as directory, patch("nebulalog_manager.firstboot.trusted_file", lambda path: path):
            path = Path(directory) / "crypttab"
            row = "nebulalog-data UUID=owned none luks"
            _append_unique(path, row, "nebulalog-data")
            _append_unique(path, row, "nebulalog-data")
            self.assertEqual(path.read_text().count(row), 1)
            with self.assertRaises(Refused):
                _append_unique(path, "nebulalog-data UUID=foreign none luks", "nebulalog-data")


class DiskModel:
    """A stateful device model to exercise refusal/resume across command failures."""
    def __init__(self):
        self.calls, self.table, self.luks, self.pv, self.vg, self.lv, self.fs = [], None, None, None, None, None, None
        self.mounted, self.recovery, self.interrupt_after = False, False, None
        self.serial, self.size = "nebulalog-test-data", 2 * 1024**3

    def probe(self, disk):
        return blank_disk_plan(disk, self.serial, self.size, ["gpt"] if self.table else [], [], [], False, False, False)

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        program = argv[0]
        result = ""
        if program == "nmcli" and "--get-values" in argv:
            result = CONFIG["network"]["connection_uuid"]
        elif program == "lsblk":
            result = json.dumps({"blockdevices": [{"name": "vdb", "type": "disk", "serial": self.serial, "size": self.size, "ro": False, "rm": False}]})
        elif program == "wipefs":
            result = json.dumps({"signatures": [{"type": "gpt"}] if self.table else []})
        elif program == "sfdisk":
            if "--json" in argv:
                result = json.dumps({"partitiontable": self.table})
            else:
                lines = kwargs["input"].decode().splitlines()
                self.table = {"label": "gpt", "id": lines[1].split(": ")[1], "partitions": [{"node": CONFIG["disk"] + "-part1", "uuid": lines[2].split("uuid=")[1]}]}
        elif program == "blkid":
            device = argv[-1]
            if device.endswith("-part1") and self.luks:
                result = "TYPE=crypto_LUKS\nUUID=" + self.luks
            elif device == "/dev/mapper/nebulalog-data" and self.pv:
                result = "TYPE=LVM2_member"
            elif device == "/dev/nebulalog/data" and self.fs:
                result = "TYPE=xfs\nUUID=" + self.fs
            else:
                raise CommandFailed("blkid", 2)
        elif program == "cryptsetup":
            if argv[1] == "luksFormat":
                self.luks = argv[argv.index("--uuid") + 1]
            elif argv[1] == "luksAddKey":
                self.recovery = True
            elif argv[1] == "status":
                result = "  device: " + CONFIG["disk"] + "-part1"
            elif "--test-passphrase" in argv and "luks-recovery-" in argv[argv.index("--key-file") + 1] and not self.recovery:
                raise CommandFailed("cryptsetup", 2)
        elif program == "pvcreate":
            self.pv = "pv-owned"
        elif program == "vgcreate":
            self.vg = "vg-owned"
        elif program == "lvcreate":
            self.lv = {"lv_path": "/dev/nebulalog/data", "lv_uuid": "lv-owned", "vg_uuid": self.vg, "lv_tags": argv[argv.index("--addtag") + 1], "segtype": "linear"}
        elif program == "pvs":
            result = json.dumps({"report": [{"pv": [{"pv_name": "/dev/mapper/nebulalog-data", "pv_uuid": self.pv, "vg_name": "nebulalog" if self.vg else "", "vg_uuid": self.vg or ""}] if self.pv else []}]})
        elif program == "vgs":
            result = json.dumps({"report": [{"vg": [{"vg_name": "nebulalog"}] if self.vg else []}]})
        elif program == "lvs":
            result = json.dumps({"report": [{"lv": [self.lv] if self.lv else []}]})
        elif program == "mkfs.xfs":
            self.fs = argv[2].split("=", 1)[1]
        elif program == "mountpoint":
            if not self.mounted:
                raise CommandFailed("mountpoint", 32)
        elif program == "mount":
            self.mounted = True
        if self.interrupt_after == program:
            self.interrupt_after = None
            raise CommandFailed(program, 99)
        return result


class TransactionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.paths = Locations(self.root / "etc", self.root / "data", self.root / "run", self.root / "crypttab", self.root / "fstab", self.root / "chrony.d/test.sources", self.root / "chrony.conf")
        self.model = DiskModel()
        self.manager = FirstBoot(self.paths, runner=self.model, prober=self.model.probe, inspector=lambda identity: identity.validate())
        for target, value in (("nebulalog_manager.firstboot.trusted_file", lambda path: path), ("nebulalog_manager.firstboot._private_dir", lambda path: path.mkdir(parents=True, exist_ok=True)), ("nebulalog_manager.firstboot.FirstBoot._host", lambda self: None)):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        original = _private_file
        patcher = patch("nebulalog_manager.firstboot._private_file", lambda path, **kwargs: b"a long input credential" if str(path) in (CONFIG["unlock_key_file"], CONFIG["administrator"]["password_file"]) else original(path, **kwargs))
        patcher.start()
        self.addCleanup(patcher.stop)

    def apply(self):
        plan = self.manager.plan(CONFIG)
        return self.manager.apply(CONFIG, plan["confirmation"])

    def test_stale_confirmation_does_not_initialize_disk(self):
        with self.assertRaisesRegex(Refused, "confirmation"):
            self.manager.apply(CONFIG, "0" * 64)
        self.assertFalse(any(call[0][0] in ("sfdisk", "cryptsetup", "pvcreate") for call in self.model.calls))
        self.assertFalse(self.manager.journal_path.exists())

    def test_storage_initializes_once_and_resume_keeps_secrets(self):
        first = self.apply()
        secrets_path = self.paths.data / "configuration/bootstrap/secrets.json"
        before = secrets_path.read_bytes()
        self.apply()
        self.assertEqual(first["state"], "host-ready")
        self.assertFalse(first["setup_complete"])
        self.assertFalse((self.paths.etc / "configured").exists())
        self.assertEqual(before, secrets_path.read_bytes())
        for command in ("pvcreate", "vgcreate", "lvcreate", "mkfs.xfs"):
            self.assertEqual(sum(call[0][0] == command for call in self.model.calls), 1)
        self.assertEqual(sum(call[0][:2] == ["cryptsetup", "luksFormat"] for call in self.model.calls), 1)
        self.assertEqual(set(json.loads(self.manager.journal_path.read_text())["completed"]), set(HOST_STAGES))
        self.assertNotIn("a long input credential", self.manager.journal_path.read_text())

    def test_crash_after_vg_creation_resumes_observed_volume(self):
        self.model.interrupt_after = "vgcreate"
        with self.assertRaises(CommandFailed):
            self.apply()
        failed = json.loads(self.manager.journal_path.read_text())
        self.assertEqual(failed["active_stage"], "volume-group")
        self.assertFalse((self.paths.bootstrap / "host-ready.json").exists())
        self.apply()
        self.assertEqual(sum(call[0][0] == "vgcreate" for call in self.model.calls), 1)

    def test_replaced_luks_header_is_not_reformatted(self):
        self.model.interrupt_after = "pvcreate"
        with self.assertRaises(CommandFailed):
            self.apply()
        self.model.luks = "foreign-volume"
        with self.assertRaisesRegex(Refused, "LUKS identity"):
            self.apply()
        self.assertEqual(sum(call[0][:2] == ["cryptsetup", "luksFormat"] for call in self.model.calls), 1)

    def test_changed_configuration_cannot_resume(self):
        self.model.interrupt_after = "pvcreate"
        with self.assertRaises(CommandFailed):
            self.apply()
        changed = copy.deepcopy(CONFIG)
        changed["disk"] = "/dev/disk/by-id/another-disk"
        with self.assertRaisesRegex(Refused, "different setup"):
            self.manager.plan(changed)

    def test_changed_disk_serial_cannot_resume(self):
        self.model.interrupt_after = "pvcreate"
        with self.assertRaises(CommandFailed):
            self.apply()
        self.model.serial = "replacement"
        with self.assertRaisesRegex(Refused, "identity or capacity"):
            self.apply()

    def test_existing_pool_refused_before_blank_disk_mutation(self):
        self.model.vg = "foreign"
        with self.assertRaisesRegex(Refused, "already exists"):
            self.apply()
        self.assertIsNone(self.model.table)

    def test_generated_recovery_key_is_not_silently_replaced(self):
        self.model.interrupt_after = "cryptsetup"
        with self.assertRaises(CommandFailed):
            self.apply()
        # Retry reaches recovery, then lose the credential while addition fails.
        original = self.model.__call__
        def runner(argv, **kwargs):
            if argv[:2] == ["cryptsetup", "luksAddKey"]:
                raise CommandFailed("cryptsetup", 99)
            return original(argv, **kwargs)
        self.manager.runner = runner
        with self.assertRaises(CommandFailed):
            self.apply()
        for key in self.paths.runtime.glob("luks-recovery-*.key"):
            key.unlink()
        with self.assertRaisesRegex(Refused, "lost its runtime key"):
            self.apply()

    def test_incomplete_adapter_receipt_cannot_mark_setup_complete(self):
        prepared = self.apply()
        original = self.manager.runner
        for missing in ("administrator_mfa_enrolled", "aide_enrolled", "aide_checked_clean"):
            with self.subTest(missing=missing):
                incomplete = {"schema": 1, "installation_id": prepared["installation_id"], "state": "setup-complete", "checks": {key: True for key in FINAL_CHECKS if key != missing}}
                with patch("nebulalog_manager.firstboot.os.access", return_value=True):
                    self.manager.runner = lambda argv, **kwargs: json.dumps(incomplete) if argv[0].endswith("bootstrap-runtime") else original(argv, **kwargs)
                    with self.assertRaisesRegex(Refused, "incomplete"):
                        self.manager.complete(Path(prepared["recovery_key_path"]))
                self.assertFalse((self.paths.etc / "configured").exists())

    def test_verified_final_receipt_and_disk_key_required(self):
        prepared = self.apply()
        receipt = {"schema": 1, "installation_id": prepared["installation_id"], "state": "setup-complete", "checks": {key: True for key in FINAL_CHECKS}, "tls_certificate_sha256": "AA" * 32, "tls_ca_certificate_sha256": "BB" * 32, "must_not_persist": "adapter-sensitive-output"}
        with patch("nebulalog_manager.firstboot.os.access", return_value=True):
            original = self.manager.runner
            self.manager.runner = lambda argv, **kwargs: json.dumps(receipt) if argv[0].endswith("bootstrap-runtime") else original(argv, **kwargs)
            result = self.manager.complete(Path(prepared["recovery_key_path"]))
        self.assertTrue(result["setup_complete"])
        stored = (self.paths.etc / "configured").read_text()
        self.assertNotIn("adapter-sensitive-output", stored)
        self.assertIn('"tls_certificate_sha256": "' + "aa" * 32 + '"', stored)
        self.assertIn('"tls_ca_certificate_sha256": "' + "bb" * 32 + '"', stored)
        self.assertTrue(self.manager.gate()["setup_complete"])

    def test_runtime_receipt_rejects_invalid_public_certificate_fingerprints(self):
        receipt = {"schema": 1, "installation_id": "test-installation", "state": "runtime-ready", "checks": {key: True for key in RUNTIME_CHECKS}}
        for field in ("tls_certificate_sha256", "tls_ca_certificate_sha256"):
            for invalid in (None, [], 123, "g" * 64, "ab:" * 32, "ab" * 32 + "\n"):
                with self.subTest(field=field, invalid=invalid), patch("nebulalog_manager.firstboot.os.access", return_value=True):
                    self.manager.runner = lambda argv, **kwargs: json.dumps({**receipt, field: invalid})
                    with self.assertRaisesRegex(Refused, "invalid certificate fingerprint"):
                        self.manager._runtime_receipt("prepare", "test-installation")

    def test_console_distinguishes_server_and_ca_fingerprints(self):
        receipt = {"https_url": "https://logs.example.test", "tls_certificate_sha256": "aa" * 32, "tls_ca_certificate_sha256": "bb" * 32}
        output = io.StringIO()
        with patch("nebulalog_manager.setup_integrity.pending_console"), patch("nebulalog_manager.firstboot._answer", return_value="LATER"), patch("sys.stdout", output):
            _runtime_console(self.manager, CONFIG, receipt)
        self.assertIn("TLS certificate SHA-256: " + "aa" * 32, output.getvalue())
        self.assertIn("TLS CA certificate SHA-256: " + "bb" * 32, output.getvalue())


class WizardRecoveryRoutingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.paths = Locations(base / "etc", base / "data", base / "run")
        self.paths.bootstrap.mkdir(parents=True)
        (self.paths.data / "manager").mkdir(parents=True)
        self.manager = FirstBoot(self.paths, runner=Mock())
        self.manager.journal_path.write_text("{}")
        self.manager._host = Mock()
        self.manager.status = Mock(return_value={"state": "host-ready", "setup_complete": False})
        self.manager.config = Mock(return_value=CONFIG)
        self.manager.gate = Mock(return_value={"host_ready": True, "setup_complete": False, "installation_id": "11111111-2222-4333-8444-555555555555"})
        self.manager.plan = self.manager.apply = self.manager.provision = Mock(side_effect=AssertionError("Existing host must not be rewritten"))

    def test_retained_restore_routes_before_runtime_resume_or_apply(self):
        from nebulalog_manager.firstboot import wizard
        (self.paths.data / "manager/restore.json").write_text("{}")
        with patch("nebulalog_manager.console.local_console"), patch("builtins.print"), \
                patch("nebulalog_manager.setup_integrity.resume_runtime", side_effect=AssertionError("Route retained restore first")), \
                patch("nebulalog_manager.console.host_ready_console", return_value={"state": "recovery_required"}) as menu:
            self.assertEqual(wizard(self.manager), {"state": "recovery_required"})
        menu.assert_called_once_with(self.manager, CONFIG, restore_only=True)
        self.manager.runner.assert_not_called()
        self.manager.apply.assert_not_called()

    def test_host_ready_retry_offers_choice_without_recreating_credentials(self):
        from nebulalog_manager.firstboot import wizard
        (self.paths.bootstrap / "host-ready.json").write_text("{}")
        with patch("nebulalog_manager.console.local_console"), patch("builtins.print"), \
                patch("nebulalog_manager.setup_integrity.resume_runtime", return_value=None), \
                patch("nebulalog_manager.firstboot._password_file", side_effect=AssertionError("Do not recreate credentials")), \
                patch("nebulalog_manager.firstboot._console_recovery") as export, \
                patch("nebulalog_manager.console.host_ready_console", return_value={"state": "host-ready"}) as menu:
            self.assertEqual(wizard(self.manager), {"state": "host-ready"})
        export.assert_called_once()
        menu.assert_called_once_with(self.manager, CONFIG)
        self.manager.apply.assert_not_called()
        self.manager.runner.assert_not_called()

    def test_restored_completion_keeps_existing_mfa_language(self):
        output = io.StringIO()
        with patch("nebulalog_manager.setup_integrity.pending_console"), \
                patch("nebulalog_manager.firstboot._answer", return_value="LATER"), patch("sys.stdout", output):
            _runtime_console(self.manager, CONFIG, {"restored": True})
        self.assertIn("existing MFA/recovery credentials", output.getvalue())
        self.assertNotIn("enroll MFA and recovery codes", output.getvalue())


if __name__ == "__main__":
    unittest.main()
