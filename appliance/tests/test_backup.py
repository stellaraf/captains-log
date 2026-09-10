"""Standalone backup contracts: fake Podman/runtime, real locks/files and optional CMS.

These tests do not execute a database, guest lifecycle, FIPS module or disk action.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import backup
from nebulalog_manager.common import Refused, atomic_json, locked, run

PIN = "registry.example/postgresql@sha256:" + "a" * 64
IMAGE_ID = "b" * 64
INSTALLATION = "81f0f122-7654-486c-80b9-aa4f90453044"


class FakeCommands:
    def __init__(self):
        self.calls = []
        self.units = {}
        self.fail_dump = False
        self.fail_feed = False
        self.bad_image = False
        self.bad_role = False
        self.encrypt_error = False
        self.real_crypto = False
        self.mutate = None
        self.publish_race = None
        self.luks = True

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv == ["prlimit", "--version"]:
            return "prlimit from util-linux (test fixture)"
        if argv[0] == "prlimit":
            argv = argv[argv.index("--") + 1:]
        if argv[0] == "findmnt":
            return json.dumps({"filesystems": [{"target": "/var/lib/nebulalog", "fstype": "xfs", "source": "/dev/mapper/data"}]})
        if argv[0] == "lsblk":
            return json.dumps({"blockdevices": [{"name": "data", "type": "lvm", "fstype": "xfs", "children": [
                {"type": "part", "fstype": "crypto_LUKS" if self.luks else "ext4"}]}]})
        if argv[:2] == ["systemctl", "show"]:
            return self.units.get(argv[-1], "active")
        if argv[:3] == ["podman", "image", "inspect"]:
            return json.dumps([PIN]) if "{{json .RepoDigests}}" in argv else IMAGE_ID
        if argv[:3] == ["podman", "container", "inspect"]:
            return "c" * 64 if self.bad_image else IMAGE_ID
        if "psql" in argv:
            return json.dumps({"server_version": "17.11", "databases": {name: {
                "owner": name, "can_login": True, "superuser": self.bad_role, "create_role": False,
                "create_database": False, "bytes": 1024} for name in backup.DATABASES}})
        if argv[0] == "openssl":
            if self.real_crypto:
                return run(argv, **kwargs)
            if "cms" in argv:
                if self.encrypt_error:
                    raise Refused("synthetic secret must not enter receipt")
                source = Path(argv[argv.index("-in") + 1])
                target = Path(argv[argv.index("-out") + 1])
                target.write_bytes(source.read_bytes())  # Fake encryption, test contract only.
                if self.publish_race:
                    self.publish_race.write_bytes(b"another backup")
            return ""
        raise AssertionError("Unexpected command: " + repr(argv))

    def capture(self, argv, target, **kwargs):
        self.calls.append(argv)
        if self.fail_dump:
            raise Refused("synthetic secret must not enter receipt")
        target.write_bytes(b"PGDMP synthetic unit-test archive")
        target.chmod(0o600)
        if self.mutate:
            self.mutate.write_text("SYNTHETIC_SECRET=changed")
            self.mutate = None

    def feed(self, argv, source, **kwargs):
        self.calls.append(argv)
        if self.fail_feed or not source.read_bytes().startswith(b"PGDMP"):
            raise Refused("synthetic archive validation failure")


class FakeLifecycle:
    def __init__(self, root, cmd):
        self.root, self.cmd = root, cmd
        self.quadlets = root / "quadlets"
        self.actions = []
        self.fail_start = False
        self.fail_health = False
        self.partial_marker_failure = False

    def encrypted(self):
        backup._encrypted_staging(self.root / "manager", self.cmd)

    def service(self, action, names):
        self.actions.append((action, tuple(names)))
        for name in names:
            if action == "start" and self.fail_start:
                raise Refused("Synthetic restart failure")
            self.cmd.units["nebulalog-" + name + ".service"] = "active" if action == "start" else "inactive"

    def maintenance(self, active, stage):
        for path in (self.root / "manager/maintenance.json", self.root / "public/maintenance.json"):
            if active:
                atomic_json(path, {"active": True, "release": str(stage)})
                if self.partial_marker_failure:
                    raise Refused("Synthetic public marker failure")
            else:
                path.unlink(missing_ok=True)

    def api_ready(self):
        if self.fail_health:
            raise Refused("Synthetic API health failure")


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "configuration"
        for path in (self.config / "bootstrap", self.root / "manager", self.root / "host-bootstrap", self.root / "quadlets"):
            path.mkdir(parents=True, mode=0o700)
        self.secret = self.config / "app.env"
        self.secret.write_text("SYNTHETIC_SECRET=fixture-only")
        self.secret.chmod(0o600)
        (self.root / "quadlets/nebulalog-postgresql.container").write_text("[Container]\nImage=" + PIN + "\n")
        self.cert = self.root / "recipient.pem"
        self.cert.write_text("synthetic certificate fixture")
        self.output = self.root / "backups/backup.cms"
        self.staging = self.root / "backup-staging"
        self.cmd = FakeCommands()
        self.lifecycle = FakeLifecycle(self.root, self.cmd)
        self.gate = Mock(return_value={"host_ready": True, "setup_complete": True, "installation_id": INSTALLATION})
        self.runtime = backup.ConfigurationBackup(self.lifecycle, self.gate, data=self.root,
                        bootstrap=self.root / "host-bootstrap", public=self.root / "public/maintenance.json")
        # Host/FIPS ownership and mount evidence are substituted solely for temporary
        # test fixtures. Real file types, file modes, lock contention and hashes remain.
        for item in (patch.object(backup, "require_linux_root"),
                     patch.object(backup, "_directory", side_effect=self.directory),
                     patch.object(backup, "trusted_file", side_effect=self.trusted),
                     patch.object(backup.shutil, "disk_usage", return_value=Mock(free=1024**4))):
            item.start()
            self.addCleanup(item.stop)

    def directory(self, path, *, private=False, create=False):
        if not path.is_relative_to(self.root) or ".." in path.parts:
            raise Refused("Outside fixture")
        if create:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        for item in (path, *path.parents):
            if item == self.root.parent:
                break
            if item.is_symlink() or not item.is_dir() or item.stat().st_mode & 0o022:
                raise Refused("Unsafe fixture directory")
        if private and path.stat().st_mode & 0o077:
            raise Refused("Not private")

    def trusted(self, path):
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o022:
            raise Refused("Untrusted fixture file")
        return path

    def create(self):
        return backup.create_backup(self.config, self.output, self.cert, staging=self.staging, runtime=self.runtime)

    def transaction(self):
        return json.loads(next((self.root / "manager/backups").glob("*/transaction.json")).read_text())

    def assert_writers_running(self):
        self.assertFalse((self.root / "manager/maintenance.json").exists())
        self.assertFalse((self.root / "public/maintenance.json").exists())
        self.assertEqual(self.lifecycle.actions[-1], ("start", ("keycloak", "api")))
        self.assertTrue(all("ingest" not in names for _, names in self.lifecycle.actions))

    def test_fixed_transport_snapshot_metadata_private_publication(self):
        result = self.create()
        self.assertTrue(result["ok"])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assert_writers_running()
        with tarfile.open(self.output) as archive:
            manifest = json.load(archive.extractfile("backup.json"))
            self.assertEqual(manifest["installation_id"], INSTALLATION)
            self.assertEqual(manifest["postgresql"]["image"], PIN)
            self.assertFalse(manifest["snapshot"]["cross_database_atomic"])
            self.assertFalse(manifest["snapshot"]["ingestion_paused"])
            self.assertEqual(manifest["snapshot"]["paused_writers"], ["api", "keycloak"])
            self.assertEqual(set(manifest["snapshot"]["databases"]), set(backup.DATABASES))
        dumps = [argv for argv in self.cmd.calls if "pg_dump" in argv]
        self.assertEqual(len(dumps), 2)
        for name, argv in zip(backup.DATABASES, dumps):
            self.assertEqual(argv[:2], ["prlimit", "--core=0"])
            self.assertTrue(argv[2].startswith("--fsize="))
            self.assertEqual(argv[4:9], ["podman", "exec", "--user", "999:999", "nebulalog-postgresql"])
            self.assertIn("--username=" + name, argv)
            self.assertIn("--host=/var/run/postgresql", argv)
            self.assertIn("--no-password", argv)
            self.assertNotIn("--username=postgres", argv)
        restores = [argv for argv in self.cmd.calls if "pg_restore" in argv]
        self.assertTrue(all("--interactive" in argv for argv in restores))
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(self.cmd.calls))
        self.assertEqual(self.transaction()["state"], "complete")
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_gate_failure_has_no_database_or_service_effects(self):
        self.gate.side_effect = Refused("FIPS/storage failure")
        with self.assertRaises(Refused):
            self.create()
        self.assertEqual(self.cmd.calls, [])
        self.assertEqual(self.lifecycle.actions, [])

    def test_setup_completion_required(self):
        self.gate.return_value["setup_complete"] = False
        with self.assertRaises(Refused):
            self.create()
        self.assertEqual(self.cmd.calls, [])

    def test_unencrypted_storage_refused_before_dump(self):
        self.cmd.luks = False
        with self.assertRaises(Refused):
            self.create()
        self.assertFalse(any("pg_dump" in argv for argv in self.cmd.calls))

    def test_low_space_refuses_before_writer_pause(self):
        with patch.object(backup.shutil, "disk_usage", return_value=Mock(free=1024)):
            with self.assertRaises(Refused):
                self.create()
        self.assertEqual(self.lifecycle.actions, [])

    def test_global_and_nested_locks_refuse_before_pause(self):
        paths = (self.root / "manager/transaction.lock", self.root / "host-bootstrap/firstboot.lock",
                 self.config / "bootstrap/runtime.lock", self.config / "baseline.lock")
        for path in paths:
            with self.subTest(path=path), locked(path), self.assertRaises(Refused):
                self.create()
        self.assertEqual(self.lifecycle.actions, [])

    def test_foreign_maintenance_is_never_cleared(self):
        atomic_json(self.root / "manager/maintenance.json", {"active": True, "release": "other-operation"})
        with self.assertRaises(Refused):
            self.create()
        self.assertEqual(self.lifecycle.actions, [])
        self.assertTrue((self.root / "manager/maintenance.json").exists())

    def test_pending_os_or_component_transaction_refused(self):
        for path, value in (("os-transaction.json", {"state": "reboot_pending"}),
                            ("updates/transaction.json", {"state": "committed"})):
            record = self.root / "manager" / path
            atomic_json(record, value)
            with self.assertRaises(Refused):
                self.create()
            record.unlink()
        self.assertEqual(self.lifecycle.actions, [])

    def test_wrong_running_image_or_privileged_role_refused(self):
        for option in ("bad_image", "bad_role"):
            setattr(self.cmd, option, True)
            with self.assertRaises(Refused):
                self.create()
            setattr(self.cmd, option, False)
        self.assertEqual(self.lifecycle.actions, [])

    def test_symlink_and_hardlink_configuration_refused(self):
        link = self.config / "linked"
        for create in (lambda: link.symlink_to(self.secret), lambda: os.link(self.secret, link)):
            create()
            with self.assertRaises(Refused):
                self.create()
            link.unlink()
        self.assertFalse(self.output.exists())

    def test_invalid_scope_or_untrusted_certificate_refused(self):
        with self.assertRaises(Refused):
            backup.create_backup(self.config, self.output, self.cert, pg_services=("postgres",), runtime=self.runtime)
        self.cert.chmod(0o666)
        with self.assertRaises(Refused):
            self.create()
        self.assertEqual(self.lifecycle.actions, [])

    def test_capture_failure_restores_writers_and_redacts_error(self):
        self.cmd.fail_dump = True
        with self.assertRaises(Refused) as raised:
            self.create()
        self.assert_writers_running()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.transaction()["state"], "failed")
        self.assertNotIn("synthetic secret", str(raised.exception) + json.dumps(self.transaction()))

    def test_changed_configuration_or_bad_dump_never_published(self):
        for name, value in (("mutate", self.secret), ("fail_feed", True)):
            setattr(self.cmd, name, value)
            with self.assertRaises(Refused):
                self.create()
            setattr(self.cmd, name, None if name == "mutate" else False)
            self.assert_writers_running()
            self.assertFalse(self.output.exists())

    def test_failed_restart_retains_marker_and_can_recover_without_backup(self):
        self.cmd.fail_dump = True
        self.lifecycle.fail_start = True
        with self.assertRaises(Refused):
            self.create()
        value = self.transaction()
        self.assertEqual(value["state"], "recovery_required")
        self.assertTrue((self.root / "manager/maintenance.json").exists())
        self.lifecycle.fail_start = False
        result = self.runtime.recover(value["id"])
        self.assertFalse(result["backup_created"])
        self.assertEqual(self.transaction()["state"], "recovered_without_backup")
        self.assert_writers_running()

    def test_failed_health_retains_marker(self):
        self.lifecycle.fail_health = True
        with self.assertRaises(Refused):
            self.create()
        self.assertEqual(self.transaction()["state"], "recovery_required")
        self.assertTrue((self.root / "manager/maintenance.json").exists())

    def test_partial_maintenance_creation_recovers(self):
        self.lifecycle.partial_marker_failure = True
        with self.assertRaises(Refused):
            self.create()
        self.assert_writers_running()
        self.assertEqual(self.transaction()["state"], "failed")

    def test_recovery_rejects_other_installation_or_foreign_marker(self):
        self.cmd.fail_dump = True
        self.lifecycle.fail_start = True
        with self.assertRaises(Refused):
            self.create()
        identifier = self.transaction()["id"]
        self.gate.return_value["installation_id"] = "88a5a0f4-a656-487a-a44e-7f66165874c5"
        with self.assertRaises(Refused):
            self.runtime.recover(identifier)
        self.gate.return_value["installation_id"] = INSTALLATION
        atomic_json(self.root / "manager/maintenance.json", {"active": True, "release": "foreign"})
        with self.assertRaises(Refused):
            self.runtime.recover(identifier)

    def test_recovery_handles_crash_after_marker_removal_without_claiming_backup(self):
        self.cmd.fail_dump = True
        self.lifecycle.fail_start = True
        with self.assertRaises(Refused):
            self.create()
        value = self.transaction()
        self.lifecycle.maintenance(False, self.root / "manager/backups" / value["id"])
        self.lifecycle.fail_start = False
        result = self.runtime.recover(value["id"])
        self.assertEqual(result["state"], "recovered_without_backup")
        self.assertFalse(result["backup_created"])

    def test_recovery_never_bypasses_pending_os_transaction(self):
        self.cmd.fail_dump = True
        self.lifecycle.fail_start = True
        with self.assertRaises(Refused):
            self.create()
        identifier = self.transaction()["id"]
        atomic_json(self.root / "manager/os-transaction.json", {"state": "reboot_pending"})
        self.lifecycle.fail_start = False
        self.lifecycle.actions.clear()
        with self.assertRaises(Refused):
            self.runtime.recover(identifier)
        self.assertEqual(self.lifecycle.actions, [])

    def test_encryption_failure_happens_after_runtime_recovery(self):
        self.cmd.encrypt_error = True
        with self.assertRaises(Refused):
            self.create()
        self.assert_writers_running()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.output.parent.iterdir()), [])

    def test_concurrent_output_is_not_overwritten(self):
        self.cmd.publish_race = self.output
        with self.assertRaises(Refused):
            self.create()
        self.assertEqual(self.output.read_bytes(), b"another backup")
        self.assert_writers_running()

    def test_staged_restore_uses_container_validation_and_never_applies(self):
        self.create()
        self.lifecycle.actions.clear()
        key = self.root / "key.pem"
        key.write_text("synthetic private key fixture")
        key.chmod(0o600)
        destination = self.root / "recovery/staged"
        result = backup.restore_backup(self.output, key, self.cert, destination, staging=self.staging, runtime=self.runtime)
        self.assertIn("not applied", result["database_restore"])
        self.assertEqual(self.lifecycle.actions, [])
        self.assertTrue((destination / "nebulalog.dump").exists())
        self.assertEqual((destination / "configuration/app.env").stat().st_mode & 0o777, 0o600)

    def test_bad_staged_database_archive_removes_owned_destination(self):
        self.create()
        self.cmd.fail_feed = True
        key = self.root / "key.pem"
        key.write_text("synthetic private key fixture")
        key.chmod(0o600)
        destination = self.root / "recovery/staged"
        with self.assertRaises(Refused):
            backup.restore_backup(self.output, key, self.cert, destination, staging=self.staging, runtime=self.runtime)
        self.assertFalse(destination.exists())

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_real_cms_round_trip_and_tamper_never_unpacks(self):
        if not subprocess.check_output(["openssl", "version"], text=True).startswith("OpenSSL 3."):
            self.skipTest("OpenSSL 3 CMS authenticated envelope required")
        key = self.root / "recipient.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1",
                        "-subj", "/CN=Unit Test Recipient", "-keyout", str(key), "-out", str(self.cert)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        key.chmod(0o600)
        self.cmd.real_crypto = True
        result = self.create()
        self.assertEqual(result["encryption"], "CMS AES-256-GCM")
        destination = self.root / "recovery/good"
        restored = backup.restore_backup(self.output, key, self.cert, destination, staging=self.staging, runtime=self.runtime)
        self.assertEqual(restored["manifest"]["installation_id"], INSTALLATION)
        value = bytearray(self.output.read_bytes())
        value[-8] ^= 1
        self.output.write_bytes(value)
        bad = self.root / "recovery/tampered"
        with self.assertRaises(Refused):
            backup.restore_backup(self.output, key, self.cert, bad, staging=self.staging, runtime=self.runtime)
        self.assertFalse(bad.exists())
        self.assertEqual(list(self.staging.iterdir()), [])


class StagingTests(unittest.TestCase):
    def test_missing_encrypted_mount_does_not_create_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "not-created/scratch"
            runner = Mock(return_value=json.dumps({"filesystems": [{"target": "/", "fstype": "xfs", "source": "/dev/sda"}]}))
            with self.assertRaises(Refused):
                backup._encrypted_staging(destination, runner)
            self.assertFalse(destination.parent.exists())

    def test_luks_missing_refuses_before_staging_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "scratch"
            cmd = FakeCommands()
            cmd.luks = False
            with self.assertRaises(Refused):
                backup._encrypted_staging(destination, cmd)
            self.assertFalse(destination.exists())

    def test_real_directory_guard_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "linked"
            destination.symlink_to(temporary, target_is_directory=True)
            with self.assertRaises(Refused):
                backup._directory(destination)


if __name__ == "__main__":
    unittest.main()
