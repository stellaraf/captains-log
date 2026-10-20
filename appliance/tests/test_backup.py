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
        self.probe_error = False
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
                source = Path(argv[argv.index("-in") + 1])
                if self.probe_error or self.encrypt_error and source.name != "recipient-probe.txt":
                    raise Refused("synthetic secret must not enter receipt")
                target = Path(argv[argv.index("-out") + 1])
                target.write_bytes(source.read_bytes())  # Fake encryption, test contract only.
                if self.publish_race and source.name != "recipient-probe.txt":
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

    def application_schema_current(self):
        return {"revision": "2"}


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
        for service in ("postgresql", "clickhouse", "keycloak", "api", "ingest"):
            (self.root / "quadlets" / ("nebulalog-" + service + ".container")).write_text("[Container]\nImage=" + PIN + "\n")
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
                     patch("nebulalog_manager.recovery_set._directory", side_effect=self.directory),
                     patch("nebulalog_manager.log_recovery_set.ROOT_UID", os.getuid()),
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
            self.assertEqual(manifest["runtime"], {"schema_revision": "2", "images": {
                name: PIN for name in ("NEBULALOG_IMAGE", "POSTGRESQL_IMAGE", "CLICKHOUSE_IMAGE", "KEYCLOAK_FIPS_IMAGE")}})
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

    def linked_policy(self, value=None):
        self.lifecycle.application_schema_current = lambda: {"revision": "3"}
        self.lifecycle._schema_psql = Mock(return_value=json.dumps(value if value is not None else {"revision": 7, "global_days": 90, "per_type": {}}))

    def test_linked_capture_records_exact_ciphertext_runtime_policy_and_child_identity(self):
        self.linked_policy()
        result = self.runtime.create_for_log_set(self.output, self.cert, INSTALLATION)
        self.assertEqual(result["id"], INSTALLATION)
        self.assertEqual(result["log_link"], {"source_installation_id": INSTALLATION,
            "configuration_backup": {"sha256": backup.digest_file(self.output), "bytes": self.output.stat().st_size},
            "runtime": {"schema_revision": "3", "images": {name: PIN for name in
                ("NEBULALOG_IMAGE", "POSTGRESQL_IMAGE", "CLICKHOUSE_IMAGE", "KEYCLOAK_FIPS_IMAGE")}}})
        self.assertEqual(result["configuration_capture"]["retention_policy"]["revision"], 7)
        self.assertEqual(self.transaction()["result"], result)
        self.assertFalse(result["includes_logs"])
        self.assert_writers_running()

    def test_linked_capture_legacy_missing_revision_is_explicit_one(self):
        self.linked_policy({"global_days": 90, "per_type": {}})
        result = self.runtime.create_for_log_set(self.output, self.cert, INSTALLATION)
        policy = result["configuration_capture"]["retention_policy"]
        self.assertEqual(policy["revision"], 1)
        self.assertEqual(policy["normalization"], "absent_defaults_to_1")

    def test_linked_capture_rejects_policy_change_and_restores_writers(self):
        self.linked_policy()
        self.lifecycle._schema_psql.side_effect = [json.dumps({"revision": 7}), json.dumps({"revision": 8})]
        with self.assertRaises(Refused):
            self.runtime.create_for_log_set(self.output, self.cert, INSTALLATION)
        self.assertFalse(self.output.exists())
        self.assert_writers_running()
        self.assertEqual(self.transaction()["state"], "failed")

    def test_linked_capture_rejects_malformed_policy_revision(self):
        self.linked_policy()
        for revision in (True, None, "7", 0, -1, 2**63):
            with self.subTest(revision=revision):
                self.lifecycle._schema_psql.return_value = json.dumps({"revision": revision})
                with self.assertRaises(Refused):
                    self.runtime._log_policy()

    def test_linked_capture_requires_schema_three_before_writer_pause(self):
        with self.assertRaisesRegex(Refused, "schema 3"):
            self.runtime.create_for_log_set(self.output, self.cert, INSTALLATION)
        self.assertEqual(self.lifecycle.actions, [])

    def test_linked_preflight_failure_has_positive_receipt_and_fresh_settlement(self):
        with self.assertRaisesRegex(Refused, "schema 3"):
            self.runtime.create_for_log_set(self.output, self.cert, INSTALLATION)
        result = self.runtime.settle_for_log_set(INSTALLATION, self.output)
        self.assertEqual(result["outcome"], "no_capture_started")
        self.assertTrue(result["settled"])
        self.assertIsNone(result["journal_sha256"])
        self.assertFalse(self.output.exists())
        self.assertEqual(self.lifecycle.actions, [])

    def test_missing_or_ambiguous_configuration_never_supplies_settlement(self):
        with self.assertRaises(Refused):
            self.runtime.settle_for_log_set(INSTALLATION, self.output)
        self.linked_policy()
        self.cmd.fail_dump = True
        with self.assertRaises(Refused):
            self.runtime.create_for_log_set(self.output, self.cert, INSTALLATION)
        with self.assertRaises(Refused):
            self.runtime.settle_for_log_set(INSTALLATION, self.output)

    def test_preflight_settlement_refuses_foreign_maintenance_and_unhealthy_runtime(self):
        with self.assertRaises(Refused):
            self.runtime.create_for_log_set(self.output, self.cert, INSTALLATION)
        marker = self.root / "manager/maintenance.json"
        atomic_json(marker, {"active": True, "release": "/unrelated"})
        with self.assertRaises(Refused):
            self.runtime.settle_for_log_set(INSTALLATION, self.output)
        marker.unlink()
        self.lifecycle.fail_health = True
        with self.assertRaises(Refused):
            self.runtime.settle_for_log_set(INSTALLATION, self.output)

    def test_signalled_or_failed_container_client_does_not_prove_command_settlement(self):
        from nebulalog_adapters.commands import Commands
        from types import SimpleNamespace
        import uuid
        commands = Commands()
        self.runtime.cmd = self.lifecycle.cmd = commands
        for argv, code in ((["podman", "exec", "nebulalog-postgresql", "pg_dump"], -9),
                           (["prlimit", "--core=0", "--", "podman", "exec", "nebulalog-postgresql", "pg_dump"], -9),
                           (["podman", "exec", "nebulalog-postgresql", "pg_restore"], 125),
                           (["podman", "exec", "nebulalog-postgresql", "pg_dump"], 1)):
            identifier = str(uuid.uuid4())
            def child(*args, **kwargs):
                kwargs["_capture_intent"]()
                self.runtime.cmd(argv)
            with self.subTest(argv=argv, code=code), patch.object(self.runtime, "_guard", return_value=INSTALLATION), \
                    patch.object(self.runtime, "create", side_effect=child), \
                    patch("nebulalog_adapters.commands.subprocess.run", return_value=SimpleNamespace(returncode=code, stdout=b"")):
                with self.assertRaises(Refused):
                    self.runtime.create_for_log_set(self.output, self.cert, identifier)
            admission = json.loads((self.root / "manager/backup-admissions" / identifier / "admission.json").read_text())
            self.assertEqual(admission["state"], "failed_ambiguous")
            self.assertFalse(admission["commands_settled"])
            self.assertIs(self.runtime.cmd, commands)

    def test_completed_commands_then_validation_failure_can_recover_owned_services(self):
        from nebulalog_adapters.commands import Commands
        from types import SimpleNamespace
        commands = Commands()
        self.runtime.cmd = self.lifecycle.cmd = commands
        stage = self.root / "manager/backups" / INSTALLATION
        def child(*args, **kwargs):
            kwargs["_capture_intent"]()
            self.runtime.cmd(["podman", "exec", "nebulalog-postgresql", "pg_dump"])
            atomic_json(stage / "transaction.json", {"schema": 1, "kind": "configuration-backup", "id": INSTALLATION,
                        "installation_id": INSTALLATION, "state": "recovery_required"})
            raise Refused("Synthetic post-command validation and service recovery failure")
        with patch.object(self.runtime, "_guard", return_value=INSTALLATION), \
                patch.object(self.runtime, "create", side_effect=child), \
                patch("nebulalog_adapters.commands.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=b"")):
            with self.assertRaises(Refused):
                self.runtime.create_for_log_set(self.output, self.cert, INSTALLATION)
        admission = json.loads((self.root / "manager/backup-admissions" / INSTALLATION / "admission.json").read_text())
        self.assertEqual(admission["state"], "failed_settled")
        self.runtime.cmd = self.lifecycle.cmd = self.cmd
        self.lifecycle.maintenance(True, stage)
        result = self.runtime.settle_for_log_set(INSTALLATION, self.output)
        self.assertEqual(result["outcome"], "settled_failed_capture")
        self.assertEqual(json.loads((stage / "settlement-before.json").read_text())["state"], "recovery_required")
        self.assertEqual(json.loads((stage / "transaction.json").read_text())["state"], "recovered_without_backup")
        self.assertFalse((self.root / "manager/maintenance.json").exists())

    def test_linked_capture_never_replays_an_existing_child(self):
        self.linked_policy()
        self.runtime.create_for_log_set(self.output, self.cert, INSTALLATION)
        journal = (self.root / "manager/backups" / INSTALLATION / "transaction.json").read_bytes()
        other = self.root / "backups/second.cms"
        before = len(self.lifecycle.actions)
        with self.assertRaisesRegex(Refused, "already exists"):
            self.runtime.create_for_log_set(other, self.cert, INSTALLATION)
        self.assertFalse(other.exists())
        self.assertEqual(len(self.lifecycle.actions), before)
        self.assertEqual((self.root / "manager/backups" / INSTALLATION / "transaction.json").read_bytes(), journal)

    def test_linked_capture_invalid_child_identity_has_no_effect(self):
        for identifier in ("../escape", "00000000-0000-0000-0000-000000000000", True):
            with self.subTest(identifier=identifier), self.assertRaises(Refused):
                self.runtime.create_for_log_set(self.output, self.cert, identifier)
        self.assertEqual(self.cmd.calls, [])

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

    def test_unsupported_recipient_refuses_before_maintenance_or_capture(self):
        self.cmd.probe_error = True
        with self.assertRaisesRegex(Refused, "RSA-OAEP"):
            self.create()
        self.assertEqual(self.lifecycle.actions, [])
        self.assertFalse(any("pg_dump" in argv for argv in self.cmd.calls))
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

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
        # This case substitutes ciphertext only; the real CMS test below exercises
        # admission and decryption without replacing either cryptographic boundary.
        with patch("nebulalog_manager.configuration_restore.authenticated_cms") as admission:
            result = backup.restore_backup(self.output, key, self.cert, destination, staging=self.staging, runtime=self.runtime)
        admission.assert_called_once_with(self.output)
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
        with patch("nebulalog_manager.configuration_restore.authenticated_cms"), self.assertRaises(Refused):
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
        envelope = subprocess.check_output(["openssl", "cms", "-cmsout", "-print", "-inform", "DER", "-in", str(self.output)], text=True)
        self.assertIn("rsaesOaep", envelope)
        self.assertIn("mgf1", envelope)
        self.assertEqual(envelope.count("OBJECT            :sha256"), 2)
        self.assertIn("aes-256-gcm", envelope)
        self.assertNotIn("rsaEncryption", envelope)
        destination = self.root / "recovery/good"
        restored = backup.restore_backup(self.output, key, self.cert, destination, staging=self.staging, runtime=self.runtime)
        self.assertEqual(restored["manifest"]["installation_id"], INSTALLATION)
        # Re-encrypt the same valid tar with CBC: OpenSSL can decrypt it, but this
        # path must reject its missing authentication before issuing decryption.
        plain, cbc = self.root / "cbc-input.tar", self.root / "unauthenticated.cms"
        run(["openssl", "cms", "-decrypt", "-binary", "-inform", "DER", "-in", str(self.output),
             "-recip", str(self.cert), "-inkey", str(key), "-out", str(plain)])
        run(["openssl", "cms", "-encrypt", "-binary", "-aes-256-cbc", "-outform", "DER",
             "-in", str(plain), "-out", str(cbc), str(self.cert)])
        calls_before = len(self.cmd.calls)
        rejected = self.root / "recovery/unauthenticated"
        with self.assertRaisesRegex(Refused, "authenticated"):
            backup.restore_backup(cbc, key, self.cert, rejected, staging=self.staging, runtime=self.runtime)
        self.assertFalse(rejected.exists())
        self.assertFalse(any("-decrypt" in argv for argv in self.cmd.calls[calls_before:]))
        value = bytearray(self.output.read_bytes())
        value[-8] ^= 1
        self.output.write_bytes(value)
        bad = self.root / "recovery/tampered"
        with self.assertRaises(Refused):
            backup.restore_backup(self.output, key, self.cert, bad, staging=self.staging, runtime=self.runtime)
        self.assertFalse(bad.exists())
        self.assertEqual(list(self.staging.iterdir()), [])


class RecipientProbeTests(unittest.TestCase):
    def test_preexisting_probe_paths_are_preserved_without_encryption(self):
        for name, link in (("recipient-probe.txt", False), ("recipient-probe.cms", False),
                           ("recipient-probe.cms", True)):
            with self.subTest(name=name, link=link), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                retained = root / name
                if link:
                    retained.symlink_to(root / "absent")
                else:
                    retained.write_bytes(b"previous caller")
                command = Mock()
                with self.assertRaises(Refused):
                    backup.probe_recipient(root / "cert.pem", root, command)
                command.assert_not_called()
                if link:
                    self.assertTrue(retained.is_symlink())
                else:
                    self.assertEqual(retained.read_bytes(), b"previous caller")
                self.assertEqual(set(root.iterdir()), {retained})

    def test_failed_and_invalid_probes_remove_only_owned_files(self):
        for outcome in ("failure", "empty", "oversize", "valid"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                def command(argv, **kwargs):
                    target = Path(argv[argv.index("-out") + 1])
                    self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                    if outcome == "failure":
                        raise Refused("synthetic sensitive diagnostic")
                    target.write_bytes(b"x" * {"empty": 0, "oversize": 65537, "valid": 512}[outcome])
                if outcome == "valid":
                    backup.probe_recipient(root / "cert.pem", root, command)
                else:
                    with self.assertRaisesRegex(Refused, "RSA-OAEP") as raised:
                        backup.probe_recipient(root / "cert.pem", root, command)
                    self.assertNotIn("synthetic", str(raised.exception))
                self.assertEqual(list(root.iterdir()), [])


class StagingTests(unittest.TestCase):
    def test_directory_payload_cannot_hide_unchecked_pax_header(self):
        for kind in (tarfile.DIRTYPE, tarfile.AREGTYPE):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "hidden-header.tar"
                directory = tarfile.TarInfo("configuration/")
                directory.type, directory.size = kind, 512
                hidden = tarfile.TarInfo("hidden-pax")
                hidden.type, hidden.size = tarfile.XHDTYPE, 1024**4
                archive.write_bytes(directory.tobuf(format=tarfile.USTAR_FORMAT) + hidden.tobuf() + bytes(1024))
                with patch.object(backup.tarfile, "open") as parser:
                    with self.assertRaisesRegex(Refused, "directory header"):
                        backup.unpack_backup(archive, root / "unpacked")
                    parser.assert_not_called()
                self.assertFalse((root / "unpacked").exists())

    def test_chained_or_dangling_pax_headers_are_rejected_before_recursive_parser(self):
        for count in (1, 400):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "nested-pax.tar"
                header = tarfile.TarInfo("pax")
                header.type, header.size = tarfile.XHDTYPE, 0
                archive.write_bytes(header.tobuf() * count + bytes(1024))
                with patch.object(backup.tarfile, "open") as parser:
                    with self.assertRaisesRegex(Refused, "extended header"):
                        backup.unpack_backup(archive, root / "unpacked")
                    parser.assert_not_called()

    def test_cumulative_pax_metadata_is_bounded_before_tarfile_retains_members(self):
        import io
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "aggregate-pax.tar"
            with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tar:
                for index in range(9):
                    info = tarfile.TarInfo("configuration/file-" + str(index))
                    info.pax_headers = {"uname": "x" * (512 * 1024)}
                    tar.addfile(info, io.BytesIO())
            with patch.object(backup.tarfile, "open") as parser:
                with self.assertRaisesRegex(Refused, "extended header exceeds"):
                    backup.unpack_backup(archive, root / "unpacked")
                parser.assert_not_called()
            self.assertFalse((root / "unpacked").exists())

    def test_extended_header_size_is_refused_before_tarfile_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "oversized.tar"
            header = tarfile.TarInfo("pax")
            header.type = tarfile.XHDTYPE
            header.size = 2 * 1024**2
            with archive.open("wb") as stream:
                stream.write(header.tobuf())
                stream.truncate(512 + header.size + 1024)
            with patch.object(backup.tarfile, "open") as parser:
                with self.assertRaisesRegex(Refused, "extended header"):
                    backup.unpack_backup(archive, root / "unpacked")
                parser.assert_not_called()
            self.assertFalse((root / "unpacked").exists())

    def test_pax_cannot_override_preflighted_member_size(self):
        import io
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "size-override.tar"
            with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tar:
                info = tarfile.TarInfo("backup.json")
                info.size = 2
                info.pax_headers = {"size": "1099511627776"}
                tar.addfile(info, io.BytesIO(b"{}"))
            with self.assertRaisesRegex(Refused, "extended header field"):
                backup.unpack_backup(archive, root / "unpacked")

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
