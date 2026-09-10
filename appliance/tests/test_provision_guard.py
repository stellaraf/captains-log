"""Private-build guard fixtures; no guest commands, policy writes or installs."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location("provision_guard", Path(__file__).resolve().parents[1] / "provision_guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
IDENTITY = {"machine_sha256": "a" * 64, "build_key_sha256": "b" * 64}
MOUNTINFO = "1 0 8:1 / / rw - xfs /dev/vda1 rw\n"


class PrivateBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("etc", "var/lib", "proc/self", "usr/lib", "dev/mapper"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / "proc/self/mountinfo").write_text(MOUNTINFO)
        self.build = guard.BuildGuard(self.root, os.getuid(), os.getgid())

    def private(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def test_fresh_guard_precedes_payload_and_finishes(self):
        self.assertIsNone(self.build.inspect(IDENTITY))
        self.build.begin(IDENTITY)
        self.assertEqual(self.build.inspect(IDENTITY)["phase"], "provisioning")
        with self.assertRaises(guard.Refused):
            self.build.inspect(IDENTITY, complete=True)
        self.build.finish(IDENTITY)
        self.assertEqual(self.build.inspect(IDENTITY, complete=True)["phase"], "installed")

    def test_interrupted_payload_can_retry_with_same_identity(self):
        self.build.begin(IDENTITY)
        (self.root / "usr/lib/nebulalog").mkdir()
        self.private("etc/nebulalog/trust.json", b"fixture\n")
        self.private("etc/nebulalog/github-updates.json", b'{"schema":1}\n')
        self.build.begin(IDENTITY)
        self.assertTrue((self.root / "usr/lib/nebulalog").is_dir())
        self.assertEqual(self.build.inspect(IDENTITY)["phase"], "provisioning")

    def test_completed_private_build_can_be_reprovisioned_but_cannot_seal_mid_retry(self):
        self.build.begin(IDENTITY)
        self.build.finish(IDENTITY)
        self.build.begin(IDENTITY)
        with self.assertRaises(guard.Refused):
            self.build.inspect(IDENTITY, complete=True)

    def test_early_receipt_resumes_missing_ancillary_markers(self):
        self.build.begin(IDENTITY)
        for name in ("unsealed-build", "state"):
            (self.build.bootstrap / name).unlink()
        self.build.begin(IDENTITY)
        self.assertEqual((self.build.bootstrap / "state").read_bytes(), b"unconfigured\n")

    def test_every_customer_or_seal_artifact_refuses_without_overwriting(self):
        for name in ("configured", "storage.json", "security-policy.json", "bootstrap/firstboot.json", "bootstrap/image-state", "bootstrap/setup-input.json", "bootstrap/runtime-ready.json", "bootstrap/host-ready.json", "bootstrap/recovery-export.json"):
            with self.subTest(name=name):
                self.build.begin(IDENTITY)
                path = self.private("etc/nebulalog/" + name, b"customer evidence\n")
                before = self.build.receipt.read_bytes()
                with self.assertRaises(guard.Refused):
                    self.build.begin(IDENTITY)
                self.assertEqual(self.build.receipt.read_bytes(), before)
                self.assertEqual(path.read_bytes(), b"customer evidence\n")
                path.unlink()

    def test_nonempty_data_refuses(self):
        self.build.begin(IDENTITY)
        self.private("var/lib/nebulalog/customer", b"data")
        with self.assertRaises(guard.Refused):
            self.build.begin(IDENTITY)

    def test_empty_bind_mount_and_nested_mount_refuse(self):
        for destination in ("/var/lib/nebulalog", "/var/lib/nebulalog/containers"):
            with self.subTest(destination=destination):
                (self.root / "proc/self/mountinfo").write_text(MOUNTINFO + f"2 1 8:1 / {destination} rw - xfs /dev/vda1 rw\n")
                with self.assertRaises(guard.Refused):
                    self.build.begin(IDENTITY)
                self.assertFalse(self.build.receipt.exists())

    def test_unknown_mount_inventory_refuses(self):
        for value in ("", "truncated"):
            with self.subTest(value=value):
                (self.root / "proc/self/mountinfo").write_text(value)
                with self.assertRaises(guard.Refused):
                    self.build.begin(IDENTITY)

    def test_enrollment_without_mounted_data_refuses(self):
        for name in ("etc/crypttab", "etc/fstab", "dev/mapper/nebulalog-data", "dev/nebulalog"):
            with self.subTest(name=name):
                path = self.private(name, b"nebulalog-data UUID=fixture none luks\n")
                with self.assertRaises(guard.Refused):
                    self.build.begin(IDENTITY)
                path.unlink()

    def test_other_vm_or_key_receipt_refuses(self):
        self.build.begin(IDENTITY)
        for field in IDENTITY:
            with self.subTest(field=field), self.assertRaises(guard.Refused):
                self.build.begin({**IDENTITY, field: "c" * 64})

    def test_bad_receipt_mode_link_content_and_schema_refuse(self):
        self.build.begin(IDENTITY)
        original = self.build.receipt.read_bytes()
        self.build.receipt.chmod(0o640)
        with self.assertRaises(guard.Refused):
            self.build.begin(IDENTITY)
        self.build.receipt.chmod(0o600)
        for value in (b"{}", b"[]", b"invalid", json.dumps({**json.loads(original), "schema": True}).encode()):
            self.build.receipt.write_bytes(value)
            with self.assertRaises((guard.Refused, ValueError)):
                self.build.begin(IDENTITY)
        self.build.receipt.unlink()
        self.build.receipt.symlink_to(self.root / "absent")
        with self.assertRaises((guard.Refused, OSError)):
            self.build.begin(IDENTITY)

    def test_modified_state_is_not_reset(self):
        self.build.begin(IDENTITY)
        path = self.build.bootstrap / "state"
        path.write_bytes(b"configured\n")
        with self.assertRaises(guard.Refused):
            self.build.begin(IDENTITY)
        self.assertEqual(path.read_bytes(), b"configured\n")

    def test_legacy_payload_or_unsealed_marker_without_receipt_refuses(self):
        (self.root / "usr/lib/nebulalog").mkdir()
        with self.assertRaises(guard.Refused):
            self.build.begin(IDENTITY)
        (self.root / "usr/lib/nebulalog").rmdir()
        self.private("etc/nebulalog/bootstrap/unsealed-build", guard.PRIVATE_MARKER)
        with self.assertRaises(guard.Refused):
            self.build.begin(IDENTITY)

    def test_symlink_directory_and_missing_completed_marker_refuse(self):
        self.build.base.symlink_to(self.root / "absent", target_is_directory=True)
        with self.assertRaises((guard.Refused, OSError)):
            self.build.begin(IDENTITY)
        self.build.base.unlink()
        self.build.begin(IDENTITY)
        self.build.finish(IDENTITY)
        (self.build.bootstrap / "unsealed-build").unlink()
        with self.assertRaises(guard.Refused):
            self.build.begin(IDENTITY)

    def test_failed_receipt_sync_does_not_publish_state_or_ancillary_markers(self):
        with patch.object(guard.os, "fsync", side_effect=OSError("fixture durability failure")):
            with self.assertRaises(OSError):
                self.build.begin(IDENTITY)
        self.assertFalse(self.build.receipt.exists())
        self.assertFalse((self.build.bootstrap / "state").exists())


class PublicKeyTests(unittest.TestCase):
    def public(self, bits):
        items = [b"ssh-rsa", b"\x01\x00\x01", b"\x00" + ((1 << (bits - 1)) | 1).to_bytes(bits // 8, "big")]
        wire = b"".join(struct.pack(">I", len(item)) + item for item in items)
        return b"ssh-rsa " + base64.b64encode(wire) + b" disposable fixture\n"

    def test_rsa3072_and_4096(self):
        for bits in (3072, 4096):
            self.assertRegex(guard.rsa_key_digest(self.public(bits)), "^[a-f0-9]{64}$")

    def test_short_non_rsa_or_multiple_keys_refuse(self):
        for value in (self.public(2048), b"ssh-ed25519 AAAA\n", self.public(3072) * 2, b"ssh-rsa malformed\n"):
            with self.subTest(value=value[:16]), self.assertRaises(guard.Refused):
                guard.rsa_key_digest(value)


class BuildIdentityTests(unittest.TestCase):
    def setUp(self):
        self.values = {"/etc/os-release": 'ID="rocky"\nVERSION_ID="9.8"\n', "/proc/sys/crypto/fips_enabled": "1\n", "/etc/machine-id": "1" * 32 + "\n"}
        self.commands = {("systemd-detect-virt", "--vm"): "kvm", ("getenforce",): "Enforcing", ("passwd", "--status", "root"): "root LK fixture", ("vgs", "--noheadings", "--options", "vg_name"): "system"}
        def path(value):
            result = MagicMock()
            result.read_text.side_effect = lambda: self.values[value]
            result.lstat.return_value = SimpleNamespace(st_mode=0o100444, st_uid=0, st_size=33)
            return result
        for target, replacement in (("checked", lambda args: self.commands[tuple(args)]), ("Path", path), ("private_dir", lambda *args: None), ("rsa_key_digest", lambda value: "b" * 64)):
            operation = patch.object(guard, target, replacement)
            operation.start()
            self.addCleanup(operation.stop)
        operations = [patch.object(guard.os, "geteuid", return_value=0), patch.object(guard.sys, "platform", "linux"), patch.object(guard.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_dir="/home/packer")), patch.dict(guard.os.environ, {"SUDO_USER": "packer", "SUDO_UID": "1000"}, clear=True), patch.object(guard, "private_file", side_effect=[b"packer ALL=(ALL) NOPASSWD: ALL\n", b"public key fixture"])]
        for operation in operations:
            operation.start()
            self.addCleanup(operation.stop)

    def test_valid_private_host_observations(self):
        self.assertEqual(guard.build_identity()["build_key_sha256"], "b" * 64)

    def test_non_vm_refuses_before_identity_files(self):
        self.commands[("systemd-detect-virt", "--vm")] = "none"
        with self.assertRaises(guard.Refused):
            guard.build_identity()
        guard.private_file.assert_not_called()

    def test_actual_kernel_flag_is_required(self):
        self.values["/proc/sys/crypto/fips_enabled"] = "0\n"
        with self.assertRaises(guard.Refused):
            guard.build_identity()
        guard.private_file.assert_not_called()

    def test_customer_sudo_identity_refuses(self):
        with patch.dict(guard.os.environ, {"SUDO_USER": "customer"}):
            with self.assertRaises(guard.Refused):
                guard.build_identity()

    def test_enrolled_volume_group_refuses(self):
        self.commands[("vgs", "--noheadings", "--options", "vg_name")] = "system\nnebulalog"
        with self.assertRaises(guard.Refused):
            guard.build_identity()

    def test_detached_sealer_still_checks_build_identity_without_sudo_env(self):
        with patch.dict(guard.os.environ, {}, clear=True):
            self.assertEqual(guard.build_identity(require_sudo=False)["build_key_sha256"], "b" * 64)


class ContextPolicyTests(unittest.TestCase):
    def records(self):
        return {(expression, "all files"): ("system_u", "object_r", label, "s0") for expression, label in guard.CONTEXTS.items()}

    def test_fresh_and_exact_retry(self):
        self.assertEqual(len(guard.context_plan({}, {}, {}, {})), 6)
        records = self.records()
        self.assertEqual(guard.context_plan(records, records, dict([guard.EQUIVALENCE]), {}), [])

    def test_partial_registration_only_adds_missing_rules(self):
        records = dict(list(self.records().items())[:2])
        plan = guard.context_plan(records, records, {}, {})
        self.assertEqual(len(plan), 4)
        self.assertFalse(any(rule[-1] in {key[0] for key in records} for rule in plan))

    def test_unexpected_context_or_file_type_refuses(self):
        expression = next(iter(guard.CONTEXTS))
        for key, value in (((expression, "all files"), ("system_u", "object_r", "var_t", "s0")), ((expression, "directory"), ("system_u", "object_r", guard.CONTEXTS[expression], "s0")), (("/custom(/.*)?", "all files"), ("system_u", "object_r", "var_t", "s0"))):
            with self.subTest(key=key), self.assertRaises(guard.Refused):
                guard.context_plan({key: value}, {key: value}, {}, {})

    def test_encrypted_aide_context_is_exact_and_does_not_override_conflicts(self):
        expression = "/var/lib/nebulalog/manager/aide(/.*)?"
        self.assertEqual(guard.CONTEXTS[expression], "aide_db_t")
        key = (expression, "all files")
        wrong = {key: ("system_u", "object_r", "var_lib_t", "s0")}
        with self.assertRaises(guard.Refused):
            guard.context_plan(wrong, wrong, {}, {})

    def test_differing_base_policy_is_not_shadowed(self):
        key = next(iter(self.records()))
        with self.assertRaises(guard.Refused):
            guard.context_plan({key: ("system_u", "object_r", "var_t", "s0")}, {}, {}, {})

    def test_unexpected_or_overlapping_equivalence_refuses(self):
        for local, distribution in (({guard.EQUIVALENCE[0]: "/wrong"}, {}), ({"/unrelated": "/other"}, {}), ({}, {"/var/lib/nebulalog": "/other"}), ({}, {"/run/nebulalog-status/child": "/other"})):
            with self.subTest(local=local, distribution=distribution), self.assertRaises(guard.Refused):
                guard.context_plan({}, {}, local, distribution)

    def test_rocky_runtime_alias_uses_only_canonical_registrations(self):
        distribution = {"/run": "/var/run", "/run/lock": "/var/lock",
                        "/run/systemd/system": "/usr/lib/systemd/system"}
        plan = guard.context_plan({}, {}, {}, distribution)
        self.assertEqual(len(plan), 6)
        self.assertIn(("-a", "-e", guard.EQUIVALENCE[1], guard.EQUIVALENCE[0]), plan)
        self.assertIn(("-a", "-t", "httpd_var_run_t", "/var/run/nebulalog-public(/.*)?"), plan)
        self.assertIn(("-a", "-t", "container_file_t", "/var/run/nebulalog-status(/.*)?"), plan)
        self.assertFalse(any(rule[-1].startswith("/run/") for rule in plan))

    def test_exact_canonical_retry_is_noop_under_distribution_alias(self):
        distribution = {"/run": "/var/run"}
        records = {(expression, "all files"): ("system_u", "object_r", label, "s0")
                   for expression, label in guard.policy_contexts(distribution).items()}
        self.assertEqual(guard.context_plan(records, records, dict([guard.EQUIVALENCE]), distribution), [])

    def test_differing_canonical_or_logical_fixed_policy_refuses(self):
        for path in ("/run/nebulalog-status(/.*)?", "/var/run/nebulalog-status(/.*)?"):
            for kind, label in (("all files", "var_t"), ("directory", "container_file_t")):
                records = {(path, kind): ("system_u", "object_r", label, "s0")}
                with self.subTest(path=path, kind=kind), self.assertRaises(guard.Refused):
                    guard.context_plan(records, {}, {}, {"/run": "/var/run"})

    def test_unsubstituted_distribution_record_does_not_count_as_registered(self):
        key = ("/run/nebulalog-status(/.*)?", "all files")
        records = {key: ("system_u", "object_r", "container_file_t", "s0")}
        plan = guard.context_plan(records, {}, {}, {"/run": "/var/run"})
        self.assertIn(("-a", "-t", "container_file_t", "/var/run/nebulalog-status(/.*)?"), plan)
        with self.assertRaises(guard.Refused):
            guard.context_plan(records, records, {}, {"/run": "/var/run"})

    def test_only_exact_distribution_runtime_alias_is_accepted(self):
        for local, distribution in (({"/run": "/var/run"}, {}),
                                    ({"/run": "/var/run"}, {"/run": "/var/run"}),
                                    ({}, {"/run": "/different"}),
                                    ({}, {"/run": "/var/run", "/var/run": "/run"}),
                                    ({}, {"/run": "/var/run/"})):
            with self.subTest(local=local, distribution=distribution), self.assertRaises(guard.Refused):
                guard.context_plan({}, {}, local, distribution)

    def test_overlap_checks_protect_both_runtime_spellings(self):
        for path in ("/run/nebulalog-status", "/run/nebulalog-public/child", "/var/run",
                     "/var/run/nebulalog-status", "/var/run/nebulalog-public/child"):
            with self.subTest(path=path), self.assertRaises(guard.Refused):
                guard.context_plan({}, {}, {}, {"/run": "/var/run", path: "/different"})


class ContextRegistrationTests(unittest.TestCase):
    """A policy-store fixture with Rocky seobject.validate's alias rejection."""
    def fixture(self, *, post_read=None, persist=True):
        state = SimpleNamespace(local={}, equiv={}, distribution={"/run": "/var/run"}, writes=[], reads=0)

        class Records:
            def __init__(self):
                state.reads += 1
                if state.reads == 2 and post_read:
                    post_read(state)
                self.equiv, self.equiv_dist = dict(state.equiv), dict(state.distribution)

            def get_all(self, local=False):
                return dict(state.local)

            def validate(self, expression):
                for mapping in (self.equiv, self.equiv_dist):
                    for alias in mapping:
                        if expression.startswith(alias + "/"):
                            raise ValueError("Rocky seobject refuses a file spec under an equivalence")

            def add(self, expression, label, kind, level, user):
                self.validate(expression)
                state.writes.append(("context", expression, label, kind, level, user))
                if persist:
                    state.local[(expression, "all files")] = (user, "object_r", label, level)

            def add_equal(self, target, source):
                self.validate(target)
                state.writes.append(("equivalence", target, source))
                if persist:
                    state.equiv[target] = source

        return state, SimpleNamespace(fcontextRecords=Records)

    def rules(self):
        return [("-a", "-e", guard.EQUIVALENCE[1], guard.EQUIVALENCE[0])] + [
            ("-a", "-t", label, expression) for expression, label in guard.CONTEXTS.items()]

    def test_complete_installer_sequence_and_retry_use_canonical_policy(self):
        state, module = self.fixture()
        with patch.dict(guard.sys.modules, {"seobject": module}):
            for rule in self.rules():
                guard.ensure_context(rule)
            first = list(state.writes)
            for rule in self.rules():
                guard.ensure_context(rule)
        self.assertEqual(len(first), 6)
        self.assertEqual(state.writes, first)
        self.assertEqual(first[0], ("equivalence", guard.EQUIVALENCE[0], guard.EQUIVALENCE[1]))
        self.assertEqual(first[1], ("context", "/var/run/nebulalog-public(/.*)?", "httpd_var_run_t", "a", "s0", "system_u"))
        self.assertEqual(first[2], ("context", "/var/run/nebulalog-status(/.*)?", "container_file_t", "a", "s0", "system_u"))
        self.assertFalse(any(key[0].startswith("/run/") for key in state.local))

    def test_fixture_reproduces_rocky_rejection_of_unresolved_expression(self):
        _, module = self.fixture()
        with self.assertRaises(ValueError):
            module.fcontextRecords().add("/run/nebulalog-public(/.*)?", "httpd_var_run_t", "a", "s0", "system_u")

    def test_direct_canonical_or_arbitrary_cli_path_is_not_an_override(self):
        module = SimpleNamespace(fcontextRecords=MagicMock())
        for expression in ("/var/run/nebulalog-status(/.*)?", "/run/custom(/.*)?"):
            with self.subTest(expression=expression), patch.dict(guard.sys.modules, {"seobject": module}), self.assertRaises(guard.Refused):
                guard.ensure_context(("-a", "-t", "container_file_t", expression))
        module.fcontextRecords.assert_not_called()

    def test_alias_disappearance_during_equivalence_registration_refuses(self):
        state, module = self.fixture(post_read=lambda current: current.distribution.clear())
        with patch.dict(guard.sys.modules, {"seobject": module}), self.assertRaisesRegex(guard.Refused, "alias changed"):
            guard.ensure_context(self.rules()[0])
        self.assertEqual(len(state.writes), 1)

    def test_alias_change_during_context_registration_refuses(self):
        for replacement in ({}, {"/run": "/different"}, {"/run": "/var/run", "/var/run/nebulalog-public": "/different"}):
            state, module = self.fixture(post_read=lambda current: setattr(current, "distribution", replacement))
            with self.subTest(replacement=replacement), patch.dict(guard.sys.modules, {"seobject": module}), self.assertRaises(guard.Refused):
                guard.ensure_context(self.rules()[1])
            self.assertEqual(len(state.writes), 1)

    def test_nonpersisted_add_is_not_treated_as_success(self):
        for rule in self.rules()[:2]:
            state, module = self.fixture(persist=False)
            with self.subTest(rule=rule), patch.dict(guard.sys.modules, {"seobject": module}), self.assertRaisesRegex(guard.Refused, "not registered"):
                guard.ensure_context(rule)
            self.assertEqual(len(state.writes), 1)

    def test_conflicting_policy_anywhere_refuses_before_first_write(self):
        state, module = self.fixture()
        state.local[("/var/run/nebulalog-status(/.*)?", "all files")] = ("system_u", "object_r", "var_t", "s0")
        with patch.dict(guard.sys.modules, {"seobject": module}), self.assertRaises(guard.Refused):
            guard.ensure_context(self.rules()[0])
        self.assertEqual(state.writes, [])


if __name__ == "__main__":
    unittest.main()
