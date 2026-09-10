import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager.common import Refused
from nebulalog_manager.guest_validation import (Collector, Result, command, listener_summary,
                                                kernel_crypto_diagnostics, package_inventory, provider_inventory,
                                                verification_diagnostics)


class ParsingTests(unittest.TestCase):
    def test_package_inventory_keeps_exact_versions_and_marks_absent(self):
        value = package_inventory("openssl-libs\t1:3.0.7-30.el9.x86_64\nopenssl-libs\t1:3.0.7-31.el9.x86_64\nPASSWORD\tPRIVATE_SECRET\nopenssl\tinvalid secret value\n")
        self.assertEqual(value["openssl-libs"]["nevra"], ["1:3.0.7-30.el9.x86_64", "1:3.0.7-31.el9.x86_64"])
        self.assertEqual(value["openssl"]["status"], "unavailable")
        self.assertNotIn("PRIVATE_SECRET", json.dumps(value))

    def test_provider_inventory_does_not_copy_unrecognized_details(self):
        value = provider_inventory("Providers:\n  fips\n    name: PRIVATE_SECRET\n    version: 3.0.7\n    status: active\n    unexpected: PRIVATE_SECRET\n  base\n    status: inactive\n")
        self.assertEqual(value["fips"], {"status": "active", "version": "3.0.7"})
        self.assertEqual(value["base"], {"status": "inactive"})
        self.assertNotIn("PRIVATE_SECRET", json.dumps(value))

    def test_listeners_redact_addresses_and_preserve_public_private_boundary(self):
        value = listener_summary("tcp LISTEN 0 128 127.0.0.1:8443 0.0.0.0:*\ntcp LISTEN 0 128 [::]:443 [::]:*\nudp UNCONN 0 0 192.0.2.250:514 0.0.0.0:*\n")
        self.assertIn({"protocol": "tcp", "port": 8443, "scope": "loopback", "family": "ipv4"}, value)
        self.assertIn({"protocol": "tcp", "port": 443, "scope": "wildcard", "family": "ipv6"}, value)
        self.assertNotIn("192.0.2.250", json.dumps(value))
        for invalid in ("malformed", "tcp LISTEN 0 128 secret:5432 *:*"):
            with self.assertRaises((Refused, ValueError)):
                listener_summary(invalid)

    def test_systemd_warning_with_exit_zero_is_not_passed_or_echoed(self):
        result = Result(0, stderr="nebulalog-edge.service: Unknown key PRIVATE_SECRET\n")
        value = verification_diagnostics(result, {"nebulalog-edge.service"})
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["diagnostic_counts"], {"unknown_directive": 1})
        self.assertNotIn("PRIVATE_SECRET", json.dumps(value))
        self.assertEqual(verification_diagnostics(Result(0), set())["status"], "passed")

    def test_kernel_self_test_failure_is_retained_without_raw_messages(self):
        # Exact spelling from the installed Rocky 9.8 kernel, including hdkf.
        output = ("Linux version 5.14.0-687.44.1.el9_8.x86_64\n"
                  "basic hdkf test(hmac(sha256-avx2)): hkdf_extract failed with -22 PRIVATE_SECRET\n"
                  "dracut: fips-load-crypto done\n")
        value = kernel_crypto_diagnostics(Result(0, output))
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["diagnostic_counts"], {"hkdf_self_test_failure": 1})
        self.assertNotIn("PRIVATE_SECRET", json.dumps(value))
        self.assertEqual(value["all_algorithms_tested"], "not established")

    def test_incomplete_kernel_journal_cannot_clear_self_test_findings(self):
        for result in (Result(1), Result(0), Result(0, "dracut: fips-load-crypto done\n"),
                       Result(0, "Linux version example\n", "PRIVATE_SECRET")):
            with self.subTest(result=result):
                value = kernel_crypto_diagnostics(result)
                self.assertEqual(value["status"], "unavailable")
                self.assertNotIn("PRIVATE_SECRET", json.dumps(value))
        value = kernel_crypto_diagnostics(Result(0, "Linux version example\nalg: self-tests for SHA256 passed\n"))
        self.assertEqual(value["status"], "no_failure_observed")

    def test_other_crypto_failures_and_hkdf_corrected_spelling_are_detected(self):
        for message in ("alg: self-tests for example failed", "alg: skcipher: test failed on vector 1",
                        "FIPS crypto self-test failed", "basic hkdf test(hmac(sha256)): hkdf_extract failed with -22",
                        "basic hdkf test(hmac(sha256)): hkdf_extract prk mismatch",
                        "basic hdkf test(hmac(sha256)): hkdf_expand() okm mismatch",
                        "hkdf test with long input(hmac(sha256)): hkdf_extract failed with -22"):
            with self.subTest(message=message):
                self.assertEqual(kernel_crypto_diagnostics(Result(0, message))["status"], "failed")

    def test_bounded_child_runner_keeps_pipes_separate(self):
        result = command([sys.executable, "-c", "import sys; print('public'); print('private',file=sys.stderr)"], timeout=5, maximum=128)
        self.assertEqual(result.stdout, "public\n")
        self.assertEqual(result.stderr, "private\n")
        with self.assertRaises(Refused):
            command([sys.executable, "-c", "print('x'*4096)"], timeout=5, maximum=128)


class GuardAndStageTests(unittest.TestCase):
    def test_nonroot_or_nonlinux_stops_before_probe(self):
        runner = Mock()
        collector = Collector(runner=runner)
        with patch("nebulalog_manager.guest_validation.require_linux_root", side_effect=Refused("not authorized")):
            with self.assertRaises(Refused):
                collector.collect()
        runner.assert_not_called()

    def test_wrong_os_and_container_detection_refuse(self):
        collector = Collector(runner=Mock(return_value=Result(0, "docker\n")))
        def file(path, *args, **kwargs):
            return 'ID="rocky"\nVERSION_ID="9.8"\n' if "os-release" in str(path) else "unconfigured\n"
        with patch("nebulalog_manager.guest_validation.require_linux_root"), patch("nebulalog_manager.guest_validation.small_file", side_effect=file), patch.object(Path, "resolve", lambda path: path):
            with self.assertRaisesRegex(Refused, "virtual machine"):
                collector.guard()
        with patch("nebulalog_manager.guest_validation.require_linux_root"), patch("nebulalog_manager.guest_validation.small_file", return_value='ID="debian"\nVERSION_ID="12"\n'), patch.object(Path, "resolve", lambda path: path):
            with self.assertRaisesRegex(Refused, "Rocky 9"):
                collector.guard()

    def test_fips_tools_without_active_provider_do_not_pass(self):
        def runner(argv, **kwargs):
            return Result(0, "FIPS\n" if argv[0] == "update-crypto-policies" else "Providers:\n  default\n    status: active\n")
        collector = Collector(runner=runner)
        with patch("nebulalog_manager.guest_validation.small_file", return_value="1"):
            value = collector.fips()
        self.assertEqual(value["status"], "failed")
        self.assertFalse(value["active_fips_provider_observed"])

    def test_enabled_fips_and_active_provider_do_not_override_kernel_failure(self):
        journal = "Linux version 5.14.0-687.44.1.el9_8.x86_64\n"
        def runner(argv, **kwargs):
            if argv[0] == "journalctl":
                self.assertEqual(argv, ["journalctl", "-k", "--boot=0", "--no-pager", "--output=cat"])
                return Result(0, journal)
            if argv[0] == "update-crypto-policies":
                return Result(0, "FIPS\n")
            if argv[0] == "openssl":
                return Result(0, "Providers:\n  fips\n    status: active\n")
            return Result(0)
        collector = Collector(runner=runner)
        with patch("nebulalog_manager.guest_validation.small_file", return_value="1"):
            self.assertEqual(collector.fips()["status"], "passed")
            journal += "basic hdkf test(hmac(sha256-avx2)): hkdf_extract failed with -22\n"
            value = collector.fips()
            self.assertTrue(value["kernel_enabled"])
            self.assertTrue(value["active_fips_provider_observed"])
            self.assertEqual(value["status"], "failed")
            journal = ""
            self.assertEqual(collector.fips()["status"], "unavailable")

    def test_initramfs_existence_alone_cannot_prove_required_drivers(self):
        def runner(argv, **kwargs):
            if argv[0] == "uname":
                return Result(0, "5.14.0-611.el9.x86_64")
            if argv[0] == "modinfo":
                return Result(0, "/lib/modules/example.ko.xz")
            return Result(0, "dracut modules:\nfips\n")
        collector = Collector(runner=runner)
        with patch("nebulalog_manager.guest_validation.trusted_file", lambda path: path):
            value = collector.drivers()
        self.assertEqual(value["status"], "failed")
        self.assertTrue(value["fips_dracut_module_observed"])
        self.assertFalse(value["drivers"]["vmw_pvscsi"]["module_in_initramfs"])

    def test_driver_evidence_uses_running_kernel_and_actual_archive_members(self):
        names = ("vmw_pvscsi", "vmxnet3", "virtio_blk", "virtio_scsi", "virtio_net")
        def runner(argv, **kwargs):
            if argv[0] == "uname":
                return Result(0, "5.14.0-611.el9.x86_64")
            if argv[0] == "modinfo":
                self.assertIn("5.14.0-611.el9.x86_64", argv)
                return Result(0, "/lib/modules/" + argv[-1] + ".ko.xz")
            if "-m" in argv:
                return Result(0, "dracut modules:\nfips\n")
            return Result(0, "\n".join("-rw-r--r-- lib/modules/drivers/" + name + ".ko.xz" for name in names))
        with patch("nebulalog_manager.guest_validation.trusted_file", lambda path: path):
            self.assertEqual(Collector(runner=runner).drivers()["status"], "passed")

    def test_unconfigured_runtime_does_not_probe_or_authenticate(self):
        firstboot = Mock()
        collector = Collector(runner=Mock(), firstboot=firstboot)
        with patch.object(Path, "exists", return_value=False), patch.object(Path, "is_symlink", return_value=False):
            self.assertEqual(collector.runtime()["status"], "pending")
        firstboot.gate.assert_not_called()
        collector.runner.assert_not_called()

    def test_encrypted_gate_evidence_survives_unavailable_https(self):
        firstboot = Mock()
        firstboot.gate.return_value = {"host_ready": True, "setup_complete": False}
        collector = Collector(firstboot=firstboot)
        with patch.object(Path, "exists", return_value=True), patch.object(collector, "runtime_health", side_effect=OSError("PRIVATE_SECRET")):
            value = collector.runtime()
        self.assertEqual(value["encrypted_host_gate"], "passed")
        self.assertEqual(value["https_health"]["status"], "unavailable")
        self.assertNotIn("PRIVATE_SECRET", json.dumps(value))

    def test_declared_readonly_collection_never_infers_overall_acceptance(self):
        collector = Collector()
        with patch.object(collector, "guard", return_value={"os": "rocky", "major_version": 9, "virtualization": "qemu"}), patch.object(collector, "section", return_value={"status": "passed"}):
            value = collector.collect()
        self.assertEqual(value["qualification"], "pending")
        self.assertEqual(value["acceptance"]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
