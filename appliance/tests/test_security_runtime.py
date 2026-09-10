"""Measured kernel failures must reach the common host/lifecycle health gate."""
from pathlib import Path
import unittest
from unittest.mock import patch

from nebulalog_manager import security, guest_validation
from nebulalog_manager.common import Refused
from nebulalog_manager.firstboot import FirstBoot


class RuntimeSecurityTests(unittest.TestCase):
    def observe(self, journal, *, unavailable=False):
        calls = []

        def runner(argv):
            calls.append(argv)
            if argv[0] == "journalctl":
                if unavailable:
                    raise Refused("fixture inaccessible journal")
                return journal
            if argv[0] == "update-crypto-policies":
                return "FIPS"
            if argv[0] == "getenforce":
                return "Enforcing"
            return "active"

        with patch.object(Path, "read_text", return_value="1\n"):
            value = security.status(runner)
        self.assertIn(["journalctl", "-k", "--boot=0", "--no-pager", "--output=cat", "--lines=10000"], calls)
        return value

    def test_native_hkdf_failure_overrides_enabled_fips_mode(self):
        value = self.observe("Linux version fixture\nbasic hdkf test(hmac(sha256-ni)): hkdf_extract failed with -22\n")
        self.assertTrue(value["fips_kernel"])
        self.assertTrue(value["fips_tool"]["ok"])
        self.assertFalse(value["host_controls_ok"])
        self.assertEqual(value["kernel_crypto_diagnostics"]["diagnostic_counts"], {"hkdf_self_test_failure": 1})
        self.assertNotIn("sha256-ni", str(value))

    def test_success_means_only_no_failure_observed(self):
        value = self.observe("Linux version fixture\nFIPS mode initialized\n")
        self.assertTrue(value["host_controls_ok"])
        self.assertEqual(value["kernel_crypto_diagnostics"]["status"], "no_failure_observed")
        self.assertEqual(value["certification"], "not asserted")
        self.assertEqual(value["kernel_crypto_diagnostics"]["all_algorithms_tested"], "not established")

    def test_missing_rotated_or_unreadable_boot_evidence_is_not_healthy(self):
        for text, unavailable in (("", False), ("FIPS mode initialized\n", False), ("", True)):
            with self.subTest(text=text, unavailable=unavailable):
                value = self.observe(text, unavailable=unavailable)
                self.assertFalse(value["host_controls_ok"])
                self.assertEqual(value["kernel_crypto_diagnostics"]["status"], "unavailable")

    def test_kernel_test_failure_without_boot_header_still_fails(self):
        value = self.observe("alg: self-test failed for fixture\n")
        self.assertFalse(value["host_controls_ok"])
        self.assertEqual(value["kernel_crypto_diagnostics"]["status"], "failed")

    def test_guest_qualification_and_runtime_use_identical_classifier(self):
        self.assertIs(guest_validation.kernel_crypto_diagnostics, security.kernel_crypto_diagnostics)

    def test_firstboot_reports_crypto_refusal_without_mislabeling_enabled_controls(self):
        for diagnostic, message in (("failed", "cryptographic self-test failure"), ("unavailable", "diagnostics are unavailable")):
            with self.subTest(diagnostic=diagnostic):
                calls = []
                firstboot = FirstBoot(runner=lambda argv: calls.append(argv), security=lambda _: {
                    "host_controls_ok": False, "kernel_crypto_diagnostics": {"status": diagnostic, "raw": "PRIVATE-DIAGNOSTIC"}})
                with patch("nebulalog_manager.firstboot.require_linux_root"), patch("nebulalog_manager.firstboot.trusted_file"), \
                        patch.object(Path, "read_text", return_value='ID="rocky"\nVERSION_ID="9.8"\n'), \
                        self.assertRaisesRegex(Refused, message) as observed:
                    firstboot._host()
                self.assertNotIn("PRIVATE-DIAGNOSTIC", str(observed.exception))
                self.assertEqual(calls, [["systemd-detect-virt", "--vm"]])


if __name__ == "__main__":
    unittest.main()
