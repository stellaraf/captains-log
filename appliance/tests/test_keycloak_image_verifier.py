"""Verify actual generated crypto startup code, including tamper rejection."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "keycloak_image_verifier", ROOT / "images/keycloak-fips/verify_image.py"
)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class KeycloakCryptoRecorderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = json.loads(
            (ROOT / "tests/fixtures/keycloak-26.8.1-init-crypto.json").read_text()
        )
        cls.bytecode = base64.b64decode(fixture["class_base64"], validate=True)
        if hashlib.sha256(cls.bytecode).hexdigest() != fixture["sha256"]:
            raise AssertionError("Recorded image fixture checksum differs")

    def test_actual_strict_image_recorder(self):
        VERIFIER.verify_recorded_strict_mode(self.bytecode)

    def test_changed_mode_rejected(self):
        altered = self.bytecode.replace(b"STRICT", b"RELAXD")
        self.assertNotEqual(altered, self.bytecode)
        with self.assertRaises(AssertionError):
            VERIFIER.verify_recorded_strict_mode(altered)

    def test_changed_provider_method_rejected(self):
        altered = self.bytecode.replace(b"setCryptoProvider", b"getCryptoProvider")
        self.assertNotEqual(altered, self.bytecode)
        with self.assertRaises(AssertionError):
            VERIFIER.verify_recorded_strict_mode(altered)

    def test_changed_truststore_method_rejected(self):
        altered = self.bytecode.replace(b"configureTruststore", b"configureTruststorX")
        self.assertNotEqual(altered, self.bytecode)
        with self.assertRaises(AssertionError):
            VERIFIER.verify_recorded_strict_mode(altered)

    def test_correct_constants_with_changed_instructions_rejected(self):
        # This pinned class invokes setCryptoProvider through pool entry 43.
        # Leave STRICT and all method names intact, but change the invocation.
        original = b"\x2d\x19\x04\xb6\x00\x2b"
        self.assertEqual(self.bytecode.count(original), 1)
        altered = self.bytecode.replace(original, b"\x2d\x19\x04\xb8\x00\x2b")
        with self.assertRaises(AssertionError):
            VERIFIER.verify_recorded_strict_mode(altered)

    def test_truncated_class_rejected(self):
        with self.assertRaises(AssertionError):
            VERIFIER.verify_recorded_strict_mode(self.bytecode[:len(self.bytecode) // 2])


if __name__ == "__main__":
    unittest.main()
