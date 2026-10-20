"""Execute the actual Kickstart key decoder with synthetic public wire records."""
import base64
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
from urllib.parse import quote_plus


KICKSTART = Path(__file__).resolve().parents[1] / "packer/http/nebulalog.ks"
SCRIPT = KICKSTART.read_text().split("python3.14 - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]


def ssh_string(value):
    return struct.pack(">I", len(value)) + value


def mpint(value):
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return b"\x00" + encoded if encoded[0] & 0x80 else encoded


def public_key(bits=3072, exponent=65537, modulus=None, wire_type=b"ssh-rsa", suffix=b""):
    # These are structural parser fixtures, not generated credentials or primes.
    modulus = (1 << (bits - 1)) + 1 if modulus is None else modulus
    wire = b"".join(ssh_string(value) for value in (wire_type, mpint(exponent), mpint(modulus))) + suffix
    return "ssh-rsa " + base64.b64encode(wire).decode("ascii")


class KickstartKeyTests(unittest.TestCase):
    def execute(self, cmdline):
        writes = {}

        class FixturePath:
            def __init__(self, value):
                self.value = value

            def read_text(self):
                if self.value != "/proc/cmdline":
                    raise AssertionError("Unexpected source path")
                return cmdline

            def write_text(self, value, *, encoding):
                if self.value != "/home/packer/.ssh/authorized_keys" or encoding != "ascii":
                    raise AssertionError("Unexpected output path or encoding")
                writes[self.value] = value

        with patch("pathlib.Path", FixturePath):
            exec(compile(SCRIPT, str(KICKSTART), "exec"), {})
        return writes

    def accepted(self, key):
        written = self.execute("fips=1 PACKER_AUTHORIZED_KEY=" + quote_plus(key))
        return written["/home/packer/.ssh/authorized_keys"]

    def refused(self, cmdline):
        with self.assertRaisesRegex(SystemExit, "one valid per-build RSA public key"):
            self.execute(cmdline)

    def test_exact_packer_terminal_lf_roundtrip(self):
        key = public_key()
        self.assertEqual(self.accepted(key + "\n"), key + "\n")

    def test_no_lf_and_larger_rsa_roundtrip(self):
        for bits in (3072, 4096, 8192):
            with self.subTest(bits=bits):
                key = public_key(bits)
                self.assertEqual(self.accepted(key), key + "\n")

    def test_multiple_lines_and_control_characters_refused(self):
        key = public_key()
        for value in (key + "\n\n", key + "\r\n", key + "\n" + key,
                      key.replace(" ", "\t"), key + "\x00", key + "\x1b", key + "é"):
            with self.subTest(shape=len(value)):
                self.refused("PACKER_AUTHORIZED_KEY=" + quote_plus(value))

    def test_missing_duplicate_and_oversize_transport_refused(self):
        item = "PACKER_AUTHORIZED_KEY=" + quote_plus(public_key())
        for value in ("fips=1", item + " " + item, "PACKER_AUTHORIZED_KEY=" + "A" * 16385):
            with self.subTest(shape=len(value)):
                self.refused(value)

    def test_options_comments_and_extra_spaces_refused(self):
        key = public_key()
        for value in ("restrict " + key, key + " comment", " " + key, key.replace(" ", "  ")):
            self.refused("PACKER_AUTHORIZED_KEY=" + quote_plus(value))

    def test_short_oversize_even_modulus_and_invalid_exponent_refused(self):
        for value in (public_key(2048), public_key(8193), public_key(exponent=2),
                      public_key(exponent=2**24 + 1), public_key(modulus=1 << 3071)):
            self.refused("PACKER_AUTHORIZED_KEY=" + quote_plus(value))

    def test_wire_type_truncation_extra_fields_and_invalid_base64_refused(self):
        for value in (public_key(wire_type=b"ssh-ed25519"), public_key(suffix=ssh_string(b"extra")),
                      "ssh-rsa AAAA", "ssh-rsa AAA!", "ssh-ed25519 AAAA"):
            self.refused("PACKER_AUTHORIZED_KEY=" + quote_plus(value))

    def test_negative_noncanonical_and_zero_wire_integers_refused(self):
        for modulus in (b"\x80" + b"\xff" * 383, b"\x00\x00\x80" + b"\xff" * 383, b"\x00"):
            wire = ssh_string(b"ssh-rsa") + ssh_string(mpint(65537)) + ssh_string(modulus)
            key = "ssh-rsa " + base64.b64encode(wire).decode("ascii")
            self.refused("PACKER_AUTHORIZED_KEY=" + quote_plus(key))


if __name__ == "__main__":
    unittest.main()
