"""Validate publisher-supplied public build inputs; never generate or fetch trust."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import tempfile

from .common import Refused, run
from .image_bundle import strict_json

PUBLIC_SOURCE = "appliance/security/publisher-public.spki"
DESCRIPTOR_SOURCE = "appliance/security/publisher-trust.json"
REPOSITORY = "stellaraf/captains-log"
SHA256 = re.compile(r"[a-f0-9]{64}")
KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
PRIVATE_BINDING = {"mode": "private-unsealed"}
FACTORY_FIELDS = {"mode", "descriptor_sha256", "public_spki_pem_sha256", "spki_sha256", "repository", "key_id"}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _tlv(raw, offset=0):
    if offset + 2 > len(raw):
        raise Refused("Malformed public SPKI DER")
    tag, length = raw[offset:offset + 2]
    start = offset + 2
    if length & 128:
        size = length & 127
        if not 1 <= size <= 4 or start + size > len(raw) or raw[start] == 0:
            raise Refused("Malformed public SPKI DER length")
        length = int.from_bytes(raw[start:start + size], "big")
        start += size
        if length < 128:
            raise Refused("Noncanonical public SPKI DER length")
    end = start + length
    if end > len(raw):
        raise Refused("Truncated public SPKI DER")
    return tag, start, end


def public_key(raw, fingerprint, *, runner=run, temporary_root=None):
    """Return canonical RSA public bytes validated for the fixed PSS/SHA256 verifier."""
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= 16384
            or not re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*", raw)):
        raise Refused("Only one public SPKI PEM is accepted; private keys and certificates are refused")
    if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
        raise Refused("Publisher SPKI SHA256 must be explicit lowercase hexadecimal")
    with tempfile.TemporaryDirectory(prefix="publisher-public-", dir=temporary_root) as directory:
        stage = Path(directory)
        source, pem, der = (stage / name for name in ("input.spki", "public.spki", "public.der"))
        source.write_bytes(raw)
        source.chmod(0o600)
        runner(["openssl", "pkey", "-pubin", "-in", str(source), "-pubcheck", "-noout"], timeout=30)
        details = runner(["openssl", "rsa", "-pubin", "-in", str(source), "-text", "-noout"], timeout=30)
        match = re.search(r"(?m)^Public-Key: \(([0-9]+) bit\)", details)
        if not match or not 3072 <= int(match[1]) <= 8192:
            raise Refused("Publisher trust requires an RSA public key from 3072 to 8192 bits")
        runner(["openssl", "pkey", "-pubin", "-in", str(source), "-pubout", "-out", str(pem)], timeout=30)
        runner(["openssl", "pkey", "-pubin", "-in", str(source), "-pubout", "-outform", "DER", "-out", str(der)], timeout=30)
        encoded, canonical = der.read_bytes(), pem.read_bytes()
    tag, start, end = _tlv(encoded)
    algorithm, _, algorithm_end = _tlv(encoded, start)
    # Generic rsaEncryption SPKI supports the appliance's RSA-PSS SHA256/MGF1
    # SHA256/salt32 signature contract. Restricted RSA-PSS keys are not silently
    # accepted with incompatible digest/salt constraints.
    if (tag != 0x30 or end != len(encoded) or algorithm != 0x30
            or encoded[start:algorithm_end] != bytes.fromhex("300d06092a864886f70d0101010500")):
        raise Refused("Publisher SPKI must be unrestricted RSA for RSA-PSS-SHA256 verification")
    if digest(encoded) != fingerprint:
        raise Refused("Public key does not match the authenticated SPKI fingerprint")
    return {"public": canonical, "rsa_bits": int(match[1]), "spki_sha256": fingerprint}


def descriptor(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 16384:
        raise Refused("Factory publisher descriptor must be bounded")
    value = strict_json(raw)
    fields = {"schema", "publisher", "repository", "key_id", "algorithm", "spki_sha256"}
    if (not isinstance(value, dict) or set(value) != fields or type(value.get("schema")) is not int or value["schema"] != 1
            or not isinstance(value.get("publisher"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .,'&()-]{0,127}", value["publisher"])
            or value.get("repository") != REPOSITORY or value.get("algorithm") != "RSA-PSS-SHA256"
            or not isinstance(value.get("key_id"), str) or not KEY_ID.fullmatch(value["key_id"])
            or not isinstance(value.get("spki_sha256"), str) or not SHA256.fullmatch(value["spki_sha256"])):
        raise Refused("Factory publisher descriptor has unsupported identity, algorithm or fields")
    return value


def binding(value, files):
    """Check public input hashes against the independently frozen source inventory."""
    if value == PRIVATE_BINDING:
        if PUBLIC_SOURCE in files or DESCRIPTOR_SOURCE in files:
            raise Refused("Private unsealed mode cannot ignore supplied publisher inputs")
        return value
    if (not isinstance(value, dict) or set(value) != FACTORY_FIELDS or value.get("mode") != "factory"
            or value.get("repository") != REPOSITORY or not isinstance(value.get("key_id"), str) or not KEY_ID.fullmatch(value["key_id"])
            or any(not isinstance(value.get(key), str) or not SHA256.fullmatch(value[key])
                   for key in ("descriptor_sha256", "public_spki_pem_sha256", "spki_sha256"))
            or files.get(PUBLIC_SOURCE) != value["public_spki_pem_sha256"] or files.get(DESCRIPTOR_SOURCE) != value["descriptor_sha256"]):
        raise Refused("Factory publisher provenance does not match captured public trust inputs")
    return value


def validate(value, files, descriptor_raw=None, key_raw=None, *, runner=run, temporary_root=None, require_factory=False):
    binding(value, files)
    if value == PRIVATE_BINDING:
        if require_factory:
            raise Refused("Distributable appliances require factory publisher trust; private unsealed candidates cannot be sealed")
        if descriptor_raw is not None or key_raw is not None:
            raise Refused("Private unsealed build contains unexpected publisher inputs")
        return {"mode": "private-unsealed", "update_ready": False, "distribution_trust_ready": False}
    description = descriptor(descriptor_raw)
    if (digest(descriptor_raw) != value["descriptor_sha256"] or not isinstance(key_raw, bytes)
            or digest(key_raw) != value["public_spki_pem_sha256"]
            or any(description[key] != value[key] for key in ("spki_sha256", "repository", "key_id"))):
        raise Refused("Packaged publisher inputs differ from factory source provenance")
    key = public_key(key_raw, value["spki_sha256"], runner=runner, temporary_root=temporary_root)
    return {"mode": "factory", "descriptor": description, "rsa_bits": key["rsa_bits"],
            "spki_sha256": key["spki_sha256"], "public": key["public"], "update_ready": False,
            "distribution_trust_ready": True}
