"""Inspect the actual host and native OpenSSL defaults before database access."""
import ctypes
import json
import os
from pathlib import Path


def require_fips():
    try:
        enabled = Path("/proc/sys/crypto/fips_enabled").read_text().strip()
    except OSError:
        raise RuntimeError("an actual FIPS-enabled host kernel is required") from None
    if enabled != "1":
        raise RuntimeError("an actual FIPS-enabled host kernel is required")
    if Path("/etc/crypto-policies/config").read_text().strip() != "FIPS":
        raise RuntimeError("the inherited system crypto policy must be FIPS")
    for name, expected in (("OPENSSL_CONF", "/etc/pki/tls/openssl.cnf"), ("OPENSSL_MODULES", None),
                           ("OPENSSL_CONF_INCLUDE", None), ("OPENSSL_ENGINES", None),
                           ("OPENSSL_FORCE_FIPS_MODE", None), ("LD_PRELOAD", None), ("LD_LIBRARY_PATH", None)):
        if os.environ.get(name) not in (None, expected):
            raise RuntimeError("custom cryptographic configuration or library overrides are refused")
    library = ctypes.CDLL("/usr/lib64/libcrypto.so.3")
    library.OPENSSL_init_crypto.argtypes = [ctypes.c_uint64, ctypes.c_void_p]
    library.OPENSSL_init_crypto.restype = ctypes.c_int
    library.EVP_default_properties_is_fips_enabled.argtypes = [ctypes.c_void_p]
    library.EVP_default_properties_is_fips_enabled.restype = ctypes.c_int
    library.OSSL_PROVIDER_available.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    library.OSSL_PROVIDER_available.restype = ctypes.c_int
    library.EVP_MD_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    library.EVP_MD_fetch.restype = ctypes.c_void_p
    library.EVP_MD_get0_provider.argtypes = [ctypes.c_void_p]
    library.EVP_MD_get0_provider.restype = ctypes.c_void_p
    library.OSSL_PROVIDER_get0_name.argtypes = [ctypes.c_void_p]
    library.OSSL_PROVIDER_get0_name.restype = ctypes.c_char_p
    library.EVP_MD_free.argtypes = [ctypes.c_void_p]
    if library.OPENSSL_init_crypto(0x40, None) != 1:
        raise RuntimeError("native OpenSSL configuration initialization failed")
    if library.EVP_default_properties_is_fips_enabled(None) != 1 or library.OSSL_PROVIDER_available(None, b"fips") != 1:
        raise RuntimeError("native OpenSSL approved defaults and active FIPS provider are required")
    algorithm = library.EVP_MD_fetch(None, b"SHA256", None)
    if not algorithm:
        raise RuntimeError("native OpenSSL could not select an approved SHA256 implementation")
    try:
        provider = library.OSSL_PROVIDER_get0_name(library.EVP_MD_get0_provider(algorithm))
        if provider != b"fips":
            raise RuntimeError("default SHA256 selection did not use the FIPS provider")
    finally:
        library.EVP_MD_free(algorithm)
    return {"host_kernel_fips": True, "system_policy": "FIPS", "openssl_default_fips": True,
            "sha256_provider": "fips", "certification": "not asserted"}


if __name__ == "__main__":
    try:
        print(json.dumps(require_fips(), sort_keys=True))
    except (OSError, RuntimeError) as exc:
        print("Captain’s Log PostgreSQL refused: " + (str(exc) if not isinstance(exc, OSError) else "actual host FIPS state or native provider is unavailable"), file=__import__("sys").stderr)
        raise SystemExit(78)
