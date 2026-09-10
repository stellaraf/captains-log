# Local candidate verification

Recorded 2026-09-08T05:16:45.499314+00:00. This is isolated Docker Desktop build evidence, not positive FIPS guest qualification.

| Check | Observed result |
| --- | --- |
| Local tag | `nebulalog/postgresql-fips:17.11-1` |
| OCI index / local image ID | `sha256:ff3fa2f8f14224731a920d117d1eb7a948a587f2bd5eb5167aaf4cbf45ef20d7` |
| linux/amd64 manifest | `sha256:64301a7ece568d3454a677e619315383c44c26f40522102653a0915cffce24b5` |
| PostgreSQL/server/client tools | 17.11 |
| Runtime UID/GID | 999:999 |
| OpenSSL libraries/provider RPMs | 3.5.5-6.el9_8, matched |
| System crypto policy | FIPS configured |
| PostgreSQL and libpq linkage | Native `/lib64/libcrypto.so.3` and `/lib64/libssl.so.3` |
| Additional/upgraded RPM inputs | All 20 signatures and pinned download hashes verified |
| Image data directory | Empty; no build-time `initdb` |
| Socket directory | UID/GID 999, mode 0700 |
| Container machine identity | Cleared before publication |
| Actual host kernel | FIPS state unavailable on LinuxKit |
| Default startup on that host | Refused with exit 78 before any data/socket writes |
| Initializer fixture tests | 7 passed; no real `initdb` executed |

The tag is local and has not been published to a registry. All immutable source inputs are in `BOM.json`. Detailed local receipts are `.local/postgresql-fips/verification.json`, `build.log`, `rpm-signatures.txt`, and `inspection.txt`; the verifier's final receipt is authoritative for this digest. Earlier inspection text may predate final changes. Temporary verification containers were removed. Existing application/development database services were not changed.

The verification script used readonly diagnostics, disabled networking, no capabilities and no privilege escalation. Its dedicated refusal check used a disposable writable container solely to prove the gate returned 78 without writing database/socket paths. No fake host flag, alternate provider, real database initialization or bypass was used.

Required before acceptance: the actual Rocky FIPS guest must pass native provider/default-selection checks, initdb, SCRAM success/failure, role boundaries, restart/backup/restore, migrations and readonly/SELinux mount behavior. Verify the correct secret uid/gid/mode and explicit private socket mount. Internal TLS, a complete SBOM/vulnerability review and exact validated module/operating-environment mapping remain separate open gates. See [README.md](README.md) and [FIPS boundaries](../../../docs/FIPS.md).
