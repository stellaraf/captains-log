# ClickHouse candidate validation record

This is development build evidence, not guest acceptance or certification.

## Final local artifact

| Identity | Value |
|---|---|
| Local tag | `nebulalog/clickhouse-fips:25.3.8.30001-1` |
| OCI index | `sha256:efc85eb91e2db494af306f8683672ea2b5be8996ff1e0cfde2c31656f00ab428` |
| Linux amd64 manifest | `sha256:112d46c5a4686a8ad649106dd16000fe1d186013d591e5f9c0755c5c352a0e0b` |
| Image configuration | `sha256:1a27004a7cbfc571837c6ec282bb3e95fb9501e48f20d72a6e48c8c94f78edf4` |
| Vendor base | `altinity/clickhouse-server@sha256:6254bc404966150468130d2b5b02ebdf7238f21d2d85fbde77bc76c7181447df` |

The build ran with `--platform linux/amd64 --network=none` using already pulled vendor layers. No package installation, source compilation, database initialization, certificate creation or per-install credential generation occurred. No image was pushed or exported, and no running development container was changed.

## Completed checks

- **13 development image checks passed:** Linux amd64 identity, fixed UID and entrypoint, exact parity of seven embedded source/configuration files, server/health refusal on an actual non-FIPS Docker host, unsupported-command refusal, and no persistent-data writes for each refused invocation.
- **23 storage fixture tests passed:** accepted LVM-over-LUKS2, direct LUKS2 and fully encrypted branching; rejected mixed plaintext branches, unsupported mapper types, missing metadata, inconsistent links, cycles, traversal limits and invalid/missing XFS mount records.
- **33 data-state fixture checks passed in the final image:** empty claim, owned partial retry with fixture-file preservation, readiness/idempotent restart, mismatched credential, foreign/version/malformed/link/permission refusal, failed directory inspection, failed synchronization and concurrent directory-lock refusal. No database engine ran; these fixtures do not establish actual ClickHouse crash recovery or guest filesystem durability.
- Shell syntax, XML parsing, and scoped whitespace checks passed.
- The exact vendor binary extracted the fixed part-log TTL and parsed its MergeTree CREATE definition successfully in an isolated development container. This proves configuration syntax, not live table creation, retained observations or TTL deletion. An initial diagnostic invocation omitted the private `/tmp` mount and failed in the Mac's translation layer before execution; only the corrected exit-zero invocations count as parser evidence.
- Exact vendor image inspection observed `FIPS_CLICKHOUSE=1`, `OPENSSL_VERSION=AWS-LC-FIPS-2.0.0`, expected source/version identity and binary SHA256. A public-input SHA256 query through standard input returned the expected `SHA256("abc")` result.

The development verifier sets `HOME` to the runtime tmpfs. Docker Desktop's amd64 translation layer otherwise creates a `.cache` directory in the vendor's original data-directory home before the wrapper runs. The final candidate prevents that development artifact from touching the database mount; no synthetic FIPS flag or bypass was introduced.

Evidence generated in this workspace:

- `.local/clickhouse-boundary/candidate-build.log`
- `.local/clickhouse-boundary/candidate-verification.json`
- `.local/clickhouse-boundary/data-state-verification.json`
- `.local/clickhouse-boundary/part-log-syntax.txt`
- `.local/clickhouse-boundary/reproducible-altinity-inspection/inspection.json`
- `.local/clickhouse-boundary/public-hash-probe.txt`

These local files are not release evidence for any deployed guest. [BOM.json](BOM.json) records the module/version/certificate boundary, source references, composite licensing and SBOM/provenance gaps.

## Required guest and release checks

1. Boot the actual Rocky FIPS guest, verify SELinux and host LUKS headers, and demonstrate the container's bounded sysfs traversal sees its real XFS/LVM/LUKS2 topology without privileged mode or broader metadata exposure.
2. Confirm the loopback-only TLS preflight passes full KAT/integrity and authenticated readiness, then exits zero on SIGTERM. An earlier development no-listener probe logged successful self-tests but exited with `NO_ELEMENTS_IN_CONFIG` code139; that nonzero result is **not** accepted by the implemented gate.
3. Confirm the real server exposes HTTPS 8443/native TLS 9440 only. Test CA/IP/hostname rejection, TLS protocol/cipher rejection, wrong-password rejection and absence of plaintext protocol listeners.
4. Confirm only the configured SHA256 account exists and account-management attempts fail; test secret handling, real first-start interruption before the readiness marker, owned recovery, recognized restart, foreign-data refusal, signal handling and process readiness. Record host power-loss/forced-stop durability behavior separately from the shell fixtures.
5. On fresh encrypted data, run NebulaLog migrations and API/ingest/search/retention/backup/restore tests. Verify actual successful `NewPart` observations for `nebulalog.events`, part-log settings and eventual TTL deletion, absence of query-log tables, and sizing's honest unavailable state before sufficient history. Do not mount existing development 25.8 data into this 25.3 candidate.
6. Resolve full linked-dependency SBOM, artifact/source build provenance, security maintenance, approved-service use, entropy and exact Rocky/hypervisor/module operating-environment mapping. The vendor module certificate does not certify this image or the appliance.

The candidate remains unqualified until those checks and the broader release acceptance matrix are complete.
