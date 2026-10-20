# PostgreSQL FIPS container candidate

This recipe builds PostgreSQL **17.11-1PGDG.rhel9.8** for **linux/amd64** using the pinned RESF Rocky Linux 9.8 image and its system OpenSSL **3.5.5-6.el9_8** libraries/provider. It is an appliance qualification candidate. Neither PostgreSQL nor this composite container is represented as FIPS certified.

PostgreSQL 17.11 is the August 13, 2026 maintenance/security release. Its native PGDG packages link to system `libssl.so.3`/`libcrypto.so.3`; the recipe uses the RHEL 9.8 package build with Rocky 9.8, preserving the required OpenSSL ABI. PostgreSQL major-version migrations are separate release operations. [Release announcement](https://www.postgresql.org/about/news/postgresql-186-1711-1615-1519-1424-and-19-beta-3-released-3365/), [PGDG 17 package repository](https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-9.8-x86_64/), [versioning policy](https://www.postgresql.org/support/versioning/).

## Immutable inputs and licenses

`BOM.json` pins the amd64 RESF base manifest, every additional/upgraded RPM URL and SHA-256, the PGDG signing-key bytes/fingerprints and the Rocky key inherited from the pinned base. The image downloads the exact inputs, checks each checksum, verifies all RPM signatures with the two keys and installs with repositories disabled and local-package signature checks enabled. Dependency resolution happened before those pins were generated; the released recipe cannot resolve a newer package silently. Mirror removal causes a failed build instead of an unreviewed substitute.

The initializer runs explicitly under public Rocky Python **3.14.8-1.el9_8**, installed alongside the OS interpreter. Its Python libraries, pip wheel, mpdecimal and SQLite dependency are checksum-pinned and signature-verified with the other inputs. The image contains 25 additional/upgraded RPM inputs.

The input list includes the three PostgreSQL packages, the matched OpenSSL library/provider triplet, ICU, locale/glibc and required package dependencies. DNF weak dependencies are disabled. The base manifest fixes other inherited packages; pinning does not mean their vulnerability review is complete. `/opt/nebulalog/rpm-bom.tsv` retains every installed RPM's version, architecture and declared license, and `/opt/nebulalog/rpm-signatures.txt` retains signature-verification results.

PGDG's current RHEL key fingerprint is `D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20`, with signing subkey `190043FB30BA8636FCB021BEC07038AF3576435C`. [Official key](https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-RHEL), [key-selection README](https://download.postgresql.org/pub/repos/yum/keys/README.txt).

PostgreSQL uses the PostgreSQL License. Distribution RPM licenses and license files remain in the image. The small NebulaLog initializer is original repository code under AGPL-3.0-only, with the project license at `/opt/nebulalog/LICENSE-NEBULALOG`; no Docker Library entrypoint was copied. These component licenses remain separate. [PostgreSQL license](https://www.postgresql.org/about/licence/).

## Build and verification

From the repository root:

```sh
docker build --platform linux/amd64 \
  -f appliance/images/postgresql-fips/Containerfile \
  -t nebulalog/postgresql-fips:17.11-2 .
python3 appliance/images/postgresql-fips/verify_image.py \
  --image nebulalog/postgresql-fips:17.11-2 \
  --output .local/postgresql-fips/verification.json
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s appliance/images/postgresql-fips -p test_entrypoint.py -v
```

The build does not run `initdb`, create database roles/passwords, or start PostgreSQL. It configures the distribution's FIPS crypto policy without running `fips-mode-setup` inside the container. Package-generated container machine identity/random-seed files are cleared before publication. No appliance credentials are included.

The verifier uses isolated disposable containers without networking or capabilities. It checks versions, UID, signature receipts, system-library linkage, empty data, private socket and the real default refusal on the non-FIPS development host. A separate disposable start verifies no database/socket paths were written before that refusal. It never supplies a fake FIPS flag or bypasses the gate to initialize a database. The small unit suite checks control flow using fixtures; it does not perform a simulated “FIPS database” run.

## Guest runtime contract

- Image user **999:999**. Use a readonly root, no added capabilities and no privilege escalation. Keep `PATH` including `/usr/pgsql-17/bin` so bootstrap/lifecycle `psql`, `pg_dump`, `pg_restore` and `pg_isready` work directly.
- Mount enrolled encrypted storage at **`/var/lib/postgresql/data`**, UID/GID 999 and mode=0700. It must initially be empty. `PGDATA` is fixed to this path.
- Mount private tmpfs **`/run/postgresql`** (or `/var/run/postgresql`, which resolves to it), **uid=999,gid=999,mode=0700**. An explicit mode avoids runtime-dependent tmpfs permissions. The private socket uses local trust for the appliance's host-controlled UID 999 maintenance clients; never share that socket with another container or user.
- Mount the first-boot secret at **`/run/secrets/nebulalog-pg-password`**, **uid=999,gid=999,mode=0400**. Set `POSTGRES_PASSWORD_FILE` to that path. The file contains 14–1024 bytes, no line terminator, and is read only after the FIPS gate. The initializer never puts the password in argv or logs.
- Supported environment is `POSTGRES_USER=postgres`, `POSTGRES_DB=postgres`, and `POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust`. Those defaults are accepted; other users/databases, inline password, arbitrary initialization arguments, WAL relocation and host-auth overrides are rejected. Bootstrap creates the application/Keycloak roles and databases separately using guarded SQL.
- Command is **`postgres`**. Only `--version`, `postgres --version`, and `check-fips` diagnostics are also supported by the entrypoint. No arbitrary initialization scripts or imported development database are run.

Initialization uses UTF8, `en_US.UTF-8`, data checksums and SCRAM-SHA-256. A durable `.nebulalog-initialized.json` receipt is written only after `initdb` succeeds. A nonempty directory without that receipt is a recovery condition; it is not wiped, reinitialized or silently adopted. A different PostgreSQL major version is also refused. An existing database created by another image needs an explicitly qualified migration/import procedure, not a hand-written receipt.

The image supplies its fixed server/HBA configuration, disables `ALTER SYSTEM`, pins socket/HBA/password settings on the server command line, and refuses active settings in writable `postgresql.auto.conf`. PostgreSQL normally loads that file after its main configuration, so a retained override cannot silently change this appliance contract. Tuning/configuration changes require a reviewed image/configuration release. [PostgreSQL configuration precedence](https://www.postgresql.org/docs/17/config-setting.html).

The server binds port 5432 on the private appliance container network; do not publish that port externally. Its TCP authentication uses SCRAM-SHA-256. **This candidate retains the current appliance's unencrypted internal transport (`ssl=off`)**; SCRAM protects password authentication but does not encrypt queries/results. It does not establish an encrypted database-transport claim. If the release boundary requires TLS internally, provision a guest-generated server certificate and validate PostgreSQL, libpq and JDBC TLS together before acceptance. [PostgreSQL encryption options](https://www.postgresql.org/docs/17/encryption-options.html), [password authentication](https://www.postgresql.org/docs/17/auth-password.html).

## FIPS gate and remaining qualification

Before reading the secret or invoking `initdb`, the entrypoint requires the actual host `/proc/sys/crypto/fips_enabled=1`, system crypto-policy `FIPS`, the native default OpenSSL configuration, `EVP_default_properties_is_fips_enabled=1`, an active `fips` provider and default SHA256 selection from that provider. Arbitrary crypto configuration/module/library overrides are refused. This uses the native system library; it neither copies a provider from another distribution nor forces an approved-mode flag on a non-FIPS kernel. [RHEL container guidance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/switching-rhel-to-fips-mode_security-hardening), [OpenSSL FIPS provider guidance](https://docs.openssl.org/3.5/man7/fips_module/).

CMVP certificate 5116 identifies an exact older Rocky module/package, `openssl-fips-provider-so-3.0.7-27.el9_2.ciqfips.0.2.7.x86_64`, with provider version `Rocky 9.20250210`. That certificate does not establish coverage for this public Rocky 3.5.5 provider, this image or this operating environment. The observed provider label/build string is evidence to retain, not a certification determination. [Certificate 5116](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5116), [security policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5116.pdf).

Before acceptance, boot the exact image on the real FIPS Rocky guest and prove provider activation/self-tests, successful initialization, SCRAM login and wrong-password rejection, non-superuser role boundaries, restart durability, backup/restore and update behavior. Verify libpq and PostgreSQL actually use the expected cryptographic provider for exercised operations. Qualify the complete crypto-module/OE boundary, evaluate transitive libraries/features, review the final SBOM/CVEs, and test readonly/SELinux/secret/socket mounts. A build, link inspection or non-FIPS refusal is not that positive runtime evidence.
