#!/usr/bin/python3
"""Minimal appliance-only initialization; no arbitrary init scripts or SQL."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from crypto_gate import require_fips

DATA = Path("/var/lib/postgresql/data")
SOCKET = Path("/run/postgresql")
READY = DATA / ".nebulalog-initialized.json"


def refuse(message):
    raise RuntimeError(message)


def private_directory(path):
    value = path.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != 999 or value.st_gid != 999 or value.st_mode & 0o077:
        refuse("database data and Unix socket directories must be private UID/GID999 directories")


def initialize():
    if os.getuid() != 999 or os.getgid() != 999:
        refuse("fixed nonroot UID/GID999 is required")
    for name, default in (("PGDATA", str(DATA)), ("POSTGRES_USER", "postgres"), ("POSTGRES_DB", "postgres"),
                          ("POSTGRES_INITDB_ARGS", "--auth-host=scram-sha-256 --auth-local=trust")):
        if os.environ.get(name, default) != default:
            refuse("runtime database identity, storage path or authentication initialization differs from the appliance contract")
    if any(os.environ.get(name) for name in ("POSTGRES_PASSWORD", "POSTGRES_HOST_AUTH_METHOD", "POSTGRES_INITDB_WALDIR")):
        refuse("inline credentials and authentication/storage overrides are not accepted")
    private_directory(DATA)
    private_directory(SOCKET)
    if READY.exists():
        value = READY.lstat()
        if not stat.S_ISREG(value.st_mode) or value.st_uid != 999 or value.st_mode & 0o077 or json.loads(READY.read_text()) != {"schema": 1, "postgres_major": 17, "initialization": "complete"}:
            refuse("database initialization receipt is invalid")
        if (DATA / "PG_VERSION").read_text().strip() != "17":
            refuse("database major version requires a separately qualified migration")
        return
    if any(DATA.iterdir()):
        refuse("database directory is nonempty without a completed initialization receipt; recovery review is required")
    secret = Path(os.environ.get("POSTGRES_PASSWORD_FILE", "/run/secrets/nebulalog-pg-password"))
    if secret != Path("/run/secrets/nebulalog-pg-password"):
        refuse("use the enrolled PostgreSQL password secret mount")
    value = secret.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid not in (0, 999) or value.st_mode & 0o077 or not 14 <= value.st_size <= 1024:
        refuse("PostgreSQL secret must be a private readable file of 14 to 1024 bytes")
    password = secret.read_bytes()
    if b"\n" in password or b"\r" in password or b"\0" in password:
        refuse("PostgreSQL password secret must be a single value without line terminators")
    del password
    # The actual FIPS gate ran before reading credentials or invoking initdb.
    # The password travels via a file, never argv, stdout or an image layer.
    subprocess.run(["/usr/pgsql-17/bin/initdb", "--pgdata=" + str(DATA), "--username=postgres",
                    "--pwfile=" + str(secret), "--auth-host=scram-sha-256", "--auth-local=trust",
                    "--encoding=UTF8", "--locale=en_US.UTF-8", "--data-checksums"], check=True)
    temporary = DATA / ".nebulalog-initialized.pending"
    with temporary.open("x") as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump({"schema": 1, "postgres_major": 17, "initialization": "complete"}, output)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, READY)
    descriptor = os.open(DATA, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_no_persisted_overrides():
    path = DATA / "postgresql.auto.conf"
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid != 999 or value.st_mode & 0o077:
        refuse("PostgreSQL persisted override file has unsafe ownership or permissions")
    if any(line.strip() and not line.lstrip().startswith("#") for line in path.read_text().splitlines()):
        refuse("persisted ALTER SYSTEM overrides require a reviewed appliance configuration migration")


def main():
    os.umask(0o077)
    args = sys.argv[1:] or ["postgres"]
    if args in (["--version"], ["postgres", "--version"]):
        os.execv("/usr/pgsql-17/bin/postgres", ["postgres", "--version"])
    if args == ["check-fips"]:
        print(json.dumps(require_fips(), sort_keys=True))
        return
    if args != ["postgres"]:
        refuse("only the fixed PostgreSQL server command and diagnostics are supported")
    require_fips()
    initialize()
    verify_no_persisted_overrides()
    os.execv("/usr/pgsql-17/bin/postgres", ["postgres", "-D", str(DATA), "-c", "config_file=/etc/nebulalog/postgresql.conf",
              "-c", "allow_alter_system=off", "-c", "hba_file=/etc/nebulalog/pg_hba.conf",
              "-c", "unix_socket_directories=/run/postgresql", "-c", "unix_socket_permissions=0700",
              "-c", "password_encryption=scram-sha-256"])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        message = str(exc) if isinstance(exc, RuntimeError) else "host FIPS, secret, initialization, or runtime precondition failed"
        print("Captain’s Log PostgreSQL refused: " + message, file=sys.stderr)
        raise SystemExit(78)
