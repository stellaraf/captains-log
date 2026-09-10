#!/usr/bin/env python3
"""Readonly candidate checks and real non-FIPS refusal; never initialize a DB."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=180)


def checked(argv):
    value = run(argv)
    value.check_returncode()
    return value.stdout.strip()


def main():
    if not __debug__:
        raise RuntimeError("Verification requires Python assertions; disable optimization")
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    info = json.loads(checked(["docker", "image", "inspect", args.image]))[0]
    assert info["Architecture"] == "amd64"
    assert info["Config"]["User"] == "999:999"
    prefix = ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    version = checked(prefix + [args.image, "--version"])
    assert version == "postgres (PostgreSQL) 17.11"
    script = r'''import json, pathlib, subprocess
def command(*args): return subprocess.check_output(args, text=True).strip()
print(json.dumps({
"tools": {name: command(name, "--version") for name in ("psql", "pg_dump", "pg_restore", "initdb", "pg_isready")},
"packages": command("rpm", "-q", "postgresql17", "postgresql17-libs", "postgresql17-server", "openssl", "openssl-libs", "openssl-fips-provider"),
"openssl": command("openssl", "version"),
"system_policy": pathlib.Path("/etc/crypto-policies/config").read_text().strip(),
"host_kernel_fips": pathlib.Path("/proc/sys/crypto/fips_enabled").read_text().strip() if pathlib.Path("/proc/sys/crypto/fips_enabled").is_file() else "unavailable",
"postgres_libraries": command("ldd", "/usr/pgsql-17/bin/postgres"),
"libpq_libraries": command("ldd", "/usr/pgsql-17/lib/libpq.so.5"),
"signatures": pathlib.Path("/opt/nebulalog/rpm-signatures.txt").read_text().splitlines(),
"data_empty": not any(pathlib.Path("/var/lib/postgresql/data").iterdir()),
"machine_id_empty": pathlib.Path("/etc/machine-id").stat().st_size == 0,
"socket_mode": oct(pathlib.Path("/run/postgresql").stat().st_mode & 0o777),
"crypto_files": command("sha256sum", "/usr/lib64/libcrypto.so.3", "/usr/lib64/libssl.so.3", "/usr/lib64/ossl-modules/fips.so"),
"rpm_bom": pathlib.Path("/opt/nebulalog/rpm-bom.tsv").read_text()
}, sort_keys=True))'''
    observed = json.loads(checked(prefix + ["--entrypoint", "/usr/bin/python3", args.image, "-c", script]))
    assert all("17.11" in value for value in observed["tools"].values())
    assert observed["system_policy"] == "FIPS" and observed["data_empty"] and observed["machine_id_empty"]
    assert observed["socket_mode"] == "0o700"
    assert len(observed["signatures"]) == 20 and all(line.endswith("digests signatures OK") for line in observed["signatures"])
    for key in ("postgres_libraries", "libpq_libraries"):
        assert "not found" not in observed[key]
        for library in ("libcrypto.so.3", "libssl.so.3"):
            assert library + " => /lib64/" + library in observed[key]
    refusal = "not_run_on_fips_host"
    if observed["host_kernel_fips"] != "1":
        created = checked(["docker", "create", "--platform", "linux/amd64", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", args.image])
        try:
            started = run(["docker", "start", "--attach", created])
            state = json.loads(checked(["docker", "container", "inspect", created]))[0]
            assert state["State"]["ExitCode"] == 78
            assert "actual FIPS-enabled host kernel is required" in started.stderr
            changes = checked(["docker", "diff", created])
            assert not any(path in changes for path in ("/var/lib/postgresql", "/run/postgresql")), changes
            refusal = "passed_before_data_or_socket_writes"
        finally:
            checked(["docker", "rm", created])
    receipt = {"checked_at": datetime.now(timezone.utc).isoformat(), "image_id": info["Id"], "repo_digests": info.get("RepoDigests", []),
               "platform": "linux/amd64", "user": info["Config"]["User"], "version": version, "observed": observed,
               "non_fips_refusal": refusal, "guest_initialization": "not_tested", "scram_authentication": "not_tested",
               "fips_provider_positive_test": "not_tested", "qualification": "not_established"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: value for key, value in receipt.items() if key != "observed"}, indent=2))


if __name__ == "__main__":
    main()
