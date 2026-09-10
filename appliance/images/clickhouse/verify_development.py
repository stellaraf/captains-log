#!/usr/bin/env python3
"""Check candidate identity and non-FIPS refusal; never initializes ClickHouse."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def invoke(argv):
    return subprocess.run(argv, capture_output=True, timeout=90)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", default="nebulalog/clickhouse-fips:25.3.8.30001-1")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    image = json.loads(subprocess.check_output(["docker", "image", "inspect", args.image]))[0]
    assert image["Architecture"] == "amd64" and image["Os"] == "linux"
    assert image["Config"]["User"] == "101:101"
    assert image["Config"]["Entrypoint"] == ["/opt/nebulalog/entrypoint.sh"]
    base = ["docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
        "--tmpfs", "/run/nebulalog-clickhouse:rw,nosuid,nodev,size=256m,mode=0700,uid=101,gid=101",
        "--tmpfs", "/var/log/clickhouse-server:rw,nosuid,nodev,size=16m"]
    kernel = invoke(base + ["--entrypoint", "/bin/sh", args.image, "-c", "cat /proc/sys/crypto/fips_enabled 2>/dev/null || true"])
    assert kernel.returncode == 0 and kernel.stdout.strip() != b"1", "This negative test requires a genuinely non-FIPS development host"
    source = Path(__file__).resolve().parent
    hashes = {}
    for name in ("entrypoint.sh", "storage-gate.sh", "data-state.sh", "server.xml", "users.xml.in", "client.xml.in", "BOM.json"):
        result = invoke(base + ["--entrypoint", "/bin/cat", args.image, "/opt/nebulalog/" + name])
        assert result.returncode == 0 and result.stdout == (source / name).read_bytes(), "Stale candidate file: " + name
        hashes[name] = hashlib.sha256(result.stdout).hexdigest()
    cases = []
    with tempfile.TemporaryDirectory(prefix="nebulalog-ch-negative-") as temporary:
        data = Path(temporary) / "data"
        data.mkdir()
        for command in ("server", "health", "unsupported-command"):
            result = invoke(base + ["-v", str(data) + ":/var/lib/clickhouse:rw", args.image, command])
            assert result.returncode == 78, (command, result.returncode, result.stderr.decode())
            assert not list(data.iterdir()), "Refusal data mount changed: " + repr(sorted(p.name for p in data.iterdir()))
            expected = b"actual FIPS-enabled host kernel" if command != "unsupported-command" else b"only server and health"
            assert expected in result.stderr, (command, result.stderr.decode())
            cases.append({"command": command, "exit_code": result.returncode, "data_unchanged": True})
    report = {"schema_revision": 1, "image_reference": args.image, "image_id": image["Id"],
        "repository_digests": image.get("RepoDigests", []), "source_file_sha256": hashes,
        "negative_checks": cases, "real_guest_runtime_verified": False, "fips_qualified": False,
        "limitations": "No secrets or TLS certificates generated; no positive FIPS startup, guest ingestion, or migration tested"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"checks_passed": len(cases) + len(hashes) + 3, "fips_qualified": False, "evidence": str(args.output)}))


if __name__ == "__main__":
    main()
