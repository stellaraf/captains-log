#!/usr/bin/env python3
"""Inspect pinned ClickHouse artifacts without starting a server or using credentials.

Exit zero means the inspection completed, never that FIPS qualification passed.
Images must already exist locally; this tool cannot pull or modify running services.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess


ARTIFACTS = {
    "upstream": {
        "image": "docker.io/clickhouse/clickhouse-server@sha256:4ff0d6c199a9ebb906af75ae406496e8a96edd0187afdc16d51c0fb77ffca588",
        "version": "ClickHouse 25.8.33.6",
        "binary_sha256": "6a96266c0f00897225f9bb2ab0f965111298da75d7ec1b67465c6c9d5cf5ae81",
    },
    "altinity-fips": {
        "image": "docker.io/altinity/clickhouse-server@sha256:6254bc404966150468130d2b5b02ebdf7238f21d2d85fbde77bc76c7181447df",
        "version": "ClickHouse 25.3.8.30001.altinityfips",
        "binary_sha256": "080dce0336607e1d38e4deb9c9b95bfca34f587bdfd0613d8584fdce6bf8ee21",
    },
}


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=120).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", choices=ARTIFACTS)
    parser.add_argument("output", type=Path, help="new evidence directory; existing directories are refused")
    args = parser.parse_args()
    artifact = ARTIFACTS[args.artifact]
    # Refuse to overwrite any earlier evidence, including after a failed attempt.
    args.output.mkdir(parents=True, exist_ok=False)
    inspected = json.loads(run(["docker", "image", "inspect", artifact["image"]]))[0]
    if inspected["Architecture"] != "amd64" or inspected["Os"] != "linux":
        raise RuntimeError("Expected the exact Linux amd64 artifact")
    base = [
        "docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "101:101",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--memory", "1g", "--cpus", "2",
        # Replace image-declared anonymous volumes with disposable tmpfs too.
        "--tmpfs", "/var/lib/clickhouse:rw,nosuid,nodev,size=16m",
        "--tmpfs", "/var/log/clickhouse-server:rw,nosuid,nodev,size=16m",
    ]
    query = (
        "SELECT name,value FROM system.build_options WHERE "
        "positionCaseInsensitive(name,'ssl')>0 OR positionCaseInsensitive(name,'fips')>0 "
        "OR name LIKE 'VERSION%' FORMAT JSONEachRow"
    )
    build_text = run(base + ["--entrypoint", "/usr/bin/clickhouse", artifact["image"],
        "local", "--path", "/tmp/ch-inspection", "--max_threads", "1", "--query", query])
    build = {row["name"]: row["value"] for row in map(json.loads, build_text.splitlines())}
    platform = run(base + ["--entrypoint", "/bin/sh", artifact["image"], "-c",
        "cat /etc/os-release; ldd /usr/bin/clickhouse; sha256sum /usr/bin/clickhouse"])
    if build.get("VERSION_FULL") != artifact["version"]:
        raise RuntimeError("Unexpected ClickHouse version in the pinned artifact")
    actual_hash = platform.splitlines()[-1].split()[0]
    if actual_hash != artifact["binary_sha256"]:
        raise RuntimeError("Unexpected ClickHouse executable hash")
    files = {"build-options.jsonl": build_text, "platform.txt": platform}
    for name, content in files.items():
        (args.output / name).write_text(content)
    result = {
        "schema_revision": 1,
        "inspected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "artifact": args.artifact,
        "image_reference": artifact["image"],
        "image_id": inspected["Id"],
        "repository_digests": inspected.get("RepoDigests", []),
        "platform": "linux/amd64",
        "execution_environment": "isolated development Docker container; host qualification not asserted",
        "server_started": False,
        "credential_bearing_operations_performed": False,
        "guest_runtime_verified": False,
        "fips_qualified": False,
        "binary_sha256": actual_hash,
        "build_options": build,
        "evidence_sha256": {name: hashlib.sha256(content.encode()).hexdigest() for name, content in files.items()},
    }
    (args.output / "inspection.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"inspection_completed": True, "fips_qualified": False, "evidence": str(args.output)}))


if __name__ == "__main__":
    main()
