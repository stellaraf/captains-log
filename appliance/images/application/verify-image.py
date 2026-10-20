#!/usr/bin/env python3
"""Exercise the actual local application image without credentials or networking."""
import argparse
import json
import re
import subprocess
import sys


def command(args, *, success=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if success and result.returncode:
        raise ValueError("Image inspection or isolated execution failed")
    return result


def verify(image):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}", image):
        raise ValueError("Supply a local image name or immutable digest")
    metadata = json.loads(command(["docker", "image", "inspect", image]).stdout)
    if len(metadata) != 1:
        raise ValueError("Image must resolve to one local artifact")
    info = metadata[0]
    config = info["Config"]
    if info["Architecture"] != "amd64" or info["Os"] != "linux":
        raise ValueError("Appliance application must target Linux/amd64")
    if config["User"] != "10001:10001" or config["Entrypoint"] != ["nebulalog"]:
        raise ValueError("Unexpected runtime identity or entry point")
    if "REQUIRE_FIPS=true" not in config["Env"]:
        raise ValueError("Default application FIPS gate is missing")
    source_sha = config.get("Labels", {}).get("io.nebulalog.application-source-sha256", "")
    if not re.fullmatch(r"[a-f0-9]{64}", source_sha):
        raise ValueError("Immutable application source identity is missing")
    # Local-only: never pull an image, attach a network, mount data, or inject secrets.
    isolated = ["docker", "run", "--rm", "--pull=never", "--platform=linux/amd64",
                "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges"]
    version = command(isolated + ["--env", "REQUIRE_FIPS=true", image, "version"]).stdout.strip()
    disabled = command(isolated + ["--env", "REQUIRE_FIPS=true", "--env", "GODEBUG=fips140=off", image, "version"], success=False)
    if disabled.returncode != 1 or "cryptographic module is not in FIPS mode" not in disabled.stderr:
        raise ValueError("Application did not refuse disabled FIPS mode before startup")
    invalid = command(isolated + ["--env", "REQUIRE_FIPS=invalid", image, "version"], success=False)
    if invalid.returncode != 1 or "REQUIRE_FIPS must be a Boolean" not in invalid.stderr:
        raise ValueError("Application did not refuse malformed FIPS policy")
    build = command(isolated + ["--entrypoint", "/bin/cat", image, "/opt/nebulalog/go-build-info.txt"]).stdout
    for required in ("go1.27.2", "GOFIPS140=v1.0.0-c2097c7c", "CGO_ENABLED=0", "GOARCH=amd64", "GOOS=linux"):
        if required not in build:
            raise ValueError("Application build metadata does not match the reviewed toolchain/module")
    return {"schema": 1, "status": "isolated_checks_passed", "image": image,
            "local_image_id": info["Id"], "version": version, "application_source_sha256": source_sha,
            "checks": {"linux_amd64": True, "nonroot": True, "readonly_execution": True,
                       "frozen_go_module": True, "runtime_fips_enabled": True,
                       "fips_disabled_refused": True, "malformed_policy_refused": True},
            "network_used": False, "guest_operating_environment_qualified": False,
            "end_to_end_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="Already-built local image; this tool never pulls")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.image), indent=2, sort_keys=True))
        return 0
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        print("Application image verification failed; inspect its local build and configuration", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
