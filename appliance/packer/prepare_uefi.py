#!/usr/bin/env python3
"""Snapshot explicitly pinned x86 OVMF inputs; never launch QEMU or enroll keys.

Use vendor CODE and a pristine vendor VARS template, not a previous VM's NVRAM.
Pins must come from a trusted package/build input, not an unverified download.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def pinned(path, expected):
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise ValueError("An explicit ordinary SHA256 firmware pin is required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 64 * 1024 <= before.st_size <= 32 * 1024**2:
            raise ValueError("Firmware must be a bounded regular OVMF file")
        raw = stream.read(32 * 1024**2 + 1)
        after = os.fstat(stream.fileno())
        if any(getattr(before, field) != getattr(after, field) for field in
               ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
            raise ValueError("Firmware changed while being read")
    if raw[40:44] != b"_FVH" or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("OVMF volume header or supplied SHA256 pin differs")
    return raw


def prepare(code, variables, code_sha256, vars_sha256, output):
    code_raw, vars_raw = pinned(code, code_sha256), pinned(variables, vars_sha256)
    if code_raw == vars_raw or os.path.samefile(code, variables):
        raise ValueError("OVMF CODE and pristine VARS must be distinct inputs")
    output = output.absolute()
    output.mkdir(mode=0o700)  # Exclusive new directory; never overwrite a build.
    def write(name, raw):
        with (output / name).open("xb") as stream:
            os.fchmod(stream.fileno(), 0o400)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    write("OVMF_CODE.fd", code_raw)
    write("OVMF_VARS.fd", vars_raw)
    values = {"code": str(output / "OVMF_CODE.fd"), "vars": str(output / "OVMF_VARS.fd"),
              "code_base64_sha256": hashlib.sha256(base64.b64encode(code_raw)).hexdigest(),
              "vars_base64_sha256": hashlib.sha256(base64.b64encode(vars_raw)).hexdigest()}
    # JSON var files do not perform HCL string interpolation.
    write("uefi.pkrvars.json", (json.dumps({"uefi": values}, indent=2) + "\n").encode())
    record = {"schema": 1, "architecture": "x86_64", "code_sha256": code_sha256,
              "vars_template_sha256": vars_sha256, "packer_variables": values,
              "firmware_boot_validated": False, "secure_boot_validated": False,
              "tpm_created": False}
    write("firmware-inputs.json", (json.dumps(record, indent=2) + "\n").encode())
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", type=Path, required=True)
    parser.add_argument("--vars", type=Path, required=True)
    parser.add_argument("--code-sha256", required=True)
    parser.add_argument("--vars-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.code, args.vars, args.code_sha256, args.vars_sha256, args.output), indent=2))
