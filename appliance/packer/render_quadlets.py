#!/usr/bin/env python3
"""Render release-controlled image digests into a NEW staging directory."""
import argparse
import json
from pathlib import Path
import re

REQUIRED={"NEBULALOG_IMAGE","POSTGRESQL_IMAGE","CLICKHOUSE_IMAGE","KEYCLOAK_FIPS_IMAGE"}

def render(images, templates, output):
    if set(images) != REQUIRED:
        raise ValueError("All four explicit component image references are required")
    for value in images.values():
        if not isinstance(value,str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]+@sha256:[0-9a-f]{64}",value):
            raise ValueError("Images must be immutable registry references pinned by SHA256")
    output.mkdir(parents=True,exist_ok=False)
    for source in templates.iterdir():
        content=source.read_text()
        for key,value in images.items():content=content.replace("@"+key+"@",value)
        if re.search(r"@[A-Z_]+@",content):raise ValueError("Unresolved image reference")
        (output/source.name.removesuffix(".in")).write_text(content)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--images",type=Path,required=True)
    p.add_argument("--templates",type=Path,default=Path("appliance/quadlet"))
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();render(json.loads(a.images.read_text()),a.templates,a.output)
