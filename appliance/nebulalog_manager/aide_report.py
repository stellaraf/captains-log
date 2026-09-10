"""Pure AIDE 0.19.2 configuration and report contracts; never execute AIDE.

The caller retains raw reports privately.  Only measured counts and the pinned
version leave this parser; diagnostics and filenames never enter its exceptions.
"""
from __future__ import annotations

import json
import re

from .common import Refused


AIDE_VERSION = "0.19.2"
MAX_REPORT_CHARS = 16 * 1024 * 1024
MAX_POLICY_CHARS = 64 * 1024
_MAX_COUNT = (1 << 63) - 1
_GROUPS = ("added", "removed", "changed")
_PATH = re.compile(r"/[A-Za-z0-9_.\-/]+\Z")
_GROUP_DEFINITION = re.compile(r"[A-Z][A-Z0-9_]*\s*=\s*[A-Za-z0-9_+\-]+\Z")


def _database_path(value: object) -> str:
    if (not isinstance(value, str) or len(value) > 4096
            or not _PATH.fullmatch(value)
            or any(part in ("", ".", "..") for part in value.split("/")[1:])):
        raise Refused("AIDE database path is invalid")
    return value


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_COUNT:
        raise Refused("AIDE report counts are invalid")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("non-finite JSON constant")


def _json_integer(value: str) -> int:
    # Bound conversion before int() on Python 3.9, which has no digit limit.
    if len(value.lstrip("-")) > 19:
        raise ValueError("oversized JSON integer")
    return int(value)


def parse_report(stdout: str, stderr: str, exit_code: int, action: str,
                 expected_database: str | None = None) -> dict:
    """Parse the fixed JSON/list_entries/grouped/summarized report contract.

    Actions are ``init`` and ``check``.  Initialization requires the exact
    expected output database.  Operational failures, warnings, unsupported
    versions and incomplete reports raise ``Refused`` rather than returning a
    clean state.  This does not authenticate the report or replace host checks.
    """
    if action not in ("init", "check") or not isinstance(action, str):
        raise Refused("AIDE report action is unsupported")
    if type(exit_code) is not int or exit_code not in range(8):
        raise Refused("AIDE operation did not complete")
    if action == "init" and exit_code != 0:
        raise Refused("AIDE initialization did not complete")
    if not isinstance(stderr, str) or stderr.strip():
        raise Refused("AIDE operation reported diagnostics")
    if (not isinstance(stdout, str) or not stdout.strip()
            or len(stdout) > MAX_REPORT_CHARS):
        raise Refused("AIDE report is malformed")
    try:
        report = json.loads(stdout, object_pairs_hook=_unique_object,
                            parse_constant=_invalid_constant, parse_int=_json_integer)
    except (ValueError, TypeError, RecursionError):
        raise Refused("AIDE report is malformed") from None
    if not isinstance(report, dict):
        raise Refused("AIDE report is malformed")
    if report.get("aide_version") != AIDE_VERSION:
        raise Refused("AIDE report version is unsupported")
    # AIDE can report changed attribute selection separately from file-change
    # counts.  It cannot establish a clean check against the fixed policy.
    if report.get("different_attributes"):
        raise Refused("AIDE monitored attributes differ from the database")
    for field in ("start_time", "end_time", "outline"):
        if not isinstance(report.get(field), str) or not report[field].strip():
            raise Refused("AIDE report is incomplete")
    _count(report.get("run_time_seconds"))
    raw_counts = report.get("number_of_entries")
    if not isinstance(raw_counts, dict) or set(raw_counts) not in (
            {"total"}, {"total", *_GROUPS}):
        raise Refused("AIDE report counts are invalid")
    counts = {"total": _count(raw_counts["total"])}
    counts.update({field: _count(raw_counts.get(field, 0)) for field in _GROUPS})
    if not counts["total"]:
        raise Refused("AIDE report contains no monitored entries")

    observed_mask = sum(bit for field, bit in zip(_GROUPS, (1, 2, 4)) if counts[field])
    if observed_mask != exit_code:
        raise Refused("AIDE report does not match exit status")
    seen_paths = set()
    for field in _GROUPS:
        entries = report.get(field, {})
        if not isinstance(entries, dict) or len(entries) != counts[field]:
            raise Refused("AIDE report entries do not match counts")
        for filename, summary in entries.items():
            if (not isinstance(filename, str) or not filename.startswith("/")
                    or "\0" in filename or not isinstance(summary, str) or not summary
                    or filename in seen_paths):
                raise Refused("AIDE report entries are invalid")
            seen_paths.add(filename)
    # The configured grouped report never emits the ungrouped entries field.
    if "entries" in report:
        raise Refused("AIDE report entry format is unsupported")

    if expected_database is not None:
        expected_database = _database_path(expected_database)
    if action == "init":
        if expected_database is None or report.get("new_database") != expected_database:
            raise Refused("AIDE initialized database does not match candidate")
        state = "initialized"
    else:
        if "new_database" in report:
            raise Refused("AIDE check unexpectedly wrote a database")
        if expected_database is not None:
            databases = report.get("databases")
            if not isinstance(databases, dict) or set(databases) != {expected_database}:
                raise Refused("AIDE checked database does not match candidate")
        state = "differences" if exit_code else "clean"
    return {"state": state, "exit_code": exit_code, "counts": counts,
            "aide_version": AIDE_VERSION}


def render_config(policy: str, database_in: str, database_out: str) -> str:
    """Render fixed modern directives around trusted selection/group rules.

    Policy is supplied by appliance code, not a user.  It may contain comments,
    uppercase group definitions and selection rules, but cannot add directives,
    macros, includes, executable includes or alternative report destinations.
    AIDE's separate --config-check still validates actual rule syntax.
    """
    database_in = _database_path(database_in)
    database_out = _database_path(database_out)
    if database_in == database_out:
        raise Refused("AIDE input and output databases must differ")
    if (not isinstance(policy, str) or not policy.strip()
            or len(policy) > MAX_POLICY_CHARS or "@@" in policy
            or any(ord(char) < 32 and char not in "\n\t" for char in policy)):
        raise Refused("AIDE policy is invalid")
    positive_rule = False
    for raw_line in policy.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            raise Refused("AIDE policy is invalid")
        if _GROUP_DEFINITION.fullmatch(line):
            continue
        if line.startswith(("/", "!/", "-/", "=/")):
            positive_rule = positive_rule or line.startswith(("/", "=/"))
            continue
        raise Refused("AIDE policy may contain only selection rules and groups")
    if not positive_rule:
        raise Refused("AIDE policy contains no monitored selection")
    directives = [
        "# Managed AIDE 0.19.2 configuration.",
        "database_in=file:" + database_in,
        "database_out=file:" + database_out,
        "gzip_dbout=yes",
        "database_attrs=sha512",
        "database_add_metadata=yes",
        "num_workers=1",
        "log_level=warning",
        "report_format=json",
        "report_level=list_entries",
        "report_grouped=yes",
        "report_summarize_changes=yes",
        "report_quiet=no",
        "report_append=no",
        "report_base16=yes",
        # AIDE captures report options when report_url is parsed.
        "report_url=stdout",
    ]
    return "\n".join(directives) + "\n\n" + policy.strip() + "\n"


def render_default_config(policy: str) -> str:
    """Source-owned /etc/aide.conf, also recognized by the pinned SCAP content.

    This pure build/test helper does not install or change host configuration.
    The defined directory and database filename identify the same managed DB
    used by the explicit enrollment/check lifecycle.
    """
    directory = "/var/lib/nebulalog/manager/aide"
    rendered = render_config(policy, directory + "/aide.db.gz", directory + "/unused-output.db.gz")
    return rendered.replace("database_in=file:" + directory + "/aide.db.gz\n",
                            "@@define DBDIR " + directory + "\ndatabase_in=file:@@{DBDIR}/aide.db.gz\n", 1)
