"""Data-only host operation schemas. Registration does not enable execution."""
from __future__ import annotations

import ipaddress
import re
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .common import Refused


def uuid_value(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError) as exc:
        raise Refused("invalid_resource_id") from exc
    return value


def digest_value(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise Refused("invalid_digest")
    return value


def choice(*allowed):
    def validate(value):
        if type(value) is not str or value not in allowed:
            raise Refused("invalid_choice")
        return value
    return validate


def hostname(value):
    if (not isinstance(value, str) or len(value) > 253 or not value
            or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", item) for item in value.split("."))):
        raise Refused("invalid_hostname")
    return value


def servers(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise Refused("invalid_time_servers")
    for item in value:
        # ipaddress also accepts integers/packed bytes; the wire contract does not.
        if not isinstance(item, str):
            raise Refused("invalid_time_server")
        # Scoped IPv6 parsing accepts arbitrary scope text, including newlines.
        # Keep every server a bounded single configuration token before parsing.
        if len(item) > 253 or not re.fullmatch(r"[A-Za-z0-9:._%\-]+", item):
            raise Refused("invalid_time_server")
        try:
            ipaddress.ip_address(item)
        except ValueError:
            hostname(item)
    if len(set(value)) != len(value):
        raise Refused("duplicate_time_server")
    return list(value)


def timezone(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", value) or len(value) > 128:
        raise Refused("invalid_timezone")
    try:
        ZoneInfo(value)
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise Refused("invalid_timezone") from exc
    return value


def boolean(value):
    if type(value) is not bool:
        raise Refused("invalid_boolean")
    return value


def weekday(value):
    if type(value) is not int or not 0 <= value <= 6:
        raise Refused("invalid_weekday")
    return value


def walltime(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value):
        raise Refused("invalid_wall_time")
    return value


# IDs are opaque references issued by a future host resource/artifact registry.
# In particular network_configuration_id is not a path or an arbitrary JSON body.
SCHEMAS = {
    "storage.grow": {"pool_id": uuid_value},
    "storage.add_disk": {"pool_id": uuid_value, "disk_id": uuid_value},
    "updates.check": {"channel": choice("stable")},
    "updates.install": {"release_id": uuid_value},
    "updates.rollback": {"transaction_id": uuid_value},
    "updates.finalize": {"transaction_id": uuid_value},
    "updates.schedule": {"weekday": weekday, "start": walltime, "end": walltime, "timezone": timezone,
                         "automatic_os_updates": boolean, "automatic_application_updates": boolean},
    "os.apply": {"policy_revision": digest_value},
    "reboot.complete": {"transaction_id": uuid_value},
    "backup.create": {"recipient_id": uuid_value, "scope": choice("configuration")},
    "restore.apply": {"backup_id": uuid_value},
    "baseline.scan": {"selection_id": uuid_value},
    "baseline.review": {"assessment_id": uuid_value, "review_id": uuid_value},
    "baseline.select": {"policy_id": uuid_value, "baseline": choice("cis-level2", "stig", "unified")},
    "settings.network": {"network_configuration_id": uuid_value},
    "settings.time": {"ntp_servers": servers, "timezone": timezone},
    "certificates.activate": {"certificate_id": uuid_value, "target": choice("https", "syslog", "internal")},
}


def parameters(operation, value):
    if not isinstance(operation, str) or operation not in SCHEMAS:
        raise Refused("operation_not_registered")
    schema = SCHEMAS[operation]
    if not isinstance(value, dict) or set(value) != set(schema):
        raise Refused("invalid_operation_parameters")
    result = {name: validator(value[name]) for name, validator in schema.items()}
    if operation == "updates.schedule" and result["start"] == result["end"]:
        raise Refused("empty_maintenance_window")
    return result
