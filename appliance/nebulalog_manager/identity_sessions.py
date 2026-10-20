"""Keycloak session invalidation within an externally held maintenance window."""
from .common import Refused


def invalidate_realm_sessions(call, installation_id, cutoff):
    """Reconcile session invalidation and return the effective issuance floor.

    The caller serializes identity maintenance, persists its requested cutoff
    before dispatch, keeps access fenced on uncertainty, and durably applies
    the returned (possibly newer) floor to every API and rollback before
    releasing maintenance. Locally verified JWTs need that separate API floor.

    Keycloak logout-all replaces notBefore with its server clock. Reconcile
    that side effect without discarding either the requested or observed floor.
    Lost acknowledgements are uncertain. A newer observed floor requires
    persisting a revised intent before retrying while fenced.
    """
    if (not isinstance(installation_id, str) or not installation_id
            or type(cutoff) is not int or not 1577836800 <= cutoff < 2**31):
        raise Refused("Session invalidation requires an installation identity and canonical cutoff")
    realm = call("")
    identity = realm.get("id")
    if not isinstance(identity, str) or not identity:
        raise Refused("Session invalidation requires a realm identity")

    def inspect(observed):
        if (observed.get("id") != identity or observed.get("realm") != "nebulalog"
                or observed.get("attributes", {}).get("nebulalog.installation-id") != installation_id):
            raise Refused("Session invalidation ownership readback failed")
        floor = observed.get("notBefore")
        if type(floor) is not int or not 0 <= floor < 2**31:
            raise Refused("Session invalidation cutoff readback is malformed")
        return floor

    def write_verify(floor):
        call("", "PUT", {"notBefore": floor})
        if inspect(call("")) != floor:
            raise Refused("Session invalidation cutoff readback failed")

    previous = inspect(realm)
    if previous > cutoff:
        # Do not invoke logout with a stronger boundary known only in RAM:
        # the vendor can lower it and lose the response. The caller must first
        # persist a revised intent, then retry with at least this boundary.
        raise Refused("Session invalidation needs a durable intent for the newer realm cutoff")
    effective = cutoff
    write_verify(effective)
    call("logout-all", "POST")
    observed = inspect(call(""))
    # The vendor may move the floor forwards or backwards (clock skew or a
    # previously future-dated policy). Access remains fenced through repair.
    if observed < effective:
        write_verify(effective)
    else:
        effective = observed
    return {"realm_id": identity, "token_not_before": effective,
            "api_cutoff_required": True, "locally_verified_tokens_revoked": False}


class SessionCutoffJournal:
    """Retain the authentication floor outside database/configuration backups.

    The directory must already be private, root-owned encrypted manager state.
    The caller supplies an operation-bound fence check and owns server/API
    startup and health. A receipt never authorizes releasing that fence.
    """

    def __init__(self, directory, installation_id):
        from pathlib import Path
        import re
        self.directory = Path(directory)
        if (not self.directory.is_absolute() or self.directory.resolve() != self.directory
                or not isinstance(installation_id, str)
                or not re.fullmatch(r"[a-f0-9-]{32,36}", installation_id)):
            raise Refused("Session journal requires canonical owned paths and installation identity")
        self.installation_id = installation_id
        self.path = self.directory / "session-cutoff.json"
        self._directory(self.directory)

    @staticmethod
    def _directory(path):
        import stat
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise Refused("Session journal requires a private root-owned directory")

    @staticmethod
    def _read(path):
        import os
        import stat
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > 1024 * 1024):
                raise Refused("Session maintenance requires a bounded private root-owned file")
            with os.fdopen(os.dup(fd), "rb") as stream:
                result = stream.read(1024 * 1024 + 1)
            if len(result) > 1024 * 1024:
                raise Refused("Session maintenance file exceeds its bound")
            return result
        finally:
            os.close(fd)

    @staticmethod
    def _environment(raw):
        import hashlib
        import re
        if not raw or not raw.endswith(b"\n") or b"\x00" in raw or b"\r" in raw:
            raise Refused("API environment is not canonical")
        floor, retained, seen = 0, [], set()
        for line in raw.splitlines(keepends=True):
            key, sep, value = line[:-1].partition(b"=")
            if not sep or not re.fullmatch(rb"[A-Z][A-Z0-9_]*", key) or key in seen:
                raise Refused("API environment contains an ambiguous key")
            seen.add(key)
            if key == b"OIDC_TOKEN_NOT_BEFORE":
                if not re.fullmatch(rb"[1-9][0-9]{0,9}", value):
                    raise Refused("API token cutoff is malformed")
                floor = int(value)
                if not 1577836800 <= floor < 2**31:
                    raise Refused("API token cutoff is outside the supported range")
            else:
                retained.append(line)
        if not {b"OIDC_ISSUER", b"OIDC_CLIENT_ID"} <= seen:
            raise Refused("API environment is missing identity settings")
        body = b"".join(retained)
        return floor, body, hashlib.sha256(body).hexdigest()

    def reconcile(self, call, operation, api_environment, minimum, fence, *, initialize=False):
        """Persist intent, invalidate sessions and repair the API's durable floor.

        ``fence(operation)`` must positively verify external maintenance and an
        inactive API. During retry/rollback of the same operation, only the
        cutoff line may differ. A new authorized operation can bind updated
        customer settings after the previous operation reached the API phase.
        """
        from pathlib import Path
        import hashlib
        import os
        import re
        from .common import atomic_json, locked
        from .host_payload import strict_json
        if (not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{64}", operation)
                or type(minimum) is not int or not 1577836800 <= minimum < 2**31):
            raise Refused("Session reconciliation requires a durable operation and canonical minimum")
        api = Path(api_environment)
        if not api.is_absolute() or api.resolve() != api:
            raise Refused("API environment must be a canonical regular file")
        self._directory(self.directory)
        self._directory(api.parent)

        def held():
            if fence(operation) is not True:
                raise Refused("Session reconciliation requires its external maintenance fence")

        if type(initialize) is not bool:
            raise Refused("Session initialization requires an explicit boolean")
        held()
        lock = self.directory / "session-cutoff.lock"
        if os.path.lexists(lock):
            self._read(lock)
        with locked(lock):
            self._read(lock)
            raw = self._read(api)
            api_floor, body, configuration_hash = self._environment(raw)
            previous = None
            if os.path.lexists(self.path):
                previous = strict_json(self._read(self.path))
                fields = {"schema", "installation_id", "operation", "floor", "phase",
                          "api_path", "api_configuration_sha256", "realm_id"}
                if (not isinstance(previous, dict) or set(previous) != fields
                        or type(previous["schema"]) is not int or previous["schema"] != 1
                        or previous["installation_id"] != self.installation_id
                        or not isinstance(previous["realm_id"], str) or not previous["realm_id"]
                        or not isinstance(previous["operation"], str)
                        or not re.fullmatch(r"[a-f0-9]{64}", previous["operation"])
                        or type(previous["floor"]) is not int
                        or not 1577836800 <= previous["floor"] < 2**31
                        or previous["phase"] not in ("intent", "realm", "api")
                        or previous["api_path"] != str(api)
                        or not isinstance(previous["api_configuration_sha256"], str)
                        or not re.fullmatch(r"[a-f0-9]{64}", previous["api_configuration_sha256"])
                        or (previous["operation"] == operation or previous["phase"] != "api")
                        and previous["api_configuration_sha256"] != configuration_hash):
                    raise Refused("Session journal ownership or preserved configuration changed")
                if previous["operation"] != operation and previous["phase"] != "api":
                    raise Refused("An unfinished operation owns session recovery")
            if previous is None and not initialize:
                raise Refused("Missing session journal requires authorized initialization, not recovery")
            realm = call("")
            if (not isinstance(realm.get("id"), str) or not realm["id"]
                    or previous is not None and previous["realm_id"] != realm["id"]
                    or realm.get("realm") != "nebulalog"
                    or realm.get("attributes", {}).get("nebulalog.installation-id") != self.installation_id):
                raise Refused("Session journal cannot adopt a foreign realm")
            realm_floor = realm.get("notBefore")
            if type(realm_floor) is not int or not 0 <= realm_floor < 2**31:
                raise Refused("Session journal cannot adopt a malformed realm floor")
            floor = max(minimum, api_floor, realm_floor, previous["floor"] if previous else 0)
            record = {"schema": 1, "installation_id": self.installation_id,
                      "operation": operation, "floor": floor, "phase": "intent",
                      "api_path": str(api), "api_configuration_sha256": configuration_hash, "realm_id": realm["id"]}

            def persist(phase):
                held()
                record["phase"] = phase
                atomic_json(self.path, record)
                if strict_json(self._read(self.path)) != record:
                    raise Refused("Session journal durable readback failed")

            persist("intent")

            def guarded(path, method="GET", data=None):
                held()
                return call(path, method, data)

            result = invalidate_realm_sessions(guarded, self.installation_id, floor)
            record["floor"] = result["token_not_before"]
            persist("realm")
            expected = body + b"OIDC_TOKEN_NOT_BEFORE=" + str(record["floor"]).encode() + b"\n"
            held()
            if self._read(api) != raw:
                raise Refused("API configuration changed during session maintenance")
            _atomic_private_bytes(api, expected)
            if self._read(api) != expected:
                raise Refused("API cutoff durable readback failed")
            persist("api")
            return {"installation_id": self.installation_id, "operation": operation,
                    "token_not_before": record["floor"], "api_sha256": hashlib.sha256(expected).hexdigest(),
                    "api_configuration_sha256": configuration_hash, "phase": "api",
                    "maintenance_release_authorized": False, "fresh_login_required": True}


def _atomic_private_bytes(path, body):
    import os
    import tempfile
    fd, name = tempfile.mkstemp(prefix=".session-cutoff-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.lexists(name):
            os.unlink(name)
