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

    def _restore_record(self, api):
        """Read the monotonic floor captured before identity database replacement."""
        import os
        import re
        from .host_payload import strict_json
        path = self.directory / "restore-cutoff.json"
        if not os.path.lexists(path):
            return None
        value = strict_json(self._read(path))
        if (not isinstance(value, dict)
                or set(value) != {"schema", "installation_id", "operation", "floor", "api_path", "realm_id"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or value["installation_id"] != self.installation_id
                or not isinstance(value["operation"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["operation"])
                or type(value["floor"]) is not int or not 1577836800 <= value["floor"] < 2**31
                or value["api_path"] != str(api)
                or not isinstance(value["realm_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["realm_id"])):
            raise Refused("Pre-restore identity cutoff has invalid ownership or shape")
        return value

    def _session_record(self, api):
        """Validate the retained intent independently of a live API or realm.

        Database-replacement resume may have neither available. A retained
        record is evidence of a floor, not authority to adopt another operation
        or release maintenance.
        """
        import os
        import re
        from .host_payload import strict_json
        if not os.path.lexists(self.path):
            return None
        value = strict_json(self._read(self.path))
        fields = {"schema", "installation_id", "operation", "floor", "phase",
                  "api_path", "api_configuration_sha256", "realm_id"}
        if (not isinstance(value, dict) or set(value) != fields
                or type(value["schema"]) is not int or value["schema"] != 1
                or value["installation_id"] != self.installation_id
                or not isinstance(value["realm_id"], str) or not value["realm_id"]
                or not isinstance(value["operation"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", value["operation"])
                or type(value["floor"]) is not int
                or not 1577836800 <= value["floor"] < 2**31
                or value["phase"] not in ("intent", "realm", "api")
                or value["api_path"] != str(api)
                or not isinstance(value["api_configuration_sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", value["api_configuration_sha256"])):
            raise Refused("Session journal ownership or shape changed")
        return value

    @staticmethod
    def _session_configuration(record, configuration_hash, operation):
        if (record is not None
                and (record["operation"] == operation or record["phase"] != "api")
                and record["api_configuration_sha256"] != configuration_hash):
            raise Refused("Session journal preserved configuration changed")

    def capture_restore(self, observe, operation, api_environment, minimum, fence, *, resume=False):
        """Persist the live issuance floor before a destructive database intent.

        The caller proves stopped identity/API writers and continuous maintenance.
        Once database replacement has been admitted, resume requires the exact
        retained capture; it must never learn a lower floor from a restored DB.
        Capture alone does not revoke tokens or authorize service startup.
        """
        from pathlib import Path
        import os
        import re
        from .common import atomic_json, locked
        if (not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{64}", operation)
                or type(resume) is not bool or type(minimum) is not int
                or not 1577836800 <= minimum < 2**31):
            raise Refused("Identity restore capture requires a bound operation and canonical minimum")
        api = Path(api_environment)
        if not api.is_absolute() or api.resolve() != api:
            raise Refused("Identity restore capture requires a canonical API environment")
        self._directory(self.directory)

        def held():
            if fence(operation) is not True:
                raise Refused("Identity restore capture lost its writer fence")

        held()
        lock = self.directory / "session-cutoff.lock"
        if os.path.lexists(lock):
            self._read(lock)
        with locked(lock):
            self._read(lock)
            held()
            previous = self._restore_record(api)
            session = self._session_record(api)
            if resume:
                if previous is None or previous["operation"] != operation:
                    raise Refused("Interrupted database replacement lost its pre-restore identity cutoff")
                if session is not None and (session["realm_id"] != previous["realm_id"]
                                            or session["floor"] > previous["floor"]):
                    raise Refused("Retained restore cutoff does not cover the session journal")
                return previous
            self._directory(api.parent)
            api_floor, _, configuration_hash = self._environment(self._read(api))
            self._session_configuration(session, configuration_hash, operation)
            realm = observe()
            if (not isinstance(realm, dict) or set(realm) != {"realm_id", "installation_id", "floor"}
                    or realm["installation_id"] != self.installation_id
                    or not isinstance(realm["realm_id"], str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", realm["realm_id"])
                    or type(realm["floor"]) is not int or not 0 <= realm["floor"] < 2**31
                    or previous is not None and previous["realm_id"] != realm["realm_id"]
                    or session is not None and session["realm_id"] != realm["realm_id"]):
                raise Refused("Pre-restore identity observation belongs to another realm")
            value = {"schema": 1, "installation_id": self.installation_id, "operation": operation,
                     "floor": max(minimum, api_floor, realm["floor"], previous["floor"] if previous else 0,
                                  session["floor"] if session else 0),
                     "api_path": str(api), "realm_id": realm["realm_id"]}
            held()
            if self._session_record(api) != session:
                raise Refused("Session journal changed during pre-restore capture")
            atomic_json(self.directory / "restore-cutoff.json", value)
            if self._restore_record(api) != value:
                raise Refused("Pre-restore identity cutoff did not persist")
            held()
            return value

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
            previous = self._session_record(api)
            self._session_configuration(previous, configuration_hash, operation)
            if previous is not None:
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
            captured = self._restore_record(api)
            if captured is not None and captured["realm_id"] != realm["id"]:
                raise Refused("Session reconciliation differs from the pre-restore realm")
            floor = max(minimum, api_floor, realm_floor, previous["floor"] if previous else 0,
                        captured["floor"] if captured else 0)
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
            _atomic_private_bytes(api, expected, preserve_metadata=True)
            if self._read(api) != expected:
                raise Refused("API cutoff durable readback failed")
            persist("api")
            return {"installation_id": self.installation_id, "operation": operation,
                    "token_not_before": record["floor"], "api_sha256": hashlib.sha256(expected).hexdigest(),
                    "api_configuration_sha256": configuration_hash, "phase": "api",
                    "maintenance_release_authorized": False, "fresh_login_required": True}


def _atomic_private_bytes(path, body, *, preserve_metadata=False):
    """Replace private bytes, retaining API security metadata when requested.

    ACLs and SELinux labels are extended attributes on the supported Linux
    appliance. Copy and verify them before rename; an unsupported attribute or
    denied write must leave the old API file intact and maintenance held.
    Fresh temporary-authority credentials use the private-file default.
    """
    import os
    import stat
    import tempfile
    source, name = None, None

    def metadata(fd):
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise Refused("API replacement requires a private root-owned regular file")
        attrs = {key: os.getxattr(fd, key) for key in os.listxattr(fd)}
        return info, attrs

    def identity(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                info.st_mode, info.st_nlink, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)

    try:
        if preserve_metadata:
            source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            before, attributes = metadata(source)
            if identity(os.fstat(source)) != identity(before):
                raise Refused("API security metadata changed during capture")
        fd, name = tempfile.mkstemp(prefix=".session-cutoff-", dir=path.parent)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(body)
            stream.flush()
            if preserve_metadata:
                target = stream.fileno()
                current = os.fstat(target)
                if (current.st_uid, current.st_gid) != (before.st_uid, before.st_gid):
                    os.fchown(target, before.st_uid, before.st_gid)
                for key in set(os.listxattr(target)) - attributes.keys():
                    os.removexattr(target, key)
                for key, value in attributes.items():
                    os.setxattr(target, key, value)
                copied, copied_attributes = metadata(target)
                if (copied.st_gid != before.st_gid or copied_attributes != attributes):
                    raise Refused("API replacement security metadata did not persist")
            os.fsync(stream.fileno())
        if preserve_metadata:
            current, current_attributes = metadata(source)
            if (identity(current) != identity(before) or current_attributes != attributes
                    or identity(path.lstat()) != identity(before)):
                raise Refused("API file changed during metadata-preserving replacement")
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if source is not None:
            os.close(source)
        if name is not None and os.path.lexists(name):
            os.unlink(name)


class TemporaryIdentityAuthority(SessionCutoffJournal):
    """Durable, operation-owned authority for the fixed maintenance workflow.

    The trusted backend controls the sole identity server, vendor recovery CLI,
    SQL observations and verified Admin REST transport. This controller never
    accepts a replacement bootstrap user or arbitrary downloaded commands.
    """

    def __init__(self, directory, installation_id):
        super().__init__(directory, installation_id)
        self.path = self.directory / 'temporary-authority.json'

    @staticmethod
    def _receipt(value, installation_id, operation):
        import re
        fields = {'installation_id', 'operation', 'token_not_before', 'api_sha256',
                  'api_configuration_sha256', 'phase', 'maintenance_release_authorized',
                  'fresh_login_required'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['installation_id'] != installation_id or value['operation'] != operation
                or type(value['token_not_before']) is not int
                or not 1577836800 <= value['token_not_before'] < 2**31
                or value['phase'] != 'api' or value['maintenance_release_authorized'] is not False
                or value['fresh_login_required'] is not True
                or any(not isinstance(value[k], str) or not re.fullmatch(r'[a-f0-9]{64}', value[k])
                       for k in ('api_sha256', 'api_configuration_sha256'))):
            raise Refused('Temporary authority requires a bounded session-journal receipt')
        return value

    def run(self, operation, backend, work, *, initialize=False):
        """Resume creation/work/removal while keeping external access fenced.

        ``work(token)`` performs fixed scope reconciliation and session journaling.
        Failed work keeps the private authority record for recovery. A successful
        return proves removal, but still does not release maintenance or prove
        native host health. Only explicit first-use admission may initialize a
        missing record; a completed record is retained with credentials erased.
        """
        import os
        import re
        import secrets
        from .common import atomic_json, locked
        from .host_payload import strict_json
        if (not isinstance(operation, str) or not re.fullmatch(r'[a-f0-9]{64}', operation)
                or type(initialize) is not bool):
            raise Refused('Temporary authority requires a canonical operation')
        self._directory(self.directory)

        def held():
            if backend.fenced(operation) is not True:
                raise Refused('Temporary authority requires its external maintenance fence')

        held()
        lock = self.directory / 'temporary-authority.lock'
        if os.path.lexists(lock): self._read(lock)
        with locked(lock):
            self._read(lock)
            record = None
            if os.path.lexists(self.path):
                record = strict_json(self._read(self.path))
                fields = {'schema', 'installation_id', 'operation', 'realm_id', 'bootstrap_id',
                          'client_name', 'client_id', 'service_user_id', 'secret', 'token',
                          'phase', 'work_receipt'}
                if (not isinstance(record, dict) or set(record) != fields
                        or type(record['schema']) is not int or record['schema'] != 1
                        or record['installation_id'] != self.installation_id
                        or not isinstance(record['operation'], str)
                        or not re.fullmatch(r'[a-f0-9]{64}', record['operation'])
                        or not isinstance(record['client_name'], str)
                        or not re.fullmatch(r'cl-maint-[a-f0-9]{32}', record['client_name'])
                        or record['phase'] not in ('intent', 'creating', 'ready', 'removing', 'removed')
                        or any(not isinstance(record[k], str) or not record[k]
                               for k in ('realm_id', 'bootstrap_id'))):
                    raise Refused('Temporary authority record has invalid ownership or shape')
                removed = record['phase'] == 'removed'
                if (removed and (record['secret'] is not None or record['token'] is not None)
                        or not removed and (not isinstance(record['secret'], str)
                            or not re.fullmatch(r'[a-f0-9]{64}', record['secret']))):
                    raise Refused('Temporary authority credential state is inconsistent')
                if record['token'] is not None:
                    self._token(record['token'], record['client_name'], record['service_user_id'])
                for key in ('client_id', 'service_user_id'):
                    if record[key] is not None and (not isinstance(record[key], str)
                            or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', record[key])):
                        raise Refused('Temporary authority has an invalid retained identity')
                if ((record['client_id'] is None) != (record['service_user_id'] is None)
                        or record['phase'] == 'intent' and record['client_id'] is not None
                        or record['phase'] in ('intent', 'creating') and record['token'] is not None):
                    raise Refused('Temporary authority has inconsistent creation evidence')
                if record['phase'] in ('ready', 'removing', 'removed') and not all(
                        record[k] for k in ('client_id', 'service_user_id')):
                    raise Refused('Temporary authority lost its bound identity')
                if record['phase'] in ('ready', 'removing') and record['token'] is None:
                    raise Refused('Temporary authority lost its administration token')
                if record['phase'] in ('removing', 'removed'):
                    self._receipt(record['work_receipt'], self.installation_id, record['operation'])
                elif record['work_receipt'] is not None:
                    raise Refused('Temporary authority has premature work evidence')
                if record['operation'] != operation and not removed:
                    raise Refused('Another unfinished operation owns temporary authority')

            def observe(value):
                held()
                current = backend.observe(value['client_name'], value['service_user_id'])
                if (not isinstance(current, dict)
                        or current.get('installation_id') != self.installation_id
                        or current.get('realm_id') != value['realm_id']
                        or current.get('bootstrap_id') != value['bootstrap_id']
                        or current.get('bootstrap_disabled') is not True
                        or current.get('other_temporary_clients') != []
                        or not isinstance(current.get('service_users'), list)):
                    raise Refused('Temporary authority installation or disabled bootstrap changed')
                client = current.get('client')
                if client is not None:
                    expected = {'client_name': value['client_name'], 'realm': 'master',
                                'temporary': True, 'enabled': True, 'public': False,
                                'service_accounts': True, 'standard_flow': False,
                                'implicit_flow': False, 'password_grant': False, 'admin_role': True}
                    if (not isinstance(client, dict) or any(type(client.get(k)) is not type(v) or client.get(k) != v for k, v in expected.items())
                            or any(not isinstance(client.get(k), str)
                                or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', client[k])
                                for k in ('id', 'service_user_id'))
                            or current['service_users'] != [client['service_user_id']]
                            or value['client_id'] is not None and value['client_id'] != client['id']
                            or value['service_user_id'] is not None and value['service_user_id'] != client['service_user_id']):
                        raise Refused('Temporary administration client is not the owned vendor recovery identity')
                elif current['service_users']:
                    raise Refused('Temporary administration left an orphan service user')
                return client

            if record is not None and record['phase'] == 'removed':
                if observe(record) is not None:
                    raise Refused('Removed temporary authority reappeared; explicit recovery is required')
                if record['operation'] == operation:
                    held()
                    if backend.settled(record['work_receipt']) is not True:
                        raise Refused('Completed identity maintenance no longer matches live state')
                    return self._receipt(record['work_receipt'], self.installation_id, operation)
                record = None
                initialize = True  # A checked completed record authorizes a new operation.
            if record is None:
                if not initialize:
                    raise Refused('Missing temporary-authority record requires authorized initialization')
                name = 'cl-maint-' + secrets.token_hex(16)
                held()
                initial = backend.observe(name, None)
                if (not isinstance(initial, dict) or initial.get('installation_id') != self.installation_id
                        or initial.get('bootstrap_disabled') is not True
                        or initial.get('other_temporary_clients') != []
                        or initial.get('client') is not None or initial.get('service_users') != []
                        or any(not isinstance(initial.get(k), str) or not initial[k]
                               for k in ('realm_id', 'bootstrap_id'))):
                    raise Refused('Cannot initialize temporary authority in this identity database')
                record = {'schema': 1, 'installation_id': self.installation_id, 'operation': operation,
                          'realm_id': initial['realm_id'], 'bootstrap_id': initial['bootstrap_id'],
                          'client_name': name, 'client_id': None, 'service_user_id': None,
                          'secret': secrets.token_hex(32), 'token': None, 'phase': 'intent',
                          'work_receipt': None}
                held(); atomic_json(self.path, record)

            def persist(phase):
                held(); record['phase'] = phase; atomic_json(self.path, record)
                if strict_json(self._read(self.path)) != record:
                    raise Refused('Temporary authority durable readback failed')

            if record['phase'] in ('intent', 'creating'):
                if record['phase'] == 'intent':
                    if observe(record) is not None:
                        raise Refused('Uncreated temporary identity already exists')
                    persist('creating')
                held(); backend.quiesce(record['client_name'])
                client = observe(record)
                if client is None:
                    if record['client_id'] is not None:
                        raise Refused('Bound temporary authority disappeared during creation recovery')
                    held(); backend.create(record['client_name'], record['secret'])
                    client = observe(record)
                    if client is None:
                        raise Refused('Vendor recovery command did not create its identity')
                record['client_id'], record['service_user_id'] = client['id'], client['service_user_id']
                persist('creating')
                held(); backend.start()
                token = backend.authenticate(record['client_name'], record['secret'])
                self._token(token, record['client_name'], record['service_user_id'])
                if backend.probe(token, self.installation_id, record['realm_id']) is not True:
                    raise Refused('Temporary authority cannot administer the owned realm')
                observe(record); record['token'] = token; persist('ready')

            if record['phase'] == 'ready':
                held(); backend.start()
                if observe(record) is None:
                    raise Refused('Ready temporary authority disappeared before work completed')
                token = backend.authenticate(record['client_name'], record['secret'])
                self._token(token, record['client_name'], record['service_user_id'])
                if backend.probe(token, self.installation_id, record['realm_id']) is not True:
                    raise Refused('Temporary authority lost its realm administration')
                record['token'] = token; persist('ready')
                held()
                record['work_receipt'] = self._receipt(work(token), self.installation_id, operation)
                persist('removing')

            if record['phase'] == 'removing':
                held(); backend.start()
                client = observe(record)
                if client is not None:
                    held()
                    token = backend.authenticate(record['client_name'], record['secret'])
                    self._token(token, record['client_name'], record['service_user_id'])
                    if backend.probe(token, self.installation_id, record['realm_id']) is not True:
                        raise Refused('Temporary authority lost access before removal')
                    record['token'] = token; persist('removing')
                    held(); backend.delete(token, record['client_id'])
                if observe(record) is not None:
                    raise Refused('Temporary administration client survived removal')
                held()
                if (backend.credentials_refused(record['client_name'], record['secret']) is not True
                        or backend.token_refused(record['token']) is not True):
                    raise Refused('Removed temporary administration retained usable authority')
                record['secret'] = record['token'] = None
                persist('removed')
            held()
            if backend.settled(record['work_receipt']) is not True:
                raise Refused('Completed identity maintenance no longer matches live state')
            return self._receipt(record['work_receipt'], self.installation_id, operation)

    @staticmethod
    def _token(value, client_name=None, service_user_id=None):
        import re
        if (not isinstance(value, str) or len(value) > 32768
                or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', value)):
            raise Refused('Temporary administration returned an invalid token')
        if client_name is not None:
            import base64
            from .host_payload import strict_json
            try:
                claims = strict_json(base64.urlsafe_b64decode(value.split('.')[1] + '==='))
            except (ValueError, TypeError) as exc:
                raise Refused('Temporary administration token claims are malformed') from exc
            if (not isinstance(claims, dict) or claims.get('azp') != client_name
                    or claims.get('sub') != service_user_id):
                raise Refused('Temporary administration token belongs to another identity')
