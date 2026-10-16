"""Initial GRUB credential enrollment; caller holds initial_hardening locks."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from .common import Refused, atomic_json, require_linux_root, run
from .update_enrollment import _read, _tree


@dataclass(frozen=True)
class Paths:
    users: Path = Path('/etc/grub.d/01_users')
    credential: Path = Path('/boot/grub2/user.cfg')
    config: Path = Path('/boot/grub2/grub.cfg')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _same_configuration(planned, generated):
    if planned == generated:
        return True
    def normalize(raw):
        lines = raw.decode('utf-8').splitlines(keepends=True)
        found = 0
        for index, line in enumerate(lines):
            match = re.fullmatch(r'([ \t]*set kernelopts=")([^"\n]*)("\n?)', line)
            if not match:
                continue
            found += 1
            tokens = match[2].split()
            movable = [token for token in tokens if token.split('=', 1)[0] in {'fips', 'boot'}]
            if (not tokens or any(not re.fullmatch(r'[A-Za-z0-9_=/.:,+%\-]+', token) for token in tokens)
                    or len(movable) != 2 or {token.split('=', 1)[0] for token in movable} != {'fips', 'boot'}):
                return None
            fixed = [token for token in tokens if token.split('=', 1)[0] not in {'fips', 'boot'}]
            lines[index] = match[1] + ' '.join(fixed + sorted(movable)) + match[3]
        return ''.join(lines) if found == 1 else None
    left, right = normalize(planned), normalize(generated)
    return left is not None and left == right


def _observed(path):
    if not path.exists() and not path.is_symlink():
        return None
    return sha(_read(path, 4 * 1024**2))


def _install(path, old_digest, content, mode):
    _tree(path.parent)
    current = _observed(path)
    if current == sha(content):
        return
    if current != old_digest:
        raise Refused('Boot configuration changed outside credential enrollment')
    fd, name = tempfile.mkstemp(prefix='.nebulalog-grub-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if old_digest is None:
            os.link(name, path)  # Never replace a newly appeared credential.
            os.unlink(name)
        else:
            os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def enroll(state, installation_id, username, password=None, *, paths=Paths(), runner=run):
    """Resume only this installation's exact retained credential/configuration."""
    require_linux_root()
    state = Path(state)
    _tree(state)
    if (not re.fullmatch(r'[a-z][a-z0-9_-]{7,31}', username)
            or username in {'root', 'admin', 'administrator'}):
        raise Refused('Use a distinct 8–32 character GRUB recovery username')
    journal = state / 'bootloader-enrollment.json'
    destinations = {'users': paths.users, 'credential': paths.credential, 'config': paths.config}
    if journal.exists() or journal.is_symlink():
        record = json.loads(_read(journal, 12 * 1024**2))
        if (record.get('schema') != 1 or record.get('installation_id') != installation_id
                or record.get('username') != username
                or record.get('paths') != {k: str(v) for k, v in destinations.items()}
                or record.get('state') not in {'prepared', 'recovery_required', 'enrolled'}):
            raise Refused('Bootloader enrollment belongs to another installation or configuration')
    else:
        if (not isinstance(password, str) or not 14 <= len(password) <= 128
                or any(not 33 <= ord(c) <= 126 for c in password)):
            raise Refused('GRUB password requires 14–128 printable non-space ASCII characters')
        if _observed(paths.credential) is not None:
            raise Refused('An existing GRUB credential requires explicit recovery review')
        users = _read(paths.users, 65536).decode('utf-8')
        config = _read(paths.config, 4 * 1024**2).decode('utf-8')
        new = {}
        for name, source, escape in [('users', users, '\\'), ('config', config, '')]:
            superuser = 'set superusers="root"'
            credential = 'password_pbkdf2 root ' + escape + '${GRUB2_PASSWORD}'
            if source.count(superuser) != 1 or source.count(credential) != 1:
                raise Refused('Expected the stock Rocky GRUB user block')
            new[name] = source.replace(superuser, 'set superusers="' + username + '"').replace(
                credential, 'password_pbkdf2 ' + username + ' ' + escape + '${GRUB2_PASSWORD}')
        output = runner(['grub2-mkpasswd-pbkdf2', '--iteration-count=100000'],
                        input=(password + '\n' + password + '\n').encode(), timeout=120)
        matches = re.findall(r'grub\.pbkdf2\.sha512\.100000\.[A-Fa-f0-9]{128}\.[A-Fa-f0-9]{128}(?![A-Fa-f0-9])', output)
        if len(matches) != 1:
            raise Refused('GRUB did not return the expected PBKDF2 credential')
        new['credential'] = 'GRUB2_PASSWORD=' + matches[0] + '\n'
        record = {'schema': 1, 'state': 'prepared', 'installation_id': installation_id,
                  'username': username, 'paths': {k: str(v) for k, v in destinations.items()},
                  'original': {'users': users, 'config': config, 'credential': None}, 'new': new}
        atomic_json(journal, record)
    for name, path in destinations.items():
        original = record['original'][name]
        old_hash = sha(original.encode()) if original is not None else None
        allowed = {sha(record['new'][name].encode())}
        if record['state'] != 'enrolled':
            allowed.add(old_hash)
        if _observed(path) not in allowed:
            raise Refused('Boot configuration differs from retained enrollment evidence')
        if (_observed(path) == sha(record['new'][name].encode())
                and path.stat().st_mode & 0o777 != (0o755 if name == 'users' else 0o600)):
            raise Refused('Enrolled boot configuration permissions changed')
    if record['state'] == 'enrolled':
        return {'state': 'enrolled', 'username': username}
    try:
        for name, mode in [('users', 0o755), ('credential', 0o600)]:
            original = record['original'][name]
            _install(destinations[name], sha(original.encode()) if original is not None else None,
                     record['new'][name].encode(), mode)
        with tempfile.TemporaryDirectory(prefix='grub-check-', dir=state) as temporary:
            candidate = Path(temporary) / 'grub.cfg'
            runner(['grub2-mkconfig', '-o', str(candidate)], timeout=180)
            runner(['grub2-script-check', str(candidate)])
            planned = record['new']['config'].encode()
            if not _same_configuration(planned, _read(candidate, 4 * 1024**2)):
                raise Refused('GRUB regeneration changed settings beyond recovery identity')
            # The FIPS tooling moves fips=/boot= in fallback kernelopts. Accept
            # only movement of those two unique, literal arguments, then retain
            # the original order in the actual installed configuration.
            candidate.write_bytes(planned)
            runner(['grub2-script-check', str(candidate)])
        _install(paths.config, sha(record['original']['config'].encode()), record['new']['config'].encode(), 0o600)
        runner(['restorecon', str(paths.users), str(paths.credential), str(paths.config)])
        record['state'] = 'enrolled'
        atomic_json(journal, record)
        return {'state': 'enrolled', 'username': username}
    except Exception:
        record['state'] = 'recovery_required'
        atomic_json(journal, record)
        raise


def remediation_checkpoint(state, installation_id, *, paths=Paths()):
    """Read-only binding captured under initial-hardening locks before SCAP."""
    journal = Path(state) / 'bootloader-enrollment.json'
    if not journal.exists() and not journal.is_symlink():
        return None
    raw = _read(journal, 12 * 1024**2)
    record = json.loads(raw)
    if record.get('state') != 'enrolled':
        raise Refused('Complete GRUB recovery enrollment before baseline remediation')
    enroll(state, installation_id, record['username'], paths=paths)
    if _read(journal, 12 * 1024**2) != raw:
        raise Refused('GRUB enrollment changed while preparing remediation')
    return {'receipt_sha256': sha(raw), 'installation_id': installation_id}


def accept_remediation(state, checkpoint, remediation_id, policy_sha256, *, paths=Paths(), runner=run):
    """Refresh only after the locked caller verifies SCAP inputs and host health."""
    if checkpoint is None:
        return None
    require_linux_root()
    if (not re.fullmatch(r'[a-f0-9]{32}', remediation_id)
            or not re.fullmatch(r'[a-f0-9]{64}', policy_sha256)):
        raise Refused('Bound baseline remediation identity required')
    journal = Path(state) / 'bootloader-enrollment.json'
    raw = _read(journal, 12 * 1024**2)
    if sha(raw) != checkpoint['receipt_sha256']:
        raise Refused('GRUB enrollment changed during baseline remediation')
    record = json.loads(raw)
    if (record.get('state') != 'enrolled' or record.get('installation_id') != checkpoint['installation_id']
            or record.get('paths') != {'users': str(paths.users), 'credential': str(paths.credential), 'config': str(paths.config)}):
        raise Refused('GRUB remediation checkpoint differs from enrollment')
    for name, path, mode in [('users', paths.users, 0o755), ('credential', paths.credential, 0o600)]:
        if (_observed(path) != sha(record['new'][name].encode()) or path.stat().st_mode & 0o777 != mode):
            raise Refused('Baseline remediation changed the GRUB recovery identity or credential')
    config = _read(paths.config, 4 * 1024**2).decode('utf-8')
    username = record['username']
    if (config.count('set superusers=') != 1 or config.count('set superusers="' + username + '"') != 1
            or config.count('password_pbkdf2 ') != 1
            or config.count('password_pbkdf2 ' + username + ' ${GRUB2_PASSWORD}') != 1
            or paths.config.stat().st_mode & 0o777 != 0o600):
        raise Refused('Remediated GRUB configuration lost the enrolled recovery identity')
    runner(['grub2-script-check', str(paths.config)])
    refresh = {'remediation_id': remediation_id, 'policy_sha256': policy_sha256,
               'previous_config_sha256': sha(record['new']['config'].encode()), 'config_sha256': sha(config.encode())}
    record['new']['config'] = config
    record['last_baseline_refresh'] = refresh
    atomic_json(journal, record)
    return refresh
