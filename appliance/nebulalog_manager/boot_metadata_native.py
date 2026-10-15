"""Read-only, vendor-pinned evidence for two native reboot metadata effects.

This module observes; it never enrolls, changes a database, or accepts drift.
The caller must independently authenticate ``database`` through the retained
AIDE chain and bind the returned proof to a full strict AIDE scan. Old scalar
values come ONLY from those database rows. Stable authority deliberately has
no historical target rows: accepted package updates can change those rows.
"""
from __future__ import annotations

import base64
import binascii
import copy
import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from . import ordinary_boot_metadata as db
from .common import Refused, require_linux_root, run
from .host_job_storage import digest, exact

KIND = 'rocky-boot-metadata-v1'
SYSTEMD = 'systemd-0:252-67.el9_8.6.rocky.0.1.x86_64'
LIBACL = '/usr/lib64/libacl.so.1.2.2400'
SERVICE = '/usr/lib/systemd/system/systemd-tmpfiles-setup.service'
WRITERS = {
    '/usr/bin/systemd-tmpfiles': ('b5c8e357413ecfd4d33a62d3149aabff6f49dc74655bc895ced9b7b6aa2d9d1c', SYSTEMD, 0o755),
    '/usr/lib/tmpfiles.d/etc.conf': ('1190049ba66a72efbb88acb4c6a2ef89587306ae567a3425ded29a0dcf4610f8', SYSTEMD, 0o644),
    '/usr/lib/tmpfiles.d/rootfiles.conf': ('b2858a8e0ae109193e28d96f7fd8a8cfa1b42aad1766f5932814321dd821b7c8', 'rootfiles-0:8.1-35.el9.noarch', 0o644),
    SERVICE: ('47e78c5975ba44930fde06bead57f7113e16f6c69c77503556a192f688127760', SYSTEMD, 0o644),
    LIBACL: ('65c479508b966795f7f53accf0b383643c74e02c66b29f85c70849ca8a763538', 'libacl-0:2.4.0-1.el9_8.x86_64', 0o755),
}
ACL_LINK = '/usr/lib64/libacl.so.1'
ACL_OWNER = 'libacl-0:2.4.0-1.el9_8.x86_64'
# Exact effective native configuration, including otherwise unrelated files:
# an added rule could operate recursively on a qualified path. No generic
# override or "unrelated" file exemption is supported. Future RPM/config
# changes require a separately reviewed authority migration.
CONFIGURATION_PINS = {'/etc/tmpfiles.d': {'nebulalog-status.conf': 'd56e174cd7b398c211bd966516ead0cbc2ac37110ad4b11d1621bb17ca6346aa'},
 '/run/tmpfiles.d': {'static-nodes.conf': '7abd192fac309b2882dafece6af9433531a67fc2221f42690fc6100a62728c0e'},
 '/usr/local/lib/tmpfiles.d': None,
 '/usr/lib/tmpfiles.d': {'aide.conf': '2c21a355865df1ee7fde4750c5ee13a54b83678de2ae1e028d1a01b092fbfce2',
                         'audit.conf': 'd4ea0b752525c573cd144461ed3ac5c4e86d19501150df278add839e758c19c4',
                         'criu.conf': 'd40c7153756d170c4d68ac57598236a011c177ac41a1125813f8b2e16dc15c1a',
                         'cronie-anacron.conf': '30c0ca5cdb48ed1f03c44e21efd110389cc191dc36e26833337d4ea79ef64ffd',
                         'cronie.conf': 'fe15680575e2ea8ae35602b4c7ee69685e9e84fb15c5c4bcc4010443de89bbd7',
                         'cryptsetup.conf': 'd6bb4b689200c2348945700a6b0dad5df92bc2015860d15f36a25590814d77b0',
                         'dnf.conf': '365360de240de77d77843de09d14272cb91fe853400473178f44903de4949b68',
                         'etc.conf': '1190049ba66a72efbb88acb4c6a2ef89587306ae567a3425ded29a0dcf4610f8',
                         'home.conf': '135d4d63b7a841a921f5c2ddc0c2c38b72286070097883196bd58375bd1674e2',
                         'httpd.conf': '29b9a9dc9cbe9778d2409ca74220877c01df21ad4c6baf6233c6cebe2f0c6bc7',
                         'journal-nocow.conf': 'c53a809900502c8cce9a2dd1a37318aad2a3988592c4493f2c0c2bfd49c2b656',
                         'legacy.conf': 'a80ef4f7798e295347a49cc4ea1009c3e0f0e368f82a7dad78fec509768f7a3b',
                         'libselinux.conf': 'afe23890fb2e12e6756e5d81bad3c3da33f38a95d072731c0422fbeb0b1fa1fc',
                         'lvm2.conf': '670a21702d32d3a14a15494d8419aea5f2de9ca058ba9da46dd951492cf18411',
                         'man-db.conf': '37c7cc3806c28affbca0420225ebde2425923193de32f18452effa0a255f6504',
                         'mdadm.conf': '6382e48282297663adbe1b1db55c1554d27badd8ab0ee5a4d2e1bbf880f62af3',
                         'pam.conf': 'e3624a553821869612788f30ba9f3addfbcdce807084f7bb2afeb1da4ba22abe',
                         'podman.conf': '365d5b16e4da09af560b143fb84756940db616ee1d175f76925bccd9529788f7',
                         'provision.conf': 'aec58a0437f01a8abe5b594316639ed6b32c5b51587ddf2aa8d7ef1ce505da3f',
                         'rootfiles.conf': 'b2858a8e0ae109193e28d96f7fd8a8cfa1b42aad1766f5932814321dd821b7c8',
                         'rsyslog.conf': 'b41fdcd32719feba05c9f069959180410c2edfd51e02c199c2d5d55be238bc69',
                         'selinux-policy.conf': '8a0beca7f576064bfe85859d53e85dfc31157974115cac99b4e52ae31b77b185',
                         'setup.conf': 'b1a7958d03497b0e231f8f14ee501ebb4d15a822d096c180226af5429df15f78',
                         'static-nodes-permissions.conf': 'c71eaa456734db96094d0090f7ff8e3847c4da9a3da54810cbdcc571026fdce6',
                         'sudo.conf': '8b5ca911b7e0db3ca947da704ebd5acd95ae3f12832a3a2569082600600008be',
                         'systemd-nologin.conf': 'b19b25702e003a96bf635250751c58824531834d0bcd5c98575f609125b1b148',
                         'systemd-pstore.conf': 'cdb3efb34ea12ef62140dc86ffbe90045729f3e8227698848e44bed4fdd5fe2f',
                         'systemd-tmp.conf': '5814667bc3c0c5064405446a88b49456f4ddae00a5338f645daaa30ff8f9fbbe',
                         'systemd.conf': 'a5330acff881872bd46c59b4bba687172477241feeb0138ce3b519dc2ea8cef5',
                         'tmp.conf': 'af72ed4f31d787b16c2ea01a7132d7a389fb81f9e656a7e1208b870c634acd84',
                         'tpm2-tss-fapi.conf': '50d70673c1902a6e6427a28757ed5b3dc19e9718a96f5aa454a5ee3e71e4fce4',
                         'udisks2.conf': '27a7496ddf7e465995059a0410d47387b9e82ccd7aac9c3763f2ac6659ca9c21',
                         'var.conf': '285585556332d5f014914358d1053d8af48617e01eccab9c49666e14459e6306',
                         'x11.conf': '499513ddbf7dfb7fb0492d948e7e9030ea08404396c48ec1b3d3b2ec6edce56d'}}
MOUNT_OPTIONS = 'rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro'
CONFIGURATION_MODES = {'/usr/lib/tmpfiles.d/audit.conf': 0o640,
                       '/usr/lib/tmpfiles.d/lvm2.conf': 0o444}
CREDENTIALS = '/run/credentials/systemd-tmpfiles-setup.service'
EXECUTION = {'search_path': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin',
             'absent': ['/usr/local/sbin/systemd-tmpfiles', '/usr/local/bin/systemd-tmpfiles',
                        '/usr/sbin/systemd-tmpfiles'], 'resolved': '/usr/bin/systemd-tmpfiles'}
MAX_FILE = 64 * 1024 * 1024
MAX_CONFIG = 1024 * 1024
ROW_FIELDS = {'kind', 'mode', 'uid', 'gid', 'bytes', 'inode', 'nlink', 'ctime_s', 'mtime_s',
              'attributes', 'target', 'sha512', 'acl', 'selinux', 'xattrs'}
SERVICE_FIELDS = {'invocation_id', 'start_us', 'end_us', 'start_monotonic_us', 'end_monotonic_us',
                  'active_monotonic_us', 'result', 'exit_code', 'exit_status', 'credentials'}
SNAPSHOT_FIELDS = {'schema', 'boot_id', 'authority', 'service', 'rows', 'observed_at_ns', 'uptime_us'}


def refuse(reason):
    raise Refused('boot_metadata_native_' + reason)


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        refuse('invalid_boot_id')


def _integer(value, maximum=(1 << 63) - 1, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        refuse('invalid_integer')


def _sha(value):
    if not isinstance(value, str) or not db.SHA.fullmatch(value):
        refuse('invalid_digest')


def _base64(value):
    if not isinstance(value, str) or len(value) > 4 * ((db.MAX_VALUE + 2) // 3):
        refuse('invalid_base64')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        refuse('invalid_base64')
    if len(raw) > db.MAX_VALUE or base64.b64encode(raw).decode() != value:
        refuse('invalid_base64')
    return raw


def _row(value, path, *, live):
    exact(value, ROW_FIELDS | ({'ctime_ns', 'mtime_ns'} if live else set()))
    link, efi = path == '/etc/os-release', path in db.EFI
    mask = db.SYMLINK_MASK if link else db.EFI_MASK if efi else db.REGULAR_MASK
    for key in ('mode', 'uid', 'gid', 'bytes', 'inode', 'nlink', 'ctime_s', 'mtime_s', 'attributes'):
        _integer(value[key])
    if (value['kind'] != ('symlink' if link else 'file') or value['attributes'] != mask
            or value['uid'] != 0 or value['gid'] != 0 or value['nlink'] != 1 or not value['inode']
            or value['bytes'] > MAX_FILE or value['mode'] > 0o7777
            or link and (value['mode'] != 0o777 or value['target'] != '../usr/lib/os-release' or value['sha512'] is not None)
            or not link and (value['mode'] & 0o7022 or value['target'] is not None
                             or not isinstance(value['sha512'], str) or not re.fullmatch('[a-f0-9]{128}', value['sha512']))):
        refuse('unqualified_row')
    if link or efi:
        if value['acl'] is not None:
            refuse('unexpected_acl')
    else:
        exact(value['acl'], {'access', 'default'})
        if value['acl']['default'] is not None or not _base64(value['acl']['access']) or b'\0' in _base64(value['acl']['access']):
            refuse('invalid_acl')
    if not isinstance(value['xattrs'], dict) or len(value['xattrs']) > db.MAX_XATTRS:
        refuse('invalid_xattrs')
    for name, data in value['xattrs'].items():
        if not isinstance(name, str) or not 0 < len(name.encode('utf-8')) <= 255 or '\0' in name:
            refuse('invalid_xattr_name')
        _base64(data)
    label = _base64(value['selinux'])
    if not label or b'\0' in label or value['xattrs'].get('security.selinux') != base64.b64encode(label + b'\0').decode():
        refuse('security_label_mismatch')
    if live:
        for key in ('ctime', 'mtime'):
            _integer(value[key + '_ns'])
            if value[key + '_ns'] // 1_000_000_000 != value[key + '_s']:
                refuse('inconsistent_time_precision')
    return value


def _description(value, *, sha256=None, mode=None, link=None):
    exact(value, {'kind', 'uid', 'gid', 'mode', 'xattrs_sha256'} | ({'target'} if link else {'sha256', 'bytes'}))
    if (value['kind'] != ('symlink' if link else 'file') or type(value['uid']) is not int
            or type(value['gid']) is not int or value['uid'] != 0 or value['gid'] != 0
            or type(value['mode']) is not int or value['mode'] != mode):
        refuse('unsafe_authority_file')
    _sha(value['xattrs_sha256'])
    if link:
        if value['target'] != link:
            refuse('changed_library_link')
    else:
        _integer(value['bytes'], MAX_FILE)
        if value['sha256'] != sha256:
            refuse('unqualified_authority_bytes')


def validate_authority(value):
    """Check retained stable authority; no host read or adoption occurs."""
    exact(value, {'schema', 'writers', 'configuration', 'mount', 'targets', 'execution'})
    if type(value['schema']) is not int or value['schema'] != 1 or value['targets'] != sorted(db.TARGETS):
        refuse('invalid_authority')
    if value['execution'] != EXECUTION:
        refuse('unqualified_executable_resolution')
    exact(value['writers'], set(WRITERS) | {ACL_LINK})
    for path, (checksum, owner, mode) in WRITERS.items():
        item = value['writers'][path]
        exact(item, {'owner', 'description'})
        if item['owner'] != owner:
            refuse('unqualified_vendor_owner')
        _description(item['description'], sha256=checksum, mode=mode)
    item = value['writers'][ACL_LINK]
    exact(item, {'owner', 'description'})
    if item['owner'] != ACL_OWNER:
        refuse('unqualified_vendor_owner')
    _description(item['description'], mode=0o777, link=Path(LIBACL).name)
    exact(value['configuration'], CONFIGURATION_PINS)
    for directory, pins in CONFIGURATION_PINS.items():
        actual = value['configuration'][directory]
        if pins is None:
            if actual is not None:
                refuse('unexpected_configuration_directory')
        else:
            exact(actual, pins)
            for name, checksum in pins.items():
                _description(actual[name], sha256=checksum,
                             mode=CONFIGURATION_MODES.get(directory + '/' + name, 0o644))
    mount = value['mount']
    exact(mount, {'target', 'fstype', 'options', 'uuid', 'partuuid', 'fsroot'})
    if (mount['target'] != '/boot/efi' or mount['fstype'] != 'vfat' or mount['options'] != MOUNT_OPTIONS
            or mount['fsroot'] != '/' or not isinstance(mount['uuid'], str)
            or not re.fullmatch('[A-F0-9]{4}-[A-F0-9]{4}', mount['uuid'])):
        refuse('unqualified_efi_mount')
    _uuid(mount['partuuid'])
    return value


def authority(snapshot):
    return copy.deepcopy(validate_snapshot(snapshot)['authority'])


def stable_snapshot(snapshot):
    """Comparable observation; discard only the two advancing read clocks."""
    value = copy.deepcopy(validate_snapshot(snapshot))
    del value['observed_at_ns']
    del value['uptime_us']
    return value


def validate_snapshot(value):
    exact(value, SNAPSHOT_FIELDS)
    if type(value['schema']) is not int or value['schema'] != 1:
        refuse('invalid_snapshot')
    _uuid(value['boot_id'])
    validate_authority(value['authority'])
    _integer(value['observed_at_ns'])
    _integer(value['uptime_us'])
    service = value['service']
    exact(service, SERVICE_FIELDS)
    if (not isinstance(service['invocation_id'], str) or not re.fullmatch('[a-f0-9]{32}', service['invocation_id'])
            or service['result'] != 'success' or type(service['exit_code']) is not int or service['exit_code'] != 1
            or type(service['exit_status']) is not int or service['exit_status'] != 0 or service['credentials'] != []):
        refuse('tmpfiles_service_not_qualified')
    for key in ('start_us', 'end_us', 'start_monotonic_us', 'end_monotonic_us', 'active_monotonic_us'):
        _integer(service[key], minimum=1)
    if (not service['start_us'] <= service['end_us'] <= value['observed_at_ns'] // 1000
            or not service['start_monotonic_us'] <= service['end_monotonic_us'] <= service['active_monotonic_us'] <= value['uptime_us']
            or service['start_monotonic_us'] > 300_000_000
            or service['end_monotonic_us'] - service['start_monotonic_us'] > 60_000_000
            or abs((service['end_us'] - service['start_us']) -
                   (service['end_monotonic_us'] - service['start_monotonic_us'])) > 1_000_000):
        refuse('tmpfiles_interval_not_boot_bound')
    exact(value['rows'], db.TARGETS)
    for path, row in value['rows'].items():
        _row(row, path, live=True)
        if row['ctime_ns'] > value['observed_at_ns']:
            refuse('future_target_timestamp')
    return value


def transition(stable, after, *, database, source_boot_id):
    """Narrow proof only; caller must authenticate DB and perform full AIDE scan.

    A plain parsed DB has no ``source`` and is refused. This structural check
    cannot replace the caller's chain authentication; the exact source is bound
    into the result for that caller's retained-plan revalidation.
    """
    validate_authority(stable); validate_snapshot(after); _uuid(source_boot_id)
    if after['authority'] != stable:
        refuse('authority_changed')
    exact(database, {'schema', 'format', 'database_sha256', 'entry_count', 'rows', 'source'})
    if type(database['schema']) is not int or database['schema'] != 1 or database['format'] != db.FORMAT:
        refuse('invalid_database_format')
    _sha(database['database_sha256'])
    _integer(database['entry_count'], db.MAX_ROWS, len(db.TARGETS))
    exact(database['rows'], db.TARGETS)
    if not isinstance(database['source'], dict) or not database['source']:
        refuse('missing_database_authority')
    changes = []
    for path in sorted(db.TARGETS):
        old = _row(database['rows'][path], path, live=False)
        current = after['rows'][path]
        new = {key: current[key] for key in ROW_FIELDS}
        fields = {key for key in ROW_FIELDS if old[key] != new[key]}
        if not fields:
            continue
        attribute = 'inode' if path in db.EFI else 'ctime_s'
        if fields != {attribute} or source_boot_id == after['boot_id']:
            refuse('unqualified_target_change')
        if attribute == 'ctime_s':
            service = after['service']
            if (not old['ctime_s'] < new['ctime_s'] or
                    not service['start_us'] * 1000 <= current['ctime_ns'] <= service['end_us'] * 1000 + 999):
                refuse('ctime_outside_successful_boot_service')
        label = 'inode' if attribute == 'inode' else 'ctime'
        summary = 'f = ... ..i.. ..  ' if label == 'inode' else 'l.= ... .c..  ..  ' if path == '/etc/os-release' else 'f = ... .c......  '
        db.validate_change_summary(path, summary, row=old, attribute=label)
        changes.append({'path': path, 'attribute': label, 'before': old[attribute], 'after': new[attribute], 'summary': summary})
    return {'schema': 1, 'kind': KIND, 'authority_sha256': digest(stable),
            'database_sha256': database['database_sha256'], 'database_source': copy.deepcopy(database['source']),
            'database_rows_sha256': digest(database['rows']), 'source_boot_id': source_boot_id,
            'boot_id': after['boot_id'], 'snapshot_sha256': digest(after), 'changes': changes}


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _parents(path):
    values = {}
    for parent in Path(path).parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            refuse('unsafe_parent')
        values[str(parent)] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    return values


def _xattrs(path):
    names = os.listxattr(path, follow_symlinks=False)
    if len(names) > db.MAX_XATTRS or len(set(names)) != len(names):
        refuse('xattr_count')
    values = {}
    for name in sorted(names):
        if not 0 < len(name.encode('utf-8')) <= 255 or '\0' in name:
            refuse('invalid_xattr_name')
        raw = os.getxattr(path, name, follow_symlinks=False)
        if len(raw) > db.MAX_VALUE:
            refuse('xattr_too_large')
        values[name] = raw
    return values


def _file(path, maximum=MAX_FILE):
    """No-follow stable file observation used for all executable/config pins."""
    path = Path(path)
    parents, before = _parents(path), path.lstat()
    value = {'uid': before.st_uid, 'gid': before.st_gid, 'mode': stat.S_IMODE(before.st_mode)}
    if before.st_uid != 0 or before.st_gid != 0 or before.st_nlink != 1:
        refuse('unsafe_file_owner_or_links')
    if stat.S_ISLNK(before.st_mode):
        value.update(kind='symlink', target=os.readlink(path))
    elif stat.S_ISREG(before.st_mode) and not before.st_mode & 0o7022 and before.st_size <= maximum:
        checksum, size = hashlib.sha256(), 0
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if _identity(os.fstat(fd)) != _identity(before):
                refuse('file_changed_before_open')
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                size += len(block)
                if size > maximum:
                    refuse('file_too_large')
                checksum.update(block)
            if _identity(os.fstat(fd)) != _identity(before):
                refuse('file_changed_during_read')
        finally:
            os.close(fd)
        value.update(kind='file', bytes=size, sha256=checksum.hexdigest())
    else:
        refuse('unsupported_file')
    value['xattrs_sha256'] = digest({name: hashlib.sha256(raw).hexdigest() for name, raw in _xattrs(path).items()})
    if _identity(path.lstat()) != _identity(before) or _parents(path) != parents:
        refuse('file_changed_during_read')
    return value


class _Acl:
    """Pinned native libacl; same read-only access ACL calls as vendor AIDE."""
    def __init__(self):
        _description(_file(LIBACL), sha256=WRITERS[LIBACL][0], mode=0o755)
        try:
            self.library = ctypes.CDLL(LIBACL, use_errno=True)
            self.library.acl_get_fd.argtypes = [ctypes.c_int]
            self.library.acl_get_fd.restype = ctypes.c_void_p
            self.library.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
            self.library.acl_to_text.restype = ctypes.c_void_p
            self.library.acl_free.argtypes = [ctypes.c_void_p]
            self.library.acl_free.restype = ctypes.c_int
        except (OSError, AttributeError):
            refuse('acl_library_unavailable')
        _description(_file(LIBACL), sha256=WRITERS[LIBACL][0], mode=0o755)

    def access(self, fd, *, unsupported=False):
        ctypes.set_errno(0)
        acl = self.library.acl_get_fd(fd)
        if not acl:
            if unsupported and ctypes.get_errno() in {errno.ENOSYS, errno.ENOTSUP}:
                return None
            refuse('acl_read_failed')
        text = None
        try:
            length = ctypes.c_ssize_t()
            text = self.library.acl_to_text(acl, ctypes.byref(length))
            if not text or not 0 < length.value <= db.MAX_VALUE:
                refuse('acl_text_failed')
            raw = ctypes.string_at(text, length.value)
            if b'\0' in raw:
                refuse('invalid_acl_text')
            if unsupported:
                refuse('unexpected_filesystem_acl_support')
            return {'access': base64.b64encode(raw).decode(), 'default': None}
        finally:
            if text:
                self.library.acl_free(text)
            self.library.acl_free(acl)


def _target(path, acl):
    parents, before = _parents(path), Path(path).lstat()
    link, efi = path == '/etc/os-release', path in db.EFI
    if (not (stat.S_ISLNK(before.st_mode) if link else stat.S_ISREG(before.st_mode))
            or before.st_nlink != 1 or before.st_uid != 0 or before.st_gid != 0
            or before.st_size > MAX_FILE):
        refuse('unsafe_target')
    row = {'kind': 'symlink' if link else 'file', 'mode': stat.S_IMODE(before.st_mode),
           'uid': before.st_uid, 'gid': before.st_gid, 'bytes': before.st_size,
           'inode': before.st_ino, 'nlink': before.st_nlink,
           'ctime_s': before.st_ctime_ns // 1_000_000_000, 'mtime_s': before.st_mtime_ns // 1_000_000_000,
           'ctime_ns': before.st_ctime_ns, 'mtime_ns': before.st_mtime_ns,
           'attributes': db.SYMLINK_MASK if link else db.EFI_MASK if efi else db.REGULAR_MASK,
           'target': os.readlink(path) if link else None, 'sha512': None, 'acl': None}
    if not link:
        checksum, size = hashlib.sha512(), 0
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if _identity(os.fstat(fd)) != _identity(before):
                refuse('target_changed_before_open')
            while True:
                raw = os.read(fd, 65536)
                if not raw:
                    break
                size += len(raw)
                if size > MAX_FILE:
                    refuse('target_too_large')
                checksum.update(raw)
            row['sha512'] = checksum.hexdigest()
            row['acl'] = acl.access(fd, unsupported=efi)
            if size != before.st_size or _identity(os.fstat(fd)) != _identity(before):
                refuse('target_changed_during_read')
        finally:
            os.close(fd)
    attributes = _xattrs(path)
    label = attributes.get('security.selinux', b'')
    if not label.endswith(b'\0') or b'\0' in label[:-1]:
        refuse('missing_native_security_label')
    row['selinux'] = base64.b64encode(label[:-1]).decode()
    row['xattrs'] = {name: base64.b64encode(raw).decode() for name, raw in attributes.items()}
    if _identity(Path(path).lstat()) != _identity(before) or _parents(path) != parents:
        refuse('target_changed_during_read')
    return _row(row, path, live=True)


def _configuration():
    result = {}
    for directory, pins in CONFIGURATION_PINS.items():
        path = Path(directory)
        _parents(path)
        if not path.exists() and not path.is_symlink():
            if pins is not None:
                refuse('missing_configuration_directory')
            result[directory] = None
            continue
        info = path.lstat()
        if (pins is None or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_mode & 0o022):
            refuse('unsafe_configuration_directory')
        names = sorted(item.name for item in path.iterdir())
        if names != sorted(pins):
            refuse('configuration_inventory_changed')
        result[directory] = {name: _file(path / name, MAX_CONFIG) for name in names}
        if sorted(item.name for item in path.iterdir()) != names:
            refuse('configuration_inventory_changed')
    return result


def _mount(runner):
    def get(path):
        raw = runner(['/usr/bin/findmnt', '--json', '--target', path, '--output',
                      'TARGET,SOURCE,FSTYPE,OPTIONS,UUID,PARTUUID,FSROOT'])
        if not isinstance(raw, str) or len(raw) > 16384:
            refuse('mount_output_bounds')
        try:
            value = json.loads(raw)
        except ValueError:
            refuse('invalid_mount_output')
        exact(value, {'filesystems'})
        if not isinstance(value['filesystems'], list) or len(value['filesystems']) != 1:
            refuse('ambiguous_mount')
        value = value['filesystems'][0]
        exact(value, {'target', 'source', 'fstype', 'options', 'uuid', 'partuuid', 'fsroot'})
        if not isinstance(value['source'], str) or not re.fullmatch(r'/dev/[a-zA-Z0-9_./\-]+', value['source']):
            refuse('non_block_efi_mount')
        return value
    expected = get('/boot/efi')
    device = Path('/boot/efi').stat().st_dev
    for path in db.EFI:
        if get(path) != expected or Path(path).lstat().st_dev != device:
            refuse('efi_target_mount_changed')
    return {key: value for key, value in expected.items() if key != 'source'}


def _authority(runner):
    for path in EXECUTION['absent']:
        _parents(path)
        if os.path.lexists(path):
            refuse('shadowed_tmpfiles_executable')
    writers = {}
    for path in sorted(set(WRITERS) | {ACL_LINK}):
        owner = runner(['/usr/bin/rpm', '--query', '--file', path, '--queryformat',
                        '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n']).strip()
        writers[path] = {'owner': owner, 'description': _file(path)}
    return validate_authority({'schema': 1, 'writers': writers, 'configuration': _configuration(),
                               'execution': copy.deepcopy(EXECUTION),
                               'mount': _mount(runner), 'targets': sorted(db.TARGETS)})


def _timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Z][a-z]{2} \d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6} UTC', value):
        refuse('invalid_service_timestamp')
    try:
        instant = datetime.strptime(value, '%a %Y-%m-%d %H:%M:%S.%f UTC').replace(tzinfo=timezone.utc)
    except ValueError:
        refuse('invalid_service_timestamp')
    delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _service(runner):
    props = ('Type', 'RemainAfterExit', 'Result', 'ExecMainCode', 'ExecMainStatus', 'InvocationID',
             'FragmentPath', 'DropInPaths', 'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecCondition',
             'ExecMainStartTimestamp', 'ExecMainExitTimestamp', 'ExecMainStartTimestampMonotonic',
             'ExecMainExitTimestampMonotonic', 'ActiveEnterTimestampMonotonic', 'Environment',
             'EnvironmentFiles', 'RootDirectory', 'RootImage', 'User', 'Group', 'NeedDaemonReload', 'ExecSearchPath')
    raw = runner(['/usr/bin/systemctl', '--timestamp=us', 'show', 'systemd-tmpfiles-setup.service'] +
                 ['--property=' + prop for prop in props])
    if not isinstance(raw, str) or len(raw) > 32768:
        refuse('service_output_bounds')
    values = {}
    for line in raw.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key in values or key not in props:
            refuse('invalid_service_output')
        values[key] = value
    for key, expected in {'Type': 'oneshot', 'RemainAfterExit': 'yes', 'Result': 'success',
                          'ExecMainCode': '1', 'ExecMainStatus': '0', 'FragmentPath': SERVICE,
                          'NeedDaemonReload': 'no', 'DropInPaths': '', 'Environment': '',
                          'RootDirectory': '', 'RootImage': '', 'User': '', 'Group': '', 'ExecSearchPath': ''}.items():
        if values.get(key) != expected:
            refuse('changed_service_execution')
    for key in ('EnvironmentFiles', 'ExecStartPre', 'ExecStartPost', 'ExecCondition'):
        if values.get(key, ''):
            refuse('additional_service_execution')
    expression = (r'\{ path=systemd-tmpfiles ; argv\[\]=systemd-tmpfiles --create --remove --boot --exclude-prefix=/dev ; '
                  r'ignore_errors=no ; start_time=\[(.*?)\] ; stop_time=\[(.*?)\] ; pid=([1-9][0-9]*) ; code=exited ; status=0 \}')
    match = re.fullmatch(expression, values.get('ExecStart', ''))
    if not match or match.group(1) != values.get('ExecMainStartTimestamp') or match.group(2) != values.get('ExecMainExitTimestamp'):
        refuse('unqualified_service_command')
    credential_path = Path(CREDENTIALS)
    _parents(credential_path)
    info = credential_path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022
            or list(credential_path.iterdir())):
        refuse('service_credentials_present')
    def integer(key):
        value = values.get(key, '')
        if not re.fullmatch('[1-9][0-9]{0,18}', value):
            refuse('invalid_service_monotonic_time')
        return int(value)
    return {'invocation_id': values.get('InvocationID'),
            'start_us': _timestamp(values.get('ExecMainStartTimestamp')),
            'end_us': _timestamp(values.get('ExecMainExitTimestamp')),
            'start_monotonic_us': integer('ExecMainStartTimestampMonotonic'),
            'end_monotonic_us': integer('ExecMainExitTimestampMonotonic'),
            'active_monotonic_us': integer('ActiveEnterTimestampMonotonic'),
            'result': 'success', 'exit_code': 1, 'exit_status': 0, 'credentials': []}


def capture(*, runner=run):
    """Observe native state without default-kernel assumptions or any writes."""
    require_linux_root()
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    stable, service = _authority(runner), _service(runner)
    acl = _Acl()
    rows = {path: _target(path, acl) for path in sorted(db.TARGETS)}
    if (Path('/proc/sys/kernel/random/boot_id').read_text().strip() != boot_id
            or _service(runner) != service or _authority(runner) != stable
            or any(_target(path, acl) != value for path, value in rows.items())):
        refuse('observation_changed_during_capture')
    return validate_snapshot({'schema': 1, 'boot_id': boot_id, 'authority': stable, 'service': service,
                              'rows': rows, 'observed_at_ns': time.time_ns(),
                              'uptime_us': time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1000})
