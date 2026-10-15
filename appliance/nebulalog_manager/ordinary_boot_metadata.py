"""Strict historical rows from the pinned AIDE database, never drift acceptance.

Rocky aide-0.19.2-5.el9_8.1 source (db_file.c, attributes.h, util.c and
report.c) defines this format. The signed SRPM SHA-256 is
1d2d3d1591df6f3f79d7bf0a01dbfc8d405712aa9577f2d75a431206681b019a.
Only the fixed policy's 15-column, single-member gzip output is supported.
Times in that format are integer seconds: no nanosecond precision is invented.

parse_database checks bytes against a supplied digest; that alone is NOT an
acceptance authority. read_accepted_database independently reads the existing
verified AIDE chain and binds its exact input, including an explicitly owned
already-copied CAS output. Neither API measures or adopts the current files,
changes a database, migrates an enrollment, or authorizes metadata drift.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime
import hashlib
import re
import stat
import zlib

from .common import Refused
from .host_job_storage import digest

FORMAT = 'rocky-aide-0.19.2-static-v1'
FIELDS = ('name', 'lname', 'perm', 'uid', 'gid', 'size', 'ctime', 'mtime',
          'inode', 'lcount', 'attr', 'acl', 'sha512', 'selinux', 'xattrs')
SPEC = b'@@db_spec ' + ' '.join(FIELDS).encode()
TMPFILES = ('/etc/issue', '/etc/locale.conf', '/etc/nsswitch.conf', '/etc/os-release',
            '/root/.bash_logout', '/root/.bash_profile', '/root/.bashrc',
            '/root/.cshrc', '/root/.tcshrc')
EFI = ('/boot/efi/EFI/BOOT/BOOTX64.EFI', '/boot/efi/EFI/BOOT/fbx64.efi',
       '/boot/efi/EFI/rocky/BOOTX64.CSV', '/boot/efi/EFI/rocky/grub.cfg',
       '/boot/efi/EFI/rocky/grubx64.efi', '/boot/efi/EFI/rocky/mmx64.efi',
       '/boot/efi/EFI/rocky/shim.efi', '/boot/efi/EFI/rocky/shimx64-rocky.efi',
       '/boot/efi/EFI/rocky/shimx64.efi')
TARGETS = frozenset(TMPFILES + EFI)
MAX_COMPRESSED = 128 * 1024 * 1024
MAX_UNCOMPRESSED = 128 * 1024 * 1024
MAX_LINE = 256 * 1024
MAX_ROWS = 250000
MAX_XATTRS = 256
MAX_VALUE = 65536
MAX_PATH = 4096
CHUNK = 65536
SHA = re.compile(r'[a-f0-9]{64}\Z')
DECIMAL = re.compile(rb'(?:0|[1-9][0-9]{0,19})\Z')
OCTAL = re.compile(rb'(?:0|[1-7][0-7]{0,6})\Z')
UNSAFE = frozenset(b' <>"#%{}|\\^~[]`@:\x1b\',')
# Bit positions are the vendor ATTRIBUTE enum, not the column positions.
ATTR = {'filename': 1 << 0, 'linkname': 1 << 1, 'perm': 1 << 2,
        'uid': 1 << 3, 'gid': 1 << 4, 'size': 1 << 5, 'ctime': 1 << 7,
        'mtime': 1 << 8, 'inode': 1 << 9, 'linkcount': 1 << 11,
        'acl': 1 << 21, 'sha512': 1 << 31, 'selinux': 1 << 32,
        'xattrs': 1 << 33, 'ftype': 1 << 35}
KNOWN_MASK = sum(ATTR.values())
REGULAR_MASK = KNOWN_MASK & ~ATTR['linkname']
EFI_MASK = REGULAR_MASK & ~ATTR['acl']
SYMLINK_MASK = KNOWN_MASK & ~(ATTR['sha512'] | ATTR['acl'])


def refuse(reason):
    raise Refused('ordinary_boot_metadata_' + reason)


def _number(raw, maximum=(1 << 63) - 1, *, octal=False):
    if not (OCTAL if octal else DECIMAL).fullmatch(raw):
        refuse('noncanonical_number')
    value = int(raw, 8 if octal else 10)
    if value > maximum:
        refuse('number_out_of_bounds')
    return value


def _encode(raw):
    return b''.join(('%%%02X' % b).encode() if b in UNSAFE or not 32 <= b < 127
                    else bytes((b,)) for b in raw)


def _string(raw, *, maximum=MAX_PATH):
    if not raw or len(raw) > maximum * 3:
        refuse('string_out_of_bounds')
    result = bytearray()
    position = 0
    while position < len(raw):
        if raw[position] == 37:
            token = raw[position + 1:position + 3]
            if len(token) != 2 or not re.fullmatch(rb'[0-9A-F]{2}', token):
                refuse('invalid_escape')
            result.append(int(token, 16)); position += 3
        else:
            result.append(raw[position]); position += 1
    value = bytes(result)
    if len(value) > maximum or b'\0' in value or _encode(value) != raw:
        refuse('noncanonical_string')
    return value


def _filename(raw):
    value = _string(raw)
    if (not value.startswith(b'/') or value == b'/'
            or any(part in (b'', b'.', b'..') for part in value.split(b'/')[1:])):
        refuse('invalid_filename')
    return value


def _link(raw):
    if raw == b'0':
        return None
    if raw == b'0-':
        return b''
    encoded = raw[1:] if raw.startswith(b'00') else raw
    value = _string(encoded)
    if ((b'0' if value.startswith(b'0') else b'') + _encode(value)) != raw:
        refuse('noncanonical_link')
    return value


def _base64(raw, *, length=None):
    if raw == b'0':
        return None
    if not raw or len(raw) > ((MAX_VALUE + 2) // 3) * 4:
        refuse('encoded_value_out_of_bounds')
    try:
        value = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error):
        refuse('invalid_base64')
    if (base64.b64encode(value) != raw or len(value) > MAX_VALUE
            or length is not None and len(value) != length):
        refuse('noncanonical_base64')
    return value


def _acl(raw):
    if raw == b'0':
        return None
    values = raw.split(b',')
    if len(values) != 3 or values[0] != b'POSIX':
        refuse('invalid_acl')
    access, default = (_base64(value) for value in values[1:])
    if any(value is not None and (not value or b'\0' in value) for value in (access, default)):
        refuse('invalid_acl')
    return {'access': access, 'default': default}


def _xattrs(raw):
    parts = raw.split(b',')
    count = _number(parts[0], MAX_XATTRS)
    if len(parts) != 1 + 2 * count:
        refuse('invalid_xattr_count')
    values = {}
    for offset in range(1, len(parts), 2):
        name = _string(parts[offset], maximum=255)
        if name in values:
            refuse('duplicate_xattr')
        values[name] = _base64(parts[offset + 1]) or b''
    return values


def _lines(raw):
    """Bound both compressed bytes and expansion; reject trailers/members."""
    decompressor, pending, total = zlib.decompressobj(31), b'', 0
    try:
        for start in range(0, len(raw), CHUNK):
            compressed = raw[start:start + CHUNK]
            while compressed:
                block = decompressor.decompress(compressed, CHUNK)
                compressed = decompressor.unconsumed_tail
                total += len(block)
                if total > MAX_UNCOMPRESSED:
                    refuse('database_expansion_limit')
                pending += block
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    if len(line) > MAX_LINE:
                        refuse('line_too_large')
                    yield line
                if len(pending) > MAX_LINE:
                    refuse('line_too_large')
                if decompressor.eof:
                    if decompressor.unused_data or start + CHUNK < len(raw):
                        refuse('multiple_members_or_trailer')
                    break
        if not decompressor.eof or pending:
            refuse('incomplete_database')
    except zlib.error:
        refuse('invalid_compressed_database')


def _row(line):
    parts = line.split(b' ')
    if len(parts) != len(FIELDS) or any(not part for part in parts):
        refuse('wrong_column_count')
    fields = dict(zip(FIELDS, parts))
    name, target = _filename(fields['name']), _link(fields['lname'])
    mode = _number(fields['perm'], 0o177777, octal=True)
    if stat.S_IFMT(mode) not in {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK,
                                stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK}:
        refuse('invalid_file_type')
    numbers = {key: _number(fields[key], (1 << 32) - 1 if key in {'uid', 'gid'} else (1 << 63) - 1)
               for key in ('uid', 'gid', 'size', 'ctime', 'mtime', 'inode', 'lcount')}
    mask = _number(fields['attr'], (1 << 64) - 1)
    if not mask or mask & ~KNOWN_MASK or not numbers['inode']:
        refuse('unsupported_attributes')
    acl, checksum = _acl(fields['acl']), _base64(fields['sha512'], length=64)
    label, xattrs = _base64(fields['selinux']), _xattrs(fields['xattrs'])
    if (bool(mask & ATTR['sha512']) != (checksum is not None)
            or not mask & ATTR['acl'] and acl is not None
            or not mask & ATTR['linkname'] and target is not None
            or not mask & ATTR['selinux'] and label is not None
            or not mask & ATTR['xattrs'] and xattrs):
        refuse('attribute_value_mismatch')
    return name, {'mode': mode, 'attr': mask, **numbers, 'target': target,
                  'acl': acl, 'sha512': checksum, 'selinux': label, 'xattrs': xattrs}


def _qualified(path, row):
    expected_mask = EFI_MASK if path in EFI else SYMLINK_MASK if path == '/etc/os-release' else REGULAR_MASK
    expected_type = stat.S_IFLNK if path == '/etc/os-release' else stat.S_IFREG
    if (row['attr'] != expected_mask or stat.S_IFMT(row['mode']) != expected_type
            or row['uid'] != 0 or row['gid'] != 0 or row['lcount'] != 1
            or expected_type == stat.S_IFREG and row['mode'] & 0o7022
            or expected_type == stat.S_IFLNK and stat.S_IMODE(row['mode']) != 0o777
            or path == '/etc/os-release' and row['target'] != b'../usr/lib/os-release'
            or expected_type == stat.S_IFREG and row['target'] is not None
            or expected_mask & ATTR['acl'] and (row['acl'] is None or row['acl']['access'] is None
                                               or row['acl']['default'] is not None)):
        refuse('unqualified_target_row')
    if row['selinux'] is None or row['xattrs'].get(b'security.selinux') != row['selinux'] + b'\0':
        refuse('target_security_label_mismatch')
    try:
        xattrs = {name.decode('utf-8'): base64.b64encode(value).decode()
                  for name, value in row['xattrs'].items()}
    except UnicodeError:
        refuse('unsupported_target_xattr_name')
    acl = None if row['acl'] is None else {
        key: None if value is None else base64.b64encode(value).decode() for key, value in row['acl'].items()}
    return {'kind': 'symlink' if expected_type == stat.S_IFLNK else 'file',
            'mode': stat.S_IMODE(row['mode']), 'uid': row['uid'], 'gid': row['gid'],
            'bytes': row['size'], 'inode': row['inode'], 'nlink': row['lcount'],
            'ctime_s': row['ctime'], 'mtime_s': row['mtime'], 'attributes': row['attr'],
            'target': row['target'].decode() if row['target'] is not None else None,
            'sha512': row['sha512'].hex() if row['sha512'] is not None else None,
            'acl': acl, 'selinux': base64.b64encode(row['selinux']).decode(), 'xattrs': xattrs}


def parse_database(raw, *, expected_sha256):
    """Parse fixed historical rows after digest verification, not authorization."""
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_COMPRESSED
            or not isinstance(expected_sha256, str) or not SHA.fullmatch(expected_sha256)
            or hashlib.sha256(raw).hexdigest() != expected_sha256):
        refuse('database_digest_or_size_mismatch')
    lines = iter(_lines(raw))
    try:
        if next(lines) != b'@@begin_db' or next(lines) != b'# This file was generated by Aide, version 0.19.2':
            refuse('unsupported_database_header')
        generated = next(lines)
        if not re.fullmatch(rb'# Time of generation was [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}', generated):
            refuse('unsupported_database_metadata')
        try:
            datetime.strptime(generated.removeprefix(b'# Time of generation was ').decode(), '%Y-%m-%d %H:%M:%S %z')
        except ValueError:
            refuse('invalid_generation_time')
        if next(lines) != SPEC:
            refuse('unsupported_database_spec')
    except StopIteration:
        refuse('incomplete_database_header')
    rows, seen, ended = {}, set(), False
    for line in lines:
        if ended:
            refuse('data_after_end_marker')
        if line == b'@@end_db':
            ended = True
            continue
        if len(seen) >= MAX_ROWS:
            refuse('too_many_entries')
        name, value = _row(line)
        if name in seen:
            refuse('duplicate_filename')
        seen.add(name)
        path = name.decode('ascii') if name.isascii() else None
        if path in TARGETS:
            rows[path] = _qualified(path, value)
    if not ended or set(rows) != TARGETS:
        refuse('missing_end_or_required_targets')
    return {'schema': 1, 'format': FORMAT, 'database_sha256': expected_sha256,
            'entry_count': len(seen), 'rows': rows}


def validate_change_summary(path, summary, *, row, attribute):
    """Check a single pinned summary; this does not permit a file transition."""
    wanted = 'inode' if path in EFI else 'ctime' if path in TMPFILES else None
    expected_mask = EFI_MASK if path in EFI else SYMLINK_MASK if path == '/etc/os-release' else REGULAR_MASK
    if wanted is None or attribute != wanted or row.get('attributes') != expected_mask:
        refuse('unqualified_summary_target')
    # Vendor report.c order: type/link/size/blocks/p/u/g/a/m/c/i/n/hash/ACL/X/S/E/caps.
    bits = (35, 1, 5, 10, 2, 3, 4, 6, 8, 7, 9, 11, 31, 21, 33, 32, 36, 37)
    expected = ''.join(('=' if index == 2 else '.') if expected_mask & (1 << bit) else ' '
                       for index, bit in enumerate(bits))
    expected = ('l' if path == '/etc/os-release' else 'f') + expected[1:]
    offset, marker = (10, 'i') if attribute == 'inode' else (9, 'c')
    expected = expected[:offset] + marker + expected[offset + 1:]
    if summary != expected:
        refuse('unqualified_change_summary')


def read_accepted_database(manager, *, source_head, source_database_sha256, pending_owner=None, pending_authority=None):
    """Read a verified AIDE input with exact typed pending ancestry when needed.

    As with accepted_plan_history, the caller holds the outer manager/update
    locks. An unpublished ready output is returned as that exact input, never
    mislabeled as a published acceptance or a clean current-host check.
    """
    from . import aide_updates

    arguments = {'manager': manager, 'allow_pending_owner': pending_owner, 'pending_authority': pending_authority}
    history = aide_updates.accepted_plan_history(**arguments)
    head, checksum, basis = history['head'], history['database_sha256'], 'published'
    pending = history['pending']
    if pending is not None and pending['state'] != 'complete':
        # When input and output have identical bytes this deliberately chooses
        # the fully verified proposed output. It does not infer that a copy
        # happened, or claim the proposal has been published or the host clean.
        output_matches = pending['state'] == 'ready' and history['current_database_sha256'] == pending['database_sha256']
        if output_matches and head != pending['entry']:
            proposed = pending['proposed_entry']
            if proposed['previous'] != head or proposed['previous_database_sha256'] != checksum:
                refuse('pending_prefix_changed')
            head, checksum, basis = pending['entry'], pending['database_sha256'], 'owned-ready-output'
    if (source_head != head or source_database_sha256 != checksum
            or history['current_database_sha256'] != checksum):
        refuse('verified_input_changed')
    identity = manager.guard()
    raw = manager._bytes(identity.root / 'manager/aide/aide.db.gz', identity)
    parsed = parse_database(raw, expected_sha256=checksum)
    if aide_updates.accepted_plan_history(**arguments) != history:
        refuse('history_changed_during_read')
    parsed['source'] = {'basis': basis, 'head': head, 'observed_head': history['head'],
                        'original_enrollment_sha256': digest(history['original_enrollment']),
                        'pending_sha256': digest(pending) if pending is not None and pending['state'] != 'complete' else None}
    return parsed
