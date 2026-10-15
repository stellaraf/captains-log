"""Read-only native boot measurements and narrowly qualified GRUB transitions.

The initial enrollment and accepted-lineage owner supplies the trusted preimage.
Capturing a current host is observation, never authority to adopt its changes.
Descriptions retain content, type, owner, mode and every xattr (including ACLs
and SELinux); inode/timestamps are deliberately left to AIDE's measured scan,
because the qualified success helper atomically replaces the environment inode.
"""
from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path
import re
import stat
import uuid

from . import kernel_boot as boot, kernel_updates as kernel, os_payload as rpm
from .common import Refused, require_linux_root, run
from .host_job_storage import digest, exact

ENV = kernel.GRUBENV
ROOTS = ('/boot', '/usr/lib/modules', '/etc/grub.d')
FIXED = ('/etc/machine-id', '/etc/default/grub', '/etc/sysconfig/kernel',
         '/usr/lib/systemd/system/system-update.target.wants/grub-boot-indeterminate.service',
         '/usr/lib/systemd/user/timers.target.wants/grub-boot-success.timer')
TOOLS = 'grub2-tools-1:2.06-126.el9_8.rocky.0.3.x86_64'
MINIMAL = 'grub2-tools-minimal-1:2.06-126.el9_8.rocky.0.3.x86_64'
# Native vendor receipts bind these exact Rocky files. The pinned set-bootflag
# binary copies the existing 1024-byte block and changes only the existing flag
# line to boot_success=1; it returns without writing when already 1. Its reviewed
# x86_64 code is at 0x1718..0x18de (strstr, value validation, memcmp, memcpy).
WRITERS = {
    '/usr/bin/grub2-editenv': (boot.TOOL_SHA256, MINIMAL, 0o755),
    '/usr/sbin/grub2-set-bootflag': ('914015fe79445943ef4b8554abfb069b077f2c2653d3b5b0917e8cfe371c484b', MINIMAL, 0o4755),
    '/usr/lib/systemd/user/grub-boot-success.service': ('a362368fb87e725afe60c6184b34f17f5a76b5be7176232a5c79b02c2f34021a', TOOLS, 0o644),
    '/usr/lib/systemd/user/grub-boot-success.timer': ('b3d5dbe0109343635d4b2912146e900531d7584646f611b48103d753faceac16', TOOLS, 0o644),
    '/usr/lib/systemd/system/grub-boot-indeterminate.service': ('a69dec093fc4996a167054bb5e5c805526bef3936a88a4b548ee524fb6b7b5ed', TOOLS, 0o644),
    '/usr/lib/systemd/system/grub2-systemd-integration.service': ('953e1508a90ceec0ca4a101e1ea29f0833e01bb9255593f5fdf6578288c5e3c7', TOOLS, 0o644),
    '/etc/grub.d/00_header': ('7231b4005f6745cdb9f970c1ef6e117a5628ad9573da6f6f169c0f8d9b8f874c', TOOLS, 0o755),
    '/etc/grub.d/10_reset_boot_success': ('ed77b248dffc4022a52219cbc97f5c10f8ddf067fd83a21f02c934f5fab78e87', TOOLS, 0o755),
    '/etc/grub.d/12_menu_auto_hide': ('d950c569cd0949987d1f167ab8e4bc8f018c9c8f2ede3b6f5dd35c33fa60130f', TOOLS, 0o755),
    '/etc/grub.d/14_menu_show_once': ('13047e84a91b7757c719b66f215d2308b13eceb0d63f2c2d0fbd9a64de44a763', TOOLS, 0o755),
}
FIELDS = {'schema', 'boot_id', 'kernel', 'default_kernel', 'machine_id', 'inventory', 'artifacts', 'grub', 'writers'}
MAX_PATHS = 100000
MAX_FILE = 1024 ** 3


def refuse(reason):
    raise Refused('ordinary_boot_state_' + reason)


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        refuse('invalid_boot_identity')


def _path(value):
    if (not isinstance(value, str) or not value.startswith('/') or str(Path(value)) != value
            or '..' in Path(value).parts):
        refuse('invalid_artifact_path')
    return value


def protected_path(value):
    """The fixed measurement scope, also used by accepted-lineage reduction."""
    _path(value)
    return value != ENV and (value in FIXED or value in WRITERS
                            or any(value == root or value.startswith(root + '/') for root in ROOTS))


def _description(value, path):
    if not isinstance(value, dict):
        refuse('invalid_artifact_description')
    kind = value.get('kind')
    fields = {'kind', 'uid', 'gid', 'mode', 'xattrs_sha256'}
    exact(value, fields | ({'sha256', 'bytes'} if kind == 'file' else {'target'} if kind == 'symlink' else set()))
    if (kind not in {'file', 'directory', 'symlink'}
            or any(type(value.get(key)) is not int for key in ('uid', 'gid', 'mode'))
            or value['uid'] != 0 or value['gid'] != 0 or not 0 <= value['mode'] <= 0o7777
            or kind != 'symlink' and value['mode'] & 0o022
            or kind != 'symlink' and value['mode'] & 0o7000 and path != '/usr/sbin/grub2-set-bootflag'
            or not kernel.SHA.fullmatch(str(value['xattrs_sha256']))):
        refuse('unsafe_artifact_metadata')
    if kind == 'file' and (type(value['bytes']) is not int or not 0 <= value['bytes'] <= MAX_FILE
                           or not kernel.SHA.fullmatch(str(value['sha256']))):
        refuse('invalid_file_description')
    if kind == 'symlink' and (not isinstance(value['target'], str) or not value['target']
                              or '\0' in value['target'] or len(value['target']) > 4096 or value['mode'] != 0o777):
        refuse('invalid_symlink_description')


def _environment(snapshot):
    exact(snapshot['grub'], {'raw', 'description'})
    try:
        raw = base64.b64decode(snapshot['grub']['raw'], validate=True)
    except (ValueError, TypeError, binascii.Error):
        refuse('invalid_environment_encoding')
    if base64.b64encode(raw).decode() != snapshot['grub']['raw']:
        refuse('noncanonical_environment_encoding')
    value = boot.parse_environment(raw)
    description = snapshot['grub']['description']
    _description(description, ENV)
    if (description['kind'] != 'file' or description['mode'] != 0o600
            or description['bytes'] != 1024 or description['sha256'] != rpm.sha(raw)
            or value.get('saved_entry') != snapshot['machine_id'] + '-' + snapshot['kernel']
            or value.get('boot_success') not in {'0', '1'} or value.get('boot_indeterminate') not in {'0', '1', '2'}
            or any(value.get(key) not in (None, '') for key in ('next_entry', 'prev_saved_entry', 'boot_counter', 'menu_show_once'))):
        refuse('unqualified_environment')
    # The qualified userspace helper searches a substring, not an anchored key.
    # Refuse an ambiguous unknown key/value instead of predicting the wrong byte.
    if raw.count(b'boot_success=') != 1:
        refuse('ambiguous_success_writer_target')
    return raw, value


def validate_snapshot(value):
    """Validate retained bytes structurally; this never reads the current host."""
    exact(value, FIELDS)
    _uuid(value['boot_id'])
    if (type(value['schema']) is not int or value['schema'] != 1
            or not kernel.KERNEL.fullmatch(str(value['kernel'])) or value['default_kernel'] != value['kernel']
            or not isinstance(value['machine_id'], str) or not re.fullmatch(r'[a-f0-9]{32}', value['machine_id'])):
        refuse('invalid_host_identity')
    inventory = value['inventory']
    if (not isinstance(inventory, list) or not 0 < len(inventory) <= 4096
            or any(not isinstance(item, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.:~^\-]{1,511}', item) for item in inventory)
            or inventory != sorted(set(inventory))):
        refuse('invalid_inventory')
    if not {name + '-0:' + value['kernel'] for name in kernel.NAMES} <= set(inventory):
        refuse('running_kernel_not_installed')
    artifacts = value['artifacts']
    if not isinstance(artifacts, dict) or not 0 < len(artifacts) <= MAX_PATHS:
        refuse('invalid_artifact_inventory')
    required = set(ROOTS) | set(FIXED) | set(WRITERS) | {
        '/boot/grub2/grub.cfg', '/boot/vmlinuz-' + value['kernel'],
        '/boot/initramfs-' + value['kernel'] + '.img',
        '/boot/loader/entries/' + value['machine_id'] + '-' + value['kernel'] + '.conf',
        '/usr/lib/modules/' + value['kernel']}
    if not required <= set(artifacts):
        refuse('required_boot_artifact_missing')
    for path, description in artifacts.items():
        if not protected_path(path):
            refuse('artifact_outside_fixed_scope')
        _description(description, path)
    for path in ROOTS:
        if artifacts[path]['kind'] != 'directory':
            refuse('artifact_root_not_directory')
    expected_writers = {path: {'sha256': pin, 'owner': owner} for path, (pin, owner, _) in WRITERS.items()}
    if value['writers'] != expected_writers:
        refuse('unqualified_flag_writer')
    for path, (checksum, owner, mode) in WRITERS.items():
        item = artifacts[path]
        if item['kind'] != 'file' or item['sha256'] != checksum or item['mode'] != mode or owner not in inventory:
            refuse('flag_writer_artifact_changed')
    _environment(value)
    return value


def describe(path):
    """Measure without following symlinks, including vfat's empty xattr set."""
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            refuse('unsafe_artifact_parent')
    before = path.lstat()
    value = {'uid': before.st_uid, 'gid': before.st_gid, 'mode': stat.S_IMODE(before.st_mode)}
    if stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
        raw = rpm.read(path, MAX_FILE)
        value.update(kind='file', bytes=len(raw), sha256=rpm.sha(raw))
    elif stat.S_ISDIR(before.st_mode):
        value.update(kind='directory')
    elif stat.S_ISLNK(before.st_mode) and before.st_nlink == 1:
        value.update(kind='symlink', target=os.readlink(path))
    else:
        refuse('unsupported_artifact_type')
    attributes = {name: rpm.sha(os.getxattr(path, name, follow_symlinks=False))
                  for name in sorted(os.listxattr(path, follow_symlinks=False))}
    value['xattrs_sha256'] = digest(attributes)
    after = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                             info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if identity(before) != identity(after):
        refuse('artifact_changed_during_read')
    _description(value, str(path))
    return value


def _paths():
    paths = set(FIXED) | set(WRITERS)
    def failed(_error):
        refuse('artifact_enumeration_failed')
    for root in ROOTS:
        if not stat.S_ISDIR(Path(root).lstat().st_mode):
            refuse('artifact_root_not_directory')
        paths.add(root)
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
            paths.update(str(Path(directory) / name) for name in dirs + files)
            if len(paths) > MAX_PATHS:
                refuse('artifact_inventory_too_large')
    paths.discard(ENV)
    return sorted(paths)


def capture(*, runner=run):
    """Observe twice around the measurement; callers separately prove lineage."""
    require_linux_root()
    def identity():
        return {'boot_id': boot.boot_id(), 'kernel': runner(['/usr/bin/uname', '-r']),
                'default_kernel': runner(['/usr/sbin/grubby', '--default-kernel']).removeprefix('/boot/vmlinuz-'),
                'machine_id': rpm.read('/etc/machine-id', 128).decode().strip(),
                'inventory': rpm.inventory(runner)[2]}
    before = identity()
    paths = _paths()
    artifacts = {path: describe(path) for path in paths}
    env_description = describe(ENV)
    raw = rpm.read(ENV, 1024)
    writers = {}
    for path, (checksum, owner, _) in WRITERS.items():
        actual_owner = runner(['/usr/bin/rpm', '--query', '--file', path, '--queryformat',
                               '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n']).strip()
        if actual_owner != owner:
            refuse('flag_writer_package_changed')
        writers[path] = {'sha256': artifacts[path].get('sha256'), 'owner': actual_owner}
    if (identity() != before or _paths() != paths or describe(ENV) != env_description
            or any(describe(path) != expected for path, expected in artifacts.items())):
        refuse('snapshot_changed_during_capture')
    value = {'schema': 1, **before, 'artifacts': artifacts,
             'grub': {'raw': base64.b64encode(raw).decode(), 'description': env_description}, 'writers': writers}
    return validate_snapshot(value)


def validate_transition(before, after, *, same_boot):
    """Authorize only the exact vendor byte edits, never a mutable GRUB path."""
    validate_snapshot(before)
    validate_snapshot(after)
    if type(same_boot) is not bool or (before['boot_id'] == after['boot_id']) != same_boot:
        refuse('transition_boot_identity_changed')
    if any(before[key] != after[key] for key in FIELDS - {'boot_id', 'grub'}):
        refuse('protected_host_state_changed')
    old_raw, old = _environment(before)
    new_raw, new = _environment(after)
    old_description, new_description = before['grub']['description'], after['grub']['description']
    if ({key: item for key, item in old_description.items() if key not in {'sha256', 'bytes'}}
            != {key: item for key, item in new_description.items() if key not in {'sha256', 'bytes'}}):
        refuse('environment_security_metadata_changed')
    if same_boot:
        if old['boot_success'] != '0' or new['boot_success'] != '1':
            refuse('same_boot_success_transition_required')
        wanted = {**old, 'boot_success': '1'}
        kind = 'boot-success'
    else:
        indeterminate = ('0' if old['boot_success'] == '1' else
                         '2' if old['boot_indeterminate'] == '1' else old['boot_indeterminate'])
        wanted = {**old, 'boot_success': new['boot_success'], 'boot_indeterminate': indeterminate}
        kind = 'ordinary-reboot'
    if new != wanted:
        refuse('unqualified_environment_transition')
    expected = old_raw
    for key in ('boot_success', 'boot_indeterminate'):
        expected = expected.replace(('\n' + key + '=' + old[key] + '\n').encode(),
                                    ('\n' + key + '=' + wanted[key] + '\n').encode(), 1)
    if new_raw != expected:
        refuse('environment_bytes_outside_qualified_writer')
    return {'kind': kind, 'before_boot_id': before['boot_id'], 'boot_id': after['boot_id'],
            'files': [{'path': ENV, 'before': old_description, 'after': new_description}]}
