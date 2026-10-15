"""Exact signed Rocky RPM transactions and separate file-level AIDE plans.

The first ABI executes only scriptless replacements with unchanged regular-file
and directory sets. It refuses unknown generated outputs, links, config files,
checker/boot transitions and applicable external triggers before host mutation.
No solver is rerun during application: RPM receives the retained verified files.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
import xml.etree.ElementTree as ET

from .common import Refused, atomic_json, require_linux_root, run, trusted_file
from .host_job_storage import digest, exact, strict_json

MAX_XML = 128 * 1024**2
MAX_RPM = 128 * 1024**2
MAX_FILES = 4096
KEY = Path('/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9')
KEY_SHA256 = '3a66e521e7a4abac9768d889c7cd60a8250f59512b275cf576c8a10ff34624c1'
KEY_ID = '350d275d'
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}')
# These cannot use the inert-payload ABI even if a vendor header lacks scripts.
MIGRATION = re.compile(r'^(?:kernel|aide|rpm|dnf|python3|glibc|openssl|crypto-policies|selinux-policy|grub2|shim|systemd|dracut|cryptsetup)(?:-|$)')
SCRIPTS = ('Prein', 'Postin', 'Preun', 'Postun', 'Pretrans', 'Posttrans', 'Verifyscript',
           'Triggerscripts', 'Filetriggerscripts', 'Transfiletriggerscripts')


def refuse(reason):
    raise Refused('os_payload_' + reason)


def read(path, maximum=MAX_RPM):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            refuse('unsafe_parent')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > maximum:
        refuse('unsafe_file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(raw) != opened.st_size:
        refuse('file_changed')
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def immutable(path, raw):
    if path.exists():
        if read(path, max(MAX_XML, MAX_RPM)) != raw:
            refuse('retained_evidence_changed')
        return
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def headers(xml):
    if not isinstance(xml, str) or len(xml.encode()) > MAX_XML or '<!' in xml:
        refuse('invalid_rpm_xml')
    try:
        root = ET.fromstring('<headers>' + xml + '</headers>')
    except ET.ParseError:
        refuse('invalid_rpm_xml')
    result = []
    for header in root:
        if header.tag != 'rpmHeader':
            refuse('invalid_rpm_xml')
        value = {}
        for tag in header:
            name = tag.attrib.get('name')
            if tag.tag != 'rpmTag' or not isinstance(name, str) or name in value:
                refuse('invalid_rpm_xml')
            values = []
            for item in tag:
                if item.tag == 'integer':
                    values.append(int(item.text or ''))
                elif item.tag in {'string', 'base64'}:
                    values.append(item.text or '')
                else:
                    refuse('invalid_rpm_xml')
            value[name] = values
        result.append(value)
    if not 1 <= len(result) <= 4096:
        refuse('invalid_rpm_xml')
    return result


def one(header, name, default=None):
    values = header.get(name, [] if default is None else [default])
    if len(values) != 1:
        refuse('invalid_rpm_scalar')
    return values[0]


def identity(header):
    name, version, release = (one(header, field) for field in ('Name', 'Version', 'Release'))
    epoch = one(header, 'Epoch', 0)
    if name == 'gpg-pubkey':
        # RPM's installed-key pseudo-package has no Arch tag. Preserve its key
        # ID and creation time in the complete inventory instead of dropping it
        # or treating every package with a missing architecture as equivalent.
        if ('Arch' in header or type(epoch) is not int or epoch != 0
                or any(not isinstance(item, str) or not re.fullmatch(r'[a-f0-9]{8}', item)
                       for item in (version, release))):
            refuse('invalid_gpg_key_identity')
        arch = 'none'
    else:
        arch = one(header, 'Arch')
    if any(not isinstance(item, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.~^-]{0,127}', item) for item in (name, version, release, arch)) or type(epoch) is not int or epoch < 0:
        refuse('invalid_package_identity')
    return {'name': name, 'nevra': f'{name}-{epoch}:{version}-{release}.{arch}', 'arch': arch}


def inventory(runner):
    xml = runner(['/usr/bin/rpm', '--query', '--all', '--xml'], timeout=180)
    result = headers(xml)
    return xml, result, sorted(identity(item)['nevra'] for item in result)


def payload(header):
    package = identity(header)
    if package['arch'] not in {'noarch', 'x86_64'} or MIGRATION.match(package['name']):
        refuse('package_requires_migration_recipe')
    if any(any(value not in ('', None) for value in header.get(tag, [])) for tag in SCRIPTS):
        refuse('scriptlet_or_trigger_requires_recipe')
    if one(header, 'Filedigestalgo', 0) != 8:
        refuse('unsupported_payload_digest')
    names, directories, indexes = (header.get(tag, []) for tag in ('Basenames', 'Dirnames', 'Dirindexes'))
    if not 1 <= len(names) <= MAX_FILES or len(indexes) != len(names):
        refuse('invalid_payload_file_list')
    tags = ('Filemodes', 'Filesizes', 'Filedigests', 'Fileusername', 'Filegroupname', 'Fileflags', 'Filelinktos')
    arrays = {tag: header.get(tag, []) for tag in tags}
    if any(len(items) != len(names) for items in arrays.values()):
        refuse('invalid_payload_metadata')
    if any(value for value in header.get('Filecaps', [])):
        refuse('file_capability_requires_recipe')
    files = []
    for index, name in enumerate(names):
        parent = indexes[index]
        if type(parent) is not int or not 0 <= parent < len(directories):
            refuse('invalid_payload_directory')
        path = directories[parent] + name
        mode, flags = arrays['Filemodes'][index], arrays['Fileflags'][index]
        if (not isinstance(path, str) or not path.startswith('/usr/') or str(Path(path)) != path
                or '..' in Path(path).parts or arrays['Fileusername'][index] != 'root' or arrays['Filegroupname'][index] != 'root'
                or mode & 0o7022 or flags & ~(2 | 128) or arrays['Filelinktos'][index]):
            refuse('unsupported_payload_metadata')
        directory = stat.S_ISDIR(mode)
        if not directory and not stat.S_ISREG(mode):
            refuse('link_or_special_file_requires_recipe')
        value = {'path': path, 'kind': 'directory' if directory else 'file', 'uid': 0, 'gid': 0, 'mode': stat.S_IMODE(mode), 'doc': bool(flags & 2)}
        if not directory:
            checksum, size = arrays['Filedigests'][index], arrays['Filesizes'][index]
            if not re.fullmatch(r'[a-f0-9]{64}', checksum) or type(size) is not int or not 0 <= size <= MAX_RPM:
                refuse('invalid_payload_file_digest')
            value.update(bytes=size, sha256=checksum)
        files.append(value)
    if len({item['path'] for item in files}) != len(files):
        refuse('duplicate_payload_path')
    return {**package, 'files': sorted(files, key=lambda item: item['path'])}


def external_triggers(installed, packages, paths):
    selected = set(packages)
    for header in installed:
        if set(header.get('Triggername', [])) & selected:
            refuse('external_package_trigger_requires_recipe')
        for tag in ('Filetriggername', 'Transfiletriggername'):
            for prefix in header.get(tag, []):
                if not isinstance(prefix, str) or not prefix.startswith('/'):
                    refuse('unrecognized_external_trigger')
                if any(path == prefix.rstrip('/') or path.startswith(prefix.rstrip('/') + '/') for path in paths):
                    refuse('external_file_trigger_requires_recipe')


def init_keydb(path, runner):
    """Use RPM's existing SELinux database label on this private directory only.

    Rocky's confined rpm process cannot create its lock/database in var_lib_t.
    The native proof requires rpm_var_lib_t; copy the system database reference
    label without changing the policy, system keyring or any parent directory.
    """
    path = Path(path)
    path.mkdir(mode=0o700, exist_ok=False)
    runner(['/usr/bin/chcon', '--reference=/var/lib/rpm', str(path)])
    runner(['/usr/bin/rpm', '--dbpath', str(path), '--initdb'])
    runner(['/usr/bin/rpmkeys', '--dbpath', str(path), '--import', str(KEY)])
    enrolled = runner(['/usr/bin/rpm', '--dbpath', str(path), '--query', '--all', '--queryformat', '%{NAME} %{VERSION}\n'])
    if enrolled.splitlines() != ['gpg-pubkey ' + KEY_ID]:
        refuse('isolated_keyring_changed')


def signature(path, keydb, runner):
    text = runner(['/usr/bin/rpmkeys', '--dbpath', str(keydb), '--checksig', '--verbose', str(path)], timeout=120)
    lines = [line.strip() for line in text.splitlines()]
    signatures = [line for line in lines if 'Signature' in line]
    if not signatures or any(not re.fullmatch(r'(?:Header )?V[34] RSA/SHA(?:256|512) Signature, key ID ' + KEY_ID + r': OK', line) for line in signatures):
        refuse('rocky_signature_not_verified')
    if any(any(word in line.upper() for word in ('NOKEY', 'NOT OK', 'BAD', 'NOTTRUSTED')) for line in lines):
        refuse('rocky_signature_not_verified')
    return {'key_id': KEY_ID, 'report_sha256': sha(text.encode())}


def describe(path):
    info = Path(path).lstat()
    value = {'kind': 'directory' if stat.S_ISDIR(info.st_mode) else 'file', 'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}
    if value['kind'] == 'file':
        raw = read(path)
        value.update(bytes=len(raw), sha256=sha(raw))
    return value


def platform(runner):
    if runner(['/usr/bin/rpm', '--eval', '%{_dbpath}']) != '/var/lib/rpm':
        refuse('rpmdb_location_requires_recipe')
    if not runner(['/usr/bin/rpm', '--version']).startswith('RPM version 4.16.'):
        refuse('rpm_abi_not_qualified')
    if runner(['/usr/bin/uname', '-m']) != 'x86_64':
        refuse('unsupported_architecture')
    release = runner(['/usr/bin/rpm', '--query', '--queryformat', '%{NAME} %{VERSION} %{ARCH}', 'rocky-release'])
    if not re.fullmatch(r'rocky-release 9(?:\.[0-9]+)? noarch', release):
        refuse('unsupported_distribution')


def plan_cached(stage, packages, *, runner=run):
    """Read package payloads and host state; never installs a package.

    Exposed separately for actual Rocky qualification without inventing healthy
    application/storage evidence. Production calls prepare(), which also binds
    the OS operation and runs the unmodified AIDE preparation guard.
    """
    require_linux_root()
    stage = Path(stage)
    read(stage / 'operation.json', 8192)
    platform(runner)
    if sha(read(KEY, 65536)) != KEY_SHA256:
        refuse('rocky_trust_changed')
    if not 1 <= len(packages) <= 32:
        refuse('unsupported_transaction_size')
    keydb, retained = stage / 'keydb', stage / 'packages'
    retained.mkdir(mode=0o700, exist_ok=True)
    init_keydb(keydb, runner)
    xml, installed, before = inventory(runner)
    immutable(stage / 'rpm-inventory-before.xml', xml.encode())
    proposed, files, directories, skipped = [], [], [], []
    for source in packages:
        raw = read(source)
        target = retained / (sha(raw) + '.rpm')
        immutable(target, raw)
        verified = signature(target, keydb, runner)
        values = headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(target)]))
        if len(values) != 1:
            refuse('ambiguous_package')
        new = payload(values[0])
        prior = [item for item in installed if identity(item)['name'] == new['name']]
        if len(prior) != 1:
            refuse('replacement_requires_one_installed_package')
        old = payload(prior[0])
        if old['nevra'] == new['nevra'] or old['arch'] != new['arch']:
            refuse('replacement_must_change_version')
        if [item['path'] for item in old['files']] != [item['path'] for item in new['files']]:
            refuse('file_set_change_requires_recipe')
        for before_file, after_file in zip(old['files'], new['files']):
            path = Path(before_file['path'])
            if before_file['kind'] != after_file['kind'] or before_file['doc'] != after_file['doc']:
                refuse('file_type_or_doc_policy_changed')
            if before_file['doc'] and not path.exists():
                skipped.append(str(path))
                continue
            expected_before = {key: value for key, value in before_file.items() if key not in {'path', 'doc'}}
            expected_after = {key: value for key, value in after_file.items() if key not in {'path', 'doc'}}
            if describe(path) != expected_before:
                refuse('installed_payload_drift')
            if before_file['kind'] == 'directory':
                if expected_before != expected_after:
                    refuse('directory_metadata_change_requires_recipe')
                directories.append({'path': str(path), **expected_before})
            else:
                owners = runner(['/usr/bin/rpm', '--query', '--file', '--queryformat', '%{NAME}\n', str(path)]).splitlines()
                if owners != [new['name']]:
                    refuse('shared_payload_file')
                files.append({'path': str(path), 'before': expected_before, 'after': expected_after})
        proposed.append({'name': new['name'], 'before': old['nevra'], 'after': new['nevra'], 'rpm': target.name,
                         'sha256': sha(raw), 'bytes': len(raw), 'signature': verified})
    if len({item['name'] for item in proposed}) != len(proposed) or len({item['path'] for item in files}) != len(files):
        refuse('overlapping_package_set')
    external_triggers(installed, [item['name'] for item in proposed], [item['path'] for item in files])
    expected = list(before)
    for item in proposed:
        expected.remove(item['before'])
        expected.append(item['after'])
    directories = list({item['path']: item for item in directories}.values())
    plan = {'schema': 1, 'kind': 'rocky-inert-rpm-v1', 'operation_sha256': sha(read(stage / 'operation.json', 8192)),
            'key_sha256': KEY_SHA256, 'rpm_inventory_sha256': sha(xml.encode()), 'before_inventory': before,
            'after_inventory': sorted(expected), 'packages': proposed, 'files': files,
            'directories': directories, 'skipped_docs': sorted(set(skipped)), 'excludedocs': bool(skipped)}
    # Exact RPM test performs dependency/conflict/version checks, no mutation.
    runner(command(stage, plan, test=True), timeout=180)
    raw = (json.dumps(plan, sort_keys=True, indent=2) + '\n').encode()
    immutable(stage / 'os-payload-plan.json', raw)
    return {'ok': True, 'plan_sha256': sha(raw), 'packages': len(proposed)}


def command(stage, plan, *, test=False):
    argv = ['/usr/bin/rpm', '--upgrade']
    if test:
        argv.append('--test')
    if plan['excludedocs']:
        argv.append('--excludedocs')
    # No --nodeps, --nosignature, --noscripts, --oldpackage or --replacefiles.
    return argv + [str(stage / 'packages' / item['rpm']) for item in plan['packages']]


def load_plan(stage):
    raw = read(stage / 'os-payload-plan.json', MAX_XML)
    plan = strict_json(raw)
    exact(plan, {'schema', 'kind', 'operation_sha256', 'key_sha256', 'rpm_inventory_sha256', 'before_inventory', 'after_inventory', 'packages', 'files', 'directories', 'skipped_docs', 'excludedocs'})
    if plan['schema'] != 1 or plan['kind'] != 'rocky-inert-rpm-v1' or plan['operation_sha256'] != sha(read(stage / 'operation.json', 8192)) or plan['key_sha256'] != KEY_SHA256:
        refuse('plan_binding_changed')
    return plan, sha(raw)


def validate_files(plan, phase):
    for item in plan['files']:
        if describe(Path(item['path'])) != item[phase]:
            refuse('live_file_not_planned')
    for item in plan['directories']:
        if describe(Path(item['path'])) != {key: value for key, value in item.items() if key != 'path'}:
            refuse('directory_metadata_changed')
    if any(os.path.lexists(path) for path in plan['skipped_docs']):
        refuse('excluded_document_created')


def execute_cached(stage, *, runner=run):
    """Execute an already planned exact transaction once; no health bypass.

    This low-level operation records only RPM results. It cannot complete appliance
    maintenance or adopt an AIDE baseline; apply() supplies that context.
    """
    require_linux_root()
    stage = Path(stage)
    plan, plan_sha = load_plan(stage)
    platform(runner)
    if (stage / 'rpm-apply-intent.json').exists():
        refuse('transaction_already_attempted_use_postcheck')
    if sha(read(KEY, 65536)) != plan['key_sha256']:
        refuse('rocky_trust_changed')
    xml, installed, before = inventory(runner)
    if sha(xml.encode()) != plan['rpm_inventory_sha256'] or before != plan['before_inventory']:
        refuse('installed_package_state_changed')
    validate_files(plan, 'before')
    for item in plan['packages']:
        path = stage / 'packages' / item['rpm']
        raw = read(path)
        if sha(raw) != item['sha256'] or len(raw) != item['bytes']:
            refuse('retained_package_changed')
        if signature(path, stage / 'keydb', runner) != item['signature']:
            refuse('retained_signature_changed')
    runner(command(stage, plan, test=True), timeout=180)
    immutable(stage / 'rpm-apply-intent.json', (json.dumps({'schema': 1, 'plan_sha256': plan_sha, 'state': 'applying'}, sort_keys=True) + '\n').encode())
    runner(command(stage, plan), timeout=3600)
    return postcheck_cached(stage, runner=runner)


def postcheck_cached(stage, *, runner=run):
    plan, plan_sha = load_plan(stage)
    intent = strict_json(read(stage / 'rpm-apply-intent.json', 8192))
    if intent != {'schema': 1, 'plan_sha256': plan_sha, 'state': 'applying'}:
        refuse('apply_intent_changed')
    xml, _, current = inventory(runner)
    if current != plan['after_inventory']:
        refuse('installed_package_result_changed')
    validate_files(plan, 'after')
    immutable(stage / 'rpm-inventory-after.xml', xml.encode())
    result = {'schema': 1, 'ok': True, 'scope': 'exact_rpm_payload_only', 'plan_sha256': plan_sha,
              'rpm_inventory_sha256': sha(xml.encode()), 'packages': plan['packages']}
    atomic_json(stage / 'rpm-result.json', result)
    return result


def prepare(stage, policy, *, runner=run):
    # No general OS update is claimed while kernel/generated-file transitions
    # remain unqualified. Downloaded candidates are inert until fully planned.
    stage = Path(stage)
    requested = policy.get('os_packages', [])
    if not isinstance(requested, list) or len(requested) > 32 or any(not isinstance(name, str) or not NAME.fullmatch(name) for name in requested):
        refuse('invalid_package_selection')
    journal = strict_json(read(stage.parent.parent / 'os-transaction.json', 65536))
    if journal.get('state') != 'planning' or journal.get('stage') != str(stage):
        refuse('operation_binding_required')
    operation = {'schema': 1, 'id': str(uuid.uuid4()), 'stage': str(stage), 'boot_id': journal.get('boot_id')}
    immutable(stage / 'operation.json', (json.dumps(operation, sort_keys=True) + '\n').encode())
    from . import kernel_updates, kernel_integrity
    pending = kernel_updates.adopt_pending(stage)
    if pending is not None:
        return pending
    download = stage / 'download'
    download.mkdir(mode=0o700)
    _, _, before = inventory(runner)
    runner(['/usr/bin/dnf', '--releasever=9', '--refresh', '--assumeyes', '--downloadonly', '--downloaddir=' + str(download), 'upgrade', *requested], timeout=3600)
    packages = sorted(download.glob('*.rpm'))
    if not packages:
        if inventory(runner)[2] != before:
            refuse('package_inventory_changed_during_download')
        observation = {'schema': 1, 'kind': 'rocky-no-updates-v1',
                       'operation_sha256': sha(read(stage / 'operation.json', 8192)),
                       'inventory_sha256': digest(before)}
        immutable(stage / 'os-no-updates.json', (json.dumps(observation, sort_keys=True) + '\n').encode())
        return {'ok': True, 'status': 'no_updates', 'plan_sha256': None}
    names = [one(header, 'Name') for path in packages
             for header in headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(path)]))]
    if len(names) == 4 and set(names) == kernel_updates.NAMES:
        result = kernel_updates.plan_cached(stage, packages, runner=runner)
        kernel_integrity.prepare(stage)
        return result
    result = plan_cached(stage, packages, runner=runner)
    plan, plan_sha = load_plan(stage)
    integrity = integrity_plan(plan, plan_sha)
    path = stage / 'os-integrity-plan.json'
    immutable(path, (json.dumps(integrity, sort_keys=True, indent=2) + '\n').encode())
    from . import aide
    accepted = aide.Aide().authorized_update_prepare(stage, path)
    if accepted.get('ok') is not True:
        refuse('integrity_preparation_failed')
    return result


def integrity_plan(plan, plan_sha):
    return {'schema': 1, 'kind': 'os-payload-v1', 'sequence': 0, 'manifest_sha256': plan_sha,
            'files': plan['files'], 'directories': plan['directories'], 'skipped_docs': plan['skipped_docs']}


def bound_integrity_plan(manager, stage, path, *, preparing):
    from . import aide
    identity = manager.guard()
    parent = identity.root / 'manager/os-updates'
    if stage.is_symlink() or stage.parent != parent or path != stage / 'os-integrity-plan.json':
        refuse('unowned_integrity_stage')
    raw = manager.reader(path, maximum=MAX_XML, private=True)
    parsed = strict_json(raw)
    if parsed.get('kind') == 'kernel-install-v1':
        from . import kernel_integrity
        return kernel_integrity.bound_integrity_plan(manager, stage, path, preparing=preparing)
    plan, plan_sha = load_plan(stage)
    if parsed != integrity_plan(plan, plan_sha):
        refuse('integrity_plan_changed')
    operation = strict_json(read(stage / 'operation.json', 8192))
    exact(operation, {'schema', 'id', 'stage', 'boot_id'})
    try:
        uuid.UUID(operation['id'])
        uuid.UUID(operation['boot_id'])
    except (ValueError, TypeError, AttributeError):
        refuse('invalid_operation_identity')
    journal = strict_json(read(identity.root / 'manager/os-transaction.json', 65536))
    latest = strict_json(read(identity.root / 'manager/os-latest.json', 65536))
    phases = {'planning', 'updating'} if preparing else {'updating', 'postcheck', 'recovery_required', 'complete'}
    if (journal.get('state') not in phases or operation['schema'] != 1 or operation['stage'] != str(stage)
            or journal.get('stage') != str(stage) or latest.get('stage') != str(stage)
            or operation['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or operation['boot_id'] != journal.get('boot_id') or operation['boot_id'] != latest.get('boot_id')
            or (not preparing or journal.get('state') == 'updating') and journal.get('plan_sha256') != plan_sha
            or preparing and (stage / 'rpm-apply-intent.json').exists()):
        refuse('integrity_operation_binding_changed')
    return parsed, sha(raw)


def integrity_snapshot(manager, plan, phase, retained=None):
    from . import aide_updates
    if phase not in {'prepare', 'forward'}:
        refuse('rpm_rollback_requires_separate_recipe')
    values = {}
    for item in plan['files']:
        description, metadata = aide_updates._measure(manager, {'path': item['path']})
        if description != item['before' if phase == 'prepare' else 'after']:
            refuse('live_file_not_planned')
        if retained is not None and retained.get(item['path']) != metadata:
            refuse('acl_xattrs_or_selinux_changed')
        values[item['path']] = metadata
    for item in plan['directories']:
        description, metadata = aide_updates._measure(manager, item)
        if description != {key: value for key, value in item.items() if key != 'path'}:
            refuse('directory_metadata_changed')
        if retained is not None and retained.get(item['path']) != metadata:
            refuse('directory_acl_xattrs_or_selinux_changed')
        values[item['path']] = metadata
    if any(os.path.lexists(path) for path in plan['skipped_docs']):
        refuse('excluded_document_created')
    return values


def allowed_integrity_report(report, plan, phase):
    if phase not in {'prepare', 'forward'}:
        refuse('rpm_rollback_requires_separate_recipe')
    changed = set() if phase == 'prepare' else {item['path'] for item in plan['files']}
    if report.get('added') or report.get('removed') or set(report.get('changed', {})) - changed:
        refuse('unrelated_integrity_change')


def _verify_no_updates(stage, identity, runner):
    """Bind an empty download to this same-boot operation, never an RPM bypass."""
    parent = identity.root / 'manager/os-updates'
    if stage.is_symlink() or stage.resolve().parent != parent.resolve():
        refuse('no_updates_stage_changed')
    raw = read(stage / 'operation.json', 8192)
    operation = strict_json(raw)
    exact(operation, {'schema', 'id', 'stage', 'boot_id'})
    try:
        uuid.UUID(operation['id'])
        uuid.UUID(operation['boot_id'])
    except (ValueError, TypeError, AttributeError):
        refuse('invalid_operation_identity')
    observation = strict_json(read(stage / 'os-no-updates.json', 8192))
    exact(observation, {'schema', 'kind', 'operation_sha256', 'inventory_sha256'})
    journal = strict_json(read(parent.parent / 'os-transaction.json', 65536))
    latest = strict_json(read(parent.parent / 'os-latest.json', 65536))
    if (operation['schema'] != 1 or operation['stage'] != str(stage)
            or observation['schema'] != 1 or observation['kind'] != 'rocky-no-updates-v1'
            or observation['operation_sha256'] != sha(raw)
            or journal.get('state') not in {'postcheck', 'recovery_required', 'complete'}
            or journal.get('no_updates') is not True or journal.get('plan_sha256') is not None
            or journal.get('stage') != str(stage) or latest.get('stage') != str(stage)
            or operation['boot_id'] != journal.get('boot_id') or operation['boot_id'] != latest.get('boot_id')
            or operation['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
        refuse('no_updates_operation_binding_changed')
    if any(os.path.lexists(stage / name) for name in ('os-payload-plan.json', 'os-integrity-plan.json', 'rpm-apply-intent.json',
                                                    'kernel-plan.json', 'kernel-deferred.json', 'kernel-apply-intent.json')):
        refuse('no_updates_conflicts_with_package_transaction')
    if digest(inventory(runner)[2]) != observation['inventory_sha256']:
        refuse('no_updates_package_inventory_changed')
    return observation


def accept_integrity(stage, *, runner=run):
    # Recovery verifies the installed exact package/file result and never reruns
    # RPM or treats dnf history undo as a scriptlet/data rollback guarantee.
    stage = Path(stage)
    from . import aide, aide_updates
    from . import kernel_integrity
    if os.path.lexists(stage / 'kernel-deferred.json'):
        return kernel_integrity.accept_deferred(stage, runner=runner)
    if os.path.lexists(stage / 'kernel-plan.json'):
        return kernel_integrity.accept(stage, runner=runner)
    if os.path.lexists(stage / 'os-no-updates.json'):
        # The lifecycle caller owns manager/update locks. The existing update
        # coordination takes the remaining locks for a fresh ordinary AIDE check.
        # No --update, acceptance or baseline replacement is permitted here.
        manager = aide.Aide()
        with aide_updates._locked(manager) as (state, identity):
            observation = _verify_no_updates(stage, identity, runner)
            integrity = manager._check_locked(state, identity)
            if integrity.get('state') != 'clean' or integrity.get('exit_code') != 0:
                refuse('no_updates_integrity_not_clean')
            _verify_no_updates(stage, identity, runner)
        return {'ok': True, 'package': {'status': 'no_updates', **observation}, 'integrity': integrity}
    package = postcheck_cached(stage, runner=runner)
    integrity = aide.Aide().authorized_update_accept(stage, stage / 'os-integrity-plan.json')
    if integrity.get('ok') is not True:
        refuse('integrity_acceptance_failed')
    return {'ok': True, 'package': package, 'integrity': integrity}


def apply(stage, *, runner=run):
    stage = Path(stage)
    from . import kernel_integrity
    if os.path.lexists(stage / 'kernel-deferred.json'):
        return kernel_integrity.accept_deferred(stage, runner=runner)
    if os.path.lexists(stage / 'kernel-plan.json'):
        return kernel_integrity.apply(stage, runner=runner)
    # Revalidate both the operation and the prepared AIDE context immediately
    # before the exact signed RPM transaction. The manager lock excludes scans.
    from . import aide
    manager = aide.Aide()
    bound_integrity_plan(manager, stage, stage / 'os-integrity-plan.json', preparing=False)
    prepared = manager.authorized_update_prepare(stage, stage / 'os-integrity-plan.json')
    if prepared.get('ok') is not True:
        refuse('integrity_preparation_failed')
    execute_cached(stage, runner=runner)
    return accept_integrity(stage, runner=runner)
