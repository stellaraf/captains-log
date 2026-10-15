"""Exact, once-only removal of one vendor kernel after lifecycle acceptance.

Four complete kernel sets may exist while a candidate is qualified. Only the
oldest set can then be removed, leaving three and preserving the running,
accepted kernel and its recorded recovery kernel. The caller owns lifecycle,
maintenance and AIDE locks. This module never accepts a baseline or release.
Retained signed RPMs for the erased version are mandatory, including for a
factory kernel; installed RPM headers alone are not signed provenance.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import uuid

from . import kernel_updates as kernel, os_payload as rpm
from .common import Refused, require_linux_root, run
from .host_job_storage import exact, strict_json
from .updates import REQUIRED_CHECKS

KIND = 'rocky-kernel-retention-v1'
PLAN = 'kernel-retention-plan.json'
INTEGRITY = 'kernel-retention-integrity-plan.json'
INTENT = 'kernel-retention-intent.json'
RESULT = 'kernel-retention-result.json'
WEAK_MODULES_SHA = '43131f95ebe5724fffedcd2e8f4f2f80fdaeb4b4c047162e2a940033f9bcf91b'
ACCEPTED_FIELDS = {'schema', 'operation_sha256', 'kernel_plan_sha256', 'installed_sha256',
                   'postboot_sha256', 'promotion_sha256', 'resume_sha256', 'kernel', 'boot_id',
                   'recovery_kernel', 'checks', 'finalization', 'previous_acceptance_sha256'}
PROJECTION_FIELDS = {'ok', 'kernel', 'recovery_kernel', 'boot_id', 'receipt_sha256', 'install_plan_sha256'}


def refuse(reason):
    raise Refused('kernel_retention_' + reason)


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    try:
        if str(uuid.UUID(value)) != value:
            refuse('invalid_boot_identity')
    except (ValueError, TypeError, AttributeError):
        refuse('invalid_boot_identity')
    return value


def acceptance_record(stage):
    """Validate immutable receipt bytes; caller still proves fresh live health."""
    stage = Path(stage)
    value, receipt_sha, _ = kernel.read_acceptance(stage)
    exact(value, ACCEPTED_FIELDS)
    if (type(value['schema']) is not int or value['schema'] != 1 or value['finalization'] != 'complete'
            or type(value['checks']) is not dict or set(value['checks']) != REQUIRED_CHECKS
            or any(result is not True for result in value['checks'].values())
            or not kernel.KERNEL.fullmatch(str(value['kernel']))
            or not kernel.KERNEL.fullmatch(str(value['recovery_kernel']))
            or value['kernel'] == value['recovery_kernel']
            or value['boot_id'] != boot_id()):
        refuse('final_lifecycle_acceptance_missing')
    for field in ('operation_sha256', 'kernel_plan_sha256', 'installed_sha256', 'postboot_sha256', 'promotion_sha256'):
        if not kernel.SHA.fullmatch(str(value[field])):
            refuse('invalid_acceptance_binding')
    for field in ('resume_sha256', 'previous_acceptance_sha256'):
        if value[field] is not None and not kernel.SHA.fullmatch(str(value[field])):
            refuse('invalid_acceptance_binding')
    candidate_stage, candidate, candidate_sha, _ = kernel.load_candidate(stage)
    if (value['operation_sha256'] != rpm.sha(rpm.read(stage / 'operation.json', 8192))
            or value['kernel_plan_sha256'] != candidate_sha
            or value['installed_sha256'] != rpm.sha(rpm.read(candidate_stage / 'kernel-installed.json', rpm.MAX_XML))
            or value['kernel'] != candidate['kernel'] or value['recovery_kernel'] != candidate['old_kernel']):
        refuse('accepted_record_binding_changed')
    return {'ok': True, 'kernel': value['kernel'], 'recovery_kernel': value['recovery_kernel'],
            'boot_id': value['boot_id'], 'receipt_sha256': receipt_sha,
            'install_plan_sha256': value['kernel_plan_sha256']}


def acceptance(stage, accepted, runner):
    # A mandatory trusted lifecycle callback must verify the entire acceptance
    # chain, all current runtime checks, and a fresh backup. Merely presenting
    # correctly shaped digests cannot authorize removal.
    actual = accepted(Path(stage))
    exact(actual, PROJECTION_FIELDS)
    if actual != acceptance_record(stage):
        refuse('fresh_lifecycle_acceptance_changed')
    if (runner(['/usr/bin/uname', '-r']) != actual['kernel']
            or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + actual['kernel']):
        refuse('accepted_kernel_is_not_running_default')
    return actual


def version_order(value):
    if not kernel.KERNEL.fullmatch(value):
        refuse('unsupported_kernel_identity')
    return tuple(int(part) for part in re.findall(r'\d+', value))


def select_oldest(installed, accepted):
    groups = {}
    for header in installed:
        name = rpm.one(header, 'Name')
        if name not in kernel.NAMES:
            continue
        version = kernel.version(header)
        group = groups.setdefault(version, {})
        if name in group:
            refuse('duplicate_kernel_package')
        group[name] = header
    if len(groups) != 4 or any(set(group) != kernel.NAMES for group in groups.values()):
        refuse('requires_four_complete_kernel_sets')
    ordered = sorted(groups, key=version_order)
    if (accepted['kernel'] != ordered[-1] or accepted['recovery_kernel'] not in groups
            or ordered[0] in {accepted['kernel'], accepted['recovery_kernel']}):
        refuse('oldest_kernel_is_protected_or_candidate_not_newest')
    return ordered[0], groups


def command(plan, test=False):
    return ['/usr/bin/rpm', '--erase', *(['--test'] if test else []), *sorted(p['nevra'] for p in plan['packages'])]


def verify_remove_hooks():
    kernel.verify_install_hooks()
    if rpm.sha(rpm.read('/usr/sbin/weak-modules', 256 * 1024)) != WEAK_MODULES_SHA:
        refuse('weak_modules_helper_changed')
    # The qualified helper uses the stock BLS layout and no override files.
    for root in ('/etc/kernel', '/run/kernel'):
        for name in ('install.conf', 'entry-token', 'tries'):
            if os.path.lexists(Path(root) / name):
                refuse('kernel_remove_layout_override')


def preserved_description(path):
    value = kernel.describe(path)
    if value['kind'] == 'directory':
        info = Path(path).lstat()
        value.update(device=info.st_dev, inode=info.st_ino)
    return value


def validate_boot_scope(version, machine, generated):
    expected = {p for p in generated if p.startswith('/boot/')}
    actual = {str(p) for p in Path('/boot').rglob('*') if version in p.name}
    if actual != expected:
        refuse('unqualified_versioned_boot_output')
    # These additional names are removed by the vendor hook; never authorize
    # their deletion merely because they happen to contain the same version.
    if any(os.path.lexists(p) for p in (
            '/boot/loader/entries/ffffffffffffffffffffffffffffffff-' + version + '.conf',
            '/boot/loader/entries/' + machine + '-' + version + '~debug.conf')):
        refuse('unexpected_alternate_boot_entry')


def plan_cached(stage, packages, *, accepted, runner=run):
    require_linux_root()
    stage = Path(stage)
    approved = acceptance(stage, accepted, runner)
    rpm.platform(runner)
    verify_remove_hooks()
    if os.readlink('/lib') != 'usr/lib' or rpm.sha(rpm.read(rpm.KEY, 65536)) != rpm.KEY_SHA256 or len(packages) != 4:
        refuse('platform_or_signed_package_set_changed')
    if any(os.path.lexists(stage / name) for name in (PLAN, INTENT, RESULT)):
        refuse('retention_already_planned_or_attempted')
    xml, installed, before = rpm.inventory(runner)
    oldest, groups = select_oldest(installed, approved)
    package_dir = stage / 'kernel-retention-packages'
    package_dir.mkdir(mode=0o700, exist_ok=True)
    info = package_dir.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700 or package_dir.resolve() != package_dir):
        refuse('unsafe_retained_package_directory')
    # A planning crash may leave a partial key database. Preserve that evidence
    # and create a new isolated trust store instead of reopening or deleting it.
    keydb = 'kernel-retention-keydb-' + uuid.uuid4().hex
    rpm.init_keydb(stage / keydb, runner)
    rpm.immutable(stage / 'kernel-retention-inventory.xml', xml.encode())
    proposed, files = [], {}
    for source in packages:
        raw = rpm.read(source)
        path = package_dir / (rpm.sha(raw) + '.rpm')
        rpm.immutable(path, raw)
        signature = rpm.signature(path, stage / keydb, runner)
        headers = rpm.headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(path)]))
        if len(headers) != 1:
            refuse('ambiguous_signed_package')
        item = kernel.payload(headers[0])
        if item['kernel'] != oldest or item['name'] not in groups[oldest] or kernel.payload(groups[oldest][item['name']]) != item:
            refuse('signed_package_differs_from_installed_oldest')
        for entry in item.pop('files'):
            if entry['path'] in files and files[entry['path']] != entry:
                refuse('overlapping_target_payload')
            files[entry['path']] = entry
        proposed.append({**item, 'rpm': path.name, 'sha256': rpm.sha(raw), 'bytes': len(raw), 'signature': signature})
    if {p['name'] for p in proposed} != kernel.NAMES or len({p['nevra'] for p in proposed}) != 4:
        refuse('incomplete_signed_erase_set')
    proposed.sort(key=lambda p: p['name'])
    machine = rpm.read('/etc/machine-id', 64).decode().strip()
    generated = kernel.generated_paths(oldest, machine)
    shared_paths = {'/usr/lib/modules', '/usr/share/licenses/kernel-core'} & set(files)
    if any(files[p]['kind'] != 'directory' for p in shared_paths):
        refuse('unexpected_shared_target_payload')
    shared = {p: kernel.describe(p) for p in shared_paths}
    bls = '/boot/loader/entries/' + machine + '-' + oldest + '.conf'
    target = {'kernel': oldest, 'old_kernel': oldest, 'machine_id': machine,
              'packages': proposed, 'files': list(files.values()), 'generated': sorted(generated),
              'shared': shared, 'preserved': {}, 'old_bls': rpm.read(bls, 65536).decode()}
    kernel.verify_payload(target, runner=runner)
    kernel.generated_snapshot(target, runner=runner)
    validate_boot_scope(oldest, machine, generated)
    removable = (set(files) | generated) - shared_paths
    # No remaining package may own a target path. A dependency solver can
    # refuse the exact erase, but it may never add another erasure to the plan.
    erase = {p['nevra'] for p in proposed}
    for header in installed:
        if rpm.identity(header)['nevra'] in erase:
            continue
        dirs = header.get('Dirnames', [])
        if len(header.get('Basenames', [])) != len(header.get('Dirindexes', [])):
            refuse('invalid_installed_file_inventory')
        for name, index in zip(header.get('Basenames', []), header.get('Dirindexes', [])):
            if type(index) is not int or not 0 <= index < len(dirs):
                refuse('invalid_installed_file_inventory')
            if kernel.canonical(dirs[index] + name) in removable:
                refuse('target_path_owned_by_retained_package')
    rpm.external_triggers(installed, kernel.NAMES, removable | {p.removeprefix('/usr') for p in removable if p.startswith('/usr/lib/')})
    preserved_paths = set(shared_paths) | {kernel.GRUBENV, kernel.KERNEL_CONFIG, '/etc/default/grub', '/boot/grub2/grub.cfg'}
    for version, group in groups.items():
        if version == oldest:
            continue
        for header in group.values():
            preserved_paths.update(p['path'] for p in kernel.payload(header)['files'])
        preserved_paths.update(kernel.generated_paths(version, machine))
    # Only immediate surviving parents can have expected directory timestamp
    # or link-count changes. Their identity, mode and xattrs must remain fixed.
    parents = {str(Path(p).parent) for p in removable} - removable
    preserved_paths |= parents
    if preserved_paths & removable:
        refuse('protected_removal_overlap')
    preserved = {p: preserved_description(p) for p in sorted(preserved_paths)}
    if any(preserved[p]['kind'] != 'directory' for p in parents):
        refuse('removal_parent_is_not_directory')
    removal = {p: kernel.describe(p) for p in sorted(removable)}
    plan = {'schema': 1, 'kind': KIND, 'operation_sha256': rpm.sha(rpm.read(stage / 'operation.json', 8192)),
            'acceptance': approved, 'boot_id': approved['boot_id'], 'kernel': oldest, 'machine_id': machine,
            'key_sha256': rpm.KEY_SHA256, 'keydb': keydb, 'packages': proposed, 'target': target,
            'before_inventory': before, 'after_inventory': sorted(set(before) - erase),
            'inventory_sha256': rpm.sha(xml.encode()), 'removed': removal, 'preserved': preserved,
            'mutable_directories': sorted(parents), 'retained_kernels': sorted(set(groups) - {oldest}, key=version_order)}
    if len(before) - len(plan['after_inventory']) != 4:
        refuse('erase_inventory_not_exact')
    runner(command(plan, True), timeout=180)
    if acceptance(stage, accepted, runner) != approved or rpm.inventory(runner)[0] != xml:
        refuse('planning_context_changed')
    verify_files(plan, 'prepare', runner=runner)
    kernel.record(stage, PLAN, plan)
    checksum = rpm.sha(kernel.encode(plan))
    kernel.record(stage, INTEGRITY, integrity_plan(plan, checksum))
    return {'ok': True, 'kernel': oldest, 'plan_sha256': checksum, 'retained_kernels': plan['retained_kernels']}


def load_plan(stage):
    stage = Path(stage)
    raw = rpm.read(stage / PLAN, rpm.MAX_XML)
    plan = strict_json(raw)
    exact(plan, {'schema', 'kind', 'operation_sha256', 'acceptance', 'boot_id', 'kernel', 'machine_id', 'key_sha256', 'keydb',
                 'packages', 'target', 'before_inventory', 'after_inventory', 'inventory_sha256', 'removed',
                 'preserved', 'mutable_directories', 'retained_kernels'})
    if (plan['schema'] != 1 or plan['kind'] != KIND or plan['key_sha256'] != rpm.KEY_SHA256
            or not re.fullmatch(r'kernel-retention-keydb-[a-f0-9]{32}', str(plan['keydb']))
            or plan['operation_sha256'] != rpm.sha(rpm.read(stage / 'operation.json', 8192))
            or plan['acceptance'] != acceptance_record(stage) or plan['boot_id'] != boot_id()
            or plan['kernel'] in plan['retained_kernels'] or len(set(plan['retained_kernels'])) != 3
            or {plan['acceptance']['kernel'], plan['acceptance']['recovery_kernel']} - set(plan['retained_kernels'])
            or set(plan['removed']) & set(plan['preserved'])
            or set(plan['mutable_directories']) - set(plan['preserved'])):
        refuse('plan_binding_changed')
    erase = {p['nevra'] for p in plan['packages']}
    if (len(plan['packages']) != 4 or {p['name'] for p in plan['packages']} != kernel.NAMES
            or any(p['kernel'] != plan['kernel'] for p in plan['packages'])
            or any(p['nevra'] != p['name'] + '-0:' + plan['kernel'] for p in plan['packages'])
            or len(erase) != 4 or not erase <= set(plan['before_inventory'])
            or plan['before_inventory'] != sorted(set(plan['before_inventory']))
            or plan['after_inventory'] != sorted(set(plan['before_inventory']) - erase)):
        refuse('frozen_erase_set_changed')
    generated = kernel.generated_paths(plan['kernel'], plan['machine_id'])
    target = plan['target']
    exact(target, {'kernel', 'old_kernel', 'machine_id', 'packages', 'files', 'generated', 'shared', 'preserved', 'old_bls'})
    paths = {p['path'] for p in target['files']}
    shared = {'/usr/lib/modules', '/usr/share/licenses/kernel-core'} & paths
    expected_removed = (paths | generated) - shared
    root = '/usr/lib/modules/' + plan['kernel']
    docs = '/usr/share/doc/kernel-keys/' + plan['kernel']
    license_path = '/usr/share/licenses/kernel-core/COPYING-' + plan['kernel'].removesuffix('.x86_64')
    if (target['kernel'] != plan['kernel'] or target['old_kernel'] != plan['kernel']
            or target['machine_id'] != plan['machine_id'] or target['packages'] != plan['packages']
            or target['generated'] != sorted(generated) or set(target['shared']) != shared or target['preserved']
            or len(paths) != len(target['files']) or set(plan['removed']) != expected_removed
            or any(kernel.canonical(p) != p or not (p == root or p.startswith(root + '/')
                       or p == docs or p.startswith(docs + '/') or p == license_path or p in generated)
                   for p in expected_removed)
            or set(plan['mutable_directories']) != {str(Path(p).parent) for p in expected_removed} - expected_removed
            or any(plan['preserved'][p].get('kind') != 'directory' for p in plan['mutable_directories'])
            or version_order(plan['kernel']) >= min(version_order(v) for v in plan['retained_kernels'])
            or plan['acceptance']['kernel'] != max(plan['retained_kernels'], key=version_order)):
        refuse('frozen_path_scope_changed')
    required = {kernel.GRUBENV, kernel.KERNEL_CONFIG, '/etc/default/grub', '/boot/grub2/grub.cfg'}
    for retained in plan['retained_kernels']:
        required.update(kernel.generated_paths(retained, plan['machine_id']))
    if required - set(plan['preserved']):
        refuse('retained_boot_protection_missing')
    return plan, rpm.sha(raw)


def verify_files(plan, phase, *, runner=run):
    if phase not in {'prepare', 'forward'}:
        refuse('unsupported_integrity_phase')
    for path, expected in plan['preserved'].items():
        if preserved_description(path) != expected:
            refuse('retained_kernel_or_boot_state_changed')
    for path, expected in plan['removed'].items():
        if phase == 'prepare':
            if kernel.describe(path) != expected:
                refuse('erase_target_drift')
        elif os.path.lexists(path):
            refuse('erase_target_still_present')
    if runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + plan['acceptance']['kernel']:
        refuse('persistent_default_changed')


def authorize_execution(stage, plan, checksum, authorize):
    result = authorize(Path(stage), checksum)
    exact(result, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    if (result['ok'] is not True or result['plan_sha256'] != checksum or result['boot_id'] != plan['boot_id']
            or boot_id() != plan['boot_id']
            or any(not kernel.SHA.fullmatch(str(result[k])) for k in ('backup_sha256', 'aide_preparation_sha256'))):
        refuse('execution_authorization_changed')
    return result


def execute_cached(stage, *, authorize, accepted, runner=run):
    require_linux_root()
    stage = Path(stage)
    plan, checksum = load_plan(stage)
    if os.path.lexists(stage / INTENT):
        refuse('already_attempted_use_recovery')
    authorization = authorize_execution(stage, plan, checksum, authorize)
    if acceptance(stage, accepted, runner) != plan['acceptance']:
        refuse('accepted_context_changed')
    rpm.platform(runner)
    verify_remove_hooks()
    xml, _, inventory = rpm.inventory(runner)
    if inventory != plan['before_inventory'] or rpm.sha(xml.encode()) != plan['inventory_sha256']:
        refuse('installed_inventory_changed')
    for item in plan['packages']:
        path = stage / 'kernel-retention-packages' / item['rpm']
        raw = rpm.read(path)
        if (rpm.sha(raw) != item['sha256'] or len(raw) != item['bytes']
                or rpm.signature(path, stage / plan['keydb'], runner) != item['signature']):
            refuse('retained_signed_rpm_changed')
    if rpm.sha(rpm.read(rpm.KEY, 65536)) != plan['key_sha256']:
        refuse('vendor_trust_changed')
    verify_files(plan, 'prepare', runner=runner)
    runner(command(plan, True), timeout=180)
    if (authorize_execution(stage, plan, checksum, authorize) != authorization
            or acceptance(stage, accepted, runner) != plan['acceptance']):
        refuse('execution_context_changed')
    if rpm.inventory(runner)[0] != xml:
        refuse('inventory_changed_after_preflight')
    verify_files(plan, 'prepare', runner=runner)
    kernel.record(stage, INTENT, {'schema': 1, 'plan_sha256': checksum, 'authorization': authorization})
    runner(command(plan), timeout=1800)
    return recover_cached(stage, authorize=authorize, accepted=accepted, runner=runner)


def recover_cached(stage, *, authorize, accepted, runner=run):
    """Inspect a complete erase; never retry RPM or delete residual paths."""
    require_linux_root()
    stage = Path(stage)
    plan, checksum = load_plan(stage)
    intent = strict_json(rpm.read(stage / INTENT, 8192))
    exact(intent, {'schema', 'plan_sha256', 'authorization'})
    original = intent['authorization']
    exact(original, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    current = authorize_execution(stage, plan, checksum, authorize)
    if (intent['schema'] != 1 or intent['plan_sha256'] != checksum or original['ok'] is not True
            or original['plan_sha256'] != checksum or original['boot_id'] != plan['boot_id']
            or not kernel.SHA.fullmatch(str(original['backup_sha256']))
            or original['aide_preparation_sha256'] != current['aide_preparation_sha256']
            or acceptance(stage, accepted, runner) != plan['acceptance']):
        refuse('recovery_authorization_changed')
    # A refreshed backup is required after a long interruption. Retain the
    # new observation separately without changing the original apply intent
    # or its AIDE preparation identity. A new boot remains explicitly refused.
    if current != original:
        kernel.record(stage, 'kernel-retention-recovery-' + rpm.sha(kernel.encode(current)) + '.json',
                      {'schema': 1, 'intent_sha256': rpm.sha(kernel.encode(intent)), 'authorization': current})
    if rpm.inventory(runner)[2] != plan['after_inventory']:
        refuse('partial_erase_requires_recovery')
    verify_files(plan, 'forward', runner=runner)
    result = {'schema': 1, 'status': 'erased_pending_integrity', 'plan_sha256': checksum,
              'kernel': plan['kernel'], 'boot_id': plan['boot_id'],
              'retained_kernels': plan['retained_kernels'], 'release_accepted': False}
    kernel.record(stage, RESULT, result)
    return result


def integrity_plan(plan, checksum):
    return {'schema': 1, 'kind': KIND, 'sequence': 0, 'manifest_sha256': checksum,
            'removed': plan['removed'], 'preserved': plan['preserved'],
            'mutable_directories': plan['mutable_directories']}


def bound_integrity_plan(manager, stage, path, *, preparing):
    identity = manager.guard()
    stage, path = Path(stage), Path(path)
    if stage.is_symlink() or stage.parent != identity.root / 'manager/os-updates' or path != stage / INTEGRITY:
        refuse('unowned_integrity_stage')
    plan, checksum = load_plan(stage)
    raw = manager.reader(path, maximum=rpm.MAX_XML, private=True)
    parsed = strict_json(raw)
    latest = strict_json(rpm.read(identity.root / 'manager/os-latest.json', 65536))
    journal = strict_json(rpm.read(identity.root / 'manager/os-transaction.json', 65536))
    if (parsed != integrity_plan(plan, checksum) or latest.get('stage') != str(stage)
            or journal.get('stage') != str(stage)
            or journal.get('state') not in {'complete', 'retaining', 'retention_postcheck', 'retention_recovery_required'}
            or preparing and os.path.lexists(stage / INTENT)):
        refuse('integrity_operation_binding_changed')
    return parsed, rpm.sha(raw)


def integrity_snapshot(manager, plan, phase, retained=None):
    if phase not in {'prepare', 'forward'}:
        refuse('unsupported_integrity_phase')
    values = {}
    for path, expected in plan['preserved'].items():
        value = preserved_description(path)
        if value != expected or retained is not None and retained.get(path) != value:
            refuse('integrity_preserved_metadata_changed')
        values[path] = value
    for path, expected in plan['removed'].items():
        if phase == 'prepare':
            if kernel.describe(path) != expected:
                refuse('integrity_erase_target_changed')
        elif os.path.lexists(path):
            refuse('integrity_erase_target_still_present')
        # AIDE retains this authorized preimage metadata through its database
        # swap. Live absence is checked above; do not pretend absence is a new
        # metadata baseline or drop entries from the immutable preparation.
        if retained is not None and retained.get(path) != expected:
            refuse('integrity_erase_preimage_changed')
        values[path] = expected
    return values


def allowed_integrity_report(report, plan, phase):
    if phase not in {'prepare', 'forward'}:
        refuse('unsupported_integrity_phase')
    removed = set(plan['removed']) if phase == 'forward' else set()
    changed = set(plan['mutable_directories']) if phase == 'forward' else set()
    if report.get('added') or set(report.get('removed', {})) - removed or set(report.get('changed', {})) - changed:
        refuse('unrelated_integrity_change')
