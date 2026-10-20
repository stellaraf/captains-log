"""Exact, once-only removal of one vendor kernel after lifecycle acceptance.

Four complete kernel sets may exist while a candidate is qualified. Only the
oldest set can then be removed, leaving three and preserving the running,
accepted kernel and its recorded recovery kernel. The caller owns lifecycle,
maintenance and AIDE locks. This module never accepts a baseline or release.
Retained signed RPMs for the erased version are mandatory, including for a
factory kernel; installed RPM headers alone are not signed provenance.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import stat
import uuid

from . import kernel_updates as kernel, os_payload as rpm
from .common import Refused, atomic_json, require_linux_root, run
from .host_job_storage import digest, exact, strict_json
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
RESUME_KIND = 'rocky-kernel-retention-resume-v1'
OBSERVATION = re.compile(r'kernel-retention-observation-([a-f0-9-]{36})\.json')
RESUME_PLAN = re.compile(r'kernel-retention-resume-([a-f0-9]{32})-plan\.json')
RESUME_NAME = RESUME_PLAN
RESUME_RESULT = re.compile(r'kernel-retention-resume-([a-f0-9]{32})-result\.json')
PROVISIONAL_FIELDS = {'ok', 'stage', 'boot_id', 'backup_stage', 'backup_sha256',
                      'operation_sha256', 'retention_plan_sha256'}


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
    return _acceptance_projection(stage, value, receipt_sha, current=True)


def _acceptance_projection(stage, value, receipt_sha, *, current):
    stage = Path(stage)
    exact(value, ACCEPTED_FIELDS | ({'retention_integrity_sha256'} if 'retention_integrity_sha256' in value else set()))
    if (type(value['schema']) is not int or value['schema'] != 1 or value['finalization'] != 'complete'
            or type(value['checks']) is not dict or set(value['checks']) != REQUIRED_CHECKS
            or any(result is not True for result in value['checks'].values())
            or not kernel.KERNEL.fullmatch(str(value['kernel']))
            or not kernel.KERNEL.fullmatch(str(value['recovery_kernel']))
            or value['kernel'] == value['recovery_kernel']
            or current and value['boot_id'] != boot_id()):
        refuse('final_lifecycle_acceptance_missing')
    for field in ('operation_sha256', 'kernel_plan_sha256', 'installed_sha256', 'postboot_sha256', 'promotion_sha256'):
        if not kernel.SHA.fullmatch(str(value[field])):
            refuse('invalid_acceptance_binding')
    for field in ('resume_sha256', 'previous_acceptance_sha256'):
        if value[field] is not None and not kernel.SHA.fullmatch(str(value[field])):
            refuse('invalid_acceptance_binding')
    if value.get('retention_integrity_sha256') is not None and not kernel.SHA.fullmatch(str(value['retention_integrity_sha256'])):
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


def historical_acceptance(stage, approved):
    """Resolve an exact ancestor; historical validity never authorizes erasure."""
    exact(approved, PROJECTION_FIELDS)
    matches = [item for item in kernel._acceptance_chain(Path(stage)) if item[1] == approved['receipt_sha256']]
    if len(matches) != 1:
        refuse('original_acceptance_not_in_current_history')
    value, checksum, _ = matches[0]
    if _acceptance_projection(stage, value, checksum, current=False) != approved:
        refuse('original_acceptance_projection_changed')
    return value


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
    from . import kernel_retention_generation as generation
    reference = generation.selected(stage)
    if reference is not None:
        plan, checksum = generation.load(stage, reference)
        erase_intent(stage, plan, checksum)
        return plan, checksum
    return _load_plan(stage, historical=False)


def load_historical_plan(stage):
    """Validate frozen scope and accepted ancestry without granting authority."""
    from . import kernel_retention_generation as generation
    reference = generation.selected(stage)
    if reference is not None:
        plan, checksum = generation.load(stage, reference, historical=True)
        erase_intent(stage, plan, checksum)
        return plan, checksum
    return _load_plan(stage, historical=True)


def load_original_plan(stage, *, historical=True):
    """Read the immutable root recipe, even after a later generation attempts."""
    return _load_plan(stage, historical=historical)


def load_plan_by_checksum(stage, checksum):
    from . import kernel_retention_generation as generation
    original, original_sha = load_original_plan(stage, historical=True)
    if checksum == original_sha:
        return original, original_sha
    reference = generation.selected(stage)
    if reference is None:
        refuse('execution_history_requires_global_attempt')
    plan, actual = generation.load(stage, reference, historical=True)
    if actual != checksum:
        refuse('execution_history_checksum_changed')
    erase_intent(stage, plan, checksum)
    return plan, checksum


def execution_integrity_path(stage, checksum):
    """Resolve the exact preimage/preparation for the actual erase recipe."""
    from . import kernel_retention_generation as generation
    _, original_sha = load_original_plan(stage, historical=True)
    if checksum == original_sha:
        return Path(stage) / INTEGRITY
    reference = generation.selected(stage)
    if reference is None:
        refuse('execution_integrity_requires_global_attempt')
    _, actual = generation.load(stage, reference, historical=True)
    if actual != checksum:
        refuse('execution_integrity_checksum_changed')
    return generation.integrity_path(stage, reference)


def verify_unattempted(stage, *, runner=run):
    """Prove a later execution may be planned; never authorizes a command."""
    stage = Path(stage)
    if any(os.path.lexists(stage / name) for name in (INTENT, RESULT, 'kernel-retention-complete.json')):
        refuse('already_attempted_use_recovery')
    plan, checksum = load_original_plan(stage, historical=True)
    verify_signed_history(stage, plan, runner=runner)
    xml, _, inventory = rpm.inventory(runner)
    classify_inventory(plan, inventory, attempted=False)
    if rpm.sha(xml.encode()) != plan['inventory_sha256']:
        refuse('unattempted_header_inventory_changed')
    for path, expected in plan['preserved'].items():
        if path != kernel.GRUBENV and preserved_description(path) != expected:
            refuse('unattempted_protected_state_changed')
    for path, expected in plan['removed'].items():
        if kernel.describe(path) != expected:
            refuse('unattempted_target_changed')
    if (runner(['/usr/bin/uname', '-r']) != plan['acceptance']['kernel']
            or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + plan['acceptance']['kernel']):
        refuse('unattempted_running_default_changed')
    return plan, checksum


def _load_plan(stage, *, historical):
    stage = Path(stage)
    raw = rpm.read(stage / PLAN, rpm.MAX_XML)
    plan = strict_json(raw)
    exact(plan, {'schema', 'kind', 'operation_sha256', 'acceptance', 'boot_id', 'kernel', 'machine_id', 'key_sha256', 'keydb',
                 'packages', 'target', 'before_inventory', 'after_inventory', 'inventory_sha256', 'removed',
                 'preserved', 'mutable_directories', 'retained_kernels'})
    approved = plan['acceptance']
    if historical:
        historical_acceptance(stage, approved)
    elif approved != acceptance_record(stage) or plan['boot_id'] != boot_id():
        refuse('plan_binding_changed')
    if (type(plan['schema']) is not int or plan['schema'] != 1 or plan['kind'] != KIND or plan['key_sha256'] != rpm.KEY_SHA256
            or not re.fullmatch(r'kernel-retention-keydb-[a-f0-9]{32}', str(plan['keydb']))
            or plan['operation_sha256'] != rpm.sha(rpm.read(stage / 'operation.json', 8192))
            or plan['boot_id'] != approved['boot_id'] or raw != kernel.encode(plan)
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


def execute_cached(stage, *, authorize, accepted, runner=run, generation=None):
    require_linux_root()
    stage = Path(stage)
    if os.path.lexists(stage / INTENT):
        refuse('already_attempted_use_recovery')
    if generation is None:
        plan, checksum = load_plan(stage)
    else:
        from . import kernel_retention_generation
        plan, checksum = kernel_retention_generation.load(stage, generation, runner=runner)
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
    intent = {'schema': 1, 'plan_sha256': checksum, 'authorization': authorization}
    if generation is not None:
        intent.update(schema=2, generation=generation)
    kernel.record(stage, INTENT, intent)
    runner(command(plan), timeout=1800)
    return recover_cached(stage, authorize=authorize, accepted=accepted, runner=runner)


def recover_cached(stage, *, authorize, accepted, runner=run):
    """Inspect a complete erase; never retry RPM or delete residual paths."""
    require_linux_root()
    stage = Path(stage)
    plan, checksum = load_plan(stage)
    intent, _ = erase_intent(stage, plan, checksum)
    original = intent['authorization']
    exact(original, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    current = authorize_execution(stage, plan, checksum, authorize)
    if (intent['plan_sha256'] != checksum or original['ok'] is not True
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
    if not preparing:
        verify_integrity_attempt(manager, identity, stage, plan, checksum, parsed, rpm.sha(raw))
    return parsed, rpm.sha(raw)


def verify_integrity_attempt(manager, identity, stage, plan, checksum, integrity, integrity_sha):
    """A forward baseline change requires the actual once-only erase owner."""
    from . import aide_updates
    if not os.path.lexists(Path(stage) / INTENT):
        refuse('integrity_acceptance_requires_erase_intent')
    intent, _ = erase_intent(stage, plan, checksum)
    _, prepared = aide_updates._prepared(manager, identity.root / 'manager/aide', identity,
                                         stage, integrity, integrity_sha)
    if prepared is None or digest(prepared) != intent['authorization']['aide_preparation_sha256']:
        refuse('integrity_attempt_preparation_changed')


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


def erase_intent(stage, plan, checksum):
    """Validate the one global attempt sentinel without authorizing its replay."""
    raw = rpm.read(Path(stage) / INTENT, 8192)
    intent = strict_json(raw)
    from . import kernel_retention_generation as generation
    exact(intent, {'schema', 'plan_sha256', 'authorization'} | ({'generation'} if intent.get('schema') == 2 else set()))
    if intent.get('schema') == 2:
        effective, effective_sha = generation.load(stage, intent['generation'], historical=True)
        if effective != plan or effective_sha != checksum:
            refuse('execution_intent_plan_changed')
    value = intent['authorization']
    exact(value, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    if (type(intent['schema']) is not int or intent['schema'] not in (1, 2) or raw != kernel.encode(intent)
            or intent['plan_sha256'] != checksum or value['ok'] is not True
            or value['plan_sha256'] != checksum or value['boot_id'] != plan['boot_id']
            or any(not kernel.SHA.fullmatch(str(value[key])) for key in ('backup_sha256', 'aide_preparation_sha256'))):
        refuse('historical_erase_intent_changed')
    return intent, rpm.sha(raw)


def classify_inventory(plan, inventory, *, attempted):
    """Pure classification; even unchanged RPM inventory cannot disprove execution."""
    if inventory == plan['before_inventory']:
        if attempted:
            refuse('attempted_erase_outcome_ambiguous_no_replay')
        return 'unattempted'
    if inventory == plan['after_inventory'] and attempted:
        return 'exact_erased'
    refuse('partial_or_unowned_erase_requires_recovery')


def verify_signed_history(stage, plan, *, runner=run):
    """Revalidate the vendor bytes and original headers after installed erasure."""
    stage = Path(stage)
    rpm.platform(runner)
    verify_remove_hooks()
    if os.readlink('/lib') != 'usr/lib' or rpm.sha(rpm.read(rpm.KEY, 65536)) != plan['key_sha256']:
        refuse('historical_vendor_trust_changed')
    original = rpm.read(stage / 'kernel-retention-inventory.xml', rpm.MAX_XML)
    headers = rpm.headers(original.decode())
    inventory = sorted(rpm.identity(header)['nevra'] for header in headers)
    if rpm.sha(original) != plan['inventory_sha256'] or inventory != plan['before_inventory']:
        refuse('historical_inventory_changed')
    original_by_nevra = {rpm.identity(header)['nevra']: header for header in headers}
    files = {}
    for item in plan['packages']:
        if (item.get('rpm') != item.get('sha256', '') + '.rpm'
                or not kernel.SHA.fullmatch(str(item.get('sha256')))
                or type(item.get('bytes')) is not int or not 0 < item['bytes'] <= rpm.MAX_RPM):
            refuse('historical_package_identity_changed')
        path = stage / 'kernel-retention-packages' / item['rpm']
        raw = rpm.read(path)
        if (len(raw) != item['bytes'] or rpm.sha(raw) != item['sha256']
                or rpm.signature(path, stage / plan['keydb'], runner) != item['signature']):
            refuse('historical_signed_package_changed')
        queried = rpm.headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(path)], timeout=180))
        if len(queried) != 1:
            refuse('historical_signed_header_ambiguous')
        payload = kernel.payload(queried[0])
        if payload != kernel.payload(original_by_nevra[item['nevra']]):
            refuse('historical_installed_header_changed')
        for entry in payload.pop('files'):
            if entry['path'] in files and files[entry['path']] != entry:
                refuse('historical_payload_overlap')
            files[entry['path']] = entry
        if payload != {key: value for key, value in item.items() if key not in {'rpm', 'sha256', 'bytes', 'signature'}}:
            refuse('historical_signed_payload_changed')
    if files != {item['path']: item for item in plan['target']['files']}:
        refuse('historical_frozen_payload_changed')


def _exact_erased(stage, plan, *, runner):
    verify_signed_history(stage, plan, runner=runner)
    _, _, inventory = rpm.inventory(runner)
    classify_inventory(plan, inventory, attempted=True)
    for path, expected in plan['preserved'].items():
        # Boot owns the *exact* transition of this one file. This observation
        # only supplies inventory authority; it cannot accept integrity.
        if path != kernel.GRUBENV and preserved_description(path) != expected:
            refuse('recovery_protected_state_changed')
    if any(os.path.lexists(path) for path in plan['removed']):
        refuse('recovery_erase_target_still_present')
    approved = plan['acceptance']
    if (runner(['/usr/bin/uname', '-r']) != approved['kernel']
            or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + approved['kernel']):
        refuse('recovery_running_default_changed')
    return inventory


def _boot_observation(stage, *, runner):
    plan, checksum = load_historical_plan(stage)
    _, intent_sha = erase_intent(stage, plan, checksum)
    inventory = _exact_erased(stage, plan, runner=runner)
    current = boot_id()
    if current == plan['boot_id']:
        refuse('later_boot_required')
    candidate_stage, candidate, candidate_sha, _ = kernel.load_candidate(stage)
    raw = rpm.read(kernel.GRUBENV, 1024)
    observed = kernel.describe(kernel.GRUBENV)
    if (len(raw) != 1024 or observed.get('kind') != 'file'
            or observed.get('sha256') != rpm.sha(raw) or observed.get('bytes') != len(raw)):
        refuse('recovery_environment_observation_changed')
    return {'schema': 1, 'kind': 'kernel-retention-observation-v1', 'stage': str(stage),
            'operation_sha256': plan['operation_sha256'], 'retention_plan_sha256': checksum,
            'erase_intent_sha256': intent_sha, 'original_acceptance_sha256': plan['acceptance']['receipt_sha256'],
            'candidate_plan_sha256': candidate_sha,
            'installed_sha256': rpm.sha(rpm.read(candidate_stage / 'kernel-installed.json', rpm.MAX_XML)),
            'boot_id': current, 'kernel': candidate['kernel'], 'recovery_kernel': candidate['old_kernel'],
            'after_inventory': inventory, 'grub_before': plan['preserved'][kernel.GRUBENV],
            'grub_observed': observed, 'grub_observed_raw': base64.b64encode(raw).decode()}


def _reference(stage, reference, pattern):
    exact(reference, {'filename', 'sha256'})
    if (not isinstance(reference['filename'], str) or not pattern.fullmatch(reference['filename'])
            or not kernel.SHA.fullmatch(str(reference['sha256']))):
        refuse('invalid_recovery_reference')
    raw = rpm.read(Path(stage) / reference['filename'], rpm.MAX_XML)
    value = strict_json(raw)
    if rpm.sha(raw) != reference['sha256'] or raw != kernel.encode(value):
        refuse('recovery_reference_changed')
    return value


def observe_boot_authority(stage, *, runner=run):
    """Retain exact erasure evidence; this cannot authorize RPM or AIDE adoption."""
    require_linux_root()
    stage = Path(stage)
    value = _boot_observation(stage, runner=runner)
    name = 'kernel-retention-observation-' + value['boot_id'] + '.json'
    kernel.record(stage, name, value)
    return {'filename': name, 'sha256': rpm.sha(kernel.encode(value))}


def validate_boot_authority(stage, reference, *, runner=run, historical=False):
    """The only supported exact-three inventory exception for candidate proof."""
    stage = Path(stage)
    value = _reference(stage, reference, OBSERVATION)
    plan, checksum = load_historical_plan(stage)
    _, intent_sha = erase_intent(stage, plan, checksum)
    candidate_stage, candidate, candidate_sha, _ = kernel.load_candidate(stage)
    exact(value, {'schema', 'kind', 'stage', 'operation_sha256', 'retention_plan_sha256', 'erase_intent_sha256',
                  'original_acceptance_sha256', 'candidate_plan_sha256', 'installed_sha256', 'boot_id', 'kernel',
                  'recovery_kernel', 'after_inventory', 'grub_before', 'grub_observed', 'grub_observed_raw'})
    if (type(value['schema']) is not int or value['schema'] != 1 or value['kind'] != 'kernel-retention-observation-v1'
            or value['stage'] != str(stage) or value['operation_sha256'] != plan['operation_sha256']
            or value['retention_plan_sha256'] != checksum or value['erase_intent_sha256'] != intent_sha
            or value['original_acceptance_sha256'] != plan['acceptance']['receipt_sha256']
            or value['candidate_plan_sha256'] != candidate_sha
            or value['installed_sha256'] != rpm.sha(rpm.read(candidate_stage / 'kernel-installed.json', rpm.MAX_XML))
            or value['kernel'] != candidate['kernel'] or value['recovery_kernel'] != candidate['old_kernel']
            or value['after_inventory'] != plan['after_inventory']
            or value['grub_before'] != plan['preserved'][kernel.GRUBENV]
            or reference['filename'] != 'kernel-retention-observation-' + value['boot_id'] + '.json'
            or value['boot_id'] == plan['boot_id']):
        refuse('recovery_observation_binding_changed')
    try:
        raw = base64.b64decode(value['grub_observed_raw'], validate=True)
        valid_boot = str(uuid.UUID(value['boot_id'])) == value['boot_id']
    except (ValueError, TypeError, AttributeError):
        refuse('invalid_recovery_observation')
    if (not valid_boot or len(raw) != 1024 or value['grub_observed'].get('sha256') != rpm.sha(raw)
            or value['grub_observed'].get('bytes') != 1024):
        refuse('invalid_recovery_observation')
    if not historical and value != _boot_observation(stage, runner=runner):
        refuse('recovery_observation_no_longer_current')
    return value


def resume_origin(stage, path):
    """Identify the original AIDE preparation, independent of its current DB."""
    stage, path = Path(stage), Path(path)
    if path.parent != stage or not RESUME_NAME.fullmatch(path.name):
        refuse('unowned_resume_plan')
    value = strict_json(rpm.read(path, rpm.MAX_XML))
    original, checksum = load_historical_plan(stage)
    intent, intent_sha = erase_intent(stage, original, checksum)
    integrity_raw = rpm.read(execution_integrity_path(stage, checksum), rpm.MAX_XML)
    integrity = strict_json(integrity_raw)
    if (integrity_raw != kernel.encode(integrity) or integrity != integrity_plan(original, checksum)
            or value.get('retention_plan_sha256') != checksum
            or value.get('original_integrity_sha256') != rpm.sha(integrity_raw)
            or value.get('original_preparation_sha256') != intent['authorization']['aide_preparation_sha256']
            or value.get('erase_intent_sha256') != intent_sha):
        refuse('resume_original_preparation_changed')
    return {'plan': original, 'plan_sha256': checksum, 'integrity': integrity,
            'integrity_sha256': rpm.sha(integrity_raw),
            'prepared_sha256': intent['authorization']['aide_preparation_sha256'],
            'intent': intent, 'intent_sha256': intent_sha}


def _provisional(value, stage, observation):
    exact(value, PROVISIONAL_FIELDS)
    if (value['ok'] is not True or value['stage'] != str(stage)
            or value['boot_id'] != observation['boot_id']
            or value['operation_sha256'] != observation['operation_sha256']
            or value['retention_plan_sha256'] != observation['retention_plan_sha256']
            or not kernel.SHA.fullmatch(str(value['backup_sha256']))
            or not isinstance(value['backup_stage'], str)
            or Path(value['backup_stage']).parent != Path(stage).parent
            or not re.fullmatch(r'[a-f0-9]{32}', Path(value['backup_stage']).name)):
        refuse('provisional_recovery_authorization_changed')
    return value


def prepare_resume(stage, authority_ref, boot_ref, *, authorize, runner=run):
    """Freeze a compound integrity reconciliation; never invoke RPM erasure."""
    from . import kernel_boot
    require_linux_root()
    stage = Path(stage)
    observed = validate_boot_authority(stage, authority_ref, runner=runner)
    boot = kernel_boot.validate_retention_resume(stage, boot_ref, runner=runner)
    authorization = _provisional(authorize(stage, observed['retention_plan_sha256']), stage, observed)
    pointer = stage / 'kernel-retention-resume-current.json'
    linked = kernel_boot.read_retention_integrity_binding(stage, boot_ref)
    if linked is not None:
        parsed, _ = load_resume(stage, linked, runner=runner)
        if parsed['authority_ref'] != authority_ref or parsed['boot_ref'] != boot_ref:
            refuse('linked_resume_plan_changed')
        atomic_json(pointer, linked)
        return stage / linked['filename'], parsed
    if os.path.lexists(pointer):
        previous = strict_json(rpm.read(pointer, 8192))
        value = _reference(stage, previous, RESUME_NAME)
        if value.get('boot_id') == observed['boot_id']:
            parsed, checksum = load_resume(stage, previous, runner=runner)
            if parsed['authority_ref'] != authority_ref or parsed['boot_ref'] != boot_ref:
                refuse('current_resume_plan_changed')
            kernel_boot.bind_retention_integrity(stage, boot_ref, previous, runner=runner)
            return stage / previous['filename'], parsed
    original, checksum = load_historical_plan(stage)
    intent, intent_sha = erase_intent(stage, original, checksum)
    integrity_raw = rpm.read(execution_integrity_path(stage, checksum), rpm.MAX_XML)
    if strict_json(integrity_raw) != integrity_plan(original, checksum):
        refuse('original_integrity_plan_changed')
    if (boot['plan_sha256'] != boot_ref['sha256'] or boot['boot_id'] != observed['boot_id']
            or boot['authority_ref'] != authority_ref or boot['kernel'] != observed['kernel']
            or boot['recovery_kernel'] != observed['recovery_kernel']
            or boot['operation_sha256'] != observed['operation_sha256']
            or len(boot['files']) != 1 or boot['files'][0]['path'] != kernel.GRUBENV
            or boot['files'][0]['after'] != observed['grub_observed']):
        refuse('qualified_boot_resume_changed')
    token = uuid.uuid4().hex
    value = {'schema': 1, 'kind': RESUME_KIND, 'sequence': 0, 'id': token, 'stage': str(stage),
             'operation_sha256': original['operation_sha256'], 'boot_id': observed['boot_id'],
             'retention_plan_sha256': checksum, 'authority_ref': authority_ref, 'boot_ref': boot_ref,
             'previous_retention_plan': boot['previous_retention_plan'],
             'original_integrity_sha256': rpm.sha(integrity_raw),
             'original_preparation_sha256': intent['authorization']['aide_preparation_sha256'],
             'erase_intent_sha256': intent_sha, 'authorization': authorization,
             'removed': original['removed'],
             'preserved': {key: value for key, value in original['preserved'].items() if key != kernel.GRUBENV},
             'mutable_directories': original['mutable_directories'],
             'files': [{'path': kernel.GRUBENV, 'before': original['preserved'][kernel.GRUBENV],
                        'after': observed['grub_observed']}]}
    value['manifest_sha256'] = digest(value)
    name = 'kernel-retention-resume-' + token + '-plan.json'
    kernel.record(stage, name, value)
    reference = {'filename': name, 'sha256': rpm.sha(kernel.encode(value))}
    load_resume(stage, reference, runner=runner)
    kernel_boot.bind_retention_integrity(stage, boot_ref, reference, runner=runner)
    # Publishing the pointer does not supersede the original erase sentinel.
    atomic_json(pointer, reference)
    return stage / name, value


def load_resume(stage, reference, *, runner=run, historical=False):
    from . import kernel_boot
    stage = Path(stage)
    value = _reference(stage, reference, RESUME_NAME)
    exact(value, {'schema', 'kind', 'sequence', 'id', 'stage', 'operation_sha256', 'boot_id',
                  'retention_plan_sha256', 'authority_ref', 'boot_ref', 'original_integrity_sha256',
                  'previous_retention_plan',
                  'original_preparation_sha256', 'erase_intent_sha256', 'authorization', 'removed',
                  'preserved', 'mutable_directories', 'files', 'manifest_sha256'})
    origin = resume_origin(stage, stage / reference['filename'])
    original = origin['plan']
    observed = validate_boot_authority(stage, value['authority_ref'], runner=runner, historical=historical)
    boot = kernel_boot.validate_retention_resume(stage, value['boot_ref'], runner=runner, historical=historical)
    _provisional(value['authorization'], stage, observed)
    if (type(value['schema']) is not int or value['schema'] != 1 or value['kind'] != RESUME_KIND
            or type(value['sequence']) is not int or value['sequence'] != 0
            or reference['filename'] != 'kernel-retention-resume-' + value['id'] + '-plan.json'
            or value['stage'] != str(stage) or value['operation_sha256'] != original['operation_sha256']
            or value['boot_id'] != observed['boot_id'] or boot['boot_id'] != observed['boot_id']
            or boot['plan_sha256'] != value['boot_ref']['sha256'] or boot['authority_ref'] != value['authority_ref']
            or value['previous_retention_plan'] != boot['previous_retention_plan']
            or boot['kernel'] != observed['kernel'] or boot['recovery_kernel'] != observed['recovery_kernel']
            or boot['operation_sha256'] != observed['operation_sha256']
            or len(boot['files']) != 1 or boot['files'][0]['path'] != kernel.GRUBENV
            or boot['files'][0]['after'] != observed['grub_observed']
            or value['removed'] != original['removed']
            or value['preserved'] != {key: item for key, item in original['preserved'].items() if key != kernel.GRUBENV}
            or value['mutable_directories'] != original['mutable_directories']
            or value['files'] != [{'path': kernel.GRUBENV, 'before': original['preserved'][kernel.GRUBENV],
                                   'after': observed['grub_observed']}]
            or value['manifest_sha256'] != digest({key: item for key, item in value.items() if key != 'manifest_sha256'})):
        refuse('compound_resume_scope_changed')
    return value, reference['sha256']


def resume_integrity_predecessor(stage, path):
    """One exact ancestry edge, including planned generations never prepared."""
    from . import kernel_boot
    stage, path = Path(stage), Path(path)
    raw = rpm.read(path, rpm.MAX_XML)
    reference = {'filename': path.name, 'sha256': rpm.sha(raw)}
    plan, _ = load_resume(stage, reference, historical=True)
    kernel_boot.verify_retention_integrity_binding(stage, plan['boot_ref'], reference)
    previous = plan['previous_retention_plan']
    if previous is None:
        origin = resume_origin(stage, path)
        return origin['integrity'], origin['integrity_sha256']
    prior, checksum = load_resume(stage, previous, historical=True)
    kernel_boot.verify_retention_integrity_binding(stage, prior['boot_ref'], previous)
    if (prior['id'] == plan['id'] or prior['boot_id'] == plan['boot_id']
            or any(prior[key] != plan[key] for key in ('operation_sha256', 'retention_plan_sha256',
                   'original_integrity_sha256', 'original_preparation_sha256', 'erase_intent_sha256'))):
        refuse('resume_predecessor_changed')
    return prior, checksum


def bound_resume_integrity_plan(manager, stage, path, *, preparing):
    from . import kernel_boot
    identity = manager.guard()
    stage, path = Path(stage), Path(path)
    if stage.is_symlink() or stage.parent != identity.root / 'manager/os-updates' or path.parent != stage:
        refuse('unowned_resume_integrity_stage')
    raw = manager.reader(path, maximum=rpm.MAX_XML, private=True)
    reference = {'filename': path.name, 'sha256': rpm.sha(raw)}
    value, checksum = load_resume(stage, reference, runner=run)
    kernel_boot.verify_retention_integrity_binding(stage, value['boot_ref'], reference)
    latest = strict_json(rpm.read(identity.root / 'manager/os-latest.json', 65536))
    journal = strict_json(rpm.read(identity.root / 'manager/os-transaction.json', 65536))
    if (latest.get('stage') != str(stage) or journal.get('stage') != str(stage)
            or journal.get('kernel_retention') not in {'pending', 'failed'}
            or journal.get('state') not in {'complete', 'recovery_required', 'retaining', 'retention_postcheck', 'retention_recovery_required'}):
        refuse('resume_integrity_operation_binding_changed')
    return value, checksum


def resume_integrity_snapshot(manager, plan, phase, retained=None):
    if phase not in {'prepare', 'forward'}:
        refuse('unsupported_resume_integrity_phase')
    # Retain original authorized preimages through every CAS. A fresh scan
    # observes the compound delta; it does not invent a clean preparation.
    values = integrity_snapshot(manager, plan, 'forward',
                                None if retained is None else {key: item for key, item in retained.items() if key != kernel.GRUBENV})
    item = plan['files'][0]
    if item['path'] != kernel.GRUBENV or kernel.describe(kernel.GRUBENV) != item['after']:
        refuse('resume_environment_metadata_changed')
    if retained is not None and retained.get(kernel.GRUBENV) != item['before']:
        refuse('resume_environment_preimage_changed')
    values[kernel.GRUBENV] = item['before']
    return values


def allowed_resume_integrity_report(report, plan, phase):
    if phase not in {'prepare', 'forward'}:
        refuse('unsupported_resume_integrity_phase')
    allowed = {**plan, 'mutable_directories': [*plan['mutable_directories'], kernel.GRUBENV]}
    allowed_integrity_report(report, allowed, 'forward')


def validate_boot_completion(stage, boot_ref, compound_ref, *, runner=run, historical=False):
    """Verify real published AIDE evidence; never accept a hash-shaped approval."""
    from . import aide_updates, kernel_boot
    stage = Path(stage)
    result = _reference(stage, compound_ref, RESUME_RESULT)
    exact(result, {'schema', 'status', 'plan', 'boot_ref', 'authority_ref', 'boot_id', 'kernel',
                   'retention_plan_sha256', 'aide', 'release_accepted'})
    plan, checksum = load_resume(stage, result['plan'], runner=runner, historical=historical)
    kernel_boot.verify_retention_integrity_binding(stage, boot_ref, result['plan'])
    observed = validate_boot_authority(stage, plan['authority_ref'], runner=runner, historical=historical)
    if (type(result['schema']) is not int or result['schema'] != 1 or result['status'] != 'integrity_reconciled'
            or result['release_accepted'] is not False or result['plan']['sha256'] != checksum
            or compound_ref['filename'] != 'kernel-retention-resume-' + plan['id'] + '-result.json'
            or result['boot_ref'] != boot_ref or result['boot_ref'] != plan['boot_ref']
            or result['authority_ref'] != plan['authority_ref'] or result['boot_id'] != plan['boot_id']
            or result['kernel'] != observed['kernel'] or result['retention_plan_sha256'] != plan['retention_plan_sha256']):
        refuse('compound_integrity_result_changed')
    aide_updates.retained_plan_acceptance(stage, stage / result['plan']['filename'],
                                         expected=result['aide'], historical=historical)
    return result
