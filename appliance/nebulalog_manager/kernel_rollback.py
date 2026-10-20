"""Remove one rejected, never accepted vendor kernel after verified fallback.

The install receipt selects the four packages; age never selects a rollback.
The caller owns lifecycle/update locks. RPM has one durable attempt sentinel,
and recovery only inspects its result. Source RPMs and all boot/AIDE evidence
remain intact. Completing this recipe is not release or kernel acceptance.
"""
from __future__ import annotations

import base64
import copy
import os
from pathlib import Path
import re
import uuid

from . import kernel_boot as boot, kernel_retention as mechanical, kernel_updates as kernel, os_payload as rpm
from .common import Refused, atomic_json, require_linux_root, run
from .host_job_storage import digest, exact, strict_json

KIND = 'rocky-kernel-rollback-v1'
PLAN = 'kernel-rollback-plan.json'
INTEGRITY = 'kernel-rollback-integrity-plan.json'
INTENT = 'kernel-rollback-intent.json'
RESULT = 'kernel-rollback-result.json'
COMPLETE = 'kernel-rollback-complete.json'
OWNER = 'kernel-rollback-owner.json'
RESUME_NAME = re.compile(r'kernel-rollback-resume-([a-f0-9]{32})-integrity\.json')
RESUME_CURRENT = 'kernel-rollback-resume-current.json'
EXECUTION_NAME = re.compile(r'kernel-rollback-execution-([a-f0-9]{32})-integrity\.json')
EXECUTION_PLAN = re.compile(r'kernel-rollback-execution-([a-f0-9]{32})-plan\.json')
EXECUTION_CURRENT = 'kernel-rollback-execution-current.json'


def refuse(reason):
    raise Refused('kernel_rollback_' + reason)


def _read(path):
    raw = rpm.read(path, rpm.MAX_XML)
    value = strict_json(raw)
    if raw != kernel.encode(value):
        refuse('noncanonical_record')
    return value, rpm.sha(raw)


def _candidate(stage, plan):
    """Historical origin lookup deliberately does not require live payloads."""
    from .kernel_retention_integration import owned_stage
    source = Path(plan['candidate_stage'])
    owned_stage(source, Path(stage).parent)
    candidate, checksum = kernel.load_plan(source)
    installed, installed_sha = _read(source / 'kernel-installed.json')
    owner, _ = _read(source / OWNER)
    if (type(owner.get('schema')) is not int or owner != {
            'schema': 1, 'stage': str(stage), 'candidate_plan_sha256': checksum,
            'installed_sha256': installed_sha, 'operation_sha256': plan['operation_sha256']}):
        refuse('candidate_rollback_owner_changed')
    if (type(installed.get('schema')) is not int or installed['schema'] != 1
            or installed.get('status') != 'installed_pending_integrity_and_reboot'
            or checksum != plan['candidate_plan_sha256'] or installed_sha != plan['installed_sha256']
            or installed.get('plan_sha256') != checksum or installed.get('kernel') != candidate['kernel']
            or installed.get('old_kernel') != candidate['old_kernel']
            or installed.get('release_accepted') is not False
            or plan['kernel'] != candidate['kernel'] or plan['recovery_kernel'] != candidate['old_kernel']):
        refuse('candidate_origin_changed')
    return source, candidate, installed


def _scope(candidate):
    paths = {item['path'] for item in candidate['files']}
    generated = kernel.generated_paths(candidate['kernel'], candidate['machine_id'])
    shared = set(candidate['shared'])
    removed = (paths | generated) - shared
    version = candidate['kernel']
    root, docs = '/usr/lib/modules/' + version, '/usr/share/doc/kernel-keys/' + version
    license_path = '/usr/share/licenses/kernel-core/COPYING-' + version.removesuffix('.x86_64')
    if (len(paths) != len(candidate['files']) or candidate['generated'] != sorted(generated)
            or not shared <= paths
            or any(item['kind'] != 'directory' for item in candidate['files'] if item['path'] in shared)
            or any(kernel.canonical(path) != path or not (path == root or path.startswith(root + '/')
                    or path == docs or path.startswith(docs + '/') or path == license_path or path in generated)
                   for path in removed)):
        refuse('candidate_path_scope_changed')
    return removed, {str(Path(path).parent) for path in removed} - removed


def _installed_scope(headers, candidate, removed):
    erase = {p['nevra'] for p in candidate['packages']}
    groups, preserved = {}, set(candidate['shared']) | {kernel.GRUBENV, kernel.KERNEL_CONFIG,
                                                       '/etc/default/grub', '/boot/grub2/grub.cfg'}
    for header in headers:
        identity = rpm.identity(header)
        if identity['nevra'] in erase:
            if kernel.payload(header) != _signed_payload(candidate, identity['name']):
                refuse('installed_candidate_header_changed')
            continue
        dirs, names, indices = header.get('Dirnames', []), header.get('Basenames', []), header.get('Dirindexes', [])
        if len(names) != len(indices):
            refuse('installed_file_inventory_invalid')
        for name, index in zip(names, indices):
            if type(index) is not int or not 0 <= index < len(dirs):
                refuse('installed_file_inventory_invalid')
            if kernel.canonical(dirs[index] + name) in removed:
                refuse('target_owned_by_retained_package')
        if identity['name'] in kernel.NAMES:
            version = kernel.version(header)
            names = groups.setdefault(version, set())
            if identity['name'] in names:
                refuse('duplicate_retained_package')
            names.add(identity['name'])
            preserved.update(p['path'] for p in kernel.payload(header)['files'])
            preserved.update(kernel.generated_paths(version, candidate['machine_id']))
    if (not 1 <= len(groups) <= 3 or candidate['old_kernel'] not in groups or candidate['kernel'] in groups
            or any(names != kernel.NAMES for names in groups.values())):
        refuse('incomplete_protected_kernel_sets')
    rpm.external_triggers(headers, kernel.NAMES, removed | {p.removeprefix('/usr') for p in removed if p.startswith('/usr/lib/')})
    return sorted(groups, key=mechanical.version_order), preserved


def _signed_payload(candidate, name):
    # Package overlap is allowed only when every signed descriptor agrees.
    item = next(p for p in candidate['packages'] if p['name'] == name)
    return {key: value for key, value in item.items() if key not in {'rpm', 'sha256', 'bytes', 'signature'}} | {
        'files': candidate['_package_files'][name]}


def verify_signed_history(stage, plan, *, runner=run):
    """Revalidate retained vendor RPMs even after the installed files are gone."""
    source, candidate, installed = _candidate(stage, plan)
    rpm.platform(runner)
    mechanical.verify_remove_hooks()
    if os.readlink('/lib') != 'usr/lib' or rpm.sha(rpm.read(rpm.KEY, 65536)) != rpm.KEY_SHA256:
        refuse('vendor_trust_changed')
    packages, files, by_package = candidate['packages'], {}, {}
    if (len(packages) != 4 or {p['name'] for p in packages} != kernel.NAMES
            or len({p['nevra'] for p in packages}) != 4):
        refuse('candidate_package_set_changed')
    for item in packages:
        if (item['kernel'] != candidate['kernel'] or item['nevra'] != item['name'] + '-0:' + candidate['kernel']
                or not kernel.SHA.fullmatch(str(item['sha256'])) or item['rpm'] != item['sha256'] + '.rpm'
                or type(item['bytes']) is not int or not 0 < item['bytes'] <= rpm.MAX_RPM):
            refuse('candidate_package_identity_changed')
        path = source / 'kernel-packages' / item['rpm']
        raw = rpm.read(path)
        if (len(raw) != item['bytes'] or rpm.sha(raw) != item['sha256']
                or rpm.signature(path, source / 'kernel-keydb', runner) != item['signature']):
            refuse('retained_signed_rpm_changed')
        queried = rpm.headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(path)], timeout=180))
        if len(queried) != 1:
            refuse('ambiguous_retained_signed_header')
        payload = kernel.payload(queried[0])
        by_package[item['name']] = payload.pop('files')
        if payload != {key: value for key, value in item.items() if key not in {'rpm', 'sha256', 'bytes', 'signature'}}:
            refuse('retained_signed_header_changed')
        for entry in by_package[item['name']]:
            if entry['path'] in files and files[entry['path']] != entry:
                refuse('retained_signed_payload_overlap')
            files[entry['path']] = entry
    if sorted(files.values(), key=lambda p: p['path']) != candidate['files']:
        refuse('retained_signed_payload_changed')
    return {**candidate, '_package_files': by_package}


def plan_cached(stage, *, authorize, runner=run):
    require_linux_root()
    stage = Path(stage)
    if any(os.path.lexists(stage / name) for name in (PLAN, INTENT, RESULT, COMPLETE)):
        refuse('already_planned_or_attempted')
    recovery = boot.verified_recovery(stage, runner=runner)
    authority = boot.recovery_authorization(stage, authorize, runner=runner)
    source, candidate, checksum, installed = kernel.load_candidate(stage)
    plan = {'schema': 1, 'kind': KIND, 'operation_sha256': rpm.sha(rpm.read(stage / 'operation.json', 8192)),
            'boot_id': recovery['boot_id'], 'candidate_stage': str(source), 'candidate_plan_sha256': checksum,
            'installed_sha256': rpm.sha(rpm.read(source / 'kernel-installed.json', rpm.MAX_XML)),
            'kernel': candidate['kernel'], 'recovery_kernel': candidate['old_kernel'], 'recovery': recovery}
    kernel.record(source, OWNER, {'schema': 1, 'stage': str(stage), 'candidate_plan_sha256': checksum,
                                 'installed_sha256': plan['installed_sha256'],
                                 'operation_sha256': plan['operation_sha256']})
    signed = verify_signed_history(stage, plan, runner=runner)
    kernel.verify_payload(candidate, runner=runner)
    if kernel.generated_snapshot(candidate, runner=runner) != installed['generated']:
        refuse('candidate_generated_outputs_changed')
    mechanical.validate_boot_scope(candidate['kernel'], candidate['machine_id'], set(candidate['generated']))
    xml, headers, inventory = rpm.inventory(runner)
    if inventory != candidate['after_inventory']:
        refuse('candidate_installed_inventory_changed')
    removed, parents = _scope(candidate)
    retained, preserved_paths = _installed_scope(headers, signed, removed)
    preserved_paths |= parents
    if preserved_paths & removed:
        refuse('protected_removal_overlap')
    preserved = {p: mechanical.preserved_description(p) for p in sorted(preserved_paths)}
    if any(preserved[p]['kind'] != 'directory' for p in parents):
        refuse('removal_parent_is_not_directory')
    if preserved[kernel.GRUBENV] != recovery['mutable'][kernel.GRUBENV]:
        refuse('recovery_environment_changed')
    plan.update(before_inventory=inventory, after_inventory=candidate['before_inventory'],
                inventory_sha256=rpm.sha(xml.encode()), packages=candidate['packages'],
                removed={p: kernel.describe(p) for p in sorted(removed)}, preserved=preserved,
                mutable_directories=sorted(parents), retained_kernels=retained)
    runner(mechanical.command(plan, True), timeout=180)
    if (boot.verified_recovery(stage, runner=runner) != recovery
            or boot.recovery_authorization(stage, authorize, runner=runner) != authority
            or rpm.inventory(runner)[0] != xml):
        refuse('planning_context_changed')
    verify_files(plan, 'prepare', runner=runner)
    rpm.immutable(stage / 'kernel-rollback-inventory.xml', xml.encode())
    kernel.record(stage, PLAN, plan)
    checksum = rpm.sha(kernel.encode(plan))
    kernel.record(stage, INTEGRITY, integrity_plan(plan, checksum))
    return plan, checksum


def _load_frozen(stage, path, *, runner=run):
    stage = Path(stage)
    plan, checksum = _read(path)
    exact(plan, {'schema', 'kind', 'operation_sha256', 'boot_id', 'candidate_stage', 'candidate_plan_sha256',
                 'installed_sha256', 'kernel', 'recovery_kernel', 'recovery', 'before_inventory', 'after_inventory',
                 'inventory_sha256', 'packages', 'removed', 'preserved', 'mutable_directories', 'retained_kernels'})
    _, candidate, installed = _candidate(stage, plan)
    removed, parents = _scope(candidate)
    erase = {p['nevra'] for p in candidate['packages']}
    recovery = plan['recovery']
    if (type(plan['schema']) is not int or plan['schema'] != 1 or plan['kind'] != KIND
            or plan['operation_sha256'] != rpm.sha(rpm.read(stage / 'operation.json', 8192))
            or plan['packages'] != candidate['packages'] or len(erase) != 4
            or plan['before_inventory'] != candidate['after_inventory']
            or plan['after_inventory'] != candidate['before_inventory']
            or plan['after_inventory'] != sorted(set(plan['before_inventory']) - erase)
            or plan['boot_id'] != recovery['boot_id'] or plan['kernel'] != recovery['kernel']
            or plan['recovery_kernel'] != recovery['recovery_kernel']
            or plan['candidate_plan_sha256'] != recovery['candidate_plan_sha256']
            or plan['installed_sha256'] != recovery['installed_sha256']
            or plan['operation_sha256'] != recovery['operation_sha256']
            or plan['preserved'].get(kernel.GRUBENV) != recovery['mutable'][kernel.GRUBENV]
            or set(plan['removed']) != removed or plan['mutable_directories'] != sorted(parents)
            or set(plan['preserved']) & removed):
        refuse('frozen_rollback_scope_changed')
    signed = verify_signed_history(stage, plan, runner=runner)
    xml = rpm.read(stage / 'kernel-rollback-inventory.xml', rpm.MAX_XML)
    headers = rpm.headers(xml.decode())
    retained, protected = _installed_scope(headers, signed, removed)
    if (rpm.sha(xml) != plan['inventory_sha256']
            or sorted(rpm.identity(h)['nevra'] for h in headers) != plan['before_inventory']
            or plan['retained_kernels'] != retained or set(plan['preserved']) != protected | parents
            or any(plan['preserved'][p].get('kind') != 'directory' for p in parents)
            or any(plan['removed'].get(p) != value for p, value in installed['generated'].items())):
        refuse('historical_inventory_or_artifacts_changed')
    boot.validate_recovery_proof(stage, recovery, historical=True, runner=runner)
    return plan, checksum


def _execution_reference(stage, *, attempted_only=False):
    stage = Path(stage)
    if os.path.lexists(stage / INTENT):
        value, _ = _read(stage / INTENT)
        if type(value.get('schema')) is not int or value['schema'] not in (1, 2):
            refuse('invalid_global_erase_intent')
        exact(value, {'schema', 'plan_sha256', 'authorization'} | ({'generation'} if value['schema'] == 2 else set()))
        return value.get('generation')
    if not attempted_only and os.path.lexists(stage / EXECUTION_CURRENT):
        return strict_json(rpm.read(stage / EXECUTION_CURRENT, 8192))
    return None


def _load_execution(stage, reference, *, runner=run):
    exact(reference, {'filename', 'sha256'})
    if (not isinstance(reference['filename'], str) or not EXECUTION_PLAN.fullmatch(reference['filename'])
            or not kernel.SHA.fullmatch(str(reference['sha256']))):
        refuse('invalid_execution_reference')
    original, _ = _load_frozen(stage, Path(stage) / PLAN, runner=runner)
    plan, checksum = _load_frozen(stage, Path(stage) / reference['filename'], runner=runner)
    expected = copy.deepcopy(original)
    expected.update(boot_id=plan['boot_id'], recovery=plan['recovery'])
    expected['preserved'][kernel.GRUBENV] = plan['preserved'][kernel.GRUBENV]
    if plan != expected or reference['sha256'] != checksum:
        refuse('execution_original_scope_changed')
    return plan, checksum


def load_historical_plan(stage, *, runner=run):
    reference = _execution_reference(stage, attempted_only=True)
    if reference is None:
        return _load_frozen(stage, Path(stage) / PLAN, runner=runner)
    return _load_execution(stage, reference, runner=runner)


def load_plan_by_checksum(stage, checksum, *, runner=run):
    plan, actual = load_historical_plan(stage, runner=runner)
    if checksum != actual:
        refuse('history_exact_recipe_not_found')
    erase_intent(stage, plan, checksum, runner=runner)
    return plan, actual


def execution_integrity_path(stage):
    reference = _execution_reference(stage)
    return Path(stage) / (INTEGRITY if reference is None else reference['filename'].replace('-plan.json', '-integrity.json'))


def load_plan(stage, *, runner=run):
    reference = _execution_reference(stage)
    plan, checksum = (load_historical_plan(stage, runner=runner) if reference is None
                      else _load_execution(stage, reference, runner=runner))
    if plan['boot_id'] != boot.boot_id():
        refuse('later_boot_requires_compound_recovery')
    return plan, checksum


def prepare_execution(stage, *, authorize, manager, runner=run):
    """Create a fresh observed execution generation only before any RPM intent."""
    stage = Path(stage)
    if any(os.path.lexists(stage / name) for name in (INTENT, RESULT, COMPLETE)):
        refuse('execution_already_attempted')
    original, _ = _load_frozen(stage, stage / PLAN, runner=runner)
    if rpm.inventory(runner)[2] != original['before_inventory']:
        refuse('unattempted_inventory_changed')
    for path, expected in original['preserved'].items():
        if path != kernel.GRUBENV and mechanical.preserved_description(path) != expected:
            refuse('unattempted_protected_state_changed')
    for path, expected in original['removed'].items():
        if kernel.describe(path) != expected:
            refuse('unattempted_target_changed')
    boot.reconcile_recovery(stage, prepare=manager.authorized_update_prepare,
                            accept=manager.authorized_update_accept, runner=runner)
    recovery = boot.verified_recovery(stage, runner=runner)
    boot.recovery_authorization(stage, authorize, runner=runner)
    value = copy.deepcopy(original)
    value.update(boot_id=recovery['boot_id'], recovery=recovery)
    value['preserved'][kernel.GRUBENV] = recovery['mutable'][kernel.GRUBENV]
    # The verified recovery may have a qualified same-boot success transition.
    # Its exact accepted boot plan chooses the deterministic execution name.
    token = rpm.sha(kernel.encode(recovery))[:32]
    tokens = {match.group(1) for path in stage.iterdir()
              if (match := re.fullmatch(r'kernel-rollback-execution-([a-f0-9]{32})-(?:plan|integrity)\.json', path.name))}
    if len(tokens) > 64 or token not in tokens and len(tokens) >= 64:
        refuse('execution_generation_limit')
    name = 'kernel-rollback-execution-' + token + '-plan.json'
    kernel.record(stage, name, value)
    reference = {'filename': name, 'sha256': rpm.sha(kernel.encode(value))}
    plan, checksum = _load_execution(stage, reference, runner=runner)
    verify_files(plan, 'prepare', runner=runner)
    kernel.record(stage, name.replace('-plan.json', '-integrity.json'), integrity_plan(plan, checksum))
    atomic_json(stage / EXECUTION_CURRENT, reference)
    return plan, checksum


def verify_files(plan, phase, *, runner=run):
    if phase not in {'prepare', 'forward'}:
        refuse('invalid_integrity_phase')
    mechanical.integrity_snapshot(None, integrity_plan(plan, ''), phase)
    if (runner(['/usr/bin/uname', '-r']) != plan['recovery_kernel']
            or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + plan['recovery_kernel']):
        refuse('running_recovery_default_changed')


def integrity_plan(plan, checksum):
    return {'schema': 1, 'kind': KIND, 'sequence': 0, 'manifest_sha256': checksum,
            'removed': plan['removed'], 'preserved': plan['preserved'],
            'mutable_directories': plan['mutable_directories']}


def integrity_snapshot(manager, plan, phase, retained=None):
    if 'rollback_plan_sha256' in plan:
        return mechanical.resume_integrity_snapshot(manager, plan, phase, retained)
    return mechanical.integrity_snapshot(manager, plan, phase, retained)


def allowed_integrity_report(report, plan, phase):
    if 'rollback_plan_sha256' in plan:
        return mechanical.allowed_resume_integrity_report(report, plan, phase)
    return mechanical.allowed_integrity_report(report, plan, phase)


def erase_intent(stage, plan, checksum, *, runner=run):
    intent, intent_sha = _read(Path(stage) / INTENT)
    exact(intent, {'schema', 'plan_sha256', 'authorization'} | ({'generation'} if intent.get('schema') == 2 else set()))
    authority = intent['authorization']
    exact(authority, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    if (type(intent['schema']) is not int or intent['schema'] not in (1, 2) or intent['plan_sha256'] != checksum
            or authority['ok'] is not True or authority['plan_sha256'] != checksum
            or authority['boot_id'] != plan['boot_id']
            or any(not kernel.SHA.fullmatch(str(authority[k])) for k in ('backup_sha256', 'aide_preparation_sha256'))):
        refuse('erase_intent_changed')
    if intent['schema'] == 2:
        selected, selected_sha = _load_execution(stage, intent['generation'], runner=runner)
        if selected != plan or selected_sha != checksum:
            refuse('erase_execution_generation_changed')
    return intent, intent_sha


def bound_integrity_plan(manager, stage, path, *, preparing):
    identity = manager.guard()
    stage, path = Path(stage), Path(path)
    from .kernel_retention_integration import owned_stage
    owned_stage(stage, identity.root / 'manager/os-updates')
    if path.parent == stage and RESUME_NAME.fullmatch(path.name):
        value, checksum = load_resume(stage, {'filename': path.name, 'sha256': rpm.sha(rpm.read(path, rpm.MAX_XML))}, runner=run)
        _journal_owner(identity, stage)
        return value, checksum
    if path != execution_integrity_path(stage) or path.name != INTEGRITY and not EXECUTION_NAME.fullmatch(path.name):
        refuse('unowned_integrity_path')
    plan, checksum = load_plan(stage, runner=run)
    parsed, parsed_sha = _read(path)
    latest = strict_json(rpm.read(identity.root / 'manager/os-latest.json', 65536))
    journal = strict_json(rpm.read(identity.root / 'manager/os-transaction.json', 65536))
    if (parsed != integrity_plan(plan, checksum) or latest.get('stage') != str(stage)
            or journal.get('stage') != str(stage) or preparing and os.path.lexists(stage / INTENT)):
        refuse('integrity_operation_binding_changed')
    if not preparing:
        from . import aide_updates
        intent, _ = erase_intent(stage, plan, checksum, runner=run)
        _, prepared = aide_updates._prepared(manager, identity.root / 'manager/aide', identity, stage, parsed, parsed_sha)
        if prepared is None or digest(prepared) != intent['authorization']['aide_preparation_sha256']:
            refuse('integrity_attempt_preparation_changed')
    return parsed, parsed_sha


def _journal_owner(identity, stage):
    latest = strict_json(rpm.read(identity.root / 'manager/os-latest.json', 65536))
    journal = strict_json(rpm.read(identity.root / 'manager/os-transaction.json', 65536))
    if latest.get('stage') != str(stage) or journal.get('stage') != str(stage):
        refuse('operation_owner_changed')


def authorization(stage, checksum, *, manager, authorize, recovery, runner=run):
    from . import aide_updates
    stage = Path(stage)
    approved = boot.recovery_authorization(stage, authorize, runner=runner)
    with aide_updates._locked(manager) as (state, identity):
        integrity, integrity_sha = bound_integrity_plan(manager, stage, execution_integrity_path(stage), preparing=not recovery)
        if integrity['manifest_sha256'] != checksum:
            refuse('authorization_plan_changed')
        base = manager._initial_enrollment(state, identity)
        manager._monitor(identity, state, base)
        _, prepared = aide_updates._prepared(manager, state, identity, stage, integrity, integrity_sha)
        if prepared is None or prepared['original_enrollment_sha256'] != digest(base):
            refuse('aide_preparation_required')
        if not recovery:
            enrolled = aide_updates.active_enrollment(manager, state, identity, base)
            if enrolled['database_sha256'] != prepared['database_sha256']:
                refuse('prepared_database_changed')
            integrity_snapshot(manager, integrity, 'prepare', prepared['metadata'])
        return {'ok': True, 'plan_sha256': checksum, 'boot_id': approved['boot_id'],
                'backup_sha256': approved['backup_sha256'], 'aide_preparation_sha256': digest(prepared)}


def _authorize(stage, plan, checksum, authorize):
    value = authorize(Path(stage), checksum)
    exact(value, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    if (value['ok'] is not True or value['plan_sha256'] != checksum or value['boot_id'] != plan['boot_id']
            or boot.boot_id() != plan['boot_id']
            or any(not kernel.SHA.fullmatch(str(value[k])) for k in ('backup_sha256', 'aide_preparation_sha256'))):
        refuse('execution_authorization_changed')
    return value


def execute_cached(stage, *, authorize, runner=run):
    require_linux_root()
    stage = Path(stage)
    if os.path.lexists(stage / INTENT):
        refuse('already_attempted_no_replay')
    plan, checksum = load_plan(stage, runner=runner)
    authority = _authorize(stage, plan, checksum, authorize)
    if boot.verified_recovery(stage, runner=runner) != plan['recovery']:
        refuse('verified_fallback_changed')
    verify_signed_history(stage, plan, runner=runner)
    xml, _, inventory = rpm.inventory(runner)
    if inventory != plan['before_inventory'] or rpm.sha(xml.encode()) != plan['inventory_sha256']:
        refuse('installed_inventory_changed')
    verify_files(plan, 'prepare', runner=runner)
    runner(mechanical.command(plan, True), timeout=180)
    if (_authorize(stage, plan, checksum, authorize) != authority
            or boot.verified_recovery(stage, runner=runner) != plan['recovery']
            or rpm.inventory(runner)[0] != xml):
        refuse('execution_context_changed')
    verify_files(plan, 'prepare', runner=runner)
    intent = {'schema': 1, 'plan_sha256': checksum, 'authorization': authority}
    reference = _execution_reference(stage)
    if reference is not None:
        intent.update(schema=2, generation=reference)
    kernel.record(stage, INTENT, intent)
    runner(mechanical.command(plan), timeout=1800)
    return recover_cached(stage, authorize=authorize, runner=runner)


def recover_cached(stage, *, authorize, runner=run):
    require_linux_root()
    stage = Path(stage)
    plan, checksum = load_plan(stage, runner=runner)
    intent, intent_sha = erase_intent(stage, plan, checksum, runner=runner)
    authority = _authorize(stage, plan, checksum, authorize)
    if authority['aide_preparation_sha256'] != intent['authorization']['aide_preparation_sha256']:
        refuse('recovery_preparation_changed')
    mechanical.classify_inventory(plan, rpm.inventory(runner)[2], attempted=True)
    verify_files(plan, 'forward', runner=runner)
    if authority != intent['authorization']:
        kernel.record(stage, 'kernel-rollback-recovery-' + digest(authority) + '.json',
                      {'schema': 1, 'intent_sha256': intent_sha, 'authorization': authority})
    result = {'schema': 1, 'status': 'erased_pending_integrity', 'plan_sha256': checksum,
              'boot_id': plan['boot_id'], 'kernel': plan['kernel'], 'recovery_kernel': plan['recovery_kernel'],
              'release_accepted': False}
    kernel.record(stage, RESULT, result)
    return result


def _resume_reference(stage, reference):
    exact(reference, {'filename', 'sha256'})
    if (not isinstance(reference['filename'], str) or not RESUME_NAME.fullmatch(reference['filename'])
            or not kernel.SHA.fullmatch(str(reference['sha256']))):
        refuse('invalid_resume_reference')
    value, checksum = _read(Path(stage) / reference['filename'])
    if checksum != reference['sha256']:
        refuse('resume_reference_changed')
    return value


def resume_origin(stage, path, *, runner=run):
    stage, path = Path(stage), Path(path)
    if path.parent != stage or not RESUME_NAME.fullmatch(path.name):
        refuse('unowned_resume_integrity_path')
    value, _ = _read(path)
    original, checksum = load_historical_plan(stage, runner=runner)
    intent, intent_sha = erase_intent(stage, original, checksum, runner=runner)
    integrity, integrity_sha = _read(execution_integrity_path(stage))
    if (integrity != integrity_plan(original, checksum) or value.get('rollback_plan_sha256') != checksum
            or value.get('erase_intent_sha256') != intent_sha
            or value.get('original_integrity_sha256') != integrity_sha
            or value.get('original_preparation_sha256') != intent['authorization']['aide_preparation_sha256']):
        refuse('resume_original_preparation_changed')
    return {'plan': original, 'plan_sha256': checksum, 'integrity': integrity,
            'integrity_sha256': integrity_sha, 'prepared_sha256': intent['authorization']['aide_preparation_sha256'],
            'intent': intent, 'intent_sha256': intent_sha}


def _environment_after(stage, original, previous, *, runner, seen):
    if previous is not None:
        prior, _ = load_resume(stage, previous, historical=True, runner=runner, seen=seen)
        return prior['after_raw'], prior['boot_id'], prior['files'][0]['after']
    _, accepted = boot._referenced_plan(stage, original['recovery']['boot_ref'])
    return accepted['after_raw'], accepted['boot_id'], original['preserved'][kernel.GRUBENV]


def _resume_authority(value, stage, plan):
    from .updates import REQUIRED_CHECKS
    exact(value, {'ok', 'stage', 'boot_id', 'kernel', 'checks', 'backup_stage', 'backup_sha256'})
    if (value['ok'] is not True or value['stage'] != str(stage) or value['boot_id'] != plan['boot_id']
            or value['kernel'] != plan['recovery_kernel'] or set(value['checks']) != REQUIRED_CHECKS
            or any(item is not True for item in value['checks'].values())
            or not kernel.SHA.fullmatch(str(value['backup_sha256']))
            or Path(value['backup_stage']).parent != Path(stage).parent
            or not re.fullmatch(r'[a-f0-9]{32}', Path(value['backup_stage']).name)):
        refuse('resume_health_authorization_changed')


def _verify_erased(plan, *, runner, allow_environment=False):
    mechanical.classify_inventory(plan, rpm.inventory(runner)[2], attempted=True)
    preserved = {p: v for p, v in plan['preserved'].items() if not allow_environment or p != kernel.GRUBENV}
    mechanical.integrity_snapshot(None, {**plan, 'preserved': preserved}, 'forward')
    if (runner(['/usr/bin/uname', '-r']) != plan['recovery_kernel']
            or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + plan['recovery_kernel']):
        refuse('running_recovery_default_changed')


def load_resume(stage, reference, *, historical=False, runner=run, seen=None):
    stage = Path(stage)
    seen = set() if seen is None else set(seen)
    if reference.get('sha256') in seen or len(seen) >= 64:
        refuse('resume_ancestry_limit')
    seen.add(reference.get('sha256'))
    value = _resume_reference(stage, reference)
    exact(value, {'schema', 'kind', 'sequence', 'id', 'stage', 'operation_sha256', 'boot_id', 'kernel',
                  'recovery_kernel', 'rollback_plan_sha256', 'original_integrity_sha256',
                  'original_preparation_sha256', 'erase_intent_sha256', 'previous', 'after_raw', 'authorization',
                  'removed', 'preserved', 'mutable_directories', 'files', 'manifest_sha256'})
    origin = resume_origin(stage, stage / reference['filename'], runner=runner)
    original = origin['plan']
    before_raw, previous_boot, before = _environment_after(stage, original, value['previous'], runner=runner, seen=seen)
    after = boot._raw(value['after_raw'])
    _, candidate, _ = _candidate(stage, original)
    old_entry = candidate['machine_id'] + '-' + candidate['old_kernel']
    candidate_entry = candidate['machine_id'] + '-' + candidate['kernel']
    before_vars, after_vars = boot.parse_environment(boot._raw(before_raw)), boot.parse_environment(after)
    boot.transition_variables(before_vars, 'recovery_resume', old_entry=old_entry, candidate_entry=candidate_entry,
                              observed=after_vars, same_boot=value['boot_id'] == previous_boot)
    expected_after = {**before, 'bytes': len(after), 'sha256': rpm.sha(after)}
    _resume_authority(value['authorization'], stage, value)
    try:
        valid_boot = str(uuid.UUID(value['boot_id'])) == value['boot_id']
    except (ValueError, TypeError, AttributeError):
        valid_boot = False
    if (type(value['schema']) is not int or value['schema'] != 1 or value['kind'] != KIND
            or type(value['sequence']) is not int or value['sequence'] != 0 or not valid_boot
            or reference['filename'] != 'kernel-rollback-resume-' + value['id'] + '-integrity.json'
            or value['stage'] != str(stage) or value['operation_sha256'] != original['operation_sha256']
            or value['kernel'] != original['kernel'] or value['recovery_kernel'] != original['recovery_kernel']
            or value['removed'] != original['removed']
            or value['preserved'] != {p: v for p, v in original['preserved'].items() if p != kernel.GRUBENV}
            or value['mutable_directories'] != original['mutable_directories']
            or value['files'] != [{'path': kernel.GRUBENV, 'before': original['preserved'][kernel.GRUBENV], 'after': expected_after}]
            or value['manifest_sha256'] != digest({k: v for k, v in value.items() if k != 'manifest_sha256'})):
        refuse('resume_scope_changed')
    if not historical:
        if value['boot_id'] != boot.boot_id() or kernel.describe(kernel.GRUBENV) != expected_after:
            refuse('resume_current_boot_changed')
        _verify_erased(original, runner=runner, allow_environment=True)
    return value, reference['sha256']


def resume_integrity_predecessor(stage, path):
    path = Path(path)
    plan, _ = load_resume(stage, {'filename': path.name, 'sha256': rpm.sha(rpm.read(path, rpm.MAX_XML))}, historical=True, runner=run)
    if plan['previous'] is None:
        origin = resume_origin(stage, path, runner=run)
        return origin['integrity'], origin['integrity_sha256']
    return load_resume(stage, plan['previous'], historical=True, runner=run)


def prepare_resume(stage, *, authorize, runner=run):
    require_linux_root()
    stage = Path(stage)
    original, checksum = load_historical_plan(stage, runner=runner)
    intent, intent_sha = erase_intent(stage, original, checksum, runner=runner)
    _verify_erased(original, runner=runner, allow_environment=True)
    approved = boot.recovery_authorization(stage, authorize, runner=runner)
    current_boot = boot.boot_id()
    previous = None
    pointer = stage / RESUME_CURRENT
    if os.path.lexists(pointer):
        previous = strict_json(rpm.read(pointer, 8192))
        prior, _ = load_resume(stage, previous, historical=True, runner=runner)
        if prior['boot_id'] == current_boot and kernel.describe(kernel.GRUBENV) == prior['files'][0]['after']:
            load_resume(stage, previous, runner=runner)
            return stage / previous['filename'], prior
    before_raw, previous_boot, before = _environment_after(stage, original, previous, runner=runner, seen=set())
    after = rpm.read(kernel.GRUBENV, 1024)
    _, candidate, _ = _candidate(stage, original)
    boot.transition_variables(boot.parse_environment(boot._raw(before_raw)), 'recovery_resume',
                              old_entry=candidate['machine_id'] + '-' + candidate['old_kernel'],
                              candidate_entry=candidate['machine_id'] + '-' + candidate['kernel'],
                              observed=boot.parse_environment(after), same_boot=current_boot == previous_boot)
    expected = {**before, 'bytes': len(after), 'sha256': rpm.sha(after)}
    if kernel.describe(kernel.GRUBENV) != expected:
        refuse('resume_environment_security_metadata_changed')
    token = uuid.uuid4().hex
    if sum(RESUME_NAME.fullmatch(path.name) is not None for path in stage.iterdir()) >= 64:
        refuse('resume_generation_limit')
    integrity, integrity_sha = _read(execution_integrity_path(stage))
    if integrity != integrity_plan(original, checksum):
        refuse('original_integrity_projection_changed')
    value = {'schema': 1, 'kind': KIND, 'sequence': 0, 'id': token, 'stage': str(stage),
             'operation_sha256': original['operation_sha256'], 'boot_id': current_boot,
             'kernel': original['kernel'], 'recovery_kernel': original['recovery_kernel'],
             'rollback_plan_sha256': checksum, 'original_integrity_sha256': integrity_sha,
             'original_preparation_sha256': intent['authorization']['aide_preparation_sha256'],
             'erase_intent_sha256': intent_sha, 'previous': previous, 'after_raw': base64.b64encode(after).decode(),
             'authorization': approved, 'removed': original['removed'],
             'preserved': {p: v for p, v in original['preserved'].items() if p != kernel.GRUBENV},
             'mutable_directories': original['mutable_directories'],
             'files': [{'path': kernel.GRUBENV, 'before': original['preserved'][kernel.GRUBENV], 'after': expected}]}
    value['manifest_sha256'] = digest(value)
    name = 'kernel-rollback-resume-' + token + '-integrity.json'
    kernel.record(stage, name, value)
    reference = {'filename': name, 'sha256': rpm.sha(kernel.encode(value))}
    load_resume(stage, reference, runner=runner)
    atomic_json(pointer, reference)
    return stage / name, value


def verified_completion(stage, *, runner=run):
    from . import aide_updates
    stage = Path(stage)
    plan, checksum = load_historical_plan(stage, runner=runner)
    intent, _ = erase_intent(stage, plan, checksum, runner=runner)
    completion, _ = _read(stage / COMPLETE)
    result, result_sha = _read(stage / RESULT)
    retained, _ = _read(stage / 'kernel-rollback-completion-proof.json')
    exact(retained, {'integrity', 'aide'})
    reference = retained['integrity']
    exact(reference, {'filename', 'sha256'})
    if reference['filename'] == execution_integrity_path(stage).name:
        projection, integrity_sha = _read(stage / reference['filename'])
        if projection != integrity_plan(plan, checksum) or reference['sha256'] != integrity_sha:
            refuse('completion_integrity_changed')
        accepted_boot = plan['boot_id']
        if retained['aide']['prepared_sha256'] != intent['authorization']['aide_preparation_sha256']:
            refuse('completion_preparation_changed')
    else:
        projection, integrity_sha = load_resume(stage, reference, historical=True, runner=runner)
        accepted_boot = projection['boot_id']
    proof = aide_updates.retained_plan_acceptance(stage, stage / reference['filename'],
                                                  expected=retained['aide'], historical=True)
    expected = {'schema': 1, 'status': 'rolled_back', 'plan_sha256': checksum,
                'result_sha256': result_sha, 'integrity_sha256': integrity_sha,
                'database_sha256': proof['database_sha256'], 'boot_id': accepted_boot,
                'kernel': plan['kernel'], 'recovery_kernel': plan['recovery_kernel'],
                'candidate_plan_sha256': plan['candidate_plan_sha256'], 'installed_sha256': plan['installed_sha256'],
                'release_accepted': False}
    if (completion != expected
            or result != {'schema': 1, 'status': 'erased_pending_integrity', 'plan_sha256': checksum,
                          'boot_id': plan['boot_id'], 'kernel': plan['kernel'],
                          'recovery_kernel': plan['recovery_kernel'], 'release_accepted': False}):
        refuse('completion_evidence_changed')
    if os.path.lexists(stage / RESUME_CURRENT):
        current = strict_json(rpm.read(stage / RESUME_CURRENT, 8192))
        load_resume(stage, current, runner=runner)
        aide_updates.retained_plan_acceptance(stage, stage / current['filename'])
    else:
        if plan['boot_id'] != boot.boot_id():
            refuse('completion_current_boot_requires_resume')
        aide_updates.retained_plan_acceptance(stage, execution_integrity_path(stage))
        _verify_erased(plan, runner=runner)
    return completion


def rollback(stage, *, authorize, runner=run):
    """Publish exact rollback completion; lifecycle owns health and disposition."""
    from . import aide, aide_updates
    require_linux_root()
    stage = Path(stage)
    if not os.path.lexists(stage / PLAN):
        plan_cached(stage, authorize=authorize, runner=runner)
    manager = aide.Aide()
    attempted = os.path.lexists(stage / INTENT)
    plan, checksum = load_historical_plan(stage, runner=runner)
    if not attempted and (plan['boot_id'] != boot.boot_id()
                          or kernel.describe(kernel.GRUBENV) != plan['preserved'][kernel.GRUBENV]):
        prepare_execution(stage, authorize=authorize, manager=manager, runner=runner)
        plan, checksum = load_plan(stage, runner=runner)
    compound = attempted and (os.path.lexists(stage / RESUME_CURRENT) or plan['boot_id'] != boot.boot_id()
                             or kernel.describe(kernel.GRUBENV) != plan['preserved'][kernel.GRUBENV])
    if compound:
        path, resume = prepare_resume(stage, authorize=authorize, runner=runner)
    else:
        path = execution_integrity_path(stage)
        kernel.record(stage, path.name, integrity_plan(plan, checksum))
    integrity_sha = rpm.sha(rpm.read(path, rpm.MAX_XML))
    if compound or not attempted:
        prepared = manager.authorized_update_prepare(stage, path)
        if prepared.get('ok') is not True or prepared.get('plan_sha256') != integrity_sha:
            refuse('integrity_preparation_failed')
    callback = lambda current, sha: authorization(current, sha, manager=manager, authorize=authorize,
                                                  recovery=os.path.lexists(current / INTENT), runner=runner)
    if compound:
        _verify_erased(plan, runner=runner, allow_environment=True)
        kernel.record(stage, RESULT, {'schema': 1, 'status': 'erased_pending_integrity', 'plan_sha256': checksum,
                      'boot_id': plan['boot_id'], 'kernel': plan['kernel'], 'recovery_kernel': plan['recovery_kernel'],
                      'release_accepted': False})
    else:
        (recover_cached if attempted else execute_cached)(stage, authorize=callback, runner=runner)
    accepted = manager.authorized_update_accept(stage, path)
    if (accepted.get('ok') is not True or accepted.get('direction') != 'forward'
            or accepted.get('plan_sha256') != integrity_sha):
        refuse('integrity_acceptance_failed')
    boot.recovery_authorization(stage, authorize, runner=runner)
    if compound:
        load_resume(stage, {'filename': path.name, 'sha256': integrity_sha}, runner=runner)
    else:
        verify_files(plan, 'forward', runner=runner)
    proof = aide_updates.retained_plan_acceptance(stage, path, manager=manager)
    completion = {'schema': 1, 'status': 'rolled_back', 'plan_sha256': checksum,
                  'result_sha256': rpm.sha(rpm.read(stage / RESULT, rpm.MAX_XML)),
                  'integrity_sha256': integrity_sha, 'database_sha256': accepted['database_sha256'],
                  'boot_id': boot.boot_id(), 'kernel': plan['kernel'], 'recovery_kernel': plan['recovery_kernel'],
                  'candidate_plan_sha256': plan['candidate_plan_sha256'], 'installed_sha256': plan['installed_sha256'],
                  'release_accepted': False}
    if not os.path.lexists(stage / 'kernel-rollback-completion-proof.json'):
        kernel.record(stage, 'kernel-rollback-completion-proof.json',
                      {'integrity': {'filename': path.name, 'sha256': integrity_sha}, 'aide': proof})
    if not os.path.lexists(stage / COMPLETE):
        # A power loss after publishing the proof must keep that first accepted
        # generation as the completion owner, even after another boot resumes.
        retained, _ = _read(stage / 'kernel-rollback-completion-proof.json')
        first, first_sha = _read(stage / retained['integrity']['filename'])
        completion.update(integrity_sha256=first_sha, database_sha256=retained['aide']['database_sha256'],
                          boot_id=first.get('boot_id', plan['boot_id']))
        kernel.record(stage, COMPLETE, completion)
    return {'ok': True, **verified_completion(stage, runner=runner)}
