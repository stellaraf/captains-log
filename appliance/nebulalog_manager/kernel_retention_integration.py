"""Lifecycle-bound four-to-three vendor kernel retention and AIDE acceptance.

The caller holds lifecycle/update locks and supplies the real final acceptance
verifier. Signed RPMs come only from bounded owned transaction stages or the
factory provenance directory. Recovery observes a prior erase; it cannot replay
it. Missing provenance or partial erasure preserves all intent and evidence.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import uuid

from . import kernel_retention as retain, kernel_updates as kernel, os_payload as rpm
from .common import require_linux_root, run
from .host_job_storage import digest, exact, strict_json

FACTORY = Path('/usr/share/nebulalog/kernel-provenance/manifest.json')
MAX_STAGES = 1024
STAGE = re.compile(r'[a-f0-9]{32}')
REQUIRED = 'kernel-retention-required.json'
COMPLETE = 'kernel-retention-complete.json'


def owned_directory(path, *, private=False):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or private and stat.S_IMODE(info.st_mode) != 0o700 or path.resolve() != path):
        retain.refuse('unsafe_provenance_directory')
    return path


def owned_stage(stage, parent):
    stage, parent = Path(stage), Path(parent)
    if stage.parent != parent or not STAGE.fullmatch(stage.name):
        retain.refuse('unowned_provenance_stage')
    owned_directory(parent, private=True)
    owned_directory(stage, private=True)
    value = strict_json(rpm.read(stage / 'operation.json', 8192))
    exact(value, {'schema', 'id', 'stage', 'boot_id'})
    try:
        valid = all(str(uuid.UUID(value[key])) == value[key] for key in ('id', 'boot_id'))
    except (ValueError, TypeError, AttributeError):
        valid = False
    if type(value['schema']) is not int or value['schema'] != 1 or value['stage'] != str(stage) or not valid:
        retain.refuse('provenance_operation_changed')
    return value


def complete_sets(headers, approved):
    groups = {}
    for header in headers:
        name = rpm.one(header, 'Name')
        if name not in kernel.NAMES:
            continue
        version = kernel.version(header)
        group = groups.setdefault(version, set())
        if name in group:
            retain.refuse('duplicate_kernel_package')
        group.add(name)
    if not 2 <= len(groups) <= 4 or any(names != kernel.NAMES for names in groups.values()):
        retain.refuse('incomplete_retained_kernel_sets')
    if (approved['kernel'] == approved['recovery_kernel'] or approved['recovery_kernel'] not in groups
            or approved['kernel'] != max(groups, key=retain.version_order)):
        retain.refuse('accepted_recovery_kernel_missing')
    return sorted(groups, key=retain.version_order)


def package_paths(directory, packages, version, *, runner):
    owned_directory(directory)
    if not isinstance(packages, list) or len(packages) != 4:
        retain.refuse('incomplete_retained_signed_packages')
    paths, names = [], set()
    for item in packages:
        if (not isinstance(item, dict) or item.get('name') not in kernel.NAMES or item['name'] in names
                or not kernel.SHA.fullmatch(str(item.get('sha256')))
                or item.get('rpm') != item['sha256'] + '.rpm'
                or item.get('nevra') != item['name'] + '-0:' + version
                or type(item.get('bytes')) is not int or not 0 < item['bytes'] <= rpm.MAX_RPM):
            retain.refuse('invalid_retained_signed_package_identity')
        path = Path(directory) / item['rpm']
        raw = rpm.read(path)
        if len(raw) != item['bytes'] or rpm.sha(raw) != item['sha256']:
            retain.refuse('retained_signed_package_bytes_changed')
        headers = rpm.headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(path)], timeout=180))
        if len(headers) != 1:
            retain.refuse('ambiguous_retained_signed_header')
        payload = kernel.payload(headers[0])
        if any(payload[key] != value for key, value in
               {'kernel': version, 'name': item['name'], 'nevra': item['nevra']}.items()):
            retain.refuse('retained_signed_header_changed')
        # The erase planner rechecks the vendor signature in its private
        # keyring and compares this full payload with the installed header.
        names.add(item['name'])
        paths.append(path)
    return paths


def retained_packages(stage, version, *, runner=run):
    """Inspect one bounded stage directory, never a recursive filesystem glob."""
    stage = Path(stage)
    owned_stage(stage, stage.parent)
    candidates = []
    with os.scandir(stage.parent) as entries:
        for count, entry in enumerate(entries, 1):
            if count > MAX_STAGES:
                retain.refuse('provenance_stage_limit_exceeded')
            if STAGE.fullmatch(entry.name) and os.path.lexists(Path(entry.path) / 'kernel-plan.json'):
                candidates.append(Path(entry.path))
    for prior in sorted(candidates):
        owned_stage(prior, stage.parent)
        payload, _ = kernel.load_plan(prior)
        if payload['kernel'] == version:
            return package_paths(prior / 'kernel-packages', payload['packages'], version, runner=runner)
    if not os.path.lexists(FACTORY):
        retain.refuse('signed_factory_or_stage_provenance_required')
    value = strict_json(rpm.read(FACTORY, 65536))
    exact(value, {'schema', 'kernel', 'packages'})
    if (type(value['schema']) is not int or value['schema'] != 1 or value['kernel'] != version
            or type(value['packages']) is not list or len(value['packages']) != 4):
        retain.refuse('signed_factory_or_stage_provenance_required')
    for item in value['packages']:
        exact(item, {'name', 'nevra', 'rpm', 'sha256', 'bytes'})
    return package_paths(FACTORY.parent, value['packages'], version, runner=runner)


def context(manager, stage):
    identity = manager.guard()
    stage = Path(stage)
    owned_stage(stage, identity.root / 'manager/os-updates')
    latest = strict_json(rpm.read(identity.root / 'manager/os-latest.json', 65536))
    journal = strict_json(rpm.read(identity.root / 'manager/os-transaction.json', 65536))
    if (latest.get('stage') != str(stage) or journal.get('stage') != str(stage)
            or journal.get('state') not in {'complete', 'recovery_required', 'retaining', 'retention_postcheck', 'retention_recovery_required'}):
        retain.refuse('retention_operation_changed')
    return identity, latest, journal


def authorization(stage, checksum, *, manager, recovery=False):
    from . import aide_updates, kernel_integrity
    stage = Path(stage)
    with aide_updates._locked(manager) as (state, identity):
        bound_identity, latest, journal = context(manager, stage)
        if bound_identity != identity:
            retain.refuse('retention_storage_identity_changed')
        integrity, integrity_sha = retain.bound_integrity_plan(manager, stage, stage / retain.INTEGRITY, preparing=False)
        if integrity['manifest_sha256'] != checksum:
            retain.refuse('authorization_plan_changed')
        backup_stage = stage
        if latest.get('recovery_backup_stage') is not None:
            backup_stage = Path(latest['recovery_backup_stage'])
            if (backup_stage.parent != stage.parent or not STAGE.fullmatch(backup_stage.name)
                    or journal.get('recovery_backup_stage') != str(backup_stage)):
                retain.refuse('recovery_backup_stage_changed')
            owned_directory(backup_stage, private=True)
        backup_sha = kernel_integrity.checked_backup(backup_stage)
        base = manager._initial_enrollment(state, identity)
        manager._monitor(identity, state, base)
        _, prepared = aide_updates._prepared(manager, state, identity, stage, integrity, integrity_sha)
        if prepared is None or prepared['original_enrollment_sha256'] != digest(base):
            retain.refuse('aide_preparation_required')
        if not recovery:
            enrolled = aide_updates.active_enrollment(manager, state, identity, base)
            if enrolled['database_sha256'] != prepared['database_sha256']:
                retain.refuse('prepared_integrity_database_changed')
            retain.integrity_snapshot(manager, integrity, 'prepare', prepared['metadata'])
        return {'ok': True, 'plan_sha256': checksum, 'backup_sha256': backup_sha,
                'aide_preparation_sha256': digest(prepared), 'boot_id': retain.boot_id()}


def retain_three(stage, *, accepted, runner=run):
    from . import aide
    require_linux_root()
    stage = Path(stage)
    manager = aide.Aide()
    context(manager, stage)
    approved = retain.acceptance(stage, accepted, runner)
    _, headers, inventory = rpm.inventory(runner)
    versions = complete_sets(headers, approved)
    # Existing erase intent takes precedence over the now-three inventory.
    # Otherwise interruption after RPM but before AIDE acceptance is skipped.
    if not os.path.lexists(stage / retain.PLAN):
        if any(os.path.lexists(stage / name) for name in (retain.INTENT, retain.RESULT, COMPLETE)):
            retain.refuse('retention_plan_missing')
        if len(versions) <= 3:
            return {'ok': True, 'status': 'not_required', 'retained_kernels': versions}
        oldest, _ = retain.select_oldest(headers, approved)
        kernel.record(stage, REQUIRED, {'schema': 1, 'acceptance': approved,
                                      'kernel': oldest, 'before_inventory': inventory})
        packages = retained_packages(stage, oldest, runner=runner)
        retain.plan_cached(stage, packages, accepted=accepted, runner=runner)
    plan, checksum = retain.load_plan(stage)
    if plan['acceptance'] != approved:
        retain.refuse('retention_acceptance_changed')
    integrity_path = stage / retain.INTEGRITY
    if not os.path.lexists(integrity_path):
        # The immutable erase plan is published first. Reconstruct only its
        # deterministic integrity projection after a crash between the writes.
        kernel.record(stage, retain.INTEGRITY, retain.integrity_plan(plan, checksum))
    integrity_sha = rpm.sha(rpm.read(integrity_path, rpm.MAX_XML))
    attempted = os.path.lexists(stage / retain.INTENT)
    if not attempted:
        result = manager.authorized_update_prepare(stage, integrity_path)
        if result.get('ok') is not True or result.get('plan_sha256') != integrity_sha:
            retain.refuse('integrity_preparation_failed')
    # The callback's mode is evaluated afresh: execute_cached creates INTENT
    # before calling its own recovery inspector after successful RPM erasure.
    authorize = lambda current, sha: authorization(current, sha, manager=manager,
                                                    recovery=os.path.lexists(current / retain.INTENT))
    if attempted:
        result = retain.recover_cached(stage, authorize=authorize, accepted=accepted, runner=runner)
    else:
        result = retain.execute_cached(stage, authorize=authorize, accepted=accepted, runner=runner)
    if result.get('status') != 'erased_pending_integrity' or result.get('plan_sha256') != checksum:
        retain.refuse('erase_result_changed')
    integrity = manager.authorized_update_accept(stage, integrity_path)
    if (integrity.get('ok') is not True or integrity.get('direction') != 'forward'
            or integrity.get('plan_sha256') != integrity_sha
            or not kernel.SHA.fullmatch(str(integrity.get('database_sha256')))):
        retain.refuse('integrity_acceptance_failed')
    # Re-observe after AIDE's database swap before declaring retention done.
    if (retain.acceptance(stage, accepted, runner) != approved
            or rpm.inventory(runner)[2] != plan['after_inventory']):
        retain.refuse('retention_completion_context_changed')
    retain.verify_files(plan, 'forward', runner=runner)
    completion = {'schema': 1, 'status': 'complete', 'plan_sha256': checksum,
                  'result_sha256': rpm.sha(rpm.read(stage / retain.RESULT, rpm.MAX_XML)),
                  'acceptance_sha256': approved['receipt_sha256'], 'integrity_sha256': integrity_sha,
                  'database_sha256': integrity['database_sha256'], 'retained_kernels': plan['retained_kernels']}
    kernel.record(stage, COMPLETE, completion)
    return {'ok': True, **completion}


def provisional_authorization(stage, checksum, *, authorize, manager):
    """Reread actual backup ownership; this authority can never invoke RPM."""
    from . import kernel_integrity
    stage = Path(stage)
    _, latest, journal = context(manager, stage)
    value = authorize(stage, checksum)
    original, original_sha = retain.load_historical_plan(stage)
    observation = {'boot_id': retain.boot_id(), 'operation_sha256': original['operation_sha256'],
                   'retention_plan_sha256': original_sha}
    retain._provisional(value, stage, observation)
    if checksum != original_sha or journal.get('kernel_retention') not in {'pending', 'failed'}:
        retain.refuse('provisional_operation_changed')
    expected = latest.get('recovery_backup_stage', str(stage))
    if (journal.get('recovery_backup_stage', str(stage)) != expected or value['backup_stage'] != expected):
        retain.refuse('provisional_backup_owner_changed')
    backup = owned_directory(Path(expected), private=True)
    if backup.parent != stage.parent or not STAGE.fullmatch(backup.name):
        retain.refuse('provisional_backup_stage_changed')
    actual = kernel_integrity.checked_backup(backup)
    if value['backup_sha256'] != actual:
        retain.refuse('provisional_backup_inventory_changed')
    if backup != stage:
        reference = strict_json(rpm.read(stage / 'recovery-backup-current.json', 8192))
        exact(reference, {'filename', 'sha256'})
        if (reference['filename'] != 'recovery-backup-' + backup.name + '.json'
                or not kernel.SHA.fullmatch(str(reference['sha256']))):
            retain.refuse('provisional_backup_reference_changed')
        raw = rpm.read(stage / reference['filename'], 8192)
        intent = strict_json(raw)
        exact(intent, {'schema', 'owner_stage', 'boot_id', 'previous', 'backup', 'inventory_sha256'})
        if (rpm.sha(raw) != reference['sha256'] or raw != kernel.encode(intent)
                or type(intent['schema']) is not int or intent['schema'] != 1
                or intent['owner_stage'] != str(stage) or intent['backup'] != str(backup)
                or intent['inventory_sha256'] != actual or intent['boot_id'] != journal.get('boot_id')
                or latest.get('boot_id') != journal.get('boot_id')
                or Path(intent['previous']).parent != stage.parent or not STAGE.fullmatch(Path(intent['previous']).name)):
            retain.refuse('provisional_backup_intent_changed')
    return value


def recover_later_boot(stage, *, authorize, runner=run):
    """Reconcile an exact completed erase through AIDE and boot, never RPM.

    Final runtime acceptance belongs to lifecycle. Call finish_later_boot only
    after that owner has published a current immutable acceptance generation.
    """
    from . import aide, aide_updates, kernel_boot
    require_linux_root()
    stage = Path(stage)
    manager = aide.Aide()
    context(manager, stage)
    original, checksum = retain.load_historical_plan(stage)
    # The pure classifier refuses an unchanged or partial inventory once an
    # erase intent exists. No recovery branch calls execute_cached/command.
    retain.erase_intent(stage, original, checksum)
    checked = lambda current, sha: provisional_authorization(current, sha, authorize=authorize, manager=manager)
    checked(stage, checksum)
    authority_ref = retain.observe_boot_authority(stage, runner=runner)
    boot_path, boot_plan = kernel_boot.plan_retention_resume(stage, authority_ref, runner=runner)
    boot_ref = {'filename': Path(boot_path).name, 'sha256': rpm.sha(kernel.encode(boot_plan))}
    plan_path, plan = retain.prepare_resume(stage, authority_ref, boot_ref, authorize=checked, runner=runner)
    plan_ref = {'filename': plan_path.name, 'sha256': rpm.sha(kernel.encode(plan))}
    current = checked(stage, checksum)
    kernel.record(stage, 'kernel-retention-resume-' + plan['id'] + '-authorization-' + digest(current) + '.json',
                  {'schema': 1, 'plan': plan_ref, 'authorization': current})
    kernel.record(stage, 'kernel-retention-resume-' + plan['id'] + '-intent.json',
                  {'schema': 1, 'plan': plan_ref, 'authorization': plan['authorization']})
    prepared = manager.authorized_update_prepare(stage, plan_path)
    if prepared.get('ok') is not True or prepared.get('plan_sha256') != plan_ref['sha256']:
        retain.refuse('compound_preparation_failed')
    checked(stage, checksum)
    retain.load_resume(stage, plan_ref, runner=runner)
    accepted = manager.authorized_update_accept(stage, plan_path)
    if (accepted.get('ok') is not True or accepted.get('direction') != 'forward'
            or accepted.get('plan_sha256') != plan_ref['sha256']):
        retain.refuse('compound_acceptance_failed')
    proof = aide_updates.retained_plan_acceptance(stage, plan_path, manager=manager)
    if proof['database_sha256'] != accepted.get('database_sha256') or proof['plan_sha256'] != plan_ref['sha256']:
        retain.refuse('compound_published_evidence_changed')
    checked(stage, checksum)
    retain.load_resume(stage, plan_ref, runner=runner)
    result = {'schema': 1, 'status': 'integrity_reconciled', 'plan': plan_ref, 'boot_ref': boot_ref,
              'authority_ref': authority_ref, 'boot_id': plan['boot_id'], 'kernel': original['acceptance']['kernel'],
              'retention_plan_sha256': checksum, 'aide': proof, 'release_accepted': False}
    name = 'kernel-retention-resume-' + plan['id'] + '-result.json'
    kernel.record(stage, name, result)
    compound_ref = {'filename': name, 'sha256': rpm.sha(kernel.encode(result))}
    retain.validate_boot_completion(stage, boot_ref, compound_ref, runner=runner)
    boot = kernel_boot.complete_retention_resume(stage, boot_ref, compound_ref, runner=runner)
    return {'ok': True, 'status': 'integrity_reconciled', 'compound_ref': compound_ref,
            'boot': boot, 'release_accepted': False}


def finish_later_boot(stage, compound_ref, *, accepted, runner=run):
    """Append completion only after real fresh lifecycle acceptance and backup."""
    require_linux_root()
    stage = Path(stage)
    result = retain._reference(stage, compound_ref, retain.RESUME_RESULT)
    retain.validate_boot_completion(stage, result['boot_ref'], compound_ref, runner=runner)
    approved = retain.acceptance(stage, accepted, runner)
    value, acceptance_sha, _ = kernel.read_acceptance(stage)
    original, checksum = retain.load_historical_plan(stage)
    if (approved['boot_id'] != result['boot_id'] or approved['kernel'] != result['kernel']
            or approved['recovery_kernel'] != original['acceptance']['recovery_kernel']
            or value.get('retention_integrity_sha256') != compound_ref['sha256']
            or checksum != result['retention_plan_sha256'] or acceptance_sha != approved['receipt_sha256']):
        retain.refuse('resumed_final_acceptance_changed')
    completion = {'schema': 1, 'status': 'complete', 'compound_ref': compound_ref,
                  'original_plan_sha256': checksum, 'acceptance_sha256': acceptance_sha,
                  'boot_id': result['boot_id'], 'database_sha256': result['aide']['database_sha256'],
                  'retained_kernels': original['retained_kernels']}
    token = retain.RESUME_RESULT.fullmatch(compound_ref['filename'])[1]
    kernel.record(stage, 'kernel-retention-resume-' + token + '-complete.json', completion)
    return {'ok': True, **completion}
