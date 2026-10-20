"""Production operation, backup and AIDE binding for kernel install recipes.

The original AIDE enrollment stays immutable. These adapters use its existing
authorized-update chain and permit only an exact retained kernel plan's delta.
They do not infer success from an updater-supplied boolean or from RPM alone.
"""
from datetime import datetime, timezone
import os
from pathlib import Path
import uuid

from . import kernel_updates as kernel, os_payload as rpm
from .common import run
from .host_job_storage import digest, exact, strict_json


def operation(manager, stage, *, preparing=False):
    identity = manager.guard()
    stage = Path(stage)
    parent = identity.root / 'manager/os-updates'
    if stage.is_symlink() or stage.resolve().parent != parent.resolve():
        kernel.refuse('unowned_stage')
    value = strict_json(rpm.read(stage / 'operation.json', 8192))
    exact(value, {'schema', 'id', 'stage', 'boot_id'})
    try:
        uuid.UUID(value['id'])
        uuid.UUID(value['boot_id'])
    except (ValueError, TypeError, AttributeError):
        kernel.refuse('invalid_operation_identity')
    journal = strict_json(rpm.read(parent.parent / 'os-transaction.json', 65536))
    latest = strict_json(rpm.read(parent.parent / 'os-latest.json', 65536))
    allowed = {'planning', 'updating'} if preparing else {'updating', 'postcheck', 'recovery_required', 'complete'}
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if (value['schema'] != 1 or value['stage'] != str(stage) or journal.get('stage') != str(stage)
            or latest.get('stage') != str(stage) or journal.get('state') not in allowed
            or journal.get('boot_id') != value['boot_id'] or latest.get('boot_id') != value['boot_id']):
        kernel.refuse('operation_binding_changed')
    if boot != value['boot_id']:
        # Only lifecycle may establish this fresh recovery observation after a
        # safe old-kernel boot. Original operation/backup evidence is retained.
        if (preparing or journal.get('state') != 'recovery_required'
                or journal.get('recovery_boot_id') != boot or latest.get('recovery_boot_id') != boot
                or journal.get('recovery_observed_at') != latest.get('recovery_observed_at')):
            kernel.refuse('unbound_recovery_boot')
        fresh(journal.get('recovery_observed_at'))
    return identity, value, journal, latest, boot


def fresh(value):
    try:
        observed = datetime.fromisoformat(value)
        age = (datetime.now(timezone.utc) - observed).total_seconds()
    except (ValueError, TypeError):
        kernel.refuse('invalid_backup_time')
    if not 0 <= age <= 7200:
        kernel.refuse('fresh_backup_required')


def checked_backup(stage):
    """Use the real lifecycle inventory verifier, including every retained file."""
    from nebulalog_adapters.lifecycle import verify_inventory
    stage = Path(stage)
    receipt = strict_json(rpm.read(stage / 'adapter-backup.json', 65536))
    raw = rpm.read(stage / 'adapter-backup-inventory.json', rpm.MAX_XML)
    evidence = strict_json(raw)
    if (receipt.get('ok') is not True or receipt.get('action') != 'backup'
            or receipt.get('postgresql') is not True or receipt.get('configuration') is not True
            or receipt.get('inventory_sha256') != rpm.sha(raw)
            or evidence.get('schema') != 1 or evidence.get('includes_clickhouse_logs') is not False):
        kernel.refuse('verified_backup_required')
    fresh(receipt.get('observed_at'))
    verify_inventory(stage / 'recovery', evidence['files'])
    return rpm.sha(raw)


def plan(stage, payload, payload_sha):
    additions = ({p['path'] for p in payload['files']} - set(payload['shared'])) | set(payload['generated'])
    return {'schema': 1, 'kind': 'kernel-install-v1', 'sequence': 0,
            'manifest_sha256': payload_sha, 'stage': str(stage), 'payload': payload,
            'delta': {'added': sorted(additions), 'removed': [], 'changed': sorted(payload['mutable_before'])}}


def bound_integrity_plan(manager, stage, path, *, preparing):
    stage, path = Path(stage), Path(path)
    _, value, journal, _, boot = operation(manager, stage, preparing=preparing)
    if path != stage / 'os-integrity-plan.json':
        kernel.refuse('unexpected_integrity_plan')
    payload, payload_sha = kernel.load_plan(stage)
    raw = manager.reader(path, maximum=rpm.MAX_XML, private=True)
    parsed = strict_json(raw)
    if (parsed != plan(stage, payload, payload_sha) or payload['boot_id'] != value['boot_id']
            or (not preparing or journal['state'] == 'updating') and journal.get('plan_sha256') != payload_sha
            or preparing and (stage / 'kernel-apply-intent.json').exists()
            or boot != value['boot_id'] and run(['/usr/bin/uname', '-r']) != payload['old_kernel']):
        kernel.refuse('integrity_plan_binding_changed')
    return parsed, rpm.sha(raw)


def _labels(paths):
    result = {}
    paths = sorted(paths)
    for start in range(0, len(paths), 128):
        batch = paths[start:start + 128]
        contexts = run(['/usr/sbin/matchpathcon', '-n', *batch], timeout=120).splitlines()
        if len(contexts) != len(batch) or any(not text or text == '<<none>>' for text in contexts):
            kernel.refuse('selinux_policy_context_unavailable')
        result.update(zip(batch, contexts))
    return result


def snapshot(manager, integrity, phase, retained=None):
    if phase not in {'prepare', 'forward'}:
        kernel.refuse('kernel_erase_requires_retention_recipe')
    payload, stage = integrity['payload'], Path(integrity['stage'])
    metadata = {'labels': _labels(integrity['delta']['added']),
                'shared': payload['shared'], 'preserved': payload['preserved'],
                'mutable_metadata': {path: {key: value for key, value in item.items() if key not in {'sha256', 'bytes'}}
                                     for path, item in payload['mutable_before'].items()}}
    if retained is not None and retained != metadata:
        kernel.refuse('integrity_security_context_changed')
    kernel.verify_preserved(payload)
    if phase == 'prepare':
        if any(os.path.lexists(path) for path in integrity['delta']['added']):
            kernel.refuse('candidate_path_not_absent_at_preparation')
        if {path: kernel.describe(path) for path in payload['mutable_before']} != payload['mutable_before']:
            kernel.refuse('mutable_boot_state_changed_before_install')
    else:
        installed = strict_json(rpm.read(stage / 'kernel-installed.json', rpm.MAX_XML))
        if installed.get('plan_sha256') != integrity['manifest_sha256'] or rpm.inventory(run)[2] != payload['after_inventory']:
            kernel.refuse('installed_integrity_receipt_changed')
        kernel.verify_payload(payload, runner=run)
        if kernel.generated_snapshot(payload, runner=run) != installed.get('generated'):
            kernel.refuse('generated_integrity_receipt_changed')
        if {path: kernel.describe(path) for path in payload['mutable_before']} != installed.get('mutable'):
            kernel.refuse('mutable_integrity_receipt_changed')
        for path, item in installed['mutable'].items():
            if {key: value for key, value in item.items() if key not in {'sha256', 'bytes'}} != metadata['mutable_metadata'][path]:
                kernel.refuse('mutable_security_metadata_changed')
        if run(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + payload['old_kernel']:
            kernel.refuse('unaccepted_kernel_selected')
    return metadata


def allowed_report(report, integrity, phase):
    if phase == 'prepare':
        if any(report.get(key) for key in ('added', 'removed', 'changed')):
            kernel.refuse('integrity_preparation_not_clean')
    elif phase == 'forward':
        kernel.check_integrity_report(report, integrity['delta'])
    else:
        kernel.refuse('kernel_erase_requires_retention_recipe')


def authorization(stage, payload_sha, *, manager=None, recovery=False):
    from . import aide, aide_updates
    manager = manager or aide.Aide()
    stage = Path(stage)
    with aide_updates._locked(manager) as (state, identity):
        _, _, journal, latest, boot = operation(manager, stage)
        integrity, integrity_sha = bound_integrity_plan(manager, stage, stage / 'os-integrity-plan.json', preparing=False)
        if integrity['manifest_sha256'] != payload_sha:
            kernel.refuse('authorization_plan_changed')
        backup_stage = stage
        if latest.get('recovery_backup_stage') is not None:
            backup_stage = Path(latest['recovery_backup_stage'])
            if (backup_stage.is_symlink() or backup_stage.resolve().parent != stage.parent.resolve()
                    or journal.get('recovery_backup_stage') != str(backup_stage)):
                kernel.refuse('recovery_backup_stage_changed')
        backup_sha = checked_backup(backup_stage)
        base = manager._initial_enrollment(state, identity)
        manager._monitor(identity, state, base)
        _, prepared = aide_updates._prepared(manager, state, identity, stage, integrity, integrity_sha)
        if prepared is None or prepared['original_enrollment_sha256'] != digest(base):
            kernel.refuse('aide_preparation_required')
        if not recovery:
            enrolled = aide_updates.active_enrollment(manager, state, identity, base)
            if enrolled['database_sha256'] != prepared['database_sha256']:
                kernel.refuse('prepared_integrity_database_changed')
            snapshot(manager, integrity, 'prepare', prepared['metadata'])
        return {'ok': True, 'plan_sha256': payload_sha, 'backup_sha256': backup_sha,
                'aide_preparation_sha256': digest(prepared), 'boot_id': boot}


def prepare(stage, *, manager=None):
    from . import aide
    manager = manager or aide.Aide()
    payload, payload_sha = kernel.load_plan(stage)
    path = Path(stage) / 'os-integrity-plan.json'
    rpm.immutable(path, kernel.encode(plan(stage, payload, payload_sha)))
    result = manager.authorized_update_prepare(stage, path)
    if result.get('ok') is not True:
        kernel.refuse('integrity_preparation_failed')
    return result


def apply(stage, *, runner=run):
    from . import aide
    stage = Path(stage)
    manager = aide.Aide()
    # Fresh check against the prepared, unchanged original database immediately
    # before mutation; the executor then revalidates the exact preparation twice.
    prepared = manager.authorized_update_prepare(stage, stage / 'os-integrity-plan.json')
    if prepared.get('ok') is not True:
        kernel.refuse('integrity_preparation_failed')
    kernel.execute_cached(stage,
                          authorize=lambda path, checksum: authorization(path, checksum, manager=manager),
                          authorize_recovery=lambda path, checksum: authorization(path, checksum, manager=manager, recovery=True),
                          runner=runner)
    return accept(stage, runner=runner)


def accept(stage, *, runner=run):
    from . import aide
    stage = Path(stage)
    if os.path.lexists(stage.parent.parent / 'kernel-pending.json'):
        return _accept_pending(stage, runner=runner)
    manager = aide.Aide()
    installed = kernel.recover_generated(stage, authorize=lambda path, checksum: authorization(path, checksum, manager=manager, recovery=True), runner=runner)
    result = manager.authorized_update_accept(stage, stage / 'os-integrity-plan.json')
    if result.get('ok') is not True:
        kernel.refuse('integrity_acceptance_failed')
    kernel.mark_pending(stage, installed)
    return {'ok': True, 'package': installed, 'integrity': result}


def accept_deferred(stage, *, runner=run):
    """Fresh backup + ordinary AIDE check; never replay or rebaseline the kernel."""
    return _accept_pending(Path(stage), deferred=True, runner=runner)


def _accept_pending(stage, *, deferred=False, runner=run):
    from . import aide, aide_updates
    from . import kernel_boot
    manager = aide.Aide()
    with aide_updates._locked(manager) as (state, identity):
        _, _, journal, latest, _ = operation(manager, stage)
        raw = rpm.read(stage / ('kernel-deferred.json' if deferred else 'kernel-plan.json'), rpm.MAX_XML)
        if journal.get('plan_sha256') != rpm.sha(raw):
            kernel.refuse('deferred_operation_plan_changed')
        backup_stage = stage
        if latest.get('recovery_backup_stage') is not None:
            backup_stage = Path(latest['recovery_backup_stage'])
            if (backup_stage.is_symlink() or backup_stage.resolve().parent != stage.parent.resolve()
                    or journal.get('recovery_backup_stage') != str(backup_stage)):
                kernel.refuse('recovery_backup_stage_changed')
        checked_backup(backup_stage)
        _, payload, _, installed = kernel.load_candidate(stage)
        if runner(['/usr/bin/uname', '-r']) != payload['old_kernel']:
            kernel.refuse('deferred_candidate_requires_boot_completion')
        # Once boot transitions are present, their accepted inverse must own
        # the restored bytes. Reusing the old install preparation would create
        # another AIDE baseline after its original acceptance.
        if os.path.lexists(stage / 'kernel-boot-current.json'):
            kernel_boot.verified_abort(stage, runner=runner)
        kernel.verify_payload(payload, runner=runner)
        if kernel.generated_snapshot(payload, runner=runner) != installed['generated']:
            kernel.refuse('deferred_candidate_artifact_changed')
        if ({path: kernel.describe(path) for path in payload['mutable_before']} != installed['mutable']
                or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + payload['old_kernel']):
            kernel.refuse('deferred_mutable_boot_state_changed')
        integrity = manager._check_locked(state, identity)
        if integrity.get('state') != 'clean' or integrity.get('exit_code') != 0:
            kernel.refuse('deferred_integrity_not_clean')
        kernel.load_candidate(stage)
    return {'ok': True, 'status': 'kernel_pending', 'package': installed, 'integrity': integrity}


def retain_three(stage, *, accepted, runner=run):
    """Finish signed four-to-three retention after full lifecycle acceptance."""
    from . import kernel_retention_integration
    return kernel_retention_integration.retain_three(stage, accepted=accepted, runner=runner)
