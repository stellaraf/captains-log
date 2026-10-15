"""Fresh execution authority for a retained kernel erase never attempted.

The original signed erase recipe is immutable. A later boot must first have
its own accepted boot transition and lifecycle acceptance. Only those bindings
and the already accepted GRUB environment may change in this derived recipe.
The single owner-stage erase intent, not a generation pointer, limits RPM to
one attempt across all generations. Nothing here repairs or replays an erase.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import uuid

from . import kernel_retention as retain, kernel_updates as kernel, os_payload as rpm
from .common import require_linux_root, run
from .host_job_storage import exact, strict_json

KIND = 'kernel-retention-execution-v1'
BINDING_NAME = re.compile(r'kernel-retention-execution-([a-f0-9]{32})-binding\.json')
INTEGRITY_NAME = re.compile(r'kernel-retention-execution-([a-f0-9]{32})-integrity\.json')
MAX_GENERATIONS = 64


def names(token):
    if not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{32}', token):
        retain.refuse('invalid_execution_generation')
    prefix = 'kernel-retention-execution-' + token
    return {kind: prefix + '-' + kind + '.json' for kind in ('plan', 'binding', 'integrity')}


def selected(stage):
    """Return only the immutable generation named by the global attempt."""
    path = Path(stage) / retain.INTENT
    if not os.path.lexists(path):
        return None
    raw = rpm.read(path, 8192)
    value = strict_json(raw)
    if type(value.get('schema')) is not int or value['schema'] not in (1, 2) or raw != kernel.encode(value):
        retain.refuse('invalid_global_erase_intent')
    if value['schema'] == 1:
        exact(value, {'schema', 'plan_sha256', 'authorization'})
        return None
    exact(value, {'schema', 'plan_sha256', 'authorization', 'generation'})
    auth = value['authorization']
    exact(auth, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    if (auth['ok'] is not True or auth['plan_sha256'] != value['plan_sha256']
            or any(not kernel.SHA.fullmatch(str(item)) for item in
                   (value['plan_sha256'], auth['backup_sha256'], auth['aide_preparation_sha256']))):
        retain.refuse('invalid_global_erase_authorization')
    return value['generation']


def _read(path):
    raw = rpm.read(path, rpm.MAX_XML)
    value = strict_json(raw)
    if raw != kernel.encode(value):
        retain.refuse('execution_record_not_canonical')
    return value, rpm.sha(raw)


def _boot_evidence(stage, binding, plan, *, runner):
    from . import aide_updates, kernel_boot as boot
    path, value = boot._referenced_plan(stage, binding['boot_ref'])
    source, candidate, candidate_sha, installed, installed_sha = boot._candidate(stage)
    operation = strict_json(rpm.read(stage / 'operation.json', 8192))
    boot._validate_plan(stage, value, source, candidate, candidate_sha, installed, installed_sha,
                        {'boot_id': operation['boot_id']}, runner=runner)
    boot._accepted(stage, value, historical=True, runner=runner)
    receipt = retain.historical_acceptance(stage, plan['acceptance'])
    if (value['phase'] != 'resume' or value['boot_id'] != plan['boot_id']
            or value['operation_sha256'] != plan['operation_sha256']
            or value['kernel'] != plan['acceptance']['kernel']
            or value['old_kernel'] != plan['acceptance']['recovery_kernel']
            or receipt['resume_sha256'] != rpm.sha(rpm.read(boot._result_path(stage, value), rpm.MAX_XML))
            or plan['preserved'][kernel.GRUBENV] != value['files'][0]['after']):
        retain.refuse('execution_accepted_boot_changed')
    aide_updates.retained_plan_acceptance(stage, path, expected=binding['boot_integrity'], historical=True)


def load(stage, reference, *, historical=False, runner=run):
    """Validate the derived recipe against the immutable original and boot."""
    stage = Path(stage)
    binding = retain._reference(stage, reference, BINDING_NAME)
    exact(binding, {'schema', 'kind', 'id', 'root_plan_sha256', 'plan_sha256', 'boot_ref', 'boot_integrity'})
    paths = names(binding['id'])
    if (type(binding['schema']) is not int or binding['schema'] != 1 or binding['kind'] != KIND
            or reference['filename'] != paths['binding']):
        retain.refuse('execution_binding_changed')
    original, original_sha = retain.load_original_plan(stage, historical=True)
    plan, checksum = _read(stage / paths['plan'])
    try:
        valid_boot = str(uuid.UUID(plan['boot_id'])) == plan['boot_id']
    except (KeyError, ValueError, TypeError, AttributeError):
        valid_boot = False
    if (binding['root_plan_sha256'] != original_sha or binding['plan_sha256'] != checksum
            or set(plan) != set(original) or not valid_boot or binding['id'] != uuid.UUID(plan['boot_id']).hex
            or plan['boot_id'] == original['boot_id'] or plan['boot_id'] != plan['acceptance']['boot_id']):
        retain.refuse('execution_original_binding_changed')
    approved = plan['acceptance']
    retain.historical_acceptance(stage, approved)
    expected = copy.deepcopy(original)
    expected.update(boot_id=plan['boot_id'], acceptance=approved)
    expected['preserved'][kernel.GRUBENV] = plan['preserved'][kernel.GRUBENV]
    if (plan != expected or any(approved[key] != original['acceptance'][key]
                               for key in ('ok', 'kernel', 'recovery_kernel', 'install_plan_sha256'))):
        retain.refuse('execution_scope_changed')
    ancestry = [item[1] for item in kernel._acceptance_chain(stage)]
    if ancestry.index(approved['receipt_sha256']) >= ancestry.index(original['acceptance']['receipt_sha256']):
        retain.refuse('execution_acceptance_ancestry_changed')
    _boot_evidence(stage, binding, plan, runner=runner)
    if not historical and (plan['boot_id'] != retain.boot_id() or approved != retain.acceptance_record(stage)):
        retain.refuse('execution_current_acceptance_changed')
    return plan, checksum


def prepare(stage, *, accepted, runner=run):
    """Freeze a current-boot generation; the caller still prepares AIDE."""
    from . import aide_updates, kernel_boot as boot
    require_linux_root()
    stage = Path(stage)
    original, original_sha = retain.verify_unattempted(stage, runner=runner)
    approved = retain.acceptance(stage, accepted, runner)
    if approved['boot_id'] == original['boot_id']:
        retain.refuse('execution_later_boot_required')
    transitions = boot.accepted_transitions(stage, runner=runner)
    receipt, _, _ = kernel.read_acceptance(stage)
    if any(receipt.get(key) != value for key, value in transitions.items()):
        retain.refuse('execution_current_boot_not_accepted')
    current = boot._current(stage)
    if current is None or current[1]['phase'] != 'resume':
        retain.refuse('execution_normal_boot_resume_required')
    boot_path, boot_plan = current
    proof = aide_updates.retained_plan_acceptance(stage, boot_path)
    plan = copy.deepcopy(original)
    plan.update(boot_id=approved['boot_id'], acceptance=approved)
    plan['preserved'][kernel.GRUBENV] = kernel.describe(kernel.GRUBENV)
    paths = names(uuid.UUID(approved['boot_id']).hex)
    # Count even partially published generations. An unattempted generation
    # may be superseded after another boot, but evidence is never deleted and
    # the resulting lookup must remain bounded before any RPM attempt.
    tokens = set()
    with os.scandir(stage) as entries:
        for entry in entries:
            match = re.fullmatch(r'kernel-retention-execution-([a-f0-9]{32})-(?:plan|binding|integrity)\.json', entry.name)
            if match:
                tokens.add(match[1])
                if len(tokens) > MAX_GENERATIONS:
                    retain.refuse('execution_generation_limit')
    if uuid.UUID(approved['boot_id']).hex not in tokens and len(tokens) >= MAX_GENERATIONS:
        retain.refuse('execution_generation_limit')
    binding = {'schema': 1, 'kind': KIND, 'id': uuid.UUID(approved['boot_id']).hex,
               'root_plan_sha256': original_sha, 'plan_sha256': rpm.sha(kernel.encode(plan)),
               'boot_ref': boot._plan_reference(boot_plan), 'boot_integrity': proof}
    # Deterministic names make power loss between immutable publications
    # retryable without a mutable pointer or adopting any stale generation.
    kernel.record(stage, paths['plan'], plan)
    kernel.record(stage, paths['binding'], binding)
    reference = {'filename': paths['binding'], 'sha256': rpm.sha(kernel.encode(binding))}
    loaded, checksum = load(stage, reference, runner=runner)
    retain.verify_files(loaded, 'prepare', runner=runner)
    if retain.acceptance(stage, accepted, runner) != approved:
        retain.refuse('execution_acceptance_changed_during_plan')
    kernel.record(stage, paths['integrity'], retain.integrity_plan(loaded, checksum))
    return reference, loaded, checksum


def integrity_path(stage, reference):
    exact(reference, {'filename', 'sha256'})
    match = BINDING_NAME.fullmatch(str(reference['filename']))
    if not match:
        retain.refuse('invalid_execution_reference')
    return Path(stage) / names(match[1])['integrity']


def bound_integrity_plan(manager, stage, path, *, preparing):
    from . import kernel_retention_integration as integration
    stage, path = Path(stage), Path(path)
    match = INTEGRITY_NAME.fullmatch(path.name)
    if path.parent != stage or match is None:
        retain.refuse('unowned_execution_integrity_plan')
    identity, _, journal = integration.context(manager, stage)
    if stage.parent != identity.root / 'manager/os-updates' or journal.get('kernel_retention') not in {'pending', 'failed'}:
        retain.refuse('execution_integrity_operation_changed')
    binding_path = stage / names(match[1])['binding']
    _, binding_sha = _read(binding_path)
    reference = {'filename': binding_path.name, 'sha256': binding_sha}
    plan, checksum = load(stage, reference, runner=run)
    raw = manager.reader(path, maximum=rpm.MAX_XML, private=True)
    parsed = strict_json(raw)
    attempted = os.path.lexists(stage / retain.INTENT)
    if (raw != kernel.encode(parsed) or parsed != retain.integrity_plan(plan, checksum)
            or preparing and attempted or attempted and selected(stage) != reference):
        retain.refuse('execution_integrity_binding_changed')
    if not preparing:
        retain.verify_integrity_attempt(manager, identity, stage, plan, checksum, parsed, rpm.sha(raw))
    return parsed, rpm.sha(raw)
