"""Ordinary boot generations over the immutable original AIDE enrollment.

This owner never runs RPM, changes GRUB, or creates an OS update journal. Its
GRUB delta is the qualified vendor flag transition. Schema-2 AIDE preparations
separately bind narrowly qualified reboot metadata to the authenticated DB.
The expected host comes from enrollment plus the actual accepted AIDE chain;
capturing the current host is observation, never replacement authority.
"""
from __future__ import annotations

import base64
import copy
import os
from pathlib import Path
import re
import uuid

from . import aide, aide_updates, kernel_updates as kernel, os_payload as rpm
from . import ordinary_boot_state as native
from .common import Refused, run
from .host_job_storage import digest, exact, strict_json
from .updates import REQUIRED_CHECKS

KIND = 'ordinary-boot-v1'
PLAN = 'ordinary-boot-plan.json'
RESULT = 'ordinary-boot-result.json'
FINAL = 'ordinary-boot-complete.json'
PENDING = 'pending.json'
CURRENT = 'current.json'
HOLD = 'hold-current.json'
TOKEN = re.compile(r'[a-f0-9]{32}')
MAX_GENERATIONS = 1000
FIELDS = {'schema', 'kind', 'sequence', 'manifest_sha256', 'stage', 'boot_id',
          'original_enrollment_sha256', 'initial_snapshot_sha256', 'source_head',
          'source_observed_head', 'source_database_sha256', 'source_pending',
          'before', 'after', 'transition', 'metadata_bound_paths',
          'checkpoint_required', 'previous', 'hold'}


def refuse(reason):
    raise Refused('ordinary_boot_' + reason)


def _json(path, *, canonical=True):
    raw = rpm.read(Path(path), rpm.MAX_XML)
    value = strict_json(raw)
    if canonical and raw != kernel.encode(value):
        refuse('noncanonical_evidence')
    return value, rpm.sha(raw)


def _stage(stage, identity=None):
    stage = Path(stage)
    if (not stage.is_absolute() or not TOKEN.fullmatch(stage.name)
            or stage.parent.name != 'boot-integrity' or stage.resolve() != stage):
        refuse('unowned_generation')
    if identity is not None and stage.parent != identity.root / 'manager/boot-integrity':
        refuse('wrong_enrolled_generation')
    return stage


def _pointer(value):
    exact(value, {'stage', 'plan_sha256'})
    _stage(value['stage'])
    if not kernel.SHA.fullmatch(str(value['plan_sha256'])):
        refuse('invalid_generation_reference')
    return value


def _snapshot(stage, reference):
    exact(reference, {'filename', 'sha256'})
    if reference['filename'] not in {'before.json', 'after.json'}:
        refuse('invalid_snapshot_reference')
    value, checksum = _json(Path(stage) / reference['filename'])
    if checksum != reference['sha256']:
        refuse('snapshot_reference_changed')
    return native.validate_snapshot(value)


def _load(stage):
    """Pure retained validation; never requires an ancestor boot to be current."""
    stage = _stage(stage)
    value, checksum = _json(stage / PLAN)
    exact(value, FIELDS)
    if (type(value['schema']) is not int or value['schema'] != 1 or value['kind'] != KIND
            or value['stage'] != str(stage) or type(value['sequence']) is not int
            or not 0 <= value['sequence'] < MAX_GENERATIONS
            or value['manifest_sha256'] != digest({k: v for k, v in value.items() if k != 'manifest_sha256'})
            or type(value['checkpoint_required']) is not bool
            or not isinstance(value['metadata_bound_paths'], list)
            or value['metadata_bound_paths'] != sorted(set(value['metadata_bound_paths']))):
        refuse('generation_plan_changed')
    for key in ('original_enrollment_sha256', 'initial_snapshot_sha256', 'source_database_sha256'):
        if not kernel.SHA.fullmatch(str(value[key])):
            refuse('invalid_generation_digest')
    before, after = (_snapshot(stage, value[key]) for key in ('before', 'after'))
    if after['boot_id'] != value['boot_id'] or any(not native.protected_path(p) for p in value['metadata_bound_paths']):
        refuse('generation_snapshot_identity_changed')
    previous = value['previous']
    if value['hold'] is not None:
        _hold_reference(stage.parent, value['hold'])
    observation = before
    if previous is not None:
        _pointer(previous)
        prior_stage = _stage(previous['stage'])
        if prior_stage == stage or prior_stage.parent != stage.parent:
            refuse('foreign_generation_ancestor')
        prior, prior_sha = _json(prior_stage / PLAN)
        if (prior_sha != previous['plan_sha256'] or prior.get('kind') != KIND
                or prior.get('sequence') != value['sequence'] - 1
                or prior.get('original_enrollment_sha256') != value['original_enrollment_sha256']):
            refuse('generation_ancestor_changed')
        observation = _snapshot(prior_stage, prior['after'])
        # An intervening accepted OS update may change all of these. Its actual
        # AIDE prefix is checked by the reducer, so the old ordinary observation
        # is used only when the protected state still matches.
        if any(observation.get(k) != before[k] for k in native.fields(before) - {'boot_id', 'grub'}):
            observation = before
    elif value['sequence'] != 0:
        refuse('generation_ancestry_missing')
    expected_transition = _transition(observation, after, checkpoint=value['checkpoint_required'])
    if expected_transition != value['transition']:
        refuse('generation_transition_changed')
    if any(before[k] != after.get(k) for k in native.fields(before) - {'boot_id', 'grub'}):
        refuse('generation_protected_state_changed')
    return value, checksum


def _transition(before, after, *, checkpoint):
    if before == after:
        if not checkpoint:
            refuse('unnecessary_generation')
        return {'kind': 'checkpoint', 'before_boot_id': before['boot_id'],
                'boot_id': after['boot_id'], 'files': []}
    return native.validate_transition(before, after, same_boot=before['boot_id'] == after['boot_id'])


def _ancestors(stage):
    stage, seen, result = _stage(stage), set(), []
    while True:
        if stage in seen or len(seen) >= MAX_GENERATIONS:
            refuse('generation_ancestry_limit')
        seen.add(stage)
        value, checksum = _load(stage)
        result.append((stage, value, checksum))
        if value['previous'] is None:
            return result
        stage = Path(value['previous']['stage'])


def integrity_predecessor(stage, path):
    stage, path = _stage(stage), Path(path)
    if path != stage / PLAN:
        refuse('unexpected_integrity_plan')
    chain = _ancestors(stage)
    return None if len(chain) == 1 else (chain[1][1], chain[1][2])


def owns_maintenance(stage, owner):
    """Only the current generation or an immutable ancestor owns this gate."""
    if isinstance(owner, dict):
        owner = owner.get('release')
    if not isinstance(owner, str):
        return False
    if Path(stage).parent.name == 'holds':
        _load_hold(Path(stage))
        return str(stage) == owner
    for path, plan, _ in _ancestors(stage):
        if str(path) == owner:
            return True
        if plan['hold'] is not None and plan['hold']['stage'] == owner:
            _hold_reference(path.parent, plan['hold'])
            return True
    return False


def _load_hold(stage, identity=None):
    stage = Path(stage)
    if (not stage.is_absolute() or stage.parent.name != 'holds' or stage.parent.parent.name != 'boot-integrity'
            or not TOKEN.fullmatch(stage.name) or stage.resolve() != stage):
        refuse('unowned_observation_hold')
    data = stage.parent.parent.parent.parent
    if identity is not None and data != identity.root:
        refuse('foreign_observation_hold')
    value, checksum = _json(stage / 'receipt.json')
    exact(value, {'schema', 'kind', 'stage', 'installation_id', 'enrollment_sha256', 'boot_id'})
    try:
        valid = all(str(uuid.UUID(value[key])) == value[key] for key in ('installation_id', 'boot_id'))
    except (ValueError, TypeError, AttributeError):
        valid = False
    raw = rpm.read(data / 'manager/aide-enrollment.json', rpm.MAX_XML)
    if (type(value['schema']) is not int or value['schema'] != 1 or value['kind'] != 'ordinary-boot-observation-hold-v1'
            or value['stage'] != str(stage) or not valid or value['enrollment_sha256'] != rpm.sha(raw)
            or identity is not None and value['installation_id'] != identity.installation_id):
        refuse('observation_hold_binding_changed')
    return value, checksum


def _hold_reference(root, reference, identity=None):
    exact(reference, {'stage', 'sha256'})
    stage = Path(reference['stage'])
    if stage.parent != root / 'holds':
        refuse('foreign_observation_hold')
    value, checksum = _load_hold(stage, identity)
    if checksum != reference['sha256']:
        refuse('observation_hold_reference_changed')
    return value


def _hold(manager, identity):
    root = identity.root / 'manager/boot-integrity'
    path = root / HOLD
    if not os.path.lexists(path):
        return None
    reference = manager.records.read(path, identity)
    _hold_reference(root, reference, identity)
    manager.records.directory(Path(reference['stage']), identity)
    return reference


def _settled(identity, stage=None):
    from . import livepatch
    from .updates import UpdateManager
    root = identity.root / 'manager'
    livepatch.require_settled(root / 'updates')
    for name in ('kernel-pending.json',):
        if os.path.lexists(root / name):
            refuse('pending_kernel_owner')
    if os.path.lexists(root / 'os-transaction.json') != os.path.lexists(root / 'os-latest.json'):
        refuse('orphaned_os_owner')
    if os.path.lexists(root / 'os-transaction.json'):
        value, _ = _json(root / 'os-transaction.json', canonical=False)
        if (value.get('state') not in {'complete', 'failed', 'reboot_aborted'}
                or value.get('finalization', 'complete') != 'complete'
                or value.get('kernel_finalization') not in {None, 'complete'}
                or value.get('kernel_retention') not in {None, 'complete'}
                or value.get('kernel_rollback') not in {None, 'complete'}
                or value.get('reboot_pending') is True):
            refuse('pending_os_owner')
        _settled_os_pair(identity, value)
    if os.path.lexists(root / 'updates/transaction.json'):
        value, _ = _json(root / 'updates/transaction.json', canonical=False)
        if (value.get('state') not in {'preflight_failed', 'committed', 'rolled_back'}
                or value.get('state') != 'preflight_failed' and value.get('finalization') != 'complete'):
            refuse('pending_component_owner')
        # Phase labels cannot exclude a surviving hook with later effects. Use
        # the same completed-dispatch authority as component/OS admission before
        # observing a new boot generation or accepting an integrity database.
        UpdateManager(root / 'updates')._guard_hooks(
            value, Path(value.get('release', '')), legacy_accepted=True)
    if os.path.lexists(root / 'maintenance.json'):
        marker, _ = _json(root / 'maintenance.json', canonical=False)
        hold = None
        pointer = root / 'boot-integrity' / HOLD
        if os.path.lexists(pointer):
            hold, _ = _json(pointer, canonical=False)
            _hold_reference(pointer.parent, hold, identity)
        inherited_hold = hold is not None and marker.get('release') == hold['stage']
        if (marker.get('active') is not True or not inherited_hold
                and (stage is None or not owns_maintenance(stage, marker.get('release')))):
            refuse('foreign_maintenance_owner')


def _settled_os_pair(identity, transaction):
    latest, _ = _json(identity.root / 'manager/os-latest.json', canonical=False)
    try:
        stage = Path(transaction['stage'])
        boot = transaction['boot_id']
        valid_boot = isinstance(boot, str) and str(uuid.UUID(boot)) == boot
    except (KeyError, TypeError, ValueError, AttributeError):
        refuse('os_journal_owner_missing')
    _os_stage(stage, identity)
    if not stage.is_dir() or latest.get('stage') != str(stage) or latest.get('boot_id') != boot or not valid_boot:
        refuse('os_journal_owner_mismatch')
    state = transaction.get('state')
    if state == 'failed':
        executed = {'rpm-apply-intent.json', 'kernel-apply-intent.json', 'kernel-rpm-command.json',
                    'kernel-installed.json', 'kernel-completed.json', 'kernel-deferred.json'}
        with os.scandir(stage) as entries:
            for count, item in enumerate(entries, 1):
                if count > 4096:
                    refuse('failed_os_stage_limit')
                if item.name.startswith(('kernel-boot-', 'kernel-default-', 'kernel-retention-', 'kernel-acceptance-')):
                    executed.add(item.name)
        if (latest.get('state') != 'prepared' or transaction.get('recovery_phase') not in {'preflight', 'planning'}
                or any(os.path.lexists(stage / name) for name in executed)):
            refuse('failed_os_execution_requires_recovery')
    elif state == 'complete':
        status = latest.get('state')
        if status == 'prepared':
            if (transaction.get('no_updates') is not True or transaction.get('status') != 'no_updates'
                    or transaction.get('reboot_pending') is not False):
                refuse('os_preflight_is_not_completion')
        elif status == 'postcheck_passed':
            if transaction.get('status') not in {'updated', 'no_updates'} or transaction.get('reboot_pending') is not False:
                refuse('os_postcheck_completion_changed')
        elif status == 'reboot_completed':
            try:
                observed = transaction['observed_boot_id']
                valid = str(uuid.UUID(observed)) == observed
            except (KeyError, TypeError, ValueError, AttributeError):
                valid = False
            if not valid or latest.get('observed_boot_id') != observed or transaction.get('reboot_pending') is not False:
                refuse('os_completed_boot_mismatch')
        else:
            refuse('os_latest_not_completed')
    else:
        refuse('os_recovery_still_pending')
    operation = stage / 'operation.json'
    if state == 'complete' or os.path.lexists(operation):
        value, _ = _json(operation, canonical=False)
        exact(value, {'schema', 'id', 'stage', 'boot_id'})
        try:
            valid_id = str(uuid.UUID(value['id'])) == value['id']
        except (TypeError, ValueError, AttributeError):
            valid_id = False
        if (type(value['schema']) is not int or value['schema'] != 1 or not valid_id
                or value.get('stage') != str(stage) or value.get('boot_id') != boot):
            refuse('os_operation_identity_changed')


def observation_hold(data, *, boot_id, manager=None):
    """Retain failure ownership, never an enrollment or integrity acceptance."""
    manager = manager or aide.Aide()
    identity = manager.guard()
    if Path(data) != identity.root:
        refuse('unenrolled_data_root')
    try:
        if str(uuid.UUID(boot_id)) != boot_id:
            raise ValueError()
    except (TypeError, ValueError, AttributeError):
        refuse('invalid_hold_boot_identity')
    root = identity.root / 'manager/boot-integrity'
    manager.records.directory(root, identity, create=True)
    hold = _hold(manager, identity)
    try:
        existing = _existing(manager, identity)
    except (Refused, OSError, ValueError, KeyError):
        # Corrupt ordinary evidence itself can require a hold. With no gate or
        # pending AIDE owner, recording failure does not adopt that evidence.
        if os.path.lexists(identity.root / 'manager/maintenance.json'):
            marker, _ = _json(identity.root / 'manager/maintenance.json', canonical=False)
            if hold is None or marker.get('active') is not True or marker.get('release') != hold['stage']:
                raise
        existing = None
    _settled(identity, existing)
    marker_path = identity.root / 'manager/maintenance.json'
    if os.path.lexists(marker_path):
        marker, _ = _json(marker_path, canonical=False)
        owner = marker['release']
        if existing is not None and owns_maintenance(existing, owner):
            return Path(owner)
        if hold is not None and hold['stage'] == owner:
            return Path(owner)
        refuse('foreign_maintenance_owner')
    if hold is not None:
        return Path(hold['stage'])
    # Incomplete AIDE work belongs to its existing ordinary operation. A
    # foreign owner must not be covered by a newly invented failure hold.
    pending_path = identity.root / 'manager/aide/authorized/pending.json'
    if os.path.lexists(pending_path):
        pending = manager.records.read(pending_path, identity)
        if pending.get('state') != 'complete':
            if existing is None:
                refuse('foreign_integrity_owner')
            _history(manager, existing)
            return existing
    raw = rpm.read(identity.root / 'manager/aide-enrollment.json', rpm.MAX_XML)
    stage = root / 'holds' / uuid.uuid4().hex
    manager.records.directory(stage, identity, create=True)
    value = {'schema': 1, 'kind': 'ordinary-boot-observation-hold-v1', 'stage': str(stage),
             'installation_id': identity.installation_id, 'boot_id': boot_id,
             'enrollment_sha256': rpm.sha(raw)}
    kernel.record(stage, 'receipt.json', value)
    _load_hold(stage, identity)
    manager.records.write(root / HOLD, {'stage': str(stage), 'sha256': rpm.sha(kernel.encode(value))}, identity)
    return stage


def _description(item):
    return {key: value for key, value in item.items() if key not in {'path', 'ghost', 'device', 'inode'}}


def _inventory(state, before, after, *, repeated=False):
    if state['inventory'] == before:
        state['inventory'] = copy.deepcopy(after)
    elif not repeated or state['inventory'] != after:
        refuse('accepted_inventory_discontinuity')


def _env(state, before, after, raw_before=None, raw_after=None, *, repeated=False):
    if state['grub']['description'] != before:
        if not repeated or state['grub']['description'] != after:
            refuse('accepted_environment_discontinuity')
    if raw_before is not None and rpm.sha(base64.b64decode(raw_before, validate=True)) != before['sha256']:
        refuse('accepted_environment_preimage_changed')
    if raw_after is not None and rpm.sha(base64.b64decode(raw_after, validate=True)) != after['sha256']:
        refuse('accepted_environment_output_changed')
    state['grub'] = {'raw': raw_after, 'description': copy.deepcopy(after)}


def _replace_artifact(state, path, before, after, unresolved, *, adding=False):
    if not native.protected_path(path):
        return
    prior = state['artifacts'].get(path)
    if adding:
        if prior is not None:
            refuse('accepted_addition_already_present')
    elif prior is None or any(prior.get(k) != v for k, v in _description(before).items()):
        refuse('accepted_artifact_discontinuity')
    value = _description(after)
    if 'xattrs_sha256' not in value:
        unresolved.add(path)
    else:
        unresolved.discard(path)
    state['artifacts'][path] = value


def _known_description(actual, expected):
    """Old payload receipts can lack xattrs, never content/security fields."""
    expected = _description(expected)
    return (actual is not None and set(expected) - set(actual) <= {'xattrs_sha256'}
            and all(expected.get(key) == value for key, value in actual.items()))


def _boot_history_environment(state, stage, plan):
    """Follow exact retained observations skipped by an interrupted old scan."""
    chain, seen = [], set()
    current = plan
    while state['grub']['description'] != current['files'][0]['before']:
        if current['id'] in seen or len(seen) >= MAX_GENERATIONS or current['previous'] is None:
            refuse('accepted_boot_observation_gap')
        seen.add(current['id']); chain.append(current)
        pointer = current['previous']
        prior, checksum = _json(stage / ('kernel-boot-' + pointer['id'] + '-plan.json'))
        if (checksum != pointer['sha256'] or prior.get('id') != pointer['id']
                or prior.get('stage') != str(stage) or prior.get('kind') != 'kernel-boot-v1'
                or prior.get('candidate_plan_sha256') != plan['candidate_plan_sha256']
                or prior.get('installed_sha256') != plan['installed_sha256']):
            refuse('accepted_boot_observation_ancestor_changed')
        current = prior
    chain.append(current)
    for item in reversed(chain):
        files = item['files']
        if len(files) != 1 or files[0]['path'] != native.ENV:
            refuse('accepted_boot_observation_scope_changed')
        _env(state, files[0]['before'], files[0]['after'], item['before_raw'], item['after_raw'])


def _qualified_boot(stage, plan):
    """Validate old boot recipes without borrowing today's operation or boot."""
    from . import kernel_boot as boot
    candidate_stage, candidate, candidate_sha, installed, installed_sha = boot._candidate(stage)
    operation, _ = _json(stage / 'operation.json', canonical=False)
    boot._validate_plan(stage, plan, candidate_stage, candidate, candidate_sha,
                        installed, installed_sha, {'boot_id': operation['boot_id']})


def _rollback_history_environment(state, stage, plan, original):
    """A compound removal may span only its verified recovery observations."""
    from . import kernel_rollback as rollback
    prior = plan.get('previous')
    seen = set()
    boundaries = [(original['recovery']['boot_id'], original['preserved'][native.ENV])]
    while prior is not None:
        if prior['sha256'] in seen or len(seen) >= MAX_GENERATIONS:
            refuse('accepted_rollback_observation_limit')
        seen.add(prior['sha256'])
        value, _ = rollback.load_resume(stage, prior, historical=True)
        boundaries.append((value['boot_id'], value['files'][0]['after']))
        prior = value['previous']
    if (state['kernel'] != original['recovery_kernel'] or state['default_kernel'] != original['recovery_kernel']
            or not any(state['boot_id'] == boot and state['grub']['description'] == description
                       for boot, description in boundaries)):
        refuse('accepted_rollback_observation_gap')
    _env(state, state['grub']['description'], plan['files'][0]['after'],
         state['grub']['raw'], plan['after_raw'])
    state['boot_id'] = plan['boot_id']


def _os_stage(stage, identity):
    if stage.parent != identity.root / 'manager/os-updates' or not TOKEN.fullmatch(stage.name) or stage.resolve() != stage:
        refuse('accepted_os_stage_changed')


def _fold(initial, history, identity):
    """Reduce only exact, already scan-accepted typed transactions.

    New signed payload xattrs absent from old receipts remain unresolved. They
    can become a checkpoint only after a full scan against that accepted DB.
    """
    state, unresolved, erased = copy.deepcopy(initial), set(), set()
    checkpoint = False
    for row in history:
        plan, entry, prepared = row['plan'], row['entry'], row['prepared']
        kind, stage = plan.get('kind'), Path(prepared['release'])
        if kind != KIND and entry['direction'] != 'forward' and kind is not None:
            refuse('unsupported_accepted_inverse')
        if kind == KIND:
            value, checksum = _load(stage)
            if (value != plan or checksum != entry['plan_sha256']
                    or entry['previous'] != value['source_head']
                    or entry['previous_database_sha256'] != value['source_database_sha256']):
                refuse('accepted_ordinary_prefix_changed')
            before, after = _snapshot(stage, plan['before']), _snapshot(stage, plan['after'])
            _match_expected(state, before, unresolved)
            if sorted(unresolved) != plan['metadata_bound_paths'] or state['boot_id'] != before['boot_id']:
                refuse('accepted_metadata_binding_changed')
            state, unresolved, checkpoint = copy.deepcopy(after), set(), False
        elif kind == 'kernel-install-v1':
            from . import kernel_integrity
            _os_stage(stage, identity)
            payload, checksum = kernel.load_plan(stage)
            if plan != kernel_integrity.plan(stage, payload, checksum):
                refuse('accepted_kernel_payload_changed')
            installed, _ = _json(stage / 'kernel-installed.json')
            if (installed.get('plan_sha256') != checksum or installed.get('kernel') != payload['kernel']
                    or installed.get('old_kernel') != payload['old_kernel']
                    or set(installed.get('generated', {})) != set(payload['generated'])
                    or set(installed.get('mutable', {})) != set(payload['mutable_before'])):
                refuse('accepted_kernel_generated_receipt_changed')
            _inventory(state, payload['before_inventory'], payload['after_inventory'])
            for path, value in {**payload['shared'], **payload['preserved']}.items():
                if native.protected_path(path):
                    if not _known_description(state['artifacts'].get(path), value):
                        refuse('accepted_kernel_preserved_changed')
                    state['artifacts'][path] = _description(value)
                    unresolved.discard(path)
            for item in payload['files']:
                if item['ghost'] or item['path'] in payload['shared'] or not native.protected_path(item['path']):
                    continue
                _replace_artifact(state, item['path'], None, item, unresolved, adding=True)
            for path, value in installed['generated'].items():
                if native.protected_path(path):
                    # A generated ghost may replace a signed-payload path, but
                    # only the exact frozen generated inventory grants this.
                    state['artifacts'][path] = _description(value)
                    unresolved.discard(path)
            for path, value in installed['mutable'].items():
                if path == native.ENV:
                    _env(state, payload['mutable_before'][path], value)
                else:
                    _replace_artifact(state, path, payload['mutable_before'][path], value, unresolved)
            checkpoint = True
        elif kind == 'os-payload-v1':
            _os_stage(stage, identity)
            payload, checksum = rpm.load_plan(stage)
            if plan != rpm.integrity_plan(payload, checksum):
                refuse('accepted_os_payload_changed')
            _inventory(state, payload['before_inventory'], payload['after_inventory'])
            for item in payload['files']:
                value = {**item['after'], 'xattrs_sha256': prepared['metadata'][item['path']]['xattrs_sha256']}
                _replace_artifact(state, item['path'], item['before'], value, unresolved)
            checkpoint = True
        elif kind == 'kernel-boot-v1':
            _os_stage(stage, identity)
            path = stage / ('kernel-boot-' + plan['id'] + '-plan.json')
            stored, checksum = _json(path)
            if stored != plan or checksum != entry['plan_sha256'] or len(plan['files']) != 1 or plan['files'][0]['path'] != native.ENV:
                refuse('accepted_boot_plan_changed')
            _qualified_boot(stage, plan)
            _boot_history_environment(state, stage, plan)
            state['boot_id'], state['kernel'] = plan['boot_id'], plan['running_kernel']
            from .kernel_boot import parse_environment
            saved = parse_environment(base64.b64decode(plan['after_raw'], validate=True))['saved_entry']
            prefix = state['machine_id'] + '-'
            if not saved.startswith(prefix):
                refuse('accepted_default_identity_changed')
            state['default_kernel'] = saved[len(prefix):]
            checkpoint = True
        elif kind in {'rocky-kernel-retention-v1', 'rocky-kernel-retention-resume-v1'}:
            from . import kernel_retention as retain
            _os_stage(stage, identity)
            # An execution after a later accepted boot has its own immutable
            # GRUB preimage and AIDE preparation. Resolve the plan this entry
            # actually accepted, never whichever generation is current now.
            wanted = plan['manifest_sha256'] if kind == retain.KIND else plan['retention_plan_sha256']
            original, checksum = retain.load_plan_by_checksum(stage, wanted)
            if kind == retain.KIND:
                if plan != retain.integrity_plan(original, checksum):
                    refuse('accepted_retention_plan_changed')
            elif (plan['retention_plan_sha256'] != checksum or plan['removed'] != original['removed']
                  or plan['preserved'] != {p: v for p, v in original['preserved'].items() if p != native.ENV}
                  or plan['mutable_directories'] != original['mutable_directories']):
                refuse('accepted_compound_retention_changed')
            repeated = checksum in erased
            _inventory(state, original['before_inventory'], original['after_inventory'], repeated=repeated)
            for path, value in original['removed'].items():
                if not native.protected_path(path):
                    continue
                if not repeated and not _known_description(state['artifacts'].get(path), value):
                    refuse('accepted_retention_preimage_changed')
                if repeated and path in state['artifacts']:
                    refuse('accepted_erased_artifact_reappeared')
                state['artifacts'].pop(path, None); unresolved.discard(path)
            erased.add(checksum)
            if kind == retain.RESUME_KIND:
                boot, boot_sha = _json(stage / plan['boot_ref']['filename'])
                if (boot_sha != plan['boot_ref']['sha256'] or boot['phase'] != 'retention_resume'
                        or boot['boot_id'] != plan['boot_id'] or plan['files'][0]['after'] != boot['files'][0]['after']):
                    refuse('accepted_retention_boot_changed')
                _qualified_boot(stage, boot)
                # A repeated compound scan can include a removal already
                # accepted by a prior entry; its GRUB observation still has
                # exact ancestry in the separately retained boot plan.
                _boot_history_environment(state, stage, boot)
                state['boot_id'], state['kernel'] = boot['boot_id'], boot['running_kernel']
                state['default_kernel'] = boot['running_kernel']
            checkpoint = True
        elif kind == 'rocky-kernel-rollback-v1':
            from . import kernel_rollback as rollback
            _os_stage(stage, identity)
            compound = 'rollback_plan_sha256' in plan
            wanted = plan['rollback_plan_sha256'] if compound else plan['manifest_sha256']
            original, checksum = rollback.load_plan_by_checksum(stage, wanted)
            if compound:
                reference = {'filename': 'kernel-rollback-resume-' + plan['id'] + '-integrity.json',
                             'sha256': entry['plan_sha256']}
                retained, _ = rollback.load_resume(stage, reference, historical=True)
                if retained != plan:
                    refuse('accepted_rollback_resume_changed')
            elif plan != rollback.integrity_plan(original, checksum):
                refuse('accepted_rollback_plan_changed')
            repeated = checksum in erased
            _inventory(state, original['before_inventory'], original['after_inventory'], repeated=repeated)
            for path, value in original['removed'].items():
                if not native.protected_path(path):
                    continue
                if not repeated and not _known_description(state['artifacts'].get(path), value):
                    refuse('accepted_rollback_preimage_changed')
                if repeated and path in state['artifacts']:
                    refuse('accepted_rollback_artifact_reappeared')
                state['artifacts'].pop(path, None); unresolved.discard(path)
            erased.add(checksum)
            if compound:
                _rollback_history_environment(state, stage, plan, original)
            checkpoint = True
        elif kind is None:
            # Fixed runtime generations cannot write any boot artifact or RPM
            # inventory. Do not silently ignore an overlapping future recipe.
            paths = [i['path'] for key in ('files', 'generation_additions', 'content_additions', 'preserved') for i in plan.get(key, [])]
            paths.append(plan.get('selection', {}).get('path', '/invalid'))
            if any(path == native.ENV or native.protected_path(path) for path in paths):
                refuse('host_recipe_overlaps_boot_scope')
        else:
            refuse('unsupported_accepted_plan_kind')
    return state, unresolved, checkpoint


def _match_expected(expected, actual, unresolved):
    if set(expected['artifacts']) != set(actual['artifacts']):
        refuse('artifact_membership_changed')
    for path, value in expected['artifacts'].items():
        observed = actual['artifacts'][path]
        keys = set(observed) - ({'xattrs_sha256'} if path in unresolved else set())
        if set(value) != keys or any(observed.get(key) != item for key, item in value.items()):
            refuse('accepted_artifact_changed')
    for key in native.fields(expected) - {'artifacts', 'grub', 'boot_id'}:
        if expected[key] != actual.get(key):
            refuse('accepted_host_identity_changed')
    if expected['grub']['description'] != actual['grub']['description']:
        refuse('accepted_environment_changed')
    if expected['grub']['raw'] is not None and expected['grub']['raw'] != actual['grub']['raw']:
        refuse('accepted_environment_bytes_changed')


def _root_snapshot(history, identity):
    enrollment = history['original_enrollment']
    checksum = enrollment['facts'].get('ordinary_boot_snapshot_sha256')
    if not kernel.SHA.fullmatch(str(checksum)):
        refuse('explicit_enrollment_migration_required')
    return aide.verify_initial_boot_snapshot(identity, checksum), checksum


def _history(manager, stage=None):
    authority = None
    if stage is not None:
        # Determine the real pending owner, then require exact immutable
        # ancestry before allowing the reader's narrowly scoped CAS view.
        identity = manager.guard()
        path = identity.root / 'manager/aide/authorized/pending.json'
        if os.path.lexists(path):
            pending = manager.records.read(path, identity)
            if pending.get('state') != 'complete':
                prepared = manager.records.read(identity.root / 'manager/aide/authorized/prepared' /
                                                (pending['prepared']['id'] + '.json'), identity)
                owner = prepared.get('release')
                if not owns_maintenance(stage, owner):
                    refuse('foreign_integrity_owner')
                authority = aide_updates.pending_plan_authority(stage, Path(stage) / PLAN)
    return aide_updates.accepted_plan_history(manager=manager, pending_authority=authority)


def _effective(history):
    rows = list(history['history'])
    pending = history['pending']
    head, checksum = history['head'], history['database_sha256']
    evidence = None
    if pending is not None and pending['state'] != 'complete':
        prepared = history['pending_prepared']
        evidence = {'owner': prepared['release'], 'sha256': digest(pending), 'entry': pending.get('entry')}
        copied = pending['state'] == 'ready' and history['current_database_sha256'] == pending['database_sha256']
        if copied and head != pending['entry']:
            # Byte-identical input/output DBs also follow the root CAS helper's
            # output branch. Treating these as input would disagree once that
            # exact historical entry is published during recovery.
            if history['current_database_sha256'] != pending['database_sha256']:
                refuse('unbound_integrity_database')
            entry = pending['proposed_entry']
            if entry['previous'] != head or entry['previous_database_sha256'] != checksum:
                refuse('unbound_integrity_proposal')
            rows.append({'entry_ref': pending['entry'], 'entry': entry, 'prepared': prepared, 'plan': prepared['plan']})
            head, checksum = pending['entry'], pending['database_sha256']
        elif history['current_database_sha256'] != checksum:
            refuse('unbound_integrity_database')
    return rows, head, checksum, evidence


def _reference(stage, checksum):
    return {'stage': str(stage), 'plan_sha256': checksum}


def _existing(manager, identity):
    root = identity.root / 'manager/boot-integrity'
    for name in (PENDING, CURRENT):
        path = root / name
        if os.path.lexists(path):
            pointer = manager.records.read(path, identity)
            _pointer(pointer)
            stage = _stage(pointer['stage'], identity)
            manager.records.directory(stage, identity)
            _, checksum = _load(stage)
            if pointer['plan_sha256'] != checksum:
                refuse('current_generation_changed')
            return stage
    return None


def _completed(stage, plan_sha):
    value, _ = _json(stage / FINAL)
    exact(value, {'schema', 'ok', 'status', 'stage', 'boot_id', 'plan_sha256', 'result_sha256', 'checks'})
    result, result_sha = _json(stage / RESULT)
    if (value['schema'] != 1 or value['ok'] is not True or value['status'] != 'complete'
            or value['stage'] != str(stage) or value['plan_sha256'] != plan_sha
            or value['result_sha256'] != result_sha or result.get('plan_sha256') != plan_sha
            or result.get('boot_id') != value['boot_id'] or set(value['checks']) != REQUIRED_CHECKS
            or any(value['checks'][key] is not True for key in REQUIRED_CHECKS)):
        refuse('completed_generation_changed')
    return value


def pending_stage(data, runner=run, *, manager=None):
    """Observe and freeze one generation; never scan or adopt a database."""
    manager = manager or aide.Aide()
    identity = manager.guard()
    if Path(data) != identity.root:
        refuse('unenrolled_data_root')
    root = identity.root / 'manager/boot-integrity'
    manager.records.directory(root, identity)
    previous_stage = _existing(manager, identity)
    _settled(identity, previous_stage)
    hold = _hold(manager, identity)
    history = _history(manager, previous_stage)
    initial, initial_sha = _root_snapshot(history, identity)
    rows, head, database_sha, pending = _effective(history)
    expected, unresolved, checkpoint = _fold(initial, rows, identity)
    observed = native.capture(runner=runner)
    previous, sequence, observation = None, 0, None
    if previous_stage is not None:
        prior, prior_sha = _load(previous_stage)
        previous = _reference(previous_stage, prior_sha)
        sequence = prior['sequence'] + 1
        observation = _snapshot(previous_stage, prior['after'])
        if observation == observed:
            if ((hold is None or prior['hold'] == hold)
                    and (os.path.lexists(root / PENDING) or os.path.lexists(identity.root / 'manager/maintenance.json'))):
                return previous_stage
        elif any(observation.get(k) != expected[k] for k in native.fields(expected) - {'grub', 'boot_id', 'artifacts'}):
            observation = None
    # Fill ONLY missing xattrs for precise previously accepted payload paths.
    # No checkpoint is published until an actual AIDE scan proves these match
    # its already accepted DB. Even unchanged GRUB must take that scan path.
    before = copy.deepcopy(expected)
    for path in unresolved:
        if path not in observed['artifacts']:
            refuse('accepted_payload_missing')
        before['artifacts'][path]['xattrs_sha256'] = observed['artifacts'][path]['xattrs_sha256']
    if before['grub']['raw'] is None:
        raw = observed['grub']['raw']
        if rpm.sha(base64.b64decode(raw, validate=True)) != before['grub']['description']['sha256']:
            refuse('accepted_environment_preimage_unavailable')
        before['grub']['raw'] = raw
    native.validate_snapshot(before)
    # Before is the accepted DB state. Only a qualified environment transition
    # may differ in the observation; all other fields are compared exactly.
    comparison = copy.deepcopy(observed)
    comparison['grub'] = copy.deepcopy(before['grub'])
    _match_expected(expected, comparison, unresolved)
    if before == observed and not checkpoint and pending is None and hold is None:
        if previous_stage is not None:
            _completed(previous_stage, previous['plan_sha256'])
        elif any(row['plan'].get('kind') == KIND for row in rows):
            refuse('ordinary_generation_pointer_missing')
        return None
    if observation is None or any(observation.get(k) != before[k] for k in native.fields(before) - {'boot_id', 'grub'}):
        observation = before
    # Resolving a failure hold requires an actual fresh scan and health even
    # when the now-valid native observation is byte-identical to its baseline.
    if hold is not None and observation == observed:
        checkpoint = True
    transition = _transition(observation, observed, checkpoint=checkpoint)
    stage = root / uuid.uuid4().hex
    manager.records.directory(stage, identity, create=True)
    refs = {}
    for name, value in (('before', before), ('after', observed)):
        kernel.record(stage, name + '.json', value)
        refs[name] = {'filename': name + '.json', 'sha256': rpm.sha(kernel.encode(value))}
    if pending is not None:
        kernel.record(stage, 'source-pending.json', {'pending': history['pending'], 'prepared': history['pending_prepared']})
    value = {'schema': 1, 'kind': KIND, 'sequence': sequence, 'stage': str(stage),
             'boot_id': observed['boot_id'], 'original_enrollment_sha256': digest(history['original_enrollment']),
             'initial_snapshot_sha256': initial_sha, 'source_head': head,
             'source_observed_head': history['head'], 'source_database_sha256': database_sha,
             'source_pending': pending, **refs, 'transition': transition,
             'metadata_bound_paths': sorted(unresolved), 'checkpoint_required': checkpoint,
             'previous': previous, 'hold': hold}
    value['manifest_sha256'] = digest(value)
    kernel.record(stage, PLAN, value)
    _load(stage)
    manager.records.write(root / PENDING, _reference(stage, rpm.sha(kernel.encode(value))), identity)
    return stage


def _bound_history(manager, stage, plan):
    identity = manager.guard()
    _ancestors(stage)
    history = _history(manager, stage)
    initial, initial_sha = _root_snapshot(history, identity)
    if (digest(history['original_enrollment']) != plan['original_enrollment_sha256']
            or initial_sha != plan['initial_snapshot_sha256']):
        refuse('enrollment_binding_changed')
    rows, effective_head, database_sha, _ = _effective(history)
    prefix, seen_source = [], plan['source_head'] is None
    checksum = history['original_enrollment']['database_sha256']
    extensions = 0
    for row in rows:
        if seen_source:
            extensions += 1
            if (row['plan'] != plan or row['prepared']['release'] != str(stage)
                    or row['entry']['direction'] != 'forward' or extensions > 1):
                refuse('foreign_integrity_extension')
        else:
            prefix.append(row)
            checksum = row['entry']['database_sha256']
            if row['entry_ref'] == plan['source_head']:
                seen_source = True
    if not seen_source or checksum != plan['source_database_sha256']:
        refuse('integrity_input_prefix_changed')
    expected, unresolved, checkpoint = _fold(initial, prefix, identity)
    before = _snapshot(stage, plan['before'])
    _match_expected(expected, before, unresolved)
    expected_checkpoint = checkpoint or plan['hold'] is not None and plan['transition']['kind'] == 'checkpoint'
    if (sorted(unresolved) != plan['metadata_bound_paths'] or expected_checkpoint != plan['checkpoint_required']
            or expected['boot_id'] != before['boot_id']):
        refuse('checkpoint_authority_changed')
    # The only permitted unpublished prefix was a prior owned ready CAS whose
    # output was already current at observation. Validate its immutable plan
    # ancestry even after recovery published that exact entry.
    if plan['source_pending'] is not None:
        item = plan['source_pending']
        exact(item, {'owner', 'sha256', 'entry'})
        if not owns_maintenance(stage, item['owner']) or item['owner'] == str(stage) or not kernel.SHA.fullmatch(str(item['sha256'])):
            refuse('pending_ancestry_changed')
        frozen, _ = _json(stage / 'source-pending.json')
        exact(frozen, {'pending', 'prepared'})
        pending, prepared = frozen['pending'], frozen['prepared']
        retained, _ = _json(identity.root / 'manager/aide/authorized/prepared' / (prepared['id'] + '.json'), canonical=False)
        if (digest(pending) != item['sha256'] or prepared != retained or prepared['release'] != item['owner']
                or pending['prepared'] != {'id': prepared['id'], 'sha256': digest(prepared)}
                or plan['source_observed_head'] not in (pending['previous'], pending.get('entry'))
                or pending.get('entry') != item['entry']):
            refuse('frozen_pending_evidence_changed')
        if plan['source_observed_head'] != plan['source_head']:
            match = next((row for row in prefix if row['entry_ref'] == plan['source_head']), None)
            if (item['entry'] != plan['source_head'] or match is None
                    or pending.get('proposed_entry') != match['entry']):
                refuse('pending_proposed_prefix_changed')
    elif plan['source_observed_head'] != plan['source_head']:
        refuse('unbound_observed_prefix')
    return history


def bound_integrity_plan(manager, stage, path, *, preparing):
    identity = manager.guard()
    stage = _stage(stage, identity)
    manager.records.directory(stage, identity)
    if Path(path) != stage / PLAN:
        refuse('unexpected_integrity_plan')
    value, checksum = _load(stage)
    _settled(identity, stage)
    _bound_history(manager, stage, value)
    if native.capture(runner=run) != _snapshot(stage, value['after']):
        refuse('current_observation_changed')
    return value, checksum


def integrity_snapshot(manager, plan, phase, retained=None):
    if phase not in {'prepare', 'forward'}:
        refuse('unsupported_integrity_direction')
    stage = _stage(plan['stage'], manager.guard())
    actual = native.capture(runner=run)
    if actual != _snapshot(stage, plan['after']):
        refuse('integrity_observation_changed')
    value = {'snapshot_sha256': plan['after']['sha256'], 'boot_id': plan['boot_id'],
             'environment': actual['grub']['description']}
    if retained is not None and retained != value:
        refuse('integrity_metadata_changed')
    return value


def allowed_integrity_report(report, plan, phase):
    if phase not in {'prepare', 'forward'}:
        refuse('unsupported_integrity_direction')
    permitted = {native.ENV} if plan['transition']['kind'] != 'checkpoint' else set()
    if report.get('added') or report.get('removed') or set(report.get('changed', {})) - permitted:
        refuse('unrelated_integrity_change')


def _fresh_check(manager):
    # Lifecycle already holds manager/update locks. Take only the remaining
    # AIDE coordination locks, as the prepare/accept adapters do; check() would
    # attempt to acquire the outer manager lock again through another fd.
    with aide_updates._locked(manager) as (state, identity):
        result = manager._check_locked(state, identity)
        if result.get('state') != 'clean':
            refuse('fresh_full_integrity_check_required')
    return result


def reconcile(stage, *, prepare, accept, runner=run, manager=None):
    manager = manager or aide.Aide()
    stage = _stage(stage, manager.guard())
    plan, checksum = _load(stage)
    _settled(manager.guard(), stage)
    _bound_history(manager, stage, plan)
    if native.capture(runner=runner) != _snapshot(stage, plan['after']):
        refuse('reconciliation_observation_changed')
    if not os.path.lexists(stage / RESULT):
        result = prepare(stage, stage / PLAN)
        if result.get('ok') is not True or result.get('plan_sha256') != checksum:
            refuse('integrity_preparation_failed')
        result = accept(stage, stage / PLAN)
        if result.get('ok') is not True or result.get('plan_sha256') != checksum or result.get('direction') != 'forward':
            refuse('integrity_acceptance_failed')
        proof = aide_updates.retained_plan_acceptance(stage, stage / PLAN, manager=manager)
        value = {'schema': 1, 'ok': True, 'status': 'integrity_reconciled', 'stage': str(stage),
                 'boot_id': plan['boot_id'], 'plan_sha256': checksum, 'aide': proof}
        kernel.record(stage, RESULT, value)
    else:
        _fresh_check(manager)
    return _result(manager, stage, runner=runner)


def _result(manager, stage, *, runner):
    plan, checksum = _load(stage)
    value, _ = _json(stage / RESULT)
    exact(value, {'schema', 'ok', 'status', 'stage', 'boot_id', 'plan_sha256', 'aide'})
    if (value['schema'] != 1 or value['ok'] is not True or value['status'] != 'integrity_reconciled'
            or value['stage'] != str(stage) or value['boot_id'] != plan['boot_id'] or value['plan_sha256'] != checksum):
        refuse('integrity_result_changed')
    aide_updates.retained_plan_acceptance(stage, stage / PLAN, manager=manager, expected=value['aide'])
    _bound_history(manager, stage, plan)
    if native.capture(runner=runner) != _snapshot(stage, plan['after']):
        refuse('accepted_observation_changed')
    return value


def finalize(stage, health, runner=run, *, manager=None):
    manager = manager or aide.Aide()
    identity = manager.guard()
    stage = _stage(stage, identity)
    _settled(identity, stage)
    result = _result(manager, stage, runner=runner)
    if (health.get('ok') is not True or health.get('stage') != str(stage)
            or health.get('boot_id') != result['boot_id'] or set(health.get('checks', {})) != REQUIRED_CHECKS
            or any(health['checks'][key] is not True for key in REQUIRED_CHECKS)):
        refuse('fresh_complete_health_required')
    # Runtime/SCAP checks do not replace AIDE's complete protected filesystem
    # scan, especially when an old result survived a failed gate release.
    _fresh_check(manager)
    value = {'schema': 1, 'ok': True, 'status': 'complete', 'stage': str(stage), 'boot_id': result['boot_id'],
             'plan_sha256': result['plan_sha256'], 'result_sha256': rpm.sha(kernel.encode(result)),
             'checks': dict(health['checks'])}
    kernel.record(stage, FINAL, value)
    pointer = _reference(stage, result['plan_sha256'])
    root = stage.parent
    if os.path.lexists(root / PENDING) and manager.records.read(root / PENDING, identity) != pointer:
        refuse('pending_generation_changed')
    manager.records.write(root / CURRENT, pointer, identity)
    if os.path.lexists(root / PENDING):
        (root / PENDING).unlink()
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    if plan_hold := _load(stage)[0]['hold']:
        if os.path.lexists(root / HOLD):
            if manager.records.read(root / HOLD, identity) != plan_hold:
                refuse('observation_hold_owner_changed')
            (root / HOLD).unlink()
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    # A caller can release the owned gate only after this final re-observation.
    _result(manager, stage, runner=runner)
    return value
