"""Immutable boot metadata evidence over the actual accepted AIDE lineage.

Native observations alone are not authority. The live constructor requires a
verified source prefix and database. Historical verification accepts retained
database bytes and walks existing chain entries in chronological order; it
never calls a live capture or any plan loader that could re-enter AIDE.

Observation proofs may account for the two qualified native reboot effects.
Mutation anchors grant no exceptions and describe the preparation, not the
post-update host. The only different-prefix reuse is the existing exact
same-preparation forward-to-rollback progression.
"""
from __future__ import annotations

import copy
import uuid

from . import boot_metadata_native as native, ordinary_boot_metadata as database
from .common import Refused
from .host_job_storage import digest, exact

KEY = '@boot-metadata-v1'
FIELDS = {'schema', 'mode', 'plan_sha256', 'original_enrollment_sha256', 'lineage', 'pending',
          'initial_snapshot_sha256', 'source_boot_id', 'source_head',
          'source_database_sha256', 'database_source', 'after', 'transition'}
SOURCE_FIELDS = {'basis', 'head', 'observed_head', 'original_enrollment_sha256', 'pending_sha256'}
BOOT_PHASES = {'arm', 'abort', 'postboot', 'commit', 'resume', 'retry_arm', 'recovery_resume', 'rearm'}
OBSERVATIONS = {'postboot', 'resume', 'recovery_resume'}


def refuse(reason):
    raise Refused('boot_metadata_proof_' + reason)


def _sha(value):
    if not isinstance(value, str) or not database.SHA.fullmatch(value):
        refuse('invalid_digest')


def _boot(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        refuse('invalid_boot_identity')


def _head(value):
    if value is not None:
        exact(value, {'id', 'sha256'})
        _boot(value['id']); _sha(value['sha256'])


def mode(plan):
    """Only these already-bound plan kinds can observe a different boot."""
    if not isinstance(plan, dict) or type(plan.get('schema')) is not int:
        refuse('invalid_plan')
    kind = plan.get('kind')
    if kind is None:
        from .boot_metadata_lineage import validate_host_schema
        validate_host_schema(plan)
        return 'mutation'
    if plan['schema'] != 1:
        refuse('invalid_plan')
    if kind == 'ordinary-boot-v1':
        result = 'observation'
    elif kind == 'kernel-boot-v1':
        if plan.get('phase') not in BOOT_PHASES:
            refuse('unsupported_boot_phase')
        result = 'observation' if plan['phase'] in OBSERVATIONS else 'mutation'
    elif kind == 'rocky-kernel-retention-resume-v1':
        result = 'observation'
    elif kind == 'rocky-kernel-rollback-v1':
        result = 'observation' if 'rollback_plan_sha256' in plan else 'mutation'
    elif kind in {'os-payload-v1', 'kernel-install-v1', 'rocky-kernel-retention-v1'}:
        result = 'mutation'
    else:
        refuse('unsupported_plan_kind')
    if result == 'observation' or kind == 'kernel-boot-v1':
        _boot(plan.get('boot_id'))
    return result


def root_anchor(initial, base):
    """The caller supplies the independently verified original snapshot."""
    if type(initial.get('schema')) is int and initial['schema'] == 1:
        return None
    if type(initial.get('schema')) is not int or initial['schema'] != 2:
        refuse('explicit_snapshot_migration_required')
    native.validate_authority(initial['boot_metadata_authority'])
    _boot(initial['boot_id'])
    checksum = base['facts']['ordinary_boot_snapshot_sha256']
    _sha(checksum); _sha(base['database_sha256'])
    return {'head': None, 'database_sha256': base['database_sha256'],
            'boot_id': initial['boot_id'], 'authority': copy.deepcopy(initial['boot_metadata_authority']),
            'initial_snapshot_sha256': checksum, 'original_enrollment_sha256': digest(base)}


def _source(value, anchor, pending):
    exact(value, SOURCE_FIELDS)
    _head(value['head']); _head(value['observed_head'])
    if (value['head'] != anchor['head'] or value['original_enrollment_sha256'] != anchor['original_enrollment_sha256']
            or value['basis'] not in {'published', 'owned-ready-output'}):
        refuse('database_source_changed')
    if value['pending_sha256'] is not None:
        _sha(value['pending_sha256'])
    if value['basis'] == 'published':
        if value['observed_head'] != value['head']:
            refuse('published_source_head_changed')
    elif value['pending_sha256'] is None or value['head'] is None or value['observed_head'] == value['head']:
        refuse('unpublished_source_provenance_missing')
    if pending is None:
        if value['pending_sha256'] is not None or value['basis'] != 'published':
            refuse('pending_provenance_missing')
        return
    if not isinstance(pending, dict) or digest(pending) != value['pending_sha256']:
        refuse('pending_provenance_changed')
    basic = {'schema', 'state', 'id', 'prepared', 'direction', 'previous', 'previous_database_sha256'}
    ready = pending.get('state') == 'ready'
    exact(pending, basic | ({'entry', 'proposed_entry', 'database_sha256'} if ready else set()))
    _boot(pending['id']); _head(pending['prepared']); _head(pending['previous'])
    _sha(pending['previous_database_sha256'])
    if (type(pending['schema']) is not int or pending['schema'] != 1 or pending['direction'] != 'forward'
            or pending['prepared'] is None or pending['state'] not in {'scanning', 'ready'}):
        refuse('pending_provenance_changed')
    if ready:
        _head(pending['entry']); _sha(pending['database_sha256'])
        proposed = pending['proposed_entry']
        if (not isinstance(proposed, dict) or pending['entry'] != {'id': pending['id'], 'sha256': digest(proposed)}
                or proposed.get('id') != pending['id'] or proposed.get('prepared') != pending['prepared']
                or proposed.get('direction') != 'forward' or proposed.get('previous') != pending['previous']
                or proposed.get('previous_database_sha256') != pending['previous_database_sha256']
                or proposed.get('database_sha256') != pending['database_sha256']):
            refuse('pending_proposal_changed')
    uses_output = ready and value['head'] == pending['entry']
    if uses_output:
        if anchor['database_sha256'] != pending['database_sha256']:
            refuse('pending_output_source_changed')
        observed = pending['previous'] if value['basis'] == 'owned-ready-output' else pending['entry']
        if value['observed_head'] != observed:
            refuse('pending_observed_head_changed')
        if 'entry' in anchor and anchor['entry'] != pending['proposed_entry']:
            refuse('pending_output_not_authenticated_prefix')
    elif (value['basis'] != 'published' or value['head'] != pending['previous']
          or anchor['database_sha256'] != pending['previous_database_sha256']
          or ready and pending['database_sha256'] == pending['previous_database_sha256']):
        # Identical bytes follow the verified proposed-output branch. A byte
        # match does not prove a physical copy, and must not choose arbitrarily.
        refuse('pending_input_source_changed')


def _bind_plan(plan, value, anchor):
    expected_mode = mode(plan)
    if value['mode'] != expected_mode:
        refuse('plan_mode_changed')
    boot = value['after']['boot_id']
    if expected_mode == 'mutation':
        if boot != anchor['boot_id'] or value['transition']['changes']:
            refuse('mutation_cannot_accept_boot_drift')
    if (expected_mode == 'observation' or plan.get('kind') == 'kernel-boot-v1') and plan['boot_id'] != boot:
        refuse('plan_boot_changed')
    if plan.get('kind') == 'ordinary-boot-v1':
        if (plan['source_head'] != value['source_head']
                or plan['source_database_sha256'] != value['source_database_sha256']
                or plan['original_enrollment_sha256'] != value['original_enrollment_sha256']
                or plan['initial_snapshot_sha256'] != value['initial_snapshot_sha256']):
            refuse('ordinary_source_changed')
    if expected_mode == 'observation' and mutable_targets(plan):
        refuse('observation_overlaps_mutation_targets')


def mutable_targets(plan):
    """Only direction-specific payload validation can authorize these writes.

    This list never grants a report exception. It prevents the independent
    same-boot capture recheck from mislabeling an authorized payload update as
    unexplained metadata drift. Existing payload validators still run first.
    """
    paths = set()
    for key in ('files', 'generation_additions'):
        values = plan.get(key, [])
        if not isinstance(values, list):
            refuse('invalid_mutation_scope')
        for item in values:
            if not isinstance(item, dict) or not isinstance(item.get('path'), str):
                refuse('invalid_mutation_scope')
            paths.add(item['path'])
    selection = plan.get('selection')
    if selection is not None:
        paths.add(selection.get('path'))
    for key in ('removed', 'mutable_directories'):
        values = plan.get(key, {}) if key == 'removed' else plan.get(key, [])
        if not isinstance(values, dict if key == 'removed' else list):
            refuse('invalid_mutation_scope')
        paths.update(values)
    return paths & database.TARGETS


def _pending_preparation(pending, prepared, lineage, anchor):
    if pending is None:
        if prepared is not None:
            refuse('unexpected_pending_preparation')
        return
    if not isinstance(prepared, dict):
        refuse('pending_preparation_missing')
    exact(prepared, {'schema', 'id', 'release', 'plan', 'plan_sha256', 'metadata',
                     'original_enrollment_sha256', 'database_sha256', 'report', 'prepared_at'})
    if (type(prepared['schema']) is not int or prepared['schema'] != 1
            or {'id': prepared['id'], 'sha256': digest(prepared)} != pending['prepared']
            or prepared['original_enrollment_sha256'] != anchor['original_enrollment_sha256']
            or prepared['database_sha256'] != pending['previous_database_sha256']):
        refuse('pending_preparation_changed')
    from . import boot_metadata_lineage
    boot_metadata_lineage.validate_pending(lineage, prepared)


def make(plan, plan_sha, *, anchor, authenticated_database, after, lineage, pending=None, pending_prepared=None):
    """Build evidence only after a live caller has authenticated the prefix."""
    _sha(plan_sha)
    if authenticated_database['database_sha256'] != anchor['database_sha256']:
        refuse('preparation_database_changed')
    from . import boot_metadata_lineage
    _source(authenticated_database['source'], anchor, pending)
    _pending_preparation(pending, pending_prepared, lineage, anchor)
    boot_metadata_lineage.validate(lineage, plan, plan_sha, anchor['boot_id'], after['boot_id'])
    transition = native.transition(anchor['authority'], after, database=authenticated_database,
                                   source_boot_id=anchor['boot_id'])
    value = {'schema': 1, 'mode': mode(plan), 'plan_sha256': plan_sha,
             'original_enrollment_sha256': anchor['original_enrollment_sha256'],
             'initial_snapshot_sha256': anchor['initial_snapshot_sha256'],
             'source_boot_id': anchor['boot_id'], 'source_head': copy.deepcopy(anchor['head']),
             'source_database_sha256': anchor['database_sha256'],
             'lineage': copy.deepcopy(lineage), 'pending': copy.deepcopy(pending),
             'database_source': copy.deepcopy(authenticated_database['source']),
             'after': copy.deepcopy(after), 'transition': transition}
    _bind_plan(plan, value, anchor)
    return value


def validate(value, *, plan, plan_sha, anchor, input_database, pending_prepared=None):
    """Pure revalidation against bytes of the authenticated preparation input."""
    exact(value, FIELDS)
    if (type(value['schema']) is not int or value['schema'] != 1 or value['plan_sha256'] != plan_sha
            or value['original_enrollment_sha256'] != anchor['original_enrollment_sha256']
            or value['initial_snapshot_sha256'] != anchor['initial_snapshot_sha256']
            or value['source_head'] != anchor['head'] or value['source_database_sha256'] != anchor['database_sha256']
            or value['source_boot_id'] != anchor['boot_id']):
        refuse('preparation_binding_changed')
    parsed = database.parse_database(input_database, expected_sha256=anchor['database_sha256'])
    parsed['source'] = copy.deepcopy(value['database_source'])
    _source(parsed['source'], anchor, value['pending'])
    expected = make(plan, plan_sha, anchor=anchor, authenticated_database=parsed, after=value['after'],
                    lineage=value['lineage'], pending=value['pending'], pending_prepared=pending_prepared)
    if expected != value:
        refuse('retained_transition_changed')
    return value


def recheck(value, plan, phase, current):
    """Verify the current boot, never turn a later capture into old authority."""
    if phase not in {'prepare', 'forward', 'rollback'}:
        refuse('invalid_phase')
    first, fresh = native.stable_snapshot(value['after']), native.stable_snapshot(current)
    if value['mode'] != mode(plan):
        refuse('plan_mode_changed')
    allowed = mutable_targets(plan) if value['mode'] == 'mutation' and phase != 'prepare' else set()
    # A payload may change rows on its exact paths. Every other field, including
    # the service invocation, mount, writer and effective config, stays equal.
    for snapshot in (first, fresh):
        snapshot['rows'] = {path: row for path, row in snapshot['rows'].items() if path not in allowed}
    if first != fresh:
        refuse('live_observation_changed')
    return value


def filter_report(report, metadata):
    """Remove only exactly proven metadata summaries before payload checking.

    A caller must independently validate the proof before accepting a chain or
    changing a database. Counts and the unmodified full report remain retained
    and are checked by the normal pinned AIDE parser.
    """
    value = metadata.get(KEY) if isinstance(metadata, dict) else None
    if value is None:
        return report
    exact(value, FIELDS)
    result = copy.deepcopy(report)
    changes = value['transition']['changes']
    if value['mode'] == 'mutation' and changes:
        refuse('mutation_cannot_filter_report')
    seen = set()
    for item in changes:
        exact(item, {'path', 'attribute', 'before', 'after', 'summary'})
        path = item['path']
        if path not in database.TARGETS or path in seen or path in report.get('added', {}) or path in report.get('removed', {}):
            refuse('invalid_report_exception')
        seen.add(path)
        if path not in report.get('changed', {}):
            refuse('expected_metadata_change_missing')
        row = value['after']['rows'][path]
        database.validate_change_summary(path, report['changed'][path], row=row, attribute=item['attribute'])
        if report['changed'][path] != item['summary']:
            refuse('report_exception_changed')
        del result['changed'][path]
    return result


def validate_chain(initial, base, rows):
    """Fold already hash-checked entries, supplied with actual retained DB bytes.

    Each row supplies entry_ref, entry, prepared and input/output database bytes.
    No live reads or
    callbacks occur here. This is deliberately independent of _chain and the
    typed live pending-owner readers, so it cannot recurse into acceptance.
    """
    anchor = root_anchor(initial, base)
    if anchor is None:
        if any(KEY in row['prepared']['metadata'] for row in rows):
            refuse('legacy_enrollment_cannot_gain_authority')
        return None
    previous = None
    for row in rows:
        entry, prepared = row['entry'], row['prepared']
        value = prepared['metadata'].get(KEY)
        if value is None:
            refuse('missing_preparation_anchor')
        if entry['previous'] != anchor['head'] or entry['previous_database_sha256'] != anchor['database_sha256']:
            refuse('entry_prefix_changed')
        # Actual input is checked even for rollback, where the preparation
        # itself intentionally refers to the pre-forward database.
        parsed = database.parse_database(row['input_database'], expected_sha256=anchor['database_sha256'])
        output = database.parse_database(row['output_database'], expected_sha256=entry['database_sha256'])
        source, source_bytes = anchor, row['input_database']
        if value['source_head'] != anchor['head'] or value['source_database_sha256'] != anchor['database_sha256']:
            if (value['mode'] != 'mutation' or entry['direction'] != 'rollback' or previous is None
                    or previous['entry']['direction'] != 'forward'
                    or entry['prepared'] != previous['entry']['prepared']
                    or prepared != previous['prepared']):
                refuse('preparation_reuse_not_exact_rollback')
            source, source_bytes = previous['source_anchor'], previous['source_bytes']
            if anchor['boot_id'] != source['boot_id']:
                refuse('rollback_crossed_boot')
        validate(value, plan=prepared['plan'], plan_sha=entry['plan_sha256'],
                 anchor=source, input_database=source_bytes, pending_prepared=row.get('pending_prepared'))
        if prepared['database_sha256'] != source['database_sha256']:
            refuse('preparation_database_changed')
        if value['mode'] == 'observation' and entry['direction'] != 'forward':
            refuse('observation_direction_changed')
        if value['mode'] == 'observation':
            expected_rows = {path: {key: measured[key] for key in native.ROW_FIELDS}
                             for path, measured in value['after']['rows'].items()}
        else:
            expected_rows = {path: measured for path, measured in parsed['rows'].items()
                             if path not in mutable_targets(prepared['plan'])}
        if any(output['rows'].get(path) != measured for path, measured in expected_rows.items()):
            refuse('output_rows_not_authorized')
        # A mutation anchor never adopts its current targets as post-state.
        # The next proof will read these values from the actual output DB.
        anchor = {**anchor, 'head': copy.deepcopy(row['entry_ref']), 'entry': copy.deepcopy(entry),
                  'database_sha256': entry['database_sha256'],
                  'boot_id': value['after']['boot_id']}
        previous = {**row, 'source_anchor': source, 'source_bytes': source_bytes}
    return anchor


def capture_context(manager, state, identity, base, stage, plan_path, plan, plan_sha):
    """Authenticate the live input before any pending-journal normalization.

    The retained source description deliberately survives normalization. An
    owned, already-current proposed output is not mislabeled as previously
    published history, including when input and output bytes are identical.
    """
    from . import aide_updates
    initial = manager.boot_snapshot(identity, base['facts']['ordinary_boot_snapshot_sha256'])
    anchor = root_anchor(initial, base)
    if anchor is None:
        return None
    from . import boot_metadata_lineage
    journal = aide_updates._pending(manager, state, identity)
    authority = (aide_updates.pending_plan_authority(stage, plan_path)
                 if journal is not None and journal['state'] != 'complete' else None)
    history = aide_updates.accepted_plan_history(manager=manager, pending_authority=authority)
    if history['original_enrollment'] != base:
        refuse('enrollment_changed_during_capture')
    rows = list(history['history'])
    head, checksum = history['head'], history['database_sha256']
    pending = history['pending']
    if (pending is not None and pending['state'] == 'ready'
            and history['current_database_sha256'] == pending['database_sha256'] and head != pending['entry']):
        entry = pending['proposed_entry']
        if entry['previous'] != head or entry['previous_database_sha256'] != checksum:
            refuse('pending_prefix_changed')
        rows.append({'entry_ref': pending['entry'], 'entry': entry, 'prepared': history['pending_prepared']})
        head, checksum = pending['entry'], pending['database_sha256']
    if rows:
        # Both published rows and a proposed ready entry were fully verified by
        # accepted_plan_history/_chain, including the pure boot anchor fold.
        last = rows[-1]['prepared']['metadata'].get(KEY)
        if last is None:
            refuse('missing_preparation_anchor')
        anchor['boot_id'] = last['after']['boot_id']
        anchor['entry'] = copy.deepcopy(rows[-1]['entry'])
    anchor.update(head=copy.deepcopy(head), database_sha256=checksum)
    parsed = database.read_accepted_database(manager, source_head=head, source_database_sha256=checksum,
                                            pending_authority=authority)
    observed = native.capture()
    if aide_updates.accepted_plan_history(manager=manager, pending_authority=authority) != history:
        refuse('history_changed_during_capture')
    pending_prepared = history['pending_prepared'] if pending is not None and pending['state'] != 'complete' else None
    lineage = boot_metadata_lineage.capture(manager, stage, plan_path, plan, plan_sha, pending_prepared=pending_prepared)
    return make(plan, plan_sha, anchor=anchor, authenticated_database=parsed, after=observed, lineage=lineage,
                pending=pending if pending is not None and pending['state'] != 'complete' else None,
                pending_prepared=pending_prepared)


def validate_current_preparation(manager, state, identity, base, plan, plan_sha, value):
    """Live preparation gate; historical chain validators never call this."""
    from . import aide_updates
    initial = manager.boot_snapshot(identity, base['facts']['ordinary_boot_snapshot_sha256'])
    anchor = root_anchor(initial, base)
    if anchor is None:
        if value is not None:
            refuse('legacy_enrollment_cannot_gain_authority')
        return
    if value is None:
        refuse('missing_preparation_anchor')
    head, checksum, latest = aide_updates._chain(manager, state, identity, base)
    anchor.update(head=copy.deepcopy(head), database_sha256=checksum)
    if latest is not None:
        prepared = aide_updates._read_bound(manager, state / 'authorized/prepared', latest['prepared'], identity)
        anchor.update(boot_id=prepared['metadata'][KEY]['after']['boot_id'], entry=latest)
        if (latest['direction'] == 'forward' and latest['plan_sha256'] == plan_sha
                and prepared['plan'] == plan and prepared['metadata'].get(KEY) == value):
            # The verified chain has already authenticated the immutable old
            # preparation against its original input. A fresh check below
            # must use the current output and must be wholly clean; it cannot
            # apply the old preparation's metadata exceptions a second time.
            return True
    pending_prepared = None
    if value['pending'] is not None:
        pending_prepared = aide_updates._read_bound(manager, state / 'authorized/prepared', value['pending']['prepared'], identity)
    raw, current_sha = manager._database(state / 'aide.db.gz', identity)
    if current_sha != checksum:
        refuse('current_database_changed')
    validate(value, plan=plan, plan_sha=plan_sha, anchor=anchor, input_database=raw, pending_prepared=pending_prepared)
    return False
