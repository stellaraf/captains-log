"""Self-contained boot ancestry for metadata proofs; no acceptance or host writes.

The live caller has already bound its current plan and any pending preparation.
Capture retains only canonical referenced records through the protected reader.
Validation walks those bytes without commands, filesystem reads, or AIDE calls.
This proves boot lineage, not RPM provenance or historical AIDE acceptance.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import struct
import uuid
import zlib

from . import kernel_boot as boot, kernel_updates as kernel, os_payload as rpm
from .common import Refused
from .host_job_storage import digest, exact, strict_json

MAX_RECORDS = 1100
MAX_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024
COMPRESS_AT = 64 * 1024
MAX_RATIO = 256
GZIP_HEADER = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff'
MAX_BOOTS = 64
TOKEN = re.compile(r'[a-f0-9]{32}\Z')
KERNEL_NAME = re.compile(r'kernel-boot-([a-f0-9]{32})-plan\.json\Z')
RETENTION_NAME = re.compile(r'kernel-retention-resume-([a-f0-9]{32})-plan\.json\Z')
ROLLBACK_NAME = re.compile(r'kernel-rollback-resume-([a-f0-9]{32})-integrity\.json\Z')
MUTATIONS = {None, 'os-payload-v1', 'kernel-install-v1', 'rocky-kernel-retention-v1'}
IDENTITY = ('stage', 'operation_sha256', 'candidate_stage', 'candidate_plan_sha256',
            'installed_sha256', 'kernel', 'old_kernel', 'candidate_entry', 'old_entry')


def refuse(reason):
    raise Refused('boot_metadata_lineage_' + reason)


def _sha(value):
    if not isinstance(value, str) or not kernel.SHA.fullmatch(value):
        refuse('invalid_digest')


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        refuse('invalid_boot')


def _stage(value):
    if (not isinstance(value, str) or not value.startswith('/') or str(Path(value)) != value
            or '..' in Path(value).parts or '\\' in value or '\0' in value):
        refuse('invalid_stage')
    path = Path(value)
    boot_stage = (TOKEN.fullmatch(path.name) and path.parent.name in {'os-updates', 'boot-integrity'}
                  and path.parent.parent.name == 'manager')
    host_stage = (re.fullmatch(r'[1-9][0-9]*-[A-Za-z0-9_-]{1,100}', path.name)
                  and tuple(path.parts[-4:-1]) == ('manager', 'updates', 'releases'))
    if not (boot_stage or host_stage):
        refuse('invalid_stage')
    return value


def _record_bytes(body, checksum, filename):
    """The retained SHA selects one exact producer encoding, never a rebase."""
    raw = kernel.encode(body)
    if rpm.sha(raw) == checksum:
        return raw
    if filename in {'host-runtime-plan.json', 'os-integrity-plan.json'}:
        raw = (json.dumps(body, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        if rpm.sha(raw) == checksum:
            return raw
    refuse('record_bytes_changed')


def _pack_record(item):
    """Avoid duplicating multi-megabyte snapshot maps in indented journals."""
    raw = _record_bytes(item['body'], item['sha256'], item['filename'])
    if item['filename'] not in {'before.json', 'after.json'} or len(raw) < COMPRESS_AT:
        return item
    compressor = zlib.compressobj(level=9, wbits=-15)
    compressed = (GZIP_HEADER + compressor.compress(raw) + compressor.flush()
                  + struct.pack('<II', zlib.crc32(raw), len(raw)))
    if len(raw) > len(compressed) * MAX_RATIO:
        refuse('snapshot_compression_ratio')
    return {k: v for k, v in item.items() if k != 'body'} | {
        'gzip_base64': base64.b64encode(compressed).decode('ascii')}


def _unpack_record(item):
    fields = {'stage', 'filename', 'sha256'}
    if not isinstance(item, dict):
        refuse('invalid_record')
    exact(item, fields | ({'gzip_base64'} if 'gzip_base64' in item else {'body'}))
    _stage(item['stage']); _reference({'filename': item['filename'], 'sha256': item['sha256']})
    if 'gzip_base64' not in item:
        raw = _record_bytes(item['body'], item['sha256'], item['filename'])
        if len(raw) > MAX_RECORD_BYTES:
            refuse('record_expansion_limit')
        return item, raw
    encoded = item['gzip_base64']
    if (item['filename'] not in {'before.json', 'after.json'}
            or Path(item['stage']).parent.name != 'boot-integrity'
            or not isinstance(encoded, str) or len(encoded) > MAX_BYTES):
        refuse('compressed_record_scope')
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        refuse('compressed_record_encoding')
    if base64.b64encode(compressed).decode('ascii') != encoded or not compressed.startswith(GZIP_HEADER):
        refuse('compressed_record_encoding')
    try:
        decompressor = zlib.decompressobj(wbits=31)
        raw = decompressor.decompress(compressed, MAX_RECORD_BYTES + 1)
        if (len(raw) > MAX_RECORD_BYTES or decompressor.unconsumed_tail
                or decompressor.unused_data or not decompressor.eof):
            refuse('record_expansion_or_trailing_data')
    except zlib.error:
        refuse('compressed_record_corrupt')
    if len(raw) < COMPRESS_AT or len(raw) > len(compressed) * MAX_RATIO:
        refuse('snapshot_compression_ratio')
    body = strict_json(raw)
    if raw != kernel.encode(body) or rpm.sha(raw) != item['sha256']:
        refuse('record_bytes_changed')
    return {k: v for k, v in item.items() if k != 'gzip_base64'} | {'body': body}, raw


def _reference(value):
    exact(value, {'filename', 'sha256'})
    name = value['filename']
    if (not isinstance(name, str) or not name or Path(name).name != name
            or name in {'.', '..'} or '\\' in name or '\0' in name):
        refuse('invalid_reference')
    _sha(value['sha256'])
    return value


def _manifest(plan):
    if (type(plan.get('schema')) is not int or plan['schema'] != 1
            or plan.get('manifest_sha256') != digest({k: v for k, v in plan.items() if k != 'manifest_sha256'})):
        refuse('manifest_changed')


def _kernel_chain(stage, reference, get):
    """Validate retained phase/boot/GRUB edges, without full recipe loaders."""
    chain, seen = [], set()
    while reference is not None:
        name = _reference(reference)['filename']
        match = KERNEL_NAME.fullmatch(name)
        if match is None or name in seen or len(seen) >= MAX_BOOTS:
            refuse('kernel_ancestry_limit_or_cycle')
        seen.add(name)
        plan = get(stage, reference)
        if plan.get('phase') != 'retention_resume':
            get(stage, reference, pending=True)
        extra = ({'retention_authority', 'previous_retention_plan'} if plan.get('phase') == 'retention_resume'
                 else {'authorization', 'recovery_proof'} if plan.get('phase') == 'retry_arm' else set())
        exact(plan, boot.PLAN_FIELDS | extra)
        _manifest(plan); _uuid(plan['boot_id'])
        if (plan['kind'] != 'kernel-boot-v1' or plan['stage'] != stage or plan['id'] != match[1]
                or plan['phase'] not in boot.PHASES or type(plan['sequence']) is not int
                or plan['running_kernel'] not in {plan['kernel'], plan['old_kernel']}
                or not kernel.KERNEL.fullmatch(str(plan['kernel']))
                or not kernel.KERNEL.fullmatch(str(plan['old_kernel']))):
            refuse('kernel_identity_changed')
        _stage(plan['candidate_stage'])
        if Path(plan['candidate_stage']).parent != Path(stage).parent:
            refuse('foreign_candidate_stage')
        for key in ('operation_sha256', 'candidate_plan_sha256', 'installed_sha256'):
            _sha(plan[key])
        if chain and any(plan[key] != chain[0][key] for key in IDENTITY):
            refuse('kernel_identity_discontinuity')
        prefix = plan['old_entry'].removesuffix('-' + plan['old_kernel'])
        if (not TOKEN.fullmatch(prefix) or plan['old_entry'] != prefix + '-' + plan['old_kernel']
                or plan['candidate_entry'] != prefix + '-' + plan['kernel']):
            refuse('kernel_entry_changed')
        chain.append(plan)
        previous = plan['previous']
        if previous is not None:
            exact(previous, {'id', 'sha256'})
            if not isinstance(previous['id'], str) or not TOKEN.fullmatch(previous['id']):
                refuse('invalid_kernel_predecessor')
            reference = {'filename': 'kernel-boot-' + previous['id'] + '-plan.json', 'sha256': previous['sha256']}
        else:
            reference = None
    for index in range(len(chain) - 1, -1, -1):
        plan = chain[index]
        previous = chain[index + 1] if index + 1 < len(chain) else None
        phase = plan['phase']
        before, after = boot._raw(plan['before_raw']), boot._raw(plan['after_raw'])
        if len(plan['files']) != 1:
            refuse('kernel_scope_changed')
        item = plan['files'][0]
        exact(item, {'path', 'before', 'after'})
        if (item['path'] != boot.ENV or item['before'].get('sha256') != rpm.sha(before)
                or item['before'].get('bytes') != 1024
                or item['after'] != {**item['before'], 'sha256': rpm.sha(after), 'bytes': len(after)}):
            refuse('kernel_environment_changed')
        if phase == 'arm':
            if previous is not None or plan['sequence'] != 1 or plan['running_kernel'] != plan['old_kernel']:
                refuse('kernel_origin_changed')
        else:
            if previous is None:
                refuse('kernel_origin_missing')
            wanted = ({'postboot'} if phase == 'commit' else {'commit'} | boot.RESUMES if phase in boot.RESUMES
                      else boot.RECOVERY if phase in {'retry_arm', 'recovery_resume'} else {'arm', 'retry_arm'})
            same = plan['boot_id'] == previous['boot_id']
            if (previous['phase'] not in wanted or plan['before_raw'] != previous['after_raw']
                    or item['before'] != previous['files'][0]['after']
                    or phase != 'recovery_resume' and same != (phase in {'abort', 'commit', 'retry_arm'})
                    or phase == 'abort' and plan['running_kernel'] != plan['old_kernel']
                    or phase in {'commit'} | boot.RESUMES and (plan['running_kernel'] != plan['kernel']
                                                          or previous['running_kernel'] != plan['kernel'])
                    or phase in {'retry_arm', 'recovery_resume'} and (plan['running_kernel'] != plan['old_kernel']
                                                                  or previous['running_kernel'] != plan['old_kernel'])):
                refuse('kernel_predecessor_changed')
            if phase in {'retry_arm', 'recovery_resume'} and previous['phase'] == 'abort':
                if index + 2 >= len(chain) or chain[index + 2]['phase'] != 'retry_arm':
                    refuse('kernel_retry_abort_changed')
        sequence = previous['sequence'] + 1 if phase in boot.RESUMES | {'recovery_resume'} else boot.PHASES[phase]
        if plan['sequence'] != sequence:
            refuse('kernel_sequence_changed')
        expected = boot.transition_variables(boot.parse_environment(before), 'resume' if phase in boot.RESUMES else phase,
                    plan['old_entry'], plan['candidate_entry'],
                    observed=boot.parse_environment(after) if phase in boot.OBSERVATIONS else None,
                    restored=boot.parse_environment(boot._raw(previous['before_raw'])) if phase == 'abort' else None,
                    same_boot=previous is not None and plan['boot_id'] == previous['boot_id'])
        if boot.parse_environment(after) != expected:
            refuse('kernel_transition_changed')
        if phase == 'retry_arm':
            proof = plan['recovery_proof']
            if (proof.get('boot_ref') != {'filename': 'kernel-boot-' + previous['id'] + '-plan.json',
                                         'sha256': rpm.sha(kernel.encode(previous))}
                    or proof.get('boot_id') != plan['boot_id']):
                refuse('retry_recovery_predecessor_changed')
    return chain


def _ordinary(stage, name, plan, get):
    if name != 'ordinary-boot-plan.json' or Path(stage).parent.name != 'boot-integrity':
        refuse('ordinary_owner_changed')
    current, current_stage, seen = plan, stage, set()
    while True:
        if current_stage in seen or len(seen) >= 1000:
            refuse('ordinary_ancestry_limit_or_cycle')
        seen.add(current_stage); _manifest(current); _uuid(current['boot_id'])
        if (current.get('kind') != 'ordinary-boot-v1' or current.get('stage') != current_stage
                or type(current.get('sequence')) is not int or not 0 <= current['sequence'] < 1000
                or current.get('original_enrollment_sha256') != plan['original_enrollment_sha256']
                or current.get('initial_snapshot_sha256') != plan['initial_snapshot_sha256']):
            refuse('ordinary_ancestor_changed')
        previous = current['previous']
        if previous is None:
            if current['sequence'] != 0:
                refuse('ordinary_origin_changed')
            break
        exact(previous, {'stage', 'plan_sha256'})
        next_stage = _stage(previous['stage'])
        if Path(next_stage).parent != Path(stage).parent:
            refuse('foreign_ordinary_stage')
        prior = get(next_stage, {'filename': 'ordinary-boot-plan.json', 'sha256': previous['plan_sha256']}, pending=True)
        if prior.get('sequence') != current['sequence'] - 1:
            refuse('ordinary_sequence_changed')
        current, current_stage = prior, next_stage
    snapshots = []
    for key in ('before', 'after'):
        if _reference(plan[key])['filename'] != key + '.json':
            refuse('ordinary_snapshot_reference_changed')
        value = get(stage, plan[key])
        if type(value.get('schema')) is not int or value['schema'] not in (1, 2):
            refuse('ordinary_snapshot_schema_changed')
        _uuid(value['boot_id']); snapshots.append(value)
    if snapshots[1]['boot_id'] != plan['boot_id']:
        refuse('ordinary_target_boot_changed')
    return {snapshots[0]['boot_id']}, plan['boot_id']


def _erase_origin(stage, kind, plan, get):
    """Bind the once-only erase origin and its exact AIDE projection."""
    prefix = 'kernel-retention' if kind == 'retention' else 'kernel-rollback'
    intent = get(stage, {'filename': prefix + '-intent.json', 'sha256': plan.get('erase_intent_sha256')})
    if type(intent.get('schema')) is not int or intent['schema'] not in (1, 2):
        refuse('erase_intent_schema_changed')
    exact(intent, {'schema', 'plan_sha256', 'authorization'} | ({'generation'} if intent['schema'] == 2 else set()))
    auth = intent['authorization']
    exact(auth, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    for key in ('plan_sha256', 'backup_sha256', 'aide_preparation_sha256'):
        _sha(auth[key])
    if auth['ok'] is not True or auth['plan_sha256'] != intent['plan_sha256']:
        refuse('erase_authorization_changed')
    recipe_name = prefix + '-plan.json'
    if intent['schema'] == 2:
        ref = _reference(intent['generation'])
        pattern = prefix + r'-execution-([a-f0-9]{32})-' + ('binding' if kind == 'retention' else 'plan') + r'\.json'
        match = re.fullmatch(pattern, ref['filename'])
        if match is None:
            refuse('erase_generation_reference_changed')
        if kind == 'retention':
            binding = get(stage, ref)
            if (binding.get('id') != match[1] or binding.get('plan_sha256') != intent['plan_sha256']
                    or binding.get('kind') != 'kernel-retention-execution-v1'):
                refuse('erase_generation_binding_changed')
        elif ref['sha256'] != intent['plan_sha256']:
            refuse('erase_generation_binding_changed')
        recipe_name = prefix + '-execution-' + match[1] + '-plan.json'
    recipe = get(stage, {'filename': recipe_name, 'sha256': intent['plan_sha256']})
    if (recipe.get('boot_id') != auth['boot_id'] or recipe.get('kind') != 'rocky-' + prefix + '-v1'):
        refuse('erase_recipe_changed')
    _uuid(recipe['boot_id'])
    integrity_name = (prefix + '-integrity-plan.json' if recipe_name == prefix + '-plan.json'
                      else recipe_name.replace('-plan.json', '-integrity.json'))
    integrity = get(stage, {'filename': integrity_name, 'sha256': plan.get('original_integrity_sha256')}, pending=True,
                    preparation=auth['aide_preparation_sha256'])
    expected = {'schema': 1, 'kind': recipe['kind'], 'sequence': 0, 'manifest_sha256': intent['plan_sha256'],
                'removed': recipe['removed'], 'preserved': recipe['preserved'], 'mutable_directories': recipe['mutable_directories']}
    if integrity != expected:
        refuse('erase_projection_changed')
    wanted = plan.get('retention_plan_sha256' if kind == 'retention' else 'rollback_plan_sha256', plan.get('manifest_sha256'))
    if (wanted != intent['plan_sha256'] or plan.get('original_preparation_sha256', auth['aide_preparation_sha256']) != auth['aide_preparation_sha256']):
        refuse('erase_origin_changed')
    return recipe, intent


def _compound(stage, name, plan, get, kind):
    pattern = RETENTION_NAME if kind == 'retention' else ROLLBACK_NAME
    original, intent = _erase_origin(stage, kind, plan, get)
    current, current_name, seen, boot_ids = plan, name, set(), set()
    first_boot = None
    while True:
        match = pattern.fullmatch(current_name)
        if match is None or current_name in seen or len(seen) >= MAX_BOOTS:
            refuse('compound_ancestry_limit_or_cycle')
        seen.add(current_name); _manifest(current); _uuid(current['boot_id'])
        key = 'retention_plan_sha256' if kind == 'retention' else 'rollback_plan_sha256'
        if (current.get('id') != match[1] or current.get('stage') != stage
                or current.get('kind') != ('rocky-kernel-retention-resume-v1' if kind == 'retention' else 'rocky-kernel-rollback-v1')
                or current.get('sequence') != 0 or type(current.get('sequence')) is not int
                or any(current.get(k) != plan.get(k) for k in (key, 'operation_sha256', 'original_integrity_sha256',
                                                              'original_preparation_sha256', 'erase_intent_sha256'))
                or current['operation_sha256'] != original['operation_sha256']
                or current['removed'] != original['removed'] or current['mutable_directories'] != original['mutable_directories']
                or current['preserved'] != {p: v for p, v in original['preserved'].items() if p != kernel.GRUBENV}
                or len(current['files']) != 1 or current['files'][0]['path'] != kernel.GRUBENV
                or current['files'][0]['before'] != original['preserved'][kernel.GRUBENV]):
            refuse('compound_scope_changed')
        if kind == 'retention':
            chain = _kernel_chain(stage, current['boot_ref'], get)
            head = chain[0]
            if (head['phase'] != 'retention_resume' or head['boot_id'] != current['boot_id']
                    or head['operation_sha256'] != current['operation_sha256']
                    or head['retention_authority'] != current['authority_ref']
                    or head['previous_retention_plan'] != current['previous_retention_plan']
                    or head['files'][0]['after'] != current['files'][0]['after']):
                refuse('retention_boot_reference_changed')
            boot_ids.update(item['boot_id'] for item in chain[1:])
            previous = current['previous_retention_plan']
        else:
            if current['kernel'] != original['kernel'] or current['recovery_kernel'] != original['recovery_kernel']:
                refuse('rollback_kernel_changed')
            previous = current['previous']
        if first_boot is None:
            first_boot = current['boot_id']
        else:
            boot_ids.add(current['boot_id'])
        if previous is None:
            break
        prior = get(stage, _reference(previous), pending=True)
        if kind == 'retention' and prior['boot_id'] == current['boot_id']:
            refuse('retention_predecessor_boot_changed')
        if kind == 'rollback':
            _rollback_edge(current, prior['after_raw'], prior['boot_id'], prior['files'][0]['after'], original)
        current, current_name = prior, previous['filename']
    if kind == 'rollback':
        recovery = original['recovery']
        chain = _kernel_chain(stage, recovery['boot_ref'], get)
        head = chain[0]
        if (head['phase'] not in boot.RECOVERY or head['running_kernel'] != head['old_kernel']
                or recovery.get('ok') is not True or head['boot_id'] != original['boot_id']
                or any(recovery.get(k) != original.get(k) for k in ('boot_id', 'kernel', 'recovery_kernel',
                        'operation_sha256', 'candidate_plan_sha256', 'installed_sha256'))
                or head['operation_sha256'] != original['operation_sha256']
                or head['candidate_plan_sha256'] != original['candidate_plan_sha256']
                or head['installed_sha256'] != original['installed_sha256']
                or head['kernel'] != original['kernel'] or head['old_kernel'] != original['recovery_kernel']
                or head['files'][0]['after'] != original['preserved'][kernel.GRUBENV]):
            refuse('rollback_recovery_origin_changed')
        boot_ids.update(item['boot_id'] for item in chain)
        _rollback_edge(current, head['after_raw'], head['boot_id'], head['files'][0]['after'], original)
    return boot_ids, first_boot


def _rollback_edge(current, before_raw, before_boot, before, original):
    after = boot._raw(current['after_raw'])
    variables = boot.parse_environment(boot._raw(before_raw))
    old_entry = variables.get('saved_entry', '')
    suffix = '-' + original['recovery_kernel']
    if not old_entry.endswith(suffix) or not TOKEN.fullmatch(old_entry[:-len(suffix)]):
        refuse('rollback_recovery_entry_changed')
    candidate = old_entry[:-len(suffix)] + '-' + original['kernel']
    boot.transition_variables(variables, 'recovery_resume', old_entry, candidate,
                              observed=boot.parse_environment(after), same_boot=current['boot_id'] == before_boot)
    if current['files'][0]['after'] != {**before, 'bytes': len(after), 'sha256': rpm.sha(after)}:
        refuse('rollback_environment_edge_changed')


def _walk(stage, reference, plan, get, *, pending_origin=False):
    kind, name = plan.get('kind'), reference['filename']
    if type(plan.get('schema')) is not int or plan['schema'] != 1:
        refuse('invalid_plan_schema')
    if kind == 'ordinary-boot-v1':
        return 'observation', *_ordinary(stage, name, plan, get)
    if kind is None:
        if name != 'host-runtime-plan.json' or Path(stage).parent.name != 'releases':
            refuse('host_owner_changed')
        return 'mutation', set(), None
    if Path(stage).parent.name != 'os-updates':
        # Host plans use their separate enrolled update stage family. The
        # caller supplies that exact private stage; it cannot observe a boot.
        refuse('wrong_stage_family')
    if kind == 'kernel-boot-v1':
        if plan.get('phase') not in boot.PHASES or plan['phase'] == 'retention_resume':
            refuse('unsupported_boot_phase')
        if plan['phase'] in {'postboot', 'resume', 'recovery_resume'}:
            chain = _kernel_chain(stage, reference, get)
            return 'observation', {p['boot_id'] for p in chain[1:]}, plan['boot_id']
        _uuid(plan['boot_id'])
        return 'mutation', set(), plan['boot_id']
    if kind == 'rocky-kernel-retention-resume-v1':
        return 'observation', *_compound(stage, name, plan, get, 'retention')
    if kind == 'rocky-kernel-rollback-v1' and 'rollback_plan_sha256' in plan:
        return 'observation', *_compound(stage, name, plan, get, 'rollback')
    if kind in MUTATIONS | {'rocky-kernel-rollback-v1'}:
        if pending_origin and kind in {'rocky-kernel-retention-v1', 'rocky-kernel-rollback-v1'}:
            _erase_origin(stage, 'retention' if kind == 'rocky-kernel-retention-v1' else 'rollback', plan, get)
        return 'mutation', set(), None
    refuse('unsupported_plan_kind')


def capture(manager, stage, plan_path, plan, plan_sha, *, pending_prepared=None):
    """Read canonical typed references only, under the caller's existing locks."""
    stage, path = Path(stage), Path(plan_path)
    identity = manager.guard()
    _stage(str(stage)); _sha(plan_sha)
    manager_root = stage.parent.parent if stage.parent.name != 'releases' else stage.parent.parent.parent
    if (manager_root != identity.root / 'manager' or stage.resolve() != stage
            or path.parent != stage or path.is_symlink()):
        refuse('unenrolled_stage')
    records, total = {}, 0
    def get(owner, reference, *, pending=False, preparation=None):
        nonlocal total
        _stage(owner)
        if Path(owner).parent != stage.parent:
            refuse('foreign_record_stage')
        name = reference['filename']
        if reference['sha256'] is not None:
            _reference(reference)
        elif name not in {'kernel-retention-intent.json', 'kernel-rollback-intent.json',
                          'kernel-retention-integrity-plan.json', 'kernel-rollback-integrity-plan.json'} and not re.fullmatch(r'kernel-(retention|rollback)-execution-[a-f0-9]{32}-integrity\.json', name):
            refuse('unbound_record_reference')
        key = owner, name
        if key not in records:
            manager.records.directory(Path(owner), identity)
            raw = manager._bytes(Path(owner) / name, identity)
            body = strict_json(raw)
            if raw != _record_bytes(body, rpm.sha(raw), name):
                refuse('noncanonical_record')
            total += len(raw)
            if total > MAX_BYTES or len(records) >= MAX_RECORDS:
                refuse('evidence_limit')
            records[key] = {'stage': owner, 'filename': name, 'sha256': rpm.sha(raw), 'body': body}
        value = records[key]
        if reference['sha256'] is not None and value['sha256'] != reference['sha256']:
            refuse('record_reference_changed')
        return value['body']
    reference = {'filename': path.name, 'sha256': plan_sha}
    if get(str(stage), reference) != plan:
        refuse('current_plan_changed')
    _walk(str(stage), reference, plan, get, pending_origin=pending_prepared is not None)
    result = {'schema': 1, 'stage': str(stage), 'plan': reference,
              'records': [_pack_record(item) for item in records.values()]}
    if pending_prepared is not None:
        validate_pending(result, pending_prepared)
    return result


def _evidence(evidence, plan=None, plan_sha=None):
    exact(evidence, {'schema', 'stage', 'plan', 'records'})
    if type(evidence['schema']) is not int or evidence['schema'] != 1:
        refuse('invalid_evidence_schema')
    stage = _stage(evidence['stage']); reference = _reference(evidence['plan'])
    if not isinstance(evidence['records'], list) or not 0 < len(evidence['records']) <= MAX_RECORDS:
        refuse('evidence_limit')
    records, used, eligible, total = {}, set(), {}, 0
    for item in evidence['records']:
        item, raw = _unpack_record(item)
        _stage(item['stage']); _reference({'filename': item['filename'], 'sha256': item['sha256']})
        key = item['stage'], item['filename']
        if Path(item['stage']).parent != Path(stage).parent or key in records:
            refuse('foreign_or_duplicate_record')
        total += len(raw)
        if total > MAX_BYTES or rpm.sha(raw) != item['sha256']:
            refuse('record_bytes_changed')
        records[key] = item
    def get(owner, ref, *, pending=False, preparation=None):
        if ref['sha256'] is not None:
            _reference(ref)
        key = owner, ref['filename']
        if key not in records or ref['sha256'] is not None and records[key]['sha256'] != ref['sha256']:
            refuse('missing_or_changed_reference')
        used.add(key)
        if pending:
            eligible[key] = preparation
        return records[key]['body']
    current = get(stage, reference, pending=True)
    if (plan is not None and current != plan or plan_sha is not None and reference['sha256'] != plan_sha):
        refuse('current_plan_changed')
    origin = any(item['filename'] in {'kernel-retention-intent.json', 'kernel-rollback-intent.json'} for item in records.values())
    result = _walk(stage, reference, current, get, pending_origin=origin)
    if used != set(records):
        refuse('unreferenced_record')
    return result, records, eligible


def validate(evidence, plan, plan_sha, source_boot_id, observed_boot_id):
    """Pure boot ancestry check; current plan provenance belongs to its owner."""
    _uuid(source_boot_id); _uuid(observed_boot_id); _sha(plan_sha)
    (mode, ancestors, observed), _, _ = _evidence(evidence, plan, plan_sha)
    if mode == 'mutation':
        if source_boot_id != observed_boot_id or observed is not None and observed != observed_boot_id:
            refuse('mutation_cannot_advance_boot')
    elif observed != observed_boot_id or source_boot_id not in ancestors:
        refuse('source_boot_not_in_typed_ancestry')
    return evidence


def validate_pending(evidence, pending_prepared):
    """The caller independently authenticates this retained prepared record."""
    _, records, eligible = _evidence(evidence)
    for key, preparation in eligible.items():
        item = records[key]
        if (pending_prepared.get('release') == item['stage']
                and pending_prepared.get('plan_sha256') == item['sha256']
                and pending_prepared.get('plan') == item['body']):
            if preparation is not None and digest(pending_prepared) != preparation:
                refuse('pending_preparation_changed')
            return pending_prepared
    refuse('pending_plan_not_in_typed_ancestry')
