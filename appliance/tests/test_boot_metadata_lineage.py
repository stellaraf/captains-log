"""Pure frozen ancestry plus protected capture against real generated plans.

The kernel and rollback cases use the actual plan generators and AIDE fixture
chain. Native signatures/scanning remain fixture boundaries; no host boot or
package operation runs. Pure validators must continue working without files.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
import struct
import zlib

from nebulalog_manager import boot_metadata_lineage as lineage, kernel_boot as boot
from nebulalog_manager import boot_metadata_proof as metadata_proof
from nebulalog_manager import kernel_rollback as rollback, aide_updates as updates
from nebulalog_manager.common import Refused
from nebulalog_manager.host_job_storage import digest
import test_ordinary_boot_aide as ordinary_fixture
import test_kernel_boot_aide as kernel_fixture
import test_kernel_boot as native
import test_kernel_rollback as rollback_fixture
import test_retention_generation_review as retention_fixture
from nebulalog_manager import kernel_retention as retention

OLD, NEXT, LATER = native.ORIGINAL_BOOT, native.NEW_BOOT, 'cccccccc-cccc-cccc-cccc-cccccccccccc'


def checksum(body): return boot.rpm.sha(boot.kernel.encode(body))


def record(stage, name, body):
    return {'stage': str(stage), 'filename': name, 'sha256': checksum(body), 'body': copy.deepcopy(body)}


def evidence(stage, name, body, *others):
    return {'schema': 1, 'stage': str(stage), 'plan': {'filename': name, 'sha256': checksum(body)},
            'records': [record(stage, name, body), *others]}


def validate(value, source=OLD, observed=NEXT):
    current = next(item for item in value['records'] if item['stage'] == value['stage']
                   and item['filename'] == value['plan']['filename'])
    return lineage.validate(value, current['body'], value['plan']['sha256'], source, observed)


def rehash_current(value):
    current = next(item for item in value['records'] if item['stage'] == value['stage']
                   and item['filename'] == value['plan']['filename'])
    body = current['body']
    body['manifest_sha256'] = digest({k: v for k, v in body.items() if k != 'manifest_sha256'})
    current['sha256'] = value['plan']['sha256'] = checksum(body)


class PureLineageTests(TestCase):
    def ordinary(self, *, stage='/fixture/manager/boot-integrity/' + '1' * 32,
                 before=OLD, after=NEXT, previous=None, sequence=0):
        first, last = {'schema': 2, 'boot_id': before}, {'schema': 2, 'boot_id': after}
        plan = {'schema': 1, 'kind': 'ordinary-boot-v1', 'stage': stage, 'boot_id': after,
                'sequence': sequence, 'original_enrollment_sha256': 'e' * 64, 'initial_snapshot_sha256': 'a' * 64,
                'before': {'filename': 'before.json', 'sha256': checksum(first)},
                'after': {'filename': 'after.json', 'sha256': checksum(last)}, 'previous': previous}
        plan['manifest_sha256'] = digest(plan)
        return evidence(stage, 'ordinary-boot-plan.json', plan,
                        record(stage, 'before.json', first), record(stage, 'after.json', last))

    def test_ordinary_exact_before_and_target_boot(self):
        value = self.ordinary(); self.assertEqual(validate(value), value)
        for source, target in ((LATER, NEXT), (OLD, LATER), (NEXT, NEXT)):
            with self.subTest(source=source, target=target), self.assertRaises(Refused):
                validate(value, source, target)

    def test_ordinary_pending_ancestor_can_precede_immediate_generation(self):
        first = self.ordinary()
        previous = {'stage': first['stage'], 'plan_sha256': first['plan']['sha256']}
        second = self.ordinary(stage='/fixture/manager/boot-integrity/' + '2' * 32,
                               after=LATER, previous=previous, sequence=1)
        second['records'].append(first['records'][0])
        self.assertEqual(validate(second, OLD, LATER), second)
        pending = {'release': first['stage'], 'plan_sha256': first['plan']['sha256'], 'plan': first['records'][0]['body']}
        self.assertEqual(lineage.validate_pending(second, pending), pending)
        with self.assertRaises(Refused): validate(second, NEXT, LATER)

    def test_pending_requires_exact_plan_owner_hash_and_body(self):
        value = self.ordinary(); current = value['records'][0]
        good = {'release': current['stage'], 'plan_sha256': current['sha256'], 'plan': current['body']}
        self.assertEqual(lineage.validate_pending(value, good), good)
        for key, replacement in (('release', '/foreign/manager/boot-integrity/' + '1' * 32),
                                 ('plan_sha256', 'f' * 64), ('plan', {'schema': 1})):
            with self.subTest(key=key), self.assertRaises(Refused):
                lineage.validate_pending(value, {**good, key: replacement})
        snapshot = value['records'][1]
        with self.assertRaises(Refused):
            lineage.validate_pending(value, {'release': snapshot['stage'], 'plan_sha256': snapshot['sha256'], 'plan': snapshot['body']})

    def test_foreign_duplicate_missing_unreferenced_and_changed_records_refused(self):
        first = self.ordinary()
        for mutate in (lambda v: v['records'].append(copy.deepcopy(v['records'][0])),
                       lambda v: v['records'].pop(),
                       lambda v: v['records'].append(record(v['stage'], 'orphan.json', {'schema': 1})),
                       lambda v: v['records'][1].update(stage='/foreign/manager/boot-integrity/' + '1' * 32),
                       lambda v: v['records'][1]['body'].update(boot_id=LATER)):
            value = copy.deepcopy(first); mutate(value)
            with self.subTest(value=value), self.assertRaises(Refused): validate(value)

    def test_ordinary_rehashed_reference_cannot_change_snapshot_target(self):
        value = self.ordinary(); value['records'][2]['body']['boot_id'] = LATER
        value['records'][2]['sha256'] = checksum(value['records'][2]['body'])
        value['records'][0]['body']['after']['sha256'] = value['records'][2]['sha256']; rehash_current(value)
        with self.assertRaisesRegex(Refused, 'target_boot'): validate(value)

    def test_ordinary_foreign_previous_stage_refused_even_with_canonical_hash(self):
        first = self.ordinary(stage='/other/manager/boot-integrity/' + '2' * 32)
        second = self.ordinary(previous={'stage': first['stage'], 'plan_sha256': first['plan']['sha256']}, sequence=1)
        second['records'].append(first['records'][0])
        with self.assertRaises(Refused): validate(second)

    def test_host_release_and_os_indented_mutations_preserve_boot(self):
        for stage, name, plan in (
                ('/fixture/manager/updates/releases/12-test_release', 'host-runtime-plan.json', {'schema': 1, 'sequence': 12}),
                ('/fixture/manager/os-updates/' + '1' * 32, 'os-integrity-plan.json', {'schema': 1, 'kind': 'os-payload-v1'})):
            value = evidence(stage, name, plan)
            raw = (json.dumps(plan, sort_keys=True, indent=2) + '\n').encode()
            value['plan']['sha256'] = value['records'][0]['sha256'] = boot.rpm.sha(raw)
            with self.subTest(name=name):
                self.assertEqual(validate(value, OLD, OLD), value)
                with self.assertRaisesRegex(Refused, 'cannot_advance'): validate(value)

    def test_host_cannot_pose_as_boot_observation_or_use_foreign_stage_shape(self):
        for stage in ('/fixture/manager/updates/releases/0-release', '/fixture/manager/updates/releases/../release',
                      '/fixture/releases/1-release', '/fixture/manager/os-updates/' + '1' * 32):
            with self.subTest(stage=stage), self.assertRaises(Refused):
                validate(evidence(stage, 'host-runtime-plan.json', {'schema': 1}), OLD, OLD)
        value = self.ordinary(stage='/fixture/manager/updates/releases/1-release')
        with self.assertRaises(Refused): validate(value)

    def content_host(self):
        return {'schema': 2, 'sequence': 12, 'manifest_sha256': 'a' * 64,
                'coordinator_generation': 'b' * 64, 'candidate_generation': 'c' * 64,
                'files': [], 'generation_additions': [], 'selection': {}, 'preserved': [],
                'migration_only': [], 'content': {'schema': 1}, 'content_additions': []}

    def test_content_host_schema2_retains_exact_body_and_cannot_advance_boot(self):
        plan = self.content_host()
        value = evidence('/fixture/manager/updates/releases/12-content', 'host-runtime-plan.json', plan)
        self.assertEqual(validate(value, OLD, OLD), value)
        self.assertEqual(metadata_proof.mode(plan), 'mutation')
        with self.assertRaisesRegex(Refused, 'cannot_advance'): validate(value)
        with self.assertRaisesRegex(Refused, 'current_plan_changed'):
            lineage.validate(value, {**plan, 'manifest_sha256': 'd' * 64}, value['plan']['sha256'], OLD, OLD)
        pending = {'release': value['stage'], 'plan_sha256': value['plan']['sha256'], 'plan': plan}
        self.assertEqual(lineage.validate_pending(value, pending), pending)
        with self.assertRaises(Refused):
            lineage.validate_pending(value, {**pending, 'release': '/foreign/manager/updates/releases/12-content'})

    def test_content_schema2_is_not_a_generic_plan_schema_extension(self):
        stage = '/fixture/manager/updates/releases/12-content'
        for change in ({'schema': 3}, {'schema': True}, {'kind': 'ordinary-boot-v1'},
                       {'content': []}, {'content_additions': {}}, {'unexpected': True}):
            with self.subTest(change=change), self.assertRaises(Refused):
                validate(evidence(stage, 'host-runtime-plan.json', {**self.content_host(), **change}), OLD, OLD)
            with self.subTest(proof_change=change), self.assertRaises(Refused):
                metadata_proof.mode({**self.content_host(), **change})
        for name in ('foreign-plan.json', 'os-integrity-plan.json'):
            with self.subTest(name=name), self.assertRaises(Refused):
                validate(evidence(stage, name, self.content_host()), OLD, OLD)
        plan = self.content_host(); del plan['content']
        with self.assertRaises(Refused): validate(evidence(stage, 'host-runtime-plan.json', plan), OLD, OLD)
        ordinary = self.ordinary(); ordinary['records'][0]['body']['schema'] = 2; rehash_current(ordinary)
        with self.assertRaisesRegex(Refused, 'invalid_plan_schema'): validate(ordinary)

    def test_mutation_does_not_accept_arbitrary_json_serialization(self):
        plan = {'schema': 1, 'kind': 'os-payload-v1'}
        value = evidence('/fixture/manager/os-updates/' + '1' * 32, 'os-integrity-plan.json', plan)
        value['plan']['sha256'] = value['records'][0]['sha256'] = boot.rpm.sha(json.dumps(plan).encode())
        with self.assertRaisesRegex(Refused, 'record_bytes'): validate(value, OLD, OLD)

    def large_snapshot_evidence(self, count=1200):
        value = self.ordinary()
        for item in value['records'][1:]:
            item['body']['artifacts'] = {
                '/usr/lib/modules/5.14.0-687.57.1.el9_8.x86_64/kernel/vendor-%05d.ko' % index:
                {'kind': 'file', 'bytes': index + 1, 'sha256': hashlib.sha256(str(index).encode()).hexdigest(),
                 'mode': 420, 'uid': 0, 'gid': 0, 'xattrs_sha256': 'f' * 64}
                for index in range(count)}
            item['sha256'] = checksum(item['body'])
            value['records'][0]['body'][item['filename'].removesuffix('.json')]['sha256'] = item['sha256']
        rehash_current(value)
        value['records'] = [lineage._pack_record(item) for item in value['records']]
        return value

    @staticmethod
    def encoded_gzip(raw):
        encoder = zlib.compressobj(level=9, wbits=-15)
        return base64.b64encode(lineage.GZIP_HEADER + encoder.compress(raw) + encoder.flush()
                                + struct.pack('<II', zlib.crc32(raw), len(raw))).decode('ascii')

    def test_large_snapshots_roundtrip_with_exact_sha_and_bounded_prepared_size(self):
        value = self.large_snapshot_evidence(6253)
        self.assertIn('gzip_base64', value['records'][1]); self.assertNotIn('body', value['records'][1])
        self.assertEqual(validate(value), value)
        prepared = {'metadata': {'@boot-metadata-v1': {'lineage': value}}}
        self.assertLess(len((json.dumps(prepared, sort_keys=True, indent=2) + '\n').encode()), 2 * 1024 * 1024)
        with patch.object(lineage, 'MAX_BYTES', 1024), self.assertRaises(Refused): validate(value)
        _, one_snapshot = lineage._unpack_record(value['records'][1])
        with patch.object(lineage, 'MAX_BYTES', len(one_snapshot) + 8192), self.assertRaisesRegex(Refused, 'record_bytes'):
            validate(value)

    def test_compressed_corruption_trailing_multistream_and_ambiguous_base64_refused(self):
        original = self.large_snapshot_evidence()
        encoded = original['records'][1]['gzip_base64']; raw = base64.b64decode(encoded)
        for replacement in (encoded + '\n', encoded[:-2], base64.b64encode(raw + b'trailing').decode(),
                            base64.b64encode(raw + raw).decode(), base64.b64encode(raw[:-5] + b'bad!!').decode()):
            value = copy.deepcopy(original); value['records'][1]['gzip_base64'] = replacement
            with self.subTest(replacement=replacement[:30]), self.assertRaises(Refused): validate(value)
        value = copy.deepcopy(original); value['records'][1]['body'] = {'schema': 2}
        with self.assertRaises(Refused): validate(value)

    def test_compressed_bomb_ratio_duplicate_json_and_wrong_scope_refused(self):
        original = self.large_snapshot_evidence()
        for raw in (b'x' * (lineage.MAX_RECORD_BYTES + 1), b'x' * (lineage.COMPRESS_AT + 1)):
            value = copy.deepcopy(original); value['records'][1]['gzip_base64'] = self.encoded_gzip(raw)
            with self.assertRaises(Refused): validate(value)
        raw = zlib.decompress(base64.b64decode(original['records'][1]['gzip_base64']), wbits=31)
        duplicate = b'{"schema":2,' + raw[1:]
        value = copy.deepcopy(original); value['records'][1]['gzip_base64'] = self.encoded_gzip(duplicate)
        with self.assertRaisesRegex(Refused, 'duplicate_record_key'): validate(value)
        value = copy.deepcopy(original); value['records'][1]['filename'] = 'ordinary-boot-plan.json'
        with self.assertRaises(Refused): validate(value)

    def test_thousand_ordinary_generations_keep_only_current_large_snapshots(self):
        value = self.large_snapshot_evidence(6253)
        ancestors, previous = [], None
        for sequence in range(999):
            stage = '/fixture/manager/boot-integrity/' + format(sequence + 2, '032x')
            ancestor = self.ordinary(stage=stage, previous=previous, sequence=sequence)['records'][0]
            ancestors.append(ancestor)
            previous = {'stage': stage, 'plan_sha256': ancestor['sha256']}
        value['records'][0]['body'].update(sequence=999, previous=previous); rehash_current(value)
        value['records'].extend(ancestors)
        self.assertEqual(validate(value), value)
        self.assertEqual(sum('gzip_base64' in item for item in value['records']), 2)
        prepared = {'metadata': {'@boot-metadata-v1': {'lineage': value}}}
        self.assertLess(len((json.dumps(prepared, sort_keys=True, indent=2) + '\n').encode()), 8 * 1024 * 1024)


class OrdinaryCaptureTests(TestCase):
    for _name, _value in ordinary_fixture.OrdinaryAideTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_'): locals()[_name] = _value

    def test_real_plan_capture_is_self_contained_and_pure(self):
        self.change(boot=NEXT); stage = self.pending(); path = stage / 'ordinary-boot-plan.json'
        plan = json.loads(path.read_text()); checksum = boot.rpm.sha(path.read_bytes())
        value = lineage.capture(self.manager, stage, path, plan, checksum)
        path.unlink()
        with (patch.object(updates, 'accepted_plan_history', side_effect=AssertionError('recursive history')),
                patch.object(updates, 'retained_plan_acceptance', side_effect=AssertionError('recursive acceptance')),
                patch.object(Path, 'read_bytes', side_effect=AssertionError('pure validator read'))):
            self.assertEqual(lineage.validate(value, plan, checksum, self.initial['boot_id'], NEXT), value)

    def test_capture_refuses_noncanonical_retained_bytes_and_symlink(self):
        self.change(boot=NEXT); stage = self.pending(); path = stage / 'ordinary-boot-plan.json'
        plan = json.loads(path.read_text()); path.write_bytes(json.dumps(plan).encode())
        with self.assertRaises(Refused): lineage.capture(self.manager, stage, path, plan, boot.rpm.sha(path.read_bytes()))
        raw = boot.kernel.encode(plan); path.unlink(); target = stage / 'foreign.json'; self.write_private(target, raw)
        path.symlink_to(target)
        with self.assertRaises(Refused): lineage.capture(self.manager, stage, path, plan, boot.rpm.sha(raw))


class KernelCaptureTests(TestCase):
    for _name, _value in kernel_fixture.KernelAideIntegrationTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_'): locals()[_name] = _value

    def captured_postboot(self):
        self.call(boot.arm_candidate); self.new_boot()
        path, plan = boot._new_plan(self.stage, 'postboot', runner=self.runner)
        value = lineage.capture(self.manager, self.stage, path, plan, boot.rpm.sha(path.read_bytes()))
        return value

    def test_actual_kernel_postboot_uses_retained_arm_boot(self):
        value = self.captured_postboot()
        self.assertEqual(validate(value), value)
        with self.assertRaisesRegex(Refused, 'typed_ancestry'): validate(value, LATER, NEXT)
        arm = next(item for item in value['records'] if item['body']['phase'] == 'arm')
        pending = {'release': arm['stage'], 'plan_sha256': arm['sha256'], 'plan': arm['body']}
        self.assertEqual(lineage.validate_pending(value, pending), pending)

    def test_kernel_observation_rehashed_current_cannot_change_phase_edge(self):
        value = self.captured_postboot(); value['records'][0]['body']['phase'] = 'resume'; rehash_current(value)
        with self.assertRaisesRegex(Refused, 'predecessor'): validate(value)

    def test_kernel_observation_rehashed_current_cannot_change_identity_or_boot(self):
        original = self.captured_postboot()
        for key, replacement in (('candidate_plan_sha256', 'f' * 64), ('boot_id', OLD),
                                 ('stage', '/foreign/manager/os-updates/' + '1' * 32)):
            value = copy.deepcopy(original); value['records'][0]['body'][key] = replacement; rehash_current(value)
            with self.subTest(key=key), self.assertRaises(Refused): validate(value)

    def test_actual_resume_can_reach_source_before_unaccepted_observation(self):
        self.call(boot.arm_candidate); self.new_boot(); self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.next_candidate_boot(LATER)
        path, plan = boot._new_plan(self.stage, 'resume', runner=self.runner)
        value = lineage.capture(self.manager, self.stage, path, plan, boot.rpm.sha(path.read_bytes()))
        self.assertEqual(validate(value, NEXT, LATER), value)
        self.assertEqual(validate(value, OLD, LATER), value)


class RollbackCaptureTests(TestCase):
    for _name, _value in rollback_fixture.RollbackAideTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_'): locals()[_name] = _value

    def captured_rollback(self):
        original_path = self.attempt_only(); self.later_boot()
        path, plan = rollback.prepare_resume(self.stage, authorize=self.authorize, runner=self.runner)
        value = lineage.capture(self.manager, self.stage, path, plan, boot.rpm.sha(path.read_bytes()))
        original_plan = json.loads(original_path.read_text())
        _, prepared = updates._prepared(self.manager, self.state, self.identity, self.stage,
                                        original_plan, boot.rpm.sha(original_path.read_bytes()))
        return value, prepared

    def test_actual_finished_erase_compound_and_original_preparation(self):
        value, prepared = self.captured_rollback()
        self.assertEqual(validate(value, NEXT, LATER), value)
        self.assertEqual(validate(value, OLD, LATER), value)
        self.assertEqual(lineage.validate_pending(value, prepared), prepared)
        with self.assertRaisesRegex(Refused, 'pending_preparation_changed'):
            lineage.validate_pending(value, {**prepared, 'prepared_at': 'changed'})

    def test_actual_compound_rejects_rehashed_erase_or_scope_rebinding(self):
        original, _ = self.captured_rollback()
        for key, replacement in (('erase_intent_sha256', 'f' * 64), ('original_preparation_sha256', 'f' * 64),
                                 ('removed', {})):
            value = copy.deepcopy(original); value['records'][0]['body'][key] = replacement; rehash_current(value)
            with self.subTest(key=key), self.assertRaises(Refused): validate(value, NEXT, LATER)

    def test_second_unaccepted_compound_preserves_exact_previous_and_origin_boots(self):
        first, prepared = self.captured_rollback()
        self.later_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        path, plan = rollback.prepare_resume(self.stage, authorize=self.authorize, runner=self.runner)
        second = lineage.capture(self.manager, self.stage, path, plan, boot.rpm.sha(path.read_bytes()))
        for source in (OLD, NEXT, LATER):
            with self.subTest(source=source): validate(second, source, self.boot_id)
        self.assertEqual(lineage.validate_pending(second, prepared), prepared)
        pending_first = {'release': first['stage'], 'plan_sha256': first['plan']['sha256'],
                         'plan': first['records'][0]['body']}
        self.assertEqual(lineage.validate_pending(second, pending_first), pending_first)
        with patch.object(lineage, 'MAX_BOOTS', 1), self.assertRaises(Refused):
            validate(second, LATER, self.boot_id)

    def test_selected_rollback_execution_generation_reaches_new_recovery_origin(self):
        self.prepare_only(); self.later_boot()
        result = self.execute()
        self.assertTrue(result['ok'])
        intent = json.loads((self.stage / rollback.INTENT).read_text()); self.assertEqual(intent['schema'], 2)
        path = rollback.execution_integrity_path(self.stage)
        plan = json.loads(path.read_text())
        _, prepared = updates._prepared(self.manager, self.state, self.identity, self.stage,
                                        plan, boot.rpm.sha(path.read_bytes()))
        self.later_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        path, plan = rollback.prepare_resume(self.stage, authorize=self.authorize, runner=self.runner)
        value = lineage.capture(self.manager, self.stage, path, plan, boot.rpm.sha(path.read_bytes()))
        self.assertEqual(validate(value, LATER, self.boot_id), value)
        self.assertEqual(lineage.validate_pending(value, prepared), prepared)


class RetentionCaptureTests(TestCase):
    for _name, _value in retention_fixture.RetentionGenerationReviewTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_') and _name != 'setUp': locals()[_name] = _value

    def setUp(self):
        retention_fixture.RetentionGenerationReviewTests.setUp(self)
        # The shared signed-provenance fixture omits two native recipe fields;
        # retain them here because the pure evidence checks the actual kind.
        self.original.update(schema=1, kind=retention.KIND)
        self.original_sha = checksum(self.original)
        self.write_private(self.stage / retention.PLAN, boot.kernel.encode(self.original))
        self.original_integrity = retention.integrity_plan(self.original, self.original_sha)
        self.write_private(self.original_path, boot.kernel.encode(self.original_integrity))
        updates.prepare(self.manager, self.stage, self.original_path)
        self.original_bytes = (self.stage / retention.PLAN).read_bytes()
        self.original_integrity_bytes = self.original_path.read_bytes()

    def captured_retention(self):
        self.later_boot(); reference, plan, checksum, path = self.prepare_generation()
        self.attempt(reference, plan, checksum, path)
        integrity = json.loads(path.read_text())
        _, prepared = updates._prepared(self.manager, self.state, self.identity, self.stage,
                                        integrity, boot.rpm.sha(path.read_bytes()))
        compound_path, compound = self.compound_boot()
        return lineage.capture(self.manager, self.stage, compound_path, compound,
                               boot.rpm.sha(compound_path.read_bytes())), prepared

    def test_actual_retention_generation_compound_uses_selected_erase_projection(self):
        value, prepared = self.captured_retention()
        observed = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.assertEqual(validate(value, LATER, observed), value)
        self.assertEqual(validate(value, NEXT, observed), value)
        self.assertEqual(lineage.validate_pending(value, prepared), prepared)
        boot_only = next(item for item in value['records'] if item['body'].get('phase') == 'retention_resume')
        with self.assertRaisesRegex(Refused, 'pending_plan_not'):
            lineage.validate_pending(value, {'release': boot_only['stage'], 'plan_sha256': boot_only['sha256'],
                                             'plan': boot_only['body']})

    def test_retention_pending_must_bind_actual_prepared_digest(self):
        value, prepared = self.captured_retention()
        with self.assertRaisesRegex(Refused, 'pending_preparation_changed'):
            lineage.validate_pending(value, {**prepared, 'prepared_at': 'another record'})
        old_integrity = json.loads(self.original_path.read_text())
        with self.assertRaisesRegex(Refused, 'pending_plan_not'):
            lineage.validate_pending(value, {'release': str(self.stage), 'plan_sha256': checksum(old_integrity),
                                             'plan': old_integrity})
