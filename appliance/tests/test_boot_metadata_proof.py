"""Pure proof folding over strict native-format gzip DBs, never mocked parsing.

Inputs represent independently authenticated initial snapshots and AIDE entries;
the production caller still supplies that trust boundary. Tests do not claim
native boot, filesystem, scanner or production acceptance.
"""
import base64
import copy
import hashlib
import uuid
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import boot_metadata_proof as proof, ordinary_boot_metadata as database
from nebulalog_manager import boot_metadata_native as native, kernel_updates as kernel, kernel_boot as boot
from nebulalog_manager.common import Refused
from nebulalog_manager.host_job_storage import digest
import test_ordinary_boot_metadata as db_fixture
import test_boot_metadata_native as native_fixture
import test_ordinary_boot_state as state_fixture
import test_kernel_boot as boot_fixture


class ProofTests(TestCase):
    def setUp(self):
        self.raw = db_fixture.compressed()
        self.initial = {'schema': 2, 'boot_id': native_fixture.OLD_BOOT,
                        'boot_metadata_authority': native_fixture.stable_authority()}
        self.base = {'database_sha256': self.sha(self.raw), 'facts': {
            'ordinary_boot_snapshot_sha256': self.sha(kernel.encode(self.initial))}}
        self.anchor = proof.root_anchor(self.initial, self.base)
        self.sequence = 0

    @staticmethod
    def sha(value): return hashlib.sha256(value).hexdigest()

    def authenticated(self, raw=None, anchor=None, *, source=None):
        raw, anchor = self.raw if raw is None else raw, self.anchor if anchor is None else anchor
        parsed = database.parse_database(raw, expected_sha256=anchor['database_sha256'])
        parsed['source'] = copy.deepcopy(source) if source is not None else {
            'basis': 'published', 'head': anchor['head'], 'observed_head': anchor['head'],
            'original_enrollment_sha256': anchor['original_enrollment_sha256'], 'pending_sha256': None}
        return parsed

    def observation(self, parsed=None, *, boot_id=None, drift=False):
        parsed = self.authenticated() if parsed is None else parsed
        value = native_fixture.fixture()[1]
        value['boot_id'] = boot_id or native_fixture.NEW_BOOT
        value['rows'] = copy.deepcopy(parsed['rows'])
        for row in value['rows'].values():
            row['ctime_ns'] = row['ctime_s'] * 1_000_000_000
            row['mtime_ns'] = row['mtime_s'] * 1_000_000_000
        if drift:
            for path in database.TMPFILES:
                value['rows'][path].update(ctime_s=1760000100, ctime_ns=1760000100_500000000)
            for path in database.EFI: value['rows'][path]['inode'] += 1
        return value

    def plan(self, *, anchor=None, kind='ordinary-boot-v1', boot_id=None, **extra):
        anchor = self.anchor if anchor is None else anchor
        ordinary = kind == 'ordinary-boot-v1'
        value = {'schema': 1, 'kind': kind, 'stage': '/fixture/manager/' +
                 ('boot-integrity/' if ordinary else 'os-updates/') + 'a' * 32}
        if kind == 'ordinary-boot-v1':
            value.update({key: copy.deepcopy(anchor[key]) for key in (
                'original_enrollment_sha256', 'initial_snapshot_sha256')})
            value.update(source_head=copy.deepcopy(anchor['head']), source_database_sha256=anchor['database_sha256'])
        if kind in {'ordinary-boot-v1', 'kernel-boot-v1', 'rocky-kernel-retention-resume-v1'}:
            value['boot_id'] = boot_id or native_fixture.NEW_BOOT
        value.update(extra)
        if ordinary:
            before, after = self.snapshots(anchor['boot_id'], value['boot_id'])
            value.update(sequence=0, previous=None,
                before={'filename': 'before.json', 'sha256': self.sha(kernel.encode(before))},
                after={'filename': 'after.json', 'sha256': self.sha(kernel.encode(after))})
            value['manifest_sha256'] = digest(value)
        return value

    def snapshots(self, before_boot, after_boot):
        before = state_fixture.fixture_v2(); before['boot_id'] = before_boot
        after = copy.deepcopy(before); after['boot_id'] = after_boot
        return before, after

    def lineage(self, plan, anchor):
        filename = 'ordinary-boot-plan.json' if plan['kind'] == 'ordinary-boot-v1' else 'os-integrity-plan.json'
        def record(name, body):
            return {'stage': plan['stage'], 'filename': name, 'sha256': self.sha(kernel.encode(body)), 'body': copy.deepcopy(body)}
        records = [record(filename, plan)]
        if plan['kind'] == 'ordinary-boot-v1':
            before, after = self.snapshots(anchor['boot_id'], plan['boot_id'])
            records.extend([record('before.json', before), record('after.json', after)])
        return {'schema': 1, 'stage': plan['stage'], 'plan': {'filename': filename,
                'sha256': self.sha(kernel.encode(plan))}, 'records': records}

    def make(self, *, plan=None, anchor=None, raw=None, after=None, drift=True):
        anchor = self.anchor if anchor is None else anchor
        parsed = self.authenticated(raw, anchor)
        plan = self.plan(anchor=anchor) if plan is None else plan
        after = self.observation(parsed, drift=drift) if after is None else after
        checksum = self.sha(kernel.encode(plan))
        return proof.make(plan, checksum, anchor=anchor, authenticated_database=parsed, after=after,
                          lineage=self.lineage(plan, anchor))

    def validate(self, value, *, plan=None, anchor=None, raw=None, pending_prepared=None):
        plan = self.plan() if plan is None else plan
        return proof.validate(value, plan=plan, plan_sha=self.sha(kernel.encode(plan)),
                              anchor=self.anchor if anchor is None else anchor,
                              input_database=self.raw if raw is None else raw, pending_prepared=pending_prepared)

    def entry(self, plan, value, *, anchor=None, input_database=None, output_database=None,
              direction='forward', prepared=None):
        anchor = self.anchor if anchor is None else anchor
        input_database = self.raw if input_database is None else input_database
        if output_database is None:
            output_database = (self.rows_database(value['after']['rows'])
                               if value['mode'] == 'observation' else input_database)
        self.sequence += 1
        if prepared is None:
            prepared = {'schema': 1, 'id': str(uuid.UUID(int=100 + self.sequence)),
                        'release': plan['stage'], 'plan': copy.deepcopy(plan),
                        'plan_sha256': self.sha(kernel.encode(plan)), 'metadata': {proof.KEY: copy.deepcopy(value)},
                        'original_enrollment_sha256': self.anchor['original_enrollment_sha256'],
                        'database_sha256': value['source_database_sha256'], 'report': None, 'prepared_at': 'fixture'}
        entry = {'id': str(uuid.UUID(int=self.sequence)), 'previous': copy.deepcopy(anchor['head']),
                 'previous_database_sha256': anchor['database_sha256'],
                 'database_sha256': self.sha(output_database), 'direction': direction,
                 'plan_sha256': self.sha(kernel.encode(plan)),
                 'prepared': {'id': prepared['id'], 'sha256': digest(prepared)}}
        return {'entry_ref': {'id': entry['id'], 'sha256': digest(entry)}, 'entry': entry,
                'prepared': copy.deepcopy(prepared), 'input_database': input_database,
                'output_database': output_database}

    def rows_database(self, measured):
        """Encode actual projected rows using the strict pinned gzip grammar."""
        rows = []
        for path in sorted(database.TARGETS):
            value, row = measured[path], db_fixture.fixture_row(path)
            for field, key in {'uid': 'uid', 'gid': 'gid', 'size': 'bytes', 'ctime': 'ctime_s',
                               'mtime': 'mtime_s', 'inode': 'inode', 'lcount': 'nlink',
                               'attr': 'attributes'}.items():
                row[field] = str(value[key])
            row['perm'] = format((0o120000 if value['kind'] == 'symlink' else 0o100000) | value['mode'], 'o')
            row['lname'] = value['target'] or '0'
            row['sha512'] = '0' if value['sha512'] is None else base64.b64encode(bytes.fromhex(value['sha512'])).decode()
            row['selinux'] = value['selinux']
            row['acl'] = ('0' if value['acl'] is None else 'POSIX,' +
                          ','.join(value['acl'][key] or '0' for key in ('access', 'default')))
            row['xattrs'] = str(len(value['xattrs'])) + ''.join(',' + key + ',' + val for key, val in sorted(value['xattrs'].items()))
            rows.append(row)
        return db_fixture.compressed(db_fixture.text_database(rows))

    def kernel_observation(self):
        """Full typed arm->postboot ancestry, with no native loader stubs."""
        stage = '/fixture/manager/os-updates/' + 'a' * 32
        old_entry = boot_fixture.MACHINE + '-' + boot_fixture.OLD
        candidate_entry = boot_fixture.MACHINE + '-' + boot_fixture.NEW
        original = boot_fixture.block(boot_fixture.variables())
        armed = boot_fixture.block({**boot_fixture.variables(), 'next_entry': candidate_entry})
        observed = boot_fixture.block({**boot_fixture.variables(), 'boot_success': '1'})

        def build(phase, token, boot_id, running, before, after, previous):
            before_desc = {'kind': 'file', 'bytes': len(before), 'sha256': self.sha(before),
                           'uid': 0, 'gid': 0, 'mode': 0o600, 'xattrs_sha256': 'e' * 64}
            value = {'schema': 1, 'kind': 'kernel-boot-v1', 'id': token, 'phase': phase,
                     'sequence': boot.PHASES[phase], 'stage': stage, 'operation_sha256': 'c' * 64,
                     'boot_id': boot_id, 'running_kernel': running, 'candidate_stage': stage,
                     'candidate_plan_sha256': 'd' * 64, 'installed_sha256': 'e' * 64,
                     'kernel': boot_fixture.NEW, 'old_kernel': boot_fixture.OLD,
                     'candidate_entry': candidate_entry, 'old_entry': old_entry, 'previous': previous,
                     'before_raw': base64.b64encode(before).decode(), 'after_raw': base64.b64encode(after).decode(),
                     'files': [{'path': kernel.GRUBENV, 'before': before_desc,
                                'after': {**before_desc, 'bytes': len(after), 'sha256': self.sha(after)}}], 'health': None}
            value['manifest_sha256'] = digest(value)
            return value

        arm = build('arm', 'a' * 32, native_fixture.OLD_BOOT, boot_fixture.OLD, original, armed, None)
        post = build('postboot', 'b' * 32, native_fixture.NEW_BOOT, boot_fixture.NEW, armed, observed,
                     {'id': arm['id'], 'sha256': self.sha(kernel.encode(arm))})
        records = [{'stage': stage, 'filename': 'kernel-boot-' + value['id'] + '-plan.json',
                    'sha256': self.sha(kernel.encode(value)), 'body': copy.deepcopy(value)} for value in (post, arm)]
        lineage = {'schema': 1, 'stage': stage,
                   'plan': {key: records[0][key] for key in ('filename', 'sha256')}, 'records': records}
        return post, lineage

    def changed_database(self):
        rows = [db_fixture.fixture_row(path) for path in sorted(database.TARGETS)]
        row = next(row for row in rows if row['name'] == '/etc/issue')
        row.update(sha512=base64.b64encode(hashlib.sha512(b'new exact payload').digest()).decode(), size='17', mtime='1750000010')
        return db_fixture.compressed(db_fixture.text_database(rows))

    def mutation(self):
        plan = self.plan(kind='os-payload-v1', files=[{'path': '/etc/issue'}])
        after = self.observation(boot_id=native_fixture.OLD_BOOT)
        value = self.make(plan=plan, after=after)
        return plan, value

    def pending_context(self, *, state='ready', output=True, equal=False, published=False):
        """Freeze an actual prior prepared body and proposal, then a new plan."""
        prior_plan = self.plan()
        prior_value = self.make(plan=prior_plan, drift=False)
        next_raw = (self.raw if equal else db_fixture.compressed(
            db_fixture.text_database().replace(b'17:00:52', b'17:00:53')))
        prior = self.entry(prior_plan, prior_value, output_database=next_raw)
        pending = {'schema': 1, 'state': state, 'id': prior['entry']['id'],
                   'prepared': prior['entry']['prepared'], 'direction': 'forward', 'previous': None,
                   'previous_database_sha256': self.anchor['database_sha256']}
        if state == 'ready':
            pending.update(entry=prior['entry_ref'], proposed_entry=prior['entry'], database_sha256=self.sha(next_raw))
        anchor = proof.validate_chain(self.initial, self.base, [prior]) if output else self.anchor
        raw = next_raw if output else self.raw
        boot_id = str(uuid.UUID(int=3))
        plan = self.plan(anchor=anchor, boot_id=boot_id, stage='/fixture/manager/boot-integrity/' + 'b' * 32)
        plan.update(sequence=1, previous={'stage': prior_plan['stage'], 'plan_sha256': self.sha(kernel.encode(prior_plan))})
        plan['manifest_sha256'] = digest({k: v for k, v in plan.items() if k != 'manifest_sha256'})
        lineage = self.lineage(plan, anchor)
        lineage['records'].append(self.lineage(prior_plan, self.anchor)['records'][0])
        parsed = self.authenticated(raw, anchor)
        parsed['source'].update(basis='published' if not output or published else 'owned-ready-output',
                                observed_head=anchor['head'] if published else None, pending_sha256=digest(pending))
        after = self.observation(parsed, boot_id=boot_id)
        return {'plan': plan, 'plan_sha': self.sha(kernel.encode(plan)), 'anchor': anchor,
                'authenticated_database': parsed, 'after': after, 'lineage': lineage, 'pending': pending,
                'pending_prepared': prior['prepared'], 'input_database': raw}

    def make_pending(self, context):
        return proof.make(context['plan'], context['plan_sha'], **{key: context[key] for key in (
            'anchor', 'authenticated_database', 'after', 'lineage', 'pending', 'pending_prepared')})

    def validate_pending(self, value, context):
        return proof.validate(value, **{key: context[key] for key in (
            'plan', 'plan_sha', 'anchor', 'input_database', 'pending_prepared')})

    def test_root_anchor_copies_exact_original_identity_and_authority(self):
        self.assertEqual(self.anchor['boot_id'], native_fixture.OLD_BOOT)
        self.assertEqual(self.anchor['original_enrollment_sha256'], digest(self.base))
        self.assertEqual(self.anchor['initial_snapshot_sha256'], self.base['facts']['ordinary_boot_snapshot_sha256'])
        self.assertIsNone(self.anchor['head'])
        self.initial['boot_metadata_authority']['mount']['uuid'] = 'AAAA-BBBB'
        self.assertNotEqual(self.anchor['authority'], self.initial['boot_metadata_authority'])

    def test_eighteen_qualified_changes_revalidate_real_gzip_and_exact_proof(self):
        value = self.make()
        self.assertEqual(len(value['transition']['changes']), 18)
        self.assertEqual(self.validate(value), value)
        self.assertEqual({item['path'] for item in value['transition']['changes']}, database.TARGETS)
        self.assertEqual(value['transition']['database_rows_sha256'], digest(self.authenticated()['rows']))

    def test_candidate_postboot_proof_requires_actual_typed_arm_ancestry(self):
        plan, lineage = self.kernel_observation()
        value = proof.make(plan, self.sha(kernel.encode(plan)), anchor=self.anchor,
                           authenticated_database=self.authenticated(), after=self.observation(drift=True), lineage=lineage)
        self.assertEqual(len(value['transition']['changes']), 18)
        self.validate(value, plan=plan)
        result = proof.validate_chain(self.initial, self.base, [self.entry(plan, value)])
        self.assertEqual(result['boot_id'], native_fixture.NEW_BOOT)
        wrong = {**self.anchor, 'boot_id': str(uuid.UUID(int=999))}
        with self.assertRaises(Refused):
            proof.make(plan, self.sha(kernel.encode(plan)), anchor=wrong,
                       authenticated_database=self.authenticated(anchor=wrong),
                       after=self.observation(drift=True), lineage=lineage)
        orphan = copy.deepcopy(lineage); orphan['records'].pop()
        with self.assertRaises(Refused):
            proof.make(plan, self.sha(kernel.encode(plan)), anchor=self.anchor,
                       authenticated_database=self.authenticated(), after=self.observation(drift=True), lineage=orphan)

    def test_all_other_target_content_security_and_scalars_refuse(self):
        for field, changed in {'bytes': 8, 'sha512': 'f' * 128, 'uid': 1, 'gid': 1, 'mode': 0o600,
                               'nlink': 2, 'inode': 99, 'mtime_s': 1750000001,
                               'xattrs': {'user.unowned': 'eA=='}}.items():
            after = self.observation(drift=True); after['rows']['/etc/issue'][field] = changed
            if field == 'mtime_s': after['rows']['/etc/issue']['mtime_ns'] = changed * 1_000_000_000
            with self.subTest(field=field), self.assertRaises(Refused): self.make(after=after)

    def test_exact_plan_source_head_database_boot_and_enrollment_bindings(self):
        value = self.make()
        for field, changed in {'plan_sha256': 'f' * 64, 'source_database_sha256': 'f' * 64,
                               'source_boot_id': native_fixture.NEW_BOOT, 'initial_snapshot_sha256': 'f' * 64,
                               'original_enrollment_sha256': 'f' * 64,
                               'source_head': {'id': str(uuid.UUID(int=9)), 'sha256': 'f' * 64}}.items():
            candidate = copy.deepcopy(value); candidate[field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(Refused, 'preparation_binding_changed'):
                self.validate(candidate)
        with self.assertRaises(Refused): self.validate(value, raw=self.changed_database())
        plan = self.plan(boot_id=native_fixture.OLD_BOOT)
        with self.assertRaises(Refused): self.make(plan=plan)

    def test_plan_ordinary_prefix_cannot_diverge_from_verified_input(self):
        for field, changed in {'source_database_sha256': 'f' * 64, 'initial_snapshot_sha256': 'f' * 64,
                               'original_enrollment_sha256': 'f' * 64,
                               'source_head': {'id': str(uuid.UUID(int=9)), 'sha256': 'f' * 64}}.items():
            plan = self.plan(); plan[field] = changed
            plan['manifest_sha256'] = digest({k: v for k, v in plan.items() if k != 'manifest_sha256'})
            with self.subTest(field=field), self.assertRaisesRegex(Refused, 'ordinary_source_changed'):
                self.make(plan=plan)

    def test_unpublished_source_retains_observed_head_and_pending_digest(self):
        context = self.pending_context()
        value = self.make_pending(context)
        self.validate_pending(value, context)
        self.assertIsNone(value['database_source']['observed_head'])
        self.assertEqual(value['pending'], context['pending'])
        self.assertEqual(value['database_source']['pending_sha256'], digest(context['pending']))
        for change in ({'pending_sha256': None}, {'observed_head': context['anchor']['head']}, {'basis': 'published'}):
            changed = copy.deepcopy(context); changed['authenticated_database']['source'].update(change)
            with self.assertRaises(Refused): self.make_pending(changed)

    def test_each_pending_state_and_equal_bytes_keep_the_exact_source_branch(self):
        for state, output, equal, published in (('scanning', False, False, False), ('ready', False, False, False),
                                               ('ready', True, False, True), ('ready', True, True, False)):
            with self.subTest(state=state, output=output, equal=equal, published=published):
                context = self.pending_context(state=state, output=output, equal=equal, published=published)
                self.validate_pending(self.make_pending(context), context)
        context = self.pending_context(output=False, equal=True)
        with self.assertRaisesRegex(Refused, 'pending_input_source_changed'): self.make_pending(context)

    def test_pending_hash_proposal_and_actual_retained_preparation_are_required(self):
        for mutation in (lambda c: c.update(pending=None), lambda c: c.update(pending_prepared=None),
                         lambda c: c['pending'].update(direction='rollback'),
                         lambda c: c['pending']['proposed_entry'].update(database_sha256='f' * 64),
                         lambda c: c['pending_prepared'].update(database_sha256='f' * 64),
                         lambda c: c['anchor']['entry'].update(prepared={'id': str(uuid.UUID(int=9)), 'sha256': 'f' * 64})):
            context = self.pending_context(); mutation(context)
            with self.assertRaises(Refused): self.make_pending(context)

    def test_self_rehashed_foreign_preparation_cannot_join_scanning_lineage(self):
        context = self.pending_context(state='scanning', output=False)
        prepared = context['pending_prepared']
        prepared['plan'] = {**prepared['plan'], 'stage': '/fixture/manager/boot-integrity/' + 'f' * 32}
        prepared['release'] = prepared['plan']['stage']
        prepared['plan_sha256'] = self.sha(kernel.encode(prepared['plan']))
        context['pending']['prepared'] = {'id': prepared['id'], 'sha256': digest(prepared)}
        context['authenticated_database']['source']['pending_sha256'] = digest(context['pending'])
        with self.assertRaises(Refused): self.make_pending(context)

    def test_mutations_require_same_boot_and_grant_zero_report_exceptions(self):
        plan, value = self.mutation()
        self.assertEqual(value['mode'], 'mutation'); self.assertEqual(value['transition']['changes'], [])
        self.validate(value, plan=plan)
        with self.assertRaisesRegex(Refused, 'mutation_cannot_(accept_boot_drift|advance_boot)'):
            self.make(plan=plan, after=self.observation())
        with self.assertRaises(Refused):
            self.make(plan=plan, after=self.observation(boot_id=native_fixture.OLD_BOOT, drift=True))
        observation = self.make()
        invalid = {**value, 'transition': observation['transition']}
        with self.assertRaisesRegex(Refused, 'mutation_cannot_filter_report'):
            proof.filter_report({'added': {}, 'removed': {}, 'changed': {}}, {proof.KEY: invalid})

    def test_supported_boot_phase_modes_and_overlapping_observation_refusal(self):
        for phase in proof.BOOT_PHASES:
            plan = self.plan(kind='kernel-boot-v1', phase=phase)
            self.assertEqual(proof.mode(plan), 'observation' if phase in proof.OBSERVATIONS else 'mutation')
        for plan in (self.plan(kind='unqualified-kind'), self.plan(kind='kernel-boot-v1', phase='unknown'),
                     {**self.plan(), 'schema': True}):
            with self.assertRaises(Refused): proof.mode(plan)
        with self.assertRaisesRegex(Refused, 'observation_overlaps_mutation_targets'):
            self.make(plan=self.plan(files=[{'path': '/etc/issue'}]))

    def test_observation_recheck_ignores_only_read_clocks(self):
        value, plan = self.make(), self.plan()
        later = copy.deepcopy(value['after']); later['observed_at_ns'] += 1_000_000_000; later['uptime_us'] += 1_000_000
        self.assertEqual(proof.recheck(value, plan, 'forward', later), value)
        for mutate in (lambda v: v['rows']['/etc/issue'].update(inode=999),
                       lambda v: v['service'].update(invocation_id='e' * 32),
                       lambda v: v['authority']['mount'].update(uuid='AAAA-BBBB'),
                       lambda v: v.update(boot_id=native_fixture.OLD_BOOT)):
            changed = copy.deepcopy(later); mutate(changed)
            with self.assertRaisesRegex(Refused, 'live_observation_changed'): proof.recheck(value, plan, 'forward', changed)

    def test_mutation_recheck_excludes_only_exact_payload_targets_after_prepare(self):
        plan, value = self.mutation()
        changed = copy.deepcopy(value['after'])
        changed['rows']['/etc/issue'].update(bytes=17, sha512='f' * 128, inode=222)
        for phase in ('forward', 'rollback'):
            self.assertEqual(proof.recheck(value, plan, phase, changed), value)
        with self.assertRaisesRegex(Refused, 'live_observation_changed'): proof.recheck(value, plan, 'prepare', changed)
        for mutate in (lambda v: v['rows']['/etc/locale.conf'].update(inode=222),
                       lambda v: v['service'].update(invocation_id='e' * 32),
                       lambda v: v.update(boot_id=native_fixture.NEW_BOOT)):
            other = copy.deepcopy(changed); mutate(other)
            with self.assertRaisesRegex(Refused, 'live_observation_changed'): proof.recheck(value, plan, 'forward', other)

    def test_exact_summaries_filtered_without_mutating_retained_report(self):
        value = self.make()
        report = {'added': {}, 'removed': {}, 'changed': {v['path']: v['summary'] for v in value['transition']['changes']}}
        original = copy.deepcopy(report)
        report['changed']['/unrelated.conf'] = 'unrelated-summary'
        filtered = proof.filter_report(report, {proof.KEY: value})
        self.assertEqual(filtered['changed'], {'/unrelated.conf': 'unrelated-summary'})
        self.assertEqual({k: v for k, v in report['changed'].items() if k != '/unrelated.conf'}, original['changed'])
        self.assertEqual(proof.filter_report(report, {}), report)
        with self.assertRaisesRegex(Refused, 'expected_metadata_change_missing'):
            proof.filter_report({'added': {}, 'removed': {}, 'changed': {}}, {proof.KEY: value})
        unchanged = self.make(drift=False)
        self.assertEqual(proof.filter_report({'added': {}, 'removed': {}, 'changed': {}}, {proof.KEY: unchanged})['changed'], {})

    def test_other_attribute_added_removed_duplicate_and_changed_summary_refuse(self):
        value = self.make(); path = value['transition']['changes'][0]['path']
        summary = value['transition']['changes'][0]['summary']
        for report in ({'added': {path: summary}, 'removed': {}, 'changed': {}},
                       {'added': {}, 'removed': {path: summary}, 'changed': {}},
                       {'added': {}, 'removed': {}, 'changed': {path: summary + 'X'}}):
            with self.assertRaises(Refused): proof.filter_report(report, {proof.KEY: value})
        duplicate = copy.deepcopy(value); duplicate['transition']['changes'].append(copy.deepcopy(duplicate['transition']['changes'][0]))
        with self.assertRaisesRegex(Refused, 'invalid_report_exception'):
            proof.filter_report({'added': {}, 'removed': {}, 'changed': {
                item['path']: item['summary'] for item in value['transition']['changes']}}, {proof.KEY: duplicate})
        changed = copy.deepcopy(value); changed['transition']['changes'][0]['summary'] = summary + 'X'
        with self.assertRaisesRegex(Refused, 'retained_transition_changed'): self.validate(changed)

    def test_legacy_missing_proof_and_unsupported_schema_never_gain_scope(self):
        legacy = {'schema': 1, 'boot_id': native_fixture.OLD_BOOT}
        self.assertIsNone(proof.root_anchor(legacy, self.base))
        self.assertIsNone(proof.validate_chain(legacy, self.base, []))
        row = self.entry(self.plan(), self.make())
        with self.assertRaisesRegex(Refused, 'legacy_enrollment_cannot_gain_authority'):
            proof.validate_chain(legacy, self.base, [row])
        row['prepared']['metadata'] = {}
        with self.assertRaisesRegex(Refused, 'missing_preparation_anchor'):
            proof.validate_chain(self.initial, self.base, [row])
        with self.assertRaisesRegex(Refused, 'explicit_snapshot_migration_required'):
            proof.root_anchor({**self.initial, 'schema': 3}, self.base)

    def test_historical_fold_has_no_live_capture_or_chain_dependencies(self):
        plan = self.plan(); value = self.make(); row = self.entry(plan, value)
        with patch.object(native, 'capture', side_effect=AssertionError('historical capture')), \
                patch('nebulalog_manager.aide_updates.accepted_plan_history', side_effect=AssertionError('recursive history')):
            result = proof.validate_chain(self.initial, self.base, [row])
        self.assertEqual(result['head'], row['entry_ref'])
        self.assertEqual(result['boot_id'], native_fixture.NEW_BOOT)
        self.assertEqual(result['authority'], self.anchor['authority'])

    def test_mutation_output_rows_come_from_next_actual_database(self):
        plan, value = self.mutation(); output = self.changed_database()
        first = self.entry(plan, value, output_database=output)
        anchor = proof.validate_chain(self.initial, self.base, [first])
        parsed = self.authenticated(output, anchor)
        after = self.observation(parsed, drift=True)
        observation_plan = self.plan(anchor=anchor)
        observation_value = self.make(plan=observation_plan, anchor=anchor, raw=output, after=after)
        second = self.entry(observation_plan, observation_value, anchor=anchor, input_database=output)
        result = proof.validate_chain(self.initial, self.base, [first, second])
        self.assertEqual(result['head'], second['entry_ref'])
        self.assertNotEqual(value['after']['rows']['/etc/issue']['sha512'], observation_value['after']['rows']['/etc/issue']['sha512'])
        # A stale original input cannot stand in for the accepted payload DB.
        second['input_database'] = self.raw
        with self.assertRaises(Refused): proof.validate_chain(self.initial, self.base, [first, second])

    def test_self_consistent_output_hash_cannot_authorize_unobserved_metadata_or_content(self):
        for path, field, change in (('/etc/issue', 'ctime_s', 1760000101),
                                    ('/etc/issue', 'sha512', 'f' * 128),
                                    (database.EFI[0], 'inode', 999)):
            value = self.make(); row = self.entry(self.plan(), value)
            changed = copy.deepcopy(value['after']['rows']); changed[path][field] = change
            row['output_database'] = self.rows_database(changed)
            row['entry']['database_sha256'] = self.sha(row['output_database'])
            row['entry_ref']['sha256'] = digest(row['entry'])
            with self.subTest(path=path, field=field), self.assertRaisesRegex(Refused, 'output_rows_not_authorized'):
                proof.validate_chain(self.initial, self.base, [row])

    def test_mutation_output_scope_and_output_database_bytes_are_independently_bound(self):
        plan, value = self.mutation()
        changed = self.authenticated()['rows']
        changed['/etc/locale.conf']['sha512'] = 'f' * 128
        row = self.entry(plan, value, output_database=self.rows_database(changed))
        with self.assertRaisesRegex(Refused, 'output_rows_not_authorized'):
            proof.validate_chain(self.initial, self.base, [row])
        row = self.entry(plan, value, output_database=self.changed_database())
        row['output_database'] = self.raw
        with self.assertRaisesRegex(Refused, 'database_digest_or_size_mismatch'):
            proof.validate_chain(self.initial, self.base, [row])

    def test_same_preparation_forward_to_rollback_reuses_only_original_anchor(self):
        plan, value = self.mutation(); output = self.changed_database()
        first = self.entry(plan, value, output_database=output)
        anchor = proof.validate_chain(self.initial, self.base, [first])
        reverse = self.entry(plan, value, anchor=anchor, input_database=output,
                             output_database=self.raw, direction='rollback', prepared=first['prepared'])
        result = proof.validate_chain(self.initial, self.base, [first, reverse])
        self.assertEqual(result['database_sha256'], self.base['database_sha256'])
        self.assertEqual(result['boot_id'], native_fixture.OLD_BOOT)
        altered = copy.deepcopy(reverse); altered['prepared']['id'] = str(uuid.UUID(int=999))
        altered['entry']['prepared'] = {'id': altered['prepared']['id'], 'sha256': digest(altered['prepared'])}
        with self.assertRaisesRegex(Refused, 'preparation_reuse_not_exact_rollback'):
            proof.validate_chain(self.initial, self.base, [first, altered])

    def test_foreign_gap_crossboot_and_wrong_prefix_prevent_old_preparation_reuse(self):
        plan, value = self.mutation(); output = self.changed_database()
        first = self.entry(plan, value, output_database=output)
        anchor = proof.validate_chain(self.initial, self.base, [first])
        parsed = self.authenticated(output, anchor)
        for crossboot in (False, True):
            middle_plan = self.plan(anchor=anchor) if crossboot else self.plan(kind='os-payload-v1')
            after = self.observation(parsed, boot_id=native_fixture.NEW_BOOT if crossboot else native_fixture.OLD_BOOT)
            middle_value = self.make(plan=middle_plan, anchor=anchor, raw=output, after=after)
            middle = self.entry(middle_plan, middle_value, anchor=anchor, input_database=output)
            next_anchor = proof.validate_chain(self.initial, self.base, [first, middle])
            reverse = self.entry(plan, value, anchor=next_anchor, input_database=output,
                                 output_database=self.raw, direction='rollback', prepared=first['prepared'])
            with self.subTest(crossboot=crossboot), self.assertRaisesRegex(Refused, 'preparation_reuse_not_exact_rollback'):
                proof.validate_chain(self.initial, self.base, [first, middle, reverse])
        altered = copy.deepcopy(first); altered['entry']['previous_database_sha256'] = 'f' * 64
        with self.assertRaisesRegex(Refused, 'entry_prefix_changed'):
            proof.validate_chain(self.initial, self.base, [altered])

    def test_observation_cannot_be_accepted_as_rollback(self):
        plan = self.plan(); row = self.entry(plan, self.make(), direction='rollback')
        with self.assertRaisesRegex(Refused, 'observation_direction_changed'):
            proof.validate_chain(self.initial, self.base, [row])
