"""Typed metadata DB access over actual private AIDE/boot/CAS ancestry.

Only native host/RPM inputs and the scanner are fixture dependencies. The
authority resolvers, retained chain, dispatcher and compare-and-swap are real.
The wrapper's parser is injected for JSON scanner DBs; its independent suite
checks the pinned native database grammar and hostile inputs.
"""
import copy
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import aide_updates as updates, ordinary_boot_metadata as metadata
from nebulalog_manager import ordinary_boot as ordinary, kernel_boot as boot
from nebulalog_manager import kernel_retention as retention, kernel_rollback as rollback
from nebulalog_manager.common import Refused, atomic_json, locked
from nebulalog_manager.host_job_storage import digest
import test_ordinary_boot_aide as ordinary_fixture
import test_kernel_boot_aide as kernel_fixture
import test_kernel_rollback as rollback_fixture


class AuthorityMixin:
    def history(self, stage, path):
        authority = updates.pending_plan_authority(stage, path)
        before = (self.state / 'aide.db.gz').read_bytes()
        pending = (self.state / 'authorized/pending.json').read_bytes()
        result = updates.accepted_plan_history(manager=self.manager, pending_authority=authority)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assertEqual((self.state / 'authorized/pending.json').read_bytes(), pending)
        self.assertIsNotNone(result['pending_prepared'])
        return result, authority

    def interrupt_accept(self, stage, path, point):
        if point == 'scanning':
            def stop(action, *_):
                if action == 'update': raise OSError('fixture scanner interruption')
            self.scan_hook = stop
            try:
                with self.assertRaises(OSError): updates.accept(self.manager, stage, path)
            finally: self.scan_hook = None
        elif point == 'ready_input':
            with patch.object(updates, '_complete', side_effect=OSError('fixture before copy')):
                with self.assertRaises(OSError): updates.accept(self.manager, stage, path)
        else:
            original = updates._replace_current
            def stop(*args):
                original(*args); raise OSError('fixture after copy')
            with patch.object(updates, '_replace_current', side_effect=stop):
                with self.assertRaises(OSError): updates.accept(self.manager, stage, path)

    def wrapper(self, history, authority):
        pending = history['pending']
        proposed = (pending['state'] == 'ready'
                    and history['current_database_sha256'] == pending['database_sha256']
                    and history['head'] != pending['entry'])
        head = pending['entry'] if proposed else history['head']
        checksum = history['current_database_sha256']
        raw = (self.state / 'aide.db.gz').read_bytes()
        def parse(content, *, expected_sha256):
            self.assertEqual(content, raw)
            self.assertEqual(expected_sha256, boot.rpm.sha(raw))
            return {'schema': 1, 'database_sha256': expected_sha256, 'rows': {}}
        with patch.object(metadata, 'parse_database', side_effect=parse):
            result = metadata.read_accepted_database(self.manager, source_head=head,
                source_database_sha256=checksum, pending_authority=authority)
        self.assertEqual(result['source']['head'], head)
        self.assertEqual(result['source']['observed_head'], history['head'])
        self.assertEqual(result['source']['pending_sha256'], digest(pending))
        self.assertEqual(result['source']['basis'], 'owned-ready-output' if proposed else 'published')
        return result


class OrdinaryAuthorityTests(AuthorityMixin, TestCase):
    for _name, _value in ordinary_fixture.OrdinaryAideTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_'):
            locals()[_name] = _value

    def cas_window(self, point):
        self.change(boot=ordinary_fixture.NEXT, success='1')
        stage = self.pending(); self.interrupt(stage, point)
        history, authority = self.history(stage, stage / ordinary.PLAN)
        self.wrapper(history, authority)
        self.finish(stage)

    def test_scanning_authority(self): self.cas_window('scanning')
    def test_ready_input_authority(self): self.cas_window('ready_input')
    def test_ready_output_authority(self): self.cas_window('ready_output')
    def test_published_head_authority(self): self.cas_window('published_head')

    def test_new_unprepared_generation_can_read_only_its_actual_ancestor(self):
        self.change(boot=ordinary_fixture.NEXT, success='1')
        first = self.pending(); self.interrupt(first, 'ready_output')
        self.change(boot='cccccccc-cccc-cccc-cccc-cccccccccccc', success='0')
        second = self.pending()
        history, authority = self.history(second, second / ordinary.PLAN)
        self.assertEqual(history['pending_prepared']['release'], str(first))
        self.wrapper(history, authority)
        changed = copy.deepcopy(authority); changed['plan']['sha256'] = '0' * 64
        with self.assertRaisesRegex(Refused, 'reference_changed'):
            updates.accepted_plan_history(manager=self.manager, pending_authority=changed)

    def test_equal_input_output_chooses_proposed_with_pending_provenance(self):
        self.observed['boot_id'] = ordinary_fixture.NEXT
        stage = self.pending(); self.interrupt(stage, 'ready_input')
        history, authority = self.history(stage, stage / ordinary.PLAN)
        self.assertEqual(history['pending']['database_sha256'], history['pending']['previous_database_sha256'])
        result = self.wrapper(history, authority)
        self.assertEqual(result['source']['basis'], 'owned-ready-output')

    def test_both_authorities_and_foreign_stage_refuse_without_db_changes(self):
        self.change(boot=ordinary_fixture.NEXT)
        stage = self.pending(); self.interrupt(stage, 'scanning')
        history, authority = self.history(stage, stage / ordinary.PLAN)
        for invalid in ({**authority, 'stage': str(self.root / 'manager/os-updates' / ('f' * 32))},
                        {**authority, 'plan': {'filename': '../ordinary-boot-plan.json', 'sha256': authority['plan']['sha256']}}):
            with self.assertRaises((Refused, FileNotFoundError)):
                updates.accepted_plan_history(manager=self.manager, pending_authority=invalid)
        with self.assertRaisesRegex(Refused, 'conflicting_pending_authorities'):
            updates.accepted_plan_history(manager=self.manager, pending_authority=authority, allow_pending_owner=stage)
        self.assertEqual(self.history(stage, stage / ordinary.PLAN)[0], history)

    def test_valid_but_unrelated_generation_is_not_pending_owner(self):
        self.change(boot=ordinary_fixture.NEXT, success='1')
        stage = self.pending(); self.interrupt(stage, 'scanning')
        foreign = stage.with_name('f' * 32); foreign.mkdir(mode=0o700)
        plan, _ = ordinary._load(stage)
        plan['stage'] = str(foreign)
        plan['manifest_sha256'] = digest({k: v for k, v in plan.items() if k != 'manifest_sha256'})
        for name in ('before.json', 'after.json'):
            self.write_private(foreign / name, (stage / name).read_bytes())
        self.write_private(foreign / ordinary.PLAN, boot.kernel.encode(plan))
        authority = updates.pending_plan_authority(foreign, foreign / ordinary.PLAN)
        with self.assertRaisesRegex(Refused, 'pending_not_in_authority_ancestry'):
            updates.accepted_plan_history(manager=self.manager, pending_authority=authority)

    def test_retained_pending_preparation_report_must_still_match(self):
        self.change(boot=ordinary_fixture.NEXT)
        stage = self.pending(); self.interrupt(stage, 'scanning')
        history, authority = self.history(stage, stage / ordinary.PLAN)
        report_ref = history['pending_prepared']['report']
        path = self.state / 'reports' / (report_ref['id'] + '.json')
        report = self.manager.records.read(path, self.identity)
        report['facts_sha256'] = '0' * 64
        self.write_private(path, boot.kernel.encode(report))
        with self.assertRaisesRegex(Refused, 'retained_record_changed'):
            updates.accepted_plan_history(manager=self.manager, pending_authority=authority)


class CandidateAuthorityTests(AuthorityMixin, TestCase):
    for _name, _value in kernel_fixture.KernelAideIntegrationTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_'):
            locals()[_name] = _value

    def interrupted_arm(self):
        def stop(action, *_):
            if action == 'update': raise OSError('fixture arm interruption')
        self.scan_hook = stop
        try:
            with self.assertRaises(OSError): self.call(boot.arm_candidate)
        finally: self.scan_hook = None
        return boot._current(self.stage)

    def test_candidate_arm_pending_requires_exact_plan_and_operation(self):
        path, _ = self.interrupted_arm()
        with locked(self.root / 'manager/transaction.lock'):
            history, authority = self.history(self.stage, path)
            self.wrapper(history, authority)
        atomic_json(self.root / 'manager/os-latest.json', {'stage': str(self.stage.with_name('f' * 32)), 'boot_id': self.boot_id})
        with self.assertRaisesRegex(Refused, 'operation_or_maintenance_not_owned'):
            updates.accepted_plan_history(manager=self.manager, pending_authority=authority)

    def test_observed_postboot_authority_walks_to_interrupted_arm(self):
        path, _ = self.interrupted_arm()
        self.new_boot()
        post_path, _ = boot._new_plan(self.stage, 'postboot', runner=self.runner)
        history, authority = self.history(self.stage, post_path)
        self.assertEqual(history['pending_prepared']['plan_sha256'], boot.rpm.sha(path.read_bytes()))
        self.wrapper(history, authority)

    def test_missing_attempt_and_rehashed_boot_scope_cannot_authorize_pending(self):
        path, plan = self.interrupted_arm()
        authority = updates.pending_plan_authority(self.stage, path)
        intent_path = self.stage / ('kernel-boot-' + plan['id'] + '-intent.json')
        intent_raw = intent_path.read_bytes(); intent_path.unlink()
        with self.assertRaises((Refused, FileNotFoundError)):
            updates.accepted_plan_history(manager=self.manager, pending_authority=authority)
        self.write_private(intent_path, intent_raw)
        plan['files'][0]['path'] = str(self.unrelated)
        plan['manifest_sha256'] = digest({k: v for k, v in plan.items() if k != 'manifest_sha256'})
        self.write_private(path, boot.kernel.encode(plan))
        authority = updates.pending_plan_authority(self.stage, path)
        with self.assertRaisesRegex(Refused, 'transition_file_binding_changed'):
            updates.accepted_plan_history(manager=self.manager, pending_authority=authority)

    def test_reserialized_ancestor_cannot_replace_exact_retained_bytes(self):
        import json
        arm_path, arm = self.interrupted_arm()
        self.new_boot()
        path, plan = boot._new_plan(self.stage, 'postboot', runner=self.runner)
        changed = json.dumps(arm, sort_keys=True, separators=(',', ':')).encode()
        self.write_private(arm_path, changed)
        plan['previous']['sha256'] = boot.rpm.sha(changed)
        plan['manifest_sha256'] = digest({k: v for k, v in plan.items() if k != 'manifest_sha256'})
        self.write_private(path, boot.kernel.encode(plan))
        authority = updates.pending_plan_authority(self.stage, path)
        with self.assertRaisesRegex(Refused, 'noncanonical_authority_ancestor'):
            updates.accepted_plan_history(manager=self.manager, pending_authority=authority)

    def test_ready_promotion_output_keeps_unpublished_identity(self):
        self.call(boot.arm_candidate); self.new_boot(); self.call(boot.verify_postboot)
        original = updates._replace_current
        def stop(*args): original(*args); raise OSError('fixture promotion after copy')
        with patch.object(updates, '_replace_current', side_effect=stop):
            with self.assertRaises(OSError): self.call(boot.commit_candidate, health=self.health())
        path, _ = boot._current(self.stage)
        history, authority = self.history(self.stage, path)
        result = self.wrapper(history, authority)
        self.assertNotEqual(result['source']['head'], result['source']['observed_head'])
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        next_path, _ = boot._new_plan(self.stage, 'resume', runner=self.runner)
        self.wrapper(*self.history(self.stage, next_path))

    def test_retention_base_and_compound_bind_actual_erase_preparation(self):
        self.retention_origin()
        # Signed header/recipe provenance is the existing native fixture seam.
        with patch.object(retention, 'load_plan_by_checksum', return_value=(self.original_retention, self.original_sha)):
            self.interrupt_accept(self.stage, self.original_path, 'ready_output')
            self.wrapper(*self.history(self.stage, self.original_path))
            path, _, _ = self.compound_after_boot()
            history, authority = self.history(self.stage, path)
            self.assertEqual(history['pending_prepared']['plan'], self.original_integrity)
            self.wrapper(history, authority)
            intent = boot._read_json(self.stage / retention.INTENT)
            intent['authorization']['aide_preparation_sha256'] = '0' * 64
            self.write_private(self.stage / retention.INTENT, boot.kernel.encode(intent))
            with self.assertRaises(Refused):
                updates.accepted_plan_history(manager=self.manager, pending_authority=authority)


class RollbackAuthorityTests(AuthorityMixin, TestCase):
    for _name, _value in rollback_fixture.RollbackAideTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_'):
            locals()[_name] = _value

    def test_attempted_rollback_and_new_compound_read_exact_pending(self):
        path = self.attempt_only()
        self.interrupt_accept(self.stage, path, 'ready_output')
        self.wrapper(*self.history(self.stage, path))
        self.later_boot()
        compound, _ = rollback.prepare_resume(self.stage, authorize=self.authorize, runner=self.runner)
        self.wrapper(*self.history(self.stage, compound))
        self.assertEqual(len([command for command in self.erase_commands if '--test' not in command]), 1)

    def test_unowned_or_changed_erase_intent_never_grants_pending_read(self):
        path = self.attempt_only(); self.interrupt_accept(self.stage, path, 'scanning')
        _, authority = self.history(self.stage, path)
        intent = boot._read_json(self.stage / rollback.INTENT)
        intent['authorization']['aide_preparation_sha256'] = '0' * 64
        self.write_private(self.stage / rollback.INTENT, boot.kernel.encode(intent))
        with self.assertRaisesRegex(Refused, 'preparation_changed'):
            updates.accepted_plan_history(manager=self.manager, pending_authority=authority)
        (self.stage / rollback.INTENT).unlink()
        with self.assertRaises((Refused, FileNotFoundError)):
            updates.accepted_plan_history(manager=self.manager, pending_authority=authority)
