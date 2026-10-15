"""Ordinary generations and typed history fixtures; no native host mutation."""
import base64
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import ordinary_boot as core, kernel_integrity, kernel_retention as retain
from nebulalog_manager.common import Refused
from test_ordinary_boot_state import fixture, environment, description, BOOT, NEXT, KERNEL, MACHINE


class Records:
    def directory(self, path, identity, create=False):
        if create: path.mkdir(parents=True, mode=0o700, exist_ok=True)
        if not path.is_dir() or path.resolve() != path: raise Refused('fixture unsafe directory')
    def read(self, path, identity):
        return core.strict_json(path.read_bytes())
    def write(self, path, value, identity):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(core.kernel.encode(value))


class Fixtures(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.owner = self.root / 'manager/boot-integrity'; self.owner.mkdir(parents=True)
        self.identity = SimpleNamespace(root=self.root, installation_id='458a08e3-ef3b-4cd1-83e5-b402a2c1e913')
        self.manager = SimpleNamespace(guard=lambda: self.identity, records=Records(), check=lambda: {'state': 'clean'})
        self.initial = fixture(); self.observed = copy.deepcopy(self.initial)
        self.base = {'facts': {'ordinary_boot_snapshot_sha256': core.rpm.sha(core.kernel.encode(self.initial))},
                     'database_sha256': 'a' * 64}
        self.history = {'original_enrollment': self.base, 'head': None, 'database_sha256': 'a' * 64,
                        'current_database_sha256': 'a' * 64, 'pending': None, 'pending_prepared': None, 'history': []}
        self.patch(core.rpm, 'read', side_effect=lambda path, *args: Path(path).read_bytes())
        self.patch(core.kernel, 'record', side_effect=self.record)
        self.patch(core.native, 'capture', side_effect=lambda **kw: copy.deepcopy(self.observed))
        self.patch(core.aide, 'verify_initial_boot_snapshot', side_effect=lambda identity, sha: copy.deepcopy(self.initial))
        self.reader = self.patch(core.aide_updates, 'accepted_plan_history', side_effect=lambda **kw: copy.deepcopy(self.history))
        self.patch(core, '_fresh_check', return_value={'state': 'clean'})

    def patch(self, obj, name, **kwargs):
        item = patch.object(obj, name, **kwargs); result = item.start(); self.addCleanup(item.stop); return result

    def record(self, stage, name, value):
        path = Path(stage) / name; raw = core.kernel.encode(value)
        if path.exists() and path.read_bytes() != raw: raise Refused('fixture immutable changed')
        path.write_bytes(raw)

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(core.kernel.encode(value))

    def pending(self):
        return core.pending_stage(self.root, manager=self.manager)

    def reboot(self, boot=NEXT):
        self.observed['boot_id'] = boot
        return self.pending()

    def accepted_row(self, stage, plan, *, number=1, database=None):
        identifier = str(__import__('uuid').UUID(int=number))
        prepared = {'id': identifier, 'release': str(stage), 'plan': plan,
                    'plan_sha256': core.rpm.sha(core.kernel.encode(plan)),
                    'database_sha256': self.history['database_sha256'], 'metadata': {}}
        entry = {'id': identifier, 'direction': 'forward', 'plan_sha256': prepared['plan_sha256'],
                 'previous': self.history['head'], 'previous_database_sha256': self.history['database_sha256'],
                 'database_sha256': database or f'{number + 1:x}' * 64}
        ref = {'id': identifier, 'sha256': core.digest(entry)}
        return {'entry_ref': ref, 'entry': entry, 'prepared': prepared, 'plan': plan}

    def append(self, row):
        self.history['history'].append(row)
        self.history['head'] = row['entry_ref']
        self.history['database_sha256'] = self.history['current_database_sha256'] = row['entry']['database_sha256']

    def reconcile_and_finalize(self, stage):
        plan, checksum = core._load(stage)
        def accept(*args):
            self.append(self.accepted_row(stage, plan, number=len(self.history['history']) + 1))
            return {'ok': True, 'direction': 'forward', 'plan_sha256': checksum}
        def proof(*args, **kw):
            value = {'entry': self.history['head'], 'original_enrollment_sha256': core.digest(self.base),
                     'plan_sha256': checksum, 'prepared_sha256': '3' * 64,
                     'database_sha256': self.history['database_sha256']}
            if kw.get('expected') is not None and kw['expected'] != value: raise Refused('proof changed')
            return value
        with patch.object(core.aide_updates, 'retained_plan_acceptance', side_effect=proof):
            core.reconcile(stage, prepare=lambda *args: {'ok': True, 'plan_sha256': checksum},
                           accept=accept, manager=self.manager)
            health = {'ok': True, 'stage': str(stage), 'boot_id': self.observed['boot_id'],
                      'checks': {key: True for key in core.REQUIRED_CHECKS}}
            receipt = core.finalize(stage, health, manager=self.manager)
            self.assertEqual(core.finalize(stage, health, manager=self.manager), receipt)
            return receipt


class GenerationTests(Fixtures):
    def test_pristine_same_boot_nochange_creates_no_owner(self):
        self.assertIsNone(self.pending())
        self.assertEqual(list(self.owner.iterdir()), [])

    def test_reboot_small_plan_real_snapshot_binding_and_idempotent_pending(self):
        stage = self.reboot()
        plan, checksum = core._load(stage)
        self.assertEqual(plan['kind'], core.KIND)
        self.assertLess(len(core.kernel.encode(plan)), 4096)
        self.assertEqual(plan['transition']['kind'], 'ordinary-reboot')
        self.assertEqual(self.pending(), stage)
        self.assertEqual(core.bound_integrity_plan(self.manager, stage, stage / core.PLAN, preparing=True), (plan, checksum))
        self.assertIsNone(core.integrity_predecessor(stage, stage / core.PLAN))

    def test_snapshot_corruption_refuses_without_replacement(self):
        stage = self.reboot(); original = (stage / 'after.json').read_bytes()
        changed = copy.deepcopy(self.observed); changed['artifacts']['/boot/grub2/grub.cfg']['sha256'] = 'f' * 64
        self.write(stage / 'after.json', changed)
        with self.assertRaisesRegex(Refused, 'snapshot_reference_changed'): self.pending()
        self.assertNotEqual((stage / 'after.json').read_bytes(), original)

    def test_new_owner_retains_exact_ancestor_when_reboot_before_aide_prepare(self):
        first = self.reboot()
        second = self.reboot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.assertNotEqual(first, second)
        previous, checksum = core.integrity_predecessor(second, second / core.PLAN)
        self.assertEqual(previous['stage'], str(first))
        self.assertTrue(core.owns_maintenance(second, str(first)))
        self.assertFalse(core.owns_maintenance(second, str(self.owner / ('e' * 32))))
        plan, _ = core._load(second)
        self.assertEqual(plan['transition']['before_boot_id'], NEXT)
        core.bound_integrity_plan(self.manager, second, second / core.PLAN, preparing=True)

    def test_late_success_has_separate_same_boot_generation(self):
        first = self.reboot(); self.reconcile_and_finalize(first)
        self.assertIsNone(self.pending())
        environment(self.observed, boot_success='1')
        second = self.pending(); plan, _ = core._load(second)
        self.assertEqual(plan['transition']['kind'], 'boot-success')
        self.assertEqual(plan['previous']['stage'], str(first))
        self.reconcile_and_finalize(second)
        self.assertIsNone(self.pending())

    def test_finalization_retry_keeps_gate_owned_and_requires_health(self):
        stage = self.reboot(); receipt = self.reconcile_and_finalize(stage)
        self.write(self.root / 'manager/maintenance.json', {'active': True, 'release': str(stage)})
        self.assertEqual(self.pending(), stage)
        self.assertEqual(receipt['status'], 'complete')
        self.assertFalse((self.owner / core.PENDING).exists())

    def test_incomplete_health_cannot_publish_completion(self):
        stage = self.reboot()
        with patch.object(core, '_result', return_value={'boot_id': NEXT, 'plan_sha256': 'a' * 64}):
            with self.assertRaisesRegex(Refused, 'fresh_complete_health'):
                core.finalize(stage, {'ok': True, 'stage': str(stage), 'boot_id': NEXT, 'checks': {}}, manager=self.manager)
        self.assertFalse((stage / core.FINAL).exists())

    def test_artifact_or_inventory_drift_cannot_be_adopted(self):
        for kind in ('artifact', 'inventory', 'xattrs', 'extra'):
            self.observed = copy.deepcopy(self.initial); self.observed['boot_id'] = NEXT
            if kind == 'artifact': self.observed['artifacts']['/boot/grub2/grub.cfg']['sha256'] = 'c' * 64
            if kind == 'inventory': self.observed['inventory'] = sorted(self.observed['inventory'] + ['evil-0:1-1.x86_64'])
            if kind == 'xattrs': self.observed['artifacts']['/boot/grub2/grub.cfg']['xattrs_sha256'] = 'd' * 64
            if kind == 'extra': self.observed['artifacts']['/boot/extra'] = description()
            with self.subTest(kind=kind), self.assertRaises(Refused): self.pending()
        self.assertEqual(list(self.owner.iterdir()), [])

    def test_foreign_or_incomplete_maintenance_owners_refuse_before_creation(self):
        cases = [('maintenance.json', {'active': True, 'release': '/foreign'}),
                 ('os-transaction.json', {'state': 'complete', 'kernel_retention': 'pending'}),
                 ('os-transaction.json', {'state': 'complete', 'kernel_finalization': 'pending'}),
                 ('os-transaction.json', {'state': 'reboot_requested'}),
                 ('updates/transaction.json', {'state': 'committed', 'finalization': 'pending'}),
                 ('kernel-pending.json', {'schema': 1})]
        for name, value in cases:
            path = self.root / 'manager' / name; self.write(path, value)
            with self.subTest(name=name), self.assertRaises(Refused): self.reboot()
            path.unlink()
        self.assertEqual(list(self.owner.iterdir()), [])

    def test_only_environment_can_differ_in_aide_report(self):
        stage = self.reboot(); plan, _ = core._load(stage)
        for phase in ('prepare', 'forward'):
            core.allowed_integrity_report({'changed': {core.native.ENV: {}}}, plan, phase)
            for report in ({'added': {'/boot/evil': {}}}, {'removed': {'/boot/file': {}}},
                           {'changed': {'/usr/lib/modules/evil': {}}}):
                with self.assertRaisesRegex(Refused, 'unrelated_integrity_change'):
                    core.allowed_integrity_report(report, plan, phase)
        with self.assertRaisesRegex(Refused, 'unsupported_integrity_direction'):
            core.allowed_integrity_report({}, plan, 'rollback')

    def test_fake_aide_result_is_not_completion_authority(self):
        stage = self.reboot(); _, checksum = core._load(stage)
        with patch.object(core.aide_updates, 'retained_plan_acceptance', side_effect=Refused('real proof required')):
            with self.assertRaisesRegex(Refused, 'real proof required'):
                core.reconcile(stage, prepare=lambda *a: {'ok': True, 'plan_sha256': checksum},
                               accept=lambda *a: {'ok': True, 'direction': 'forward', 'plan_sha256': checksum}, manager=self.manager)
        self.assertFalse((stage / core.RESULT).exists())

    def test_post_scan_change_prevents_final_result_validation(self):
        stage = self.reboot(); self.reconcile_and_finalize(stage)
        environment(self.observed, boot_success='1')
        with patch.object(core.aide_updates, 'retained_plan_acceptance', return_value={}):
            with self.assertRaisesRegex(Refused, 'accepted_observation_changed'):
                core._result(self.manager, stage, runner=Mock())


class ReducerTests(Fixtures):
    def setUp(self):
        super().setUp()
        # These tests isolate folding. The separate historical boot fixture
        # exercises the native recipe validator and interrupted intent chain.
        self.patch(core, '_qualified_boot')

    def os_stage(self, token='1'):
        stage = self.root / 'manager/os-updates' / (token * 32); stage.mkdir(parents=True)
        return stage

    def install(self):
        stage = self.os_stage()
        candidate = '5.14.0-687.57.1.el9_8.x86_64'
        operation = {'schema': 1, 'id': BOOT, 'stage': str(stage), 'boot_id': BOOT}
        self.write(stage / 'operation.json', operation)
        packages = [{'name': name, 'nevra': name + '-0:' + candidate} for name in sorted(core.kernel.NAMES)]
        paths = ['/usr/lib/modules/' + candidate, '/usr/lib/modules/' + candidate + '/vendor.ko']
        files = [{'path': path, 'ghost': False, **{key: value for key, value in desc.items() if key != 'xattrs_sha256'}}
                 for path, desc in zip(paths, [description(kind='directory', mode=0o755), description()])]
        generated = {path: description() for path in ('/boot/vmlinuz-' + candidate, '/boot/initramfs-' + candidate + '.img',
                    '/boot/loader/entries/' + MACHINE + '-' + candidate + '.conf')}
        payload = {'schema': 1, 'kind': 'rocky-kernel-install-v1', 'kernel': candidate, 'old_kernel': KERNEL,
                   'operation_sha256': core.rpm.sha(core.kernel.encode(operation)), 'key_sha256': core.rpm.KEY_SHA256,
                   'packages': packages, 'solve': sorted([{'action': 'install', 'nevra': p['nevra'], 'repo': '@commandline'} for p in packages], key=lambda p: p['nevra']),
                   'before_inventory': self.initial['inventory'],
                   'after_inventory': sorted(self.initial['inventory'] + [p['nevra'] for p in packages]),
                   'files': files, 'shared': {}, 'preserved': {}, 'generated': sorted(generated),
                   'mutable_before': {core.native.ENV: self.initial['grub']['description']}}
        checksum = core.rpm.sha(core.kernel.encode(payload)); self.write(stage / 'kernel-plan.json', payload)
        installed = {'plan_sha256': checksum, 'kernel': candidate, 'old_kernel': KERNEL,
                     'generated': generated, 'mutable': payload['mutable_before']}
        self.write(stage / 'kernel-installed.json', installed)
        plan = kernel_integrity.plan(stage, payload, checksum)
        self.append(self.accepted_row(stage, plan, number=1))
        after = copy.deepcopy(self.initial)
        after['inventory'] = payload['after_inventory']
        after['artifacts'].update(generated)
        after['artifacts'].update({path: {**core._description(item), 'xattrs_sha256': 'b' * 64} for path, item in zip(paths, files)})
        return stage, payload, after, paths

    def commit(self, stage, payload, after):
        output = copy.deepcopy(after); output['kernel'] = output['default_kernel'] = payload['kernel']; output['boot_id'] = NEXT
        environment(output, saved_entry=MACHINE + '-' + payload['kernel'])
        token = '2' * 32
        plan = {'schema': 1, 'kind': 'kernel-boot-v1', 'id': token, 'phase': 'commit', 'stage': str(stage),
                'boot_id': NEXT, 'running_kernel': payload['kernel'], 'previous': None,
                'before_raw': after['grub']['raw'], 'after_raw': output['grub']['raw'],
                'files': [{'path': core.native.ENV, 'before': after['grub']['description'], 'after': output['grub']['description']}]}
        self.write(stage / ('kernel-boot-' + token + '-plan.json'), plan)
        self.append(self.accepted_row(stage, plan, number=2))
        return output

    def test_exact_signed_install_and_commit_require_full_metadata_checkpoint(self):
        stage, payload, after, paths = self.install()
        self.observed = self.commit(stage, payload, after)
        current = self.pending(); plan, _ = core._load(current)
        self.assertTrue(plan['checkpoint_required'])
        self.assertEqual(plan['metadata_bound_paths'], sorted(paths))
        self.assertEqual(plan['transition']['kind'], 'checkpoint')
        with self.assertRaisesRegex(Refused, 'unrelated_integrity_change'):
            core.allowed_integrity_report({'changed': {paths[1]: {}}}, plan, 'prepare')
        self.reconcile_and_finalize(current)
        self.assertIsNone(self.pending())
        # Once actually checkpointed, all xattrs have immutable authority.
        self.observed['artifacts'][paths[1]]['xattrs_sha256'] = 'f' * 64
        with self.assertRaisesRegex(Refused, 'accepted_artifact_changed'): self.pending()

    def test_completed_retention_reduces_inventory_and_exact_removed_artifacts(self):
        stage, payload, after, _ = self.install(); self.observed = self.commit(stage, payload, after)
        removed = {p: v for p, v in self.initial['artifacts'].items()
                   if KERNEL in p and (p.startswith('/boot/') or p.startswith('/usr/lib/modules/'))}
        original = {'before_inventory': payload['after_inventory'],
                    'after_inventory': [v for v in payload['after_inventory'] if not v.endswith(KERNEL)],
                    'removed': removed, 'preserved': {core.native.ENV: self.observed['grub']['description']},
                    'mutable_directories': ['/boot', '/usr/lib/modules']}
        checksum = 'd' * 64
        self.patch(retain, 'load_historical_plan', return_value=(original, checksum))
        plan = retain.integrity_plan(original, checksum)
        self.append(self.accepted_row(stage, plan, number=3))
        for path in removed: del self.observed['artifacts'][path]
        self.observed['inventory'] = original['after_inventory']
        self.observed['boot_id'] = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        current = self.pending(); value, _ = core._load(current)
        self.assertEqual(value['transition']['kind'], 'ordinary-reboot')
        self.assertTrue(value['checkpoint_required'])
        self.reconcile_and_finalize(current)
        self.assertIsNone(self.pending())

    def test_updated_payload_content_cannot_be_filled_from_observation(self):
        stage, payload, after, paths = self.install(); self.observed = self.commit(stage, payload, after)
        self.observed['artifacts'][paths[1]]['sha256'] = 'f' * 64
        with self.assertRaisesRegex(Refused, 'accepted_artifact_changed'): self.pending()

    def test_unknown_typed_plan_and_inventory_discontinuity_refuse(self):
        row = self.accepted_row(self.os_stage(), {'kind': 'future-anything-v9'}, number=1)
        self.append(row)
        with self.assertRaisesRegex(Refused, 'unsupported_accepted_plan_kind'): self.pending()
        with self.assertRaisesRegex(Refused, 'accepted_inventory_discontinuity'):
            core._inventory(copy.deepcopy(self.initial), ['missing-0:1-1.x86_64'], [])


class InterruptedTests(Fixtures):
    def interrupt(self, *, output_copied):
        first = self.reboot(); plan, _ = core._load(first)
        row = self.accepted_row(first, plan, number=1)
        prepared = row['prepared']
        self.write(self.root / 'manager/aide/authorized/prepared' / (prepared['id'] + '.json'), prepared)
        pending = {'id': prepared['id'], 'state': 'ready', 'direction': 'forward',
                   'prepared': {'id': prepared['id'], 'sha256': core.digest(prepared)},
                   'previous': self.history['head'], 'previous_database_sha256': self.history['database_sha256'],
                   'entry': row['entry_ref'], 'proposed_entry': row['entry'], 'database_sha256': row['entry']['database_sha256']}
        self.write(self.root / 'manager/aide/authorized/pending.json', pending)
        self.history['pending'], self.history['pending_prepared'] = pending, prepared
        if output_copied: self.history['current_database_sha256'] = pending['database_sha256']
        return first, row

    def test_second_reboot_after_output_copy_binds_exact_unpublished_entry(self):
        first, row = self.interrupt(output_copied=True)
        current = self.reboot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        plan, _ = core._load(current)
        self.assertEqual(plan['source_head'], row['entry_ref'])
        self.assertIsNone(plan['source_observed_head'])
        self.assertEqual(plan['source_pending']['owner'], str(first))
        core.bound_integrity_plan(self.manager, current, current / core.PLAN, preparing=True)
        self.append(row); self.history['pending'] = self.history['pending_prepared'] = None
        (self.root / 'manager/aide/authorized/pending.json').unlink()
        core.bound_integrity_plan(self.manager, current, current / core.PLAN, preparing=True)

    def test_second_reboot_before_database_copy_keeps_original_input(self):
        first, row = self.interrupt(output_copied=False)
        current = self.reboot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        plan, _ = core._load(current)
        self.assertIsNone(plan['source_head'])
        self.assertEqual(plan['source_database_sha256'], self.base['database_sha256'])
        self.assertEqual(core._snapshot(current, plan['before'])['boot_id'], BOOT)
        self.assertEqual(plan['transition']['before_boot_id'], NEXT)
        core.bound_integrity_plan(self.manager, current, current / core.PLAN, preparing=True)

    def test_frozen_pending_preparation_tampering_refuses(self):
        first, row = self.interrupt(output_copied=True)
        current = self.reboot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        path = self.root / 'manager/aide/authorized/prepared' / (row['prepared']['id'] + '.json')
        changed = copy.deepcopy(row['prepared']); changed['metadata'] = {'evil': True}; self.write(path, changed)
        with self.assertRaisesRegex(Refused, 'frozen_pending_evidence_changed'):
            core.bound_integrity_plan(self.manager, current, current / core.PLAN, preparing=True)

    def test_foreign_aide_owner_is_not_adopted(self):
        first, row = self.interrupt(output_copied=False)
        changed = copy.deepcopy(row['prepared']); changed['release'] = str(self.owner / ('f' * 32))
        self.write(self.root / 'manager/aide/authorized/prepared' / (changed['id'] + '.json'), changed)
        with self.assertRaisesRegex(Refused, 'foreign_integrity_owner'): self.pending()


class HoldTests(Fixtures):
    def setUp(self):
        super().setUp()
        self.write(self.root / 'manager/aide-enrollment.json', {'legacy': 'intentionally missing new fact'})

    def hold(self):
        return core.observation_hold(self.root, boot_id=self.observed['boot_id'], manager=self.manager)

    def test_hold_binds_raw_enrollment_without_claiming_valid_new_fact(self):
        stage = self.hold(); receipt, checksum = core._load_hold(stage, self.identity)
        self.assertEqual(receipt['installation_id'], self.identity.installation_id)
        self.assertEqual(receipt['enrollment_sha256'], core.rpm.sha((self.root / 'manager/aide-enrollment.json').read_bytes()))
        self.assertTrue(core.owns_maintenance(stage, str(stage)))
        self.assertFalse((stage / core.FINAL).exists())
        self.assertEqual(self.hold(), stage)

    def test_corrupted_current_plan_can_be_held_but_never_adopted(self):
        stage = self.reboot(); (stage / core.PLAN).write_bytes(b'corrupted')
        hold = self.hold(); self.assertTrue((hold / 'receipt.json').exists())
        with self.assertRaises(Refused): self.pending()

    def test_corrupted_snapshot_hold_retry_preserves_existing_failure_owner(self):
        stage = self.reboot(); (stage / 'after.json').write_bytes(b'corrupted')
        hold = self.hold()
        self.write(self.root / 'manager/maintenance.json', {'active': True, 'release': str(hold)})
        before = (hold / 'receipt.json').read_bytes()
        self.assertEqual(self.hold(), hold)
        self.assertEqual((hold / 'receipt.json').read_bytes(), before)
        with self.assertRaises(Refused): self.pending()

    def test_legacy_fact_failure_hold_has_no_aide_reenrollment(self):
        self.base['facts'].pop('ordinary_boot_snapshot_sha256')
        with self.assertRaisesRegex(Refused, 'explicit_enrollment_migration_required'): self.pending()
        self.assertTrue((self.hold() / 'receipt.json').exists())

    def test_foreign_gate_and_orphaned_os_pairs_refuse_without_hold(self):
        for name, value in [('maintenance.json', {'active': True, 'release': '/foreign'}),
                            ('os-latest.json', {'stage': '/foreign'}),
                            ('os-transaction.json', {'state': 'complete'})]:
            path = self.root / 'manager' / name; self.write(path, value)
            with self.subTest(name=name), self.assertRaises(Refused): self.hold()
            self.assertFalse((self.owner / core.HOLD).exists()); path.unlink()

    def test_existing_owned_generation_gate_is_preserved(self):
        stage = self.reboot()
        self.write(self.root / 'manager/maintenance.json', {'active': True, 'release': str(stage)})
        self.assertEqual(self.hold(), stage)
        self.assertFalse((self.owner / core.HOLD).exists())

    def test_changed_enrollment_identity_receipt_or_hold_pointer_refuses(self):
        stage = self.hold(); raw = (stage / 'receipt.json').read_bytes()
        receipt = core.strict_json(raw)
        for changes in ({'installation_id': NEXT}, {'boot_id': 'bad'}, {'enrollment_sha256': 'f' * 64}):
            self.write(stage / 'receipt.json', {**receipt, **changes})
            with self.subTest(changes=changes), self.assertRaises(Refused): self.hold()
            (stage / 'receipt.json').write_bytes(raw)
        pointer = self.manager.records.read(self.owner / core.HOLD, self.identity)
        self.write(self.owner / core.HOLD, {**pointer, 'sha256': 'f' * 64})
        with self.assertRaisesRegex(Refused, 'hold_reference_changed'): self.hold()

    def test_nochange_hold_forces_scan_and_health_generation(self):
        hold = self.hold()
        self.write(self.root / 'manager/maintenance.json', {'active': True, 'release': str(hold)})
        stage = self.pending(); plan, _ = core._load(stage)
        self.assertEqual(plan['hold']['stage'], str(hold))
        self.assertEqual(plan['transition']['kind'], 'checkpoint')
        self.assertTrue(plan['checkpoint_required'])
        self.assertTrue(core.owns_maintenance(stage, str(hold)))
        self.reconcile_and_finalize(stage)
        self.assertFalse((self.owner / core.HOLD).exists())
        # Root has not released the inherited gate yet: retry remains owned.
        self.assertEqual(self.pending(), stage)


class JournalPairTests(Fixtures):
    def setUp(self):
        super().setUp()
        self.stage = self.root / 'manager/os-updates' / ('e' * 32); self.stage.mkdir(parents=True)
        self.write(self.stage / 'operation.json', {'schema': 1, 'id': BOOT, 'stage': str(self.stage), 'boot_id': BOOT})
        self.latest = {'stage': str(self.stage), 'boot_id': BOOT, 'state': 'prepared'}
        self.transaction = {'stage': str(self.stage), 'boot_id': BOOT, 'state': 'complete', 'reboot_pending': False,
                            'no_updates': True, 'status': 'no_updates'}

    def check(self):
        self.write(self.root / 'manager/os-latest.json', self.latest)
        self.write(self.root / 'manager/os-transaction.json', self.transaction)
        return core._settled(self.identity)

    def test_no_updates_nonreboot_postcheck_and_old_completed_boot_are_settled(self):
        self.check()
        self.latest['state'] = 'postcheck_passed'; self.transaction['status'] = 'updated'; self.check()
        self.latest.update(state='reboot_completed', observed_boot_id=NEXT)
        self.transaction['observed_boot_id'] = NEXT; self.check()

    def test_mismatched_stage_boot_or_unfinished_latest_is_refused(self):
        original = dict(self.latest)
        for changed in ({'stage': str(self.stage.with_name('f' * 32))}, {'boot_id': NEXT},
                        {'state': 'postcheck_failed'}, {'state': 'reboot_prepared'}):
            self.latest = {**original, **changed}
            with self.subTest(changed=changed), self.assertRaises(Refused): self.check()

    def test_no_updates_flags_and_completed_observed_boot_must_match(self):
        self.transaction['no_updates'] = False
        with self.assertRaisesRegex(Refused, 'preflight_is_not_completion'): self.check()
        self.latest.update(state='reboot_completed', observed_boot_id=NEXT)
        self.transaction['observed_boot_id'] = BOOT
        with self.assertRaisesRegex(Refused, 'completed_boot_mismatch'): self.check()

    def test_failed_preflight_without_owner_or_with_execution_intent_is_held(self):
        self.transaction = {'state': 'failed', 'recovery_phase': 'preflight'}
        with self.assertRaisesRegex(Refused, 'owner_missing'): self.check()
        self.transaction.update(stage=str(self.stage), boot_id=BOOT, recovery_phase='planning')
        self.check()
        for name in ('kernel-apply-intent.json', 'kernel-rpm-command.json', 'kernel-installed.json',
                     'kernel-completed.json', 'kernel-boot-' + 'a' * 32 + '-intent.json',
                     'kernel-default-current.json', 'kernel-acceptance-current.json'):
            self.write(self.stage / name, {'schema': 1})
            with self.subTest(name=name), self.assertRaisesRegex(Refused, 'execution_requires_recovery'): self.check()
            (self.stage / name).unlink()


if __name__ == '__main__':
    unittest.main()
