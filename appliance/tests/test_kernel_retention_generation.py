"""Generation publication/no-replay boundaries; native commands are injected.

The separate review suite exercises real boot plans and AIDE ancestry. Here
the original signed recipe and native descriptions are injected so each write
and unsafe inventory outcome can be isolated without erasing a host kernel.
"""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager import aide_updates, kernel_boot as boot
from nebulalog_manager import kernel_retention as retain, kernel_retention_generation as gen
from nebulalog_manager.common import Refused
from test_kernel_retention import BOOT, CURRENT, RECOVERY, OLDEST, VERSIONS, projection

NEW = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'


class GenerationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.stage = Path(temporary.name)
        self.before = {'kind': 'file', 'sha256': '1' * 64, 'mode': 0o600, 'uid': 0, 'gid': 0,
                       'bytes': 1024, 'xattrs_sha256': '2' * 64}
        self.after = {**self.before, 'sha256': '3' * 64}
        self.original = {'schema': 1, 'kind': retain.KIND, 'boot_id': BOOT, 'acceptance': projection(),
                         'operation_sha256': '4' * 64, 'kernel': OLDEST, 'packages': [],
                         'before_inventory': ['before'], 'after_inventory': ['after'],
                         'inventory_sha256': retain.rpm.sha(b'xml'), 'key_sha256': retain.rpm.sha(b'key'),
                         'removed': {'/boot/old': self.before},
                         'preserved': {retain.kernel.GRUBENV: self.before, '/boot/kept': self.before},
                         'mutable_directories': [], 'retained_kernels': VERSIONS[1:]}
        self.root_sha = retain.rpm.sha(retain.kernel.encode(self.original))
        self.approved = {**projection(), 'boot_id': NEW, 'receipt_sha256': '5' * 64}
        self.receipt = {'resume_sha256': '6' * 64, 'boot_id': NEW}
        self.write(retain.PLAN, self.original)
        self.write(retain.INTEGRITY, retain.integrity_plan(self.original, self.root_sha))
        self.original_bytes = {name: (self.stage / name).read_bytes() for name in (retain.PLAN, retain.INTEGRITY)}
        self.patch(retain.rpm, 'read', side_effect=lambda path, *args: b'key' if path == retain.rpm.KEY else Path(path).read_bytes())
        self.patch(gen, 'require_linux_root')
        self.patch(retain, 'require_linux_root')
        self.patch(retain, 'load_original_plan', side_effect=lambda *a, **kw: (copy.deepcopy(self.original), self.root_sha))
        self.patch(retain, 'boot_id', return_value=NEW)
        self.patch(retain, 'historical_acceptance', return_value=self.receipt)
        self.patch(retain, 'acceptance_record', side_effect=lambda stage: self.approved)
        self.patch(retain, 'acceptance', side_effect=lambda *a: self.approved)
        self.patch(retain.kernel, '_acceptance_chain', side_effect=lambda stage: [({}, self.approved['receipt_sha256'], ''), ({}, projection()['receipt_sha256'], '')])
        self.signed = self.patch(retain, 'verify_signed_history')
        self.inventory = self.patch(retain.rpm, 'inventory', return_value=('xml', [], ['before']))
        self.patch(retain, 'preserved_description', side_effect=lambda path: self.after if path == retain.kernel.GRUBENV else self.before)
        self.describe = self.patch(retain.kernel, 'describe', side_effect=lambda path: self.after if path == retain.kernel.GRUBENV else self.before)
        self.patch(retain.kernel, 'read_acceptance', return_value=(self.receipt, self.approved['receipt_sha256'], 'acceptance.json'))
        self.patch(boot, 'accepted_transitions', return_value=self.receipt)
        self.boot_plan = {'id': '7' * 32, 'phase': 'resume'}
        self.patch(boot, '_current', return_value=(self.stage / 'boot.json', self.boot_plan))
        self.proof = {'entry': {'id': BOOT, 'sha256': '8' * 64}, 'original_enrollment_sha256': '9' * 64,
                      'plan_sha256': 'a' * 64, 'prepared_sha256': 'b' * 64, 'database_sha256': 'c' * 64}
        self.patch(aide_updates, 'retained_plan_acceptance', return_value=self.proof)
        self.boot_evidence = self.patch(gen, '_boot_evidence')
        self.events = []
        def runner(argv, **kw):
            self.events.append(argv)
            if argv[0] == '/usr/bin/uname': return CURRENT
            if argv[0] == '/usr/sbin/grubby': return '/boot/vmlinuz-' + CURRENT
            return ''
        self.runner = Mock(side_effect=runner)
        self.accepted = Mock()

    def patch(self, target, name, **kwargs):
        item = patch.object(target, name, **kwargs)
        result = item.start(); self.addCleanup(item.stop); return result

    def write(self, name, value):
        (self.stage / name).write_bytes(retain.kernel.encode(value))

    def prepare(self):
        return gen.prepare(self.stage, accepted=self.accepted, runner=self.runner)

    def intent(self, reference, plan, checksum):
        auth = {'ok': True, 'plan_sha256': checksum, 'boot_id': plan['boot_id'],
                'backup_sha256': 'd' * 64, 'aide_preparation_sha256': 'e' * 64}
        value = {'schema': 2, 'generation': reference, 'plan_sha256': checksum, 'authorization': auth}
        self.write(retain.INTENT, value)
        return value

    def test_new_plan_changes_only_accepted_boot_and_environment_original_bytes_unchanged(self):
        reference, plan, checksum = self.prepare()
        self.assertEqual(gen.load(self.stage, reference, runner=self.runner), (plan, checksum))
        changed = copy.deepcopy(plan)
        changed.update(boot_id=BOOT, acceptance=projection())
        changed['preserved'][retain.kernel.GRUBENV] = self.before
        self.assertEqual(changed, self.original)
        self.assertEqual({name: (self.stage / name).read_bytes() for name in self.original_bytes}, self.original_bytes)
        self.assertFalse((self.stage / retain.INTENT).exists())
        self.assertFalse(any('/usr/bin/rpm' in event for event in self.events))

    def test_retry_after_each_immutable_publication_uses_same_generation(self):
        actual = retain.kernel.record
        for boundary in ('plan', 'binding', 'integrity'):
            with self.subTest(boundary=boundary):
                def fail(stage, name, value):
                    actual(stage, name, value)
                    if name.endswith('-' + boundary + '.json'): raise RuntimeError('power loss')
                with patch.object(retain.kernel, 'record', side_effect=fail), self.assertRaisesRegex(RuntimeError, 'power loss'):
                    self.prepare()
                result = self.prepare()
                self.assertEqual(result, self.prepare())
                self.assertEqual(len(list(self.stage.glob('*-binding.json'))), 1)
                self.assertFalse((self.stage / retain.INTENT).exists())

    def test_scope_change_cannot_be_rehashed_into_a_new_execution_plan(self):
        reference, plan, _ = self.prepare()
        paths = gen.names(NEW.replace('-', ''))
        binding = retain.strict_json((self.stage / paths['binding']).read_bytes())
        for change in ({'removed': {'/etc/shadow': self.before}}, {'after_inventory': ['injected']},
                       {'preserved': {**plan['preserved'], '/boot/kept': self.after}},
                       {'packages': [{'nevra': '--allmatches'}]}, {'key_sha256': '0' * 64}):
            changed = {**plan, **change}
            self.write(paths['plan'], changed)
            self.write(paths['binding'], {**binding, 'plan_sha256': retain.rpm.sha(retain.kernel.encode(changed))})
            forged = {'filename': reference['filename'], 'sha256': retain.rpm.sha((self.stage / reference['filename']).read_bytes())}
            with self.subTest(change=change), self.assertRaisesRegex(Refused, 'scope_changed'):
                gen.load(self.stage, forged, historical=True, runner=self.runner)

    def test_historical_lookup_does_not_adopt_current_boot_or_authorize_execution(self):
        reference, plan, checksum = self.prepare()
        self.intent(reference, plan, checksum)
        retain.boot_id.return_value = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.assertEqual(retain.load_historical_plan(self.stage), (plan, checksum))
        self.assertEqual(retain.load_plan_by_checksum(self.stage, checksum), (plan, checksum))
        with self.assertRaisesRegex(Refused, 'current_acceptance'):
            retain.load_plan(self.stage)

    def test_intent_reference_or_authorization_mismatch_refuses_effective_plan(self):
        reference, plan, checksum = self.prepare()
        value = self.intent(reference, plan, checksum)
        for change in ({'plan_sha256': 'f' * 64}, {'authorization': {**value['authorization'], 'boot_id': BOOT}},
                       {'generation': {**reference, 'sha256': '0' * 64}}, {'schema': True}):
            self.write(retain.INTENT, {**value, **change})
            with self.subTest(change=change), self.assertRaises(Refused): retain.load_historical_plan(self.stage)

    def test_torn_unattempted_older_generation_cannot_poison_exact_attempt_lookup(self):
        orphan = self.stage / ('kernel-retention-execution-' + 'a' * 32 + '-binding.json')
        orphan.write_bytes(b'{"schema":')
        reference, plan, checksum = self.prepare()
        self.intent(reference, plan, checksum)
        self.assertEqual(retain.load_plan_by_checksum(self.stage, checksum), (plan, checksum))
        self.assertEqual(retain.execution_integrity_path(self.stage, checksum), gen.integrity_path(self.stage, reference))
        self.assertEqual(orphan.read_bytes(), b'{"schema":')

    def test_global_intent_prevents_new_generation_and_any_rpm_replay(self):
        reference, plan, checksum = self.prepare()
        self.intent(reference, plan, checksum)
        self.runner.reset_mock()
        for operation in (self.prepare, lambda: retain.execute_cached(self.stage, generation=reference,
                                  authorize=Mock(), accepted=self.accepted, runner=self.runner)):
            with self.assertRaisesRegex(Refused, 'already_attempted'): operation()
        self.runner.assert_not_called()

    def test_unattempted_inventory_partial_erased_or_changed_headers_refuse_before_publication(self):
        for inventory in (['after'], ['partial'], ['before', 'extra']):
            self.inventory.return_value = ('xml', [], inventory)
            with self.subTest(inventory=inventory), self.assertRaises(Refused): self.prepare()
        self.inventory.return_value = ('different header bytes', [], ['before'])
        with self.assertRaisesRegex(Refused, 'header_inventory'): self.prepare()
        self.assertEqual(list(self.stage.glob('*execution*')), [])

    def test_changed_preserved_metadata_and_target_refuse_before_boot_reconciliation(self):
        self.describe.side_effect = lambda path: self.after
        with self.assertRaisesRegex(Refused, 'target_changed'):
            retain.verify_unattempted(self.stage, runner=self.runner)
        self.describe.side_effect = lambda path: self.before
        retain.preserved_description.side_effect = lambda path: self.after
        with self.assertRaisesRegex(Refused, 'protected_state'):
            retain.verify_unattempted(self.stage, runner=self.runner)

    def test_generation_limit_counts_partial_publications_and_allows_existing_retry(self):
        self.prepare()
        with patch.object(gen, 'MAX_GENERATIONS', 1):
            self.prepare()
            self.write('kernel-retention-execution-' + 'd' * 32 + '-plan.json', {})
            with self.assertRaisesRegex(Refused, 'generation_limit'): self.prepare()
        self.assertFalse((self.stage / retain.INTENT).exists())

    def test_fresh_backup_change_after_dryrun_does_not_publish_intent_or_erase(self):
        reference, plan, checksum = self.prepare()
        self.patch(retain.rpm, 'platform')
        self.patch(retain, 'verify_remove_hooks')
        auth = {'ok': True, 'plan_sha256': checksum, 'boot_id': NEW,
                'backup_sha256': 'd' * 64, 'aide_preparation_sha256': 'e' * 64}
        authorize = Mock(side_effect=[auth, {**auth, 'backup_sha256': 'f' * 64}])
        with self.assertRaisesRegex(Refused, 'context_changed'):
            retain.execute_cached(self.stage, generation=reference, authorize=authorize,
                                  accepted=self.accepted, runner=self.runner)
        self.assertFalse((self.stage / retain.INTENT).exists())
        self.assertEqual([event for event in self.events if event[0] == '/usr/bin/rpm'], [retain.command(plan, True)])

    def test_erase_interruption_writes_global_generation_intent_then_never_replays(self):
        reference, plan, checksum = self.prepare()
        self.patch(retain.rpm, 'platform'); self.patch(retain, 'verify_remove_hooks')
        auth = {'ok': True, 'plan_sha256': checksum, 'boot_id': NEW,
                'backup_sha256': 'd' * 64, 'aide_preparation_sha256': 'e' * 64}
        original_runner = self.runner.side_effect
        def interrupted(argv, **kwargs):
            if argv == retain.command(plan):
                self.assertEqual(gen.selected(self.stage), reference)
                raise RuntimeError('command outcome unknown')
            return original_runner(argv, **kwargs)
        self.runner.side_effect = interrupted
        with self.assertRaisesRegex(RuntimeError, 'outcome unknown'):
            retain.execute_cached(self.stage, generation=reference, authorize=Mock(return_value=auth),
                                  accepted=self.accepted, runner=self.runner)
        before = self.runner.call_count
        with self.assertRaisesRegex(Refused, 'already_attempted'):
            retain.execute_cached(self.stage, generation=reference, authorize=Mock(return_value=auth),
                                  accepted=self.accepted, runner=self.runner)
        self.assertEqual(self.runner.call_count, before)
        with self.assertRaisesRegex(Refused, 'partial_erase'):
            retain.recover_cached(self.stage, authorize=Mock(return_value=auth), accepted=self.accepted, runner=self.runner)
        self.assertEqual(self.runner.call_count, before)
