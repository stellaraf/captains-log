"""Reduce real accepted boot/AIDE chains over private native-host fixtures.

The host candidate provenance, renderer and scanner are injected by the shared
fixture. Boot plan validators, AIDE dispatch/retained-chain verification and the
ordinary history reducer remain real. These tests do not qualify a native boot.
"""
import base64
import copy
from unittest import TestCase
from unittest.mock import patch

from nebulalog_manager import ordinary_boot as core
from nebulalog_manager import kernel_boot as boot, aide_updates as updates
from nebulalog_manager.common import Refused
import test_kernel_boot as native_fixture
import test_kernel_boot_aide as integration
from test_ordinary_boot_state import fixture


class OrdinaryBootHistoryTests(TestCase):
    # Reuse setup/helpers without inheriting and rerunning the unrelated suites.
    for _name, _value in integration.KernelAideIntegrationTests.__dict__.items():
        if callable(_value) and not _name.startswith('test_') and _name != 'setUp':
            locals()[_name] = _value

    def setUp(self):
        integration.KernelAideIntegrationTests.setUp(self)
        self.initial_snapshot = fixture()
        self.initial_snapshot['grub'] = {
            'raw': base64.b64encode(self.env.read_bytes()).decode(),
            'description': self.description(self.env),
        }
        for context in (
                patch.object(core.native, 'ENV', str(self.env)),
                patch.object(boot.kernel, 'load_plan', return_value=(self.candidate, native_fixture.PLAN_SHA))):
            context.start()
            self.addCleanup(context.stop)

    def fold_verified_history(self):
        history = updates.accepted_plan_history(manager=self.manager)
        database = (self.state / 'aide.db.gz').read_bytes()
        state, unresolved, checkpoint = core._fold(self.initial_snapshot, history['history'], self.identity)
        self.assertEqual(state['grub']['raw'], base64.b64encode(self.env.read_bytes()).decode())
        self.assertEqual(state['grub']['description'], self.description(self.env))
        self.assertEqual(state['boot_id'], self.boot_id)
        self.assertEqual(state['kernel'], self.running)
        self.assertEqual(state['default_kernel'], native_fixture.NEW)
        self.assertEqual(unresolved, set())
        self.assertTrue(checkpoint)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), database)
        self.assertEqual(self.scan_calls.count('init'), 1)
        return history

    def begin_promotion(self):
        self.call(boot.arm_candidate)
        self.new_boot()
        self.call(boot.verify_postboot)

    def finish_later_boot(self):
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())

    def test_completed_kernel_boot_chain_reduces_without_new_host_adoption(self):
        self.begin_promotion()
        self.call(boot.commit_candidate, health=self.health())
        history = self.fold_verified_history()
        self.assertEqual([row['plan']['phase'] for row in history['history']], ['arm', 'postboot', 'commit'])

    def test_arm_scan_interruption_reduces_validated_unaccepted_predecessor(self):
        def stop(action, *_):
            if action == 'update':
                raise OSError('arm scan interrupted before database copy')
        self.scan_hook = stop
        with self.assertRaises(OSError):
            self.call(boot.arm_candidate)
        arm = boot._current(self.stage)[1]
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.scan_hook = None
        self.new_boot()
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        history = self.fold_verified_history()
        self.assertEqual([row['plan']['phase'] for row in history['history']], ['postboot', 'commit'])
        self.assertFalse(boot._result_path(self.stage, arm).exists())

    def test_promotion_scan_interruption_reduces_validated_unaccepted_predecessor(self):
        self.begin_promotion()
        def stop(action, *_):
            if action == 'update':
                raise OSError('promotion scan interrupted before database copy')
        self.scan_hook = stop
        with self.assertRaises(OSError):
            self.call(boot.commit_candidate, health=self.health())
        promotion = boot._current(self.stage)[1]
        self.scan_hook = None
        self.finish_later_boot()
        history = self.fold_verified_history()
        self.assertEqual([row['plan']['phase'] for row in history['history']], ['arm', 'postboot', 'resume'])
        self.assertFalse(boot._result_path(self.stage, promotion).exists())

    def test_promotion_copied_database_retains_exact_published_prefix(self):
        self.begin_promotion()
        replace = updates._replace_current
        def crash(*args):
            replace(*args)
            raise OSError('promotion database copied before head')
        with patch.object(updates, '_replace_current', side_effect=crash):
            with self.assertRaises(OSError):
                self.call(boot.commit_candidate, health=self.health())
        promotion = boot._current(self.stage)[1]
        copied = (self.state / 'aide.db.gz').read_bytes()
        self.finish_later_boot()
        history = self.fold_verified_history()
        self.assertEqual([row['plan']['phase'] for row in history['history']], ['arm', 'postboot', 'commit', 'resume'])
        self.assertFalse(boot._result_path(self.stage, promotion).exists())
        self.assertTrue(any(path.read_bytes() == copied for path in (self.state / 'authorized/artifacts').glob('*.db.gz')))

    def test_changed_skipped_predecessor_cannot_authorize_a_reducer_bridge(self):
        def stop(action, *_):
            if action == 'update': raise OSError('arm scan interrupted')
        self.scan_hook = stop
        with self.assertRaises(OSError): self.call(boot.arm_candidate)
        arm = boot._current(self.stage)[1]
        self.scan_hook = None
        self.new_boot()
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        history = updates.accepted_plan_history(manager=self.manager)
        before = (self.state / 'aide.db.gz').read_bytes()
        path = self.stage / ('kernel-boot-' + arm['id'] + '-plan.json')
        changed = copy.deepcopy(arm)
        changed['running_kernel'] = native_fixture.NEW
        changed['manifest_sha256'] = core.digest({key: value for key, value in changed.items() if key != 'manifest_sha256'})
        path.write_bytes(core.kernel.encode(changed))
        with self.assertRaises(Refused):
            core._fold(self.initial_snapshot, history['history'], self.identity)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)

    def retention_reducer_origin(self):
        self.retention_origin()
        # The existing native fixture uses symbolic exact four/three-set
        # inventories and a private file in place of an old /boot artifact.
        # Preserve those host inputs while keeping compound and AIDE proofs real.
        self.initial_snapshot['inventory'] = ['after']
        self.original_retention['before_inventory'] = ['after']
        self.original_retention['after_inventory'] = ['retained-exact']
        self.initial_snapshot['artifacts'][str(self.retired)] = copy.deepcopy(
            self.original_retention['removed'][str(self.retired)])
        def retained_plan(stage, checksum):
            self.assertEqual(stage, self.stage)
            if checksum != self.original_sha:
                raise Refused('fixture_retention_manifest_changed')
            return self.original_retention, self.original_sha
        from nebulalog_manager import kernel_retention
        context = patch.object(kernel_retention, 'load_plan_by_checksum', side_effect=retained_plan)
        context.start()
        self.addCleanup(context.stop)
        context = patch.object(core.native, 'ROOTS', (*core.native.ROOTS, str(self.retired)))
        context.start()
        self.addCleanup(context.stop)

    def assert_folded_retention(self):
        history = self.fold_verified_history()
        state, _, _ = core._fold(self.initial_snapshot, history['history'], self.identity)
        self.assertEqual(state['inventory'], ['retained-exact'])
        self.assertNotIn(str(self.retired), state['artifacts'])
        return history

    def test_accepted_compound_retention_reduces_exact_boot_and_erase_history(self):
        self.retention_reducer_origin()
        path, plan, observation = self.compound_after_boot()
        self.finish_compound(path, plan, observation)
        history = self.assert_folded_retention()
        self.assertEqual(history['history'][-1]['plan']['kind'], 'rocky-kernel-retention-resume-v1')

    def test_later_compound_boot_can_bridge_an_unprepared_observation(self):
        self.retention_reducer_origin()
        first_path, first, first_observation = self.compound_after_boot()
        self.assertFalse((self.stage / ('kernel-retention-resume-' + first['id'] + '-result.json')).exists())
        path, plan, observation = self.compound_after_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        self.finish_compound(path, plan, observation)
        self.assert_folded_retention()
        self.assertFalse(boot._result_path(self.stage, first_observation).exists())
        self.assertNotEqual(path, first_path)


if __name__ == '__main__':
    __import__('unittest').main()
