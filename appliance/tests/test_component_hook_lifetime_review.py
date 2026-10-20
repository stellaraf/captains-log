"""Independent component lifetime tests using inert processes and real journals.

These fixtures never invoke native services, databases, containers or guest tools.
Manager cases retain real signed releases, dispatch guards and filesystem state;
only the existing host-runtime receipt producer is injected.
"""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from nebulalog_manager import host_dispatch as dispatch, host_payload as payload, os_updates, updates
from nebulalog_manager.common import CommandFailed, Refused, atomic_json, locked
from nebulalog_adapters.commands import Commands
from nebulalog_adapters.lifecycle import Lifecycle
from nebulalog_adapters import host_runtime
from nebulalog_adapters import lifecycle as lifecycle_module
from test_host_updates import HostUpdateFixture, PowerLoss


class HookJournalReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stage = self.root / 'manager/updates/releases/1-fixture'
        self.stage.mkdir(parents=True, mode=0o700)
        self.manifest = {'product': 'nebulalog', 'sequence': 1, 'components': {}}
        raw = payload.encoded(self.manifest)
        (self.stage / 'manifest.json').write_bytes(raw)
        self.transaction = {'hook_protocol': 1, 'sequence': 1, 'release': str(self.stage),
            'manifest_sha256': payload.digest(raw), 'state': 'preflight',
            'previous': {'sequence': 0, 'components': {}}, 'host_coordinator': None}
        atomic_json(self.stage.parent.parent / 'transaction.json', self.transaction)
        self.journal = dispatch.HookJournal(self.stage, self.transaction)

    def test_success_json_does_not_resolve_unacknowledged_native_command(self):
        ref = self.journal.begin('update-backup', {'fixture': 'inert'})
        self.assertEqual(self.journal.enter('update-backup'), ref)
        self.journal.command_event(ref, 'dispatch', 'call', argv=['fixture-no-effect'])
        with self.assertRaisesRegex(Refused, 'acknowledgement'):
            self.journal.finish(ref, 'success', result={'ok': True})
        with self.assertRaisesRegex(Refused, 'acknowledgement'):
            self.journal.successful_result(ref, {'ok': True})
        self.assertFalse(self.journal._path(ref['id'], 'terminal').exists())

    def test_terminal_cannot_be_reused_for_new_result_or_entered_twice(self):
        ref = self.journal.begin('update-preflight', {'fixture': 'inert'})
        self.journal.enter('update-preflight')
        with self.assertRaisesRegex(Refused, 'already entered'):
            self.journal.enter('update-preflight')
        result = {'ok': True, 'fixture': 'exact-result'}
        self.journal.finish(ref, 'success', result=result)
        self.journal.successful_result(ref, result)
        with self.assertRaisesRegex(Refused, 'exact successful'):
            self.journal.successful_result(ref, {'ok': True, 'fixture': 'replacement'})
        with self.assertRaises(Refused):
            self.journal.command_event(ref, 'dispatch', 'call', argv=['fixture-no-effect'])

    def test_terminal_is_bound_to_original_coordinator_and_previous_release(self):
        ref = self.journal.begin('update-preflight', {'fixture': 'inert'})
        self.journal.enter('update-preflight')
        self.journal.finish(ref, 'failed')
        self.assertEqual(self.journal.assert_settled(), 1)
        for key, changed in [('host_coordinator', {'generation': 'a' * 64}),
                             ('previous', {'sequence': 0, 'components': {'x': 'new'}})]:
            with self.subTest(key=key):
                altered = dict(self.transaction, **{key: changed})
                with self.assertRaisesRegex(Refused, 'another operation'):
                    dispatch.HookJournal(self.stage, altered).assert_settled()

    def test_only_exact_normal_readiness_failure_can_be_acknowledged(self):
        for index, (argv, returncode, allowed) in enumerate([
                (dispatch.HookJournal.POSTGRES_READY, 2, True),
                (dispatch.HookJournal.POSTGRES_READY, -signal.SIGKILL, False),
                (dispatch.HookJournal.POSTGRES_READY, 137, False),
                ([*dispatch.HookJournal.POSTGRES_READY[:-1], 'SELECT 1; SELECT 2'], 2, False),
                (['podman', 'exec', 'fixture', 'pg_restore'], 1, False)]):
            with self.subTest(argv=argv, returncode=returncode):
                stage = self.stage.parent / ('1-case-' + str(index))
                stage.mkdir(mode=0o700)
                (stage / 'manifest.json').write_bytes((self.stage / 'manifest.json').read_bytes())
                journal = dispatch.HookJournal(stage, dict(self.transaction, release=str(stage)))
                ref = journal.begin('update-backup', {'fixture': 'probe classification'})
                journal.enter('update-backup')
                ticket = journal.command_event(ref, 'dispatch', 'call', argv=argv)
                journal.command_event(ref, 'failed', 'call', ticket=ticket, returncode=returncode)
                if allowed:
                    journal.finish(ref, 'failed')
                    self.assertEqual(journal.assert_settled(), 1)
                else:
                    with self.assertRaisesRegex(Refused, 'acknowledgement'):
                        journal.finish(ref, 'failed')
                    self.assertFalse(journal._path(ref['id'], 'terminal').exists())

    def test_os_admission_refuses_unknown_component_before_new_journal_or_probe(self):
        self.journal.begin('update-backup', {'fixture': 'unknown component executor'})
        manager = self.stage.parent.parent.parent
        policy = manager / 'maintenance-policy.json'
        atomic_json(policy, {'automatic_os_updates': True, 'timezone': 'UTC'})
        for state in ('preflight_failed', 'committed', 'rolled_back'):
            with self.subTest(state=state):
                atomic_json(self.stage.parent.parent / 'transaction.json',
                            dict(self.transaction, state=state, finalization='complete'))
                with patch.object(os_updates, 'in_maintenance_window', return_value=True), \
                     patch.object(os_updates, 'status', side_effect=AssertionError('must not probe')) as probe:
                    with self.assertRaisesRegex(Refused, 'unresolved'):
                        os_updates.maintain(policy, manager,
                            runner=lambda *args, **kwargs: self.fail('must not invoke OS command'))
                probe.assert_not_called()
                self.assertFalse((manager / 'os-transaction.json').exists())

    def host_integrity_fixture(self):
        manager = Lifecycle({}, Commands(), data=self.root,
            state=self.stage.parent.parent, guard=lambda: None)
        manager.release = lambda stage: ({'components': {}}, self.transaction)
        host = object.__new__(host_runtime.HostRuntime)
        host.lifecycle, host.stage = manager, self.stage
        host.plan_path = self.stage / 'host-runtime-plan.json'
        manager.preflight = lambda stage: host.integrity('prepare')
        ref = self.journal.begin('update-preflight', {'fixture': 'fixed host integrity wrapper'})
        return manager, host, ref

    def test_host_aide_helper_is_fenced_before_its_native_boundary(self):
        manager, host, ref = self.host_integrity_fixture()
        seen = []
        def interrupted(stage, plan):
            seen.append((stage, plan))
            with self.assertRaisesRegex(Refused, 'acknowledgement'):
                self.journal.assert_settled(allow=ref)
            raise Refused('injected AIDE timeout or unknown child outcome')
        with patch.object(host_runtime.aide, 'Aide') as factory:
            factory.return_value.authorized_update_prepare.side_effect = interrupted
            with self.assertRaisesRegex(Refused, 'acknowledgement'):
                manager.component_hook('update-preflight', self.stage)
        self.assertEqual(seen, [(self.stage, host.plan_path)])
        self.assertFalse(self.journal._path(ref['id'], 'terminal').exists())
        self.assertEqual(len(list(self.stage.glob('component-command-*-intent.json'))), 1)
        self.assertEqual(list(self.stage.glob('component-command-*-complete.json')), [])

    def test_host_aide_success_validates_result_before_compound_ack(self):
        manager, host, ref = self.host_integrity_fixture()
        result = {'ok': True, 'fixture': 'accepted by typed AIDE boundary'}
        with patch.object(host_runtime.aide, 'Aide') as factory:
            factory.return_value.authorized_update_prepare.return_value = result
            self.assertEqual(manager.component_hook('update-preflight', self.stage), result)
            factory.return_value.authorized_update_prepare.assert_called_once_with(self.stage, host.plan_path)
        self.journal.successful_result(ref, result)
        self.assertEqual(len(list(self.stage.glob('component-command-*-complete.json'))), 1)

    def test_host_aide_malformed_result_cannot_acknowledge_compound(self):
        manager, _, ref = self.host_integrity_fixture()
        with patch.object(host_runtime.aide, 'Aide') as factory:
            factory.return_value.authorized_update_prepare.return_value = {'ok': 1}
            with self.assertRaisesRegex(Refused, 'acknowledgement'):
                manager.component_hook('update-preflight', self.stage)
        self.assertFalse(self.journal._path(ref['id'], 'terminal').exists())
        self.assertEqual(list(self.stage.glob('component-command-*-complete.json')), [])

    def test_actual_compliance_runner_only_settles_valid_completed_findings(self):
        profile = 'xccdf_fixture_profile_cis'
        def private_directory(value, create=False):
            # Only the private fixture root substitutes for production's trusted
            # filesystem ancestry; XML parsing, policy hashes and records remain real.
            value = Path(value)
            if create: value.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.assertTrue(value.is_relative_to(self.root))
            for path in (value, *value.parents):
                info = path.lstat()
                self.assertTrue(stat.S_ISDIR(info.st_mode))
                self.assertEqual(info.st_uid, os.geteuid())
                self.assertFalse(info.st_mode & 0o022)
                if path == self.root: break
            return value
        directory_boundary = patch('nebulalog_manager.baseline._directory', side_effect=private_directory)
        directory_boundary.start()
        self.addCleanup(directory_boundary.stop)
        for label in ('findings', 'historical-sources', 'timeout', 'signal', 'other-returncode',
                      'malformed', 'wrong-profile', 'incomplete', 'changed-datastream', 'changed-tailoring'):
            with self.subTest(case=label):
                stage = self.stage.parent / ('1-scap-' + label)
                stage.mkdir(mode=0o700)
                (stage / 'manifest.json').write_bytes((self.stage / 'manifest.json').read_bytes())
                tx = dict(self.transaction, release=str(stage), state='checking')
                journal = dispatch.HookJournal(stage, tx)
                source = stage / 'fixture-datastream.xml'
                source.write_text('<Benchmark/>')
                tailoring = stage / 'fixture-tailoring.xml'
                tailoring.write_text('<Tailoring/>')
                configuration = stage / 'configuration'
                configuration.mkdir(mode=0o700)
                atomic_json(configuration / 'security-policy.json', {'schema': 1, 'baseline': 'cis-level2',
                    'assessments': [{'kind': 'cis', 'profile_id': profile, 'platform': 'rocky9',
                        'reviewed': True, 'datastream': str(source), 'sha256': payload.digest(source.read_bytes()),
                        'tailoring': str(tailoring), 'tailoring_sha256': payload.digest(tailoring.read_bytes())}]})
                manager = Lifecycle({}, Commands(), data=self.root,
                    state=stage.parent.parent, configuration=configuration, guard=lambda: None)
                manager.release = lambda selected, value=tx: ({'components': {}}, value)
                context = {'installation_id': 'fixture', 'baseline': 'cis-level2',
                    'policy_sha256': payload.digest((configuration / 'security-policy.json').read_bytes())}
                manager._compliance_context = lambda value=context: value
                manager.health = lambda selected: manager.compliance(selected)
                ref = journal.begin('update-health', {'fixture': 'fixed compliance runner'})
                class FakeScanBoundary:
                    def __init__(self, directory, *, runner):
                        self.directory, self.runner = directory, runner
                        self.policy_path = directory / 'security-policy.json'
                    def scan(self, installation_id, baseline):
                        output = self.directory / 'baseline-assessments/fixture'
                        output.mkdir(parents=True, mode=0o700)
                        argv = ['oscap', 'xccdf', 'eval', '--profile', profile,
                            '--results', str(output / 'cis.xml'), '--report', str(output / 'cis.html'),
                            '--tailoring-file', str(tailoring), str(source)]
                        try:
                            self.runner(argv, timeout=900)
                        except CommandFailed as error:
                            if error.returncode == 2:
                                raise Refused('fixture health findings require review') from error
                            raise
                        raise AssertionError('fixture requires nonzero scan result')
                def native(argv, **kwargs):
                    # The real Commands observer must have persisted intent
                    # before this injected native syscall boundary is reached.
                    with self.assertRaisesRegex(Refused, 'acknowledgement'):
                        journal.assert_settled(allow=ref)
                    xml = Path(argv[argv.index('--results') + 1])
                    html = Path(argv[argv.index('--report') + 1])
                    selected = 'xccdf_other' if label == 'wrong-profile' else profile
                    end = '' if label == 'incomplete' else ' end-time="2026-10-15T01:00:01Z"'
                    raw = ('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">'
                        '<TestResult id="fixture" start-time="2026-10-15T01:00:00Z"' + end + '>'
                        '<profile idref="' + selected + '"/><rule-result idref="xccdf_fixture_rule">'
                        '<result>fail</result></rule-result></TestResult></Benchmark>')
                    xml.write_text('<broken' if label == 'malformed' else raw)
                    html.write_text('<html>fixture findings</html>')
                    if label == 'timeout': raise subprocess.TimeoutExpired(argv, 900)
                    if label == 'changed-datastream': source.write_text('<Benchmark changed="true"/>')
                    if label == 'changed-tailoring': tailoring.write_text('<Tailoring changed="true"/>')
                    code = -9 if label == 'signal' else 1 if label == 'other-returncode' else 2
                    return SimpleNamespace(returncode=code, stdout=b'')
                with patch.object(lifecycle_module, 'Baseline', FakeScanBoundary), \
                     patch('nebulalog_adapters.commands.subprocess.run', side_effect=native):
                    known = label in ('findings', 'historical-sources')
                    expected = 'health findings' if known else 'acknowledgement'
                    with self.assertRaisesRegex(Refused, expected):
                        manager.component_hook('update-health', stage)
                terminal = journal._path(ref['id'], 'terminal')
                if known:
                    self.assertEqual(journal.assert_settled(), 1)
                    self.assertEqual(json.loads(terminal.read_text())['outcome'], 'failed')
                    if label == 'historical-sources':
                        source.write_text('<Benchmark later-authorized-version="true"/>')
                        tailoring.write_text('<Tailoring later-authorized-version="true"/>')
                        self.assertEqual(journal.assert_settled(), 1)
                    html = next(stage.glob('compliance-*/baseline-assessments/fixture/cis.html'))
                    html.write_text('<html>changed evidence</html>')
                    with self.assertRaises(Refused): journal.assert_settled()
                else:
                    self.assertFalse(terminal.exists())
                    self.assertEqual(list(stage.glob('component-command-*-complete.json')), [])

    def test_parent_sigkill_releases_lock_but_live_child_keeps_journal_unresolved(self):
        ready, release, effect = (self.root / name for name in ('ready.json', 'release', 'effect'))
        transaction_path = self.stage.parent.parent / 'transaction.json'
        module_root = str(Path(dispatch.__file__).resolve().parents[1])
        child_code = """
import json, os, pathlib, sys, time
sys.path.insert(0, sys.argv[1])
from nebulalog_manager.host_dispatch import HookJournal
stage, transaction, ready, release, effect = map(pathlib.Path, sys.argv[2:])
journal = HookJournal(stage, json.loads(transaction.read_text()))
ref = journal.enter('update-backup')
ticket = journal.command_event(ref, 'dispatch', 'call', argv=['private-inert-effect'])
pending = ready.with_suffix('.pending')
pending.write_text(json.dumps({'pid': os.getpid(), 'sid': os.getsid(0)}))
pending.replace(ready)
while not release.exists(): time.sleep(.01)
effect.write_text('private effect after manager termination')
journal.command_event(ref, 'complete', 'call', ticket=ticket)
journal.finish(ref, 'success', result={'ok': True})
print('{"ok":true}', flush=True)
"""
        child_args = [sys.executable, '-c', child_code, module_root, str(self.stage),
                      str(transaction_path), str(ready), str(release), str(effect)]
        parent_code = """
import json, pathlib, sys
sys.path.insert(0, sys.argv[1])
from nebulalog_manager.host_dispatch import HookJournal, _run_bounded
from nebulalog_manager.common import locked
stage, transaction, lock = map(pathlib.Path, sys.argv[2:5])
with locked(lock):
    journal = HookJournal(stage, json.loads(transaction.read_text()))
    journal.begin('update-backup', {'fixture': 'private inert subprocess'})
    _run_bounded(json.loads(sys.argv[5]))
"""
        lock_path = self.root / 'manager/transaction.lock'
        process = subprocess.Popen([sys.executable, '-c', parent_code, module_root, str(self.stage),
            str(transaction_path), str(lock_path), json.dumps(child_args)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child_pid = None
        try:
            deadline = time.monotonic() + 15
            while not ready.exists() and time.monotonic() < deadline and process.poll() is None:
                time.sleep(.02)
            if not ready.exists():
                self.fail('Inert child did not enter durable hook: ' + repr(process.communicate(timeout=2)))
            identity = json.loads(ready.read_text()); child_pid = identity['pid']
            self.assertEqual(identity['sid'], child_pid)
            process.kill(); self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)
            with locked(lock_path):
                os.kill(child_pid, 0)
                with self.assertRaisesRegex(Refused, 'acknowledgement'):
                    self.journal.assert_settled()
                self.assertFalse(effect.exists())
                release.write_text('allow only private inert effect')
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        self.journal.assert_settled()
                        break
                    except Refused:
                        time.sleep(.02)
                self.assertTrue(effect.exists())
                self.assertEqual(self.journal.assert_settled(), 1)
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
            if child_pid is not None:
                try: os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError: pass
            if process.stdout: process.stdout.close()
            if process.stderr: process.stderr.close()


class ComponentManagerLifetimeReviewTests(HostUpdateFixture):
    def test_unknown_backup_stops_recovery_before_restore_or_new_hook(self):
        self.crash = 'update-backup'
        with self.assertRaises(PowerLoss): self.install()
        calls = list(self.calls)
        stage = self.retained()
        journal_before = (self.state / 'transaction.json').read_bytes()
        with patch.object(self.manager, '_restore_host', side_effect=AssertionError('must not restore')) as restore:
            with self.assertRaisesRegex(Refused, 'unresolved'):
                self.manager.recover(self.public)
        restore.assert_not_called()
        self.assertEqual(self.calls, calls)
        self.assertEqual((self.state / 'transaction.json').read_bytes(), journal_before)
        self.assertTrue(self.manager.status()['hook_outcome_unsettled'])
        self.assertFalse((stage / 'adapter-activate.json').exists())

    def test_unresolved_preflight_failed_cannot_be_replaced_by_another_install(self):
        self.crash = 'update-preflight'
        with self.assertRaises(PowerLoss): self.install()
        transaction = self.manager.status()['transaction']
        transaction['state'] = 'preflight_failed'
        atomic_json(self.state / 'transaction.json', transaction)
        raw = (self.state / 'transaction.json').read_bytes()
        stages = sorted(p.name for p in (self.state / 'releases').iterdir())
        calls = list(self.calls)
        self.crash = None
        with self.assertRaisesRegex(Refused, 'unresolved'):
            self.install()
        self.assertEqual((self.state / 'transaction.json').read_bytes(), raw)
        self.assertEqual(sorted(p.name for p in (self.state / 'releases').iterdir()), stages)
        self.assertEqual(self.calls, calls)
        self.assertEqual(self.manager.status()['current'], self.initial)

    def test_unresolved_finalize_cannot_run_fresh_health_or_release_gate(self):
        self.crash = 'update-finalize'
        with self.assertRaises(PowerLoss): self.install()
        calls = list(self.calls)
        transaction = self.manager.status()['transaction']
        self.assertEqual(transaction['state'], 'committed')
        self.assertTrue(self.maintenance.exists())
        with self.assertRaisesRegex(Refused, 'unresolved'):
            self.manager.finalize(self.public)
        self.assertEqual(self.calls, calls)
        self.assertTrue(self.maintenance.exists())
        self.assertEqual(self.manager.status()['transaction'], transaction)

    def test_parent_visible_success_without_adapter_terminal_stays_held(self):
        with patch.object(dispatch, 'run_hook', return_value={'ok': True}) as hook:
            with self.assertRaisesRegex(Refused, 'unresolved'):
                self.install()
        self.assertEqual(hook.call_count, 1)
        state = self.manager.status()
        self.assertEqual(state['transaction']['state'], 'recovery_required')
        self.assertTrue(state['hook_outcome_unsettled'])
        self.assertEqual(state['current'], self.initial)
        with patch.object(self.manager, '_restore_host', side_effect=AssertionError('must not restore')) as restore:
            with self.assertRaisesRegex(Refused, 'unresolved'):
                self.manager.recover(self.public)
        restore.assert_not_called()

    def test_completed_health_failure_still_permits_known_rollback(self):
        self.fail_evidence = 'update-health'
        with self.assertRaises(Refused): self.install()
        status = self.manager.status()
        self.assertEqual(status['transaction']['state'], 'rolled_back')
        self.assertEqual(status['transaction']['finalization'], 'complete')
        self.assertFalse(status['hook_outcome_unsettled'])
        self.assertFalse(self.maintenance.exists())
        self.assertEqual(status['current']['components'], self.initial['components'])
        self.assertIn('update-rollback', [name for name, _, _ in self.calls])

    def test_legacy_complete_bridge_cannot_ignore_new_unresolved_hook_evidence(self):
        self.install()
        transaction = self.manager.status()['transaction']
        stage = Path(transaction['release'])
        dispatch.HookJournal(stage, transaction).begin('update-finalize', {'fixture': 'unknown late dispatch'})
        transaction.pop('hook_protocol')
        atomic_json(self.state / 'transaction.json', transaction)
        calls = list(self.calls)
        with self.assertRaises(Refused):
            self.manager.finalize(self.public)
        self.assertEqual(self.calls, calls)
        self.assertTrue(self.manager.status()['hook_outcome_unsettled'])

    def test_unknown_schema_transport_stays_held_before_restore_or_fencing_hook(self):
        self.crash = 'update-activate'
        with self.assertRaises(PowerLoss): self.install()
        transaction = self.manager.status()['transaction']
        stage = Path(transaction['release'])
        journal = dispatch.HookJournal(stage, transaction)
        pending = [(intent, ref) for intent, ref in journal._intents().values()
                   if intent['name'] == 'update-activate']
        self.assertEqual(len(pending), 1)
        ref = pending[0][1]
        journal.command_event(ref, 'dispatch', 'call', argv=[
            'systemd-run', '--unit=private-migration-fixture', '--wait', '--',
            'podman', 'start', '--attach', '--interactive', 'fixture-client'])
        schema_intent = stage / 'adapter-application-schema-intent.json'
        atomic_json(schema_intent, {'fixture': 'retained executor evidence, not recovery authorization'})
        evidence = schema_intent.read_bytes()
        calls = list(self.calls)
        with patch.object(self.manager, '_restore_host', side_effect=AssertionError('must not restore')) as restore:
            with self.assertRaisesRegex(Refused, 'acknowledgement'):
                self.manager.recover(self.public)
        restore.assert_not_called()
        self.assertEqual(self.calls, calls)
        self.assertEqual(schema_intent.read_bytes(), evidence)
        self.assertTrue(self.maintenance.exists())
        self.assertFalse((stage / 'adapter-application-schema-fence.json').exists())

    def test_genuine_legacy_complete_history_allows_new_install_admission(self):
        self.install()
        transaction = self.manager.status()['transaction']
        stage = Path(transaction['release'])
        # Reconstruct an actual pre-protocol completed fixture. No running hook
        # exists; retaining any new-protocol record is tested separately above.
        transaction.pop('hook_protocol')
        for path in stage.glob('component-hook-*'): path.unlink()
        for path in stage.glob('component-command-*'): path.unlink()
        atomic_json(self.state / 'transaction.json', transaction)
        before = (self.state / 'transaction.json').read_bytes()
        original_verify = updates.verify_release
        observed = []
        def verify(path, *args, **kwargs):
            if path == self.bundle / 'manifest.json':
                observed.append('new candidate admitted')
                raise Refused('fixture stops at new candidate verification')
            observed.append('retained signature verified')
            return original_verify(path, *args, **kwargs)
        with patch.object(updates, 'verify_release', side_effect=verify):
            with self.assertRaisesRegex(Refused, 'new candidate verification'):
                self.install()
        self.assertEqual(observed, ['retained signature verified', 'new candidate admitted'])
        self.assertEqual((self.state / 'transaction.json').read_bytes(), before)
        self.assertFalse(self.manager.status()['hook_outcome_unsettled'])


if __name__ == '__main__':
    unittest.main()
