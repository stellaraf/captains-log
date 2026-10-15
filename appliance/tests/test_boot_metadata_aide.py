"""Actual AIDE transaction/chain/CAS plumbing with strict vendor-format fixtures.

Only native host measurements, storage identity and the AIDE command boundary
are injected. Ordinary generation ownership, metadata proof/parser/lineage,
report filtering, archived DBs, scans, and acceptance/CAS remain production code.
This is source integration evidence, not native scanner or appliance acceptance.
"""
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from nebulalog_manager import aide, aide_updates as updates, ordinary_boot as core
from nebulalog_manager import boot_metadata_native as native, ordinary_boot_metadata as database
from nebulalog_manager import boot_metadata_proof as proof
from nebulalog_manager.common import Refused, locked, atomic_json
from nebulalog_manager.host_job_storage import digest
import test_aide_lifecycle as baseline
import test_ordinary_boot_aide as ordinary_fixture
import test_ordinary_boot_metadata as db_fixture
import test_boot_metadata_native as native_fixture
from test_ordinary_boot_state import fixture_v2
import test_kernel_boot_aide as kernel_integration
import test_kernel_boot as kernel_fixture
from nebulalog_manager import kernel_boot as boot, kernel_retention as retention


class MetadataAideTests(unittest.TestCase):
    for _name in ('write_private', 'reader', 'facts', 'monitor', 'fresh', 'run_fixture', 'enrolled'):
        locals()[_name] = getattr(baseline.AideLifecycleTests, _name)
    for _name in ('capture', 'original_snapshot', 'pending', 'reconcile', 'interrupt'):
        locals()[_name] = getattr(ordinary_fixture.OrdinaryAideTests, _name)

    def setUp(self):
        baseline.AideLifecycleTests.setUp(self)
        self.owner = self.root / 'manager/boot-integrity'
        self.owner.mkdir(parents=True, mode=0o700); self.owner.parent.chmod(0o700)
        self.env = self.root / 'private-grubenv'
        self.initial = fixture_v2(); self.initial['boot_id'] = native_fixture.OLD_BOOT
        self.current_rows = {path: db_fixture.fixture_row(path) for path in sorted(database.TARGETS)}
        self.boot_generation = 0
        self.native_current = native_fixture.fixture()[1]; self.native_current['boot_id'] = self.initial['boot_id']
        self.refresh_native()
        # Keep both injected native readers internally consistent on the18 files.
        for path, row in self.native_current['rows'].items():
            item = {'kind': row['kind'], 'uid': row['uid'], 'gid': row['gid'], 'mode': row['mode'],
                    'xattrs_sha256': digest({name: hashlib.sha256(base64.b64decode(raw)).hexdigest()
                                             for name, raw in row['xattrs'].items()})}
            if row['kind'] == 'file': item.update(bytes=row['bytes'], sha256=hashlib.sha256(b'fixture').hexdigest())
            else: item.update(target=row['target'])
            self.initial['artifacts'][path] = item
        self.observed = copy.deepcopy(self.initial)
        self.write_private(self.env, base64.b64decode(self.initial['grub']['raw']))
        self.scan_calls, self.scan_hook, self.report_hook, self.output_hook = [], None, None, None
        self.manager.runner = self.scan_runner
        self.metadata = {'xattrs_sha256': 'a' * 64, 'acl_sha256': 'b' * 64, 'selinux_sha256': 'c' * 64}
        for context in (
                patch.object(updates, '_metadata', side_effect=lambda path: dict(self.metadata)),
                patch.object(core.native, 'ENV', str(self.env)),
                patch.object(core.native, 'capture', side_effect=self.capture),
                patch.object(native, 'capture', side_effect=lambda: copy.deepcopy(self.native_current)),
                patch.object(core.rpm, 'read', side_effect=lambda path, maximum=core.rpm.MAX_XML: self.reader(path, maximum=maximum)),
                patch.object(core.aide, 'verify_initial_boot_snapshot', side_effect=self.original_snapshot)):
            context.start(); self.addCleanup(context.stop)
        self.values['ordinary_boot_snapshot_sha256'] = core.rpm.sha(core.kernel.encode(self.initial))
        self.boot_snapshot.side_effect = self.original_snapshot
        self.write_private(self.owner / 'initial.json', core.kernel.encode(self.initial))
        _, self.base = self.enrolled()
        self.initial_db = (self.state / 'aide.db.gz').read_bytes()
        self.original = {path: path.read_bytes() for path in
                         (self.marker, self.state / 'candidate.json', self.state / 'candidate.db.gz', self.state / 'commit-pending.json')}

    def current_database(self):
        return db_fixture.compressed(db_fixture.text_database([self.current_rows[path] for path in sorted(self.current_rows)]))

    def refresh_native(self):
        parsed = database.parse_database(self.current_database(), expected_sha256=hashlib.sha256(self.current_database()).hexdigest())
        self.native_current['rows'] = copy.deepcopy(parsed['rows'])
        for path, row in self.native_current['rows'].items():
            row['ctime_ns'] = row['ctime_s'] * 1_000_000_000 + (500_000_000 if self.boot_generation and path in database.TMPFILES else 0)
            row['mtime_ns'] = row['mtime_s'] * 1_000_000_000
        if self.boot_generation:
            start = 1760000000 + self.boot_generation * 100
            self.native_current['service'].update(start_us=start * 1_000_000, end_us=(start + 1) * 1_000_000)
            self.native_current['observed_at_ns'] = (start + 100) * 1_000_000_000
        native.validate_snapshot(self.native_current)

    def reboot(self, boot_id=native_fixture.NEW_BOOT, *, drift=True):
        self.observed['boot_id'] = self.native_current['boot_id'] = boot_id
        self.boot_generation += 1
        if drift:
            for path in database.TMPFILES:
                self.current_rows[path]['ctime'] = str(1760000000 + self.boot_generation * 100)
            for path in database.EFI:
                self.current_rows[path]['inode'] = str(int(self.current_rows[path]['inode']) + 1)
        self.refresh_native()

    @staticmethod
    def summary(path, old, new):
        # These summaries are emitted by the scanner boundary, not the proof.
        changed = {key for key in old if old[key] != new[key]}
        markers = {'bytes': (2, '>'), 'ctime_s': (9, 'c'), 'mtime_s': (8, 'm'),
                   'inode': (10, 'i'), 'sha512': (12, 'H')}
        if not changed <= set(markers): raise AssertionError('unmodeled fixture attribute change')
        bits = (35, 1, 5, 10, 2, 3, 4, 6, 8, 7, 9, 11, 31, 21, 33, 32, 36, 37)
        result = list(''.join(('=' if index == 2 else '.') if old['attributes'] & (1 << bit) else ' '
                              for index, bit in enumerate(bits)))
        result[0] = 'l' if path == '/etc/os-release' else 'f'
        for key in changed:
            offset, character = markers[key]; result[offset] = character
        return ''.join(result)

    def scanner_rows(self, raw):
        return database.parse_database(raw, expected_sha256=hashlib.sha256(raw).hexdigest())['rows']

    def scan_runner(self, argv, *, tmpdir, **kwargs):
        self.assertEqual(Path(tmpdir), self.state / 'tmp')
        if argv[0] == '/usr/sbin/restorecon': return aide.Result(0)
        self.assertEqual(argv[0], '/usr/sbin/aide')
        config = Path(argv[1].split('=', 1)[1])
        self.assertTrue(config.is_relative_to(self.state))
        options = dict(line.split('=', 1) for line in config.read_text().splitlines() if '=' in line and not line.startswith('#'))
        source, output = [Path(options[key].removeprefix('file:')) for key in ('database_in', 'database_out')]
        self.assertTrue(source.is_relative_to(self.state)); self.assertTrue(output.is_relative_to(self.state))
        action = argv[-1].removeprefix('--')
        if action == 'config-check': return aide.Result(0)
        self.assertIn(action, {'init', 'update', 'check'}); self.scan_calls.append(action)
        raw = self.current_database()
        current = self.scanner_rows(raw)
        old_raw = b'' if action == 'init' else source.read_bytes()
        old = {} if action == 'init' else self.scanner_rows(old_raw)
        added, removed = current.keys() - old.keys(), old.keys() - current.keys()
        changed = {path for path in current.keys() & old.keys() if current[path] != old[path]}
        code = 0 if action == 'init' else int(bool(added)) + 2 * int(bool(removed)) + 4 * int(bool(changed))
        report = {'aide_version': '0.19.2', 'start_time': self.now, 'end_time': self.now, 'run_time_seconds': 0,
                  'outline': 'Strict native DB private scanner fixture', 'number_of_entries': {'total': len(current)},
                  'databases': {str(output if action == 'init' else source): {'sha512': hashlib.sha512(raw if action == 'init' else old_raw).hexdigest()}}}
        if action != 'init':
            report['number_of_entries'].update(added=len(added), removed=len(removed), changed=len(changed))
            if added: report['added'] = {path: ('l' if current[path]['kind'] == 'symlink' else 'f') + '+' * 17 for path in sorted(added)}
            if removed: report['removed'] = {path: ('l' if old[path]['kind'] == 'symlink' else 'f') + '-' * 17 for path in sorted(removed)}
            if changed: report['changed'] = {path: self.summary(path, old[path], current[path]) for path in sorted(changed)}
        if action in {'init', 'update'}:
            self.assertFalse(output.exists(), 'never overwrite retained DB output')
            if self.output_hook: raw = self.output_hook(action, raw)
            self.write_private(output, raw)
            report['new_database'] = str(output)
            report['databases'][str(output)] = {'sha512': hashlib.sha512(raw).hexdigest()}
        if self.report_hook:
            replacement_code = self.report_hook(action, report)
            if replacement_code is not None: code = replacement_code
        if self.scan_hook: self.scan_hook(action, source, output)
        return aide.Result(code, json.dumps(report))

    def complete(self, stage):
        result = self.reconcile(stage)
        health = {'ok': True, 'stage': str(stage), 'boot_id': self.observed['boot_id'],
                  'checks': {key: True for key in core.REQUIRED_CHECKS}}
        core.finalize(stage, health, manager=self.manager)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertIsNone(self.pending())
        self.assertEqual(self.scan_calls.count('init'), 1)
        for path, raw in self.original.items(): self.assertEqual(path.read_bytes(), raw)
        return result

    def test_actual_ordinary_ownership_records_parser_scans_and_cas_accept_eighteen_changes(self):
        self.assertIsNone(self.pending())
        self.reboot(); stage = self.pending(); self.complete(stage)
        history = updates.accepted_plan_history(manager=self.manager)
        self.assertEqual(len(history['history']), 1)
        value = history['history'][0]['prepared']['metadata'][proof.KEY]
        self.assertEqual(len(value['transition']['changes']), 18)
        self.assertEqual(value['source_boot_id'], native_fixture.OLD_BOOT)
        self.assertEqual(value['after']['boot_id'], native_fixture.NEW_BOOT)
        self.assertNotEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertEqual(database.parse_database((self.state / 'aide.db.gz').read_bytes(),
                         expected_sha256=history['database_sha256'])['rows'],
                         {path: {key: value for key, value in row.items() if not key.endswith('_ns')}
                          for path, row in self.native_current['rows'].items()})

    def test_content_drift_refuses_before_scan_or_cas(self):
        self.reboot(); stage = self.pending()
        self.current_rows['/etc/issue']['sha512'] = base64.b64encode(hashlib.sha512(b'changed').digest()).decode()
        self.refresh_native()
        count = self.scan_calls.count('update')
        with self.assertRaises(Refused): self.reconcile(stage)
        self.assertEqual(self.scan_calls.count('update'), count)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertFalse((self.state / 'authorized/head.json').exists())

    def test_changed_report_summary_refuses_before_cas(self):
        self.reboot(); stage = self.pending()
        def tamper(action, report):
            if action == 'update': report['changed']['/etc/issue'] = 'f = ... .ci.H...  '
        self.report_hook = tamper
        with self.assertRaises(Refused): self.reconcile(stage)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertFalse((self.state / 'authorized/head.json').exists())
        pending = self.manager.records.read(self.state / 'authorized/pending.json', self.identity)
        self.assertEqual(pending['state'], 'scanning')
        self.assertTrue(any(json.loads(path.read_text()).get('action') == 'update' for path in (self.state / 'reports').iterdir()))

    def test_missing_expected_report_exception_refuses_before_cas(self):
        self.reboot(); stage = self.pending()
        def tamper(action, report):
            if action == 'update':
                del report['changed']['/etc/issue']
                report['number_of_entries']['changed'] -= 1
        self.report_hook = tamper
        with self.assertRaises(Refused): self.reconcile(stage)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_actual_output_database_content_not_in_capture_refuses(self):
        self.reboot(); stage = self.pending()
        output = None
        def tamper(action, raw):
            nonlocal output
            if action != 'update': return raw
            rows = copy.deepcopy(self.current_rows)
            rows['/etc/issue']['sha512'] = base64.b64encode(hashlib.sha512(b'tampered-output').digest()).decode()
            output = db_fixture.compressed(db_fixture.text_database([rows[path] for path in sorted(rows)]))
            return output
        self.output_hook = tamper
        with self.assertRaises(Refused): self.reconcile(stage)
        self.assertIsNotNone(output)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_live_boot_change_during_acceptance_recheck_refuses_before_cas(self):
        self.reboot(); stage = self.pending()
        def switched(action, source, output):
            if action == 'update': self.native_current['boot_id'] = '33333333-3333-4333-8333-333333333333'
        self.scan_hook = switched
        with self.assertRaises(Refused): self.reconcile(stage)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertFalse((self.state / 'authorized/head.json').exists())

    def recover_second_boot(self, point, *, middle=False):
        self.reboot(); first = self.pending(); self.interrupt(first, point)
        pending = self.manager.records.read(self.state / 'authorized/pending.json', self.identity)
        self.assertEqual(pending['state'], 'scanning' if point == 'scanning' else 'ready')
        copied = (self.state / 'aide.db.gz').read_bytes()
        self.reboot('33333333-3333-4333-8333-333333333333')
        second = self.pending()
        if middle:
            self.reboot('44444444-4444-4444-8444-444444444444')
            second = self.pending()
        self.assertTrue(core.owns_maintenance(second, str(first)))
        self.complete(second)
        history = updates.accepted_plan_history(manager=self.manager)
        last = history['history'][-1]['prepared']['metadata'][proof.KEY]
        self.assertEqual(last['pending']['prepared'], pending['prepared'])
        self.assertEqual(last['after']['boot_id'], self.native_current['boot_id'])
        self.assertEqual(len(last['transition']['changes']), 18)
        if point == 'ready_output':
            self.assertEqual(last['source_database_sha256'], hashlib.sha256(copied).hexdigest())
            self.assertEqual(last['database_source']['basis'], 'owned-ready-output')
            self.assertEqual(last['source_boot_id'], native_fixture.NEW_BOOT)
            self.assertEqual(len(history['history']), 2)
        else:
            self.assertEqual(last['source_database_sha256'], hashlib.sha256(self.initial_db).hexdigest())
            self.assertEqual(last['source_boot_id'], native_fixture.OLD_BOOT)
        self.assertFalse((first / core.FINAL).exists())

    def test_second_boot_recovers_actual_scanning_interruption(self):
        self.recover_second_boot('scanning')

    def test_second_boot_recovers_actual_ready_input_interruption(self):
        self.recover_second_boot('ready_input')

    def test_second_boot_recovers_actual_ready_output_interruption(self):
        self.recover_second_boot('ready_output')

    def test_third_boot_traverses_unprepared_middle_generation(self):
        self.recover_second_boot('ready_output', middle=True)

    def test_same_boot_ready_output_recovery_does_not_replay_init(self):
        self.reboot(); stage = self.pending(); self.interrupt(stage, 'ready_output')
        self.complete(stage)
        history = updates.accepted_plan_history(manager=self.manager)
        self.assertEqual(len(history['history']), 1)

    def test_retained_proof_tamper_is_rejected_by_actual_chain(self):
        self.reboot(); stage = self.pending(); self.complete(stage)
        history = updates.accepted_plan_history(manager=self.manager)
        prepared = history['history'][0]['prepared']
        path = self.state / 'authorized/prepared' / (prepared['id'] + '.json')
        bad = copy.deepcopy(prepared); bad['metadata'][proof.KEY]['after']['rows']['/etc/issue']['inode'] += 1
        self.manager.records.write(path, bad, self.identity)
        with self.assertRaises(Refused): updates.accepted_plan_history(manager=self.manager)

    def test_next_complete_boot_uses_actual_accepted_output_rows(self):
        self.reboot(); first = self.pending(); self.complete(first)
        accepted = updates.accepted_plan_history(manager=self.manager)
        self.reboot('33333333-3333-4333-8333-333333333333')
        second = self.pending(); self.complete(second)
        history = updates.accepted_plan_history(manager=self.manager)
        self.assertEqual(len(history['history']), 2)
        value = history['history'][-1]['prepared']['metadata'][proof.KEY]
        self.assertEqual(value['source_head'], accepted['head'])
        self.assertEqual(value['source_database_sha256'], accepted['database_sha256'])
        for item in value['transition']['changes']:
            self.assertEqual(item['before'], 74 if item['attribute'] == 'inode' else 1760000100)

    def test_boot_change_at_actual_database_replace_keeps_acceptance_pending(self):
        self.reboot(); stage = self.pending(); updates.prepare(self.manager, stage, stage / core.PLAN)
        original = updates._replace_current
        def changed_boot(*args):
            original(*args)
            self.native_current['boot_id'] = '33333333-3333-4333-8333-333333333333'
        with patch.object(updates, '_replace_current', side_effect=changed_boot):
            with self.assertRaises(Refused): updates.accept(self.manager, stage, stage / core.PLAN)
        pending = self.manager.records.read(self.state / 'authorized/pending.json', self.identity)
        self.assertEqual(pending['state'], 'ready')
        self.assertFalse((self.state / 'authorized/head.json').exists())
        self.assertNotEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def host_fixture(self):
        stage = self.root / 'manager/updates/releases/1-fixture'
        for directory in (stage.parent.parent, stage.parent, stage):
            directory.mkdir(mode=0o700)
            self.manager.records.directory(directory, self.identity)
        plan = {'schema': 1, 'sequence': 1, 'manifest_sha256': 'a' * 64,
                'files': [{'path': '/etc/issue', 'before': {'fixture_sha512': self.current_rows['/etc/issue']['sha512']},
                           'after': {'fixture_sha512': base64.b64encode(hashlib.sha512(b'updated').digest()).decode()}}],
                'selection': {'path': '/fixture/private-selection'}, 'generation_additions': [], 'preserved': []}
        path = stage / 'host-runtime-plan.json'
        self.write_private(path, (json.dumps(plan, sort_keys=True, indent=2) + '\n').encode())
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        original_bound, original_snapshot = updates._bound_plan, updates._plan_snapshot
        def bound(manager, actual_stage, actual_path, **kwargs):
            if actual_stage != stage or actual_path != path:
                return original_bound(manager, actual_stage, actual_path, **kwargs)
            raw = manager.reader(path, private=True)
            if hashlib.sha256(raw).hexdigest() != checksum or json.loads(raw) != plan:
                raise Refused('fixture host binding changed')
            return copy.deepcopy(plan), checksum
        def snapshot(manager, actual_plan, phase, retained=None):
            if actual_plan != plan:
                return original_snapshot(manager, actual_plan, phase, retained)
            expected = plan['files'][0]['after' if phase == 'forward' else 'before']['fixture_sha512']
            if self.current_rows['/etc/issue']['sha512'] != expected:
                raise Refused('fixture host payload differs from exact direction')
            value = {'/etc/issue': copy.deepcopy(self.metadata)}
            if retained is not None and value != retained:
                raise Refused('fixture host security metadata changed')
            return value
        for context in (patch.object(updates, '_bound_plan', side_effect=bound),
                        patch.object(updates, '_plan_snapshot', side_effect=snapshot)):
            context.start(); self.addCleanup(context.stop)
        return stage, path, plan

    def test_actual_host_shape_mutation_anchor_forward_and_exact_same_preparation_rollback(self):
        stage, path, plan = self.host_fixture()
        updates.prepare(self.manager, stage, path)
        self.current_rows['/etc/issue']['sha512'] = plan['files'][0]['after']['fixture_sha512']
        self.refresh_native()
        accepted = updates.accept(self.manager, stage, path)
        self.assertTrue(accepted['baseline_changed'])
        forward = updates.accepted_plan_history(manager=self.manager)
        value = forward['history'][0]['prepared']['metadata'][proof.KEY]
        self.assertEqual(value['mode'], 'mutation'); self.assertEqual(value['transition']['changes'], [])
        self.assertEqual(value['after']['rows']['/etc/issue']['sha512'], hashlib.sha512(b'fixture').hexdigest())
        self.current_rows['/etc/issue']['sha512'] = plan['files'][0]['before']['fixture_sha512']
        self.refresh_native()
        result = updates.accept(self.manager, stage, path, direction='rollback')
        self.assertEqual(result['direction'], 'rollback')
        history = updates.accepted_plan_history(manager=self.manager)
        self.assertEqual(len(history['history']), 2)
        first, second = history['history']
        self.assertEqual(first['entry']['prepared'], second['entry']['prepared'])
        self.assertEqual(first['prepared'], second['prepared'])
        self.assertEqual(second['entry']['previous'], first['entry_ref'])
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_host_mutation_cannot_accept_boot_drift(self):
        stage, path, plan = self.host_fixture()
        self.reboot()
        with self.assertRaises(Refused): updates.prepare(self.manager, stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertEqual(self.scan_calls.count('update'), 0)

    def test_host_rollback_after_new_boot_cannot_reuse_old_preparation(self):
        stage, path, plan = self.host_fixture()
        updates.prepare(self.manager, stage, path)
        self.current_rows['/etc/issue']['sha512'] = plan['files'][0]['after']['fixture_sha512']; self.refresh_native()
        updates.accept(self.manager, stage, path)
        accepted = (self.state / 'aide.db.gz').read_bytes()
        self.current_rows['/etc/issue']['sha512'] = plan['files'][0]['before']['fixture_sha512']; self.refresh_native()
        self.native_current['boot_id'] = native_fixture.NEW_BOOT
        with self.assertRaises(Refused): updates.accept(self.manager, stage, path, direction='rollback')
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), accepted)

    def test_forged_clean_scan_cannot_authorize_wrong_actual_output_rows(self):
        self.reboot(); stage = self.pending()
        def tamper_output(action, raw):
            if action != 'update': return raw
            rows = copy.deepcopy(self.current_rows)
            rows['/etc/issue']['sha512'] = base64.b64encode(hashlib.sha512(b'forged-content').digest()).decode()
            return db_fixture.compressed(db_fixture.text_database([rows[path] for path in sorted(rows)]))
        def forged_clean(action, report):
            if action == 'check' and '/authorized/artifacts/' in next(iter(report['databases'])):
                report.pop('changed', None); report['number_of_entries']['changed'] = 0
                return 0
        self.output_hook, self.report_hook = tamper_output, forged_clean
        with self.assertRaisesRegex(Refused, 'output_rows_not_authorized'):
            self.reconcile(stage)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertFalse((self.state / 'authorized/head.json').exists())

    def test_same_boot_scanning_retry_reuses_original_preparation(self):
        self.reboot(); stage = self.pending(); self.interrupt(stage, 'scanning')
        old = self.manager.records.read(self.state / 'authorized/pending.json', self.identity)['prepared']
        self.complete(stage)
        self.assertEqual(updates.accepted_plan_history(manager=self.manager)['history'][0]['entry']['prepared'], old)

    def test_same_boot_ready_input_retry_preserves_original_preparation(self):
        self.reboot(); stage = self.pending(); self.interrupt(stage, 'ready_input')
        old = self.manager.records.read(self.state / 'authorized/pending.json', self.identity)['prepared']
        self.complete(stage)
        self.assertEqual(updates.accepted_plan_history(manager=self.manager)['history'][0]['entry']['prepared'], old)

    def test_boot_change_after_head_write_keeps_completion_pending(self):
        self.reboot(); stage = self.pending(); updates.prepare(self.manager, stage, stage / core.PLAN)
        original = self.manager.records.write
        def changed_boot(path, value, identity):
            original(path, value, identity)
            if path.name == 'head.json':
                self.native_current['boot_id'] = '33333333-3333-4333-8333-333333333333'
        with patch.object(self.manager.records, 'write', side_effect=changed_boot):
            with self.assertRaises(Refused): updates.accept(self.manager, stage, stage / core.PLAN)
        pending = self.manager.records.read(self.state / 'authorized/pending.json', self.identity)
        self.assertEqual(pending['state'], 'ready')
        self.assertTrue((self.state / 'authorized/head.json').exists())
        self.assertNotEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_host_mutation_scope_does_not_hide_unrelated_native_content(self):
        stage, path, plan = self.host_fixture(); updates.prepare(self.manager, stage, path)
        self.current_rows['/etc/issue']['sha512'] = plan['files'][0]['after']['fixture_sha512']
        self.current_rows['/etc/locale.conf']['sha512'] = base64.b64encode(hashlib.sha512(b'unrelated').digest()).decode()
        self.refresh_native()
        with self.assertRaises(Refused): updates.accept(self.manager, stage, path)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_real_metadata_chain_under_outer_manager_and_update_transaction_locks(self):
        self.reboot(); stage = self.pending()
        self.manager.records.directory(self.root / 'manager/updates', self.identity, create=True)
        health = {'ok': True, 'stage': str(stage), 'boot_id': self.observed['boot_id'],
                  'checks': {key: True for key in core.REQUIRED_CHECKS}}
        with locked(self.root / 'manager/transaction.lock'), locked(self.root / 'manager/updates/transaction.lock'):
            self.reconcile(stage)
            self.reconcile(stage)  # Existing-result retry also performs a real full fixture scan.
            core.finalize(stage, health, manager=self.manager)
            self.assertEqual(len(updates.accepted_plan_history(manager=self.manager)['history']), 1)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)


class KernelMetadataAideTests(unittest.TestCase):
    """Real boot plans and metadata chain; signed host/renderer inputs injected."""
    for _name, _method in kernel_integration.KernelAideIntegrationTests.__dict__.items():
        if callable(_method) and not _name.startswith('test_') and _name not in {'setUp', 'enrolled'}:
            locals()[_name] = _method
    for _name in ('scan_runner', 'summary', 'refresh_native'):
        locals()[_name] = MetadataAideTests.__dict__[_name]

    def setUp(self):
        kernel_integration.KernelAideIntegrationTests.setUp(self)

    def enrolled(self):
        # Existing integration setup invokes this once, after all native host
        # boundaries exist but BEFORE the actual manager prepare/enroll calls.
        self.current_rows = {path: db_fixture.fixture_row(path) for path in sorted(database.TARGETS)}
        self.boot_generation = 0
        self.native_current = native_fixture.fixture()[1]; self.native_current['boot_id'] = self.boot_id
        self.report_hook, self.output_hook = None, None
        self.refresh_native()
        self.initial_snapshot = fixture_v2(); self.initial_snapshot['boot_id'] = self.boot_id
        self.initial_snapshot['grub'] = {'raw': base64.b64encode(self.env.read_bytes()).decode(),
                                         'description': self.description(self.env)}
        owner = self.root / 'manager/boot-integrity'
        self.manager.records.directory(owner, self.identity, create=True)
        raw = boot.kernel.encode(self.initial_snapshot)
        self.write_private(owner / 'initial.json', raw)
        self.values['ordinary_boot_snapshot_sha256'] = hashlib.sha256(raw).hexdigest()
        def original(identity, checksum):
            self.assertEqual(identity, self.identity)
            actual = (owner / 'initial.json').read_bytes()
            if hashlib.sha256(actual).hexdigest() != checksum: raise Refused('fixture initial root changed')
            return core.native.validate_snapshot(json.loads(actual))
        self.boot_snapshot.side_effect = original
        for context in (patch.object(native, 'capture', side_effect=lambda: copy.deepcopy(self.native_current)),
                        patch.object(boot.kernel, 'GRUBENV', str(self.env)),
                        patch.object(boot.kernel, 'load_plan', return_value=(self.candidate, kernel_fixture.PLAN_SHA))):
            context.start(); self.addCleanup(context.stop)
        return baseline.AideLifecycleTests.enrolled(self)

    def current_database(self):
        rows = [copy.deepcopy(self.current_rows[path]) for path in sorted(self.current_rows)]
        # Unselected DB rows measure actual private payload bytes/stat values.
        # Deleted payload stays absent, so compound scans see exact removals.
        for path in self.monitored:
            if not path.exists(): continue
            value, info = db_fixture.fixture_row(str(path)), path.stat()
            value.update(size=str(info.st_size), inode=str(info.st_ino), ctime=str(info.st_ctime_ns // 1_000_000_000),
                         mtime=str(info.st_mtime_ns // 1_000_000_000), perm=oct(info.st_mode)[2:],
                         sha512=base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode())
            rows.append(value)
        return db_fixture.compressed(db_fixture.text_database(rows))

    def scanner_rows(self, raw):
        result = database.parse_database(raw, expected_sha256=hashlib.sha256(raw).hexdigest())['rows']
        for line in gzip.decompress(raw).splitlines():
            if not line.startswith(b'/'): continue
            name, value = database._row(line)
            path = name.decode('ascii')
            if path not in database.TARGETS:
                self.assertTrue(Path(path).is_relative_to(self.root))
                result[path] = database._qualified(path, value)
        return result

    def metadata_reboot(self):
        self.boot_generation += 1
        self.native_current['boot_id'] = self.boot_id
        for path in database.TMPFILES:
            self.current_rows[path]['ctime'] = str(1760000000 + self.boot_generation * 100)
        for path in database.EFI:
            self.current_rows[path]['inode'] = str(int(self.current_rows[path]['inode']) + 1)
        self.refresh_native()

    def new_boot(self, candidate=True):
        kernel_fixture.BootTransactionTests.new_boot(self, candidate=candidate)
        self.metadata_reboot()

    def next_candidate_boot(self, value):
        kernel_fixture.BootTransactionTests.next_candidate_boot(self, value)
        self.metadata_reboot()

    def begin(self):
        self.call(boot.arm_candidate)
        self.assertEqual(self.running, kernel_fixture.OLD)
        self.new_boot()
        self.assertEqual(self.running, kernel_fixture.NEW)
        # Candidate qualification must work while persistent recovery remains old.
        self.assertEqual(self.runner(['/usr/sbin/grubby', '--default-kernel']), '/boot/vmlinuz-' + kernel_fixture.OLD)
        self.assertEqual(self.call(boot.verify_postboot)['outcome'], 'candidate')

    def test_real_schema2_arm_postboot_promotion_binds_boot_rows_and_actual_grub(self):
        self.begin(); promoted = self.call(boot.commit_candidate, health=self.health())
        history = updates.accepted_plan_history(manager=self.manager)
        self.assertEqual([row['plan']['phase'] for row in history['history']], ['arm', 'postboot', 'commit'])
        values = [row['prepared']['metadata'][proof.KEY] for row in history['history']]
        self.assertEqual([value['mode'] for value in values], ['mutation', 'observation', 'mutation'])
        self.assertEqual([len(value['transition']['changes']) for value in values], [0, 18, 0])
        self.assertEqual(values[1]['source_boot_id'], kernel_fixture.ORIGINAL_BOOT)
        self.assertEqual(values[1]['after']['boot_id'], kernel_fixture.NEW_BOOT)
        parsed = database.parse_database((self.state / 'aide.db.gz').read_bytes(), expected_sha256=history['database_sha256'])
        self.assertEqual(parsed['entry_count'], 21)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)
        self.assertEqual(self.runner(['/usr/sbin/grubby', '--default-kernel']), '/boot/vmlinuz-' + kernel_fixture.NEW)
        self.assertFalse(promoted['release_accepted'])

    def test_schema2_arm_scan_interruption_recovers_on_candidate_boot(self):
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError('arm before DB copy')) if action == 'update' else None
        with self.assertRaises(OSError): self.call(boot.arm_candidate)
        self.scan_hook = None; self.new_boot()
        self.call(boot.verify_postboot); self.call(boot.commit_candidate, health=self.health())
        history = updates.accepted_plan_history(manager=self.manager)
        self.assertEqual([row['plan']['phase'] for row in history['history']], ['postboot', 'commit'])
        value = history['history'][0]['prepared']['metadata'][proof.KEY]
        self.assertEqual(value['pending']['state'], 'scanning')
        self.assertEqual(len(value['transition']['changes']), 18)
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_schema2_copied_promotion_recovers_on_later_candidate_boot(self):
        self.begin()
        replace = updates._replace_current
        def crash(*args):
            replace(*args); raise OSError('copied promotion before head')
        with patch.object(updates, '_replace_current', side_effect=crash):
            with self.assertRaises(OSError): self.call(boot.commit_candidate, health=self.health())
        copied = (self.state / 'aide.db.gz').read_bytes()
        self.next_candidate_boot('cccccccc-cccc-cccc-cccc-cccccccccccc')
        self.call(boot.verify_postboot); self.call(boot.commit_candidate, health=self.health())
        history = updates.accepted_plan_history(manager=self.manager)
        self.assertEqual([row['plan']['phase'] for row in history['history']], ['arm', 'postboot', 'commit', 'resume'])
        value = history['history'][-1]['prepared']['metadata'][proof.KEY]
        self.assertEqual(value['database_source']['basis'], 'owned-ready-output')
        self.assertEqual(value['source_database_sha256'], hashlib.sha256(copied).hexdigest())
        self.assertEqual(len(value['transition']['changes']), 18)
        self.assertEqual(self.manager.check()['state'], 'clean')
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_schema2_candidate_boot_tampered_output_database_refuses_before_cas(self):
        self.call(boot.arm_candidate); self.new_boot()
        before = (self.state / 'aide.db.gz').read_bytes()
        head = (self.state / 'authorized/head.json').read_bytes()
        def tamper(action, raw):
            if action != 'update': return raw
            lines = gzip.decompress(raw).splitlines()
            replacement = base64.b64encode(hashlib.sha512(b'tampered candidate output').digest())
            for index, line in enumerate(lines):
                if line.startswith(b'/etc/issue '):
                    fields = line.split(b' '); fields[12] = replacement
                    lines[index] = b' '.join(fields)
            return db_fixture.compressed(b'\n'.join(lines) + b'\n')
        self.output_hook = tamper
        with self.assertRaisesRegex(Refused, 'new_baseline_not_clean'):
            self.call(boot.verify_postboot)
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), before)
        self.assertEqual((self.state / 'authorized/head.json').read_bytes(), head)
        self.assertEqual(self.scan_calls.count('init'), 1)

    def retention_origin(self):
        """Signed provenance boundary with real retained recipe/intent bytes."""
        self.call(boot.arm_candidate)
        self.new_boot()
        self.call(boot.verify_postboot)
        self.call(boot.commit_candidate, health=self.health())
        self.initial_acceptance = boot.accepted_transitions(self.stage, runner=self.runner)
        self.original_retention = {
            'schema': 1, 'kind': retention.KIND,
            'operation_sha256': boot._operation_sha(self.stage), 'boot_id': self.boot_id,
            'removed': {str(self.retired): self.description(self.retired)},
            'preserved': {str(path): self.description(path) for path in (self.env, self.unrelated)},
            'mutable_directories': []}
        recipe = boot.kernel.encode(self.original_retention)
        self.original_sha = hashlib.sha256(recipe).hexdigest()
        self.write_private(self.stage / retention.PLAN, recipe)
        self.retention_authorities = {}
        self.live_inventory = ['after']
        original_read_text = Path.read_text
        def read_text(path, *args, **kwargs):
            if str(path) == '/proc/sys/kernel/random/boot_id':
                return self.boot_id
            return original_read_text(path, *args, **kwargs)
        def authority(stage, reference, *, historical=False, **kwargs):
            self.assertEqual(stage, self.stage)
            boot.exact(reference, {'filename', 'sha256'})
            path = stage / reference['filename']
            raw = path.read_bytes()
            value = json.loads(raw)
            if (path.parent != stage or boot.rpm.sha(raw) != reference['sha256']
                    or value != self.retention_authorities.get(value['boot_id'])
                    or not historical and value['boot_id'] != self.boot_id):
                raise Refused('fixture_signed_retention_authority_changed')
            return value
        for context in (
                patch.object(boot.kernel, 'GRUBENV', str(self.env)),
                patch.object(boot.kernel, 'load_plan', return_value=(self.candidate, kernel_fixture.PLAN_SHA)),
                patch.object(Path, 'read_text', new=read_text),
                patch.object(boot.rpm, 'inventory', side_effect=lambda runner: ('', [], list(self.live_inventory))),
                patch.object(retention, 'validate_boot_authority', side_effect=authority),
                patch.object(retention, 'load_plan', return_value=(self.original_retention, self.original_sha)),
                patch.object(retention, 'load_historical_plan', return_value=(self.original_retention, self.original_sha)),
                patch.object(retention, 'load_original_plan', return_value=(self.original_retention, self.original_sha)),
                patch.object(retention, 'require_linux_root'),
                patch.object(retention, 'run', side_effect=self.runner),
                patch.object(updates.aide, 'Aide', return_value=self.manager)):
            context.start()
            self.addCleanup(context.stop)
        atomic_json(self.root / 'manager/os-transaction.json', {
            **self.transaction, 'state': 'retaining', 'kernel_retention': 'pending'})
        self.original_integrity = retention.integrity_plan(self.original_retention, self.original_sha)
        self.original_path = self.stage / retention.INTEGRITY
        self.write_private(self.original_path, boot.kernel.encode(self.original_integrity))
        updates.prepare(self.manager, self.stage, self.original_path)
        _, prepared = updates._prepared(self.manager, self.state, self.identity, self.stage,
                                         self.original_integrity, boot.rpm.sha(self.original_path.read_bytes()))
        intent = {'schema': 1, 'plan_sha256': self.original_sha, 'authorization': {
            'ok': True, 'plan_sha256': self.original_sha, 'boot_id': self.boot_id,
            'backup_sha256': 'f' * 64, 'aide_preparation_sha256': digest(prepared)}}
        self.write_private(self.stage / retention.INTENT, boot.kernel.encode(intent))
        self.retired.unlink()
        self.live_inventory = ['retained-exact']

    def observe_retention(self, **changes):
        return kernel_fixture.BootTransactionTests.observe_retention(
            self, retention_plan_sha256=self.original_sha, **changes)

    def test_schema2_retention_compound_accepts_exact_erase_and_eighteen_metadata_changes(self):
        self.retention_origin()
        path, plan, observation = self.compound_after_boot()
        self.finish_compound(path, plan, observation)
        history = updates.accepted_plan_history(manager=self.manager)
        row = history['history'][-1]
        self.assertEqual(row['plan']['kind'], 'rocky-kernel-retention-resume-v1')
        value = row['prepared']['metadata'][proof.KEY]
        self.assertEqual(value['mode'], 'observation')
        self.assertEqual(len(value['transition']['changes']), 18)
        self.assertEqual(value['source_boot_id'], kernel_fixture.NEW_BOOT)
        self.assertEqual(value['after']['boot_id'], self.boot_id)
        self.assertNotIn(str(self.retired), self.scanner_rows((self.state / 'aide.db.gz').read_bytes()))
        self.assertEqual(len(self.scanner_rows((self.state / 'aide.db.gz').read_bytes())), 20)

    def test_schema2_retention_copied_output_second_boot_preserves_real_chain(self):
        self.retention_origin()
        self.scan_hook = lambda action, *_: (_ for _ in ()).throw(OSError('retention scan interrupted')) if action == 'update' else None
        with self.assertRaises(OSError): updates.accept(self.manager, self.stage, self.original_path)
        self.scan_hook = None
        path, plan, observation = self.compound_after_boot()
        updates.prepare(self.manager, self.stage, path)
        replace = updates._replace_current
        def crash(*args):
            replace(*args); raise OSError('compound output copied before head')
        with patch.object(updates, '_replace_current', side_effect=crash):
            with self.assertRaises(OSError): updates.accept(self.manager, self.stage, path)
        copied = (self.state / 'aide.db.gz').read_bytes()
        second_path, second, second_observation = self.compound_after_boot('dddddddd-dddd-dddd-dddd-dddddddddddd')
        self.assertEqual(second['previous_retention_plan'], {'filename': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        self.finish_compound(second_path, second, second_observation)
        self.assertFalse(boot._result_path(self.stage, observation).exists())
        history = updates.accepted_plan_history(manager=self.manager)
        value = history['history'][-1]['prepared']['metadata'][proof.KEY]
        self.assertEqual(value['database_source']['basis'], 'owned-ready-output')
        self.assertEqual(value['source_database_sha256'], hashlib.sha256(copied).hexdigest())
        self.assertEqual(len(value['transition']['changes']), 18)
        self.assertEqual([row['plan']['kind'] for row in history['history'][-2:]],
                         ['rocky-kernel-retention-resume-v1'] * 2)
