"""Content schema2 through the real signed-plan binder and metadata/AIDE chain.

The content/host producer, protected plan binding, parser, lineage, preparation,
history and CAS are real. The native scanner is the strict vendor-format fixture;
fixed system destinations are measured through aliases into a private filesystem.
No system files, service, native AIDE executable or appliance are changed.
"""
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import patch

from nebulalog_adapters import host_runtime as runtime
from nebulalog_manager import aide, aide_updates as updates, boot_metadata_proof as proof
from nebulalog_manager import host_dispatch as dispatch
from nebulalog_manager import ordinary_boot_metadata as database
from nebulalog_manager.common import Refused, atomic_json
import test_aide_lifecycle as initial_fixture
import test_boot_metadata_aide as metadata_fixture
import test_ordinary_boot_metadata as row_fixture
import test_content_lifecycle_review as content_fixture


class ContentMetadataAideTests(content_fixture.ContentRuntimeReviewTests):
    # Reuse the full real content producer, not its independently run test cases.
    for _name in dir(content_fixture.ContentRuntimeReviewTests):
        if _name.startswith('test_'):
            locals()[_name] = None

    def setUp(self):
        super().setUp()
        old_state = self.state
        self.state = self.root / 'manager/updates'
        self.state.parent.mkdir(mode=0o700)
        old_state.rename(self.state)
        self.stage = self.state / 'releases/10-fixture'
        for directory in (self.state, self.stage.parent, self.stage):
            directory.chmod(0o700)
        self.transaction['release'] = str(self.stage)
        self.lifecycle.state = self.state
        for context in (patch.object(dispatch, 'STATE', self.state),
                        patch.object(updates, 'CONFIGURATION', self.configuration)):
            context.start(); self.addCleanup(context.stop)
        self.bind_manifest(); self.save_transaction('preflight')
        self.host = runtime.HostRuntime(self.lifecycle, self.stage)
        self.aliases = {}
        for physical in self.host._target_paths():
            logical = self.logical(physical)
            self.aliases[logical] = physical
        self.monitored = {**self.aliases, str(self.selection): self.selection}
        self.monitored.update({item['path']: Path(item['path']) for item in self.host.preserved()})
        self.metadata_fixture = metadata_fixture.MetadataAideTests()
        self.addCleanup(self.metadata_fixture.doCleanups)
        self.metadata_fixture.current_database = self.current_database
        self.metadata_fixture.scanner_rows = self.scanner_rows
        # Both independently established fixtures use this one private root.
        temporary = SimpleNamespace(name=str(self.root), cleanup=lambda: None)
        with patch.object(initial_fixture.tempfile, 'TemporaryDirectory', return_value=temporary):
            self.metadata_fixture.setUp()
        # The initial ordinary observation precedes admission of the component
        # operation; its retained fixture transaction is not active yet.
        transaction_path = self.state / 'transaction.json'
        transaction_raw = transaction_path.read_bytes(); transaction_path.unlink()
        self.metadata_fixture.reboot()
        self.metadata_fixture.complete(self.metadata_fixture.pending())
        transaction_path.write_bytes(transaction_raw); transaction_path.chmod(0o600)
        self.prior_history = updates.accepted_plan_history(manager=self.metadata_fixture.manager)
        self.assertEqual(len(self.prior_history['history']), 1)
        original_measure = updates._measure
        def measure(manager, item, **kwargs):
            return original_measure(manager, {**item, 'path': str(self.aliases.get(item['path'], Path(item['path'])))}, **kwargs)
        context = patch.object(updates, '_measure', side_effect=measure)
        context.start(); self.addCleanup(context.stop)
        self.produced_plan = None
        def prepare(_aide, stage, path):
            self.assertEqual(stage, self.stage)
            self.integrity_calls.append(('prepare', stage, path))
            produced = dispatch.protected_json(path)
            self.produced_plan = copy.deepcopy(produced)
            # Actual binder uses its fixed system destinations. Only physical
            # file access is translated; no binder/snapshot validator is mocked.
            for item in produced['files']:
                item['path'] = self.logical(Path(item['path']))
            atomic_json(path, produced)
            for item in produced['generation_additions'] + produced['content_additions']:
                self.monitored[item['path']] = Path(item['path'])
            return updates.prepare(self.metadata_fixture.manager, stage, path)
        context = patch.object(aide.Aide, 'authorized_update_prepare', prepare)
        context.start(); self.addCleanup(context.stop)

    def logical(self, path):
        if path == runtime.EDGE:
            return '/etc/httpd/conf.d/nebulalog.conf'
        for physical, canonical in ((runtime.SYSTEMD, '/etc/systemd/system'),
                                    (runtime.SHARE, '/usr/share/nebulalog'),
                                    (self.lifecycle.quadlets, '/etc/containers/systemd')):
            if path.is_relative_to(physical):
                return str(Path(canonical) / path.relative_to(physical))
        return str(path)

    def current_database(self):
        rows = list(self.metadata_fixture.current_rows.values())
        for logical, path in sorted(self.monitored.items()):
            if not path.exists():
                continue
            info = path.stat()
            row = row_fixture.fixture_row(logical)
            row['name'] = database._encode(logical.encode()).decode()
            row.update(perm=format(info.st_mode, 'o'), uid=str(info.st_uid), gid=str(info.st_gid),
                       size=str(info.st_size), inode=str(info.st_ino), lcount=str(info.st_nlink))
            if stat.S_ISDIR(info.st_mode):
                row.update(sha512='0', attr=str(database.REGULAR_MASK & ~database.ATTR['sha512']))
            else:
                row['sha512'] = base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode()
            rows.append(row)
        return row_fixture.compressed(row_fixture.text_database(rows))

    def scanner_rows(self, raw):
        rows = database.parse_database(raw, expected_sha256=hashlib.sha256(raw).hexdigest())['rows']
        for line in gzip.decompress(raw).splitlines():
            if not line or line.startswith((b'@', b'#')):
                continue
            name, row = database._row(line)
            name = name.decode()
            if name not in rows:
                rows[name] = {'kind': 'directory' if stat.S_ISDIR(row['mode']) else 'file',
                              'attributes': row['attr'], 'bytes': row['size'],
                              'sha512': row['sha512'].hex() if row['sha512'] else None}
        return rows

    def prepared(self):
        self.reviewed()
        self.host.preflight()
        self.assertIsNotNone(self.produced_plan)
        plan = dispatch.protected_json(self.host.plan_path)
        self.assertEqual(plan['schema'], 2)
        self.assertEqual(plan['content'], self.produced_plan['content'])
        bound, checksum = updates._bound_plan(self.metadata_fixture.manager, self.stage, self.host.plan_path, preparing=True)
        self.assertEqual(bound, plan)
        self.assertEqual(checksum, hashlib.sha256(self.host.plan_path.read_bytes()).hexdigest())
        self.payloads = list(self.host._resources())
        return plan

    def change_payload(self, direction):
        # The already-tested HostRuntime writer is the native mutation boundary.
        # Write its exact real producer bytes into only the private aliases.
        for physical, old, new in self.payloads:
            physical.write_bytes(new if direction == 'forward' else old)
        atomic_json(self.selection, {'schema': 1,
            'generation': self.new['generation'] if direction == 'forward' else self.old['generation'],
            'sequence': self.transaction['sequence']})
        self.save_transaction('checking' if direction == 'forward' else 'rolling_back')

    def test_content_after_ordinary_observation_forward_and_rollback_keep_exact_anchor(self):
        plan = self.prepared()
        self.change_payload('forward')
        result = updates.accept(self.metadata_fixture.manager, self.stage, self.host.plan_path)
        self.assertTrue(result['baseline_changed'])
        history = updates.accepted_plan_history(manager=self.metadata_fixture.manager)
        prepared = history['history'][-1]['prepared']
        value = prepared['metadata'][proof.KEY]
        self.assertEqual(prepared['plan'], plan)
        self.assertEqual(value['mode'], 'mutation')
        self.assertEqual(value['source_head'], self.prior_history['head'])
        self.assertEqual(value['source_boot_id'], self.metadata_fixture.native_current['boot_id'])
        self.assertEqual(value['transition']['changes'], [])
        self.assertEqual(value['lineage']['records'][0]['body'], plan)
        self.change_payload('rollback')
        updates.accept(self.metadata_fixture.manager, self.stage, self.host.plan_path, direction='rollback')
        history = updates.accepted_plan_history(manager=self.metadata_fixture.manager)
        self.assertEqual(len(history['history']), 3)
        self.assertEqual(history['history'][-1]['prepared'], prepared)
        self.assertEqual(history['history'][-1]['entry']['previous'], history['history'][-2]['entry_ref'])
        self.assertEqual((self.configuration / 'security-policy.json').read_bytes(), self.original)
        self.assertEqual(self.metadata_fixture.scan_calls.count('init'), 1)
        self.transaction['finalization'] = 'complete'
        self.save_transaction('rolled_back')
        self.metadata_fixture.reboot('33333333-3333-4333-8333-333333333333')
        self.metadata_fixture.complete(self.metadata_fixture.pending())
        after = updates.accepted_plan_history(manager=self.metadata_fixture.manager)
        self.assertEqual(len(after['history']), 4)
        self.assertEqual(after['history'][-1]['prepared']['metadata'][proof.KEY]['source_head'], history['head'])

    def test_content_copy_before_head_retry_keeps_original_prepared_lineage(self):
        self.prepared(); self.change_payload('forward')
        records = self.metadata_fixture.manager.records
        write = records.write
        def interrupted(path, value, identity):
            if Path(path).name == 'head.json':
                raise RuntimeError('fixture power loss after exact DB copy')
            return write(path, value, identity)
        with patch.object(records, 'write', side_effect=interrupted), self.assertRaises(RuntimeError):
            updates.accept(self.metadata_fixture.manager, self.stage, self.host.plan_path)
        result = updates.accept(self.metadata_fixture.manager, self.stage, self.host.plan_path)
        self.assertTrue(result['ok'])
        history = updates.accepted_plan_history(manager=self.metadata_fixture.manager)
        self.assertEqual(len(history['history']), 2)
        self.assertEqual(history['history'][-1]['prepared']['plan']['schema'], 2)
        self.assertEqual(self.metadata_fixture.scan_calls.count('init'), 1)

    def test_unbound_content_and_wrong_owner_are_refused_before_any_new_preparation(self):
        plan = self.prepared()
        baseline = (self.metadata_fixture.state / 'aide.db.gz').read_bytes()
        for key, value in (('manifest_sha256', 'f' * 64), ('candidate_generation', 'e' * 64)):
            atomic_json(self.host.plan_path, {**plan, key: value})
            with self.subTest(key=key), self.assertRaises(Refused):
                updates.prepare(self.metadata_fixture.manager, self.stage, self.host.plan_path)
            self.assertEqual((self.metadata_fixture.state / 'aide.db.gz').read_bytes(), baseline)
        atomic_json(self.host.plan_path, plan)
        with self.assertRaises(Refused):
            updates.prepare(self.metadata_fixture.manager, self.stage.parent / '11-foreign', self.host.plan_path)

    def test_real_binder_refuses_content_scope_policy_and_previous_identity_drift(self):
        plan = self.prepared()
        manager = self.metadata_fixture.manager
        baseline = (self.metadata_fixture.state / 'aide.db.gz').read_bytes()
        prepared = self.metadata_fixture.state / 'authorized/prepared'
        retained = {path.name: path.read_bytes() for path in prepared.iterdir()}
        cases = []
        wrong = copy.deepcopy(plan); wrong['content_additions'].pop(); cases.append(wrong)
        for direction in ('before', 'after'):
            wrong = copy.deepcopy(plan)
            item = next(item for item in wrong['files'] if item['path'] == str(self.configuration / 'security-policy.json'))
            item[direction]['sha256'] = 'f' * 64; cases.append(wrong)
        for index, wrong in enumerate(cases):
            atomic_json(self.host.plan_path, wrong)
            with self.subTest(index=index), self.assertRaises(Refused):
                updates.prepare(manager, self.stage, self.host.plan_path)
            self.assertEqual((self.metadata_fixture.state / 'aide.db.gz').read_bytes(), baseline)
            self.assertEqual({path.name: path.read_bytes() for path in prepared.iterdir()}, retained)
        atomic_json(self.host.plan_path, plan)
        self.transaction['previous']['components']['baseline']['generation'] = 'f' * 64
        self.save_transaction()
        with self.assertRaisesRegex(Refused, 'content_inventory_mismatch'):
            updates.prepare(manager, self.stage, self.host.plan_path)
        self.assertEqual((self.metadata_fixture.state / 'aide.db.gz').read_bytes(), baseline)
        self.assertEqual({path.name: path.read_bytes() for path in prepared.iterdir()}, retained)

    def test_content_mutation_cannot_authorize_a_new_boot(self):
        self.prepared(); self.change_payload('forward')
        before = (self.metadata_fixture.state / 'aide.db.gz').read_bytes()
        self.metadata_fixture.reboot('33333333-3333-4333-8333-333333333333')
        with self.assertRaises(Refused):
            updates.accept(self.metadata_fixture.manager, self.stage, self.host.plan_path)
        self.assertEqual((self.metadata_fixture.state / 'aide.db.gz').read_bytes(), before)
