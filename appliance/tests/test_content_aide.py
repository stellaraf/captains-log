"""Actual retained AIDE transaction/CAS with injected scanner/Linux metadata.

These cases exercise filesystem/prepared/history/rollback production machinery,
not the native AIDE binary or the release-specific plan producer.
"""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from nebulalog_manager import aide_updates
from nebulalog_manager.common import Refused
import test_aide_updates as fixture


class ContentAideTests(unittest.TestCase):
    for _name, _method in fixture.AuthorizedAideTests.__dict__.items():
        if callable(_method) and not _name.startswith('test_') and not _name.startswith('__'):
            locals()[_name] = _method

    def content_fixture(self):
        self.authorized_fixture()
        self.content = self.root / 'content.xml'
        self.content.write_bytes(b'fixed reviewed source\n'); self.content.chmod(0o444)
        self.monitored.append(self.content)
        self.plan['schema'] = 2
        self.plan['content'] = {'typed_fixture': True}
        self.plan['content_additions'] = [{'path': str(self.content), **self.desc(self.content)}]
        self.write_private(self.plan_path, json.dumps(self.plan).encode())

    def test_content_additions_are_measured_then_same_preparation_rolls_back(self):
        self.content_fixture()
        self.assertTrue(self.prepare_update()['ok'])
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.activate()
        self.assertTrue(self.accept_update()['ok'])
        forward = (self.state / 'aide.db.gz').read_bytes()
        self.runtime.write_bytes(b'old managed\n')
        self.selection.write_bytes(b'restored selection highwater\n')
        self.assertTrue(self.accept_update('rollback')['ok'])
        self.assertNotEqual((self.state / 'aide.db.gz').read_bytes(), forward)
        self.assertEqual(self.content.read_bytes(), b'fixed reviewed source\n')
        self.assert_original()
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_content_hash_or_metadata_drift_prevents_preparation_and_acceptance(self):
        self.content_fixture()
        self.content.chmod(0o644)
        with self.assertRaises(Refused): self.prepare_update()
        self.content.chmod(0o444)
        self.assertTrue(self.prepare_update()['ok'])
        self.activate()
        self.content.write_bytes(b'foreign content\n')
        with self.assertRaises(Refused): self.accept_update()
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_content_additions_do_not_allow_an_unlisted_sibling(self):
        self.content_fixture()
        extra = self.root / 'unlisted-content.xml'; extra.write_bytes(b'foreign\n'); extra.chmod(0o444)
        self.monitored.append(extra)
        with self.assertRaisesRegex(Refused, 'unrelated_integrity_change'): self.prepare_update()
        self.assertEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)

    def test_interrupted_copy_recovers_only_exact_output_and_retained_preparation(self):
        self.content_fixture(); self.prepare_update(); self.activate()
        original = self.manager.records.write
        def fail_head(path, value, identity):
            if Path(path).name == 'head.json':
                raise RuntimeError('injected publication interruption after verified database copy')
            return original(path, value, identity)
        with patch.object(self.manager.records, 'write', side_effect=fail_head), self.assertRaises(RuntimeError): self.accept_update()
        self.assertNotEqual((self.state / 'aide.db.gz').read_bytes(), self.initial_db)
        self.assertTrue(self.accept_update()['ok'])
        self.assert_original()
        self.assertEqual(self.scan_calls.count('init'), 1)

    def test_large_content_uses_only_typed_content_bound_not_generic_runtime_bound(self):
        self.content_fixture()
        raw = b'x' * (9 * 1024**2)
        self.content.write_bytes(raw)
        self.plan['content_additions'][0].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self.write_private(self.plan_path, json.dumps(self.plan).encode())
        self.assertTrue(self.prepare_update()['ok'])
        self.activate(); self.assertTrue(self.accept_update()['ok'])
        with self.assertRaises(Refused):
            aide_updates._description({key: value for key, value in self.plan['content_additions'][0].items() if key != 'path'})
