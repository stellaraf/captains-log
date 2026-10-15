"""Real content parsing/derivation/filesystem authority; native scanner is injected.

Root-only publication tests run in an isolated container, never on installed host
content. Archive and policy validators remain production code.
"""
import copy
from datetime import timedelta
import io
import json
import os
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

from nebulalog_manager import baseline, host_dispatch, host_payload, os_payload
from nebulalog_manager.baseline import ContentUpdate as Content
from nebulalog_manager.common import Refused, atomic_json
import test_baseline as baseline_fixture
from test_baseline import CONTENT, INSTALLATION
from test_host_payload import fixture_tree


def closed_source(raw=CONTENT):
    raw = raw.replace('<data-stream-collection xmlns:x=', '<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:x=')
    raw = raw.replace('<component>', '<data-stream id="stream"><checklists><component-ref id="ref" xlink:href="#benchmark"/></checklists></data-stream><component id="benchmark">')
    return raw.encode()


class ContentFixture(unittest.TestCase):
    policy = baseline_fixture.BaselineTests.policy
    directory = baseline_fixture.BaselineTests.directory

    def setUp(self):
        baseline_fixture.BaselineTests.setUp(self)
        self.source.write_bytes(closed_source())
        self.state = self.root / 'updates'
        self.stage = self.state / 'releases/2-fixture'
        self.stage.mkdir(parents=True, mode=0o700)
        self.generation_root = self.root / 'content-generations'
        for target, name, value in ((Content, 'ROOT', self.generation_root), (host_dispatch, 'STATE', self.state),
                                    (host_payload, '_trusted_tree', fixture_tree(self.root))):
            context = patch.object(target, name, value); context.start(); self.addCleanup(context.stop)
        self.selected = self.policy()
        self.selected.update(installation_id=INSTALLATION, selection_id='1'*32, exceptions=[{'id': 'site-exception', 'expires_at': '2099-01-01T00:00:00Z'}])
        atomic_json(self.configuration / 'security-policy.json', self.selected)
        self.identity = Content.measure(self.configuration / 'security-policy.json', self.runner)
        self.addCleanup(self.writable)

    def writable(self):
        if self.generation_root.exists():
            for path in (self.generation_root, *self.generation_root.rglob('*')):
                if path.is_dir(): path.chmod(0o700)

    def runner(self, argv, **kwargs):
        if argv == ['rpm', '-q', '--qf', '%{NEVRA}', 'openscap-scanner']:
            return 'openscap-scanner-1.3.14-1.el9.x86_64'
        return baseline_fixture.BaselineTests.runner(self, argv, **kwargs)

    def archive(self, *, changed=True, raw=None):
        source = raw if raw is not None else closed_source(CONTENT.replace('Level 2 - Server', 'Level 2 - Server revision 2') if changed else CONTENT)
        policies, files = {}, {'source.xml': source}
        for name in ('cis-level2', 'stig', 'unified'):
            policy = self.policy(name)
            for item in policy['assessments']:
                item.update(datastream='source.xml', sha256=Content.digest(source), content_revision='fixture-v2')
            if name == 'unified':
                mapping = baseline._json(policy['unified_mapping']['path'])
                mapping['assessments'] = {item['kind']: baseline.assessment_binding(item) for item in policy['assessments']}
                files['mapping.json'] = Content.encoded(mapping)
                policy['unified_mapping'] = {'path': 'mapping.json', 'sha256': Content.digest(files['mapping.json'])}
            policies[name] = policy
        descriptor = {'schema': 1, 'kind': Content.KIND, 'version': '1.2.3', 'platform': 'rocky9-x86_64',
            'source_url': 'https://example.invalid/content', 'content_revision': 'fixture-v2', 'engine': self.identity['engine'],
            'policies': policies, 'files': {name: {'bytes': len(body), 'sha256': Content.digest(body)} for name, body in files.items()}}
        path = self.stage / 'content.tar'
        with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for name, body in [('content.json', Content.encoded(descriptor)), *files.items()]:
                entry = tarfile.TarInfo(name); entry.mode = 0o644; entry.size = len(body)
                archive.addfile(entry, io.BytesIO(body))
        self.release = {'components': {'baseline': {'artifact': 'content.tar', 'version': '1.2.3', 'from_versions': [self.identity['version']],
            'rollback_safe': True, 'content_schema': 1, 'descriptor_sha256': Content.digest(Content.encoded(descriptor))}},
            'artifacts': [{'name': 'content.tar', 'bytes': path.stat().st_size, 'sha256': Content.digest(path.read_bytes())}]}
        return path

    def approve_request(self):
        request = json.loads((self.stage / 'content-review-request.json').read_bytes())
        value = {'schema': 1, 'binding': request['binding'], 'approved': True, 'control_semantics_reviewed': True,
            'reviewer': 'Exact fixture content reviewer', 'rationale': 'Explicitly reviewed changed complete content semantics',
            'reviewed_at': (self.now - timedelta(seconds=3)).isoformat(), 'expires_at': (self.now + timedelta(days=20)).isoformat()}
        root = self.state / 'content-reviews'; root.mkdir(mode=0o700, exist_ok=True)
        atomic_json(root / (request['generation'] + '.json'), value)
        return value

    def prepare(self):
        return Content.prepare_transition(self.stage, self.release, self.identity, self.configuration, self.runner)


@unittest.skipUnless(os.geteuid() == 0, 'Immutable content publication requires isolated root filesystem fixture')
class ContentTests(ContentFixture):
    def test_changed_content_requires_exact_review_and_preserves_original_authority(self):
        self.archive()
        original = (self.configuration / 'security-policy.json').read_bytes()
        with self.assertRaisesRegex(Refused, 'semantics changed'): self.prepare()
        self.assertFalse(self.generation_root.exists())
        self.approve_request()
        plan = self.prepare()
        result = Content.publish(self.stage, plan)
        self.assertEqual((self.configuration / 'security-policy.json').read_bytes(), original)
        self.assertEqual(result['policy']['exceptions'], self.selected['exceptions'])
        self.assertEqual(result['policy']['selection_id'], self.selected['selection_id'])
        self.assertEqual(result['policy']['assessments'][0]['content_review'], self.selected['assessments'][0]['content_review'])
        self.assertEqual(Content.publish(self.stage, plan)['plan'], plan)
        self.assertEqual(Content.selected_authority(result['policy'])['policy'], result['policy'])

    def test_same_source_revision_updates_without_new_semantic_review(self):
        self.archive(changed=False)
        plan = self.prepare()
        result = Content.publish(self.stage, plan)
        self.assertIsNone(result['transition']['review'])
        self.assertFalse(json.loads((self.stage / 'content-review-request.json').read_bytes())['review_required'])

    def test_committed_measurement_uses_signed_semver_without_relabeling(self):
        self.archive(changed=False)
        content=Content.publish(self.stage,self.prepare())
        (self.configuration/'security-policy.json').write_bytes(content['after'])
        measured=Content.measure(self.configuration/'security-policy.json',self.runner)
        self.assertEqual(measured['version'],'1.2.3')
        self.assertEqual(measured['policy_sha256'],content['plan']['after_policy_sha256'])
        self.assertNotEqual(measured['generation'],self.identity['generation'])

    def test_review_cannot_extend_original_expiry_or_approve_another_candidate(self):
        self.archive()
        with self.assertRaises(Refused): self.prepare()
        value = self.approve_request()
        request = json.loads((self.stage / 'content-review-request.json').read_bytes())
        for change in ({'expires_at': (self.now + timedelta(days=60)).isoformat()}, {'binding': {**value['binding'], 'candidate_policy_sha256': 'f'*64}}, {'approved': 1}):
            with self.subTest(change=change), self.assertRaises(Refused):
                Content.validate_review({**value, **change}, request['binding'], self.selected)

    def test_generation_conflict_and_tamper_are_never_adopted(self):
        self.archive(changed=False); plan = self.prepare()
        self.generation_root.mkdir(mode=0o555)
        generation = Path(plan['root']); generation.mkdir(mode=0o555)
        with self.assertRaisesRegex(Refused, 'no protected publication owner'): Content.publish(self.stage, plan)
        generation.rmdir()
        result = Content.publish(self.stage, plan)
        target = Path(plan['root']) / 'source.xml'; target.chmod(0o644); target.write_bytes(b'changed')
        with self.assertRaises(Refused): Content.validate_plan(self.stage, result['plan'])

    def test_wrong_engine_and_active_identity_change_refuse_before_publication(self):
        self.archive()
        with patch.object(Content, 'engine', return_value={**self.identity['engine'], 'version_sha256': 'd'*64}), self.assertRaises(Refused): self.prepare()
        self.assertFalse(self.generation_root.exists())
        with self.assertRaises(Refused): Content.prepare_transition(self.stage, self.release, {**self.identity, 'generation': 'f'*64}, self.configuration, self.runner)

    def test_all_selected_baselines_preserve_exact_existing_selection(self):
        for selected in ('stig', 'unified'):
            with self.subTest(selected=selected):
                policy = self.policy(selected); policy.update(installation_id=INSTALLATION, selection_id='2'*32)
                atomic_json(self.configuration / 'security-policy.json', policy)
                archive = Content.verify_archive(self.archive())
                candidate, files = Content.derive(archive, policy, self.root / 'new')
                self.assertEqual(candidate['baseline'], selected)
                self.assertEqual(candidate['selection_id'], policy['selection_id'])
                if selected == 'unified':
                    mapping = json.loads(files['site-unified-mapping.json'])
                    self.assertEqual(mapping['controls'], baseline._json(policy['unified_mapping']['path'])['controls'])
                    self.assertEqual(mapping['review'], baseline._json(policy['unified_mapping']['path'])['review'])


class ArchiveTests(ContentFixture):
    def test_archive_requires_closed_inert_check_graph(self):
        source = closed_source()
        for raw in (source.replace(b'http://oval.mitre.org/XMLSchema/oval-definitions-5', b'http://open-scap.org/page/SCE'),
                    source.replace(b'<x:Rule id="xccdf_rule_2"/>', b'<x:Rule id="xccdf_rule_2"><x:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5"><x:check-content-ref href="https://bad.invalid/check.xml"/></x:check></x:Rule>'),
                    source.replace(b'<x:Rule id="xccdf_rule_2"/>', b'<x:Rule id="xccdf_rule_2"><x:fix system="urn:xccdf:fix:script:sh">true</x:fix></x:Rule>'),
                    source.replace(b'<component id="benchmark">', b'<extended-component id="benchmark">').replace(b'</component>', b'</extended-component>')):
            with self.subTest(raw=Content.digest(raw)), self.assertRaises(Refused): Content.verify_archive(self.archive(raw=raw))

    def test_trailing_archive_and_inventory_tamper_refuse(self):
        path = self.archive()
        raw = path.read_bytes(); path.write_bytes(raw + b'foreign'.ljust(512, b'\0'))
        with self.assertRaisesRegex(Refused, 'trailing'): Content.verify_archive(path)
        path.write_bytes(raw.replace(b'fixture-v2', b'fixture-v3', 1))
        with self.assertRaises(Refused): Content.verify_archive(path, expected_sha256=Content.digest(raw))

    def test_initial_version_is_portable_but_selected_generation_is_not(self):
        before = self.identity
        policy = copy.deepcopy(self.selected); policy['selection_id'] = '3'*32
        atomic_json(self.configuration / 'security-policy.json', policy)
        after = Content.measure(self.configuration / 'security-policy.json', self.runner)
        self.assertEqual(before['version'], after['version'])
        self.assertNotEqual(before['generation'], after['generation'])

    def test_engine_and_content_packages_cannot_bypass_through_inert_os_payload(self):
        for name in ('openscap', 'openscap-scanner', 'openscap-engine-sce', 'scap-security-guide'):
            self.assertIsNotNone(os_payload.MIGRATION.match(name))
