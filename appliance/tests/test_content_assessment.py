"""Full retained ARF/review comparison, with only scanner/host observations injected."""
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

from nebulalog_manager import baseline
from nebulalog_manager.baseline import ContentUpdate as Content
from nebulalog_manager.common import CommandFailed, Refused, atomic_json
from test_content_update import ContentFixture

X = '{http://checklists.nist.gov/xccdf/1.2}'
A = '{http://scap.nist.gov/schema/asset-reporting-format/1.1}'
O = '{http://oval.mitre.org/XMLSchema/oval-results-5}'
S = '{http://oval.mitre.org/XMLSchema/oval-system-characteristics-5}'
C = '{http://oval.mitre.org/XMLSchema/oval-common-5}'
D = '{http://oval.mitre.org/XMLSchema/oval-definitions-5}'


def reports(source, profile, rules, *, fact='unchanged', timestamp='2026-10-15T01:00:00+00:00'):
    """Native-format graph fixture; intentionally not a qualified SCAP benchmark."""
    test = ET.Element(X+'TestResult', {'id': 'xccdf_org.open-scap_testresult_'+profile, 'start-time': timestamp, 'end-time': timestamp})
    ET.SubElement(test, X+'benchmark', {'href': str(source), 'id': 'xccdf_example_benchmark'})
    ET.SubElement(test, X+'profile', {'idref': profile})
    for number, result in enumerate(rules):
        rule = ET.SubElement(test, X+'rule-result', {'idref': 'xccdf_rule_'+str(number), 'time': timestamp})
        ET.SubElement(rule, X+'result').text = result
        check = ET.SubElement(rule, X+'check', {'system': D[1:-1]})
        ET.SubElement(check, X+'check-content-ref', {'name': 'oval:fixture:def:1', 'href': 'source.xml'})
    standalone = ET.Element(X+'Benchmark'); standalone.append(copy.deepcopy(test))
    arf = ET.Element(A+'asset-report-collection')
    requests = ET.SubElement(arf, A+'report-requests')
    request = ET.SubElement(requests, A+'report-request', {'id': 'collection1'})
    ET.SubElement(request, A+'content').append(ET.fromstring(source.read_bytes()))
    assets = ET.SubElement(arf, A+'assets'); ET.SubElement(assets, A+'asset', {'id': 'asset0'})
    container = ET.SubElement(arf, A+'reports')
    report = ET.SubElement(container, A+'report', {'id': 'xccdf1'})
    test.find(X+'benchmark').set('href', '#benchmark')
    ET.SubElement(test, X+'target-id-ref', {'name': 'asset0', 'href': '', 'system': 'http://scap.nist.gov/schema/asset-identification/1.1'})
    for node in test.iter(X+'check-content-ref'): node.set('href', '#oval0')
    ET.SubElement(report, A+'content').append(test)
    report = ET.SubElement(container, A+'report', {'id': 'oval0'})
    oval = ET.SubElement(ET.SubElement(report, A+'content'), O+'oval_results')
    ET.SubElement(ET.SubElement(oval, O+'generator'), C+'timestamp').text = timestamp[:19]
    definitions = ET.SubElement(oval, D+'oval_definitions')
    ET.SubElement(ET.SubElement(definitions, D+'generator'), C+'timestamp').text = '2026-01-01T00:00:00Z'
    ET.SubElement(definitions, D+'definition', {'id': 'oval:fixture:def:1'})
    system = ET.SubElement(ET.SubElement(oval, O+'results'), O+'system')
    facts = ET.SubElement(system, S+'oval_system_characteristics')
    ET.SubElement(ET.SubElement(facts, S+'generator'), C+'timestamp').text = timestamp[:19]
    collected = ET.SubElement(facts, S+'collected_objects')
    obj = ET.SubElement(collected, S+'object', {'id': 'oval:fixture:obj:1', 'flag': 'complete'})
    ET.SubElement(obj, S+'reference', {'item_ref': '100001'})
    data = ET.SubElement(facts, S+'system_data')
    ET.SubElement(data, S+'fixture_item', {'id': '100001', 'status': 'exists'}).text = fact
    return ET.tostring(standalone), ET.tostring(arf)


@unittest.skipUnless(os.geteuid() == 0, 'Protected assessment ownership requires isolated root fixture')
class AssessmentTests(ContentFixture):
    def setUp(self):
        super().setUp()
        self.now = datetime.now(timezone.utc)-timedelta(seconds=2)
        self.fact = 'unchanged'
        self.timestamp = '2026-10-15T01:00:00+00:00'
        self.archive(changed=False); self.plan = self.prepare(); self.content = Content.publish(self.stage,self.plan)
        self.host = lambda _: copy.deepcopy(self.host_value)

    def runner(self, argv, **kwargs):
        if argv[:3] == ['oscap','xccdf','eval'] and '--results-arf' in argv:
            source, profile = Path(argv[-1]), argv[argv.index('--profile')+1]
            kind = Path(argv[argv.index('--results')+1]).stem
            xml, arf = reports(source, profile, self.results[kind], fact=self.fact, timestamp=self.timestamp)
            Path(argv[argv.index('--results')+1]).write_bytes(xml)
            Path(argv[argv.index('--results-arf')+1]).write_bytes(arf)
            Path(argv[argv.index('--report')+1]).write_text('<html>Fixture assessment</html>')
            if 'fail' in self.results[kind]: raise CommandFailed('oscap',2)
            return ''
        return super().runner(argv, **kwargs)

    def assess(self, stage=None, *, role='candidate'):
        return Content.candidate_assessment(stage or self.stage, self.content['after' if role=='candidate' else 'before'], self.runner, host=self.host, role=role)

    def manager_for(self, stage=None, role='candidate'):
        return baseline.Baseline((stage or self.stage)/('content-'+role+'-assessment'),runner=self.runner,host=self.host,full_evidence=True)

    def approve(self, role='candidate'):
        manager=self.manager_for(role=role)
        review=manager.review_template(self.selected['installation_id'],self.selected['baseline'])
        now=datetime.now(timezone.utc)
        review.update(approved=True,selection_reviewed=True,reviewer='Explicit fixture reviewer',rationale='Exact candidate and full collected evidence reviewed',reviewed_at=now.isoformat(),expires_at=(now+timedelta(days=1)).isoformat())
        for finding in review['findings']:
            finding.update(disposition={'fail':'exception','notapplicable':'not-applicable','notchecked':'manual-pass'}[finding['result']],reason='Exact fixture finding review',compensating_control='Exact fixture compensation',owner='Fixture operator',approval='Fixture approval',evidence='Fixture reviewed evidence',expires_at=review['expires_at'])
            if finding['result']=='notchecked':
                path=self.root/'manual.txt'; path.write_text('Exact manual scope evidence')
                finding['manual_evidence']={'path':str(path),'sha256':baseline._sha(path)}
        path=self.root/'review.json';atomic_json(path,review)
        manager.review(path,baseline._sha(manager.assessment_path),self.selected['installation_id'],self.selected['baseline'])
        return manager

    def retry_stage(self):
        stage=self.state/'releases'/'second-fixture';stage.mkdir(mode=0o700);return stage

    def test_preflight_review_retains_original_and_fresh_exact_facts_continue(self):
        with self.assertRaisesRegex(Refused,'Review the retained'):self.assess()
        manager=self.approve(); original=manager.review_path.read_bytes()
        self.timestamp='2026-10-15T02:00:00+00:00'
        stage=self.retry_stage(); result=self.assess(stage)
        self.assertEqual(manager.review_path.read_bytes(),original)
        self.assertEqual(result['continuation']['review_sha256'],baseline._sha(manager.review_path))
        self.assertNotEqual(result['continuation']['reviewed_assessment_sha256'],result['continuation']['current_assessment_sha256'])
        self.assertEqual((self.configuration/'security-policy.json').read_bytes(),self.content['before'])

    def test_changed_fact_with_identical_rule_results_never_carries_exception(self):
        with self.assertRaises(Refused):self.assess()
        self.approve();self.fact='different affected object, still fail';stage=self.retry_stage()
        with self.assertRaises(Refused):self.assess(stage)
        with self.assertRaisesRegex(Refused,'facts or instance scope changed'):
            Content.finding_continuation(stage,self.manager_for(stage),self.runner,host=self.host)

    def test_candidate_and_rollback_reviews_are_distinct_and_both_retained(self):
        for role in ('rollback','candidate'):
            with self.assertRaises(Refused):self.assess(role=role)
            self.approve(role)
        first=self.assess(role='candidate');second=self.assess(role='rollback')
        self.assertNotEqual(first['policy_sha256'],second['policy_sha256'])
        self.assertNotEqual(first['directory'],second['directory'])

    def test_changed_manual_evidence_and_expired_review_refuse(self):
        self.results['cis'][-1]='notchecked'
        with self.assertRaises(Refused):self.assess()
        manager=self.approve();(self.root/'manual.txt').write_text('Changed manual scope')
        with self.assertRaises(Refused):self.assess(self.retry_stage())
        value=json.loads(manager.review_path.read_bytes());value['expires_at']='2026-01-01T00:00:00Z';atomic_json(manager.review_path,value)
        with self.assertRaises(Refused):Content.finding_continuation(self.stage,manager,self.runner,host=self.host)

    def test_same_status_source_generator_or_object_identity_changes_refuse(self):
        with self.assertRaises(Refused):self.assess()
        self.approve(); manager=self.manager_for();record=json.loads(manager.assessment_path.read_bytes())
        directory=manager.configuration/'baseline-assessments'/record['artifact_directory']
        before=Content.assessment_evidence(directory,'cis',self.selected['assessments'][0]['profile_id'])
        path=directory/'cis.arf.xml';original=path.read_bytes()
        for old,new in ((b'2026-01-01T00:00:00Z',b'2026-01-02T00:00:00Z'),(b'100001',b'100002'),(b'unchanged',b'changed!!')):
            path.write_bytes(original.replace(old,new))
            self.assertNotEqual(before,Content.assessment_evidence(directory,'cis',self.selected['assessments'][0]['profile_id']))
        path.write_bytes(original)

    def test_foreign_arf_reference_and_missing_fact_collection_refuse(self):
        with self.assertRaises(Refused):self.assess()
        manager=self.manager_for();record=json.loads(manager.assessment_path.read_bytes());directory=manager.configuration/'baseline-assessments'/record['artifact_directory']
        path=directory/'cis.arf.xml';original=path.read_bytes()
        for body in (original.replace(b'#oval0',b'#foreign'),original.replace(b'collected_objects',b'unknown_objects'), original.replace(b'item_ref="100001"',b'item_ref="foreign"'), original.replace(b'id="100001"',b'id="foreign"')):
            path.write_bytes(body)
            with self.assertRaises(Refused):Content.assessment_evidence(directory,'cis',self.selected['assessments'][0]['profile_id'])
        path.write_bytes(original)

    def test_cli_review_uses_exact_content_host_and_retained_arf_contract(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        with self.assertRaises(Refused):self.assess()
        manager=self.manager_for()
        setup=self.configuration/'bootstrap/setup.json';atomic_json(setup,{'installation_id':self.selected['installation_id'],'baseline':self.selected['baseline']})
        output=StringIO()
        with patch.object(Content,'assessment_host',self.host), redirect_stdout(output):
            code=baseline.main(['--configuration',str(manager.configuration),'--setup',str(setup),'review-template'])
        self.assertEqual(code,0)
        self.assertEqual(json.loads(output.getvalue())['assessment_sha256'],baseline._sha(manager.assessment_path))

    def test_missing_duplicate_and_foreign_collected_item_graph_refuse(self):
        with self.assertRaises(Refused):self.assess()
        manager=self.manager_for();record=json.loads(manager.assessment_path.read_bytes());directory=manager.configuration/'baseline-assessments'/record['artifact_directory']
        path=directory/'cis.arf.xml';original=path.read_bytes()
        for defect in ('missing','duplicate','foreign-source','duplicate-report','external-ref'):
            tree=ET.fromstring(original)
            if defect=='missing':
                facts=next(tree.iter(S+'oval_system_characteristics'));facts.remove(facts.find(S+'system_data'))
            elif defect=='duplicate':
                data=next(tree.iter(S+'system_data'));data.append(copy.deepcopy(data[0]))
            elif defect=='foreign-source':
                source=next(tree.iter('{http://scap.nist.gov/schema/scap/source/1.2}component'));source[0].set('substantive-change','same-id-foreign-source')
            elif defect=='duplicate-report':
                group=next(tree.iter(A+'reports'));group.append(copy.deepcopy(group[-1]))
            else:
                test=next(tree.iter(X+'TestResult'));next(test.iter(X+'check-content-ref')).set('href','oval0')
            path.write_bytes(ET.tostring(tree))
            with self.subTest(defect=defect),self.assertRaises(Refused):Content.assessment_evidence(directory,'cis',self.selected['assessments'][0]['profile_id'])
        path.write_bytes(original)
