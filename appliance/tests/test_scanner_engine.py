"""Nonmutating scanner boundary; vendor/native qualification is separate.

The small RPM bytes and command replies below are explicit fixtures. Private
qualification runs additionally use the retained, actually signed vendor RPMs
and full native headers without altering the production acquisition pins.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from nebulalog_manager import os_payload as rpm
from nebulalog_manager.common import Refused

Engine = rpm.ScannerEngine


def native_header(member):
    name, version, release, _, _ = Engine.PACKAGES[member]
    suffix = 'old' if member.startswith('from/') else 'new'
    if name == 'openscap':
        paths = [('/usr/lib64', stat.S_IFDIR | 0o755, 0, ''),
                 ('/usr/lib64/libopenscap.' + suffix, stat.S_IFREG | 0o644, 0, '')]
        paths += [(p, stat.S_IFDIR | 0o755, 0, '') for p in sorted(Engine.OMITTED_DOCUMENT_DIRECTORIES)]
        paths += [('/usr/share/doc/openscap/' + p, stat.S_IFREG | 0o644, 2, '') for p in
                  ('AUTHORS','NEWS','README.md','manual/images/vertical-logo.png','manual/manual.html')]
    else:
        paths = [('/usr/bin/oscap', stat.S_IFREG | 0o755, 0, ''),
                 ('/usr/share/man/man8/oscap.8.gz', stat.S_IFREG | 0o644, 2, '')]
    directories = sorted({str(Path(p).parent) + '/' for p, *_ in paths})
    return {'Name': [name], 'Epoch': [1], 'Version': [version], 'Release': [release], 'Arch': ['x86_64'],
            'Filedigestalgo': [8], 'Basenames': [Path(p).name for p, *_ in paths], 'Dirnames': directories,
            'Dirindexes': [directories.index(str(Path(p).parent) + '/') for p, *_ in paths],
            'Filemodes': [m for _, m, *_ in paths], 'Filesizes': [0 if stat.S_ISDIR(m) else 3 for _, m, *_ in paths],
            'Filedigests': ['' if stat.S_ISDIR(m) else rpm.sha(b'abc') for _, m, *_ in paths],
            'Fileusername': ['root'] * len(paths), 'Filegroupname': ['root'] * len(paths),
            'Fileflags': [f for _, _, f, _ in paths], 'Filelinktos': [l for _, _, _, l in paths]}


def xml(headers):
    output = []
    for h in headers:
        root = ET.Element('rpmHeader')
        for name, values in h.items():
            tag = ET.SubElement(root, 'rpmTag', name=name)
            for value in values:
                ET.SubElement(tag, 'integer' if type(value) is int else 'string').text = str(value)
        output.append(ET.tostring(root, encoding='unicode'))
    return ''.join(output)


def package(name, version, release):
    return {'Name': [name], 'Epoch': [0], 'Version': [version], 'Release': [release], 'Arch': ['x86_64']}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bodies = {member: ('fixture:' + member).encode() for member in Engine.PACKAGES}
        self.pins = {member: (*value[:3], len(self.bodies[member]), rpm.sha(self.bodies[member]))
                     for member, value in Engine.PACKAGES.items()}
        p = patch.object(Engine, 'PACKAGES', self.pins)
        p.start(); self.addCleanup(p.stop)
        self.headers = {member: native_header(member) for member in self.pins}
        self.descriptor = {'schema': 1, 'kind': Engine.KIND, 'version': '1.0.1', 'platform': dict(Engine.PLATFORM),
                           'transaction': dict(Engine.TRANSACTION), 'trigger_profile': Engine.TRIGGER_PROFILE,
                           'rollback_profile': Engine.ROLLBACK_PROFILE}
        for side in ('from', 'to'):
            self.descriptor[side] = []
            for member in sorted(m for m in self.pins if m.startswith(side + '/')):
                h = self.headers[member]
                n, v, r, length, checksum = self.pins[member]
                self.descriptor[side].append({'name': n, 'nevra': f'{n}-1:{v}-{r}.x86_64', 'member': member,
                    'bytes': length, 'sha256': checksum, 'header_sha256': rpm.sha(Engine.encoded(h)),
                    'payload_sha256': rpm.sha(Engine.encoded(Engine.payload(h)))})
        self.path = self.root / 'scanner-engine.tar'
        self.archive()

    def archive(self, *, descriptor=None, extra=None, mutate=None, tail=b''):
        files = {'engine.json': Engine.encoded(self.descriptor if descriptor is None else descriptor), **self.bodies}
        if extra: files.update(extra)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, body in files.items():
                entry = tarfile.TarInfo(name); entry.size = len(body); entry.mode = 0o644
                if mutate: mutate(entry)
                archive.addfile(entry, io.BytesIO(body))
        self.path.write_bytes(stream.getvalue() + tail)

    def current(self, side='from'):
        scanner = self.headers[side + '/openscap-scanner.rpm']
        engine = {'scanner_nevra': rpm.identity(scanner)['nevra'], 'version_sha256': rpm.sha(b'OpenSCAP fixture')}
        return {'sequence': 10, 'version': '1.0.0', 'components': {'host': {'version': '1.0.0'},
                'nebulalog': {'version': '1.0.0'}, 'baseline': {'version': 'sha256:' + 'a' * 64,
                'generation': 'b' * 64, 'policy_sha256': 'c' * 64, 'engine': engine}}}


class ArchiveTests(Fixture):
    def test_canonical_archive_checks_every_member_without_claiming_vendor_or_execution_acceptance(self):
        result = Engine.verify_archive(self.path, expected_sha256=rpm.sha(self.path.read_bytes()),
            expected_descriptor_sha256=rpm.sha(Engine.encoded(self.descriptor)), expected_version='1.0.1')
        self.assertEqual(result['descriptor'], self.descriptor)
        self.assertEqual(result['files'], self.bodies)
        self.assertIs(result['vendor_signatures_verified'], False)
        self.assertIs(result['activation_allowed'], False)
        with self.assertRaisesRegex(Refused, 'execution_not_implemented'):
            Engine.require_executable({**result, 'activation_allowed': True, 'qualification_gaps': []})

    def test_component_is_exact_and_has_explicit_first_admission_identifier(self):
        component = {'artifact': 'scanner-engine.tar', 'version': '1.0.1', 'from_versions': [Engine.admission_identity(self.current())],
                     'rollback_safe': True, 'engine_schema': 1, 'descriptor_sha256': rpm.sha(Engine.encoded(self.descriptor))}
        self.assertEqual(Engine.validate_component(component), component)
        for changes in ({'argv': ['rpm']}, {'engine_schema': True}, {'rollback_safe': False}, {'from_versions': ['*']},
                        {'from_versions': ['1.0.1']}, {'from_versions': ['1.0.0', '1.0.0']}, {'artifact': 'other.tar'}):
            with self.subTest(changes=changes), self.assertRaises(Refused): Engine.validate_component({**component, **changes})

    def test_first_admission_is_exact_read_only_and_existing_identity_is_bound(self):
        current = self.current(); before = copy.deepcopy(current)
        expected = 'enrolled-engine-sha256:' + rpm.sha(Engine.encoded(current['components']['baseline']['engine']))
        self.assertEqual(Engine.admission_identity(current), expected)
        self.assertEqual(current, before)
        current['components']['scap'] = {'version': '1.0.0', 'engine_sha256': expected.split(':')[1], 'descriptor_sha256': 'd' * 64}
        self.assertEqual(Engine.admission_identity(current), '1.0.0')
        for field, value in [('engine_sha256', '0' * 64), ('descriptor_sha256', 'bad'), ('artifact', 'label-only')]:
            changed = copy.deepcopy(current); changed['components']['scap'][field] = value
            with self.subTest(field=field), self.assertRaises(Refused): Engine.admission_identity(changed)

    def test_empty_fabricated_or_wrong_engine_baseline_cannot_supply_admission(self):
        cases = [{}, {'components': {}}, {**self.current(), 'sequence': True}]
        for baseline in ({}, {'engine': {}}, {**self.current()['components']['baseline'], 'generation': 'not-digest'},
                         {**self.current()['components']['baseline'], 'engine': {'scanner_nevra': 'future', 'version_sha256': 'a' * 64}}):
            current = self.current(); current['components']['baseline'] = baseline; cases.append(current)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(Refused): Engine.admission_identity(value)

    def test_unknown_pair_profile_flags_shape_and_hashes_refuse(self):
        cases = []
        for key, val in [('schema', True), ('trigger_profile', 'approved'), ('rollback_profile', '*'),
                         ('transaction', {'excludedocs': True, 'vendor_triggers': 'skip'}), ('argv', ['rpm', '-U'])]:
            d = copy.deepcopy(self.descriptor); d[key] = val; cases.append(d)
        for field, val in [('nevra', 'openscap-1:1.3.15-1.el9.x86_64'), ('sha256', '0' * 64), ('bytes', True), ('header_sha256', 'bad')]:
            d = copy.deepcopy(self.descriptor); d['to'][0][field] = val; cases.append(d)
        for d in cases:
            with self.subTest(d=d), self.assertRaises(Refused): Engine.descriptor(d)
        for kwargs in ({'expected_version': 'other'}, {'expected_sha256': '0' * 64}, {'expected_descriptor_sha256': '0' * 64}):
            with self.subTest(kwargs=kwargs), self.assertRaises(Refused): Engine.verify_archive(self.path, **kwargs)

    def test_tar_extra_trailing_link_pax_mode_and_missing_member_refuse(self):
        for kwargs in ({'extra': {'../outside': b'x'}}, {'tail': b'x' * 512},
                       {'mutate': lambda e: setattr(e, 'mode', 0o666)},
                       {'mutate': lambda e: setattr(e, 'linkname', '/etc/passwd')}):
            self.archive(**kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(Refused): Engine.verify_archive(self.path)
        del self.bodies['to/openscap.rpm']; self.archive()
        with self.assertRaises(Refused): Engine.verify_archive(self.path)

    def test_noncanonical_duplicate_json_and_member_tampering_refuse(self):
        good = self.path.read_bytes()
        for raw in (json.dumps(self.descriptor, indent=2).encode(), b'{"schema":1,"schema":1}'):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                for name, body in {'engine.json': raw, **self.bodies}.items():
                    e = tarfile.TarInfo(name); e.size=len(body); e.mode=0o644; archive.addfile(e, io.BytesIO(body))
            self.path.write_bytes(stream.getvalue())
            with self.assertRaises(Refused): Engine.verify_archive(self.path)
        self.path.write_bytes(good)
        self.bodies['from/openscap.rpm'] += b'x'; self.archive()
        with self.assertRaisesRegex(Refused, 'rpm_member_changed'): Engine.verify_archive(self.path)

    def test_generic_os_still_refuses_scanner(self):
        for header in self.headers.values():
            with self.assertRaisesRegex(Refused, 'migration_recipe'): rpm.payload(header)

    def test_signed_header_rejects_scripts_capabilities_foreign_paths_links_and_dependencies(self):
        for change in ({'Postin': ['touch /etc/arbitrary']}, {'Filecaps': ['cap_net_admin=ep']},
                       {'Filedigestalgo': [1]}, {'Requireflags': [8]}, {'Fileflags': [0, 1, 2]},
                       {'Filelinktos': ['', '/etc/passwd', '']}):
            with self.subTest(change=change), self.assertRaises(Refused): Engine.payload({**self.headers['from/openscap.rpm'], **change})


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Native protected-path fixtures require Linux root')
class NativeInspectionTests(Fixture):
    def setUp(self):
        super().setUp()
        # /work is a private root-owned tmpfs in the pinned test runner. This is
        # an explicit test storage boundary, not relaxed production ancestry.
        self.private = tempfile.TemporaryDirectory(dir='/work')
        self.addCleanup(self.private.cleanup)
        self.stage = Path(self.private.name)
        self.key = self.stage / 'rocky-key'; self.key.write_bytes(b'fixture-key')
        for p in (patch.object(rpm, 'KEY', self.key), patch.object(rpm, 'KEY_SHA256', rpm.sha(b'fixture-key'))):
            p.start(); self.addCleanup(p.stop)
        self.calls = []
        self.signature = ('Header V4 RSA/SHA256 Signature, key ID 350d275d: OK\n'
                          'Header SHA256 digest: OK\nPayload SHA256 digest: OK')
        self.installed = []
        for member in ('from/openscap.rpm', 'from/openscap-scanner.rpm'):
            h=copy.deepcopy(self.headers[member]); h['Filestates']=[2 if f & 2 or p in Engine.OMITTED_DOCUMENT_DIRECTORIES else 0 for f,p in zip(h['Fileflags'],Engine._paths(h))]
            h.update(Installcolor=[3],Installtime=[100],Installtid=[90],Packagedigestalgos=[8,10],
                     Packagedigests=[rpm.sha(self.bodies[member]),hashlib.sha512(self.bodies[member]).hexdigest()])
            self.installed.append(h)
        self.installed += [package('rpm', '4.16.1.3', '40.el9'), package('rpm-libs', '4.16.1.3', '40.el9')]
        self.trigger_pins = {}
        for name, version, release, prefix in [('glibc-common','2.34','283.el9_8','/usr/lib64'), ('man-db','2.9.3','9.el9','/usr/share/man')]:
            h=package(name,version,release); h.update(Transfiletriggername=[prefix], Transfiletriggerscripts=['fixture only'])
            self.installed.append(h)
            self.trigger_pins[rpm.identity(h)['nevra']]=rpm.sha(Engine.encoded({k:v for k,v in h.items() if k.startswith('Transfiletrigger')}))
        p=patch.object(Engine,'TRIGGERS',self.trigger_pins); p.start(); self.addCleanup(p.stop)
        self.observations = {}
        for h in self.installed[:2]:
            for row in Engine.payload(h)['files']:
                self.observations[row['path']] = None if row['flags'] & 2 or row['path'] in Engine.OMITTED_DOCUMENT_DIRECTORIES else {**{k:v for k,v in row.items() if k not in ('path','flags')},'xattrs':{}}

    def runner(self, argv, **kwargs):
        self.calls.append(list(argv))
        if '--checksig' in argv: return self.signature
        if '--query' in argv and '--package' in argv:
            checksum=Path(argv[-1]).stem
            member=next(m for m,p in self.pins.items() if p[-1]==checksum)
            return xml([self.headers[member]])
        if argv == ['/usr/bin/rpm','--query','--all','--xml']: return xml(self.installed)
        if '--dbpath' in argv and '--query' in argv: return 'gpg-pubkey 350d275d'
        if '--initdb' in argv or '--import' in argv: return ''
        if argv == ['/usr/bin/rpm','--eval','%{_dbpath}']: return '/var/lib/rpm'
        if argv == ['/usr/bin/rpm','--version']: return 'RPM version 4.16.1.3'
        if argv == ['/usr/bin/uname','-m']: return 'x86_64'
        if argv[-1] == 'rocky-release': return 'rocky-release 9.8 noarch'
        if argv == ['/usr/bin/oscap','--version']: return 'OpenSCAP fixture'
        self.fail('Unexpected command: ' + repr(argv))

    def test_actual_private_files_and_all_four_signature_header_bindings(self):
        value=Engine.inspect_archive(self.path,self.stage,runner=self.runner)
        self.assertTrue(value['vendor_signatures_verified']); self.assertFalse(value['activation_allowed'])
        self.assertEqual(len([a for a in self.calls if '--checksig' in a]),4)
        self.assertEqual(value['qualification_gaps'],list(Engine.QUALIFICATION_GAPS))
        self.assertEqual(Engine.inspect_archive(self.path,self.stage,runner=self.runner),value)
        self.assertFalse(any(a[0]=='/usr/bin/rpm' and any(flag in a for flag in ['--upgrade','--install','--erase']) for a in self.calls))

    def test_missing_payload_digest_wrong_signature_and_header_refuse(self):
        for report in (self.signature.replace('Payload SHA256 digest: OK',''),self.signature.replace('350d275d','deadbeef')):
            self.signature=report
            with self.assertRaises(Refused): Engine.inspect_archive(self.path,self.stage,runner=self.runner)
        self.signature='Header V4 RSA/SHA256 Signature, key ID 350d275d: OK\nHeader SHA256 digest: OK\nPayload SHA256 digest: OK'
        self.headers['from/openscap-scanner.rpm']['Summary']=['changed query bytes']
        with self.assertRaisesRegex(Refused,'signed_header_or_payload_changed'): Engine.inspect_archive(self.path,self.stage,runner=self.runner)

    def test_private_stage_symlink_and_changed_retained_rpm_refuse(self):
        link=self.stage/'link'; link.symlink_to(self.stage,target_is_directory=True)
        with self.assertRaises(Refused): Engine.inspect_archive(self.path,link,runner=self.runner)
        Engine.inspect_archive(self.path,self.stage,runner=self.runner)
        next((self.stage/'scanner-engine-inspection').glob('*.rpm')).write_bytes(b'changed')
        with self.assertRaises(Refused): Engine.inspect_archive(self.path,self.stage,runner=self.runner)

    def measure(self):
        with patch.object(Engine,'_observe',side_effect=lambda path:copy.deepcopy(self.observations.get(str(path)))):
            return Engine.measure(self.path,self.stage,current=self.current(),runner=self.runner)

    def test_measurement_keeps_exact_omissions_closure_and_execution_refusal(self):
        result=self.measure()
        self.assertFalse(result['activation_allowed'])
        self.assertFalse(result['closure']['dependency_solver_verified'])
        self.assertEqual(len(result['closure']['triggers']),2)
        self.assertEqual(result['files']['/usr/share/man/man8/oscap.8.gz'],{'disposition':2,'flags':2,'observed':None})
        self.assertEqual(result['prospective_paths']['/usr/lib64/libopenscap.new']['observed'],None)

    def test_docs_present_bad_disposition_foreign_ownership_and_candidate_conflict_refuse(self):
        cases=['present_doc','doc_state','shared','new_conflict','new_owned_absent','installed_bytes']
        saved_i=copy.deepcopy(self.installed);saved_o=copy.deepcopy(self.observations)
        for case in cases:
            self.installed=copy.deepcopy(saved_i);self.observations=copy.deepcopy(saved_o)
            if case=='present_doc': self.observations['/usr/share/man/man8/oscap.8.gz']={'kind':'file'}
            if case=='doc_state': self.installed[1]['Filestates'][-1]=0
            if case=='shared':
                h=copy.deepcopy(self.installed[1]);h['Name']=['foreign'];self.installed.append(h)
            if case=='new_conflict': self.observations['/usr/lib64/libopenscap.new']={'kind':'file'}
            if case=='new_owned_absent':
                h=package('foreign','1','1');h.update(Basenames=['libopenscap.new'],Dirnames=['/usr/lib64/'],Dirindexes=[0]);self.installed.append(h)
            if case=='installed_bytes': self.observations['/usr/bin/oscap']['sha256']='0'*64
            with self.subTest(case=case),self.assertRaises(Refused):self.measure()

    def test_native_profile_or_provider_drift_is_not_approved_by_recipe_label(self):
        payloads=[Engine.payload(h) for h in self.headers.values()]
        for change in ('owner','body','missing','plugin','rpm','provider'):
            h=copy.deepcopy(self.installed)
            if change=='owner': h[-1]['Release']=['other']
            if change=='body': h[-1]['Transfiletriggerscripts']=['changed']
            if change=='missing':h.pop()
            if change=='plugin':h.append(package('openscap-engine-sce','1','1'))
            if change=='rpm':h[2]['Release']=['future']
            p=copy.deepcopy(payloads)
            if change=='provider':p[0]['dependencies']['require']=[{'name':'missing','flags':8,'version':'1'}]
            with self.subTest(change=change),self.assertRaises(Refused):Engine.closure(h,p)

    def test_omitted_parent_graph_nondoc_shared_present_and_state_refuse(self):
        payload=Engine.payload(self.headers['from/openscap.rpm'])
        self.assertEqual(Engine.omitted_directories(payload),set(Engine.OMITTED_DOCUMENT_DIRECTORIES))
        for change in ('nondoc','link','missing_parent','extra_file'):
            p=copy.deepcopy(payload)
            if change=='nondoc': next(r for r in p['files'] if r['path'].endswith('README.md'))['flags']=0
            if change=='link': next(r for r in p['files'] if r['path'].endswith('README.md'))['kind']='symlink'
            if change=='missing_parent':p['files']=[r for r in p['files'] if r['path']!='/usr/share/doc/openscap/manual']
            if change=='extra_file':p['files'].append({'path':'/usr/share/doc/openscap/manual/hidden','kind':'file','flags':0})
            with self.subTest(change=change),self.assertRaises(Refused):Engine.omitted_directories(p)
        saved_i=copy.deepcopy(self.installed);saved_o=copy.deepcopy(self.observations)
        for change in ('shared','foreign_descendant','present','state'):
            self.installed=copy.deepcopy(saved_i);self.observations=copy.deepcopy(saved_o)
            path='/usr/share/doc/openscap/manual'
            if change=='shared':
                h=copy.deepcopy(self.installed[0]);h['Name']=['foreign'];self.installed.append(h)
            if change=='foreign_descendant':
                h=package('foreign','1','1');h.update(Basenames=['foreign'],Dirnames=['/usr/share/doc/openscap/manual/'],Dirindexes=[0]);self.installed.append(h)
            if change=='present':self.observations[path]={'kind':'directory'}
            if change=='state':self.installed[0]['Filestates'][Engine._paths(self.installed[0]).index(path)]=0
            with self.subTest(change=change),self.assertRaises(Refused):self.measure()

    def test_all_signed_header_invariants_and_installation_tags_are_checked(self):
        signed=self.headers['from/openscap.rpm'];actual=self.installed[0];body=self.bodies['from/openscap.rpm']
        proof=Engine.installed_header(signed,actual,body)
        self.assertEqual(proof['signed_invariants_sha256'],rpm.sha(Engine.encoded(signed)))
        for key,value in [('Summary',['foreign']),('Installtime',[True]),('Installcolor',[1]),
                          ('Packagedigests',['0'*64,'0'*128]),('Packagedigestalgos',[8]),('Filestates',[0])]:
            changed={**actual,key:value}
            with self.subTest(key=key),self.assertRaises(Refused):Engine.installed_header(signed,changed,body)

    def test_root_filesystem_path_is_valid_but_other_empty_basenames_refuse(self):
        self.assertEqual(Engine._paths({'Basenames':[''],'Dirnames':['/'],'Dirindexes':[0]}),['/'])
        with self.assertRaises(Refused):Engine._paths({'Basenames':[''],'Dirnames':['/usr/'],'Dirindexes':[0]})

    def test_real_native_read_observes_link_xattrs_and_refuses_foreign_ancestry(self):
        file=self.stage/'file';file.write_bytes(b'abc');file.chmod(0o644)
        self.assertEqual(Engine._observe(file)['sha256'],rpm.sha(b'abc'))
        link=self.stage/'link';link.symlink_to('file')
        self.assertEqual(Engine._observe(link)['target'],'file')
        self.assertIsNone(Engine._observe(self.stage/'missing'))
        bad=self.stage/'unsafe';bad.mkdir();bad.chmod(0o777)
        with self.assertRaises(Refused):Engine._observe(bad/'file')


class BuilderTests(NativeInspectionTests):
    def setUp(self):
        super().setUp()
        temporary=tempfile.TemporaryDirectory(dir='/work');self.addCleanup(temporary.cleanup)
        self.inputs=Path(temporary.name)
        for side in ('from','to'):(self.inputs/side).mkdir(mode=0o700)
        for member,raw in self.bodies.items():(self.inputs/member).write_bytes(raw)

    def build(self,stage=None,runner=None):
        return Engine.build_archive(self.inputs,stage or self.stage,version='1.0.1',runner=runner or self.runner)

    def test_deterministic_builder_roundtrip_and_actual_verifier_gate(self):
        first=self.build();body=(self.stage/'scanner-engine.tar').read_bytes()
        temporary=tempfile.TemporaryDirectory(dir='/work');self.addCleanup(temporary.cleanup)
        second=self.build(Path(temporary.name))
        self.assertEqual((Path(temporary.name)/'scanner-engine.tar').read_bytes(),body)
        self.assertEqual(first,second)
        consumed=Engine.verify_archive(self.stage/first['filename'],expected_sha256=first['archive_sha256'],
            expected_descriptor_sha256=first['descriptor_sha256'],expected_version=first['version'])
        self.assertEqual(consumed['descriptor'],self.descriptor)
        self.assertTrue(first['vendor_signatures_verified']);self.assertFalse(first['activation_allowed'])
        self.assertEqual(sum('--checksig' in a for a in self.calls),8)
        with tarfile.open(fileobj=io.BytesIO(body),mode='r:') as archive:
            self.assertEqual(archive.getnames(),['engine.json',*sorted(self.bodies)])
            self.assertTrue(all((e.uid,e.gid,e.mode,e.mtime,e.uname,e.gname)==(0,0,0o644,0,'','') for e in archive))

    def test_preexisting_output_never_overwritten_or_reinterpreted_as_success(self):
        output=self.stage/'scanner-engine.tar';output.write_bytes(b'owned evidence')
        with self.assertRaisesRegex(Refused,'builder_output_exists'):self.build()
        self.assertEqual(output.read_bytes(),b'owned evidence');self.assertEqual(self.calls,[])
        output.unlink();output.symlink_to(self.stage/'missing')
        with self.assertRaisesRegex(Refused,'builder_output_exists'):self.build()
        self.assertTrue(output.is_symlink());self.assertEqual(self.calls,[])

    def test_overlapping_directories_and_unsafe_input_aliases_refuse(self):
        for stage in (self.inputs,self.inputs/'from'):
            with self.subTest(stage=stage),self.assertRaisesRegex(Refused,'overlap'):self.build(stage)
        original=self.inputs/'from/openscap.rpm';original.unlink();original.symlink_to(self.inputs/'to/openscap.rpm')
        with self.assertRaises(Refused):self.build()
        original.unlink();os.link(self.inputs/'to/openscap.rpm',original)
        with self.assertRaises(Refused):self.build()
        self.assertFalse((self.stage/'scanner-engine.tar').exists())

    def test_unpinned_input_and_unexpected_source_inventory_refuse(self):
        extra=self.inputs/'unlisted';extra.write_bytes(b'x')
        with self.assertRaisesRegex(Refused,'builder_input_inventory'):self.build()
        extra.unlink();(self.inputs/'from/openscap.rpm').write_bytes(b'not pinned')
        with self.assertRaisesRegex(Refused,'builder_input_not_pinned'):self.build()
        self.assertFalse((self.stage/'scanner-engine.tar').exists())

    def test_signature_failure_preserves_private_evidence_and_publishes_nothing(self):
        self.signature=self.signature.replace('350d275d','deadbeef')
        with self.assertRaisesRegex(Refused,'signature_not_verified'):self.build()
        self.assertTrue((self.stage/'scanner-engine-build/scanner-engine.tar').is_file())
        self.assertTrue((self.stage/'scanner-engine-inspection/engine.json').is_file())
        self.assertFalse((self.stage/'scanner-engine.tar').exists())

    def test_input_change_after_verification_prevents_publication(self):
        count=0
        def changed(argv,**kwargs):
            nonlocal count
            result=self.runner(argv,**kwargs)
            if '--package' in argv and 'scanner-engine-inspection' in argv[-1]:
                count+=1
                if count==4:(self.inputs/'from/openscap.rpm').write_bytes(b'changed after native check')
            return result
        with self.assertRaisesRegex(Refused,'builder_input_changed'):self.build(runner=changed)
        self.assertFalse((self.stage/'scanner-engine.tar').exists())
        self.assertTrue((self.stage/'scanner-engine-inspection/inspection.json').is_file())

    def test_private_candidate_change_after_verification_prevents_publication(self):
        count=0
        def changed(argv,**kwargs):
            nonlocal count
            result=self.runner(argv,**kwargs)
            if '--package' in argv and 'scanner-engine-inspection' in argv[-1]:
                count+=1
                if count==4:(self.stage/'scanner-engine-build/scanner-engine.tar').write_bytes(b'changed candidate')
            return result
        with self.assertRaisesRegex(Refused,'builder_candidate_changed'):self.build(runner=changed)
        self.assertFalse((self.stage/'scanner-engine.tar').exists())
        self.assertTrue((self.stage/'scanner-engine-inspection/inspection.json').is_file())

    def test_concurrent_output_publication_is_not_overwritten(self):
        count=0
        def changed(argv,**kwargs):
            nonlocal count
            result=self.runner(argv,**kwargs)
            if '--package' in argv and 'scanner-engine-inspection' in argv[-1]:
                count+=1
                if count==4:(self.stage/'scanner-engine.tar').write_bytes(b'other publisher evidence')
            return result
        with self.assertRaises(FileExistsError):self.build(runner=changed)
        self.assertEqual((self.stage/'scanner-engine.tar').read_bytes(),b'other publisher evidence')
        self.assertTrue((self.stage/'scanner-engine-inspection/inspection.json').is_file())

    def test_builder_consumer_version_and_descriptor_mismatch_remain_refused(self):
        built=self.build()
        for expected in ({'expected_version':'1.0.2'},{'expected_descriptor_sha256':'0'*64},{'expected_sha256':'0'*64}):
            with self.subTest(expected=expected),self.assertRaises(Refused):Engine.verify_archive(self.stage/built['filename'],**expected)
        with self.assertRaisesRegex(Refused,'execution_not_implemented'):Engine.require_executable(built)


# Reuse only the protected native fixture; do not run its existing tests twice.
for _name in NativeInspectionTests.__dict__:
    if _name.startswith('test_'):
        setattr(BuilderTests,_name,None)


if __name__=='__main__': unittest.main()
