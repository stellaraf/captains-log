"""Real publisher/CMS signatures; native kernel observations remain separate."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from nebulalog_manager import livepatch as lp
from nebulalog_manager.common import Refused, run

KERNEL = '5.14.0-687.56.1.el9_8.x86_64'
NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)


class LivepatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name).resolve()
        cls.key = cls.root / 'publisher-private.pem'
        cls.pub = cls.root / 'publisher.pem'
        cls.signer = cls.root / 'signer-private.pem'
        cls.cert = cls.root / 'signer.pem'
        for key in (cls.key, cls.signer):
            run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(key)])
        run(['openssl', 'pkey', '-in', str(cls.key), '-pubout', '-out', str(cls.pub)])
        run(['openssl', 'req', '-new', '-x509', '-key', str(cls.signer), '-out', str(cls.cert), '-days', '2', '-subj', '/CN=Disposable test signer'])
        run(['openssl', 'x509', '-in', str(cls.cert), '-outform', 'DER', '-out', str(cls.root / 'signer.der')])
        elf = bytearray(128)
        elf[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HH', elf, 16, 1, 62)
        (cls.root / 'unsigned').write_bytes(elf)
        run(['openssl', 'cms', '-sign', '-binary', '-noattr', '-nocerts', '-md', 'sha256', '-in', str(cls.root / 'unsigned'), '-signer', str(cls.cert), '-inkey', str(cls.signer), '-outform', 'DER', '-out', str(cls.root / 'signature')])
        sig = (cls.root / 'signature').read_bytes()
        cls.module = bytes(elf) + sig + b'\0\0\x02\0\0\0\0\0' + struct.pack('!I', len(sig)) + lp.MARKER

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(tmp.cleanup)
        self.bundle = Path(tmp.name)
        self.state = self.bundle / 'state'
        self.state.mkdir()
        self.manifest = dict(schema=1, product='captains-log', channel='kernel-livepatch-stable', sequence=2,
                             issued_at='2026-10-11T00:00:00Z', expires_at='2026-11-01T00:00:00Z', kernel_release=KERNEL,
                             kernel_image_sha256='a'*64, kernel_config_sha256='b'*64, module_name='livepatch_test',
                             security_fixes=['qualification-only; no security coverage'])
        self.report = dict(schema=1, kernel_release=KERNEL, module_sha256=lp.digest(self.module),
                           checks={key: True for key in lp.CHECKS}, evidence_sha256='c'*64)
        self.artifact('module', self.module)
        self.artifact('certificate', (self.root / 'signer.der').read_bytes())
        self.artifact('qualification', json.dumps(self.report).encode())
        self.trust = dict(pem_sha256=lp.digest(self.pub.read_bytes()), spki_sha256='d'*64)
        self.calls = []
        for item in (patch.object(lp, 'require_linux_root'), patch.object(lp, 'enrolled_key', return_value=self.trust),
                     patch.object(lp, '_tree'), patch('nebulalog_manager.update_enrollment._tree'),
                     patch('nebulalog_manager.update_enrollment.ROOT_UID', os.getuid())):
            item.start()
            self.addCleanup(item.stop)

    def artifact(self, role, raw):
        name = lp.FILES[role]
        (self.bundle / name).write_bytes(raw)
        (self.bundle / name).chmod(0o600)
        self.manifest[role] = dict(name=name, bytes=len(raw), sha256=lp.digest(raw))

    def publish(self):
        path = self.bundle / 'livepatch.json'
        path.write_text(json.dumps(self.manifest))
        run(['openssl', 'dgst', '-sha256', '-sign', str(self.key), '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32', '-out', str(self.bundle / 'livepatch.sig'), str(path)])

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == 'modinfo':
            return dict(name='livepatch_test', livepatch='Y', vermagic=KERNEL+' SMP mod_unload', sig_hashalgo='sha256')[argv[2]]
        return run(argv, **kwargs)

    def verify(self, **kwargs):
        args = dict(current_sequence=1, kernel_release=KERNEL, kernel_image_sha256='a'*64,
                    kernel_config_sha256='b'*64, now=NOW, runner=self.runner)
        args.update(kwargs)
        return lp.verify_bundle(self.bundle, self.state, self.pub, **args)

    def test_real_rsa_pss_and_detached_cms_do_not_claim_kernel_acceptance(self):
        self.publish()
        result = self.verify()
        self.assertTrue(result['module_signature_verified'])
        for key in ('kernel_trust_verified', 'applied', 'native_transition_verified'):
            self.assertFalse(result[key])
        self.assertEqual(list((self.state / 'livepatch-verification').iterdir()), [])
        self.assertFalse(any(call[0] in ('insmod', 'modprobe', 'mokutil') for call in self.calls))

    def test_tampered_publisher_manifest_refused(self):
        self.publish()
        with (self.bundle / 'livepatch.json').open('ab') as stream:
            stream.write(b' ')
        with self.assertRaises((Refused, subprocess.CalledProcessError)):
            self.verify()

    def test_tampered_module_with_republished_hash_fails_actual_cms(self):
        altered = bytearray(self.module)
        altered[70] ^= 1
        self.artifact('module', bytes(altered))
        self.report['module_sha256'] = lp.digest(bytes(altered))
        self.artifact('qualification', json.dumps(self.report).encode())
        self.publish()
        with self.assertRaises((Refused, subprocess.CalledProcessError)):
            self.verify()

    def test_wrong_pinned_certificate_fails_actual_cms(self):
        other = self.bundle / 'other.pem'
        run(['openssl', 'req', '-new', '-x509', '-key', str(self.key), '-out', str(other), '-days', '2', '-subj', '/CN=Wrong signer'])
        run(['openssl', 'x509', '-in', str(other), '-outform', 'DER', '-out', str(self.bundle / 'other.der')])
        self.artifact('certificate', (self.bundle / 'other.der').read_bytes())
        self.publish()
        with self.assertRaises((Refused, subprocess.CalledProcessError)):
            self.verify()

    def test_artifact_hash_mismatch(self):
        self.publish()
        (self.bundle / 'module.ko').write_bytes(self.module+b'x')
        with self.assertRaisesRegex(Refused, 'descriptor'):
            self.verify()

    def test_replay_kernel_mismatch_and_expiry(self):
        self.publish()
        for kwargs in (dict(current_sequence=2), dict(kernel_release='other'), dict(kernel_image_sha256='f'*64),
                       dict(now=datetime(2026, 12, 1, tzinfo=timezone.utc))):
            with self.subTest(kwargs=kwargs), self.assertRaises(Refused):
                self.verify(**kwargs)

    def test_unqualified_report_refused(self):
        self.report['checks']['live_transition_complete'] = False
        self.artifact('qualification', json.dumps(self.report).encode())
        self.publish()
        with self.assertRaisesRegex(Refused, 'qualification'):
            self.verify()

    def test_unsafe_descriptor_and_unknown_metadata(self):
        for change in (dict(schema=True), dict(sequence=True), dict(extra=True), dict(module_name='other'),
                       dict(module=dict(name='../module.ko', bytes=3, sha256='a'*64))):
            value = {**self.manifest, **change}
            with self.subTest(change=change), self.assertRaises(Refused):
                lp.validate_manifest(json.dumps(value).encode(), current_sequence=1, kernel_release=KERNEL, now=NOW)

    def test_malformed_trailers_and_wrong_elf_machine(self):
        for raw in (b'x'*200, self.module[:-1], self.module[:-len(lp.MARKER)-4]+b'\xff'*4+lp.MARKER,
                    self.module[:18]+b'\xb7\x00'+self.module[20:]):
            with self.assertRaises(Refused):
                lp.module_parts(raw)

    def test_enrollment_change_refused_after_verification(self):
        self.publish()
        with patch.object(lp, 'enrolled_key', side_effect=[self.trust, {**self.trust, 'spki_sha256':'e'*64}]), self.assertRaisesRegex(Refused, 'enrollment changed'):
            self.verify()

    def test_staging_retains_authenticated_bytes_after_incoming_changes(self):
        self.publish()
        result = lp.stage_bundle(self.bundle, self.state, self.pub, current_sequence=1,
                                 kernel_release=KERNEL, kernel_image_sha256='a'*64,
                                 kernel_config_sha256='b'*64, now=NOW, runner=self.runner)
        captured = Path(result['captured_bundle'])
        original = (captured / 'module.ko').read_bytes()
        (self.bundle / 'module.ko').write_bytes(b'changed incoming file')
        self.assertEqual((captured / 'module.ko').read_bytes(), original)
        self.assertEqual(lp.digest(original), result['manifest']['module']['sha256'])
        self.assertEqual(json.loads((captured / 'capture.json').read_text())['state'], 'captured_and_authenticated')
        self.assertFalse(result['applied'])
        self.assertFalse(any(c[0] in ('insmod', 'modprobe') for c in self.calls))

    def test_failed_staging_retains_evidence_without_verified_receipt(self):
        self.publish()
        (self.bundle / 'module.ko').write_bytes(b'invalid module')
        with self.assertRaises(Refused):
            lp.stage_bundle(self.bundle, self.state, self.pub, current_sequence=1,
                            kernel_release=KERNEL, kernel_image_sha256='a'*64,
                            kernel_config_sha256='b'*64, now=NOW, runner=self.runner)
        captured, = (self.state / 'livepatch-candidates').iterdir()
        record = json.loads((captured / 'capture.json').read_text())
        self.assertEqual(record['state'], 'capture_failed')
        self.assertFalse(record['authenticated'])
        self.assertFalse((captured / 'verification.json').exists())
        self.assertTrue((captured / 'module.ko').exists())

    def apply_candidate(self, health=lambda: True, transition_error=None, reapply=False, boot_id=None, image_hash=None, integrity=True, default_health=False):
        target = dict(kernel_release=KERNEL, boot_id=boot_id or '11111111-2222-4333-8444-555555555555',
                      kernel_image_sha256=image_hash or 'a'*64, kernel_config_sha256='b'*64)
        def runner(argv, **kwargs):
            if argv[0] == 'keyctl':
                journal = json.loads((self.state / 'livepatch-transaction.json').read_text())
                self.assertEqual(journal['state'], 'loading')
                self.assertEqual(kwargs['input'], (Path(journal['captured_bundle']) / 'module-signer.der').read_bytes())
                self.calls.append(argv)
                return '12345'
            if argv[0] == 'insmod':
                journal = json.loads((self.state / 'livepatch-transaction.json').read_text())
                self.assertEqual(journal['state'], 'loading')
                self.assertEqual(journal['signer']['key_serial'], 12345)
                self.assertEqual(lp.digest(Path(argv[1]).read_bytes()), journal['module_sha256'])
                self.calls.append(argv)
                return ''
            return self.runner(argv, **kwargs)
        def runtime_health(stage):
            self.observed_health_stage = stage
            return health()
        with patch.object(lp, 'measure_target', return_value=target), \
             patch.object(lp, '_runtime_health', side_effect=runtime_health), \
             patch.object(lp, '_integrity_clean', return_value=integrity), \
             patch.object(lp.security, 'status', return_value={'host_controls_ok': True}), \
             patch.object(lp, 'wait_for_transition', side_effect=transition_error, return_value={'boot_id':target['boot_id'],'state':'transition_complete'}):
            return lp.apply_bundle(None if reapply else self.bundle, self.state, self.pub, health_check=None if default_health else health, runner=runner, now=NOW, reapply=reapply)

    def test_signer_rejection_prevents_module_load_and_retains_recovery(self):
        self.publish()
        with patch.object(lp, 'load_signer', side_effect=Refused('untrusted signer')):
            with self.assertRaisesRegex(Refused, 'untrusted signer'):
                self.apply_candidate()
        self.assertFalse(any(c[0] == 'insmod' for c in self.calls))
        record = json.loads((self.state / 'livepatch-transaction.json').read_text())
        self.assertEqual(record['state'], 'recovery_required')
        self.assertFalse(record['force_attempted'])

    def test_signer_bytes_are_checked_before_kernel_request(self):
        descriptor = dict(self.manifest['certificate'])
        with (self.bundle / 'module-signer.der').open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaisesRegex(Refused, 'signer changed'):
            lp.load_signer(self.bundle, descriptor, self.runner)
        self.assertFalse(any(c[0] == 'keyctl' for c in self.calls))

    def test_signer_loading_uses_only_restricted_secondary_keyring(self):
        def runner(argv, **kwargs):
            self.assertEqual(argv, ['keyctl', 'padd', 'asymmetric', '', '%:.secondary_trusted_keys'])
            self.assertEqual(kwargs['input'], (self.bundle / 'module-signer.der').read_bytes())
            return '12345'
        observed = lp.load_signer(self.bundle, self.manifest['certificate'], runner)
        self.assertEqual(observed['certificate_sha256'], self.manifest['certificate']['sha256'])
        for invalid in ('', '0', '-1', '2147483648', '12345\nextra'):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(Refused, 'invalid key identity'):
                lp.load_signer(self.bundle, self.manifest['certificate'], lambda *a, **k: invalid)

    def test_application_journals_before_load_and_refuses_replay(self):
        self.publish()
        result = self.apply_candidate()
        self.assertEqual(result['state'], 'applied')
        self.assertTrue(result['post_load_health_verified'])
        self.assertEqual(sum(c[0]=='insmod' for c in self.calls), 1)
        with self.assertRaisesRegex(Refused, 'replay'):
            self.apply_candidate()
        self.assertEqual(sum(c[0]=='insmod' for c in self.calls), 1)

    def test_post_load_failure_requires_recovery_without_unload_or_retry(self):
        self.publish()
        health = iter([True, False])
        with self.assertRaisesRegex(Refused, 'post-load'):
            self.apply_candidate(lambda: next(health))
        record = json.loads((self.state / 'livepatch-transaction.json').read_text())
        self.assertEqual(record['state'], 'recovery_required')
        self.assertFalse(record['automatic_unload_attempted'])
        self.assertFalse(record['force_attempted'])
        with self.assertRaisesRegex(Refused, 'explicit recovery'):
            self.apply_candidate()
        self.assertEqual(sum(c[0]=='insmod' for c in self.calls), 1)
        self.assertFalse(any(c[0] in ('rmmod', 'modprobe') for c in self.calls))

    def test_unhealthy_service_and_interrupted_maintenance_prevent_load(self):
        self.publish()
        with self.assertRaisesRegex(Refused, 'healthy host'):
            self.apply_candidate(lambda: False)
        (self.state / 'transaction.json').write_text(json.dumps({'state':'activating'}))
        with self.assertRaisesRegex(Refused, 'maintenance requires recovery'):
            self.apply_candidate()
        self.assertFalse(any(c[0]=='insmod' for c in self.calls))

    def test_failed_kernel_security_refuses_before_loading(self):
        self.publish()
        with patch.object(lp.security, 'status', return_value={'host_controls_ok': False}):
            with self.assertRaisesRegex(Refused, 'healthy host'):
                lp.apply_bundle(self.bundle, self.state, self.pub, health_check=lambda: True,
                                runner=self.runner, now=NOW)
        self.assertFalse(any(c[0]=='insmod' for c in self.calls))
        self.assertFalse((self.state / 'livepatch-transaction.json').exists())

    def test_transition_timeout_retains_recovery_boundary(self):
        self.publish()
        with self.assertRaisesRegex(Refused, 'timed out'):
            self.apply_candidate(transition_error=Refused('transition timed out'))
        journal = json.loads((self.state / 'livepatch-transaction.json').read_text())
        self.assertEqual(journal['state'], 'recovery_required')
        self.assertNotIn('post_load_health_verified', journal)
        self.assertEqual(sum(c[0]=='insmod' for c in self.calls), 1)

    def test_other_maintenance_accepts_only_completed_healthy_transaction(self):
        path = self.state / 'livepatch-transaction.json'
        lp.require_settled(self.state)
        for state in ('prepared', 'loading', 'recovery_required', 'unknown'):
            path.write_text(json.dumps(dict(schema=1, state=state, sequence=2, post_load_health_verified=True)))
            path.chmod(0o600)
            with self.subTest(state=state), self.assertRaisesRegex(Refused, 'Livepatch recovery'):
                lp.require_settled(self.state)
        path.write_text(json.dumps(dict(schema=1, state='applied', sequence=2, post_load_health_verified=False)))
        with self.assertRaises(Refused): lp.require_settled(self.state)
        path.write_text(json.dumps(dict(schema=1, state='applied', sequence=2, post_load_health_verified=True)))
        lp.require_settled(self.state)

    def test_new_boot_reapplies_exact_committed_candidate_without_sequence_advance(self):
        self.publish()
        first = self.apply_candidate()
        second = self.apply_candidate(reapply=True, boot_id='aaaaaaaa-2222-4333-8444-555555555555')
        self.assertEqual(second['operation'], 'reapply_after_reboot')
        for key in ('sequence', 'manifest_sha256', 'module_sha256', 'captured_bundle'):
            self.assertEqual(first[key], second[key])
        self.assertNotEqual(first['target']['boot_id'], second['target']['boot_id'])
        self.assertEqual(sum(c[0]=='insmod' for c in self.calls), 2)

    def test_reapplication_refuses_same_boot_and_changed_kernel(self):
        self.publish()
        self.apply_candidate()
        with self.assertRaisesRegex(Refused, 'Same-boot'):
            self.apply_candidate(reapply=True)
        with self.assertRaisesRegex(Refused, 'Replacement kernel'):
            self.apply_candidate(reapply=True, boot_id='aaaaaaaa-2222-4333-8444-555555555555', image_hash='f'*64)
        self.assertEqual(sum(c[0]=='insmod' for c in self.calls), 1)

    def test_reapplication_refuses_changed_committed_manifest_identity(self):
        self.publish()
        self.apply_candidate()
        path = self.state / 'livepatch-transaction.json'
        journal = json.loads(path.read_text())
        journal['manifest_sha256'] = 'f'*64
        path.write_text(json.dumps(journal))
        with self.assertRaisesRegex(Refused, 'committed livepatch identity'):
            self.apply_candidate(reapply=True, boot_id='aaaaaaaa-2222-4333-8444-555555555555')
        self.assertEqual(sum(c[0]=='insmod' for c in self.calls), 1)

    def test_reapplication_refuses_missing_prior_boot_identity(self):
        self.publish()
        self.apply_candidate()
        path = self.state / 'livepatch-transaction.json'
        journal = json.loads(path.read_text())
        del journal['target']['boot_id']
        path.write_text(json.dumps(journal))
        with self.assertRaisesRegex(Refused, 'boot identity is incomplete'):
            self.apply_candidate(reapply=True, boot_id='aaaaaaaa-2222-4333-8444-555555555555')
        self.assertEqual(sum(c[0]=='insmod' for c in self.calls), 1)

    def test_dirty_integrity_refuses_before_module_load(self):
        self.publish()
        with self.assertRaisesRegex(Refused, 'healthy host'):
            self.apply_candidate(integrity=False)
        self.assertFalse(any(c[0]=='insmod' for c in self.calls))

    def test_default_health_uses_protected_reusable_boot_stage(self):
        self.publish()
        result = self.apply_candidate(default_health=True)
        self.assertEqual(self.observed_health_stage, self.state / 'livepatch-health' / result['target']['boot_id'])
        self.assertTrue(self.observed_health_stage.is_dir())

    def test_runtime_health_requires_all_existing_lifecycle_checks(self):
        from nebulalog_manager.updates import REQUIRED_CHECKS
        from nebulalog_adapters import lifecycle
        result = {'ok':True, 'checks':{name:True for name in REQUIRED_CHECKS}}
        with patch.object(lifecycle, 'load_config', return_value={}), patch.object(lifecycle, 'Lifecycle') as factory:
            factory.return_value.livepatch_health.return_value = result
            self.assertTrue(lp._runtime_health(self.state))
            result['checks']['ingestion'] = False
            self.assertFalse(lp._runtime_health(self.state))

    def feed_fixture(self):
        from types import SimpleNamespace
        self.publish()
        self.feed_calls = []
        self.feed_bytes = {}
        assets = []
        for number, name in enumerate(['livepatch.json', 'livepatch.sig', *lp.FILES.values()], 1):
            raw = (self.bundle / name).read_bytes()
            self.feed_bytes[str(number)] = raw
            assets.append({'id':number, 'name':name, 'size':len(raw), 'state':'uploaded'})
        self.feed_release = {'id':7, 'draft':False, 'prerelease':False,
                             'tag_name':'livepatch-'+KERNEL, 'assets':assets}
        def fetch(path, *, maximum, output=None, expected_size=None, expected_hash=None):
            self.feed_calls.append(path)
            raw = json.dumps(self.feed_release).encode() if '/releases/tags/' in path else self.feed_bytes[path.rsplit('/',1)[1]]
            if len(raw)>maximum or expected_size is not None and len(raw)!=expected_size or expected_hash is not None and lp.digest(raw)!=expected_hash:
                raise Refused('fixture transport size/hash refusal')
            if output is not None:
                output.write(raw)
                return {'bytes':len(raw), 'sha256':lp.digest(raw)}
            return raw
        return SimpleNamespace(fetch=fetch)

    def fetch_candidate(self, transport, sequence=1):
        return lp.fetch_candidate(transport, self.state, self.pub, 'stellaraf/captains-log',
                                  kernel_release=KERNEL, kernel_image_sha256='a'*64,
                                  kernel_config_sha256='b'*64, current_sequence=sequence,
                                  runner=self.runner, now=NOW)

    def test_feed_authenticates_metadata_and_artifacts_without_loading(self):
        result = self.fetch_candidate(self.feed_fixture())
        self.assertEqual(result['state'], 'authenticated_candidate')
        self.assertFalse(result['applied'])
        self.assertEqual(self.feed_calls[0], '/repos/stellaraf/captains-log/releases/tags/livepatch-'+KERNEL)
        self.assertEqual(len(self.feed_calls), 6)
        self.assertTrue((Path(result['downloaded_bundle'])/'download.json').exists())
        self.assertFalse(any(c[0]=='insmod' for c in self.calls))

    def test_feed_rejects_forged_manifest_before_module_download(self):
        transport = self.feed_fixture()
        self.feed_bytes['1'] += b' '
        self.feed_release['assets'][0]['size'] += 1
        with self.assertRaises(Refused): self.fetch_candidate(transport)
        self.assertEqual(len(self.feed_calls), 3)
        stage, = (self.state/'livepatch-downloads').iterdir()
        self.assertEqual(json.loads((stage/'download.json').read_text())['state'], 'failed')
        self.assertFalse((stage/'module.ko').exists())

    def test_feed_reports_authenticated_nonnewer_without_payload_download(self):
        result = self.fetch_candidate(self.feed_fixture(), sequence=2)
        self.assertEqual(result['state'], 'not_newer')
        self.assertFalse(result['artifacts_verified'])
        self.assertEqual(len(self.feed_calls), 3)

    def test_feed_rejects_draft_or_wrong_tag_and_payload_tampering(self):
        transport = self.feed_fixture()
        self.feed_release['draft'] = True
        with self.assertRaises(Refused): self.fetch_candidate(transport)
        self.feed_release['draft'] = False
        self.feed_release['tag_name'] = 'other'
        with self.assertRaises(Refused): self.fetch_candidate(transport)
        self.feed_release['tag_name'] = 'livepatch-'+KERNEL
        damaged = bytearray(self.feed_bytes['3']); damaged[70] ^= 1
        self.feed_bytes['3'] = bytes(damaged)
        with self.assertRaises(Refused): self.fetch_candidate(transport)

    def test_status_distinguishes_current_boot_reboot_and_replacement_kernel(self):
        self.assertEqual(lp.status(self.state, self.pub)['state'], 'no_committed_patch')
        self.publish()
        transaction = self.apply_candidate()
        target = dict(transaction['target'])
        with patch.object(lp, 'measure_target', return_value=target), patch.object(lp, 'wait_for_transition', return_value={'boot_id':target['boot_id']}) as observe:
            result = lp.status(self.state, self.pub, runner=self.runner, now=NOW)
            self.assertTrue(result['active_observed'])
            self.assertFalse(result['services_verified'])
            self.assertFalse(result['fips_postcheck_verified'])
            observe.assert_called_once()
            observe.reset_mock()
            target['boot_id'] = 'aaaaaaaa-2222-4333-8444-555555555555'
            result = lp.status(self.state, self.pub, runner=self.runner, now=NOW)
            self.assertEqual(result['state'], 'reapplication_required')
            self.assertFalse(result['active_observed'])
            observe.assert_not_called()
            target['kernel_image_sha256'] = 'f'*64
            self.assertEqual(lp.status(self.state, self.pub, runner=self.runner, now=NOW)['state'], 'replacement_kernel_requires_patch')
        self.assertEqual(sum(c[0]=='insmod' for c in self.calls), 1)

    def test_status_refuses_changed_retained_bytes_and_unfinished_load(self):
        self.publish()
        transaction = self.apply_candidate()
        with patch.object(lp, 'measure_target', return_value=transaction['target']), patch.object(lp, 'wait_for_transition') as observe:
            (Path(transaction['captured_bundle']) / 'module.ko').write_bytes(b'changed')
            with self.assertRaises(Refused): lp.status(self.state, self.pub, runner=self.runner, now=NOW)
            observe.assert_not_called()
            transaction['state'] = 'loading'
            (self.state / 'livepatch-transaction.json').write_text(json.dumps(transaction))
            with self.assertRaisesRegex(Refused, 'recovery'): lp.status(self.state, self.pub, runner=self.runner, now=NOW)

    def test_status_refuses_missing_module_or_boot_change_during_observation(self):
        self.publish()
        transaction = self.apply_candidate()
        with patch.object(lp, 'measure_target', return_value=transaction['target']), patch.object(lp, 'wait_for_transition', side_effect=Refused('missing module')):
            with self.assertRaisesRegex(Refused, 'missing module'): lp.status(self.state, self.pub, runner=self.runner, now=NOW)
        with patch.object(lp, 'measure_target', return_value=transaction['target']), patch.object(lp, 'wait_for_transition', return_value={'boot_id':'aaaaaaaa-2222-4333-8444-555555555555'}):
            with self.assertRaisesRegex(Refused, 'target changed'): lp.status(self.state, self.pub, runner=self.runner, now=NOW)
