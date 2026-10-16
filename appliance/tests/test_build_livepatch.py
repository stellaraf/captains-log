"""Candidate builder refuses mismatched inputs; these are not live kernel tests."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'packer/build_livepatch.py'
SPEC = importlib.util.spec_from_file_location('build_livepatch', SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class LivepatchBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.output = self.root / 'build'
        self.manifest = self.root / 'recipe.json'
        self.release = '5.14.0-687.9.1.el9_8.x86_64'
        self.value = {'schema': 1, 'kernel_release': self.release, 'module_name': 'livepatch_fixture',
                      'security_fixes': ['Qualification fixture only; no vulnerability claim']}
        for key, raw in {'source_rpm': b'fixture RPM', 'vmlinux': b'fixture ELF',
                         'config': b'CONFIG_LIVEPATCH=y\nCONFIG_HAVE_RELIABLE_STACKTRACE=y\nCONFIG_MODULE_SIG=y\nCONFIG_FUNCTION_TRACER=y\nCONFIG_X86_64=y\n',
                         'patch': b'fixture source diff'}.items():
            f = self.root / key
            f.write_bytes(raw)
            entry = {'path': str(f), 'sha256': builder.sha(f)}
            if key == 'patch':
                self.value['patches'] = [entry]
            else:
                self.value[key] = entry
        self.calls = []
        self.bad_release = False
        self.bad_signature = False
        self.dirty = False
        self.fail_build = False
        for target, value in [('platform.system', 'Linux'), ('platform.machine', 'x86_64')]:
            context = patch.object(getattr(builder, target.split('.')[0]), target.split('.')[1], return_value=value)
            context.start(); self.addCleanup(context.stop)
        original_sha = builder.sha
        context = patch.object(builder, 'sha', side_effect=lambda p: builder.ROCKY_KEY_SHA256 if str(p).startswith('/etc/pki/') else original_sha(p))
        context.start(); self.addCleanup(context.stop)

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[0] == 'rpmkeys':
            return 'Header V4 RSA/SHA256 Signature, key ID 350d275d: ' + ('NOKEY' if self.bad_signature else 'OK')
        if argv[:2] == ['rpm', '-qp']:
            return 'kernel-' + self.release.removesuffix('.x86_64') + ':1'
        if argv[0] == 'git':
            return builder.KPATCH_COMMIT if 'rev-parse' in argv else ' M tracked' if self.dirty else ''
        if argv[:2] == ['gcc', '--version']:
            return 'Fixture compiler'
        if argv[:2] == ['rpm', '-qa']:
            return 'Fixture package inventory'
        if argv[0] == 'kpatch-build':
            if self.fail_build:
                raise RuntimeError('Fixture compiler mismatch')
            (self.output / 'modules/livepatch_fixture.ko').write_bytes(b'fixture module')
            return ''
        if argv[0] == 'modinfo':
            return {'livepatch': 'Y', 'name': 'livepatch_fixture',
                    'vermagic': ('wrong-kernel' if self.bad_release else self.release) + ' SMP mod_unload modversions'}[argv[2]]
        raise AssertionError(argv)

    def invoke(self):
        self.manifest.write_text(json.dumps(self.value))
        return builder.build(self.manifest, self.output, runner=self.runner)

    def test_bound_candidate_retains_provenance_without_deployment_claim(self):
        result = self.invoke()
        self.assertEqual(result['state'], 'candidate_requires_signing_and_guest_validation')
        self.assertFalse(result['module_signed'])
        self.assertFalse(result['native_transition_verified'])
        self.assertFalse(result['published'])
        args, options = next(call for call in self.calls if call[0][0] == 'kpatch-build')
        self.assertNotIn('--skip-compiler-check', args)
        self.assertNotIn('--non-replace', args)
        self.assertEqual(Path(options['env']['CACHEDIR']).parent, self.output)
        self.assertNotIn('HOME', options['env'])
        self.assertTrue(all(call[0][0] not in ('insmod', 'modprobe', 'kpatch') for call in self.calls))
        self.assertEqual(json.loads((self.output / 'build-receipt.json').read_text()), result)

    def test_changed_input_never_invokes_build(self):
        (self.root / 'patch').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'pin'):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.assertEqual(json.loads((self.output / 'build-receipt.json').read_text())['state'], 'failed')

    def test_unsigned_source_rpm_refused_before_execution(self):
        self.bad_signature = True
        with self.assertRaisesRegex(ValueError, 'signature'):
            self.invoke()
        self.assertFalse(any(call[0][0] == 'kpatch-build' for call in self.calls))

    def test_modified_toolchain_source_refused(self):
        self.dirty = True
        with self.assertRaisesRegex(ValueError, 'Modified kpatch'):
            self.invoke()

    def test_wrong_target_module_refused(self):
        self.bad_release = True
        with self.assertRaisesRegex(ValueError, 'different kernel'):
            self.invoke()
        self.assertEqual(json.loads((self.output / 'build-receipt.json').read_text())['state'], 'failed')

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir()
        (self.output / 'retained').write_text('keep')
        with self.assertRaises(FileExistsError):
            self.invoke()
        self.assertEqual((self.output / 'retained').read_text(), 'keep')
        self.assertEqual(self.calls, [])

    def test_config_without_livepatch_refused(self):
        path = self.root / 'config'; path.write_bytes(b'CONFIG_MODULE_SIG=y\n')
        self.value['config']['sha256'] = builder.sha(path)
        with self.assertRaisesRegex(ValueError, 'CONFIG_LIVEPATCH'):
            self.invoke()
        self.assertEqual(self.calls, [])

    def test_build_failure_retains_inputs_and_receipt(self):
        self.fail_build = True
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.assertTrue((self.output / 'inputs/000.patch').exists())
        self.assertEqual(json.loads((self.output / 'build-receipt.json').read_text())['state'], 'failed')

    def test_duplicate_keys_and_pathlike_module_names_refused(self):
        with self.assertRaises(ValueError):
            builder.recipe(b'{"schema":1,"schema":1}')
        self.value['module_name'] = '../escape'
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertFalse(self.output.exists())
