#!/usr/bin/env python3
"""Build a pinned kernel-patch candidate in the isolated Rocky toolchain.

This never loads a module, signs a release, or labels a patch qualified. Run in a
network-disabled build container with /build on dedicated build storage. Native
qualification and publisher/module signing are separate release steps.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess

KPATCH_COMMIT = '74ac9ffe96df2704eb6f141bc7e680a7f449503e'
ROCKY_KEY_SHA256 = '3a66e521e7a4abac9768d889c7cd60a8250f59512b275cf576c8a10ff34624c1'
SHA = re.compile(r'[a-f0-9]{64}')
RELEASE = re.compile(r'5\.14\.0-[0-9][A-Za-z0-9._-]*\.el9(?:_[0-9]+)?\.x86_64')
MAX_INPUT = 8 * 1024**3


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate build metadata')
        value[key] = item
    return value


def command(argv, **kwargs):
    kwargs.setdefault('stdout', subprocess.PIPE)
    result = subprocess.run(argv, text=True, check=True, **kwargs)
    return (result.stdout or '').strip()


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            digest.update(block)
    return digest.hexdigest()


def snapshot(entry, destination):
    if not isinstance(entry, dict) or set(entry) != {'path', 'sha256'} or not SHA.fullmatch(str(entry['sha256'])):
        raise ValueError('Every build input requires an explicit SHA256 pin')
    source = Path(entry['path'])
    if not source.is_absolute():
        raise ValueError('Build inputs must use absolute paths')
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_INPUT:
            raise ValueError('Build input must be a bounded regular file')
        digest = hashlib.sha256()
        with destination.open('xb') as target:
            os.fchmod(target.fileno(), 0o400)
            for block in iter(lambda: stream.read(1024**2), b''):
                target.write(block)
                digest.update(block)
            target.flush()
            os.fsync(target.fileno())
        after = os.fstat(stream.fileno())
        if any(getattr(before, name) != getattr(after, name) for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('Build input changed during capture')
        if digest.hexdigest() != entry['sha256']:
            raise ValueError('Build input differs from its pin')
    return destination


def recipe(raw):
    if len(raw) > 128 * 1024:
        raise ValueError('Oversized livepatch recipe')
    value = json.loads(raw, object_pairs_hook=unique)
    fields = {'schema', 'kernel_release', 'module_name', 'source_rpm', 'config', 'vmlinux', 'patches', 'security_fixes'}
    if not isinstance(value, dict) or set(value) != fields or type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Unsupported livepatch build recipe')
    if not isinstance(value['kernel_release'], str) or not RELEASE.fullmatch(value['kernel_release']):
        raise ValueError('Expected an exact Rocky 9 x86_64 kernel release')
    if not isinstance(value['module_name'], str) or not re.fullmatch(r'livepatch_[a-z0-9_]{1,40}', value['module_name']):
        raise ValueError('Unsafe livepatch module name')
    if not isinstance(value['patches'], list) or not 1 <= len(value['patches']) <= 100:
        raise ValueError('At least one explicit source patch is required')
    fixes = value['security_fixes']
    if not isinstance(fixes, list) or not fixes or any(not isinstance(s, str) or not 1 <= len(s) <= 300 for s in fixes):
        raise ValueError('Document the security fixes or qualification-only purpose')
    return value


def build(manifest, output, *, runner=command, jobs=2):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('Use the isolated Rocky x86_64 livepatch builder')
    if type(jobs) is not int or not 1 <= jobs <= 32:
        raise ValueError('Invalid parallel build count')
    value = recipe(Path(manifest).read_bytes())
    output = Path(output).absolute()
    output.mkdir(mode=0o700)  # Never reuse/delete another build or cache.
    for name in ('inputs', 'cache', 'tmp', 'modules'):
        (output / name).mkdir(mode=0o700)
    record = {'schema': 1, 'state': 'capturing', 'kernel_release': value['kernel_release'],
              'module_name': value['module_name'], 'security_fixes': value['security_fixes'],
              'kpatch_commit': KPATCH_COMMIT, 'module_signed': False,
              'native_transition_verified': False, 'published': False}
    def save():
        target = output / 'build-receipt.json'
        target.write_text(json.dumps(record, indent=2) + '\n')
        target.chmod(0o600)
    save()
    try:
        names = {'source_rpm': 'kernel-' + value['kernel_release'].removesuffix('.x86_64') + '.src.rpm',
                 'config': 'kernel.config', 'vmlinux': 'vmlinux'}
        paths = {key: snapshot(value[key], output / 'inputs' / name) for key, name in names.items()}
        patches = [snapshot(item, output / 'inputs' / ('%03d.patch' % i)) for i, item in enumerate(value['patches'])]
        if len({item['sha256'] for item in value['patches']}) != len(patches):
            raise ValueError('Duplicate source patches')
        config = paths['config'].read_text()
        for option in ('CONFIG_LIVEPATCH=y', 'CONFIG_HAVE_RELIABLE_STACKTRACE=y', 'CONFIG_MODULE_SIG=y', 'CONFIG_FUNCTION_TRACER=y', 'CONFIG_X86_64=y'):
            if option not in config.splitlines():
                raise ValueError('Kernel config lacks ' + option)
        if sha('/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9') != ROCKY_KEY_SHA256:
            raise ValueError('Unexpected Rocky RPM trust key')
        signature = runner(['rpmkeys', '--checksig', '--verbose', str(paths['source_rpm'])])
        if not re.search(r'Signature, key ID 350d275d: OK', signature) or 'NOT OK' in signature or 'NOKEY' in signature:
            raise ValueError('Source RPM lacks the expected Rocky signature')
        rpm_identity = runner(['rpm', '-qp', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}:%{SOURCEPACKAGE}', str(paths['source_rpm'])])
        if rpm_identity != names['source_rpm'].removesuffix('.src.rpm') + ':1':
            raise ValueError('Source RPM and target kernel release differ')
        if runner(['git', '-C', '/opt/kpatch', 'rev-parse', 'HEAD']) != KPATCH_COMMIT:
            raise ValueError('Unexpected kpatch source revision')
        if runner(['git', '-C', '/opt/kpatch', 'status', '--porcelain', '--untracked-files=no']):
            raise ValueError('Modified kpatch source tree')
        record.update(state='building', source_inputs=value,
                      compiler=runner(['gcc', '--version']),
                      toolchain_rpms=runner(['rpm', '-qa', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n']))
        save()
        env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C',
               'CACHEDIR': str(output / 'cache'), 'TMPDIR': str(output / 'tmp'),
               'XDG_CACHE_HOME': str(output / 'cache'), 'CCACHE_DIR': str(output / 'cache/ccache')}
        argv = ['kpatch-build', '--sourcerpm', str(paths['source_rpm']), '--config', str(paths['config']),
                '--vmlinux', str(paths['vmlinux']), '--name', value['module_name'], '--jobs', str(jobs),
                '--output', str(output / 'modules'), '--skip-cleanup'] + list(map(str, patches))
        with (output / 'build.log').open('x') as log:
            # No compiler check bypass, non-replace mode or module loading.
            runner(argv, cwd=output, env=env, stdout=log, stderr=subprocess.STDOUT)
        modules = list((output / 'modules').glob('*.ko'))
        if len(modules) != 1 or modules[0].name != value['module_name'] + '.ko':
            raise ValueError('Expected exactly the requested livepatch module')
        module = modules[0]
        if runner(['modinfo', '-F', 'livepatch', str(module)]) != 'Y':
            raise ValueError('Output is not a kernel livepatch module')
        vermagic = runner(['modinfo', '-F', 'vermagic', str(module)])
        if vermagic.split()[0] != value['kernel_release']:
            raise ValueError('Patch module targets a different kernel')
        if runner(['modinfo', '-F', 'name', str(module)]) != value['module_name']:
            raise ValueError('Patch module identity differs')
        if any(sha(paths[key]) != value[key]['sha256'] for key in names) or any(sha(p) != entry['sha256'] for p, entry in zip(patches, value['patches'])):
            raise ValueError('Captured inputs changed during the build')
        record.update(state='candidate_requires_signing_and_guest_validation', module=str(module),
                      module_sha256=sha(module), module_bytes=module.stat().st_size, vermagic=vermagic)
        save()
        return record
    except Exception as exc:
        record.update(state='failed', error_type=type(exc).__name__, error=str(exc))
        save()
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    print(json.dumps(build(args.manifest, args.output, jobs=args.jobs), indent=2))
