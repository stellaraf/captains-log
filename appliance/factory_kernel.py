#!/usr/bin/python3
"""Retain the factory's exact signed vendor kernel RPMs during image creation.

Capture runs only under the inherited private provisioner lock. Verification is
offline and read-only apart from a disposable isolated RPM signature keyring.
Neither action installs/removes packages or changes any boot configuration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


def protected_source(path, maximum):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Unsafe fixed factory verifier ancestry')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & 0o022 or not 0 < before.st_size <= maximum):
            raise RuntimeError('Unsafe fixed factory verifier input')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in
            ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        raise RuntimeError('Factory verifier input changed while read')
    return raw


def verify_runtime_source():
    """Measure original factory dependencies before importing any of them."""
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise RuntimeError('Duplicate factory source property')
            value[key] = item
        return value
    share = Path('/usr/share/nebulalog')
    raw = protected_source(share / 'source-manifest.json', 8 * 1024**2)
    descriptor = json.loads(protected_source(share / 'initial-release.json', 65536), object_pairs_hook=pairs)
    source = json.loads(raw, object_pairs_hook=pairs)
    if (descriptor.get('source_snapshot_sha256') != hashlib.sha256(raw).hexdigest()
            or type(source) is not dict or set(source) != {'schema', 'files'} or source['schema'] != 1
            or type(source['files']) is not dict or not 1 <= len(source['files']) <= 10000):
        raise RuntimeError('Factory dependency source binding changed')
    required = {'kernel_updates.py', 'os_payload.py', 'common.py', 'host_job_storage.py'}
    found = set()
    for prefix, target in (('appliance/nebulalog_manager/', Path('/usr/lib/nebulalog/nebulalog_manager')),
                           ('appliance/adapters/nebulalog_adapters/', Path('/usr/lib/nebulalog/nebulalog_adapters'))):
        for name, checksum in source['files'].items():
            if name.startswith(prefix) and name.endswith('.py'):
                filename = name.removeprefix(prefix)
                if not re.fullmatch(r'[a-z_][a-z0-9_]*\.py', filename) or not re.fullmatch(r'[a-f0-9]{64}', str(checksum)):
                    raise RuntimeError('Invalid factory dependency source identity')
                if hashlib.sha256(protected_source(target / filename, 8 * 1024**2)).hexdigest() != checksum:
                    raise RuntimeError('Factory verifier dependency differs from captured source')
                if prefix == 'appliance/nebulalog_manager/': found.add(filename)
    if not required <= found:
        raise RuntimeError('Factory verifier dependency inventory is incomplete')


if __name__ == '__main__':
    if '--verify' in sys.argv[1:]:
        verify_runtime_source()
    else:
        # Refuse a runtime capture invocation before importing build helpers.
        # The full provisioning/customer-state guard runs again in capture().
        descriptor, lock = os.fstat(9), Path('/etc').stat()
        if (Path(__file__).name != 'factory_kernel.py'
                or (descriptor.st_dev, descriptor.st_ino) != (lock.st_dev, lock.st_ino)):
            raise RuntimeError('Factory capture requires its inherited provisioner lock')

sys.path.insert(0, '/usr/lib/nebulalog')
from nebulalog_manager import kernel_updates as kernel, os_payload as rpm
from nebulalog_manager.common import Refused, require_linux_root, run
from nebulalog_manager.host_job_storage import exact, strict_json

DESTINATION = Path('/usr/share/nebulalog/kernel-provenance')
SCRATCH = Path('/run')
REPOSITORY = 'https://download.rockylinux.org/pub/rocky/9.8/BaseOS/x86_64/os/'
META = {'manifest.json', 'capture.json', 'installed-inventory.xml'}


def guard():
    # The source provisioner invokes this helper from beside factory_host.py.
    # It is deliberately unavailable as a customer/runtime capture command.
    from factory_host import guard as private_build_guard
    private_build_guard()


def directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o700 or path.resolve() != path):
        raise Refused('Factory kernel provenance requires an owned private real directory')


def ancestry(path):
    for parent in path.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022):
            raise Refused('Unsafe factory kernel provenance ancestry')


def installed(runner):
    rpm.platform(runner)
    xml, headers, _ = rpm.inventory(runner)
    versions, items = set(), {}
    for header in headers:
        name = rpm.one(header, 'Name')
        if name not in kernel.NAMES:
            continue
        item = kernel.payload(header)
        if name in items:
            raise Refused('Factory capture requires one complete installed kernel set')
        items[name] = item
        versions.add(item['kernel'])
    if set(items) != kernel.NAMES or len(versions) != 1:
        raise Refused('Factory capture requires one complete installed kernel set')
    version = next(iter(versions))
    if (not re.fullmatch(r'5\.14\.0-[0-9.]+\.el9_8\.x86_64', version)
            or runner(['/usr/bin/uname', '-r']) != version
            or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + version):
        raise Refused('Factory provenance requires the running/default Rocky 9.8 vendor kernel')
    for name in sorted(kernel.NAMES):
        if runner(['/usr/bin/rpm', '--verify', items[name]['nevra']], timeout=180):
            raise Refused('Installed factory kernel payload does not verify')
    return xml, version, items


def trusted_key():
    if rpm.sha(rpm.read(rpm.KEY, 65536)) != rpm.KEY_SHA256:
        raise Refused('Factory kernel vendor trust changed')


def entries(destination, *, complete=False):
    directory(destination)
    names = set()
    with os.scandir(destination) as files:
        for count, entry in enumerate(files, 1):
            if count > 7 or not (entry.name in META or re.fullmatch(r'[a-f0-9]{64}\.rpm', entry.name)):
                raise Refused('Unexpected factory kernel provenance content')
            rpm.read(Path(entry.path), rpm.MAX_XML if entry.name == 'installed-inventory.xml' else rpm.MAX_RPM)
            names.add(entry.name)
    if complete and (not META <= names or len(names) != 7):
        raise Refused('Incomplete factory kernel provenance')
    return names


def verify(*, runner=run):
    require_linux_root()
    trusted_key()
    names = entries(DESTINATION, complete=True)
    manifest_raw = rpm.read(DESTINATION / 'manifest.json', 65536)
    manifest = strict_json(manifest_raw)
    exact(manifest, {'schema', 'kernel', 'packages'})
    if (type(manifest['schema']) is not int or manifest['schema'] != 1
            or type(manifest['packages']) is not list or len(manifest['packages']) != 4
            or manifest_raw != kernel.encode(manifest)):
        raise Refused('Invalid factory kernel manifest')
    inventory_raw = rpm.read(DESTINATION / 'installed-inventory.xml', rpm.MAX_XML)
    captured = {rpm.one(h, 'Name'): kernel.payload(h) for h in rpm.headers(inventory_raw.decode())
                if rpm.one(h, 'Name') in kernel.NAMES}
    _, version, current = installed(runner)
    if captured != current or manifest['kernel'] != version:
        raise Refused('Factory kernel installed inventory changed')
    signatures, seen, expected = {}, set(), set(META)
    with tempfile.TemporaryDirectory(prefix='captainslog-factory-verify-', dir=SCRATCH) as temporary:
        keydb = Path(temporary) / 'keydb'
        rpm.init_keydb(keydb, runner)
        for item in manifest['packages']:
            exact(item, {'name', 'nevra', 'rpm', 'sha256', 'bytes'})
            if (item['name'] not in kernel.NAMES or item['name'] in seen
                    or not kernel.SHA.fullmatch(str(item['sha256'])) or item['rpm'] != item['sha256'] + '.rpm'
                    or type(item['bytes']) is not int or not 0 < item['bytes'] <= rpm.MAX_RPM
                    or item['nevra'] != current[item['name']]['nevra']):
                raise Refused('Invalid factory kernel package identity')
            path = DESTINATION / item['rpm']
            raw = rpm.read(path)
            if rpm.sha(raw) != item['sha256'] or len(raw) != item['bytes']:
                raise Refused('Factory kernel retained RPM bytes changed')
            headers = rpm.headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(path)], timeout=180))
            if len(headers) != 1 or kernel.payload(headers[0]) != current[item['name']]:
                raise Refused('Factory signed RPM and installed header differ')
            signatures[item['name']] = rpm.signature(path, keydb, runner)
            seen.add(item['name']); expected.add(item['rpm'])
    if names != expected:
        raise Refused('Factory kernel file inventory changed')
    receipt = strict_json(rpm.read(DESTINATION / 'capture.json', 65536))
    if receipt != {'schema': 1, 'kernel': version, 'key_sha256': rpm.KEY_SHA256,
                   'manifest_sha256': rpm.sha(manifest_raw), 'inventory_sha256': rpm.sha(inventory_raw),
                   'signatures': signatures, 'release_accepted': False}:
        raise Refused('Factory kernel signature/capture receipt changed')
    return {'schema': 1, 'verified': True, 'kernel': version,
            'manifest_sha256': receipt['manifest_sha256'], 'inventory_sha256': receipt['inventory_sha256']}


def capture(*, runner=run):
    guard()
    trusted_key()
    xml, version, current = installed(runner)
    ancestry(DESTINATION)
    if DESTINATION.exists() or DESTINATION.is_symlink():
        entries(DESTINATION)
        if os.path.lexists(DESTINATION / 'manifest.json'):
            return verify(runner=runner)
    else:
        DESTINATION.mkdir(mode=0o700)
        directory(DESTINATION)
    # Temporary work is confined to the disposable build guest. DNF downloads
    # only exact installed NEVRAs from the fixed HTTPS vendor repository.
    # It never solves a replacement, enables arbitrary repos or executes RPM.
    with tempfile.TemporaryDirectory(prefix='captainslog-factory-capture-', dir=SCRATCH) as temporary:
        work = Path(temporary)
        for name in ('packages', 'repos', 'cache', 'persist', 'logs'):
            (work / name).mkdir(mode=0o700)
        configuration = work / 'dnf.conf'
        rpm.immutable(configuration, b'[main]\ngpgcheck=1\nsslverify=1\n')
        runner(['/usr/bin/dnf', '--config', str(configuration), '--releasever=9.8',
                '--setopt=reposdir=' + str(work / 'repos'), '--setopt=cachedir=' + str(work / 'cache'),
                '--setopt=persistdir=' + str(work / 'persist'), '--setopt=logdir=' + str(work / 'logs'),
                '--disableplugin=*', '--enableplugin=download', '--disablerepo=*',
                '--repofrompath=captainslog-factory,' + REPOSITORY, '--enablerepo=captainslog-factory',
                '--setopt=captainslog-factory.sslverify=1', '--setopt=captainslog-factory.gpgcheck=1',
                'download', '--destdir', str(work / 'packages'),
                *sorted(item['nevra'] for item in current.values())], timeout=1800)
        paths = list((work / 'packages').iterdir())
        if len(paths) != 4:
            raise Refused('Factory download did not return exactly four signed RPMs')
        keydb = work / 'keydb'
        rpm.init_keydb(keydb, runner)
        proposed, signatures, seen = [], {}, set()
        for path in sorted(paths):
            raw = rpm.read(path)
            rpm.signature(path, keydb, runner)
            headers = rpm.headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(path)], timeout=180))
            if len(headers) != 1:
                raise Refused('Ambiguous factory kernel RPM header')
            payload = kernel.payload(headers[0])
            name = payload['name']
            if name in seen or payload != current.get(name):
                raise Refused('Downloaded vendor RPM differs from exact installed kernel')
            checksum = rpm.sha(raw)
            target = DESTINATION / (checksum + '.rpm')
            rpm.immutable(target, raw)
            signatures[name] = rpm.signature(target, keydb, runner)
            proposed.append({'name': name, 'nevra': payload['nevra'], 'rpm': target.name,
                             'sha256': checksum, 'bytes': len(raw)})
            seen.add(name)
        if seen != kernel.NAMES or installed(runner)[2] != current:
            raise Refused('Factory package inventory changed during capture')
        manifest = {'schema': 1, 'kernel': version, 'packages': sorted(proposed, key=lambda item: item['name'])}
        raw = kernel.encode(manifest)
        rpm.immutable(DESTINATION / 'installed-inventory.xml', xml.encode())
        rpm.immutable(DESTINATION / 'capture.json', kernel.encode({
            'schema': 1, 'kernel': version, 'key_sha256': rpm.KEY_SHA256,
            'manifest_sha256': rpm.sha(raw), 'inventory_sha256': rpm.sha(xml.encode()),
            'signatures': signatures, 'release_accepted': False}))
        # The manifest is the completion marker and is published last.
        rpm.immutable(DESTINATION / 'manifest.json', raw)
        runner(['/usr/sbin/restorecon', '-RF', str(DESTINATION)])
    return verify(runner=runner)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args(argv)
    result = verify() if args.verify else capture()
    sys.stdout.write(kernel.encode(result).decode())


if __name__ == '__main__':
    main()
