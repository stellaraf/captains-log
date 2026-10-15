"""Frozen Rocky kernel installs, generated-output validation and boot binding.

This is a separate installonly recipe, not an extension of the inert RPM ABI.
It never removes a kernel, commits application state, accepts an AIDE database,
reboots, or releases maintenance. The lifecycle owner must supply the fresh
backup/AIDE authorization callback before executing, then accept the exact
returned integrity delta and perform the guarded reboot workflow.

The script templates and generated paths are derived from the signed Rocky
9.8 5.14.0-687.57.1 packages. A changed template requires recipe review. Passing
these transaction checks does not qualify that kernel's FIPS self-tests.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import uuid

from . import os_payload as rpm, security
from .common import Refused, run, require_linux_root, atomic_json
from .host_job_storage import digest, exact, strict_json

NAMES = frozenset(('kernel', 'kernel-core', 'kernel-modules', 'kernel-modules-core'))
KERNEL = re.compile(r'5\.14\.0-[0-9]+(?:\.[0-9]+)+\.el9_[0-9]+\.x86_64')
SHA = re.compile(r'[a-f0-9]{64}')
ACCEPTANCE_FIELDS = {'schema', 'operation_sha256', 'kernel_plan_sha256', 'installed_sha256',
                     'postboot_sha256', 'promotion_sha256', 'resume_sha256', 'kernel', 'boot_id',
                     'recovery_kernel', 'checks', 'finalization', 'previous_acceptance_sha256'}
SCRIPT_TEMPLATES = {
    'kernel': '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    'kernel-core': 'e2d266b02ce22ae1c53c8b40845375220edadc949c7bd1dc20a3e69c78f9531f',
    'kernel-modules': 'da2074658ab63b30798d59906948f4d125feae0841db27d264bf20dd923dca3f',
    'kernel-modules-core': '1b864a32eb7d1fe1f26bca93a8281dcaf6f1c1fd9567111604a74901cd1cf995',
}
DEPMOD = ('modules.alias', 'modules.alias.bin', 'modules.builtin.alias.bin',
          'modules.builtin.bin', 'modules.dep', 'modules.dep.bin', 'modules.devname',
          'modules.softdep', 'modules.symbols', 'modules.symbols.bin')
GRUBENV = '/boot/grub2/grubenv'
KERNEL_CONFIG = '/etc/sysconfig/kernel'
SETTINGS = '/usr/sbin/grub2-get-kernel-settings'
SETTINGS_SHA = 'fc55dfbb2f22e03cc61ca58c09ed60c80ecaf303d2fc74acf3e92d0b5f78fa2d'
INSTALL_HOOKS = {
    '10-devicetree.install': '0829d1d8b5cd1977e95b890163abe5c188df1f6335000a1b3f2c4072fd9001a4',
    '20-grub.install': 'f85c0fe68120d3eb71a8fe96266c2490453b529e5611b2ef2dcbf6ebb46f579f',
    '20-grubby.install': 'ec23c7012ddc92c411a03514f7190758c222b29ed9aa214b5be7b12788568df9',
    '50-depmod.install': 'e94fd6c7bbc239ca0967e36ec3b29db224c6bd20597756da17c087f1400fd409',
    '50-dracut.install': 'b8137a62a191c144e840309cfe6101409013fd5d303780462d3c724ceea633f3',
    '51-dracut-rescue.install': '09f3ed321a4562cffec617c55ed100ab161e98929cc013037242e9e1a257ce6d',
    '60-kdump.install': '22e660fe4a0e3f4a7273990266e35c16d272ed1eecc5d6c2fac76e78656c42b8',
    '90-loaderentry.install': 'c800c57af9d07efe8360f68571e0a16d39239e402947b50fd913cbb58666d942',
    '90-uki-copy.install': 'e4185fc1bd764e21195e3e303e816403b1d2b18a0c83623617a92b41bd780bef',
    '92-crashkernel.install': '4b131cd27490c399f009e2b994948cbb3a7b29511b55618a7d7d918c4e4c621e',
    '95-kernel-hooks.install': 'a238bf9184e9db9511a4f4b589d1bda1296a957fc6dc7ec7344eac008da8e7fd',
    '99-grub-mkconfig.install': 'd41b49fb354c1e110cfca5ead715a42e1b242692091310360ec842a0b87c76e4',
}
MAX_FILE = 256 * 1024**2

# Use the installed native DNF API solely to solve the offline transaction.
# No repos, plugins, remote locations, package execution or history writes.
SOLVE = '''import dnf,dnf.transaction,json,sys,os
for name in ('solve-cache','solve-persist','solve-log'):
    os.makedirs(sys.argv[1]+'/'+name,mode=0o700,exist_ok=True)
with dnf.Base() as base:
    base.conf.plugins=False
    base.conf.cachedir=sys.argv[1]+'/solve-cache'
    base.conf.persistdir=sys.argv[1]+'/solve-persist'
    base.conf.logdir=sys.argv[1]+'/solve-log'
    base.conf.installonly_limit=0
    base.fill_sack(load_system_repo=True,load_available_repos=False)
    for pkg in base.add_remote_rpms(sys.argv[2:],strict=True):
        base.package_install(pkg,strict=True)
    base.resolve(allow_erasing=False)
    rows=[]
    for item in base.transaction:
        pkg=item.pkg
        rows.append({'action':'install' if item.action==dnf.transaction.PKG_INSTALL else 'unsupported',
                     'nevra':pkg.name+'-'+str(pkg.epoch)+':'+pkg.version+'-'+pkg.release+'.'+pkg.arch,
                     'repo':pkg.reponame})
    print(json.dumps(sorted(rows,key=lambda row:row['nevra']),sort_keys=True))
'''


def refuse(reason):
    raise Refused('kernel_update_' + reason)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def record(stage, name, value):
    rpm.immutable(Path(stage) / name, encode(value))


def version(header):
    value = rpm.one(header, 'Version') + '-' + rpm.one(header, 'Release') + '.' + rpm.one(header, 'Arch')
    if not KERNEL.fullmatch(value) or rpm.one(header, 'Epoch', 0) != 0:
        refuse('unsupported_kernel_identity')
    return value


def canonical(path):
    if not isinstance(path, str) or not path.startswith('/') or str(Path(path)) != path or '..' in Path(path).parts:
        refuse('unsafe_payload_path')
    # Rocky usrmerge is verified separately before native access. Never resolve
    # arbitrary symlinks supplied by the payload or follow the build/source links.
    return '/usr' + path if path.startswith('/lib/') else path


def script_binding(header):
    name, kernel = rpm.one(header, 'Name'), version(header)
    scripts = {key: value for key, value in header.items()
               if any(token in key for token in ('Pre', 'Post', 'Trigger', 'trigger', 'Verify'))}
    normalized = json.dumps(scripts, sort_keys=True, separators=(',', ':')).replace(kernel, '$KERNEL')
    if name not in NAMES or rpm.sha(normalized.encode()) != SCRIPT_TEMPLATES[name]:
        refuse('unqualified_vendor_script_template')
    return digest(scripts)


def payload(header):
    """Validate exact vendor files including ghosts and three qualified links."""
    package, kernel = rpm.identity(header), version(header)
    scripts = script_binding(header)
    names = header.get('Basenames', [])
    if package['name'] == 'kernel':
        if names:
            refuse('meta_package_has_payload')
        return {**package, 'kernel': kernel, 'scripts_sha256': scripts, 'files': []}
    if rpm.one(header, 'Filedigestalgo', 0) != 8 or not 1 <= len(names) <= 4096:
        refuse('invalid_payload_digest_or_size')
    tags = ('Dirindexes', 'Filemodes', 'Filesizes', 'Filedigests', 'Fileusername',
            'Filegroupname', 'Fileflags', 'Filelinktos', 'Fileinodes')
    if any(len(header.get(tag, [])) != len(names) for tag in tags) or any(header.get('Filecaps', [])):
        refuse('invalid_payload_metadata')
    if len(set(header['Fileinodes'])) != len(names):
        refuse('hardlinked_payload_requires_recipe')
    root = '/usr/lib/modules/' + kernel
    links = {root + '/build': '/usr/src/kernels/' + kernel, root + '/source': 'build',
             '/usr/share/doc/kernel-keys/' + kernel + '/secureboot-uki-x86_64.cer': 'rocky-uki-virt.cer'}
    allowed_shared = {'/usr/lib/modules', '/usr/share/licenses/kernel-core'}
    files = []
    for i, name in enumerate(names):
        index = header['Dirindexes'][i]
        if type(index) is not int or not 0 <= index < len(header.get('Dirnames', [])):
            refuse('invalid_payload_directory')
        path = canonical(header['Dirnames'][index] + name)
        mode, flags = header['Filemodes'][i], header['Fileflags'][i]
        if (not (path in allowed_shared or path == root or path.startswith(root + '/')
                 or path.startswith('/boot/') and kernel in Path(path).name
                 or path == '/usr/share/doc/kernel-keys/' + kernel
                 or path.startswith('/usr/share/doc/kernel-keys/' + kernel + '/')
                 or path == '/usr/share/licenses/kernel-core/COPYING-' + kernel.removesuffix('.x86_64'))
                or header['Fileusername'][i] != 'root' or header['Filegroupname'][i] != 'root'
                or type(mode) is not int or type(flags) is not int or flags & ~(2 | 64 | 128)):
            refuse('unsupported_payload_metadata')
        ghost = bool(flags & 64)
        value = {'path': path, 'uid': 0, 'gid': 0, 'mode': stat.S_IMODE(mode), 'ghost': ghost}
        if stat.S_ISLNK(mode):
            if links.get(path) != header['Filelinktos'][i] or ghost:
                refuse('unqualified_payload_link')
            value.update(kind='symlink', target=header['Filelinktos'][i])
        elif stat.S_ISDIR(mode):
            if mode & 0o7022 or ghost:
                refuse('unsafe_payload_directory')
            value.update(kind='directory')
        elif stat.S_ISREG(mode):
            checksum, size = header['Filedigests'][i], header['Filesizes'][i]
            if mode & 0o7022 or type(size) is not int or not 0 <= size <= MAX_FILE or not ghost and not SHA.fullmatch(checksum):
                refuse('unsafe_payload_file')
            value.update(kind='file', bytes=size, sha256=checksum)
        else:
            refuse('special_payload_file')
        if not stat.S_ISLNK(mode) and header['Filelinktos'][i]:
            refuse('unexpected_payload_link')
        files.append(value)
    if len({item['path'] for item in files}) != len(files):
        refuse('duplicate_payload_path')
    return {**package, 'kernel': kernel, 'scripts_sha256': scripts, 'files': files}


def generated_paths(kernel, machine_id):
    if not KERNEL.fullmatch(kernel) or not re.fullmatch(r'[a-f0-9]{32}', machine_id):
        refuse('invalid_generated_identity')
    root = '/usr/lib/modules/' + kernel
    return ({root + '/' + name for name in DEPMOD}
            | {'/boot/' + name for name in ('.vmlinuz-' + kernel + '.hmac', 'System.map-' + kernel,
                  'config-' + kernel, 'initramfs-' + kernel + '.img', 'symvers-' + kernel + '.gz', 'vmlinuz-' + kernel)}
            | {'/boot/loader/entries/' + machine_id + '-' + kernel + '.conf'})


def validate_solve(rows, packages):
    expected = sorted(({'action': 'install', 'nevra': p['nevra'], 'repo': '@commandline'} for p in packages), key=lambda p: p['nevra'])
    if rows != expected or len(rows) != 4:
        refuse('offline_solve_is_not_exact_installonly_set')
    return rows


def newer_kernel(candidate, current):
    if not KERNEL.fullmatch(candidate) or not KERNEL.fullmatch(current):
        refuse('unsupported_kernel_identity')
    # The qualified family has only decimal release components. Refuse changed
    # RPM version syntax rather than approximating general RPM label ordering.
    release = lambda value: tuple(int(part) for part in re.findall(r'\d+', value.removeprefix('5.14.0-').removesuffix('.x86_64')))
    if release(candidate) <= release(current):
        refuse('candidate_is_not_newer_than_running_kernel')


def command(stage, plan, test=False):
    # Deliberately install, not upgrade. No old kernel is implicitly erased and
    # no resolver is rerun after the frozen offline solve was validated.
    return ['/usr/bin/env', 'GRUB_UPDATE_DEFAULT_KERNEL=false', '/usr/bin/rpm', '--install', *(['--test'] if test else []),
            *(str(Path(stage) / 'kernel-packages' / p['rpm']) for p in plan['packages'])]


def default_policy(original):
    if not isinstance(original, str) or any(c in original for c in ('\r', '\v', '\f', '\x85', '\u2028', '\u2029', '\0')):
        refuse('unqualified_kernel_default_configuration')
    values = {}
    for line in original.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        matched = re.fullmatch(r'(UPDATEDEFAULT|DEFAULTKERNEL|MAKEDEBUG|DEFAULTDEBUG)=(yes|no|kernel-core)', line)
        if not matched or matched[1] in values:
            refuse('unqualified_kernel_default_configuration')
        values[matched[1]] = matched[2]
    if (values.get('UPDATEDEFAULT') not in {'yes', 'no'} or values.get('DEFAULTKERNEL') != 'kernel-core'
            or any(values.get(key, 'no') != 'no' for key in ('MAKEDEBUG', 'DEFAULTDEBUG'))):
        refuse('unqualified_kernel_default_configuration')
    updated, count = re.subn(r'(?m)^UPDATEDEFAULT=(?:yes|no)$', 'UPDATEDEFAULT=no', original)
    if count != 1:
        refuse('unqualified_kernel_default_configuration')
    return updated


def verify_install_hooks():
    directory = Path('/usr/lib/kernel/install.d')
    if {p.name for p in directory.glob('*.install')} != set(INSTALL_HOOKS):
        refuse('kernel_install_hook_inventory_changed')
    for name, checksum in INSTALL_HOOKS.items():
        if rpm.sha(rpm.read(directory / name, 1024**2)) != checksum:
            refuse('kernel_install_hook_changed')
    for root in ('/etc/kernel/install.d', '/run/kernel/install.d', '/usr/local/lib/kernel/install.d'):
        if any(Path(root).glob('*.install')):
            refuse('kernel_install_override_requires_recipe')
    for root in ('/etc/kernel/postinst.d', '/etc/kernel/prerm.d'):
        if any(Path(root).rglob('*')):
            refuse('kernel_install_legacy_hook_requires_recipe')
    if rpm.sha(rpm.read(SETTINGS, 1024**2)) != SETTINGS_SHA or os.path.lexists('/usr/sbin/new-kernel-pkg'):
        refuse('kernel_default_hook_changed')
    grub = rpm.read('/etc/default/grub', 65536).decode()
    if (not re.search(r'(?m)^GRUB_DEFAULT=saved$', grub)
            or not re.search(r'(?m)^GRUB_ENABLE_BLSCFG=true$', grub)
            or 'GRUB_UPDATE_DEFAULT_KERNEL' in grub):
        refuse('unqualified_grub_default_policy')


def _identity(path):
    info = Path(path).lstat()
    return {'device': info.st_dev, 'inode': info.st_ino}


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _configuration_description(plan, raw):
    return {**plan['mutable_before'][KERNEL_CONFIG], 'sha256': rpm.sha(raw), 'bytes': len(raw)}


def _finish_configuration(stage, intent, *, vendor_replaced=False):
    """Publish only a fully synced replacement; interrupted live bytes stay intact.

    The vendor postin already replaces this inode using sed -i. Our AIDE plan
    authorizes that exact path, but preserves its owner/mode/complete xattrs.
    Before publication we also bind both source and replacement inode identity.
    """
    token = intent['id']
    path = Path(KERNEL_CONFIG)
    temporary = path.parent / ('.captains-log-kernel-' + token)
    prepared_path = stage / ('kernel-default-' + token + '-prepared.json')
    result_path = stage / ('kernel-default-' + token + '-result.json')
    after = bytes.fromhex(intent['after_raw'])
    actual = describe(path)
    prepared = strict_json(rpm.read(prepared_path, 8192)) if os.path.lexists(prepared_path) else None
    if prepared is not None:
        exact(prepared, {'schema', 'intent_sha256', 'identity'})
        if prepared['schema'] != 1 or prepared['intent_sha256'] != rpm.sha(encode(intent)):
            refuse('kernel_configuration_preparation_changed')
    if os.path.lexists(result_path):
        result = strict_json(rpm.read(result_path, 8192))
        if (prepared is None or result != {'schema': 1, 'intent_sha256': rpm.sha(encode(intent)), 'identity': prepared['identity']}
                or actual != intent['after'] or not vendor_replaced and _identity(path) != prepared['identity']
                or os.path.lexists(temporary)):
            refuse('kernel_configuration_publication_changed')
        return
    if actual == intent['after'] and prepared is not None and _identity(path) == prepared['identity']:
        if os.path.lexists(temporary):
            refuse('kernel_configuration_duplicate_replacement')
        # Rename may have completed before its directory fsync/result receipt.
        _sync_directory(path.parent)
    else:
        if actual != intent['before'] or _identity(path) != intent['before_identity']:
            refuse('kernel_configuration_changed')
        if prepared is None and os.path.lexists(temporary):
            raw = rpm.read(temporary, 65536)
            metadata = describe(temporary)
            if (metadata['kind'] != 'file' or metadata['mode'] not in (0o600, intent['after']['mode'])
                    or not after.startswith(raw)):
                refuse('kernel_configuration_unowned_temporary')
            # Preserve the actual interrupted bytes/metadata before discarding
            # this intent's unpublished, incomplete temporary inode.
            evidence = {'schema': 1, 'intent_sha256': rpm.sha(encode(intent)), 'raw': raw.hex(),
                        'metadata': metadata, 'identity': _identity(temporary)}
            record(stage, 'kernel-default-interrupted-' + rpm.sha(encode(evidence)) + '.json', evidence)
            temporary.unlink()
            _sync_directory(path.parent)
        if prepared is None:
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as out:
                out.write(after)
                out.flush()
                os.fchown(out.fileno(), intent['after']['uid'], intent['after']['gid'])
                os.fchmod(out.fileno(), intent['after']['mode'])
                for key, value in intent['xattrs'].items():
                    os.setxattr(temporary, key, bytes.fromhex(value), follow_symlinks=False)
                os.fsync(out.fileno())
            if describe(temporary) != intent['after']:
                refuse('kernel_configuration_replacement_metadata_changed')
            _sync_directory(path.parent)
            prepared = {'schema': 1, 'intent_sha256': rpm.sha(encode(intent)), 'identity': _identity(temporary)}
            record(stage, prepared_path.name, prepared)
        if (not os.path.lexists(temporary) or describe(temporary) != intent['after']
                or _identity(temporary) != prepared['identity']
                or describe(path) != intent['before'] or _identity(path) != intent['before_identity']):
            refuse('kernel_configuration_replaced')
        os.replace(temporary, path)
        _sync_directory(path.parent)
    if describe(path) != intent['after'] or _identity(path) != prepared['identity']:
        refuse('kernel_configuration_write_not_verified')
    record(stage, result_path.name, {'schema': 1, 'intent_sha256': rpm.sha(encode(intent)), 'identity': prepared['identity']})


def _configuration_transition(stage, plan, phase, *, vendor_replaced=False):
    stage = Path(stage)
    original = plan['kernel_configuration'].encode()
    pinned = default_policy(plan['kernel_configuration']).encode()
    wanted = pinned if phase == 'pin' else original
    pointer = stage / 'kernel-default-current.json'
    if os.path.lexists(pointer):
        reference = strict_json(rpm.read(pointer, 8192))
        exact(reference, {'id', 'sha256'})
        if not re.fullmatch(r'[0-9a-f]{32}', str(reference['id'])):
            refuse('kernel_configuration_pointer_changed')
        raw = rpm.read(stage / ('kernel-default-' + reference['id'] + '-intent.json'), rpm.MAX_XML)
        intent = strict_json(raw)
        exact(intent, {'schema', 'id', 'plan_sha256', 'phase', 'before', 'after', 'before_raw', 'after_raw', 'before_identity', 'xattrs'})
        target = pinned if intent['phase'] == 'pin' else original
        before = bytes.fromhex(intent['before_raw'])
        attributes = {key: rpm.sha(bytes.fromhex(value)) for key, value in intent['xattrs'].items()}
        if (raw != encode(intent) or rpm.sha(raw) != reference['sha256'] or intent['id'] != reference['id']
                or intent['schema'] != 1 or intent['plan_sha256'] != rpm.sha(encode(plan))
                or intent['phase'] not in {'pin', 'restore'} or before not in (original, pinned)
                or intent['after_raw'] != target.hex() or intent['before'] != _configuration_description(plan, before)
                or intent['after'] != _configuration_description(plan, target)
                or digest(attributes) != intent['after']['xattrs_sha256']):
            refuse('kernel_configuration_intent_changed')
        _finish_configuration(stage, intent, vendor_replaced=vendor_replaced)
    current = rpm.read(KERNEL_CONFIG, 65536)
    if current not in (original, pinned) or describe(KERNEL_CONFIG) != _configuration_description(plan, current):
        refuse('kernel_configuration_changed')
    if current == wanted:
        return
    token = uuid.uuid4().hex
    attrs = {key: os.getxattr(KERNEL_CONFIG, key, follow_symlinks=False).hex()
             for key in sorted(os.listxattr(KERNEL_CONFIG, follow_symlinks=False))}
    intent = {'schema': 1, 'id': token, 'plan_sha256': rpm.sha(encode(plan)), 'phase': phase,
              'before_raw': current.hex(), 'after_raw': wanted.hex(), 'before_identity': _identity(KERNEL_CONFIG),
              'before': _configuration_description(plan, current), 'after': _configuration_description(plan, wanted), 'xattrs': attrs}
    if digest({key: rpm.sha(bytes.fromhex(value)) for key, value in attrs.items()}) != intent['before']['xattrs_sha256']:
        refuse('kernel_configuration_attributes_changed')
    record(stage, 'kernel-default-' + token + '-intent.json', intent)
    atomic_json(pointer, {'id': token, 'sha256': rpm.sha(encode(intent))})
    _finish_configuration(stage, intent)


def pin_default(stage, plan, *, vendor_replaced=False):
    verify_install_hooks()
    _configuration_transition(stage, plan, 'pin', vendor_replaced=vendor_replaced)


def restore_default_policy(stage, plan):
    _configuration_transition(stage, plan, 'restore', vendor_replaced=True)


def describe(path):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            refuse('unsafe_parent')
    before = path.lstat()
    if before.st_uid != 0 or before.st_gid != 0 or not stat.S_ISLNK(before.st_mode) and before.st_mode & 0o7022:
        refuse('unsafe_live_file')
    value = {'uid': before.st_uid, 'gid': before.st_gid, 'mode': stat.S_IMODE(before.st_mode)}
    if stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
        raw = rpm.read(path, MAX_FILE)
        value.update(kind='file', bytes=len(raw), sha256=rpm.sha(raw))
    elif stat.S_ISDIR(before.st_mode):
        value.update(kind='directory')
    elif stat.S_ISLNK(before.st_mode) and before.st_nlink == 1:
        value.update(kind='symlink', target=os.readlink(path))
    else:
        refuse('unqualified_live_file_type')
    attributes = {name: rpm.sha(os.getxattr(path, name, follow_symlinks=False))
                  for name in sorted(os.listxattr(path, follow_symlinks=False))}
    if 'security.selinux' not in attributes or 'security.capability' in attributes:
        refuse('unqualified_live_security_metadata')
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
        refuse('live_file_changed_during_read')
    return {**value, 'xattrs_sha256': digest(attributes)}


def description(item):
    return {key: value for key, value in item.items() if key not in {'path', 'ghost', 'xattrs_sha256'}}


def validate_bls(text, old_text, old_kernel, kernel):
    # The native vendor hook preserves every boot argument and policy field.
    # Comparing the complete entry catches duplicate security options, changed
    # root/boot identity, alternate initrds and unreviewed extra commands.
    if text != old_text.replace(old_kernel, kernel):
        refuse('candidate_bls_changed_boot_policy')
    fields = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        key, _, value = line.partition(' ')
        if key in fields:
            refuse('duplicate_bls_field')
        fields[key] = value
    if (fields.get('version') != kernel or fields.get('linux') != '/vmlinuz-' + kernel
            or fields.get('initrd') != '/initramfs-' + kernel + '.img'
            or not {'fips=1', 'module.sig_enforce=1', 'audit=1'} <= set(fields.get('options', '').split())):
        refuse('candidate_bls_security_policy_missing')
    for prefix in ('fips=', 'module.sig_enforce=', 'audit=', 'root=', 'boot='):
        if sum(token.startswith(prefix) for token in fields['options'].split()) != 1:
            refuse('candidate_bls_ambiguous_security_policy')
    return fields


def required_space(stage, files, package_bytes):
    # Reserve the maximum accepted initramfs plus fixed boot copies, and enough
    # room for installed payloads and depmod scratch data. Sum requirements when
    # directories share a filesystem; separate checks would overcommit it.
    return {str(stage): package_bytes + 32 * 1024**2,
            '/boot': MAX_FILE + 64 * 1024**2,
            '/usr/lib/modules': sum(item.get('bytes', 0) for item in files) + 64 * 1024**2}


def verify_space(requirements):
    grouped = {}
    for path, minimum in requirements.items():
        if type(minimum) is not int or minimum <= 0:
            refuse('invalid_space_requirement')
        info, filesystem = os.stat(path), os.statvfs(path)
        entry = grouped.setdefault(info.st_dev, {'needed': 0, 'free': filesystem.f_bavail * filesystem.f_frsize})
        entry['needed'] += minimum
        entry['free'] = min(entry['free'], filesystem.f_bavail * filesystem.f_frsize)
    if any(item['free'] < item['needed'] for item in grouped.values()):
        refuse('insufficient_space_for_preserved_kernel_update')


def plan_cached(stage, packages, *, runner=run):
    """Retain, verify and solve four local RPMs without installing anything."""
    require_linux_root()
    stage = Path(stage)
    operation_raw = rpm.read(stage / 'operation.json', 8192)
    operation = strict_json(operation_raw)
    if operation.get('stage') != str(stage) or operation.get('boot_id') != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        refuse('operation_boot_changed')
    rpm.platform(runner)
    verify_install_hooks()
    if os.readlink('/lib') != 'usr/lib' or rpm.sha(rpm.read(rpm.KEY, 65536)) != rpm.KEY_SHA256 or len(packages) != 4:
        refuse('platform_or_package_set_changed')
    retained = stage / 'kernel-packages'
    retained.mkdir(mode=0o700)
    rpm.init_keydb(stage / 'kernel-keydb', runner)
    xml, installed, before = rpm.inventory(runner)
    rpm.immutable(stage / 'kernel-inventory-before.xml', xml.encode())
    proposed, all_files = [], {}
    for source in packages:
        raw = rpm.read(source)
        target = retained / (rpm.sha(raw) + '.rpm')
        rpm.immutable(target, raw)
        signature = rpm.signature(target, stage / 'kernel-keydb', runner)
        headers = rpm.headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(target)]))
        if len(headers) != 1:
            refuse('ambiguous_package')
        item = payload(headers[0])
        for entry in item.pop('files'):
            if entry['path'] in all_files and entry != all_files[entry['path']]:
                refuse('overlapping_payload')
            all_files[entry['path']] = entry
        proposed.append({**item, 'rpm': target.name, 'sha256': rpm.sha(raw), 'bytes': len(raw), 'signature': signature})
    if {p['name'] for p in proposed} != NAMES or len({p['kernel'] for p in proposed}) != 1:
        refuse('incomplete_kernel_package_set')
    proposed.sort(key=lambda p: p['name'])
    kernel = proposed[0]['kernel']
    old = runner(['/usr/bin/uname', '-r'])
    if not KERNEL.fullmatch(old) or kernel == old or any(p['nevra'] in before for p in proposed):
        refuse('candidate_is_not_a_new_kernel')
    newer_kernel(kernel, old)
    installed_kernels = [h for h in installed if rpm.one(h, 'Name') == 'kernel-core']
    if not any(version(h) == old for h in installed_kernels):
        refuse('running_kernel_package_missing')
    # Never prune a recovery kernel in the installation transaction. A separate
    # A fourth is temporary until acceptance and explicit retention restore
    # three. Never begin a fifth while that retention operation is pending.
    if len(installed_kernels) >= 4:
        refuse('kernel_retention_requires_separate_prune')
    installed_sets = {}
    for header in installed:
        name = rpm.one(header, 'Name')
        if name in NAMES:
            members = installed_sets.setdefault(version(header), [])
            members.append(name)
    if any(len(members) != 4 or set(members) != NAMES for members in installed_sets.values()):
        refuse('incomplete_existing_kernel_package_set')
    paths = set(all_files)
    rpm.external_triggers(installed, NAMES, paths | {p.removeprefix('/usr') for p in paths if p.startswith('/usr/lib/')})
    machine = rpm.read('/etc/machine-id', 64).decode().strip()
    generated = generated_paths(kernel, machine)
    ghosts = {p for p, value in all_files.items() if value['ghost']}
    if ghosts != generated - {'/boot/loader/entries/' + machine + '-' + kernel + '.conf'}:
        refuse('unqualified_generated_outputs')
    old_bls = '/boot/loader/entries/' + machine + '-' + old + '.conf'
    old_text = rpm.read(old_bls, 65536).decode()
    validate_bls(old_text, old_text, old, old)
    if runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + old:
        refuse('running_kernel_must_be_recovery_default')
    preserved = {path: describe(path) for path in generated_paths(old, machine) if path.startswith('/boot/')}
    shared = {p: describe(p) for p in paths if os.path.lexists(p)}
    if any(all_files[p]['kind'] != 'directory' or all_files[p]['ghost'] for p in shared):
        refuse('candidate_would_overwrite_existing_file')
    if any(os.path.lexists(path) for path in generated):
        refuse('candidate_generated_path_already_exists')
    solve = strict_json(runner(['/usr/bin/python3', '-c', SOLVE, str(stage), *(str(retained / p['rpm']) for p in proposed)], timeout=180))
    validate_solve(solve, proposed)
    if rpm.inventory(runner)[2] != before:
        refuse('inventory_changed_during_planning')
    configuration = rpm.read(KERNEL_CONFIG, 65536).decode()
    default_policy(configuration)
    space = required_space(stage, all_files.values(), sum(p['bytes'] for p in proposed))
    verify_space(space)
    plan = {'schema': 1, 'kind': 'rocky-kernel-install-v1', 'operation_sha256': rpm.sha(operation_raw),
            'key_sha256': rpm.KEY_SHA256, 'boot_id': operation['boot_id'], 'kernel': kernel, 'old_kernel': old,
            'machine_id': machine, 'before_inventory': before, 'after_inventory': sorted(before + [p['nevra'] for p in proposed]),
            'inventory_sha256': rpm.sha(xml.encode()), 'packages': proposed, 'solve': solve,
            'files': sorted(all_files.values(), key=lambda p: p['path']), 'generated': sorted(generated),
            'shared': shared, 'preserved': preserved, 'old_bls': old_text, 'kernel_configuration': configuration,
            'mutable_before': {p: describe(p) for p in (GRUBENV, '/etc/sysconfig/kernel')},
            'space_requirements': space}
    runner(command(stage, plan, True), timeout=180)
    record(stage, 'kernel-plan.json', plan)
    return {'ok': True, 'plan_sha256': rpm.sha(encode(plan)), 'kernel': kernel, 'reboot_required': True}


def load_plan(stage):
    stage = Path(stage)
    raw = rpm.read(stage / 'kernel-plan.json', rpm.MAX_XML)
    plan = strict_json(raw)
    if (plan.get('schema') != 1 or plan.get('kind') != 'rocky-kernel-install-v1'
            or plan.get('operation_sha256') != rpm.sha(rpm.read(stage / 'operation.json', 8192))
            or plan.get('key_sha256') != rpm.KEY_SHA256):
        refuse('plan_binding_changed')
    validate_solve(plan['solve'], plan['packages'])
    return plan, rpm.sha(raw)


def verify_preserved(plan):
    for path, expected in {**plan['shared'], **plan['preserved']}.items():
        if describe(path) != expected:
            refuse('recovery_or_shared_file_changed')


def verify_labels(paths, *, runner=run):
    """Expected contexts come from the AIDE-pinned SELinux policy, not observation."""
    paths = sorted(set(paths))
    for start in range(0, len(paths), 128):
        batch = paths[start:start + 128]
        contexts = runner(['/usr/sbin/matchpathcon', '-n', *batch], timeout=120).splitlines()
        if len(contexts) != len(batch):
            refuse('selinux_policy_context_unavailable')
        for path, context in zip(batch, contexts):
            if (set(os.listxattr(path, follow_symlinks=False)) != {'security.selinux'}
                    or os.getxattr(path, 'security.selinux', follow_symlinks=False).rstrip(b'\0') != context.encode()):
                refuse('payload_security_metadata_differs_from_policy')


def verify_payload(plan, *, runner=run, allow_missing_generated=False):
    for item in plan['files']:
        if not item['ghost'] and description(describe(item['path'])) != description(item):
            refuse('installed_vendor_payload_changed')
    root = Path('/usr/lib/modules') / plan['kernel']
    actual = {str(root), *(str(p) for p in root.rglob('*'))}
    expected = {p['path'] for p in plan['files'] if p['path'] == str(root) or p['path'].startswith(str(root) + '/')}
    repairable = {p['path'] for p in plan['files'] if p['ghost']}
    if actual - expected or expected - actual - (repairable if allow_missing_generated else set()):
        refuse('unplanned_module_tree_output')
    immutable = {p['path'] for p in plan['files'] if not p['ghost']} - set(plan['shared'])
    verify_labels(immutable, runner=runner)
    if not allow_missing_generated:
        for item in plan['packages']:
            if runner(['/usr/bin/rpm', '--verify', item['nevra']], timeout=180):
                refuse('vendor_rpm_verification_failed')
    verify_preserved(plan)


def generated_snapshot(plan, *, runner=run):
    """Validate semantics before a generated byte hash can enter the receipt."""
    kernel = plan['kernel']
    root = '/usr/lib/modules/' + kernel
    for suffix, original in (('vmlinuz', 'vmlinuz'), ('System.map', 'System.map'), ('config', 'config')):
        if rpm.read('/boot/' + suffix + '-' + kernel, MAX_FILE) != rpm.read(root + '/' + original, MAX_FILE):
            refuse('boot_copy_differs_from_signed_payload')
    if rpm.read('/boot/.vmlinuz-' + kernel + '.hmac') != rpm.read(root + '/.vmlinuz.hmac'):
        refuse('boot_hmac_differs_from_signed_payload')
    if os.readlink('/boot/symvers-' + kernel + '.gz') != '/lib/modules/' + kernel + '/symvers.gz':
        refuse('boot_symbol_link_changed')
    bls = '/boot/loader/entries/' + plan['machine_id'] + '-' + kernel + '.conf'
    validate_bls(rpm.read(bls, 65536).decode(), plan['old_bls'], plan['old_kernel'], kernel)
    initramfs = '/boot/initramfs-' + kernel + '.img'
    modules = runner(['/usr/bin/lsinitrd', '-m', initramfs], timeout=180).splitlines()
    if not {'fips', 'crypt'} <= {line.strip() for line in modules}:
        refuse('initramfs_missing_fips_or_encryption')
    crypttab = rpm.read('/etc/crypttab', 65536).decode().strip()
    if not crypttab or runner(['/usr/bin/lsinitrd', '-f', 'etc/crypttab', initramfs], timeout=180).strip() != crypttab:
        refuse('initramfs_encrypted_storage_changed')
    # Native depmod emits only these ten ghost files, regular root-owned 0644.
    for name in DEPMOD:
        value = describe(root + '/' + name)
        if value['kind'] != 'file' or value['mode'] != 0o644:
            refuse('depmod_output_metadata_changed')
    result = {path: describe(path) for path in plan['generated']}
    verify_labels(plan['generated'], runner=runner)
    for path, value in result.items():
        if path == '/boot/symvers-' + kernel + '.gz':
            wanted_kind, wanted_mode = 'symlink', 0o777
        else:
            wanted_kind = 'file'
            wanted_mode = (0o600 if path in {'/boot/initramfs-' + kernel + '.img', '/boot/System.map-' + kernel}
                           else 0o755 if path == '/boot/vmlinuz-' + kernel else 0o644)
        if value['kind'] != wanted_kind or value['mode'] != wanted_mode:
            refuse('generated_output_type_or_mode_changed')
    if result[initramfs]['bytes'] < 10 * 1024**2:
        refuse('generated_initramfs_incomplete')
    return result


def authorize_execution(stage, plan, plan_sha, authorize, *, recovery=False):
    """The lifecycle callback rechecks fresh backup, maintenance and AIDE locks."""
    value = authorize(Path(stage), plan_sha)
    exact(value, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    try:
        uuid.UUID(boot)
    except ValueError:
        refuse('invalid_boot_identity')
    if (value['ok'] is not True or value['plan_sha256'] != plan_sha or value['boot_id'] != boot
            or not SHA.fullmatch(str(value['backup_sha256'])) or not SHA.fullmatch(str(value['aide_preparation_sha256']))
            or not recovery and boot != plan['boot_id']):
        refuse('execution_authorization_changed')
    return value


def execute_cached(stage, *, authorize, authorize_recovery=None, runner=run):
    """Install the frozen RPM set once; leave the old kernel as boot default.

    authorize is mandatory and owned by the lifecycle/AIDE integration. A valid
    signature or RPM preflight by itself never authorizes host mutation.
    """
    require_linux_root()
    stage = Path(stage)
    plan, plan_sha = load_plan(stage)
    if (stage / 'kernel-apply-intent.json').exists():
        refuse('already_attempted_use_recovery')
    authorization = authorize_execution(stage, plan, plan_sha, authorize)
    verify_space(plan['space_requirements'])
    rpm.platform(runner)
    xml, _, inventory = rpm.inventory(runner)
    if inventory != plan['before_inventory'] or rpm.sha(xml.encode()) != plan['inventory_sha256']:
        refuse('installed_inventory_changed')
    if rpm.sha(rpm.read(rpm.KEY, 65536)) != plan['key_sha256']:
        refuse('vendor_trust_changed')
    for item in plan['packages']:
        path = stage / 'kernel-packages' / item['rpm']
        raw = rpm.read(path)
        if rpm.sha(raw) != item['sha256'] or len(raw) != item['bytes'] or rpm.signature(path, stage / 'kernel-keydb', runner) != item['signature']:
            refuse('retained_rpm_changed')
    verify_preserved(plan)
    if ({path: describe(path) for path in plan['mutable_before']} != plan['mutable_before']
            or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + plan['old_kernel']):
        refuse('boot_or_kernel_configuration_changed')
    if any(os.path.lexists(path) for path in plan['generated']):
        refuse('candidate_output_created_before_install')
    runner(command(stage, plan, True), timeout=180)
    if authorize_execution(stage, plan, plan_sha, authorize) != authorization:
        refuse('execution_context_changed')
    intent = {'schema': 2, 'plan_sha256': plan_sha, 'authorization': authorization}
    record(stage, 'kernel-apply-intent.json', intent)
    _run_rpm_once(stage, plan, plan_sha, intent, authorization, runner=runner)
    return recover_generated(stage, authorize=authorize_recovery or authorize, runner=runner)


def _run_rpm_once(stage, plan, plan_sha, intent, authorization, *, runner):
    sentinel = stage / 'kernel-rpm-command.json'
    if intent['schema'] != 2 or os.path.lexists(sentinel):
        refuse('rpm_command_already_attempted_or_ambiguous')
    # The pinned vendor hook honors UPDATEDEFAULT=no. Persist it before RPM can
    # execute any scriptlet, so SIGKILL/power loss also leaves the old default.
    pin_default(stage, plan)
    if (rpm.inventory(runner)[2] != plan['before_inventory']
            or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + plan['old_kernel']):
        refuse('precommand_inventory_or_default_changed')
    record(stage, sentinel.name, {'schema': 1, 'plan_sha256': plan_sha,
                                 'intent_sha256': rpm.sha(encode(intent)), 'authorization': authorization})
    try:
        runner(command(stage, plan), timeout=3600)
    finally:
        # Vendor kernel-install changes the default. Even a partial/scriptlet
        # failure must not leave an unaccepted kernel as the persistent default.
        runner(['/usr/sbin/grubby', '--set-default=/boot/vmlinuz-' + plan['old_kernel']])


def recover_generated(stage, *, authorize, runner=run):
    """Resume an owned pin or complete payload, without replaying an RPM attempt."""
    require_linux_root()
    stage = Path(stage)
    plan, plan_sha = load_plan(stage)
    intent = strict_json(rpm.read(stage / 'kernel-apply-intent.json', 8192))
    exact(intent, {'schema', 'plan_sha256', 'authorization'})
    original = intent['authorization']
    exact(original, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
    current = authorize_execution(stage, plan, plan_sha, authorize, recovery=True)
    if (type(intent['schema']) is not int or intent['schema'] not in (1, 2) or intent['plan_sha256'] != plan_sha or original['ok'] is not True
            or original['plan_sha256'] != plan_sha or original['boot_id'] != plan['boot_id']
            or not SHA.fullmatch(str(original['backup_sha256']))
            or original['aide_preparation_sha256'] != current['aide_preparation_sha256']
            or current['boot_id'] != plan['boot_id'] and runner(['/usr/bin/uname', '-r']) != plan['old_kernel']):
        refuse('recovery_authorization_changed')
    # A fresh backup/old-kernel recovery boot may differ from the immutable
    # install intent. Retain that observation separately; never rewrite intent
    # or replay RPM. The integration callback binds it to the original journal.
    if current != original:
        record(stage, 'kernel-recovery-authorization-' + rpm.sha(encode(current)) + '.json',
               {'schema': 1, 'intent_sha256': rpm.sha(encode(intent)), 'authorization': current})
    inventory_xml, _, inventory = rpm.inventory(runner)
    sentinel = stage / 'kernel-rpm-command.json'
    if intent['schema'] == 2 and not os.path.lexists(sentinel):
        # Schema 2 distinguishes a pin interrupted BEFORE any RPM command from
        # an ambiguous interrupted command. Legacy schema 1 never permits this.
        if inventory != plan['before_inventory'] or rpm.sha(inventory_xml.encode()) != plan['inventory_sha256']:
            refuse('precommand_inventory_changed')
        rpm.platform(runner)
        verify_space(plan['space_requirements'])
        if rpm.sha(rpm.read(rpm.KEY, 65536)) != plan['key_sha256']:
            refuse('vendor_trust_changed')
        for item in plan['packages']:
            path = stage / 'kernel-packages' / item['rpm']
            raw = rpm.read(path)
            if (rpm.sha(raw) != item['sha256'] or len(raw) != item['bytes']
                    or rpm.signature(path, stage / 'kernel-keydb', runner) != item['signature']):
                refuse('retained_rpm_changed')
        verify_preserved(plan)
        if any(os.path.lexists(path) for path in plan['generated']):
            refuse('candidate_output_created_before_install')
        runner(command(stage, plan, True), timeout=180)
        if authorize_execution(stage, plan, plan_sha, authorize, recovery=True) != current:
            refuse('execution_context_changed')
        _run_rpm_once(stage, plan, plan_sha, intent, current, runner=runner)
        inventory = rpm.inventory(runner)[2]
    if intent['schema'] == 2:
        attempted = strict_json(rpm.read(sentinel, 8192))
        exact(attempted, {'schema', 'plan_sha256', 'intent_sha256', 'authorization'})
        permission = attempted['authorization']
        exact(permission, {'ok', 'plan_sha256', 'backup_sha256', 'aide_preparation_sha256', 'boot_id'})
        if (type(attempted['schema']) is not int or attempted['schema'] != 1 or attempted['plan_sha256'] != plan_sha
                or attempted['intent_sha256'] != rpm.sha(encode(intent)) or permission['ok'] is not True
                or permission['plan_sha256'] != plan_sha or permission['aide_preparation_sha256'] != original['aide_preparation_sha256']
                or not SHA.fullmatch(str(permission['backup_sha256']))):
            refuse('rpm_command_sentinel_changed')
        if permission != original:
            evidence = strict_json(rpm.read(stage / ('kernel-recovery-authorization-' + rpm.sha(encode(permission)) + '.json'), 8192))
            if evidence != {'schema': 1, 'intent_sha256': rpm.sha(encode(intent)), 'authorization': permission}:
                refuse('rpm_command_authorization_changed')
    if inventory != plan['after_inventory']:
        refuse('partial_package_install_requires_recovery')
    verify_payload(plan, runner=runner, allow_missing_generated=True)
    result_path = stage / 'kernel-installed.json'
    if result_path.exists():
        result = strict_json(rpm.read(result_path, rpm.MAX_XML))
        if (result.get('plan_sha256') != plan_sha or result.get('generated') != generated_snapshot(plan, runner=runner)
                or result.get('mutable') != {path: describe(path) for path in plan['mutable_before']}
                or runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + plan['old_kernel']):
            refuse('accepted_generated_output_changed')
        return result
    # Regenerate under the qualified tools after payload validation. The receipt
    # is never created by blindly recording arbitrary files observed after RPM.
    pin_default(stage, plan, vendor_replaced=True)
    runner(['/usr/bin/env', 'GRUB_UPDATE_DEFAULT_KERNEL=false', '/usr/bin/kernel-install', 'add', plan['kernel'],
            '/lib/modules/' + plan['kernel'] + '/vmlinuz'], timeout=1800)
    runner(['/usr/sbin/depmod', '-a', plan['kernel']], timeout=180)
    runner(['/usr/bin/dracut', '--force', '--reproducible', '--kver', plan['kernel'],
            '/boot/initramfs-' + plan['kernel'] + '.img'], timeout=1800)
    runner(['/usr/sbin/grubby', '--set-default=/boot/vmlinuz-' + plan['old_kernel']])
    if runner(['/usr/sbin/grubby', '--default-kernel']) != '/boot/vmlinuz-' + plan['old_kernel']:
        refuse('recovery_default_not_restored')
    restore_default_policy(stage, plan)
    verify_payload(plan, runner=runner)
    generated = generated_snapshot(plan, runner=runner)
    mutable = {path: describe(path) for path in plan['mutable_before']}
    # sed -i in the vendor postin may change inode/time, but not the configured
    # policy. Supporting the obsolete DEFAULTKERNEL=kernel-smp rewrite is separate.
    if mutable['/etc/sysconfig/kernel'] != plan['mutable_before']['/etc/sysconfig/kernel']:
        refuse('kernel_configuration_changed')
    if ({key: value for key, value in mutable[GRUBENV].items() if key != 'sha256'}
            != {key: value for key, value in plan['mutable_before'][GRUBENV].items() if key != 'sha256'}):
        refuse('boot_environment_security_metadata_changed')
    result = {'schema': 1, 'status': 'installed_pending_integrity_and_reboot', 'plan_sha256': plan_sha,
              'kernel': plan['kernel'], 'old_kernel': plan['old_kernel'], 'boot_id': plan['boot_id'],
              'generated': generated, 'mutable': mutable, 'release_accepted': False}
    record(stage, 'kernel-installed.json', result)
    return result


def integrity_delta(plan, installed):
    """Exact AIDE scope; no prefix allowlist or acceptance of unrelated drift."""
    if installed.get('kernel') != plan['kernel'] or set(installed.get('generated', {})) != set(plan['generated']):
        refuse('integrity_generated_binding_changed')
    additions = {item['path'] for item in plan['files']} - set(plan['shared'])
    additions |= set(plan['generated'])
    return {'added': sorted(additions), 'removed': [], 'changed': sorted(plan['mutable_before'])}


def check_integrity_report(report, delta):
    if (set(report.get('added', {})) - set(delta['added']) or report.get('removed')
            or set(report.get('changed', {})) - set(delta['changed'])):
        refuse('unrelated_integrity_change')


def postboot_inventory(candidate_stage, *, owner_stage=None, retention_authority=None, runner=run):
    """Resolve the frozen inventory, or an independently verified exact erase.

    A supplied digest/list never authorizes an inventory change. The retention
    validator reloads its immutable authority and original signed erase proof.
    """
    candidate_stage = Path(candidate_stage)
    plan, checksum = load_plan(candidate_stage)
    raw = rpm.read(candidate_stage / 'kernel-installed.json', rpm.MAX_XML)
    installed = strict_json(raw)
    if installed.get('plan_sha256') != checksum:
        refuse('candidate_install_binding_changed')
    if retention_authority is None:
        return plan['after_inventory']
    if owner_stage is None:
        refuse('retention_owner_required')
    from . import kernel_retention
    owner_stage = Path(owner_stage)
    resolved, owner_plan, owner_checksum, owner_installed = load_candidate(owner_stage)
    if (resolved != candidate_stage or owner_plan != plan or owner_checksum != checksum or owner_installed != installed):
        refuse('retention_candidate_binding_changed')
    authority = kernel_retention.validate_boot_authority(owner_stage, retention_authority, runner=runner)
    if (authority.get('candidate_plan_sha256') != checksum or authority.get('installed_sha256') != rpm.sha(raw)
            or authority.get('operation_sha256') != rpm.sha(rpm.read(owner_stage / 'operation.json', 8192))
            or authority.get('boot_id') != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or authority.get('kernel') != plan['kernel'] or authority.get('recovery_kernel') != plan['old_kernel']
            or not isinstance(authority.get('after_inventory'), list)):
        refuse('retention_boot_authority_changed')
    return authority['after_inventory']


def verify_postboot(stage, *, owner_stage=None, retention_authority=None, runner=run):
    """Bind the candidate boot before lifecycle health can release maintenance."""
    plan, plan_sha = load_plan(stage)
    installed = strict_json(rpm.read(Path(stage) / 'kernel-installed.json', rpm.MAX_XML))
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    try:
        uuid.UUID(boot)
    except ValueError:
        refuse('invalid_boot_identity')
    if (installed.get('plan_sha256') != plan_sha or boot == plan['boot_id']
            or runner(['/usr/bin/uname', '-r']) != plan['kernel']
            or Path('/proc/sys/kernel/tainted').read_text().strip() != '0'
            or rpm.inventory(runner)[2] != postboot_inventory(stage, owner_stage=owner_stage,
                                                            retention_authority=retention_authority, runner=runner)):
        refuse('candidate_boot_not_proven')
    verify_payload(plan, runner=runner)
    if generated_snapshot(plan, runner=runner) != installed['generated']:
        refuse('candidate_boot_artifacts_changed')
    status = security.status(runner)
    if status.get('host_controls_ok') is not True:
        refuse('candidate_host_security_failed')
    return {'ok': True, 'kernel': plan['kernel'], 'boot_id': boot, 'plan_sha256': plan_sha,
            'scope': 'kernel_boot_binding_only', 'release_accepted': False}


def mark_pending(stage, installed):
    stage = Path(stage)
    plan, checksum = load_plan(stage)
    raw = rpm.read(stage / 'kernel-installed.json', rpm.MAX_XML)
    if strict_json(raw) != installed or installed.get('plan_sha256') != checksum:
        refuse('pending_candidate_binding_changed')
    value = {'schema': 1, 'stage': str(stage), 'plan_sha256': checksum,
             'installed_sha256': rpm.sha(raw), 'operation_sha256': plan['operation_sha256'],
             'kernel': plan['kernel'], 'old_kernel': plan['old_kernel']}
    path = stage.parent.parent / 'kernel-pending.json'
    if os.path.lexists(path):
        if strict_json(rpm.read(path, 8192)) != value:
            refuse('another_kernel_candidate_pending')
    else:
        record(path.parent, path.name, value)
    return value


def _acceptance_file(stage, filename):
    from .updates import REQUIRED_CHECKS
    name = re.fullmatch(r'kernel-acceptance-([a-f0-9-]{36})\.json', filename)
    if not name:
        refuse('invalid_acceptance_filename')
    try:
        if str(uuid.UUID(name[1])) != name[1]:
            raise ValueError()
    except ValueError:
        refuse('invalid_acceptance_boot_identity')
    raw = rpm.read(Path(stage) / filename, 65536)
    value = strict_json(raw)
    # Earlier immutable generations omit this newly introduced optional proof.
    # Validate both exact schemas without normalizing or rewriting their bytes.
    exact(value, ACCEPTANCE_FIELDS | ({'retention_integrity_sha256'} if 'retention_integrity_sha256' in value else set()))
    if (type(value['schema']) is not int or value['schema'] != 1 or value['boot_id'] != name[1]
            or value['finalization'] != 'complete' or type(value['checks']) is not dict
            or set(value['checks']) != REQUIRED_CHECKS or any(value['checks'][key] is not True for key in REQUIRED_CHECKS)
            or not KERNEL.fullmatch(str(value['kernel'])) or not KERNEL.fullmatch(str(value['recovery_kernel']))
            or value['kernel'] == value['recovery_kernel']):
        refuse('complete_lifecycle_acceptance_required')
    for field in ('operation_sha256', 'kernel_plan_sha256', 'installed_sha256', 'postboot_sha256', 'promotion_sha256'):
        if not SHA.fullmatch(str(value[field])):
            refuse('invalid_acceptance_binding')
    for field in ('resume_sha256', 'previous_acceptance_sha256', 'retention_integrity_sha256'):
        if value.get(field) is not None and not SHA.fullmatch(str(value[field])):
            refuse('invalid_acceptance_binding')
    if raw != encode(value):
        refuse('noncanonical_acceptance_record')
    return value, rpm.sha(raw), filename


def _acceptance_chain(stage):
    stage = Path(stage)
    pointer = strict_json(rpm.read(stage / 'kernel-acceptance-current.json', 8192))
    exact(pointer, {'boot_id', 'sha256'})
    if not isinstance(pointer['boot_id'], str) or not SHA.fullmatch(str(pointer['sha256'])):
        refuse('invalid_acceptance_pointer')
    current = _acceptance_file(stage, 'kernel-acceptance-' + pointer['boot_id'] + '.json')
    if current[1] != pointer['sha256']:
        refuse('acceptance_pointer_changed')
    candidates = list(stage.glob('kernel-acceptance-*.json'))
    if len(candidates) > 1001:
        refuse('acceptance_history_limit')
    chain, seen = [current], {current[1]}
    fixed = ('operation_sha256', 'kernel_plan_sha256', 'installed_sha256', 'postboot_sha256', 'promotion_sha256', 'kernel', 'recovery_kernel')
    while chain[-1][0]['previous_acceptance_sha256'] is not None:
        wanted = chain[-1][0]['previous_acceptance_sha256']
        if wanted in seen or len(chain) >= 1000:
            refuse('acceptance_history_cycle')
        matches = [path for path in candidates if path.name != 'kernel-acceptance-current.json'
                   and rpm.sha(rpm.read(path, 65536)) == wanted]
        if len(matches) != 1:
            refuse('acceptance_predecessor_missing')
        prior = _acceptance_file(stage, matches[0].name)
        if (any(prior[0][key] != current[0][key] for key in fixed)
                or any(prior[0]['boot_id'] == item[0]['boot_id'] for item in chain)):
            refuse('acceptance_predecessor_changed')
        chain.append(prior)
        seen.add(wanted)
    return chain


def read_acceptance(stage):
    """Resolve current immutable acceptance generation and verify its history."""
    return _acceptance_chain(stage)[0]


def load_candidate(stage):
    """Resolve a current operation's exact accepted-install candidate reference."""
    stage = Path(stage)
    pending_path = stage.parent.parent / 'kernel-pending.json'
    first = None
    if os.path.lexists(pending_path):
        pending = strict_json(rpm.read(pending_path, 8192))
    else:
        completed = strict_json(rpm.read(stage / 'kernel-completed.json', 65536))
        exact(completed, {'schema', 'pending', 'first_acceptance'})
        exact(completed['first_acceptance'], {'filename', 'sha256'})
        first = _acceptance_file(stage, completed['first_acceptance']['filename'])
        if completed['schema'] != 1 or completed['first_acceptance']['sha256'] != first[1]:
            refuse('completed_candidate_binding_changed')
        pending = completed['pending']
    exact(pending, {'schema', 'stage', 'plan_sha256', 'installed_sha256', 'operation_sha256', 'kernel', 'old_kernel'})
    candidate = Path(pending['stage'])
    if pending['schema'] != 1 or candidate.is_symlink() or candidate.resolve().parent != stage.resolve().parent:
        refuse('pending_candidate_stage_changed')
    if candidate != stage:
        reference = strict_json(rpm.read(stage / 'kernel-deferred.json', 8192))
        if reference != {'schema': 1, 'kind': 'kernel-deferred-v1', 'candidate': pending,
                         'operation_sha256': rpm.sha(rpm.read(stage / 'operation.json', 8192))}:
            refuse('deferred_candidate_binding_changed')
    payload, checksum = load_plan(candidate)
    raw = rpm.read(candidate / 'kernel-installed.json', rpm.MAX_XML)
    installed = strict_json(raw)
    if (checksum != pending['plan_sha256'] or rpm.sha(raw) != pending['installed_sha256']
            or payload['operation_sha256'] != pending['operation_sha256']
            or payload['kernel'] != pending['kernel'] or payload['old_kernel'] != pending['old_kernel']
            or installed.get('plan_sha256') != checksum):
        refuse('pending_candidate_receipt_changed')
    if first is not None and (first[0]['operation_sha256'] != rpm.sha(rpm.read(stage / 'operation.json', 8192))
            or first[0]['kernel_plan_sha256'] != checksum or first[0]['installed_sha256'] != pending['installed_sha256']
            or first[0]['kernel'] != payload['kernel'] or first[0]['recovery_kernel'] != payload['old_kernel']):
        refuse('completed_candidate_acceptance_changed')
    return candidate, payload, checksum, installed


def mark_complete(stage, acceptance, *, runner=run):
    """Retain exact accepted pointer before atomically clearing only our pending.

    The lifecycle caller owns manager/update locks and supplies durable kernel
    boot/runtime acceptance. The operation journal may keep maintenance active
    for retention recovery; this helper never releases that gate. A retry can
    resolve the completed pointer after unlink; it never adopts or removes
    another operation's candidate.
    """
    from . import kernel_boot
    stage = Path(stage)
    chain = _acceptance_chain(stage)
    value, acceptance_sha, filename = chain[0]
    if acceptance != value:
        refuse('complete_lifecycle_acceptance_required')
    proof = kernel_boot.accepted_transitions(stage, runner=runner)
    if any(value.get(key) != item for key, item in proof.items()):
        refuse('final_acceptance_transition_changed')
    candidate, payload, checksum, installed = load_candidate(stage)
    pending = {'schema': 1, 'stage': str(candidate), 'plan_sha256': checksum,
               'installed_sha256': rpm.sha(rpm.read(candidate / 'kernel-installed.json', rpm.MAX_XML)),
               'operation_sha256': payload['operation_sha256'], 'kernel': payload['kernel'], 'old_kernel': payload['old_kernel']}
    completion_path = stage / 'kernel-completed.json'
    if os.path.lexists(completion_path):
        completion = strict_json(rpm.read(completion_path, 65536))
        if (completion.get('schema') != 1 or completion.get('pending') != pending
                or completion.get('first_acceptance') not in [{'filename': item[2], 'sha256': item[1]} for item in chain]):
            refuse('completion_acceptance_history_changed')
    else:
        completion = {'schema': 1, 'pending': pending, 'first_acceptance': {'filename': filename, 'sha256': acceptance_sha}}
        record(stage, 'kernel-completed.json', completion)
    path = stage.parent.parent / 'kernel-pending.json'
    if os.path.lexists(path):
        if strict_json(rpm.read(path, 8192)) != pending:
            refuse('another_kernel_candidate_pending')
        path.unlink()
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    return {'ok': True, 'status': 'complete', 'acceptance_sha256': acceptance_sha}


def adopt_pending(stage):
    stage = Path(stage)
    pending_path = stage.parent.parent / 'kernel-pending.json'
    if not os.path.lexists(pending_path):
        return None
    pending = strict_json(rpm.read(pending_path, 8192))
    reference = {'schema': 1, 'kind': 'kernel-deferred-v1', 'candidate': pending,
                 'operation_sha256': rpm.sha(rpm.read(stage / 'operation.json', 8192))}
    record(stage, 'kernel-deferred.json', reference)
    _, payload, _, _ = load_candidate(stage)
    return {'ok': True, 'status': 'kernel_pending', 'plan_sha256': rpm.sha(encode(reference)),
            'kernel': payload['kernel'], 'reboot_required': True}
