"""Exact signed Rocky RPM transactions and separate file-level AIDE plans.

The first ABI executes only scriptless replacements with unchanged regular-file
and directory sets. It refuses unknown generated outputs, links, config files,
checker/boot transitions and applicable external triggers before host mutation.
No solver is rerun during application: RPM receives the retained verified files.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import tarfile
import uuid
import xml.etree.ElementTree as ET

from .common import Refused, atomic_json, require_linux_root, run, trusted_file
from .host_job_storage import digest, exact, strict_json

MAX_XML = 128 * 1024**2
MAX_RPM = 128 * 1024**2
MAX_FILES = 4096
KEY = Path('/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9')
KEY_SHA256 = '3a66e521e7a4abac9768d889c7cd60a8250f59512b275cf576c8a10ff34624c1'
KEY_ID = '350d275d'
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}')
# These cannot use the inert-payload ABI even if a vendor header lacks scripts.
MIGRATION = re.compile(r'^(?:kernel|aide|rpm|dnf|python3|glibc|openssl|crypto-policies|selinux-policy|grub2|shim|systemd|dracut|cryptsetup|openscap|scap-security-guide)(?:-|$)')
SCRIPTS = ('Prein', 'Postin', 'Preun', 'Postun', 'Pretrans', 'Posttrans', 'Verifyscript',
           'Triggerscripts', 'Filetriggerscripts', 'Transfiletriggerscripts')


class ScannerEngine:
    """Inspection only. No package command or activation authority is exposed.

    Structural archive verification is portable and does not verify vendor
    signatures. Native inspection writes only its private evidence/key database.
    Measurement does not establish dependency solving, trigger execution, AIDE,
    recovery or assessment qualification. Those remain mandatory separate gates.
    A caller must authenticate accepted current inventory before admission_identity;
    shape/hash checks here cannot turn an arbitrary dictionary into enrollment.
    """

    VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?')
    SHA = re.compile(r'[a-f0-9]{64}')
    MAX_ARCHIVE = 16 * 1024**2
    MAX_DESCRIPTOR = 65536
    KIND = 'scanner-engine-rpm-v1'
    PLATFORM = {'distribution': 'rocky', 'major': 9, 'arch': 'x86_64',
                'rpm': '4.16.1.3-40.el9', 'key_sha256': KEY_SHA256}
    TRANSACTION = {'excludedocs': True, 'vendor_triggers': 'intact'}
    TRIGGER_PROFILE = 'rocky9-scanner-native283-mandb9-v1-unqualified'
    ROLLBACK_PROFILE = 'paired-rpm-reverse-v1-unqualified'
    OMITTED_DOCUMENT_DIRECTORIES = frozenset({
        '/usr/share/doc/openscap', '/usr/share/doc/openscap/manual',
        '/usr/share/doc/openscap/manual/images',
    })
    # Acquisition pins, not execution qualification. No wildcard future pair.
    PACKAGES = {
        'from/openscap.rpm': ('openscap', '1.3.13', '1.el9_7.rocky.0.1', 1990515,
                             '2fd5474e0f220b75c2b376ad5dd055df0d4b22ae5624e7f7cb878a1106922a18'),
        'from/openscap-scanner.rpm': ('openscap-scanner', '1.3.13', '1.el9_7.rocky.0.1', 59143,
                                     '219e0853338357286236869dbb7ad9e52345082223193e3a4b586820a61fdada'),
        'to/openscap.rpm': ('openscap', '1.3.14', '1.el9_8.rocky.0.1', 1999186,
                           'f4468c8f480a672273f2c8449dd46d66bf5252a0bdca0a8637cb2c50911234ff'),
        'to/openscap-scanner.rpm': ('openscap-scanner', '1.3.14', '1.el9_8.rocky.0.1', 58845,
                                   'a3f6f365a51e0c8cbff06b4b6664407a0bccb5a5e590d1712f6002a9006a5b16'),
    }
    TRIGGERS = {
        'glibc-common-0:2.34-283.el9_8.x86_64': '4515ccd61d4e9de001a2db703b26d3bee9060748270f8e7f155c5cb561ce6c20',
        'man-db-0:2.9.3-9.el9.x86_64': '09475e782a4c6e7e27c9015c4fafec59321c7091b5c3a8118a0e9847f50b3fdd',
    }
    QUALIFICATION_GAPS = (
        'native_dependency_solver', 'native_engine_capability_and_tool_provenance',
        'native_excluded_docs_trigger_selection',
        'native_generated_output_and_reverse_recipe', 'owned_hook_worker_and_trigger_lifetime',
        'composed_aide_and_ordinary_history', 'fresh_engine_bound_assessment_and_review',
        'qualified_commit_rollback_recovery_and_finalization',
    )

    @staticmethod
    def encoded(value):
        return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

    @staticmethod
    def _refuse(reason):
        raise Refused('scanner_engine_' + reason)

    @classmethod
    def _exact(cls, value, fields):
        if not isinstance(value, dict) or set(value) != set(fields):
            cls._refuse('invalid_shape')

    @classmethod
    def _hash(cls, value):
        if not isinstance(value, str) or not cls.SHA.fullmatch(value):
            cls._refuse('invalid_digest')
        return value

    @classmethod
    def validate_component(cls, value):
        cls._exact(value, {'artifact', 'version', 'from_versions', 'rollback_safe', 'engine_schema', 'descriptor_sha256'})
        if (value['artifact'] != 'scanner-engine.tar' or type(value['engine_schema']) is not int
                or value['engine_schema'] != 1 or value['rollback_safe'] is not True
                or not isinstance(value['version'], str) or not cls.VERSION.fullmatch(value['version'])):
            cls._refuse('unsupported_component')
        versions = value['from_versions']
        if (not isinstance(versions, list) or not 1 <= len(versions) <= 16
                or any(not isinstance(v, str) or not (cls.VERSION.fullmatch(v)
                       or re.fullmatch(r'enrolled-engine-sha256:[a-f0-9]{64}', v)) for v in versions)
                or len(set(versions)) != len(versions) or value['version'] in versions):
            cls._refuse('unsupported_admission_versions')
        cls._hash(value['descriptor_sha256'])
        return value

    @classmethod
    def descriptor(cls, value):
        cls._exact(value, {'schema', 'kind', 'version', 'platform', 'from', 'to',
                           'transaction', 'trigger_profile', 'rollback_profile'})
        if (type(value['schema']) is not int or value['schema'] != 1 or value['kind'] != cls.KIND
                or not isinstance(value['version'], str) or not cls.VERSION.fullmatch(value['version'])
                or value['platform'] != cls.PLATFORM or type(value['platform'].get('major')) is not int
                or value['transaction'] != cls.TRANSACTION or value['transaction'].get('excludedocs') is not True
                or value['trigger_profile'] != cls.TRIGGER_PROFILE or value['rollback_profile'] != cls.ROLLBACK_PROFILE):
            cls._refuse('unsupported_recipe')
        for side in ('from', 'to'):
            records = value[side]
            expected = sorted(member for member in cls.PACKAGES if member.startswith(side + '/'))
            if not isinstance(records, list) or len(records) != 2:
                cls._refuse('exact_pair_required')
            for item, member in zip(records, expected):
                cls._exact(item, {'name', 'nevra', 'member', 'bytes', 'sha256', 'header_sha256', 'payload_sha256'})
                name, version, release, length, checksum = cls.PACKAGES[member]
                if (item['member'] != member or item['name'] != name
                        or item['nevra'] != f'{name}-1:{version}-{release}.x86_64'
                        or type(item['bytes']) is not int or item['bytes'] != length or item['sha256'] != checksum):
                    cls._refuse('unqualified_package_pair')
                cls._hash(item['header_sha256'])
                cls._hash(item['payload_sha256'])
        return value

    @classmethod
    def verify_archive(cls, path, *, expected_sha256=None, expected_descriptor_sha256=None, expected_version=None):
        """Canonical member/hash validation only; does not approve a release."""
        from . import host_payload
        raw = host_payload.read_regular(Path(path), cls.MAX_ARCHIVE)
        checksum = sha(raw)
        if expected_sha256 is not None and cls._hash(expected_sha256) != checksum:
            cls._refuse('archive_hash_changed')
        files, end = {}, 0
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
                for entry in archive:
                    maximum = cls.MAX_DESCRIPTOR if entry.name == 'engine.json' else MAX_RPM
                    if (entry.name not in {'engine.json', *cls.PACKAGES} or entry.name in files
                            or entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or entry.pax_headers
                            or entry.uid != 0 or entry.gid != 0 or entry.mode != 0o644
                            or entry.offset != end or entry.offset_data != entry.offset + 512
                            or entry.linkname or not 0 < entry.size <= maximum):
                        cls._refuse('unsafe_archive_member')
                    body = archive.extractfile(entry).read(entry.size + 1)
                    if len(body) != entry.size:
                        cls._refuse('archive_member_changed')
                    files[entry.name] = body
                    end = entry.offset_data + ((entry.size + 511) // 512) * 512
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise Refused('scanner_engine_malformed_archive') from exc
        if set(files) != {'engine.json', *cls.PACKAGES} or len(raw) - end < 1024 or len(raw) % 512 or any(raw[end:]):
            cls._refuse('archive_inventory_or_trailing_data')
        descriptor_raw = files.pop('engine.json')
        value = cls.descriptor(strict_json(descriptor_raw))
        if descriptor_raw != cls.encoded(value):
            cls._refuse('noncanonical_descriptor')
        if expected_descriptor_sha256 is not None and cls._hash(expected_descriptor_sha256) != sha(descriptor_raw):
            cls._refuse('descriptor_hash_changed')
        if expected_version is not None and value['version'] != expected_version:
            cls._refuse('version_changed')
        for item in value['from'] + value['to']:
            body = files[item['member']]
            if len(body) != item['bytes'] or sha(body) != item['sha256']:
                cls._refuse('rpm_member_changed')
        return {'descriptor': value, 'descriptor_sha256': sha(descriptor_raw), 'files': files,
                'archive_sha256': checksum, 'vendor_signatures_verified': False, 'activation_allowed': False}

    @classmethod
    def build_archive(cls, source, stage, *, version, runner=run):
        """Build a reproducible inspection artifact from the four fixed inputs.

        The caller creates separate private source/stage directories. Only after
        native vendor verification and unchanged-input readback is the fixed
        output created exclusively. Failed private evidence is preserved; a
        preexisting or torn output is never replaced or treated as completion.
        No signed release or execution qualification is created by this method.
        """
        require_linux_root()
        source, stage = Path(source), Path(stage)
        for path in (source, stage):
            cls._directory(path)
            if not path.is_absolute() or path.resolve() != path:
                cls._refuse('noncanonical_builder_directory')
        if source == stage or source in stage.parents or stage in source.parents:
            cls._refuse('builder_directories_overlap')
        if not isinstance(version, str) or not cls.VERSION.fullmatch(version):
            cls._refuse('invalid_builder_version')
        output = stage / 'scanner-engine.tar'
        if os.path.lexists(output):
            cls._refuse('builder_output_exists')

        def input_layout():
            if {p.name for p in source.iterdir()} != {'from', 'to'}:
                cls._refuse('builder_input_inventory')
            for side in ('from', 'to'):
                directory = source / side
                cls._directory(directory)
                if {p.name for p in directory.iterdir()} != {'openscap.rpm', 'openscap-scanner.rpm'}:
                    cls._refuse('builder_input_inventory')

        input_layout()
        platform(runner)
        retained = stage / 'scanner-engine-build'
        retained.mkdir(mode=0o700, exist_ok=True)
        cls._directory(retained)
        bodies, identities, inodes = {}, {}, set()
        descriptor = {'schema': 1, 'kind': cls.KIND, 'version': version, 'platform': dict(cls.PLATFORM),
                      'transaction': dict(cls.TRANSACTION), 'trigger_profile': cls.TRIGGER_PROFILE,
                      'rollback_profile': cls.ROLLBACK_PROFILE, 'from': [], 'to': []}
        for member in sorted(cls.PACKAGES):
            path = source / member
            raw = read(path)
            info = path.lstat()
            inode = (info.st_dev, info.st_ino)
            if inode in inodes:
                cls._refuse('builder_input_alias')
            inodes.add(inode)
            identities[member] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                                  info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            name, native_version, release, length, checksum = cls.PACKAGES[member]
            if len(raw) != length or sha(raw) != checksum:
                cls._refuse('builder_input_not_pinned')
            bodies[member] = raw
            private_rpm = retained / (checksum + '.rpm')
            immutable(private_rpm, raw)
            # The acquisition digest is fixed before RPM parses the input. The
            # complete native signature verification below gates publication.
            values = headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(private_rpm)], timeout=120))
            if len(values) != 1:
                cls._refuse('ambiguous_signed_header')
            projected = cls.payload(values[0])
            cls.omitted_directories(projected)
            descriptor[member.split('/')[0]].append({'name': name,
                'nevra': f'{name}-1:{native_version}-{release}.x86_64', 'member': member,
                'bytes': length, 'sha256': checksum, 'header_sha256': sha(cls.encoded(values[0])),
                'payload_sha256': sha(cls.encoded(projected))})
        cls.descriptor(descriptor)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in [('engine.json', cls.encoded(descriptor)), *sorted(bodies.items())]:
                entry = tarfile.TarInfo(name)
                entry.uid, entry.gid, entry.mode, entry.mtime = 0, 0, 0o644, 0
                entry.uname = entry.gname = ''
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        raw = buffer.getvalue()
        if len(raw) > cls.MAX_ARCHIVE:
            cls._refuse('builder_archive_too_large')
        candidate = retained / 'scanner-engine.tar'
        immutable(candidate, raw)
        inspection = cls.inspect_archive(candidate, stage, runner=runner, expected_sha256=sha(raw),
            expected_descriptor_sha256=sha(cls.encoded(descriptor)), expected_version=version)
        input_layout()
        for member, body in bodies.items():
            path = source / member
            if read(path) != body:
                cls._refuse('builder_input_changed')
            info = path.lstat()
            after = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                     info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if after != identities[member]:
                cls._refuse('builder_input_changed')
        if read(candidate, cls.MAX_ARCHIVE) != raw:
            cls._refuse('builder_candidate_changed')
        # O_EXCL also handles a concurrent publisher after the early check.
        # Interrupted output is kept for diagnosis and cannot be overwritten.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return {'schema': 1, 'kind': 'scanner-engine-built-archive-v1', 'filename': output.name,
                'bytes': len(raw), 'archive_sha256': inspection['archive_sha256'],
                'descriptor_sha256': inspection['descriptor_sha256'], 'version': version,
                'vendor_signatures_verified': True, 'activation_allowed': False,
                'qualification_gaps': list(cls.QUALIFICATION_GAPS)}

    @classmethod
    def admission_identity(cls, current):
        """Caller must first authenticate current and its accepted baseline receipt."""
        if (not isinstance(current, dict) or type(current.get('sequence')) is not int or current['sequence'] < 1
                or not isinstance(current.get('version'), str) or not cls.VERSION.fullmatch(current['version'])
                or not isinstance(current.get('components'), dict)
                or not {'host', 'nebulalog', 'baseline'} <= set(current['components'])):
            cls._refuse('accepted_content_inventory_required')
        baseline = current['components']['baseline']
        for name in ('host', 'nebulalog'):
            component = current['components'][name]
            if (not isinstance(component, dict) or not isinstance(component.get('version'), str)
                    or not cls.VERSION.fullmatch(component['version'])):
                cls._refuse('invalid_current_component_identity')
        cls._exact(baseline, {'version', 'generation', 'policy_sha256', 'engine'})
        if (not isinstance(baseline['version'], str) or not (cls.VERSION.fullmatch(baseline['version'])
                or re.fullmatch(r'sha256:[a-f0-9]{64}', baseline['version']))):
            cls._refuse('invalid_content_version')
        cls._hash(baseline['generation']); cls._hash(baseline['policy_sha256'])
        engine = baseline['engine']
        cls._exact(engine, {'scanner_nevra', 'version_sha256'})
        if engine['scanner_nevra'] not in {f'{n}-1:{v}-{r}.x86_64' for n, v, r, _, _ in cls.PACKAGES.values() if n == 'openscap-scanner'}:
            cls._refuse('unsupported_enrolled_engine')
        cls._hash(engine['version_sha256'])
        checksum = sha(cls.encoded(engine))
        if 'scap' not in current['components']:
            return 'enrolled-engine-sha256:' + checksum
        installed = current['components']['scap']
        cls._exact(installed, {'version', 'engine_sha256', 'descriptor_sha256'})
        if (not isinstance(installed['version'], str) or not cls.VERSION.fullmatch(installed['version'])
                or installed['engine_sha256'] != checksum):
            cls._refuse('installed_engine_identity_changed')
        cls._hash(installed['descriptor_sha256'])
        return installed['version']

    @classmethod
    def payload(cls, header):
        """Signed header projection; separate from the inert OS payload ABI."""
        package = identity(header)
        allowed = {f'{n}-1:{v}-{r}.x86_64' for n, v, r, _, _ in cls.PACKAGES.values()}
        if package['nevra'] not in allowed or one(header, 'Filedigestalgo', 0) != 8:
            cls._refuse('unqualified_signed_header')
        if any(any(v not in ('', None) for v in header.get(tag, [])) for tag in SCRIPTS):
            cls._refuse('package_script_or_trigger')
        names, parents, indexes = (header.get(k, []) for k in ('Basenames', 'Dirnames', 'Dirindexes'))
        tags = ('Filemodes', 'Filesizes', 'Filedigests', 'Fileusername', 'Filegroupname', 'Fileflags', 'Filelinktos')
        arrays = {tag: header.get(tag, []) for tag in tags}
        if (not 1 <= len(names) <= MAX_FILES or len(indexes) != len(names)
                or any(len(v) != len(names) for v in arrays.values()) or any(header.get('Filecaps', []))):
            cls._refuse('invalid_payload_metadata')
        files = []
        for i, name in enumerate(names):
            index = indexes[i]
            if (type(index) is not int or not 0 <= index < len(parents) or not isinstance(parents[index], str)
                    or not isinstance(name, str) or not name or '/' in name):
                cls._refuse('invalid_payload_path')
            path = parents[index] + name
            mode, flags, size, target = (arrays[k][i] for k in ('Filemodes', 'Fileflags', 'Filesizes', 'Filelinktos'))
            if (not path.startswith('/usr/') and path not in {'/etc/bash_completion.d', '/etc/bash_completion.d/oscap'}
                    or str(Path(path)) != path or '..' in Path(path).parts
                    or type(mode) is not int or type(flags) is not int or flags & ~(2 | 128 | 4096)
                    or type(size) is not int or not 0 <= size <= MAX_RPM
                    or arrays['Fileusername'][i] != 'root' or arrays['Filegroupname'][i] != 'root'):
                cls._refuse('unsupported_payload_metadata')
            kind = 'directory' if stat.S_ISDIR(mode) else 'file' if stat.S_ISREG(mode) else 'symlink' if stat.S_ISLNK(mode) else None
            if kind is None or mode & 0o7000 or kind != 'symlink' and mode & 0o022:
                cls._refuse('unsupported_payload_type_or_mode')
            if flags & 4096 and not (path == '/usr/lib/.build-id' or path.startswith('/usr/lib/.build-id/')):
                cls._refuse('unexpected_artifact_flag')
            row = {'path': path, 'kind': kind, 'uid': 0, 'gid': 0, 'mode': stat.S_IMODE(mode), 'flags': flags}
            if kind == 'symlink':
                if (not isinstance(target, str) or not target or target.startswith('/') or '\x00' in target
                        or stat.S_IMODE(mode) != 0o777 or flags & (2 | 128)):
                    cls._refuse('unsafe_payload_link')
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
                if resolved not in {'/usr/bin/oscap', '/usr/lib64/libopenscap.so.25.7.3', '/usr/lib64/libopenscap.so.25.7.4'}:
                    cls._refuse('foreign_payload_link_target')
                row['target'] = target
            elif target:
                cls._refuse('unexpected_payload_link')
            elif kind == 'file':
                row.update(bytes=size, sha256=cls._hash(arrays['Filedigests'][i]))
            files.append(row)
        if len({v['path'] for v in files}) != len(files):
            cls._refuse('duplicate_payload_path')
        dependencies = {}
        for prefix in ('Require', 'Provide', 'Conflict', 'Obsolete', 'Recommend', 'Suggest', 'Supplement', 'Enhance'):
            keys = (prefix + 'name', prefix + 'flags', prefix + 'version')
            values = [header.get(k, []) for k in keys]
            if len({len(v) for v in values}) != 1 or len(values[0]) > MAX_FILES:
                cls._refuse('invalid_dependency_metadata')
            if any(not isinstance(n, str) or not n or type(f) is not int or f < 0 or not isinstance(v, str)
                   for n, f, v in zip(*values)):
                cls._refuse('invalid_dependency_metadata')
            dependencies[prefix.lower()] = [dict(name=n, flags=f, version=v) for n, f, v in zip(*values)]
        return {**package, 'files': sorted(files, key=lambda row: row['path']), 'dependencies': dependencies}

    @classmethod
    def _directory(cls, path):
        for item in (path, *path.parents):
            info = item.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                cls._refuse('unsafe_private_directory')
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            cls._refuse('private_stage_mode')

    @classmethod
    def omitted_directories(cls, payload):
        """The exact unflagged structural parents omitted by this signed pair.

        This is a closed payload-graph check, not a generic directory exception.
        Native disposition, ownership and actual absence are checked separately.
        """
        if payload['name'] != 'openscap':
            return set()
        rows = {row['path']: row for row in payload['files']}
        for path in cls.OMITTED_DOCUMENT_DIRECTORIES:
            if path not in rows or rows[path]['kind'] != 'directory' or rows[path]['flags'] != 0:
                cls._refuse('omitted_directory_graph_changed')
        descendants = [row for path, row in rows.items() if path.startswith('/usr/share/doc/openscap/')]
        docs = [row for row in descendants if row['path'] not in cls.OMITTED_DOCUMENT_DIRECTORIES]
        if len(docs) != 5 or any(row['kind'] != 'file' or row['flags'] != 2 for row in docs):
            cls._refuse('omitted_directory_graph_changed')
        return set(cls.OMITTED_DOCUMENT_DIRECTORIES)

    @classmethod
    def inspect_archive(cls, path, stage, *, runner=run, **expected):
        """Verify all four actual vendor RPMs; mutate only private retained evidence."""
        require_linux_root()
        stage = Path(stage)
        cls._directory(stage)
        archive = cls.verify_archive(path, **expected)
        platform(runner)
        if sha(read(KEY, 65536)) != KEY_SHA256:
            cls._refuse('rocky_trust_changed')
        retained = stage / 'scanner-engine-inspection'
        retained.mkdir(mode=0o700, exist_ok=True)
        cls._directory(retained)
        immutable(retained / 'engine.json', cls.encoded(archive['descriptor']))
        keydb = retained / 'keydb'
        if not keydb.exists():
            keydb.mkdir(mode=0o700)
            if Path('/sys/fs/selinux/enforce').exists():
                runner(['/usr/bin/chcon', '--reference=/var/lib/rpm', str(keydb)])
            runner(['/usr/bin/rpm', '--dbpath', str(keydb), '--initdb'])
            runner(['/usr/bin/rpmkeys', '--dbpath', str(keydb), '--import', str(KEY)])
        cls._directory(keydb)
        if runner(['/usr/bin/rpm', '--dbpath', str(keydb), '--query', '--all', '--queryformat', '%{NAME} %{VERSION}\n']).splitlines() != ['gpg-pubkey ' + KEY_ID]:
            cls._refuse('private_keyring_changed')
        packages = []
        for item in archive['descriptor']['from'] + archive['descriptor']['to']:
            target = retained / (item['sha256'] + '.rpm')
            immutable(target, archive['files'][item['member']])
            report = runner(['/usr/bin/rpmkeys', '--dbpath', str(keydb), '--checksig', '--verbose', str(target)], timeout=120)
            verified = signature(target, keydb, lambda *_a, **_k: report)
            if not {'Header SHA256 digest: OK', 'Payload SHA256 digest: OK'} <= {line.strip() for line in report.splitlines()}:
                cls._refuse('rpm_payload_digest_not_verified')
            xml = runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(target)], timeout=120)
            native = headers(xml)
            if len(native) != 1:
                cls._refuse('ambiguous_signed_header')
            projected = cls.payload(native[0])
            cls.omitted_directories(projected)
            if (sha(cls.encoded(native[0])) != item['header_sha256'] or sha(cls.encoded(projected)) != item['payload_sha256']
                    or projected['nevra'] != item['nevra'] or sha(read(target)) != item['sha256']):
                cls._refuse('signed_header_or_payload_changed')
            immutable(retained / (item['sha256'] + '.xml'), xml.encode())
            packages.append({'member': item['member'], 'sha256': item['sha256'], 'signature': verified,
                             'signed_header': native[0], 'payload': projected})
        result = {'schema': 1, 'kind': 'scanner-engine-inspection-v1', 'descriptor': archive['descriptor'],
                  'archive_sha256': archive['archive_sha256'], 'descriptor_sha256': archive['descriptor_sha256'],
                  'packages': packages, 'vendor_signatures_verified': True, 'activation_allowed': False,
                  'qualification_gaps': list(cls.QUALIFICATION_GAPS)}
        immutable(retained / 'inspection.json', cls.encoded(result))
        return result

    @classmethod
    def _observe(cls, path):
        """No-follow native filesystem observation, not a metadata acceptance rule."""
        path = Path(path)
        for parent in reversed(path.parents):
            try:
                info = parent.lstat()
            except FileNotFoundError:
                return None
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                cls._refuse('unsafe_payload_ancestry')
        try:
            before = path.lstat()
        except FileNotFoundError:
            return None
        kind = 'directory' if stat.S_ISDIR(before.st_mode) else 'file' if stat.S_ISREG(before.st_mode) else 'symlink' if stat.S_ISLNK(before.st_mode) else None
        if kind is None or before.st_uid != 0 or before.st_gid != 0 or kind == 'file' and before.st_nlink != 1:
            cls._refuse('unsafe_installed_payload')
        value = {'kind': kind, 'uid': before.st_uid, 'gid': before.st_gid, 'mode': stat.S_IMODE(before.st_mode)}
        if kind == 'file':
            raw = read(path)
            value.update(bytes=len(raw), sha256=sha(raw))
        elif kind == 'symlink':
            value['target'] = os.readlink(path)
        attributes = {}
        for name in sorted(os.listxattr(path, follow_symlinks=False)):
            raw = os.getxattr(path, name, follow_symlinks=False)
            if len(raw) > 65536 or len(attributes) >= 64:
                cls._refuse('oversized_payload_xattrs')
            attributes[name] = {'bytes': len(raw), 'sha256': sha(raw)}
        after = path.lstat()
        if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_size, before.st_nlink, before.st_ctime_ns, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_size, after.st_nlink, after.st_ctime_ns, after.st_mtime_ns):
            cls._refuse('installed_payload_changed_during_read')
        return {**value, 'xattrs': attributes}

    @classmethod
    def _paths(cls, header):
        names, parents, indexes = (header.get(k, []) for k in ('Basenames', 'Dirnames', 'Dirindexes'))
        if len(names) != len(indexes) or len(names) > 100000:
            cls._refuse('invalid_installed_file_inventory')
        result = []
        for name, index in zip(names, indexes):
            if (not isinstance(name, str) or '/' in name or type(index) is not int
                    or not 0 <= index < len(parents) or not isinstance(parents[index], str)):
                cls._refuse('invalid_installed_file_inventory')
            # Rocky's filesystem package owns '/' as basename '' + dirname '/'.
            if not name and parents[index] != '/':
                cls._refuse('invalid_installed_file_inventory')
            path = parents[index] + name
            if not path.startswith('/') or str(Path(path)) != path or '..' in Path(path).parts:
                cls._refuse('invalid_installed_file_inventory')
            result.append(path)
        if len(result) != len(set(result)):
            cls._refuse('duplicate_installed_file_path')
        return result

    @classmethod
    def closure(cls, installed, payloads):
        """Read-only actual header closure. Candidate lists are not solver approval."""
        identities = [identity(h)['nevra'] for h in installed]
        if len(set(identities)) != len(identities):
            cls._refuse('duplicate_installed_identity')
        if any(identity(h)['name'].startswith('openscap-engine-') for h in installed):
            cls._refuse('unqualified_engine_plugin')
        if 'rpm-0:4.16.1.3-40.el9.x86_64' not in identities or 'rpm-libs-0:4.16.1.3-40.el9.x86_64' not in identities:
            cls._refuse('native_rpm_profile_changed')
        paths = {f['path'] for p in payloads for f in p['files']}
        triggers = []
        for h in installed:
            fields = {k: v for k, v in h.items() if k.startswith(('Trigger', 'Filetrigger', 'Transfiletrigger'))}
            if set(h.get('Triggername', [])) & {'openscap', 'openscap-scanner'}:
                cls._refuse('unqualified_package_trigger')
            matches = []
            for tag in ('Filetriggername', 'Transfiletriggername'):
                for prefix in h.get(tag, []):
                    if not isinstance(prefix, str) or not prefix.startswith('/') or '..' in Path(prefix).parts:
                        cls._refuse('invalid_trigger_prefix')
                    if any(p == prefix.rstrip('/') or p.startswith(prefix.rstrip('/') + '/') for p in paths):
                        matches.append({'tag': tag, 'prefix': prefix})
            if matches:
                owner = identity(h)['nevra']
                if cls.TRIGGERS.get(owner) != sha(cls.encoded(fields)):
                    cls._refuse('unqualified_external_trigger_profile')
                triggers.append({'owner': owner, 'fields': fields, 'matches': matches})
        if {t['owner'] for t in triggers} != set(cls.TRIGGERS):
            cls._refuse('incomplete_native_trigger_profile')
        providers = {}
        required_paths = {r['name'] for p in payloads for r in p['dependencies']['require'] if r['name'].startswith('/')}
        for h in installed:
            names, flags, versions = (h.get(k, []) for k in ('Providename', 'Provideflags', 'Provideversion'))
            if len({len(names), len(flags), len(versions)}) != 1:
                cls._refuse('invalid_installed_providers')
            for n, f, v in zip(names, flags, versions):
                if not isinstance(n, str) or not isinstance(v, str) or type(f) is not int:
                    cls._refuse('invalid_installed_providers')
                providers.setdefault(n, []).append({'owner': identity(h)['nevra'], 'flags': f, 'version': v})
            for path in required_paths.intersection(cls._paths(h)):
                providers.setdefault(path, []).append({'owner': identity(h)['nevra'], 'flags': 0, 'version': ''})
        requirements = []
        for p in payloads:
            for req in p['dependencies']['require']:
                paired = req['name'] == 'openscap(x86-64)'
                internal = req['name'].startswith('rpmlib(')
                candidates = providers.get(req['name'], [])
                if not paired and not internal and not candidates:
                    cls._refuse('missing_dependency_provider')
                requirements.append({'package': p['nevra'], **req, 'paired': paired, 'internal_rpmlib': internal,
                                     'provider_candidates': candidates})
        return {'inventory': sorted(identities), 'header_sha256': sha(cls.encoded(installed)),
                'triggers': sorted(triggers, key=lambda row: row['owner']), 'requirements': requirements,
                'dependency_solver_verified': False, 'trigger_execution_verified': False}

    @classmethod
    def installed_header(cls, signed, actual, rpm_raw):
        """Exact signed invariants plus the six observed RPM installation tags."""
        added = {'Filestates', 'Installcolor', 'Installtime', 'Installtid', 'Packagedigestalgos', 'Packagedigests'}
        if (set(signed) & added or set(actual) != set(signed) | added
                or {k: v for k, v in actual.items() if k not in added} != signed
                or actual['Installcolor'] != [3]
                or actual['Packagedigestalgos'] != [8, 10]
                or any(type(v) is not int for v in actual['Installcolor'] + actual['Packagedigestalgos'])
                or actual['Packagedigests'] != [sha(rpm_raw), hashlib.sha512(rpm_raw).hexdigest()]):
            cls._refuse('installed_signed_header_changed')
        for key in ('Installtime', 'Installtid'):
            if len(actual[key]) != 1 or type(actual[key][0]) is not int or not 0 < actual[key][0] < 2**32:
                cls._refuse('invalid_installation_metadata')
        states = actual['Filestates']
        if len(states) != len(signed.get('Basenames', [])) or any(type(s) is not int or s not in (0, 2) for s in states):
            cls._refuse('invalid_installed_file_disposition')
        return {'signed_invariants_sha256': sha(cls.encoded(signed)),
                'installed_header_sha256': sha(cls.encoded(actual)),
                'installation': {k: actual[k] for k in sorted(added)}}

    @classmethod
    def measure(cls, path, stage, *, current, side='from', runner=run, **expected):
        if side not in ('from', 'to'):
            cls._refuse('invalid_measurement_side')
        admission = cls.admission_identity(current)
        inspected = cls.inspect_archive(path, stage, runner=runner, **expected)
        xml, installed, _ = inventory(runner)
        inventory_name = 'scanner-inventory-' + sha(xml.encode()) + '.xml'
        immutable(Path(stage) / 'scanner-engine-inspection' / inventory_name, xml.encode())
        payloads = [item['payload'] for item in inspected['packages']]
        closure = cls.closure(installed, payloads)
        selected = [p for row, p in zip(inspected['packages'], payloads) if row['member'].startswith(side + '/')]
        scope = {f['path'] for p in payloads for f in p['files']}
        owners = {}
        for h in installed:
            paths = cls._paths(h)
            if (identity(h)['name'] != 'openscap'
                    and any(p == '/usr/share/doc/openscap' or p.startswith('/usr/share/doc/openscap/') for p in paths)):
                cls._refuse('foreign_omitted_document_descendant')
            for name in scope.intersection(paths):
                owners.setdefault(name, []).append(identity(h)['nevra'])
        observed, installed_proofs = {}, []
        for p in selected:
            omitted_directories = cls.omitted_directories(p)
            actual = [h for h in installed if identity(h)['name'] == p['name']]
            if len(actual) != 1 or cls.payload(actual[0]) != p:
                cls._refuse('installed_signed_header_changed')
            source = next(row for row in inspected['packages'] if row['payload']['nevra'] == p['nevra'])
            raw = read(Path(stage) / 'scanner-engine-inspection' / (source['sha256'] + '.rpm'))
            if sha(raw) != source['sha256']:
                cls._refuse('retained_package_changed')
            installed_proofs.append({'nevra': p['nevra'], **cls.installed_header(source['signed_header'], actual[0], raw)})
            states = actual[0].get('Filestates', [])
            names = actual[0].get('Basenames', [])
            if len(states) != len(names) or any(type(s) is not int for s in states):
                cls._refuse('missing_installed_file_disposition')
            state_by_path = {actual[0]['Dirnames'][actual[0]['Dirindexes'][i]] + n: states[i] for i, n in enumerate(names)}
            for row in p['files']:
                state, value = state_by_path[row['path']], cls._observe(row['path'])
                if (row['kind'] != 'directory' or row['path'] in omitted_directories) and owners.get(row['path']) != [p['nevra']]:
                    cls._refuse('shared_installed_payload')
                if row['flags'] & 2 or row['path'] in omitted_directories:
                    if state != 2 or value is not None:
                        cls._refuse('excluded_document_present_or_disposition_changed')
                else:
                    want = {k: v for k, v in row.items() if k not in ('path', 'flags')}
                    if state != 0 or value is None or {k: v for k, v in value.items() if k != 'xattrs'} != want:
                        cls._refuse('installed_payload_drift')
                record = {'disposition': state, 'flags': row['flags'], 'observed': value}
                if row['path'] in observed and observed[row['path']] != record:
                    cls._refuse('overlapping_installed_payload')
                observed[row['path']] = record
        prospective = {}
        for p in payloads:
            for row in p['files']:
                if row['path'] in observed or row['path'] in prospective:
                    continue
                value = cls._observe(row['path'])
                claimed = owners.get(row['path'], [])
                if claimed and (value is None or row['kind'] != 'directory'):
                    cls._refuse('candidate_path_already_owned')
                if value is not None:
                    want = {k: v for k, v in row.items() if k not in ('path', 'flags')}
                    if row['kind'] != 'directory' or not claimed or {k: v for k, v in value.items() if k != 'xattrs'} != want:
                        cls._refuse('candidate_payload_conflict')
                prospective[row['path']] = {'observed': value, 'owners': sorted(owners.get(row['path'], []))}
        # Querying the actual executable is observational, not assessment or
        # approval. Existing enrolled version text must still match exactly.
        version = runner(['/usr/bin/oscap', '--version'])
        if not isinstance(version, str) or not 1 <= len(version) <= 65536 or 'OpenSCAP' not in version:
            cls._refuse('invalid_engine_version_observation')
        engine = {'scanner_nevra': next(p['nevra'] for p in selected if p['name'] == 'openscap-scanner'),
                  'version_sha256': sha(version.encode())}
        if current['components']['baseline']['engine'] != engine:
            cls._refuse('enrolled_engine_drift')
        if inventory(runner)[0] != xml or any(cls._observe(p) != r['observed'] for p, r in {**observed, **prospective}.items()):
            cls._refuse('installed_state_changed_during_measurement')
        return {'schema': 1, 'kind': 'scanner-engine-measurement-v1', 'admission_identity': admission,
                'archive_sha256': inspected['archive_sha256'], 'descriptor_sha256': inspected['descriptor_sha256'],
                'side': side, 'engine': engine, 'files': observed, 'prospective_paths': prospective, 'closure': closure,
                'installed_headers': installed_proofs,
                'inventory_xml': {'filename': inventory_name, 'sha256': sha(xml.encode()), 'bytes': len(xml.encode())},
                'omitted_document_directories': sorted(cls.OMITTED_DOCUMENT_DIRECTORIES),
                'vendor_signatures_verified': True, 'activation_allowed': False,
                'qualification_gaps': list(cls.QUALIFICATION_GAPS)}

    @classmethod
    def require_executable(cls, _measurement=None):
        # Neither publisher JSON nor matching acquisition hashes can waive any
        # of these still-unimplemented native/lifecycle acceptance gates.
        cls._refuse('execution_not_implemented_or_qualified')


def refuse(reason):
    raise Refused('os_payload_' + reason)


def read(path, maximum=MAX_RPM):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            refuse('unsafe_parent')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > maximum:
        refuse('unsafe_file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(raw) != opened.st_size:
        refuse('file_changed')
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def immutable(path, raw):
    if path.exists():
        if read(path, max(MAX_XML, MAX_RPM)) != raw:
            refuse('retained_evidence_changed')
        return
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def headers(xml):
    if not isinstance(xml, str) or len(xml.encode()) > MAX_XML or '<!' in xml:
        refuse('invalid_rpm_xml')
    try:
        root = ET.fromstring('<headers>' + xml + '</headers>')
    except ET.ParseError:
        refuse('invalid_rpm_xml')
    result = []
    for header in root:
        if header.tag != 'rpmHeader':
            refuse('invalid_rpm_xml')
        value = {}
        for tag in header:
            name = tag.attrib.get('name')
            if tag.tag != 'rpmTag' or not isinstance(name, str) or name in value:
                refuse('invalid_rpm_xml')
            values = []
            for item in tag:
                if item.tag == 'integer':
                    values.append(int(item.text or ''))
                elif item.tag in {'string', 'base64'}:
                    values.append(item.text or '')
                else:
                    refuse('invalid_rpm_xml')
            value[name] = values
        result.append(value)
    if not 1 <= len(result) <= 4096:
        refuse('invalid_rpm_xml')
    return result


def one(header, name, default=None):
    values = header.get(name, [] if default is None else [default])
    if len(values) != 1:
        refuse('invalid_rpm_scalar')
    return values[0]


def identity(header):
    name, version, release = (one(header, field) for field in ('Name', 'Version', 'Release'))
    epoch = one(header, 'Epoch', 0)
    if name == 'gpg-pubkey':
        # RPM's installed-key pseudo-package has no Arch tag. Preserve its key
        # ID and creation time in the complete inventory instead of dropping it
        # or treating every package with a missing architecture as equivalent.
        if ('Arch' in header or type(epoch) is not int or epoch != 0
                or any(not isinstance(item, str) or not re.fullmatch(r'[a-f0-9]{8}', item)
                       for item in (version, release))):
            refuse('invalid_gpg_key_identity')
        arch = 'none'
    else:
        arch = one(header, 'Arch')
    if any(not isinstance(item, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.~^-]{0,127}', item) for item in (name, version, release, arch)) or type(epoch) is not int or epoch < 0:
        refuse('invalid_package_identity')
    return {'name': name, 'nevra': f'{name}-{epoch}:{version}-{release}.{arch}', 'arch': arch}


def inventory(runner):
    xml = runner(['/usr/bin/rpm', '--query', '--all', '--xml'], timeout=180)
    result = headers(xml)
    return xml, result, sorted(identity(item)['nevra'] for item in result)


def payload(header):
    package = identity(header)
    if package['arch'] not in {'noarch', 'x86_64'} or MIGRATION.match(package['name']):
        refuse('package_requires_migration_recipe')
    if any(any(value not in ('', None) for value in header.get(tag, [])) for tag in SCRIPTS):
        refuse('scriptlet_or_trigger_requires_recipe')
    if one(header, 'Filedigestalgo', 0) != 8:
        refuse('unsupported_payload_digest')
    names, directories, indexes = (header.get(tag, []) for tag in ('Basenames', 'Dirnames', 'Dirindexes'))
    if not 1 <= len(names) <= MAX_FILES or len(indexes) != len(names):
        refuse('invalid_payload_file_list')
    tags = ('Filemodes', 'Filesizes', 'Filedigests', 'Fileusername', 'Filegroupname', 'Fileflags', 'Filelinktos')
    arrays = {tag: header.get(tag, []) for tag in tags}
    if any(len(items) != len(names) for items in arrays.values()):
        refuse('invalid_payload_metadata')
    if any(value for value in header.get('Filecaps', [])):
        refuse('file_capability_requires_recipe')
    files = []
    for index, name in enumerate(names):
        parent = indexes[index]
        if type(parent) is not int or not 0 <= parent < len(directories):
            refuse('invalid_payload_directory')
        path = directories[parent] + name
        mode, flags = arrays['Filemodes'][index], arrays['Fileflags'][index]
        if (not isinstance(path, str) or not path.startswith('/usr/') or str(Path(path)) != path
                or '..' in Path(path).parts or arrays['Fileusername'][index] != 'root' or arrays['Filegroupname'][index] != 'root'
                or mode & 0o7022 or flags & ~(2 | 128) or arrays['Filelinktos'][index]):
            refuse('unsupported_payload_metadata')
        directory = stat.S_ISDIR(mode)
        if not directory and not stat.S_ISREG(mode):
            refuse('link_or_special_file_requires_recipe')
        value = {'path': path, 'kind': 'directory' if directory else 'file', 'uid': 0, 'gid': 0, 'mode': stat.S_IMODE(mode), 'doc': bool(flags & 2)}
        if not directory:
            checksum, size = arrays['Filedigests'][index], arrays['Filesizes'][index]
            if not re.fullmatch(r'[a-f0-9]{64}', checksum) or type(size) is not int or not 0 <= size <= MAX_RPM:
                refuse('invalid_payload_file_digest')
            value.update(bytes=size, sha256=checksum)
        files.append(value)
    if len({item['path'] for item in files}) != len(files):
        refuse('duplicate_payload_path')
    return {**package, 'files': sorted(files, key=lambda item: item['path'])}


def external_triggers(installed, packages, paths):
    selected = set(packages)
    for header in installed:
        if set(header.get('Triggername', [])) & selected:
            refuse('external_package_trigger_requires_recipe')
        for tag in ('Filetriggername', 'Transfiletriggername'):
            for prefix in header.get(tag, []):
                if not isinstance(prefix, str) or not prefix.startswith('/'):
                    refuse('unrecognized_external_trigger')
                if any(path == prefix.rstrip('/') or path.startswith(prefix.rstrip('/') + '/') for path in paths):
                    refuse('external_file_trigger_requires_recipe')


def init_keydb(path, runner):
    """Use RPM's existing SELinux database label on this private directory only.

    Rocky's confined rpm process cannot create its lock/database in var_lib_t.
    The native proof requires rpm_var_lib_t; copy the system database reference
    label without changing the policy, system keyring or any parent directory.
    """
    path = Path(path)
    path.mkdir(mode=0o700, exist_ok=False)
    runner(['/usr/bin/chcon', '--reference=/var/lib/rpm', str(path)])
    runner(['/usr/bin/rpm', '--dbpath', str(path), '--initdb'])
    runner(['/usr/bin/rpmkeys', '--dbpath', str(path), '--import', str(KEY)])
    enrolled = runner(['/usr/bin/rpm', '--dbpath', str(path), '--query', '--all', '--queryformat', '%{NAME} %{VERSION}\n'])
    if enrolled.splitlines() != ['gpg-pubkey ' + KEY_ID]:
        refuse('isolated_keyring_changed')


def signature(path, keydb, runner):
    text = runner(['/usr/bin/rpmkeys', '--dbpath', str(keydb), '--checksig', '--verbose', str(path)], timeout=120)
    lines = [line.strip() for line in text.splitlines()]
    signatures = [line for line in lines if 'Signature' in line]
    if not signatures or any(not re.fullmatch(r'(?:Header )?V[34] RSA/SHA(?:256|512) Signature, key ID ' + KEY_ID + r': OK', line) for line in signatures):
        refuse('rocky_signature_not_verified')
    if any(any(word in line.upper() for word in ('NOKEY', 'NOT OK', 'BAD', 'NOTTRUSTED')) for line in lines):
        refuse('rocky_signature_not_verified')
    return {'key_id': KEY_ID, 'report_sha256': sha(text.encode())}


def describe(path):
    info = Path(path).lstat()
    value = {'kind': 'directory' if stat.S_ISDIR(info.st_mode) else 'file', 'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}
    if value['kind'] == 'file':
        raw = read(path)
        value.update(bytes=len(raw), sha256=sha(raw))
    return value


def platform(runner):
    if runner(['/usr/bin/rpm', '--eval', '%{_dbpath}']) != '/var/lib/rpm':
        refuse('rpmdb_location_requires_recipe')
    if not runner(['/usr/bin/rpm', '--version']).startswith('RPM version 4.16.'):
        refuse('rpm_abi_not_qualified')
    if runner(['/usr/bin/uname', '-m']) != 'x86_64':
        refuse('unsupported_architecture')
    release = runner(['/usr/bin/rpm', '--query', '--queryformat', '%{NAME} %{VERSION} %{ARCH}', 'rocky-release'])
    if not re.fullmatch(r'rocky-release 9(?:\.[0-9]+)? noarch', release):
        refuse('unsupported_distribution')


def plan_cached(stage, packages, *, runner=run):
    """Read package payloads and host state; never installs a package.

    Exposed separately for actual Rocky qualification without inventing healthy
    application/storage evidence. Production calls prepare(), which also binds
    the OS operation and runs the unmodified AIDE preparation guard.
    """
    require_linux_root()
    stage = Path(stage)
    read(stage / 'operation.json', 8192)
    platform(runner)
    if sha(read(KEY, 65536)) != KEY_SHA256:
        refuse('rocky_trust_changed')
    if not 1 <= len(packages) <= 32:
        refuse('unsupported_transaction_size')
    keydb, retained = stage / 'keydb', stage / 'packages'
    retained.mkdir(mode=0o700, exist_ok=True)
    init_keydb(keydb, runner)
    xml, installed, before = inventory(runner)
    immutable(stage / 'rpm-inventory-before.xml', xml.encode())
    proposed, files, directories, skipped = [], [], [], []
    for source in packages:
        raw = read(source)
        target = retained / (sha(raw) + '.rpm')
        immutable(target, raw)
        verified = signature(target, keydb, runner)
        values = headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(target)]))
        if len(values) != 1:
            refuse('ambiguous_package')
        new = payload(values[0])
        prior = [item for item in installed if identity(item)['name'] == new['name']]
        if len(prior) != 1:
            refuse('replacement_requires_one_installed_package')
        old = payload(prior[0])
        if old['nevra'] == new['nevra'] or old['arch'] != new['arch']:
            refuse('replacement_must_change_version')
        if [item['path'] for item in old['files']] != [item['path'] for item in new['files']]:
            refuse('file_set_change_requires_recipe')
        for before_file, after_file in zip(old['files'], new['files']):
            path = Path(before_file['path'])
            if before_file['kind'] != after_file['kind'] or before_file['doc'] != after_file['doc']:
                refuse('file_type_or_doc_policy_changed')
            if before_file['doc'] and not path.exists():
                skipped.append(str(path))
                continue
            expected_before = {key: value for key, value in before_file.items() if key not in {'path', 'doc'}}
            expected_after = {key: value for key, value in after_file.items() if key not in {'path', 'doc'}}
            if describe(path) != expected_before:
                refuse('installed_payload_drift')
            if before_file['kind'] == 'directory':
                if expected_before != expected_after:
                    refuse('directory_metadata_change_requires_recipe')
                directories.append({'path': str(path), **expected_before})
            else:
                owners = runner(['/usr/bin/rpm', '--query', '--file', '--queryformat', '%{NAME}\n', str(path)]).splitlines()
                if owners != [new['name']]:
                    refuse('shared_payload_file')
                files.append({'path': str(path), 'before': expected_before, 'after': expected_after})
        proposed.append({'name': new['name'], 'before': old['nevra'], 'after': new['nevra'], 'rpm': target.name,
                         'sha256': sha(raw), 'bytes': len(raw), 'signature': verified})
    if len({item['name'] for item in proposed}) != len(proposed) or len({item['path'] for item in files}) != len(files):
        refuse('overlapping_package_set')
    external_triggers(installed, [item['name'] for item in proposed], [item['path'] for item in files])
    expected = list(before)
    for item in proposed:
        expected.remove(item['before'])
        expected.append(item['after'])
    directories = list({item['path']: item for item in directories}.values())
    plan = {'schema': 1, 'kind': 'rocky-inert-rpm-v1', 'operation_sha256': sha(read(stage / 'operation.json', 8192)),
            'key_sha256': KEY_SHA256, 'rpm_inventory_sha256': sha(xml.encode()), 'before_inventory': before,
            'after_inventory': sorted(expected), 'packages': proposed, 'files': files,
            'directories': directories, 'skipped_docs': sorted(set(skipped)), 'excludedocs': bool(skipped)}
    # Exact RPM test performs dependency/conflict/version checks, no mutation.
    runner(command(stage, plan, test=True), timeout=180)
    raw = (json.dumps(plan, sort_keys=True, indent=2) + '\n').encode()
    immutable(stage / 'os-payload-plan.json', raw)
    return {'ok': True, 'plan_sha256': sha(raw), 'packages': len(proposed)}


def command(stage, plan, *, test=False):
    argv = ['/usr/bin/rpm', '--upgrade']
    if test:
        argv.append('--test')
    if plan['excludedocs']:
        argv.append('--excludedocs')
    # No --nodeps, --nosignature, --noscripts, --oldpackage or --replacefiles.
    return argv + [str(stage / 'packages' / item['rpm']) for item in plan['packages']]


def load_plan(stage):
    raw = read(stage / 'os-payload-plan.json', MAX_XML)
    plan = strict_json(raw)
    exact(plan, {'schema', 'kind', 'operation_sha256', 'key_sha256', 'rpm_inventory_sha256', 'before_inventory', 'after_inventory', 'packages', 'files', 'directories', 'skipped_docs', 'excludedocs'})
    if plan['schema'] != 1 or plan['kind'] != 'rocky-inert-rpm-v1' or plan['operation_sha256'] != sha(read(stage / 'operation.json', 8192)) or plan['key_sha256'] != KEY_SHA256:
        refuse('plan_binding_changed')
    return plan, sha(raw)


def validate_files(plan, phase):
    for item in plan['files']:
        if describe(Path(item['path'])) != item[phase]:
            refuse('live_file_not_planned')
    for item in plan['directories']:
        if describe(Path(item['path'])) != {key: value for key, value in item.items() if key != 'path'}:
            refuse('directory_metadata_changed')
    if any(os.path.lexists(path) for path in plan['skipped_docs']):
        refuse('excluded_document_created')


def execute_cached(stage, *, runner=run):
    """Execute an already planned exact transaction once; no health bypass.

    This low-level operation records only RPM results. It cannot complete appliance
    maintenance or adopt an AIDE baseline; apply() supplies that context.
    """
    require_linux_root()
    stage = Path(stage)
    plan, plan_sha = load_plan(stage)
    platform(runner)
    if (stage / 'rpm-apply-intent.json').exists():
        refuse('transaction_already_attempted_use_postcheck')
    if sha(read(KEY, 65536)) != plan['key_sha256']:
        refuse('rocky_trust_changed')
    xml, installed, before = inventory(runner)
    if sha(xml.encode()) != plan['rpm_inventory_sha256'] or before != plan['before_inventory']:
        refuse('installed_package_state_changed')
    validate_files(plan, 'before')
    for item in plan['packages']:
        path = stage / 'packages' / item['rpm']
        raw = read(path)
        if sha(raw) != item['sha256'] or len(raw) != item['bytes']:
            refuse('retained_package_changed')
        if signature(path, stage / 'keydb', runner) != item['signature']:
            refuse('retained_signature_changed')
    runner(command(stage, plan, test=True), timeout=180)
    immutable(stage / 'rpm-apply-intent.json', (json.dumps({'schema': 1, 'plan_sha256': plan_sha, 'state': 'applying'}, sort_keys=True) + '\n').encode())
    runner(command(stage, plan), timeout=3600)
    return postcheck_cached(stage, runner=runner)


def postcheck_cached(stage, *, runner=run):
    plan, plan_sha = load_plan(stage)
    intent = strict_json(read(stage / 'rpm-apply-intent.json', 8192))
    if intent != {'schema': 1, 'plan_sha256': plan_sha, 'state': 'applying'}:
        refuse('apply_intent_changed')
    xml, _, current = inventory(runner)
    if current != plan['after_inventory']:
        refuse('installed_package_result_changed')
    validate_files(plan, 'after')
    immutable(stage / 'rpm-inventory-after.xml', xml.encode())
    result = {'schema': 1, 'ok': True, 'scope': 'exact_rpm_payload_only', 'plan_sha256': plan_sha,
              'rpm_inventory_sha256': sha(xml.encode()), 'packages': plan['packages']}
    atomic_json(stage / 'rpm-result.json', result)
    return result


def prepare(stage, policy, *, runner=run):
    # No general OS update is claimed while kernel/generated-file transitions
    # remain unqualified. Downloaded candidates are inert until fully planned.
    stage = Path(stage)
    requested = policy.get('os_packages', [])
    if not isinstance(requested, list) or len(requested) > 32 or any(not isinstance(name, str) or not NAME.fullmatch(name) for name in requested):
        refuse('invalid_package_selection')
    journal = strict_json(read(stage.parent.parent / 'os-transaction.json', 65536))
    if journal.get('state') != 'planning' or journal.get('stage') != str(stage):
        refuse('operation_binding_required')
    operation = {'schema': 1, 'id': str(uuid.uuid4()), 'stage': str(stage), 'boot_id': journal.get('boot_id')}
    immutable(stage / 'operation.json', (json.dumps(operation, sort_keys=True) + '\n').encode())
    from . import kernel_updates, kernel_integrity
    pending = kernel_updates.adopt_pending(stage)
    if pending is not None:
        return pending
    download = stage / 'download'
    download.mkdir(mode=0o700)
    _, _, before = inventory(runner)
    runner(['/usr/bin/dnf', '--releasever=9', '--refresh', '--assumeyes', '--downloadonly', '--downloaddir=' + str(download), 'upgrade', *requested], timeout=3600)
    packages = sorted(download.glob('*.rpm'))
    if not packages:
        if inventory(runner)[2] != before:
            refuse('package_inventory_changed_during_download')
        observation = {'schema': 1, 'kind': 'rocky-no-updates-v1',
                       'operation_sha256': sha(read(stage / 'operation.json', 8192)),
                       'inventory_sha256': digest(before)}
        immutable(stage / 'os-no-updates.json', (json.dumps(observation, sort_keys=True) + '\n').encode())
        return {'ok': True, 'status': 'no_updates', 'plan_sha256': None}
    names = [one(header, 'Name') for path in packages
             for header in headers(runner(['/usr/bin/rpm', '--query', '--package', '--xml', str(path)]))]
    if len(names) == 4 and set(names) == kernel_updates.NAMES:
        result = kernel_updates.plan_cached(stage, packages, runner=runner)
        kernel_integrity.prepare(stage)
        return result
    result = plan_cached(stage, packages, runner=runner)
    plan, plan_sha = load_plan(stage)
    integrity = integrity_plan(plan, plan_sha)
    path = stage / 'os-integrity-plan.json'
    immutable(path, (json.dumps(integrity, sort_keys=True, indent=2) + '\n').encode())
    from . import aide
    accepted = aide.Aide().authorized_update_prepare(stage, path)
    if accepted.get('ok') is not True:
        refuse('integrity_preparation_failed')
    return result


def integrity_plan(plan, plan_sha):
    return {'schema': 1, 'kind': 'os-payload-v1', 'sequence': 0, 'manifest_sha256': plan_sha,
            'files': plan['files'], 'directories': plan['directories'], 'skipped_docs': plan['skipped_docs']}


def bound_integrity_plan(manager, stage, path, *, preparing):
    from . import aide
    identity = manager.guard()
    parent = identity.root / 'manager/os-updates'
    if stage.is_symlink() or stage.parent != parent or path != stage / 'os-integrity-plan.json':
        refuse('unowned_integrity_stage')
    raw = manager.reader(path, maximum=MAX_XML, private=True)
    parsed = strict_json(raw)
    if parsed.get('kind') == 'kernel-install-v1':
        from . import kernel_integrity
        return kernel_integrity.bound_integrity_plan(manager, stage, path, preparing=preparing)
    plan, plan_sha = load_plan(stage)
    if parsed != integrity_plan(plan, plan_sha):
        refuse('integrity_plan_changed')
    operation = strict_json(read(stage / 'operation.json', 8192))
    exact(operation, {'schema', 'id', 'stage', 'boot_id'})
    try:
        uuid.UUID(operation['id'])
        uuid.UUID(operation['boot_id'])
    except (ValueError, TypeError, AttributeError):
        refuse('invalid_operation_identity')
    journal = strict_json(read(identity.root / 'manager/os-transaction.json', 65536))
    latest = strict_json(read(identity.root / 'manager/os-latest.json', 65536))
    phases = {'planning', 'updating'} if preparing else {'updating', 'postcheck', 'recovery_required', 'complete'}
    if (journal.get('state') not in phases or operation['schema'] != 1 or operation['stage'] != str(stage)
            or journal.get('stage') != str(stage) or latest.get('stage') != str(stage)
            or operation['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or operation['boot_id'] != journal.get('boot_id') or operation['boot_id'] != latest.get('boot_id')
            or (not preparing or journal.get('state') == 'updating') and journal.get('plan_sha256') != plan_sha
            or preparing and (stage / 'rpm-apply-intent.json').exists()):
        refuse('integrity_operation_binding_changed')
    return parsed, sha(raw)


def integrity_snapshot(manager, plan, phase, retained=None):
    from . import aide_updates
    if phase not in {'prepare', 'forward'}:
        refuse('rpm_rollback_requires_separate_recipe')
    values = {}
    for item in plan['files']:
        description, metadata = aide_updates._measure(manager, {'path': item['path']})
        if description != item['before' if phase == 'prepare' else 'after']:
            refuse('live_file_not_planned')
        if retained is not None and retained.get(item['path']) != metadata:
            refuse('acl_xattrs_or_selinux_changed')
        values[item['path']] = metadata
    for item in plan['directories']:
        description, metadata = aide_updates._measure(manager, item)
        if description != {key: value for key, value in item.items() if key != 'path'}:
            refuse('directory_metadata_changed')
        if retained is not None and retained.get(item['path']) != metadata:
            refuse('directory_acl_xattrs_or_selinux_changed')
        values[item['path']] = metadata
    if any(os.path.lexists(path) for path in plan['skipped_docs']):
        refuse('excluded_document_created')
    return values


def allowed_integrity_report(report, plan, phase):
    if phase not in {'prepare', 'forward'}:
        refuse('rpm_rollback_requires_separate_recipe')
    changed = set() if phase == 'prepare' else {item['path'] for item in plan['files']}
    if report.get('added') or report.get('removed') or set(report.get('changed', {})) - changed:
        refuse('unrelated_integrity_change')


def _verify_no_updates(stage, identity, runner):
    """Bind an empty download to this same-boot operation, never an RPM bypass."""
    parent = identity.root / 'manager/os-updates'
    if stage.is_symlink() or stage.resolve().parent != parent.resolve():
        refuse('no_updates_stage_changed')
    raw = read(stage / 'operation.json', 8192)
    operation = strict_json(raw)
    exact(operation, {'schema', 'id', 'stage', 'boot_id'})
    try:
        uuid.UUID(operation['id'])
        uuid.UUID(operation['boot_id'])
    except (ValueError, TypeError, AttributeError):
        refuse('invalid_operation_identity')
    observation = strict_json(read(stage / 'os-no-updates.json', 8192))
    exact(observation, {'schema', 'kind', 'operation_sha256', 'inventory_sha256'})
    journal = strict_json(read(parent.parent / 'os-transaction.json', 65536))
    latest = strict_json(read(parent.parent / 'os-latest.json', 65536))
    if (operation['schema'] != 1 or operation['stage'] != str(stage)
            or observation['schema'] != 1 or observation['kind'] != 'rocky-no-updates-v1'
            or observation['operation_sha256'] != sha(raw)
            or journal.get('state') not in {'postcheck', 'recovery_required', 'complete'}
            or journal.get('no_updates') is not True or journal.get('plan_sha256') is not None
            or journal.get('stage') != str(stage) or latest.get('stage') != str(stage)
            or operation['boot_id'] != journal.get('boot_id') or operation['boot_id'] != latest.get('boot_id')
            or operation['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
        refuse('no_updates_operation_binding_changed')
    if any(os.path.lexists(stage / name) for name in ('os-payload-plan.json', 'os-integrity-plan.json', 'rpm-apply-intent.json',
                                                    'kernel-plan.json', 'kernel-deferred.json', 'kernel-apply-intent.json')):
        refuse('no_updates_conflicts_with_package_transaction')
    if digest(inventory(runner)[2]) != observation['inventory_sha256']:
        refuse('no_updates_package_inventory_changed')
    return observation


def accept_integrity(stage, *, runner=run):
    # Recovery verifies the installed exact package/file result and never reruns
    # RPM or treats dnf history undo as a scriptlet/data rollback guarantee.
    stage = Path(stage)
    from . import aide, aide_updates
    from . import kernel_integrity
    if os.path.lexists(stage / 'kernel-deferred.json'):
        return kernel_integrity.accept_deferred(stage, runner=runner)
    if os.path.lexists(stage / 'kernel-plan.json'):
        return kernel_integrity.accept(stage, runner=runner)
    if os.path.lexists(stage / 'os-no-updates.json'):
        # The lifecycle caller owns manager/update locks. The existing update
        # coordination takes the remaining locks for a fresh ordinary AIDE check.
        # No --update, acceptance or baseline replacement is permitted here.
        manager = aide.Aide()
        with aide_updates._locked(manager) as (state, identity):
            observation = _verify_no_updates(stage, identity, runner)
            integrity = manager._check_locked(state, identity)
            if integrity.get('state') != 'clean' or integrity.get('exit_code') != 0:
                refuse('no_updates_integrity_not_clean')
            _verify_no_updates(stage, identity, runner)
        return {'ok': True, 'package': {'status': 'no_updates', **observation}, 'integrity': integrity}
    package = postcheck_cached(stage, runner=runner)
    integrity = aide.Aide().authorized_update_accept(stage, stage / 'os-integrity-plan.json')
    if integrity.get('ok') is not True:
        refuse('integrity_acceptance_failed')
    return {'ok': True, 'package': package, 'integrity': integrity}


def apply(stage, *, runner=run):
    stage = Path(stage)
    from . import kernel_integrity
    if os.path.lexists(stage / 'kernel-deferred.json'):
        return kernel_integrity.accept_deferred(stage, runner=runner)
    if os.path.lexists(stage / 'kernel-plan.json'):
        return kernel_integrity.apply(stage, runner=runner)
    # Revalidate both the operation and the prepared AIDE context immediately
    # before the exact signed RPM transaction. The manager lock excludes scans.
    from . import aide
    manager = aide.Aide()
    bound_integrity_plan(manager, stage, stage / 'os-integrity-plan.json', preparing=False)
    prepared = manager.authorized_update_prepare(stage, stage / 'os-integrity-plan.json')
    if prepared.get('ok') is not True:
        refuse('integrity_preparation_failed')
    execute_cached(stage, runner=runner)
    return accept_integrity(stage, runner=runner)
