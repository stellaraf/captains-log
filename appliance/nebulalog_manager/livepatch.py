"""Authenticate, retain and apply kernel livepatch candidates under host checks.

The publisher signature binds the exact kernel, signed module, signer certificate
and qualification report. Kernel trust enrollment remains a separate prerequisite.
"""
from datetime import datetime, timezone, timedelta
import hashlib
import os
from pathlib import Path
import re
import struct
import tempfile

from .common import Refused, atomic_json, locked, require_linux_root, run
from .update_enrollment import _read, _tree, enrolled_key
from .host_payload import strict_json
from . import security

MARKER = b'~Module signature appended~\n'
MAX_MODULE = 64 * 1024**2
SHA = re.compile(r'[a-f0-9]{64}')
KERNEL = re.compile(r'5\.14\.0-[0-9][A-Za-z0-9._-]*\.el9(?:_[0-9]+)?\.x86_64')
CHECKS = {'kernel_signature_enforced', 'live_transition_complete', 'services_healthy',
          'same_kernel_reboot_reapplies', 'fips_postcheck'}
FILES = {'module': 'module.ko', 'certificate': 'module-signer.der', 'qualification': 'qualification.json'}
LIMITS = {'module': MAX_MODULE, 'certificate': 16384, 'qualification': 1024**2}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def instant(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        raise Refused('Livepatch timestamps require an explicit UTC offset') from None


def module_parts(raw):
    """Parse Linux's bounded PKCS#7 trailer, not a new signature algorithm."""
    if not isinstance(raw, bytes) or not 64 + 12 + len(MARKER) < len(raw) <= MAX_MODULE or not raw.endswith(MARKER):
        raise Refused('An uncompressed signed kernel module is required')
    end = len(raw) - len(MARKER)
    trailer = raw[end-12:end]
    if trailer[:8] != b'\0\0\x02\0\0\0\0\0':
        raise Refused('Only the Linux PKCS#7 module signature format is supported')
    size = struct.unpack('!I', trailer[8:])[0]
    if not 1 <= size <= 1024**2 or end - 12 - size < 64:
        raise Refused('Invalid module signature length')
    unsigned, signature = raw[:end-12-size], raw[end-12-size:end-12]
    if (unsigned[:7] != b'\x7fELF\x02\x01\x01'
            or struct.unpack_from('<HH', unsigned, 16) != (1, 62)):
        raise Refused('Expected a relocatable x86_64 ELF module')
    return unsigned, signature


def validate_manifest(raw, *, current_sequence, kernel_release, now):
    value = strict_json(raw)
    fields = {'schema', 'product', 'channel', 'sequence', 'issued_at', 'expires_at',
              'kernel_release', 'kernel_image_sha256', 'kernel_config_sha256', 'module_name',
              'module', 'certificate', 'qualification', 'security_fixes'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema']) is not int or value['schema'] != 1
            or value['product'] != 'captains-log' or value['channel'] != 'kernel-livepatch-stable'):
        raise Refused('Unsupported livepatch manifest')
    if (type(current_sequence) is not int or current_sequence < 0 or type(value['sequence']) is not int
            or not current_sequence < value['sequence'] < 2**63):
        raise Refused('Livepatch replay or downgrade refused')
    issued, expires = instant(value['issued_at']), instant(value['expires_at'])
    if issued > now or not issued < expires <= issued + timedelta(days=90) or now >= expires:
        raise Refused('Livepatch publication is future-dated, expired or exceeds its validity limit')
    if not isinstance(value['kernel_release'], str) or not KERNEL.fullmatch(value['kernel_release']) or value['kernel_release'] != kernel_release:
        raise Refused('Livepatch targets a different or unsupported kernel')
    if not isinstance(value['module_name'], str) or not re.fullmatch(r'livepatch_[a-z0-9_]{1,40}', value['module_name']):
        raise Refused('Invalid livepatch module identity')
    for key in ('kernel_image_sha256', 'kernel_config_sha256'):
        if not isinstance(value[key], str) or not SHA.fullmatch(value[key]):
            raise Refused('Exact kernel image and configuration hashes are required')
    for key, name in FILES.items():
        item = value[key]
        if (not isinstance(item, dict) or set(item) != {'name', 'bytes', 'sha256'} or item['name'] != name
                or type(item['bytes']) is not int or not 0 < item['bytes'] <= LIMITS[key]
                or not isinstance(item['sha256'], str) or not SHA.fullmatch(item['sha256'])):
            raise Refused('Livepatch artifact descriptor is unsafe or incomplete')
    fixes = value['security_fixes']
    if not isinstance(fixes, list) or not 1 <= len(fixes) <= 100 or any(not isinstance(x, str) or not 1 <= len(x) <= 300 for x in fixes):
        raise Refused('Livepatch security coverage must be explicit')
    return value


def qualification(raw, manifest):
    value = strict_json(raw)
    if (not isinstance(value, dict) or set(value) != {'schema', 'kernel_release', 'module_sha256', 'checks', 'evidence_sha256'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['kernel_release'] != manifest['kernel_release'] or value['module_sha256'] != manifest['module']['sha256']
            or not isinstance(value['checks'], dict) or set(value['checks']) != CHECKS
            or any(value['checks'][key] is not True for key in CHECKS)
            or not isinstance(value['evidence_sha256'], str) or not SHA.fullmatch(value['evidence_sha256'])):
        raise Refused('Publisher qualification must bind this module/kernel and every required acceptance check')
    return value


def verify_bundle(bundle, state, public_key, *, current_sequence, kernel_release,
                  kernel_image_sha256, kernel_config_sha256, runner=run, now=None):
    """Verify captured bytes against already enrolled publisher trust.

    Kernel identities and monotonic sequence come from the trusted caller's
    measured host/journal, never from the download or unsigned feed metadata.
    This API does not advance that sequence or claim a native transition.
    """
    require_linux_root()
    now = now or datetime.now(timezone.utc)
    bundle, state, public_key = map(Path, (bundle, state, public_key))
    trust = enrolled_key(state, public_key)
    raw = _read(bundle / 'livepatch.json', 128 * 1024)
    signature = _read(bundle / 'livepatch.sig', 16384)
    key = _read(public_key, 16384)
    if digest(key) != trust['pem_sha256']:
        raise Refused('Publisher key changed during livepatch verification')
    temporary = state / 'livepatch-verification'
    temporary.mkdir(mode=0o700, exist_ok=True)
    _tree(temporary)
    with tempfile.TemporaryDirectory(prefix='candidate-', dir=temporary) as directory:
        captured = Path(directory)
        def write(name, data):
            path = captured / name
            path.write_bytes(data)
            path.chmod(0o600)
            return str(path)
        manifest_path = write('livepatch.json', raw)
        signature_path = write('livepatch.sig', signature)
        key_path = write('publisher.pem', key)
        runner(['openssl', 'dgst', '-sha256', '-verify', key_path, '-signature', signature_path,
                '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32', manifest_path])
        manifest = validate_manifest(raw, current_sequence=current_sequence, kernel_release=kernel_release, now=now)
        if (manifest['kernel_image_sha256'] != kernel_image_sha256
                or manifest['kernel_config_sha256'] != kernel_config_sha256):
            raise Refused('Livepatch kernel image or configuration differs from the measured target')
        inputs = {}
        for role, filename in FILES.items():
            content = _read(bundle / filename, LIMITS[role])
            item = manifest[role]
            if len(content) != item['bytes'] or digest(content) != item['sha256']:
                raise Refused('Livepatch artifact differs from its signed descriptor')
            inputs[role] = content
            write(filename, content)
        report = qualification(inputs['qualification'], manifest)
        unsigned, cms = module_parts(inputs['module'])
        unsigned_path = write('unsigned.ko', unsigned)
        cms_path = write('module.p7s', cms)
        cert = captured / 'module-signer.pem'
        runner(['openssl', 'x509', '-inform', 'DER', '-in', str(captured / 'module-signer.der'), '-out', str(cert)])
        # No chain enrollment: the publisher pins this exact certificate, and
        # the kernel must independently trust it before any future module load.
        runner(['openssl', 'cms', '-verify', '-binary', '-inform', 'DER', '-in', cms_path,
                '-content', unsigned_path, '-certfile', str(cert), '-nointern', '-noverify', '-out', '/dev/null'])
        module_path = str(captured / 'module.ko')
        observed = {name: runner(['modinfo', '-F', name, module_path])
                    for name in ('name', 'livepatch', 'vermagic', 'sig_hashalgo')}
        if (observed['name'] != manifest['module_name'] or observed['livepatch'] != 'Y'
                or observed['vermagic'].split()[:1] != [kernel_release]
                or observed['sig_hashalgo'] not in ('sha256', 'sha384', 'sha512')):
            raise Refused('Signed module identity, kernel target or signature algorithm differs')
        if enrolled_key(state, public_key) != trust:
            raise Refused('Publisher enrollment changed during livepatch verification')
    return {'schema': 1, 'state': 'authenticated_candidate', 'manifest': manifest,
            'manifest_sha256': digest(raw), 'publisher_spki_sha256': trust['spki_sha256'],
            'module_signature_verified': True, 'qualification_evidence_sha256': report['evidence_sha256'],
            'qualification_scope': 'publisher-signed qualification assertion; evidence retained by publisher',
            'kernel_trust_verified': False, 'applied': False, 'native_transition_verified': False}



def stage_bundle(bundle, state, public_key, **verification):
    """Retain and authenticate the exact candidate bytes for a later transaction.

    Does not commit sequence state or load a module. Failed captures remain
    explicitly unverified; a caller must never load by directory existence.
    Verification is against the retained copy, not paths in the incoming bundle.
    """
    require_linux_root()
    bundle, state = Path(bundle), Path(state)
    _tree(state)
    parent = state / 'livepatch-candidates'
    parent.mkdir(mode=0o700, exist_ok=True)
    _tree(parent)
    captured = Path(tempfile.mkdtemp(prefix='candidate-', dir=parent))
    atomic_json(captured / 'capture.json', {'schema': 1, 'state': 'capturing', 'authenticated': False})
    try:
        files = {'livepatch.json': 128 * 1024, 'livepatch.sig': 16384,
                 **{FILES[role]: limit for role, limit in LIMITS.items()}}
        for name, limit in files.items():
            raw = _read(bundle / name, limit)
            descriptor = os.open(captured / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        result = verify_bundle(captured, state, public_key, **verification)
        # A directory receipt alone never authorizes loading: the transaction
        # must reverify its bytes, trust, kernel identity, expiry and sequence.
        atomic_json(captured / 'verification.json', result)
        atomic_json(captured / 'capture.json', {'schema': 1, 'state': 'captured_and_authenticated',
                                               'authenticated': True, 'manifest_sha256': result['manifest_sha256']})
        return {**result, 'captured_bundle': str(captured)}
    except Exception as error:
        atomic_json(captured / 'capture.json', {'schema': 1, 'state': 'capture_failed',
                                               'authenticated': False, 'error_type': type(error).__name__})
        raise

def wait_for_transition(module_name, kernel_release, *, timeout=120, root=Path('/'),
                        monotonic=None, sleep=None):
    """Observe a loaded patch; never load, force, reverse, signal or unload it.

    The caller must authenticate and load captured bytes under its transaction
    lock first. A matching sysfs name alone does not authenticate module bytes.
    Two consistent completed observations avoid accepting a single mixed read.
    """
    import os
    import stat
    import time
    require_linux_root()
    if not isinstance(module_name, str) or not re.fullmatch(r'livepatch_[a-z0-9_]{1,40}', module_name):
        raise Refused('Invalid livepatch module identity')
    if not isinstance(kernel_release, str) or not KERNEL.fullmatch(kernel_release):
        raise Refused('Unsupported livepatch kernel target')
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise Refused('Livepatch transition timeout must be 1 to 600 seconds')
    root = Path(root)
    if not root.is_absolute():
        raise Refused('Livepatch observation root must be absolute')
    monotonic, sleep = monotonic or time.monotonic, sleep or time.sleep

    def read(relative, allowed=None):
        path = root / relative
        try:
            # proc/sys expose virtual regular files whose stat size may be zero.
            for parent in (path.parent, *path.parent.parents):
                if parent == root.parent:
                    break
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode):
                    raise Refused('Livepatch observation contains an unsafe directory')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise Refused('Livepatch observation is not a kernel attribute')
                raw = stream.read(257)
            if not raw or len(raw) > 256:
                raise Refused('Invalid livepatch kernel attribute length')
            value = raw.decode('ascii').strip()
            if allowed is not None and value not in allowed:
                raise Refused('Unexpected livepatch kernel attribute value')
            return value
        except (OSError, UnicodeError) as exc:
            raise Refused('Required livepatch kernel observation is unavailable') from exc

    boot = read('proc/sys/kernel/random/boot_id')
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot):
        raise Refused('Invalid kernel boot identity')
    start, stable = monotonic(), 0
    while True:
        if read('proc/sys/kernel/osrelease') != kernel_release or read('proc/sys/kernel/random/boot_id') != boot:
            raise Refused('Kernel or boot identity changed during livepatch transition')
        if read('sys/module/module/parameters/sig_enforce', {'Y', 'N'}) != 'Y':
            raise Refused('Kernel module signature enforcement is required')
        if read(f'sys/module/{module_name}/initstate', {'live', 'coming', 'going'}) != 'live':
            raise Refused('Livepatch module is not live')
        enabled = read(f'sys/kernel/livepatch/{module_name}/enabled', {'0', '1'})
        transition = read(f'sys/kernel/livepatch/{module_name}/transition', {'0', '1'})
        if enabled != '1':
            raise Refused('Livepatch was disabled or its transition reversed')
        stable = stable + 1 if transition == '0' else 0
        elapsed = monotonic() - start
        if stable >= 2 and elapsed <= timeout:
            return {'schema': 1, 'state': 'transition_complete', 'module_name': module_name,
                    'kernel_release': kernel_release, 'boot_id': boot,
                    'module_signatures_enforced': True, 'enabled': True, 'transition': False,
                    'observation_scope': 'kernel sysfs only; caller must bind authenticated loaded bytes and post-load health',
                    'services_verified': False, 'fips_postcheck_verified': False}
        if elapsed >= timeout:
            raise Refused('Livepatch transition timed out; no force, rollback or unload attempted')
        sleep(min(0.25, timeout - elapsed))


def measure_target(runner=run):
    """Measure vendor-owned boot files for the running release under the host lock."""
    require_linux_root()
    release = runner(['uname', '-r'])
    if not KERNEL.fullmatch(release):
        raise Refused('Unsupported running kernel for livepatch')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot):
        raise Refused('Invalid kernel boot identity')
    image, config = Path('/boot/vmlinuz-' + release), Path('/boot/config-' + release)
    if runner(['rpm', '-Vf', str(image), str(config)]):
        raise Refused('Installed kernel package verification reported differences')
    return {'kernel_release': release, 'boot_id': boot,
            'kernel_image_sha256': digest(_read(image, 128 * 1024**2)),
            'kernel_config_sha256': digest(_read(config, 1024**2))}


def _integrity_clean(manager_lock_fd):
    from .aide import Aide
    return Aide().check_for_transaction(manager_lock_fd).get('state') == 'clean'


def _runtime_health(stage):
    from nebulalog_adapters.lifecycle import Lifecycle, load_config
    from .updates import REQUIRED_CHECKS
    result = Lifecycle(load_config()).livepatch_health(stage)
    return (result.get('ok') is True
            and all(result.get('checks', {}).get(name) is True for name in REQUIRED_CHECKS))


def load_signer(captured, descriptor, runner=run):
    """Load an authenticated leaf under the kernel's existing trust restriction.

    This cannot enroll a new CA or change firmware trust. The secondary keyring
    accepts the certificate only when its signing chain is already trusted.
    """
    certificate = _read(Path(captured) / 'module-signer.der', LIMITS['certificate'])
    if len(certificate) != descriptor['bytes'] or digest(certificate) != descriptor['sha256']:
        raise Refused('Livepatch signer changed before kernel trust loading')
    serial = runner(['keyctl', 'padd', 'asymmetric', '', '%:.secondary_trusted_keys'],
                    input=certificate)
    if not re.fullmatch(r'[1-9][0-9]{0,9}', serial) or int(serial) >= 2**31:
        raise Refused('Kernel signer loading returned an invalid key identity')
    return {'certificate_sha256': digest(certificate), 'key_serial': int(serial)}


def apply_bundle(bundle, state, public_key, *, health_check=None, runner=run, now=None, reapply=False):
    """Apply one authenticated candidate with a durable interruption boundary.

    Internal API: health_check must perform the appliance's service
    checks and return exactly True on success. Feed, enrollment and reboot
    reconciliation must use this transaction rather than invoking insmod alone.
    No automatic rollback or forced transition is attempted on failure.
    """
    require_linux_root()
    state = Path(state)
    _tree(state)
    if type(reapply) is not bool or (reapply and bundle is not None):
        raise Refused('Reapplication uses only the previously committed candidate')
    if health_check is not None and not callable(health_check):
        raise Refused('Appliance health integration is required for livepatch')
    journal = state / 'livepatch-transaction.json'
    with locked(state.parent / 'transaction.lock') as manager_lock_fd, locked(state / 'livepatch.lock'):
        # A released flock does not mean interrupted maintenance has finished.
        for path, terminal in ((state / 'transaction.json', {'committed', 'rolled_back', 'preflight_failed'}),
                               (state.parent / 'os-transaction.json', {'complete', 'failed', 'reboot_aborted'})):
            if path.exists() or path.is_symlink():
                record = strict_json(_read(path, 128 * 1024))
                if (not isinstance(record, dict) or record.get('state') not in terminal
                        or record.get('finalization', 'complete') != 'complete'):
                    raise Refused('Existing appliance maintenance requires recovery before livepatch')
        if (state.parent / 'maintenance.json').exists():
            raise Refused('Existing appliance maintenance has not been released')
        sequence, previous = 0, None
        if journal.exists() or journal.is_symlink():
            previous = strict_json(_read(journal, 128 * 1024))
            if (not isinstance(previous, dict) or type(previous.get('schema')) is not int or previous['schema'] != 1
                    or previous.get('post_load_health_verified') is not True
                    or previous.get('state') != 'applied' or type(previous.get('sequence')) is not int
                    or not 0 < previous['sequence'] < 2**63):
                raise Refused('Prior livepatch transaction requires explicit recovery')
            sequence = previous['sequence']
        if security.status(runner)['host_controls_ok'] is not True:
            raise Refused('Livepatch requires healthy host security, services and integrity')
        target = measure_target(runner)
        if health_check is None:
            parent = state / 'livepatch-health'
            parent.mkdir(mode=0o700, exist_ok=True)
            _tree(parent)
            health_stage = parent / target['boot_id']
            health_stage.mkdir(mode=0o700, exist_ok=True)
            _tree(health_stage)
            health_check = lambda: _runtime_health(health_stage)
        if health_check() is not True or not _integrity_clean(manager_lock_fd):
            raise Refused('Livepatch requires healthy host security, services and integrity')
        arguments = {key: value for key, value in target.items() if key != 'boot_id'}
        arguments.update(current_sequence=sequence, runner=runner, now=now)
        if reapply:
            if previous is None or not isinstance(previous.get('target'), dict):
                raise Refused('No completed livepatch is available for reboot reapplication')
            original = previous['target']
            if not isinstance(original.get('boot_id'), str) or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', original['boot_id']):
                raise Refused('Prior livepatch boot identity is incomplete')
            if original.get('boot_id') == target['boot_id']:
                raise Refused('Same-boot livepatch replay is refused')
            if any(original.get(key) != target[key] for key in arguments if key.startswith('kernel_')):
                raise Refused('Replacement kernel requires its own qualified livepatch')
            stored = previous.get('captured_bundle')
            if not isinstance(stored, str):
                raise Refused('Retained livepatch candidate is unavailable')
            captured = Path(stored)
            if captured.parent != state / 'livepatch-candidates' or not captured.name.startswith('candidate-'):
                raise Refused('Reapplication candidate is outside protected retained storage')
            # Equality is authorized only for these exact previously committed
            # bytes on a new boot of the identical measured kernel. The general
            # verifier keeps strict increasing-sequence semantics.
            arguments['current_sequence'] = sequence - 1
            verified = verify_bundle(captured, state, public_key, **arguments)
            if (verified['manifest']['sequence'] != sequence
                    or any(verified[key] != previous.get(key) for key in ('manifest_sha256', 'publisher_spki_sha256'))):
                raise Refused('Reapplication differs from the committed livepatch identity')
        else:
            verified = stage_bundle(bundle, state, public_key, **arguments)
            captured = Path(verified['captured_bundle'])
        manifest = verified['manifest']
        # Refuse adoption of a module loaded outside this transaction.
        if Path('/sys/module', manifest['module_name']).exists():
            raise Refused('Livepatch module is already loaded; reconcile its transaction first')
        if measure_target(runner) != target:
            raise Refused('Kernel target changed before livepatch application')
        verified_again = verify_bundle(captured, state, public_key, **arguments)
        if any(verified_again[key] != verified[key] for key in ('manifest_sha256', 'publisher_spki_sha256')):
            raise Refused('Captured candidate or publisher trust changed before application')
        transaction = {'schema': 1, 'state': 'prepared', 'sequence': manifest['sequence'],
                       'operation': 'reapply_after_reboot' if reapply else 'apply_new_candidate',
                       'manifest_sha256': verified['manifest_sha256'],
                       'publisher_spki_sha256': verified['publisher_spki_sha256'],
                       'captured_bundle': str(captured), 'target': target,
                       'module_name': manifest['module_name'], 'module_sha256': manifest['module']['sha256']}
        atomic_json(journal, transaction)
        try:
            transaction['state'] = 'loading'
            atomic_json(journal, transaction)
            transaction['signer'] = load_signer(captured, manifest['certificate'], runner)
            atomic_json(journal, transaction)
            runner(['insmod', str(captured / 'module.ko')])
            observation = wait_for_transition(manifest['module_name'], target['kernel_release'])
            if observation['boot_id'] != target['boot_id'] or measure_target(runner) != target:
                raise Refused('Kernel target changed during livepatch application')
            if (security.status(runner)['host_controls_ok'] is not True or health_check() is not True
                    or not _integrity_clean(manager_lock_fd)):
                raise Refused('Livepatch post-load host or application health check failed')
            if enrolled_key(state, public_key)['spki_sha256'] != verified['publisher_spki_sha256']:
                raise Refused('Publisher trust changed during livepatch application')
            transaction.update(state='applied', transition=observation, post_load_health_verified=True)
            atomic_json(journal, transaction)
            return transaction
        except Exception as error:
            transaction.update(state='recovery_required', error_type=type(error).__name__,
                               automatic_unload_attempted=False, force_attempted=False)
            atomic_json(journal, transaction)
            raise


def status(state, public_key, *, runner=run, now=None):
    """Reconcile retained identity with this boot; never load or claim fresh health."""
    require_linux_root()
    state = Path(state)
    _tree(state)
    with locked(state.parent / 'transaction.lock'), locked(state / 'livepatch.lock'):
        result = {'schema': 1, 'active_observed': False, 'services_verified': False,
                  'fips_postcheck_verified': False}
        journal = state / 'livepatch-transaction.json'
        if not journal.exists() and not journal.is_symlink():
            return dict(result, state='no_committed_patch')
        require_settled(state)
        previous = strict_json(_read(journal, 128 * 1024))
        target = measure_target(runner)
        original = previous.get('target')
        if not isinstance(original, dict) or not isinstance(original.get('boot_id'), str) or not re.fullmatch(
                r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', original['boot_id']):
            raise Refused('Prior livepatch boot identity is incomplete')
        result['sequence'] = previous['sequence']
        result['manifest_sha256'] = previous.get('manifest_sha256')
        if any(original.get(key) != target[key] for key in ('kernel_release', 'kernel_image_sha256', 'kernel_config_sha256')):
            return dict(result, state='replacement_kernel_requires_patch')
        stored = previous.get('captured_bundle')
        if not isinstance(stored, str):
            raise Refused('Retained livepatch candidate is unavailable')
        captured = Path(stored)
        if captured.parent != state / 'livepatch-candidates' or not captured.name.startswith('candidate-'):
            raise Refused('Retained candidate is outside protected storage')
        verified = verify_bundle(captured, state, public_key, current_sequence=previous['sequence'] - 1,
                                 runner=runner, now=now, **{k: v for k, v in target.items() if k != 'boot_id'})
        if (verified['manifest']['sequence'] != previous['sequence']
                or any(verified[k] != previous.get(k) for k in ('manifest_sha256', 'publisher_spki_sha256'))
                or verified['manifest']['module_name'] != previous.get('module_name')
                or verified['manifest']['module']['sha256'] != previous.get('module_sha256')):
            raise Refused('Retained livepatch identity differs from the committed transaction')
        if original['boot_id'] != target['boot_id']:
            return dict(result, state='reapplication_required')
        observation = wait_for_transition(previous['module_name'], target['kernel_release'], timeout=1)
        if observation['boot_id'] != target['boot_id'] or measure_target(runner) != target:
            raise Refused('Kernel target changed during livepatch status')
        return dict(result, state='committed_patch_observed', active_observed=True,
                    observation=observation, manifest_sha256=verified['manifest_sha256'])


def require_settled(state):
    """Other maintenance engines must not cross an interrupted module load."""
    path = Path(state) / 'livepatch-transaction.json'
    if not path.exists() and not path.is_symlink():
        return
    record = strict_json(_read(path, 128 * 1024))
    if (not isinstance(record, dict) or type(record.get('schema')) is not int or record['schema'] != 1
            or record.get('state') != 'applied' or record.get('post_load_health_verified') is not True
            or type(record.get('sequence')) is not int or not 0 < record['sequence'] < 2**63):
        raise Refused('Livepatch recovery must finish before other appliance maintenance')


def poll_configured(state):
    from .github_updates import load_policy, GitHubTransport, PUBLIC_KEY
    require_linux_root()
    policy, token = load_policy()
    # Vendor-only factory policy disables self-built kernel patches. Retained
    # qualification tooling requires an explicit opt-in before any network/load.
    if policy.get('automatic_livepatch', False) is not True:
        return {'schema': 1, 'state': 'disabled', 'active_status_requires_readback': True}
    return poll(GitHubTransport(token), state, PUBLIC_KEY, policy['repository'])


def poll(transport, state, public_key, repository, *, runner=run, now=None):
    """Reapply locally before network access, then authenticate and apply a newer patch.

    The caller must enforce its automatic-update policy. This lock serializes
    pollers; every mutation separately takes the shared maintenance lock and
    revalidates the candidate and host at the point of application.
    """
    require_linux_root()
    state = Path(state)
    _tree(state)
    with locked(state / 'livepatch-poll.lock'):
        try:
            observed = status(state, public_key, runner=runner, now=now)
            reapplied = False
            if observed['state'] == 'reapplication_required':
                apply_bundle(None, state, public_key, runner=runner, now=now, reapply=True)
                reapplied = True
                observed = status(state, public_key, runner=runner, now=now)
            target = measure_target(runner)
            candidate = fetch_candidate(transport, state, public_key, repository,
                                        current_sequence=observed.get('sequence', 0), runner=runner, now=now,
                                        **{k: v for k, v in target.items() if k != 'boot_id'})
            if candidate['state'] == 'not_newer':
                if (candidate['manifest']['sequence'] != observed.get('sequence')
                        or candidate['manifest_sha256'] != observed.get('manifest_sha256')):
                    raise Refused('Published livepatch rolls back or conflicts with the committed sequence')
            elif candidate['state'] == 'authenticated_candidate':
                apply_bundle(Path(candidate['downloaded_bundle']), state, public_key, runner=runner, now=now)
            elif candidate['state'] != 'no_published_patch':
                raise Refused('Unexpected livepatch feed result')
            # A feed hit or saved sequence is never evidence of an active patch.
            observed = status(state, public_key, runner=runner, now=now)
            result = {'schema': 1, 'state': 'checked', 'feed_state': candidate['state'],
                      'reapplied_before_network': reapplied, 'observation': observed,
                      'checked_at': (now or datetime.now(timezone.utc)).isoformat()}
            atomic_json(state / 'livepatch-poll.json', result)
            return result
        except Exception as error:
            atomic_json(state / 'livepatch-poll.json', {'schema': 1, 'state': 'failed',
                        'error_type': type(error).__name__,
                        'checked_at': (now or datetime.now(timezone.utc)).isoformat(),
                        'active_status_requires_readback': True})
            raise


def inspect_publication(bundle, state, public_key, *, kernel_release, runner=run, now=None):
    """Authenticate bounded metadata before downloading module payloads."""
    require_linux_root()
    bundle, state, public_key = map(Path, (bundle, state, public_key))
    trust = enrolled_key(state, public_key)
    raw = _read(bundle / 'livepatch.json', 128 * 1024)
    signature = _read(bundle / 'livepatch.sig', 16384)
    key = _read(public_key, 16384)
    if digest(key) != trust['pem_sha256']:
        raise Refused('Publisher key changed during publication inspection')
    _tree(state)
    with tempfile.TemporaryDirectory(prefix='livepatch-metadata-', dir=state) as directory:
        captured = Path(directory)
        for name, content in (('livepatch.json', raw), ('livepatch.sig', signature), ('publisher.pem', key)):
            (captured / name).write_bytes(content)
            (captured / name).chmod(0o600)
        runner(['openssl', 'dgst', '-sha256', '-verify', str(captured / 'publisher.pem'),
                '-signature', str(captured / 'livepatch.sig'), '-sigopt', 'rsa_padding_mode:pss',
                '-sigopt', 'rsa_pss_saltlen:32', str(captured / 'livepatch.json')])
        manifest = validate_manifest(raw, current_sequence=0, kernel_release=kernel_release,
                                     now=now or datetime.now(timezone.utc))
        if enrolled_key(state, public_key) != trust:
            raise Refused('Publisher trust changed during publication inspection')
    return {'state': 'authenticated_metadata', 'manifest': manifest, 'manifest_sha256': digest(raw),
            'publisher_spki_sha256': trust['spki_sha256'], 'artifacts_verified': False}


def fetch_candidate(transport, state, public_key, repository, *, kernel_release,
                    kernel_image_sha256, kernel_config_sha256, current_sequence,
                    runner=run, now=None):
    """Fetch a stable per-kernel tag; GitHub metadata cannot authorize a load."""
    import shutil
    from .github_updates import REPOSITORY, MAX_RELEASE, HTTPFailure
    require_linux_root()
    if (not isinstance(repository, str) or not REPOSITORY.fullmatch(repository)
            or repository.endswith('.git') or not isinstance(kernel_release, str)
            or not KERNEL.fullmatch(kernel_release) or type(current_sequence) is not int or current_sequence < 0):
        raise Refused('Invalid livepatch feed target')
    state = Path(state)
    _tree(state)
    prefix = '/repos/' + repository
    tag = 'livepatch-' + kernel_release
    try:
        release = strict_json(transport.fetch(prefix + '/releases/tags/' + tag, maximum=MAX_RELEASE))
    except HTTPFailure as error:
        if error.status == 404:
            return {'state': 'no_published_patch', 'kernel_release': kernel_release}
        raise
    if (not isinstance(release, dict) or release.get('draft') is not False
            or release.get('prerelease') is not False or release.get('tag_name') != tag
            or type(release.get('id')) is not int or release['id'] <= 0
            or not isinstance(release.get('assets'), list) or len(release['assets']) > 100):
        raise Refused('Livepatch feed requires the exact published stable kernel tag')
    assets = {}
    for asset in release['assets']:
        if (not isinstance(asset, dict) or not isinstance(asset.get('name'), str)
                or asset['name'] in assets or type(asset.get('id')) is not int or asset['id'] <= 0
                or asset.get('state') != 'uploaded' or type(asset.get('size')) is not int or asset['size'] <= 0):
            raise Refused('Ambiguous livepatch release assets')
        assets[asset['name']] = asset
    names = {'livepatch.json': 128 * 1024, 'livepatch.sig': 16384,
             **{FILES[role]: maximum for role, maximum in LIMITS.items()}}
    if not names.keys() <= assets.keys() or any(assets[name]['size'] > limit for name, limit in names.items()):
        raise Refused('Livepatch release is incomplete or exceeds bounded artifact limits')
    if shutil.disk_usage(state).free < 4 * sum(assets[name]['size'] for name in names) + 1024**2:
        raise Refused('Insufficient livepatch capture and verification reserve')
    parent = state / 'livepatch-downloads'
    parent.mkdir(mode=0o700, exist_ok=True)
    _tree(parent)
    stage = Path(tempfile.mkdtemp(prefix='github-', dir=parent))
    def download(name, expected_hash=None):
        asset = assets[name]
        fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            transport.fetch(prefix + '/releases/assets/' + str(asset['id']), maximum=names[name],
                            output=stream, expected_size=asset['size'], expected_hash=expected_hash)
            stream.flush()
            os.fsync(stream.fileno())
    try:
        download('livepatch.json')
        download('livepatch.sig')
        metadata = inspect_publication(stage, state, public_key, kernel_release=kernel_release, runner=runner, now=now)
        manifest = metadata['manifest']
        if (manifest['kernel_image_sha256'] != kernel_image_sha256
                or manifest['kernel_config_sha256'] != kernel_config_sha256):
            raise Refused('Published patch targets different measured kernel files')
        if manifest['sequence'] <= current_sequence:
            result = {**metadata, 'state': 'not_newer', 'downloaded_bundle': str(stage)}
        else:
            for role, name in FILES.items():
                if assets[name]['size'] != manifest[role]['bytes']:
                    raise Refused('GitHub artifact length differs from authenticated manifest')
                download(name, manifest[role]['sha256'])
            result = verify_bundle(stage, state, public_key, current_sequence=current_sequence,
                                   kernel_release=kernel_release, kernel_image_sha256=kernel_image_sha256,
                                   kernel_config_sha256=kernel_config_sha256, runner=runner, now=now)
            result['downloaded_bundle'] = str(stage)
        atomic_json(stage / 'download.json', {'schema': 1, 'state': result['state'], 'release_id': release['id'],
                                            'manifest_sha256': result['manifest_sha256'], 'applied': False})
        return result
    except Exception as error:
        atomic_json(stage / 'download.json', {'schema': 1, 'state': 'failed', 'error_type': type(error).__name__, 'applied': False})
        raise
