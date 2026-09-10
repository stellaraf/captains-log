#!/usr/bin/env python3
"""Generate unique local deployment secrets. Never prints credentials."""
import ipaddress, json, os, pathlib, secrets, stat, subprocess

root = pathlib.Path(__file__).resolve().parents[1]
local = root / '.local'
local.mkdir(mode=0o700, exist_ok=True)
info = local.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
    raise SystemExit('.local must be an owner-only real directory (mode0700).')
path = local / 'dev.env'
if not path.exists():
    values = {key: secrets.token_hex(24) for key in ('PG_ADMIN_PASSWORD', 'PG_PASSWORD', 'KC_DB_PASSWORD', 'KC_ADMIN_PASSWORD', 'CH_PASSWORD', 'NL_ADMIN_PASSWORD')}
    values['NL_ADMIN_PASSWORD'] = secrets.token_urlsafe(32) + 'Aa1!'
    values.update(SYSLOG_BIND_IP='127.0.0.1', PANOS_TIMEZONE='America/Phoenix', DEV_UID=str(os.getuid()), DEV_GID=str(os.getgid()))
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as f:
        f.write(''.join(f'{k}={v}\n' for k, v in values.items()))
info = path.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
    raise SystemExit('dev.env must be an owner-only regular file, not a symbolic link.')
values = dict(line.split('=', 1) for line in path.read_text().splitlines() if line and not line.startswith('#'))
if 'KC_IDENTITY_CLIENT_SECRET' not in values:
    # Upgrade an existing local deployment without rotating its other secrets.
    values['KC_IDENTITY_CLIENT_SECRET'] = secrets.token_urlsafe(48)
    temporary = local / 'dev.env.next'
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as f:
        f.write(''.join(f'{k}={v}\n' for k, v in values.items()))
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
for name in ('app-data', 'app-data/spool', 'app-data/exports', 'certs'):
    (local / name).mkdir(mode=0o700, exist_ok=True)
info = (local / 'certs').lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
    raise SystemExit('certs must be an owner-only real directory.')
for item in (local / 'certs/syslog.key', local / 'certs/syslog.crt'):
    if item.is_symlink() or item.exists() and not item.is_file():
        raise SystemExit('Legacy syslog certificate inputs must be regular files.')
if (local / 'certs/syslog.crt').exists() and not (local / 'certs/syslog.key').exists():
    raise SystemExit('The existing legacy syslog certificate has lost its key; recovery is required.')
if not (local / 'certs/syslog.key').exists():
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '30', '-subj', '/CN=nebulalog-development', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(local/'certs/syslog.key'), '-out', str(local/'certs/syslog.crt')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(local / 'certs/syslog.key', 0o600)
print('Local secrets and temporary Syslog TLS certificate are ready in .local/. No credentials printed.')

# Development analogue of appliance first-boot generation. The CA signing key
# lives outside every application bind mount; only public trust and the TLS
# listener's own key are exposed to the combined development service.
authority = local / 'syslog-authority'
authority.mkdir(mode=0o700, exist_ok=True)
info = authority.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
    raise SystemExit('syslog-authority must be an owner-only real directory.')
ca_key, ca_cert = authority / 'ca.key', local / 'certs/syslog-ca.crt'
server_key, server_cert = local / 'certs/syslog-server.key', local / 'certs/syslog-server.crt'
def openssl(*args):
    return subprocess.run(['openssl', *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180).stdout
for item in (ca_key, ca_cert, server_key, server_cert):
    if item.is_symlink():
        raise SystemExit('Syslog certificate inputs must not be symbolic links.')
    if item.exists():
        info = item.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise SystemExit('Syslog certificate inputs have unsafe ownership or permissions.')
if ca_cert.exists() and not ca_key.exists() or server_cert.exists() and not server_key.exists():
    raise SystemExit('An existing syslog certificate has lost its key; recovery is required.')
old_umask = os.umask(0o077)
try:
    for key in (ca_key, server_key):
        if not key.exists():
            openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(key))
        os.chmod(key, 0o600)
    if not ca_cert.exists():
        openssl('req', '-new', '-x509', '-sha256', '-days', '3650', '-key', str(ca_key), '-out', str(ca_cert),
                '-subj', "/CN=Captain's Log development syslog CA", '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    addresses = {'127.0.0.1', '::1'}
    address = ipaddress.ip_address(values.get('SYSLOG_BIND_IP', '127.0.0.1'))
    if not address.is_unspecified:
        addresses.add(str(address))
    if not server_cert.exists():
        extension, csr = authority / 'server.ext', authority / 'server.csr'
        extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                             'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,' + ','.join('IP:' + item for item in sorted(addresses)) + '\n')
        openssl('req', '-new', '-sha256', '-key', str(server_key), '-out', str(csr), '-subj', '/CN=localhost')
        openssl('x509', '-req', '-sha256', '-days', '397', '-in', str(csr), '-CA', str(ca_cert), '-CAkey', str(ca_key),
                '-set_serial', '0x' + secrets.token_hex(16), '-extfile', str(extension), '-out', str(server_cert))
        csr.unlink(); extension.unlink()
    for key, cert in ((ca_key, ca_cert), (server_key, server_cert)):
        if openssl('pkey', '-in', str(key), '-pubout') != openssl('x509', '-in', str(cert), '-pubkey', '-noout'):
            raise SystemExit('Syslog certificate and key do not match.')
        openssl('x509', '-in', str(cert), '-checkend', '86400', '-noout')
    openssl('verify', '-CAfile', str(ca_cert), '-verify_hostname', 'localhost', str(server_cert))
    for address in addresses:
        openssl('verify', '-CAfile', str(ca_cert), '-verify_ip', address, str(server_cert))
    if server_cert.read_bytes().count(b'-----BEGIN CERTIFICATE-----') == 1:
        with server_cert.open('ab') as stream:
            stream.write(ca_cert.read_bytes())
    for cert in (ca_cert, server_cert): os.chmod(cert, 0o644)
finally:
    os.umask(old_umask)
print('Unique development syslog CA and server certificates verified. CA signing key is outside application mounts.')
