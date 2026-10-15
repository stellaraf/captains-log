# Opt-in UEFI installer/build recipe. This file is used only inside a new disposable VM.
text
url --url=https://download.rockylinux.org/pub/rocky/9.8/BaseOS/x86_64/os/
repo --name=AppStream --baseurl=https://download.rockylinux.org/pub/rocky/9.8/AppStream/x86_64/os/
lang en_US.UTF-8
keyboard us
timezone Etc/UTC --utc
network --bootproto=dhcp --device=link --activate
rootpw --lock
selinux --enforcing
firewall --enabled --service=ssh
services --enabled="chronyd,firewalld,auditd,sshd,qemu-guest-agent" --disabled="kdump"
bootloader --append="fips=1 module.sig_enforce=1 audit=1 audit_backlog_limit=8192"
# The build layout uses vda for the disposable system disk. Never use this
# Kickstart against an existing server; data disk vdb is excluded from clearing.
ignoredisk --only-use=vda
zerombr
clearpart --all --initlabel --disklabel=gpt --drives=vda
part /boot --fstype=xfs --size=1024 --ondisk=vda
part /boot/efi --fstype=efi --size=600 --ondisk=vda
part pv.system --fstype=lvmpv --grow --size=1024 --ondisk=vda
volgroup system pv.system
logvol / --fstype=xfs --vgname=system --name=root --size=18000
logvol /var --fstype=xfs --vgname=system --name=var --size=20000
logvol /var/log --fstype=xfs --vgname=system --name=log --size=8000
logvol /var/log/audit --fstype=xfs --vgname=system --name=audit --size=8000
logvol /home --fstype=xfs --vgname=system --name=home --size=1024
logvol /tmp --fstype=xfs --vgname=system --name=tmp --size=4096
logvol /var/tmp --fstype=xfs --vgname=system --name=var_tmp --size=4096 --fsoptions="nodev,nosuid,noexec"
logvol swap --fstype=swap --vgname=system --name=swap --size=4096
reboot

%pre --interpreter=/bin/bash --erroronfail
set -euo pipefail
test -d /sys/firmware/efi
test "$(uname -m)" = x86_64
test "$(cat /proc/sys/crypto/fips_enabled)" = 1
%end

%packages --excludedocs
@^minimal-environment
podman
skopeo
container-selinux
python3
cryptsetup
lvm2
xfsprogs
shim-x64
grub2-efi-x64
grub2-efi-x64-modules
efibootmgr
dosfstools
cloud-utils-growpart
openscap-scanner
scap-security-guide
crypto-policies-scripts
aide
audit
firewalld
chrony
qemu-guest-agent
open-vm-tools
policycoreutils-python-utils
openssl
keyutils
sudo
openssh-server
postgresql
dnf-plugins-core
curl
httpd
mod_ssl
acl
%end

%post --interpreter=/bin/bash --erroronfail
set -euo pipefail
umask 077
test "$(cat /proc/sys/crypto/fips_enabled)" = 1
update-crypto-policies --set FIPS
fips-mode-setup --enable
useradd --create-home --groups wheel packer
# Random inaccessible password exists only during build; SSH allows keys only.
openssl rand -base64 48 | passwd --stdin packer >/dev/null
mkdir -p /home/packer/.ssh
python3 - <<'PY'
import base64
import struct
from pathlib import Path
from urllib.parse import unquote_plus

def build_public_key(cmdline):
    values = [word.split('=', 1)[1] for word in cmdline.split()
              if word.startswith('PACKER_AUTHORIZED_KEY=')]
    try:
        if len(values) != 1 or len(values[0]) > 16384:
            raise ValueError()
        key = unquote_plus(values[0], encoding='ascii', errors='strict')
        # Packer's ssh.MarshalAuthorizedKey emits exactly one terminal LF.
        # Accept that serialization; never strip embedded or repeated newlines.
        if key.endswith('\n'):
            key = key[:-1]
        if not key or any(ord(char) < 32 or ord(char) > 126 for char in key):
            raise ValueError()
        fields = key.split(' ')
        if len(fields) != 2 or fields[0] != 'ssh-rsa':
            raise ValueError()
        wire = base64.b64decode(fields[1], validate=True)
        parts = []
        for _ in range(3):
            length = struct.unpack('>I', wire[:4])[0]
            if length == 0 or length > len(wire) - 4:
                raise ValueError()
            parts.append(wire[4:4 + length])
            wire = wire[4 + length:]
        if wire or parts[0] != b'ssh-rsa':
            raise ValueError()
        for integer in parts[1:]:
            if integer[0] & 0x80 or (integer[0] == 0 and
                    (len(integer) == 1 or not integer[1] & 0x80)):
                raise ValueError()
        exponent, modulus = (int.from_bytes(part, 'big') for part in parts[1:])
        if not (3 <= exponent < 2**24 and exponent % 2 == 1 and
                3072 <= modulus.bit_length() <= 8192 and modulus % 2 == 1):
            raise ValueError()
        return key + '\n'
    except (ValueError, UnicodeError, struct.error):
        raise SystemExit('Build requires one valid per-build RSA public key of at least 3072 bits') from None

Path('/home/packer/.ssh/authorized_keys').write_text(
    build_public_key(Path('/proc/cmdline').read_text()), encoding='ascii')
PY
chown -R packer:packer /home/packer/.ssh
chmod 700 /home/packer/.ssh
chmod 600 /home/packer/.ssh/authorized_keys
printf 'packer ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/nebulalog-build
chmod 440 /etc/sudoers.d/nebulalog-build
printf 'PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/00-nebulalog.conf
restorecon -RF /home/packer/.ssh
%end
