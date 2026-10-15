#!/bin/bash
# Packer guest provisioner. Do not run on the development host.
set -euo pipefail
[ "$(id -u)" = 0 ]
. /etc/os-release
[ "$ID" = rocky ] && [ "${VERSION_ID%%.*}" = 9 ]
[ "$(cat /proc/sys/crypto/fips_enabled)" = 1 ]
fips-mode-setup --check
[ "$(cat /sys/module/module/parameters/sig_enforce)" = Y ]
[ "$(getenforce)" = Enforcing ]
APPLIANCE_SOURCE=$(cd "$(dirname "$0")" && pwd)
# Serialize the complete provisioner and sealer without creating a lock file.
# The fixed /etc directory inode stays open until this shell and its children exit.
exec 9</etc
flock -n 9 || { echo 'Another image provisioner or sealer is active' >&2; exit 78; }
# This guard durably creates the private receipt before the first payload write.
# It never resets customer state or adopts a legacy unmarked partial installation.
python3 "$APPLIANCE_SOURCE/provision_guard.py" begin
install -d -m 0755 /usr/lib/nebulalog/nebulalog_manager /usr/libexec/nebulalog /usr/share/nebulalog/quadlet-templates /usr/share/nebulalog/httpd /usr/share/nebulalog/keycloak
install -d -m 0700 /etc/nebulalog
install -o root -g root -m 0600 "$APPLIANCE_SOURCE/security/github-updates.json" /etc/nebulalog/github-updates.json
install -m 0755 "$APPLIANCE_SOURCE/provision_guard.py" /usr/libexec/nebulalog/provision-guard
install -m 0755 "$APPLIANCE_SOURCE/host_boot.py" /usr/libexec/nebulalog/host-boot
install -m 0755 "$APPLIANCE_SOURCE/factory_host.py" /usr/libexec/nebulalog/factory-host
install -m 0644 "$APPLIANCE_SOURCE"/nebulalog_manager/*.py /usr/lib/nebulalog/nebulalog_manager/
install -d -m 0755 /usr/lib/nebulalog/nebulalog_adapters
install -m 0644 "$APPLIANCE_SOURCE"/adapters/nebulalog_adapters/*.py /usr/lib/nebulalog/nebulalog_adapters/
install -m 0755 "$APPLIANCE_SOURCE"/adapters/bin/* /usr/libexec/nebulalog/
install -m 0755 "$APPLIANCE_SOURCE/bin/nebulalog" /usr/local/bin/nebulalog
install -m 0755 "$APPLIANCE_SOURCE/bin/nebulalog-seal" /usr/local/sbin/nebulalog-seal
install -m 0755 "$APPLIANCE_SOURCE/bin/nebulalog-firstboot" /usr/libexec/nebulalog/nebulalog-firstboot
install -m 0755 "$APPLIANCE_SOURCE/bin/nebulalog-aide" /usr/libexec/nebulalog/nebulalog-aide
install -m 0755 "$APPLIANCE_SOURCE/bin/nebulalog-setup" /usr/local/sbin/nebulalog-setup
if [ -f "$APPLIANCE_SOURCE/bin/bootstrap-runtime" ]; then
  install -m 0755 "$APPLIANCE_SOURCE/bin/bootstrap-runtime" /usr/libexec/nebulalog/bootstrap-runtime
fi
for helper in load-image-bundle nebulalog-baseline publish-status nebulalog-console enroll-installed-release validate-guest; do
  if [ -f "$APPLIANCE_SOURCE/bin/$helper" ]; then
    install -m 0755 "$APPLIANCE_SOURCE/bin/$helper" "/usr/libexec/nebulalog/$helper"
  fi
done
install -m 0644 "$APPLIANCE_SOURCE"/systemd/*.service "$APPLIANCE_SOURCE"/systemd/*.timer /etc/systemd/system/
if [ -d "$APPLIANCE_SOURCE/systemd/getty@tty1.service.d" ]; then
  install -d -m 0755 /etc/systemd/system/getty@tty1.service.d
  install -m 0644 "$APPLIANCE_SOURCE"/systemd/getty@tty1.service.d/*.conf /etc/systemd/system/getty@tty1.service.d/
fi
install -m 0644 "$APPLIANCE_SOURCE"/quadlet/* /usr/share/nebulalog/quadlet-templates/
install -m 0644 "$APPLIANCE_SOURCE/httpd/nebulalog.conf.in" /usr/share/nebulalog/httpd/nebulalog.conf.in
if [ -f /tmp/nebulalog-keycloak-realm.json ]; then
  install -m 0644 /tmp/nebulalog-keycloak-realm.json /usr/share/nebulalog/keycloak/realm.json
else
  echo "The sealed Keycloak realm template is missing" >&2
  exit 1
fi
install -m 0644 "$APPLIANCE_SOURCE/security/storage.conf" /etc/containers/storage.conf
install -d -m 0755 /etc/dracut.conf.d
install -m 0644 "$APPLIANCE_SOURCE/security/dracut-nebulalog.conf" /etc/dracut.conf.d/90-nebulalog.conf
install -d -m 0755 /usr/share/nebulalog/baselines
for baseline_file in baseline-catalog.json baseline-cis.xml baseline-stig.xml; do
  install -m 0644 "$APPLIANCE_SOURCE/security/$baseline_file" "/usr/share/nebulalog/baselines/$baseline_file"
done
install -d -m 0755 /usr/share/nebulalog/aide
install -m 0644 "$APPLIANCE_SOURCE/security/aide-policy.conf" /usr/share/nebulalog/aide/policy.conf
install -o root -g root -m 0600 "$APPLIANCE_SOURCE/security/aide.conf" /etc/aide.conf
restorecon /etc/aide.conf
for driver in vmw_pvscsi vmxnet3 virtio_blk virtio_scsi virtio_net; do
  modinfo "$driver" >/dev/null
done
install -m 0600 "$APPLIANCE_SOURCE/security/trust.json" /etc/nebulalog/trust.json
python3 - <<'PYTRUST'
import hashlib, json
from pathlib import Path
trust=json.loads(Path('/etc/nebulalog/trust.json').read_text())
key=Path('/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9').read_bytes()
if trust['schema'] != 1 or hashlib.sha256(key).hexdigest() != trust['rocky_key_sha256']:
    raise SystemExit('Installed Rocky release key differs from the independently reviewed key')
PYTRUST
if [ -f /tmp/nebulalog-image-bundle/manifest.json ]; then
  install -d -m 0755 /usr/share/nebulalog/images
  install -m 0644 /tmp/nebulalog-image-bundle/*.oci.tar /usr/share/nebulalog/images/
  install -m 0644 /tmp/nebulalog-image-bundle/manifest.json /usr/share/nebulalog/images/manifest.json
  install -m 0644 /tmp/nebulalog-image-bundle/images.json /etc/nebulalog/images.json
  # Image loading waits for the encrypted mount; no Podman graph is created now.
  PYTHONPATH=/usr/lib/nebulalog python3 - <<'PYBUNDLE'
from pathlib import Path
import json
from nebulalog_manager.image_bundle import verify_bundle
verify_bundle(Path('/usr/share/nebulalog/images'), json.loads(Path('/etc/nebulalog/images.json').read_text()), root_owned=True)
PYBUNDLE
fi
if [ -f /tmp/nebulalog-image-bundle/initial-release.json ] || [ -f /tmp/nebulalog-image-bundle/source-manifest.json ]; then
  # Both explicit provenance inputs are mandatory together; the unsealed build
  # may omit both, but first boot and sealing refuse missing or changed inputs.
  install -m 0600 /tmp/nebulalog-image-bundle/initial-release.json /usr/share/nebulalog/initial-release.json
  for publisher_input in publisher-public.spki publisher-trust.json; do
    if [ -e "$APPLIANCE_SOURCE/security/$publisher_input" ] || [ -L "$APPLIANCE_SOURCE/security/$publisher_input" ]; then
      [ -f "$APPLIANCE_SOURCE/security/$publisher_input" ] && [ ! -L "$APPLIANCE_SOURCE/security/$publisher_input" ] || exit 1
      install -m 0644 "$APPLIANCE_SOURCE/security/$publisher_input" "/usr/share/nebulalog/$publisher_input"
    fi
  done
  install -m 0600 /tmp/nebulalog-image-bundle/source-manifest.json /usr/share/nebulalog/source-manifest.json
  # Build only from the captured installer/realm bytes, before first boot. This
  # helper retains the parent's /etc lock and cannot run on enrolled appliances.
  PYTHONPATH=/usr/lib/nebulalog python3 "$APPLIANCE_SOURCE/factory_host.py" --source "$APPLIANCE_SOURCE"
  PYTHONPATH=/usr/lib/nebulalog python3 - <<'PYPROVENANCE'
from nebulalog_manager.update_enrollment import UpdateEnrollment
UpdateEnrollment().verify_build_inputs()
PYPROVENANCE
fi
# Read the exact policy records first. Matching registrations are no-ops;
# unexpected local policy or differing fixed expressions are never modified.
ensure_fcontext() { python3 "$APPLIANCE_SOURCE/provision_guard.py" fcontext "$@"; }
ensure_fcontext -a -e /var/lib/containers/storage /var/lib/nebulalog/containers
ensure_fcontext -a -t httpd_var_run_t '/run/nebulalog-public(/.*)?'
ensure_fcontext -a -t container_file_t '/run/nebulalog-status(/.*)?'
ensure_fcontext -a -t container_file_t '/var/lib/nebulalog/configuration/tls(/.*)?'
ensure_fcontext -a -t httpd_config_t '/var/lib/nebulalog/configuration/edge-tls(/.*)?'
ensure_fcontext -a -t aide_db_t '/var/lib/nebulalog/manager/aide(/.*)?'
install -d -m 0755 /etc/tmpfiles.d
printf 'd /run/nebulalog-status 0755 root root -\n' > /etc/tmpfiles.d/nebulalog-status.conf
chmod 0644 /etc/tmpfiles.d/nebulalog-status.conf
systemd-tmpfiles --create /etc/tmpfiles.d/nebulalog-status.conf
setsebool -P httpd_can_network_connect on
# The generated HTTPS-only profile replaces the distribution example virtual
# host; there is no plaintext management listener or shared sample certificate.
rm -f /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/welcome.conf
python3 - <<'PYHTTP'
from pathlib import Path
p=Path('/etc/httpd/conf/httpd.conf')
lines=p.read_text().splitlines()
p.write_text('\n'.join('# Disabled by NebulaLog: '+line if line.strip() == 'Listen 80' else line for line in lines)+'\n')
PYHTTP
systemctl disable httpd
install -d -m 0755 /run/httpd /var/log/httpd /var/lib/httpd
install -m 0600 "$APPLIANCE_SOURCE/security/90-nebulalog.rules" /etc/audit/rules.d/90-nebulalog.rules
install -m 0644 "$APPLIANCE_SOURCE/security/90-nebulalog.conf" /etc/sysctl.d/90-nebulalog.conf
# Reserve host persistence for the future encrypted mount, never write logs here.
install -d -m 0700 /var/lib/nebulalog
# No universal database/auth/release-signing secrets are embedded in the image.
python3 - <<'PYCONFIG'
from pathlib import Path
import configparser
p=Path("/etc/dnf/dnf.conf")
c=configparser.ConfigParser();c.read(p)
c["main"]["gpgcheck"]="1"
c["main"]["installonly_limit"]="3"
with p.open("w") as f:c.write(f)
PYCONFIG
# The OS timer's service requires enrolled maintenance policy; its adapter then
# verifies encrypted storage, healthy services/authentication and backups before DNF.
systemctl enable nebulalog-firstboot.service nebulalog-storage.timer nebulalog-aide.timer nebulalog-os-update.timer nebulalog-app-update.timer nebulalog-reboot-verify.service nebulalog-status.timer
if [ -f /etc/systemd/system/nebulalog-console.service ]; then
  systemctl enable nebulalog-console.service
fi
# Keep the per-build key usable when an explicitly unsealed private base is
# rebooted for qualification. The mandatory seal operation stops/disables SSH,
# removes this account and deletes host keys before a distributable image exists.
systemctl enable sshd
systemctl daemon-reload
python3 "$APPLIANCE_SOURCE/provision_guard.py" finish
