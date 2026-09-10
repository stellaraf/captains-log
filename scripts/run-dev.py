#!/usr/bin/env python3
"""Run a local binary with secrets loaded without shell expansion."""
import os, pathlib, sys
root=pathlib.Path(__file__).resolve().parents[1]
v=dict(line.split('=',1) for line in (root/'.local/dev.env').read_text().splitlines() if line and not line.startswith('#'))
env=os.environ.copy()
env.update(PG_DSN=f"postgres://nebulalog:{v['PG_PASSWORD']}@127.0.0.1:25432/nebulalog?sslmode=disable",CH_URL='http://127.0.0.1:28123',CH_USER='nebulalog',CH_PASSWORD=v['CH_PASSWORD'],OIDC_ISSUER='http://127.0.0.1:18089/realms/nebulalog',OIDC_URL='http://127.0.0.1:18089',OIDC_REALM='nebulalog',OIDC_CLIENT_ID='nebulalog',API_LISTEN='127.0.0.1:18080',SYSLOG_TCP=v['SYSLOG_BIND_IP']+':5514',SYSLOG_UDP=v['SYSLOG_BIND_IP']+':5514',SYSLOG_TLS=v['SYSLOG_BIND_IP']+':6514',SYSLOG_CERT=str(root/'.local/certs/syslog.crt'),SYSLOG_KEY=str(root/'.local/certs/syslog.key'),SPOOL_DIR=str(root/'.local/app-data/spool'),EXPORT_DIR=str(root/'.local/app-data/exports'),PANOS_TIMEZONE=v['PANOS_TIMEZONE'])
os.chdir(root)
if v.get('KC_IDENTITY_CLIENT_SECRET'):
    env.update(IDENTITY_ADMIN_URL='http://127.0.0.1:18089',IDENTITY_CLIENT_ID='nebulalog-identity-manager',IDENTITY_CLIENT_SECRET=v['KC_IDENTITY_CLIENT_SECRET'],IDENTITY_ALLOW_HTTP='true',IDENTITY_ENABLE_WRITES='true')
os.execve(str(root/'bin/nebulalog'),['nebulalog']+sys.argv[1:],env)
