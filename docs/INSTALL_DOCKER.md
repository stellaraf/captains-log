# Docker development and community deployment

Docker Compose is a development deployment. It does not supply the Rocky Linux
host controls, strict Keycloak FIPS bundle or encrypted appliance data disk.
Use only trusted local networks while developing; browser/identity HTTP is
loopback-only, and the temporary Syslog TLS certificate expires after 30 days.

1. Install Docker with Compose, Python 3 and OpenSSL.
2. Run `python3 scripts/dev-init.py`. Unique secrets are stored in `.local/dev.env`
   with mode 0600. Back this file up privately; do not regenerate credentials
   against existing database volumes.
3. Set `SYSLOG_BIND_IP` to a reachable host interface to receive firewall logs.
   The default is loopback. Set `PANOS_TIMEZONE` to the device timezone for legacy
   timestamps (high-resolution timestamps carry their own offset).
4. Start dependencies: `docker compose --env-file .local/dev.env up -d postgres clickhouse keycloak`.
5. Build: `docker compose --env-file .local/dev.env --profile application build app`.
6. Initialize schema: `docker compose --env-file .local/dev.env --profile application run --rm app migrate`.
7. After Keycloak starts, run `python3 scripts/dev-auth.py` to create the unique
   administrator and require TOTP enrollment. It is safe to rerun without
   overwriting an enrolled account's factors.
8. Start the application: `docker compose --env-file .local/dev.env --profile application up -d app`.
9. Open `http://127.0.0.1:18080`; credentials are in `.local/login.txt`.

Ports: Web/API18080, identity18089, Syslog TCP/UDP5514 and TLS6514. Database ports
25432/28123 are loopback-only for integration development; remove those mappings
for a community server. Never expose Keycloak development mode to the Internet.

PostgreSQL and ClickHouse use dedicated named volumes. Spool, private CSV exports
and the local TLS key use `.local/app-data` / `.local/certs`. The app drops all
capabilities, has a read-only root, uses a non-root development UID, and has no
container-management socket. Configure the development UID/GID for your host.

The container uses an internal Keycloak transport URL while retaining the exact
public issuer for signature/issuer validation. Tokens stay only in browser memory.
There is no development auth bypass and the client disables password grants.

Docker Desktop may translate incoming connection addresses to its VM gateway
(for example192.168.65.1). `sender_ip` records the actual transport peer observed
by the collector; firewall serial/device name remain the identity. A native
collector or a qualified Linux appliance network is needed to preserve original
sender addresses end to end. Do not present the gateway as a management IP.

Check `docker compose --env-file .local/dev.env ps` and `/api/health`. Inspect
the app logs and authenticated Diagnostics. Stopping the application interrupts
receipt; TCP senders must reconnect. Retained spool replays after restart. `down`
does not delete database volumes; do not use `down -v` unless explicitly destroying
the deployment and all logs.

For rapid native Go iteration, build `go build -o bin/nebulalog ./cmd/nebulalog`
and run `python3 scripts/run-dev.py all` after dependencies/schema/identity setup.
Do not run native and container collectors against the same spool or port.
