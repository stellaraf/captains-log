# Captain’s Log

**Fast, local-first PAN-OS log collection and search.**

Formerly NebulaLog. The product name is **Captain’s Log**; its repository/module slug is `captains-log`. Existing installation and identity identifiers are preserved. See [name and compatibility](docs/PRODUCT_NAME.md).

Captain’s Log is a fast, local-first, open-source log collector and explorer for
PAN-OS firewalls.

Forward firewall logs to Captain’s Log using Syslog and get a familiar,
PAN-OS-inspired interface for centralized searching, filtering, retention, and
export without requiring cloud logging services or a traditional SIEM.

## Project status

This repository is an actively tested **development implementation**, not a
version 1 appliance release. The browser reads real PostgreSQL and ClickHouse
state and requires Keycloak authentication. Appliance security, OVA deployment,
external federation and large-scale performance have separate acceptance gates.
See [validation evidence](docs/ACCEPTANCE.md) and the
[implementation plan](docs/MILESTONES.md).

## Run locally

Requirements: Docker Compose, Python 3, OpenSSL. The development stack publishes
only loopback ports unless a Syslog bind address is explicitly configured.
Existing installations must follow the [upgrade and rollback
procedure](docs/DEVELOPMENT_UPGRADES.md) before updating dependency images.

```sh
python3 scripts/dev-init.py
docker compose --env-file .local/dev.env up -d postgres clickhouse keycloak
docker compose --env-file .local/dev.env --profile application build app
docker compose --env-file .local/dev.env --profile application run --rm app migrate
python3 scripts/dev-auth.py
docker compose --env-file .local/dev.env --profile application up -d app
```

Wait for Keycloak startup before running `dev-auth.py`. Open
<http://127.0.0.1:18080>. The unique local administrator credentials are in
`.local/login.txt` (mode 0600); enroll TOTP on first login. No universal password
or authentication bypass is provided. Never commit `.local/`.

To receive a firewall, set `SYSLOG_BIND_IP` in `.local/dev.env` to the host's
reachable interface address and recreate the app service. Match `PANOS_TIMEZONE`
to the firewall's configured timezone for legacy timestamps without an offset.
Development listeners are UDP/TCP **5514** and TLS **6514**. The temporary TLS
certificate is for testing and must be replaced/trusted before firewall TLS use.

The Compose deployment is not the Rocky/FIPS/LUKS production appliance.
See [Docker deployment](docs/INSTALL_DOCKER.md) and
[complete firewall logging setup](docs/FIREWALL_SETUP.md). The setup guide covers
all available log types, rule/profile coverage, informational events, and the
WildFire benign/grayware reporting settings needed to generate submission logs.

## Architecture

- Go collector and API, bounded fsynced spool, native UDP/TCP/TLS listeners.
- Versioned PAN-OS family registry; original messages and parser failures retained.
- ClickHouse MergeTree firewall data, PostgreSQL metadata, Keycloak identity.
- Dense React viewer, typed PAN-OS filter compiler, graphical/click filters,
  saved searches, column layouts, asynchronous reverse DNS and CSV jobs.
- Stellar-branded Light/Dark/System themes, compact/comfortable density, stable
  event and firewall pages, plus in-app Okta/Entra SAML setup and detailed guides.
- Host appliance manager tooling for measured security/compliance, guarded
  storage plans, signed update validation, encrypted configuration backups.

[Architecture](docs/ARCHITECTURE.md) · [query language](docs/QUERY_LANGUAGE.md) ·
[storage](docs/STORAGE.md) · [security](SECURITY.md) · [development](docs/DEVELOPMENT.md)

## Verify

```sh
go test -race ./...
cd web
npm ci
npm test
npm run build
```

The appliance package has its own test instructions in `appliance/README.md`.
Tests never make host block-device changes. Browser and integration tests require
the actual services and unique test identities. Benchmark numbers always record
hardware, data shape and whether the test covers parsing, ingestion or querying.

## License and trademarks

Original Captain’s Log code is licensed under the GNU Affero General Public
License version 3 only (`AGPL-3.0-only`). See [LICENSE](LICENSE) and
[LICENSING.md](LICENSING.md) for the terms and third-party license boundaries.
Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

Captain’s Log is an independent open-source project and is not affiliated with,
endorsed by, or sponsored by Palo Alto Networks. Palo Alto Networks, PAN-OS,
and related names are trademarks of their respective owner.
