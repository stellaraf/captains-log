# Changelog

## 0.1.0-dev — Unreleased

- Persist per-account refresh interval and pause state in the browser; cancel
  pending automatic refreshes on Pause and refresh immediately on Resume.
- Explain empty log views and unsupported Tunnel parsing, add a wider-range
  shortcut, and label derived high/critical System events as System alerts.
- Recognize Advanced DNS Security `adns-*` categories alongside `dns-*`.

- Correct Threat view/search/export membership to include DNS-related THREAT
  records, which also remain visible in DNS Security with the same event IDs.

- Initial durable PAN-OS Syslog collector, schema registry and query compiler.
- PostgreSQL/ClickHouse integration, Keycloak PKCE and mandatory local TOTP.
- Dense engineering log viewer, saved filters, layouts, DNS and CSV exports.
- Stellar dual-theme application and login branding, persisted density/preferences,
  direct event/firewall routes, and detailed Entra/Okta SAML guides.
- Audited SAML metadata review/configuration with scoped identity-management
  credentials, exact role mapping, mandatory broker OTP and safe state controls.
- Real firewall/transport/recovery checks and bounded10M query measurements;
  dependency scanning and fixes recorded with their validation scope.
- Appliance manager, security/storage/lifecycle research and packaging recipes.

This entry describes development work. See docs/ACCEPTANCE.md for executed
validation and outstanding version 1 gates.
