# Security policy

This project has not released a production-qualified appliance. Development
builds receive fixes but do not carry production support or compliance claims.

Report vulnerabilities using GitHub's private vulnerability reporting for
`stellaraf/captains-log` when the repository is published. If it is unavailable,
contact a maintainer privately before publishing exploit details. Include the
affected revision, reproduction, scope and suggested mitigation; omit secrets
and unsanitized firewall records.

Application endpoints enforce Keycloak issuer/audience/signature/expiry and role
checks. Sensitive metadata persists in PostgreSQL and firewall records in
ClickHouse. Development databases bind to loopback; production databases must
remain on private container networks. Short-lived CSV download capabilities
authorize one completed export and must be treated as secrets.

The production boundary includes the exact OS, crypto providers, Go module,
Keycloak bundle, LUKS unlock method, SELinux policy and release-signing trust root.
FIPS enabled is not a claim that Captain’s Log is certified. See docs/FIPS.md.

Never use firewall or identity administrator credentials in a frontend, fixture,
git repository or application log. Temporary development secrets live in ignored,
permission-restricted local files and are unique per deployment.
