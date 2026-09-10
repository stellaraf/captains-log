# Active Directory federation

Use Keycloak User Federation → LDAP with the Active Directory vendor. Production
connections use LDAPS and a trusted directory certificate chain; never disable
certificate verification to make an integration pass. Start with read-only
federation, a scoped directory service account, bounded synchronization and the
appropriate users/groups DN.

Map username/UPN/email and directory groups intentionally. Assign groups to the
Captain’s Log client roles ADMINISTRATOR, ANALYST or VIEWER. Do not give every domain
user administrator access. The browser flow must still require Keycloak's second
factor after directory password validation. Test users with and without enrolled
OTP and verify no un-enrolled bypass is possible.

Before switching identity defaults, preserve and test a local break-glass
administrator. Test directory outage, expired/untrusted LDAPS certificates,
disabled accounts, removed group membership and token/session expiry.

No AD test directory was supplied with this repository. AD/federated MFA remain
unverified release gates until an actual directory test passes. The development
UI does not claim these tests have run.

[Official Keycloak LDAP federation guidance](https://www.keycloak.org/docs/latest/server_admin/#_ldap).
