# SAML setup: Microsoft Entra ID and Okta

Verified against official documentation on **2026-09-07** and the deployed Keycloak **26.3.3** image. Microsoft Entra ID is the default Microsoft guide. These are configuration instructions, not evidence that an external tenant is connected: no Okta or Entra tenant was configured or tested during this build.

Captain’s Log signs users in through Keycloak using OIDC and PKCE. Keycloak acts as the SAML service provider (SP) when it brokers an external identity provider (IdP). The Captain’s Log OIDC client remains `nebulalog`; creating a second SAML application client inside Keycloak is unnecessary for this topology.

## 1. Prepare public URLs and local recovery access

Read the public `/api/config` response and take `auth.url` as `AUTH_BASE` and `auth.realm` as `REALM`. Remove a trailing slash from `AUTH_BASE`; preserve an explicitly configured base path. Use alias `entra` or `okta` exactly, including case. An alias is part of the callback URL and should remain stable after users are linked.

| Value | Template |
|---|---|
| Keycloak realm / default SP entity ID | `{AUTH_BASE}/realms/{REALM}` |
| Entra assertion consumer service (ACS / Reply URL) | `{AUTH_BASE}/realms/{REALM}/broker/entra/endpoint` |
| Okta assertion consumer service (ACS / Single sign-on URL) | `{AUTH_BASE}/realms/{REALM}/broker/okta/endpoint` |
| Entra SP metadata | `{AUTH_BASE}/realms/{REALM}/broker/entra/endpoint/descriptor` |
| Okta SP metadata | `{AUTH_BASE}/realms/{REALM}/broker/okta/endpoint/descriptor` |
| Keycloak administration | `{AUTH_BASE}/admin/` |
| Application sign-on / bookmark target | The public HTTPS Captain’s Log application URL |

The entity ID is the realm URL, **not** the ACS URL, descriptor URL, or OIDC client ID. An intentionally overridden SP entity ID must match the IdP registration and the saved SP metadata. Save the Keycloak provider before opening its descriptor, then compare its `entityID` and HTTP-POST ACS location with the values registered at the IdP. [Keycloak SAML broker reference, deployed version](https://github.com/keycloak/keycloak/blob/26.3.3/docs/documentation/server_admin/topics/identity-broker/saml.adoc).

The observed development configuration is `AUTH_BASE=http://127.0.0.1:18089`, `REALM=nebulalog`. Thus its Entra ACS would be `http://127.0.0.1:18089/realms/nebulalog/broker/entra/endpoint`. This is a **development-only derived value**, not a configured provider or suitable production callback. Set a stable, browser-reachable HTTPS Keycloak hostname and correct reverse-proxy handling first; update Captain’s Log’s OIDC issuer and redirect origins together. A hostname such as `https://auth.example.com` gives SP entity ID `https://auth.example.com/realms/nebulalog`. [Keycloak hostname configuration](https://www.keycloak.org/server/hostname).

Before making federation changes, retain a local administrator with working password and enrolled OTP, and verify a fresh local login in a separate browser session. Preserve the realm's `nebulalog-browser` flow and its required password/OTP executions. Keep provider buttons optional during rollout; do not make a new external provider the default redirect. Store recovery credentials using the operator's existing credential-management process and keep the management route reachable during an IdP outage.

## 2. Create the Microsoft Entra ID application (default Microsoft option)

Use the organization's **workforce tenant**, with a Cloud Application Administrator, Application Administrator, or appropriately delegated application owner. This guide does not require an on-premises domain controller.

1. In the Microsoft Entra admin center, open **Entra ID → Enterprise apps → All applications → New application → Create your own application**. Name it `Captain’s Log`, choose the non-gallery integration option, and create it. Open **Single sign-on → SAML**. [Microsoft enterprise application creation](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups#integrate-your-scim-endpoint-with-the-microsoft-entra-provisioning-service); only the application-creation step applies here, not SCIM provisioning.
2. In **Basic SAML Configuration**, set **Identifier (Entity ID)** to the realm URL above and **Reply URL (Assertion Consumer Service URL)** to the `entra` ACS. Set **Sign on URL** to the public Captain’s Log application URL. Start validation from Captain’s Log so it establishes its OIDC authentication session. Leave Relay State and logout configuration unset until a separate IdP-initiated/logout test is qualified. [Microsoft SAML configuration](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso).
3. In **Attributes & Claims**, edit the unique user identifier: choose **Persistent** format, source `user.objectid`. Add the simple, namespace-free profile claims below. A missing `user.mail` needs an explicit tenant decision; a UPN is not necessarily a routable email address. Keep the immutable NameID independent of the display username and email. [Microsoft SAML claims](https://learn.microsoft.com/en-us/entra/identity-platform/saml-claims-customization).
4. In **SAML Certificates**, select signing for **both response and assertion**, using **SHA-256**. Copy the application's **App Federation Metadata URL**, and retain the signing-certificate fingerprint and expiry in the deployment record. Copy the displayed **Microsoft Entra Identifier**, **Login URL**, and any intended Logout URL; import these values through metadata rather than constructing tenant endpoints. [Microsoft signing options](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/certificate-signing-options).
5. Require assignment in the enterprise application's properties and assign the intended users/groups under **Users and groups**. Add the group claim as described below. Finish the Keycloak provider and MFA sections before granting broader access. [Microsoft assignment control](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal).

| SAML attribute name | Entra source |
|---|---|
| `email` | `user.mail` |
| `firstName` | `user.givenname` |
| `lastName` | `user.surname` |
| `groups` | Assigned application groups, values = group object IDs |

For `groups`, use **Attributes & Claims → Add a group claim → Groups assigned to the application**, source **Group ID**. Under advanced options, customize the claim name to `groups` with no namespace. Record each allowed group's object ID for the Keycloak mapper. Members must be directly assigned through those groups; this mode does not include nested membership. SAML assertions have a 150-group limit, and an overage can omit the group list. Captain’s Log does not resolve a Microsoft Graph overage URL. A missing list must not produce an administrative fallback. Application group assignment requires Microsoft Entra ID P1 or P2; individual assignment plus an explicitly managed Keycloak role is an alternative for a small pilot. [Microsoft group-claim behavior](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims), [assignment prerequisites](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal).

Microsoft Entra ID (formerly Azure AD) is the cloud identity service in this guide. **AD FS** is a separate SAML federation service with its own metadata and certificate rules. **Active Directory over LDAP/LDAPS** is Keycloak user federation, configured under User federation rather than Identity providers. Use [ACTIVE_DIRECTORY.md](ACTIVE_DIRECTORY.md) for that option. Do not substitute an AD FS endpoint or LDAP URL into the Entra metadata field.

## 3. Create the Okta application

1. In Okta Admin Console, open **Applications → Applications → Create App Integration**, select **SAML 2.0**, and name the integration `Captain’s Log`. This creates an app where Okta is the IdP; the separate Okta “Add Identity Provider” workflow is the opposite direction. [Okta SAML application wizard](https://help.okta.com/en-us/Content/Topics/Apps/apps_app_integration_wizard_saml.htm).
2. Set **Single sign-on URL** to the `okta` ACS. Use that same URL for Recipient and Destination. Set **Audience URI (SP Entity ID)** to the Keycloak realm URL. Leave Default RelayState blank for this initial application-initiated flow. Choose **Persistent** Name ID and a **Custom** application username expression of `user.getInternalProperty("id")`, preserving the user's immutable Okta ID. [Okta field reference](https://help.okta.com/en-us/Content/Topics/Apps/aiw-saml-reference.htm), [Okta user-ID expression](https://developer.okta.com/docs/reference/okta-expression-language/#okta-user-id-and-status).
3. Add attribute statements `email=user.email`, `firstName=user.firstName`, and `lastName=user.lastName`. Add a group statement named `groups`, name format Unspecified, with a narrow filter that includes only the approved `NebulaLog-` groups. Use `NebulaLog-Viewers`, `NebulaLog-Analysts`, and `NebulaLog-Administrators` as this guide's suggested group names. [Okta group attribute statements](https://help.okta.com/en-us/Content/Topics/Apps/define-group-attribute-statements.htm).
4. In the SAML advanced settings, sign both **Response** and **Assertion**, using **RSA-SHA256** and a **SHA256** digest. Complete the wizard. In **Sign On**, retrieve the app's IdP metadata URL/XML and its active app-specific signing certificate. Record the IdP issuer and SSO endpoint from that metadata. [Okta SAML fields](https://help.okta.com/en-us/Content/Topics/Apps/aiw-saml-reference.htm), [Okta signing certificates](https://help.okta.com/en-us/Content/Topics/Apps/manage-signing-certificates.htm).
5. Under **Assignments**, assign only the intended pilot groups/users. Apply an app sign-in policy that requires the intended MFA assurance before wider access. Start the first login from Captain’s Log; a dashboard SAML tile that sends an unsolicited response is not the initial acceptance test. A bookmark tile may point to Captain’s Log’s public URL.

A compatibility configuration may use **Unspecified** NameID in both Keycloak and the IdP while retaining the same immutable identifier. Selecting the Persistent format alone does not make an email address immutable. Do not switch an existing linked deployment between email, object ID, and another identifier without an account-migration plan: a changed principal can create a different external identity.

## 4. Import and constrain the Keycloak provider

In the `nebulalog` realm, choose **Identity providers → Add provider → SAML v2.0**. Use alias `entra` or `okta`; display name may be `Microsoft Entra ID` or `Okta`. Import the intended app's trusted IdP metadata. Review the issuer, SSO endpoint, and signing keys before saving. Keep **Identity Provider Entity ID** populated so issuer checking is enabled.

Use these Captain’s Log deployment defaults:

| Keycloak setting | Value / purpose |
|---|---|
| Service Provider Entity ID | The exact realm URL registered at the IdP |
| NameID Policy Format / Principal Type | Persistent / Subject NameID |
| HTTP-POST Binding Response | On; assertions return to the ACS via POST |
| HTTP-POST Binding for AuthnRequest | Off for Redirect binding unless the imported IdP requires POST |
| Validate Signature / Want Assertions Signed | Both On |
| Want AuthnRequests Signed / Signature Algorithm | On / RSA-SHA256; publish the SP verification certificate to the IdP |
| Trust Email | Off initially; enable only for an IdP whose email verification and account-linking policy is understood |
| Store Tokens | Off; Captain’s Log does not need the upstream SAML token |
| First login flow | Retain the normal first-broker-login flow with account ownership verification |
| Post login flow | `nebulalog-broker-mfa`, configured below |

These selections are this project's recommended configuration, not assertions about every vendor's factory defaults. Keycloak's signature, NameID, metadata and binding controls are defined in its [versioned SAML reference](https://github.com/keycloak/keycloak/blob/26.3.3/docs/documentation/server_admin/topics/identity-broker/saml.adoc). For Okta, enable Signed Requests after uploading the SP signing certificate if request-signature validation is required; for Entra, configure the application's request-verification certificate and its verification requirement. Signing a request on Keycloak alone does not prove the IdP validates it. In Entra, **SAML Certificates → Verification certificates → Edit → Require verification certificates** and upload the public SP signing certificate. This disables Entra's portal SSO Test/unsolicited IdP-initiated path; use the flow initiated by Captain’s Log. [Okta request-signature setting](https://help.okta.com/en-us/Content/Topics/Apps/aiw-saml-reference.htm), [Microsoft request-signature verification](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/howto-enforce-signed-saml-authentication).

Do not enable automatic account linking based solely on a matching asserted email. Keep confirmation/re-authentication for an existing account, especially the local recovery administrator. [Keycloak first broker login](https://github.com/keycloak/keycloak/blob/26.3.3/docs/documentation/server_admin/topics/identity-broker/first-login-flow.adoc).

## 5. Map identity attributes and client roles

Under the provider's **Mappers**, create **Attribute Importer** mappers for `email → email`, `firstName → firstName`, and `lastName → lastName`. Use exact attribute Names; leave Friendly Name empty. For stable local usernames, add **Username Template Importer**, target `LOCAL`, template `${ALIAS}.${NAMEID}`. The stable external principal remains Subject NameID; email and names remain editable profile data. [Keycloak attribute importer](https://github.com/keycloak/keycloak/blob/26.3.3/services/src/main/java/org/keycloak/broker/saml/mappers/UserAttributeMapper.java), [username importer](https://github.com/keycloak/keycloak/blob/26.3.3/services/src/main/java/org/keycloak/broker/saml/mappers/UsernameTemplateMapper.java).

Create three **SAML Attribute to Role** mappers. Set Attribute Name `groups`, an exact Attribute Value from the table, and select the role under the **nebulalog client**, not a same-named realm role. Set each role mapper's sync mode override to **Force**.

| Approved IdP value | Keycloak client role | Captain’s Log result |
|---|---|---|
| Entra viewer-group object ID, or Okta `NebulaLog-Viewers` | `nebulalog.VIEWER` | Read/search |
| Entra analyst-group object ID, or Okta `NebulaLog-Analysts` | `nebulalog.ANALYST` | Search/export and own saved filters |
| Entra administrator-group object ID, or Okta `NebulaLog-Administrators` | `nebulalog.ADMINISTRATOR` | Appliance application administration |

These are three explicit mappings, not a rule that turns arbitrary group names into privileges. Do not grant an administrative default or hardcoded role to all federated users. The backend reads `resource_access.nebulalog.roles`, requires audience `nebulalog`, and denies a user without a recognized client role. When multiple listed roles are present, the backend selects ADMINISTRATOR before ANALYST before VIEWER. Captain’s Log ADMINISTRATOR does not itself grant Keycloak realm-management permission.

The mapper matches a specific value within the SAML attribute list; Force mode updates the role on subsequent broker logins, including removal when the condition no longer applies. Test removal as well as assignment. Already issued tokens and existing sessions are a separate revocation concern; force a fresh broker login or revoke the affected sessions when validating a role change. [Keycloak role mapper](https://github.com/keycloak/keycloak/blob/26.3.3/services/src/main/java/org/keycloak/broker/saml/mappers/AttributeToRoleMapper.java), [role update behavior](https://github.com/keycloak/keycloak/blob/26.3.3/services/src/main/java/org/keycloak/broker/saml/mappers/AbstractAttributeToRoleMapper.java).

## 6. Preserve mandatory MFA

The local password-plus-OTP browser flow does **not** automatically prove that a SAML-brokered login used MFA. For the initial deployment, add a separate basic authentication flow named `nebulalog-broker-mfa`, containing **OTP Form** as **Required**, and select it as each provider's **Post login flow**. Keycloak then requests OTP after broker authentication and prompts an unenrolled user to configure it. Leave the existing local flow unchanged. [Keycloak post-login OTP flow](https://github.com/keycloak/keycloak/blob/26.3.3/docs/documentation/server_admin/topics/identity-broker/post-login-flow.adoc).

For Entra, scope a Conditional Access policy to the Captain’s Log enterprise application and intended users, with a required MFA/authentication-strength grant; verify the policy is enabled and the sign-in record shows its result. For Okta Identity Engine, associate an app sign-in policy requiring the chosen factor assurance with this exact application and check all matching rules. Merely enabling MFA methods on a tenant, retaining an IdP browser session, or setting SAML Force Authentication is not evidence of enforced MFA. [Microsoft grant controls](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant), [Okta app sign-in policy](https://help.okta.com/oie/en-us/content/topics/identity-engine/policies/create-auth-policy.htm).

An operator may later qualify upstream-enforced MFA to replace the additional Keycloak OTP for federated users, after testing policy coverage, exclusions, recovery, and reused sessions. Until that is demonstrated, keep the post-login OTP requirement. The local recovery path must continue to require its own MFA during any external-provider change or outage.

## 7. Encryption, certificates, and rotation

TLS remains required. Assertion encryption is an additional setting: configure a suitable **ENC** realm key in Keycloak, export only its public certificate, register it as the IdP's SP encryption certificate, and then enable **Want Assertions Encrypted**. Check the saved SP metadata includes the expected encryption key. Never upload the SP private key to the IdP. In Entra, use **Token encryption → Import Certificate → Activate**; token encryption requires the applicable P1/P2 feature. Okta exposes assertion encryption and encryption-certificate settings in its SAML advanced options. Qualify algorithms with the deployed Keycloak build before requiring encryption. [Microsoft assertion encryption](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/howto-saml-token-encryption), [Okta encryption controls](https://help.okta.com/en-us/Content/Topics/Apps/aiw-saml-reference.htm).

For IdP signing-key rotation, first make the replacement public certificate trusted by Keycloak, retain the old trusted certificate during overlap, activate the new signing key at the IdP, and verify a fresh login before retiring the old trust. Keycloak supports multiple validation certificates and metadata-based key refresh; imported XML/static certificates alone do not establish ongoing refresh. Check the saved metadata-URL option and cache behavior on the deployed version. Okta custom SAML app certificates require administrator-managed renewal; Entra's rollover should be staged before expiry. [Keycloak metadata/key controls](https://github.com/keycloak/keycloak/blob/26.3.3/docs/documentation/server_admin/topics/identity-broker/saml.adoc), [Okta rotation](https://support.okta.com/help/s/article/how-to-rotate-signing-certificate-for-custom-saml-applications?language=en_US), [Entra certificate lifecycle](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tutorial-manage-certificates-for-federated-single-sign-on).

SP request-signing and decryption keys have their own rollout direction: publish the new public SP key to the IdP before switching signing/encryption use, retain the necessary old private decryption key while in-flight assertions remain valid, and record the tested overlap. Keep signing and encryption key purposes distinct.

## 8. Acceptance and troubleshooting

Run each provider's pilot using a fresh private browser session, starting at Captain’s Log. Record the public URLs, provider alias, certificate fingerprints/expiry, selected MFA policy and Keycloak version without recording passwords, private keys, bearer tokens or full assertions.

| Check | Required evidence |
|---|---|
| End-to-end login | IdP authentication returns through the exact ACS, completes MFA, and loads Captain’s Log |
| Identity stability | Repeat login and a display-name/email change retain the intended linked identity |
| Least privilege | Viewer cannot export/administer; analyst cannot administer; unmapped user is denied |
| Role removal | Remove pilot membership, revoke/expire sessions as appropriate, fresh broker login loses access |
| Negative assertion tests | Invalid signature, wrong issuer/audience/recipient, expired assertion and replay rejected in an isolated test setup |
| Recovery | Fresh local administrator password+OTP login succeeds while the external provider is unavailable |
| Rotation / logout | Fresh login works with new keys; logout and session reuse behave as documented for both systems |

Use Keycloak login events plus the corresponding Entra sign-in logs or Okta System Log to locate the failed boundary. “Application not found” or audience errors usually point to a mismatched entity ID; reply/recipient errors point to the ACS, HTTPS scheme, proxy host or alias. Signature errors require comparing the active signing key and imported trust. A NameID error needs matching format and principal value. A successful SAML response followed by API 403 requires inspecting **client-scoped** role mapping and audience. Missing Entra groups require checking assignment, direct membership and overage. Time-condition errors require checking NTP before widening clock skew. A failed dashboard tile with a working application-initiated login may be an unqualified unsolicited/IdP-initiated flow, not an incorrect ACS.

## Appliance configuration service

Administrators can upload IdP XML metadata through the appliance's identity-provider API. Configuration uses the dedicated confidential `nebulalog-identity-manager` Keycloak client with only `manage-identity-providers`, `view-identity-providers`, and `view-realm`; the application does not use a master/realm-administrator credential. Root-level realm changes and the required `nebulalog-broker-mfa` flow are provisioned separately. No users or active sessions are managed by this client.

`GET /api/identity/providers` lists Entra and Okta configuration. `POST /api/identity/providers/{alias}/preview` validates uploaded metadata and derives the public SP values without contacting the IdP. `PUT /api/identity/providers/{alias}` saves an explicit `metadata_xml`, `groups` object with `viewer`/`analyst`/`administrator`, and `enabled` flag. Omitted `enabled` means disabled. `POST /api/identity/providers/{alias}/test` checks saved configuration, exact mappers, current signing certificates, and the actual required OTP execution; it always reports `external_login_tested=false`.

`PATCH /api/identity/providers/{alias}/state` accepts only an explicit boolean `enabled`. Disabling an app-managed SAML provider requires no metadata upload and succeeds even with expired or malformed signing certificates, invalid mappings, or an unavailable broker MFA flow. The service preserves the current configuration and verifies that Keycloak actually stored the disabled state. Re-enabling first validates the saved certificates, signature settings, exact mappers and required OTP execution; it stages and verifies a disabled operation, enables last, and verifies everything again. Failure cleanup disables only the matching operation and reports uncertainty if a disabled state cannot be confirmed. A state change does not revoke existing sessions or tokens.

Identity writes require `IDENTITY_ENABLE_WRITES=true`. `IDENTITY_ALLOW_HTTP` permits explicitly configured development Keycloak backchannel/public URLs; the independent `IDENTITY_ALLOW_METADATA_HTTP` controls IdP endpoint acceptance and should remain false for HTTPS IdP metadata. The public base URL is separate from the internal Keycloak service address, preventing an internal container hostname from becoming the SP audience or browser callback.

Metadata uploads are capped at 256 KiB and parsed locally. The service rejects DTD/entity directives, XInclude, external XML references, multiple roots, ambiguous IdP descriptors, excessive nesting, unsupported signing keys and invalid certificate/metadata validity. No URL supplied inside the upload is fetched. IdP service URLs must be absolute HTTPS URLs without embedded credentials or fragments by default. Uploaded metadata certificates are static trust: certificate rotation requires a new upload. Expired configured certificates remain inspectable, with dates and a `currently_valid` flag, so the operator can repair them; preview/validation reject them for a new save.

A save first verifies the required broker OTP flow and refuses an unrelated provider or unmanaged mappers at the reserved alias. It disables an existing app-owned provider, replaces all seven owned mappers (three exact FORCE role mappings, three profile attributes, one stable username importer), rereads and verifies them, and enables the provider **last**, only when explicitly requested. After a partial failure, cleanup identifies the current operation using a random marker, disables only that operation's provider, and rereads the result before reporting that it is disabled. If the state cannot be confirmed, the API reports that uncertainty. A concurrent create conflict never authorizes overwriting another provider.

Keycloak's alias-based update API has no atomic compare-and-swap operation. Saves are serialized within one manager process and obvious external changes are checked before mutation; the supported operational model is **one configuration-manager instance and no simultaneous manual edits of its managed aliases**. This is not distributed transaction isolation. The service cannot revoke existing sessions/tokens; role changes are evaluated on later broker logins. Retain the local MFA recovery administrator through configuration changes.

Local validation on 2026-09-07 used the real Keycloak 26.3.3 container and the restricted service account to create a temporary **disabled** `okta` fixture, save seven mappers, verify the required OTP flow, update one group, reread the configuration, and remove the fixture. No external tenant was contacted and no external SAML login was performed. Unit/HTTP-server tests additionally cover unsafe XML, exact role/MFA checks, failure cleanup, concurrent create conflicts, expired-certificate inspection, bounded upstream responses, and redirect refusal. State-control tests cover emergency disable with expired/malformed certificates and broken MFA, preservation of unmodeled Keycloak fields, enable rejection for unsafe token/default-authentication grants, changed settings after enable, ambiguous update responses, cleanup ownership conflicts, and successful HTTP responses that did not persist the requested state.
