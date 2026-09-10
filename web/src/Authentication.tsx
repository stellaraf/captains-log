import { useState } from "react";
import { ArrowUpRight, Check, Copy, KeyRound, ShieldCheck } from "lucide-react";
import type { Config, User } from "./types";
import { IdentityProvider } from "./IdentityProvider";
const kc =
  "https://github.com/keycloak/keycloak/blob/26.3.3/docs/documentation/server_admin/topics/identity-broker/";
export function Authentication({
  config,
  user,
}: {
  config: Config;
  user: User;
}) {
  const [view, setView] = useState(
    new URLSearchParams(location.search).get("view") || "guide",
  );
  const [provider, setProvider] = useState<"entra" | "okta">(
    new URLSearchParams(location.search).get("provider") === "okta"
      ? "okta"
      : "entra",
  );
  const [copied, setCopied] = useState("");
  const base = config.auth.url.replace(/\/$/, "");
  const realm = `${base}/realms/${encodeURIComponent(config.auth.realm)}`;
  const acs = `${realm}/broker/${provider}/endpoint`;
  const development =
    !base.startsWith("https://") ||
    ["localhost", "127.0.0.1", "[::1]"].includes(new URL(base).hostname);
  const isEntra = provider === "entra";
  const providerName = isEntra ? "Microsoft Entra ID" : "Okta";
  const sections = [
    ["prepare", "1. Prepare public URLs"],
    ["provider-app", "2. Create the IdP app"],
    ["trust", "3. Establish trust"],
    ["claims", "4. Map claims & roles"],
    ["mfa", "5. Require MFA"],
    ["rotation", "6. Certificates & rotation"],
    ["verify", "7. Test & troubleshoot"],
  ];
  function choose(next: "entra" | "okta") {
    setProvider(next);
    setCopied("");
    const p = new URLSearchParams(location.search);
    p.set("provider", next);
    history.replaceState({}, "", `${location.pathname}?${p}`);
  }
  function Value({ label, value }: { label: string; value: string }) {
    return (
      <div className="sp-value">
        <div>
          <span>{label}</span>
          <code>{value}</code>
        </div>
        <button
          className="icon-button"
          aria-label={`Copy ${label}`}
          title={`Copy ${label}`}
          onClick={() =>
            void navigator.clipboard
              .writeText(value)
              .then(() => setCopied(`${label} copied.`))
              .catch(() =>
                setCopied("Clipboard unavailable. Select and copy the value."),
              )
          }
        >
          <Copy size={14} />
        </button>
      </div>
    );
  }
  return (
    <div className="admin-workspace authentication-page">
      <div className="authentication-intro">
        <span className="resource-icon">
          <KeyRound size={23} />
        </span>
        <div>
          <h2>Connect your identity provider</h2>
          <p>
            Use Microsoft Entra ID or Okta for SAML single sign-on. Keycloak
            brokers the identity and enforces the appliance’s access rules. Keep
            a local administrator with working password and OTP available
            throughout setup.
          </p>
        </div>
      </div>
      <div className="provider-picker" aria-label="SAML provider guides">
        <button
          className={isEntra ? "selected" : ""}
          aria-pressed={isEntra}
          onClick={() => choose("entra")}
        >
          <span className="provider-monogram entra" aria-hidden="true">
            <i />
            <i />
            <i />
            <i />
          </span>
          <span>
            <strong>Microsoft Entra ID</strong>
            <small>Workforce tenant · formerly Azure AD</small>
          </span>
        </button>
        <button
          className={!isEntra ? "selected" : ""}
          aria-pressed={!isEntra}
          onClick={() => choose("okta")}
        >
          <span className="provider-monogram" aria-hidden="true">
            O
          </span>
          <span>
            <strong>Okta</strong>
            <small>SAML 2.0 application integration</small>
          </span>
        </button>
      </div>
      <nav className="section-tabs" aria-label="Authentication sections">
        {[
          ["guide", "Setup guide"],
          ["configuration", "Provider configuration"],
        ].map(([key, label]) => (
          <a
            key={key}
            href={`${location.pathname}?${new URLSearchParams({ provider, view: key })}`}
            aria-current={view === key ? "page" : undefined}
            onClick={(e) => {
              if (!e.metaKey && !e.ctrlKey) {
                e.preventDefault();
                setView(key);
                const p = new URLSearchParams(location.search);
                p.set("view", key);
                history.replaceState({}, "", `${location.pathname}?${p}`);
              }
            }}
          >
            {label}
          </a>
        ))}
      </nav>
      {view === "configuration" ? (
        user.role === "ADMINISTRATOR" ? (
          <IdentityProvider key={provider} alias={provider} />
        ) : (
          <div className="notice">
            An administrator can configure identity providers. The setup guide
            is available to your account.
          </div>
        )
      ) : (
        <div className="guide-layout">
          <div>
            <div className="notice">
              <ShieldCheck size={17} />
              <span>
                This guide derives SP values from the current appliance
                configuration. It does not establish that an external provider
                is configured or that sign-in has been tested.
              </span>
            </div>
            <section className="guide-section" id="prepare">
              <h3>1. Prepare public URLs and recovery access</h3>
              <p>
                Set the stable public HTTPS hostname of Keycloak before
                registering an application. Its realm URL is the{" "}
                <strong>SAML service provider entity ID</strong>. The callback
                is specific to the provider alias <code>{provider}</code>. Keep
                this alias stable after users are linked.
              </p>
              {development && (
                <div className="notice warning">
                  Development URLs detected. These values reflect this local
                  installation. Configure a public, browser-reachable HTTPS
                  identity hostname before using an external production tenant.
                </div>
              )}
              <div className="sp-values">
                <Value label="SP entity ID / audience" value={realm} />
                <Value
                  label={
                    isEntra ? "Reply URL / ACS" : "Single sign-on URL / ACS"
                  }
                  value={acs}
                />
                <Value
                  label="SP metadata (after provider is saved)"
                  value={`${acs}/descriptor`}
                />
                <Value
                  label="Application sign-on URL"
                  value={location.origin}
                />
              </div>
              <div className="copy-feedback" role="status">
                {copied}
              </div>
              <p>
                The entity ID is the realm URL, not the callback, metadata URL
                or OIDC client ID. Register these exact values and compare them
                with the saved SP descriptor. Captain’s Log continues to use its
                existing OIDC client <code>{config.auth.client_id}</code>; a
                second SAML client in Keycloak is unnecessary.
              </p>
              <p>
                Verify a fresh local administrator login with password and OTP
                in a separate browser session. Keep provider selection optional
                during rollout and preserve local recovery access during an IdP
                outage.
              </p>
              <p className="guide-source">
                <a
                  href="https://www.keycloak.org/server/hostname"
                  target="_blank"
                  rel="noreferrer"
                >
                  Keycloak hostname configuration ↗
                </a>
                <a href={`${kc}saml.adoc`} target="_blank" rel="noreferrer">
                  SAML broker reference ↗
                </a>
              </p>
            </section>
            <section className="guide-section" id="provider-app">
              <h3>2. Create the {providerName} application</h3>
              {isEntra ? (
                <ol>
                  <li>
                    In the Microsoft Entra admin center, open{" "}
                    <strong>
                      Entra ID → Enterprise apps → All applications → New
                      application → Create your own application
                    </strong>
                    . Name it Captain’s Log and choose the non-gallery integration
                    option. Open <strong>Single sign-on → SAML</strong>.
                  </li>
                  <li>
                    In <strong>Basic SAML Configuration</strong>, set Identifier
                    (Entity ID) to the realm URL above, Reply URL to the Entra
                    ACS, and Sign on URL to the public Captain’s Log URL. Leave
                    Relay State and logout configuration unset until separately
                    tested.
                  </li>
                  <li>
                    In <strong>Attributes & Claims</strong>, use a{" "}
                    <strong>Persistent</strong> unique user identifier sourced
                    from <code>user.objectid</code>. Add the profile and groups
                    claims below. A missing <code>user.mail</code> needs a
                    tenant-specific decision; a UPN is not necessarily a
                    routable email address.
                  </li>
                  <li>
                    In <strong>SAML Certificates</strong>, sign{" "}
                    <strong>both response and assertion</strong> with{" "}
                    <strong>SHA-256</strong>. Obtain the app’s Federation
                    Metadata XML from the displayed metadata URL. Record its
                    issuer, signing-certificate fingerprint and expiry.
                  </li>
                  <li>
                    Require assignment in the application properties. Assign
                    only the intended pilot users/groups under{" "}
                    <strong>Users and groups</strong>. Configure MFA and verify
                    role access before wider assignment.
                  </li>
                </ol>
              ) : (
                <ol>
                  <li>
                    In Okta Admin Console, open{" "}
                    <strong>
                      Applications → Applications → Create App Integration →
                      SAML 2.0
                    </strong>
                    . Name the application Captain’s Log. This is an application
                    integration where Okta is the IdP.
                  </li>
                  <li>
                    Set <strong>Single sign-on URL</strong>, Recipient and
                    Destination to the Okta ACS above. Set{" "}
                    <strong>Audience URI (SP Entity ID)</strong> to the realm
                    URL. Leave Default RelayState blank for the first
                    application-initiated test.
                  </li>
                  <li>
                    Choose <strong>Persistent</strong> Name ID and Custom
                    application username expression{" "}
                    <code>{'user.getInternalProperty("id")'}</code>. Keep the
                    immutable Okta ID as the principal; names and email remain
                    profile fields.
                  </li>
                  <li>
                    Add profile attributes and a <code>groups</code> statement
                    as shown below. Use a narrow filter for approved{" "}
                    <code>NebulaLog-</code> groups.
                  </li>
                  <li>
                    In SAML advanced settings, sign{" "}
                    <strong>both Response and Assertion</strong> with{" "}
                    <strong>RSA-SHA256</strong> and a <strong>SHA256</strong>{" "}
                    digest. Finish the wizard, retrieve the app-specific
                    metadata XML and active signing certificate from{" "}
                    <strong>Sign On</strong>, and assign only intended pilot
                    users/groups.
                  </li>
                </ol>
              )}
              <p className="guide-source">
                {isEntra ? (
                  <>
                    <a
                      href="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Entra SAML setup ↗
                    </a>
                    <a
                      href="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/certificate-signing-options"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Signing options ↗
                    </a>
                  </>
                ) : (
                  <>
                    <a
                      href="https://help.okta.com/en-us/Content/Topics/Apps/apps_app_integration_wizard_saml.htm"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Okta application wizard ↗
                    </a>
                    <a
                      href="https://help.okta.com/en-us/Content/Topics/Apps/aiw-saml-reference.htm"
                      target="_blank"
                      rel="noreferrer"
                    >
                      SAML settings reference ↗
                    </a>
                  </>
                )}
              </p>
            </section>
            <section className="guide-section" id="trust">
              <h3>3. Establish and review trust</h3>
              <p>
                In the <code>{config.auth.realm}</code> realm, open{" "}
                <strong>Identity providers → Add provider → SAML v2.0</strong>,
                using alias <code>{provider}</code>. Import only this
                application’s trusted IdP metadata. Compare the issuer, SSO
                endpoint and public signing certificates with the source before
                saving.
              </p>
              <div
                className="panel-table-scroll"
                role="region"
                aria-label="Keycloak SAML settings"
                tabIndex={0}
              >
                <table className="guide-table">
                  <thead>
                    <tr>
                      <th>Setting</th>
                      <th>Required deployment value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      [
                        "Provider entity ID",
                        "Keep the imported issuer populated for issuer validation.",
                      ],
                      [
                        "SP entity ID",
                        "Exact realm URL registered at the IdP.",
                      ],
                      ["NameID / principal", "Persistent / Subject NameID."],
                      [
                        "Response binding",
                        "HTTP-POST. AuthnRequests use Redirect unless the imported IdP requires POST.",
                      ],
                      [
                        "Validate Signature / Want Assertions Signed",
                        "Both on.",
                      ],
                      [
                        "Want AuthnRequests Signed",
                        "On, RSA-SHA256. Publish the public SP verification certificate to the IdP.",
                      ],
                      [
                        "Trust Email / Store Tokens",
                        "Off initially. Do not automatically link accounts by email.",
                      ],
                      [
                        "First login / Post login flow",
                        "Preserve first-broker-login ownership verification / nebulalog-broker-mfa.",
                      ],
                    ].map(([a, b]) => (
                      <tr key={a}>
                        <td>{a}</td>
                        <td>{b}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p>
                {isEntra ? (
                  <>
                    <strong>Entra request verification:</strong> open SAML
                    Certificates → Verification certificates → Edit → Require
                    verification certificates, then upload the public SP signing
                    certificate. This disables Entra’s portal SSO Test and
                    unsolicited IdP-initiated flow; test from Captain’s Log.
                  </>
                ) : (
                  <>
                    <strong>Okta request verification:</strong> upload the
                    public SP signing certificate and enable Signed Requests in
                    the SAML advanced settings. Sending a signed request from
                    Keycloak alone does not prove Okta validates it.
                  </>
                )}
              </p>
              <p>
                Keep the provider disabled while reviewing its trust and
                mappings. Saving metadata is configuration acceptance; a fresh
                end-to-end login is a separate test. A metadata XML import does
                not establish automatic signing-key refresh.
              </p>
              <a
                className="button"
                href={`${base}/admin/`}
                target="_blank"
                rel="noreferrer"
              >
                Open Keycloak administration <ArrowUpRight size={14} />
              </a>
              <p className="guide-source">
                <a
                  href={
                    isEntra
                      ? "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/howto-enforce-signed-saml-authentication"
                      : "https://help.okta.com/en-us/Content/Topics/Apps/aiw-saml-reference.htm"
                  }
                  target="_blank"
                  rel="noreferrer"
                >
                  Request-signature verification ↗
                </a>
                <a
                  href={`${kc}first-login-flow.adoc`}
                  target="_blank"
                  rel="noreferrer"
                >
                  Account ownership and linking ↗
                </a>
              </p>
            </section>
            <section className="guide-section" id="claims">
              <h3>4. Map profile claims and explicit roles</h3>
              <p>
                Use simple, namespace-free claim names. In Keycloak, create{" "}
                <strong>Attribute Importer</strong> mappers to the matching
                profile properties. Add a{" "}
                <strong>Username Template Importer</strong> with target LOCAL
                and template <code>{"${ALIAS}.${NAMEID}"}</code> for stable
                local usernames.
              </p>
              <div
                className="panel-table-scroll"
                role="region"
                aria-label="SAML profile claims"
                tabIndex={0}
              >
                <table className="guide-table">
                  <thead>
                    <tr>
                      <th>Attribute name</th>
                      <th>{providerName} source</th>
                      <th>Keycloak property</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      ["email", isEntra ? "user.mail" : "user.email", "email"],
                      [
                        "firstName",
                        isEntra ? "user.givenname" : "user.firstName",
                        "firstName",
                      ],
                      [
                        "lastName",
                        isEntra ? "user.surname" : "user.lastName",
                        "lastName",
                      ],
                      [
                        "groups",
                        isEntra
                          ? "Assigned application groups · Group ID"
                          : "Approved NebulaLog- group names",
                        "Exact role mappings below",
                      ],
                    ].map(([a, b, c]) => (
                      <tr key={a}>
                        <td>
                          <code>{a}</code>
                        </td>
                        <td>
                          <code>{b}</code>
                        </td>
                        <td>{c}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {isEntra ? (
                <p>
                  Choose <strong>Groups assigned to the application</strong>,
                  source <strong>Group ID</strong>, and customize the claim name
                  to <code>groups</code> with no namespace. Use group object
                  IDs, not display names. This mode requires direct membership
                  and applicable P1/P2 licensing. The SAML limit is 150 groups;
                  Captain’s Log does not resolve Microsoft Graph overage links.
                  Missing groups must not grant administrative access.
                </p>
              ) : (
                <p>
                  Create a <code>groups</code> statement with Unspecified name
                  format and a narrow filter covering only approved application
                  groups. Compatible group names are <code>NebulaLog-Viewers</code>,{" "}
                  <code>NebulaLog-Analysts</code>, and{" "}
                  <code>NebulaLog-Administrators</code>.
                  These identifiers retain the earlier product name; preserve
                  existing group values and mappings when updating the app name.
                </p>
              )}
              <p>
                Create three <strong>SAML Attribute to Role</strong> mappers.
                Attribute Name is <code>groups</code>; Attribute Value is one
                exact approved group value. Select the role under the{" "}
                <strong>{config.auth.client_id} client</strong> and set sync
                override to <strong>Force</strong>.
              </p>
              <div
                className="panel-table-scroll"
                role="region"
                aria-label="SAML role mappings"
                tabIndex={0}
              >
                <table className="guide-table">
                  <thead>
                    <tr>
                      <th>Approved group value</th>
                      <th>Client role</th>
                      <th>Access</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      [
                        isEntra
                          ? "Viewer-group object ID"
                          : "NebulaLog-Viewers",
                        "VIEWER",
                        "Read and search",
                      ],
                      [
                        isEntra
                          ? "Analyst-group object ID"
                          : "NebulaLog-Analysts",
                        "ANALYST",
                        "Search, export and own saved filters",
                      ],
                      [
                        isEntra
                          ? "Administrator-group object ID"
                          : "NebulaLog-Administrators",
                        "ADMINISTRATOR",
                        "Appliance application administration",
                      ],
                    ].map(([group, role, access]) => (
                      <tr key={role}>
                        <td>{group}</td>
                        <td>
                          <code>
                            {config.auth.client_id}.{role}
                          </code>
                        </td>
                        <td>{access}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p>
                An unmapped identity has no application role. Never grant a
                hardcoded administrative default. Force sync updates mappings on
                a subsequent broker login; already-issued tokens and sessions
                need separate revocation. Test role removal with a fresh login.
                Application administration does not grant Keycloak
                realm-management permission.
              </p>
              <p className="guide-source">
                <a
                  href={
                    isEntra
                      ? "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims"
                      : "https://help.okta.com/en-us/Content/Topics/Apps/define-group-attribute-statements.htm"
                  }
                  target="_blank"
                  rel="noreferrer"
                >
                  Provider group claims ↗
                </a>
                <a
                  href="https://github.com/keycloak/keycloak/blob/26.3.3/services/src/main/java/org/keycloak/broker/saml/mappers/AttributeToRoleMapper.java"
                  target="_blank"
                  rel="noreferrer"
                >
                  Keycloak exact role matching ↗
                </a>
              </p>
            </section>
            <section className="guide-section" id="mfa">
              <h3>5. Require MFA after broker authentication</h3>
              <div className="notice warning">
                The local password and OTP flow does not by itself prove that a
                federated SAML login used MFA.
              </div>
              <p>
                Use a separate basic Keycloak authentication flow named{" "}
                <code>nebulalog-broker-mfa</code>, containing{" "}
                <strong>OTP Form</strong> as <strong>Required</strong>. Select
                it as this provider’s Post login flow. An unenrolled user must
                configure OTP. Preserve the existing local browser flow.
              </p>
              <p>
                {isEntra
                  ? "Scope a Conditional Access policy to this enterprise application and intended users with the required MFA or authentication-strength grant. Verify that the policy is enabled and the sign-in log shows its result."
                  : "Associate an Okta Identity Engine app sign-in policy with this exact application and require the intended factor assurance. Inspect every matching rule and verify the System Log result."}
              </p>
              <p>
                Enabling MFA methods at tenant level, reusing a browser session,
                or setting Force Authentication is not proof of policy
                enforcement. Keep the additional Keycloak OTP until upstream
                MFA, exclusions, recovery and reused sessions have been
                qualified.
              </p>
              <p className="guide-source">
                <a
                  href={`${kc}post-login-flow.adoc`}
                  target="_blank"
                  rel="noreferrer"
                >
                  Keycloak post-login OTP ↗
                </a>
                <a
                  href={
                    isEntra
                      ? "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant"
                      : "https://help.okta.com/oie/en-us/content/topics/identity-engine/policies/create-auth-policy.htm"
                  }
                  target="_blank"
                  rel="noreferrer"
                >
                  {providerName} MFA policy ↗
                </a>
              </p>
            </section>
            <section className="guide-section" id="rotation">
              <h3>6. Encryption and certificate rotation</h3>
              <p>
                <strong>Signing-key rotation:</strong> trust the replacement
                public IdP certificate in Keycloak before activation, retain the
                old trusted key during overlap, activate the new signing key,
                verify a fresh login, and then retire the old trust. Record
                fingerprints and expiry. Static XML alone does not establish
                recurring refresh; re-import reviewed metadata when keys change.
              </p>
              <p>
                <strong>Assertion encryption:</strong> this is additional to
                TLS. Configure a suitable ENC realm key, publish only its public
                certificate to the IdP, and then enable Want Assertions
                Encrypted. Qualify algorithms with the deployed Keycloak build.{" "}
                {isEntra
                  ? "In Entra, use Token encryption → Import Certificate → Activate; applicable P1/P2 licensing is required."
                  : "In Okta, use assertion encryption and certificate settings in the SAML advanced options."}{" "}
                Never upload a private SP key to the IdP.
              </p>
              <p>
                Request-signing and decryption keys have their own rollout:
                publish new public SP keys before switching use and retain old
                decryption keys while in-flight assertions remain valid. Keep
                key purposes distinct.
              </p>
              <p className="guide-source">
                <a
                  href={
                    isEntra
                      ? "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tutorial-manage-certificates-for-federated-single-sign-on"
                      : "https://help.okta.com/en-us/Content/Topics/Apps/manage-signing-certificates.htm"
                  }
                  target="_blank"
                  rel="noreferrer"
                >
                  Signing certificate lifecycle ↗
                </a>
                <a
                  href={
                    isEntra
                      ? "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/howto-saml-token-encryption"
                      : "https://help.okta.com/en-us/Content/Topics/Apps/aiw-saml-reference.htm"
                  }
                  target="_blank"
                  rel="noreferrer"
                >
                  Assertion encryption ↗
                </a>
              </p>
            </section>
            <section className="guide-section" id="verify">
              <h3>7. Verify before broad access</h3>
              <p>
                Start each pilot in a fresh private browser session at
                Captain’s Log. Record public URLs, alias, certificate fingerprints
                and expiry, MFA policy and Keycloak version. Avoid storing
                passwords, private keys, tokens or full assertions in test
                evidence.
              </p>
              <ul className="guide-checks">
                {[
                  "Complete IdP authentication, exact ACS return, mandatory MFA and a loaded Captain’s Log page.",
                  "Confirm repeat login and a display-name/email change retain the intended linked identity.",
                  "Verify viewer, analyst and administrator boundaries; an unmapped user must be denied.",
                  "Remove pilot membership, revoke or expire sessions, and confirm fresh login loses the role.",
                  "Reject invalid signatures, wrong issuer/audience/recipient, expiry and replay in an isolated test setup.",
                  "Verify local password-plus-OTP recovery while the external provider is unavailable.",
                  "Test new signing keys, application logout and session reuse independently.",
                ].map((text) => (
                  <li key={text}>
                    <Check size={15} />
                    <span>{text}</span>
                  </li>
                ))}
              </ul>
              <div
                className="panel-table-scroll"
                role="region"
                aria-label="SAML troubleshooting"
                tabIndex={0}
              >
                <table className="guide-table">
                  <thead>
                    <tr>
                      <th>Observed failure</th>
                      <th>Check next</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      [
                        "Application / audience error",
                        "Compare the exact realm entity ID with the IdP registration.",
                      ],
                      [
                        "Reply URL / recipient error",
                        "Compare ACS, alias, public HTTPS scheme and proxy hostname.",
                      ],
                      [
                        "Signature failure",
                        "Compare active IdP signing certificate with imported trust; confirm response and assertion signing.",
                      ],
                      [
                        "NameID / duplicate identity",
                        "Match format and immutable principal. Do not silently change an existing deployment’s identifier.",
                      ],
                      [
                        "SAML succeeds, API returns 403",
                        "Check client-scoped role mapping and OIDC audience; realm roles are not interchangeable.",
                      ],
                      [
                        "Missing Entra groups",
                        "Check assigned application groups, direct membership, exact object IDs and overage.",
                      ],
                      [
                        "Expired / future assertion",
                        "Verify time synchronization before widening clock skew.",
                      ],
                      [
                        "Dashboard tile fails",
                        "Test from Captain’s Log; unsolicited IdP-initiated login requires separate qualification.",
                      ],
                    ].map(([a, b]) => (
                      <tr key={a}>
                        <td>{a}</td>
                        <td>{b}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p>
                Correlate Keycloak login events with{" "}
                {isEntra ? "Entra sign-in logs" : "Okta System Log"} to identify
                where authentication failed. A successful configuration save is
                not proof that any of these checks passed.
              </p>
            </section>
            <section className="guide-section">
              <h3>Other identity systems</h3>
              <p>
                AD FS uses a separate SAML application and its own trusted
                metadata. Active Directory over LDAP/LDAPS is configured in
                Keycloak <strong>User federation</strong>, not as an Entra SAML
                provider. For another SAML IdP, use a stable alias, the same SP
                URL pattern, explicit role mapping and required post-login MFA.
                Its signature, principal, logout and recovery behavior require
                separate qualification.
              </p>
              <a
                href="https://www.keycloak.org/docs/latest/server_admin/#_user-storage-federation"
                target="_blank"
                rel="noreferrer"
              >
                Keycloak user federation documentation ↗
              </a>
            </section>
          </div>
          <aside
            className="guide-toc"
            aria-label="Authentication guide contents"
          >
            <h3>Setup guide</h3>
            {sections.map(([id, label]) => (
              <a key={id} href={`#${id}`}>
                {label}
              </a>
            ))}
            <div className="guide-scope">
              <strong>{providerName}</strong>
              <br />
              Alias <code>{provider}</code>
              <br />
              Guide verified against Keycloak 26.3.3.
              <br />
              <br />
              Provider status and external sign-in evidence are separate from
              these instructions.
            </div>
          </aside>
        </div>
      )}
    </div>
  );
}
