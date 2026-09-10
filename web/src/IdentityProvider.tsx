import { useEffect, useRef, useState } from "react";
import { Check, FileUp, RefreshCw, ShieldCheck } from "lucide-react";
import { api, json } from "./api";
import { ErrorNotice, Loading, Modal } from "./components";
import { timestamp } from "./utils";
interface GroupMapping {
  viewer: string;
  analyst: string;
  administrator: string;
}
interface Certificate {
  sha256: string;
  subject: string;
  not_before: string;
  not_after: string;
  currently_valid?: boolean;
}
interface Provider {
  alias: string;
  configured: boolean;
  managed: boolean;
  enabled: boolean;
  display_name: string;
  entity_id: string;
  sso_url: string;
  sp_entity_id: string;
  acs_url: string;
  metadata_url: string;
  groups: GroupMapping;
  certificates: Certificate[];
  external_login_tested: boolean;
}
interface Preview extends Provider {
  warnings: string[];
}
interface TestStatus {
  configured: boolean;
  configuration_valid: boolean;
  external_login_tested: boolean;
  status: string;
  message: string;
  checked_at: string;
}
interface Draft {
  metadata_xml: string;
  groups: GroupMapping;
  enabled: boolean;
}
const emptyGroups: GroupMapping = {
  viewer: "",
  analyst: "",
  administrator: "",
};
export function IdentityProvider({ alias }: { alias: "entra" | "okta" }) {
  const alive = useRef(true);
  const generation = useRef(0);
  const readController = useRef<AbortController | undefined>(undefined);
  const [provider, setProvider] = useState<Provider>();
  const [available, setAvailable] = useState<boolean>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [draft, setDraft] = useState<Draft>({
    metadata_xml: "",
    groups: emptyGroups,
    enabled: false,
  });
  const [preview, setPreview] = useState<Preview>();
  const [reviewDraft, setReviewDraft] = useState<Draft>();
  const [test, setTest] = useState<TestStatus>();
  const [stateReview, setStateReview] = useState<boolean | null>(null);
  async function load() {
    const current = ++generation.current;
    readController.current?.abort();
    const controller = new AbortController();
    readController.current = controller;
    setPreview(undefined);
    setReviewDraft(undefined);
    setTest(undefined);
    setStateReview(null);
    setBusy(true);
    setError("");
    try {
      const list = await api<{ available: boolean; providers: Provider[] }>(
        "/api/identity/providers",
        { signal: controller.signal },
      );
      if (!alive.current || current !== generation.current) return;
      setAvailable(list.available);
      if (list.available) {
        const { provider: p } = await api<{ provider: Provider }>(
          `/api/identity/providers/${alias}`,
          { signal: controller.signal },
        );
        if (!alive.current || current !== generation.current) return;
        setProvider(p);
        setDraft({
          metadata_xml: "",
          groups: p.groups || emptyGroups,
          enabled: p.enabled || false,
        });
      }
    } catch (e) {
      if (
        alive.current &&
        current === generation.current &&
        (e as Error).name !== "AbortError"
      )
        setError((e as Error).message);
    } finally {
      if (alive.current && current === generation.current) setBusy(false);
    }
  }
  useEffect(() => {
    alive.current = true;
    void load();
    return () => {
      alive.current = false;
      generation.current++;
      readController.current?.abort();
    };
  }, [alias]);
  const update = (change: Partial<Draft>) => {
    setDraft({ ...draft, ...change });
    setPreview(undefined);
    setReviewDraft(undefined);
    setNotice("");
  };
  const external = provider?.configured && !provider?.managed;
  async function previewConfiguration() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (new TextEncoder().encode(draft.metadata_xml).byteLength > 262144)
        throw new Error("Metadata must be at most 256 KiB.");
      const r = await api<{ preview: Preview }>(
        `/api/identity/providers/${alias}/preview`,
        json("POST", draft),
      );
      if (!alive.current) return;
      if (r.preview.alias !== alias)
        throw new Error(
          "Provider preview alias did not match the requested provider.",
        );
      setPreview(r.preview);
      setReviewDraft(structuredClone(draft));
    } catch (e) {
      if (alive.current && (e as Error).name !== "AbortError")
        setError((e as Error).message);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function save() {
    if (!preview || !reviewDraft || preview.alias !== alias) return;
    setBusy(true);
    setError("");
    try {
      const r = await api<{ provider: Provider }>(
        `/api/identity/providers/${alias}`,
        json("PUT", reviewDraft),
      );
      if (!alive.current) return;
      setProvider(r.provider);
      setDraft({
        metadata_xml: "",
        groups: r.provider.groups || emptyGroups,
        enabled: r.provider.enabled,
      });
      setPreview(undefined);
      setReviewDraft(undefined);
      setTest(undefined);
      setNotice(
        `Provider configuration saved ${r.provider.enabled ? "and enabled" : "with sign-in disabled"}. External sign-in and MFA still require a fresh pilot login.`,
      );
    } catch (e) {
      if (alive.current && (e as Error).name !== "AbortError")
        setError((e as Error).message);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function check() {
    setBusy(true);
    setError("");
    try {
      const r = await api<{ status: TestStatus }>(
        `/api/identity/providers/${alias}/test`,
        { method: "POST" },
      );
      if (alive.current) setTest(r.status);
    } catch (e) {
      if (alive.current && (e as Error).name !== "AbortError")
        setError((e as Error).message);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function changeState() {
    if (stateReview === null || !provider?.configured || !provider.managed)
      return;
    const enabled = stateReview;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const r = await api<{ provider: Provider }>(
        `/api/identity/providers/${alias}/state`,
        json("PATCH", { enabled }),
      );
      if (!alive.current) return;
      if (r.provider.alias !== alias || r.provider.enabled !== enabled)
        throw new Error(
          "The requested provider state could not be confirmed. Refresh before retrying.",
        );
      setProvider(r.provider);
      setDraft((old) => ({ ...old, enabled: r.provider.enabled }));
      setStateReview(null);
      setTest(undefined);
      setNotice(
        enabled
          ? "Provider sign-in enabled. External sign-in and MFA still require a fresh pilot login."
          : "Provider sign-in disabled. Existing sessions are not automatically revoked.",
      );
    } catch (e) {
      if (alive.current) setError((e as Error).message);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  return (
    <section className="provider-configuration">
      <div className="section-toolbar">
        <div>
          <h2>
            {alias === "entra" ? "Microsoft Entra ID" : "Okta"} configuration
          </h2>
          <p>
            Import trusted application metadata, review its signing keys, and
            map exact groups to appliance roles.
          </p>
        </div>
        <button onClick={() => void load()} disabled={busy}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>
      {error && <ErrorNotice>{error}</ErrorNotice>}
      {notice && (
        <div className="notice success" role="status">
          {notice}
        </div>
      )}
      {available === undefined && !error ? (
        <Loading label="Reading identity provider configuration…" />
      ) : available === false ? (
        <div className="notice warning">
          Identity-provider management is unavailable on this appliance. An
          administrator must configure the Keycloak management service. The
          setup guide and manual Keycloak configuration remain available.
        </div>
      ) : (
        provider && (
          <>
            <div className="provider-observation">
              <div>
                <span>Current configuration</span>
                <strong>
                  {provider.configured
                    ? provider.enabled
                      ? "Enabled"
                      : "Saved · disabled"
                    : "Not configured"}
                </strong>
              </div>
              <div>
                <span>Provider alias</span>
                <strong className="mono">{provider.alias}</strong>
              </div>
              <div>
                <span>External sign-in</span>
                <strong>Not verified by appliance</strong>
              </div>
              {provider.configured && (
                <button disabled={busy} onClick={() => void check()}>
                  <ShieldCheck size={14} /> Check configuration
                </button>
              )}
            </div>
            {provider.configured && provider.managed && (
              <div className="provider-state-action">
                <button
                  className={provider.enabled ? "danger" : ""}
                  disabled={busy}
                  onClick={() => {
                    setError("");
                    setStateReview(!provider.enabled);
                  }}
                >
                  {provider.enabled ? "Disable sign-in" : "Enable sign-in"}
                </button>
                <span className="muted">
                  Change sign-in availability without replacing metadata.
                  Disabling remains available when certificates expire.
                </span>
              </div>
            )}
            {provider.configured && (
              <dl className="event-details">
                <div>
                  <dt>Identity provider issuer</dt>
                  <dd>{provider.entity_id}</dd>
                </div>
                <div>
                  <dt>Sign-on endpoint</dt>
                  <dd>{provider.sso_url}</dd>
                </div>
                <div>
                  <dt>SP entity ID</dt>
                  <dd>{provider.sp_entity_id}</dd>
                </div>
                <div>
                  <dt>Assertion consumer URL</dt>
                  <dd>{provider.acs_url}</dd>
                </div>
              </dl>
            )}
            {provider.configured && !!provider.certificates?.length && (
              <details className="current-certificates">
                <summary>
                  Trusted signing certificates ({provider.certificates.length})
                </summary>
                <div className="certificate-list">
                  {provider.certificates.map((c) => (
                    <article key={c.sha256}>
                      <strong>{c.subject || "Signing certificate"}</strong>
                      <code>{c.sha256}</code>
                      <span>
                        Valid {timestamp(c.not_before)} →{" "}
                        {timestamp(c.not_after)}
                      </span>
                      <p
                        className={
                          c.currently_valid === false ? "text-danger" : "muted"
                        }
                      >
                        {c.currently_valid === false
                          ? "Outside its validity window — replace the trusted certificate before sign-in."
                          : c.currently_valid === true
                            ? "Within its validity window."
                            : "Validity must be checked against the certificate dates."}
                      </p>
                    </article>
                  ))}
                </div>
              </details>
            )}
            {test && (
              <div
                className={`notice ${test.configuration_valid ? "success" : "warning"}`}
                role="status"
              >
                <div>
                  <strong>
                    {test.configuration_valid
                      ? "Configuration checks passed"
                      : "Configuration needs attention"}
                  </strong>
                  <p>{test.message}</p>
                  <small>
                    Checked {timestamp(test.checked_at)}. These checks do not
                    perform an external SAML login or establish upstream MFA.
                  </small>
                </div>
              </div>
            )}
            {external && (
              <div className="notice warning">
                This provider is managed outside Captain’s Log. Review or edit it in
                Keycloak administration. Captain’s Log will not overwrite an
                unmanaged provider.
              </div>
            )}
            <form
              className="provider-form"
              onSubmit={(e) => {
                e.preventDefault();
                void previewConfiguration();
              }}
            >
              <fieldset disabled={busy || !!external}>
                <section className="resource-section">
                  <h3>Trusted IdP metadata</h3>
                  <p className="muted">
                    Download this application’s metadata XML from its IdP
                    console, then upload or paste it here. Re-upload metadata to
                    change an existing configuration. Maximum 256 KiB; public
                    certificates only.
                  </p>
                  <label className="metadata-upload">
                    <FileUp size={17} />
                    <span>Upload metadata XML</span>
                    <input
                      type="file"
                      accept=".xml,application/xml,text/xml"
                      aria-label="Upload metadata XML"
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        try {
                          if (file.size > 262144)
                            throw new Error(
                              "Metadata must be at most 256 KiB.",
                            );
                          update({ metadata_xml: await file.text() });
                          setError("");
                        } catch (err) {
                          setError((err as Error).message);
                        }
                        e.target.value = "";
                      }}
                    />
                  </label>
                  <label className="metadata-label">
                    Metadata XML
                    <textarea
                      spellCheck={false}
                      placeholder="Paste the trusted IdP EntityDescriptor XML"
                      value={draft.metadata_xml}
                      onChange={(e) => update({ metadata_xml: e.target.value })}
                    />
                  </label>
                </section>
                <section className="resource-section">
                  <h3>Exact group-to-role mappings</h3>
                  <p className="muted">
                    {alias === "entra"
                      ? "Use the approved Entra group object IDs emitted in the groups claim."
                      : "Use the exact approved Okta group names emitted in the groups statement."}{" "}
                    Each mapping uses Force sync. No administrative fallback is
                    granted.
                  </p>
                  <div className="role-mapping-fields">
                    {(
                      [
                        ["viewer", "Viewer", "Read and search"],
                        [
                          "analyst",
                          "Analyst",
                          "Search, exports and own saved filters",
                        ],
                        [
                          "administrator",
                          "Administrator",
                          "Appliance application administration",
                        ],
                      ] as const
                    ).map(([key, label, description]) => (
                      <label key={key}>
                        <span>
                          <strong>{label}</strong>
                          <small>{description}</small>
                        </span>
                        <input
                          aria-label={`${label} group ${alias === "entra" ? "object ID" : "name"}`}
                          placeholder={
                            alias === "entra"
                              ? `${label} group object ID`
                              : `NebulaLog-${label === "Viewer" ? "Viewers" : label === "Analyst" ? "Analysts" : "Administrators"}`
                          }
                          value={draft.groups[key] || ""}
                          required
                          onChange={(e) =>
                            update({
                              groups: {
                                ...draft.groups,
                                [key]: e.target.value,
                              },
                            })
                          }
                        />
                      </label>
                    ))}
                  </div>
                </section>
                <section className="resource-section">
                  <h3>Sign-in availability</h3>
                  <label className="checkbox-row">
                    <input
                      type="checkbox"
                      checked={draft.enabled}
                      onChange={(e) => update({ enabled: e.target.checked })}
                    />{" "}
                    Enable this provider after saving
                  </label>
                  <p className="muted">
                    New providers start disabled. Enable only after trust,
                    assignment and group values are ready for a pilot. Required
                    Keycloak OTP is applied after broker authentication;
                    preserve local password-plus-OTP recovery.
                  </p>
                </section>
                <div className="form-actions">
                  <button
                    className="primary"
                    disabled={!draft.metadata_xml.trim() || busy}
                  >
                    {busy ? "Validating…" : "Review configuration"}
                  </button>
                </div>
              </fieldset>
            </form>
          </>
        )
      )}
      {stateReview !== null && provider && (
        <Modal
          title={`${stateReview ? "Enable" : "Disable"} ${alias === "entra" ? "Microsoft Entra ID" : "Okta"} sign-in`}
          onClose={() => {
            if (!busy) setStateReview(null);
          }}
        >
          <p>
            {stateReview
              ? "This adds the provider to new sign-in choices after the appliance validates its configuration. Verify the exact IdP, group assignments and required MFA before wider access."
              : "This prevents new sign-ins through this provider. Existing sessions are not automatically revoked; manage those separately when access must end immediately."}
          </p>
          <dl className="event-details">
            <div>
              <dt>Provider alias</dt>
              <dd>{alias}</dd>
            </div>
            <div>
              <dt>Identity provider</dt>
              <dd>{provider.entity_id}</dd>
            </div>
            <div>
              <dt>Requested state</dt>
              <dd>{stateReview ? "Enabled" : "Disabled"}</dd>
            </div>
          </dl>
          <p className="muted">
            Keep local administrator password-plus-OTP recovery available. A
            successful state change does not test an external SAML login.
          </p>
          {error && <ErrorNotice>{error}</ErrorNotice>}
          <div className="modal-actions">
            <button disabled={busy} onClick={() => setStateReview(null)}>
              Cancel
            </button>
            <button
              className={stateReview ? "primary" : "danger"}
              disabled={busy}
              onClick={() => void changeState()}
            >
              {busy
                ? "Applying…"
                : stateReview
                  ? "Enable provider sign-in"
                  : "Disable provider sign-in"}
            </button>
          </div>
        </Modal>
      )}
      {preview && reviewDraft && (
        <Modal
          title={`Review ${alias === "entra" ? "Microsoft Entra ID" : "Okta"} configuration`}
          onClose={() => {
            if (!busy) {
              setPreview(undefined);
              setReviewDraft(undefined);
            }
          }}
          wide
        >
          <p>
            Review the exact trust and access changes for provider{" "}
            <code>{alias}</code> before applying them.{" "}
            {reviewDraft.enabled
              ? "The provider will be enabled after its mappings are saved."
              : "The provider will remain disabled."}
          </p>
          <dl className="event-details">
            <div>
              <dt>Issuer</dt>
              <dd>{preview.entity_id}</dd>
            </div>
            <div>
              <dt>SSO endpoint</dt>
              <dd>{preview.sso_url}</dd>
            </div>
            <div>
              <dt>SP entity ID</dt>
              <dd>{preview.sp_entity_id}</dd>
            </div>
            <div>
              <dt>ACS</dt>
              <dd>{preview.acs_url}</dd>
            </div>
            {Object.entries(reviewDraft.groups).map(([role, group]) => (
              <div key={role}>
                <dt>{role} group</dt>
                <dd>{group}</dd>
              </div>
            ))}
            <div>
              <dt>Sign-in after save</dt>
              <dd>{reviewDraft.enabled ? "Enabled" : "Disabled"}</dd>
            </div>
            <div>
              <dt>Broker MFA</dt>
              <dd>Required Keycloak OTP</dd>
            </div>
          </dl>
          <h3>IdP signing certificates</h3>
          <div className="certificate-list">
            {preview.certificates?.map((c) => (
              <article key={c.sha256}>
                <strong>{c.subject || "Signing certificate"}</strong>
                <code>{c.sha256}</code>
                <span>
                  Valid {timestamp(c.not_before)} → {timestamp(c.not_after)}
                </span>
              </article>
            ))}
          </div>
          {preview.warnings?.map((warning, i) => (
            <div key={i} className="notice warning">
              {warning}
            </div>
          ))}
          <div className="notice">
            <Check size={16} />
            <span>
              Metadata and configuration checks do not test external sign-in.
              Run the provider guide’s fresh-login, role-removal, MFA and
              recovery checks before broader access.
            </span>
          </div>
          {error && <ErrorNotice>{error}</ErrorNotice>}
          <div className="modal-actions">
            <button
              disabled={busy}
              onClick={() => {
                setPreview(undefined);
                setReviewDraft(undefined);
              }}
            >
              Back to editing
            </button>
            <button
              className="primary"
              disabled={busy}
              onClick={() => void save()}
            >
              {busy
                ? "Saving…"
                : reviewDraft.enabled
                  ? "Save and enable provider"
                  : "Save disabled provider"}
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}
