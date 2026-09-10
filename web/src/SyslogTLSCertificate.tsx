import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Download, LockKeyhole, RefreshCw, ShieldCheck } from "lucide-react";
import { api, authenticatedFetch, authSessionSnapshot, saveBlob, subscribeAuthSession } from "./api";
import { ErrorNotice, Loading } from "./components";
import type { User } from "./types";

type Certificate = {
  subject: string;
  issuer: string;
  sha256: string;
  not_before: string;
  not_after: string;
  dns_names: string[];
  ip_addresses: string[];
};
export type SyslogCertificates = {
  status: "ready";
  ca: Certificate;
  server: Certificate;
  download_etag: string;
  scope: "configured_public_certificates";
};
type Response = SyslogCertificates | { status: "unconfigured"; reason: string };

const certificatePath = "/api/collector/tls/ca.pem";
const fingerprint = (value: string) => value.match(/.{2}/g)?.join(":").toUpperCase() || value;
const date = (value: string) => new Date(value).toLocaleDateString(undefined, { dateStyle: "medium" });

export async function fetchSyslogCA(value: SyslogCertificates, signal?: AbortSignal) {
  if (!/^[a-f0-9]{64}$/.test(value.ca.sha256) || value.download_etag !== `"sha256:${value.ca.sha256}"`) {
    throw new Error("Certificate identity is unavailable. Refresh before downloading.");
  }
  const response = await authenticatedFetch(certificatePath, {
    headers: { "If-Match": value.download_etag }, signal,
  });
  if (response.headers.get("ETag") !== value.download_etag) {
    throw new Error("The certificate changed. Refresh and verify its new fingerprint.");
  }
  const pem = await response.text();
  const match = /^-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\r?\n?$/.exec(pem);
  if (pem.length > 65536 || !match) throw new Error("The certificate download is not a public CA certificate.");
  const der = Uint8Array.from(atob(match[1].replace(/\s/g, "")), (character) => character.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
  const actual = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  if (actual !== value.ca.sha256) throw new Error("The downloaded certificate does not match the displayed fingerprint.");
  return new Blob([pem], { type: "application/x-pem-file" });
}

export function SyslogCertificateDetails({ value }: { value: SyslogCertificates }) {
  const names = [...(value.server.dns_names || []), ...(value.server.ip_addresses || [])];
  return <>
    <dl className="syslog-certificate-details">
      <div><dt>Certificate authority</dt><dd>{value.ca.subject}</dd></div>
      <div><dt>CA expires</dt><dd>{date(value.ca.not_after)}</dd></div>
      <div><dt>Server certificate expires</dt><dd>{date(value.server.not_after)}</dd></div>
      <div><dt>Covered server names and addresses</dt><dd>{names.join(" · ") || "No names available"}</dd></div>
      <div className="syslog-certificate-fingerprint"><dt>CA fingerprint · SHA-256</dt><dd className="mono">{fingerprint(value.ca.sha256)}</dd></div>
    </dl>
    <p className="muted">Use a covered name or address that the firewall can reach. Certificate details alone do not confirm an active TLS connection.</p>
  </>;
}

function CertificatePanel() {
  const session = useSyncExternalStore(subscribeAuthSession, authSessionSnapshot, authSessionSnapshot);
  const [result, setResult] = useState<{ value: Response; session: number }>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [notice, setNotice] = useState("");
  const [refresh, setRefresh] = useState(0);
  const request = useRef(0);
  const downloadController = useRef<AbortController | undefined>(undefined);
  useEffect(() => {
    const current = ++request.current;
    const controller = new AbortController();
    downloadController.current?.abort();
    setResult(undefined);
    setBusy(true);
    setDownloading(false);
    setError("");
    setNotice("");
    void api<Response>("/api/collector/tls", { signal: controller.signal }).then((value) => {
      if (current !== request.current || session !== authSessionSnapshot()) return;
      setResult({ value, session });
    }).catch((reason: unknown) => {
      if (current === request.current && !controller.signal.aborted) setError((reason as Error).message);
    }).finally(() => {
      if (current === request.current) setBusy(false);
    });
    return () => { request.current++; controller.abort(); downloadController.current?.abort(); };
  }, [session, refresh]);
  const value = result?.session === session ? result.value : undefined;
  const ready = value?.status === "ready" ? value : undefined;
  async function download() {
    if (!ready || downloading) return;
    const current = request.current;
    const controller = new AbortController();
    downloadController.current = controller;
    setDownloading(true);
    setError("");
    setNotice("");
    try {
      const blob = await fetchSyslogCA(ready, controller.signal);
      if (controller.signal.aborted || current !== request.current || session !== authSessionSnapshot()) return;
      saveBlob(blob, "captains-log-syslog-ca.pem");
      setNotice("Public CA certificate downloaded. Its private key stays on the appliance.");
    } catch (reason) {
      if (!controller.signal.aborted && current === request.current) {
        setResult(undefined);
        setError((reason as Error).message);
      }
    } finally {
      if (current === request.current) setDownloading(false);
    }
  }
  return <section className="panel syslog-certificate" aria-labelledby="syslog-certificate-title">
    <div className="syslog-certificate-heading">
      <div className="syslog-certificate-intro">
        <span className="syslog-certificate-icon"><LockKeyhole size={22} aria-hidden="true" /></span>
        <div><h3 id="syslog-certificate-title">Encrypted log forwarding</h3>
          <p>Trust this appliance on your Palo Alto firewall, then send logs over TLS.</p></div>
      </div>
      <button onClick={() => setRefresh((number) => number + 1)} disabled={busy || downloading} aria-label="Refresh syslog certificates"><RefreshCw size={14} /> Refresh</button>
    </div>
    {error && <ErrorNotice>{error}</ErrorNotice>}
    {busy && <Loading />}
    {value?.status === "unconfigured" && <p role="status" className="notice">{value.reason} Complete appliance certificate setup to enable this download.</p>}
    {ready && <>
      <SyslogCertificateDetails value={ready} />
      <div className="syslog-certificate-download">
        <p><ShieldCheck size={16} aria-hidden="true" /> Public certificate only. No private keys are exported.</p>
        <button className="primary" disabled={downloading} onClick={() => void download()}><Download size={15} />{downloading ? "Verifying download…" : "Download Syslog CA Certificate"}</button>
      </div>
    </>}
    {notice && <p className="notice success" role="status">{notice}</p>}
    <details className="syslog-certificate-guide">
      <summary>Configure encrypted forwarding on Palo Alto</summary>
      <ol>
        <li><strong>Verify the appliance.</strong> Compare the CA fingerprint above with the fingerprint shown on the trusted VM console before installing it as a trust anchor. Download the public CA certificate through this authenticated appliance UI.</li>
        <li><strong>Import the CA.</strong> Open Device → Certificate Management → Certificates. On PAN-OS 12.1 and later, use Custom Certificates; earlier versions use Device Certificates. Import the PEM file without a private key and mark the imported CA as a Trusted Root CA.</li>
        <li><strong>Choose TLS.</strong> Under Device → Server Profiles → Syslog, use a reachable name or address covered by the server certificate. Set Transport to SSL (PAN-OS calls TLS “SSL”) and port to 6514. Allow TCP 6514 from the firewall to the appliance. Keep the standard PAN-OS CSV log fields.</li>
        <li><strong>Apply and verify.</strong> Assign the server profile to the intended log-forwarding profiles and log settings, commit, and check fresh events here and TLS connection errors in the firewall System logs.</li>
      </ol>
      <p>The “Certificate for Secure Syslog” checkbox selects a firewall client certificate for mutual TLS. It is not used for this public CA import. Client-certificate authentication is a separate configuration.</p>
      <p>If the server certificate expires or its name changes, fix the certificate and trust configuration before resuming forwarding. Do not bypass certificate validation.</p>
      <a href="https://docs.paloaltonetworks.com/ngfw/help/12-2/configure-syslog-monitoring" target="_blank" rel="noreferrer">Palo Alto syslog configuration reference ↗</a>
    </details>
  </section>;
}

export function SyslogTLSCertificate({ user }: { user: User }) {
  return user.role === "ADMINISTRATOR" ? <CertificatePanel /> : null;
}
