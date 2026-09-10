import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { authenticatedFetch } from "./api";
import { fetchSyslogCA, SyslogCertificateDetails, SyslogTLSCertificate, type SyslogCertificates } from "./SyslogTLSCertificate";
import type { User } from "./types";

vi.mock("./api", () => ({ authenticatedFetch: vi.fn(), api: vi.fn(), saveBlob: vi.fn(),
  authSessionSnapshot: () => 1, subscribeAuthSession: () => () => {} }));

// The backend tests validate X.509. This fixture isolates browser transfer/hash checks.
const encoded = btoa("public certificate transfer fixture");
const sha256 = "e56dd667767681b5ba321695471f0ee824e8a777cd5a4ffd49cad3652fc748cb";
const pem = `-----BEGIN CERTIFICATE-----\n${encoded}\n-----END CERTIFICATE-----\n`;
const ca = { subject: "CN=Captain's Log test CA", issuer: "CN=Captain's Log test CA", sha256,
  not_before: "2026-09-09T00:00:00Z", not_after: "2036-09-09T00:00:00Z", dns_names: [], ip_addresses: [] };
const value: SyslogCertificates = { status: "ready", ca,
  server: { ...ca, subject: "CN=logs.example.test", dns_names: ["logs.example.test"], ip_addresses: ["192.0.2.5"] },
  scope: "configured_public_certificates", download_etag: `"sha256:${sha256}"` };

function response(body = pem, etag = value.download_etag) {
  return new Response(body, { headers: { ETag: etag, "Content-Type": "application/x-pem-file" } });
}

describe("syslog public CA download", () => {
  beforeEach(() => vi.mocked(authenticatedFetch).mockReset());

  it("downloads only the fixed route with the reviewed fingerprint and verifies returned bytes", async () => {
    vi.mocked(authenticatedFetch).mockResolvedValue(response());
    const controller = new AbortController();
    const blob = await fetchSyslogCA(value, controller.signal);
    expect(authenticatedFetch).toHaveBeenCalledWith("/api/collector/tls/ca.pem", {
      headers: { "If-Match": value.download_etag }, signal: controller.signal,
    });
    expect(await blob.text()).toBe(pem);
  });

  it("refuses a changed certificate instead of saving new trust silently", async () => {
    vi.mocked(authenticatedFetch).mockResolvedValue(response(pem, '"sha256:changed"'));
    await expect(fetchSyslogCA(value)).rejects.toThrow("certificate changed");
    vi.mocked(authenticatedFetch).mockResolvedValue(response(pem.replace(encoded, "Y2hhbmdlZA==")));
    await expect(fetchSyslogCA(value)).rejects.toThrow("does not match");
  });

  it("refuses private-key blocks, extra certificates, HTML and oversized payloads", async () => {
    for (const body of [pem + "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
      pem + pem, "<html>Error</html>", "x".repeat(65537)]) {
      vi.mocked(authenticatedFetch).mockResolvedValue(response(body));
      await expect(fetchSyslogCA(value)).rejects.toThrow("not a public CA certificate");
    }
  });

  it("does not dispatch with a missing or contradictory review identity", async () => {
    await expect(fetchSyslogCA({ ...value, download_etag: "*" })).rejects.toThrow("identity is unavailable");
    expect(authenticatedFetch).not.toHaveBeenCalled();
  });

  it("hides the feature from non-administrators", () => {
    for (const role of ["VIEWER", "AUDITOR", "OPERATOR"]) {
      expect(renderToStaticMarkup(<SyslogTLSCertificate user={{ role } as User} />)).toBe("");
    }
  });

  it("shows public identity and expiry without claiming an active encrypted connection", () => {
    const html = renderToStaticMarkup(<SyslogCertificateDetails value={value} />);
    expect(html).toContain("logs.example.test");
    expect(html).toContain("192.0.2.5");
    expect(html).toContain("CA expires");
    expect(html).toContain("CA fingerprint");
    expect(html).toContain("do not confirm an active TLS connection");
  });
});
