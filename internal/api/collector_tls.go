package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/stellaraf/captains-log/internal/auth"
)

const collectorCertificateLimit = 64 << 10

var errCollectorCertificate = errors.New("collector public certificate unavailable")

type collectorCertificateMetadata struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	SHA256    string   `json:"sha256"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DNSNames  []string `json:"dns_names"`
	IPs       []string `json:"ip_addresses"`
}

type collectorTLSMaterial struct {
	ca, server collectorCertificateMetadata
	caPEM      []byte
}

func (m collectorTLSMaterial) etag() string { return `"sha256:` + m.ca.SHA256 + `"` }

// These two operator-configured public paths are independent of the collector's
// private key configuration. Requests cannot select a file or a trust store.
func readCollectorCertificates(path string) ([]*x509.Certificate, error) {
	if !filepath.IsAbs(path) {
		return nil, errCollectorCertificate
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errCollectorCertificate
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > collectorCertificateLimit || info.Mode().Perm()&0022 != 0 {
		return nil, errCollectorCertificate
	}
	raw, err := io.ReadAll(io.LimitReader(f, collectorCertificateLimit+1))
	if err != nil || len(raw) > collectorCertificateLimit {
		return nil, errCollectorCertificate
	}
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(raw)) > 0 {
		raw = bytes.TrimSpace(raw)
		if len(certificates) == 4 || !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----\n")) && !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----\r\n")) {
			return nil, errCollectorCertificate
		}
		// Decode exactly one block: pem.Decode otherwise skips malformed blocks
		// or leading text while searching for a later valid block.
		end := bytes.Index(raw, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, errCollectorCertificate
		}
		end += len("-----END CERTIFICATE-----")
		if bytes.Count(raw[:end], []byte("-----BEGIN ")) != 1 {
			return nil, errCollectorCertificate
		}
		block, rest := pem.Decode(raw[:end])
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errCollectorCertificate
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errCollectorCertificate
		}
		certificates = append(certificates, certificate)
		raw = raw[end:]
	}
	if len(certificates) == 0 {
		return nil, errCollectorCertificate
	}
	return certificates, nil
}

func describeCollectorCertificate(c *x509.Certificate) collectorCertificateMetadata {
	digest := sha256.Sum256(c.Raw)
	value := collectorCertificateMetadata{Subject: c.Subject.String(), Issuer: c.Issuer.String(), SHA256: hex.EncodeToString(digest[:]),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		DNSNames: append([]string{}, c.DNSNames...), IPs: []string{}}
	for _, ip := range c.IPAddresses {
		value.IPs = append(value.IPs, ip.String())
	}
	return value
}

func loadCollectorTLS(c Config, now time.Time) (collectorTLSMaterial, error) {
	var material collectorTLSMaterial
	roots, err := readCollectorCertificates(c.CollectorTLSCAPath)
	if err != nil || len(roots) != 1 {
		return material, errCollectorCertificate
	}
	ca := roots[0]
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!bytes.Equal(ca.RawIssuer, ca.RawSubject) || ca.CheckSignatureFrom(ca) != nil || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return material, errCollectorCertificate
	}
	chain, err := readCollectorCertificates(c.CollectorTLSCertPath)
	if err != nil {
		return material, errCollectorCertificate
	}
	leaf := chain[0]
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth
	}
	if leaf.IsCA || !serverAuth || len(leaf.DNSNames)+len(leaf.IPAddresses) == 0 {
		return material, errCollectorCertificate
	}
	pool, intermediates := x509.NewCertPool(), x509.NewCertPool()
	pool.AddCert(ca)
	for _, certificate := range chain {
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return material, errCollectorCertificate
		}
		if certificate.IsCA && bytes.Equal(certificate.RawIssuer, certificate.RawSubject) &&
			certificate.CheckSignatureFrom(certificate) == nil && !bytes.Equal(certificate.Raw, ca.Raw) {
			return material, errCollectorCertificate
		}
	}
	for i, certificate := range chain[1:] {
		if !bytes.Equal(chain[i].RawIssuer, certificate.RawSubject) || chain[i].CheckSignatureFrom(certificate) != nil || bytes.Equal(chain[i].Raw, certificate.Raw) {
			return material, errCollectorCertificate
		}
		intermediates.AddCert(certificate)
	}
	// Reject unrelated extra PEM certificates, including an unrelated root that
	// x509.Verify could otherwise ignore when finding a valid alternate chain.
	if !bytes.Equal(chain[len(chain)-1].RawIssuer, ca.RawSubject) || chain[len(chain)-1].CheckSignatureFrom(ca) != nil {
		return material, errCollectorCertificate
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return material, errCollectorCertificate
	}
	material.ca, material.server = describeCollectorCertificate(ca), describeCollectorCertificate(leaf)
	material.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	return material, nil
}

func (s *Server) collectorTLSRequest(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	session, present := auth.CurrentSession(r.Context())
	user := auth.Current(r.Context())
	if s.Auth == nil || len(r.Header.Values("Authorization")) != 1 || !present ||
		!session.MatchesApplication(user.ID, s.Auth.ClientID, time.Now()) {
		problem(w, 401, "A current administrator session is required.")
		return false
	}
	if r.URL.RawQuery != "" {
		problem(w, 400, "This request does not accept query parameters.")
		return false
	}
	return true
}

func collectorTLSUnavailable(w http.ResponseWriter) {
	respond(w, 503, map[string]string{"status": "unavailable", "error": "Collector TLS public certificates could not be verified. Check appliance diagnostics."})
}

func (s *Server) collectorTLSMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.collectorTLSRequest(w, r) {
		return
	}
	if s.Config.CollectorTLSCAPath == "" && s.Config.CollectorTLSCertPath == "" {
		respond(w, 200, map[string]string{"status": "unconfigured", "reason": "Collector TLS public certificates are not configured."})
		return
	}
	material, err := loadCollectorTLS(s.Config, time.Now())
	if err != nil {
		collectorTLSUnavailable(w)
		return
	}
	w.Header().Set("ETag", material.etag())
	respond(w, 200, map[string]any{"status": "ready", "ca": material.ca, "server": material.server,
		"download_url": "/api/collector/tls/ca.pem", "download_etag": material.etag(), "scope": "configured_public_certificates"})
}

func (s *Server) collectorTLSDownload(w http.ResponseWriter, r *http.Request) {
	if !s.collectorTLSRequest(w, r) {
		return
	}
	material, err := loadCollectorTLS(s.Config, time.Now())
	if err != nil {
		collectorTLSUnavailable(w)
		return
	}
	serveCollectorTLSCA(w, r, material, func() error {
		if s.Store == nil || s.Store.PG == nil {
			return errors.New("audit store unavailable")
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		detail, _ := json.Marshal(map[string]string{"ca_sha256": material.ca.SHA256, "server_sha256": material.server.SHA256})
		_, err := s.Store.PG.Exec(ctx, "INSERT INTO audit_events(actor,action,target,detail) VALUES($1,$2,$3,$4)",
			auth.Current(r.Context()).ID, "collector.tls.ca.download", "collector-tls", detail)
		return err
	})
}

// Record the authorized transfer before publishing the public trust anchor.
// A failed audit cannot be reported as a completed, audited download.
func serveCollectorTLSCA(w http.ResponseWriter, r *http.Request, material collectorTLSMaterial, record func() error) {
	values := r.Header.Values("If-Match")
	if len(values) == 0 {
		problem(w, http.StatusPreconditionRequired, "Review the current collector TLS certificate before downloading its CA.")
		return
	}
	if len(values) != 1 || values[0] != material.etag() {
		problem(w, http.StatusPreconditionFailed, "Collector TLS certificate changed. Refresh its details before downloading.")
		return
	}
	if err := record(); err != nil {
		slog.Error("collector CA download audit could not be persisted")
		problem(w, 503, "The CA download could not be audited. Retry after checking appliance diagnostics.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="captains-log-syslog-ca.pem"`)
	w.Header().Set("ETag", material.etag())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(material.caPEM)
}
