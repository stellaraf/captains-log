package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type collectorTLSFixture struct {
	config           Config
	ca, leaf         *x509.Certificate
	caKey, serverKey *ecdsa.PrivateKey
	caPEM, serverPEM []byte
}

func newCollectorTLSFixture(t *testing.T, changeCA, changeLeaf func(*x509.Certificate)) collectorTLSFixture {
	t.Helper()
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic appliance CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if changeCA != nil {
		changeCA(ca)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "collector.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"collector.example.test", "localhost"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.4"), net.ParseIP("2001:db8::4")}}
	if changeLeaf != nil {
		changeLeaf(leaf)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), caPEM...)
	dir := t.TempDir()
	fixture := collectorTLSFixture{Config{CollectorTLSCAPath: filepath.Join(dir, "ca.crt"), CollectorTLSCertPath: filepath.Join(dir, "server.crt")}, ca, leaf, caKey, serverKey, caPEM, serverPEM}
	writeCollectorTestFile(t, fixture.config.CollectorTLSCAPath, caPEM)
	writeCollectorTestFile(t, fixture.config.CollectorTLSCertPath, serverPEM)
	return fixture
}

func writeCollectorTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorTLSValidPublicChainAndMetadata(t *testing.T) {
	f := newCollectorTLSFixture(t, nil, nil)
	m, err := loadCollectorTLS(f.config, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.caPEM, f.caPEM) || m.ca.SHA256 == m.server.SHA256 || len(m.ca.SHA256) != 64 ||
		strings.Join(m.server.DNSNames, ",") != "collector.example.test,localhost" || strings.Join(m.server.IPs, ",") != "192.0.2.4,2001:db8::4" {
		t.Fatalf("wrong public certificate metadata: %+v", m)
	}
	// Leaf-only and CRLF public PEM files also represent the same trust chain.
	leafOnly := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw})
	writeCollectorTestFile(t, f.config.CollectorTLSCertPath, bytes.ReplaceAll(leafOnly, []byte("\n"), []byte("\r\n")))
	if _, err := loadCollectorTLS(f.config, time.Now()); err != nil {
		t.Fatal("valid leaf-only chain rejected", err)
	}
}

func TestCollectorTLSRejectsInvalidCertificateRolesAndValidity(t *testing.T) {
	cases := []struct {
		name     string
		ca, leaf func(*x509.Certificate)
	}{
		{"expired CA", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, nil},
		{"future CA", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }, nil},
		{"CA cannot sign", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }, nil},
		{"expired leaf", nil, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{"future leaf", nil, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }},
		{"leaf CA", nil, func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{"client only", nil, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"missing EKU", nil, func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{"CN only", nil, func(c *x509.Certificate) { c.DNSNames = nil; c.IPAddresses = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCollectorTLSFixture(t, tc.ca, tc.leaf)
			if _, err := loadCollectorTLS(f.config, time.Now()); err == nil {
				t.Fatal("invalid certificate accepted")
			}
		})
	}
}

func TestCollectorTLSRejectsUnexpectedPEMAndChain(t *testing.T) {
	for _, name := range []string{"empty", "private key", "private key suffix", "text prefix", "text suffix", "malformed preceding block", "missing end before valid block", "nested private block", "PEM headers", "DER garbage", "unrelated CA", "extra unrelated root", "expired alternate presented root", "different presented root", "wrong issuer same signer key", "reversed chain", "repeated root", "two CA blocks", "self signed server as CA", "too many blocks", "oversize"} {
		t.Run(name, func(t *testing.T) {
			f := newCollectorTLSFixture(t, nil, nil)
			path, raw := f.config.CollectorTLSCertPath, append([]byte{}, f.serverPEM...)
			switch name {
			case "empty":
				raw = nil
			case "private key":
				raw = []byte("-----BEGIN PRIVATE KEY-----\nUFJJVkFURV9TRUNSRVQ=\n-----END PRIVATE KEY-----\n")
			case "private key suffix":
				raw = append(raw, []byte("-----BEGIN RSA PRIVATE KEY-----\nUFJJVkFURV9TRUNSRVQ=\n-----END RSA PRIVATE KEY-----\n")...)
			case "text prefix":
				raw = append([]byte("PRIVATE_SECRET\n"), raw...)
			case "text suffix":
				raw = append(raw, []byte("PRIVATE_SECRET")...)
			case "malformed preceding block":
				raw = append([]byte("-----BEGIN CERTIFICATE-----\n!!invalid!!\n-----END CERTIFICATE-----\n"), raw...)
			case "missing end before valid block":
				raw = append([]byte("-----BEGIN CERTIFICATE-----\n!!invalid!!\n"), raw...)
			case "nested private block":
				raw = append([]byte("-----BEGIN CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nUFJJVkFURV9TRUNSRVQ=\n-----END PRIVATE KEY-----\n"), raw...)
			case "PEM headers":
				raw = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw, Headers: map[string]string{"Test": "PRIVATE_SECRET"}})
			case "DER garbage":
				raw = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("PRIVATE_SECRET")})
			case "unrelated CA":
				other := newCollectorTLSFixture(t, nil, nil)
				path, raw = f.config.CollectorTLSCAPath, other.caPEM
			case "extra unrelated root":
				other := newCollectorTLSFixture(t, nil, nil)
				raw = append(raw, other.caPEM...)
			case "expired alternate presented root", "different presented root":
				alternate := *f.ca
				alternate.SerialNumber = big.NewInt(3)
				if name == "expired alternate presented root" {
					alternate.NotAfter = time.Now().Add(-time.Minute)
				}
				der, err := x509.CreateCertificate(rand.Reader, &alternate, &alternate, &f.caKey.PublicKey, f.caKey)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
			case "wrong issuer same signer key":
				alternate := *f.ca
				alternate.SerialNumber = big.NewInt(4)
				alternate.RawSubject = nil
				alternate.Subject = pkix.Name{CommonName: "Unrelated presented issuer"}
				der, err := x509.CreateCertificate(rand.Reader, &alternate, f.ca, &f.caKey.PublicKey, f.caKey)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
			case "reversed chain":
				raw = append(append([]byte{}, f.caPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw})...)
			case "repeated root":
				raw = append(raw, f.caPEM...)
			case "two CA blocks":
				path, raw = f.config.CollectorTLSCAPath, append(append([]byte{}, f.caPEM...), f.caPEM...)
			case "self signed server as CA":
				path, raw = f.config.CollectorTLSCAPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw})
			case "too many blocks":
				raw = bytes.Repeat(f.caPEM, 5)
			case "oversize":
				raw = bytes.Repeat([]byte(" "), collectorCertificateLimit+1)
			}
			writeCollectorTestFile(t, path, raw)
			if _, err := loadCollectorTLS(f.config, time.Now()); err == nil {
				t.Fatal("invalid PEM accepted")
			}
		})
	}
}

func TestCollectorTLSRejectsUnsafePublicFileInputs(t *testing.T) {
	for _, name := range []string{"relative", "missing", "directory", "symlink", "FIFO", "writable"} {
		t.Run(name, func(t *testing.T) {
			f := newCollectorTLSFixture(t, nil, nil)
			path := f.config.CollectorTLSCAPath
			switch name {
			case "relative":
				f.config.CollectorTLSCAPath = "ca.crt"
			case "missing":
				f.config.CollectorTLSCAPath += ".missing"
			case "directory":
				f.config.CollectorTLSCAPath = filepath.Dir(path)
			case "symlink":
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				f.config.CollectorTLSCAPath = link
			case "FIFO":
				fifo := path + ".fifo"
				if err := syscall.Mkfifo(fifo, 0600); err != nil {
					t.Fatal(err)
				}
				f.config.CollectorTLSCAPath = fifo
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loadCollectorTLS(f.config, time.Now()); err == nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}
}

func TestCollectorTLSAuthenticatedAdministratorRoutes(t *testing.T) {
	for _, route := range []string{"/api/collector/tls", "/api/collector/tls/ca.pem"} {
		for _, name := range []string{"missing token", "analyst", "viewer", "wrong authorized party", "ID token", "duplicate authorization"} {
			t.Run(route+"/"+name, func(t *testing.T) {
				h := newHostPlanHarness(t)
				token, expected := h.token(t, nil), 401
				var change func(*http.Request)
				switch name {
				case "missing token":
					token = ""
				case "analyst", "viewer":
					token = h.token(t, func(c map[string]any) {
						c["resource_access"] = map[string]any{"nebulalog": map[string]any{"roles": []string{strings.ToUpper(name)}}}
					})
					expected = 403
				case "wrong authorized party":
					token = h.token(t, func(c map[string]any) { c["azp"] = "foreign" })
				case "ID token":
					token = h.token(t, func(c map[string]any) { c["typ"] = "ID" })
				case "duplicate authorization":
					change = func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+token) }
				}
				w := h.request("GET", route, "", token, change)
				if w.Code != expected || strings.Contains(w.Body.String(), "CERTIFICATE") {
					t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestCollectorTLSMetadataStatesAndRedaction(t *testing.T) {
	h := newHostPlanHarness(t)
	token := h.token(t, nil)
	w := h.request("GET", "/api/collector/tls", "", token, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"unconfigured"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	f := newCollectorTLSFixture(t, nil, nil)
	h.server.Config.CollectorTLSCAPath, h.server.Config.CollectorTLSCertPath = f.config.CollectorTLSCAPath, f.config.CollectorTLSCertPath
	w = h.request("GET", "/api/collector/tls", "", token, nil)
	var body struct {
		Status       string
		CA, Server   collectorCertificateMetadata
		DownloadETag string `json:"download_etag"`
		Scope        string
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Status != "ready" || body.CA.SHA256 != describeCollectorCertificate(f.ca).SHA256 || body.Scope != "configured_public_certificates" || w.Header().Get("ETag") != body.DownloadETag {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), filepath.Dir(f.config.CollectorTLSCAPath)) || strings.Contains(w.Body.String(), "BEGIN") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("unexpected disclosure or caching", w.Body.String())
	}
	for _, route := range []string{"/api/collector/tls", "/api/collector/tls/ca.pem"} {
		if got := h.request("GET", route+"?path=/private.key", "", token, nil); got.Code != 400 {
			t.Fatal("request selected a path", got.Code)
		}
	}
	writeCollectorTestFile(t, f.config.CollectorTLSCertPath, []byte("PRIVATE_SECRET"))
	w = h.request("GET", "/api/collector/tls", "", token, nil)
	if w.Code != 503 || strings.Contains(w.Body.String(), "PRIVATE_SECRET") || strings.Contains(w.Body.String(), f.config.CollectorTLSCertPath) || !strings.Contains(w.Body.String(), `"status":"unavailable"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestCollectorTLSDownloadPreconditionAuditAndPublicBytes(t *testing.T) {
	f := newCollectorTLSFixture(t, nil, nil)
	m, err := loadCollectorTLS(f.config, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "changed", "wildcard", "weak", "list", "duplicate", "audit failure", "success"} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/collector/tls/ca.pem", nil)
			r.Header.Set("If-Match", m.etag())
			want, calls := 412, 0
			switch name {
			case "missing":
				r.Header.Del("If-Match")
				want = 428
			case "changed":
				r.Header.Set("If-Match", `"sha256:`+strings.Repeat("0", 64)+`"`)
			case "wildcard":
				r.Header.Set("If-Match", "*")
			case "weak":
				r.Header.Set("If-Match", "W/"+m.etag())
			case "list":
				r.Header.Set("If-Match", m.etag()+", "+m.etag())
			case "duplicate":
				r.Header.Add("If-Match", m.etag())
			case "audit failure":
				want = 503
			case "success":
				want = 200
			}
			w := httptest.NewRecorder()
			serveCollectorTLSCA(w, r, m, func() error {
				calls++
				if name == "audit failure" {
					return errors.New("PRIVATE_SECRET")
				}
				return nil
			})
			if w.Code != want {
				t.Fatal(w.Code, w.Body.String())
			}
			if name == "success" || name == "audit failure" {
				if calls != 1 {
					t.Fatal("download audit missing", calls)
				}
			} else if calls != 0 {
				t.Fatal("refused download audited as transfer")
			}
			if name == "success" {
				if !bytes.Equal(w.Body.Bytes(), f.caPEM) || w.Header().Get("Content-Type") != "application/x-pem-file" || w.Header().Get("ETag") != m.etag() || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Content-Disposition") != `attachment; filename="captains-log-syslog-ca.pem"` {
					t.Fatal("incorrect public download", w.Header())
				}
			} else if strings.Contains(w.Body.String(), "CERTIFICATE") || strings.Contains(w.Body.String(), "PRIVATE_SECRET") {
				t.Fatal("refusal leaked material")
			}
		})
	}
	// Exercise the complete authenticated route: a missing audit store fails
	// closed even with valid certificates and a matching reviewed fingerprint.
	h := newHostPlanHarness(t)
	h.server.Config.CollectorTLSCAPath, h.server.Config.CollectorTLSCertPath = f.config.CollectorTLSCAPath, f.config.CollectorTLSCertPath
	w := h.request("GET", "/api/collector/tls/ca.pem", "", h.token(t, nil), func(r *http.Request) { r.Header.Set("If-Match", m.etag()) })
	if w.Code != 503 || strings.Contains(w.Body.String(), "CERTIFICATE") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestCollectorTLSDownloadedCAAuthenticatesMatchingServerOnly(t *testing.T) {
	f := newCollectorTLSFixture(t, nil, nil)
	m, err := loadCollectorTLS(f.config, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{f.leaf.Raw, f.ca.Raw}, PrivateKey: f.serverKey}}}
	server.StartTLS()
	defer server.Close()
	other := newCollectorTLSFixture(t, nil, nil)
	for _, tc := range []struct {
		name, serverName string
		ca               []byte
		valid            bool
	}{
		{"trusted DNS", "collector.example.test", m.caPEM, true},
		{"trusted IPv4", "192.0.2.4", m.caPEM, true},
		{"trusted IPv6", "2001:db8::4", m.caPEM, true},
		{"wrong CA", "collector.example.test", other.caPEM, false},
		{"wrong name", "foreign.example.test", m.caPEM, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(tc.ca) {
				t.Fatal("download was not a PEM CA")
			}
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: tc.serverName}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			response, err := client.Get(server.URL)
			if response != nil {
				response.Body.Close()
			}
			if (err == nil) != tc.valid {
				t.Fatalf("TLS verification valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
