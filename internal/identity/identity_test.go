package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) string {
	return fixtureAt(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}
func fixtureAt(t *testing.T, before, after time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic SAML test"}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="urn:nebulalog:synthetic-idp"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(der) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`
}
func setup(t *testing.T) Setup {
	return Setup{Alias: "okta", MetadataXML: fixture(t), Groups: GroupMappings{"Viewers", "Analysts", "Administrators"}}
}

type fakeKC struct {
	mu          sync.Mutex
	providers   map[string]representation
	mappers     map[string][]mapper
	calls       []string
	otpRequired bool
	failMapper  int
	createRace  bool
	putHook     func(representation) (status int, store bool)
}

func newFake(t *testing.T) (*Manager, *fakeKC) {
	f := &fakeKC{providers: map[string]representation{}, mappers: map[string][]mapper{}, otpRequired: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			user, secret, ok := r.BasicAuth()
			if !ok || user != "nebulalog-identity-manager" || secret != "synthetic-service-secret" {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access-token", "expires_in": 300})
			return
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-access-token" {
			w.WriteHeader(401)
			return
		}
		if strings.Contains(r.URL.Path, "/authentication/flows/") {
			requirement := "REQUIRED"
			if !f.otpRequired {
				requirement = "ALTERNATIVE"
			}
			json.NewEncoder(w).Encode([]map[string]any{{"providerId": "auth-otp-form", "requirement": requirement, "authenticationFlow": false}})
			return
		}
		base := "/admin/realms/nebulalog/identity-provider/instances"
		if r.URL.Path == base && r.Method == http.MethodPost {
			var p representation
			json.NewDecoder(r.Body).Decode(&p)
			if f.createRace {
				f.providers[p.Alias] = representation{Alias: p.Alias, ProviderID: "saml", Enabled: true, Config: map[string]string{"unrelated": "preserve"}}
				w.WriteHeader(409)
				return
			}
			f.providers[p.Alias] = p
			w.WriteHeader(201)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, base+"/")
		parts := strings.Split(rest, "/")
		alias := parts[0]
		if len(parts) > 1 && parts[1] == "mappers" {
			switch r.Method {
			case http.MethodGet:
				items := f.mappers[alias]
				if items == nil {
					items = []mapper{}
				}
				json.NewEncoder(w).Encode(items)
			case http.MethodPost:
				if f.failMapper > 0 && len(f.mappers[alias])+1 == f.failMapper {
					w.WriteHeader(500)
					fmt.Fprint(w, "private-upstream-secret")
					return
				}
				var item mapper
				json.NewDecoder(r.Body).Decode(&item)
				item.ID = fmt.Sprint(len(f.mappers[alias]) + 1)
				f.mappers[alias] = append(f.mappers[alias], item)
				w.WriteHeader(201)
			case http.MethodDelete:
				items := f.mappers[alias]
				for i, item := range items {
					if item.ID == parts[2] {
						f.mappers[alias] = append(items[:i], items[i+1:]...)
						break
					}
				}
				w.WriteHeader(204)
			}
			return
		}
		switch r.Method {
		case http.MethodGet:
			p, ok := f.providers[alias]
			if !ok {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(p)
		case http.MethodPut:
			var p representation
			json.NewDecoder(r.Body).Decode(&p)
			if p.Enabled && len(f.mappers[alias]) != 7 {
				t.Error("provider enabled before all mappers")
			}
			status, store := http.StatusNoContent, true
			if f.putHook != nil {
				status, store = f.putHook(p)
			}
			if store {
				f.providers[alias] = p
			}
			w.WriteHeader(status)
		case http.MethodDelete:
			delete(f.providers, alias)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	m, err := New(Config{BaseURL: server.URL, PublicBaseURL: "https://auth.example.test", Realm: "nebulalog", ClientID: "nebulalog-identity-manager", ClientSecret: "synthetic-service-secret", AllowHTTP: true, EnableWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	return m, f
}
func TestMetadataPreviewRejectsDangerousOrAmbiguousInput(t *testing.T) {
	m, f := newFake(t)
	s := setup(t)
	preview, err := m.Preview(s)
	if err != nil {
		t.Fatal(err)
	}
	if preview.EntityID != "urn:nebulalog:synthetic-idp" || preview.ACSURL != "https://auth.example.test/realms/nebulalog/broker/okta/endpoint" || len(preview.Certificates) != 1 || preview.ExternalLoginTested {
		t.Fatal(preview)
	}
	cases := map[string]string{
		"DTD":                `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` + s.MetadataXML,
		"entity":             "<!DOCTYPE x [<!ENTITY e 'expanded'>]>" + s.MetadataXML,
		"HTTP":               strings.ReplaceAll(s.MetadataXML, "https://idp.example.test", "http://127.0.0.1"),
		"wrong namespace":    strings.ReplaceAll(s.MetadataXML, metadataNS, "urn:other"),
		"two roots":          s.MetadataXML + s.MetadataXML,
		"XInclude":           strings.Replace(s.MetadataXML, "</md:EntityDescriptor>", `<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd"/></md:EntityDescriptor>`, 1),
		"external reference": strings.Replace(s.MetadataXML, "</md:EntityDescriptor>", `<ds:Reference URI="https://example.test/external"/></md:EntityDescriptor>`, 1),
		"expired metadata":   strings.Replace(s.MetadataXML, `entityID=`, `validUntil="2000-01-01T00:00:00Z" entityID=`, 1),
		"size":               strings.Repeat("x", MaxMetadataBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := s
			candidate.MetadataXML = raw
			if _, err := m.Preview(candidate); !IsKind(err, "validation") {
				t.Fatalf("unexpected result %v", err)
			}
		})
	}
	if len(f.calls) != 0 {
		t.Fatal("preview performed network access")
	}
	s.Groups.Administrator = s.Groups.Viewer
	if _, err := m.Preview(s); !IsKind(err, "validation") {
		t.Fatal(err)
	}
}
func TestSaveVerifiesConfigurationAndEnablesLast(t *testing.T) {
	m, f := newFake(t)
	s := setup(t)
	s.Enabled = true
	p, err := m.Save(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || !p.Configured || !p.Managed || p.ExternalLoginTested {
		t.Fatal(p)
	}
	status, err := m.TestStatus(context.Background(), s.Alias)
	if err != nil || !status.ConfigurationValid || status.ExternalLoginTested {
		t.Fatal(status, err)
	}
	f.mu.Lock()
	f.mappers[s.Alias][0].Config["role"] = "realm-admin"
	f.mu.Unlock()
	status, err = m.TestStatus(context.Background(), s.Alias)
	if err != nil || status.ConfigurationValid {
		t.Fatal("role drift was accepted", status, err)
	}
}
func TestSaveFailureLeavesProviderVerifiedDisabled(t *testing.T) {
	m, f := newFake(t)
	f.failMapper = 3
	s := setup(t)
	s.Enabled = true
	_, err := m.Save(context.Background(), s)
	if err == nil || strings.Contains(err.Error(), "private-upstream-secret") || !strings.Contains(err.Error(), "verified disabled") {
		t.Fatal(err)
	}
	if f.providers[s.Alias].Enabled {
		t.Fatal("partial roles with enabled provider")
	}
}
func TestCreateConflictDoesNotOverwriteConcurrentUnownedProvider(t *testing.T) {
	m, f := newFake(t)
	f.createRace = true
	s := setup(t)
	_, err := m.Save(context.Background(), s)
	if !IsKind(err, "conflict") {
		t.Fatal(err)
	}
	got := f.providers[s.Alias]
	if !got.Enabled || got.Config["unrelated"] != "preserve" || len(got.Config) != 1 {
		t.Fatal("unrelated provider was overwritten")
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "PUT ") {
			t.Fatal("cleanup mutated concurrent owner")
		}
	}
}
func TestRequiredMFAAndWriteSwitchPreventMutation(t *testing.T) {
	m, f := newFake(t)
	s := setup(t)
	f.otpRequired = false
	if _, err := m.Save(context.Background(), s); !IsKind(err, "conflict") {
		t.Fatal(err)
	}
	if len(f.providers) != 0 {
		t.Fatal("provider created with optional OTP")
	}
	m.config.EnableWrites = false
	if _, err := m.Save(context.Background(), s); !IsKind(err, "disabled") {
		t.Fatal(err)
	}
	missing, err := m.Inspect(context.Background(), "entra")
	if err != nil || missing.Configured || missing.Alias != "entra" {
		t.Fatal(missing, err)
	}
	if _, err := m.Inspect(context.Background(), "../../master"); !IsKind(err, "validation") {
		t.Fatal(err)
	}
}

// Explicit opt-in writes a temporary DISABLED broker to local Keycloak only.
// It reads the scoped service secret privately and never authenticates upstream.
func TestLocalKeycloakDisabledProviderRoundTrip(t *testing.T) {
	if os.Getenv("NEBULALOG_IDENTITY_LIVE_TEST") != "1" {
		t.Skip("opt-in local integration")
	}
	b, err := os.ReadFile(filepath.Join("..", "..", ".local", "dev.env"))
	if err != nil {
		t.Fatal("local environment unavailable")
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			env[k] = v
		}
	}
	m, err := New(Config{BaseURL: "http://127.0.0.1:18089", PublicBaseURL: "http://127.0.0.1:18089", Realm: "nebulalog", ClientID: "nebulalog-identity-manager", ClientSecret: env["KC_IDENTITY_CLIENT_SECRET"], AllowHTTP: true, EnableWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	before, err := m.Inspect(ctx, "okta")
	if err != nil {
		t.Fatal(err)
	}
	if before.Configured {
		t.Skip("okta alias already exists; no modification")
	}
	s := setup(t)
	s.Groups = GroupMappings{"synthetic-live-viewer", "synthetic-live-analyst", "synthetic-live-admin"}
	uniqueIssuer := fmt.Sprintf("urn:nebulalog:synthetic-idp:%d", time.Now().UnixNano())
	s.MetadataXML = strings.ReplaceAll(s.MetadataXML, "urn:nebulalog:synthetic-idp", uniqueIssuer)
	defer func() {
		r, found, err := m.read(context.Background(), s.Alias)
		if err == nil && found && r.Config[ownerKey] == ownerValue && r.Config["idpEntityId"] == uniqueIssuer {
			if _, err := m.request(context.Background(), http.MethodDelete, instancePath(s.Alias), nil, nil); err != nil {
				t.Error("temporary disabled provider cleanup failed")
			}
			_, exists, readErr := m.read(context.Background(), s.Alias)
			if readErr != nil || exists {
				t.Error("temporary provider removal could not be independently verified")
			}
		}
	}()
	p, err := m.Save(ctx, s)
	if err != nil {
		actual, _, _ := m.read(ctx, s.Alias)
		parsed, _ := parseMetadata(s.MetadataXML, false, time.Now())
		expected := m.desired(s, parsed)
		for key, value := range actual.Config {
			if key == "nebulalog.operation" {
				continue
			}
			if want, ok := expected.Config[key]; !ok {
				t.Log("unexpected config key", key)
			} else if value != want {
				t.Log("changed config key", key)
			}
		}
		for key := range expected.Config {
			if _, ok := actual.Config[key]; !ok {
				t.Log("missing config key", key)
			}
		}
		t.Fatal(err)
	}
	if p.Enabled || !p.Configured {
		t.Fatal("temporary fixture must be disabled")
	}
	status, err := m.TestStatus(ctx, s.Alias)
	if err != nil || !status.ConfigurationValid || status.ExternalLoginTested {
		t.Fatal(status, err)
	}
	s.Groups.Viewer = "synthetic-live-viewer-updated"
	p, err = m.Save(ctx, s)
	if err != nil || p.Enabled || p.Groups.Viewer != s.Groups.Viewer {
		t.Fatal(p, err)
	}
}

func TestExpiredCertificateRemainsInspectableForRotation(t *testing.T) {
	m, f := newFake(t)
	s := setup(t)
	s.MetadataXML = fixtureAt(t, time.Now().Add(-3*time.Hour), time.Now().Add(-time.Hour))
	old, err := parseMetadata(s.MetadataXML, false, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.providers[s.Alias] = m.desired(s, old)
	p, err := m.Inspect(context.Background(), s.Alias)
	if err != nil || len(p.Certificates) != 1 || p.Certificates[0].CurrentlyValid || p.Certificates[0].SHA256 == "" {
		t.Fatal(p, err)
	}
	if _, err := m.Preview(s); !IsKind(err, "validation") {
		t.Fatal("expired certificate admitted", err)
	}
	status, err := m.TestStatus(context.Background(), s.Alias)
	if err != nil || status.ConfigurationValid {
		t.Fatal(status, err)
	}
}

func TestUpstreamBodiesBoundedAndRedirectsNotFollowed(t *testing.T) {
	for _, mode := range []string{"large", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			contacted := false
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contacted = true; w.WriteHeader(200) }))
			defer other.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/token") {
					json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access-token", "expires_in": 300})
					return
				}
				if mode == "large" {
					fmt.Fprint(w, strings.Repeat("private-upstream-data", 100000))
					return
				}
				http.Redirect(w, r, other.URL, http.StatusFound)
			}))
			defer server.Close()
			m, err := New(Config{BaseURL: server.URL, PublicBaseURL: "https://auth.example.test", Realm: "nebulalog", ClientID: "nebulalog-identity-manager", ClientSecret: "synthetic-service-secret", AllowHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			_, err = m.Inspect(context.Background(), "okta")
			if err == nil || strings.Contains(err.Error(), "private-upstream-data") || contacted {
				t.Fatal("unsafe upstream handling", err, contacted)
			}
		})
	}
}
