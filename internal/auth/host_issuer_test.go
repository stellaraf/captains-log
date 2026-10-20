package auth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const hiUser = "10000000-0000-4000-8000-000000000099"

type hiFixture struct {
	c         *hostIssuer
	server    *httptest.Server
	calls     atomic.Int32
	responses map[string]any
	override  func(http.ResponseWriter, *http.Request) bool
}

func hiID(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012d", n) }

func newHIFixture(t *testing.T) *hiFixture {
	t.Helper()
	f := &hiFixture{responses: map[string]any{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.URL.RawQuery != "" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Cache-Control") != "no-store" {
			t.Error("unexpected request metadata")
		}
		if r.URL.Path == "/realms/nebulalog/protocol/openid-connect/token" {
			name, secret, ok := r.BasicAuth()
			if !ok || name != hostInspectorClient || secret != url.QueryEscape("synthetic-root-secret:+/ &") || r.Method != http.MethodPost || r.ParseForm() != nil ||
				len(r.Form) != 2 || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != hostInspectorClient || r.Form.Has("client_secret") {
				t.Error("incorrect read-only inspector credential request")
			}
		} else if r.Method != http.MethodGet {
			t.Error("non-GET issuer evidence request")
		} else if r.URL.Path != "/realms/nebulalog/protocol/openid-connect/userinfo" && r.Header.Get("Authorization") != "Bearer synthetic-inspector-token" {
			t.Error("admin request did not use private inspector token")
		}
		if f.override != nil && f.override(w, r) {
			return
		}
		value, ok := f.responses[r.URL.Path]
		if !ok {
			t.Error("unexpected endpoint")
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error("response write failed")
		}
	}))
	t.Cleanup(f.server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	config := hostIssuerConfig{issuer: f.server.URL + "/realms/nebulalog", installationID: hiID(1), applicationID: hiID(2), administratorRoleID: hiID(3), inspectorID: hiID(4), inspectorUserID: hiID(5), managementID: hiID(6), inspectorSecret: "synthetic-root-secret:+/ &", roots: pool, inspectorRoleIDs: map[string]string{}}
	roles := []any{}
	for i, name := range []string{"view-users", "view-clients", "view-realm", "query-users", "query-groups", "query-clients"} {
		config.inspectorRoleIDs[name] = hiID(10 + i)
		roles = append(roles, map[string]any{"id": hiID(10 + i), "name": name, "clientRole": true, "composite": hostInspectorRoles[name], "containerId": config.managementID})
	}
	var err error
	f.c, err = newHostIssuer(config)
	if err != nil {
		t.Fatal("fixture construction failed")
	}
	t.Cleanup(f.c.client.CloseIdleConnections)
	base := "/admin/realms/nebulalog/"
	f.responses["/realms/nebulalog/protocol/openid-connect/userinfo"] = map[string]any{"sub": hiUser, "other": "discarded"}
	f.responses["/realms/nebulalog/protocol/openid-connect/token"] = map[string]any{"access_token": "synthetic-inspector-token", "token_type": "Bearer", "expires_in": 300}
	f.responses[base+"clients/"+config.inspectorID] = map[string]any{"id": config.inspectorID, "clientId": hostInspectorClient, "protocol": "openid-connect", "enabled": true, "publicClient": false, "serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "bearerOnly": false, "clientAuthenticatorType": "client-secret", "attributes": map[string]string{"nebulalog-installation": config.installationID, "nebulalog-managed": "true"}}
	// Actual 26.7.3 ModelToRepresentation does not emit serviceAccountClientId.
	// The exact client endpoint plus pinned returned user ID establishes this link.
	f.responses[base+"clients/"+config.inspectorID+"/service-account-user"] = map[string]any{"id": config.inspectorUserID, "enabled": true}
	f.responses[base+"clients/"+config.managementID] = map[string]any{"id": config.managementID, "clientId": "realm-management"}
	f.responses[base+"users/"+config.inspectorUserID+"/role-mappings/clients/"+config.managementID+"/composite"] = roles
	f.responses[base+"clients/"+config.applicationID] = map[string]any{"id": config.applicationID, "clientId": "nebulalog", "enabled": true, "protocol": "openid-connect"}
	f.responses[base+"users/"+hiUser+"/role-mappings/clients/"+config.applicationID+"/composite"] = []any{map[string]any{"id": config.administratorRoleID, "name": "ADMINISTRATOR", "clientRole": true, "composite": false, "containerId": config.applicationID}}
	return f
}

func (f *hiFixture) session(client string) VerifiedSession {
	now := time.Now()
	return VerifiedSession{verified: true, issuer: f.c.config.issuer, subject: hiUser, client: client, sid: "synthetic-session", tokenType: "Bearer", audience: []string{client}, issuedAt: now.Add(-time.Second), expiresAt: now.Add(time.Minute)}
}

func TestHostIssuerExactSessionsAndUncachedAdministrator(t *testing.T) {
	f := newHIFixture(t)
	seen := []string{}
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/userinfo") {
			seen = append(seen, r.Header.Get("Authorization"))
		}
		return false
	}
	for _, pair := range [][2]string{{"original-token", "nebulalog"}, {"new-token", HostControlClient}} {
		if err := f.c.CheckSession(context.Background(), pair[0], f.session(pair[1])); err != nil {
			t.Fatal("session refused")
		}
	}
	if len(seen) != 2 || seen[0] != "Bearer original-token" || seen[1] != "Bearer new-token" {
		t.Fatal("exact bearer changed")
	}
	for i := 0; i < 2; i++ {
		if err := f.c.CurrentAdministrator(context.Background(), hiUser); err != nil {
			t.Fatal("administrator refused")
		}
	}
	if f.calls.Load() != 16 {
		t.Fatal("evidence cached or request sequence changed")
	}
	// A new role read must observe revocation, not the previous successful result.
	f.responses["/admin/realms/nebulalog/users/"+hiUser+"/role-mappings/clients/"+f.c.config.applicationID+"/composite"] = []any{}
	if !errors.Is(f.c.CurrentAdministrator(context.Background(), hiUser), errHostIssuer) {
		t.Fatal("revoked role reused")
	}
}

func TestHostIssuerConfigurationIsPinnedAndCopied(t *testing.T) {
	f := newHIFixture(t)
	for name, change := range map[string]func(*hostIssuerConfig){
		"http":           func(c *hostIssuerConfig) { c.issuer = strings.Replace(c.issuer, "https:", "http:", 1) },
		"query":          func(c *hostIssuerConfig) { c.issuer += "?next=foreign" },
		"fragment":       func(c *hostIssuerConfig) { c.issuer += "#fragment" },
		"path":           func(c *hostIssuerConfig) { c.issuer += "/other" },
		"realm":          func(c *hostIssuerConfig) { c.issuer = strings.Replace(c.issuer, "nebulalog", "master", 1) },
		"userinfo":       func(c *hostIssuerConfig) { c.issuer = strings.Replace(c.issuer, "https://", "https://user:pass@", 1) },
		"encoded":        func(c *hostIssuerConfig) { c.issuer = strings.Replace(c.issuer, "nebulalog", "%6eebulalog", 1) },
		"no trust":       func(c *hostIssuerConfig) { c.roots = nil },
		"no secret":      func(c *hostIssuerConfig) { c.inspectorSecret = "" },
		"ID traversal":   func(c *hostIssuerConfig) { c.inspectorID = "../other" },
		"shared ID":      func(c *hostIssuerConfig) { c.inspectorID = c.applicationID },
		"zero ID":        func(c *hostIssuerConfig) { c.installationID = "00000000-0000-0000-0000-000000000000" },
		"missing role":   func(c *hostIssuerConfig) { delete(c.inspectorRoleIDs, "view-users") },
		"extra role":     func(c *hostIssuerConfig) { c.inspectorRoleIDs["manage-users"] = hiID(88) },
		"role collision": func(c *hostIssuerConfig) { c.inspectorRoleIDs["view-users"] = c.applicationID },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.c.config
			c.inspectorRoleIDs = map[string]string{}
			for k, v := range f.c.config.inspectorRoleIDs {
				c.inspectorRoleIDs[k] = v
			}
			change(&c)
			if _, err := newHostIssuer(c); !errors.Is(err, errHostIssuer) {
				t.Fatal("unsafe config accepted")
			}
		})
	}
	cfg := f.c.config
	cfg.inspectorRoleIDs = map[string]string{}
	for k, v := range f.c.config.inspectorRoleIDs {
		cfg.inspectorRoleIDs[k] = v
	}
	c, err := newHostIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.client.CloseIdleConnections)
	cfg.inspectorRoleIDs["view-users"] = hiID(88)
	if c.config.inspectorRoleIDs["view-users"] == hiID(88) {
		t.Fatal("configuration map aliased")
	}
	transport := c.client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableKeepAlives || !transport.DisableCompression || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.RootCAs == cfg.roots {
		t.Fatal("unsafe transport")
	}
	if f.calls.Load() != 0 {
		t.Fatal("constructor reached issuer")
	}
}

func TestHostIssuerSessionGuardsBeforeNetwork(t *testing.T) {
	f := newHIFixture(t)
	for name, mutate := range map[string]func(*VerifiedSession){
		"unverified": func(s *VerifiedSession) { s.verified = false }, "issuer": func(s *VerifiedSession) { s.issuer = "https://other/realms/nebulalog" },
		"expired": func(s *VerifiedSession) { s.expiresAt = time.Now().Add(-time.Minute) }, "future": func(s *VerifiedSession) { s.issuedAt = time.Now().Add(time.Minute) },
		"no sid": func(s *VerifiedSession) { s.sid = "" }, "wrong audience": func(s *VerifiedSession) { s.audience = []string{"other"} },
		"no subject": func(s *VerifiedSession) { s.subject = "" }, "wrong type": func(s *VerifiedSession) { s.tokenType = "ID" },
	} {
		t.Run(name, func(t *testing.T) {
			s := f.session("nebulalog")
			mutate(&s)
			if f.c.CheckSession(context.Background(), "token", s) == nil {
				t.Fatal("invalid session accepted")
			}
		})
	}
	for _, token := range []string{"", "token\r\nInjected: value", "has space", "unicode-é", strings.Repeat("a", (64<<10)+1)} {
		if f.c.CheckSession(context.Background(), token, f.session("nebulalog")) == nil {
			t.Fatal("unsafe token accepted")
		}
	}
	for _, subject := range []string{"", "..", "../other", "a/b", "a%2fb", "a?b", "a\nb"} {
		if f.c.CurrentAdministrator(context.Background(), subject) == nil {
			t.Fatal("unsafe subject accepted")
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("invalid evidence reached issuer")
	}
}

func TestHostIssuerRejectsMalformedOrUnavailableUserInfo(t *testing.T) {
	for name, tc := range map[string]struct {
		status                int
		media, body, encoding string
	}{
		"revoked": {401, "application/json", `{"error":"sensitive-upstream"}`, ""}, "disabled": {403, "application/json", `{}`, ""}, "outage": {503, "application/json", `{}`, ""},
		"redirect": {302, "application/json", `{}`, ""}, "HTML": {200, "text/html", `{}`, ""}, "compressed": {200, "application/json", `{}`, "gzip"},
		"duplicate": {200, "application/json", `{"sub":"wrong","\u0073ub":"` + hiUser + `"}`, ""}, "nested duplicate": {200, "application/json", `{"sub":"` + hiUser + `","x":{"a":1,"a":2}}`, ""},
		"wrong subject": {200, "application/json", `{"sub":"another"}`, ""}, "wrong type": {200, "application/json", `{"sub":42}`, ""}, "null": {200, "application/json", `null`, ""},
		"trailing": {200, "application/json", `{"sub":"` + hiUser + `"}{}`, ""}, "invalid UTF8": {200, "application/json", "{\"sub\":\"\xff\"}", ""},
		"oversize": {200, "application/json", strings.Repeat("a", hostIssuerLimit+1), ""}, "error field": {200, "application/json", `{"sub":"` + hiUser + `","error":"sensitive-upstream"}`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newHIFixture(t)
			f.override = func(w http.ResponseWriter, r *http.Request) bool {
				w.Header().Set("Content-Type", tc.media)
				w.Header().Set("Content-Encoding", tc.encoding)
				w.Header().Set("Location", f.server.URL+"/foreign")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
				return true
			}
			err := f.c.CheckSession(context.Background(), "original-token", f.session("nebulalog"))
			if !errors.Is(err, errHostIssuer) || f.calls.Load() != 1 || strings.Contains(err.Error(), "sensitive-upstream") {
				t.Fatal("invalid response accepted, retried, redirected or leaked")
			}
		})
	}
}

func TestHostIssuerAdministratorIdentityAndRoleDrift(t *testing.T) {
	for _, name := range []string{"client name", "installation", "managed", "public", "flow", "missing boolean", "service user", "service disabled", "federated service", "management client", "extra privilege", "missing privilege", "duplicate privilege", "replaced privilege", "composite drift", "application disabled", "application name", "missing admin", "replaced admin", "composite admin", "realm role", "duplicate admin", "wrong container", "null roles", "null composite"} {
		t.Run(name, func(t *testing.T) {
			f := newHIFixture(t)
			c := f.c.config
			base := "/admin/realms/nebulalog/"
			cp := base + "clients/" + c.inspectorID
			up := cp + "/service-account-user"
			rp := base + "users/" + c.inspectorUserID + "/role-mappings/clients/" + c.managementID + "/composite"
			ap := base + "clients/" + c.applicationID
			ar := base + "users/" + hiUser + "/role-mappings/clients/" + c.applicationID + "/composite"
			client := f.responses[cp].(map[string]any)
			user := f.responses[up].(map[string]any)
			roles := f.responses[rp].([]any)
			admin := f.responses[ar].([]any)[0].(map[string]any)
			switch name {
			case "client name":
				client["clientId"] = "nebulalog-identity-manager"
			case "installation":
				client["attributes"].(map[string]string)["nebulalog-installation"] = hiID(77)
			case "managed":
				client["attributes"].(map[string]string)["nebulalog-managed"] = "false"
			case "public":
				client["publicClient"] = true
			case "flow":
				client["standardFlowEnabled"] = true
			case "missing boolean":
				delete(client, "publicClient")
			case "service user":
				user["id"] = hiID(77)
			case "service disabled":
				user["enabled"] = false
			case "federated service":
				user["federationLink"] = hiID(77)
			case "management client":
				f.responses[base+"clients/"+c.managementID].(map[string]any)["clientId"] = "other"
			case "extra privilege":
				f.responses[rp] = append(roles, map[string]any{"id": hiID(88), "name": "manage-users", "clientRole": true, "composite": false, "containerId": c.managementID})
			case "missing privilege":
				f.responses[rp] = roles[:len(roles)-1]
			case "duplicate privilege":
				roles[1] = roles[0]
			case "replaced privilege":
				roles[0].(map[string]any)["id"] = hiID(88)
			case "composite drift":
				roles[0].(map[string]any)["composite"] = false
			case "application disabled":
				f.responses[ap].(map[string]any)["enabled"] = false
			case "application name":
				f.responses[ap].(map[string]any)["clientId"] = "other"
			case "missing admin":
				f.responses[ar] = []any{}
			case "replaced admin":
				admin["id"] = hiID(88)
			case "composite admin":
				admin["composite"] = true
			case "realm role":
				admin["clientRole"] = false
			case "duplicate admin":
				f.responses[ar] = []any{admin, admin}
			case "wrong container":
				admin["containerId"] = c.managementID
			case "null roles":
				f.responses[ar] = nil
			case "null composite":
				admin["composite"] = nil
			}
			if !errors.Is(f.c.CurrentAdministrator(context.Background(), hiUser), errHostIssuer) {
				t.Fatal("identity/permission drift accepted")
			}
		})
	}
}

func TestHostIssuerTokenResponseRefusal(t *testing.T) {
	for _, body := range []string{`{"access_token":"one","access_token":"two","token_type":"Bearer","expires_in":300}`, `{"access_token":"token","token_type":"Bearer","expires_in":0}`, `{"access_token":"token","token_type":"Bearer","expires_in":300.5}`, `{"access_token":"token","token_type":"Bearer","expires_in":300,"refresh_token":"refresh"}`, `{"access_token":"token","token_type":"ID","expires_in":300}`, `null`, `[]`} {
		f := newHIFixture(t)
		f.override = func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, body)
			return true
		}
		if !errors.Is(f.c.CurrentAdministrator(context.Background(), hiUser), errHostIssuer) || f.calls.Load() != 1 {
			t.Fatal("malformed credential response accepted")
		}
	}
}

func TestHostIssuerTLSCancellationAndBodyDeadline(t *testing.T) {
	f := newHIFixture(t)
	config := f.c.config
	config.roots = x509.NewCertPool()
	c, err := newHostIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.client.CloseIdleConnections)
	if c.CheckSession(context.Background(), "token", f.session("nebulalog")) == nil || f.calls.Load() != 0 {
		t.Fatal("untrusted TLS accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f.c.CheckSession(ctx, "token", f.session("nebulalog")) == nil || f.c.CurrentAdministrator(ctx, hiUser) == nil || f.calls.Load() != 0 {
		t.Fatal("cancelled work dispatched")
	}
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sub":"`)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return true
	}
	ctx, cancel = context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	if f.c.CheckSession(ctx, "token", f.session("nebulalog")) == nil || time.Since(start) > time.Second {
		t.Fatal("streaming body escaped deadline")
	}
}

func TestHostIssuerRedactionAndNoPolicyAdmission(t *testing.T) {
	f := newHIFixture(t)
	for _, v := range []any{f.c, f.c.config} {
		s := fmt.Sprintf("%v %+v %#v", v, v, v)
		if strings.Contains(s, "synthetic-root-secret") || strings.Contains(s, f.c.config.issuer) {
			t.Fatal("configuration leaked")
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("private issuer serialized")
		}
	}
	type policyAdmission interface {
		Validate(context.Context, string) error
	}
	if _, ok := any(f.c).(policyAdmission); ok {
		t.Fatal("live-check client can admit policy")
	}
}

func TestHostIssuerFixedApplianceRoutingPreservesTLSIdentity(t *testing.T) {
	f := newHIFixture(t)
	config := f.c.config
	config.issuer, config.localKeycloak = "https://example.com/realms/nebulalog", true
	c, err := newHostIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.client.CloseIdleConnections)
	var dials atomic.Int32
	target, _ := url.Parse(f.server.URL)
	// A synthetic network backend intercepts the SAME fixed routing function
	// used in production. Nothing binds or contacts the live local :8443 port.
	backend := func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp" || address != "127.0.0.1:8443" {
			t.Error("appliance destination changed")
		}
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}
	transport := c.client.Transport.(*http.Transport)
	transport.DialContext = hostIssuerDial("example.com:443", true, backend)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Host != "example.com" || r.TLS.ServerName != "example.com" {
			t.Error("issuer Host or SNI changed")
		}
		return false
	}
	session := f.session("nebulalog")
	session.issuer = config.issuer
	if c.CheckSession(context.Background(), "token", session) != nil || c.CurrentAdministrator(context.Background(), hiUser) != nil {
		t.Fatal("fixed private routing failed")
	}
	if dials.Load() != 8 {
		t.Fatal("private path did not obtain fresh evidence")
	}
	for _, address := range []string{"foreign.example:443", "example.com:8443", "127.0.0.1:8443"} {
		if conn, err := transport.DialContext(context.Background(), "tcp", address); conn != nil || !errors.Is(err, errHostIssuer) {
			t.Fatal("unexpected host reached dialer")
		}
	}
	if dials.Load() != 8 {
		t.Fatal("dial mismatch touched network")
	}
	// Fixed IP routing never relaxes CA validation.
	config.roots = x509.NewCertPool()
	untrusted, err := newHostIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(untrusted.client.CloseIdleConnections)
	untrusted.client.Transport.(*http.Transport).DialContext = hostIssuerDial("example.com:443", true, backend)
	before := f.calls.Load()
	if untrusted.CheckSession(context.Background(), "token", session) == nil || f.calls.Load() != before {
		t.Fatal("private route bypassed CA verification")
	}
}
