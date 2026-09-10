package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/stellaraf/captains-log/internal/auth"
	"github.com/stellaraf/captains-log/internal/hostcontrol"
)

const hostTestOrigin = "https://appliance.example.test"
const hostTestPool = "11111111-1111-4111-8111-111111111111"
const hostTestPlan = "22222222-2222-4222-8222-222222222222"
const hostTestDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const hostTestBody = `{"operation":"storage.grow","parameters":{"pool_id":"` + hostTestPool + `"}}`

// This is only the trusted in-process reader seam. Every HTTP request still
// passes through the real OIDC verifier and signed-session middleware.
type hostPlanTestReader struct {
	calls            []string
	actors           []hostcontrol.Actor
	pool, id, digest string
	err              error
}

func (r *hostPlanTestReader) capture(action string, actor hostcontrol.Actor) {
	r.calls = append(r.calls, action)
	r.actors = append(r.actors, actor)
}
func (r *hostPlanTestReader) Capabilities(_ context.Context, actor hostcontrol.Actor) (hostcontrol.Capabilities, error) {
	r.capture("capabilities", actor)
	return hostcontrol.Capabilities{Control: "read_only", PoolID: hostTestPool,
		Operations: []hostcontrol.Operation{{Operation: "storage.grow", PlanningAvailable: true, Reason: "execution_not_qualified"}}}, r.err
}
func (r *hostPlanTestReader) CreatePlan(_ context.Context, actor hostcontrol.Actor, pool string) (hostcontrol.Plan, error) {
	r.capture("create", actor)
	r.pool = pool
	return hostTestPlanValue(), r.err
}
func (r *hostPlanTestReader) LookupPlan(_ context.Context, actor hostcontrol.Actor, id, digest string) (hostcontrol.Plan, error) {
	r.capture("lookup", actor)
	r.id, r.digest = id, digest
	return hostTestPlanValue(), r.err
}
func hostTestPlanValue() hostcontrol.Plan {
	return hostcontrol.Plan{ID: hostTestPlan, InstallationID: "33333333-3333-4333-8333-333333333333",
		Operation: "storage.grow", Parameters: hostcontrol.Parameters{PoolID: hostTestPool},
		ResourceRevision: strings.Repeat("b", 64), Digest: hostTestDigest,
		IssuedAt: 1788868800, ExpiresAt: 1788868980,
		Review: hostcontrol.Review{CurrentBytes: 1024, PresentedBytes: 2048, UnallocatedDiskBytes: 1024,
			Stages: []string{"partition", "luks", "pv", "lv", "xfs"}, RequiresUnlockCredential: true, Irreversible: true}}
}

type hostPlanHarness struct {
	server *Server
	reader *hostPlanTestReader
	now    time.Time
	sign   func([]byte) string
}

func newHostPlanHarness(t *testing.T) *hostPlanHarness {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := &hostPlanHarness{reader: &hostPlanTestReader{}, now: time.Now().UTC().Truncate(time.Second)}
	verifier := oidc.NewVerifier("https://identity.example.test/realms/nebulalog",
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}},
		&oidc.Config{ClientID: "nebulalog", SupportedSigningAlgs: []string{"ES256"}, Now: func() time.Time { return h.now }})
	h.server = &Server{Auth: &auth.Auth{Verifier: verifier, ClientID: "nebulalog"},
		HostPlans: h.reader, Config: Config{ClientID: "nebulalog", HostPlanPublicOrigin: hostTestOrigin}}
	h.sign = func(raw []byte) string {
		t.Helper()
		signed, err := signer.Sign(raw)
		if err != nil {
			t.Fatal(err)
		}
		token, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	return h
}
func (h *hostPlanHarness) claims() map[string]any {
	return map[string]any{"iss": "https://identity.example.test/realms/nebulalog", "sub": "private-synthetic-subject",
		"preferred_username": "synthetic-administrator", "aud": []string{"nebulalog", "account"},
		"azp": "nebulalog", "sid": "private-synthetic-session", "typ": "Bearer",
		"iat": h.now.Add(-time.Minute).Unix(), "exp": h.now.Add(5 * time.Minute).Unix(),
		"resource_access": map[string]any{"nebulalog": map[string]any{"roles": []string{"ADMINISTRATOR"}}}}
}
func (h *hostPlanHarness) token(t *testing.T, change func(map[string]any)) string {
	t.Helper()
	claims := h.claims()
	if change != nil {
		change(claims)
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return h.sign(raw)
}
func (h *hostPlanHarness) request(method, target, body, token string, change func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Host = "appliance.example.test"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Origin", hostTestOrigin)
	r.Header.Set("Content-Type", "application/json")
	if change != nil {
		change(r)
	}
	w := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(w, r)
	return w
}
func requireHostRejection(t *testing.T, h *hostPlanHarness, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status || len(h.reader.calls) != 0 {
		t.Fatalf("status=%d want=%d host calls=%v body=%s", w.Code, status, h.reader.calls, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("refusal was cacheable: %v", w.Header())
	}
}

func TestHostPlanSignedAdministratorRoutesAndActorBinding(t *testing.T) {
	h := newHostPlanHarness(t)
	token := h.token(t, nil) // No MFA claims: planning cannot grant execution.
	requests := []struct {
		method, target, body string
		status               int
	}{
		{"GET", "/api/appliance/capabilities", "", 200},
		{"POST", "/api/appliance/plans", hostTestBody, 201},
		{"GET", "/api/appliance/plans/" + hostTestPlan + "?digest=" + hostTestDigest, "", 200},
	}
	for _, request := range requests {
		w := h.request(request.method, request.target, request.body, token, nil)
		if w.Code != request.status {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("private response headers missing: %v", w.Header())
		}
		var value map[string]any
		if json.Unmarshal(w.Body.Bytes(), &value) != nil || value["execution_available"] != false {
			t.Fatal("response did not explicitly withhold execution", w.Body.String())
		}
		for _, secret := range []string{token, "private-synthetic-subject", "private-synthetic-session", "synthetic-administrator", "owner_token", "actor"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("response disclosed private identity")
			}
		}
	}
	if len(h.reader.calls) != 3 || h.reader.pool != hostTestPool || h.reader.id != hostTestPlan || h.reader.digest != hostTestDigest {
		t.Fatalf("wrong host requests: %#v", h.reader.calls)
	}
	if h.reader.actors[0] == (hostcontrol.Actor{}) || h.reader.actors[0] != h.reader.actors[1] || h.reader.actors[0] != h.reader.actors[2] {
		t.Fatal("same signed application session was not bound across routes")
	}
	rotated := h.token(t, func(c map[string]any) { c["sid"] = "other-private-session" })
	if w := h.request("GET", "/api/appliance/capabilities", "", rotated, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if h.reader.actors[0] == h.reader.actors[3] {
		t.Fatal("session rotation reused plan ownership")
	}
	otherSubject := h.token(t, func(c map[string]any) { c["sub"] = "other-private-subject" })
	if w := h.request("GET", "/api/appliance/capabilities", "", otherSubject, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if h.reader.actors[0] == h.reader.actors[4] {
		t.Fatal("another subject reused plan ownership")
	}
}

func TestHostPlanRejectsNonadministratorAndUnboundSignedClaims(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any)
		status int
	}{
		{"analyst", func(c map[string]any) {
			c["resource_access"] = map[string]any{"nebulalog": map[string]any{"roles": []string{"ANALYST"}}}
		}, 403},
		{"viewer", func(c map[string]any) {
			c["resource_access"] = map[string]any{"nebulalog": map[string]any{"roles": []string{"VIEWER"}}}
		}, 403},
		{"no role", func(c map[string]any) { delete(c, "resource_access") }, 403},
		{"foreign role", func(c map[string]any) {
			c["resource_access"] = map[string]any{"foreign": map[string]any{"roles": []string{"ADMINISTRATOR"}}}
		}, 403},
		{"missing sid", func(c map[string]any) { delete(c, "sid") }, 401},
		{"missing azp", func(c map[string]any) { delete(c, "azp") }, 401},
		{"wrong azp", func(c map[string]any) { c["azp"] = "other-client" }, 401},
		{"missing typ", func(c map[string]any) { delete(c, "typ") }, 401},
		{"ID token", func(c map[string]any) { c["typ"] = "ID" }, 401},
		{"lowercase bearer", func(c map[string]any) { c["typ"] = "bearer" }, 401},
		{"null sid", func(c map[string]any) { c["sid"] = nil }, 401},
		{"wrong audience", func(c map[string]any) { c["aud"] = []string{"other-client"} }, 401},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://attacker.example.test" }, 401},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }, 401},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }, 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostPlanHarness(t)
			w := h.request("GET", "/api/appliance/capabilities", "", h.token(t, tc.change), nil)
			requireHostRejection(t, h, w, tc.status)
		})
	}
}

func TestHostPlanRejectsInvalidTokensAndAmbiguousAuthentication(t *testing.T) {
	for _, name := range []string{"missing", "malformed", "untrusted signature", "expired", "future nbf", "duplicate authorization", "duplicate sub", "duplicate roles"} {
		t.Run(name, func(t *testing.T) {
			h := newHostPlanHarness(t)
			token := h.token(t, nil)
			var change func(*http.Request)
			switch name {
			case "missing":
				token = ""
			case "malformed":
				token = "not.a.valid-token"
			case "untrusted signature":
				token = newHostPlanHarness(t).token(t, nil)
			case "expired":
				token = h.token(t, func(c map[string]any) { c["exp"] = h.now.Add(-time.Second).Unix() })
			case "future nbf":
				token = h.token(t, func(c map[string]any) { c["nbf"] = h.now.Add(time.Minute).Unix() })
			case "duplicate authorization":
				change = func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+token) }
			case "duplicate sub", "duplicate roles":
				raw, _ := json.Marshal(h.claims())
				if name == "duplicate sub" {
					raw = []byte(`{"sub":"shadow",` + string(raw[1:]))
				} else {
					raw = []byte(strings.Replace(string(raw), `"roles":["ADMINISTRATOR"]`, `"roles":["VIEWER"],"roles":["ADMINISTRATOR"]`, 1))
				}
				token = h.sign(raw)
			}
			requireHostRejection(t, h, h.request("GET", "/api/appliance/capabilities", "", token, change), 401)
		})
	}
}

func TestHostPlanCreateRequiresExactConfiguredOrigin(t *testing.T) {
	cases := []struct {
		name       string
		change     func(*http.Request)
		configured string
		status     int
	}{
		{"missing", func(r *http.Request) { r.Header.Del("Origin") }, hostTestOrigin, 403},
		{"foreign", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example.test") }, hostTestOrigin, 403},
		{"host spoof", func(r *http.Request) {
			r.Host = "attacker.example.test"
			r.Header.Set("Origin", "https://attacker.example.test")
		}, hostTestOrigin, 403},
		{"forwarded host spoof", func(r *http.Request) {
			r.Header.Set("X-Forwarded-Host", "attacker.example.test")
			r.Header.Set("Origin", "https://attacker.example.test")
		}, hostTestOrigin, 403},
		{"duplicate", func(r *http.Request) { r.Header.Add("Origin", hostTestOrigin) }, hostTestOrigin, 403},
		{"combined", func(r *http.Request) { r.Header.Set("Origin", hostTestOrigin+", "+hostTestOrigin) }, hostTestOrigin, 403},
		{"null", func(r *http.Request) { r.Header.Set("Origin", "null") }, hostTestOrigin, 403},
		{"trailing slash", func(r *http.Request) { r.Header.Set("Origin", hostTestOrigin+"/") }, hostTestOrigin, 403},
		{"explicit port mismatch", func(r *http.Request) { r.Header.Set("Origin", hostTestOrigin+":443") }, hostTestOrigin, 403},
		{"same site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, hostTestOrigin, 403},
		{"cross site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, hostTestOrigin, 403},
		{"duplicate fetch site", func(r *http.Request) {
			r.Header.Add("Sec-Fetch-Site", "same-origin")
			r.Header.Add("Sec-Fetch-Site", "same-origin")
		}, hostTestOrigin, 403},
		{"origin unconfigured", nil, "", 503},
		{"insecure configured origin", nil, "http://appliance.example.test", 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostPlanHarness(t)
			h.server.Config.HostPlanPublicOrigin = tc.configured
			requireHostRejection(t, h, h.request("POST", "/api/appliance/plans", hostTestBody, h.token(t, nil), tc.change), tc.status)
		})
	}
	for _, site := range []string{"", "same-origin", "none"} {
		t.Run("accepted "+site, func(t *testing.T) {
			h := newHostPlanHarness(t)
			w := h.request("POST", "/api/appliance/plans", hostTestBody, h.token(t, nil), func(r *http.Request) {
				if site != "" {
					r.Header.Set("Sec-Fetch-Site", site)
				}
			})
			if w.Code != 201 || len(h.reader.calls) != 1 {
				t.Fatalf("status=%d host calls=%v", w.Code, h.reader.calls)
			}
		})
	}
}

func TestHostPlanCreateRejectsAmbiguousOrUnboundedJSON(t *testing.T) {
	cases := map[string]string{
		"top null": "null", "empty": "", "array": "[]", "parameters null": `{"operation":"storage.grow","parameters":null}`,
		"operation null":          `{"operation":null,"parameters":{"pool_id":"` + hostTestPool + `"}}`,
		"pool null":               `{"operation":"storage.grow","parameters":{"pool_id":null}}`,
		"missing operation":       `{"parameters":{"pool_id":"` + hostTestPool + `"}}`,
		"unknown top":             strings.TrimSuffix(hostTestBody, "}") + `,"actor":"attacker"}`,
		"unknown nested":          strings.Replace(hostTestBody, `"pool_id":`, `"device":"/dev/sda","pool_id":`, 1),
		"duplicate operation":     strings.Replace(hostTestBody, `"operation":`, `"operation":"storage.grow","operation":`, 1),
		"duplicate pool":          strings.Replace(hostTestBody, `"pool_id":`, `"pool_id":"`+hostTestPool+`","pool_id":`, 1),
		"case alias top":          strings.Replace(hostTestBody, `"operation"`, `"Operation"`, 1),
		"case alias nested":       strings.Replace(hostTestBody, `"pool_id"`, `"Pool_ID"`, 1),
		"folded duplicate top":    strings.Replace(hostTestBody, `"operation":`, `"Operation":"storage.grow","operation":`, 1),
		"folded duplicate nested": strings.Replace(hostTestBody, `"pool_id":`, `"Pool_ID":"`+hostTestPool+`","pool_id":`, 1),
		"second JSON":             hostTestBody + " {}", "trailing junk": hostTestBody + "x",
		"invalid utf8":    hostTestBody + string([]byte{0xff}),
		"too large":       hostTestBody + strings.Repeat(" ", 16<<10),
		"wrong operation": strings.Replace(hostTestBody, "storage.grow", "storage.execute", 1),
		"device as pool":  strings.Replace(hostTestBody, hostTestPool, "/dev/sda", 1),
		"zero UUID":       strings.Replace(hostTestBody, hostTestPool, "00000000-0000-0000-0000-000000000000", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHostPlanHarness(t)
			requireHostRejection(t, h, h.request("POST", "/api/appliance/plans", body, h.token(t, nil), nil), 400)
		})
	}
	for _, name := range []string{"wrong type", "duplicate type", "missing type", "query"} {
		t.Run(name, func(t *testing.T) {
			h := newHostPlanHarness(t)
			target, status := "/api/appliance/plans", 415
			if name == "query" {
				target += "?unused=1"
				status = 400
			}
			w := h.request("POST", target, hostTestBody, h.token(t, nil), func(r *http.Request) {
				switch name {
				case "wrong type":
					r.Header.Set("Content-Type", "text/plain")
				case "duplicate type":
					r.Header.Add("Content-Type", "application/json")
				case "missing type":
					r.Header.Del("Content-Type")
				}
			})
			requireHostRejection(t, h, w, status)
		})
	}
}

func TestHostPlanLookupRequiresExactIDAndDigest(t *testing.T) {
	for _, target := range []string{
		"/api/appliance/capabilities?unused=1",
		"/api/appliance/plans/" + hostTestPlan,
		"/api/appliance/plans/not-a-uuid?digest=" + hostTestDigest,
		"/api/appliance/plans/" + hostTestPlan + "?digest=short",
		"/api/appliance/plans/" + hostTestPlan + "?digest=" + strings.ToUpper(hostTestDigest),
		"/api/appliance/plans/" + hostTestPlan + "?digest=" + hostTestDigest + "&digest=" + hostTestDigest,
		"/api/appliance/plans/" + hostTestPlan + "?digest=" + hostTestDigest + "&extra=1",
		"/api/appliance/plans/" + hostTestPlan + "?digest=" + hostTestDigest + ";extra=1",
	} {
		t.Run(target, func(t *testing.T) {
			h := newHostPlanHarness(t)
			requireHostRejection(t, h, h.request("GET", target, "", h.token(t, nil), nil), 400)
		})
	}
}

func TestHostPlanErrorsAreFixedAndRedacted(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
	}{
		{"invalid_request", 400}, {"plan_unavailable", 404}, {"plan_expired", 410}, {"resource_changed", 409},
		{"manager_busy", 503}, {"journal_full", 503}, {"peer_not_authorized", 503}, {"unknown-private-reason", 503},
		{"arbitrary error", 503}, {"nil service", 503},
	} {
		t.Run(tc.code, func(t *testing.T) {
			h := newHostPlanHarness(t)
			h.reader.err = &hostcontrol.Refusal{Code: tc.code}
			if tc.code == "arbitrary error" {
				h.reader.err = errors.New("private-synthetic-session /etc/nebulalog/secret /dev/sda")
			}
			if tc.code == "nil service" {
				h.server.HostPlans = nil
			}
			w := h.request("POST", "/api/appliance/plans", hostTestBody, h.token(t, nil), nil)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
			}
			var value map[string]any
			if json.Unmarshal(w.Body.Bytes(), &value) != nil || len(value) != 3 || value["execution_available"] != false {
				t.Fatal("unexpected error shape", w.Body.String())
			}
			code := tc.code
			if tc.code == "arbitrary error" || tc.code == "nil service" || tc.code == "unknown-private-reason" || tc.code == "peer_not_authorized" {
				code = "host_unavailable"
			}
			if value["code"] != code {
				t.Fatal("unexpected refusal code", value["code"])
			}
			for _, secret := range []string{"private-synthetic-session", "/etc/", "/dev/", "unknown-private-reason", "peer_not_authorized"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("private failure detail disclosed")
				}
			}
		})
	}
}

func TestHostPlanRoutesExposeNoExecutionOrStepUp(t *testing.T) {
	h := newHostPlanHarness(t)
	token := h.token(t, nil)
	for _, target := range []string{"/api/appliance/jobs", "/api/appliance/grants", "/api/appliance/step-up",
		"/api/appliance/plans/" + hostTestPlan + "/execute", "/api/appliance/plans/" + hostTestPlan + "/cancel"} {
		w := h.request("POST", target, hostTestBody, token, nil)
		if w.Code != 404 || len(h.reader.calls) != 0 {
			t.Fatalf("unexpected route %s: %d", target, w.Code)
		}
	}
}

func TestHostPlanOriginConfigurationRejectsURLsBeyondAnOrigin(t *testing.T) {
	for _, origin := range []string{"https://appliance.example.test", "https://appliance.example.test:8443", "https://[::1]:8443"} {
		if !ValidHostPlanOrigin(origin) {
			t.Fatalf("valid origin rejected: %s", origin)
		}
	}
	for _, origin := range []string{"", "http://appliance.example.test", "https://user@appliance.example.test",
		"https://appliance.example.test/", "https://appliance.example.test/path", "https://appliance.example.test?x=1",
		"https://appliance.example.test?", "https://appliance.example.test#x", " https://appliance.example.test", "https://"} {
		if ValidHostPlanOrigin(origin) {
			t.Fatalf("unsafe configured origin accepted: %s", origin)
		}
	}
}
