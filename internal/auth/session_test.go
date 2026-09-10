package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

var sessionTestNow = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func signedAuth(t *testing.T, now time.Time) (*Auth, func([]byte) string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	verifier := oidc.NewVerifier("https://auth.example.test/realms/nebulalog", &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}},
		&oidc.Config{ClientID: "nebulalog", SupportedSigningAlgs: []string{"ES256"}, Now: func() time.Time { return now }})
	sign := func(raw []byte) string {
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
	return &Auth{Verifier: verifier, ClientID: "nebulalog"}, sign
}

func syntheticClaims() map[string]any {
	return map[string]any{
		"iss": "https://auth.example.test/realms/nebulalog", "sub": "subject-synthetic", "preferred_username": "synthetic-admin",
		"aud": []string{"nebulalog", "account"}, "azp": "nebulalog", "sid": "private-session-synthetic", "typ": "Bearer",
		"auth_time": sessionTestNow.Add(-30 * time.Second).Unix(), "iat": sessionTestNow.Add(-10 * time.Second).Unix(), "exp": sessionTestNow.Add(290 * time.Second).Unix(),
		"acr": "urn:nebulalog:test-only:reviewed-local-step-up", "amr": []string{"pwd", "otp"},
		"resource_access": map[string]any{"nebulalog": map[string]any{"roles": []string{"ADMINISTRATOR"}}},
	}
}

func marshalClaims(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func captureSession(t *testing.T, a *Auth, bearer string) (VerifiedSession, bool, *httptest.ResponseRecorder) {
	t.Helper()
	var s VerifiedSession
	var available bool
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, available = CurrentSession(r.Context())
		if err := json.NewEncoder(w).Encode(Current(r.Context())); err != nil {
			t.Fatal(err)
		}
	})).ServeHTTP(w, r)
	return s, available, w
}

func testAssurancePolicy() AssurancePolicy {
	return AssurancePolicy{
		Reviewed: true, ReviewID: "synthetic-policy-unit-test-only", ReviewExpiresAt: sessionTestNow.Add(time.Hour),
		Issuer: "https://auth.example.test/realms/nebulalog", Audience: "nebulalog", ClientID: "nebulalog", TokenType: "Bearer",
		AcceptedACR: []string{"urn:nebulalog:test-only:reviewed-local-step-up"}, RequiredAMR: []string{"pwd", "otp"},
		MaxAuthenticationAge: 2 * time.Minute, MaxTokenAge: time.Minute, MaxTokenLifetime: 5 * time.Minute,
	}
}

func TestSignedMiddlewareRetainsPrivateSessionWithoutChangingMe(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	s, available, w := captureSession(t, a, sign(marshalClaims(t, syntheticClaims())))
	if w.Code != http.StatusOK || !available {
		t.Fatalf("status=%d available=%v", w.Code, available)
	}
	if got, want := strings.TrimSpace(w.Body.String()), `{"id":"subject-synthetic","name":"synthetic-admin","role":"ADMINISTRATOR"}`; got != want {
		t.Fatal("public identity contract changed", got)
	}
	if s.SessionID() != "private-session-synthetic" || s.Issuer() != aIssuer() || s.Subject() != "subject-synthetic" || s.ClientID() != "nebulalog" ||
		!s.AuthTime().Equal(sessionTestNow.Add(-30*time.Second)) || !s.IssuedAt().Equal(sessionTestNow.Add(-10*time.Second)) || !s.ExpiresAt().Equal(sessionTestNow.Add(290*time.Second)) ||
		s.ACR() != testAssurancePolicy().AcceptedACR[0] || !reflect.DeepEqual(s.AMR(), []string{"pwd", "otp"}) {
		t.Fatal("signed session claims were not retained correctly")
	}
	if err := testAssurancePolicy().Check(s, sessionTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("session evidence could be exposed as JSON")
	}
	if text := fmt.Sprintf("%v %#v %+v", s, s, s); strings.Contains(text, s.SessionID()) || strings.Contains(text, s.Subject()) {
		t.Fatal("session evidence leaked through formatting")
	}
	audience, amr := s.Audience(), s.AMR()
	audience[0], amr[0] = "modified", "modified"
	if s.Audience()[0] != "nebulalog" || s.AMR()[0] != "pwd" {
		t.Fatal("accessor exposed mutable evidence")
	}
}

func aIssuer() string { return "https://auth.example.test/realms/nebulalog" }

func TestMalformedVerifiedExtraClaimsLeaveRBACIntactButNoSessionEvidence(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	cases := map[string]func(map[string]any){
		"sid object":             func(c map[string]any) { c["sid"] = map[string]string{"value": "forged"} },
		"sid null":               func(c map[string]any) { c["sid"] = nil },
		"sid empty":              func(c map[string]any) { c["sid"] = "" },
		"sid long":               func(c map[string]any) { c["sid"] = strings.Repeat("x", 513) },
		"sid control":            func(c map[string]any) { c["sid"] = "session\ncontrol" },
		"acr numeric":            func(c map[string]any) { c["acr"] = 2 },
		"acr object":             func(c map[string]any) { c["acr"] = map[string]any{"mfa": true} },
		"azp array":              func(c map[string]any) { c["azp"] = []string{"nebulalog"} },
		"auth time text":         func(c map[string]any) { c["auth_time"] = "1788868770" },
		"auth time null":         func(c map[string]any) { c["auth_time"] = nil },
		"auth time fraction":     func(c map[string]any) { c["auth_time"] = json.Number("1788868770.5") },
		"auth time exponent":     func(c map[string]any) { c["auth_time"] = json.Number("1e9") },
		"auth time negative":     func(c map[string]any) { c["auth_time"] = -1 },
		"auth time zero":         func(c map[string]any) { c["auth_time"] = 0 },
		"auth time milliseconds": func(c map[string]any) { c["auth_time"] = sessionTestNow.UnixMilli() },
		"auth time overflow":     func(c map[string]any) { c["auth_time"] = json.Number("9223372036854775808") },
		"amr scalar":             func(c map[string]any) { c["amr"] = "mfa" },
		"amr null":               func(c map[string]any) { c["amr"] = nil },
		"amr mixed":              func(c map[string]any) { c["amr"] = []any{"otp", 2} },
		"amr duplicate":          func(c map[string]any) { c["amr"] = []string{"otp", "otp"} },
		"too many methods":       func(c map[string]any) { c["amr"] = strings.Split(strings.Repeat("method,", 17), ",") },
		"too large payload":      func(c map[string]any) { c["ignored"] = strings.Repeat("x", maxSessionClaimsBytes) },
		"too deep payload": func(c map[string]any) {
			c["ignored"] = json.RawMessage(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claims := syntheticClaims()
			mutate(claims)
			s, available, w := captureSession(t, a, sign(marshalClaims(t, claims)))
			if w.Code != 200 || available || !errors.Is(testAssurancePolicy().Check(s, sessionTestNow), ErrSessionClaims) {
				t.Fatalf("status=%d available=%v", w.Code, available)
			}
		})
	}
	for name, extra := range map[string]string{
		"duplicate sid":     `,"sid":"second-session"`,
		"escaped duplicate": `,"s\u0069d":"second-session"`,
		"nested duplicate":  `,"ignored":{"a":1,"a":2}`,
		"surrogate":         `,"ignored_extra":true,"other":0`,
	} {
		t.Run(name, func(t *testing.T) {
			raw := marshalClaims(t, syntheticClaims())
			if name == "surrogate" {
				raw = []byte(strings.Replace(string(raw), "private-session-synthetic", `\ud800`, 1))
			} else {
				raw = []byte(strings.TrimSuffix(string(raw), "}") + extra + "}")
			}
			_, available, w := captureSession(t, a, sign(raw))
			if w.Code != 200 || available {
				t.Fatalf("status=%d available=%v", w.Code, available)
			}
		})
	}
}

func TestSignedMiddlewareRejectsWrongSignatureIssuerAudienceAndExpiry(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	_, otherSign := signedAuth(t, sessionTestNow)
	for _, mode := range []string{"signature", "issuer", "audience", "expired", "no role"} {
		t.Run(mode, func(t *testing.T) {
			claims := syntheticClaims()
			useSigner := sign
			want := 401
			switch mode {
			case "signature":
				useSigner = otherSign
			case "issuer":
				claims["iss"] = "https://different.example.test/realms/nebulalog"
			case "audience":
				claims["aud"] = "other-client"
			case "expired":
				claims["exp"] = sessionTestNow.Add(-time.Second).Unix()
			case "no role":
				delete(claims, "resource_access")
				want = 403
			}
			_, available, w := captureSession(t, a, useSigner(marshalClaims(t, claims)))
			if w.Code != want || available {
				t.Fatalf("status=%d available=%v", w.Code, available)
			}
		})
	}
}

func TestAssuranceRefusesAbsentStaleFutureWrongClientAndGenericMFA(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	cases := map[string]struct {
		mutate func(map[string]any)
		want   error
	}{
		"missing sid": {func(c map[string]any) { delete(c, "sid") }, ErrSessionClaims},
		"legacy session_state fallback forbidden": {func(c map[string]any) { delete(c, "sid"); c["session_state"] = "legacy" }, ErrSessionClaims},
		"missing azp":                 {func(c map[string]any) { delete(c, "azp") }, ErrSessionClaims},
		"missing auth time":           {func(c map[string]any) { delete(c, "auth_time") }, ErrSessionClaims},
		"missing token type":          {func(c map[string]any) { delete(c, "typ") }, ErrSessionClaims},
		"wrong client":                {func(c map[string]any) { c["azp"] = "another-client" }, ErrSessionBinding},
		"ID token":                    {func(c map[string]any) { c["typ"] = "ID" }, ErrSessionBinding},
		"stale auth with fresh token": {func(c map[string]any) { c["auth_time"] = sessionTestNow.Add(-10 * time.Minute).Unix() }, ErrSessionTime},
		"auth boundary":               {func(c map[string]any) { c["auth_time"] = sessionTestNow.Add(-2 * time.Minute).Unix() }, ErrSessionTime},
		"token boundary": {func(c map[string]any) {
			c["auth_time"] = sessionTestNow.Add(-time.Minute).Unix()
			c["iat"] = sessionTestNow.Add(-time.Minute).Unix()
			c["exp"] = sessionTestNow.Add(4 * time.Minute).Unix()
		}, ErrSessionTime},
		"future auth":        {func(c map[string]any) { c["auth_time"] = sessionTestNow.Add(time.Second).Unix() }, ErrSessionTime},
		"future issue":       {func(c map[string]any) { c["iat"] = sessionTestNow.Add(time.Second).Unix() }, ErrSessionTime},
		"future not before":  {func(c map[string]any) { c["nbf"] = sessionTestNow.Add(time.Second).Unix() }, ErrSessionTime},
		"auth after issue":   {func(c map[string]any) { c["auth_time"] = sessionTestNow.Add(-5 * time.Second).Unix() }, ErrSessionTime},
		"excessive lifetime": {func(c map[string]any) { c["exp"] = sessionTestNow.Add(time.Hour).Unix() }, ErrSessionTime},
		"no ACR with MFA looking claims": {func(c map[string]any) {
			delete(c, "acr")
			c["mfa"] = true
			c["upstream_amr"] = []string{"mfa"}
			c["amr"] = []string{"pwd", "otp", "mfa"}
		}, ErrAssurance},
		"default ACR":             {func(c map[string]any) { c["acr"] = "1" }, ErrAssurance},
		"numeric ACR not ordered": {func(c map[string]any) { c["acr"] = "999" }, ErrAssurance},
		"unreviewed broker ACR":   {func(c map[string]any) { c["acr"] = "urn:broker:mfa" }, ErrAssurance},
		"missing method":          {func(c map[string]any) { c["amr"] = []string{"pwd"} }, ErrAssurance},
		"method case differs":     {func(c map[string]any) { c["amr"] = []string{"pwd", "OTP"} }, ErrAssurance},
		"AMR absent":              {func(c map[string]any) { delete(c, "amr") }, ErrAssurance},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			claims := syntheticClaims()
			test.mutate(claims)
			s, available, w := captureSession(t, a, sign(marshalClaims(t, claims)))
			if w.Code != 200 || !available {
				t.Fatalf("ordinary RBAC changed: status=%d available=%v", w.Code, available)
			}
			if err := testAssurancePolicy().Check(s, sessionTestNow); !errors.Is(err, test.want) {
				t.Fatal(err)
			}
		})
	}
}

func TestAssurancePolicyRequiresExplicitBoundedCurrentReview(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	s, _, _ := captureSession(t, a, sign(marshalClaims(t, syntheticClaims())))
	if err := (AssurancePolicy{}).Check(s, sessionTestNow); !errors.Is(err, ErrAssurancePolicy) {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AssurancePolicy){
		"unreviewed":         func(p *AssurancePolicy) { p.Reviewed = false },
		"no review ID":       func(p *AssurancePolicy) { p.ReviewID = "" },
		"expired review":     func(p *AssurancePolicy) { p.ReviewExpiresAt = sessionTestNow },
		"no ACR":             func(p *AssurancePolicy) { p.AcceptedACR = nil },
		"duplicate ACR":      func(p *AssurancePolicy) { p.AcceptedACR = []string{"same", "same"} },
		"HTTP issuer":        func(p *AssurancePolicy) { p.Issuer = "http://auth.example.test" },
		"issuer credentials": func(p *AssurancePolicy) { p.Issuer = "https://user:secret@auth.example.test" },
		"no client":          func(p *AssurancePolicy) { p.ClientID = "" },
		"no audience":        func(p *AssurancePolicy) { p.Audience = "" },
		"no type":            func(p *AssurancePolicy) { p.TokenType = "" },
		"zero auth max":      func(p *AssurancePolicy) { p.MaxAuthenticationAge = 0 },
		"excessive auth max": func(p *AssurancePolicy) { p.MaxAuthenticationAge = time.Hour },
		"negative token max": func(p *AssurancePolicy) { p.MaxTokenAge = -time.Second },
		"zero lifetime":      func(p *AssurancePolicy) { p.MaxTokenLifetime = 0 },
		"excessive skew":     func(p *AssurancePolicy) { p.ClockSkew = time.Minute },
		"negative skew":      func(p *AssurancePolicy) { p.ClockSkew = -time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			p := testAssurancePolicy()
			mutate(&p)
			if err := p.Check(s, sessionTestNow); !errors.Is(err, ErrAssurancePolicy) {
				t.Fatal(err)
			}
		})
	}
	p := testAssurancePolicy()
	p.ClientID = "other-client"
	if err := p.Check(s, sessionTestNow); !errors.Is(err, ErrSessionBinding) {
		t.Fatal(err)
	}
	p = testAssurancePolicy()
	p.Audience = "host-control"
	if err := p.Check(s, sessionTestNow); !errors.Is(err, ErrSessionBinding) {
		t.Fatal(err)
	}
	p = testAssurancePolicy()
	p.Issuer = "https://other.example.test"
	if err := p.Check(s, sessionTestNow); !errors.Is(err, ErrSessionBinding) {
		t.Fatal(err)
	}
	p = testAssurancePolicy()
	if err := p.Check(VerifiedSession{}, sessionTestNow); !errors.Is(err, ErrSessionClaims) {
		t.Fatal(err)
	}
	if _, ok := CurrentSession(context.Background()); ok {
		t.Fatal("missing context produced session evidence")
	}
	if err := p.Check(s, time.Time{}); !errors.Is(err, ErrAssurancePolicy) {
		t.Fatal(err)
	}
}

func TestExpiryAndSkewAreRecheckedAtUse(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	claims := syntheticClaims()
	claims["auth_time"], claims["iat"], claims["nbf"] = sessionTestNow.Add(5*time.Second).Unix(), sessionTestNow.Add(5*time.Second).Unix(), sessionTestNow.Add(5*time.Second).Unix()
	s, available, w := captureSession(t, a, sign(marshalClaims(t, claims)))
	if w.Code != 200 || !available {
		t.Fatalf("status=%d available=%v", w.Code, available)
	}
	p := testAssurancePolicy()
	p.ClockSkew = 5 * time.Second
	if err := p.Check(s, sessionTestNow); err != nil {
		t.Fatal(err)
	}
	p.ClockSkew = 4 * time.Second
	if err := p.Check(s, sessionTestNow); !errors.Is(err, ErrSessionTime) {
		t.Fatal(err)
	}
	claims = syntheticClaims()
	claims["exp"] = sessionTestNow.Add(time.Second).Unix()
	s, _, _ = captureSession(t, a, sign(marshalClaims(t, claims)))
	p = testAssurancePolicy()
	p.ClockSkew = 30 * time.Second
	if err := p.Check(s, sessionTestNow.Add(time.Second)); !errors.Is(err, ErrSessionTime) {
		t.Fatal("expiry was extended by clock skew", err)
	}
}

func TestSessionEvidenceDoesNotChangeRoleChecks(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	for _, role := range []string{"VIEWER", "ANALYST", "ADMINISTRATOR"} {
		t.Run(role, func(t *testing.T) {
			claims := syntheticClaims()
			claims["aud"] = "nebulalog" // Both standard audience encodings work.
			claims["resource_access"] = map[string]any{"nebulalog": map[string]any{"roles": []string{role}}}
			s, available, w := captureSession(t, a, sign(marshalClaims(t, claims)))
			if w.Code != 200 || !available || !strings.Contains(w.Body.String(), `"role":"`+role+`"`) {
				t.Fatalf("status=%d available=%v", w.Code, available)
			}
			if err := testAssurancePolicy().Check(s, sessionTestNow); err != nil {
				t.Fatal("assurance must remain separate from RBAC", err)
			}
			r := httptest.NewRequest(http.MethodPost, "/privileged-test", nil)
			r.Header.Set("Authorization", "Bearer "+sign(marshalClaims(t, claims)))
			w = httptest.NewRecorder()
			a.Middleware(Require("ADMINISTRATOR", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
			want := 403
			if role == "ADMINISTRATOR" {
				want = 204
			}
			if w.Code != want {
				t.Fatal("existing role guard changed", w.Code)
			}
		})
	}
}
