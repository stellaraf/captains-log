package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHostReadMatchesApplicationRequiresCurrentSignedBearerBinding(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	cases := []struct {
		name     string
		change   func(map[string]any)
		eligible bool
	}{
		{"current bearer", nil, true},
		{"without MFA assertions", func(c map[string]any) { delete(c, "acr"); delete(c, "amr"); delete(c, "auth_time") }, true},
		{"old authentication permitted for read only", func(c map[string]any) { c["auth_time"] = sessionTestNow.Add(-24 * time.Hour).Unix() }, true},
		{"old issuance still current", func(c map[string]any) { c["iat"] = sessionTestNow.Add(-24 * time.Hour).Unix() }, true},
		{"future issuance at skew boundary", func(c map[string]any) { c["iat"] = sessionTestNow.Add(5 * time.Second).Unix() }, true},
		{"future issuance past skew boundary", func(c map[string]any) { c["iat"] = sessionTestNow.Add(6 * time.Second).Unix() }, false},
		{"expiry before future issuance", func(c map[string]any) {
			c["iat"] = sessionTestNow.Add(5 * time.Second).Unix()
			c["exp"] = sessionTestNow.Add(time.Second).Unix()
		}, false},
		{"expiry equals future issuance", func(c map[string]any) {
			c["iat"] = sessionTestNow.Add(time.Second).Unix()
			c["exp"] = sessionTestNow.Add(time.Second).Unix()
		}, false},
		{"expires after now", func(c map[string]any) { c["exp"] = sessionTestNow.Add(time.Second).Unix() }, true},
		{"expires now", func(c map[string]any) { c["exp"] = sessionTestNow.Unix() }, false},
		{"expired", func(c map[string]any) { c["exp"] = sessionTestNow.Add(-time.Second).Unix() }, false},
		{"not before now", func(c map[string]any) { c["nbf"] = sessionTestNow.Unix() }, true},
		{"not before later", func(c map[string]any) { c["nbf"] = sessionTestNow.Add(time.Second).Unix() }, false},
		{"missing session", func(c map[string]any) { delete(c, "sid") }, false},
		{"null session", func(c map[string]any) { c["sid"] = nil }, false},
		{"empty session", func(c map[string]any) { c["sid"] = "" }, false},
		{"overlong session", func(c map[string]any) { c["sid"] = strings.Repeat("x", 513) }, false},
		{"wrong session type", func(c map[string]any) { c["sid"] = []string{"session"} }, false},
		{"missing authorized party", func(c map[string]any) { delete(c, "azp") }, false},
		{"foreign authorized party", func(c map[string]any) { c["azp"] = "other-client" }, false},
		{"missing token type", func(c map[string]any) { delete(c, "typ") }, false},
		{"ID token", func(c map[string]any) { c["typ"] = "ID" }, false},
		{"lowercase token type", func(c map[string]any) { c["typ"] = "bearer" }, false},
		{"wrong token type", func(c map[string]any) { c["typ"] = 1 }, false},
		{"missing issuance", func(c map[string]any) { delete(c, "iat") }, false},
		{"missing expiry", func(c map[string]any) { delete(c, "exp") }, false},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }, false},
		{"foreign subject", func(c map[string]any) { c["sub"] = "other-subject" }, false},
		{"foreign issuer", func(c map[string]any) { c["iss"] = "https://foreign.example.test/realm" }, false},
		{"foreign audience", func(c map[string]any) { c["aud"] = []string{"other-client"} }, false},
		{"duplicate audiences", func(c map[string]any) { c["aud"] = []string{"nebulalog", "nebulalog"} }, false},
		{"single audience", func(c map[string]any) { c["aud"] = "nebulalog" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := syntheticClaims()
			if tc.change != nil {
				tc.change(claims)
			}
			session, available, w := captureSession(t, a, sign(marshalClaims(t, claims)))
			eligible := session.MatchesApplication("subject-synthetic", "nebulalog", sessionTestNow)
			if eligible != tc.eligible {
				t.Fatalf("eligible=%v want=%v session available=%v HTTP=%d", eligible, tc.eligible, available, w.Code)
			}
			if tc.eligible && (!available || w.Code != http.StatusOK) {
				t.Fatal("eligibility did not originate from verified middleware")
			}
		})
	}
}

func TestHostReadBindingDoesNotCreateAssuranceOrAcceptDifferentApplicationIdentity(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	claims := syntheticClaims()
	delete(claims, "acr")
	delete(claims, "amr")
	delete(claims, "auth_time")
	session, available, w := captureSession(t, a, sign(marshalClaims(t, claims)))
	if w.Code != 200 || !available || !session.MatchesApplication("subject-synthetic", "nebulalog", sessionTestNow) {
		t.Fatal("ordinary current administrator session could not review")
	}
	if err := testAssurancePolicy().Check(session, sessionTestNow); err == nil {
		t.Fatal("read-only eligibility supplied step-up assurance")
	}
	for _, pair := range [][2]string{{"", "nebulalog"}, {"subject-synthetic", ""}, {"other-subject", "nebulalog"}, {"subject-synthetic", "other-client"}} {
		if session.MatchesApplication(pair[0], pair[1], sessionTestNow) {
			t.Fatal("session accepted a different application binding")
		}
	}
	if (VerifiedSession{}).MatchesApplication("subject-synthetic", "nebulalog", sessionTestNow) {
		t.Fatal("zero-value session authorized a host read")
	}
}

func TestHostReadRejectsSignedDuplicateClaimsAtEveryDepth(t *testing.T) {
	a, sign := signedAuth(t, sessionTestNow)
	original := string(marshalClaims(t, syntheticClaims()))
	cases := map[string]string{
		"authorized party": `{"azp":"nebulalog",` + original[1:],
		"session":          `{"sid":"private-session-synthetic",` + original[1:],
		"token type":       `{"typ":"ID",` + original[1:],
		"roles":            strings.Replace(original, `"roles":["ADMINISTRATOR"]`, `"roles":["VIEWER"],"roles":["ADMINISTRATOR"]`, 1),
		"unrelated nested": strings.TrimSuffix(original, "}") + `,"unused":{"claim":1,"claim":2}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			session, available, _ := captureSession(t, a, sign([]byte(raw)))
			if available || session.MatchesApplication("subject-synthetic", "nebulalog", sessionTestNow) {
				t.Fatal("duplicate signed claims created host-read evidence")
			}
		})
	}
}
