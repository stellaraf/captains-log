package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// This is a synthetic issuer, not proof of Keycloak's authentication flow. It
// exercises the real TLS/PAR/token/JWKS client, signed middleware, constructor,
// coordinator and isolated PostgreSQL together to catch integration drift.
func TestStepUpTLSPostgresIntegration(t *testing.T) {
	pool := postgresStepUpTestPool(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("signing fixture failed")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "synthetic-test"))
	if err != nil {
		t.Fatal("signer fixture failed")
	}
	sign := func(claims map[string]any) string {
		raw, e := json.Marshal(claims)
		if e != nil {
			t.Fatal("claim fixture failed")
		}
		jws, e := signer.Sign(raw)
		if e != nil {
			t.Fatal("signature fixture failed")
		}
		value, e := jws.CompactSerialize()
		if e != nil {
			t.Fatal("JWT fixture failed")
		}
		return value
	}
	var mu sync.Mutex
	var pushed url.Values
	var exchanges, keyReads atomic.Int32
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/nebulalog/protocol/openid-connect/certs":
			keyReads.Add(1)
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "synthetic-test", Algorithm: "ES256", Use: "sig"}}})
		case "/realms/nebulalog/protocol/openid-connect/ext/par/request":
			if r.ParseForm() != nil || len(r.Form) != 13 {
				t.Error("actual coordinator/provider PAR mismatch")
				w.WriteHeader(400)
				return
			}
			mu.Lock()
			pushed = r.Form
			mu.Unlock()
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"request_uri": stepUpRequestURIPrefix + "01234567-89ab-cdef-0123-456789abcdef", "expires_in": 120})
		case "/realms/nebulalog/protocol/openid-connect/token":
			exchanges.Add(1)
			if r.ParseForm() != nil {
				t.Error("code form failed")
				w.WriteHeader(400)
				return
			}
			mu.Lock()
			nonce, challenge, redirect := pushed.Get("nonce"), pushed.Get("code_challenge"), pushed.Get("redirect_uri")
			mu.Unlock()
			hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "synthetic-code" || base64.RawURLEncoding.EncodeToString(hash[:]) != challenge || r.Form.Get("redirect_uri") != redirect {
				t.Error("code binding failed")
				w.WriteHeader(400)
				return
			}
			now := time.Now().Unix()
			access := map[string]any{"iss": issuer, "sub": "synthetic-admin", "aud": HostControlClient, "azp": HostControlClient, "sid": "new-mfa-session", "typ": "Bearer", "auth_time": now, "iat": now, "exp": now + 120, "acr": HostControlACR,
				"resource_access": map[string]any{"nebulalog": map[string]any{"roles": []string{"ADMINISTRATOR"}}}}
			rawAccess := sign(access)
			id := map[string]any{}
			for k, v := range access {
				id[k] = v
			}
			delete(id, "resource_access")
			id["typ"], id["nonce"] = "ID", nonce
			atHash := sha256.Sum256([]byte(rawAccess))
			id["at_hash"] = base64.RawURLEncoding.EncodeToString(atHash[:16])
			json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "scope": "openid", "expires_in": 120, "id_token": sign(id), "access_token": rawAccess})
		default:
			t.Error("unexpected issuer path")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	issuer = server.URL + "/realms/nebulalog"
	trust := x509.NewCertPool()
	trust.AddCert(server.Certificate())
	client, err := NewStepUpOIDCClient(issuer, "synthetic-private-secret", &tls.Config{RootCAs: trust})
	if err != nil {
		t.Fatal("TLS client failed")
	}
	defer client.client.CloseIdleConnections()
	now := time.Now().UTC()
	policy := AssurancePolicy{Reviewed: true, ReviewID: "synthetic-test-only", ReviewExpiresAt: now.Add(time.Hour), Issuer: issuer, Audience: HostControlClient, ClientID: HostControlClient, TokenType: "Bearer", AcceptedACR: []string{HostControlACR}, MaxAuthenticationAge: 120 * time.Second, MaxTokenAge: 120 * time.Second, MaxTokenLifetime: 120 * time.Second}
	coordinator, err := NewStepUp(StepUpConfig{Policy: policy, PolicyGenerationSHA: strings.Repeat("c", 64), ApplicationClientID: "nebulalog", RedirectURI: "https://appliance.example.test/api/host/step-up/callback"}, NewPostgresStepUpStore(pool), client)
	if err != nil {
		t.Fatal("coordinator constructor failed")
	}
	// Mutation of caller-owned policy slices must not alter the frozen policy.
	policy.AcceptedACR[0] = "attacker-value"
	app := &Auth{ClientID: "nebulalog", Verifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{ClientID: "nebulalog", SupportedSigningAlgs: []string{"ES256"}})}
	original := sign(map[string]any{"iss": issuer, "sub": "synthetic-admin", "aud": "nebulalog", "azp": "nebulalog", "sid": "original-app-session", "typ": "Bearer", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "resource_access": map[string]any{"nebulalog": map[string]any{"roles": []string{"ADMINISTRATOR"}}}})
	var originalContext context.Context
	req := httptest.NewRequest("POST", "/synthetic-authenticated-step-up", nil)
	req.Header.Set("Authorization", "Bearer "+original)
	w := httptest.NewRecorder()
	app.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originalContext = r.Context() })).ServeHTTP(w, req)
	if w.Code != 200 || originalContext == nil {
		t.Fatal("signed original administrator middleware failed")
	}
	binding := StepUpBinding{InstallationID: "11111111-2222-3333-4444-555555555555", PlanID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Operation: "storage.grow", PlanDigest: strings.Repeat("a", 64), ResourceRevision: strings.Repeat("b", 64), ExpiresAt: now.Add(3 * time.Minute)}
	binding.Challenge = syntheticStepUpChallenge(binding, issuer, "nebulalog", "synthetic-admin", "original-app-session", now)
	start, err := coordinator.Begin(originalContext, binding)
	if err != nil || start.AuthorizationURL == "" {
		t.Fatal("real PAR and PostgreSQL begin failed")
	}
	mu.Lock()
	state := pushed.Get("state")
	mu.Unlock()
	evidence, err := coordinator.Complete(originalContext, state, "synthetic-code", binding)
	if err != nil || evidence.session.sid != "new-mfa-session" || evidence.original.SessionDigest != binding.Challenge.SessionDigest || evidence.idToken == "" || evidence.accessToken == "" {
		t.Fatal("real TLS/JWKS/PostgreSQL completion failed")
	}
	if _, err := coordinator.Complete(originalContext, state, "synthetic-code", binding); !errors.Is(err, ErrStepUpTransaction) {
		t.Fatal("integrated replay accepted")
	}
	if exchanges.Load() != 1 || keyReads.Load() != 1 {
		t.Fatal("unexpected exchange or JWK request count")
	}
	var remaining int
	if pool.QueryRow(context.Background(), "SELECT count(*) FROM host_stepup_pending_v2").Scan(&remaining) != nil || remaining != 0 {
		t.Fatal("consumed transaction persisted")
	}
}
