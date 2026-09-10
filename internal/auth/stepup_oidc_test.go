package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func oidcStepUpParams() url.Values {
	claims, _ := json.Marshal(map[string]any{"id_token": map[string]any{"acr": map[string]any{"essential": true, "values": []string{HostControlACR}}}})
	return url.Values{"client_id": {HostControlClient}, "response_type": {"code"}, "response_mode": {"query"}, "scope": {"openid"}, "redirect_uri": {"https://appliance.example.test/api/host/step-up/callback"},
		"state": {strings.Repeat("s", 43)}, "nonce": {strings.Repeat("n", 43)}, "code_challenge": {strings.Repeat("c", 43)}, "code_challenge_method": {"S256"},
		"prompt": {"login"}, "max_age": {"0"}, "acr_values": {HostControlACR}, "claims": {string(claims)}}
}

func oidcStepUpTLSClient(t *testing.T, handler http.HandlerFunc) (*StepUpOIDCClient, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	c, err := NewStepUpOIDCClient(server.URL+"/realms/nebulalog", "test-only:secret+/ &", &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal("client setup failed")
	}
	t.Cleanup(c.client.CloseIdleConnections)
	return c, server
}

func TestStepUpOIDCConfidentialPARAndCodeExchange(t *testing.T) {
	var calls atomic.Int32
	c, server := oidcStepUpTLSClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != HostControlClient || password != url.QueryEscape("test-only:secret+/ &") || r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("invalid confidential request")
		}
		if err := r.ParseForm(); err != nil {
			t.Error("form decode failed")
		}
		if r.Form.Has("client_secret") {
			t.Error("client secret duplicated in form")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/nebulalog/protocol/openid-connect/ext/par/request":
			if r.Form.Encode() != oidcStepUpParams().Encode() {
				t.Error("PAR request changed")
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"request_uri":"urn:ietf:params:oauth:request_uri:01234567-89ab-cdef-0123-456789abcdef","expires_in":60}`)
		case "/realms/nebulalog/protocol/openid-connect/token":
			if len(r.Form) != 5 || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "synthetic-code" || r.Form.Get("code_verifier") != strings.Repeat("v", 43) || r.Form.Get("redirect_uri") != oidcStepUpParams().Get("redirect_uri") {
				t.Error("token request changed")
			}
			fmt.Fprint(w, `{"token_type":"Bearer","scope":"openid","expires_in":120,"refresh_expires_in":0,"id_token":"synthetic-id","access_token":"synthetic-access"}`)
		default:
			t.Error("unexpected path")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	par, err := c.Push(context.Background(), oidcStepUpParams())
	if err != nil {
		t.Fatal("PAR failed")
	}
	authorize, err := url.Parse(c.AuthorizationURL(par.URI))
	if err != nil || !strings.HasPrefix(authorize.String(), server.URL+"/realms/nebulalog/protocol/openid-connect/auth?") || len(authorize.Query()) != 2 || authorize.Query().Get("request_uri") != par.URI || authorize.Query().Get("client_id") != HostControlClient {
		t.Fatal("unsafe authorization URL")
	}
	tokens, err := c.Exchange(context.Background(), "synthetic-code", strings.Repeat("v", 43), oidcStepUpParams().Get("redirect_uri"))
	if err != nil || tokens.IDToken != "synthetic-id" || tokens.AccessToken != "synthetic-access" || calls.Load() != 2 {
		t.Fatal("exchange failed")
	}
	for _, value := range []any{c, tokens, par} {
		text := fmt.Sprintf("%v %+v %#v", value, value, value)
		for _, secret := range []string{"test-only:secret", "synthetic-id", "synthetic-access", par.URI} {
			if strings.Contains(text, secret) {
				t.Fatal("formatting exposed authentication material")
			}
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("client serialized")
	}
}

func TestStepUpOIDCRejectsUnsafeConfiguration(t *testing.T) {
	for _, issuer := range []string{"http://auth.example/realms/nebulalog", "https://user:pass@auth.example/realms/nebulalog", "https://auth.example/realms/nebulalog?x=1", "https://auth.example/realms/nebulalog#fragment", "https://auth.example/realms/nebulalog/", "https://auth.example/other/nebulalog", "https://auth.example/realms/nebulalog%2fother", "https://auth.example/realms/.", "https://auth.example/realms/.."} {
		if _, err := NewStepUpOIDCClient(issuer, "synthetic-secret", nil); !errors.Is(err, ErrStepUpUnavailable) {
			t.Fatal("unsafe issuer accepted")
		}
	}
	for _, trust := range []*tls.Config{{InsecureSkipVerify: true}, {MaxVersion: tls.VersionTLS11}, {ServerName: "different.example"}} {
		if _, err := NewStepUpOIDCClient("https://auth.example/realms/nebulalog", "synthetic-secret", trust); !errors.Is(err, ErrStepUpUnavailable) {
			t.Fatal("unsafe TLS configuration accepted")
		}
	}
}

func TestStepUpOIDCRejectsPARMutationsBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	c, _ := oidcStepUpTLSClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) })
	for name, mutate := range map[string]func(url.Values){
		"duplicate": func(p url.Values) { p.Add("state", "second") }, "unknown": func(p url.Values) { p.Set("unknown", "value") },
		"missing": func(p url.Values) { p.Del("claims") }, "nonessential": func(p url.Values) { p.Set("claims", `{}`) },
		"scope": func(p url.Values) { p.Set("scope", "openid offline_access") }, "nonce": func(p url.Values) { p.Set("nonce", "short") },
		"redirect": func(p url.Values) { p.Set("redirect_uri", "http://appliance.example.test/api/host/step-up/callback") },
		"prompt":   func(p url.Values) { p.Set("prompt", "none") }, "code method": func(p url.Values) { p.Set("code_challenge_method", "plain") },
	} {
		t.Run(name, func(t *testing.T) {
			p := oidcStepUpParams()
			mutate(p)
			if _, err := c.Push(context.Background(), p); !errors.Is(err, ErrStepUpUnavailable) {
				t.Fatal("mutated PAR accepted")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached issuer")
	}
}

func TestStepUpOIDCRejectsMalformedResponsesWithoutRetry(t *testing.T) {
	validPAR := `{"request_uri":"urn:ietf:params:oauth:request_uri:01234567-89ab-cdef-0123-456789abcdef","expires_in":60}`
	validTokens := `{"token_type":"Bearer","scope":"openid","expires_in":120,"id_token":"synthetic-id","access_token":"synthetic-access"}`
	for name, tc := range map[string]struct {
		status      int
		media, body string
		par         bool
	}{
		"duplicate":       {status: 201, media: "application/json", body: strings.TrimSuffix(validPAR, "}") + `,"expires_in":120}`, par: true},
		"fraction":        {status: 201, media: "application/json", body: strings.Replace(validPAR, ":60", ":60.5", 1), par: true},
		"zero":            {status: 201, media: "application/json", body: strings.Replace(validPAR, ":60", ":0", 1), par: true},
		"host URI":        {status: 201, media: "application/json", body: strings.Replace(validPAR, "urn:ietf:params:oauth:request_uri:", "https://attacker.example/", 1), par: true},
		"trailing JSON":   {status: 201, media: "application/json", body: validPAR + `{}`, par: true},
		"oversize":        {status: 201, media: "application/json", body: strings.Repeat("x", stepUpResponseLimit+1), par: true},
		"HTML":            {status: 201, media: "text/html", body: validPAR, par: true},
		"error":           {status: 400, media: "application/json", body: `{"error_description":"sensitive-upstream-material"}`, par: true},
		"redirect":        {status: 307, media: "application/json", body: validPAR, par: true},
		"refresh":         {status: 200, media: "application/json", body: strings.TrimSuffix(validTokens, "}") + `,"refresh_token":"sensitive-upstream-material"}`},
		"no openid":       {status: 200, media: "application/json", body: strings.Replace(validTokens, `"openid"`, `""`, 1)},
		"wrong type":      {status: 200, media: "application/json", body: strings.Replace(validTokens, `"Bearer"`, `"bearer"`, 1)},
		"excess lifetime": {status: 200, media: "application/json", body: strings.Replace(validTokens, ":120", ":121", 1)},
		"oversize token":  {status: 200, media: "application/json", body: strings.Replace(validTokens, "synthetic-id", strings.Repeat("x", (64<<10)+1), 1)},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			c, _ := oidcStepUpTLSClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.media)
				w.Header().Set("Location", "https://attacker.example/")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			var err error
			if tc.par {
				_, err = c.Push(context.Background(), oidcStepUpParams())
			} else {
				_, err = c.Exchange(context.Background(), "synthetic-code", strings.Repeat("v", 43), oidcStepUpParams().Get("redirect_uri"))
			}
			if !errors.Is(err, ErrStepUpUnavailable) || strings.Contains(err.Error(), "sensitive-upstream-material") || calls.Load() != 1 {
				t.Fatal("response did not fail once with redacted error")
			}
		})
	}
}

func TestStepUpOIDCVerifiesTLSAndHonorsCancellation(t *testing.T) {
	var calls atomic.Int32
	c, server := oidcStepUpTLSClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Push(ctx, oidcStepUpParams()); !errors.Is(err, ErrStepUpUnavailable) || calls.Load() != 0 {
		t.Fatal("cancelled request reached issuer")
	}
	untrusted, err := NewStepUpOIDCClient(server.URL+"/realms/nebulalog", "synthetic-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.client.CloseIdleConnections()
	if _, err := untrusted.Push(context.Background(), oidcStepUpParams()); !errors.Is(err, ErrStepUpUnavailable) || calls.Load() != 0 {
		t.Fatal("untrusted TLS accepted")
	}
}
