package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const stepUpResponseLimit = 192 << 10
const stepUpRequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// StepUpOIDCClient implements only the pinned Keycloak authorization-code/PAR
// profile. Endpoints are fixed under the installation-owned HTTPS issuer; no
// request-selected URL, discovery redirect, refresh, retry or token cache exists.
type StepUpOIDCClient struct {
	issuer, secret string
	client         *http.Client
	verifier       Verifier
}

func (c *StepUpOIDCClient) String() string               { return "StepUpOIDCClient[redacted]" }
func (c *StepUpOIDCClient) GoString() string             { return c.String() }
func (c *StepUpOIDCClient) MarshalJSON() ([]byte, error) { return nil, ErrStepUpUnavailable }

// NewStepUpOIDCClient makes no network call. The supplied trust is private
// installation configuration, never an upload/request field. TLS verification
// cannot be disabled. Realm/client/flow read-back qualification is separate.
func NewStepUpOIDCClient(issuer, secret string, trust *tls.Config) (*StepUpOIDCClient, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" ||
		!claimString(issuer, 2048) || !strings.HasPrefix(u.Path, "/realms/") || len(strings.Split(u.Path, "/")) != 3 ||
		!claimString(strings.TrimPrefix(u.Path, "/realms/"), 128) || strings.ContainsAny(u.Path, "%\\ ") || !claimString(secret, 4096) {
		return nil, ErrStepUpUnavailable
	}
	if u.Path == "/realms/." || u.Path == "/realms/.." {
		return nil, ErrStepUpUnavailable
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if trust != nil {
		cfg = trust.Clone()
		if cfg.InsecureSkipVerify || (cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS12) || (cfg.ServerName != "" && cfg.ServerName != u.Hostname()) {
			return nil, ErrStepUpUnavailable
		}
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		if cfg.RootCAs != nil {
			cfg.RootCAs = cfg.RootCAs.Clone()
		}
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, ErrStepUpUnavailable
	}
	transport := base.Clone()
	transport.TLSClientConfig = cfg
	transport.Proxy = nil
	transport.MaxResponseHeaderBytes = 16 << 10
	transport.ResponseHeaderTimeout = 10 * time.Second
	client := &http.Client{Timeout: 10 * time.Second, Transport: stepUpBoundedTransport{transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := oidc.ClientContext(context.Background(), client)
	keys := oidc.NewRemoteKeySet(ctx, issuer+"/protocol/openid-connect/certs")
	verifier := oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: HostControlClient, SupportedSigningAlgs: []string{"RS256", "PS256", "ES256"}})
	return &StepUpOIDCClient{issuer, secret, client, verifier}, nil
}

type stepUpBoundedTransport struct{ inner http.RoundTripper }

func (t stepUpBoundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := t.inner.RoundTrip(r)
	if err != nil {
		return nil, ErrStepUpUnavailable
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, stepUpResponseLimit+1))
	if err != nil || len(raw) > stepUpResponseLimit {
		return nil, ErrStepUpUnavailable
	}
	res.Body = io.NopCloser(bytes.NewReader(raw))
	return res, nil
}

func (c *StepUpOIDCClient) post(ctx context.Context, path string, params url.Values, wantStatus int) (map[string]json.RawMessage, error) {
	if c == nil || c.client == nil {
		return nil, ErrStepUpUnavailable
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuer+"/protocol/openid-connect/"+path, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, ErrStepUpUnavailable
	}
	// RFC 6749 section 2.3.1: encode the components before HTTP Basic.
	r.SetBasicAuth(url.QueryEscape(HostControlClient), url.QueryEscape(c.secret))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Cache-Control", "no-store")
	res, err := c.client.Do(r)
	if err != nil {
		return nil, ErrStepUpUnavailable
	}
	defer res.Body.Close()
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || res.StatusCode != wantStatus {
		return nil, ErrStepUpUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, stepUpResponseLimit+1))
	if err != nil || len(raw) > stepUpResponseLimit {
		return nil, ErrStepUpUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	remaining := 4096
	if checkJSONValue(d, 0, &remaining) != nil {
		return nil, ErrStepUpUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrStepUpUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, ErrStepUpUnavailable
	}
	if _, exists := fields["error"]; exists {
		return nil, ErrStepUpUnavailable
	}
	return fields, nil
}

func stepUpSeconds(raw json.RawMessage, maximum int) (time.Duration, error) {
	if len(raw) == 0 || len(raw) > 6 {
		return 0, ErrStepUpUnavailable
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, ErrStepUpUnavailable
		}
	}
	n, err := strconv.Atoi(string(raw))
	if err != nil || n <= 0 || n > maximum {
		return 0, ErrStepUpUnavailable
	}
	return time.Duration(n) * time.Second, nil
}

func (c *StepUpOIDCClient) Push(ctx context.Context, params url.Values) (stepUpPAR, error) {
	// The coordinator constructs this exact request. Refuse accidental callers
	// attempting to turn this client into a generic OAuth request proxy.
	if len(params) != 13 {
		return stepUpPAR{}, ErrStepUpUnavailable
	}
	for _, v := range params {
		if len(v) != 1 || !claimString(v[0], 4096) {
			return stepUpPAR{}, ErrStepUpUnavailable
		}
	}
	for k, v := range map[string]string{"client_id": HostControlClient, "response_type": "code", "response_mode": "query", "scope": "openid", "code_challenge_method": "S256", "prompt": "login", "max_age": "0", "acr_values": HostControlACR} {
		if params.Get(k) != v {
			return stepUpPAR{}, ErrStepUpUnavailable
		}
	}
	if !stepUpOpaque.MatchString(params.Get("state")) || !stepUpOpaque.MatchString(params.Get("nonce")) || !stepUpOpaque.MatchString(params.Get("code_challenge")) {
		return stepUpPAR{}, ErrStepUpUnavailable
	}
	claims, _ := json.Marshal(map[string]any{"id_token": map[string]any{"acr": map[string]any{"essential": true, "values": []string{HostControlACR}}}})
	redirect, err := url.Parse(params.Get("redirect_uri"))
	if params.Get("claims") != string(claims) || err != nil || redirect.Scheme != "https" || redirect.Host == "" || redirect.User != nil || redirect.RawQuery != "" || redirect.ForceQuery || redirect.Fragment != "" || redirect.RawPath != "" || redirect.Path != "/api/host/step-up/callback" {
		return stepUpPAR{}, ErrStepUpUnavailable
	}
	fields, err := c.post(ctx, "ext/par/request", params, http.StatusCreated)
	if err != nil || len(fields) != 2 {
		return stepUpPAR{}, ErrStepUpUnavailable
	}
	var uri string
	lifetime, err := stepUpSeconds(fields["expires_in"], 1200)
	if err != nil || json.Unmarshal(fields["request_uri"], &uri) != nil || !validStepUpRequestURI(uri) {
		return stepUpPAR{}, ErrStepUpUnavailable
	}
	return stepUpPAR{uri, lifetime}, nil
}

func validStepUpRequestURI(uri string) bool {
	if !strings.HasPrefix(uri, stepUpRequestURIPrefix) || len(uri) > 512 {
		return false
	}
	suffix := strings.TrimPrefix(uri, stepUpRequestURIPrefix)
	if len(suffix) < 16 {
		return false
	}
	for _, c := range suffix {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func (c *StepUpOIDCClient) AuthorizationURL(uri string) string {
	if c == nil || !validStepUpRequestURI(uri) {
		return ""
	}
	return c.issuer + "/protocol/openid-connect/auth?" + url.Values{"client_id": {HostControlClient}, "request_uri": {uri}}.Encode()
}

func (c *StepUpOIDCClient) Exchange(ctx context.Context, code, verifier, redirect string) (stepUpTokens, error) {
	if !claimString(code, 4096) || !stepUpOpaque.MatchString(verifier) {
		return stepUpTokens{}, ErrStepUpUnavailable
	}
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "/api/host/step-up/callback" || u.RawPath != "" {
		return stepUpTokens{}, ErrStepUpUnavailable
	}
	fields, err := c.post(ctx, "token", url.Values{"client_id": {HostControlClient}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirect}}, http.StatusOK)
	if err != nil {
		return stepUpTokens{}, ErrStepUpUnavailable
	}
	if _, exists := fields["refresh_token"]; exists {
		return stepUpTokens{}, ErrStepUpUnavailable
	}
	var kind, scope string
	var tokens stepUpTokens
	if json.Unmarshal(fields["token_type"], &kind) != nil || kind != "Bearer" || json.Unmarshal(fields["scope"], &scope) != nil || scope != "openid" ||
		json.Unmarshal(fields["id_token"], &tokens.IDToken) != nil || !claimString(tokens.IDToken, 64<<10) ||
		json.Unmarshal(fields["access_token"], &tokens.AccessToken) != nil || !claimString(tokens.AccessToken, 64<<10) {
		return stepUpTokens{}, ErrStepUpUnavailable
	}
	if _, err := stepUpSeconds(fields["expires_in"], 120); err != nil {
		return stepUpTokens{}, ErrStepUpUnavailable
	}
	return tokens, nil
}
