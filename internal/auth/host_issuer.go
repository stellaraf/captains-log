package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var errHostIssuer = errors.New("host issuer live evidence unavailable or invalid")
var hostIssuerUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hostIssuerSubject = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,511}$`)

const hostInspectorClient = "nebulalog-appliance-inspector"
const hostIssuerLimit = 192 << 10
const hostIssuerDeadline = 10 * time.Second

// Private, installation-enrolled inputs only; never decode these from an API
// request. IDs refer to the exact existing installation, not a client-name
// search. The inspector secret comes from root runtime-secrets, never the API's
// write-capable identity-manager credential. This configuration is NOT policy
// qualification and cannot enable a host authorizer by itself.
type hostIssuerConfig struct {
	issuer, installationID, applicationID, administratorRoleID  string
	inspectorID, inspectorUserID, managementID, inspectorSecret string
	inspectorRoleIDs                                            map[string]string
	roots                                                       *x509.CertPool
	// Fixed appliance routing bypasses the edge's intentional /admin denial;
	// HTTP Host, issuer identity and TLS SNI remain the enrolled hostname.
	localKeycloak bool
}

func (hostIssuerConfig) String() string               { return "hostIssuerConfig[redacted]" }
func (c hostIssuerConfig) GoString() string           { return c.String() }
func (hostIssuerConfig) MarshalJSON() ([]byte, error) { return nil, errHostIssuer }

// The six effective roles are the three bootstrap-assigned view roles plus
// their Keycloak 26.7.3 query composites (RealmManager.addQueryCompositeRoles).
// Any extra management privilege, role replacement, or changed composition
// refuses. Broader flow/broker/client-policy/provider drift remains the separate
// mandatory policy verifier's job; no ValidatePolicy success exists here.
var hostInspectorRoles = map[string]bool{
	"view-users": true, "view-clients": true, "view-realm": false,
	"query-users": false, "query-groups": false, "query-clients": false,
}

type hostIssuer struct {
	config hostIssuerConfig
	origin string
	client *http.Client
}

func (*hostIssuer) String() string               { return "hostIssuer[redacted]" }
func (c *hostIssuer) GoString() string           { return c.String() }
func (*hostIssuer) MarshalJSON() ([]byte, error) { return nil, errHostIssuer }

func newHostIssuer(config hostIssuerConfig) (*hostIssuer, error) {
	u, err := url.Parse(config.issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "/realms/nebulalog" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		!claimString(config.issuer, 2048) || config.roots == nil || !claimString(config.inspectorSecret, 4096) {
		return nil, errHostIssuer
	}
	seen := map[string]bool{}
	for _, id := range []string{config.installationID, config.applicationID, config.administratorRoleID,
		config.inspectorID, config.inspectorUserID, config.managementID} {
		if !hostIssuerUUID.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" || seen[id] {
			return nil, errHostIssuer
		}
		seen[id] = true
	}
	if len(config.inspectorRoleIDs) != len(hostInspectorRoles) {
		return nil, errHostIssuer
	}
	roles := map[string]string{}
	for name := range hostInspectorRoles {
		id := config.inspectorRoleIDs[name]
		if !hostIssuerUUID.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" || seen[id] {
			return nil, errHostIssuer
		}
		seen[id], roles[name] = true, id
	}
	config.inspectorRoleIDs, config.roots = roles, config.roots.Clone()
	// Build an independent transport: no environment proxy, custom default
	// dialer/TLS hooks, redirect, cookie jar, compression, or stale-connection GET
	// replay. TLS verifies the configured hostname against the enrolled CA pool.
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dial := hostIssuerDial(net.JoinHostPort(u.Hostname(), port), config.localKeycloak,
		(&net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}).DialContext)
	transport := &http.Transport{
		Proxy: nil, DialContext: dial,
		TLSClientConfig:     &tls.Config{RootCAs: config.roots, MinVersion: tls.VersionTLS12, ServerName: u.Hostname()},
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true, DisableCompression: true,
	}
	client := &http.Client{Transport: transport, Timeout: hostIssuerDeadline,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &hostIssuer{config: config, origin: u.Scheme + "://" + u.Host, client: client}, nil
}

func hostIssuerDial(expected string, local bool, dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != expected {
			return nil, errHostIssuer
		}
		if local {
			address = "127.0.0.1:8443"
		}
		return dial(ctx, network, address)
	}
}

func hostBearer(value string) bool {
	if len(value) == 0 || len(value) > 64<<10 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/=", c)) {
			return false
		}
	}
	return true
}

// CheckSession must receive the same exact token the caller cryptographically
// verified into session. It does no JWT verification or token substitution.
// UserInfo verifies the live user/client/session and revocation/not-before state
// in the pinned Keycloak version. Invoke once for EACH original/new bearer.
func (c *hostIssuer) CheckSession(ctx context.Context, bearer string, session VerifiedSession) error {
	if c == nil || c.client == nil || ctx == nil || !hostBearer(bearer) || !session.verified ||
		session.issuer != c.config.issuer || !session.MatchesApplication(session.subject, session.client, time.Now()) {
		return errHostIssuer
	}
	ctx, cancel := context.WithTimeout(ctx, hostIssuerDeadline)
	defer cancel()
	raw, err := c.request(ctx, http.MethodGet, "/realms/nebulalog/protocol/openid-connect/userinfo", bearer, nil)
	if err != nil {
		return errHostIssuer
	}
	fields, err := sessionClaims(raw)
	var subject string
	if err != nil || json.Unmarshal(fields["sub"], &subject) != nil || subject != session.subject {
		return errHostIssuer
	}
	if _, exists := fields["error"]; exists {
		return errHostIssuer
	}
	return nil
}

// CurrentAdministrator performs uncached reads under one total deadline. The
// subject is already verified by the caller, not a browser-selected account.
// Safe opaque storage-provider IDs are supported as well as local UUIDs.
func (c *hostIssuer) CurrentAdministrator(ctx context.Context, subject string) error {
	if c == nil || c.client == nil || ctx == nil || !hostIssuerSubject.MatchString(subject) {
		return errHostIssuer
	}
	ctx, cancel := context.WithTimeout(ctx, hostIssuerDeadline)
	defer cancel()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {hostInspectorClient}}
	raw, err := c.request(ctx, http.MethodPost, "/realms/nebulalog/protocol/openid-connect/token", "", form)
	if err != nil {
		return errHostIssuer
	}
	var response struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		Expires     json.RawMessage `json:"expires_in"`
		Refresh     json.RawMessage `json:"refresh_token"`
	}
	if json.Unmarshal(raw, &response) != nil || !hostBearer(response.AccessToken) || response.TokenType != "Bearer" || response.Refresh != nil {
		return errHostIssuer
	}
	if _, err := stepUpSeconds(response.Expires, 3600); err != nil {
		return errHostIssuer
	}
	token := response.AccessToken // Per-call only: never returned, logged or cached.
	base := "/admin/realms/nebulalog/"
	var client struct {
		ID            string            `json:"id"`
		ClientID      string            `json:"clientId"`
		Protocol      string            `json:"protocol"`
		Enabled       *bool             `json:"enabled"`
		Public        *bool             `json:"publicClient"`
		Service       *bool             `json:"serviceAccountsEnabled"`
		Standard      *bool             `json:"standardFlowEnabled"`
		Direct        *bool             `json:"directAccessGrantsEnabled"`
		Implicit      *bool             `json:"implicitFlowEnabled"`
		BearerOnly    *bool             `json:"bearerOnly"`
		Authenticator string            `json:"clientAuthenticatorType"`
		Attributes    map[string]string `json:"attributes"`
	}
	if c.get(ctx, base+"clients/"+c.config.inspectorID, token, &client) != nil ||
		client.ID != c.config.inspectorID || client.ClientID != hostInspectorClient || client.Protocol != "openid-connect" ||
		!hostIssuerBool(client.Enabled, true) || !hostIssuerBool(client.Public, false) || !hostIssuerBool(client.Service, true) || !hostIssuerBool(client.Standard, false) || !hostIssuerBool(client.Direct, false) || !hostIssuerBool(client.Implicit, false) || !hostIssuerBool(client.BearerOnly, false) || client.Authenticator != "client-secret" ||
		client.Attributes["nebulalog-installation"] != c.config.installationID || client.Attributes["nebulalog-managed"] != "true" {
		return errHostIssuer
	}
	var user struct {
		ID         string `json:"id"`
		Enabled    *bool  `json:"enabled"`
		Federation string `json:"federationLink"`
	}
	if c.get(ctx, base+"clients/"+c.config.inspectorID+"/service-account-user", token, &user) != nil ||
		user.ID != c.config.inspectorUserID || !hostIssuerBool(user.Enabled, true) || user.Federation != "" {
		return errHostIssuer
	}
	var management struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
	}
	if c.get(ctx, base+"clients/"+c.config.managementID, token, &management) != nil || management.ID != c.config.managementID || management.ClientID != "realm-management" {
		return errHostIssuer
	}
	var roles []hostIssuerRole
	if c.get(ctx, base+"users/"+c.config.inspectorUserID+"/role-mappings/clients/"+c.config.managementID+"/composite", token, &roles) != nil || len(roles) != len(hostInspectorRoles) {
		return errHostIssuer
	}
	seen := map[string]bool{}
	for _, role := range roles {
		composite, exists := hostInspectorRoles[role.Name]
		if !exists || seen[role.Name] || role.ID != c.config.inspectorRoleIDs[role.Name] || !hostIssuerBool(role.ClientRole, true) || role.ContainerID != c.config.managementID || !hostIssuerBool(role.Composite, composite) {
			return errHostIssuer
		}
		seen[role.Name] = true
	}
	var application struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
		Enabled  *bool  `json:"enabled"`
		Protocol string `json:"protocol"`
	}
	if c.get(ctx, base+"clients/"+c.config.applicationID, token, &application) != nil || application.ID != c.config.applicationID || application.ClientID != "nebulalog" || !hostIssuerBool(application.Enabled, true) || application.Protocol != "openid-connect" {
		return errHostIssuer
	}
	if c.get(ctx, base+"users/"+url.PathEscape(subject)+"/role-mappings/clients/"+c.config.applicationID+"/composite", token, &roles) != nil || len(roles) == 0 || len(roles) > 128 {
		return errHostIssuer
	}
	seen, names, found := map[string]bool{}, map[string]bool{}, false
	for _, role := range roles {
		if !hostIssuerUUID.MatchString(role.ID) || !claimString(role.Name, 128) || seen[role.ID] || names[role.Name] || !hostIssuerBool(role.ClientRole, true) || role.ContainerID != c.config.applicationID {
			return errHostIssuer
		}
		seen[role.ID], names[role.Name] = true, true
		if role.Name == "ADMINISTRATOR" {
			if role.ID != c.config.administratorRoleID || !hostIssuerBool(role.Composite, false) {
				return errHostIssuer
			}
			found = true
		}
	}
	if !found {
		return errHostIssuer
	}
	return nil
}

type hostIssuerRole struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ClientRole  *bool  `json:"clientRole"`
	Composite   *bool  `json:"composite"`
	ContainerID string `json:"containerId"`
}

func hostIssuerBool(value *bool, wanted bool) bool { return value != nil && *value == wanted }

func (c *hostIssuer) get(ctx context.Context, path, bearer string, target any) error {
	raw, err := c.request(ctx, http.MethodGet, path, bearer, nil)
	if err != nil || json.Unmarshal(raw, target) != nil {
		return errHostIssuer
	}
	return nil
}

func (c *hostIssuer) request(ctx context.Context, method, path, bearer string, form url.Values) ([]byte, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if err != nil {
		return nil, errHostIssuer
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Cache-Control", "no-store")
	if form != nil {
		r.SetBasicAuth(url.QueryEscape(hostInspectorClient), url.QueryEscape(c.config.inspectorSecret))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := c.client.Do(r)
	if err != nil {
		return nil, errHostIssuer
	}
	defer res.Body.Close()
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || res.StatusCode != http.StatusOK || res.Header.Get("Content-Encoding") != "" {
		return nil, errHostIssuer
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, hostIssuerLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > hostIssuerLimit || !utf8.Valid(raw) {
		return nil, errHostIssuer
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	remaining := 8192
	if checkJSONValue(decoder, 0, &remaining) != nil {
		return nil, errHostIssuer
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errHostIssuer
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) == nil {
		if _, exists := fields["error"]; exists {
			return nil, errHostIssuer
		}
	}
	return raw, nil
}
