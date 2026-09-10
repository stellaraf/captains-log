package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

const ownerKey = "nebulalog.managed"
const ownerValue = "saml-v1"
const managerTimeout = 90 * time.Second

type Manager struct {
	config     Config
	client     *http.Client
	tokenMu    sync.Mutex
	token      string
	tokenUntil time.Time
	saveGate   chan struct{}
}
type representation struct {
	Alias                     string            `json:"alias"`
	DisplayName               string            `json:"displayName"`
	ProviderID                string            `json:"providerId"`
	Enabled                   bool              `json:"enabled"`
	TrustEmail                bool              `json:"trustEmail"`
	StoreToken                bool              `json:"storeToken"`
	LinkOnly                  bool              `json:"linkOnly"`
	FirstBrokerLoginFlowAlias string            `json:"firstBrokerLoginFlowAlias"`
	PostBrokerLoginFlowAlias  string            `json:"postBrokerLoginFlowAlias"`
	Config                    map[string]string `json:"config"`
	Extra                     map[string]any    `json:"-"`
}
type mapper struct {
	ID     string            `json:"id,omitempty"`
	Name   string            `json:"name"`
	Alias  string            `json:"identityProviderAlias"`
	Type   string            `json:"identityProviderMapper"`
	Config map[string]string `json:"config"`
}

var safeName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

func New(config Config) (*Manager, error) {
	if !safeName.MatchString(config.Realm) || !safeName.MatchString(config.ClientID) || config.ClientSecret == "" {
		return nil, problem("validation", "Identity manager requires a realm and confidential service client")
	}
	if config.ApplicationClientID == "" {
		config.ApplicationClientID = "nebulalog"
	}
	if config.ApplicationClientID != "nebulalog" || config.ClientID == config.ApplicationClientID || config.ClientID == "admin-cli" {
		return nil, problem("validation", "Use the dedicated identity-manager service client")
	}
	if config.BrokerMFAFlow == "" {
		config.BrokerMFAFlow = "nebulalog-broker-mfa"
	}
	if !safeName.MatchString(config.BrokerMFAFlow) {
		return nil, problem("validation", "Invalid broker MFA flow")
	}
	for _, raw := range []string{config.BaseURL, config.PublicBaseURL} {
		u, err := url.Parse(raw)
		if !validateURL(raw, config.AllowHTTP) || err != nil || u.RawQuery != "" {
			return nil, problem("validation", "Keycloak base URLs must use HTTPS (HTTP requires explicit development configuration)")
		}
	}
	config.BaseURL = strings.TrimRight(config.BaseURL, "/")
	config.PublicBaseURL = strings.TrimRight(config.PublicBaseURL, "/")
	client := &http.Client{Timeout: 15 * time.Second}
	if config.HTTPClient != nil {
		copy := *config.HTTPClient
		client = &copy
		if client.Timeout == 0 || client.Timeout > 15*time.Second {
			client.Timeout = 15 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Manager{config: config, client: client, saveGate: make(chan struct{}, 1)}, nil
}
func aliasOK(alias string) error {
	if alias != "okta" && alias != "entra" {
		return problem("validation", "Provider alias must be okta or entra")
	}
	return nil
}
func validGroups(groups GroupMappings) bool {
	seen := map[string]bool{}
	for _, s := range []string{groups.Viewer, groups.Analyst, groups.Administrator} {
		if len(s) == 0 || len(s) > 256 || s != strings.TrimSpace(s) || strings.ContainsAny(s, "\r\n\x00") || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func (m *Manager) empty(alias string) Provider {
	realm := m.config.PublicBaseURL + "/realms/" + m.config.Realm
	acs := realm + "/broker/" + alias + "/endpoint"
	display := "Okta"
	if alias == "entra" {
		display = "Microsoft Entra ID"
	}
	return Provider{Alias: alias, DisplayName: display, SPEntityID: realm, ACSURL: acs, MetadataURL: acs + "/descriptor", Certificates: []Certificate{}}
}
func (m *Manager) Preview(setup Setup) (Preview, error) {
	if err := aliasOK(setup.Alias); err != nil {
		return Preview{}, err
	}
	if !validGroups(setup.Groups) {
		return Preview{}, problem("validation", "Specify three distinct nonempty exact group values")
	}
	data, err := parseMetadata(setup.MetadataXML, m.config.AllowMetadataHTTP, time.Now())
	if err != nil {
		return Preview{}, err
	}
	p := m.empty(setup.Alias)
	p.Managed = true
	p.Enabled = setup.Enabled
	p.EntityID = data.issuer
	p.SSOURL = data.sso
	p.Certificates = data.certificates
	p.Groups = setup.Groups
	warnings := []string{"Metadata and local configuration checks do not establish a successful external login or upstream MFA policy.", "Uploaded signing keys are static; upload updated metadata before certificate rotation.", "Group and role changes apply at subsequent broker login; saving does not revoke existing sessions or tokens."}
	return Preview{Provider: p, Warnings: warnings}, nil
}
func (m *Manager) accessToken(ctx context.Context) (string, error) {
	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	if time.Now().Before(m.tokenUntil) {
		return m.token, nil
	}
	body := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.config.BaseURL+"/realms/"+m.config.Realm+"/protocol/openid-connect/token", strings.NewReader(body.Encode()))
	if err != nil {
		return "", problem("upstream", "Unable to create identity service request")
	}
	req.SetBasicAuth(m.config.ClientID, m.config.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client.Do(req)
	if err != nil {
		return "", problem("upstream", "Identity service authentication unavailable")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(b) > 65536 {
		return "", problem("upstream", "Invalid identity service authentication response")
	}
	if resp.StatusCode != 200 {
		return "", &Error{Kind: "upstream", Message: "Identity service authentication failed", StatusCode: resp.StatusCode}
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(b, &token) != nil || token.AccessToken == "" || token.ExpiresIn <= 0 {
		return "", problem("upstream", "Invalid identity service authentication response")
	}
	life := time.Duration(token.ExpiresIn) * time.Second
	if life > time.Hour {
		life = time.Hour
	}
	m.token = token.AccessToken
	m.tokenUntil = time.Now().Add(life - 15*time.Second)
	return m.token, nil
}
func (m *Manager) request(ctx context.Context, method, path string, data any, out any) (int, error) {
	token, err := m.accessToken(ctx)
	if err != nil {
		return 0, err
	}
	var body io.Reader
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return 0, problem("validation", "Invalid identity configuration")
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, m.config.BaseURL+"/admin/realms/"+m.config.Realm+path, body)
	if err != nil {
		return 0, problem("upstream", "Unable to create identity service request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, problem("upstream", "Identity service request failed")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return resp.StatusCode, problem("upstream", "Identity service response exceeded its bound")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, &Error{Kind: "upstream", Message: "Identity service rejected the operation", StatusCode: resp.StatusCode}
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return resp.StatusCode, problem("upstream", "Invalid identity service response")
	}
	return resp.StatusCode, nil
}
func instancePath(alias string) string { return "/identity-provider/instances/" + alias }
func (m *Manager) read(ctx context.Context, alias string) (representation, bool, error) {
	var r representation
	status, err := m.request(ctx, http.MethodGet, instancePath(alias), nil, &r)
	if status == 404 {
		return r, false, nil
	}
	if err == nil && r.Alias != alias {
		return r, false, problem("upstream", "Identity provider response alias does not match")
	}
	return r, err == nil, err
}
func groupsFrom(r representation) GroupMappings {
	return GroupMappings{r.Config["nebulalog.viewer"], r.Config["nebulalog.analyst"], r.Config["nebulalog.administrator"]}
}
func (m *Manager) public(r representation) (Provider, error) {
	p := m.empty(r.Alias)
	p.Configured = true
	p.Managed = r.Config[ownerKey] == ownerValue
	p.Enabled = r.Enabled
	p.DisplayName = r.DisplayName
	p.EntityID = r.Config["idpEntityId"]
	p.SSOURL = r.Config["singleSignOnServiceUrl"]
	p.Groups = groupsFrom(r)
	for _, key := range strings.Split(r.Config["signingCertificate"], ",") {
		if key == "" {
			continue
		}
		cert, _, err := parseCertificate(key, time.Now(), false)
		if err != nil {
			return p, err
		}
		p.Certificates = append(p.Certificates, cert)
	}
	return p, nil
}
func (m *Manager) Inspect(ctx context.Context, alias string) (Provider, error) {
	if err := aliasOK(alias); err != nil {
		return Provider{}, err
	}
	r, found, err := m.read(ctx, alias)
	if err != nil {
		return Provider{}, err
	}
	if !found {
		return m.empty(alias), nil
	}
	return m.public(r)
}
func (m *Manager) List(ctx context.Context) ([]Provider, error) {
	out := []Provider{}
	for _, alias := range []string{"entra", "okta"} {
		p, err := m.Inspect(ctx, alias)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
func (m *Manager) requiredMFA(ctx context.Context) error {
	var executions []struct {
		ProviderID         string `json:"providerId"`
		Requirement        string `json:"requirement"`
		AuthenticationFlow bool   `json:"authenticationFlow"`
	}
	_, err := m.request(ctx, http.MethodGet, "/authentication/flows/"+m.config.BrokerMFAFlow+"/executions", nil, &executions)
	if err != nil {
		return err
	}
	if len(executions) != 1 || executions[0].ProviderID != "auth-otp-form" || executions[0].Requirement != "REQUIRED" || executions[0].AuthenticationFlow {
		return problem("conflict", "Required broker MFA flow must contain exactly one required OTP Form execution")
	}
	return nil
}
func (m *Manager) desired(setup Setup, data parsedMetadata) representation {
	p := m.empty(setup.Alias)
	out := representation{Alias: setup.Alias, DisplayName: p.DisplayName, ProviderID: "saml", FirstBrokerLoginFlowAlias: "first broker login", PostBrokerLoginFlowAlias: m.config.BrokerMFAFlow, Config: map[string]string{
		ownerKey: ownerValue, "entityId": p.SPEntityID, "idpEntityId": data.issuer, "singleSignOnServiceUrl": data.sso, "singleLogoutServiceUrl": data.slo,
		"validateSignature": "true", "wantAssertionsSigned": "true", "wantAuthnRequestsSigned": "true", "signatureAlgorithm": "RSA_SHA256", "signingCertificate": strings.Join(data.keys, ","),
		"nameIDPolicyFormat": persistentNameID, "principalType": "SUBJECT", "postBindingResponse": "true", "postBindingAuthnRequest": map[bool]string{true: "true", false: "false"}[data.binding == postBinding],
		"useMetadataDescriptorUrl": "false", "wantAssertionsEncrypted": "false", "allowCreate": "true", "syncMode": "FORCE",
		"nebulalog.viewer": setup.Groups.Viewer, "nebulalog.analyst": setup.Groups.Analyst, "nebulalog.administrator": setup.Groups.Administrator,
	}}
	if data.slo == "" {
		delete(out.Config, "singleLogoutServiceUrl")
	}
	return out
}
func (m *Manager) desiredMappers(alias string, groups GroupMappings) []mapper {
	out := []mapper{}
	for _, role := range []struct{ name, value, role string }{{"viewer", groups.Viewer, "VIEWER"}, {"analyst", groups.Analyst, "ANALYST"}, {"administrator", groups.Administrator, "ADMINISTRATOR"}} {
		out = append(out, mapper{Name: "nebulalog-role-" + role.name, Alias: alias, Type: "saml-role-idp-mapper", Config: map[string]string{"syncMode": "FORCE", "attribute.name": "groups", "attribute.value": role.value, "role": m.config.ApplicationClientID + "." + role.role}})
	}
	for _, name := range []string{"email", "firstName", "lastName"} {
		out = append(out, mapper{Name: "nebulalog-profile-" + name, Alias: alias, Type: "saml-user-attribute-idp-mapper", Config: map[string]string{"syncMode": "FORCE", "attribute.name": name, "user.attribute": name}})
	}
	return append(out, mapper{Name: "nebulalog-username", Alias: alias, Type: "saml-username-idp-mapper", Config: map[string]string{"syncMode": "IMPORT", "template": "${ALIAS}.${NAMEID}", "target": "LOCAL"}})
}
func (m *Manager) readMappers(ctx context.Context, alias string) ([]mapper, error) {
	var out []mapper
	_, err := m.request(ctx, http.MethodGet, instancePath(alias)+"/mappers", nil, &out)
	return out, err
}
func (m *Manager) validateSaved(ctx context.Context, r representation) error {
	c := r.Config
	if c[ownerKey] != ownerValue || r.ProviderID != "saml" || r.TrustEmail || r.StoreToken || r.LinkOnly || r.FirstBrokerLoginFlowAlias != "first broker login" || r.PostBrokerLoginFlowAlias != m.config.BrokerMFAFlow || !validGroups(groupsFrom(r)) {
		return problem("conflict", "Saved provider ownership, identity or MFA configuration does not match")
	}
	for _, key := range []string{"addReadTokenRoleOnCreate", "authenticateByDefault"} {
		if value, present := r.Extra[key]; present && value != false {
			return problem("conflict", "Saved provider grants unexpected token access or default authentication")
		}
	}
	if value, present := r.Extra["organizationId"]; present && value != nil && value != "" {
		return problem("conflict", "Saved provider has an unsupported organization association")
	}
	for key, want := range map[string]string{"validateSignature": "true", "wantAssertionsSigned": "true", "wantAuthnRequestsSigned": "true", "signatureAlgorithm": "RSA_SHA256", "principalType": "SUBJECT", "nameIDPolicyFormat": persistentNameID, "postBindingResponse": "true", "useMetadataDescriptorUrl": "false", "entityId": m.empty(r.Alias).SPEntityID} {
		if c[key] != want {
			return problem("conflict", "Saved provider signature or audience configuration does not match")
		}
	}
	if c["idpEntityId"] == "" || !validateURL(c["singleSignOnServiceUrl"], m.config.AllowMetadataHTTP) {
		return problem("conflict", "Saved provider issuer or endpoint is invalid")
	}
	p, err := m.public(r)
	if err != nil {
		return err
	}
	for _, cert := range p.Certificates {
		if !cert.CurrentlyValid {
			return problem("conflict", "Saved provider signing certificate is not currently valid")
		}
	}
	if len(p.Certificates) == 0 {
		return problem("conflict", "Saved provider has no signing certificates")
	}
	if err := m.requiredMFA(ctx); err != nil {
		return err
	}
	got, err := m.readMappers(ctx, r.Alias)
	if err != nil {
		return err
	}
	want := m.desiredMappers(r.Alias, groupsFrom(r))
	if len(got) != len(want) {
		return problem("conflict", "Saved provider mappers do not match the explicit role policy")
	}
	for _, expected := range want {
		found := false
		for _, actual := range got {
			if actual.Name == expected.Name && actual.Type == expected.Type && actual.Alias == expected.Alias && reflect.DeepEqual(actual.Config, expected.Config) {
				found = true
			}
		}
		if !found {
			return problem("conflict", "Saved provider mapper configuration does not match")
		}
	}
	return nil
}
func (m *Manager) TestStatus(ctx context.Context, alias string) (TestStatus, error) {
	status := TestStatus{CheckedAt: time.Now().UTC(), Status: "not_configured", Message: "No provider is configured; external login has not been tested"}
	if err := aliasOK(alias); err != nil {
		return status, err
	}
	r, found, err := m.read(ctx, alias)
	if err != nil {
		return status, err
	}
	status.Configured = found
	if !found {
		return status, nil
	}
	if err := m.validateSaved(ctx, r); err != nil {
		status.Status = "configuration_invalid"
		status.Message = err.Error()
		return status, nil
	}
	status.ConfigurationValid = true
	status.Status = "configuration_valid"
	status.Message = "Saved provider, role mappings and required broker OTP match; external login has not been tested"
	return status, nil
}
func (m *Manager) Save(ctx context.Context, setup Setup) (provider Provider, err error) {
	if !m.config.EnableWrites {
		return Provider{}, problem("disabled", "Identity configuration writes are disabled")
	}
	if _, err = m.Preview(setup); err != nil {
		return Provider{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, managerTimeout)
	defer cancel()
	select {
	case m.saveGate <- struct{}{}:
		defer func() { <-m.saveGate }()
	case <-ctx.Done():
		return Provider{}, problem("upstream", "Identity configuration operation timed out before starting")
	}
	data, err := parseMetadata(setup.MetadataXML, m.config.AllowMetadataHTTP, time.Now())
	if err != nil {
		return Provider{}, err
	}
	original, found, err := m.read(ctx, setup.Alias)
	if err != nil {
		return Provider{}, err
	}
	if found && (original.Config[ownerKey] != ownerValue || original.ProviderID != "saml") {
		return Provider{}, problem("conflict", "Provider alias is already owned by another configuration")
	}
	if err = m.requiredMFA(ctx); err != nil {
		return Provider{}, err
	}
	oldMappers := []mapper{}
	if found {
		oldMappers, err = m.readMappers(ctx, setup.Alias)
		if err != nil {
			return Provider{}, err
		}
	}
	wanted := m.desiredMappers(setup.Alias, setup.Groups)
	names := map[string]bool{}
	for _, item := range wanted {
		names[item.Name] = true
	}
	for _, item := range oldMappers {
		if !names[item.Name] || item.ID == "" {
			return Provider{}, problem("conflict", "Provider has unmanaged mappers; review it before replacement")
		}
	}
	if found {
		latest, exists, readErr := m.read(ctx, setup.Alias)
		if readErr != nil {
			return Provider{}, readErr
		}
		if !exists || !reflect.DeepEqual(latest, original) {
			return Provider{}, problem("conflict", "Provider changed while preparing the save; reload before retrying")
		}
	}
	desired := m.desired(setup, data)
	var operation [16]byte
	if _, randomErr := rand.Read(operation[:]); randomErr != nil {
		return Provider{}, problem("upstream", "Unable to create configuration operation identity")
	}
	desired.Config["nebulalog.operation"] = hex.EncodeToString(operation[:])
	mutating := false
	defer func() {
		if err == nil || !mutating {
			return
		}
		cause := err.Error()
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		current, exists, readErr := m.read(cleanup, setup.Alias)
		if readErr != nil {
			err = problem("upstream", "Provider save failed; current state could not be confirmed. Inspect Keycloak before retrying")
			return
		}
		if !exists {
			return
		}
		if current.Config[ownerKey] != ownerValue || current.Config["nebulalog.operation"] != desired.Config["nebulalog.operation"] {
			err = problem("conflict", "Provider save failed; another configuration owns the alias. It was not modified during cleanup")
			return
		}
		current.Enabled = false
		if _, disableErr := m.request(cleanup, http.MethodPut, instancePath(setup.Alias), current, nil); disableErr != nil {
			err = problem("upstream", "Provider save failed; disabled state could not be confirmed. Inspect Keycloak before retrying")
			return
		}
		confirmed, exists, readErr := m.read(cleanup, setup.Alias)
		if readErr != nil || !exists || confirmed.Enabled || confirmed.Config["nebulalog.operation"] != desired.Config["nebulalog.operation"] {
			err = problem("upstream", "Provider save failed; disabled state could not be confirmed. Inspect Keycloak before retrying")
			return
		}
		err = problem("upstream", "Provider save failed: "+cause+"; the provider was verified disabled")
	}()
	if found {
		original.Enabled = false
		original.Config["nebulalog.operation"] = desired.Config["nebulalog.operation"]
		if _, err = m.request(ctx, http.MethodPut, instancePath(setup.Alias), original, nil); err != nil {
			return Provider{}, err
		}
		mutating = true
		if _, err = m.request(ctx, http.MethodPut, instancePath(setup.Alias), desired, nil); err != nil {
			return Provider{}, err
		}
	} else {
		// A timeout may occur after creation, so the failure path also attempts disable.
		mutating = true
		if _, err = m.request(ctx, http.MethodPost, "/identity-provider/instances", desired, nil); err != nil {
			return Provider{}, err
		}
	}
	for _, item := range oldMappers {
		if _, err = m.request(ctx, http.MethodDelete, instancePath(setup.Alias)+"/mappers/"+url.PathEscape(item.ID), nil, nil); err != nil {
			return Provider{}, err
		}
	}
	for _, item := range wanted {
		if _, err = m.request(ctx, http.MethodPost, instancePath(setup.Alias)+"/mappers", item, nil); err != nil {
			return Provider{}, err
		}
	}
	saved, exists, err := m.read(ctx, setup.Alias)
	if err != nil {
		return Provider{}, err
	}
	if !exists {
		return Provider{}, problem("upstream", "Saved provider was not found")
	}
	// Equality to this exact preview prevents a successful round-trip check from
	// accepting a different issuer, SSO endpoint, certificate, or group mapping.
	if !reflect.DeepEqual(saved.Config, desired.Config) || saved.Enabled {
		return Provider{}, problem("conflict", "Saved provider differs from the reviewed configuration")
	}
	if err = m.validateSaved(ctx, saved); err != nil {
		return Provider{}, err
	}
	if setup.Enabled {
		desired.Enabled = true
		if _, err = m.request(ctx, http.MethodPut, instancePath(setup.Alias), desired, nil); err != nil {
			return Provider{}, err
		}
		saved, exists, err = m.read(ctx, setup.Alias)
		if err != nil {
			return Provider{}, err
		}
		if !exists || !saved.Enabled || !reflect.DeepEqual(saved.Config, desired.Config) {
			return Provider{}, problem("upstream", "Enabled provider state could not be verified")
		}
		if err = m.validateSaved(ctx, saved); err != nil {
			return Provider{}, err
		}
	}
	provider, err = m.public(saved)
	return provider, err
}

// IsKind allows callers to classify safe errors without inspecting their text.
func IsKind(err error, kind string) bool { var e *Error; return errors.As(err, &e) && e.Kind == kind }
