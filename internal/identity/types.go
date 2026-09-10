// Package identity configures two explicit SAML brokers through a scoped
// Keycloak service client. Uploaded metadata is parsed locally, never fetched.
package identity

import (
	"net/http"
	"time"
)

type Config struct {
	BaseURL, PublicBaseURL, Realm               string
	ClientID, ClientSecret, ApplicationClientID string
	BrokerMFAFlow                               string
	AllowHTTP, AllowMetadataHTTP, EnableWrites  bool
	HTTPClient                                  *http.Client
}
type GroupMappings struct {
	Viewer        string `json:"viewer"`
	Analyst       string `json:"analyst"`
	Administrator string `json:"administrator"`
}
type Setup struct {
	Alias       string        `json:"alias"`
	MetadataXML string        `json:"metadata_xml"`
	Groups      GroupMappings `json:"groups"`
	Enabled     bool          `json:"enabled"`
}
type Certificate struct {
	CurrentlyValid bool      `json:"currently_valid"`
	SHA256         string    `json:"sha256"`
	Subject        string    `json:"subject"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
}
type Provider struct {
	Alias               string        `json:"alias"`
	Configured          bool          `json:"configured"`
	Managed             bool          `json:"managed"`
	Enabled             bool          `json:"enabled"`
	DisplayName         string        `json:"display_name"`
	EntityID            string        `json:"entity_id"`
	SSOURL              string        `json:"sso_url"`
	SPEntityID          string        `json:"sp_entity_id"`
	ACSURL              string        `json:"acs_url"`
	MetadataURL         string        `json:"metadata_url"`
	Groups              GroupMappings `json:"groups"`
	Certificates        []Certificate `json:"certificates"`
	ExternalLoginTested bool          `json:"external_login_tested"`
}
type Preview struct {
	Provider
	Warnings []string `json:"warnings"`
}
type TestStatus struct {
	Configured          bool      `json:"configured"`
	ConfigurationValid  bool      `json:"configuration_valid"`
	ExternalLoginTested bool      `json:"external_login_tested"`
	Status              string    `json:"status"`
	Message             string    `json:"message"`
	CheckedAt           time.Time `json:"checked_at"`
}
type Error struct {
	Kind       string
	Message    string
	StatusCode int
}

func (e *Error) Error() string           { return e.Message }
func problem(kind, message string) error { return &Error{Kind: kind, Message: message} }
