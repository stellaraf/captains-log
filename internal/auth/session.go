package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
)

const maxSessionClaimsBytes = 32 << 10
const maxClaimValues = 16

type sessionKey struct{}

// VerifiedSession is bounded evidence extracted only after the configured OIDC
// verifier accepted a signed token. It is not an authorization or proof of an
// active, unrevoked session. Its zero value is never eligible for assurance.
// Fields are opaque so another package cannot construct evidence from a request.
type VerifiedSession struct {
	verified                                     bool
	issuer, subject, client, sid, acr, tokenType string
	audience, amr                                []string
	authTime, issuedAt, expiresAt, notBefore     time.Time
}

func CurrentSession(ctx context.Context) (VerifiedSession, bool) {
	s, ok := ctx.Value(sessionKey{}).(VerifiedSession)
	return s, ok && s.verified
}

// Accessors are for internal session binding only. Never include SessionID in
// browser responses, ordinary job/audit JSON, URLs or logs.
func (s VerifiedSession) Issuer() string       { return s.issuer }
func (s VerifiedSession) Subject() string      { return s.subject }
func (s VerifiedSession) ClientID() string     { return s.client }
func (s VerifiedSession) SessionID() string    { return s.sid }
func (s VerifiedSession) AuthTime() time.Time  { return s.authTime }
func (s VerifiedSession) IssuedAt() time.Time  { return s.issuedAt }
func (s VerifiedSession) ExpiresAt() time.Time { return s.expiresAt }
func (s VerifiedSession) ACR() string          { return s.acr }
func (s VerifiedSession) AMR() []string        { return slices.Clone(s.amr) }
func (s VerifiedSession) Audience() []string   { return slices.Clone(s.audience) }

// MatchesApplication binds read-only host planning to the current signed
// application session. It supplies neither recent-MFA assurance nor revocation
// evidence and must never authorize a host mutation.
func (s VerifiedSession) MatchesApplication(subject, clientID string, now time.Time) bool {
	return s.verified && subject != "" && clientID != "" && s.subject == subject &&
		s.client == clientID && s.issuer != "" && s.sid != "" && s.tokenType == "Bearer" &&
		slices.Contains(s.audience, clientID) && !s.issuedAt.IsZero() &&
		s.expiresAt.After(s.issuedAt) &&
		!s.issuedAt.After(now.Add(5*time.Second)) && now.Before(s.expiresAt) &&
		(s.notBefore.IsZero() || !now.Before(s.notBefore))
}
func (s VerifiedSession) String() string   { return "VerifiedSession[redacted]" }
func (s VerifiedSession) GoString() string { return s.String() }
func (s VerifiedSession) MarshalJSON() ([]byte, error) {
	return nil, errors.New("verified session evidence must not be serialized")
}

func verifiedSession(token *oidc.IDToken) (VerifiedSession, error) {
	var raw json.RawMessage
	if err := token.Claims(&raw); err != nil || len(raw) > maxSessionClaimsBytes {
		return VerifiedSession{}, ErrSessionClaims
	}
	claims, err := sessionClaims(raw)
	if err != nil {
		return VerifiedSession{}, err
	}
	var s VerifiedSession
	for key, destination := range map[string]*string{
		"iss": &s.issuer, "sub": &s.subject, "azp": &s.client, "sid": &s.sid, "acr": &s.acr, "typ": &s.tokenType,
	} {
		value, exists := claims[key]
		if !exists {
			continue
		}
		limit := 512
		if key == "iss" {
			limit = 2048
		}
		if json.Unmarshal(value, destination) != nil || !claimString(*destination, limit) {
			return VerifiedSession{}, ErrSessionClaims
		}
	}
	for key, destination := range map[string]*[]string{"aud": &s.audience, "amr": &s.amr} {
		value, exists := claims[key]
		if !exists {
			continue
		}
		if key == "aud" && len(value) > 0 && value[0] == '"' {
			var single string
			if json.Unmarshal(value, &single) != nil {
				return VerifiedSession{}, ErrSessionClaims
			}
			*destination = []string{single}
		} else if json.Unmarshal(value, destination) != nil {
			return VerifiedSession{}, ErrSessionClaims
		}
		if !claimValues(*destination, key == "amr") {
			return VerifiedSession{}, ErrSessionClaims
		}
		// null is not an empty array and must not be silently coerced to one.
		if bytes.Equal(value, []byte("null")) {
			return VerifiedSession{}, ErrSessionClaims
		}
	}
	for key, destination := range map[string]*time.Time{"auth_time": &s.authTime, "iat": &s.issuedAt, "exp": &s.expiresAt, "nbf": &s.notBefore} {
		value, exists := claims[key]
		if !exists {
			continue
		}
		// The pinned Keycloak profile emits whole positive UTC seconds. Accept
		// neither strings, fractional/exponent forms, millisecond timestamps nor
		// values beyond year 9999; do not use floating point for security times.
		if len(value) == 0 || len(value) > 12 {
			return VerifiedSession{}, ErrSessionClaims
		}
		for _, c := range value {
			if c < '0' || c > '9' {
				return VerifiedSession{}, ErrSessionClaims
			}
		}
		n, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil || n <= 0 || n > 253402300799 {
			return VerifiedSession{}, ErrSessionClaims
		}
		*destination = time.Unix(n, 0).UTC()
	}
	// Cross-check the exact verified identity fields. Missing core claims cannot
	// create session evidence even if an injected Verifier has weaker behavior.
	if s.issuer == "" || s.subject == "" || len(s.audience) == 0 || s.issuedAt.IsZero() || s.expiresAt.IsZero() ||
		s.issuer != token.Issuer || s.subject != token.Subject || !slices.Equal(s.audience, token.Audience) ||
		!s.issuedAt.Equal(token.IssuedAt) || !s.expiresAt.Equal(token.Expiry) {
		return VerifiedSession{}, ErrSessionClaims
	}
	s.verified = true
	return s, nil
}

func claimString(s string, limit int) bool {
	return len(s) > 0 && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s &&
		!strings.ContainsRune(s, '\ufffd') && !strings.ContainsFunc(s, unicode.IsControl)
}

func claimValues(values []string, allowEmpty bool) bool {
	if len(values) > maxClaimValues || (!allowEmpty && len(values) == 0) {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !claimString(value, 512) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

// Reject duplicate names at every depth, including escaped spellings, so role
// claims and session claims cannot have parser-dependent meanings. Unknown
// claims are bounded/validated but are not retained or treated as assurance.
func sessionClaims(raw []byte) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxSessionClaimsBytes || !utf8.Valid(raw) {
		return nil, ErrSessionClaims
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	remaining := 4096
	if err := checkJSONValue(d, 0, &remaining); err != nil {
		return nil, ErrSessionClaims
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrSessionClaims
	}
	var out map[string]json.RawMessage
	if json.Unmarshal(raw, &out) != nil || out == nil {
		return nil, ErrSessionClaims
	}
	return out, nil
}

func checkJSONValue(d *json.Decoder, depth int, remaining *int) error {
	*remaining = *remaining - 1
	if depth > 16 || *remaining < 0 {
		return ErrSessionClaims
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if delim != '{' && delim != '[' {
		return ErrSessionClaims
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || !claimString(name, 512) || seen[name] {
				return ErrSessionClaims
			}
			seen[name] = true
		}
		if err := checkJSONValue(d, depth+1, remaining); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}
