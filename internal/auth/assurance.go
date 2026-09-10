package auth

import (
	"errors"
	"net/url"
	"slices"
	"time"
)

var (
	ErrAssurancePolicy = errors.New("reviewed assurance policy is missing, invalid or expired")
	ErrSessionClaims   = errors.New("verified session claims are missing or malformed")
	ErrSessionBinding  = errors.New("verified session issuer, audience or client does not match policy")
	ErrSessionTime     = errors.New("verified authentication or token time is invalid or no longer fresh")
	ErrAssurance       = errors.New("verified authentication assurance does not satisfy policy")
)

// AssurancePolicy is operator-owned configuration, never a browser request.
// Reviewed and ReviewID represent an external review of the pinned issuer's
// exact flows, mappers, broker paths, ACR semantics and MFA freshness behavior.
// This type cannot prove that review occurred. There is no enabled default.
type AssurancePolicy struct {
	Reviewed                              bool
	ReviewID                              string
	ReviewExpiresAt                       time.Time
	Issuer, Audience, ClientID, TokenType string
	AcceptedACR                           []string
	RequiredAMR                           []string
	MaxAuthenticationAge                  time.Duration
	MaxTokenAge                           time.Duration
	MaxTokenLifetime                      time.Duration
	ClockSkew                             time.Duration
}

// Check is a pure, local evidence check, not an action-bound grant or a role,
// session-revocation, issuer-availability or host authorization check. A caller
// must separately enforce Administrator access and all host grant bindings.
func (p AssurancePolicy) Check(s VerifiedSession, now time.Time) error {
	if !p.valid(now) {
		return ErrAssurancePolicy
	}
	if !s.verified || s.sid == "" || s.client == "" || s.authTime.IsZero() || s.tokenType == "" {
		return ErrSessionClaims
	}
	if s.issuer != p.Issuer || s.client != p.ClientID || !slices.Contains(s.audience, p.Audience) || s.tokenType != p.TokenType {
		return ErrSessionBinding
	}
	// No leeway extends token expiry or authentication freshness. ClockSkew is
	// only a bounded allowance for a clock ahead of this verifier.
	if !now.Before(s.expiresAt) || !s.expiresAt.After(s.issuedAt) || s.expiresAt.Sub(s.issuedAt) > p.MaxTokenLifetime ||
		s.authTime.After(now.Add(p.ClockSkew)) || s.issuedAt.After(now.Add(p.ClockSkew)) || s.notBefore.After(now.Add(p.ClockSkew)) ||
		s.authTime.After(s.issuedAt) || (!s.notBefore.IsZero() && !s.notBefore.Before(s.expiresAt)) ||
		now.Sub(s.authTime) >= p.MaxAuthenticationAge || now.Sub(s.issuedAt) >= p.MaxTokenAge {
		return ErrSessionTime
	}
	if !slices.Contains(p.AcceptedACR, s.acr) {
		return ErrAssurance
	}
	for _, required := range p.RequiredAMR {
		if !slices.Contains(s.amr, required) {
			return ErrAssurance
		}
	}
	return nil
}

func (p AssurancePolicy) valid(now time.Time) bool {
	issuer, err := url.Parse(p.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" {
		return false
	}
	if !p.Reviewed || !claimString(p.ReviewID, 256) || now.IsZero() || !now.Before(p.ReviewExpiresAt) ||
		!claimString(p.Issuer, 2048) || !claimString(p.Audience, 512) || !claimString(p.ClientID, 512) || !claimString(p.TokenType, 512) ||
		!claimValues(p.AcceptedACR, false) || !claimValues(p.RequiredAMR, true) ||
		p.MaxAuthenticationAge <= 0 || p.MaxAuthenticationAge > 15*time.Minute ||
		p.MaxTokenAge <= 0 || p.MaxTokenAge > 15*time.Minute ||
		p.MaxTokenLifetime <= 0 || p.MaxTokenLifetime > 15*time.Minute ||
		p.ClockSkew < 0 || p.ClockSkew > 30*time.Second {
		return false
	}
	return true
}
