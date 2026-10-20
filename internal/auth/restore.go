package auth

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// SetTokenNotBefore binds a restored API to its target-host issuance boundary.
// Keycloak's realm not-before revokes refresh/session use, but locally verified
// JWTs also need this check while their original signature remains valid.
// Empty is the normal never-restored appliance configuration.
func SetTokenNotBefore(a *Auth, value string) error {
	if value == "" {
		return nil
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 || seconds > 1<<31-1 || strconv.FormatInt(seconds, 10) != value {
		return errors.New("OIDC_TOKEN_NOT_BEFORE must be a canonical positive epoch second supported by Keycloak")
	}
	if a == nil || a.Verifier == nil {
		return errors.New("restored token boundary requires an identity verifier")
	}
	a.Verifier = restoreVerifier{a.Verifier, time.Unix(seconds, 0).UTC()}
	return nil
}

type restoreVerifier struct {
	underlying Verifier
	notBefore  time.Time
}

func (v restoreVerifier) Verify(ctx context.Context, raw string) (*oidc.IDToken, error) {
	token, err := v.underlying.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if token == nil || token.IssuedAt.IsZero() || token.IssuedAt.Before(v.notBefore) {
		return nil, errors.New("session predates appliance recovery; sign in again")
	}
	return token, nil
}
