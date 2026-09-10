package auth

import (
	"context"
	"encoding/json"
	"github.com/coreos/go-oidc/v3/oidc"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}
type key struct{}

func Current(ctx context.Context) User { u, _ := ctx.Value(key{}).(User); return u }

type Verifier interface {
	Verify(context.Context, string) (*oidc.IDToken, error)
}
type Auth struct {
	Verifier Verifier
	ClientID string
}

func New(ctx context.Context, issuer, clientID string) (*Auth, error) {
	p, e := oidc.NewProvider(ctx, issuer)
	if e != nil {
		return nil, e
	}
	return &Auth{p.Verifier(&oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256", "PS256", "ES256"}}), clientID}, nil
}

// Backchannel changes only transport routing; issuer validation remains exact.
func Backchannel(ctx context.Context, issuer, internal string) context.Context {
	if internal == "" {
		return ctx
	}
	external, e := url.Parse(issuer)
	if e != nil {
		return ctx
	}
	target, e := url.Parse(internal)
	if e != nil {
		return ctx
	}
	return oidc.ClientContext(ctx, &http.Client{Timeout: 15 * time.Second, Transport: rewriteTransport{external.Host, target}})
}

type rewriteTransport struct {
	host   string
	target *url.URL
}

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == t.host {
		r = r.Clone(r.Context())
		u := *r.URL
		u.Scheme = t.target.Scheme
		u.Host = t.target.Host
		r.URL = &u
		r.Host = ""
	}
	return http.DefaultTransport.RoundTrip(r)
}
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			deny(w, 401, "Authentication required")
			return
		}
		if a.Verifier == nil {
			deny(w, 401, "Session is invalid or expired")
			return
		}
		token, e := a.Verifier.Verify(r.Context(), strings.TrimPrefix(header, "Bearer "))
		if e != nil || token == nil {
			deny(w, 401, "Session is invalid or expired")
			return
		}
		var c struct {
			Subject  string `json:"sub"`
			Username string `json:"preferred_username"`
			Access   map[string]struct {
				Roles []string `json:"roles"`
			} `json:"resource_access"`
		}
		if e = token.Claims(&c); e != nil || c.Subject == "" {
			deny(w, 401, "Invalid identity")
			return
		}
		role := Role(c.Access[a.ClientID].Roles)
		if role == "" {
			deny(w, 403, "No Captain’s Log role is assigned")
			return
		}
		ctx := context.WithValue(r.Context(), key{}, User{c.Subject, c.Username, role})
		// Session evidence is distinct from the public user/RBAC contract. Missing
		// or malformed assurance claims do not alter ordinary login permissions.
		session, _ := verifiedSession(token)
		ctx = context.WithValue(ctx, sessionKey{}, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func Role(roles []string) string {
	for _, target := range []string{"ADMINISTRATOR", "ANALYST", "VIEWER"} {
		for _, r := range roles {
			if r == target {
				return r
			}
		}
	}
	return ""
}
func Require(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := Current(r.Context())
		if u.Role != "ADMINISTRATOR" && (role == "ADMINISTRATOR" || u.Role != role) {
			deny(w, 403, "This action requires "+role+" access")
			return
		}
		next(w, r)
	}
}
func deny(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
