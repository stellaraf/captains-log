package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"time"
)

const HostControlClient = "nebulalog-host-control"
const HostControlACR = "urn:nebulalog:host-control:local-mfa:v1"
const stepUpLifetime = 120 * time.Second

var (
	ErrStepUpUnavailable = errors.New("administrator step-up is unavailable")
	ErrStepUpTransaction = errors.New("administrator step-up transaction is invalid or expired")
	ErrStepUpIdentity    = errors.New("administrator step-up identity was not accepted")
	stepUpDigest         = regexp.MustCompile(`^[a-f0-9]{64}$`)
	stepUpUUID           = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	stepUpOpaque         = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// StepUpBinding must come from a freshly validated host-issued plan, never from
// browser assertions. This coordinator cannot authenticate the host plan. Every
// field, including its expiry, is compared again at completion. No operation is
// enabled by its presence in this binding.
type StepUpBinding struct {
	InstallationID, Operation, PlanID, PlanDigest, ResourceRevision string
	ExpiresAt                                                       time.Time
	Challenge                                                       HostChallenge
}

func (b StepUpBinding) valid(now time.Time) bool {
	if !stepUpUUID.MatchString(b.InstallationID) || !stepUpUUID.MatchString(b.PlanID) ||
		!stepUpDigest.MatchString(b.PlanDigest) || !stepUpDigest.MatchString(b.ResourceRevision) || !now.Before(b.ExpiresAt) ||
		!b.Challenge.valid(now) || b.Challenge.InstallationID != b.InstallationID || b.Challenge.Operation != b.Operation ||
		b.Challenge.PlanID != b.PlanID || b.Challenge.PlanDigest != b.PlanDigest || b.Challenge.ResourceRevision != b.ResourceRevision ||
		time.Unix(b.Challenge.ExpiresAt, 0).After(b.ExpiresAt) {
		return false
	}
	switch b.Operation {
	case "storage.grow", "storage.add_disk", "updates.check", "updates.install", "updates.rollback", "updates.finalize", "updates.schedule",
		"os.apply", "reboot.complete", "backup.create", "restore.apply", "baseline.scan", "baseline.review", "baseline.select",
		"settings.network", "settings.time", "certificates.activate":
		return true
	}
	return false
}

// StepUpConfig is installation-owned, based on reviewed issuer read-back. There
// is no enabled default and no HTTP route instantiates this coordinator yet.
type StepUpConfig struct {
	Policy                           AssurancePolicy
	ApplicationClientID, RedirectURI string
	// Protected enrollment generation; never supplied by a browser or inferred
	// from an unqualified issuer read-back. There is no production default.
	PolicyGenerationSHA string
}

func (c StepUpConfig) valid(now time.Time) bool {
	u, err := url.Parse(c.RedirectURI)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
		u.Path == "/api/host/step-up/callback" && u.RawPath == "" && claimString(c.RedirectURI, 2048) &&
		claimString(c.ApplicationClientID, 512) && c.ApplicationClientID != HostControlClient && c.Policy.valid(now) &&
		stepUpDigest.MatchString(c.PolicyGenerationSHA) &&
		c.Policy.Audience == HostControlClient && c.Policy.ClientID == HostControlClient && c.Policy.TokenType == "Bearer" &&
		slices.Equal(c.Policy.AcceptedACR, []string{HostControlACR}) && c.Policy.MaxAuthenticationAge <= stepUpLifetime &&
		c.Policy.MaxTokenAge <= stepUpLifetime && c.Policy.MaxTokenLifetime <= stepUpLifetime
}

type stepUpActor struct{ Issuer, Subject, ClientID, SessionDigest string }
type stepUpPending struct {
	StateHash, Nonce, Verifier, PolicyDigest string
	Actor                                    stepUpActor
	Binding                                  StepUpBinding
	CreatedAt, ExpiresAt                     time.Time
}

func (p stepUpPending) String() string               { return "StepUpPending[redacted]" }
func (p stepUpPending) GoString() string             { return p.String() }
func (p stepUpPending) MarshalJSON() ([]byte, error) { return nil, ErrStepUpUnavailable }
func (a stepUpActor) String() string                 { return "StepUpActor[redacted]" }
func (a stepUpActor) GoString() string               { return a.String() }
func (a stepUpActor) MarshalJSON() ([]byte, error)   { return nil, ErrStepUpUnavailable }

// Consume must atomically match all bindings and remove the record before
// returning it. An ambiguous database outcome must return no pending evidence.
type stepUpStore interface {
	Insert(context.Context, stepUpPending) error
	Consume(context.Context, string, stepUpActor, StepUpBinding, string, time.Time) (stepUpPending, error)
}

type stepUpPAR struct {
	URI      string
	Lifetime time.Duration
}
type stepUpTokens struct{ IDToken, AccessToken string }
type stepUpProvider interface {
	Push(context.Context, url.Values) (stepUpPAR, error)
	Exchange(context.Context, string, string, string) (stepUpTokens, error)
	AuthorizationURL(string) string
}

func (p stepUpPAR) String() string                  { return "StepUpPAR[redacted]" }
func (p stepUpPAR) GoString() string                { return p.String() }
func (t stepUpTokens) String() string               { return "StepUpTokens[redacted]" }
func (t stepUpTokens) GoString() string             { return t.String() }
func (t stepUpTokens) MarshalJSON() ([]byte, error) { return nil, ErrStepUpUnavailable }

// StepUp verifies an action-bound OIDC transaction. Its result is NOT a host
// authorization grant. The host must independently check tokens, current roles,
// both live sessions and the unchanged plan before accepting any operation.
type StepUp struct {
	config   StepUpConfig
	store    stepUpStore
	provider stepUpProvider
	verifier Verifier
	now      func() time.Time
}

// NewStepUp does not activate a flow, enable routes or mark a policy reviewed.
func NewStepUp(c StepUpConfig, store *PostgresStepUpStore, client *StepUpOIDCClient) (*StepUp, error) {
	if store == nil || client == nil || !c.valid(time.Now()) || c.Policy.Issuer != client.issuer {
		return nil, ErrStepUpUnavailable
	}
	c.Policy.AcceptedACR = slices.Clone(c.Policy.AcceptedACR)
	c.Policy.RequiredAMR = slices.Clone(c.Policy.RequiredAMR)
	return &StepUp{c, store, client, client.verifier, time.Now}, nil
}

// StepUpStart is the only browser-facing result. The URL contains the opaque PAR
// request_uri, not the nonce, PKCE verifier, actor, plan or any token. Treat the
// URL as sensitive: no access logs, caching, referrers or third-party content.
type StepUpStart struct {
	AuthorizationURL string    `json:"authorization_url"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (s StepUpStart) String() string   { return "StepUpStart[redacted]" }
func (s StepUpStart) GoString() string { return s.String() }

func digestStepUp(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func stepUpRandom() string {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("secure random unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}
func stepUpTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }
func (s *StepUp) policyDigest() string {
	raw, _ := json.Marshal(s.config)
	return digestStepUp(string(raw))
}

func (s *StepUp) actor(ctx context.Context, now time.Time) (stepUpActor, time.Time, error) {
	u := Current(ctx)
	v, ok := CurrentSession(ctx)
	if !ok || u.Role != "ADMINISTRATOR" || u.ID != v.subject || v.issuer != s.config.Policy.Issuer ||
		v.client != s.config.ApplicationClientID || v.sid == "" || v.tokenType != "Bearer" ||
		!slices.Contains(v.audience, s.config.ApplicationClientID) || !now.Before(v.expiresAt) ||
		v.issuedAt.After(now.Add(s.config.Policy.ClockSkew)) || v.notBefore.After(now.Add(s.config.Policy.ClockSkew)) {
		return stepUpActor{}, time.Time{}, ErrStepUpIdentity
	}
	subject := hostSubjectDigest(v.issuer, v.client, v.subject)
	return stepUpActor{v.issuer, v.subject, v.client, hostSessionDigest(subject, v.sid)}, v.expiresAt, nil
}

func (b StepUpBinding) matchesActor(a stepUpActor) bool {
	return b.Challenge.SubjectDigest == hostSubjectDigest(a.Issuer, a.ClientID, a.Subject) &&
		b.Challenge.SessionDigest == a.SessionDigest
}

func (s *StepUp) ready(now time.Time) bool {
	return s != nil && s.store != nil && s.provider != nil && s.verifier != nil && s.config.valid(now)
}

func (s *StepUp) Begin(ctx context.Context, binding StepUpBinding) (StepUpStart, error) {
	if s == nil || s.now == nil {
		return StepUpStart{}, ErrStepUpUnavailable
	}
	now := stepUpTime(s.now())
	if !s.ready(now) {
		return StepUpStart{}, ErrStepUpUnavailable
	}
	binding.ExpiresAt = stepUpTime(binding.ExpiresAt)
	actor, actorExpiry, err := s.actor(ctx, now)
	if err != nil {
		return StepUpStart{}, err
	}
	if !binding.valid(now) || !binding.matchesActor(actor) || binding.Challenge.PolicyGeneration != s.config.PolicyGenerationSHA {
		return StepUpStart{}, ErrStepUpTransaction
	}
	policyDigest := s.policyDigest()
	state, verifier := stepUpRandom(), stepUpRandom()
	nonce := binding.Challenge.Nonce
	challenge := sha256.Sum256([]byte(verifier))
	claims, _ := json.Marshal(map[string]any{"id_token": map[string]any{"acr": map[string]any{"essential": true, "values": []string{HostControlACR}}}})
	params := url.Values{"client_id": {HostControlClient}, "response_type": {"code"}, "response_mode": {"query"}, "scope": {"openid"},
		"redirect_uri": {s.config.RedirectURI}, "state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"}, "prompt": {"login"}, "max_age": {"0"}, "acr_values": {HostControlACR}, "claims": {string(claims)}}
	par, err := s.provider.Push(ctx, params)
	if err != nil || !validStepUpRequestURI(par.URI) || par.Lifetime <= 0 || par.Lifetime > 20*time.Minute {
		return StepUpStart{}, ErrStepUpUnavailable
	}
	expires := now.Add(stepUpLifetime)
	for _, limit := range []time.Time{now.Add(par.Lifetime), actorExpiry, binding.ExpiresAt, time.Unix(binding.Challenge.ExpiresAt, 0), s.config.Policy.ReviewExpiresAt} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	p := stepUpPending{digestStepUp(state), nonce, verifier, policyDigest, actor, binding, now, stepUpTime(expires)}
	after := stepUpTime(s.now())
	if after.Before(now) || !after.Before(p.ExpiresAt) || !s.ready(after) || s.policyDigest() != policyDigest || ctx.Err() != nil {
		return StepUpStart{}, ErrStepUpTransaction
	}
	if err := s.store.Insert(ctx, p); err != nil {
		return StepUpStart{}, ErrStepUpUnavailable
	}
	after = stepUpTime(s.now())
	if after.Before(now) || !after.Before(p.ExpiresAt) || !s.ready(after) || s.policyDigest() != policyDigest || ctx.Err() != nil {
		return StepUpStart{}, ErrStepUpTransaction
	}
	return StepUpStart{s.provider.AuthorizationURL(par.URI), p.ExpiresAt}, nil
}

// StepUpEvidence is kept only in server memory and cannot serialize to JSON.
// It intentionally exports no bearer token or grant. Host transport integration
// will require a separate, reviewed protocol; possession of this value does not
// enable host work. Standard formatting redacts all token/session fields.
type StepUpEvidence struct {
	binding     StepUpBinding
	original    stepUpActor
	session     VerifiedSession
	idToken     string
	accessToken string
	expiresAt   time.Time
}

func (e StepUpEvidence) String() string               { return "StepUpEvidence[redacted]" }
func (e StepUpEvidence) GoString() string             { return e.String() }
func (e StepUpEvidence) MarshalJSON() ([]byte, error) { return nil, ErrStepUpUnavailable }

// Complete requires the authenticated ORIGINAL Administrator session, not an
// unauthenticated redirect. A future HTTP layer must enforce Origin/CSRF,
// callback parameter uniqueness, no-store/no-referrer and clear the code URL.
// Failures after Consume burn the transaction; there is no code-exchange retry.
func (s *StepUp) Complete(ctx context.Context, state, code string, binding StepUpBinding) (StepUpEvidence, error) {
	if s == nil || s.now == nil {
		return StepUpEvidence{}, ErrStepUpUnavailable
	}
	now := stepUpTime(s.now())
	if !s.ready(now) {
		return StepUpEvidence{}, ErrStepUpUnavailable
	}
	if !stepUpOpaque.MatchString(state) || !claimString(code, 4096) {
		return StepUpEvidence{}, ErrStepUpTransaction
	}
	binding.ExpiresAt = stepUpTime(binding.ExpiresAt)
	actor, _, err := s.actor(ctx, now)
	if err != nil {
		return StepUpEvidence{}, err
	}
	if !binding.valid(now) || !binding.matchesActor(actor) || binding.Challenge.PolicyGeneration != s.config.PolicyGenerationSHA {
		return StepUpEvidence{}, ErrStepUpTransaction
	}
	p, err := s.store.Consume(ctx, digestStepUp(state), actor, binding, s.policyDigest(), now)
	if err != nil {
		if errors.Is(err, ErrStepUpTransaction) {
			return StepUpEvidence{}, ErrStepUpTransaction
		}
		return StepUpEvidence{}, ErrStepUpUnavailable
	}
	if p.Actor != actor || p.Binding != binding || p.PolicyDigest != s.policyDigest() || p.StateHash != digestStepUp(state) ||
		p.Nonce != binding.Challenge.Nonce || !stepUpOpaque.MatchString(p.Nonce) || !stepUpOpaque.MatchString(p.Verifier) ||
		now.Before(p.CreatedAt) || !now.Before(p.ExpiresAt) || p.ExpiresAt.Sub(p.CreatedAt) > stepUpLifetime ||
		p.CreatedAt.Before(time.Unix(binding.Challenge.IssuedAt, 0)) ||
		p.ExpiresAt.After(time.Unix(binding.Challenge.ExpiresAt, 0)) {
		return StepUpEvidence{}, ErrStepUpTransaction
	}
	validAt := func(n time.Time) bool {
		a, _, e := s.actor(ctx, n)
		return !n.Before(now) && n.Before(p.ExpiresAt) && s.ready(n) && e == nil && a == actor && binding.valid(n) &&
			binding.matchesActor(a) && s.policyDigest() == p.PolicyDigest && binding.Challenge.PolicyGeneration == s.config.PolicyGenerationSHA && ctx.Err() == nil
	}
	valid := func() bool { return validAt(stepUpTime(s.now())) }
	if !valid() {
		return StepUpEvidence{}, ErrStepUpTransaction
	}
	tokens, err := s.provider.Exchange(ctx, code, p.Verifier, s.config.RedirectURI)
	if err != nil {
		return StepUpEvidence{}, ErrStepUpUnavailable
	}
	if !valid() {
		return StepUpEvidence{}, ErrStepUpTransaction
	}
	if !claimString(tokens.IDToken, 64<<10) || !claimString(tokens.AccessToken, 64<<10) {
		return StepUpEvidence{}, ErrStepUpIdentity
	}
	id, err := s.verifier.Verify(ctx, tokens.IDToken)
	if err != nil || id == nil || !valid() {
		return StepUpEvidence{}, ErrStepUpIdentity
	}
	idSession, err := verifiedSession(id)
	if err != nil || id.Nonce != p.Nonce || id.AccessTokenHash == "" || id.VerifyAccessToken(tokens.AccessToken) != nil {
		return StepUpEvidence{}, ErrStepUpIdentity
	}
	access, err := s.verifier.Verify(ctx, tokens.AccessToken)
	if err != nil || access == nil || !valid() {
		return StepUpEvidence{}, ErrStepUpIdentity
	}
	accessSession, err := verifiedSession(access)
	if err != nil {
		return StepUpEvidence{}, ErrStepUpIdentity
	}
	after := stepUpTime(s.now())
	idPolicy := s.config.Policy
	idPolicy.TokenType = "ID"
	if idPolicy.Check(idSession, after) != nil || s.config.Policy.Check(accessSession, after) != nil ||
		idSession.subject != actor.Subject || accessSession.subject != actor.Subject || idSession.sid != accessSession.sid ||
		!idSession.authTime.Equal(accessSession.authTime) || idSession.acr != accessSession.acr ||
		accessSession.authTime.Before(p.CreatedAt.Truncate(time.Second)) || idSession.issuedAt.Before(p.CreatedAt.Truncate(time.Second)) || accessSession.issuedAt.Before(p.CreatedAt.Truncate(time.Second)) {
		return StepUpEvidence{}, ErrStepUpIdentity
	}
	var roles struct {
		Access map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}
	if access.Claims(&roles) != nil || Role(roles.Access[s.config.ApplicationClientID].Roles) != "ADMINISTRATOR" {
		return StepUpEvidence{}, ErrStepUpIdentity
	}
	expiry := p.ExpiresAt
	for _, t := range []time.Time{idSession.expiresAt, accessSession.expiresAt, accessSession.authTime.Add(s.config.Policy.MaxAuthenticationAge), idSession.issuedAt.Add(s.config.Policy.MaxTokenAge), accessSession.issuedAt.Add(s.config.Policy.MaxTokenAge)} {
		if t.Before(expiry) {
			expiry = t
		}
	}
	// Use one final decision time for the transaction, original session and both
	// signed-token policies. Earlier checks cannot extend evidence past a limit
	// reached while parsing the renewed roles or calculating its expiry.
	decision := stepUpTime(s.now())
	if decision.Before(after) || !validAt(decision) || !decision.Before(expiry) ||
		idPolicy.Check(idSession, decision) != nil || s.config.Policy.Check(accessSession, decision) != nil {
		return StepUpEvidence{}, ErrStepUpIdentity
	}
	return StepUpEvidence{binding: binding, original: actor, session: accessSession,
		idToken: tokens.IDToken, accessToken: tokens.AccessToken, expiresAt: expiry}, nil
}
