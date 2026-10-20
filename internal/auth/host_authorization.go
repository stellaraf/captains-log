package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// HostChallenge is the private wire representation of a root-issued challenge.
// Shape validation does not establish provenance. The host must load the exact
// record from its protected ledger while holding the job transaction lock.
// Never expose its nonce, actor bindings or full value in browser/audit output.
type HostChallenge struct {
	Schema           int    `json:"schema"`
	ID               string `json:"id"`
	Nonce            string `json:"nonce"`
	InstallationID   string `json:"installation_id"`
	SubjectDigest    string `json:"subject_digest"`
	SessionDigest    string `json:"session_digest"`
	Operation        string `json:"operation"`
	OperationSchema  int    `json:"operation_schema"`
	Action           string `json:"action"`
	PlanID           string `json:"plan_id"`
	PlanDigest       string `json:"plan_digest"`
	ResourceRevision string `json:"resource_revision"`
	RequestDigest    string `json:"request_digest"`
	PolicyGeneration string `json:"policy_generation"`
	IssuedAt         int64  `json:"issued_at"`
	ExpiresAt        int64  `json:"expires_at"`
}

func (c HostChallenge) String() string   { return "HostChallenge[redacted]" }
func (c HostChallenge) GoString() string { return c.String() }

func hostUUID(s string) bool {
	return stepUpUUID.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}

func (c HostChallenge) valid(now time.Time) bool {
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(c.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != c.Nonce ||
		c.Schema != 1 || c.OperationSchema != 1 || !hostUUID(c.ID) || !hostUUID(c.InstallationID) || !hostUUID(c.PlanID) ||
		!stepUpDigest.MatchString(c.SubjectDigest) || !stepUpDigest.MatchString(c.SessionDigest) ||
		!stepUpDigest.MatchString(c.PlanDigest) || !stepUpDigest.MatchString(c.ResourceRevision) ||
		!stepUpDigest.MatchString(c.RequestDigest) || !stepUpDigest.MatchString(c.PolicyGeneration) ||
		(c.Action != "job.accept" && c.Action != "job.cancel") || c.IssuedAt <= 0 || c.ExpiresAt > 253402300799 ||
		c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 120 || now.IsZero() ||
		now.Before(time.Unix(c.IssuedAt, 0)) || !now.Before(time.Unix(c.ExpiresAt, 0)) {
		return false
	}
	switch c.Operation {
	case "storage.grow", "storage.add_disk", "updates.check", "updates.install", "updates.rollback", "updates.finalize", "updates.schedule",
		"os.apply", "reboot.complete", "backup.create", "restore.apply", "baseline.scan", "baseline.review", "baseline.select",
		"settings.network", "settings.time", "certificates.activate":
		return true
	}
	return false
}

// Match the established hostcontrol actor digest, including encoding/json's
// escaping rules. The ledger carries opaque digests; it does not rehash claims.
func hostSubjectDigest(issuer, client, subject string) string {
	return hostIdentityDigest([]string{"nebulalog.host-plan.subject.v1", issuer, client, subject})
}
func hostSessionDigest(subjectDigest, sid string) string {
	return hostIdentityDigest([]string{"nebulalog.host-plan.session.v1", subjectDigest, sid})
}
func hostIdentityDigest(parts []string) string {
	raw, _ := json.Marshal(parts)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

var errHostAuthorization = errors.New("host authorization was not verified")

// These interfaces are host-owned dependencies, never request assertions. No
// exported constructor or production policy adapter enables this primitive.
// Qualification must independently validate the enrolled policy generation,
// issuer flows/mappers/brokers/user storage and required behavioral evidence.
type hostPolicyVerifier interface {
	// The adapter must compare the actual assurance policy with its qualified
	// generation, including review identity, ACR/AMR, issuer and every lifetime.
	// Accepting only a known generation name is insufficient.
	Validate(context.Context, string, AssurancePolicy) error
}
type hostLiveVerifier interface {
	CheckSession(context.Context, string, VerifiedSession) error
	CurrentAdministrator(context.Context, string) error
}

type hostAuthorizer struct {
	installationID, applicationClientID, policyGeneration string
	policy                                                AssurancePolicy
	tokenNotBefore                                        time.Time
	applicationVerifier, stepUpVerifier                   Verifier
	live                                                  hostLiveVerifier
	qualification                                         hostPolicyVerifier
	now                                                   func() time.Time
}

func (a *hostAuthorizer) validatePolicy(ctx context.Context) error {
	p := a.policy
	p.AcceptedACR, p.RequiredAMR = slices.Clone(p.AcceptedACR), slices.Clone(p.RequiredAMR)
	return a.qualification.Validate(ctx, a.policyGeneration, p)
}

// Authorization is private, ephemeral evidence. Grant consumption belongs to
// the host job ledger's atomic transaction, not to token verification.
type hostAuthorization struct {
	challenge                     HostChallenge
	issuedAt, expiresAt, authTime time.Time
}

func (a hostAuthorization) String() string               { return "hostAuthorization[redacted]" }
func (a hostAuthorization) GoString() string             { return a.String() }
func (a hostAuthorization) MarshalJSON() ([]byte, error) { return nil, errHostAuthorization }

func (a *hostAuthorizer) configured(now time.Time) bool {
	return a != nil && hostUUID(a.installationID) && claimString(a.applicationClientID, 512) && a.applicationClientID != HostControlClient &&
		stepUpDigest.MatchString(a.policyGeneration) && a.applicationVerifier != nil && a.stepUpVerifier != nil &&
		a.live != nil && a.qualification != nil && a.now != nil && a.policy.valid(now) &&
		a.policy.Audience == HostControlClient && a.policy.ClientID == HostControlClient && a.policy.TokenType == "Bearer" &&
		slices.Equal(a.policy.AcceptedACR, []string{HostControlACR}) && a.policy.MaxAuthenticationAge <= stepUpLifetime &&
		a.policy.MaxTokenAge <= stepUpLifetime && a.policy.MaxTokenLifetime <= stepUpLifetime &&
		(a.tokenNotBefore.IsZero() || a.tokenNotBefore.Unix() > 0 && a.tokenNotBefore.Unix() <= 1<<31-1 && a.tokenNotBefore.Nanosecond() == 0)
}

func hostToken(verifier Verifier, ctx context.Context, raw string) (*oidc.IDToken, VerifiedSession, error) {
	if !claimString(raw, 64<<10) {
		return nil, VerifiedSession{}, errHostAuthorization
	}
	token, err := verifier.Verify(ctx, raw)
	if err != nil || token == nil {
		return nil, VerifiedSession{}, errHostAuthorization
	}
	session, err := verifiedSession(token)
	if err != nil {
		return nil, VerifiedSession{}, errHostAuthorization
	}
	return token, session, nil
}

func hostTokenAdministrator(token *oidc.IDToken, clientID string) bool {
	// verifiedSession already rejects duplicate names at every depth. Still use
	// the strict bounded role representation rather than coercing arbitrary JSON.
	var raw json.RawMessage
	if token.Claims(&raw) != nil {
		return false
	}
	claims, err := sessionClaims(raw)
	if err != nil {
		return false
	}
	var clients map[string]json.RawMessage
	if json.Unmarshal(claims["resource_access"], &clients) != nil || clients == nil {
		return false
	}
	var entry map[string]json.RawMessage
	if json.Unmarshal(clients[clientID], &entry) != nil || entry == nil {
		return false
	}
	var roles []string
	return json.Unmarshal(entry["roles"], &roles) == nil && claimValues(roles, false) && Role(roles) == "ADMINISTRATOR"
}

// verify accepts only a challenge reloaded from the protected host ledger.
// Possession of signed tokens cannot select an installation, policy, operation
// or resource. The caller must compare the returned challenge with the exact
// host transaction binding and consume its ID in the same durable transaction.
func (a *hostAuthorizer) verify(ctx context.Context, c HostChallenge, originalBearer, idRaw, accessRaw string) (hostAuthorization, error) {
	refuse := func() (hostAuthorization, error) { return hostAuthorization{}, errHostAuthorization }
	if a == nil || a.now == nil || ctx == nil {
		return refuse()
	}
	started := a.now()
	if !a.configured(started) || !c.valid(started) || c.InstallationID != a.installationID || c.PolicyGeneration != a.policyGeneration ||
		!claimString(originalBearer, 64<<10) || !claimString(idRaw, 64<<10) || !claimString(accessRaw, 64<<10) {
		return refuse()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if ctx.Err() != nil || a.validatePolicy(ctx) != nil {
		return refuse()
	}
	originalToken, original, err := hostToken(a.applicationVerifier, ctx, originalBearer)
	if err != nil || original.issuer != a.policy.Issuer || !original.MatchesApplication(original.subject, a.applicationClientID, started) ||
		!hostTokenAdministrator(originalToken, a.applicationClientID) ||
		c.SubjectDigest != hostSubjectDigest(original.issuer, original.client, original.subject) ||
		c.SessionDigest != hostSessionDigest(c.SubjectDigest, original.sid) {
		return refuse()
	}
	idToken, id, err := hostToken(a.stepUpVerifier, ctx, idRaw)
	if err != nil || idToken.Nonce != c.Nonce || idToken.AccessTokenHash == "" || idToken.VerifyAccessToken(accessRaw) != nil {
		return refuse()
	}
	accessToken, access, err := hostToken(a.stepUpVerifier, ctx, accessRaw)
	idPolicy := a.policy
	idPolicy.TokenType = "ID"
	if err != nil || idPolicy.Check(id, started) != nil || a.policy.Check(access, started) != nil ||
		id.subject != original.subject || access.subject != original.subject || id.sid != access.sid ||
		!id.authTime.Equal(access.authTime) || id.acr != access.acr ||
		!hostTokenAdministrator(accessToken, a.applicationClientID) {
		return refuse()
	}
	for _, s := range []VerifiedSession{original, id, access} {
		if !a.tokenNotBefore.IsZero() && s.issuedAt.Before(a.tokenNotBefore) {
			return refuse()
		}
	}
	// The signed authentication must belong to this host-issued challenge.
	// A persistent SSO sid may be reused only when the qualified local MFA flow
	// independently proves a fresh authentication time and signed host nonce.
	for _, s := range []VerifiedSession{id, access} {
		if s.authTime.Before(time.Unix(c.IssuedAt, 0)) || s.issuedAt.Before(time.Unix(c.IssuedAt, 0)) {
			return refuse()
		}
	}
	if a.live.CheckSession(ctx, originalBearer, original) != nil || a.live.CheckSession(ctx, accessRaw, access) != nil ||
		a.live.CurrentAdministrator(ctx, original.subject) != nil || a.validatePolicy(ctx) != nil {
		return refuse()
	}
	now := a.now()
	if ctx.Err() != nil || now.Before(started) || now.Sub(started) >= 20*time.Second || !a.configured(now) || !c.valid(now) ||
		c.InstallationID != a.installationID || c.PolicyGeneration != a.policyGeneration ||
		!original.MatchesApplication(original.subject, a.applicationClientID, now) || idPolicy.Check(id, now) != nil || a.policy.Check(access, now) != nil {
		return refuse()
	}
	expires := time.Unix(c.ExpiresAt, 0)
	for _, limit := range []time.Time{original.expiresAt, id.expiresAt, access.expiresAt, a.policy.ReviewExpiresAt,
		id.authTime.Add(a.policy.MaxAuthenticationAge), access.authTime.Add(a.policy.MaxAuthenticationAge),
		id.issuedAt.Add(a.policy.MaxTokenAge), access.issuedAt.Add(a.policy.MaxTokenAge)} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	if !now.Before(expires) {
		return refuse()
	}
	// Stable metadata is required for an acknowledgement-loss retry: HostJobs
	// compares the complete consumed grant, not just its UUID. Reverification
	// must never turn the same challenge/proof into a different grant record.
	return hostAuthorization{challenge: c, issuedAt: time.Unix(c.IssuedAt, 0).UTC(), expiresAt: expires, authTime: access.authTime}, nil
}
