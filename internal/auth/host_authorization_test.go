package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

type hostPolicyFixture struct {
	generation string
	calls      int
	check      func(int) error
	policies   []AssurancePolicy
}

func (p *hostPolicyFixture) Validate(ctx context.Context, generation string, policy AssurancePolicy) error {
	p.calls++
	p.policies = append(p.policies, policy)
	if ctx.Err() != nil || generation != p.generation {
		return errors.New("synthetic private policy detail")
	}
	if p.check != nil {
		return p.check(p.calls)
	}
	return nil
}

type hostLiveFixture struct {
	calls []string
	check func(string) error
}

func (l *hostLiveFixture) CheckSession(ctx context.Context, raw string, s VerifiedSession) error {
	if ctx.Err() != nil || raw == "" || !s.verified {
		return errors.New("synthetic private session detail")
	}
	l.calls = append(l.calls, s.client)
	if l.check != nil {
		return l.check(s.client)
	}
	return nil
}
func (l *hostLiveFixture) CurrentAdministrator(ctx context.Context, subject string) error {
	if ctx.Err() != nil || subject != "subject-synthetic" {
		return errors.New("synthetic private role detail")
	}
	l.calls = append(l.calls, "administrator")
	if l.check != nil {
		return l.check("administrator")
	}
	return nil
}

type hostAuthorizationFixture struct {
	a          *hostAuthorizer
	challenge  HostChallenge
	policy     *hostPolicyFixture
	live       *hostLiveFixture
	now        time.Time
	original   map[string]any
	id, access map[string]any
	sign       func(map[string]any) string
}

func newHostAuthorizationFixture(t *testing.T) *hostAuthorizationFixture {
	t.Helper()
	f := &hostAuthorizationFixture{now: sessionTestNow}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f.sign = func(c map[string]any) string {
		t.Helper()
		jws, err := signer.Sign(marshalClaims(t, c))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jws.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	verifier := func(client string) Verifier {
		return oidc.NewVerifier(aIssuer(), &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}},
			&oidc.Config{ClientID: client, SupportedSigningAlgs: []string{"ES256"}, Now: func() time.Time { return f.now }})
	}
	f.original = syntheticClaims()
	subject := hostSubjectDigest(aIssuer(), "nebulalog", "subject-synthetic")
	f.challenge = HostChallenge{Schema: 1, ID: "22222222-2222-4222-8222-222222222222", Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		InstallationID: "11111111-1111-4111-8111-111111111111", SubjectDigest: subject,
		SessionDigest: hostSessionDigest(subject, "private-session-synthetic"), Operation: "backup.create", OperationSchema: 1, Action: "job.accept",
		PlanID: "33333333-3333-4333-8333-333333333333", PlanDigest: strings.Repeat("a", 64), ResourceRevision: strings.Repeat("b", 64),
		RequestDigest: strings.Repeat("c", 64), PolicyGeneration: strings.Repeat("d", 64), IssuedAt: f.now.Unix() - 2, ExpiresAt: f.now.Unix() + 110}
	f.id = syntheticClaims()
	f.access = syntheticClaims()
	for _, c := range []map[string]any{f.id, f.access} {
		c["aud"], c["azp"], c["sid"], c["acr"] = []string{HostControlClient}, HostControlClient, "host-session-synthetic", HostControlACR
		c["auth_time"], c["iat"], c["exp"] = f.now.Unix()-1, f.now.Unix(), f.now.Unix()+100
	}
	f.id["typ"], f.id["nonce"] = "ID", f.challenge.Nonce
	p := testAssurancePolicy()
	p.Audience, p.ClientID, p.TokenType, p.AcceptedACR = HostControlClient, HostControlClient, "Bearer", []string{HostControlACR}
	p.MaxAuthenticationAge, p.MaxTokenAge, p.MaxTokenLifetime = stepUpLifetime, stepUpLifetime, stepUpLifetime
	f.policy, f.live = &hostPolicyFixture{generation: f.challenge.PolicyGeneration}, &hostLiveFixture{}
	f.a = &hostAuthorizer{installationID: f.challenge.InstallationID, applicationClientID: "nebulalog", policyGeneration: f.challenge.PolicyGeneration,
		policy: p, applicationVerifier: verifier("nebulalog"), stepUpVerifier: verifier(HostControlClient),
		live: f.live, qualification: f.policy, now: func() time.Time { return f.now }}
	return f
}

func (f *hostAuthorizationFixture) tokens() (string, string, string) {
	access := f.sign(f.access)
	h := sha256.Sum256([]byte(access))
	f.id["at_hash"] = base64.RawURLEncoding.EncodeToString(h[:len(h)/2])
	return f.sign(f.original), f.sign(f.id), access
}

func (f *hostAuthorizationFixture) verify() (hostAuthorization, error) {
	original, id, access := f.tokens()
	return f.a.verify(context.Background(), f.challenge, original, id, access)
}

func TestHostAuthorizationIndependentSignedEvidence(t *testing.T) {
	f := newHostAuthorizationFixture(t)
	got, err := f.verify()
	if err != nil || got.challenge != f.challenge || got.issuedAt.Unix() != f.challenge.IssuedAt || got.expiresAt.Unix() != f.now.Unix()+100 ||
		got.authTime.Unix() != f.now.Unix()-1 || f.policy.calls != 2 ||
		!reflect.DeepEqual(f.policy.policies, []AssurancePolicy{f.a.policy, f.a.policy}) ||
		!reflect.DeepEqual(f.live.calls, []string{"nebulalog", HostControlClient, "administrator"}) {
		t.Fatal("independent host verification did not preserve exact evidence", err)
	}
	if _, err := json.Marshal(got); err == nil {
		t.Fatal("authorization evidence was serializable")
	}
	text := fmt.Sprintf("%v %#v %+v %v", got, got, got, f.challenge)
	for _, secret := range []string{f.challenge.Nonce, f.challenge.SessionDigest, f.challenge.SubjectDigest} {
		if strings.Contains(text, secret) {
			t.Fatal("private host evidence leaked in formatting")
		}
	}
}

func TestHostAuthorizationExactProofRetryKeepsGrantIdentity(t *testing.T) {
	f := newHostAuthorizationFixture(t)
	original, id, access := f.tokens()
	first, err := f.a.verify(context.Background(), f.challenge, original, id, access)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(10 * time.Second)
	second, err := f.a.verify(context.Background(), f.challenge, original, id, access)
	if err != nil || first != second || f.policy.calls != 4 || len(f.live.calls) != 6 {
		t.Fatal("exact retry changed immutable grant or bypassed fresh authority checks", err)
	}
}

func TestHostAuthorizationRequiresProtectedDependenciesBeforeNetwork(t *testing.T) {
	cases := map[string]func(*hostAuthorizationFixture){
		"no live session client":  func(f *hostAuthorizationFixture) { f.a.live = nil },
		"no qualified policy":     func(f *hostAuthorizationFixture) { f.a.qualification = nil },
		"no original verifier":    func(f *hostAuthorizationFixture) { f.a.applicationVerifier = nil },
		"no step up verifier":     func(f *hostAuthorizationFixture) { f.a.stepUpVerifier = nil },
		"wrong installation":      func(f *hostAuthorizationFixture) { f.challenge.InstallationID = "44444444-4444-4444-8444-444444444444" },
		"wrong policy generation": func(f *hostAuthorizationFixture) { f.challenge.PolicyGeneration = strings.Repeat("e", 64) },
		"unreviewed":              func(f *hostAuthorizationFixture) { f.a.policy.Reviewed = false },
		"expired review":          func(f *hostAuthorizationFixture) { f.a.policy.ReviewExpiresAt = f.now },
		"overlong MFA window":     func(f *hostAuthorizationFixture) { f.a.policy.MaxAuthenticationAge = 3 * time.Minute },
		"bad restore cutoff":      func(f *hostAuthorizationFixture) { f.a.tokenNotBefore = time.Unix(-1, 0) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newHostAuthorizationFixture(t)
			mutate(f)
			if got, err := f.verify(); err != errHostAuthorization || got != (hostAuthorization{}) || len(f.live.calls) != 0 || f.policy.calls != 0 {
				t.Fatal("unconfigured authority reached live checks")
			}
		})
	}
}

func TestHostAuthorizationRejectsSignedButUnboundEvidence(t *testing.T) {
	cases := map[string]func(*hostAuthorizationFixture){
		"original subject": func(f *hostAuthorizationFixture) { f.original["sub"] = "other" },
		"original session": func(f *hostAuthorizationFixture) { f.original["sid"] = "other" },
		"original client":  func(f *hostAuthorizationFixture) { f.original["azp"] = "other" },
		"original role":    func(f *hostAuthorizationFixture) { delete(f.original, "resource_access") },
		"nonce":            func(f *hostAuthorizationFixture) { f.id["nonce"] = strings.Repeat("x", 43) },
		"old MFA": func(f *hostAuthorizationFixture) {
			f.id["auth_time"], f.access["auth_time"] = f.now.Unix()-3, f.now.Unix()-3
		},
		"old ID issue": func(f *hostAuthorizationFixture) { f.id["iat"] = f.now.Unix() - 3 },
		"access role":  func(f *hostAuthorizationFixture) { delete(f.access, "resource_access") },
		"access role shape": func(f *hostAuthorizationFixture) {
			f.access["resource_access"] = map[string]any{"nebulalog": map[string]any{"roles": "ADMINISTRATOR"}}
		},
		"access subject":  func(f *hostAuthorizationFixture) { f.access["sub"] = "other" },
		"ID session":      func(f *hostAuthorizationFixture) { f.id["sid"] = "other" },
		"ID auth time":    func(f *hostAuthorizationFixture) { f.id["auth_time"] = f.now.Unix() },
		"ID ACR":          func(f *hostAuthorizationFixture) { f.id["acr"] = "2" },
		"access method":   func(f *hostAuthorizationFixture) { f.access["amr"] = []string{"pwd"} },
		"ID method":       func(f *hostAuthorizationFixture) { f.id["amr"] = []string{"pwd"} },
		"ID token type":   func(f *hostAuthorizationFixture) { f.id["typ"] = "Bearer" },
		"access client":   func(f *hostAuthorizationFixture) { f.access["azp"] = "nebulalog" },
		"access audience": func(f *hostAuthorizationFixture) { f.access["aud"] = []string{"nebulalog"} },
		"token lifetime":  func(f *hostAuthorizationFixture) { f.access["exp"] = f.now.Unix() + 121 },
		"future authentication": func(f *hostAuthorizationFixture) {
			f.id["auth_time"], f.access["auth_time"] = f.now.Unix()+1, f.now.Unix()+1
		},
		"original predates restore": func(f *hostAuthorizationFixture) { f.a.tokenNotBefore = f.now },
		"stepup predates restore": func(f *hostAuthorizationFixture) {
			f.original["iat"] = f.now.Unix() + 1
			f.a.tokenNotBefore = f.now.Add(time.Second)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newHostAuthorizationFixture(t)
			mutate(f)
			if got, err := f.verify(); err != errHostAuthorization || got != (hostAuthorization{}) || len(f.live.calls) != 0 {
				t.Fatal("invalid signed evidence reached live authority", err)
			}
		})
	}
}

func TestHostAuthorizationRejectsTokenSubstitutionAndBadSignatures(t *testing.T) {
	for _, which := range []string{"original signature", "ID signature", "access signature", "at_hash", "missing hash", "oversized", "cancelled"} {
		t.Run(which, func(t *testing.T) {
			f := newHostAuthorizationFixture(t)
			original, id, access := f.tokens()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			other := newHostAuthorizationFixture(t)
			switch which {
			case "original signature":
				original = other.sign(f.original)
			case "ID signature":
				id = other.sign(f.id)
			case "access signature":
				access = other.sign(f.access)
			case "at_hash":
				f.id["at_hash"] = "wrong"
				id = f.sign(f.id)
			case "missing hash":
				delete(f.id, "at_hash")
				id = f.sign(f.id)
			case "oversized":
				original = strings.Repeat("x", (64<<10)+1)
			case "cancelled":
				cancel()
			}
			if got, err := f.a.verify(ctx, f.challenge, original, id, access); err != errHostAuthorization || got != (hostAuthorization{}) {
				t.Fatal("unverified proof accepted")
			}
		})
	}
}

func TestHostAuthorizationLiveRevocationRolePolicyAndFinalClock(t *testing.T) {
	for _, failure := range []string{"nebulalog", HostControlClient, "administrator", "initial policy", "final policy", "clock rollback", "expiry during live", "deadline during live", "installation changed", "policy generation changed"} {
		t.Run(failure, func(t *testing.T) {
			f := newHostAuthorizationFixture(t)
			f.policy.check = func(call int) error {
				if failure == "initial policy" || failure == "final policy" && call == 2 {
					return errors.New("private issuer details")
				}
				return nil
			}
			f.live.check = func(stage string) error {
				if stage == failure {
					return errors.New("private issuer details")
				}
				if stage == "administrator" {
					switch failure {
					case "clock rollback":
						f.now = f.now.Add(-time.Second)
					case "expiry during live":
						f.now = f.now.Add(110 * time.Second)
					case "deadline during live":
						f.now = f.now.Add(20 * time.Second)
					case "installation changed":
						f.a.installationID = "44444444-4444-4444-8444-444444444444"
					case "policy generation changed":
						f.a.policyGeneration = strings.Repeat("e", 64)
						f.policy.generation = f.a.policyGeneration
					}
				}
				return nil
			}
			if got, err := f.verify(); err != errHostAuthorization || got != (hostAuthorization{}) {
				t.Fatal("stale or revoked authority accepted", err)
			}
		})
	}
}

func TestHostChallengeStrictShapeAndExclusiveExpiry(t *testing.T) {
	f := newHostAuthorizationFixture(t)
	for name, mutate := range map[string]func(*HostChallenge){
		"schema":             func(c *HostChallenge) { c.Schema = 2 },
		"operation schema":   func(c *HostChallenge) { c.OperationSchema = 2 },
		"zero id":            func(c *HostChallenge) { c.ID = "00000000-0000-0000-0000-000000000000" },
		"action":             func(c *HostChallenge) { c.Action = "execute" },
		"operation":          func(c *HostChallenge) { c.Operation = "exec.shell" },
		"noncanonical nonce": func(c *HostChallenge) { c.Nonce = strings.Repeat("A", 42) + "B" },
		"short nonce":        func(c *HostChallenge) { c.Nonce = "A" },
		"uppercase digest":   func(c *HostChallenge) { c.SubjectDigest = strings.Repeat("A", 64) },
		"future":             func(c *HostChallenge) { c.IssuedAt = f.now.Unix() + 1 },
		"expired":            func(c *HostChallenge) { c.ExpiresAt = f.now.Unix() },
		"long lifetime":      func(c *HostChallenge) { c.ExpiresAt = c.IssuedAt + 121 },
		"overflow time":      func(c *HostChallenge) { c.IssuedAt = -1 << 63; c.ExpiresAt = 1<<63 - 1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.challenge
			mutate(&c)
			if c.valid(f.now) {
				t.Fatal("invalid challenge accepted")
			}
		})
	}
	c := f.challenge
	c.Action = "job.cancel"
	if !c.valid(f.now) {
		t.Fatal("cancel action shape rejected")
	}
}

func TestHostAuthorizationBoundsByEveryEvidenceExpiry(t *testing.T) {
	for _, boundary := range []string{"challenge", "original", "id", "access", "review", "authentication", "issued"} {
		t.Run(boundary, func(t *testing.T) {
			f := newHostAuthorizationFixture(t)
			switch boundary {
			case "challenge":
				f.challenge.ExpiresAt = f.now.Unix() + 10
			case "original":
				f.original["exp"] = f.now.Unix() + 10
			case "id":
				f.id["exp"] = f.now.Unix() + 10
			case "access":
				f.access["exp"] = f.now.Unix() + 10
			case "review":
				f.a.policy.ReviewExpiresAt = f.now.Add(10 * time.Second)
			case "authentication":
				f.a.policy.MaxAuthenticationAge = 11 * time.Second
			case "issued":
				f.a.policy.MaxTokenAge = 10 * time.Second
			}
			got, err := f.verify()
			if err != nil || got.expiresAt.Unix() != f.now.Unix()+10 {
				t.Fatal("grant outlives evidence", err)
			}
		})
	}
}
