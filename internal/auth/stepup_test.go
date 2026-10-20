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
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// This store models the atomic compare-and-delete contract. The PostgreSQL
// adapter's query, privileges and restart behavior have separate coverage.
type testStepUpStore struct {
	mu      sync.Mutex
	pending map[string]stepUpPending
	alter   func(*stepUpPending)
}

func (s *testStepUpStore) Insert(_ context.Context, p stepUpPending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[p.StateHash]; ok {
		return ErrStepUpTransaction
	}
	s.pending[p.StateHash] = p
	return nil
}

func (s *testStepUpStore) Consume(_ context.Context, hash string, actor stepUpActor, binding StepUpBinding, policy string, now time.Time) (stepUpPending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[hash]
	if !ok || p.Actor != actor || p.Binding != binding || p.PolicyDigest != policy || now.Before(p.CreatedAt) || !now.Before(p.ExpiresAt) {
		return stepUpPending{}, ErrStepUpTransaction
	}
	delete(s.pending, hash)
	if s.alter != nil {
		s.alter(&p)
	}
	return p, nil
}

type testStepUpProvider struct {
	mu                       sync.Mutex
	params                   url.Values
	par                      stepUpPAR
	pushErr, exchangeErr     error
	afterPush, afterExchange func()
	tokens                   stepUpTokens
	exchanges                int
	code, verifier, redirect string
}

func (p *testStepUpProvider) Push(_ context.Context, params url.Values) (stepUpPAR, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.params = params
	if p.afterPush != nil {
		p.afterPush()
	}
	return p.par, p.pushErr
}

func (p *testStepUpProvider) Exchange(_ context.Context, code, verifier, redirect string) (stepUpTokens, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exchanges++
	p.code, p.verifier, p.redirect = code, verifier, redirect
	if p.afterExchange != nil {
		p.afterExchange()
	}
	return p.tokens, p.exchangeErr
}

func (p *testStepUpProvider) AuthorizationURL(uri string) string {
	return "https://auth.example.test/authorize?" + url.Values{"client_id": {HostControlClient}, "request_uri": {uri}}.Encode()
}

type stepUpFixture struct {
	s        *StepUp
	store    *testStepUpStore
	provider *testStepUpProvider
	at       time.Time
	ctx      context.Context
	binding  StepUpBinding
	sign     func(map[string]any) string
}

func newStepUpFixture(t *testing.T) *stepUpFixture {
	t.Helper()
	f := &stepUpFixture{at: sessionTestNow}
	f.store = &testStepUpStore{pending: map[string]stepUpPending{}}
	f.provider = &testStepUpProvider{par: stepUpPAR{"urn:ietf:params:oauth:request_uri:synthetic-request-only", 120 * time.Second}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &jose.SignerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f.sign = func(claims map[string]any) string {
		t.Helper()
		jws, err := signer.Sign(marshalClaims(t, claims))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jws.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	policy := testAssurancePolicy()
	policy.Audience, policy.ClientID = HostControlClient, HostControlClient
	policy.AcceptedACR, policy.RequiredAMR = []string{HostControlACR}, nil
	policy.MaxAuthenticationAge, policy.MaxTokenAge, policy.MaxTokenLifetime = 120*time.Second, 120*time.Second, 120*time.Second
	f.s = &StepUp{
		config: StepUpConfig{Policy: policy, ApplicationClientID: "nebulalog", RedirectURI: "https://app.example.test/api/host/step-up/callback", PolicyGenerationSHA: strings.Repeat("c", 64)},
		store:  f.store, provider: f.provider,
		verifier: oidc.NewVerifier(aIssuer(), &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{
			ClientID: HostControlClient, SupportedSigningAlgs: []string{"ES256"}, Now: func() time.Time { return f.at },
		}),
		now: func() time.Time { return f.at },
	}
	app, appSign := signedAuth(t, f.at)
	original, ok, _ := captureSession(t, app, appSign(marshalClaims(t, syntheticClaims())))
	if !ok {
		t.Fatal("missing original signed session")
	}
	f.ctx = context.WithValue(context.Background(), keyForUser(), User{ID: original.subject, Name: "synthetic", Role: "ADMINISTRATOR"})
	f.ctx = context.WithValue(f.ctx, sessionKey{}, original)
	f.binding = StepUpBinding{
		InstallationID: "11111111-2222-3333-4444-555555555555", Operation: "storage.grow",
		PlanID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", PlanDigest: strings.Repeat("a", 64), ResourceRevision: strings.Repeat("b", 64),
		ExpiresAt: f.at.Add(3 * time.Minute),
	}
	f.binding.Challenge = syntheticStepUpChallenge(f.binding, original.issuer, original.client, original.subject, original.sid, f.at)
	return f
}

// Explicit synthetic authority for unit fixtures only. No production policy is
// loaded, qualified, enabled or inferred by this helper.
func syntheticStepUpChallenge(b StepUpBinding, issuer, client, subject, sid string, now time.Time) HostChallenge {
	subjectDigest := hostSubjectDigest(issuer, client, subject)
	return HostChallenge{Schema: 1, ID: "01234567-89ab-cdef-0123-456789abcdef", Nonce: strings.Repeat("n", 42) + "k",
		InstallationID: b.InstallationID, SubjectDigest: subjectDigest, SessionDigest: hostSessionDigest(subjectDigest, sid),
		Operation: b.Operation, OperationSchema: 1, Action: "job.accept", PlanID: b.PlanID, PlanDigest: b.PlanDigest,
		ResourceRevision: b.ResourceRevision, RequestDigest: strings.Repeat("d", 64), PolicyGeneration: strings.Repeat("c", 64),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(120 * time.Second).Unix()}
}

func stepUpChallengeMutations() map[string]func(*HostChallenge) {
	return map[string]func(*HostChallenge){
		"schema":            func(c *HostChallenge) { c.Schema++ },
		"ID":                func(c *HostChallenge) { c.ID = "fedcba98-7654-3210-fedc-ba9876543210" },
		"nonce":             func(c *HostChallenge) { c.Nonce = strings.Repeat("x", 42) + "w" },
		"installation":      func(c *HostChallenge) { c.InstallationID = "fedcba98-7654-3210-fedc-ba9876543210" },
		"subject":           func(c *HostChallenge) { c.SubjectDigest = strings.Repeat("e", 64) },
		"session":           func(c *HostChallenge) { c.SessionDigest = strings.Repeat("e", 64) },
		"operation":         func(c *HostChallenge) { c.Operation = "backup.create" },
		"operation schema":  func(c *HostChallenge) { c.OperationSchema++ },
		"action":            func(c *HostChallenge) { c.Action = "job.cancel" },
		"plan":              func(c *HostChallenge) { c.PlanID = "fedcba98-7654-3210-fedc-ba9876543210" },
		"plan digest":       func(c *HostChallenge) { c.PlanDigest = strings.Repeat("e", 64) },
		"revision":          func(c *HostChallenge) { c.ResourceRevision = strings.Repeat("e", 64) },
		"request":           func(c *HostChallenge) { c.RequestDigest = strings.Repeat("e", 64) },
		"policy generation": func(c *HostChallenge) { c.PolicyGeneration = strings.Repeat("e", 64) },
		"issued":            func(c *HostChallenge) { c.IssuedAt-- },
		"expiry":            func(c *HostChallenge) { c.ExpiresAt-- },
	}
}

func TestStepUpHostChallengeEveryFieldSurvivesCompletionBinding(t *testing.T) {
	for name, mutate := range stepUpChallengeMutations() {
		t.Run(name, func(t *testing.T) {
			f := newStepUpFixture(t)
			f.binding.Challenge.ExpiresAt-- // leaves one second for a distinct valid earlier issue time
			_, state := f.begin(t)
			changed := f.binding
			mutate(&changed.Challenge)
			if _, err := f.s.Complete(f.ctx, state, "code", changed); !errors.Is(err, ErrStepUpTransaction) || f.provider.exchanges != 0 || len(f.store.pending) != 1 {
				t.Fatal("changed host challenge consumed or exchanged original transaction")
			}
			id, access := f.tokenClaims()
			f.setTokens(id, access)
			evidence, err := f.s.Complete(f.ctx, state, "code", f.binding)
			if err != nil || evidence.binding.Challenge != f.binding.Challenge || evidence.idToken != f.provider.tokens.IDToken {
				t.Fatal("exact host challenge did not retain private token pair")
			}
		})
	}
}

func TestStepUpHostChallengeMissingActorPolicyOrExpiryRefusesBeforePAR(t *testing.T) {
	for _, mode := range []string{"missing", "subject", "session", "policy", "unconfigured policy", "expired", "future", "outlasts plan"} {
		t.Run(mode, func(t *testing.T) {
			f := newStepUpFixture(t)
			switch mode {
			case "missing":
				f.binding.Challenge = HostChallenge{}
			case "subject":
				f.binding.Challenge.SubjectDigest = strings.Repeat("e", 64)
			case "session":
				f.binding.Challenge.SessionDigest = strings.Repeat("e", 64)
			case "policy":
				f.binding.Challenge.PolicyGeneration = strings.Repeat("e", 64)
			case "unconfigured policy":
				f.s.config.PolicyGenerationSHA = ""
			case "expired":
				f.binding.Challenge.ExpiresAt = f.at.Unix()
			case "future":
				f.binding.Challenge.IssuedAt = f.at.Add(time.Second).Unix()
			case "outlasts plan":
				f.binding.ExpiresAt = f.at.Add(10 * time.Second)
			}
			if _, err := f.s.Begin(f.ctx, f.binding); err == nil || f.provider.params != nil || len(f.store.pending) != 0 {
				t.Fatal("unbound host challenge reached PAR or persistence")
			}
		})
	}
}

func TestStepUpHostActorUsesReadOnlyPlanDomainHashes(t *testing.T) {
	f := newStepUpFixture(t)
	original, _ := CurrentSession(f.ctx)
	subjectJSON, _ := json.Marshal([]string{"nebulalog.host-plan.subject.v1", original.issuer, original.client, original.subject})
	wantSubject := digestStepUp(string(subjectJSON))
	sessionJSON, _ := json.Marshal([]string{"nebulalog.host-plan.session.v1", wantSubject, original.sid})
	wantSession := digestStepUp(string(sessionJSON))
	actor, _, err := f.s.actor(f.ctx, f.at)
	if err != nil || actor.SessionDigest != wantSession || f.binding.Challenge.SubjectDigest != wantSubject || actor.SessionDigest == digestStepUp(original.sid) {
		t.Fatal("host-control actor domain separation changed")
	}
}

// Keep the package's context key distinct from the signing-key local variable.
func keyForUser() key { return key{} }

func (f *stepUpFixture) begin(t *testing.T) (StepUpStart, string) {
	t.Helper()
	start, err := f.s.Begin(f.ctx, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	return start, f.provider.params.Get("state")
}

func (f *stepUpFixture) tokenClaims() (map[string]any, map[string]any) {
	access := map[string]any{
		"iss": aIssuer(), "sub": "subject-synthetic", "aud": HostControlClient, "azp": HostControlClient,
		"sid": "new-step-up-session", "typ": "Bearer", "auth_time": f.at.Unix(), "iat": f.at.Unix(), "exp": f.at.Add(120 * time.Second).Unix(),
		"acr": HostControlACR, "resource_access": map[string]any{"nebulalog": map[string]any{"roles": []string{"ADMINISTRATOR"}}},
	}
	id := map[string]any{}
	for k, v := range access {
		id[k] = v
	}
	delete(id, "resource_access")
	id["typ"], id["nonce"] = "ID", f.provider.params.Get("nonce")
	return id, access
}

func (f *stepUpFixture) setTokens(id, access map[string]any) {
	rawAccess := f.sign(access)
	hash := sha256.Sum256([]byte(rawAccess))
	id["at_hash"] = base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])
	f.provider.tokens = stepUpTokens{IDToken: f.sign(id), AccessToken: rawAccess}
}

func TestStepUpBeginCreatesPrivateActionBoundPAR(t *testing.T) {
	f := newStepUpFixture(t)
	start, state := f.begin(t)
	p := f.store.pending[digestStepUp(state)]
	for _, v := range []string{state, p.Nonce, p.Verifier} {
		if !stepUpOpaque.MatchString(v) {
			t.Fatal("invalid random value")
		}
	}
	if state == p.Nonce || state == p.Verifier || p.Nonce == p.Verifier {
		t.Fatal("transaction values reused")
	}
	challenge := sha256.Sum256([]byte(p.Verifier))
	for name, want := range map[string]string{
		"client_id": HostControlClient, "scope": "openid", "response_type": "code", "response_mode": "query", "prompt": "login", "max_age": "0",
		"code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "redirect_uri": f.s.config.RedirectURI,
		"nonce": p.Nonce, "acr_values": HostControlACR,
	} {
		if f.provider.params.Get(name) != want {
			t.Fatalf("wrong PAR field %s", name)
		}
	}
	var claims struct {
		IDToken struct {
			ACR struct {
				Essential bool
				Values    []string
			}
		} `json:"id_token"`
	}
	if json.Unmarshal([]byte(f.provider.params.Get("claims")), &claims) != nil || !claims.IDToken.ACR.Essential || len(claims.IDToken.ACR.Values) != 1 || claims.IDToken.ACR.Values[0] != HostControlACR {
		t.Fatal("essential ACR missing")
	}
	original, _ := CurrentSession(f.ctx)
	if p.Nonce != f.binding.Challenge.Nonce || p.Actor.SessionDigest != f.binding.Challenge.SessionDigest || p.Actor.Subject != original.subject || p.Binding != f.binding || p.PolicyDigest != f.s.policyDigest() {
		t.Fatal("stored bindings differ")
	}
	if !start.ExpiresAt.Equal(f.at.Add(120 * time.Second)) {
		t.Fatal("transaction lifetime differs")
	}
	for _, secret := range []string{state, p.Nonce, p.Verifier, original.sid, original.subject, f.binding.PlanDigest} {
		if strings.Contains(start.AuthorizationURL, secret) {
			t.Fatal("private binding exposed to browser")
		}
	}
	if _, err := json.Marshal(start); err != nil {
		t.Fatal("browser start cannot serialize")
	}
}

func TestStepUpCompleteReturnsSeparateSessionsAndRedactsEvidence(t *testing.T) {
	f := newStepUpFixture(t)
	f.s.config.Policy.MaxTokenAge = 30 * time.Second
	_, state := f.begin(t)
	id, access := f.tokenClaims()
	f.setTokens(id, access)
	evidence, err := f.s.Complete(f.ctx, state, "synthetic-authorization-code", f.binding)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := CurrentSession(f.ctx)
	if evidence.original.SessionDigest != f.binding.Challenge.SessionDigest || evidence.session.sid != "new-step-up-session" || evidence.session.sid == original.sid || evidence.binding != f.binding ||
		evidence.idToken != f.provider.tokens.IDToken || evidence.accessToken != f.provider.tokens.AccessToken {
		t.Fatal("original and new session binding lost")
	}
	if !evidence.expiresAt.Equal(f.at.Add(30 * time.Second)) {
		t.Fatal("evidence outlasts token age")
	}
	if f.provider.code != "synthetic-authorization-code" || !stepUpOpaque.MatchString(f.provider.verifier) || f.provider.redirect != f.s.config.RedirectURI {
		t.Fatal("exchange not bound to original transaction")
	}
	for _, private := range []any{evidence, evidence.original, evidence.session, f.provider.tokens} {
		if _, err := json.Marshal(private); err == nil {
			t.Fatal("private evidence serializes")
		}
		text := fmt.Sprintf("%v %+v %#v", private, private, private)
		for _, secret := range []string{original.sid, original.subject, "new-step-up-session", f.provider.tokens.IDToken, f.provider.tokens.AccessToken} {
			if strings.Contains(text, secret) {
				t.Fatal("private evidence appears in formatting")
			}
		}
	}
	if _, err := f.s.Complete(f.ctx, state, "same-code", f.binding); !errors.Is(err, ErrStepUpTransaction) || f.provider.exchanges != 1 {
		t.Fatal("completed transaction replayed")
	}
}

func TestStepUpParallelCallbacksExchangeExactlyOnce(t *testing.T) {
	f := newStepUpFixture(t)
	_, state := f.begin(t)
	id, access := f.tokenClaims()
	f.setTokens(id, access)
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.s.Complete(f.ctx, state, "one-code", f.binding)
			if err == nil {
				success.Add(1)
			} else if !errors.Is(err, ErrStepUpTransaction) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 || f.provider.exchanges != 1 {
		t.Fatalf("success=%d exchanges=%d", success.Load(), f.provider.exchanges)
	}
}

func TestStepUpRejectsEvidenceExpiringAtFinalDecision(t *testing.T) {
	for _, deadline := range []string{"ID expiry", "access expiry", "authentication age", "token age"} {
		t.Run(deadline, func(t *testing.T) {
			f := newStepUpFixture(t)
			if deadline == "authentication age" {
				f.s.config.Policy.MaxAuthenticationAge = time.Second
			}
			if deadline == "token age" {
				f.s.config.Policy.MaxTokenAge = time.Second
			}
			_, state := f.begin(t)
			id, access := f.tokenClaims()
			if deadline == "ID expiry" {
				id["exp"] = f.at.Add(time.Second).Unix()
			}
			if deadline == "access expiry" {
				access["exp"] = f.at.Add(time.Second).Unix()
			}
			f.setTokens(id, access)
			reads := 0
			f.s.now = func() time.Time {
				reads++
				// The first six samples cover transaction and signature checks
				// through the initial assurance decision. The final sample is
				// after renewed-role parsing, exactly at the shortest deadline.
				if reads >= 7 {
					return f.at.Add(time.Second)
				}
				return f.at
			}
			if _, err := f.s.Complete(f.ctx, state, "code", f.binding); !errors.Is(err, ErrStepUpIdentity) {
				t.Fatalf("expired final evidence accepted: %v", err)
			}
			if _, err := f.s.Complete(f.ctx, state, "code", f.binding); !errors.Is(err, ErrStepUpTransaction) || f.provider.exchanges != 1 {
				t.Fatal("expired final evidence allowed another exchange")
			}
		})
	}
}

func TestStepUpRefusesWrongOriginalIdentityOrActionBeforeExchange(t *testing.T) {
	for _, mode := range []string{"unauthenticated", "viewer", "analyst", "different subject", "different session", "different client", "expired original", "installation", "operation", "plan", "digest", "revision", "plan expiry", "policy", "state"} {
		t.Run(mode, func(t *testing.T) {
			f := newStepUpFixture(t)
			_, state := f.begin(t)
			ctx, binding := f.ctx, f.binding
			v, _ := CurrentSession(ctx)
			switch mode {
			case "unauthenticated":
				ctx = context.Background()
			case "viewer", "analyst":
				u := Current(ctx)
				u.Role = strings.ToUpper(mode)
				ctx = context.WithValue(ctx, key{}, u)
			case "different subject":
				v.subject = "other-subject"
				ctx = context.WithValue(ctx, sessionKey{}, v)
				u := Current(ctx)
				u.ID = v.subject
				ctx = context.WithValue(ctx, key{}, u)
			case "different session":
				v.sid = "other-session"
				ctx = context.WithValue(ctx, sessionKey{}, v)
			case "different client":
				v.client = HostControlClient
				ctx = context.WithValue(ctx, sessionKey{}, v)
			case "expired original":
				v.expiresAt = f.at
				ctx = context.WithValue(ctx, sessionKey{}, v)
			case "installation":
				binding.InstallationID = "99999999-2222-3333-4444-555555555555"
			case "operation":
				binding.Operation = "backup.create"
			case "plan":
				binding.PlanID = "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"
			case "digest":
				binding.PlanDigest = strings.Repeat("c", 64)
			case "revision":
				binding.ResourceRevision = strings.Repeat("c", 64)
			case "plan expiry":
				binding.ExpiresAt = binding.ExpiresAt.Add(time.Second)
			case "policy":
				f.s.config.Policy.ReviewID = "another-reviewed-policy"
			case "state":
				state = strings.Repeat("A", 43)
			}
			if _, err := f.s.Complete(ctx, state, "code", binding); err == nil || f.provider.exchanges != 0 {
				t.Fatal("wrong binding reached exchange")
			}
			if len(f.store.pending) != 1 {
				t.Fatal("mismatched callback consumed original transaction")
			}
		})
	}
}

func TestStepUpBurnsExchangeFailuresAndLateCompletion(t *testing.T) {
	for _, mode := range []string{"exchange failure", "exchange reaches deadline", "exchange clock rollback", "cancelled exchange", "verify reaches deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newStepUpFixture(t)
			_, state := f.begin(t)
			id, access := f.tokenClaims()
			f.setTokens(id, access)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			switch mode {
			case "exchange failure":
				f.provider.exchangeErr = errors.New("upstream contains synthetic secret")
			case "exchange reaches deadline":
				f.provider.afterExchange = func() { f.at = f.at.Add(120 * time.Second) }
			case "exchange clock rollback":
				f.provider.afterExchange = func() { f.at = f.at.Add(-time.Second) }
			case "cancelled exchange":
				f.provider.afterExchange = cancel
			case "verify reaches deadline":
				f.s.verifier = stepUpSlowVerifier{f.s.verifier, func() { f.at = f.at.Add(120 * time.Second) }}
			}
			if _, err := f.s.Complete(ctx, state, "code", f.binding); err == nil || strings.Contains(err.Error(), "synthetic secret") {
				t.Fatal("failed transaction accepted or leaked")
			}
			if _, err := f.s.Complete(f.ctx, state, "code", f.binding); err == nil || f.provider.exchanges != 1 {
				t.Fatal("exchange failure retried")
			}
		})
	}
}

type stepUpSlowVerifier struct {
	Verifier
	after func()
}

func (v stepUpSlowVerifier) Verify(ctx context.Context, raw string) (*oidc.IDToken, error) {
	token, err := v.Verifier.Verify(ctx, raw)
	v.after()
	return token, err
}

func TestStepUpRejectsSignedTokenSubstitutionAndWeakerAssurance(t *testing.T) {
	for _, mode := range []string{"nonce", "missing nonce", "wrong subject", "different subjects", "different sessions", "different authentication time", "old authentication", "old issuance", "wrong issuer", "wrong audience", "wrong client", "ID token kind", "access token kind", "wrong ACR", "missing role", "viewer role", "missing at hash", "access substitution", "future authentication", "token expiry"} {
		t.Run(mode, func(t *testing.T) {
			f := newStepUpFixture(t)
			_, state := f.begin(t)
			id, access := f.tokenClaims()
			switch mode {
			case "nonce":
				id["nonce"] = strings.Repeat("A", 43)
			case "missing nonce":
				delete(id, "nonce")
			case "wrong subject":
				id["sub"], access["sub"] = "different-subject", "different-subject"
			case "different subjects":
				access["sub"] = "different-subject"
			case "different sessions":
				access["sid"] = "another-new-session"
			case "different authentication time":
				access["auth_time"] = f.at.Add(-time.Second).Unix()
			case "old authentication":
				id["auth_time"], access["auth_time"] = f.at.Add(-time.Second).Unix(), f.at.Add(-time.Second).Unix()
			case "old issuance":
				id["iat"], id["auth_time"], id["exp"] = f.at.Add(-time.Second).Unix(), f.at.Add(-time.Second).Unix(), f.at.Add(119*time.Second).Unix()
			case "wrong issuer":
				id["iss"], access["iss"] = "https://wrong.example.test", "https://wrong.example.test"
			case "wrong audience":
				access["aud"] = "nebulalog"
			case "wrong client":
				id["azp"], access["azp"] = "nebulalog", "nebulalog"
			case "ID token kind":
				id["typ"] = "Bearer"
			case "access token kind":
				access["typ"] = "ID"
			case "wrong ACR":
				id["acr"], access["acr"] = "1", "1"
			case "missing role":
				delete(access, "resource_access")
			case "viewer role":
				access["resource_access"] = map[string]any{"nebulalog": map[string]any{"roles": []string{"VIEWER"}}}
			case "future authentication":
				id["auth_time"], access["auth_time"] = f.at.Add(time.Second).Unix(), f.at.Add(time.Second).Unix()
			case "token expiry":
				access["exp"] = f.at.Unix()
			}
			f.setTokens(id, access)
			if mode == "missing at hash" {
				delete(id, "at_hash")
				f.provider.tokens.IDToken = f.sign(id)
			}
			if mode == "access substitution" {
				access["jti"] = "substituted-access-token"
				f.provider.tokens.AccessToken = f.sign(access)
			}
			if _, err := f.s.Complete(f.ctx, state, "code", f.binding); !errors.Is(err, ErrStepUpIdentity) {
				t.Fatalf("got %v", err)
			}
			if _, err := f.s.Complete(f.ctx, state, "code", f.binding); !errors.Is(err, ErrStepUpTransaction) || f.provider.exchanges != 1 {
				t.Fatal("failed token validation replayed exchange")
			}
		})
	}
}

func TestStepUpBeginCapsExpiryAndRejectsInvalidPAR(t *testing.T) {
	for _, mode := range []string{"original expiry", "plan expiry", "host challenge expiry", "review expiry", "PAR expiry", "empty PAR", "bare PAR prefix", "short PAR suffix", "invalid PAR suffix", "external PAR", "zero PAR lifetime", "negative PAR lifetime", "excessive PAR lifetime", "push timeout", "push clock rollback", "unreviewed", "invalid plan"} {
		t.Run(mode, func(t *testing.T) {
			f := newStepUpFixture(t)
			want := f.at.Add(17 * time.Second)
			valid := true
			switch mode {
			case "original expiry":
				v, _ := CurrentSession(f.ctx)
				v.expiresAt = want
				f.ctx = context.WithValue(f.ctx, sessionKey{}, v)
			case "plan expiry":
				f.binding.ExpiresAt = want
				f.binding.Challenge.ExpiresAt = want.Unix()
			case "host challenge expiry":
				f.binding.Challenge.ExpiresAt = want.Unix()
			case "review expiry":
				f.s.config.Policy.ReviewExpiresAt = want
			case "PAR expiry":
				f.provider.par.Lifetime = 17 * time.Second
			default:
				valid = false
				switch mode {
				case "empty PAR":
					f.provider.par.URI = ""
				case "bare PAR prefix":
					f.provider.par.URI = "urn:ietf:params:oauth:request_uri:"
				case "short PAR suffix":
					f.provider.par.URI = "urn:ietf:params:oauth:request_uri:short"
				case "invalid PAR suffix":
					f.provider.par.URI = "urn:ietf:params:oauth:request_uri:synthetic-request?"
				case "external PAR":
					f.provider.par.URI = "https://attacker.example.test/par"
				case "zero PAR lifetime":
					f.provider.par.Lifetime = 0
				case "negative PAR lifetime":
					f.provider.par.Lifetime = -time.Second
				case "excessive PAR lifetime":
					f.provider.par.Lifetime = 21 * time.Minute
				case "push timeout":
					f.provider.afterPush = func() { f.at = f.at.Add(120 * time.Second) }
				case "push clock rollback":
					f.provider.afterPush = func() { f.at = f.at.Add(-time.Second) }
				case "unreviewed":
					f.s.config.Policy.Reviewed = false
				case "invalid plan":
					f.binding.Operation = "shell.exec"
				}
			}
			start, err := f.s.Begin(f.ctx, f.binding)
			if valid && (err != nil || !start.ExpiresAt.Equal(want)) {
				t.Fatalf("expiry=%v error=%v", start.ExpiresAt, err)
			}
			if !valid && (err == nil || len(f.store.pending) != 0) {
				t.Fatal("invalid begin persisted transaction")
			}
		})
	}
}

func TestStepUpRejectsCorruptConsumedRecordBeforeExchange(t *testing.T) {
	for _, field := range []string{"nonce", "verifier", "state", "actor", "plan", "policy", "created", "lifetime"} {
		t.Run(field, func(t *testing.T) {
			f := newStepUpFixture(t)
			_, state := f.begin(t)
			f.store.alter = func(p *stepUpPending) {
				switch field {
				case "nonce":
					p.Nonce = "malformed"
				case "verifier":
					p.Verifier = "malformed"
				case "state":
					p.StateHash = strings.Repeat("0", 64)
				case "actor":
					p.Actor.Subject = "other-subject"
				case "plan":
					p.Binding.Operation = "backup.create"
				case "policy":
					p.PolicyDigest = strings.Repeat("0", 64)
				case "created":
					p.CreatedAt = f.at.Add(time.Second)
				case "lifetime":
					p.ExpiresAt = f.at.Add(121 * time.Second)
				}
			}
			if _, err := f.s.Complete(f.ctx, state, "code", f.binding); !errors.Is(err, ErrStepUpTransaction) || f.provider.exchanges != 0 {
				t.Fatal("corrupt transaction reached exchange")
			}
		})
	}
}
