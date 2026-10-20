package auth

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const stepUpRetentionBatch = 128

var (
	stepUpPGDigest    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	stepUpPGUUID      = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	stepUpPGNonce     = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)
	stepUpPGVerifier  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	stepUpPGOperation = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)
)

// PostgresStepUpStore holds short-lived OAuth transaction secrets in PostgreSQL.
// The caller supplies an already configured pool with parameter tracing disabled.
// Migrations are explicit; neither construction nor failure creates a fallback.
// Store methods use private evidence types and cannot mint host authorization.
type PostgresStepUpStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStepUpStore(pool *pgxpool.Pool) *PostgresStepUpStore {
	return &PostgresStepUpStore{pool: pool}
}

func (s *PostgresStepUpStore) String() string   { return "PostgresStepUpStore[redacted]" }
func (s *PostgresStepUpStore) GoString() string { return s.String() }
func (s *PostgresStepUpStore) MarshalJSON() ([]byte, error) {
	return nil, errors.New("step-up store must not be serialized")
}

const stepUpCleanupSQL = `WITH expired AS (
 SELECT state_hash FROM host_stepup_pending_v2
 WHERE expires_at <= statement_timestamp()
 ORDER BY expires_at, state_hash LIMIT $1 FOR UPDATE SKIP LOCKED
)
DELETE FROM host_stepup_pending_v2 AS pending USING expired
WHERE pending.state_hash = expired.state_hash`

// Version 2 never reads or promotes the legacy table: those rows have no host
// challenge authority. The explicit migration retains them as inert evidence.
const stepUpInsertSQL = `INSERT INTO host_stepup_pending_v2 (
 record_schema,
 state_hash, nonce, pkce_verifier, policy_digest,
 actor_issuer, actor_subject, actor_client_id, actor_session_digest,
 installation_id, operation, plan_id, plan_digest, resource_revision,
 binding_expires_at, created_at, expires_at,
 challenge_schema, challenge_id, challenge_subject_digest, challenge_operation_schema,
 challenge_action, challenge_request_digest, challenge_policy_generation, challenge_issued_at, challenge_expires_at
) VALUES (2,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`

// Cleanup is bounded on each successful insert and skips rows being consumed by
// other replicas. No raw OAuth state or bearer/session token reaches this query.
func (s *PostgresStepUpStore) Insert(ctx context.Context, p stepUpPending) error {
	if !validPostgresStepUpPending(p) {
		return ErrStepUpTransaction
	}
	if s == nil || s.pool == nil {
		return ErrStepUpUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrStepUpUnavailable
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, stepUpCleanupSQL, stepUpRetentionBatch); err != nil {
		return ErrStepUpUnavailable
	}
	if _, err = tx.Exec(ctx, stepUpInsertSQL,
		p.StateHash, p.Nonce, p.Verifier, p.PolicyDigest,
		p.Actor.Issuer, p.Actor.Subject, p.Actor.ClientID, p.Actor.SessionDigest,
		p.Binding.InstallationID, p.Binding.Operation, p.Binding.PlanID, p.Binding.PlanDigest, p.Binding.ResourceRevision,
		p.Binding.ExpiresAt, p.CreatedAt, p.ExpiresAt,
		p.Binding.Challenge.Schema, p.Binding.Challenge.ID, p.Binding.Challenge.SubjectDigest, p.Binding.Challenge.OperationSchema,
		p.Binding.Challenge.Action, p.Binding.Challenge.RequestDigest, p.Binding.Challenge.PolicyGeneration,
		p.Binding.Challenge.IssuedAt, p.Binding.Challenge.ExpiresAt,
	); err != nil {
		return ErrStepUpUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return ErrStepUpUnavailable
	}
	return nil
}

const stepUpConsumeSQL = `DELETE FROM host_stepup_pending_v2
WHERE record_schema = 2 AND state_hash = $1
 AND actor_issuer = $2 AND actor_subject = $3 AND actor_client_id = $4 AND actor_session_digest = $5
 AND installation_id = $6 AND operation = $7 AND plan_id = $8 AND plan_digest = $9 AND resource_revision = $10
 AND binding_expires_at = $11 AND policy_digest = $12
 AND created_at <= $13 AND expires_at > $13 AND binding_expires_at > $13
 AND challenge_schema = $14 AND challenge_id = $15 AND nonce = $16 AND challenge_subject_digest = $17
 AND challenge_operation_schema = $18 AND challenge_action = $19 AND challenge_request_digest = $20
 AND challenge_policy_generation = $21 AND challenge_issued_at = $22 AND challenge_expires_at = $23
RETURNING state_hash, nonce, pkce_verifier, policy_digest,
 actor_issuer, actor_subject, actor_client_id, actor_session_digest,
 installation_id, operation, plan_id, plan_digest, resource_revision,
 binding_expires_at, created_at, expires_at,
 challenge_schema, challenge_id, challenge_subject_digest, challenge_operation_schema,
 challenge_action, challenge_request_digest, challenge_policy_generation, challenge_issued_at, challenge_expires_at`

// Consume is a single conditional DELETE RETURNING, so concurrent callbacks on
// different replicas cannot both receive a transaction. A mismatch never erases
// another actor's transaction; all missing/mismatched/expired cases are identical.
func (s *PostgresStepUpStore) Consume(ctx context.Context, stateHash string, actor stepUpActor, binding StepUpBinding, policyDigest string, now time.Time) (stepUpPending, error) {
	if !stepUpPGDigest.MatchString(stateHash) || !stepUpPGDigest.MatchString(policyDigest) ||
		!validPostgresStepUpActor(actor) || !validPostgresStepUpBinding(binding) || !stepUpPGTime(now) ||
		!binding.valid(now) || !binding.matchesActor(actor) {
		return stepUpPending{}, ErrStepUpTransaction
	}
	if s == nil || s.pool == nil {
		return stepUpPending{}, ErrStepUpUnavailable
	}
	var p stepUpPending
	err := s.pool.QueryRow(ctx, stepUpConsumeSQL,
		stateHash, actor.Issuer, actor.Subject, actor.ClientID, actor.SessionDigest,
		binding.InstallationID, binding.Operation, binding.PlanID, binding.PlanDigest, binding.ResourceRevision,
		binding.ExpiresAt, policyDigest, now,
		binding.Challenge.Schema, binding.Challenge.ID, binding.Challenge.Nonce, binding.Challenge.SubjectDigest,
		binding.Challenge.OperationSchema, binding.Challenge.Action, binding.Challenge.RequestDigest,
		binding.Challenge.PolicyGeneration, binding.Challenge.IssuedAt, binding.Challenge.ExpiresAt,
	).Scan(&p.StateHash, &p.Nonce, &p.Verifier, &p.PolicyDigest,
		&p.Actor.Issuer, &p.Actor.Subject, &p.Actor.ClientID, &p.Actor.SessionDigest,
		&p.Binding.InstallationID, &p.Binding.Operation, &p.Binding.PlanID, &p.Binding.PlanDigest, &p.Binding.ResourceRevision,
		&p.Binding.ExpiresAt, &p.CreatedAt, &p.ExpiresAt,
		&p.Binding.Challenge.Schema, &p.Binding.Challenge.ID, &p.Binding.Challenge.SubjectDigest, &p.Binding.Challenge.OperationSchema,
		&p.Binding.Challenge.Action, &p.Binding.Challenge.RequestDigest, &p.Binding.Challenge.PolicyGeneration,
		&p.Binding.Challenge.IssuedAt, &p.Binding.Challenge.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return stepUpPending{}, ErrStepUpTransaction
	}
	if err != nil {
		return stepUpPending{}, ErrStepUpUnavailable
	}
	// pgx may decode timestamptz using time.Local. The coordinator performs a
	// structural comparison of its normalized binding, so preserve UTC here.
	p.Binding.ExpiresAt = p.Binding.ExpiresAt.UTC()
	p.CreatedAt = p.CreatedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	// Fields shared with the plan/original-actor columns are validated equal on
	// insertion and in every consume predicate; reconstruct without defaults.
	p.Binding.Challenge.Nonce = p.Nonce
	p.Binding.Challenge.InstallationID = p.Binding.InstallationID
	p.Binding.Challenge.SessionDigest = p.Actor.SessionDigest
	p.Binding.Challenge.Operation = p.Binding.Operation
	p.Binding.Challenge.PlanID = p.Binding.PlanID
	p.Binding.Challenge.PlanDigest = p.Binding.PlanDigest
	p.Binding.Challenge.ResourceRevision = p.Binding.ResourceRevision
	if !validPostgresStepUpPending(p) {
		return stepUpPending{}, ErrStepUpUnavailable
	}
	return p, nil
}

func validPostgresStepUpPending(p stepUpPending) bool {
	return stepUpPGDigest.MatchString(p.StateHash) && stepUpPGNonce.MatchString(p.Nonce) &&
		stepUpPGVerifier.MatchString(p.Verifier) && stepUpPGDigest.MatchString(p.PolicyDigest) &&
		validPostgresStepUpActor(p.Actor) && validPostgresStepUpBinding(p.Binding) &&
		p.Binding.valid(p.CreatedAt) && p.Binding.matchesActor(p.Actor) && p.Nonce == p.Binding.Challenge.Nonce &&
		stepUpPGTime(p.CreatedAt) && stepUpPGTime(p.ExpiresAt) &&
		p.ExpiresAt.After(p.CreatedAt) && p.ExpiresAt.Sub(p.CreatedAt) <= 120*time.Second &&
		!p.ExpiresAt.After(p.Binding.ExpiresAt) && !p.ExpiresAt.After(time.Unix(p.Binding.Challenge.ExpiresAt, 0))
}

func validPostgresStepUpActor(a stepUpActor) bool {
	return claimString(a.Issuer, 2048) && claimString(a.Subject, 512) && claimString(a.ClientID, 512) &&
		stepUpPGDigest.MatchString(a.SessionDigest)
}

func validPostgresStepUpBinding(b StepUpBinding) bool {
	return stepUpPGUUID.MatchString(b.InstallationID) && stepUpPGOperation.MatchString(b.Operation) &&
		stepUpPGUUID.MatchString(b.PlanID) && stepUpPGDigest.MatchString(b.PlanDigest) &&
		stepUpPGDigest.MatchString(b.ResourceRevision) && stepUpPGTime(b.ExpiresAt) &&
		b.valid(time.Unix(b.Challenge.IssuedAt, 0))
}

// PostgreSQL timestamptz has microsecond precision. Refuse silent rounding of an
// exact action binding; the coordinator normalizes times before creating it.
func stepUpPGTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}
