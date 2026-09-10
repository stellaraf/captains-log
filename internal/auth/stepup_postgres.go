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
 SELECT state_hash FROM host_stepup_pending
 WHERE expires_at <= statement_timestamp()
 ORDER BY expires_at, state_hash LIMIT $1 FOR UPDATE SKIP LOCKED
)
DELETE FROM host_stepup_pending AS pending USING expired
WHERE pending.state_hash = expired.state_hash`

const stepUpInsertSQL = `INSERT INTO host_stepup_pending (
 state_hash, nonce, pkce_verifier, policy_digest,
 actor_issuer, actor_subject, actor_client_id, actor_session_digest,
 installation_id, operation, plan_id, plan_digest, resource_revision,
 binding_expires_at, created_at, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`

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
	); err != nil {
		return ErrStepUpUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return ErrStepUpUnavailable
	}
	return nil
}

const stepUpConsumeSQL = `DELETE FROM host_stepup_pending
WHERE state_hash = $1
 AND actor_issuer = $2 AND actor_subject = $3 AND actor_client_id = $4 AND actor_session_digest = $5
 AND installation_id = $6 AND operation = $7 AND plan_id = $8 AND plan_digest = $9 AND resource_revision = $10
 AND binding_expires_at = $11 AND policy_digest = $12
 AND created_at <= $13 AND expires_at > $13 AND binding_expires_at > $13
RETURNING state_hash, nonce, pkce_verifier, policy_digest,
 actor_issuer, actor_subject, actor_client_id, actor_session_digest,
 installation_id, operation, plan_id, plan_digest, resource_revision,
 binding_expires_at, created_at, expires_at`

// Consume is a single conditional DELETE RETURNING, so concurrent callbacks on
// different replicas cannot both receive a transaction. A mismatch never erases
// another actor's transaction; all missing/mismatched/expired cases are identical.
func (s *PostgresStepUpStore) Consume(ctx context.Context, stateHash string, actor stepUpActor, binding StepUpBinding, policyDigest string, now time.Time) (stepUpPending, error) {
	if !stepUpPGDigest.MatchString(stateHash) || !stepUpPGDigest.MatchString(policyDigest) ||
		!validPostgresStepUpActor(actor) || !validPostgresStepUpBinding(binding) || !stepUpPGTime(now) {
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
	).Scan(&p.StateHash, &p.Nonce, &p.Verifier, &p.PolicyDigest,
		&p.Actor.Issuer, &p.Actor.Subject, &p.Actor.ClientID, &p.Actor.SessionDigest,
		&p.Binding.InstallationID, &p.Binding.Operation, &p.Binding.PlanID, &p.Binding.PlanDigest, &p.Binding.ResourceRevision,
		&p.Binding.ExpiresAt, &p.CreatedAt, &p.ExpiresAt)
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
	if !validPostgresStepUpPending(p) {
		return stepUpPending{}, ErrStepUpUnavailable
	}
	return p, nil
}

func validPostgresStepUpPending(p stepUpPending) bool {
	return stepUpPGDigest.MatchString(p.StateHash) && stepUpPGNonce.MatchString(p.Nonce) &&
		stepUpPGVerifier.MatchString(p.Verifier) && stepUpPGDigest.MatchString(p.PolicyDigest) &&
		validPostgresStepUpActor(p.Actor) && validPostgresStepUpBinding(p.Binding) &&
		stepUpPGTime(p.CreatedAt) && stepUpPGTime(p.ExpiresAt) &&
		p.ExpiresAt.After(p.CreatedAt) && p.ExpiresAt.Sub(p.CreatedAt) <= 120*time.Second &&
		!p.ExpiresAt.After(p.Binding.ExpiresAt)
}

func validPostgresStepUpActor(a stepUpActor) bool {
	return claimString(a.Issuer, 2048) && claimString(a.Subject, 512) && claimString(a.ClientID, 512) &&
		stepUpPGDigest.MatchString(a.SessionDigest)
}

func validPostgresStepUpBinding(b StepUpBinding) bool {
	return stepUpPGUUID.MatchString(b.InstallationID) && stepUpPGOperation.MatchString(b.Operation) &&
		stepUpPGUUID.MatchString(b.PlanID) && stepUpPGDigest.MatchString(b.PlanDigest) &&
		stepUpPGDigest.MatchString(b.ResourceRevision) && stepUpPGTime(b.ExpiresAt)
}

// PostgreSQL timestamptz has microsecond precision. Refuse silent rounding of an
// exact action binding; the coordinator normalizes times before creating it.
func stepUpPGTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}
