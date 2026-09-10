package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func postgresStepUpFixture() stepUpPending {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return stepUpPending{
		StateHash: strings.Repeat("1", 64), Nonce: strings.Repeat("n", 43), Verifier: strings.Repeat("v", 43), PolicyDigest: strings.Repeat("2", 64),
		Actor:     stepUpActor{Issuer: "https://issuer.example/realms/nebulalog", Subject: "synthetic-subject", ClientID: "nebulalog", SessionDigest: strings.Repeat("3", 64)},
		Binding:   StepUpBinding{InstallationID: "11111111-2222-3333-4444-555555555555", Operation: "storage.grow", PlanID: "66666666-7777-8888-9999-aaaaaaaaaaaa", PlanDigest: strings.Repeat("4", 64), ResourceRevision: strings.Repeat("5", 64), ExpiresAt: now.Add(2 * time.Minute)},
		CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
}

func TestPostgresStepUpRefusesInvalidPendingBeforeDatabaseAccess(t *testing.T) {
	mutations := map[string]func(*stepUpPending){
		"raw state":        func(p *stepUpPending) { p.StateHash = strings.Repeat("s", 43) },
		"uppercase digest": func(p *stepUpPending) { p.PolicyDigest = strings.Repeat("A", 64) },
		"short nonce":      func(p *stepUpPending) { p.Nonce = "short" },
		"invalid verifier": func(p *stepUpPending) { p.Verifier = strings.Repeat("!", 43) },
		"empty actor":      func(p *stepUpPending) { p.Actor.Subject = "" },
		"control actor":    func(p *stepUpPending) { p.Actor.ClientID = "client\n" },
		"oversize issuer":  func(p *stepUpPending) { p.Actor.Issuer = strings.Repeat("i", 2049) },
		"raw session":      func(p *stepUpPending) { p.Actor.SessionDigest = "raw-session-id" },
		"installation":     func(p *stepUpPending) { p.Binding.InstallationID = "../installation" },
		"operation":        func(p *stepUpPending) { p.Binding.Operation = "storage.grow\n" },
		"plan ID":          func(p *stepUpPending) { p.Binding.PlanID = "plan" },
		"plan digest":      func(p *stepUpPending) { p.Binding.PlanDigest = "plan" },
		"revision":         func(p *stepUpPending) { p.Binding.ResourceRevision = "revision" },
		"missing creation": func(p *stepUpPending) { p.CreatedAt = time.Time{} },
		"empty lifetime":   func(p *stepUpPending) { p.ExpiresAt = p.CreatedAt },
		"long lifetime": func(p *stepUpPending) {
			p.ExpiresAt = p.CreatedAt.Add(121 * time.Second)
			p.Binding.ExpiresAt = p.ExpiresAt
		},
		"expired binding":    func(p *stepUpPending) { p.Binding.ExpiresAt = p.ExpiresAt.Add(-time.Microsecond) },
		"creation precision": func(p *stepUpPending) { p.CreatedAt = p.CreatedAt.Add(time.Nanosecond) },
		"expiry precision":   func(p *stepUpPending) { p.ExpiresAt = p.ExpiresAt.Add(-time.Nanosecond) },
		"binding precision":  func(p *stepUpPending) { p.Binding.ExpiresAt = p.Binding.ExpiresAt.Add(time.Nanosecond) },
	}
	store := NewPostgresStepUpStore(nil)
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := postgresStepUpFixture()
			mutate(&p)
			if err := store.Insert(context.Background(), p); !errors.Is(err, ErrStepUpTransaction) {
				t.Fatal("invalid transaction reached database")
			}
		})
	}
}

func TestPostgresStepUpUnavailableAndRedaction(t *testing.T) {
	p := postgresStepUpFixture()
	for _, store := range []*PostgresStepUpStore{nil, NewPostgresStepUpStore(nil)} {
		if err := store.Insert(context.Background(), p); !errors.Is(err, ErrStepUpUnavailable) {
			t.Fatal("missing PostgreSQL did not fail closed")
		}
		got, err := store.Consume(context.Background(), p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if !errors.Is(err, ErrStepUpUnavailable) || got != (stepUpPending{}) {
			t.Fatal("missing PostgreSQL returned evidence")
		}
		got, err = store.Consume(context.Background(), "raw-state", p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
			t.Fatal("raw OAuth state accepted")
		}
		if fmt.Sprintf("%v", store) != "PostgresStepUpStore[redacted]" || fmt.Sprintf("%#v", store) != "PostgresStepUpStore[redacted]" {
			t.Fatal("store formatting is not redacted")
		}
	}
	if _, err := json.Marshal(NewPostgresStepUpStore(nil)); err == nil {
		t.Fatal("store serialized")
	}
}

// Explicit opt-in uses only a randomly named schema in the existing loopback
// development database. It never migrates public, starts a service, or prints
// connection strings/credentials, query arguments, or transaction evidence.
func postgresStepUpTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("NEBULALOG_STEPUP_POSTGRES_TEST") != "1" {
		t.Skip("opt-in isolated local PostgreSQL integration")
	}
	b, err := os.ReadFile(filepath.Join("..", "..", ".local", "dev.env"))
	if err != nil {
		t.Fatal("local PostgreSQL configuration unavailable")
	}
	var password string
	for _, line := range strings.Split(string(b), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok && key == "PG_PASSWORD" {
			password = value
		}
	}
	if password == "" {
		t.Fatal("local PostgreSQL credential unavailable")
	}
	config, err := pgxpool.ParseConfig("postgres://127.0.0.1:25432/nebulalog?sslmode=disable")
	if err != nil {
		t.Fatal("local PostgreSQL configuration invalid")
	}
	config.ConnConfig.User, config.ConnConfig.Password = "nebulalog", password
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	config.MaxConns = 12
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("local PostgreSQL connection unavailable")
	}
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		admin.Close()
		t.Fatal("test schema entropy unavailable")
	}
	schema := "stepup_test_" + hex.EncodeToString(suffix[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal("isolated test schema could not be created")
	}
	t.Cleanup(func() {
		defer admin.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("isolated test schema cleanup failed")
			return
		}
		var remains bool
		if err := admin.QueryRow(cleanupCtx, "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)", schema).Scan(&remains); err != nil || remains {
			t.Error("isolated test schema removal could not be verified")
		}
	})
	isolated := config.Copy()
	isolated.ConnConfig.RuntimeParams["search_path"] = quoted
	pool, err := pgxpool.NewWithConfig(ctx, isolated)
	if err != nil {
		t.Fatal("isolated test connection unavailable")
	}
	t.Cleanup(pool.Close)
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "host_stepup.sql"))
	if err != nil {
		t.Fatal("step-up migration unavailable")
	}
	for range 2 {
		if _, err := pool.Exec(ctx, string(migration)); err != nil {
			t.Fatal("step-up migration failed in isolated schema")
		}
	}
	return pool
}

func insertPostgresStepUpFixture(t *testing.T, pool *pgxpool.Pool, p stepUpPending) {
	t.Helper()
	if err := NewPostgresStepUpStore(pool).Insert(context.Background(), p); err != nil {
		t.Fatal("synthetic transaction insert failed")
	}
}

func TestPostgresStepUpAtomicIntegration(t *testing.T) {
	pool := postgresStepUpTestPool(t)
	store := NewPostgresStepUpStore(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clear := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(ctx, "TRUNCATE host_stepup_pending"); err != nil {
			t.Fatal("isolated table cleanup failed")
		}
	}

	t.Run("all bindings refuse without consuming", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		mutations := map[string]func(*stepUpPending){
			"state":          func(p *stepUpPending) { p.StateHash = strings.Repeat("a", 64) },
			"issuer":         func(p *stepUpPending) { p.Actor.Issuer += "/other" },
			"subject":        func(p *stepUpPending) { p.Actor.Subject += "-other" },
			"client":         func(p *stepUpPending) { p.Actor.ClientID += "-other" },
			"session":        func(p *stepUpPending) { p.Actor.SessionDigest = strings.Repeat("a", 64) },
			"installation":   func(p *stepUpPending) { p.Binding.InstallationID = "aaaaaaaa-2222-3333-4444-555555555555" },
			"operation":      func(p *stepUpPending) { p.Binding.Operation = "storage.add_disk" },
			"plan":           func(p *stepUpPending) { p.Binding.PlanID = "aaaaaaaa-7777-8888-9999-aaaaaaaaaaaa" },
			"plan digest":    func(p *stepUpPending) { p.Binding.PlanDigest = strings.Repeat("a", 64) },
			"revision":       func(p *stepUpPending) { p.Binding.ResourceRevision = strings.Repeat("a", 64) },
			"binding expiry": func(p *stepUpPending) { p.Binding.ExpiresAt = p.Binding.ExpiresAt.Add(time.Microsecond) },
			"policy":         func(p *stepUpPending) { p.PolicyDigest = strings.Repeat("a", 64) },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				other := p
				mutate(&other)
				got, err := store.Consume(ctx, other.StateHash, other.Actor, other.Binding, other.PolicyDigest, p.CreatedAt)
				if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
					t.Fatal("mismatched binding returned evidence")
				}
			})
		}
		got, err := store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if err != nil || got != p {
			t.Fatal("matching transaction did not survive mismatches or failed exact round trip")
		}
		got, err = store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
			t.Fatal("replay returned evidence")
		}
	})

	t.Run("duplicate state does not replace transaction", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		other := p
		other.Nonce = strings.Repeat("o", 43)
		if err := store.Insert(ctx, other); !errors.Is(err, ErrStepUpUnavailable) {
			t.Fatal("duplicate state replaced pending evidence or exposed database details")
		}
		got, err := store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if err != nil || got != p {
			t.Fatal("duplicate state damaged the original transaction")
		}
	})

	t.Run("creation and expiry boundaries", func(t *testing.T) {
		for _, delta := range []time.Duration{-time.Microsecond, 0, 120*time.Second - time.Microsecond, 120 * time.Second} {
			clear(t)
			p := postgresStepUpFixture()
			insertPostgresStepUpFixture(t, pool, p)
			_, err := store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt.Add(delta))
			if delta < 0 || delta >= 120*time.Second {
				if !errors.Is(err, ErrStepUpTransaction) {
					t.Fatal("time boundary did not refuse transaction")
				}
			} else if err != nil {
				t.Fatal("valid exclusive-expiry boundary refused")
			}
		}
	})

	t.Run("concurrent replicas consume exactly once", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		var successes, failures atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 24 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				got, err := NewPostgresStepUpStore(pool).Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
				if err == nil && got.Nonce == p.Nonce && got.Verifier == p.Verifier {
					successes.Add(1)
				} else if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
					failures.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if successes.Load() != 1 || failures.Load() != 0 {
			t.Fatal("concurrent callbacks violated single consumption")
		}
	})

	t.Run("database constraints reject malformed rows", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		for _, assignment := range []string{
			"state_hash = 'raw-state'", "nonce = 'short'", "pkce_verifier = 'short'", "policy_digest = 'bad'",
			"actor_subject = ''", "actor_issuer = ''", "actor_client_id = ''", "actor_session_digest = 'raw-session'",
			"installation_id = 'bad'", "operation = '../run'", "plan_id = 'bad'", "plan_digest = 'bad'", "resource_revision = 'bad'",
			"expires_at = created_at", "expires_at = created_at + interval '121 seconds'", "binding_expires_at = created_at",
			"created_at = '-infinity'", "expires_at = 'infinity'", "binding_expires_at = 'infinity'",
		} {
			_, err := pool.Exec(ctx, "UPDATE host_stepup_pending SET "+assignment)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Fatal("database accepted malformed transaction")
			}
		}
	})

	t.Run("bounded retention preserves pending rows", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		_, err := pool.Exec(ctx, `INSERT INTO host_stepup_pending
 SELECT lpad(to_hex(n),64,'0'), nonce, pkce_verifier, policy_digest,
 actor_issuer, actor_subject, actor_client_id, actor_session_digest,
 installation_id, operation, plan_id, plan_digest, resource_revision,
 binding_expires_at - interval '5 minutes', created_at - interval '5 minutes', expires_at - interval '5 minutes'
 FROM host_stepup_pending CROSS JOIN generate_series(1,$1) AS n`, stepUpRetentionBatch+9)
		if err != nil {
			t.Fatal("expired synthetic transaction seed failed")
		}
		p.StateHash = strings.Repeat("e", 64)
		insertPostgresStepUpFixture(t, pool, p)
		var expired, live int
		if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE expires_at <= statement_timestamp()), count(*) FILTER (WHERE expires_at > statement_timestamp()) FROM host_stepup_pending`).Scan(&expired, &live); err != nil || expired != 9 || live != 2 {
			t.Fatal("retention exceeded batch bound or erased pending transaction")
		}
	})

	t.Run("database failure returns no evidence", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		pool.Close()
		got, err := store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if !errors.Is(err, ErrStepUpUnavailable) || got != (stepUpPending{}) {
			t.Fatal("database failure exposed evidence or a database error")
		}
		if err := store.Insert(ctx, p); !errors.Is(err, ErrStepUpUnavailable) {
			t.Fatal("database insert failure exposed a database error")
		}
	})
}
