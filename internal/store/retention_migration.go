package store

import (
	"context"
	"errors"
	"regexp"
	"time"
)

const retentionTableSQL = `SELECT toString(uuid) AS uuid,engine,partition_key,create_table_query FROM system.tables WHERE database='nebulalog' AND name='events'`

var retentionTTLToken = regexp.MustCompile(`(?i)\bTTL\b`)

func retentionTable(ctx context.Context, ch emergencyClickHouse) (string, bool, error) {
	rows, err := ch.Rows(ctx, retentionTableSQL, nil)
	if err != nil {
		return "", false, err
	}
	if len(rows) != 1 {
		return "", false, errors.New("Retention table is missing or ambiguous")
	}
	r := rows[0]
	id, err := emergencyString(r, "uuid")
	if err != nil || !emergencyUUID.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" || r["engine"] != "MergeTree" || r["partition_key"] != "(log_type, toDate(ingested_at))" {
		return "", false, errors.New("Retention table identity or partition contract is unsupported")
	}
	ddl, err := emergencyString(r, "create_table_query")
	if err != nil {
		return "", false, err
	}
	return id, retentionTTLToken.MatchString(ddl), nil
}

func verifyRetentionTable(ctx context.Context, ch emergencyClickHouse, expected string) error {
	id, ttl, err := retentionTable(ctx, ch)
	if err != nil {
		return err
	}
	if id != expected || ttl {
		return errors.New("Retention table changed or legacy TTL is still active; policy changes are held")
	}
	return nil
}

func retentionBackground(ctx context.Context, ch emergencyClickHouse) (uint64, uint64, error) {
	rows, err := ch.Rows(ctx, `SELECT (SELECT count() FROM system.merges WHERE database='nebulalog' AND table='events') AS merges,(SELECT count() FROM system.mutations WHERE database='nebulalog' AND table='events' AND NOT is_done) AS mutations`, nil)
	if err != nil {
		return 0, 0, err
	}
	if len(rows) != 1 {
		return 0, 0, errors.New("Retention background-work evidence unavailable")
	}
	m, err := emergencyUint(rows[0], "merges")
	if err != nil {
		return 0, 0, err
	}
	u, err := emergencyUint(rows[0], "mutations")
	return m, u, err
}

// Each stage is durable before its DDL dispatch. An interrupted/ambiguous
// transition is never automatically resumed. In particular, a stopped merge
// scheduler is not proof that a merge already running has finished.
func removeLegacyRetentionTTL(ctx context.Context, ch emergencyClickHouse, expected string, stage func(string, string) error) error {
	id, ttl, err := retentionTable(ctx, ch)
	if err != nil {
		return err
	}
	if id != expected {
		return errors.New("Retention migration table changed")
	}
	_, mutations, err := retentionBackground(ctx, ch)
	if err != nil {
		return err
	}
	if mutations != 0 {
		return errors.New("Unfinished mutations prevent retention migration")
	}
	queryID := emergencyID()
	if err = stage("stop-merges-dispatch", queryID); err != nil {
		return err
	}
	if err = ch.ExecWithQueryID(ctx, "SYSTEM STOP MERGES nebulalog.events", nil, queryID); err != nil {
		return err
	}
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		merges, mutations, e := retentionBackground(ctx, ch)
		if e != nil {
			return e
		}
		if mutations != 0 {
			return errors.New("A mutation appeared during retention migration")
		}
		if merges == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("Legacy merge drain exceeded 60 seconds; migration remains held")
		case <-tick.C:
		}
	}
	id, ttlNow, err := retentionTable(ctx, ch)
	if err != nil {
		return err
	}
	if id != expected || ttlNow != ttl {
		return errors.New("Table changed while draining legacy TTL")
	}
	if ttl {
		queryID := emergencyID()
		if err = stage("remove-ttl-dispatch", queryID); err != nil {
			return err
		}
		if err = ch.ExecWithQueryID(ctx, "ALTER TABLE nebulalog.events REMOVE TTL", nil, queryID); err != nil {
			return err
		}
	}
	if err = verifyRetentionTable(ctx, ch, expected); err != nil {
		return err
	}
	merges, mutations, err := retentionBackground(ctx, ch)
	if err != nil {
		return err
	}
	if merges != 0 || mutations != 0 {
		return errors.New("Background work appeared before TTL transition completed")
	}
	queryID = emergencyID()
	if err = stage("start-merges-dispatch", queryID); err != nil {
		return err
	}
	if err = ch.ExecWithQueryID(ctx, "SYSTEM START MERGES nebulalog.events", nil, queryID); err != nil {
		return err
	}
	return verifyRetentionTable(ctx, ch, expected)
}

// InitializeRetention only adopts a newly empty, TTL-free table. CREATE IF NOT
// EXISTS cannot migrate an existing TTL table, and must never pretend it did.
func (s *Store) InitializeRetention(ctx context.Context) error {
	conn, release, err := emergencyConnection(ctx, s.PG)
	if err != nil {
		return err
	}
	defer release()
	engine, err := readRetentionEngine(ctx, conn)
	if err != nil {
		return err
	}
	if engine.Mode == "partition" {
		return verifyRetentionTable(ctx, s.CH, engine.TableUUID)
	}
	if engine.Mode != "uninitialized" {
		return ErrRetentionHeld
	}
	id, ttl, err := retentionTable(ctx, s.CH)
	if err != nil {
		return err
	}
	if ttl {
		return errors.New("Legacy TTL requires the explicit held migrate-retention transition")
	}
	rows, err := s.CH.Rows(ctx, "SELECT count() AS parts FROM system.parts WHERE database='nebulalog' AND table='events'", nil)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return errors.New("Fresh retention table evidence unavailable")
	}
	parts, err := emergencyUint(rows[0], "parts")
	if err != nil {
		return err
	}
	if parts != 0 {
		return errors.New("Nonempty unbound retention table requires explicit migration")
	}
	_, err = conn.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='retention_engine'", emergencyJSON(RetentionEngine{Schema: 1, Mode: "partition", TableUUID: id, Message: "Fresh TTL-free partition retention initialized"}))
	return err
}

// MigrateRetention is a separate operator/host-maintenance command. A running
// API never removes TTL in response to a policy save. Existing maintenance
// ownership, quiesced insertion evidence and table identity are mandatory.
func (s *Store) CheckRetentionMigrationHold(ctx context.Context) error {
	gate, err := s.effectiveEmergencyMaintenance(ctx, s.PG)
	if err != nil {
		return err
	}
	if !gate.Held || !gate.DeliveryHeld || gate.Operation == nil {
		return errors.New("Retention migration requires an operation-owned host/database maintenance and delivery hold")
	}
	return nil
}

func (s *Store) MigrateRetention(ctx context.Context) error {
	conn, release, err := emergencyConnection(ctx, s.PG)
	if err != nil {
		return err
	}
	defer release()
	gate, err := s.effectiveEmergencyMaintenance(ctx, conn)
	if err != nil {
		return err
	}
	if !gate.Held || !gate.DeliveryHeld || gate.Operation == nil {
		return errors.New("Retention migration requires an operation-owned host/database maintenance and delivery hold")
	}
	engine, err := readRetentionEngine(ctx, conn)
	if err != nil {
		return err
	}
	if engine.Mode == "partition" {
		return verifyRetentionTable(ctx, s.CH, engine.TableUUID)
	}
	if engine.Mode != "uninitialized" {
		return errors.New("An interrupted retention migration requires operator recovery; no DDL is replayed")
	}
	var busy bool
	if err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM storage_emergency_actions WHERE completed_at IS NULL) OR EXISTS(SELECT 1 FROM retention_actions WHERE completed_at IS NULL) OR EXISTS(SELECT 1 FROM storage_emergency_inserts)`).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return ErrRetentionHeld
	}
	id, _, err := retentionTable(ctx, s.CH)
	if err != nil {
		return err
	}
	if _, err = readRetention(ctx, conn); err != nil {
		return err
	}
	engine = RetentionEngine{Schema: 1, Mode: "migrating", TableUUID: id, Operation: *gate.Operation}
	stage := func(message, queryID string) error {
		current, e := s.effectiveEmergencyMaintenance(ctx, conn)
		if e != nil {
			return e
		}
		if !current.Held || !current.DeliveryHeld || current.Operation == nil || *current.Operation != engine.Operation {
			return ErrRetentionHeld
		}
		engine.Message = message
		engine.QueryID = queryID
		tx, e := conn.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='retention_engine'", emergencyJSON(engine)); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO audit_events(actor,action,target,detail) VALUES('retention-migration','retention.migration','nebulalog.events',$1)", emergencyJSON(engine)); e != nil {
			return e
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
		return conn.Ping(ctx)
	}
	if err = removeLegacyRetentionTTL(ctx, s.CH, id, stage); err != nil {
		return err
	}
	engine.Mode = "partition"
	return stage("Legacy TTL removed and read back after merge drain; existing-data policy is active", "")
}
