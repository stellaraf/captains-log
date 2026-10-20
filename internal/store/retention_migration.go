package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// This is the captured application-image input, not an operator-supplied SQL
// program. A schema change requires an explicit source/host contract change.
const StorageInitializationSchemaSHA256 = "f3a6610f55eee8469769f9c9def9a99c76ff64ed8f76fcf3a9b0196091a3628d"
const StorageInitializationSchemaPath = "/app/migrations/clickhouse.sql"

type StorageInitialization struct {
	Operation    string
	TableUUID    string
	SchemaSHA256 string
}

func (r StorageInitialization) Validate() error {
	if !emergencyOperation.MatchString(r.Operation) || !emergencyUUID.MatchString(r.TableUUID) || r.TableUUID == "00000000-0000-0000-0000-000000000000" || r.SchemaSHA256 != StorageInitializationSchemaSHA256 {
		return errors.New("Storage initialization requires the captured schema and journal-owned operation/table identity")
	}
	return nil
}

type StorageInitializationReceipt struct {
	Schema                int    `json:"schema"`
	Operation             string `json:"operation"`
	TableUUID             string `json:"table_uuid"`
	SchemaSQLSHA256       string `json:"schema_sql_sha256"`
	DDLSHA256             string `json:"ddl_sha256"`
	RetentionPolicySHA256 string `json:"retention_policy_sha256"`
	DatabaseQueryID       string `json:"database_query_id"`
	TableQueryID          string `json:"table_query_id"`
	State                 string `json:"state"`
}

type storageInitializationPG interface {
	emergencyQuerier
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

const initializationDatabaseSQL = "SELECT engine FROM system.databases WHERE name='nebulalog'"
const initializationTablesSQL = "SELECT name,toString(uuid) AS uuid,engine,partition_key,create_table_query FROM system.tables WHERE database='nebulalog' SETTINGS show_table_uuid_in_table_create_query_if_not_nil=0"
const initializationFormatSQL = "SELECT formatQuerySingleLine({expected:String}) AS expected,formatQuerySingleLine({actual:String}) AS actual"
const initializationEmptySQL = "SELECT (SELECT count() FROM system.parts WHERE database='nebulalog' AND table='events') AS parts,(SELECT count() FROM system.detached_parts WHERE database='nebulalog' AND table='events') AS detached"
const initializationQueriesSQL = "SELECT count() AS running FROM system.processes WHERE query_id IN ({database_query:String},{table_query:String}) OR initial_query_id IN ({database_query:String},{table_query:String})"
const initializationDetachedSQL = "SELECT count() AS detached FROM system.detached_tables WHERE database='nebulalog'"
const initializationPendingSQL = "SELECT EXISTS(SELECT 1 FROM storage_emergency_actions WHERE completed_at IS NULL) OR EXISTS(SELECT 1 FROM retention_actions WHERE completed_at IS NULL) OR EXISTS(SELECT 1 FROM storage_emergency_inserts)"

func storageInitializationQueryID(operation, phase string) string {
	digest := sha256.Sum256([]byte("captains-log/storage-init/" + operation + "/" + phase))
	digest[6] = (digest[6] & 15) | 0x50
	digest[8] = (digest[8] & 63) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func storageSchemaStatements(raw []byte) (string, string, error) {
	digest := sha256.Sum256(raw)
	if len(raw) > 16384 || hex.EncodeToString(digest[:]) != StorageInitializationSchemaSHA256 {
		return "", "", errors.New("Captured ClickHouse schema bytes changed")
	}
	statements := strings.Split(string(raw), ";")
	if len(statements) != 3 || strings.TrimSpace(statements[0]) != "CREATE DATABASE IF NOT EXISTS nebulalog" || strings.TrimSpace(statements[2]) != "" || !strings.HasPrefix(strings.TrimSpace(statements[1]), "CREATE TABLE IF NOT EXISTS nebulalog.events\n") {
		return "", "", errors.New("Unsupported captured storage schema")
	}
	return "CREATE DATABASE nebulalog", strings.Replace(strings.TrimSpace(statements[1]), "CREATE TABLE IF NOT EXISTS", "CREATE TABLE", 1), nil
}

// InitializeStorage is a host-coordinated one-shot role. The host first records
// the exact factory/image/server binding, absence observation and selected UUID
// in its protected journal, then owns both maintenance gates. This command never
// adopts another UUID, executes PostgreSQL DDL or changes restored policy. A
// failed/unknown CH acknowledgement returns immediately; only an explicit host
// reconciliation may invoke it again with the same durable identity.
func (s *Store) InitializeStorage(ctx context.Context, request StorageInitialization, schema []byte) (StorageInitializationReceipt, error) {
	var none StorageInitializationReceipt
	if err := request.Validate(); err != nil {
		return none, err
	}
	if err := ValidateStorageMaintenancePath(s.StorageMaintenancePath, true); err != nil {
		return none, err
	}
	conn, release, err := emergencyConnection(ctx, s.PG)
	if err != nil {
		return none, err
	}
	defer release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return none, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	// Construct a new client: never copy its mutex or change the regular client.
	ch := s.CH.storageInitializationClient()
	receipt, err := initializeStorage(ctx, tx, ch, s.readHostMaintenance, request, schema)
	if err != nil {
		return none, err
	}
	if err = tx.Commit(ctx); err != nil {
		return none, err
	}
	return receipt, nil
}

func initializeStorage(ctx context.Context, pg storageInitializationPG, ch emergencyClickHouse, host func() (emergencyMaintenance, error), request StorageInitialization, schema []byte) (StorageInitializationReceipt, error) {
	var none StorageInitializationReceipt
	if err := request.Validate(); err != nil {
		return none, err
	}
	databaseDDL, tableDDL, err := storageSchemaStatements(schema)
	if err != nil {
		return none, err
	}
	gate := func() error {
		h, err := host()
		if err != nil {
			return err
		}
		d, err := readEmergencyMaintenance(ctx, pg)
		if err != nil {
			return err
		}
		for _, g := range []emergencyMaintenance{h, d} {
			if g.Schema != 1 || !g.Held || !g.DeliveryHeld || g.Operation == nil || *g.Operation != request.Operation {
				return errors.New("Storage initialization requires both exact operation-owned delivery holds")
			}
		}
		var busy bool
		if err := pg.QueryRow(ctx, initializationPendingSQL).Scan(&busy); err != nil {
			return err
		}
		if busy {
			return ErrRetentionHeld
		}
		return nil
	}
	if err = gate(); err != nil {
		return none, err
	}
	var policy, oldEngine []byte
	if err = pg.QueryRow(ctx, "SELECT value FROM settings WHERE key='retention' FOR UPDATE").Scan(&policy); err != nil {
		return none, err
	}
	if _, err = decodeRetention(policy); err != nil {
		return none, err
	}
	if err = pg.QueryRow(ctx, "SELECT value FROM settings WHERE key='retention_engine' FOR UPDATE").Scan(&oldEngine); err != nil {
		return none, err
	}
	var engine RetentionEngine
	if json.Unmarshal(oldEngine, &engine) != nil || engine.Schema != 1 || (engine.Mode != "uninitialized" && engine.Mode != "partition") {
		return none, ErrRetentionHeld
	}
	if engine.Mode == "uninitialized" && (engine.TableUUID != "" || engine.Operation != "" || engine.QueryID != "") {
		return none, ErrRetentionHeld
	}
	if engine.Mode == "partition" && (engine.TableUUID != request.TableUUID || engine.Operation != request.Operation || engine.QueryID != "") {
		return none, ErrRetentionHeld
	}
	dbQuery, tableQuery := storageInitializationQueryID(request.Operation, "database"), storageInitializationQueryID(request.Operation, "table")
	queries := func() error {
		rows, e := ch.Rows(ctx, initializationQueriesSQL, map[string]string{"database_query": dbQuery, "table_query": tableQuery})
		if e != nil {
			return e
		}
		if len(rows) != 1 {
			return errors.New("Storage initializer query settlement unavailable")
		}
		n, e := emergencyUint(rows[0], "running")
		if e != nil {
			return e
		}
		if n != 0 {
			return errors.New("Storage initialization query remains active; no DDL replay")
		}
		return nil
	}
	if err = queries(); err != nil {
		return none, err
	}
	detached, err := ch.Rows(ctx, initializationDetachedSQL, nil)
	if err != nil {
		return none, err
	}
	if len(detached) != 1 {
		return none, errors.New("Detached storage catalog evidence unavailable")
	}
	detachedCount, err := emergencyUint(detached[0], "detached")
	if err != nil {
		return none, err
	}
	if detachedCount != 0 {
		return none, errors.New("Detached storage catalog prevents initialization")
	}
	db, err := ch.Rows(ctx, initializationDatabaseSQL, nil)
	if err != nil {
		return none, err
	}
	tables, err := ch.Rows(ctx, initializationTablesSQL, nil)
	if err != nil {
		return none, err
	}
	if len(db) > 1 || (len(db) == 1 && db[0]["engine"] != "Atomic") || len(tables) > 1 {
		return none, errors.New("Storage initialization database/catalog is foreign")
	}
	if len(tables) == 1 && (tables[0]["name"] != "events" || tables[0]["uuid"] != request.TableUUID) {
		return none, errors.New("Storage initialization refuses an unowned existing table")
	}
	if engine.Mode == "partition" && (len(db) != 1 || len(tables) != 1) {
		return none, errors.New("Previously initialized storage identity is missing")
	}
	// Parse the captured schema before any effect; formatter failure is refusal.
	formatted, err := ch.Rows(ctx, initializationFormatSQL, map[string]string{"expected": tableDDL, "actual": tableDDL})
	if err != nil {
		return none, err
	}
	if len(formatted) != 1 || formatted[0]["actual"] != formatted[0]["expected"] {
		return none, errors.New("Storage schema formatter evidence unavailable")
	}
	if _, err = emergencyString(formatted[0], "expected"); err != nil {
		return none, err
	}
	if len(db) == 0 {
		if len(tables) != 0 {
			return none, errors.New("Inconsistent initial storage catalog")
		}
		if err = gate(); err != nil {
			return none, err
		}
		if err = ch.ExecWithQueryID(ctx, databaseDDL, nil, dbQuery); err != nil {
			return none, err
		}
	}
	db, err = ch.Rows(ctx, initializationDatabaseSQL, nil)
	if err != nil {
		return none, err
	}
	if len(db) != 1 || db[0]["engine"] != "Atomic" {
		return none, errors.New("Storage database readback is not Atomic")
	}
	if len(tables) == 0 {
		if err = gate(); err != nil {
			return none, err
		}
		ownedDDL := strings.Replace(tableDDL, "CREATE TABLE nebulalog.events", "CREATE TABLE nebulalog.events UUID '"+request.TableUUID+"'", 1)
		if err = ch.ExecWithQueryID(ctx, ownedDDL, nil, tableQuery); err != nil {
			return none, err
		}
	}
	tables, err = ch.Rows(ctx, initializationTablesSQL, nil)
	if err != nil {
		return none, err
	}
	if len(tables) != 1 || tables[0]["name"] != "events" || tables[0]["uuid"] != request.TableUUID || tables[0]["engine"] != "MergeTree" || tables[0]["partition_key"] != "(log_type, toDate(ingested_at))" {
		return none, errors.New("Initialized storage identity differs from its durable intent")
	}
	ddl, err := emergencyString(tables[0], "create_table_query")
	if err != nil {
		return none, err
	}
	formatted, err = ch.Rows(ctx, initializationFormatSQL, map[string]string{"expected": tableDDL, "actual": ddl})
	if err != nil {
		return none, err
	}
	if len(formatted) != 1 {
		return none, errors.New("Storage definition proof unavailable")
	}
	canonical, err := emergencyString(formatted[0], "actual")
	if err != nil {
		return none, err
	}
	if canonical != formatted[0]["expected"] {
		return none, errors.New("Initialized storage definition differs from captured schema")
	}
	parts, err := ch.Rows(ctx, initializationEmptySQL, nil)
	if err != nil {
		return none, err
	}
	if len(parts) != 1 {
		return none, errors.New("Initialized storage emptiness unavailable")
	}
	for _, key := range []string{"parts", "detached"} {
		n, e := emergencyUint(parts[0], key)
		if e != nil {
			return none, e
		}
		if n != 0 {
			return none, errors.New("Storage initialization refuses populated or detached data")
		}
	}
	merges, mutations, err := retentionBackground(ctx, ch)
	if err != nil {
		return none, err
	}
	if merges != 0 || mutations != 0 {
		return none, errors.New("Storage initialization background work is not settled")
	}
	if err = queries(); err != nil {
		return none, err
	}
	if err = gate(); err != nil {
		return none, err
	}
	var after []byte
	if err = pg.QueryRow(ctx, "SELECT value FROM settings WHERE key='retention'").Scan(&after); err != nil {
		return none, err
	}
	if !bytes.Equal(policy, after) {
		return none, errors.New("Retention policy changed during storage initialization")
	}
	if engine.Mode == "uninitialized" {
		bound := RetentionEngine{Schema: 1, Mode: "partition", TableUUID: request.TableUUID, Operation: request.Operation, Message: "Owned empty storage initialized without changing retention policy"}
		tag, e := pg.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='retention_engine' AND value=$2::jsonb", emergencyJSON(bound), oldEngine)
		if e != nil {
			return none, e
		}
		if tag.RowsAffected() != 1 {
			return none, errors.New("Retention engine binding changed concurrently")
		}
	}
	bound, err := readRetentionEngine(ctx, pg)
	if err != nil {
		return none, err
	}
	if bound.Mode != "partition" || bound.TableUUID != request.TableUUID || bound.Operation != request.Operation {
		return none, errors.New("Retention engine binding readback failed")
	}
	// Keep the existing host/native proof representation: exact raw catalog
	// bytes. Canonical formatting above is only the schema equality check.
	pHash, dHash := sha256.Sum256(policy), sha256.Sum256([]byte(ddl))
	return StorageInitializationReceipt{Schema: 1, Operation: request.Operation, TableUUID: request.TableUUID, SchemaSQLSHA256: request.SchemaSHA256, DDLSHA256: hex.EncodeToString(dHash[:]), RetentionPolicySHA256: hex.EncodeToString(pHash[:]), DatabaseQueryID: dbQuery, TableQueryID: tableQuery, State: "initialized"}, nil
}

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
