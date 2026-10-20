package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type storageInitRow struct {
	value any
	err   error
}

func (r storageInitRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return errors.New("unexpected scan")
	}
	switch d := dest[0].(type) {
	case *[]byte:
		*d = append([]byte(nil), r.value.([]byte)...)
	case *bool:
		*d = r.value.(bool)
	default:
		return errors.New("unexpected destination")
	}
	return nil
}

type storageInitPG struct {
	gate                                               emergencyMaintenance
	policy, engine                                     []byte
	pending                                            bool
	writes                                             []string
	changedPolicy, zeroUpdate, failUpdate, badReadback bool
}

func (p *storageInitPG) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	switch sql {
	case "SELECT value FROM settings WHERE key='storage_emergency_maintenance'":
		return storageInitRow{value: emergencyJSON(p.gate)}
	case initializationPendingSQL:
		return storageInitRow{value: p.pending}
	case "SELECT value FROM settings WHERE key='retention' FOR UPDATE":
		return storageInitRow{value: p.policy}
	case "SELECT value FROM settings WHERE key='retention'":
		if p.changedPolicy {
			return storageInitRow{value: []byte(`{"global_days":3}`)}
		}
		return storageInitRow{value: p.policy}
	case "SELECT value FROM settings WHERE key='retention_engine' FOR UPDATE":
		return storageInitRow{value: p.engine}
	case "SELECT value FROM settings WHERE key='retention_engine'":
		if p.badReadback {
			return storageInitRow{value: []byte(`{"schema":1,"mode":"uninitialized"}`)}
		}
		return storageInitRow{value: p.engine}
	default:
		return storageInitRow{err: fmt.Errorf("unexpected PG SQL %s", sql)}
	}
}
func (p *storageInitPG) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	p.writes = append(p.writes, sql)
	if sql != "UPDATE settings SET value=$1 WHERE key='retention_engine' AND value=$2::jsonb" || len(args) != 2 || !bytes.Equal(args[1].([]byte), p.engine) {
		return pgconn.CommandTag{}, errors.New("non-fixed PG mutation")
	}
	if p.failUpdate {
		return pgconn.CommandTag{}, errors.New("lost PG acknowledgement")
	}
	if p.zeroUpdate {
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}
	p.engine = append([]byte(nil), args[0].([]byte)...)
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

type storageInitCH struct {
	database                                                    bool
	table                                                       map[string]any
	canonical                                                   string
	databaseEngine                                              string
	parts, detached, detachedTables, merges, mutations, running uint64
	statements, ids                                             []string
	failSQL                                                     string
	failAfter                                                   bool
	malformedFormat                                             bool
	onExec                                                      func(string)
}

func (c *storageInitCH) Rows(_ context.Context, sql string, args map[string]string) ([]map[string]any, error) {
	if sql == c.failSQL {
		return nil, errors.New("observation failed")
	}
	switch sql {
	case initializationDatabaseSQL:
		if !c.database {
			return nil, nil
		}
		engine := c.databaseEngine
		if engine == "" {
			engine = "Atomic"
		}
		return []map[string]any{{"engine": engine}}, nil
	case initializationTablesSQL:
		if c.table == nil {
			return nil, nil
		}
		return []map[string]any{c.table}, nil
	case initializationFormatSQL:
		if c.malformedFormat {
			return []map[string]any{{}}, nil
		}
		return []map[string]any{{"expected": strings.Join(strings.Fields(args["expected"]), " "), "actual": strings.Join(strings.Fields(args["actual"]), " ")}}, nil
	case initializationEmptySQL:
		return []map[string]any{{"parts": c.parts, "detached": c.detached}}, nil
	case initializationDetachedSQL:
		return []map[string]any{{"detached": c.detachedTables}}, nil
	case initializationQueriesSQL:
		return []map[string]any{{"running": c.running}}, nil
	default:
		if strings.Contains(sql, "system.merges") {
			return []map[string]any{{"merges": c.merges, "mutations": c.mutations}}, nil
		}
		return nil, fmt.Errorf("unexpected CH SQL %s", sql)
	}
}
func (c *storageInitCH) ExecWithQueryID(_ context.Context, sql string, _ map[string]string, id string) error {
	if !emergencyUUID.MatchString(id) {
		return errors.New("non UUID query identity")
	}
	c.statements = append(c.statements, sql)
	c.ids = append(c.ids, id)
	if c.onExec != nil {
		c.onExec(sql)
	}
	failed := c.failSQL == sql
	if failed && !c.failAfter {
		return errors.New("lost acknowledgement")
	}
	if sql == "CREATE DATABASE nebulalog" {
		c.database = true
	} else if strings.HasPrefix(sql, "CREATE TABLE nebulalog.events UUID '") {
		id := strings.Split(sql, "'")[1]
		c.table = map[string]any{"name": "events", "uuid": id, "engine": "MergeTree", "partition_key": "(log_type, toDate(ingested_at))", "create_table_query": c.canonical}
	} else {
		return errors.New("unexpected DDL")
	}
	if failed {
		return errors.New("lost acknowledgement")
	}
	return nil
}
func storageInitFixture(t *testing.T) (StorageInitialization, []byte, *storageInitPG, *storageInitCH, func() (emergencyMaintenance, error)) {
	t.Helper()
	raw, err := os.ReadFile("../../migrations/clickhouse.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, ddl, err := storageSchemaStatements(raw)
	if err != nil {
		t.Fatal(err)
	}
	request := StorageInitialization{Operation: strings.Repeat("a", 64), TableUUID: fixtureTableUUID, SchemaSHA256: StorageInitializationSchemaSHA256}
	gate := emergencyMaintenance{Schema: 1, Held: true, DeliveryHeld: true, Operation: &request.Operation}
	pg := &storageInitPG{gate: gate, policy: []byte(`{"revision":17,"global_days":365,"per_type":{"alarms":7,"system":90,"dns":12}}`), engine: []byte(`{"schema":1,"mode":"uninitialized"}`)}
	ch := &storageInitCH{canonical: ddl}
	return request, raw, pg, ch, func() (emergencyMaintenance, error) { return gate, nil }
}
func TestInitializeStorageFreshAndOwnedRetryPreservePolicy(t *testing.T) {
	r, raw, pg, ch, host := storageInitFixture(t)
	before := append([]byte(nil), pg.policy...)
	receipt, err := initializeStorage(context.Background(), pg, ch, host, r, raw)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(before)
	if receipt.State != "initialized" || receipt.TableUUID != r.TableUUID || receipt.Operation != r.Operation || receipt.RetentionPolicySHA256 != hex.EncodeToString(hash[:]) || len(ch.statements) != 2 || len(pg.writes) != 1 || !bytes.Equal(before, pg.policy) {
		t.Fatal(receipt, ch.statements, pg.writes)
	}
	if !strings.Contains(ch.statements[1], "UUID '"+r.TableUUID+"'") || strings.Contains(ch.statements[1], "IF NOT EXISTS") {
		t.Fatal(ch.statements)
	}
	again, err := initializeStorage(context.Background(), pg, ch, host, r, raw)
	if err != nil || !reflect.DeepEqual(again, receipt) || len(ch.statements) != 2 || len(pg.writes) != 1 {
		t.Fatal("owned completed retry changed storage", again, err)
	}
}
func TestInitializeStorageRefusesBeforeDDL(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*StorageInitialization, *[]byte, *storageInitPG, *storageInitCH)
	}{
		{"operation", func(r *StorageInitialization, _ *[]byte, _ *storageInitPG, _ *storageInitCH) { r.Operation = "bad" }},
		{"uuid", func(r *StorageInitialization, _ *[]byte, _ *storageInitPG, _ *storageInitCH) {
			r.TableUUID = "00000000-0000-0000-0000-000000000000"
		}},
		{"schema hash", func(r *StorageInitialization, _ *[]byte, _ *storageInitPG, _ *storageInitCH) {
			r.SchemaSHA256 = strings.Repeat("0", 64)
		}},
		{"schema bytes", func(_ *StorageInitialization, b *[]byte, _ *storageInitPG, _ *storageInitCH) { *b = append(*b, ' ') }},
		{"DB idle", func(_ *StorageInitialization, _ *[]byte, p *storageInitPG, _ *storageInitCH) {
			p.gate = emergencyMaintenance{Schema: 1}
		}},
		{"DB no delivery hold", func(_ *StorageInitialization, _ *[]byte, p *storageInitPG, _ *storageInitCH) {
			p.gate.DeliveryHeld = false
		}},
		{"DB foreign owner", func(_ *StorageInitialization, _ *[]byte, p *storageInitPG, _ *storageInitCH) {
			s := strings.Repeat("b", 64)
			p.gate.Operation = &s
		}},
		{"pending", func(_ *StorageInitialization, _ *[]byte, p *storageInitPG, _ *storageInitCH) { p.pending = true }},
		{"migrating", func(_ *StorageInitialization, _ *[]byte, p *storageInitPG, _ *storageInitCH) {
			p.engine = []byte(`{"schema":1,"mode":"migrating"}`)
		}},
		{"foreign partition", func(_ *StorageInitialization, _ *[]byte, p *storageInitPG, _ *storageInitCH) {
			p.engine = []byte(`{"schema":1,"mode":"partition","table_uuid":"12345678-1234-4234-8234-123456789abc"}`)
		}},
		{"invalid policy", func(_ *StorageInitialization, _ *[]byte, p *storageInitPG, _ *storageInitCH) {
			p.policy = []byte(`{"global_days":0}`)
		}},
		{"foreign database", func(_ *StorageInitialization, _ *[]byte, _ *storageInitPG, c *storageInitCH) {
			c.database = true
			c.databaseEngine = "Ordinary"
		}},
		{"foreign table", func(_ *StorageInitialization, _ *[]byte, _ *storageInitPG, c *storageInitCH) {
			c.database = true
			c.table = map[string]any{"name": "events", "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
		}},
		{"detached table", func(_ *StorageInitialization, _ *[]byte, _ *storageInitPG, c *storageInitCH) { c.detachedTables = 1 }},
		{"unsettled query", func(_ *StorageInitialization, _ *[]byte, _ *storageInitPG, c *storageInitCH) { c.running = 1 }},
		{"unknown query", func(_ *StorageInitialization, _ *[]byte, _ *storageInitPG, c *storageInitCH) {
			c.failSQL = initializationQueriesSQL
		}},
		{"formatter unavailable", func(_ *StorageInitialization, _ *[]byte, _ *storageInitPG, c *storageInitCH) {
			c.malformedFormat = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, b, p, c, h := storageInitFixture(t)
			tc.alter(&r, &b, p, c)
			if _, err := initializeStorage(context.Background(), p, c, h, r, b); err == nil || len(c.statements) != 0 || len(p.writes) != 0 {
				t.Fatal("unsafe initialization", err, c.statements, p.writes)
			}
		})
	}
}
func TestInitializeStorageHostFenceAndMidDispatchDrift(t *testing.T) {
	for _, mode := range []string{"idle", "error", "foreign", "changed after database"} {
		t.Run(mode, func(t *testing.T) {
			r, b, p, c, h := storageInitFixture(t)
			calls := 0
			host := func() (emergencyMaintenance, error) {
				calls++
				g, e := h()
				switch mode {
				case "idle":
					return emergencyMaintenance{Schema: 1}, nil
				case "error":
					return g, errors.New("unsafe inode")
				case "foreign":
					s := strings.Repeat("b", 64)
					g.Operation = &s
				case "changed after database":
					if c.database {
						g.DeliveryHeld = false
					}
				}
				return g, e
			}
			_, err := initializeStorage(context.Background(), p, c, host, r, b)
			want := 0
			if mode == "changed after database" {
				want = 1
			}
			if err == nil || len(c.statements) != want || len(p.writes) != 0 {
				t.Fatal(err, c.statements, calls)
			}
		})
	}
}
func TestInitializeStorageAmbiguousDDLIsNotReplayed(t *testing.T) {
	for _, phase := range []string{"database", "table"} {
		t.Run(phase, func(t *testing.T) {
			r, b, p, c, h := storageInitFixture(t)
			c.failAfter = true
			if phase == "database" {
				c.failSQL = "CREATE DATABASE nebulalog"
			} else {
				c.failSQL = strings.Replace(c.canonical, "CREATE TABLE nebulalog.events", "CREATE TABLE nebulalog.events UUID '"+r.TableUUID+"'", 1)
			}
			if _, err := initializeStorage(context.Background(), p, c, h, r, b); err == nil || len(p.writes) != 0 {
				t.Fatal("ack loss accepted", err)
			}
			first := len(c.statements)
			if first != map[string]int{"database": 1, "table": 2}[phase] {
				t.Fatal(c.statements)
			}
			// A separate host-authorized reconciliation sees exact owned terminal state.
			c.failSQL = ""
			if _, err := initializeStorage(context.Background(), p, c, h, r, b); err != nil {
				t.Fatal(err)
			}
			if len(c.statements) != 2 {
				t.Fatal("DDL replayed", c.statements)
			}
		})
	}
}
func TestInitializeStorageRefusesNonemptyOrChangedReadback(t *testing.T) {
	for _, mode := range []string{"parts", "detached", "merges", "mutations", "definition", "engine", "policy", "zero update", "failed update", "bad PG readback"} {
		t.Run(mode, func(t *testing.T) {
			r, b, p, c, h := storageInitFixture(t)
			switch mode {
			case "parts":
				c.parts = 1
			case "detached":
				c.detached = 1
			case "merges":
				c.merges = 1
			case "mutations":
				c.mutations = 1
			case "definition":
				c.canonical += " COMMENT 'foreign'"
			case "engine":
				c.onExec = func(sql string) {
					if strings.HasPrefix(sql, "CREATE TABLE") {
						c.canonical += " TTL expires_at DELETE"
					}
				}
			case "policy":
				p.changedPolicy = true
			case "zero update":
				p.zeroUpdate = true
			case "failed update":
				p.failUpdate = true
			case "bad PG readback":
				p.badReadback = true
			}
			if _, err := initializeStorage(context.Background(), p, c, h, r, b); err == nil {
				t.Fatal("unsafe readback accepted")
			}
			if len(c.statements) > 2 {
				t.Fatal("replayed DDL")
			}
			if mode != "zero update" && mode != "failed update" && mode != "bad PG readback" && len(p.writes) != 0 {
				t.Fatal("bound before complete proof", p.writes)
			}
		})
	}
}
func TestInitializeStorageMetadataClientUsesFixedDefaultWithoutChangingRegularClient(t *testing.T) {
	var databases []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		databases = append(databases, r.URL.Query().Get("database"))
		if r.URL.Query().Get("database") != "default" {
			http.Error(w, "database does not exist", 404)
			return
		}
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer server.Close()
	normal := NewClickHouse(server.URL+"?database=attacker", "nebulalog", "test-fixture")
	initialization := normal.storageInitializationClient()
	if initialization == normal || initialization.URL != normal.URL || initialization.Client != normal.Client || initialization.User != normal.User || initialization.Password != normal.Password || normal.initializationMetadata {
		t.Fatal("client mutated")
	}
	if _, err := initialization.Rows(context.Background(), initializationDatabaseSQL, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := normal.Rows(context.Background(), initializationDatabaseSQL, nil); err == nil {
		t.Fatal("normal client's database changed")
	}
	if !reflect.DeepEqual(databases, []string{"default", "nebulalog"}) {
		t.Fatal(databases)
	}
}
func TestInitializeStorageQueryIDsAndFixedSchema(t *testing.T) {
	r, b, _, _, _ := storageInitFixture(t)
	db, table, err := storageSchemaStatements(b)
	if err != nil || db != "CREATE DATABASE nebulalog" || !strings.HasPrefix(table, "CREATE TABLE nebulalog.events") {
		t.Fatal(err)
	}
	first, second := storageInitializationQueryID(r.Operation, "database"), storageInitializationQueryID(r.Operation, "table")
	if !emergencyUUID.MatchString(first) || !emergencyUUID.MatchString(second) || first == second || first != storageInitializationQueryID(r.Operation, "database") {
		t.Fatal(first, second)
	}
	if StorageInitializationSchemaPath != "/app/migrations/clickhouse.sql" {
		t.Fatal("mutable schema path")
	}
}

func TestInitializeStorageReceiptUsesRawCatalogDDL(t *testing.T) {
	r, b, p, c, h := storageInitFixture(t)
	c.database = true
	rawDDL := c.canonical + "\n  "
	c.table = map[string]any{"name": "events", "uuid": r.TableUUID, "engine": "MergeTree", "partition_key": "(log_type, toDate(ingested_at))", "create_table_query": rawDDL}
	receipt, err := initializeStorage(context.Background(), p, c, h, r, b)
	expected := sha256.Sum256([]byte(rawDDL))
	normalized := sha256.Sum256([]byte(strings.Join(strings.Fields(rawDDL), " ")))
	if err != nil || receipt.DDLSHA256 != hex.EncodeToString(expected[:]) || receipt.DDLSHA256 == hex.EncodeToString(normalized[:]) || len(c.statements) != 0 {
		t.Fatal(receipt, err, c.statements)
	}
}
