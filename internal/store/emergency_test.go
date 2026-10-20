package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func partFixture(kind, day, id string) map[string]any {
	return map[string]any{"partition_id": id, "partition": fmt.Sprintf("('%s','%s')", kind, day), "disk_name": "default", "rows": uint64(2), "bytes_on_disk": uint64(1024), "parts": []EmergencyPart{{Name: id + "_1_1_0", Rows: 2, Bytes: 1024}}}
}
func TestEmergencyPolicyAndEligibility(t *testing.T) {
	p := DefaultEmergencyPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(p.MinimumDays) != 15 {
		t.Fatal("physical family set")
	}
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	rows := []map[string]any{partFixture("threat", "2026-08-01", strings.Repeat("a", 32)), partFixture("traffic", "2026-10-12", strings.Repeat("b", 32)), partFixture("traffic", "2026-10-13", strings.Repeat("c", 32)), partFixture("system", "2026-10-01", strings.Repeat("d", 32)), partFixture("unknown", "2020-01-01", strings.Repeat("e", 32)), partFixture("alarms", "2020-01-01", strings.Repeat("f", 32))}
	got, err := eligibleEmergencyPartitions(rows, p, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].LogType != "traffic" || got[1].LogType != "threat" {
		t.Fatalf("unsafe order/minimums: %+v", got)
	}
	p.MinimumDays["alarms"] = 30
	if p.Validate() == nil {
		t.Fatal("virtual category accepted")
	}
	delete(p.MinimumDays, "alarms")
	p.MinimumDays["traffic"] = 0
	if p.Validate() == nil {
		t.Fatal("zero minimum accepted")
	}
}

// This dedicated opt-in is deliberately different from the read-only CH test
// variables. It is only for freshly created, labelled disposable databases.
func emergencyTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	if os.Getenv("NEBULALOG_EMERGENCY_DESTRUCTIVE_TEST") != "1" {
		t.Skip("isolated destructive database test not enabled")
	}
	var cfg struct {
		PG       string `json:"pg_dsn"`
		URL      string `json:"ch_url"`
		User     string `json:"ch_user"`
		Password string `json:"ch_password"`
	}
	raw, err := os.ReadFile(os.Getenv("NEBULALOG_EMERGENCY_TEST_CONFIG"))
	if err != nil {
		t.Fatal("private fixture configuration unavailable")
	}
	if json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("invalid fixture configuration")
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Port() == "28123" || cfg.User != "emergency_test" {
		t.Fatal("refusing nonisolated ClickHouse endpoint")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	pc, err := pgxpool.ParseConfig(cfg.PG)
	if err != nil || pc.ConnConfig.Database != "emergency_test" || pc.ConnConfig.User != "emergency_test" || pc.ConnConfig.Host != "127.0.0.1" {
		t.Fatal("refusing nonisolated PostgreSQL endpoint")
	}
	pc.MaxConns = 12
	admin, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "emergency_" + strings.ReplaceAll(emergencyID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.RuntimeParams["search_path"] = schema
	pg, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pg.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = pg.Exec(ctx, string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	return &Store{PG: pg, CH: NewClickHouse(cfg.URL, cfg.User, cfg.Password)}, ctx
}

var fixtureTableUUID = "12345678-1234-4234-8234-123456789abc"

type emergencyFake struct {
	used         []int
	observations int
	parts        []map[string]any
	diagnostics  bool
	calls        int
	removed      bool
	inactive     bool
	fail         error
	onExec       func()
	tableUUID    string
}

func (f *emergencyFake) Rows(_ context.Context, sql string, params map[string]string) ([]map[string]any, error) {
	if strings.Contains(sql, "system.tables") {
		id := f.tableUUID
		if id == "" {
			id = fixtureTableUUID
		}
		return []map[string]any{{"uuid": id, "create_table_query": "CREATE TABLE nebulalog.events ENGINE=MergeTree", "engine": "MergeTree", "partition_key": "(log_type, toDate(ingested_at))", "storage_policy": "default", "database_engine": "Atomic", "data_paths": []any{"/var/lib/clickhouse/store/123/" + id + "/"}}}, nil
	}
	if strings.Contains(sql, "system.disks") {
		index := f.observations
		if index >= len(f.used) {
			index = len(f.used) - 1
		}
		used := f.used[index]
		f.observations++
		free := uint64((100 - used) * 100)
		if f.removed && !f.inactive {
			free += 100
		}
		return []map[string]any{{"name": "default", "path": "/var/lib/clickhouse/", "type": "Local", "total_space": uint64(10000), "free_space": free, "unreserved_space": free, "keep_free_space": uint64(1000), "is_read_only": 0, "is_remote": 0}}, nil
	}
	if strings.Contains(sql, "count() AS parts") {
		n := 0
		if !f.removed || f.inactive {
			n = 1
		}
		return []map[string]any{{"parts": n}}, nil
	}
	if sql == emergencyPartsSQL {
		if f.removed {
			return []map[string]any{}, nil
		}
		return f.parts, nil
	}
	if strings.Contains(sql, "countIf(parse_status") {
		for _, p := range f.parts {
			if p["partition_id"] == params["partition"] {
				m := emergencyPartitionValue.FindStringSubmatch(p["partition"].(string))
				d := 0
				if f.diagnostics {
					d = 1
				}
				return []map[string]any{{"rows": p["rows"], "diagnostics": d, "first_type": m[1], "last_type": m[1], "first_day": m[2], "last_day": m[2]}}, nil
			}
		}
	}
	return nil, fmt.Errorf("unhandled fixture query: %s", sql)
}
func (f *emergencyFake) ExecWithQueryID(_ context.Context, sql string, params map[string]string, id string) error {
	f.calls++
	if sql != "ALTER TABLE nebulalog.events DROP PARTITION ID {partition:String}" || !emergencyUUID.MatchString(id) {
		return errors.New("unbound destructive query")
	}
	if f.onExec != nil {
		f.onExec()
	}
	f.removed = true
	return f.fail
}
func fakeEmergency() *emergencyFake {
	return &emergencyFake{used: []int{95}, parts: []map[string]any{{"partition_id": strings.Repeat("a", 32), "partition": "('traffic','2020-01-01')", "name": "part_1_1_0", "disk_name": "default", "rows": 2, "bytes_on_disk": 1024}}}
}
func testView(t *testing.T, s *Store, ctx context.Context) EmergencyView {
	t.Helper()
	v, e := s.Emergency(ctx)
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestEmergencyControllerIsolated(t *testing.T) {
	t.Run("reserve already deducted and recovered during planning", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		f.used = []int{95, 80}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		v := testView(t, s, ctx)
		if f.calls != 0 || len(v.RecentActions) != 0 || v.Status.Active || v.Status.State != "normal" || *v.Status.UsedPercent != 80 {
			t.Fatal("purged after recovery", v)
		}
	})
	t.Run("durable intent acknowledgement physical wait hysteresis", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		f.inactive = true
		f.onExec = func() {
			var state string
			var audits int
			if e := s.PG.QueryRow(ctx, "SELECT state FROM storage_emergency_actions WHERE completed_at IS NULL").Scan(&state); e != nil {
				t.Fatal(e)
			}
			if e := s.PG.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='storage.emergency.executing'").Scan(&audits); e != nil {
				t.Fatal(e)
			}
			if state != "executing" || audits != 1 {
				t.Fatal("ALTER preceded durable audit")
			}
		}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		if testView(t, s, ctx).Status.State != "awaiting_cleanup" {
			t.Fatal("not waiting")
		}
		p := DefaultEmergencyPolicy()
		if e := s.UpdateEmergencyPolicy(ctx, "tester", 1, p); !errors.Is(e, ErrEmergencyPending) {
			t.Fatal("policy changed while unresolved", e)
		}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		if f.calls != 1 || testView(t, s, ctx).Status.Pending == nil {
			t.Fatal("did not wait for inactive parts")
		}
		f.inactive = false
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		if testView(t, s, ctx).Status.Pending != nil || !testView(t, s, ctx).Status.Active {
			t.Fatal("cleanup/hysteresis")
		}
		f.used = []int{89}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		if testView(t, s, ctx).Status.Active || f.calls != 1 {
			t.Fatal("did not recover")
		}
	})
	t.Run("uncertain server apply never replayed or absence resolved", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		f.fail = errors.New("lost HTTP response")
		if s.emergencyStep(ctx, f, time.Now()) == nil {
			t.Fatal("ambiguous response accepted")
		}
		f.fail = nil
		for range 2 {
			if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
				t.Fatal(e)
			}
		}
		v := testView(t, s, ctx)
		if f.calls != 1 || v.Status.State != "blocked" || v.Status.Pending.State != "uncertain" {
			t.Fatal("uncertain action replayed/resolved", v)
		}
	})
	t.Run("diagnostic mixed partition no candidate", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		f.diagnostics = true
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		if f.calls != 0 || testView(t, s, ctx).Status.State != "blocked" {
			t.Fatal("diagnostic erased")
		}
	})
	t.Run("missing audit prevents dispatch", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		if _, e := s.PG.Exec(ctx, "ALTER TABLE audit_events ADD CONSTRAINT refuse_destructive_audit CHECK(action NOT IN ('storage.emergency.prepared','storage.emergency.executing'))"); e != nil {
			t.Fatal(e)
		}
		if s.emergencyStep(ctx, f, time.Now()) == nil || f.calls != 0 {
			t.Fatal("dispatch without audit")
		}
		var n int
		s.PG.QueryRow(ctx, "SELECT count(*) FROM storage_emergency_actions").Scan(&n)
		if n != 0 {
			t.Fatal("partial audit transaction")
		}
	})
	t.Run("identity replacement refuses adoption", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		f.used = []int{80}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		f.tableUUID = "22345678-1234-4234-8234-123456789abc"
		f.used = []int{99}
		if s.emergencyStep(ctx, f, time.Now()) == nil || f.calls != 0 {
			t.Fatal("replacement accepted")
		}
	})
	t.Run("policy atomic revision and audit", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		p := DefaultEmergencyPolicy()
		p.MinimumDays["system"] = 365
		if e := s.UpdateEmergencyPolicy(ctx, "tester", 1, p); e != nil {
			t.Fatal(e)
		}
		if e := s.UpdateEmergencyPolicy(ctx, "tester", 1, p); !errors.Is(e, ErrEmergencyRevision) {
			t.Fatal(e)
		}
		v := testView(t, s, ctx)
		if v.Policy.Revision != 2 || v.Policy.MinimumDays["system"] != 365 {
			t.Fatal(v)
		}
		var n int
		s.PG.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='storage.emergency.policy'").Scan(&n)
		if n != 1 {
			t.Fatal("audit/revision split")
		}
	})
	t.Run("prepared interruption cancels without replay", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		f.used = []int{80}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		parts, e := inspectEmergencyPartitions(ctx, f, DefaultEmergencyPolicy(), time.Now())
		if e != nil {
			t.Fatal(e)
		}
		m, e := observeEmergency(ctx, f, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		conn, release, e := emergencyConnection(ctx, s.PG)
		if e != nil {
			t.Fatal(e)
		}
		state, e := readEmergencyStatus(ctx, conn)
		if e != nil {
			t.Fatal(e)
		}
		a := &EmergencyAction{ID: emergencyID(), EmergencyPlan: EmergencyPlan{EmergencyPartition: parts[0], Policy: DefaultEmergencyPolicy(), PolicyRevision: 1, TableUUID: m.Identity.TableUUID, Before: m, QueryID: emergencyID()}}
		if e = actionEmergency(ctx, conn, a, "prepared", "fixture interrupted before dispatch authorization", state, false); e != nil {
			t.Fatal(e)
		}
		release()
		if e = s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		v := testView(t, s, ctx)
		if f.calls != 0 || v.Status.Pending != nil || v.RecentActions[0].State != "cancelled" {
			t.Fatal("prepared replayed", v)
		}
	})
	t.Run("cleanup no net gain is visibly blocked without another deletion", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		// A post-drop allocation masks its net gain; part absence is true.
		f.used = []int{96}
		if _, e := s.PG.Exec(ctx, "UPDATE storage_emergency_actions SET updated_at=now()-interval '3 minutes' WHERE completed_at IS NULL"); e != nil {
			t.Fatal(e)
		}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		v := testView(t, s, ctx)
		if f.calls != 1 || v.Status.State != "blocked" || v.Status.Pending.State != "awaiting_cleanup" || !strings.Contains(v.Status.Message, "no net free-space gain") {
			t.Fatal("masked cleanup not held", v)
		}
		f.used = []int{80}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		if testView(t, s, ctx).Status.Pending != nil || f.calls != 1 {
			t.Fatal("same acknowledged action did not recover")
		}
	})
	t.Run("missing new schema holds delivery and idempotent migration restores evidence", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		if _, e := s.PG.Exec(ctx, "DROP TABLE storage_emergency_inserts,storage_emergency_actions,storage_emergency_state;DELETE FROM settings WHERE key='storage_emergency'"); e != nil {
			t.Fatal(e)
		}
		// Invalid endpoint proves schema refusal precedes any ClickHouse write.
		original := s.CH
		s.CH = NewClickHouse("http://127.0.0.1:1", "", "")
		if e := s.insertEmergencyGuarded(ctx, []map[string]any{{"id": "retained-wal"}}); e == nil {
			t.Fatal("legacy schema bypass")
		}
		s.CH = original
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres.sql"))
		if e != nil {
			t.Fatal(e)
		}
		for range 2 {
			if _, e = s.PG.Exec(ctx, string(raw)); e != nil {
				t.Fatal(e)
			}
		}
		v := testView(t, s, ctx)
		if !v.Policy.Enabled || v.Status.State != "not_observed" {
			t.Fatal("migration not conservative", v)
		}
	})
	t.Run("retained insert exclusions survive restart and prevent removal", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		f.used = []int{80}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		if _, e := s.PG.Exec(ctx, "INSERT INTO storage_emergency_inserts(id,table_uuid,partitions,query_id) VALUES($1,$2,$3,$4)", emergencyID(), fixtureTableUUID, emergencyJSON([]emergencyInsertPartition{{"traffic", "2020-01-01"}}), emergencyID()); e != nil {
			t.Fatal(e)
		}
		f.used = []int{99}
		for range 2 {
			if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
				t.Fatal(e)
			}
		}
		v := testView(t, s, ctx)
		if f.calls != 0 || v.Status.InsertExclusions != 1 || v.Status.ExclusionMessage == "" {
			t.Fatal("exclusion lost", v)
		}
	})
	t.Run("PG lock loss during ALTER retains global intent", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		f.onExec = func() {
			var n int
			e := s.PG.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND query='SELECT 1'").Scan(&n)
			_ = e
			_, e = s.PG.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype='advisory' AND mode='ExclusiveLock' AND granted AND pid<>pg_backend_pid()")
			if e != nil {
				t.Fatal(e)
			}
		}
		if s.emergencyStep(ctx, f, time.Now()) == nil {
			t.Fatal("lost PG acknowledgement accepted")
		}
		f.onExec = nil
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		if f.calls != 1 || testView(t, s, ctx).Status.State != "blocked" {
			t.Fatal("global intent did not fence after lock loss")
		}
	})
}

func TestEmergencyQueryIDAndLiteralBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if string(raw) != "ALTER TABLE nebulalog.events DROP PARTITION ID {partition:String}" || r.URL.Query().Get("param_partition") != "abc' OR 1=1" || r.URL.Query().Get("query_id") != fixtureTableUUID || r.URL.Query().Get("replace_running_query") != "" {
			t.Error("SQL or query identity binding changed")
		}
	}))
	defer server.Close()
	ch := NewClickHouse(server.URL, "test", "")
	if e := ch.ExecWithQueryID(context.Background(), "ALTER TABLE nebulalog.events DROP PARTITION ID {partition:String}", map[string]string{"partition": "abc' OR 1=1"}, fixtureTableUUID); e != nil {
		t.Fatal(e)
	}
}

func fakeEmergencyHTTP(t *testing.T, f *emergencyFake) (*ClickHouse, *int) {
	t.Helper()
	inserts := new(int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Query().Get("query"), "INSERT INTO events") {
			*inserts++
			return
		}
		raw, _ := io.ReadAll(r.Body)
		sql := strings.TrimSuffix(string(raw), " FORMAT JSONEachRow")
		rows, e := f.Rows(r.Context(), sql, nil)
		if e != nil {
			http.Error(w, "fixture unexpected query", 500)
			return
		}
		for _, row := range rows {
			json.NewEncoder(w).Encode(row)
		}
	}))
	t.Cleanup(server.Close)
	return NewClickHouse(server.URL, "fixture", ""), inserts
}
func setEmergencyTestGate(t *testing.T, s *Store, ctx context.Context, held, delivery bool) {
	t.Helper()
	var owner any
	if held {
		owner = strings.Repeat("a", 64)
	}
	raw := emergencyJSON(map[string]any{"schema": 1, "held": held, "delivery_held": delivery, "operation": owner})
	if _, e := s.PG.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='storage_emergency_maintenance'", raw); e != nil {
		t.Fatal(e)
	}
}
func TestEmergencyMaintenanceAndAdmissionIsolated(t *testing.T) {
	t.Run("fresh capacity refuses insert despite recent normal observation", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		f.used = []int{80}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		f.used = []int{99}
		ch, inserts := fakeEmergencyHTTP(t, f)
		s.CH = ch
		if _, e := s.PG.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='retention_engine'", emergencyJSON(RetentionEngine{Schema: 1, Mode: "partition", TableUUID: fixtureTableUUID})); e != nil {
			t.Fatal(e)
		}
		if e := s.insertEmergencyGuarded(ctx, []map[string]any{emergencyEvent("retain-wal", "traffic", "2020-01-01", "parsed")}); e != ErrStoragePressure {
			t.Fatal(e)
		}
		if *inserts != 0 {
			t.Fatal("fresh pressure ignored")
		}
		var n int
		if e := s.PG.QueryRow(ctx, "SELECT count(*) FROM storage_emergency_inserts").Scan(&n); e != nil || n != 0 {
			t.Fatal("refused request dispatched", e)
		}
	})
	t.Run("host gate suppresses removal while permitted healthy delivery continues", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		setEmergencyTestGate(t, s, ctx, true, false)
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		v := testView(t, s, ctx)
		if f.calls != 0 || !v.Status.MaintenanceHeld || v.Status.MaintenanceMessage == "" || v.Status.State != "blocked" {
			t.Fatal("purge escaped maintenance", v)
		}
		f.used = []int{80}
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		ch, inserts := fakeEmergencyHTTP(t, f)
		s.CH = ch
		if _, e := s.PG.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='retention_engine'", emergencyJSON(RetentionEngine{Schema: 1, Mode: "partition", TableUUID: fixtureTableUUID})); e != nil {
			t.Fatal(e)
		}
		if e := s.insertEmergencyGuarded(ctx, []map[string]any{emergencyEvent("health-canary", "traffic", "2020-01-01", "parsed")}); e != nil {
			t.Fatal(e)
		}
		if *inserts != 1 {
			t.Fatal("maintenance unnecessarily blocked healthy delivery")
		}
		setEmergencyTestGate(t, s, ctx, true, true)
		if e := s.insertEmergencyGuarded(ctx, []map[string]any{emergencyEvent("retained-wal", "traffic", "2020-01-01", "parsed")}); e == nil || !strings.Contains(e.Error(), "Host maintenance") {
			t.Fatal("host backup did not hold delivery", e)
		}
		if *inserts != 1 {
			t.Fatal("backup fence escaped")
		}
	})
	t.Run("host gate permits only acknowledged cleanup recovery", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		f := fakeEmergency()
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		setEmergencyTestGate(t, s, ctx, true, true)
		if e := s.emergencyStep(ctx, f, time.Now()); e != nil {
			t.Fatal(e)
		}
		v := testView(t, s, ctx)
		if f.calls != 1 || v.Status.Pending != nil || !v.Status.MaintenanceHeld || !v.Status.DeliveryHeld {
			t.Fatal("acknowledged cleanup lost host fence", v)
		}
	})
	t.Run("missing malformed foreign gate cannot be defaulted or overwritten by migration", func(t *testing.T) {
		for _, raw := range []string{`{}`, `{"schema":1,"held":false,"delivery_held":true,"operation":null}`, `{"schema":1,"held":true,"delivery_held":false,"operation":null}`, `{"schema":1,"held":null,"delivery_held":false,"operation":null}`, `{"schema":1,"held":true,"delivery_held":true,"operation":"abc"}`} {
			s, ctx := emergencyTestStore(t)
			if _, e := s.PG.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='storage_emergency_maintenance'", []byte(raw)); e != nil {
				t.Fatal(e)
			}
			f := fakeEmergency()
			if s.emergencyStep(ctx, f, time.Now()) == nil || f.calls != 0 {
				t.Fatal("bad gate adopted", raw)
			}
		}
		s, ctx := emergencyTestStore(t)
		setEmergencyTestGate(t, s, ctx, true, true)
		migration, e := os.ReadFile("../../migrations/postgres.sql")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.PG.Exec(ctx, string(migration)); e != nil {
			t.Fatal(e)
		}
		gate, e := readEmergencyMaintenance(ctx, s.PG)
		if e != nil || !gate.Held || !gate.DeliveryHeld {
			t.Fatal("migration cleared existing owner", e)
		}
		if _, e = s.PG.Exec(ctx, "DELETE FROM settings WHERE key='storage_emergency_maintenance'"); e != nil {
			t.Fatal(e)
		}
		f := fakeEmergency()
		if s.emergencyStep(ctx, f, time.Now()) == nil || f.calls != 0 {
			t.Fatal("missing gate bypassed")
		}
	})
}

type identityOverrideCH struct {
	base *emergencyFake
	edit func(string, []map[string]any)
}

func (c identityOverrideCH) Rows(ctx context.Context, sql string, p map[string]string) ([]map[string]any, error) {
	rows, e := c.base.Rows(ctx, sql, p)
	if e == nil {
		c.edit(sql, rows)
	}
	return rows, e
}
func (c identityOverrideCH) ExecWithQueryID(context.Context, string, map[string]string, string) error {
	return errors.New("identity test cannot delete")
}
func TestEmergencyRefusesUnsupportedStorageIdentity(t *testing.T) {
	tests := map[string]func(string, []map[string]any){
		"replicated engine": func(sql string, r []map[string]any) {
			if strings.Contains(sql, "system.tables") {
				r[0]["engine"] = "ReplicatedMergeTree"
			}
		},
		"non atomic": func(sql string, r []map[string]any) {
			if strings.Contains(sql, "system.tables") {
				r[0]["database_engine"] = "Ordinary"
			}
		},
		"zero uuid": func(sql string, r []map[string]any) {
			if strings.Contains(sql, "system.tables") {
				r[0]["uuid"] = "00000000-0000-0000-0000-000000000000"
			}
		},
		"wrong partition scheme": func(sql string, r []map[string]any) {
			if strings.Contains(sql, "system.tables") {
				r[0]["partition_key"] = "toDate(ingested_at)"
			}
		},
		"multiple paths": func(sql string, r []map[string]any) {
			if strings.Contains(sql, "system.tables") {
				r[0]["data_paths"] = []any{"/one/", "/two/"}
			}
		},
		"remote disk": func(sql string, r []map[string]any) {
			if strings.Contains(sql, "system.disks") {
				r[0]["is_remote"] = 1
			}
		},
		"read only disk": func(sql string, r []map[string]any) {
			if strings.Contains(sql, "system.disks") {
				r[0]["is_read_only"] = 1
			}
		},
		"different disk path": func(sql string, r []map[string]any) {
			if strings.Contains(sql, "system.disks") {
				r[0]["path"] = "/tmp/"
			}
		},
		"inconsistent reserved space": func(sql string, r []map[string]any) {
			if strings.Contains(sql, "system.disks") {
				r[0]["unreserved_space"] = 10001
			}
		},
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			if _, e := observeEmergency(context.Background(), identityOverrideCH{fakeEmergency(), edit}, time.Now()); e == nil {
				t.Fatal("unsupported storage identity accepted")
			}
		})
	}
}
