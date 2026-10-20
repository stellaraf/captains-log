package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Uses the same explicit disposable fixture opt-in as emergency tests. It never
// uses the read-only production/test endpoint or creates a service itself.
func TestRetentionRealExistingDataAndPartitionCleanup(t *testing.T) {
	s, ctx := emergencyTestStore(t)
	emergencyRealTable(t, s, ctx)
	now := time.Now().UTC()
	oldDay := now.AddDate(0, 0, -40).Format("2006-01-02")
	rows := []map[string]any{emergencyEvent("older-traffic", "traffic", now.AddDate(0, 0, -41).Format("2006-01-02"), "partial"), emergencyEvent("old-traffic", "traffic", oldDay, "partial"), emergencyEvent("old-dns", "dns", oldDay, "parsed"), emergencyEvent("today", "traffic", now.Format("2006-01-02"), "parsed")}
	// Legacy expiry is intentionally already past. With TTL removed, a policy
	// extension must preserve the stored rows without rewriting this column.
	for _, row := range rows {
		row["expires_at"] = "2020-01-01T00:00:00Z"
	}
	if err := s.CH.InsertRows(ctx, rows); err != nil {
		t.Fatal(err)
	}
	p, err := s.UpdateRetention(ctx, "fixture-admin", 1, Retention{GlobalDays: 30, PerType: map[string]int{"dns": 90}})
	if err != nil {
		t.Fatal(err)
	}
	count := func(want uint64) {
		t.Helper()
		_, where, args, e := s.RetainedPredicate(ctx, now)
		if e != nil {
			t.Fatal(e)
		}
		got, e := s.CH.Rows(ctx, "SELECT count() AS rows FROM events WHERE "+where, args)
		if e != nil || len(got) != 1 {
			t.Fatal(got, e)
		}
		n, e := emergencyUint(got[0], "rows")
		if e != nil || n != want {
			t.Fatal(n, want, e)
		}
	}
	count(2)
	if _, err = s.UpdateRetention(ctx, "fixture-admin", 1, p); !errors.Is(err, ErrRetentionRevision) {
		t.Fatal("stale policy saved", err)
	}
	p, err = s.UpdateRetention(ctx, "fixture-admin", p.Revision, Retention{GlobalDays: 90, PerType: map[string]int{"dns": 90}})
	if err != nil {
		t.Fatal(err)
	}
	count(4)
	if _, err = s.UpdateRetention(ctx, "fixture-admin", p.Revision, Retention{GlobalDays: 30, PerType: map[string]int{"dns": 90}}); err != nil {
		t.Fatal(err)
	}
	policy := DefaultEmergencyPolicy()
	policy.Enabled = false
	if err = s.UpdateEmergencyPolicy(ctx, "fixture-admin", 1, policy); err != nil {
		t.Fatal(err)
	}
	if err = s.EmergencyStep(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.RetentionStep(ctx); err != nil {
		t.Fatal(err)
	}
	action, err := pendingRetention(ctx, s.PG)
	if err != nil || action == nil || action.State != "awaiting_cleanup" || len(action.Partitions) != 2 || action.Partitions[0].LogType != "traffic" {
		t.Fatal(action, err)
	}
	// Parse errors expire under the administrator's normal policy; emergency
	// protection remains independently stricter.
	if _, err = s.UpdateRetention(ctx, "fixture-admin", 4, Retention{GlobalDays: 365}); !errors.Is(err, ErrRetentionHeld) {
		t.Fatal("pending removal allowed extension", err)
	}
	if err = s.UpdateEmergencyPolicy(ctx, "fixture-admin", 2, policy); !errors.Is(err, ErrEmergencyPending) {
		t.Fatal("pending normal removal allowed emergency edit", err)
	}
	if err = s.insertEmergencyGuarded(ctx, []map[string]any{rows[0]}); err == nil {
		t.Fatal("late same-day delivery escaped fence")
	}
	setEmergencyTestGate(t, s, ctx, true, true)
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if err = s.RetentionStep(ctx); err != nil {
			t.Fatal(err)
		}
		action, err = pendingRetention(ctx, s.PG)
		if err != nil {
			t.Fatal(err)
		}
		if action == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if action != nil {
		t.Fatal("physical cleanup not observed within fixture bound")
	}
	count(2)
	got, err := s.CH.Rows(ctx, "SELECT count() AS rows FROM events WHERE expires_at=toDateTime('2020-01-01 00:00:00','UTC')", nil)
	if err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	n, _ := emergencyUint(got[0], "rows")
	if n != 2 {
		t.Fatal("expiry column was rewritten", n)
	}
}

func TestRetentionRealLegacyTTLRequiresOwnedMigration(t *testing.T) {
	s, ctx := emergencyTestStore(t)
	emergencyRealTable(t, s, ctx)
	if err := s.CH.Exec(ctx, "SYSTEM STOP MERGES nebulalog.events", nil); err != nil {
		t.Fatal(err)
	}
	// Test-only construction of the old schema, with no event rows to discard.
	if err := s.CH.Exec(ctx, "ALTER TABLE nebulalog.events MODIFY TTL expires_at DELETE SETTINGS materialize_ttl_after_modify=0", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PG.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='retention_engine'", emergencyJSON(RetentionEngine{Schema: 1, Mode: "uninitialized"})); err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeRetention(ctx); err == nil {
		t.Fatal("legacy TTL adopted as fresh")
	}
	if err := s.MigrateRetention(ctx); err == nil {
		t.Fatal("migration without owned hold")
	}
	setEmergencyTestGate(t, s, ctx, true, true)
	if err := s.MigrateRetention(ctx); err != nil {
		t.Fatal(err)
	}
	engine, err := s.RetentionEngine(ctx)
	if err != nil || engine.Mode != "partition" || engine.TableUUID == "" {
		t.Fatal(engine, err)
	}
	if err = verifyRetentionTable(ctx, s.CH, engine.TableUUID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdateRetention(ctx, "fixture-admin", 1, Retention{GlobalDays: 365}); !errors.Is(err, ErrRetentionHeld) {
		t.Fatal("migration released host gate", err)
	}
	var stages int
	if err = s.PG.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='retention.migration' AND detail->>'query_id' IS NOT NULL").Scan(&stages); err != nil || stages != 3 {
		t.Fatal("DDL trace not retained", stages, err)
	}
}

type uncertainRetentionCH struct {
	*ClickHouse
	drops int
}

func (c *uncertainRetentionCH) ExecWithQueryID(ctx context.Context, sql string, args map[string]string, id string) error {
	if strings.Contains(sql, "DROP PARTITION") {
		c.drops++
		return errors.New("fixture delayed dispatch; acknowledgement unknown")
	}
	return c.ClickHouse.ExecWithQueryID(ctx, sql, args, id)
}
func TestRetentionRealUncertaintyFencesEvenWithoutDispatch(t *testing.T) {
	s, ctx := emergencyTestStore(t)
	emergencyRealTable(t, s, ctx)
	if err := s.CH.InsertRows(ctx, []map[string]any{emergencyEvent("expired", "traffic", "2020-01-01", "parsed")}); err != nil {
		t.Fatal(err)
	}
	p := DefaultEmergencyPolicy()
	p.Enabled = false
	if err := s.UpdateEmergencyPolicy(ctx, "fixture-admin", 1, p); err != nil {
		t.Fatal(err)
	}
	if err := s.EmergencyStep(ctx); err != nil {
		t.Fatal(err)
	}
	ch := &uncertainRetentionCH{ClickHouse: s.CH}
	if err := s.retentionStep(ctx, ch, time.Now()); err == nil {
		t.Fatal("uncertain dispatch accepted")
	}
	if err := s.retentionStep(ctx, ch, time.Now()); err != nil {
		t.Fatal(err)
	}
	a, err := pendingRetention(ctx, s.PG)
	if err != nil || a == nil || a.State != "uncertain" || ch.drops != 1 {
		t.Fatal(a, err, ch.drops)
	}
	if _, err = s.UpdateRetention(ctx, "fixture-admin", 1, Retention{GlobalDays: 365}); !errors.Is(err, ErrRetentionHeld) {
		t.Fatal("uncertainty allowed policy change", err)
	}
}
