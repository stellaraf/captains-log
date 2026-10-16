package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func emergencyRealTable(t *testing.T, s *Store, ctx context.Context) {
	t.Helper()
	if e := s.CH.Exec(ctx, "CREATE DATABASE IF NOT EXISTS nebulalog", nil); e != nil {
		t.Fatal(e)
	}
	if e := s.CH.Exec(ctx, "DROP TABLE IF EXISTS nebulalog.events SYNC", nil); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "clickhouse.sql"))
	if e != nil {
		t.Fatal(e)
	}
	for _, sql := range strings.Split(string(raw), ";") {
		if strings.TrimSpace(sql) != "" {
			if e = s.CH.Exec(ctx, sql, nil); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e = s.CH.Exec(ctx, "ALTER TABLE nebulalog.events MODIFY SETTING old_parts_lifetime=1, cleanup_delay_period=1, cleanup_delay_period_random_add=1", nil); e != nil {
		t.Fatal(e)
	}
}
func emergencyEvent(id, kind, day, status string) map[string]any {
	return map[string]any{"id": id, "ingested_at": day + "T12:00:00Z", "received_at": day + "T12:00:00Z", "expires_at": "2099-01-01T00:00:00Z", "log_type": kind, "parse_status": status, "raw": "preserved " + id, "raw_base64": base64.StdEncoding.EncodeToString([]byte("preserved " + id))}
}

type pressureCH struct {
	*ClickHouse
	pressure bool
	calls    int
	lost     bool
}

func (c *pressureCH) Rows(ctx context.Context, sql string, p map[string]string) ([]map[string]any, error) {
	rows, e := c.ClickHouse.Rows(ctx, sql, p)
	if e == nil && c.pressure && strings.Contains(sql, "system.disks") {
		for _, r := range rows {
			total, e := emergencyUint(r, "total_space")
			if e != nil {
				return nil, e
			}
			free, e := emergencyUint(r, "free_space")
			if e != nil {
				return nil, e
			}
			reserve := total / 25
			if reserve > free {
				reserve = free
			}
			r["unreserved_space"] = reserve
		}
	}
	return rows, e
}
func (c *pressureCH) ExecWithQueryID(ctx context.Context, sql string, p map[string]string, id string) error {
	c.calls++
	e := c.ClickHouse.ExecWithQueryID(ctx, sql, p, id)
	if e == nil && c.lost {
		return fmt.Errorf("fixture lost server acknowledgement after actual successful DROP")
	}
	return e
}

func TestEmergencyRealClickHouse(t *testing.T) {
	t.Run("native metadata and traffic first protected rows physical cleanup", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		emergencyRealTable(t, s, ctx)
		measured, e := observeEmergency(ctx, s.CH, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		if measured.KeepFree != 10485760 || measured.Available != measured.Unreserved {
			t.Fatal("reserve semantics changed", measured)
		}
		rows := []map[string]any{emergencyEvent("threat-old", "threat", "2020-01-01", "parsed"), emergencyEvent("system-protected", "system", time.Now().UTC().AddDate(0, 0, -2).Format("2006-01-02"), "parsed"), emergencyEvent("traffic-diagnostic", "traffic", "2020-01-02", "partial"), emergencyEvent("traffic-mixed", "traffic", "2020-01-02", "parsed"), emergencyEvent("unknown", "unknown", "2020-01-01", "parsed"), emergencyEvent("today", "traffic", time.Now().UTC().Format("2006-01-02"), "parsed")}
		// Bounded 8 MiB incompressible fixture makes native physical reclamation
		// observable without filling a real disk. Only pressure trigger is injected.
		for i := 0; i < 32; i++ {
			row := emergencyEvent(fmt.Sprintf("traffic-eligible-%d", i), "traffic", "2020-01-03", "parsed")
			b := make([]byte, 256*1024)
			rand.Read(b)
			row["raw"] = base64.StdEncoding.EncodeToString(b)
			rows = append(rows, row)
		}
		if e = s.CH.InsertRows(ctx, rows); e != nil {
			t.Fatal(e)
		}
		ch := &pressureCH{ClickHouse: s.CH, pressure: true}
		if e = s.emergencyStep(ctx, ch, time.Now()); e != nil {
			t.Fatal(e)
		}
		v := testView(t, s, ctx)
		if ch.calls != 1 || v.Status.Pending == nil || v.Status.Pending.LogType != "traffic" || v.Status.Pending.PartitionDay != "2020-01-03" {
			t.Fatalf("selection: %+v", v)
		}
		pending := v.Status.Pending
		if pending.Rows != 32 || len(pending.Parts) == 0 || pending.Bytes == 0 {
			t.Fatal("intent lacks actual evidence")
		}
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			if e = s.emergencyStep(ctx, ch, time.Now()); e != nil {
				t.Fatal(e)
			}
			v = testView(t, s, ctx)
			if v.Status.Pending == nil {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if v.Status.Pending != nil {
			t.Fatalf("native cleanup not completed: %s", v.Status.Message)
		}
		if ch.calls != 1 {
			t.Fatal("multiple removals before reclamation")
		}
		retained, e := s.CH.Rows(ctx, "SELECT id FROM nebulalog.events ORDER BY id", nil)
		if e != nil {
			t.Fatal(e)
		}
		if len(retained) != 6 {
			t.Fatalf("protected rows lost: %v", retained)
		}
		ch.pressure = false
		if e = s.emergencyStep(ctx, ch, time.Now()); e != nil {
			t.Fatal(e)
		}
		if testView(t, s, ctx).Status.State != "normal" {
			t.Fatal("did not recover")
		}
		// A later retained WAL generation can safely recreate the old day after
		// acknowledged physical cleanup; it is never silently discarded.
		late := emergencyEvent("late-wal", "traffic", "2020-01-03", "partial")
		if e = s.insertEmergencyGuarded(ctx, []map[string]any{late}); e != nil {
			t.Fatal(e)
		}
		lateRows, e := s.CH.Rows(ctx, "SELECT id,raw,raw_base64 FROM nebulalog.events WHERE id='late-wal'", nil)
		if e != nil || len(lateRows) != 1 || lateRows[0]["raw"] != late["raw"] || lateRows[0]["raw_base64"] != late["raw_base64"] {
			t.Fatal("late WAL not preserved", e)
		}
		after, e := observeEmergency(ctx, s.CH, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("NATIVE_EMERGENCY_RECEIPT %s", emergencyJSON(map[string]any{"authorized_action": pending, "after": after, "retained_ids": retained, "late_wal": lateRows, "destructive_queries": ch.calls, "pressure_injected": true, "appliance_acceptance": false}))
		t.Logf("Actual CH metadata/DROP/physical cleanup verified; table=%s partition=%s observed parts=%d estimate bytes=%d. Trigger injected, not real disk pressure.", pending.TableUUID, pending.PartitionID, len(pending.Parts), pending.Bytes)
	})
	t.Run("actual successful DROP lost response remains uncertain", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		emergencyRealTable(t, s, ctx)
		if e := s.CH.InsertRows(ctx, []map[string]any{emergencyEvent("uncertain", "traffic", "2020-01-01", "parsed")}); e != nil {
			t.Fatal(e)
		}
		ch := &pressureCH{ClickHouse: s.CH, pressure: true, lost: true}
		if s.emergencyStep(ctx, ch, time.Now()) == nil {
			t.Fatal("lost response accepted")
		}
		ch.lost = false
		for range 2 {
			if e := s.emergencyStep(ctx, ch, time.Now()); e != nil {
				t.Fatal(e)
			}
		}
		if ch.calls != 1 || testView(t, s, ctx).Status.State != "blocked" {
			t.Fatal("uncertain replay")
		}
		if e := s.insertEmergencyGuarded(ctx, []map[string]any{emergencyEvent("held", "traffic", "2020-01-01", "parsed")}); e != ErrStoragePressure {
			t.Fatal("unresolved intent did not hold WAL", e)
		}
	})
	t.Run("delayed diagnostic INSERT survives PG lock loss without purge race", func(t *testing.T) {
		s, ctx := emergencyTestStore(t)
		emergencyRealTable(t, s, ctx)
		if e := s.CH.InsertRows(ctx, []map[string]any{emergencyEvent("old-row", "traffic", "2020-01-01", "parsed")}); e != nil {
			t.Fatal(e)
		}
		if e := s.EmergencyStep(ctx); e != nil {
			t.Fatal(e)
		}
		actual := s.CH
		entered := make(chan struct{})
		resume := make(chan struct{})
		var resumeOnce sync.Once
		resumeInsert := func() { resumeOnce.Do(func() { close(resume) }) }
		defer resumeInsert()
		var once sync.Once
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, e := io.ReadAll(r.Body)
			if e != nil {
				t.Error(e)
				return
			}
			if strings.HasPrefix(r.URL.Query().Get("query"), "INSERT INTO events") {
				once.Do(func() { close(entered) })
				<-resume
			}
			target, _ := url.Parse(actual.URL)
			target.RawQuery = r.URL.RawQuery
			req, _ := http.NewRequestWithContext(r.Context(), r.Method, target.String(), strings.NewReader(string(body)))
			req.Header = r.Header.Clone()
			response, e := actual.Client.Do(req)
			if e != nil {
				http.Error(w, "fixture upstream failed", 502)
				return
			}
			defer response.Body.Close()
			for k, vs := range response.Header {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(response.StatusCode)
			io.Copy(w, response.Body)
		}))
		defer func() { resumeInsert(); proxy.Close() }()
		s.CH = NewClickHouse(proxy.URL, actual.User, actual.Password)
		done := make(chan error, 1)
		go func() {
			done <- s.insertEmergencyGuarded(ctx, []map[string]any{emergencyEvent("delayed-diagnostic", "traffic", "2020-01-01", "partial")})
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("INSERT not dispatched")
		}
		var count int
		if e := s.PG.QueryRow(ctx, "SELECT count(*) FROM storage_emergency_inserts").Scan(&count); e != nil || count != 1 {
			t.Fatal("reservation not durable before HTTP", e)
		}
		if _, e := s.PG.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype='advisory' AND mode='ShareLock' AND granted AND pid<>pg_backend_pid()"); e != nil {
			t.Fatal(e)
		}
		ch := &pressureCH{ClickHouse: actual, pressure: true}
		if e := s.emergencyStep(ctx, ch, time.Now()); e != nil {
			t.Fatal(e)
		}
		if ch.calls != 0 || testView(t, s, ctx).Status.InsertExclusions != 1 {
			t.Fatal("purged in-flight reservation")
		}
		resumeInsert()
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		found, e := actual.Rows(ctx, "SELECT id,raw FROM nebulalog.events ORDER BY id", nil)
		if e != nil || len(found) != 2 {
			t.Fatal("delayed diagnostic lost", e)
		}
		if e = s.emergencyStep(ctx, ch, time.Now()); e != nil {
			t.Fatal(e)
		}
		if ch.calls != 0 {
			t.Fatal("late diagnostic removed")
		}
	})
}
