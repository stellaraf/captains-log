package api

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stellaraf/captains-log/internal/store"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEmergencyRoutesRequireSignedSessionAndAdministrator(t *testing.T) {
	h := newHostPlanHarness(t)
	for _, method := range []string{"GET", "PUT"} {
		w := h.request(method, "/api/storage/emergency", "{}", "", nil)
		if w.Code != 401 {
			t.Fatal(method, w.Code)
		}
	}
	for _, role := range []string{"VIEWER", "ANALYST"} {
		token := h.token(t, func(c map[string]any) {
			c["resource_access"] = map[string]any{"nebulalog": map[string]any{"roles": []string{role}}}
		})
		w := h.request("PUT", "/api/storage/emergency", "{}", token, nil)
		if w.Code != 403 {
			t.Fatal(role, w.Code)
		}
	}
	for _, body := range []string{`{}`, `{"expected_revision":1,"trigger_percent":95,"recover_percent":90,"minimum_days":{"traffic":0}}`, `{"expected_revision":1,"enabled":true,"trigger_percent":100,"recover_percent":90,"minimum_days":{}}`, `{"expected_revision":1,"unknown":true}`} {
		w := h.request("PUT", "/api/storage/emergency", body, h.token(t, nil), nil)
		if w.Code != 400 {
			t.Fatal(body, w.Code)
		}
	}
}

// Only the explicitly provisioned disposable metadata database is eligible.
func TestEmergencyPolicyHTTPIsolatedPostgres(t *testing.T) {
	if os.Getenv("NEBULALOG_EMERGENCY_DESTRUCTIVE_TEST") != "1" {
		t.Skip("isolated PostgreSQL fixture not enabled")
	}
	raw, e := os.ReadFile(os.Getenv("NEBULALOG_EMERGENCY_TEST_CONFIG"))
	if e != nil {
		t.Fatal("private test configuration unavailable")
	}
	var cfg struct {
		DSN string `json:"pg_dsn"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("invalid test configuration")
	}
	pc, e := pgxpool.ParseConfig(cfg.DSN)
	if e != nil || pc.ConnConfig.Host != "127.0.0.1" || pc.ConnConfig.Database != "emergency_test" || pc.ConnConfig.User != "emergency_test" {
		t.Fatal("nonfixture database refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	schema := "emergency_api_" + strings.ReplaceAll(uuid(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+quoted); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
	pc.ConnConfig.RuntimeParams["search_path"] = schema
	pg, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	defer pg.Close()
	migration, e := os.ReadFile("../../migrations/postgres.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pg.Exec(ctx, string(migration)); e != nil {
		t.Fatal(e)
	}
	h := newHostPlanHarness(t)
	h.server.Store = &store.Store{PG: pg}
	viewer := h.token(t, func(c map[string]any) {
		c["resource_access"] = map[string]any{"nebulalog": map[string]any{"roles": []string{"VIEWER"}}}
	})
	w := h.request("GET", "/api/storage/emergency", "", viewer, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var value store.EmergencyView
	if e = json.Unmarshal(w.Body.Bytes(), &value); e != nil {
		t.Fatal(e)
	}
	if value.Policy.Revision != 1 || len(value.Policy.MinimumDays) != 15 || value.Status.State != "not_observed" || value.RecentActions == nil {
		t.Fatal("API contract", value)
	}
	payload := map[string]any{"expected_revision": 1, "enabled": false, "trigger_percent": 97, "recover_percent": 89, "minimum_days": value.Policy.MinimumDays}
	body, _ := json.Marshal(payload)
	w = h.request("PUT", "/api/storage/emergency", string(body), h.token(t, nil), nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var actor string
	if e = pg.QueryRow(ctx, "SELECT actor FROM audit_events WHERE action='storage.emergency.policy'").Scan(&actor); e != nil || actor != "private-synthetic-subject" {
		t.Fatal("signed actor not audited", e)
	}
	w = h.request("PUT", "/api/storage/emergency", string(body), h.token(t, nil), nil)
	if w.Code != 409 {
		t.Fatal("stale edit accepted", w.Code)
	}
	if _, e = pg.Exec(ctx, "INSERT INTO storage_emergency_actions(id,state,plan) VALUES($1,'executing','{}')", uuid()); e != nil {
		t.Fatal(e)
	}
	payload["expected_revision"] = 2
	body, _ = json.Marshal(payload)
	w = h.request("PUT", "/api/storage/emergency", string(body), h.token(t, nil), nil)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "unresolved") {
		t.Fatal("pending conflict not distinguished", w.Code, w.Body.String())
	}
}
