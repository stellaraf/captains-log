package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stellaraf/captains-log/internal/store"
)

func TestRetentionRoutesRequireAdministratorAndExistingDataConfirmation(t *testing.T) {
	h := newHostPlanHarness(t)
	for _, method := range []string{"GET", "PUT"} {
		if w := h.request(method, "/api/retention", "{}", "", nil); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	for _, role := range []string{"VIEWER", "ANALYST"} {
		token := h.token(t, func(c map[string]any) {
			c["resource_access"] = map[string]any{"nebulalog": map[string]any{"roles": []string{role}}}
		})
		if w := h.request("PUT", "/api/retention", `{"expected_revision":1,"apply_existing":true,"global_days":30,"per_type":{}}`, token, nil); w.Code != 403 {
			t.Fatal(role, w.Code)
		}
	}
	for _, body := range []string{
		`{}`, `{"global_days":30,"per_type":{}}`,
		`{"expected_revision":1,"apply_existing":false,"global_days":30,"per_type":{}}`,
		`{"expected_revision":1,"apply_existing":true,"global_days":30.5,"per_type":{}}`,
		`{"expected_revision":1,"apply_existing":true,"global_days":0,"per_type":{}}`,
		`{"expected_revision":1,"apply_existing":true,"global_days":90,"per_type":{"alarms":7,"system":365}}`,
		`{"expected_revision":1,"apply_existing":true,"global_days":90,"per_type":{"unified":7}}`,
		`{"expected_revision":1,"apply_existing":true,"global_days":90,"force":true}`,
	} {
		if w := h.request("PUT", "/api/retention", body, h.token(t, nil), nil); w.Code != 400 {
			t.Fatal(body, w.Code)
		}
	}
	v := retentionUpdate{ExpectedRevision: 7, GlobalDays: 123, PerType: map[string]int{"alarms": 60}, ApplyExisting: true}
	p, err := v.policy()
	if err != nil || p.Revision != 7 || p.PerType["system"] != 60 {
		t.Fatal(p, err)
	}
}

func TestRetentionChangedCursorAndUnavailableEngineCannotReadEvents(t *testing.T) {
	in := Search{LogType: "traffic", Sort: "received_at", Order: "desc", From: "2026-10-01T00:00:00Z", To: "2026-10-19T00:00:00Z"}
	raw, _ := json.Marshal(cursor{Value: "2026-10-18T00:00:00Z", ID: strings.Repeat("1", 32), From: in.From, To: in.To, Signature: signature(in), RetentionRevision: 4})
	query := url.Values{"type": {"traffic"}, "cursor": {base64.RawURLEncoding.EncodeToString(raw)}}
	s := &Server{retentionRead: func(_ context.Context, now time.Time) (store.Retention, string, map[string]string, error) {
		p := store.Retention{Revision: 5, GlobalDays: 30}
		sql, args, err := p.Predicate(now)
		return p, sql, args, err
	}}
	w := httptest.NewRecorder()
	s.logs(w, httptest.NewRequest(http.MethodGet, "/api/logs?"+query.Encode(), nil))
	if w.Code != 409 {
		t.Fatal("changed policy reused old cursor", w.Code, w.Body.String())
	}
	s.retentionRead = func(context.Context, time.Time) (store.Retention, string, map[string]string, error) {
		return store.Retention{}, "", nil, store.ErrRetentionHeld
	}
	w = httptest.NewRecorder()
	s.logs(w, httptest.NewRequest(http.MethodGet, "/api/logs?type=traffic", nil))
	if w.Code != 503 {
		t.Fatal("held engine returned rows", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/events/id?type=system&at=2026-10-18T00:00:00Z", nil)
	r.SetPathValue("id", strings.Repeat("1", 32))
	w = httptest.NewRecorder()
	s.event(w, r)
	if w.Code != 503 {
		t.Fatal("detail bypassed migration", w.Code)
	}
}
