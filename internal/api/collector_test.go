package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stellaraf/captains-log/internal/ingest"
)

func TestSeparateCollectorStatsAndMetricsFailClosedWhenStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.json")
	s := &Server{Config: Config{CollectorStatusPath: path}}
	observed := ingest.Stats{MessagesReceived: 42, EventsInserted: 40, QueueDepth: 2,
		Listeners: []ingest.ListenerStatus{{Transport: "tcp", Address: ":514", Status: "listening"}}}
	if err := ingest.WriteStatus(path, observed, time.Now()); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	s.stats(w, r)
	var actual ingest.Stats
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &actual) != nil || actual.MessagesReceived != 42 || actual.QueueDepth != 2 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.metrics(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "nebulalog_events_inserted 40\n") {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := ingest.WriteStatus(path, observed, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, handler := range []func(*httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) { s.stats(w, r) },
		func(w *httptest.ResponseRecorder) { s.metrics(w, r) },
	} {
		w = httptest.NewRecorder()
		handler(w)
		if w.Code != 503 {
			t.Fatal("stale counters returned as healthy", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "42") {
			t.Fatal("stale counters leaked", w.Body.String())
		}
	}
}
