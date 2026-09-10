package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stellaraf/captains-log/internal/store"
)

type eventReadRequest struct {
	SQL    string
	Params url.Values
}

func requireEventReadBudget(t *testing.T, request eventReadRequest) {
	t.Helper()
	for key, want := range map[string]string{"max_threads": "2", "max_block_size": "8192", "max_memory_usage": "536870912", "max_execution_time": "30", "wait_end_of_query": "1"} {
		if request.Params.Get(key) != want {
			t.Errorf("%s = %q, want %q", key, request.Params.Get(key), want)
		}
	}
	if !strings.HasPrefix(request.SQL, "SELECT * EXCEPT expires_at FROM events WHERE ") || !strings.HasSuffix(request.SQL, " FORMAT JSONEachRow") {
		t.Fatal("event read changed selected payload fields or response format")
	}
}

func TestLogPagesUseEventBudgetAndPreserveCursorContract(t *testing.T) {
	for _, test := range []struct {
		sort, order string
		limit       int
	}{
		{"received_at", "desc", 1}, {"received_at", "asc", 200},
		{"bytes", "desc", 1000}, {"bytes", "asc", 1},
		{"src_ip", "desc", 200}, {"src_ip", "asc", 1000},
	} {
		t.Run(fmt.Sprintf("%s/%s/%d", test.sort, test.order, test.limit), func(t *testing.T) {
			requests := make(chan eventReadRequest, 2)
			rows := make([]map[string]any, 2*test.limit+1)
			for i := range rows {
				id := i + 1
				if test.order == "desc" {
					id = len(rows) - i
				}
				rows[i] = map[string]any{"id": fmt.Sprintf("%032x", id), "received_at": "2026-09-08T10:00:00.123456Z", "bytes": 7, "src_ip": "192.0.2.1", "log_type": "dns", "wire_type": "THREAT", "raw": "preserved event", "raw_base64": "AP8=", "fields": map[string]string{"unrecognized": "kept"}, "extra_fields": []string{"extra"}}
			}
			ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				params := r.URL.Query()
				requests <- eventReadRequest{string(body), params}
				start := 0
				if params.Get("param_cursor_id") != "" {
					start = test.limit
				}
				encoder := json.NewEncoder(w)
				for _, row := range rows[start : start+test.limit+1] {
					_ = encoder.Encode(row)
				}
			}))
			defer ch.Close()
			server := &Server{Store: &store.Store{CH: store.NewClickHouse(ch.URL, "reader", "password")}}
			values := url.Values{"type": {"threat"}, "query": {"action eq alert"}, "from": {"2026-09-01T00:00:00Z"}, "to": {"2026-09-08T12:00:00Z"}, "sort": {test.sort}, "order": {test.order}, "limit": {strconv.Itoa(test.limit)}}
			read := func() (map[string]any, eventReadRequest) {
				recorder := httptest.NewRecorder()
				server.logs(recorder, httptest.NewRequest(http.MethodGet, "/api/logs?"+values.Encode(), nil))
				if recorder.Code != 200 {
					t.Fatalf("page failed: %d", recorder.Code)
				}
				var response map[string]any
				decoder := json.NewDecoder(recorder.Body)
				decoder.UseNumber()
				if err := decoder.Decode(&response); err != nil {
					t.Fatal(err)
				}
				request := <-requests
				requireEventReadBudget(t, request)
				if request.Params.Get("param_limit") != strconv.Itoa(test.limit+1) || request.Params.Get("param_q0") != "alert" {
					t.Fatal("lookahead limit or bound manual filter changed")
				}
				if !strings.Contains(request.SQL, "AND (log_type='threat' OR (log_type='dns' AND wire_type='THREAT'))") || !strings.Contains(request.SQL, " ORDER BY "+test.sort+" "+test.order+", id "+test.order+" LIMIT {limit:UInt32}") {
					t.Fatal("category grouping or deterministic ordering changed")
				}
				events := response["events"].([]any)
				if len(events) != test.limit {
					t.Fatal("page limit or lookahead row handling changed")
				}
				first := events[0].(map[string]any)
				if first["raw"] != "preserved event" || first["raw_base64"] != "AP8=" || first["fields"].(map[string]any)["unrecognized"] != "kept" || len(first["extra_fields"].([]any)) != 1 {
					t.Fatal("page lost full event fields")
				}
				return response, request
			}
			first, _ := read()
			token := first["next_cursor"].(string)
			decoded, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				t.Fatal(err)
			}
			var next cursor
			if err = json.Unmarshal(decoded, &next); err != nil {
				t.Fatal(err)
			}
			if next.ID != rows[test.limit-1]["id"] || next.From != values.Get("from") || next.To != values.Get("to") {
				t.Fatal("cursor did not bind the last displayed row and fixed bounds")
			}
			values.Set("cursor", token)
			values.Set("from", "2000-01-01T00:00:00Z")
			values.Set("to", "2000-01-02T00:00:00Z")
			second, request := read()
			op := "<"
			if test.order == "asc" {
				op = ">"
			}
			if !strings.Contains(request.SQL, "AND ("+test.sort+", id) "+op+" (") || request.Params.Get("param_cursor_id") != next.ID || second["from"] != next.From || second["to"] != next.To {
				t.Fatal("cursor comparator, tie breaker or frozen bounds changed")
			}
			wantValue := fmt.Sprint(rows[test.limit-1][test.sort])
			if test.sort == "received_at" {
				wantValue = "2026-09-08 10:00:00.123456"
			}
			if request.Params.Get("param_cursor_value") != wantValue {
				t.Fatal("cursor sort value lost type or precision")
			}
			values.Set("query", "action eq deny")
			recorder := httptest.NewRecorder()
			server.logs(recorder, httptest.NewRequest(http.MethodGet, "/api/logs?"+values.Encode(), nil))
			if recorder.Code != 400 {
				t.Fatal("cursor was accepted for a different filter")
			}
		})
	}
}

func TestEventDetailUsesEventBudgetAndPreservesFullPayload(t *testing.T) {
	requests := make(chan eventReadRequest, 1)
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- eventReadRequest{string(body), r.URL.Query()}
		_, _ = io.WriteString(w, `{"id":"11111111111111111111111111111111","raw":"preserved","raw_base64":"AP8=","fields":{"extra":"kept"},"extra_fields":["other"]}`+"\n")
	}))
	defer ch.Close()
	server := &Server{Store: &store.Store{CH: store.NewClickHouse(ch.URL, "reader", "password")}}
	request := httptest.NewRequest(http.MethodGet, "/api/events/11111111111111111111111111111111?at=2026-09-08T10:00:00.123456Z&type=dns", nil)
	request.SetPathValue("id", "11111111111111111111111111111111")
	recorder := httptest.NewRecorder()
	server.event(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("detail failed: %d", recorder.Code)
	}
	captured := <-requests
	requireEventReadBudget(t, captured)
	if captured.Params.Get("param_id") != "11111111111111111111111111111111" || captured.Params.Get("param_category") != "dns" || captured.Params.Get("param_from") != "2026-09-08 09:59:59.123456" || captured.Params.Get("param_to") != "2026-09-08 10:00:01.123456" || !strings.Contains(captured.SQL, "LIMIT 1 FORMAT") {
		t.Fatal("detail identity or narrow time bounds changed")
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	event := body["event"].(map[string]any)
	if event["raw"] != "preserved" || event["raw_base64"] != "AP8=" || event["fields"].(map[string]any)["extra"] != "kept" || len(event["extra_fields"].([]any)) != 1 {
		t.Fatal("detail lost full event payload")
	}
}

func TestEventReadFailureDoesNotReturnPartialPage(t *testing.T) {
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{\"id\":\"partial-event\"}\nCode: 241. Memory limit exceeded")
	}))
	defer ch.Close()
	server := &Server{Store: &store.Store{CH: store.NewClickHouse(ch.URL, "reader", "password")}}
	recorder := httptest.NewRecorder()
	server.logs(recorder, httptest.NewRequest(http.MethodGet, "/api/logs?type=traffic", nil))
	if recorder.Code != 503 || strings.Contains(recorder.Body.String(), "partial-event") || strings.Contains(recorder.Body.String(), "241") || strings.Contains(recorder.Body.String(), "events") {
		t.Fatal("incomplete database response was exposed as a partial successful page")
	}
}
