package store

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPageCapabilitiesRequireBothExactSettings(t *testing.T) {
	for _, test := range []struct {
		name, response string
		status         int
		exception      bool
		want           bool
	}{
		{"both", pageCapabilitiesResponse, 200, false, true},
		{"neither", "", 200, false, false},
		{"flag only", "query_plan_optimize_lazy_materialization\n", 200, false, false},
		{"threshold only", "query_plan_max_limit_for_lazy_materialization\n", 200, false, false},
		{"duplicate", pageCapabilitiesResponse + "query_plan_optimize_lazy_materialization\n", 200, false, false},
		{"foreign", strings.ReplaceAll(pageCapabilitiesResponse, "optimize_lazy", "other_lazy"), 200, false, false},
		{"malformed", "{broken", 200, false, false},
		{"oversized", pageCapabilitiesResponse + strings.Repeat(" ", 8192), 200, false, false},
		{"denied", "denied", 403, false, false},
		{"exception header", pageCapabilitiesResponse, 200, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var probes, pages atomic.Int32
			const sql = "SELECT * EXCEPT expires_at FROM events WHERE raw_base64={raw:String} ORDER BY raw_base64 DESC,id DESC LIMIT {limit:UInt32}"
			params := map[string]string{"raw": "AP8=", "limit": "1001"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				q := r.URL.Query()
				if string(body) == pageCapabilitiesSQL {
					probes.Add(1)
					if q.Has("query_id") || q.Has("query_plan_optimize_lazy_materialization") || q.Has("query_plan_max_limit_for_lazy_materialization") || q.Get("max_execution_time") != "1" || q.Get("max_threads") != "1" {
						t.Error("capability probe depends on optional settings or lacks its bound")
					}
					if test.exception {
						w.Header().Set("X-ClickHouse-Exception-Code", "115")
					}
					w.WriteHeader(test.status)
					_, _ = io.WriteString(w, test.response)
					return
				}
				pages.Add(1)
				if string(body) != sql+" FORMAT JSONEachRow" || q.Get("param_raw") != params["raw"] || q.Get("param_limit") != params["limit"] || q.Get("query_id") != "page-diagnostic-id" {
					t.Error("probe changed page SQL, supported sort, or parameter binding")
				}
				for key, want := range map[string]string{"max_memory_usage": "536870912", "max_execution_time": "30", "max_threads": "2", "max_block_size": "8192", "wait_end_of_query": "1"} {
					if q.Get(key) != want {
						t.Errorf("page %s=%q, want %q", key, q.Get(key), want)
					}
				}
				if test.want {
					if q.Get("query_plan_optimize_lazy_materialization") != "1" || q.Get("query_plan_max_limit_for_lazy_materialization") != "1001" {
						t.Error("both supported settings were not enabled")
					}
				} else if q.Has("query_plan_optimize_lazy_materialization") || q.Has("query_plan_max_limit_for_lazy_materialization") {
					t.Error("optional settings were sent without exact support")
				}
				_, _ = io.WriteString(w, "{\"id\":\"unchanged\",\"raw_base64\":\"AP8=\"}\n")
			}))
			defer server.Close()
			client := NewClickHouse(server.URL, "reader", "password")
			rows, err := client.EventPageRows(context.WithValue(context.Background(), clickHouseQueryIDKey{}, "page-diagnostic-id"), sql, params)
			if err != nil || !reflect.DeepEqual(rows, []map[string]any{{"id": "unchanged", "raw_base64": "AP8="}}) || probes.Load() != 1 || pages.Load() != 1 {
				t.Fatalf("page fallback or result changed: rows=%v err=%v probes=%d pages=%d", rows, err, probes.Load(), pages.Load())
			}
		})
	}
}

func TestPageCapabilitiesAreRecheckedAfterFailureOrReplacement(t *testing.T) {
	responses := []string{pageCapabilitiesResponse, "", "error", pageCapabilitiesResponse}
	var probes, pages int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) == pageCapabilitiesSQL {
			response := responses[probes]
			probes++
			if response == "error" {
				w.WriteHeader(503)
			}
			_, _ = io.WriteString(w, response)
			return
		}
		want := responses[pages] == pageCapabilitiesResponse
		pages++
		if r.URL.Query().Has("query_plan_optimize_lazy_materialization") != want {
			t.Error("stale capability reused across requests")
		}
		_, _ = io.WriteString(w, "{\"id\":\"ok\"}\n")
	}))
	defer server.Close()
	client := NewClickHouse(server.URL, "", "")
	for range responses {
		if _, err := client.EventPageRows(context.Background(), "SELECT id FROM events LIMIT 1", nil); err != nil {
			t.Fatal(err)
		}
	}
	if probes != 4 || pages != 4 {
		t.Fatal("sequential requests did not refresh capabilities")
	}
}

type pageWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *pageWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestPageCapabilitiesCoalesceAndWaiterCancellationIsIndependent(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var probes, pages atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) == pageCapabilitiesSQL {
			probes.Add(1)
			close(started)
			<-release
			_, _ = io.WriteString(w, pageCapabilitiesResponse)
			return
		}
		pages.Add(1)
		if r.URL.Query().Get("query_plan_max_limit_for_lazy_materialization") != "1001" {
			t.Error("shared successful probe lost capability")
		}
		_, _ = io.WriteString(w, "{\"id\":\"ok\"}\n")
	}))
	defer server.Close()
	client := NewClickHouse(server.URL, "", "")
	result := make(chan error, 9)
	call := func(ctx context.Context) {
		_, err := client.EventPageRows(ctx, "SELECT id FROM events LIMIT 1", nil)
		result <- err
	}
	go call(context.Background())
	<-started
	for range 7 {
		ctx := &pageWaitContext{Context: context.Background(), waiting: make(chan struct{})}
		go call(ctx)
		<-ctx.waiting
	}
	cancelled, cancel := context.WithCancel(context.Background())
	waiter := &pageWaitContext{Context: cancelled, waiting: make(chan struct{})}
	go call(waiter)
	<-waiter.waiting
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter dispatched a page: %v", err)
	}
	close(release)
	for range 8 {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	if probes.Load() != 1 || pages.Load() != 8 {
		t.Fatalf("coalescing failed: probes=%d pages=%d", probes.Load(), pages.Load())
	}
}

func TestPageCapabilitiesLeaderCancellationDoesNotPoisonNextRequest(t *testing.T) {
	started := make(chan struct{})
	var probes, pages atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) == pageCapabilitiesSQL {
			if probes.Add(1) == 1 {
				close(started)
				<-r.Context().Done()
				return
			}
			_, _ = io.WriteString(w, pageCapabilitiesResponse)
			return
		}
		pages.Add(1)
		_, _ = io.WriteString(w, "{\"id\":\"ok\"}\n")
	}))
	defer server.Close()
	client := NewClickHouse(server.URL, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.EventPageRows(ctx, "SELECT id FROM events LIMIT 1", nil); done <- err }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || pages.Load() != 0 {
		t.Fatalf("cancelled leader dispatched a page: %v", err)
	}
	if _, err := client.EventPageRows(context.Background(), "SELECT id FROM events LIMIT 1", nil); err != nil || probes.Load() != 2 || pages.Load() != 1 {
		t.Fatalf("cancelled probe poisoned next request: %v", err)
	}
}

type pageRoundTripper func(*http.Request) (*http.Response, error)

func (f pageRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPageCapabilityTimeoutFallsBackAndPrecancelledDoesNotProbe(t *testing.T) {
	var probes, pages int
	client := NewClickHouse("http://fixture.invalid", "", "")
	client.Client.Transport = pageRoundTripper(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		if string(body) == pageCapabilitiesSQL {
			probes++
			deadline, ok := r.Context().Deadline()
			if !ok || time.Until(deadline) > time.Second {
				t.Fatal("probe has no bounded client deadline")
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		pages++
		if r.URL.Query().Has("query_plan_optimize_lazy_materialization") {
			t.Fatal("timed-out probe enabled optional settings")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{\"id\":\"ok\"}\n"))}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.EventPageRows(ctx, "SELECT id FROM events LIMIT 1", nil); !errors.Is(err, context.Canceled) || probes != 0 || pages != 0 {
		t.Fatal("pre-cancelled request performed network work")
	}
	if _, err := client.EventPageRows(context.Background(), "SELECT id FROM events LIMIT 1", nil); err != nil || probes != 1 || pages != 1 {
		t.Fatalf("bounded probe failure suppressed the page: %v", err)
	}
}
