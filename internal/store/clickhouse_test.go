package store

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStreamUsesExportBudgetAndDoesNotBufferAtServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("wait_end_of_query") != "0" || r.URL.Query().Get("max_execution_time") != "1800" {
			t.Errorf("unexpected stream settings: %s", r.URL.RawQuery)
		}
		if r.URL.Query().Get("max_bytes_before_external_sort") != "134217728" || r.URL.Query().Get("max_temporary_data_on_disk_size_for_query") != "1073741824" {
			t.Errorf("export sort lacks memory/disk bounds")
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(35 * time.Millisecond)
		_, _ = w.Write([]byte("{\"id\":\"event\"}\n"))
	}))
	defer server.Close()
	client := NewClickHouse(server.URL, "reader", "password")
	client.Client.Timeout = 10 * time.Millisecond
	count := 0
	err := client.Stream(context.Background(), "SELECT id FROM events", nil, func(row map[string]any) error { count++; return nil })
	if err != nil || count != 1 {
		t.Fatalf("stream inherited interactive timeout: count=%d error=%v", count, err)
	}
	if client.Client.Timeout != 10*time.Millisecond {
		t.Fatal("stream mutated shared HTTP client timeout")
	}
}

func TestInteractiveQueryKeepsCompleteResponseSetting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("wait_end_of_query") != "1" || r.URL.Query().Get("max_execution_time") != "30" {
			t.Errorf("interactive settings changed: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte("{\"id\":\"event\"}\n"))
	}))
	defer server.Close()
	client := NewClickHouse(server.URL, "reader", "password")
	if _, err := client.Rows(context.Background(), "SELECT id FROM events", nil); err != nil {
		t.Fatal(err)
	}
}

func TestStreamLateDatabaseExceptionIsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{\"id\":\"event\"}\nCode: 241. Memory limit exceeded"))
	}))
	defer server.Close()
	client := NewClickHouse(server.URL, "reader", "password")
	if err := client.Stream(context.Background(), "SELECT id FROM events", nil, func(map[string]any) error { return nil }); err == nil {
		t.Fatal("late server exception was treated as complete export")
	}
}

func TestStreamHonorsCancellationAndConsumerFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("{\"id\":\"event\"}\n", 3)))
	}))
	defer server.Close()
	client := NewClickHouse(server.URL, "reader", "password")
	consumerErr := errors.New("export quota reached")
	if err := client.Stream(context.Background(), "SELECT id FROM events", nil, func(map[string]any) error { return consumerErr }); !errors.Is(err, consumerErr) {
		t.Fatalf("lost consumer failure: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Stream(ctx, "SELECT id FROM events", nil, func(map[string]any) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
}
