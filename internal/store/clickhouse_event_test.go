package store

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestEventReadProfileIsScopedAndPreservesPayload(t *testing.T) {
	requests := make(chan url.Values, 5)
	const payload = `{"id":"event","raw":"original\\line\n","raw_base64":"AP8=","fields":{"unrecognized":"kept"},"extra_fields":["extra"],"bytes":18446744073709551615}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Query()
		_, _ = io.WriteString(w, payload+"\n")
	}))
	defer server.Close()
	// Explicit endpoint defaults make accidental profile leakage observable.
	client := NewClickHouse(server.URL+"?max_threads=9&max_block_size=65536", "reader", "password")
	originalTimeout := client.Client.Timeout
	tests := []struct {
		name                              string
		call                              func() error
		threads, block, seconds, buffered string
	}{
		{"event", func() error {
			rows, err := client.EventRows(context.Background(), "SELECT * FROM events", map[string]string{"filter": "quoted' value"})
			if err == nil {
				if len(rows) != 1 || rows[0]["bytes"] != json.Number("18446744073709551615") || rows[0]["raw"] != "original\\line\n" || rows[0]["raw_base64"] != "AP8=" || !reflect.DeepEqual(rows[0]["fields"], map[string]any{"unrecognized": "kept"}) || !reflect.DeepEqual(rows[0]["extra_fields"], []any{"extra"}) {
					t.Fatal("event profile changed full event payload or integer precision")
				}
			}
			return err
		}, "2", "8192", "30", "1"},
		{"analytics", func() error {
			_, err := client.Rows(context.Background(), "SELECT count() FROM events", nil)
			return err
		}, "9", "65536", "30", "1"},
		{"ordinary query", func() error { return client.Exec(context.Background(), "SELECT 1", nil) }, "9", "65536", "30", "1"},
		{"ingestion", func() error { return client.InsertRows(context.Background(), []map[string]any{{"id": "new-event"}}) }, "9", "65536", "30", "1"},
		{"export", func() error {
			return client.Stream(context.Background(), "SELECT * FROM events", nil, func(map[string]any) error { return nil })
		}, "2", "8192", "1800", "0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err != nil {
				t.Fatal(err)
			}
			settings := <-requests
			for key, want := range map[string]string{"max_threads": test.threads, "max_block_size": test.block, "max_execution_time": test.seconds, "wait_end_of_query": test.buffered, "max_memory_usage": "536870912", "buffer_size": "1048576"} {
				if settings.Get(key) != want {
					t.Errorf("%s = %q, want %q", key, settings.Get(key), want)
				}
			}
			if test.name == "event" && settings.Get("param_filter") != "quoted' value" {
				t.Fatal("event parameter binding changed")
			}
			if test.name == "export" {
				if settings.Get("max_bytes_before_external_sort") != "134217728" || settings.Get("max_temporary_data_on_disk_size_for_query") != "1073741824" {
					t.Fatal("export spill budget changed")
				}
			} else if settings.Has("max_bytes_before_external_sort") || settings.Has("max_temporary_data_on_disk_size_for_query") {
				t.Fatal("export spill settings leaked into another profile")
			}
			if client.Client.Timeout != originalTimeout {
				t.Fatal("query profile mutated the shared HTTP client")
			}
		})
	}
}

// This read-only fixture verifies that ClickHouse accepts the bounded profile
// and returns the same complete wide records. It does not reproduce MergeTree
// memory pressure; that requires the retained real-table before/after queries.
func TestEventRowsWideReadClickHouse(t *testing.T) {
	endpoint := os.Getenv("NEBULALOG_TEST_CH_URL")
	if endpoint == "" {
		t.Skip("set NEBULALOG_TEST_CH_URL for read-only wide event profile comparison")
	}
	client := NewClickHouse(endpoint, os.Getenv("NEBULALOG_TEST_CH_USER"), os.Getenv("NEBULALOG_TEST_CH_PASSWORD"))
	const sql = `SELECT leftPad(toString(number),8,'0') AS id, number%7 AS bytes,
	 repeat('r',8192) AS raw, map('wide',repeat('m',4096)) AS fields,
	 [repeat('e',1024)] AS extra_fields, 'AP8=' AS raw_base64
	 FROM numbers(1001) ORDER BY bytes DESC,id ASC LIMIT {limit:UInt32}`
	for _, limit := range []int{1, 200, 1000} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			params := map[string]string{"limit": strconv.Itoa(limit)}
			ordinary, err := client.Rows(context.Background(), sql, params)
			if err != nil {
				t.Fatal(err)
			}
			bounded, err := client.EventRows(context.Background(), sql, params)
			if err != nil {
				t.Fatal(err)
			}
			if len(bounded) != limit || !reflect.DeepEqual(ordinary, bounded) {
				t.Fatal("bounded event read changed rows, fields or ordering")
			}
			if bounded[0]["raw"] != strings.Repeat("r", 8192) {
				t.Fatal("wide payload was truncated")
			}
		})
	}
}
