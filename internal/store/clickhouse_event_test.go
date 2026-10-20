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
		body, _ := io.ReadAll(r.Body)
		if string(body) == pageCapabilitiesSQL {
			_, _ = io.WriteString(w, pageCapabilitiesResponse)
			return
		}
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
		{"page", func() error {
			rows, err := client.EventPageRows(context.Background(), "SELECT * FROM events ORDER BY received_at DESC,id DESC LIMIT {limit:UInt32}", map[string]string{"limit": "1001"})
			if err == nil && (len(rows) != 1 || rows[0]["bytes"] != json.Number("18446744073709551615") || rows[0]["raw_base64"] != "AP8=") {
				t.Fatal("page profile changed event payload or integer precision")
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
			if test.name == "page" {
				if settings.Get("max_bytes_before_remerge_sort") != "67108864" || settings.Get("read_in_order_use_buffering") != "0" {
					t.Fatal("page sort or ordered-read buffers can exceed the query budget")
				}
				if settings.Get("query_plan_optimize_lazy_materialization") != "1" || settings.Get("query_plan_max_limit_for_lazy_materialization") != "1001" || settings.Get("param_limit") != "1001" {
					t.Fatal("page payload deferral or lookahead binding changed")
				}
			} else if settings.Has("query_plan_optimize_lazy_materialization") || settings.Has("query_plan_max_limit_for_lazy_materialization") {
				t.Fatal("page optimization leaked into another query profile")
			}
			if test.name != "page" && (settings.Has("max_bytes_before_remerge_sort") || settings.Has("read_in_order_use_buffering")) {
				t.Fatal("page memory settings changed another query profile")
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
			page, err := client.EventPageRows(context.Background(), sql, params)
			if err != nil || !reflect.DeepEqual(ordinary, page) {
				t.Fatalf("page optimization changed complete rows: %v", err)
			}
			if bounded[0]["raw"] != strings.Repeat("r", 8192) {
				t.Fatal("wide payload was truncated")
			}
		})
	}
}

// This read-only regression produces enough distinct wide sort keys to exercise
// bounded top-N remerging, without creating or modifying a database table.
// Expected rows and cursor boundaries are derived from the numeric sequence,
// independently of ClickHouse's sorting implementation.
func TestEventPageRowsWideSortClickHouse(t *testing.T) {
	endpoint := os.Getenv("NEBULALOG_TEST_CH_URL")
	if endpoint == "" {
		t.Skip("set NEBULALOG_TEST_CH_URL for read-only wide sort and cursor regression")
	}
	client := NewClickHouse(endpoint, os.Getenv("NEBULALOG_TEST_CH_USER"), os.Getenv("NEBULALOG_TEST_CH_PASSWORD"))
	const count = 1000000
	const selectSQL = `SELECT toString(number) AS id, number AS bytes,
	 concat('raw-',toString(number)) AS raw, map('index',toString(number)) AS fields,
	 [toString(number)] AS extra_fields,
	 concat(leftPad(toString(1000000-number),7,'0'),repeat('r',900)) AS raw_base64
	 FROM numbers(1000000)`
	for _, direction := range []string{"ASC", "DESC"} {
		t.Run(direction, func(t *testing.T) {
			var previous []map[string]any
			for _, offset := range []int{0, 1000} {
				params := map[string]string{"limit": "1001"}
				filter := ""
				if offset != 0 {
					last := previous[999]
					params["cursor_key"] = last["raw_base64"].(string)
					params["cursor_id"] = last["id"].(string)
					op := ">"
					if direction == "DESC" {
						op = "<"
					}
					filter = " WHERE (raw_base64,id) " + op + " ({cursor_key:String},{cursor_id:String})"
				}
				rows, err := client.EventPageRows(context.Background(), selectSQL+filter+" ORDER BY raw_base64 "+direction+",id "+direction+" LIMIT {limit:UInt32}", params)
				if err != nil || len(rows) != 1001 {
					t.Fatalf("wide page offset %d: rows=%d err=%v", offset, len(rows), err)
				}
				for i, row := range rows {
					number := offset + i
					if direction == "ASC" {
						number = count - 1 - number
					}
					id := strconv.Itoa(number)
					key := strconv.Itoa(count - number)
					key = strings.Repeat("0", 7-len(key)) + key + strings.Repeat("r", 900)
					want := map[string]any{"id": id, "bytes": json.Number(id), "raw": "raw-" + id, "fields": map[string]any{"index": id}, "extra_fields": []any{id}, "raw_base64": key}
					if !reflect.DeepEqual(row, want) {
						t.Fatalf("wide sort/cursor changed complete row at offset %d index %d", offset, i)
					}
				}
				if offset != 0 && !reflect.DeepEqual(previous[1000], rows[0]) {
					t.Fatal("cursor did not preserve the lookahead boundary")
				}
				previous = rows
			}
		})
	}
}
