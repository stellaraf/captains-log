package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ClickHouse struct {
	URL, User, Password string
	Client              *http.Client
}

type clickHouseQueryIDKey struct{}

type queryProfile uint8

const (
	queryDefault queryProfile = iota
	queryEventRead
	queryExport
)

func NewClickHouse(endpoint, user, password string) *ClickHouse {
	return &ClickHouse{endpoint, user, password, &http.Client{Timeout: 45 * time.Second}}
}

// Query binds all literals independently from the trusted SQL program.
func (c *ClickHouse) Query(ctx context.Context, sql string, params map[string]string) (io.ReadCloser, error) {
	return c.request(ctx, sql, params, nil, queryDefault)
}
func (c *ClickHouse) request(ctx context.Context, sql string, params map[string]string, data io.Reader, profile queryProfile) (io.ReadCloser, error) {
	u, e := url.Parse(c.URL)
	if e != nil {
		return nil, e
	}
	q := u.Query()
	q.Set("database", "nebulalog")
	if id, ok := ctx.Value(clickHouseQueryIDKey{}).(string); ok {
		q.Set("query_id", id)
	}
	if strings.HasPrefix(strings.TrimSpace(sql), "CREATE DATABASE") {
		q.Set("database", "default")
	}
	q.Set("date_time_input_format", "best_effort")
	q.Set("date_time_output_format", "iso")
	q.Set("output_format_json_quote_64bit_integers", "0")
	q.Set("max_execution_time", "30")
	q.Set("max_memory_usage", "536870912")
	q.Set("wait_end_of_query", "1")
	q.Set("buffer_size", "1048576")
	stream := profile == queryExport
	if profile == queryEventRead || stream {
		// Wide event maps can exhaust the query budget while reading blocks,
		// even when the final page is small. Bound those readers without
		// changing analytics or ingestion defaults or raising the memory cap.
		q.Set("max_threads", "2")
		q.Set("max_block_size", "8192")
	}
	if stream {
		// Exports are bounded by their context and disk quota, not the interactive
		// query timeout. Stream directly instead of buffering the whole result on
		// the ClickHouse server. A late exception fails JSON decoding and the
		// caller discards the incomplete export.
		q.Set("max_execution_time", "1800")
		q.Set("wait_end_of_query", "0")
		// Broad/category-crossing exports may sort outside the primary key.
		// Spill before the 512 MiB query limit, with bounded temporary disk use.
		q.Set("max_bytes_before_external_sort", "134217728")
		q.Set("max_temporary_data_on_disk_size_for_query", "1073741824")
	}
	for k, v := range params {
		q.Set("param_"+k, strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r", "\x00", "\\0").Replace(v))
	}
	var body io.Reader = strings.NewReader(sql)
	if data != nil {
		q.Set("query", sql)
		body = data
	}
	u.RawQuery = q.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if e != nil {
		return nil, e
	}
	req.SetBasicAuth(c.User, c.Password)
	req.Header.Set("Content-Type", "text/plain")
	client := c.Client
	if stream {
		copy := *c.Client
		copy.Timeout = 0 // the Stream context supplies the absolute deadline
		client = &copy
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	if resp.StatusCode != 200 || resp.Header.Get("X-ClickHouse-Exception-Code") != "" {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("clickhouse query failed (%d): %s", resp.StatusCode, b)
	}
	return resp.Body, nil
}
func (c *ClickHouse) Exec(ctx context.Context, sql string, params map[string]string) error {
	r, e := c.Query(ctx, sql, params)
	if e != nil {
		return e
	}
	defer r.Close()
	_, e = io.Copy(io.Discard, r)
	return e
}

// An ambiguous response must never be retried as the same destructive action.
// query_id is diagnostic identity, not a server-side idempotency key.
func (c *ClickHouse) ExecWithQueryID(ctx context.Context, sql string, params map[string]string, id string) error {
	if !emergencyUUID.MatchString(id) {
		return errors.New("invalid query identity")
	}
	return c.Exec(context.WithValue(ctx, clickHouseQueryIDKey{}, id), sql, params)
}
func (c *ClickHouse) InsertRowsWithQueryID(ctx context.Context, rows []map[string]any, id string) error {
	if !emergencyUUID.MatchString(id) {
		return errors.New("invalid query identity")
	}
	return c.InsertRows(context.WithValue(ctx, clickHouseQueryIDKey{}, id), rows)
}

func (c *ClickHouse) Rows(ctx context.Context, sql string, params map[string]string) ([]map[string]any, error) {
	return c.rows(ctx, sql, params, queryDefault)
}

// EventRows bounds wide reads for paginated logs and individual event details.
// It preserves every selected field and the ordinary complete-response budget.
func (c *ClickHouse) EventRows(ctx context.Context, sql string, params map[string]string) ([]map[string]any, error) {
	return c.rows(ctx, sql, params, queryEventRead)
}

func (c *ClickHouse) rows(ctx context.Context, sql string, params map[string]string, profile queryProfile) ([]map[string]any, error) {
	r, e := c.request(ctx, sql+" FORMAT JSONEachRow", params, nil, profile)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	rows := make([]map[string]any, 0)
	d := json.NewDecoder(r)
	d.UseNumber()
	for {
		var row map[string]any
		e = d.Decode(&row)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return nil, e
		}
		rows = append(rows, row)
	}
	return rows, nil
}
func (c *ClickHouse) Stream(ctx context.Context, sql string, params map[string]string, fn func(map[string]any) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	r, e := c.request(ctx, sql+" FORMAT JSONEachRow", params, nil, queryExport)
	if e != nil {
		return e
	}
	defer r.Close()
	d := json.NewDecoder(bufio.NewReaderSize(r, 65536))
	d.UseNumber()
	for {
		var row map[string]any
		e = d.Decode(&row)
		if errors.Is(e, io.EOF) {
			return nil
		}
		if e != nil {
			return e
		}
		if e = fn(row); e != nil {
			return e
		}
	}
}
func (c *ClickHouse) InsertRows(ctx context.Context, rows []map[string]any) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, row := range rows {
		if e := enc.Encode(row); e != nil {
			return e
		}
	}
	r, e := c.request(ctx, "INSERT INTO events FORMAT JSONEachRow", nil, &b, queryDefault)
	if e != nil {
		return e
	}
	defer r.Close()
	_, e = io.Copy(io.Discard, r)
	return e
}
func (c *ClickHouse) Ping(ctx context.Context) error { return c.Exec(ctx, "SELECT 1", nil) }
