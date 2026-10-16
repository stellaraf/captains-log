package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/stellaraf/captains-log/internal/query"
	"github.com/stellaraf/captains-log/internal/store"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var categories = map[string]bool{"traffic": true, "threat": true, "url": true, "wildfire": true, "dns": true, "data": true, "hip": true, "globalprotect": true, "iptag": true, "userid": true, "decryption": true, "tunnel": true, "configuration": true, "system": true, "alarms": true, "authentication": true, "unified": true, "parsing": true}

type Search struct {
	Query   string   `json:"query"`
	LogType string   `json:"log_type"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Columns []string `json:"columns"`
	Sort    string   `json:"sort"`
	Order   string   `json:"order"`
}
type cursor struct {
	Value     string `json:"value"`
	ID        string `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Signature string `json:"signature"`
}

func buildSearch(in *Search) (string, map[string]string, error) {
	if in.LogType == "" {
		in.LogType = "traffic"
	}
	if !categories[in.LogType] {
		return "", nil, fmt.Errorf("Unknown log category")
	}
	if in.Sort == "" {
		in.Sort = "received_at"
	}
	typ, ok := store.Columns[in.Sort]
	if !ok || in.Sort == "raw" || in.Sort == "fields" || in.Sort == "extra_fields" || in.Sort == "generated_at" {
		return "", nil, fmt.Errorf("Unsupported sort column")
	}
	_ = typ
	if in.Order == "" {
		in.Order = "desc"
	}
	in.Order = strings.ToLower(in.Order)
	if in.Order != "asc" && in.Order != "desc" {
		return "", nil, fmt.Errorf("Sort order must be asc or desc")
	}
	now := time.Now().UTC()
	if in.To == "" {
		in.To = now.Format(time.RFC3339Nano)
	}
	if in.From == "" {
		in.From = now.Add(-time.Hour).Format(time.RFC3339Nano)
	}
	from, e := time.Parse(time.RFC3339Nano, in.From)
	if e != nil {
		return "", nil, fmt.Errorf("Invalid start timestamp")
	}
	to, e := time.Parse(time.RFC3339Nano, in.To)
	if e != nil || !to.After(from) {
		return "", nil, fmt.Errorf("End time must be after start time")
	}
	if to.Sub(from) > 3660*24*time.Hour {
		return "", nil, fmt.Errorf("Time range exceeds ten years")
	}
	c, e := query.Compile(in.Query)
	if e != nil {
		return "", nil, e
	}
	p := c.Params
	p["from"] = from.UTC().Format("2006-01-02 15:04:05.999999")
	p["to"] = to.UTC().Format("2006-01-02 15:04:05.999999")
	where := "received_at >= {from:DateTime64(6)} AND received_at < {to:DateTime64(6)} AND (" + c.SQL + ")"
	switch in.LogType {
	case "unified":
	case "parsing":
		where += " AND parse_status != 'parsed'"
	case "alarms":
		where += " AND log_type='system' AND severity IN ('critical','high')"
	case "threat":
		// DNS detections use PAN-OS THREAT records and belong in both Monitor
		// views. Preserve the stored DNS category (and its retention policy).
		// Other THREAT wire families such as URL/data remain separate views.
		where += " AND (log_type='threat' OR (log_type='dns' AND wire_type='THREAT'))"
	default:
		p["category"] = in.LogType
		where += " AND log_type={category:String}"
	}
	return where, p, nil
}
func signature(in Search) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(in.Query+"\x00"+in.LogType+"\x00"+in.Sort+"\x00"+in.Order)))
}
func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	v := r.URL.Query()
	in := Search{Query: v.Get("query"), LogType: v.Get("type"), From: v.Get("from"), To: v.Get("to"), Sort: v.Get("sort"), Order: v.Get("order")}
	var cur cursor
	if token := v.Get("cursor"); token != "" {
		if len(token) > 8192 {
			problem(w, 400, "Invalid cursor")
			return
		}
		b, e := base64.RawURLEncoding.DecodeString(token)
		if e != nil || json.Unmarshal(b, &cur) != nil {
			problem(w, 400, "Invalid cursor")
			return
		}
		in.From = cur.From
		in.To = cur.To
	}
	where, p, e := buildSearch(&in)
	if e != nil {
		problem(w, 400, e.Error())
		return
	}
	if cur.ID != "" {
		if cur.Signature != signature(in) {
			problem(w, 400, "Cursor does not belong to this query")
			return
		}
		op := "<"
		if in.Order == "asc" {
			op = ">"
		}
		typ := "String"
		switch store.Columns[in.Sort] {
		case "time":
			typ = "DateTime64(6)"
		case "number":
			typ = "UInt64"
		}
		where += " AND (" + in.Sort + ", id) " + op + " ({cursor_value:" + typ + "}, {cursor_id:String})"
		p["cursor_value"] = cur.Value
		if store.Columns[in.Sort] == "time" {
			timestamp, err := time.Parse(time.RFC3339Nano, cur.Value)
			if err != nil {
				problem(w, 400, "Invalid cursor timestamp")
				return
			}
			p["cursor_value"] = timestamp.UTC().Format("2006-01-02 15:04:05.999999")
		}
		p["cursor_id"] = cur.ID
	}
	limit := 200
	if v.Get("limit") != "" {
		limit, e = strconv.Atoi(v.Get("limit"))
		if e != nil || limit < 1 || limit > 1000 {
			problem(w, 400, "Page limit must be 1–1000")
			return
		}
	}
	p["limit"] = strconv.Itoa(limit + 1)
	rows, e := s.Store.CH.EventPageRows(r.Context(), "SELECT * EXCEPT expires_at FROM events WHERE "+where+" ORDER BY "+in.Sort+" "+in.Order+", id "+in.Order+" LIMIT {limit:UInt32}", p)
	if e != nil {
		databaseError(w, e)
		return
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		cur = cursor{fmt.Sprint(last[in.Sort]), fmt.Sprint(last["id"]), in.From, in.To, signature(in)}
		b, _ := json.Marshal(cur)
		next = base64.RawURLEncoding.EncodeToString(b)
	}
	respond(w, 200, map[string]any{"events": rows, "next_cursor": next, "elapsed_ms": float64(time.Since(start).Microseconds()) / 1000, "from": in.From, "to": in.To})
}

// Event links carry their observed time and family so a detail read can prune
// partitions at large retention volumes. The ID is always separately bound.
func (s *Server) event(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	at, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("at"))
	kind := r.URL.Query().Get("type")
	if len(id) < 16 || len(id) > 64 || err != nil || kind == "" || len(kind) > 64 {
		problem(w, 400, "Event links require an ID, observed timestamp and log type")
		return
	}
	params := map[string]string{"id": id, "category": kind, "from": at.UTC().Add(-time.Second).Format("2006-01-02 15:04:05.999999"), "to": at.UTC().Add(time.Second).Format("2006-01-02 15:04:05.999999")}
	rows, err := s.Store.CH.EventRows(r.Context(), "SELECT * EXCEPT expires_at FROM events WHERE log_type={category:String} AND received_at >= {from:DateTime64(6)} AND received_at <= {to:DateTime64(6)} AND id={id:String} LIMIT 1", params)
	if err != nil {
		databaseError(w, err)
		return
	}
	if len(rows) == 0 {
		problem(w, 404, "Event was not found; it may have expired under retention policy")
		return
	}
	respond(w, 200, map[string]any{"event": rows[0]})
}
