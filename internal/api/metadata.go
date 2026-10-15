package api

import (
	"crypto/rand"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/stellaraf/captains-log/internal/auth"
	"github.com/stellaraf/captains-log/internal/query"
	"github.com/stellaraf/captains-log/internal/store"
	"net/http"
	"strings"
)

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hex[v>>4], hex[v&15])
	}
	return string(out)
}

type Filter struct {
	Order       string   `json:"order"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Query       string   `json:"query"`
	LogType     string   `json:"log_type"`
	Columns     []string `json:"columns"`
	TimeRange   string   `json:"time_range"`
	Sort        string   `json:"sort"`
	Favorite    bool     `json:"favorite"`
	Builtin     bool     `json:"builtin"`
}

var builtins = []Filter{
	{ID: "builtin-denied", Name: "Denied Traffic", Query: "(action eq deny) or (action eq drop)", LogType: "traffic"},
	{ID: "builtin-unknown", Name: "Unknown Applications", Query: "(app eq unknown-tcp) or (app eq unknown-udp)", LogType: "traffic"},
	{ID: "builtin-internet", Name: "Internet Traffic", Query: "zone.dst eq untrust", LogType: "traffic"},
	{ID: "builtin-dns", Name: "DNS", Query: "(app eq dns) or (port.dst eq 53)", LogType: "traffic"},
	{ID: "builtin-quic", Name: "QUIC", Query: "app eq quic", LogType: "traffic"},
	{ID: "builtin-ssl", Name: "SSL/TLS", Query: "app eq ssl", LogType: "traffic"},
	{ID: "builtin-threats", Name: "Threats", LogType: "threat"},
	{ID: "builtin-auth", Name: "Authentication Failures", Query: "action eq failure", LogType: "authentication"},
}

func (s *Server) filters(w http.ResponseWriter, r *http.Request) {
	rows, e := s.Store.PG.Query(r.Context(), `SELECT id::text,name,description,query,log_type,columns,time_range,sort,favorite,sort_order FROM saved_filters WHERE owner_id=$1 ORDER BY favorite DESC,name`, auth.Current(r.Context()).ID)
	if e != nil {
		databaseError(w, e)
		return
	}
	defer rows.Close()
	out := make([]Filter, 0)
	for rows.Next() {
		var f Filter
		if e = rows.Scan(&f.ID, &f.Name, &f.Description, &f.Query, &f.LogType, &f.Columns, &f.TimeRange, &f.Sort, &f.Favorite, &f.Order); e != nil {
			databaseError(w, e)
			return
		}
		out = append(out, f)
	}
	if rows.Err() != nil {
		databaseError(w, rows.Err())
		return
	}
	for _, f := range builtins {
		f.Builtin = true
		f.TimeRange = "1h"
		f.Sort = "received_at"
		f.Order = "desc"
		f.Columns = []string{}
		out = append(out, f)
	}
	respond(w, 200, map[string]any{"filters": out})
}
func (s *Server) saveFilter(w http.ResponseWriter, r *http.Request) {
	var f Filter
	if !decode(w, r, &f) {
		return
	}
	f.Name = strings.TrimSpace(f.Name)
	if len(f.Name) < 1 || len(f.Name) > 128 || len(f.Description) > 2048 {
		problem(w, 400, "Provide a name of 1–128 characters and a description under 2048 characters")
		return
	}
	if _, e := query.Compile(f.Query); e != nil {
		problem(w, 400, e.Error())
		return
	}
	if !categories[f.LogType] {
		problem(w, 400, "Unknown log category")
		return
	}
	if !validColumns(f.Columns) {
		problem(w, 400, "Invalid selected columns")
		return
	}
	if f.Sort == "" {
		f.Sort = "received_at"
	}
	if _, ok := store.Columns[f.Sort]; !ok {
		problem(w, 400, "Unknown sort column")
		return
	}
	if len(f.TimeRange) > 32 {
		problem(w, 400, "Invalid time range")
		return
	}
	if f.Order == "" {
		f.Order = "desc"
	}
	if f.Order != "asc" && f.Order != "desc" {
		problem(w, 400, "Invalid sort order")
		return
	}
	f.Builtin = false
	tx, e := s.Store.PG.Begin(r.Context())
	if e != nil {
		databaseError(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	owner := auth.Current(r.Context()).ID
	cols, _ := json.Marshal(f.Columns)
	if id := r.PathValue("id"); id != "" {
		f.ID = id
		tag, e := tx.Exec(r.Context(), `UPDATE saved_filters SET name=$1,description=$2,query=$3,log_type=$4,columns=$5,time_range=$6,sort=$7,favorite=$8,sort_order=$9,updated_at=now() WHERE id::text=$10 AND owner_id=$11`, f.Name, f.Description, f.Query, f.LogType, cols, f.TimeRange, f.Sort, f.Favorite, f.Order, id, owner)
		if e != nil {
			databaseError(w, e)
			return
		}
		if tag.RowsAffected() != 1 {
			problem(w, 404, "Saved filter not found")
			return
		}
	} else {
		f.ID = uuid()
		_, e = tx.Exec(r.Context(), `INSERT INTO saved_filters(id,owner_id,name,description,query,log_type,columns,time_range,sort,favorite,sort_order) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, f.ID, owner, f.Name, f.Description, f.Query, f.LogType, cols, f.TimeRange, f.Sort, f.Favorite, f.Order)
		if e != nil {
			databaseError(w, e)
			return
		}
	}
	if e = transactionAudit(r, tx, "filter.save", f.ID); e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		databaseError(w, e)
		return
	}
	respond(w, 200, f)
}
func (s *Server) deleteFilter(w http.ResponseWriter, r *http.Request) {
	tx, e := s.Store.PG.Begin(r.Context())
	if e != nil {
		databaseError(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	tag, e := tx.Exec(r.Context(), "DELETE FROM saved_filters WHERE id::text=$1 AND owner_id=$2", r.PathValue("id"), auth.Current(r.Context()).ID)
	if e != nil {
		databaseError(w, e)
		return
	}
	if tag.RowsAffected() != 1 {
		problem(w, 404, "Saved filter not found")
		return
	}
	if e = transactionAudit(r, tx, "filter.delete", r.PathValue("id")); e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		databaseError(w, e)
		return
	}
	respond(w, 200, map[string]bool{"deleted": true})
}
func transactionAudit(r *http.Request, tx pgx.Tx, action, target string) error {
	_, e := tx.Exec(r.Context(), "INSERT INTO audit_events(actor,action,target) VALUES($1,$2,$3)", auth.Current(r.Context()).ID, action, target)
	return e
}
func validColumns(cols []string) bool {
	if len(cols) > 60 {
		return false
	}
	seen := map[string]bool{}
	for _, c := range cols {
		if seen[c] {
			return false
		}
		seen[c] = true
		if c == "src_hostname" || c == "dst_hostname" {
			continue
		}
		if _, ok := store.Columns[c]; !ok {
			return false
		}
	}
	return true
}

type Layout struct {
	Columns []string       `json:"columns"`
	Widths  map[string]int `json:"widths"`
	Sort    string         `json:"sort"`
	Order   string         `json:"order"`
}

func (s *Server) layout(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("type")
	if !categories[kind] {
		problem(w, 400, "Unknown log category")
		return
	}
	owner := auth.Current(r.Context()).ID
	if r.Method == "GET" {
		var b []byte
		e := s.Store.PG.QueryRow(r.Context(), "SELECT layout FROM layouts WHERE owner_id=$1 AND log_type=$2", owner, kind).Scan(&b)
		if e == pgx.ErrNoRows {
			respond(w, 200, Layout{Columns: []string{}, Widths: map[string]int{}, Sort: "received_at", Order: "desc"})
			return
		}
		if e != nil {
			databaseError(w, e)
			return
		}
		respond(w, 200, json.RawMessage(b))
		return
	}
	var l Layout
	if !decode(w, r, &l) {
		return
	}
	if !validColumns(l.Columns) {
		problem(w, 400, "Invalid layout columns")
		return
	}
	for col, width := range l.Widths {
		if !validColumns([]string{col}) || width < 40 || width > 1600 {
			problem(w, 400, "Column width must be 40–1600 pixels")
			return
		}
	}
	if l.Sort != "" {
		if _, ok := store.Columns[l.Sort]; !ok {
			problem(w, 400, "Unknown sort column")
			return
		}
	}
	if l.Order != "" && l.Order != "asc" && l.Order != "desc" {
		problem(w, 400, "Invalid sort order")
		return
	}
	b, _ := json.Marshal(l)
	_, e := s.Store.PG.Exec(r.Context(), "INSERT INTO layouts(owner_id,log_type,layout) VALUES($1,$2,$3) ON CONFLICT(owner_id,log_type) DO UPDATE SET layout=EXCLUDED.layout", owner, kind, b)
	if e != nil {
		databaseError(w, e)
		return
	}
	respond(w, 200, l)
}
func (s *Server) retention(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		v, e := s.Store.Retention(r.Context())
		if e != nil {
			databaseError(w, e)
			return
		}
		respond(w, 200, v)
		return
	}
	var v store.Retention
	if !decode(w, r, &v) {
		return
	}
	if v.GlobalDays < 1 || v.GlobalDays > 3650 {
		problem(w, 400, "Retention must be 1–3650 days")
		return
	}
	for kind, days := range v.PerType {
		if !categories[kind] || kind == "unified" || kind == "parsing" || days < 1 || days > 3650 {
			problem(w, 400, "Invalid per-category retention policy")
			return
		}
	}
	b, _ := json.Marshal(v)
	tx, e := s.Store.PG.Begin(r.Context())
	if e != nil {
		databaseError(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	if e = store.LockEmergencyPolicy(r.Context(), tx); e != nil {
		databaseError(w, e)
		return
	}
	_, e = tx.Exec(r.Context(), "UPDATE settings SET value=$1 WHERE key='retention'", b)
	if e == nil {
		_, e = tx.Exec(r.Context(), "INSERT INTO audit_events(actor,action,target,detail) VALUES($1,'retention.update','future-arrivals',$2)", auth.Current(r.Context()).ID, b)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		databaseError(w, e)
		return
	}
	respond(w, 200, v)
}
