package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/stellaraf/captains-log/internal/auth"
	"github.com/stellaraf/captains-log/internal/retry"
	"github.com/stellaraf/captains-log/internal/store"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type downloadTicket struct {
	ID      string
	Expires time.Time
}

func (s *Server) downloadTicket(w http.ResponseWriter, r *http.Request) {
	var id string
	e := s.Store.PG.QueryRow(r.Context(), "SELECT id::text FROM export_jobs WHERE id::text=$1 AND owner_id=$2 AND status='complete' AND expires_at>now()", r.PathValue("id"), auth.Current(r.Context()).ID).Scan(&id)
	if e == pgx.ErrNoRows {
		problem(w, 404, "Completed export not found")
		return
	}
	if e != nil {
		databaseError(w, e)
		return
	}
	if e = s.exportRetention(r.Context(), id); e != nil {
		problem(w, 409, "Retention policy changed or is unavailable; create a new export")
		return
	}
	token := uuid() + uuid()
	s.mu.Lock()
	if s.tickets == nil {
		s.tickets = map[string]downloadTicket{}
	}
	for key, ticket := range s.tickets {
		if time.Now().After(ticket.Expires) {
			delete(s.tickets, key)
		}
	}
	if len(s.tickets) >= 1000 {
		s.mu.Unlock()
		problem(w, 429, "Too many pending download tickets")
		return
	}
	s.tickets[token] = downloadTicket{id, time.Now().Add(time.Minute)}
	s.mu.Unlock()
	respond(w, 200, map[string]string{"url": "/api/downloads/" + token})
}
func (s *Server) redeemDownload(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	s.mu.Lock()
	ticket, ok := s.tickets[token]
	delete(s.tickets, token)
	s.mu.Unlock()
	if !ok || time.Now().After(ticket.Expires) {
		problem(w, 404, "Download ticket expired or already used")
		return
	}
	if err := s.exportRetention(r.Context(), ticket.ID); err != nil {
		problem(w, 409, "Retention policy changed or is unavailable; create a new export")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=nebulalog-"+ticket.ID+".csv")
	http.ServeFile(w, r, filepath.Join(s.Config.ExportDir, ticket.ID+".csv"))
}

func (s *Server) createExport(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	ready := s.exportsReady
	s.mu.Unlock()
	if !ready {
		problem(w, 503, "Export recovery is waiting for metadata storage; retry shortly")
		return
	}
	var in Search
	if !decode(w, r, &in) {
		return
	}
	where, params, e := buildSearch(&in)
	if e != nil {
		problem(w, 400, e.Error())
		return
	}
	policy, predicate, bound, e := s.retained(r.Context(), time.Now().UTC())
	if e != nil {
		databaseError(w, e)
		return
	}
	in.RetentionRevision = policy.Revision
	where = retentionWhere(where, params, predicate, bound)
	if len(in.Columns) == 0 {
		in.Columns = []string{"received_at", "serial", "src_ip", "dst_ip", "app", "action", "rule"}
	}
	if !validColumns(in.Columns) {
		problem(w, 400, "Invalid export columns")
		return
	}
	for _, c := range in.Columns {
		if _, ok := store.Columns[c]; !ok {
			problem(w, 400, "Hostname enrichment is a live cache; export the original IP columns")
			return
		}
	}
	var retainedBytes int64
	if err := s.Store.PG.QueryRow(r.Context(), "SELECT coalesce(sum(bytes),0) FROM export_jobs WHERE status='complete' AND expires_at>now()").Scan(&retainedBytes); err != nil {
		databaseError(w, err)
		return
	}
	if retainedBytes >= 2<<30 {
		problem(w, 429, "Temporary export storage quota reached. Completed downloads expire after 24 hours.")
		return
	}
	s.mu.Lock()
	if s.activeExports >= 2 {
		s.mu.Unlock()
		problem(w, 429, "Two exports are already running; retry when one finishes")
		return
	}
	s.activeExports++
	s.mu.Unlock()
	id := uuid()
	b, _ := json.Marshal(in)
	_, e = s.Store.PG.Exec(r.Context(), "INSERT INTO export_jobs(id,owner_id,status,request) VALUES($1,$2,'queued',$3)", id, auth.Current(r.Context()).ID, b)
	if e != nil {
		s.mu.Lock()
		s.activeExports--
		s.mu.Unlock()
		databaseError(w, e)
		return
	}
	s.audit(r, "export.create", id, nil)
	go s.runExport(id, in, where, params)
	respond(w, 202, map[string]string{"id": id, "status": "queued"})
}
func SafeCSV(value string) string {
	if strings.HasPrefix(value, "=") || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "@") || strings.HasPrefix(value, "\t") || strings.HasPrefix(value, "\r") || strings.HasPrefix(value, "\n") {
		return "'" + value
	}
	return value
}
func (s *Server) runExport(id string, in Search, where string, params map[string]string) {
	defer func() { s.mu.Lock(); s.activeExports--; s.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	path := filepath.Join(s.Config.ExportDir, id+".csv")
	f, e := os.OpenFile(path+".partial", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	var count int64
	var size int64
	if e == nil {
		writer := csv.NewWriter(f)
		e = writer.Write(in.Columns)
		if e == nil {
			_, _ = s.Store.PG.Exec(ctx, "UPDATE export_jobs SET status='running' WHERE id=$1", id)
			e = s.Store.CH.Stream(ctx, "SELECT "+strings.Join(in.Columns, ",")+" FROM events WHERE "+where+" ORDER BY "+in.Sort+" "+in.Order+", id "+in.Order, params, func(row map[string]any) error {
				record := make([]string, len(in.Columns))
				for i, col := range in.Columns {
					if v := row[col]; v != nil {
						record[i] = SafeCSV(fmt.Sprint(v))
					}
				}
				if e := writer.Write(record); e != nil {
					return e
				}
				count++
				if count%1000 == 0 {
					writer.Flush()
					if e := writer.Error(); e != nil {
						return e
					}
					info, e := f.Stat()
					if e != nil {
						return e
					}
					size = info.Size()
					if size > s.Config.ExportMaxBytes {
						return errors.New("export disk quota reached")
					}
					_, e = s.Store.PG.Exec(ctx, "UPDATE export_jobs SET rows=$1,bytes=$2 WHERE id=$3", count, size, id)
					return e
				}
				return nil
			})
		}
		writer.Flush()
		if e == nil {
			e = writer.Error()
		}
		if e == nil {
			e = f.Sync()
		}
		if info, err := f.Stat(); err == nil {
			size = info.Size()
		}
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e == nil && size > s.Config.ExportMaxBytes {
			e = errors.New("export disk quota reached")
		}
		if e == nil {
			e = s.exportRetention(ctx, id)
		}
		if e == nil {
			e = os.Rename(path+".partial", path)
		}
	}
	finish, cancelFinish := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFinish()
	if e != nil {
		os.Remove(path + ".partial")
		os.Remove(path)
		_, _ = s.Store.PG.Exec(finish, "UPDATE export_jobs SET status='failed',error=$1,rows=$2,bytes=$3 WHERE id=$4", "Export failed or exceeded its time/disk limit. Narrow the query and retry.", count, size, id)
		return
	}
	_, _ = s.Store.PG.Exec(finish, "UPDATE export_jobs SET status='complete',rows=$1,bytes=$2 WHERE id=$3", count, size, id)
}
func (s *Server) getExport(w http.ResponseWriter, r *http.Request) {
	var b []byte
	e := s.Store.PG.QueryRow(r.Context(), "SELECT json_build_object('id',id,'status',status,'rows',rows,'bytes',bytes,'error',error) FROM export_jobs WHERE id::text=$1 AND owner_id=$2 AND expires_at>now()", r.PathValue("id"), auth.Current(r.Context()).ID).Scan(&b)
	if e == pgx.ErrNoRows {
		problem(w, 404, "Export not found or expired")
		return
	}
	if e != nil {
		databaseError(w, e)
		return
	}
	respond(w, 200, json.RawMessage(b))
}
func (s *Server) downloadExport(w http.ResponseWriter, r *http.Request) {
	var id, status string
	e := s.Store.PG.QueryRow(r.Context(), "SELECT id::text,status FROM export_jobs WHERE id::text=$1 AND owner_id=$2 AND expires_at>now()", r.PathValue("id"), auth.Current(r.Context()).ID).Scan(&id, &status)
	if e == pgx.ErrNoRows {
		problem(w, 404, "Export not found or expired")
		return
	}
	if e != nil {
		databaseError(w, e)
		return
	}
	if status != "complete" {
		problem(w, 409, "Export is not ready")
		return
	}
	if e = s.exportRetention(r.Context(), id); e != nil {
		problem(w, 409, "Retention policy changed or is unavailable; create a new export")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=nebulalog-"+id+".csv")
	http.ServeFile(w, r, filepath.Join(s.Config.ExportDir, id+".csv"))
}

// Export files are snapshots with their existing 24-hour lifetime. A subsequent
// policy change invalidates them, including already-issued download tickets.
func (s *Server) exportRetention(ctx context.Context, id string) error {
	var raw []byte
	if err := s.Store.PG.QueryRow(ctx, "SELECT request FROM export_jobs WHERE id::text=$1 AND expires_at>now()", id).Scan(&raw); err != nil {
		return err
	}
	var request Search
	if err := json.Unmarshal(raw, &request); err != nil {
		return err
	}
	p, _, _, err := s.retained(ctx, time.Now().UTC())
	if err != nil {
		return err
	}
	if request.RetentionRevision < 1 || request.RetentionRevision != p.Revision {
		return store.ErrRetentionRevision
	}
	return nil
}
func (s *Server) RecoverExports(ctx context.Context) error {
	if e := os.MkdirAll(s.Config.ExportDir, 0700); e != nil {
		return e
	}
	go func() {
		err := retry.Until(ctx, time.Second, 30*time.Second, func() error {
			attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_, err := s.Store.PG.Exec(attempt, "UPDATE export_jobs SET status='failed',error='Application restarted during export; retry the export.' WHERE status IN ('queued','running')")
			return err
		}, func(error) { slog.Warn("Export recovery waiting for PostgreSQL; collector remains active") })
		if err != nil {
			return
		}
		s.mu.Lock()
		s.exportsReady = true
		s.mu.Unlock()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			if e := s.cleanupExports(ctx); e != nil {
				if ctx.Err() != nil {
					return
				}
				// A database outage must not permanently disable disk cleanup.
				slog.Error("export cleanup failed; retrying at next interval", "error", e)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}
func (s *Server) cleanupExports(ctx context.Context) error {
	rows, e := s.Store.PG.Query(ctx, "SELECT id::text FROM export_jobs WHERE expires_at<now() OR status='failed'")
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return e
		}
		for _, suffix := range []string{".csv", ".csv.partial"} {
			if err := os.Remove(filepath.Join(s.Config.ExportDir, id+suffix)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove expired export: %w", err)
			}
		}
	}
	return rows.Err()
}
