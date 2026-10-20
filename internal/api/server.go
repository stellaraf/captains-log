package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stellaraf/captains-log/internal/auth"
	"github.com/stellaraf/captains-log/internal/dns"
	"github.com/stellaraf/captains-log/internal/identity"
	"github.com/stellaraf/captains-log/internal/ingest"
	"github.com/stellaraf/captains-log/internal/query"
	"github.com/stellaraf/captains-log/internal/store"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	AuthURL, Realm, ClientID, WebDir, ExportDir, Version string
	ExportMaxBytes                                       int64
	CollectorStatusPath                                  string
	CollectorTLSCAPath, CollectorTLSCertPath             string
	ApplianceStatusPath                                  string
	HostPlanPublicOrigin                                 string
}
type Server struct {
	Store         *store.Store
	Auth          *auth.Auth
	DNS           *dns.Resolver
	Collector     *ingest.Collector
	Identity      *identity.Manager
	HostPlans     HostPlanReader
	Config        Config
	mu            sync.Mutex
	activeExports int
	exportsReady  bool
	tickets       map[string]downloadTicket
	retentionRead func(context.Context, time.Time) (store.Retention, string, map[string]string, error)
}

func (s *Server) retained(ctx context.Context, at time.Time) (store.Retention, string, map[string]string, error) {
	if s.retentionRead != nil {
		return s.retentionRead(ctx, at)
	}
	return s.Store.RetainedPredicate(ctx, at)
}

func retentionWhere(where string, params map[string]string, predicate string, bound map[string]string) string {
	for key, value := range bound {
		params[key] = value
	}
	return "(" + where + ") AND " + predicate
}

func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, auth.Current(r.Context())) })
	api.HandleFunc("GET /api/preferences", s.preferences)
	api.HandleFunc("PUT /api/preferences", s.preferences)
	api.HandleFunc("GET /api/logs", s.logs)
	api.HandleFunc("GET /api/events/{id}", s.event)
	api.HandleFunc("GET /api/fields", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]any{"fields": query.Fields}) })
	api.HandleFunc("POST /api/query/validate", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Query string `json:"query"`
		}
		if !decode(w, r, &v) {
			return
		}
		if _, e := query.Compile(v.Query); e != nil {
			problem(w, 400, e.Error())
			return
		}
		respond(w, 200, map[string]bool{"valid": true})
	})
	api.HandleFunc("GET /api/filters", s.filters)
	api.HandleFunc("POST /api/filters", auth.Require("ANALYST", s.saveFilter))
	api.HandleFunc("PUT /api/filters/{id}", auth.Require("ANALYST", s.saveFilter))
	api.HandleFunc("DELETE /api/filters/{id}", auth.Require("ANALYST", s.deleteFilter))
	api.HandleFunc("GET /api/layouts/{type}", s.layout)
	api.HandleFunc("PUT /api/layouts/{type}", s.layout)
	api.HandleFunc("GET /api/firewalls", s.firewalls)
	api.HandleFunc("GET /api/firewalls/{serial}", s.firewalls)
	api.HandleFunc("PUT /api/firewalls/{serial}", auth.Require("ADMINISTRATOR", s.saveFirewall))
	api.HandleFunc("GET /api/stats", s.stats)
	api.HandleFunc("GET /api/collector/tls", auth.Require("ADMINISTRATOR", s.collectorTLSMetadata))
	api.HandleFunc("GET /api/collector/tls/ca.pem", auth.Require("ADMINISTRATOR", s.collectorTLSDownload))
	api.HandleFunc("GET /api/metrics", s.metrics)
	api.HandleFunc("GET /api/storage", s.storage)
	api.HandleFunc("GET /api/storage/emergency", s.emergencyStorage)
	api.HandleFunc("PUT /api/storage/emergency", auth.Require("ADMINISTRATOR", s.emergencyStorage))
	api.HandleFunc("GET /api/appliance/capabilities", auth.Require("ADMINISTRATOR", s.hostPlanCapabilities))
	api.HandleFunc("POST /api/appliance/plans", auth.Require("ADMINISTRATOR", s.hostPlanCreate))
	api.HandleFunc("GET /api/appliance/plans/{id}", auth.Require("ADMINISTRATOR", s.hostPlanLookup))
	api.HandleFunc("GET /api/retention", s.retention)
	api.HandleFunc("PUT /api/retention", auth.Require("ADMINISTRATOR", s.retention))
	api.HandleFunc("POST /api/dns/resolve", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			IPs []string `json:"ips"`
		}
		if !decode(w, r, &v) {
			return
		}
		if len(v.IPs) > 200 {
			problem(w, 400, "At most 200 addresses per request")
			return
		}
		respond(w, 200, map[string]any{"results": s.DNS.Resolve(v.IPs)})
	})
	api.HandleFunc("DELETE /api/dns/cache", auth.Require("ADMINISTRATOR", func(w http.ResponseWriter, r *http.Request) {
		s.DNS.Clear()
		s.audit(r, "dns.cache.clear", "dns", nil)
		respond(w, 200, map[string]bool{"cleared": true})
	}))
	api.HandleFunc("POST /api/exports", auth.Require("ANALYST", s.createExport))
	api.HandleFunc("GET /api/exports/{id}", auth.Require("ANALYST", s.getExport))
	api.HandleFunc("GET /api/exports/{id}/download", auth.Require("ANALYST", s.downloadExport))
	api.HandleFunc("POST /api/exports/{id}/download-ticket", auth.Require("ANALYST", s.downloadTicket))
	api.HandleFunc("GET /api/security", s.security)
	api.HandleFunc("GET /api/identity/providers", auth.Require("ADMINISTRATOR", s.identityProviders))
	api.HandleFunc("GET /api/identity/providers/{alias}", auth.Require("ADMINISTRATOR", s.identityProvider))
	api.HandleFunc("POST /api/identity/providers/{alias}/preview", auth.Require("ADMINISTRATOR", s.identityProvider))
	api.HandleFunc("PUT /api/identity/providers/{alias}", auth.Require("ADMINISTRATOR", s.identityProvider))
	api.HandleFunc("POST /api/identity/providers/{alias}/test", auth.Require("ADMINISTRATOR", s.identityTest))
	api.HandleFunc("PATCH /api/identity/providers/{alias}/state", auth.Require("ADMINISTRATOR", s.identityState))
	api.HandleFunc("GET /api/updates", s.updates)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"version": s.Config.Version, "auth": map[string]string{"url": s.Config.AuthURL, "realm": s.Config.Realm, "client_id": s.Config.ClientID}})
	})
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/downloads/{token}", s.redeemDownload)
	mux.Handle("/api/", s.Auth.Middleware(api))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		name := filepath.Clean(r.URL.Path)
		path := filepath.Join(s.Config.WebDir, name)
		if info, e := os.Stat(path); e == nil && !info.IsDir() {
			if strings.HasPrefix(name, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFile(w, r, path)
			return
		}
		if strings.HasPrefix(name, "/assets/") || filepath.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(s.Config.WebDir, "index.html"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' "+s.Config.AuthURL+"; frame-src "+s.Config.AuthURL+"; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeLimit(w, r, v, 65536)
}
func decodeLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		problem(w, 400, "Invalid JSON request")
		return false
	}
	if e := d.Decode(new(any)); e != io.EOF {
		problem(w, 400, "Request must contain one JSON object")
		return false
	}
	return true
}
func databaseError(w http.ResponseWriter, e error) {
	slog.Error("database operation failed", "error", e)
	problem(w, 503, "Database operation could not complete. Check appliance diagnostics.")
}
func (s *Server) audit(r *http.Request, action, target string, detail any) {
	b, _ := json.Marshal(detail)
	_, e := s.Store.PG.Exec(r.Context(), "INSERT INTO audit_events(actor,action,target,detail) VALUES($1,$2,$3,$4)", auth.Current(r.Context()).ID, action, target, b)
	if e != nil {
		slog.Error("audit persistence failed", "action", action, "error", e)
	}
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	status := 200
	ch := s.Store.CH.Ping(ctx)
	pg := s.Store.PG.Ping(ctx)
	if ch != nil || pg != nil {
		status = 503
	}
	ingestionStatus := "unavailable"
	ingestionRunning := false
	observed, observationError := s.collectorStats()
	if observationError == nil {
		listeners := observed.Listeners
		ingestionStatus = "unavailable"
		for _, listener := range listeners {
			if listener.Status != "listening" {
				ingestionStatus = "failed"
				ingestionRunning = false
				break
			}
			ingestionRunning = true
			ingestionStatus = "listening"
		}
		if !ingestionRunning {
			status = http.StatusServiceUnavailable
		}
	} else {
		status = http.StatusServiceUnavailable
	}
	respond(w, status, map[string]any{"status": map[bool]string{true: "ok", false: "degraded"}[status == 200], "application": "ok", "clickhouse": state(ch), "postgresql": state(pg), "auth": "configured", "ingestion": ingestionRunning, "ingestion_status": ingestionStatus, "dns": "running", "storage": "see authenticated /api/storage", "updates": "not_connected", "version": s.Config.Version})
}
func state(e error) string {
	if e != nil {
		return "unavailable"
	}
	return "ok"
}
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	observed, err := s.collectorStats()
	if err != nil {
		respond(w, 503, map[string]any{"status": "unavailable", "listeners": []any{}, "error": "Collector status is unavailable or stale. Check the collector service."})
		return
	}
	respond(w, 200, observed)
}
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	observed, err := s.collectorStats()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "nebulalog_collector_observation_available 0")
		return
	}
	fmt.Fprintln(w, "nebulalog_collector_observation_available 1")
	b, _ := json.Marshal(observed)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, key := range []string{"messages_received", "messages_parsed", "parse_failures", "events_inserted", "queue_depth", "spool_bytes", "messages_dropped", "events_per_second", "bytes_per_second"} {
		if v, ok := m[key].(float64); ok {
			fmt.Fprintf(w, "nebulalog_%s %g\n", key, v)
		}
	}
}
