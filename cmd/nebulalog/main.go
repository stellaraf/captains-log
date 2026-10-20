package main

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stellaraf/captains-log/internal/api"
	"github.com/stellaraf/captains-log/internal/auth"
	"github.com/stellaraf/captains-log/internal/dns"
	"github.com/stellaraf/captains-log/internal/hostcontrol"
	"github.com/stellaraf/captains-log/internal/identity"
	"github.com/stellaraf/captains-log/internal/ingest"
	"github.com/stellaraf/captains-log/internal/panos"
	"github.com/stellaraf/captains-log/internal/retry"
	"github.com/stellaraf/captains-log/internal/store"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var version = "0.1.0-dev"

func env(k, fallback string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return fallback
}
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if e := run(); e != nil {
		slog.Error("Captain’s Log stopped", "error", e)
		os.Exit(1)
	}
}
func requireFIPSMode(setting string, enabled bool) error {
	required, err := strconv.ParseBool(setting)
	if err != nil {
		return fmt.Errorf("REQUIRE_FIPS must be a Boolean")
	}
	if required && !enabled {
		return fmt.Errorf("REQUIRE_FIPS is enabled but the Go cryptographic module is not in FIPS mode")
	}
	return nil
}
func run() error {
	if e := requireFIPSMode(env("REQUIRE_FIPS", "false"), fips140.Enabled()); e != nil {
		return e
	}
	role := "all"
	if len(os.Args) > 1 {
		role = os.Args[1]
	}
	if role == "version" {
		fmt.Println(version)
		return nil
	}
	if role != "all" && role != "serve" && role != "ingest" && role != "migrate" && role != "migrate-retention" {
		return fmt.Errorf("usage: nebulalog [all|serve|ingest|migrate|migrate-retention|version]; host operations use appliance/nebulalog")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dsn := env("PG_DSN", "")
	if dsn == "" {
		return fmt.Errorf("PG_DSN is required")
	}
	pg, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return fmt.Errorf("invalid PostgreSQL configuration")
	}
	defer pg.Close()
	// The collector can durably spool while metadata or ClickHouse is offline.
	// Only the explicit migration command requires immediate database readiness.
	if role == "migrate" || role == "migrate-retention" {
		if e = pg.Ping(ctx); e != nil {
			return fmt.Errorf("PostgreSQL unavailable")
		}
	}
	ch := store.NewClickHouse(env("CH_URL", "http://127.0.0.1:28123"), env("CH_USER", "nebulalog"), env("CH_PASSWORD", ""))
	st := &store.Store{CH: ch, PG: pg}
	storagePath := env("STORAGE_MAINTENANCE_PATH", "")
	required, _ := strconv.ParseBool(env("REQUIRE_FIPS", "false"))
	if role != "migrate" {
		if e = store.ValidateStorageMaintenancePath(storagePath, required); e != nil {
			return e
		}
	}
	st.StorageMaintenancePath = storagePath
	if role == "migrate-retention" {
		attempt, stop := context.WithTimeout(ctx, 90*time.Second)
		defer stop()
		ctx = attempt
		if e = st.CheckRetentionMigrationHold(ctx); e != nil {
			return e
		}
	}
	if role == "migrate" || role == "migrate-retention" {
		b, e := os.ReadFile(env("PG_MIGRATION", "migrations/postgres.sql"))
		if e != nil {
			return e
		}
		if _, e = pg.Exec(ctx, string(b)); e != nil {
			return e
		}
		b, e = os.ReadFile(env("CH_MIGRATION", "migrations/clickhouse.sql"))
		if e != nil {
			return e
		}
		for _, statement := range strings.Split(string(b), ";") {
			if strings.TrimSpace(statement) != "" {
				if e = ch.Exec(ctx, statement, nil); e != nil {
					return e
				}
			}
		}
		if role == "migrate-retention" {
			return st.MigrateRetention(ctx)
		}
		if e = st.InitializeRetention(ctx); e != nil {
			return e
		}
		slog.Info("database migrations applied; normal retention identity verified")
		return nil
	}
	storageContext, stopStorage := context.WithCancel(ctx)
	storageDone := make(chan struct{})
	go func() { defer close(storageDone); st.RunEmergencyRetention(storageContext) }()
	defer func() { stopStorage(); <-storageDone }()
	var collector *ingest.Collector
	if role == "all" || role == "ingest" {
		location, e := time.LoadLocation(env("PANOS_TIMEZONE", "UTC"))
		if e != nil {
			return e
		}
		var tc *tls.Config
		tlsAddr := env("SYSLOG_TLS", "")
		if tlsAddr != "" {
			cert, e := tls.LoadX509KeyPair(env("SYSLOG_CERT", ""), env("SYSLOG_KEY", ""))
			if e != nil {
				return fmt.Errorf("TLS syslog certificate/key could not be loaded")
			}
			tc = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
		max, e := strconv.ParseInt(env("SPOOL_MAX_BYTES", "1073741824"), 10, 64)
		if e != nil {
			return fmt.Errorf("invalid SPOOL_MAX_BYTES")
		}
		collector, e = ingest.New(ingest.Config{UDPAddr: env("SYSLOG_UDP", ":5514"), TCPAddr: env("SYSLOG_TCP", ":5514"), TLSAddr: tlsAddr, TLSConfig: tc, SpoolDir: env("SPOOL_DIR", ".local/spool"), MaxSpoolBytes: max, BatchSize: 1000, FlushInterval: 2 * time.Second, Parser: panos.NewParser(panos.Options{Timezone: location, PANOSVersion: env("PANOS_VERSION", "")})}, st)
		if e != nil {
			return e
		}
		defer collector.Close()
		if e = collector.Start(ctx); e != nil {
			return e
		}
		slog.Info("syslog collector listening", "listeners", collector.Snapshot().Listeners)
		if path := env("COLLECTOR_STATUS_PATH", ""); path != "" {
			publisherContext, stopPublisher := context.WithCancel(ctx)
			publisherDone := make(chan struct{})
			go func() {
				defer close(publisherDone)
				collector.PublishStatus(publisherContext, path, func(error) {
					slog.Error("collector observation could not be published; API will report stale status")
				})
			}()
			defer func() { stopPublisher(); <-publisherDone }()
		}
	}
	if role == "ingest" {
		<-ctx.Done()
		return nil
	}
	issuer, clientID := env("OIDC_ISSUER", ""), env("OIDC_CLIENT_ID", "nebulalog")
	if issuer == "" {
		return fmt.Errorf("OIDC_ISSUER is required; authentication cannot be disabled")
	}
	var a *auth.Auth
	e = retry.Until(ctx, time.Second, 30*time.Second, func() error {
		attempt, stop := context.WithTimeout(ctx, 15*time.Second)
		defer stop()
		var discoveryErr error
		a, discoveryErr = auth.New(auth.Backchannel(attempt, issuer, env("OIDC_BACKCHANNEL_URL", "")), issuer, clientID)
		return discoveryErr
	}, func(error) {
		slog.Warn("Keycloak discovery unavailable; retrying with authentication closed and any active collector still buffering")
	})
	if e != nil {
		return e
	}
	if err := auth.SetTokenNotBefore(a, env("OIDC_TOKEN_NOT_BEFORE", "")); err != nil {
		return err
	}
	app := &api.Server{Store: st, Auth: a, DNS: dns.New(ctx, 4, env("DNS_RESOLVER", "")), Collector: collector, Config: api.Config{AuthURL: env("OIDC_URL", "http://127.0.0.1:18089"), Realm: env("OIDC_REALM", "nebulalog"), ClientID: clientID, WebDir: env("WEB_DIR", "web/dist"), ExportDir: env("EXPORT_DIR", ".local/exports"), Version: version, ExportMaxBytes: 512 << 20}}
	app.Config.CollectorStatusPath = env("COLLECTOR_STATUS_PATH", "")
	app.Config.CollectorTLSCAPath = env("COLLECTOR_TLS_CA_PATH", "")
	app.Config.CollectorTLSCertPath = env("COLLECTOR_TLS_CERT_PATH", "")
	app.Config.ApplianceStatusPath = env("NEBULALOG_APPLIANCE_STATUS_PATH", "")
	app.Config.HostPlanPublicOrigin = env("NEBULALOG_PUBLIC_ORIGIN", "")
	if app.Config.HostPlanPublicOrigin != "" && !api.ValidHostPlanOrigin(app.Config.HostPlanPublicOrigin) {
		return fmt.Errorf("NEBULALOG_PUBLIC_ORIGIN must be one exact HTTPS origin")
	}
	app.HostPlans = hostcontrol.New()
	if adminURL := env("IDENTITY_ADMIN_URL", ""); adminURL != "" {
		flags := map[string]bool{}
		for _, name := range []string{"IDENTITY_ALLOW_HTTP", "IDENTITY_ALLOW_METADATA_HTTP", "IDENTITY_ENABLE_WRITES"} {
			value, err := strconv.ParseBool(env(name, "false"))
			if err != nil {
				return fmt.Errorf("%s must be a Boolean", name)
			}
			flags[name] = value
		}
		manager, err := identity.New(identity.Config{BaseURL: adminURL, PublicBaseURL: app.Config.AuthURL, Realm: app.Config.Realm, ClientID: env("IDENTITY_CLIENT_ID", "nebulalog-identity-manager"), ClientSecret: env("IDENTITY_CLIENT_SECRET", ""), ApplicationClientID: clientID, BrokerMFAFlow: "nebulalog-broker-mfa", AllowHTTP: flags["IDENTITY_ALLOW_HTTP"], AllowMetadataHTTP: flags["IDENTITY_ALLOW_METADATA_HTTP"], EnableWrites: flags["IDENTITY_ENABLE_WRITES"]})
		if err != nil {
			return fmt.Errorf("identity manager configuration invalid: %w", err)
		}
		app.Identity = manager
	}
	if e = app.RecoverExports(ctx); e != nil {
		return e
	}
	app.StartSampling(ctx)
	server := &http.Server{Addr: env("API_LISTEN", "127.0.0.1:18080"), Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	errc := make(chan error, 1)
	go func() {
		slog.Info("web/API listening", "address", server.Addr, "version", version)
		if cert := env("API_CERT", ""); cert != "" {
			errc <- server.ListenAndServeTLS(cert, env("API_KEY", ""))
		} else {
			errc <- server.ListenAndServe()
		}
	}()
	select {
	case e := <-errc:
		if e != http.ErrServerClosed {
			return e
		}
	case <-ctx.Done():
		stop, c := context.WithTimeout(context.Background(), 15*time.Second)
		defer c()
		return server.Shutdown(stop)
	}
	return nil
}
