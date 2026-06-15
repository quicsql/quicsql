// Command quicsql is the quicSQL server daemon. It serves the native-JSON and
// Hrana endpoints over every transport (HTTP/1.1, cleartext h2c, HTTP/2 over TLS,
// HTTP/3 over QUIC, and Unix sockets) — see .plans/plan-quicsql-server.md.
//
// It is a single brand-named binary (not `-d`-suffixed) so later phases can add
// subcommands (`quicsql serve`, `quicsql query`, `quicsql admin`) without a rename.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gosqlite.org/server/admin"
	"gosqlite.org/server/auth"
	"gosqlite.org/server/authz"
	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/engine"
	"gosqlite.org/server/httpapi"
	"gosqlite.org/server/limits"
	"gosqlite.org/server/meta"
	"gosqlite.org/server/obs"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/secret"
	"gosqlite.org/server/session"
	"gosqlite.org/server/transport"
)

const (
	shutdownGrace           = 10 * time.Second
	warmTimeout             = 30 * time.Second
	defaultStatementTimeout = 30 * time.Second
	defaultTxIdleTimeout    = 30 * time.Second
	reapInterval            = 15 * time.Second
)

func main() {
	cfgPath := flag.String("config", "quicsql.yaml", "path to the YAML config file")
	flag.Parse()

	log := slog.Default()
	started := time.Now()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(log, "load config", err)
	}
	sec, err := secret.New(cfg.Secrets) // eager: all key material resolved at load
	if err != nil {
		fatal(log, "init secrets", err)
	}

	// The slow-query log installs a per-connection profile trace; it must be armed
	// before any database opens.
	if cfg.Logging.SlowThreshold > 0 {
		backend.InstallSlowLog(cfg.Logging.SlowThreshold, !cfg.Logging.ExpandParams, log)
	}

	// The meta store records databases created at runtime; reconcile config ∪ meta
	// (the file seeds; meta is the running truth for runtime-created entries, so it
	// wins on a name conflict).
	var store *meta.Store
	if cfg.ControlPlane.Enabled {
		store, err = meta.Open(cfg.Server.MetaStore, sec, cfg.Server.DataDir, log)
		if err != nil {
			fatal(log, "open meta store", err)
		}
	}
	dbs, err := reconcile(cfg.Databases, store, log)
	if err != nil {
		fatal(log, "reconcile databases", err)
	}
	backends, err := backend.All(dbs, sec, cfg.Server.DataDir)
	if err != nil {
		fatal(log, "build backends", err)
	}
	for _, warning := range cfg.Warnings() {
		log.Warn("quicsql: " + warning)
	}

	reg := registry.New(backends, log)

	// Eager, fail-fast: a bad seed (missing file / wrong key) errors at startup,
	// not on a client's first request.
	warmCtx, warmCancel := context.WithTimeout(context.Background(), warmTimeout)
	if err := reg.Warm(warmCtx); err != nil {
		warmCancel()
		log.Error("quicsql: opening seed databases", "err", err)
		_ = reg.Close()
		os.Exit(1)
	}
	warmCancel()

	appCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stmtTimeout := cfg.Limits.StatementTimeout
	if stmtTimeout <= 0 {
		stmtTimeout = defaultStatementTimeout
	}
	sessTTL := cfg.Limits.TxIdleTimeout
	if sessTTL <= 0 {
		sessTTL = defaultTxIdleTimeout
	}
	sessions, err := session.NewStore(sessTTL, cfg.Limits.MaxTxLifetime, cfg.Limits.MaxWriteSessionsPerDB)
	if err != nil {
		fatal(log, "init sessions", err)
	}
	sessions.StartReaper(appCtx, reapInterval)

	// Authentication (per-listener methods) and authorization (per-database
	// grants). With nothing configured the policy runs in open mode — every
	// request is an anonymous read-write principal, the pre-auth behavior.
	authn, err := auth.New(cfg, sec, log)
	if err != nil {
		fatal(log, "init auth", err)
	}
	policy := buildPolicy(cfg, dbs)
	if policy.Open() {
		log.Warn("quicsql: no auth configured — every database is publicly read-write (open mode)")
	}

	// Metrics registry with live gauges, and the admission limiter.
	metrics := obs.NewRegistry()
	metrics.SetGauge("quicsql_active_sessions", func() int64 { return int64(sessions.Count()) })
	metrics.SetGauge("quicsql_databases", func() int64 { return int64(len(backends)) })
	limiter := limits.New(cfg.Limits.Rate.PerPrincipalRPS, cfg.Limits.MaxConcurrentPerDB)

	eng := engine.New(cfg.Limits.MaxRows, cfg.Limits.MaxResultBytes)
	handlerOpts := []httpapi.Option{
		httpapi.WithLogger(log),
		httpapi.WithMaxBody(cfg.Limits.MaxRequestBytes),
		httpapi.WithStatementTimeout(stmtTimeout),
		httpapi.WithSessions(sessions),
		httpapi.WithPolicy(policy),
		httpapi.WithMetrics(metrics),
		httpapi.WithLimiter(limiter),
	}
	if cfg.ControlPlane.Enabled {
		adminH := admin.New(reg, policy, store, sessions, sec, cfg.Server.DataDir, cfg.ControlPlane.Admins, started, log)
		handlerOpts = append(handlerOpts, httpapi.WithAdmin(adminH))
		log.Info("quicsql: control plane enabled at /_admin", "admins", len(cfg.ControlPlane.Admins))
	}
	handler := httpapi.New(reg, eng, cfg.Routing, handlerOpts...)

	opts := transport.Options{
		Wrap: func(lc config.Listener, h http.Handler) http.Handler {
			return authn.Middleware(lc, log).Wrap(h)
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return auth.NewConnContext(ctx, c)
		},
	}
	servers, err := transport.Serve(log, cfg, handler, opts)
	if err != nil {
		log.Error("quicsql: start listeners", "err", err)
		_ = reg.Close() // orderly close (WAL checkpoint / vault teardown) before exit
		os.Exit(1)
	}
	log.Info("quicsql: ready", "databases", len(backends), "servers", servers.Count())

	<-appCtx.Done()
	log.Info("quicsql: shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	servers.Shutdown(sctx)
	cancel()
	sessions.CloseAll()
	if err := reg.Close(); err != nil {
		log.Error("quicsql: registry close", "err", err)
	}
	if store != nil {
		if err := store.Close(); err != nil {
			log.Error("quicsql: meta store close", "err", err)
		}
	}
}

// buildPolicy compiles the reconciled databases' grants into the authz policy.
// Open mode (no principals and no grants anywhere, config or meta store) makes
// every principal read-write.
func buildPolicy(cfg *config.Config, dbs []config.Database) *authz.Policy {
	configured := len(cfg.Auth.Principals) > 0 || config.AnyGrants(dbs)
	pol := authz.NewPolicy(!configured)
	for _, db := range dbs {
		for _, g := range db.Grants {
			if lvl, ok := authz.ParseLevel(g.Level); ok {
				pol.Grant(db.Name, g.Principal, lvl)
			}
		}
	}
	return pol
}

// reconcile merges the config seed databases with the meta store's
// runtime-created ones. A meta entry wins on a name conflict (it is the running
// truth for what the control plane created); a store-less run just returns the
// config seeds.
func reconcile(seeds []config.Database, store *meta.Store, log *slog.Logger) ([]config.Database, error) {
	if store == nil {
		return seeds, nil
	}
	created, err := store.Databases()
	if err != nil {
		return nil, err
	}
	byName := map[string]config.Database{}
	order := []string{}
	add := func(db config.Database) {
		if _, seen := byName[db.Name]; !seen {
			order = append(order, db.Name)
		}
		byName[db.Name] = db
	}
	for _, db := range seeds {
		add(db)
	}
	for _, db := range created { // meta wins on conflict
		// Re-validate every meta-store spec: the meta store (a plain container by
		// default) is a trust root, so a tampered/stale entry must not inject a
		// database that never passed config validation (bad name, unknown backend).
		if !config.ValidDBName(db.Name) || !config.KnownBackends[db.Backend] {
			log.Warn("quicsql: skipping invalid meta-store database entry", "db", db.Name, "backend", db.Backend)
			continue
		}
		if _, seen := byName[db.Name]; seen {
			log.Warn("quicsql: meta-store database shadows a config seed", "db", db.Name)
		}
		add(db)
	}
	out := make([]config.Database, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out, nil
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error("quicsql: "+msg, "err", err)
	os.Exit(1)
}
