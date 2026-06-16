// Package serverd assembles and runs a quicSQL server from a validated config:
// secrets → meta store → reconcile (config ∪ meta) → backends → registry (warm,
// fail-fast) → sessions → auth/authz → metrics + limiter → HTTP handler →
// transports. It is the single wiring shared by the cmd/quicsql daemon and the
// in-process example/tests, so the assembly lives in one place.
//
// # Composing the engine
//
// The SQLite engine quicSQL exposes is composed by the BINARY, not the wire: what
// extensions, custom functions, and VFS backends the process registers is what
// clients can use, through SQL. A client cannot add or change any of this over
// the network. Register everything BEFORE calling Run:
//
//	import (
//	    _ "gosqlite.org/server/extensions"   // the curated, network-safe bundle
//	    sqlite "gosqlite.org"
//	    "gosqlite.org/server/serverd"
//	)
//
//	func main() {
//	    // Application-defined SQL functions/collations register globally, on every
//	    // connection the server opens. (A client Go closure can never execute in
//	    // this engine — it must be registered here, server-side.)
//	    sqlite.RegisterAutoHook(func(c *sqlite.Conn) error { return myext.Register(c) })
//	    cfg, _ := config.Load("quicsql.yaml")
//	    srv, _ := serverd.Run(cfg, slog.Default())
//	    // …wait, then srv.Shutdown(ctx)
//	}
//
// Per-database storage and connection settings (backend/VFS, pragmas via
// PragmasPreset + Pragmas, grants) live in the config, also server-side.
package serverd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	warmTimeout             = 30 * time.Second
	defaultStatementTimeout = 30 * time.Second
	defaultTxIdleTimeout    = 30 * time.Second
	reapInterval            = 15 * time.Second
)

// Instance is a running server: its listeners are up and serving. The caller
// owns its lifetime and must call Shutdown to stop it cleanly.
type Instance struct {
	log      *slog.Logger
	servers  *transport.Set
	registry *registry.Registry
	sessions *session.Store
	store    *meta.Store
	reaper   context.CancelFunc

	// Metrics is the live registry, exposed for tests/introspection.
	Metrics *obs.Registry
}

// Servers reports how many listeners are running.
func (in *Instance) Servers() int { return in.servers.Count() }

// Run assembles and starts the server described by cfg. It returns once every
// listener is up (or an error if any stage — a bad seed key, a taken port —
// fails). Seed databases are opened eagerly (fail-fast). The caller drives the
// lifetime and calls Shutdown.
func Run(cfg *config.Config, log *slog.Logger) (*Instance, error) {
	if log == nil {
		log = slog.Default()
	}
	started := time.Now()

	sec, err := secret.New(cfg.Secrets) // eager: all key material resolved at load
	if err != nil {
		return nil, fmt.Errorf("init secrets: %w", err)
	}

	// The slow-query log installs a per-connection profile trace; arm it before any
	// database opens.
	if cfg.Logging.SlowThreshold > 0 {
		backend.InstallSlowLog(cfg.Logging.SlowThreshold, !cfg.Logging.ExpandParams, log)
	}

	var store *meta.Store
	if cfg.ControlPlane.Enabled {
		if store, err = meta.Open(cfg.Server.MetaStore, sec, cfg.Server.DataDir, log); err != nil {
			return nil, fmt.Errorf("open meta store: %w", err)
		}
	}
	dbs, err := reconcile(cfg.Databases, store, log)
	if err != nil {
		closeStore(store, log)
		return nil, fmt.Errorf("reconcile databases: %w", err)
	}
	backends, err := backend.All(dbs, sec, cfg.Server.DataDir)
	if err != nil {
		closeStore(store, log)
		return nil, fmt.Errorf("build backends: %w", err)
	}
	for _, warning := range cfg.Warnings() {
		log.Warn("quicsql: " + warning)
	}

	reg := registry.New(backends, log)
	warmCtx, warmCancel := context.WithTimeout(context.Background(), warmTimeout)
	if err := reg.Warm(warmCtx); err != nil {
		warmCancel()
		_ = reg.Close()
		closeStore(store, log)
		return nil, fmt.Errorf("open seed databases: %w", err)
	}
	warmCancel()

	reaperCtx, stopReaper := context.WithCancel(context.Background())
	sessions, err := session.NewStore(orDefault(cfg.Limits.TxIdleTimeout, defaultTxIdleTimeout), cfg.Limits.MaxTxLifetime, cfg.Limits.MaxWriteSessionsPerDB)
	if err != nil {
		stopReaper()
		_ = reg.Close()
		closeStore(store, log)
		return nil, fmt.Errorf("init sessions: %w", err)
	}
	sessions.StartReaper(reaperCtx, reapInterval)

	authn, err := auth.New(cfg, sec, log)
	if err != nil {
		stopReaper()
		_ = reg.Close()
		closeStore(store, log)
		return nil, fmt.Errorf("init auth: %w", err)
	}
	policy := buildPolicy(cfg, dbs)
	if policy.Open() {
		log.Warn("quicsql: no auth configured — every database is publicly read-write (open mode)")
	}

	metrics := obs.NewRegistry()
	metrics.SetGauge("quicsql_active_sessions", func() int64 { return int64(sessions.Count()) })
	metrics.SetGauge("quicsql_databases", func() int64 { return int64(len(backends)) })
	limiter := limits.New(cfg.Limits.Rate.PerPrincipalRPS, cfg.Limits.MaxConcurrentPerDB)

	eng := engine.New(cfg.Limits.MaxRows, cfg.Limits.MaxResultBytes)
	handlerOpts := []httpapi.Option{
		httpapi.WithLogger(log),
		httpapi.WithMaxBody(cfg.Limits.MaxRequestBytes),
		httpapi.WithMaxBlob(cfg.Limits.MaxBlobBytes),
		httpapi.WithStatementTimeout(orDefault(cfg.Limits.StatementTimeout, defaultStatementTimeout)),
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
		stopReaper()
		sessions.CloseAll()
		_ = reg.Close()
		closeStore(store, log)
		return nil, fmt.Errorf("start listeners: %w", err)
	}
	log.Info("quicsql: ready", "databases", len(backends), "servers", servers.Count())

	return &Instance{
		log: log, servers: servers, registry: reg, sessions: sessions,
		store: store, reaper: stopReaper, Metrics: metrics,
	}, nil
}

// Shutdown stops the listeners (draining in-flight requests within ctx), then
// the sessions (rolling back open transactions and returning connections), then
// the registry (WAL checkpoint on handle close) and the meta store — in that
// order, so nothing closes a resource still in use.
func (in *Instance) Shutdown(ctx context.Context) {
	in.log.Info("quicsql: shutting down")
	in.servers.Shutdown(ctx)
	in.reaper()
	in.sessions.CloseAll()
	if err := in.registry.Close(); err != nil {
		in.log.Error("quicsql: registry close", "err", err)
	}
	closeStore(in.store, in.log)
}

func closeStore(store *meta.Store, log *slog.Logger) {
	if store == nil {
		return
	}
	if err := store.Close(); err != nil {
		log.Error("quicsql: meta store close", "err", err)
	}
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// buildPolicy compiles the reconciled databases' grants into the authz policy.
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
// runtime-created ones (meta wins on a name conflict; a store-less run returns
// the seeds). Meta specs are re-validated so a tampered store can't inject a
// database that never passed config validation.
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
	for _, db := range created {
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
