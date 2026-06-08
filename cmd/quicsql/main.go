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

	"gosqlite.org/server/auth"
	"gosqlite.org/server/authz"
	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/engine"
	"gosqlite.org/server/httpapi"
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

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(log, "load config", err)
	}
	sec, err := secret.New(cfg.Secrets) // eager: all key material resolved at load
	if err != nil {
		fatal(log, "init secrets", err)
	}
	backends, err := backend.All(cfg, sec)
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
	policy := buildPolicy(cfg)
	if policy.Open() {
		log.Warn("quicsql: no auth configured — every database is publicly read-write (open mode)")
	}

	eng := engine.New(cfg.Limits.MaxRows, cfg.Limits.MaxResultBytes)
	handler := httpapi.New(reg, eng, cfg.Routing,
		httpapi.WithLogger(log),
		httpapi.WithMaxBody(cfg.Limits.MaxRequestBytes),
		httpapi.WithStatementTimeout(stmtTimeout),
		httpapi.WithSessions(sessions),
		httpapi.WithPolicy(policy),
	)

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
}

// buildPolicy compiles the per-database grants into the authz policy. Open mode
// (no principals and no grants anywhere) makes every principal read-write.
func buildPolicy(cfg *config.Config) *authz.Policy {
	pol := authz.NewPolicy(!cfg.AuthConfigured())
	for _, db := range cfg.Databases {
		for _, g := range db.Grants {
			if lvl, ok := authz.ParseLevel(g.Level); ok {
				pol.Grant(db.Name, g.Principal, lvl)
			}
		}
	}
	return pol
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error("quicsql: "+msg, "err", err)
	os.Exit(1)
}
