// Command quicsql is the quicSQL server daemon. Phase 1 serves the native-JSON
// endpoint over cleartext HTTP/1.1 (and Unix sockets); TLS/h2/h2c/HTTP-3 arrive
// in Phase 3. See .plans/plan-quicsql-server.md.
//
// It is a single brand-named binary (not `-d`-suffixed) so later phases can add
// subcommands (`quicsql serve`, `quicsql query`, `quicsql admin`) without a rename.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/engine"
	"gosqlite.org/server/httpapi"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/secret"
)

const (
	readHeaderTimeout       = 10 * time.Second
	readTimeout             = 30 * time.Second
	writeTimeout            = 60 * time.Second
	idleTimeout             = 120 * time.Second
	shutdownGrace           = 10 * time.Second
	warmTimeout             = 30 * time.Second
	defaultStatementTimeout = 30 * time.Second
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

	stmtTimeout := cfg.Limits.StatementTimeout
	if stmtTimeout <= 0 {
		stmtTimeout = defaultStatementTimeout
	}
	eng := engine.New(cfg.Limits.MaxRows, cfg.Limits.MaxResultBytes)
	handler := httpapi.New(reg, eng, cfg.Routing,
		httpapi.WithLogger(log),
		httpapi.WithMaxBody(cfg.Limits.MaxRequestBytes),
		httpapi.WithStatementTimeout(stmtTimeout),
	)

	servers, err := serve(log, cfg, handler)
	if err != nil {
		log.Error("quicsql: start listeners", "err", err)
		_ = reg.Close() // orderly close (WAL checkpoint / vault teardown) before exit
		os.Exit(1)
	}
	log.Info("quicsql: ready", "databases", len(backends), "listeners", len(servers))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Info("quicsql: shutting down")
	shutdown(log, servers)
	if err := reg.Close(); err != nil {
		log.Error("quicsql: registry close", "err", err)
	}
}

// serve starts an http.Server per cleartext listener (h1/h2c served as HTTP/1.1
// in Phase 1; unix as a UDS). TLS transports (h2/h3) are logged as deferred. On
// a mid-startup listen failure it shuts down the servers it already started and
// returns the error, so the caller can close the registry cleanly.
func serve(log *slog.Logger, cfg *config.Config, handler http.Handler) ([]*http.Server, error) {
	var servers []*http.Server
	for _, lc := range cfg.Listeners {
		var ln net.Listener
		var err error
		switch lc.Transport {
		case "unix":
			_ = os.Remove(lc.Address)
			ln, err = net.Listen("unix", lc.Address)
		case "h1", "h2c":
			ln, err = net.Listen("tcp", lc.Address)
		default:
			log.Warn("quicsql: transport deferred to a later phase", "listener", lc.Name, "transport", lc.Transport)
			continue
		}
		if err != nil {
			shutdown(log, servers) // unwind the listeners already started
			return nil, fmt.Errorf("listen %s: %w", lc.Name, err)
		}
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
		}
		servers = append(servers, srv)
		go func(name, addr string) {
			log.Info("quicsql: serving", "listener", name, "addr", addr)
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Error("quicsql: serve", "listener", name, "err", err)
			}
		}(lc.Name, ln.Addr().String())
	}
	return servers, nil
}

func shutdown(log *slog.Logger, servers []*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			log.Error("quicsql: server shutdown", "err", err)
		}
	}
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error("quicsql: "+msg, "err", err)
	os.Exit(1)
}
