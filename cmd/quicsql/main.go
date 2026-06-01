// Command quicsql is the quicSQL server daemon. Phase 0 wires config → secrets →
// backends → registry → engine and then idles: there are no listeners yet.
// Phase 1+ attach the http.Handler and the transport matrix over the same
// (registry, engine) pair. See .plans/plan-quicsql-server.md.
//
// It is a single brand-named binary (not `-d`-suffixed) so later phases can add
// subcommands (`quicsql serve`, `quicsql query`, `quicsql admin`) without a rename.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gosqlite.org/server/backend"
	"gosqlite.org/server/config"
	"gosqlite.org/server/engine"
	"gosqlite.org/server/obs"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/secret"
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

	reg := registry.New(backends, log)
	eng := engine.New(cfg.Limits.MaxRows, log)
	_ = eng           // Phase 1 attaches the handler that uses it
	_ = obs.Default() // Phase 7 wires the channels

	log.Info("quicsql: ready (phase 0 — no listeners yet)", "databases", len(backends))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Info("quicsql: shutting down")
	if err := reg.Close(); err != nil {
		log.Error("quicsql: registry close", "err", err)
	}
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error("quicsql: "+msg, "err", err)
	os.Exit(1)
}
