// Command quicsql is the quicSQL server daemon. It serves the native-JSON and
// Hrana endpoints over every transport (HTTP/1.1, cleartext h2c, HTTP/2 over TLS,
// HTTP/3 over QUIC, and Unix sockets) — see .plans/plan-quicsql-server.md.
//
// It is a single brand-named binary (not `-d`-suffixed) so later phases can add
// subcommands (`quicsql serve`, `quicsql query`, `quicsql admin`) without a rename.
// The assembly lives in package serverd, shared with the in-process example.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"quicsql.net/config"
	_ "quicsql.net/extensions" // curated, network-safe extension bundle (regexp, vec0, fts5, …)
	"quicsql.net/serverd"
)

const shutdownGrace = 10 * time.Second

func main() {
	cfgPath := flag.String("config", "quicsql.yaml", "path to the YAML config file")
	flag.Parse()

	log := slog.Default()
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("quicsql: load config", "err", err)
		os.Exit(1)
	}
	srv, err := serverd.Run(cfg, log)
	if err != nil {
		log.Error("quicsql: start", "err", err)
		os.Exit(1)
	}

	appCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-appCtx.Done()

	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	srv.Shutdown(sctx)
}
