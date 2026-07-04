// Command quicsql is the quicSQL server daemon. It serves the native-JSON and
// Hrana endpoints over every transport (HTTP/1.1, cleartext h2c, HTTP/2 over TLS,
// HTTP/3 over QUIC, and Unix sockets).
//
// It is a single brand-named binary (not `-d`-suffixed) so later phases can add
// subcommands (`quicsql serve`, `quicsql query`, `quicsql admin`) without a rename.
// The assembly lives in package serverd, shared with the in-process example.
package main

import (
	"context"
	"flag"
	"fmt"
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

// newLogger builds the process logger from the configured logging.format: "json"
// emits structured JSON (for a log pipeline), "text" or "" emits the default
// human-readable text. Output goes to stderr so stdout stays clean. Config
// validation has already rejected any other value.
func newLogger(format string) *slog.Logger {
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// version is the build version, stamped at release time via
// -ldflags "-X main.version=<tag>" (see .goreleaser.yaml); "dev" otherwise.
var version = "dev"

func main() {
	hardenUmask() // create data files owner-only (0600), before anything opens a file

	cfgPath := flag.String("config", "quicsql.yaml", "path to the YAML config file")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("quicsql", version)
		return
	}

	// Bootstrap logger for config-load errors — we don't know the configured format
	// until the config parses.
	log := slog.Default()
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("quicsql: load config", "err", err)
		os.Exit(1)
	}
	// Now build the real logger from logging.format (json | text) and make it the
	// process default so every component (including the slow-query log) uses it.
	log = newLogger(cfg.Logging.Format)
	slog.SetDefault(log)
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
