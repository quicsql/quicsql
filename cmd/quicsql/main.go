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
