// Package cli is the reusable quicSQL server launcher. A product binary — quicSQL
// itself (`cmd/quicsql`), or a downstream build that compiles in optional feature
// modules — calls Main with its own branding; the flag
// parsing, config load, logger setup, signal handling, and graceful shutdown live
// here once. Modeled on Caddy's caddycmd.Main / CoreDNS's coremain.Run: the product
// picks its module set (via blank imports) and its brand, and reuses this launcher.
package cli

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
	"quicsql.net/serverd"
)

const shutdownGrace = 10 * time.Second

// Options brands and configures a launch. The zero value runs as "quicsql".
type Options struct {
	// Program is the binary's brand name — shown by `--version` and used as the
	// log/error prefix (e.g. "quicsql"). Defaults to "quicsql".
	Program string
	// Version is the build version string, typically stamped via
	// -ldflags "-X main.version=<tag>" and passed in by the product's main.
	Version string
	// DefaultConfig is the default value of the -config flag. Defaults to "quicsql.yaml".
	DefaultConfig string
}

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

// Main runs the server daemon end to end: harden the umask, parse flags, load the
// config, build the logger, start the server, then block until SIGINT/SIGTERM and
// shut down gracefully. It calls os.Exit on a fatal startup error, so it does not
// return in that case — call it as the last thing in a product's main.
func Main(opts Options) {
	program := opts.Program
	if program == "" {
		program = "quicsql"
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	defaultConfig := opts.DefaultConfig
	if defaultConfig == "" {
		defaultConfig = "quicsql.yaml"
	}

	hardenUmask() // create data files owner-only (0600), before anything opens a file

	cfgPath := flag.String("config", defaultConfig, "path to the YAML config file")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(program, version)
		return
	}

	// Bootstrap logger for config-load errors — we don't know the configured format
	// until the config parses.
	log := slog.Default()
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error(program+": load config", "err", err)
		os.Exit(1)
	}
	// Now build the real logger from logging.format (json | text) and make it the
	// process default so every component (including the slow-query log) uses it.
	log = newLogger(cfg.Logging.Format)
	slog.SetDefault(log)
	srv, err := serverd.Run(cfg, log)
	if err != nil {
		log.Error(program+": start", "err", err)
		os.Exit(1)
	}

	appCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-appCtx.Done()

	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	srv.Shutdown(sctx)
}
