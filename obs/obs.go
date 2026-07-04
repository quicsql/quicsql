// Package obs is the observability seam. Live today: the Metrics interface with
// a Prometheus-text metrics Registry (served at /_metrics), alongside the slow-query log
// (driver TraceProfile — see backend.InstallSlowLog) and the admin audit log
// (meta store). The Channels type below is a seam for later work: routing each
// structured channel to its own sink (file, per-database file, syslog) and the
// live MONITOR tail are not yet wired — every channel currently fans to the
// default logger.
package obs

import (
	"io"
	"log/slog"
	"time"
)

// Channels holds one logger per structured channel. Phase 0 points them all at
// the default logger; Phase 7 gives each an independent sink and format.
type Channels struct {
	Server   *slog.Logger // lifecycle / errors
	Conn     *slog.Logger // connect / disconnect / auth outcome
	SQLExec  *slog.Logger // statements (opt-in verbose = general log)
	SQLSlow  *slog.Logger // over the slow threshold
	SQLAudit *slog.Logger // who ran what (security)
	SQLError *slog.Logger // statement errors
}

// Default fans every channel to slog.Default.
func Default() *Channels {
	l := slog.Default()
	return &Channels{Server: l, Conn: l, SQLExec: l, SQLSlow: l, SQLAudit: l, SQLError: l}
}

// Metrics is the counter/latency sink. Phase 7 backs it with a Prometheus-text
// exporter; Nop is the Phase 0 default.
type Metrics interface {
	IncRequests(db, principal string)
	ObserveLatency(db string, d time.Duration)
	Forget(db string) // drop a detached database's series
}

// Nop is a no-op Metrics.
type Nop struct{}

func (Nop) IncRequests(string, string)           {}
func (Nop) ObserveLatency(string, time.Duration) {}
func (Nop) Forget(string)                        {}

// Exposer is implemented by a Metrics sink that can render itself as
// Prometheus text (the /_metrics endpoint checks for it).
type Exposer interface {
	WritePrometheus(w io.Writer)
}
