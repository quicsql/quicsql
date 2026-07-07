package backend

import (
	"log/slog"
	"sync"
	"time"

	"gosqlite.org"
)

// slowLogOnce guards the process-global slow-log trace registration.
var slowLogOnce sync.Once

// InstallSlowLog registers a per-connection profile trace (via RegisterAutoHook,
// once per process) that logs every statement whose execution time reaches
// threshold to log. Bound parameters are redacted by default — the traced SQL is
// the unexpanded text (`?` placeholders), so no values are logged unless
// redactParams is false, which asks SQLite to expand the parameters into the SQL.
//
// It must be called before the first connection opens (like installSecurity),
// and is first-call-wins per process (a sync.Once guards the global trace
// registration) — reconfiguring the threshold on a config reload is out of scope.
// threshold<=0 logs every statement (the general/query log).
func InstallSlowLog(threshold time.Duration, redactParams bool, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	slowLogOnce.Do(func() {
		sqlite.RegisterAutoHook(func(c *sqlite.Conn) error {
			return c.SetTrace(&sqlite.TraceConfig{
				EventMask:       sqlite.TraceProfile,
				WantExpandedSQL: !redactParams,
				Callback: func(info sqlite.TraceInfo) int {
					if info.Duration < threshold {
						return 0
					}
					sql := info.Statement
					if !redactParams && info.ExpandedSQL != "" {
						sql = info.ExpandedSQL
					}
					log.Info("slow",
						"duration_ms", info.Duration.Milliseconds(),
						"sql", sql)
					return 0
				},
			})
		})
	})
}
