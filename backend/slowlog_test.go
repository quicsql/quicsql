package backend

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gosqlite.org/server/config"
	"gosqlite.org/server/secret"
)

// TestSlowLogCapturesAndRedacts installs the slow log at threshold 0 (log every
// statement) and verifies it records the statement text with bound parameters
// REDACTED (the unexpanded `?`, not the value).
func TestSlowLogCapturesAndRedacts(t *testing.T) {
	buf := &syncBuffer{}
	InstallSlowLog(0, true, slog.New(slog.NewTextHandler(buf, nil)))

	sec, _ := secret.New(nil)
	be, err := For(config.Database{Name: "sl", Backend: "file", Path: filepath.Join(t.TempDir(), "sl.db")}, sec, "")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	db, err := be.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "CREATE TABLE t(x)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO t VALUES(?)", 4242); err != nil {
		t.Fatalf("insert: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "quicsql/slow") {
		t.Fatalf("slow log produced no entries:\n%s", out)
	}
	if !strings.Contains(out, "INSERT INTO t VALUES(?)") {
		t.Fatalf("slow log did not record the statement:\n%s", out)
	}
	if strings.Contains(out, "4242") {
		t.Fatalf("bound parameter leaked into the redacted slow log:\n%s", out)
	}
}

// syncBuffer is a minimal concurrency-safe buffer. slog already serializes its
// writes, but the trace callback can fire from a pool goroutine, so guard it.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
