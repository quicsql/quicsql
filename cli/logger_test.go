package cli

import (
	"log/slog"
	"testing"
)

// TestNewLogger proves logging.format selects the handler: "json" → JSON, "text"
// and "" (default) → text.
func TestNewLogger(t *testing.T) {
	if _, ok := newLogger("json").Handler().(*slog.JSONHandler); !ok {
		t.Fatalf("newLogger(json): want *slog.JSONHandler, got %T", newLogger("json").Handler())
	}
	for _, f := range []string{"text", ""} {
		if _, ok := newLogger(f).Handler().(*slog.TextHandler); !ok {
			t.Fatalf("newLogger(%q): want *slog.TextHandler, got %T", f, newLogger(f).Handler())
		}
	}
}
