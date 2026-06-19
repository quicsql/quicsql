package backend

import (
	"testing"
	"time"

	sqlite "gosqlite.org"
	"quicsql.net/config"
)

func TestPragmasPreset(t *testing.T) {
	// No preset → bare SQLite (all zero), unchanged from the default.
	bare := pragmas(config.Database{})
	if bare.JournalMode != "" || bare.ForeignKeys || bare.BusyTimeout != 0 {
		t.Fatalf("bare preset = %+v, want zero-value pragmas", bare)
	}

	// "recommended" seeds the production preset.
	rec := pragmas(config.Database{PragmasPreset: "recommended"})
	if rec.JournalMode != sqlite.JournalWAL {
		t.Errorf("recommended JournalMode = %q, want WAL", rec.JournalMode)
	}
	if !rec.ForeignKeys {
		t.Error("recommended ForeignKeys = false, want true")
	}
	if rec.BusyTimeout != 5*time.Second {
		t.Errorf("recommended BusyTimeout = %v, want 5s", rec.BusyTimeout)
	}

	// Explicit pragmas override the preset (server operator's final say).
	ov := pragmas(config.Database{
		PragmasPreset: "recommended",
		Pragmas:       map[string]any{"foreign_keys": "off", "journal_mode": "DELETE"},
	})
	if ov.ForeignKeys {
		t.Error("explicit foreign_keys=off did not override the recommended preset")
	}
	if ov.JournalMode != sqlite.JournalMode("DELETE") {
		t.Errorf("explicit journal_mode override = %q, want DELETE", ov.JournalMode)
	}
}
