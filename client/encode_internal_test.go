package client

import (
	"encoding/json"
	"testing"
	"time"
)

// TestEncodeTimeConsistent locks in the H6 fix: the native (encodeRequest) and
// Hrana (encodeHValue) paths must encode a time.Time to the identical
// RFC3339Nano text, so the same value stores the same way whether it is bound in
// autocommit or inside an interactive transaction.
func TestEncodeTimeConsistent(t *testing.T) {
	ts := time.Date(2026, 7, 3, 12, 34, 56, 123456789, time.UTC)
	want := ts.Format(time.RFC3339Nano)

	h := encodeHValue(ts)
	if h["type"] != "text" || h["value"] != want {
		t.Fatalf("encodeHValue(time) = %v, want {text, %q}", h, want)
	}

	body, err := encodeRequest("SELECT ?", []any{ts})
	if err != nil {
		t.Fatalf("encodeRequest: %v", err)
	}
	var req struct {
		Args []any `json:"args"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(req.Args) != 1 || req.Args[0] != want {
		t.Fatalf("encodeRequest(time) arg = %#v, want %q", req.Args, want)
	}
}
