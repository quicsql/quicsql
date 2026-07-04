package sqldriver

import (
	"strings"
	"testing"
)

// TestRedactDSN proves redactDSN strips both userinfo passwords and sensitive
// query params from a well-formed secret-bearing DSN (follow-up item 1).
func TestRedactDSN(t *testing.T) {
	out := redactDSN("quicsql://user:hunter2@h:7777/db?token=SECRET&password=PW&key=K&transport=h1")
	for _, leak := range []string{"SECRET", "PW", "hunter2", "K"} {
		if strings.Contains(out, leak) {
			t.Fatalf("redactDSN leaked %q: %s", leak, out)
		}
	}
	// Non-secret structure is preserved so the message is still useful.
	if !strings.Contains(out, "transport=h1") {
		t.Fatalf("redactDSN dropped non-secret params: %s", out)
	}
	if !strings.Contains(out, "REDACTED") {
		t.Fatalf("redactDSN did not mark redacted params: %s", out)
	}
}

// TestRedactDSNUnparseable proves an unparseable (still possibly secret-bearing)
// DSN collapses to a placeholder instead of being echoed.
func TestRedactDSNUnparseable(t *testing.T) {
	if got := redactDSN("quicsql://h\x7f/db?token=SECRET"); strings.Contains(got, "SECRET") {
		t.Fatalf("redactDSN echoed an unparseable secret DSN: %s", got)
	}
}
