package transport

import (
	"testing"

	"quicsql.net/config"
)

// TestAltSvcHeader covers the opt-in Alt-Svc value: nothing unless an h3 listener
// sets advertise, then a port-only h3 authority per advertised listener.
func TestAltSvcHeader(t *testing.T) {
	ls := []config.Listener{
		{Name: "h2", Transport: "h2", Address: "127.0.0.1:7777"},
		{Name: "h3", Transport: "h3", Address: "127.0.0.1:7777"}, // not advertised
	}
	if got := altSvcHeader(ls); got != "" {
		t.Fatalf("no advertise → want empty, got %q", got)
	}

	ls[1].Advertise = true
	if got, want := altSvcHeader(ls), `h3=":7777"; ma=2592000`; got != want {
		t.Fatalf("advertise → got %q, want %q", got, want)
	}

	// A second advertised h3 (different port) joins with a comma.
	ls = append(ls, config.Listener{Name: "h3b", Transport: "h3", Address: "0.0.0.0:7779", Advertise: true})
	if got, want := altSvcHeader(ls), `h3=":7777"; ma=2592000, h3=":7779"; ma=2592000`; got != want {
		t.Fatalf("two advertised → got %q, want %q", got, want)
	}
}
