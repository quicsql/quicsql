package wire

import "testing"

// TestWireIdentifiers pins the exact on-the-wire strings. Everything else references
// these constants (single source), so this is the ONE place the literal values are
// asserted — a wrong rename that would silently break the SDK contract fails here.
// They are brand-neutral by requirement (white-label): no product name on the wire.
func TestWireIdentifiers(t *testing.T) {
	cases := map[string]string{
		HeaderSessionToken:     "X-Session-Token",
		HeaderSessionExpires:   "X-Session-Expires",
		HeaderKeyringKey:       "X-Keyring-Key",
		HeaderKeyringChallenge: "X-Keyring-Challenge",
		HeaderKeyringSignature: "X-Keyring-Signature",
		SessionTokenPrefix:     "st_",
		AuthRealm:              "restricted",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("wire identifier drifted: got %q, want %q", got, want)
		}
	}
}
