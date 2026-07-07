package wire

// Wire-protocol identifiers shared by the server (auth, transport) and the Go client:
// the custom HTTP header names, the session-token prefix, and the auth realm. Defined
// here ONCE — a single source of truth so the two sides can never drift and there are no
// scattered string literals. Brand-neutral by design (white-label): they carry no product
// name. Changing one is a wire-contract change — update every client too.
const (
	// HeaderSessionToken carries a freshly extended session token on the transparent
	// sliding-refresh response; HeaderSessionExpires carries its new expiry (RFC3339).
	HeaderSessionToken   = "X-Session-Token"
	HeaderSessionExpires = "X-Session-Expires"

	// The ed25519 keyring challenge/response request headers: the public-key line, the
	// server challenge being answered, and the signature over the request binding.
	HeaderKeyringKey       = "X-Keyring-Key"
	HeaderKeyringChallenge = "X-Keyring-Challenge"
	HeaderKeyringSignature = "X-Keyring-Signature"

	// SessionTokenPrefix shape-discriminates a minted session token from a static bearer
	// so one Authorization: Bearer value routes to exactly one auth method.
	SessionTokenPrefix = "st_"

	// AuthRealm is the WWW-Authenticate realm returned on a 401 (shown in a browser's
	// basic-auth prompt) — generic, never a product brand.
	AuthRealm = "restricted"
)
