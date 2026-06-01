// Package auth is the authentication + capability seam. Phase 0 defines the
// principal/level model the registry and engine will consult; the concrete
// Authenticators (no-auth, peercred, bearer/password, mTLS, keyring
// challenge/response) land in Phase 4.
package auth

import "context"

// Level is a capability tier on a database.
type Level int

const (
	None Level = iota
	ReadOnly
	ReadWrite
	Admin
)

// ParseLevel maps a config string to a Level.
func ParseLevel(s string) Level {
	switch s {
	case "read-only":
		return ReadOnly
	case "read-write":
		return ReadWrite
	case "admin":
		return Admin
	default:
		return None
	}
}

// Principal is an authenticated identity plus its per-database grants. A "*"
// grant is the wildcard default.
type Principal struct {
	Name   string
	Grants map[string]Level
}

// Can reports whether the principal holds at least need on db, falling back to
// the wildcard grant.
func (p *Principal) Can(db string, need Level) bool {
	if g, ok := p.Grants[db]; ok {
		return g >= need
	}
	return p.Grants["*"] >= need
}

// Credentials is the raw material an Authenticator inspects (token, client
// cert, peer creds, signed challenge). Fleshed out per-method in Phase 4.
type Credentials struct {
	Method string
	Bearer string
}

// Authenticator turns transport credentials into a Principal. Phase 4 supplies
// implementations; the interface is fixed here so the handler can depend on it.
type Authenticator interface {
	Authenticate(ctx context.Context, cr Credentials) (*Principal, error)
}
