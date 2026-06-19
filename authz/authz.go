// Package authz is the principal + capability model: it maps an authenticated
// principal to a per-database access Level. It is deliberately neutral — it
// knows nothing about HOW a principal authenticated (that is package auth) or
// which transport carried the request — so both the auth middleware (which sets
// the request principal) and the HTTP handler (which enforces the level) depend
// only on this package, never on each other.
package authz

import (
	"context"
	"sync"
)

// Level is a principal's capability on one database. The zero value (None) is
// "no access", so an unset grant fails closed.
type Level int

const (
	None      Level = iota // no access
	ReadOnly               // may read (SELECT and friends)
	ReadWrite              // may read and write
	Admin                  // read/write plus control-plane admin (Phase 6)
)

// ParseLevel maps a config level string to a Level.
func ParseLevel(s string) (Level, bool) {
	switch s {
	case "none":
		return None, true
	case "read-only", "readonly", "ro":
		return ReadOnly, true
	case "read-write", "readwrite", "rw":
		return ReadWrite, true
	case "admin":
		return Admin, true
	default:
		return None, false
	}
}

func (l Level) String() string {
	switch l {
	case ReadOnly:
		return "read-only"
	case ReadWrite:
		return "read-write"
	case Admin:
		return "admin"
	default:
		return "none"
	}
}

// CanRead reports whether the level permits reads.
func (l Level) CanRead() bool { return l >= ReadOnly }

// CanWrite reports whether the level permits writes.
func (l Level) CanWrite() bool { return l >= ReadWrite }

// CanAdmin reports whether the level permits control-plane admin.
func (l Level) CanAdmin() bool { return l >= Admin }

// Principal is an authenticated identity. The anonymous principal has an empty
// Name; Method records how it authenticated ("none", "bearer", "mtls", …) for
// logging and audit.
type Principal struct {
	Name   string
	Method string
}

// Anonymous is the identity of an unauthenticated request on a listener that
// admits `none`. It holds no named grants — only wildcard (`*`) grants and open
// mode apply to it.
var Anonymous = &Principal{Name: "", Method: "none"}

// IsAnonymous reports whether p is the anonymous (unnamed) principal.
func (p *Principal) IsAnonymous() bool { return p == nil || p.Name == "" }

// Wildcard is the grant subject that matches every principal, including the
// anonymous one.
const Wildcard = "*"

// Policy is the compiled grant table: database → principal → Level. A named
// principal's effective level on a database is the max of its explicit grant and
// any wildcard (`*`) grant. In open mode (no auth configured anywhere) every
// principal gets ReadWrite on every database, preserving the pre-auth
// bind-to-localhost behavior until the operator configures grants.
//
// Policy is safe for concurrent use: requests read levels while the control
// plane grants for a runtime-created database.
type Policy struct {
	mu     sync.RWMutex
	grants map[string]map[string]Level
	open   bool
}

// NewPolicy builds an empty policy. open=true selects open mode.
func NewPolicy(open bool) *Policy {
	return &Policy{grants: map[string]map[string]Level{}, open: open}
}

// Open reports whether the policy is in open (no-auth-configured) mode.
func (p *Policy) Open() bool { return p.open }

// Grant records that principal (a name or Wildcard) has at least level on db.
// Re-granting keeps the highest level.
func (p *Policy) Grant(db, principal string, level Level) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.grants[db]
	if m == nil {
		m = map[string]Level{}
		p.grants[db] = m
	}
	if cur, ok := m[principal]; !ok || level > cur {
		m[principal] = level
	}
}

// Revoke drops every grant on db, so a later database that reuses the name does
// not inherit the old database's privileges. Called when the control plane
// detaches a database.
func (p *Policy) Revoke(db string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.grants, db)
}

// Level returns the effective capability of pr on db.
func (p *Policy) Level(pr *Principal, db string) Level {
	if p.open {
		return ReadWrite
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	m := p.grants[db]
	if m == nil {
		return None
	}
	lvl := m[Wildcard] // absent → None (zero value)
	if pr != nil && pr.Name != "" {
		if l, ok := m[pr.Name]; ok && l > lvl {
			lvl = l
		}
	}
	return lvl
}

type principalKey struct{}

// NewContext returns a copy of ctx carrying the authenticated principal.
func NewContext(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the principal set by the auth middleware, or Anonymous if
// none was set (so a handler always has a non-nil principal to reason about).
func FromContext(ctx context.Context) *Principal {
	if p, ok := ctx.Value(principalKey{}).(*Principal); ok && p != nil {
		return p
	}
	return Anonymous
}
