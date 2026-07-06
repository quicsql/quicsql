// Package notify delivers out-of-band security notifications for the accounts
// model — "a new sign-in method was added", "a recovery was used", etc. (accounts
// design §14.1, a NIST SHALL). The core is provider-agnostic: a Notifier consumes a
// rendered Message and reports transient vs permanent failure. Built-ins cover the
// dependency-free cases; email senders (command hook, HTTP API) arrive in Phase 2.
//
// Out-of-band delivery is best-effort and separate from the always-present in-app /
// audit record the account service writes — so a channel-less account (no verified
// email) still gets its security event recorded (§21-A4).
package notify

import (
	"context"
	"errors"
)

// Event keys — machine-readable, greppable in the audit log.
const (
	EventCredentialAdded   = "credential.added"
	EventCredentialRemoved = "credential.removed"
	EventRecoveryUsed      = "recovery.used"
	EventSessionsRevoked   = "sessions.revoked"
)

// Message is a rendered notification bound to an account. Channel resolution
// (which address to reach) is the Notifier's job.
type Message struct {
	Account string // the account principal
	Event   string
	Subject string
	Body    string
	Meta    map[string]string
}

// Notifier delivers a Message over some out-of-band channel. Distinguish
// ErrTransient (retry) from ErrPermanent (drop) so the caller's outbox can decide.
type Notifier interface {
	Notify(ctx context.Context, m Message) error
}

var (
	ErrTransient = errors.New("notify: transient failure (retry)")
	ErrPermanent = errors.New("notify: permanent failure (drop)")
)

// Noop drops notifications — the default when no out-of-band channel is configured
// (the in-app/audit record still happens). Also used in tests.
type Noop struct{}

// Notify implements Notifier.
func (Noop) Notify(context.Context, Message) error { return nil }
