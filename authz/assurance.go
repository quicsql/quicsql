package authz

import (
	"errors"
	"time"
)

// This file adds the ACCOUNT-MANAGEMENT authorization dimension used by an identity feature.
// It is orthogonal to Level: Level governs per-database data access
// (unchanged), while the assurance model below governs sensitive actions on an
// account's own credentials/recovery/sessions. The vocabulary lives here (not in
// package auth) so it can travel on the Principal and be gated by handlers without
// depending on how a session was minted.

// Tier is what a session may MANAGE, as an ORDERED ladder (like Level): a higher
// tier includes every capability below it, so the gate checks "at least owner"
// with >=. Two rungs exist today; finer roles (e.g. a "member" who may invite but
// not delete) slot in AS NEW RUNGS IN ORDER — iota renumbers them and, because each
// ActionClass checks its own minimum tier, existing gates keep working. Tokens are
// ephemeral (a restart re-signs), so renumbering needs no migration. If roles ever
// become NON-linear (capabilities that don't nest — e.g. billing orthogonal to
// credential management), swap this scale for a capability bitset; RequireAssurance
// is the single chokepoint, and the token already reserves a full byte for the field.
type Tier uint8

const (
	TierDataOnly Tier = iota // may touch data (subject to Level), never authenticators
	// (insert intermediate rungs here — e.g. TierMember — as the model grows)
	TierOwner // may manage the account's own credentials / recovery / sessions
)

// Factor is a bitset of the authentication methods a session actually used (the
// OIDC `amr`). Step-up policy checks which factors are present and how fresh.
type Factor uint16

const (
	FactorPassword  Factor = 1 << 0
	FactorOTP       Factor = 1 << 1
	FactorWebAuthn  Factor = 1 << 2
	FactorDeviceKey Factor = 1 << 3
	FactorRecovery  Factor = 1 << 4
)

// StrictFactors is the factor set the STRICT assurance rung requires: WebAuthn, an
// origin/challenge-bound device keypair, and the recovery key. It is the default bar for
// credential management / destructive actions. The name states the POLICY ROLE, not a
// security claim — the *reason* we currently trust these (they resist verifier-
// impersonation phishing, unlike a re-enterable password or TOTP code) lives in
// prose that can be revised without renaming code or the wire.
const StrictFactors = FactorWebAuthn | FactorDeviceKey | FactorRecovery

// Scope narrows a session below its tier. A reduced-scope session (from a single
// recovery code or email recovery) may not perform destructive actions until
// NotBeforeDestructive passes.
type Scope uint8

const (
	ScopeFull    Scope = 0
	ScopeReduced Scope = 1
)

// Canonical wire/display names for the assurance enums — the SINGLE source of truth for
// their string form. The session-assurance readout and the tier config value
// both use these (via String() and the exported Tier* names), so they cannot drift. A UI
// may relabel them; the machine values live here, next to the types they name.
const (
	TierNameDataOnly = "data-only"
	TierNameOwner    = "owner"

	scopeNameFull    = "full"
	scopeNameReduced = "reduced"

	factorNameWebAuthn  = "webauthn"
	factorNameDeviceKey = "device_key"
	factorNameRecovery  = "recovery"
	factorNamePassword  = "password"
	factorNameOTP       = "otp"
)

// String is the canonical wire name of the tier ("data-only" | "owner").
func (t Tier) String() string {
	if t >= TierOwner {
		return TierNameOwner
	}
	return TierNameDataOnly
}

// String is the canonical wire name of the scope ("full" | "reduced").
func (s Scope) String() string {
	if s == ScopeReduced {
		return scopeNameReduced
	}
	return scopeNameFull
}

// Names returns the amr factor names present in the bitset, in a stable order — the
// whitelabel-neutral machine names in the session-assurance readout (never a brand).
func (f Factor) Names() []string {
	out := make([]string, 0, 5)
	for _, m := range []struct {
		bit  Factor
		name string
	}{
		{FactorWebAuthn, factorNameWebAuthn},
		{FactorDeviceKey, factorNameDeviceKey},
		{FactorRecovery, factorNameRecovery},
		{FactorPassword, factorNamePassword},
		{FactorOTP, factorNameOTP},
	} {
		if f&m.bit != 0 {
			out = append(out, m.name)
		}
	}
	return out
}

// Assurance is a session's authentication context, carried in the server-signed
// session token and surfaced on the Principal so account-management handlers can
// gate sensitive actions. It is nil for non-session principals (static bearer,
// mtls, peercred, anonymous), which therefore hold no owner capability.
type Assurance struct {
	Tier                 Tier
	Factors              Factor
	AuthTime             time.Time // when a factor was last freshly presented (drives step-up recency)
	CredID               string    // the credential that authenticated (for targeted revocation)
	Scope                Scope
	NotBeforeDestructive time.Time // destructive actions barred until this instant (reduced scope)
}

// ActionClass groups account-management actions by the assurance they demand.
type ActionClass int

const (
	// DataWrite is any ordinary data action — governed by Level, needs no step-up.
	DataWrite ActionClass = iota
	// CredentialMgmt adds/enumerates authenticators (owner + a fresh factor).
	CredentialMgmt
	// Destructive removes a credential, rotates recovery, deletes/transfers the DB.
	Destructive
	// RecoveryRoot rebuilds the account from the recovery key (root).
	RecoveryRoot
)

// AssurancePolicy is the operator-configured factor requirement per action class
// plus the step-up recency window. The zero value resolves to the SECURE defaults
// (phishing-resistant for credential-management and destructive actions); an
// operator may loosen it (and the server warns at startup).
type AssurancePolicy struct {
	CredentialMgmt Factor
	Destructive    Factor
	StepUpWindow   time.Duration
}

func (p AssurancePolicy) withDefaults() AssurancePolicy {
	if p.CredentialMgmt == 0 {
		p.CredentialMgmt = StrictFactors
	}
	if p.Destructive == 0 {
		p.Destructive = StrictFactors
	}
	if p.StepUpWindow == 0 {
		p.StepUpWindow = 10 * time.Minute
	}
	return p
}

// Assurance gate errors — handlers map these to 401/403 with a step-up hint.
var (
	ErrOwnerRequired  = errors.New("authz: owner capability required for this action")
	ErrStepUpRequired = errors.New("authz: step-up required — present a fresh phishing-resistant factor")
	ErrScopeReduced   = errors.New("authz: reduced-scope session may not perform destructive actions yet")
)

// RequireAssurance gates a sensitive account-management action against the
// session's Assurance and the operator policy. `now` is a parameter for
// deterministic tests. Returns nil when permitted.
func RequireAssurance(a *Assurance, action ActionClass, pol AssurancePolicy, now time.Time) error {
	if action == DataWrite {
		return nil // any valid session; Level still governs the data itself
	}
	if a == nil {
		return ErrOwnerRequired // no session assurance context ⇒ no owner capability
	}
	pol = pol.withDefaults()
	switch action {
	case CredentialMgmt, Destructive:
		if a.Tier < TierOwner { // ordered ladder: "at least owner"
			return ErrOwnerRequired
		}
		// A reduced-scope session (from a single recovery code or email recovery) may
		// not MANAGE credentials OR perform destructive actions until the hold passes.
		// Gating only Destructive is insufficient: otherwise one recovery code could
		// mint an attach code / add a fresh full-power owner credential and reach root
		// through it, defeating the hold. It keeps DataWrite access.
		if a.Scope == ScopeReduced && now.Before(a.NotBeforeDestructive) {
			return ErrScopeReduced
		}
		need := pol.CredentialMgmt
		if action == Destructive {
			need = pol.Destructive
		}
		if a.Factors&need == 0 || now.Sub(a.AuthTime) > pol.StepUpWindow {
			return ErrStepUpRequired
		}
		return nil
	case RecoveryRoot:
		// Only the recovery key (or an equivalent two-proof session, later) reaches
		// root; a single recovery code lands as reduced-scope and does not.
		if a.Factors&FactorRecovery == 0 || a.Scope == ScopeReduced {
			return ErrStepUpRequired
		}
		if now.Sub(a.AuthTime) > pol.StepUpWindow {
			return ErrStepUpRequired
		}
		return nil
	default:
		return ErrOwnerRequired
	}
}
