package auth

import (
	"testing"
	"time"

	"quicsql.net/authz"
)

// TestMintStepUpDoesNotRefreshRecency is the regression test for the audit CRITICAL
// for accounts: a phishable TOTP step-up must NOT refresh the recency of a
// carried-forward phishing-resistant factor, or a stolen STALE owner session + one
// phished code would reach owner/destructive actions and take the account over.
func TestMintStepUpDoesNotRefreshRecency(t *testing.T) {
	m := buildSession(t, time.Hour)

	// A stale owner session: a phishing-resistant factor (WebAuthn) presented 20 min ago
	// — past the default 10-min step-up window, so it can no longer do destructive actions.
	stale := authz.Assurance{
		Tier: authz.TierOwner, Factors: authz.FactorWebAuthn, Scope: authz.ScopeFull,
		AuthTime: time.Now().Add(-20 * time.Minute),
	}
	// Sanity: before the step-up, the stale session is already barred from Destructive.
	if err := authz.RequireAssurance(&stale, authz.Destructive, authz.AssurancePolicy{}, time.Now()); err != authz.ErrStepUpRequired {
		t.Fatalf("precondition: stale owner must need step-up, got %v", err)
	}

	tok, _, _, err := m.a.MintStepUp("u_alice", stale, authz.FactorOTP, "")
	if err != nil {
		t.Fatalf("MintStepUp: %v", err)
	}
	name, _, claims, err := m.a.sessions.verify(tok)
	if err != nil || name != "u_alice" {
		t.Fatalf("verify: name=%q err=%v", name, err)
	}
	asr := claims.assurance()

	// The OTP factor WAS added (it raises "strong" for data actions)…
	if asr.Factors&authz.FactorOTP == 0 {
		t.Fatal("OTP factor should have been added by the step-up")
	}
	// …but the recency clock was NOT advanced (auth_time preserved from the stale token).
	if time.Since(asr.AuthTime) < 15*time.Minute {
		t.Fatalf("auth_time must be preserved (stale), but its age is only %v", time.Since(asr.AuthTime))
	}
	// THE CRITICAL PROPERTY: the stepped-up token STILL cannot perform destructive/owner
	// actions — the phishable code did not re-validate the stale phishing-resistant factor.
	if err := authz.RequireAssurance(asr, authz.Destructive, authz.AssurancePolicy{}, time.Now()); err != authz.ErrStepUpRequired {
		t.Fatalf("stale owner + OTP step-up must STILL be barred from Destructive, got %v", err)
	}
	if err := authz.RequireAssurance(asr, authz.CredentialMgmt, authz.AssurancePolicy{}, time.Now()); err != authz.ErrStepUpRequired {
		t.Fatalf("stale owner + OTP step-up must STILL be barred from CredentialMgmt, got %v", err)
	}

	// Contrast: a genuinely fresh phishing-resistant presentation DOES pass the gate.
	fresh := authz.Assurance{Tier: authz.TierOwner, Factors: authz.FactorWebAuthn, Scope: authz.ScopeFull, AuthTime: time.Now()}
	if err := authz.RequireAssurance(&fresh, authz.Destructive, authz.AssurancePolicy{}, time.Now()); err != nil {
		t.Fatalf("a fresh phishing-resistant factor must pass Destructive, got %v", err)
	}
}
