package authz

import (
	"testing"
	"time"
)

// TestEnumWireNames pins the canonical string forms of the assurance enums — a wire
// contract (/_auth/whoami) that clients depend on, so it must not drift.
func TestEnumWireNames(t *testing.T) {
	if got := TierDataOnly.String(); got != "data-only" {
		t.Errorf("TierDataOnly: want data-only, got %q", got)
	}
	if got := TierOwner.String(); got != "owner" {
		t.Errorf("TierOwner: want owner, got %q", got)
	}
	if got := ScopeFull.String(); got != "full" {
		t.Errorf("ScopeFull: want full, got %q", got)
	}
	if got := ScopeReduced.String(); got != "reduced" {
		t.Errorf("ScopeReduced: want reduced, got %q", got)
	}
	// Names lists present factors in the stable documented order.
	got := (FactorWebAuthn | FactorPassword | FactorOTP).Names()
	want := []string{"webauthn", "password", "otp"}
	if len(got) != len(want) {
		t.Fatalf("Names: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names order: got %v, want %v", got, want)
		}
	}
	// The exported tier names (which config.PasswordTier* reference) match String().
	if TierNameDataOnly != TierDataOnly.String() || TierNameOwner != TierOwner.String() {
		t.Error("Tier name constants must equal Tier.String() — single source")
	}
}

func TestRequireAssurance(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	fresh := now.Add(-time.Minute)
	stale := now.Add(-time.Hour)
	def := AssurancePolicy{} // secure defaults: phishing-resistant, 10m window

	cases := []struct {
		name    string
		a       *Assurance
		action  ActionClass
		pol     AssurancePolicy
		wantErr error
	}{
		{"data write needs nothing", nil, DataWrite, def, nil},
		{"no assurance ⇒ no owner", nil, CredentialMgmt, def, ErrOwnerRequired},
		{"data_only refused mgmt", &Assurance{Tier: TierDataOnly, Factors: FactorWebAuthn, AuthTime: fresh}, CredentialMgmt, def, ErrOwnerRequired},
		{"owner + fresh webauthn ok", &Assurance{Tier: TierOwner, Factors: FactorWebAuthn, AuthTime: fresh}, CredentialMgmt, def, nil},
		{"owner + device key ok", &Assurance{Tier: TierOwner, Factors: FactorDeviceKey, AuthTime: fresh}, Destructive, def, nil},
		{"owner + password only ⇒ step-up", &Assurance{Tier: TierOwner, Factors: FactorPassword, AuthTime: fresh}, CredentialMgmt, def, ErrStepUpRequired},
		{"owner + TOTP only ⇒ step-up (A1/A3: TOTP not phishing-resistant)", &Assurance{Tier: TierOwner, Factors: FactorOTP, AuthTime: fresh}, Destructive, def, ErrStepUpRequired},
		{"owner + stale strong ⇒ step-up", &Assurance{Tier: TierOwner, Factors: FactorWebAuthn, AuthTime: stale}, CredentialMgmt, def, ErrStepUpRequired},
		{"reduced scope destructive held", &Assurance{Tier: TierOwner, Factors: FactorRecovery, AuthTime: fresh, Scope: ScopeReduced, NotBeforeDestructive: now.Add(time.Hour)}, Destructive, def, ErrScopeReduced},
		{"reduced scope credential-mgmt held (A2 fix — can't bootstrap a new owner cred)", &Assurance{Tier: TierOwner, Factors: FactorRecovery, AuthTime: fresh, Scope: ScopeReduced, NotBeforeDestructive: now.Add(time.Hour)}, CredentialMgmt, def, ErrScopeReduced},
		{"reduced scope after hold passes → credential-mgmt allowed", &Assurance{Tier: TierOwner, Factors: FactorRecovery, AuthTime: fresh, Scope: ScopeReduced, NotBeforeDestructive: now.Add(-time.Minute)}, CredentialMgmt, def, nil},
		{"recovery-root needs recovery+full", &Assurance{Tier: TierOwner, Factors: FactorRecovery, AuthTime: fresh}, RecoveryRoot, def, nil},
		{"recovery-root refused reduced", &Assurance{Tier: TierOwner, Factors: FactorRecovery, AuthTime: fresh, Scope: ScopeReduced}, RecoveryRoot, def, ErrStepUpRequired},
		{"loosened policy lets TOTP manage", &Assurance{Tier: TierOwner, Factors: FactorOTP, AuthTime: fresh}, Destructive, AssurancePolicy{Destructive: FactorOTP | StrictFactors}, nil},
	}
	for _, tc := range cases {
		if got := RequireAssurance(tc.a, tc.action, tc.pol, now); got != tc.wantErr {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.wantErr)
		}
	}
}
