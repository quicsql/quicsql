package authz

import (
	"testing"
	"time"
)

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
		{"loosened policy lets TOTP manage", &Assurance{Tier: TierOwner, Factors: FactorOTP, AuthTime: fresh}, Destructive, AssurancePolicy{Destructive: FactorOTP | PhishingResistant}, nil},
	}
	for _, tc := range cases {
		if got := RequireAssurance(tc.a, tc.action, tc.pol, now); got != tc.wantErr {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.wantErr)
		}
	}
}
