package auth

import (
	"testing"
	"time"

	"quicsql.net/authz"
)

// The versioned token must round-trip every assurance claim, and renewal must
// FREEZE the assurance (authTime/factors/tier) — only a fresh factor may advance
// recency, else a one-time step-up would become permanent sudo.
func TestTokenClaimsRoundTripAndRenewFreezesAssurance(t *testing.T) {
	m, err := newSessionMinter(time.Hour, 24*time.Hour) // renewable
	if err != nil {
		t.Fatal(err)
	}
	authTime := time.Now().Add(-30 * time.Minute).Truncate(time.Nanosecond)
	cid := []byte("0123456789abcdef") // 16 bytes
	tok, _, _, err := m.mint("u_alice", sessClaims{
		tier:     authz.TierOwner,
		factors:  authz.FactorWebAuthn | authz.FactorPassword,
		credID:   cid,
		authTime: authTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	name, _, c, err := m.verify(tok)
	if err != nil || name != "u_alice" {
		t.Fatalf("verify: name=%q err=%v", name, err)
	}
	if c.tier != authz.TierOwner || c.factors != (authz.FactorWebAuthn|authz.FactorPassword) {
		t.Fatalf("claims tier/factors round-trip: %+v", c)
	}
	if !c.authTime.Equal(authTime) {
		t.Fatalf("authTime round-trip: got %v want %v", c.authTime, authTime)
	}
	if a := c.assurance(); a.CredID == "" || a.Tier != authz.TierOwner {
		t.Fatalf("assurance projection: %+v", a)
	}

	// Renew and confirm the assurance is carried unchanged (frozen).
	rtok, _, _, err := m.renew(tok)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rc, err := m.verify(rtok)
	if err != nil {
		t.Fatal(err)
	}
	if !rc.authTime.Equal(authTime) {
		t.Errorf("renew must FREEZE authTime: got %v want %v", rc.authTime, authTime)
	}
	if rc.tier != authz.TierOwner || rc.factors != (authz.FactorWebAuthn|authz.FactorPassword) {
		t.Errorf("renew must freeze tier/factors: %+v", rc)
	}
}

// Malformed or wrong-prefix tokens are rejected (a non-st_ value isn't ours; a
// st_ value that's too short / not the current version fails to parse).
func TestTokenRejectsBadInput(t *testing.T) {
	m, _ := newSessionMinter(time.Hour, 0)
	for _, tok := range []string{"", "st_", "st_short", "notasession", "Bearer x"} {
		if _, _, _, err := m.verify(tok); err == nil {
			t.Errorf("expected rejection for %q", tok)
		}
	}
}
