package account

import (
	"strings"
	"testing"

	"quicsql.net/meta"
)

// The never-remove-last invariant: a detach is allowed only if the account keeps
// ≥1 usable primary AND ≥1 usable recovery afterward. Pending/expired/factor
// credentials don't count.
func TestUsableExcluding(t *testing.T) {
	now := int64(1000)
	creds := []meta.Credential{
		{ID: "dev1", Role: "primary", Type: credEd25519, Status: "active"},
		{ID: "dev2", Role: "primary", Type: credEd25519, Status: "active"},
		{ID: "rk", Role: "recovery", Type: credRecoveryKey, Status: "active"},
		{ID: "pending", Role: "primary", Status: "pending"},               // not usable
		{ID: "expired", Role: "recovery", Status: "active", ExpiresAt: 1}, // expired
		{ID: "factor", Role: "factor", Type: "totp", Status: "active"},    // not a primary/recovery
	}

	// Removing one of two devices keeps a primary + the recovery key → allowed.
	if p, r := usableExcluding(creds, "dev1", now); p != 1 || r != 1 {
		t.Fatalf("remove dev1: primary=%d recovery=%d (want 1,1)", p, r)
	}
	// Removing the recovery key leaves zero usable recovery → blocked.
	if _, r := usableExcluding(creds, "rk", now); r != 0 {
		t.Fatalf("remove rk: recovery=%d (want 0 → blocked)", r)
	}
	// Removing a device when it's the last usable primary would leave zero → blocked.
	two := []meta.Credential{
		{ID: "dev1", Role: "primary", Status: "active"},
		{ID: "rk", Role: "recovery", Status: "active"},
	}
	if p, _ := usableExcluding(two, "dev1", now); p != 0 {
		t.Fatalf("remove sole primary: primary=%d (want 0 → blocked)", p)
	}
}

func TestCryptoHelpers(t *testing.T) {
	id, err := newAccountID()
	if err != nil || !strings.HasPrefix(id, "u_") || len(id) != 2+16 {
		t.Fatalf("account id %q err=%v", id, err)
	}
	rk, hash, err := newRecoveryKey()
	if err != nil || !strings.HasPrefix(rk, "rk_") || len(hash) != 64 {
		t.Fatalf("recovery key %q hash=%q err=%v", rk, hash, err)
	}
	if hashSecret(rk) != hash {
		t.Fatal("hashSecret must be deterministic and match newRecoveryKey")
	}
	if hashSecret("a") == hashSecret("b") {
		t.Fatal("distinct secrets must hash differently")
	}
	if a := mustCredID(); len(a) != 32 || a == mustCredID() {
		t.Fatalf("cred id should be 32 hex chars and unique: %q", a)
	}
}

func TestConfigDefaults(t *testing.T) {
	var c Config
	c.applyDefaults()
	if c.MaxCredentials != 20 || c.MaxAttachCodes != 3 || c.CodeTTL <= 0 || c.Provision.NameTemplate != "{principal}" || c.Provision.Level != "read-write" {
		t.Fatalf("defaults: %+v", c)
	}
}
