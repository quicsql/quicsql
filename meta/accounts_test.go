package meta_test

import (
	"testing"

	"quicsql.net/meta"
)

func TestAccountsCredentialsRoundTrip(t *testing.T) {
	st := openStore(t)

	if err := st.PutAccount("u_alice", 100); err != nil {
		t.Fatal(err)
	}
	dev := meta.Credential{ID: "c1", Account: "u_alice", Type: "ed25519", Role: "primary", Tier: 1, Material: "ssh-ed25519 AAAA", AddedAt: 100}
	rec := meta.Credential{ID: "c2", Account: "u_alice", Type: "recovery_key", Role: "recovery", Tier: 1, Material: "hash-of-rk", AddedAt: 100}
	if err := st.PutCredential(dev); err != nil {
		t.Fatal(err)
	}
	if err := st.PutCredential(rec); err != nil {
		t.Fatal(err)
	}

	// Idempotency lookup by (type, material).
	got, ok, err := st.CredentialByMaterial("ed25519", "ssh-ed25519 AAAA")
	if err != nil || !ok || got.Account != "u_alice" || got.Role != "primary" {
		t.Fatalf("CredentialByMaterial: %+v ok=%v err=%v", got, ok, err)
	}
	// UNIQUE(type, material) rejects a duplicate key.
	if err := st.PutCredential(meta.Credential{ID: "c3", Account: "u_bob", Type: "ed25519", Role: "primary", Tier: 1, Material: "ssh-ed25519 AAAA", AddedAt: 101}); err == nil {
		t.Fatal("duplicate (type,material) should be rejected")
	}

	creds, err := st.CredentialsByAccount("u_alice")
	if err != nil || len(creds) != 2 {
		t.Fatalf("CredentialsByAccount: %d creds err=%v", len(creds), err)
	}

	removed, ok, err := st.DeleteCredential("c1")
	if err != nil || !ok || removed.Material != "ssh-ed25519 AAAA" {
		t.Fatalf("DeleteCredential: %+v ok=%v err=%v", removed, ok, err)
	}
	if creds, _ := st.CredentialsByAccount("u_alice"); len(creds) != 1 {
		t.Fatalf("after delete: %d creds", len(creds))
	}
}

func TestOTPSingleUse(t *testing.T) {
	st := openStore(t)
	if err := st.PutOTP("h1", "u_alice", "attach", 100, 200); err != nil {
		t.Fatal(err)
	}
	acct, ok, err := st.ConsumeOTP("h1", "attach", 150)
	if err != nil || !ok || acct != "u_alice" {
		t.Fatalf("first consume: acct=%q ok=%v err=%v", acct, ok, err)
	}
	if _, ok, _ := st.ConsumeOTP("h1", "attach", 150); ok {
		t.Fatal("a consumed code must not consume again")
	}
	if _, ok, _ := st.ConsumeOTP("nope", "attach", 150); ok {
		t.Fatal("unknown code must not consume")
	}
	// Wrong purpose must not match.
	if err := st.PutOTP("h2", "u_alice", "recovery", 100, 200); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.ConsumeOTP("h2", "attach", 150); ok {
		t.Fatal("purpose mismatch must not consume")
	}
}

func TestSessionStore(t *testing.T) {
	st := openStore(t)
	if err := st.PutSession("s1", "u_alice", "c1", 10, 1000, 2000); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSession("s2", "u_alice", "c2", 10, 1500, 0); err != nil {
		t.Fatal(err)
	}
	byAcct, err := st.SessionsByAccount("u_alice")
	if err != nil || len(byAcct) != 2 || byAcct["s1"] != 2000 || byAcct["s2"] != 1500 {
		t.Fatalf("SessionsByAccount: %v err=%v", byAcct, err)
	}
	byCred, err := st.SessionsByCredential("c1")
	if err != nil || len(byCred) != 1 || byCred["s1"] != 2000 {
		t.Fatalf("SessionsByCredential: %v err=%v", byCred, err)
	}
	if err := st.DeleteSessions("s1"); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListSessions("u_alice"); len(list) != 1 || list[0].SID != "s2" {
		t.Fatalf("after delete: %+v", list)
	}
	if err := st.ClearSessions(); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListSessions("u_alice"); len(list) != 0 {
		t.Fatalf("ClearSessions left %d", len(list))
	}
}

// *meta.Store must satisfy auth.SessionStore (compile-time check without importing
// auth, to avoid a cycle): the four methods below match the interface shape.
var _ interface {
	PutSession(sid, account, credID string, createdAt, exp, hardExp int64) error
	SessionsByAccount(account string) (map[string]int64, error)
	SessionsByCredential(credID string) (map[string]int64, error)
	DeleteSessions(sids ...string) error
} = (*meta.Store)(nil)
