package account

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"quicsql.net/auth"
	"quicsql.net/authz"
	"quicsql.net/config"
	"quicsql.net/meta"
	"quicsql.net/notify"
	"quicsql.net/secret"
)

// newTestSvc builds an account.Service backed by a real meta store + session-enabled
// authenticator, with a nil provisioner (these tests seed accounts directly and never
// call Register/Delete-with-drop, which are covered by the live smoke test).
func newTestSvc(t *testing.T) (*Service, *meta.Store) {
	t.Helper()
	sec, _ := secret.New(nil)
	store, err := meta.Open(config.MetaStore{Backend: "file", Path: "meta.db"}, sec, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	authn, err := auth.New(&config.Config{Auth: config.Auth{Session: config.SessionTokens{Enabled: true, IdleTTL: time.Hour, MaxTTL: 24 * time.Hour}}}, sec, nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	svc := New(Config{
		Provision: config.Provision{NameTemplate: "{principal}", Level: "read-write"},
		Password:  PasswordPolicy{Enabled: true, Pepper: []byte("test-pepper-not-a-real-secret-000"), MinLength: 15},
	}, store, authn, authz.NewPolicy(false), nil, notify.Noop{}, nil)
	return svc, store
}

func genKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

// seedAccount creates an account with one device + a recovery key + one recovery code
// directly in the store (no provisioning). Returns the device key line and pub.
func seedAccount(t *testing.T, store *meta.Store, principal, recoveryKeyHash, recoveryCodeHash string) (ed25519.PublicKey, string) {
	t.Helper()
	if err := store.PutAccount(principal, 100); err != nil {
		t.Fatal(err)
	}
	pub, canon := genKey(t)
	for _, c := range []meta.Credential{
		{ID: mustCredID(), Account: principal, Type: credEd25519, Role: "primary", Tier: int(authz.TierOwner), Material: canon, AddedAt: 100},
		{ID: mustCredID(), Account: principal, Type: credRecoveryKey, Role: "recovery", Tier: int(authz.TierOwner), Material: recoveryKeyHash, AddedAt: 100},
		{ID: mustCredID(), Account: principal, Type: credRecoveryCode, Role: "recovery", Tier: int(authz.TierOwner), Material: recoveryCodeHash, AddedAt: 100},
	} {
		if err := store.PutCredential(c); err != nil {
			t.Fatal(err)
		}
	}
	return pub, canon
}

func TestAttachAndCrossAccountReject(t *testing.T) {
	svc, store := newTestSvc(t)
	seedAccount(t, store, "u_alice", hashSecret("rk-a"), hashSecret("code-a"))
	seedAccount(t, store, "u_bob", hashSecret("rk-b"), hashSecret("code-b"))
	ctx := context.Background()

	// Alice mints an attach code; a new device redeems it → joins Alice.
	code, err := svc.MintAttachCode("u_alice")
	if err != nil {
		t.Fatal(err)
	}
	pub2, _ := genKey(t)
	res, err := svc.Attach(ctx, "ssh-ed25519 DEV2", pub2, code)
	if err != nil || res.Principal != "u_alice" || !res.Created {
		t.Fatalf("attach: %+v err=%v", res, err)
	}
	if creds, _ := svc.Credentials("u_alice"); len(creds) != 4 { // device+device2+rk+code
		t.Fatalf("alice should have 4 credentials, has %d", len(creds))
	}

	// An expired/used code must NOT fall through to register (attach-or-fail).
	if _, err := svc.Attach(ctx, "ssh-ed25519 DEV3", pub2, code); err != ErrInvalidCode {
		t.Fatalf("reused attach code: want ErrInvalidCode, got %v", err)
	}

	// A device key already on Alice cannot be attached to Bob.
	bobCode, _ := svc.MintAttachCode("u_bob")
	if _, err := svc.Attach(ctx, "ssh-ed25519 DEV2", pub2, bobCode); err != ErrKeyOnAnotherAccount {
		t.Fatalf("cross-account attach: want ErrKeyOnAnotherAccount, got %v", err)
	}
}

func TestDetachNeverRemovesLast(t *testing.T) {
	svc, store := newTestSvc(t)
	seedAccount(t, store, "u_alice", hashSecret("rk"), hashSecret("code"))
	ctx := context.Background()

	creds, _ := svc.Credentials("u_alice")
	var devID, rkID string
	for _, c := range creds {
		switch c.Type {
		case credEd25519:
			devID = c.ID
		case credRecoveryKey:
			rkID = c.ID
		}
	}

	// Deleting the sole device leaves zero usable primary → blocked.
	if err := svc.Detach(ctx, "u_alice", devID, ""); err != ErrLastCredential {
		t.Fatalf("detach sole device: want ErrLastCredential, got %v", err)
	}
	// The recovery key is not the last recovery path (a recovery code remains), but
	// removing it here would still leave the recovery key gone — a code remains, so
	// recovery count stays ≥1 → allowed.
	if err := svc.Detach(ctx, "u_alice", rkID, ""); err != nil {
		t.Fatalf("detach recovery key (a code remains): %v", err)
	}
	// Add a second device, then the first can be removed.
	pub2, _ := genKey(t)
	code, _ := svc.MintAttachCode("u_alice")
	if _, err := svc.Attach(ctx, "ssh-ed25519 DEV2", pub2, code); err != nil {
		t.Fatal(err)
	}
	if err := svc.Detach(ctx, "u_alice", devID, ""); err != nil {
		t.Fatalf("detach one of two devices: %v", err)
	}
}

func TestRecoverKeyVsCode(t *testing.T) {
	svc, store := newTestSvc(t)
	seedAccount(t, store, "u_alice", hashSecret("the-recovery-key"), hashSecret("the-code"))
	ctx := context.Background()

	// The recovery KEY yields a full-scope (root) session and is reusable.
	rk, err := svc.Recover(ctx, "the-recovery-key")
	if err != nil || rk.Principal != "u_alice" || !rk.Root || rk.Token == "" {
		t.Fatalf("recover key: %+v err=%v", rk, err)
	}
	if again, err := svc.Recover(ctx, "the-recovery-key"); err != nil || !again.Root {
		t.Fatalf("recovery key should be reusable: %+v err=%v", again, err)
	}
	// A recovery CODE yields a non-root session and is single-use.
	rc, err := svc.Recover(ctx, "the-code")
	if err != nil || rc.Root || rc.Token == "" {
		t.Fatalf("recover code: %+v err=%v", rc, err)
	}
	if _, err := svc.Recover(ctx, "the-code"); err != ErrInvalidRecovery {
		t.Fatalf("reused recovery code: want ErrInvalidRecovery, got %v", err)
	}
	// An unknown secret is uniformly rejected.
	if _, err := svc.Recover(ctx, "nonsense"); err != ErrInvalidRecovery {
		t.Fatalf("unknown secret: want ErrInvalidRecovery, got %v", err)
	}
}
