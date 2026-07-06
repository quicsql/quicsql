package account

import (
	"context"
	"testing"

	"quicsql.net/authz"
)

func TestSetPasswordAndLogin(t *testing.T) {
	svc, store := newTestSvc(t)
	seedAccount(t, store, "u_alice", hashSecret("rk"), hashSecret("code"))
	ctx := context.Background()

	// A weak password is refused before anything is stored.
	if err := svc.SetPassword(ctx, "u_alice", "short", nil); err != ErrPasswordTooShort {
		t.Fatalf("short password: want ErrPasswordTooShort, got %v", err)
	}
	// Long enough to pass the length floor, but tripped by the "quicsql" context term.
	if err := svc.SetPassword(ctx, "u_alice", "quicsql-is-my-password", nil); err != ErrPasswordBreached {
		t.Fatalf("breached password: want ErrPasswordBreached, got %v", err)
	}

	// Set a good password, then log in by principal.
	const pw = "a strong enough passphrase for alice"
	if err := svc.SetPassword(ctx, "u_alice", pw, nil); err != nil {
		t.Fatalf("set password: %v", err)
	}
	res, err := svc.Login(ctx, "u_alice", pw)
	if err != nil || res.Principal != "u_alice" || res.Token == "" {
		t.Fatalf("login: %+v err=%v", res, err)
	}

	// Wrong password and unknown identifier both fail uniformly (no panic, no leak).
	if _, err := svc.Login(ctx, "u_alice", "the wrong passphrase entirely"); err != ErrBadCredentials {
		t.Fatalf("wrong password: want ErrBadCredentials, got %v", err)
	}
	if _, err := svc.Login(ctx, "u_nobody", pw); err != ErrBadCredentials {
		t.Fatalf("unknown account: want ErrBadCredentials, got %v", err)
	}

	// Changing the password invalidates the old one.
	const pw2 = "an entirely different long passphrase"
	if err := svc.SetPassword(ctx, "u_alice", pw2, nil); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, err := svc.Login(ctx, "u_alice", pw); err != ErrBadCredentials {
		t.Fatalf("old password after change: want ErrBadCredentials, got %v", err)
	}
	if _, err := svc.Login(ctx, "u_alice", pw2); err != nil {
		t.Fatalf("new password: %v", err)
	}

	// Exactly one password credential exists (change replaced, not appended).
	pwCreds, _ := store.CredentialsByAccountType("u_alice", credPassword)
	if len(pwCreds) != 1 {
		t.Fatalf("want 1 password credential, got %d", len(pwCreds))
	}
	if pwCreds[0].Tier != int(authz.TierDataOnly) {
		t.Fatalf("password credential must be data-only tier, got %d", pwCreds[0].Tier)
	}
}
