package account

import "testing"

func TestHashVerify(t *testing.T) {
	pepper := []byte("a-server-pepper-outside-the-db")
	enc, err := hashPassword("correct horse battery staple", pepper)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(enc, "correct horse battery staple", pepper) {
		t.Error("correct password should verify")
	}
	if verifyPassword(enc, "wrong password entirely here", pepper) {
		t.Error("wrong password must not verify")
	}
	// The pepper is load-bearing: the same password with a different pepper fails,
	// so a stolen .sqlite (no pepper) is not crackable against this hash.
	if verifyPassword(enc, "correct horse battery staple", []byte("different-pepper")) {
		t.Error("a different pepper must not verify")
	}
	// NFKC: a compatibility-equivalent form of the same password verifies.
	enc2, _ := hashPassword("ﬃ-ligature-passphrase-x", pepper) // "ﬃ" NFKC→"ffi"
	if !verifyPassword(enc2, "ffi-ligature-passphrase-x", pepper) {
		t.Error("NFKC-equivalent password should verify")
	}
}

func TestVerifyMalformed(t *testing.T) {
	// A malformed encoding returns false, never panics (uniform miss path).
	for _, bad := range []string{"", "not-a-phc", "$argon2id$v=19$bad$x$y", "$argon2i$v=19$m=1,t=1,p=1$AA$BB"} {
		if verifyPassword(bad, "whatever", []byte("k")) {
			t.Errorf("malformed %q must not verify", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	if err := checkPasswordPolicy("short", 15); err != ErrPasswordTooShort {
		t.Errorf("short: got %v", err)
	}
	if err := checkPasswordPolicy("this is long enough now", 15); err != nil {
		t.Errorf("ok: got %v", err)
	}
	// ≥64 supported (no truncation), but a runaway input is capped.
	long := make([]byte, passwordMaxRunes+1)
	for i := range long {
		long[i] = 'a'
	}
	if err := checkPasswordPolicy(string(long), 15); err != ErrPasswordTooLong {
		t.Errorf("too long: got %v", err)
	}
}

func TestBreachScreen(t *testing.T) {
	if err := screenBreach("password123", nil); err != ErrPasswordBreached {
		t.Errorf("common password should be rejected: %v", err)
	}
	if err := screenBreach("Password123", nil); err != ErrPasswordBreached {
		t.Errorf("common password (case-folded) should be rejected: %v", err)
	}
	// Context term: a password containing the handle/email/"quicsql" is rejected.
	if err := screenBreach("myquicsqlpassword!!", []string{"quicsql"}); err != ErrPasswordBreached {
		t.Errorf("context-term password should be rejected: %v", err)
	}
	if err := screenBreach("a perfectly fine long passphrase", []string{"quicsql"}); err != nil {
		t.Errorf("good password should pass: %v", err)
	}
}
