package account

// Password credentials (accounts design Phase 2.1 — §13 policy, §14.5 storage). A
// password is a DATA-ONLY primary credential: a phished password can read/write the
// account's database but can never manage credentials or reach root (§5). Storage is
// Argon2id with a per-hash salt AND a server pepper keyed outside the SQLite file, so a
// stolen .sqlite is not crackable; the policy follows NIST SP 800-63B-4 (length floor,
// NFKC, no composition/rotation) with a bundled breach screen.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

//go:embed common-passwords.txt
var commonPasswordsRaw string

// commonPasswords is the parsed deny-list (lowercased, exact-match after NFKC).
var commonPasswords = parseCommonPasswords(commonPasswordsRaw)

func parseCommonPasswords(raw string) map[string]struct{} {
	m := make(map[string]struct{})
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = struct{}{}
	}
	return m
}

// Argon2id parameters (§13/§16): m=19 MiB, t=2, p=1 — the NIST/OWASP low-memory profile.
const (
	argonMemKiB  = 19456 // 19 MiB
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16

	passwordMaxRunes = 256 // accept ≥64 (NIST); cap to bound Argon2id work per attempt
)

// Password errors surfaced to the HTTP layer.
var (
	ErrPasswordTooShort = errors.New("account: password is too short")
	ErrPasswordTooLong  = errors.New("account: password is too long")
	ErrPasswordBreached = errors.New("account: password appears in a breach/common list — choose another")
	ErrBadCredentials   = errors.New("account: invalid credentials")    // uniform login failure (no enumeration)
	ErrNoPassword       = errors.New("account: no password is set")     // account has no password credential
	ErrPasswordDisabled = errors.New("account: password auth disabled") // config gate
)

// normalizePassword applies NFKC (NIST: normalize before hashing/compare).
func normalizePassword(pw string) string { return norm.NFKC.String(pw) }

// peppered keys the (normalized) password with the server pepper via HMAC-SHA-256, so
// the value fed to Argon2id — and thus every stored hash — is useless without the key
// held outside the database.
func peppered(pw string, pepper []byte) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(normalizePassword(pw)))
	return mac.Sum(nil)
}

// hashPassword returns a PHC-style encoded Argon2id hash of the peppered password.
func hashPassword(pw string, pepper []byte) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey(peppered(pw, pepper), salt, argonTime, argonMemKiB, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemKiB, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(h)), nil
}

// verifyPassword constant-time-checks a candidate against an encoded hash. A malformed
// encoding returns false (never an error the caller could time-distinguish).
func verifyPassword(encoded, pw string, pepper []byte) bool {
	m, t, p, salt, want, ok := parsePHC(encoded)
	if !ok {
		return false
	}
	got := argon2.IDKey(peppered(pw, pepper), salt, t, m, uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyEncoded is a fixed valid Argon2id hash used to equalize timing on the
// no-password / no-account path (§14.4 enumeration resistance) — its plaintext is
// unknowable, so a verify against it always fails after doing the same Argon2id work.
var dummyEncoded, _ = hashPassword("\x00dummy-verify-target\x00", []byte("dummy-pepper-not-a-secret"))

// dummyVerify does one Argon2id computation and discards it, so the miss path costs the
// same as a real verify.
func dummyVerify(pw string) {
	_ = verifyPassword(dummyEncoded, pw, []byte("dummy-pepper-not-a-secret"))
}

func parsePHC(encoded string) (m, t, p uint32, salt, hash []byte, ok bool) {
	// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return 0, 0, 0, nil, nil, false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return 0, 0, 0, nil, nil, false
	}
	b64 := base64.RawStdEncoding
	var err error
	if salt, err = b64.DecodeString(parts[4]); err != nil {
		return 0, 0, 0, nil, nil, false
	}
	if hash, err = b64.DecodeString(parts[5]); err != nil {
		return 0, 0, 0, nil, nil, false
	}
	return m, t, p, salt, hash, true
}

// checkPasswordPolicy enforces the length floor + ceiling (§13). minLen is the
// sole-factor floor (default 15); callers with an established MFA factor may pass a
// lower floor (≥8).
func checkPasswordPolicy(pw string, minLen int) error {
	n := utf8.RuneCountInString(normalizePassword(pw))
	if n < minLen {
		return ErrPasswordTooShort
	}
	if n > passwordMaxRunes {
		return ErrPasswordTooLong
	}
	return nil
}

// screenBreach rejects a candidate that is a known common/breached password or that
// contains an account-context term (handle, email local-part, "quicsql") — the §13
// breach screen. ctx terms shorter than 4 chars are ignored (too many false positives).
func screenBreach(pw string, ctx []string) error {
	low := strings.ToLower(normalizePassword(pw))
	if _, bad := commonPasswords[low]; bad {
		return ErrPasswordBreached
	}
	for _, term := range ctx {
		term = strings.ToLower(strings.TrimSpace(term))
		if len(term) >= 4 && strings.Contains(low, term) {
			return ErrPasswordBreached
		}
	}
	return nil
}
