package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

// challengeTTL bounds how long a minted challenge is accepted, so a captured
// challenge+signature can't be replayed indefinitely.
const challengeTTL = 60 * time.Second

// challenger mints and verifies short-lived, stateless challenges for the
// ed25519 challenge/response method. A challenge is base64url(nonce ‖ expiry ‖
// HMAC(nonce ‖ expiry)); it carries its own expiry and signature, so no
// server-side state is kept between the GET /_auth/challenge and the signed
// request that follows. The HMAC key is random per process (like the session
// baton key) — a challenge minted before a restart simply fails afterward.
type challenger struct {
	key []byte
}

const (
	nonceLen     = 16
	challengeLen = nonceLen + 8 + sha256.Size
)

func newChallenger() (*challenger, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &challenger{key: key}, nil
}

// mint returns a fresh challenge string valid until now+challengeTTL.
func (c *challenger) mint() (string, error) {
	buf := make([]byte, nonceLen+8)
	if _, err := rand.Read(buf[:nonceLen]); err != nil {
		return "", err
	}
	exp := time.Now().Add(challengeTTL).UnixNano()
	binary.BigEndian.PutUint64(buf[nonceLen:], uint64(exp))
	mac := hmac.New(sha256.New, c.key)
	mac.Write(buf)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(buf)), nil
}

// valid reports whether s is a challenge this challenger minted and it has not
// expired. It is the gate the signed-request path checks before trusting the
// client's signature over the same bytes.
func (c *challenger) valid(s string) bool {
	tok, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(tok) != challengeLen {
		return false
	}
	payload, sig := tok[:nonceLen+8], tok[nonceLen+8:]
	mac := hmac.New(sha256.New, c.key)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	exp := int64(binary.BigEndian.Uint64(payload[nonceLen:]))
	return time.Now().UnixNano() <= exp
}
