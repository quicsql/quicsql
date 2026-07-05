package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// sessionPrefix shape-discriminates a minted session token from a static bearer
// token, so both can share the Authorization header on one listener: the session
// method claims qs_-prefixed values and leaves everything else to bearer.
const sessionPrefix = "qs_"

// A token payload is jti(16) ‖ exp(8) ‖ hardExp(8) ‖ principal ‖ HMAC. exp is the
// sliding (idle) expiry; hardExp is the absolute deadline (0 = non-renewable). A
// renewal issues a fresh token with the SAME hardExp and a new exp, never past
// hardExp — so a renewable token's whole chain is bounded by max_ttl from its
// first mint.
const (
	jtiLen  = 16
	expLen  = 8
	hardLen = 8
	hdrLen  = jtiLen + expLen + hardLen
)

var errNotRenewable = errors.New("auth: session token is not renewable")

// sessionMinter mints, verifies, renews, and revokes short-lived bearer tokens —
// self-contained (like a challenge), so no per-token state is kept except the
// revocation set. The HMAC key is random per process (matching the challenge and
// baton keys): a restart invalidates every outstanding token AND clears the
// revocation set together, so the two can never disagree.
//
// idleTTL is each issued token's validity (the sliding window). maxTTL, when
// > 0, makes tokens renewable up to maxTTL from the FIRST mint; 0 keeps them
// strictly non-renewable (they die at idleTTL).
type sessionMinter struct {
	key     []byte
	idleTTL time.Duration
	maxTTL  time.Duration

	mu      sync.Mutex
	revoked map[string]int64 // hex(jti) → token expiry (unix nanos), kept until expiry passes
}

func newSessionMinter(idleTTL, maxTTL time.Duration) (*sessionMinter, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &sessionMinter{key: key, idleTTL: idleTTL, maxTTL: maxTTL, revoked: map[string]int64{}}, nil
}

// renewable reports whether this minter issues renewable (sliding) tokens.
func (s *sessionMinter) renewable() bool { return s.maxTTL > 0 }

func (s *sessionMinter) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	return mac.Sum(nil)
}

// issue builds a token for principal with the given sliding and hard expiries
// (hardExp zero ⇒ non-renewable).
func (s *sessionMinter) issue(principal string, exp, hardExp time.Time) (string, time.Time, time.Time, error) {
	payload := make([]byte, hdrLen, hdrLen+len(principal))
	if _, err := rand.Read(payload[:jtiLen]); err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	binary.BigEndian.PutUint64(payload[jtiLen:], uint64(exp.UnixNano()))
	var he int64
	if !hardExp.IsZero() {
		he = hardExp.UnixNano()
	}
	binary.BigEndian.PutUint64(payload[jtiLen+expLen:], uint64(he))
	payload = append(payload, principal...)
	tok := sessionPrefix + base64.RawURLEncoding.EncodeToString(append(payload, s.sign(payload)...))
	return tok, exp, hardExp, nil
}

// mint issues a fresh token for principal. Its sliding expiry is now+idleTTL;
// its hard expiry is now+maxTTL (or none when tokens aren't renewable).
func (s *sessionMinter) mint(principal string) (string, time.Time, time.Time, error) {
	now := time.Now()
	var hardExp time.Time
	if s.renewable() {
		hardExp = now.Add(s.maxTTL)
	}
	return s.issue(principal, now.Add(s.idleTTL), hardExp)
}

// renew extends a still-valid renewable token: a new token, same hard expiry,
// sliding expiry pushed to now+idleTTL but never past the hard expiry. Fails for
// a non-renewable token, an expired one (the idle window elapsed), or one past
// its hard deadline — all of which require re-authenticating with a real
// credential. The old token is left to expire on its own (sliding, not rotation),
// so an in-flight request carrying it isn't severed.
func (s *sessionMinter) renew(token string) (string, time.Time, time.Time, error) {
	jti, exp, hardExp, principal, err := s.parse(token)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	if hardExp == 0 {
		return "", time.Time{}, time.Time{}, errNotRenewable
	}
	now := time.Now().UnixNano()
	if now > exp || now >= hardExp {
		return "", time.Time{}, time.Time{}, errInvalidCredential
	}
	s.mu.Lock()
	_, dead := s.revoked[jti]
	s.mu.Unlock()
	if dead {
		return "", time.Time{}, time.Time{}, errInvalidCredential
	}
	he := time.Unix(0, hardExp)
	newExp := time.Unix(0, now).Add(s.idleTTL)
	if newExp.After(he) {
		newExp = he
	}
	return s.issue(principal, newExp, he)
}

// maybeRefresh backs the transparent "extend on use" path: for a renewable token
// more than halfway through its idle window (and not yet pinned to its hard
// deadline), it returns a freshly-extended token to hand back in a response
// header. It returns ok=false — no refresh — otherwise, so a burst of requests
// doesn't mint a token each (once the client adopts the refreshed token, it has
// a full idle window again and won't re-trigger until half-spent).
func (s *sessionMinter) maybeRefresh(token string) (string, time.Time, bool) {
	_, exp, hardExp, principal, err := s.parse(token)
	if err != nil || hardExp == 0 {
		return "", time.Time{}, false
	}
	now := time.Now().UnixNano()
	if now > exp || now >= hardExp {
		return "", time.Time{}, false // dead — let normal verify reject it
	}
	if exp-now > int64(s.idleTTL)/2 || exp >= hardExp {
		return "", time.Time{}, false // still fresh, or already at the hard cap
	}
	he := time.Unix(0, hardExp)
	newExp := time.Unix(0, now).Add(s.idleTTL)
	if newExp.After(he) {
		newExp = he
	}
	tok, e, _, err := s.issue(principal, newExp, he)
	if err != nil {
		return "", time.Time{}, false
	}
	return tok, e, true
}

// verify checks a token's signature, expiry, and revocation, returning the
// principal name it was minted for. (exp ≤ hardExp by construction, so the
// sliding-expiry check also enforces the hard deadline.)
func (s *sessionMinter) verify(token string) (string, error) {
	jti, exp, _, principal, err := s.parse(token)
	if err != nil {
		return "", err
	}
	if time.Now().UnixNano() > exp {
		return "", errInvalidCredential
	}
	s.mu.Lock()
	_, dead := s.revoked[jti]
	s.mu.Unlock()
	if dead {
		return "", errInvalidCredential
	}
	return principal, nil
}

// revoke invalidates a (still-valid) token. The jti is remembered only until the
// token's own expiry, so the set is bounded by the number of live revoked tokens
// — and only a token that verifies can enter it, so it can't be grown by junk.
// For a renewable token, revoking one link of the chain does not revoke tokens
// already issued by earlier renewals (they carry different jtis); revoke the
// token the client currently holds, or shorten max_ttl.
func (s *sessionMinter) revoke(token string) error {
	jti, exp, _, _, err := s.parse(token)
	if err != nil {
		return err
	}
	now := time.Now().UnixNano()
	if now > exp {
		return errInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.revoked { // opportunistic GC of expired entries
		if now > e {
			delete(s.revoked, id)
		}
	}
	s.revoked[jti] = exp
	return nil
}

// parse validates shape + signature and splits the payload; expiry/revocation
// checks are the callers'.
func (s *sessionMinter) parse(token string) (jti string, exp, hardExp int64, principal string, err error) {
	body, ok := strings.CutPrefix(token, sessionPrefix)
	if !ok {
		return "", 0, 0, "", errInvalidCredential
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(raw) < hdrLen+1+sha256.Size {
		return "", 0, 0, "", errInvalidCredential
	}
	payload, sig := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	if !hmac.Equal(sig, s.sign(payload)) {
		return "", 0, 0, "", errInvalidCredential
	}
	exp = int64(binary.BigEndian.Uint64(payload[jtiLen:]))
	hardExp = int64(binary.BigEndian.Uint64(payload[jtiLen+expLen:]))
	return hex.EncodeToString(payload[:jtiLen]), exp, hardExp, string(payload[hdrLen:]), nil
}
