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

	"quicsql.net/authz"
	"quicsql.net/internal/wire"
)

// sessionPrefix shape-discriminates a minted session token from a static bearer
// token, so both can share the Authorization header on one listener: the session
// method claims st_-prefixed values and leaves everything else to bearer.
const sessionPrefix = wire.SessionTokenPrefix

// tokenVer is the wire-format version byte (payload[0]) — this is the FIRST
// explicitly-versioned format (the earlier unversioned layout had no version byte
// and no longer exists), so it starts at 1. A token whose version doesn't match is
// rejected outright; bump this to evolve the format later.
const tokenVer = 1

// A token payload is a fixed 71-byte header followed by the variable principal and
// the trailing HMAC:
//
//	ver(1) | sid(16) | exp(8) | hardExp(8) | authTime(8) | notBeforeDestructive(8)
//	       | tier(1) | scope(1) | factors(2) | rot(2) | credID(16) | principal(var) | HMAC(32)
//
// All FIXED fields come first so the variable principal can be read as
// payload[offPrincipal : len-32] with no length prefix — that is what makes the
// format extensible (the previous layout put the principal last with nothing
// after it, so no field could be appended).
//
// sid is the SESSION id, minted once and carried UNCHANGED through every renewal,
// so all tokens descended from one mint share it — a single DELETE revokes the
// whole chain (revocation is keyed by sid). authTime/factors/tier/credID are the
// assurance claims: they are FROZEN across renewal/refresh
// (only a fresh factor presentation changes them) so a one-time step-up can't
// become permanent sudo.
const (
	verLen   = 1
	sidLen   = 16
	expLen   = 8
	hardLen  = 8
	atLen    = 8 // authTime
	nbdLen   = 8 // notBeforeDestructive
	tierLen  = 1
	scLen    = 1 // scope
	facLen   = 2 // factors
	rotLen   = 2
	credLen  = 16
	offSid   = verLen
	offExp   = offSid + sidLen
	offHard  = offExp + expLen
	offAT    = offHard + hardLen
	offNBD   = offAT + atLen
	offTier  = offNBD + nbdLen
	offScope = offTier + tierLen
	offFac   = offScope + scLen
	offRot   = offFac + facLen
	offCred  = offRot + rotLen
	offPrin  = offCred + credLen // 71 — start of the variable principal
	hdrLen   = offPrin
)

var errNotRenewable = errors.New("auth: session token is not renewable")

// sessClaims are the assurance fields carried in a token beyond sid/exp/hardExp.
type sessClaims struct {
	tier      authz.Tier
	scope     authz.Scope
	factors   authz.Factor
	rot       uint16
	credID    []byte // 16 bytes; nil/short ⇒ zero
	authTime  time.Time
	notBefore time.Time // notBeforeDestructive; zero ⇒ none
}

// assurance projects the claims onto the authz.Assurance carried on a Principal.
func (c sessClaims) assurance() *authz.Assurance {
	var cid string
	if len(c.credID) == credLen && !allZero(c.credID) {
		cid = hex.EncodeToString(c.credID)
	}
	return &authz.Assurance{
		Tier: c.tier, Factors: c.factors, AuthTime: c.authTime,
		CredID: cid, Scope: c.scope, NotBeforeDestructive: c.notBefore,
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// sessionMinter mints, verifies, renews, and revokes short-lived bearer tokens —
// self-contained (like a challenge), so no per-token state is kept except the
// revocation set. The HMAC key is random per process (matching the challenge and
// baton keys): a restart invalidates every outstanding token AND clears the
// revocation set together, so the two can never disagree. (A future revision
// replaces this with a persisted, versioned key + a durable revocation registry.)
//
// idleTTL is each issued token's validity (the sliding window). maxTTL, when
// > 0, makes tokens renewable up to maxTTL from the FIRST mint; 0 keeps them
// strictly non-renewable (they die at idleTTL).
type sessionMinter struct {
	key     []byte
	idleTTL time.Duration
	maxTTL  time.Duration

	store SessionStore // durable registry (device list + account/credential-wide revoke); nil ⇒ per-process only

	mu      sync.RWMutex
	revoked map[string]int64 // hex(sid) → the session's outer deadline (unix nanos), kept until it passes
}

// SessionStore durably records live sessions so they can be listed (the device
// list) and revoked account- or credential-wide. Implemented by the meta store
// (wired by the meta store). When nil, revocation is per-process only — which is still
// sound, since a restart mints a fresh signing key that invalidates every
// outstanding token at once.
type SessionStore interface {
	PutSession(sid, account, credID string, createdAt, exp, hardExp int64) error
	SessionsByAccount(account string) (map[string]int64, error) // hex(sid) → outer deadline (unix nanos)
	SessionsByCredential(credID string) (map[string]int64, error)
	DeleteSessions(sids ...string) error
}

func (s *sessionMinter) setStore(st SessionStore) { s.store = st }

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

func unixNanoOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func timeFromNano(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// issue builds a token for principal carrying session id sid, the given sliding
// and hard expiries (hardExp zero ⇒ non-renewable), and the assurance claims.
func (s *sessionMinter) issue(sid []byte, principal string, exp, hardExp time.Time, c sessClaims) (string, time.Time, time.Time, error) {
	payload := make([]byte, hdrLen, hdrLen+len(principal)+sha256.Size)
	payload[0] = tokenVer
	copy(payload[offSid:], sid)
	binary.BigEndian.PutUint64(payload[offExp:], uint64(exp.UnixNano()))
	binary.BigEndian.PutUint64(payload[offHard:], uint64(unixNanoOrZero(hardExp)))
	binary.BigEndian.PutUint64(payload[offAT:], uint64(unixNanoOrZero(c.authTime)))
	binary.BigEndian.PutUint64(payload[offNBD:], uint64(unixNanoOrZero(c.notBefore)))
	payload[offTier] = byte(c.tier)
	payload[offScope] = byte(c.scope)
	binary.BigEndian.PutUint16(payload[offFac:], uint16(c.factors))
	binary.BigEndian.PutUint16(payload[offRot:], c.rot)
	if len(c.credID) == credLen {
		copy(payload[offCred:], c.credID)
	}
	payload = append(payload, principal...)
	tok := sessionPrefix + base64.RawURLEncoding.EncodeToString(append(payload, s.sign(payload)...))
	return tok, exp, hardExp, nil
}

// mint issues a fresh session (a new sid) for principal with the given assurance
// claims. Its sliding expiry is now+idleTTL; its hard expiry is now+maxTTL (or none
// when tokens aren't renewable). authTime defaults to now when unset.
func (s *sessionMinter) mint(principal string, c sessClaims) (string, time.Time, time.Time, error) {
	sid := make([]byte, sidLen)
	if _, err := rand.Read(sid); err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	now := time.Now()
	if c.authTime.IsZero() {
		c.authTime = now
	}
	var hardExp time.Time
	if s.renewable() {
		hardExp = now.Add(s.maxTTL)
	}
	exp := now.Add(s.idleTTL)
	tok, e, he, err := s.issue(sid, principal, exp, hardExp, c)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	// Best-effort durable registration (device list + targeted revocation). A store
	// failure must not fail the login — the token is valid regardless.
	if s.store != nil {
		credHex := ""
		if len(c.credID) == credLen && !allZero(c.credID) {
			credHex = hex.EncodeToString(c.credID)
		}
		_ = s.store.PutSession(hex.EncodeToString(sid), principal, credHex, now.UnixNano(), exp.UnixNano(), unixNanoOrZero(hardExp))
	}
	return tok, e, he, nil
}

// revokeSIDs adds the given sessions (hex(sid) → outer deadline) to the in-memory
// revoked set, skipping exceptHexSID (the acting session), and drops their durable
// rows. The per-request check consults the in-memory set, so revocation takes
// effect on the next request.
func (s *sessionMinter) revokeSIDs(sids map[string]int64, exceptHexSID string) {
	del := make([]string, 0, len(sids))
	s.mu.Lock()
	for sid, deadline := range sids {
		if sid == exceptHexSID {
			continue
		}
		s.revoked[sid] = deadline
		del = append(del, sid)
	}
	s.mu.Unlock()
	if s.store != nil && len(del) > 0 {
		_ = s.store.DeleteSessions(del...)
	}
}

// revokeAccount revokes every session belonging to account except exceptHexSID —
// "log out everywhere" and the credential-mutation follow-through.
func (s *sessionMinter) revokeAccount(account, exceptHexSID string) error {
	if s.store == nil {
		return nil
	}
	sids, err := s.store.SessionsByAccount(account)
	if err != nil {
		return err
	}
	s.revokeSIDs(sids, exceptHexSID)
	return nil
}

// revokeOne revokes a single session by its hex id (revoking a specific device from
// the session list). The deadline is a conservative upper bound — it only controls
// when the in-memory entry is GC'd, so overshooting is harmless.
func (s *sessionMinter) revokeOne(sidHex string) {
	deadline := time.Now().Add(s.idleTTL + s.maxTTL).UnixNano()
	s.revokeSIDs(map[string]int64{sidHex: deadline}, "")
}

// revokeByCredential revokes every session minted by the given credential — used
// when that credential is detached.
func (s *sessionMinter) revokeByCredential(credID string) error {
	if s.store == nil {
		return nil
	}
	sids, err := s.store.SessionsByCredential(credID)
	if err != nil {
		return err
	}
	s.revokeSIDs(sids, "")
	return nil
}

// renew extends a still-valid renewable token: a new token with the SAME session id,
// hard expiry, and ASSURANCE CLAIMS (authTime/factors/tier/credID/scope carried
// UNCHANGED — a slide is not a fresh authentication), its sliding expiry pushed to
// now+idleTTL but never past the hard expiry. Fails for a non-renewable, expired,
// revoked, or past-hard-deadline token — all of which require re-authenticating.
func (s *sessionMinter) renew(token string) (string, time.Time, time.Time, error) {
	sid, exp, hardExp, principal, c, err := s.parse(token)
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
	if s.isRevoked(sid) {
		return "", time.Time{}, time.Time{}, errInvalidCredential
	}
	he := time.Unix(0, hardExp)
	newExp := time.Unix(0, now).Add(s.idleTTL)
	if newExp.After(he) {
		newExp = he
	}
	return s.issue(sid, principal, newExp, he, c) // c unchanged ⇒ assurance frozen
}

// maybeRefresh backs the transparent "extend on use" path: for a renewable token
// more than halfway through its idle window (and not yet pinned to its hard
// deadline), it returns a freshly-extended token — same sid and same FROZEN
// assurance — to hand back in a response header. ok=false otherwise, so a burst of
// requests doesn't mint a token each.
func (s *sessionMinter) maybeRefresh(token string) (string, time.Time, bool) {
	sid, exp, hardExp, principal, c, err := s.parse(token)
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
	if s.isRevoked(sid) {
		return "", time.Time{}, false // revoked — don't hand back a fresh link
	}
	he := time.Unix(0, hardExp)
	newExp := time.Unix(0, now).Add(s.idleTTL)
	if newExp.After(he) {
		newExp = he
	}
	tok, e, _, err := s.issue(sid, principal, newExp, he, c)
	if err != nil {
		return "", time.Time{}, false
	}
	return tok, e, true
}

// verify checks a token's signature, expiry, and revocation, returning the
// principal name, its hex session id (for "log out everywhere" exclusion), and its
// assurance claims. (exp ≤ hardExp by construction, so the sliding-expiry check also
// enforces the hard deadline.)
func (s *sessionMinter) verify(token string) (name, sidHex string, c sessClaims, err error) {
	sid, exp, _, principal, cl, perr := s.parse(token)
	if perr != nil {
		return "", "", sessClaims{}, perr
	}
	if time.Now().UnixNano() > exp {
		return "", "", sessClaims{}, errInvalidCredential
	}
	if s.isRevoked(sid) {
		return "", "", sessClaims{}, errInvalidCredential
	}
	return principal, hex.EncodeToString(sid), cl, nil
}

// isRevoked reports whether the session id has an unexpired revocation entry. A
// past-deadline entry is treated as not-revoked and left for the next revoke() to
// sweep: by then every descendant token has expired anyway.
func (s *sessionMinter) isRevoked(sid []byte) bool {
	key := hex.EncodeToString(sid)
	s.mu.RLock()
	until, present := s.revoked[key]
	s.mu.RUnlock()
	return present && time.Now().UnixNano() <= until
}

// revoke invalidates the WHOLE session the presented token belongs to (keyed by
// sid, shared across the renewal chain), remembering the sid until the session's
// outer deadline, after which no descendant can be valid so the entry is GC'd.
func (s *sessionMinter) revoke(token string) error {
	sid, exp, hardExp, _, _, err := s.parse(token)
	if err != nil {
		return err
	}
	now := time.Now().UnixNano()
	if now > exp {
		return errInvalidCredential
	}
	until := max(exp, hardExp)
	key := hex.EncodeToString(sid)
	s.mu.Lock()
	for id, e := range s.revoked { // opportunistic GC of expired entries
		if now > e {
			delete(s.revoked, id)
		}
	}
	s.revoked[key] = until
	s.mu.Unlock()
	if s.store != nil {
		_ = s.store.DeleteSessions(key)
	}
	return nil
}

// parse validates shape + version + signature and splits the payload; expiry and
// revocation checks are the callers'. The returned sid/credID alias the decoded
// token — callers read them, never mutate them.
func (s *sessionMinter) parse(token string) (sid []byte, exp, hardExp int64, principal string, c sessClaims, err error) {
	body, ok := strings.CutPrefix(token, sessionPrefix)
	if !ok {
		return nil, 0, 0, "", sessClaims{}, errInvalidCredential
	}
	raw, derr := base64.RawURLEncoding.DecodeString(body)
	if derr != nil || len(raw) < hdrLen+1+sha256.Size || raw[0] != tokenVer {
		return nil, 0, 0, "", sessClaims{}, errInvalidCredential
	}
	payload, sig := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	if !hmac.Equal(sig, s.sign(payload)) {
		return nil, 0, 0, "", sessClaims{}, errInvalidCredential
	}
	exp = int64(binary.BigEndian.Uint64(payload[offExp:]))
	hardExp = int64(binary.BigEndian.Uint64(payload[offHard:]))
	c = sessClaims{
		tier:      authz.Tier(payload[offTier]),
		scope:     authz.Scope(payload[offScope]),
		factors:   authz.Factor(binary.BigEndian.Uint16(payload[offFac:])),
		rot:       binary.BigEndian.Uint16(payload[offRot:]),
		credID:    payload[offCred:offPrin],
		authTime:  timeFromNano(int64(binary.BigEndian.Uint64(payload[offAT:]))),
		notBefore: timeFromNano(int64(binary.BigEndian.Uint64(payload[offNBD:]))),
	}
	return payload[offSid:offExp], exp, hardExp, string(payload[offPrin:]), c, nil
}
