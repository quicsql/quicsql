// Package auth authenticates a request into an authz.Principal. It compiles the
// configured principals + credentials once (auth.New) and exposes a per-listener
// Middleware that, for each request, tries the methods that listener accepts and
// attaches the resulting principal (or the anonymous one) to the request
// context; the HTTP handler then enforces the capability via authz.Policy.
//
// Methods: no-auth (anonymous), Unix-socket peer credentials, bearer token,
// HTTP-basic password, mTLS client certificate, and an ed25519
// challenge/response reusing crypto/keyring's signer verification — so the same
// key that opens a vault can be the network principal. Optionally, any of those
// credentials can be exchanged at POST /_auth/session for a short-lived,
// revocable session token (the `session` listener method), so a client that
// shouldn't hold a long-lived secret — a browser tab, a batch job — carries a
// bounded one instead.
package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gosqlite.org/crypto/keyring"
	"quicsql.net/authz"
	"quicsql.net/config"
	"quicsql.net/internal/httpjson"
	"quicsql.net/internal/wire"
	"quicsql.net/secret"
)

// Authenticator holds the compiled credential directory shared by every
// listener's Middleware. Its maps are read-only after New, so it is safe for
// concurrent use.
type Authenticator struct {
	challenger *challenger
	sessions   *sessionMinter // nil unless auth.session.enabled
	enroll     http.Handler   // nil unless auth.enroll.enabled (set by serverd wiring)
	log        *slog.Logger

	bearer   map[string]string       // hex(sha256(token)) → principal name
	password map[string]passwordCred // username → credential
	mtlsCN   map[string]string       // client-cert subject CN → principal name
	mtlsSPKI map[string]string       // hex(sha256(SPKI)) → principal name
	keyring  map[string]keyringCred  // canonical ssh-ed25519 key → credential
	peercred map[uint32]string       // uid → principal name

	// dynKeyring holds runtime-enrolled ed25519 identities. Unlike the static
	// maps (read-only after New), it mutates while requests read it, so it has
	// its own lock. Static config always wins a canonical-key collision.
	dynMu      sync.RWMutex
	dynKeyring map[string]keyringCred

	dummyHash []byte // a throwaway bcrypt hash, compared on unknown users to level password timing
}

// New compiles the configured principals and credentials into an Authenticator.
// Secret references in credential parameters are resolved eagerly here, so a
// broken reference fails at startup, not on the first request.
func New(cfg *config.Config, sec secret.Resolver, log *slog.Logger) (*Authenticator, error) {
	if log == nil {
		log = slog.Default()
	}
	ch, err := newChallenger()
	if err != nil {
		return nil, err
	}
	// Cost must match a real password hash's, not bcrypt.MinCost — otherwise the
	// unknown-user path (comparing this dummy) is ~64-256× faster than the
	// known-user path, leaking username existence by response timing.
	dummy, err := bcrypt.GenerateFromPassword([]byte("quicsql-timing-equalizer"), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{
		challenger: ch, log: log,
		bearer:     map[string]string{},
		password:   map[string]passwordCred{},
		mtlsCN:     map[string]string{},
		mtlsSPKI:   map[string]string{},
		keyring:    map[string]keyringCred{},
		peercred:   map[uint32]string{},
		dynKeyring: map[string]keyringCred{},
		dummyHash:  dummy,
	}
	if cfg.Auth.Session.Enabled {
		if a.sessions, err = newSessionMinter(cfg.Auth.Session.IdleTTL, cfg.Auth.Session.MaxTTL); err != nil {
			return nil, err
		}
	}
	for _, pc := range cfg.Auth.Principals {
		for _, mm := range pc.Methods {
			for name, raw := range mm {
				if err := a.compile(name, toStrMap(raw), pc.Name, sec); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := a.loadRoster(cfg.Auth.AuthorizedKeys); err != nil {
		return nil, err
	}
	return a, nil
}

// compileError names the principal + method a credential-compile error came from.
type compileError struct {
	principal, method string
	err               error
}

func (e *compileError) Error() string {
	return fmt.Sprintf("auth: principal %q %s: %v", e.principal, e.method, e.err)
}
func (e *compileError) Unwrap() error { return e.err }

func errMissing(what string) error { return fmt.Errorf("missing %s", what) }

// compile installs one principal credential into the right method map.
func (a *Authenticator) compile(method string, p map[string]string, principal string, sec secret.Resolver) error {
	fail := func(err error) error { return &compileError{principal: principal, method: method, err: err} }
	switch method {
	case "bearer":
		h, err := resolve(sec, p["token_hash"])
		if err != nil {
			return fail(err)
		}
		if h == "" {
			return fail(errMissing("token_hash"))
		}
		a.bearer[strings.ToLower(h)] = principal
	case "password":
		user := p["user"]
		if user == "" {
			return fail(errMissing("user"))
		}
		hash, err := resolve(sec, p["password_hash"])
		if err != nil {
			return fail(err)
		}
		if hash == "" {
			return fail(errMissing("password_hash"))
		}
		a.password[user] = passwordCred{hash: []byte(hash), name: principal}
	case "mtls":
		cn, spki := p["subject_cn"], p["spki_sha256"]
		if cn == "" && spki == "" {
			return fail(errMissing("subject_cn or spki_sha256"))
		}
		if cn != "" {
			a.mtlsCN[cn] = principal
		}
		if spki != "" {
			a.mtlsSPKI[strings.ToLower(spki)] = principal
		}
	case "keyring":
		line, err := resolve(sec, p["ed25519"])
		if err != nil {
			return fail(err)
		}
		if line == "" {
			return fail(errMissing("ed25519"))
		}
		canon, pub, _, err := parseEd25519AuthorizedKey([]byte(line))
		if err != nil {
			return fail(err)
		}
		a.keyring[canon] = keyringCred{pub: pub, name: principal}
	case "peercred":
		uid, err := strconv.ParseUint(p["uid"], 10, 32)
		if err != nil {
			return fail(errMissing("uid"))
		}
		a.peercred[uint32(uid)] = principal
	default:
		return fail(errMissing("known method"))
	}
	return nil
}

// loadRoster admits the keys in an authorized_keys file as keyring credentials,
// each bound to a principal named by the key's comment (so an operator can
// enumerate ed25519 network identities in one file, SSH-style). A key with no
// comment is skipped rather than bound to an unnamed principal.
func (a *Authenticator) loadRoster(path string) error {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// ParseAuthorizedKeys validates the whole file (and rejects a non-key line);
	// we then re-read each line to pull the ed25519 key + comment for the roster.
	if _, err := keyring.ParseAuthorizedKeys(b); err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		canon, pub, comment, err := parseEd25519AuthorizedKey([]byte(line))
		if err != nil {
			return err
		}
		if comment == "" {
			a.log.Warn("quicsql/auth: authorized_keys entry has no comment; skipping (no principal name)", "key", canon)
			continue
		}
		a.keyring[canon] = keyringCred{pub: pub, name: comment}
	}
	return nil
}

// Middleware builds the per-listener request wrapper. An empty auth list admits
// the anonymous principal (the pre-auth bind-to-localhost behavior).
func (a *Authenticator) Middleware(lc config.Listener, log *slog.Logger) *Middleware {
	if log == nil {
		log = a.log
	}
	acc := map[string]bool{}
	for _, m := range lc.Auth {
		acc[m] = true
	}
	if len(acc) == 0 {
		acc["none"] = true
	}
	return &Middleware{a: a, accepted: acc, log: log, listener: lc.Name}
}

// Middleware authenticates each request on one listener and attaches the
// principal to the context.
type Middleware struct {
	a        *Authenticator
	accepted map[string]bool
	log      *slog.Logger
	listener string
}

// Wrap returns next wrapped with authentication. /_auth/challenge (the
// challenge/response nonce endpoint) and /_health are public; /_auth/session
// (mint/revoke a session token) authenticates inside its own handler; everything
// else authenticates and attaches the principal.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_auth/challenge" && m.accepted["keyring"]:
			// The challenge/response nonce endpoint, served only where the listener
			// actually accepts keyring auth.
			m.serveChallenge(w, r)
			return
		case r.URL.Path == "/_auth/session" && m.accepted["session"] && m.a.sessions != nil:
			// The session mint/revoke endpoint, served only where the listener
			// actually accepts the tokens it issues.
			m.serveSession(w, r)
			return
		case r.URL.Path == "/_auth/enroll" && m.accepted["keyring"] && m.a.enroll != nil:
			// Enrollment lives where keyring auth does: an enrolled key will
			// authenticate via the keyring method, so only keyring listeners
			// expose registration. The handler does its own possession proof.
			m.a.enroll.ServeHTTP(w, r)
			return
		case r.URL.Path == "/_health":
			next.ServeHTTP(w, r.WithContext(authz.NewContext(r.Context(), authz.Anonymous)))
			return
		}
		p, err := m.authenticate(r)
		if err != nil {
			m.deny(w, err)
			return
		}
		// Transparent "extend on use": if the caller authenticated with a
		// renewable session token that's past the halfway point of its idle
		// window, hand back a freshly-extended one (capped at max_ttl) in a
		// response header. The client adopts it, so an active session slides
		// forward without re-authenticating; an idle one still lapses at idle_ttl.
		if p.Method == "session" && m.a.sessions != nil && m.a.sessions.renewable() {
			if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
				if nt, ne, ok := m.a.sessions.maybeRefresh(strings.TrimSpace(tok)); ok {
					w.Header().Set("X-Quicsql-Session", nt)
					w.Header().Set("X-Quicsql-Session-Expires", ne.UTC().Format(time.RFC3339))
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(authz.NewContext(r.Context(), p)))
	})
}

// hardMethods are tried in priority order; each, when a credential is present,
// either authenticates or fails the request (a present-but-invalid credential is
// never silently downgraded to anonymous). session precedes bearer because both
// read `Authorization: Bearer` — the qs_ prefix routes a token to exactly one of
// them. peercred is "soft" — an unmapped uid simply falls through — and `none`
// is the terminal anonymous fallback.
var hardMethods = []string{"mtls", "keyring", "session", "bearer", "password"}

func (m *Middleware) authenticate(r *http.Request) (*authz.Principal, error) {
	return m.authenticateFor(r, false)
}

// authenticateFor resolves the request to a principal. skipSession excludes the
// session method — the mint path uses it so a session token can never mint its
// successor (a leaked token then expires with its TTL instead of living forever
// through self-renewal).
func (m *Middleware) authenticateFor(r *http.Request, skipSession bool) (*authz.Principal, error) {
	for _, mth := range hardMethods {
		if !m.accepted[mth] || (skipSession && mth == "session") {
			continue
		}
		p, present, err := m.a.try(mth, r)
		if !present {
			continue
		}
		return p, err // err != nil → 401
	}
	if m.accepted["peercred"] {
		if p, ok := m.a.tryPeercred(r); ok {
			return p, nil
		}
	}
	if m.accepted["none"] {
		return authz.Anonymous, nil
	}
	return nil, errUnauthenticated
}

// try dispatches one hard method, reporting whether a credential was present.
func (a *Authenticator) try(method string, r *http.Request) (*authz.Principal, bool, error) {
	switch method {
	case "mtls":
		return a.tryMTLS(r)
	case "keyring":
		return a.tryKeyring(r)
	case "session":
		return a.trySession(r)
	case "bearer":
		return a.tryBearer(r)
	case "password":
		return a.tryPassword(r)
	default:
		return nil, false, nil
	}
}

func (a *Authenticator) tryBearer(r *http.Request) (*authz.Principal, bool, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, false, nil
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return nil, false, nil
	}
	sum := sha256.Sum256([]byte(tok))
	want := []byte(hex.EncodeToString(sum[:]))
	name, matched := "", false
	for h, nm := range a.bearer { // constant-time over the (already-hashed) set
		if subtle.ConstantTimeCompare([]byte(h), want) == 1 {
			name, matched = nm, true
		}
	}
	if !matched {
		return nil, true, errInvalidCredential
	}
	return &authz.Principal{Name: name, Method: "bearer"}, true, nil
}

// trySession claims qs_-prefixed Authorization bearer values; anything else is
// "not present" so a static bearer token on the same listener still reaches
// tryBearer. A present-but-invalid session token is decisive (401), like every
// hard method.
func (a *Authenticator) trySession(r *http.Request) (*authz.Principal, bool, error) {
	if a.sessions == nil {
		return nil, false, nil
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, false, nil
	}
	tok = strings.TrimSpace(tok)
	if !strings.HasPrefix(tok, sessionPrefix) {
		return nil, false, nil
	}
	name, err := a.sessions.verify(tok)
	if err != nil {
		return nil, true, errInvalidCredential
	}
	return &authz.Principal{Name: name, Method: "session"}, true, nil
}

func (a *Authenticator) tryPassword(r *http.Request) (*authz.Principal, bool, error) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, false, nil
	}
	cred, known := a.password[user]
	if !known {
		_ = bcrypt.CompareHashAndPassword(a.dummyHash, []byte(pass)) // equalize timing vs. a known user
		return nil, true, errInvalidCredential
	}
	if bcrypt.CompareHashAndPassword(cred.hash, []byte(pass)) != nil {
		return nil, true, errInvalidCredential
	}
	return &authz.Principal{Name: cred.name, Method: "password"}, true, nil
}

func (a *Authenticator) tryMTLS(r *http.Request) (*authz.Principal, bool, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, false, nil
	}
	cert := r.TLS.PeerCertificates[0]
	if name, ok := a.mtlsCN[cert.Subject.CommonName]; ok {
		return &authz.Principal{Name: name, Method: "mtls"}, true, nil
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if name, ok := a.mtlsSPKI[hex.EncodeToString(spki[:])]; ok {
		return &authz.Principal{Name: name, Method: "mtls"}, true, nil
	}
	// A CA-verified client cert that maps to no principal is treated as "not
	// present" so the request can still authenticate via another accepted method
	// (bearer/keyring/password) — the point of VerifyClientCertIfGiven when mtls
	// sits alongside other methods. On an mtls-only listener nothing else matches,
	// so the request still fails closed (401 errUnauthenticated).
	return nil, false, nil
}

// lookupKeyring resolves a canonical key line to a credential: static config
// first (so an operator identity can never be shadowed by an enrollee), then
// the runtime-enrolled set.
func (a *Authenticator) lookupKeyring(canon string) (keyringCred, bool) {
	if cred, ok := a.keyring[canon]; ok {
		return cred, true
	}
	a.dynMu.RLock()
	cred, ok := a.dynKeyring[canon]
	a.dynMu.RUnlock()
	return cred, ok
}

// AddKeyring admits a runtime-enrolled ed25519 identity (the enrollment
// service's registration path). A canonical key already present statically is
// left alone — config wins.
func (a *Authenticator) AddKeyring(canon string, pub ed25519.PublicKey, name string) {
	if _, exists := a.keyring[canon]; exists {
		return
	}
	a.dynMu.Lock()
	a.dynKeyring[canon] = keyringCred{pub: pub, name: name}
	a.dynMu.Unlock()
}

// RemoveKeyringName revokes every runtime-enrolled key bound to name.
func (a *Authenticator) RemoveKeyringName(name string) {
	a.dynMu.Lock()
	for canon, cred := range a.dynKeyring {
		if cred.name == name {
			delete(a.dynKeyring, canon)
		}
	}
	a.dynMu.Unlock()
}

// VerifyPresented checks the keyring header triple against the key PRESENTED in
// the request itself (not the roster): a valid, unexpired challenge and a
// signature over this request's binding by that key. It is the
// possession-proof primitive the enrollment endpoint uses — the caller proves
// it holds the private half of the key it is asking to register.
func (a *Authenticator) VerifyPresented(r *http.Request) (canon string, pub ed25519.PublicKey, err error) {
	sig := r.Header.Get("X-Quicsql-Signature")
	keyLine, chal := r.Header.Get("X-Quicsql-Key"), r.Header.Get("X-Quicsql-Challenge")
	if sig == "" || keyLine == "" || chal == "" || !a.challenger.valid(chal) {
		return "", nil, errInvalidCredential
	}
	canon, pub, _, err = parseEd25519AuthorizedKey([]byte(keyLine))
	if err != nil {
		return "", nil, errInvalidCredential
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return "", nil, errInvalidCredential
	}
	if !keyring.VerifyState([]ed25519.PublicKey{pub}, wire.KeyringSigningInput(chal, r.Method, r.URL.Path, r.URL.RawQuery), sigBytes) {
		return "", nil, errInvalidCredential
	}
	return canon, pub, nil
}

// SetEnrollHandler mounts the enrollment endpoint (nil leaves it absent). Set
// once during serverd assembly, before any listener serves.
func (a *Authenticator) SetEnrollHandler(h http.Handler) { a.enroll = h }

func (a *Authenticator) tryKeyring(r *http.Request) (*authz.Principal, bool, error) {
	sig := r.Header.Get("X-Quicsql-Signature")
	if sig == "" {
		return nil, false, nil
	}
	keyLine, chal := r.Header.Get("X-Quicsql-Key"), r.Header.Get("X-Quicsql-Challenge")
	if keyLine == "" || chal == "" || !a.challenger.valid(chal) {
		return nil, true, errInvalidCredential
	}
	canon, _, _, err := parseEd25519AuthorizedKey([]byte(keyLine))
	if err != nil {
		return nil, true, errInvalidCredential
	}
	cred, ok := a.lookupKeyring(canon)
	if !ok {
		return nil, true, errInvalidCredential
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, true, errInvalidCredential
	}
	// Verify the signature over the challenge BOUND to this request's method, path,
	// and raw query (wire.KeyringSigningInput), not the bare challenge: a captured
	// signature then can't be replayed onto a different operation target within the
	// challenge's TTL. Running keyring over a cleartext transport (where the signature
	// is observable, hence replayable onto the same path) is warned about at startup.
	if !keyring.VerifyState([]ed25519.PublicKey{cred.pub}, wire.KeyringSigningInput(chal, r.Method, r.URL.Path, r.URL.RawQuery), sigBytes) {
		return nil, true, errInvalidCredential
	}
	return &authz.Principal{Name: cred.name, Method: "keyring"}, true, nil
}

func (a *Authenticator) tryPeercred(r *http.Request) (*authz.Principal, bool) {
	c := connFrom(r.Context())
	if c == nil {
		return nil, false
	}
	uid, ok := peerUID(c)
	if !ok {
		return nil, false
	}
	name, mapped := a.peercred[uid]
	if !mapped {
		return nil, false // an unmapped peer uid is not an error — fall through to none/anonymous
	}
	return &authz.Principal{Name: name, Method: "peercred"}, true
}

// serveChallenge answers GET /_auth/challenge with a fresh challenge for the
// ed25519 challenge/response method.
func (m *Middleware) serveChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	c, err := m.a.challenger.mint()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]string{"challenge": c})
}

// serveSession mints (POST), renews (PUT), or revokes (DELETE) a session token.
//
// Minting exchanges a NON-session credential — the request authenticates with
// the session method excluded, so a token can't mint its successor — for a fresh
// idle_ttl-bounded token. The anonymous principal is refused: a caller that
// never proved an identity has nothing for a token to represent.
//
// Renewing (only when max_ttl > 0) presents a still-valid renewable token and
// gets a fresh one whose idle window is pushed forward, never past the original
// hard deadline. It is the explicit counterpart to the transparent per-request
// refresh header; a client can drive its own sliding session with it.
//
// Revoking requires presenting the (still-valid) token itself in Authorization;
// it is self-service logout, not an admin kill switch.
func (m *Middleware) serveSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		p, err := m.authenticateFor(r, true)
		if err != nil {
			m.deny(w, err)
			return
		}
		if p.IsAnonymous() {
			m.deny(w, errUnauthenticated)
			return
		}
		tok, exp, hardExp, err := m.a.sessions.mint(p.Name)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		m.log.Debug("quicsql/auth: session token minted", "listener", m.listener, "principal", p.Name, "via", p.Method)
		writeSessionToken(w, tok, p.Name, exp, hardExp)
	case http.MethodPut:
		tok, ok := m.sessionTokenFromHeader(r)
		if !ok {
			m.deny(w, errUnauthenticated)
			return
		}
		nt, exp, hardExp, err := m.a.sessions.renew(tok)
		if err != nil {
			if errors.Is(err, errNotRenewable) {
				writeJSONError(w, http.StatusConflict, "session tokens are not renewable (set auth.session.max_ttl)")
				return
			}
			m.deny(w, err)
			return
		}
		writeSessionToken(w, nt, "", exp, hardExp)
	case http.MethodDelete:
		tok, ok := m.sessionTokenFromHeader(r)
		if !ok {
			m.deny(w, errUnauthenticated)
			return
		}
		if err := m.a.sessions.revoke(tok); err != nil {
			m.deny(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "use POST (mint), PUT (renew), or DELETE (revoke)")
	}
}

// sessionTokenFromHeader extracts a qs_-prefixed session token from the
// Authorization header, or reports ok=false.
func (m *Middleware) sessionTokenFromHeader(r *http.Request) (string, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	if !strings.HasPrefix(tok, sessionPrefix) {
		return "", false
	}
	return tok, true
}

// writeSessionToken writes the mint/renew response, including max_expires_at (the
// absolute deadline) for a renewable token so the client knows the sliding cap.
func writeSessionToken(w http.ResponseWriter, tok, principal string, exp, hardExp time.Time) {
	body := map[string]any{
		"token":      tok,
		"expires_at": exp.UTC().Format(time.RFC3339),
	}
	if principal != "" {
		body["principal"] = principal
	}
	if !hardExp.IsZero() {
		body["max_expires_at"] = hardExp.UTC().Format(time.RFC3339)
	}
	httpjson.Write(w, http.StatusOK, body)
}

func (m *Middleware) deny(w http.ResponseWriter, err error) {
	m.log.Debug("quicsql/auth: request denied", "listener", m.listener, "err", err)
	w.Header().Set("WWW-Authenticate", `Bearer, Basic realm="quicsql"`)
	writeJSONError(w, http.StatusUnauthorized, "authentication required")
}

// writeJSONError writes the standard {"error":{"message":…}} envelope so an auth
// failure is shaped like every other error a client sees.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	httpjson.Error(w, status, msg)
}
