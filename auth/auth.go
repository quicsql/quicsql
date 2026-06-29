// Package auth authenticates a request into an authz.Principal. It compiles the
// configured principals + credentials once (auth.New) and exposes a per-listener
// Middleware that, for each request, tries the methods that listener accepts and
// attaches the resulting principal (or the anonymous one) to the request
// context; the HTTP handler then enforces the capability via authz.Policy.
//
// Methods: no-auth (anonymous), Unix-socket peer credentials, bearer token,
// HTTP-basic password, mTLS client certificate, and an ed25519
// challenge/response reusing crypto/keyring's signer verification — so the same
// key that opens a vault can be the network principal.
package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"gosqlite.org/crypto/keyring"
	"quicsql.net/authz"
	"quicsql.net/config"
	"quicsql.net/internal/httpjson"
	"quicsql.net/secret"
)

// Authenticator holds the compiled credential directory shared by every
// listener's Middleware. Its maps are read-only after New, so it is safe for
// concurrent use.
type Authenticator struct {
	challenger *challenger
	log        *slog.Logger

	bearer   map[string]string       // hex(sha256(token)) → principal name
	password map[string]passwordCred // username → credential
	mtlsCN   map[string]string       // client-cert subject CN → principal name
	mtlsSPKI map[string]string       // hex(sha256(SPKI)) → principal name
	keyring  map[string]keyringCred  // canonical ssh-ed25519 key → credential
	peercred map[uint32]string       // uid → principal name

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
		bearer:    map[string]string{},
		password:  map[string]passwordCred{},
		mtlsCN:    map[string]string{},
		mtlsSPKI:  map[string]string{},
		keyring:   map[string]keyringCred{},
		peercred:  map[uint32]string{},
		dummyHash: dummy,
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
// challenge/response nonce endpoint) and /_health are public; everything else
// authenticates and attaches the principal.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_auth/challenge" && m.accepted["keyring"]:
			// The challenge/response nonce endpoint, served only where the listener
			// actually accepts keyring auth.
			m.serveChallenge(w, r)
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
		next.ServeHTTP(w, r.WithContext(authz.NewContext(r.Context(), p)))
	})
}

// hardMethods are tried in priority order; each, when a credential is present,
// either authenticates or fails the request (a present-but-invalid credential is
// never silently downgraded to anonymous). peercred is "soft" — an unmapped uid
// simply falls through — and `none` is the terminal anonymous fallback.
var hardMethods = []string{"mtls", "keyring", "bearer", "password"}

func (m *Middleware) authenticate(r *http.Request) (*authz.Principal, error) {
	for _, mth := range hardMethods {
		if !m.accepted[mth] {
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
	cred, ok := a.keyring[canon]
	if !ok {
		return nil, true, errInvalidCredential
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, true, errInvalidCredential
	}
	// Verify the signature over the challenge BOUND to this request's method and
	// path, not the bare challenge: a signature captured off a cleartext listener
	// (or a header-logging proxy) then can't be replayed onto a different — e.g.
	// more privileged — request within the challenge's TTL.
	if !keyring.VerifyState([]ed25519.PublicKey{cred.pub}, keyringSigningInput(chal, r.Method, r.URL.Path), sigBytes) {
		return nil, true, errInvalidCredential
	}
	return &authz.Principal{Name: cred.name, Method: "keyring"}, true, nil
}

// keyringSigningInput is the exact byte string the ed25519 challenge/response
// signs and verifies: the server's challenge bound to the request's method and
// path. The client (client.authenticate) MUST build the identical bytes — keep
// the two in sync.
func keyringSigningInput(challenge, method, path string) []byte {
	return []byte(challenge + "\n" + method + "\n" + path)
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
