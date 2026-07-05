// Package enroll is the self-service device-enrollment service: POST
// /_auth/enroll registers a caller-presented ed25519 public key as a new
// principal with a server-assigned name and a config-templated set of grants.
// The caller proves possession of the private key by signing a fresh server
// challenge bound to the request (the same primitive as keyring auth); the
// enrolled set persists in the meta store and is reloaded at startup; the
// grants template — never the store — is the authorization truth.
//
// Abuse controls (see the security design in the plans): a hard cap on the
// enrolled set, a per-IP token bucket, an optional enrollment-token gate, and
// server-assigned names (u_<key-hash prefix>) so an enrollee can never choose —
// or shadow — an identity. Enrollment is only wired on servers with explicit
// auth AND the control plane (config validation enforces both).
package enroll

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"quicsql.net/auth"
	"quicsql.net/authz"
	"quicsql.net/config"
	"quicsql.net/internal/httpjson"
	"quicsql.net/meta"
	"quicsql.net/secret"
)

// maxBodyBytes bounds the enroll request body (it carries at most a token).
const maxBodyBytes = 4 << 10

// Service handles enrollment requests and manages the enrolled set.
type Service struct {
	cfg    config.Enroll
	store  *meta.Store
	authn  *auth.Authenticator
	policy *authz.Policy
	log    *slog.Logger

	tokens map[string]bool // hex(sha256(enrollment token)) — resolved at build

	mu      sync.Mutex
	count   int // live size of the enrolled set (loaded at startup)
	buckets map[string]*bucket
	lastGC  time.Time
}

// New builds the service, resolving enrollment-token secret references eagerly
// so a broken reference fails startup.
func New(cfg config.Enroll, store *meta.Store, authn *auth.Authenticator, policy *authz.Policy, sec secret.Resolver, log *slog.Logger) (*Service, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Service{
		cfg: cfg, store: store, authn: authn, policy: policy, log: log,
		tokens:  map[string]bool{},
		buckets: map[string]*bucket{},
		lastGC:  time.Now(),
	}
	for _, ref := range cfg.Tokens {
		h, err := auth.ResolveParam(sec, ref)
		if err != nil {
			return nil, fmt.Errorf("enroll: token: %w", err)
		}
		if h == "" {
			return nil, fmt.Errorf("enroll: empty enrollment token entry")
		}
		s.tokens[strings.ToLower(h)] = true
	}
	return s, nil
}

// LoadExisting reads the enrolled set from the meta store, re-admits each key
// into the authenticator, and re-applies the grants template. Called once at
// startup, before listeners serve. Returns how many principals were loaded.
func (s *Service) LoadExisting() (int, error) {
	list, err := s.store.EnrolledList()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range list {
		pub, err := auth.ParseEd25519PublicKey(e.Key)
		if err != nil {
			s.log.Warn("quicsql/enroll: skipping undecodable enrolled key", "principal", e.Name, "err", err)
			continue
		}
		s.authn.AddKeyring(e.Key, pub, e.Name)
		s.applyGrants(e.Name)
		n++
	}
	s.mu.Lock()
	s.count = n
	s.mu.Unlock()
	return n, nil
}

// List returns the enrolled principals (for /_admin/principals).
func (s *Service) List() ([]meta.Enrolled, error) { return s.store.EnrolledList() }

// Delete revokes an enrolled principal everywhere: meta store, keyring, grants.
// Deleting an unknown (or config-defined) name reports false.
func (s *Service) Delete(name string) (bool, error) {
	existed, err := s.store.DeleteEnrolled(name)
	if err != nil || !existed {
		return existed, err
	}
	s.authn.RemoveKeyringName(name)
	s.policy.RevokePrincipal(name)
	s.mu.Lock()
	s.count--
	s.mu.Unlock()
	return true, nil
}

// ServeHTTP handles POST /_auth/enroll. Mounted pre-auth by the auth
// middleware on keyring-accepting listeners; it performs its own possession
// proof, so an unauthenticated caller can never register a key it doesn't hold.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpjson.Error(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	ip := remoteIP(r)
	if !s.allow(ip) {
		s.store.Audit("", "enroll.denied", "", "rate limited ip="+ip)
		httpjson.Error(w, http.StatusTooManyRequests, "enrollment rate limited")
		return
	}
	// Possession proof FIRST: nothing below runs for a caller that can't sign.
	canon, pub, err := s.authn.VerifyPresented(r)
	if err != nil {
		s.store.Audit("", "enroll.denied", "", "invalid possession proof ip="+ip)
		httpjson.Error(w, http.StatusUnauthorized, "enrollment requires a valid signed challenge (see /_auth/challenge)")
		return
	}
	if s.cfg.Policy == "token" && !s.tokenOK(r) {
		s.store.Audit("", "enroll.denied", "", "missing/invalid enrollment token ip="+ip)
		httpjson.Error(w, http.StatusForbidden, "enrollment requires a valid enrollment token")
		return
	}

	name := PrincipalName(canon)
	// One registration path at a time: the check-then-insert on count and the
	// idempotency lookup must not interleave.
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.store.EnrolledList()
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "internal error")
		return
	}
	for _, e := range existing {
		if e.Key == canon {
			// Idempotent re-enroll: same key, same principal — a reinstalled app
			// doesn't multiply identities.
			httpjson.Write(w, http.StatusOK, map[string]any{"principal": e.Name, "created": false})
			return
		}
	}
	if s.cfg.MaxPrincipals > 0 && s.count >= s.cfg.MaxPrincipals {
		s.store.Audit("", "enroll.denied", "", "max_principals reached ip="+ip)
		httpjson.Error(w, http.StatusTooManyRequests, "enrollment capacity reached")
		return
	}
	if err := s.store.PutEnrolled(name, canon); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.authn.AddKeyring(canon, pub, name)
	s.applyGrants(name)
	s.count++
	s.store.Audit(name, "enroll.created", "", "ip="+ip)
	s.log.Info("quicsql/enroll: principal enrolled", "principal", name, "ip", ip)
	httpjson.Write(w, http.StatusOK, map[string]any{"principal": name, "created": true})
}

func (s *Service) applyGrants(name string) {
	for _, g := range s.cfg.Grants {
		if lvl, ok := authz.ParseLevel(g.Level); ok {
			s.policy.Grant(g.DB, name, lvl)
		}
	}
}

// tokenOK reads the request body ({"enroll_token": "…"}) and compares its hash
// against the accepted set in constant time.
func (s *Service) tokenOK(r *http.Request) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return false
	}
	var req struct {
		Token string `json:"enroll_token"`
	}
	if json.Unmarshal(body, &req) != nil || req.Token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(req.Token))
	want := []byte(hex.EncodeToString(sum[:]))
	ok := false
	for h := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(h), want) == 1 {
			ok = true
		}
	}
	return ok
}

// PrincipalName derives the server-assigned principal name from a canonical
// key line: "u_" + base32(sha256(key))[:16]. Deterministic, so re-enrolling the
// same key always resolves to the same identity, and never client-chosen.
func PrincipalName(canonicalKey string) string {
	sum := sha256.Sum256([]byte(canonicalKey))
	return "u_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10]))
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// bucket is a minimal token bucket: burst 3, refill cfg.RatePerIP per second.
type bucket struct {
	tokens float64
	last   time.Time
}

const (
	bucketBurst = 3
	// maxBuckets hard-caps the per-IP bucket map. The rate check runs before the
	// (cheap) possession proof so a flooder pays no crypto, but that means an
	// unauthenticated caller cycling source IPs (trivial on an IPv6 /64) would
	// otherwise grow the map without bound. At the cap we opportunistically evict
	// fully-refilled buckets; if none can be freed, a new IP is refused outright.
	maxBuckets = 4096
)

// allow admits or rejects one enrollment attempt from ip.
func (s *Service) allow(ip string) bool {
	if s.cfg.RatePerIP <= 0 {
		return true
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.buckets[ip]; b != nil {
		b.tokens = min(bucketBurst, b.tokens+now.Sub(b.last).Seconds()*s.cfg.RatePerIP)
		b.last = now
		if b.tokens < 1 {
			return false
		}
		b.tokens--
		return true
	}
	// A new IP needs a new bucket. Evict fully-refilled ones when the map is
	// large, and refuse (rather than grow past the cap) if that frees nothing.
	if len(s.buckets) >= maxBuckets {
		idle := time.Duration(float64(bucketBurst)/s.cfg.RatePerIP) * time.Second
		for k, b := range s.buckets {
			if now.Sub(b.last) > idle {
				delete(s.buckets, k)
			}
		}
		s.lastGC = now
		if len(s.buckets) >= maxBuckets {
			return false // saturated with active IPs — shed load rather than grow
		}
	}
	s.buckets[ip] = &bucket{tokens: bucketBurst - 1, last: now}
	return true
}
