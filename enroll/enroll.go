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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
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
	"quicsql.net/provision"
	"quicsql.net/registry"
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

	prov *provision.Provisioner // per-user database provisioning (nil ⇒ disabled)

	mu      sync.Mutex
	count   int // live size of the enrolled set (loaded at startup)
	buckets map[string]*bucket
	lastGC  time.Time
}

// SetProvisioner wires database-per-user provisioning into the service. Called
// once during serverd assembly when auth.enroll.provision is enabled.
func (s *Service) SetProvisioner(p *provision.Provisioner) { s.prov = p }

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

	// Fate of the per-user database, per on_revoke. "keep" (default) leaves it in
	// place — data is preserved and re-granted if the same key re-enrolls. "drop"
	// detaches it and deletes the file.
	if s.provisionEnabled() && s.cfg.Provision.OnRevoke == "drop" {
		dbName := s.provisionName(name)
		if err := s.prov.Drop(dbName, true); err != nil && !errors.Is(err, registry.ErrUnknownDB) {
			s.log.Warn("quicsql/enroll: could not drop per-user database on revoke", "principal", name, "db", dbName, "err", err)
		}
	}
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
	// Read the presented token now (the body is read once); validation and
	// single-use consumption happen below, only once we know this is a NEW
	// enrollment — an already-enrolled key re-proving possession needs no token.
	presentedToken := ""
	if s.cfg.Policy == "token" {
		presentedToken = s.readEnrollToken(r)
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
			// doesn't multiply identities, and needs no token (already trusted).
			httpjson.Write(w, http.StatusOK, map[string]any{"principal": e.Name, "created": false})
			return
		}
	}
	// New enrollment: the token gate applies now (it never applies to the re-enroll
	// above). A single-use code is validated here and consumed just below.
	var codeHash string
	if s.cfg.Policy == "token" {
		ok, ch := s.validateToken(presentedToken)
		if !ok {
			s.store.Audit("", "enroll.denied", "", "missing/invalid enrollment token ip="+ip)
			httpjson.Error(w, http.StatusForbidden, "enrollment requires a valid enrollment token")
			return
		}
		codeHash = ch
	}
	if s.cfg.MaxPrincipals > 0 && s.count >= s.cfg.MaxPrincipals {
		s.store.Audit("", "enroll.denied", "", "max_principals reached ip="+ip)
		httpjson.Error(w, http.StatusTooManyRequests, "enrollment capacity reached")
		return
	}
	// Consume the single-use code NOW — this is a confirmed new enrollment (past the
	// idempotency and cap gates), so a re-enroll or a rejected attempt never burns
	// one. The atomic consume also settles any race between two keys presenting the
	// same code: exactly one wins.
	if codeHash != "" {
		consumed, cerr := s.store.ConsumeEnrollCode(codeHash, time.Now().Unix())
		if cerr != nil {
			httpjson.Error(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !consumed {
			s.store.Audit("", "enroll.denied", "", "enrollment code already used or expired ip="+ip)
			httpjson.Error(w, http.StatusForbidden, "enrollment code is no longer valid")
			return
		}
	}
	if err := s.store.PutEnrolled(name, canon); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.authn.AddKeyring(canon, pub, name)
	s.applyGrants(name)
	s.count++

	// Provision the enrollee's own database, if configured. Do it as part of the
	// enrollment transaction: if it fails, roll the whole enroll back so we never
	// leave a principal without the database it was promised.
	if s.provisionEnabled() {
		if err := s.provisionFor(name); err != nil {
			_, _ = s.store.DeleteEnrolled(name)
			s.authn.RemoveKeyringName(name)
			s.policy.RevokePrincipal(name)
			s.count--
			s.store.Audit(name, "enroll.failed", "", "provision: "+err.Error())
			s.log.Error("quicsql/enroll: provisioning failed, enrollment rolled back", "principal", name, "err", err)
			httpjson.Error(w, http.StatusInternalServerError, "enrollment could not provision a database")
			return
		}
	}

	s.store.Audit(name, "enroll.created", "", "ip="+ip)
	s.log.Info("quicsql/enroll: principal enrolled", "principal", name, "ip", ip)
	httpjson.Write(w, http.StatusOK, map[string]any{"principal": name, "created": true})
}

// provisionEnabled reports whether per-user provisioning is wired and turned on.
func (s *Service) provisionEnabled() bool { return s.prov != nil && s.cfg.Provision.Enabled }

// provisionName resolves the per-user database name for a principal from the
// name_template (the "{principal}" token expands to the principal name).
func (s *Service) provisionName(principal string) string {
	return strings.ReplaceAll(s.cfg.Provision.NameTemplate, "{principal}", principal)
}

// provisionSpec builds the per-user database spec from the provision template: the
// backend/vault/pragmas, a data_dir-relative path derived from the name, the
// enrollee's grant (persisted so it reloads at startup), and the optional size cap
// (via PRAGMA max_page_count, 4 KiB pages).
func (s *Service) provisionSpec(principal string) (config.Database, error) {
	p := s.cfg.Provision
	name := s.provisionName(principal)
	if !config.ValidDBName(name) {
		return config.Database{}, fmt.Errorf("provisioned database name %q is invalid", name)
	}
	db := config.Database{
		Name:          name,
		Backend:       p.Backend,
		PragmasPreset: p.PragmasPreset,
		Vault:         p.Vault,
		Grants:        []config.Grant{{Principal: principal, Level: p.Level}},
	}
	if config.UsesPath(p.Backend) {
		ext := ".db"
		if p.Backend == "vault" {
			ext = ".vault"
		}
		db.Path = name + ext
		db.Mode = "rwc" // create the per-user file on first open
	}
	if len(p.Pragmas) > 0 || p.MaxBytes > 0 {
		db.Pragmas = make(map[string]any, len(p.Pragmas)+1)
		maps.Copy(db.Pragmas, p.Pragmas)
		if p.MaxBytes > 0 {
			db.Pragmas["max_page_count"] = p.MaxBytes / 4096
		}
	}
	return db, nil
}

// provisionFor creates the enrollee's database and grants them access on the live
// policy. An already-existing database (a prior run, or a "keep" re-enroll) is
// tolerated — the grant is (re)applied and the call succeeds.
func (s *Service) provisionFor(principal string) error {
	spec, err := s.provisionSpec(principal)
	if err != nil {
		return err
	}
	if err := s.prov.Create(context.Background(), spec); err != nil && !errors.Is(err, registry.ErrExists) {
		return err
	}
	if lvl, ok := authz.ParseLevel(s.cfg.Provision.Level); ok {
		s.policy.Grant(spec.Name, principal, lvl)
	}
	return nil
}

func (s *Service) applyGrants(name string) {
	for _, g := range s.cfg.Grants {
		if lvl, ok := authz.ParseLevel(g.Level); ok {
			s.policy.Grant(g.DB, name, lvl)
		}
	}
}

// readEnrollToken pulls the enroll_token from the request body ({"enroll_token": "…"}).
func (s *Service) readEnrollToken(r *http.Request) string {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return ""
	}
	var req struct {
		Token string `json:"enroll_token"`
	}
	if json.Unmarshal(body, &req) != nil {
		return ""
	}
	return req.Token
}

// validateToken validates the presented token WITHOUT consuming it: a static
// shared token (constant-time) passes with an empty codeHash, a valid unused
// single-use code passes with its hash (to be consumed only once the enrollment
// is confirmed new). It never consumes a code, so a re-enroll or a downstream
// failure can't burn one.
func (s *Service) validateToken(token string) (ok bool, codeHash string) {
	if token == "" {
		return false, ""
	}
	sum := sha256.Sum256([]byte(token))
	hexsum := hex.EncodeToString(sum[:])
	want := []byte(hexsum)
	for h := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(h), want) == 1 {
			return true, "" // a static shared token; nothing to consume
		}
	}
	if s.cfg.Codes.Enabled {
		valid, err := s.store.EnrollCodeValid(hexsum, time.Now().Unix())
		if err != nil {
			s.log.Error("quicsql/enroll: check code", "err", err)
			return false, ""
		}
		if valid {
			return true, hexsum
		}
	}
	return false, ""
}

// errCodesDisabled is returned by MintCode when single-use codes are off.
var errCodesDisabled = errors.New("enroll: single-use codes are not enabled (auth.enroll.codes.enabled)")

// MintCode generates a fresh single-use enrollment code, stores its hash with the
// configured TTL, and returns the plaintext code (shown only here) plus its unix
// expiry. Requires auth.enroll.codes.enabled.
func (s *Service) MintCode() (code string, expiresAt int64, err error) {
	if !s.cfg.Codes.Enabled {
		return "", 0, errCodesDisabled
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", 0, err
	}
	code = "ec_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	sum := sha256.Sum256([]byte(code))
	now := time.Now()
	s.store.GCEnrollCodes(now.Unix()) // opportunistic housekeeping
	expiresAt = now.Add(s.cfg.Codes.TTL).Unix()
	if err := s.store.PutEnrollCode(hex.EncodeToString(sum[:]), now.Unix(), expiresAt); err != nil {
		return "", 0, err
	}
	return code, expiresAt, nil
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
