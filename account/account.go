// Package account is the multi-credential account service (accounts design Phase 1):
// an account is a stable principal (u_<random>) owning a provisioned database, with
// many credentials that all resolve to it. It replaces the single-key enroll model —
// Register creates an account from a device key (plus a recovery key + codes), Attach
// adds another device via a one-time code, Detach removes one (never the last usable
// one), and Recover redeems a recovery key/code into a session. Authorization for
// these actions is enforced at the HTTP layer via authz.RequireAssurance; this
// package owns the state transitions, the never-remove-last invariant, and the
// per-account mutation lock.
package account

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"

	"quicsql.net/auth"
	"quicsql.net/authz"
	"quicsql.net/config"
	"quicsql.net/meta"
	"quicsql.net/notify"
	"quicsql.net/provision"
	"quicsql.net/registry"
)

// Credential types + the recovery-code batch size.
const (
	credEd25519      = "ed25519"
	credRecoveryKey  = "recovery_key"
	credRecoveryCode = "recovery_code"
	credPassword     = "password"
	recoveryCodeN    = 10
)

// Errors surfaced to the HTTP layer (mapped to status codes there).
var (
	ErrInvalidCode         = errors.New("account: invalid or expired code")
	ErrKeyOnAnotherAccount = errors.New("account: this device key already belongs to another account")
	ErrLastCredential      = errors.New("account: cannot remove the last usable credential")
	ErrNoSuchCredential    = errors.New("account: no such credential")
	ErrTooManyCredentials  = errors.New("account: credential limit reached")
	ErrTooManyCodes        = errors.New("account: too many outstanding codes")
	ErrInvalidRecovery     = errors.New("account: invalid recovery secret")
	ErrNoSuchSession       = errors.New("account: no such session")
)

// Config templates the per-account database and the code/limit knobs (mapped from
// auth.accounts.* in Phase 1.5). Zero values get safe defaults.
type Config struct {
	Provision      config.Provision
	CodeTTL        time.Duration // attach/recovery code lifetime
	RecoveryHold   time.Duration // destructive-action hold after a recovery-code redeem
	IdleTTL        time.Duration // 0 ⇒ keep accounts forever; else idle-GC after this
	MaxCredentials int           // 0 ⇒ default
	MaxAttachCodes int
	Password       PasswordPolicy // Phase 2.1
}

// PasswordPolicy configures password login. Pepper is the resolved key material (from
// auth.accounts.password.pepper) that keys every hash outside the store; when Enabled is
// false the password endpoints refuse.
type PasswordPolicy struct {
	Enabled   bool
	Pepper    []byte
	MinLength int
}

func (c *Config) applyDefaults() {
	if c.CodeTTL <= 0 {
		c.CodeTTL = 15 * time.Minute // an attach code is a bearer secret unbound to the redeeming key — keep the window short (§21-E2)
	}
	if c.RecoveryHold <= 0 {
		c.RecoveryHold = 24 * time.Hour
	}
	if c.MaxCredentials <= 0 {
		c.MaxCredentials = 20
	}
	if c.MaxAttachCodes <= 0 {
		c.MaxAttachCodes = 3
	}
	if c.Provision.NameTemplate == "" {
		c.Provision.NameTemplate = "{principal}"
	}
	if c.Provision.Level == "" {
		c.Provision.Level = "read-write"
	}
	if c.Provision.Backend == "" {
		c.Provision.Backend = "vault" // encrypted at rest when keyed (matches enroll); Register always provisions
	}
	if c.Provision.OnRevoke == "" {
		c.Provision.OnRevoke = "keep"
	}
}

// Service manages accounts and their credentials.
type Service struct {
	cfg    Config
	store  *meta.Store
	authn  *auth.Authenticator
	policy *authz.Policy
	prov   *provision.Provisioner
	notify notify.Notifier
	log    *slog.Logger

	gateMu sync.Mutex
	gates  map[string]*gate

	seenMu sync.Mutex       // guards seen (touched on the auth hot path)
	seen   map[string]int64 // account → last-auth unix, buffered until the reaper flushes it
}

// accountPrefix marks an account principal (u_…) — the same shape PrincipalName-style
// names use, so the seen-hook can skip static operators.
const accountPrefix = "u_"

// New builds the service. notify may be nil (⇒ Noop; the in-app/audit record still
// happens). prov must be set (accounts always own a database).
func New(cfg Config, store *meta.Store, authn *auth.Authenticator, policy *authz.Policy, prov *provision.Provisioner, n notify.Notifier, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if n == nil {
		n = notify.Noop{}
	}
	cfg.applyDefaults()
	return &Service{cfg: cfg, store: store, authn: authn, policy: policy, prov: prov, notify: n, log: log,
		gates: map[string]*gate{}, seen: map[string]int64{}}
}

// gate is a refcounted per-key mutex serializing an account's (or a device key's)
// credential mutations — the same pattern as enroll's provGate.
type gate struct {
	mu   sync.Mutex
	refs int
}

func (s *Service) lock(key string) func() {
	s.gateMu.Lock()
	g := s.gates[key]
	if g == nil {
		g = &gate{}
		s.gates[key] = g
	}
	g.refs++
	s.gateMu.Unlock()
	g.mu.Lock()
	return func() {
		g.mu.Unlock()
		s.gateMu.Lock()
		if g.refs--; g.refs == 0 {
			delete(s.gates, key)
		}
		s.gateMu.Unlock()
	}
}

// --- Register --------------------------------------------------------------

// RegisterResult carries the new (or existing) account. The recovery secrets are
// returned ONCE, only for a freshly created account.
type RegisterResult struct {
	Principal     string
	Created       bool
	RecoveryKey   string
	RecoveryCodes []string
}

// Register creates an account from a device key (its possession already proved by
// the caller), provisioning the account's database and issuing a recovery key +
// codes. Idempotent: a device key that is already a credential resolves to its
// existing account (created=false, no secrets re-shown).
func (s *Service) Register(ctx context.Context, canon string, pub ed25519.PublicKey) (RegisterResult, error) {
	unlock := s.lock("key:" + canon) // serialize concurrent registers of the same key
	defer unlock()

	if cred, ok, err := s.store.CredentialByMaterial(credEd25519, canon); err != nil {
		return RegisterResult{}, err
	} else if ok {
		s.authn.AddKeyring(canon, pub, cred.Account) // re-admit (e.g. after restart)
		s.applyGrant(cred.Account)
		return RegisterResult{Principal: cred.Account, Created: false}, nil
	}

	principal, err := newAccountID()
	if err != nil {
		return RegisterResult{}, err
	}
	if err := s.provisionFor(ctx, principal); err != nil {
		return RegisterResult{}, err
	}
	now := time.Now().Unix()
	if err := s.store.PutAccount(principal, now); err != nil {
		s.rollback(principal)
		return RegisterResult{}, err
	}
	dev := meta.Credential{ID: mustCredID(), Account: principal, Type: credEd25519, Role: "primary", Tier: int(authz.TierOwner), Material: canon, Label: "device", AddedAt: now}
	if err := s.store.PutCredential(dev); err != nil {
		s.rollback(principal)
		return RegisterResult{}, err
	}
	rk, rkHash, err := newRecoveryKey()
	if err != nil {
		s.rollback(principal)
		return RegisterResult{}, err
	}
	if err := s.store.PutCredential(meta.Credential{ID: mustCredID(), Account: principal, Type: credRecoveryKey, Role: "recovery", Tier: int(authz.TierOwner), Material: rkHash, AddedAt: now}); err != nil {
		s.rollback(principal)
		return RegisterResult{}, err
	}
	codes, err := s.mintRecoveryCodes(principal, now)
	if err != nil {
		s.rollback(principal)
		return RegisterResult{}, err
	}

	s.authn.AddKeyring(canon, pub, principal)
	s.applyGrant(principal)
	s.store.Audit(principal, "account.register", "", "")
	s.notifyEvent(ctx, principal, notify.EventCredentialAdded, "Your account was created")
	return RegisterResult{Principal: principal, Created: true, RecoveryKey: rk, RecoveryCodes: codes}, nil
}

// mintRecoveryCodes generates + stores (hashed) a fresh batch and returns the
// plaintext codes (shown once). All share a batch_id so a regenerate invalidates all.
func (s *Service) mintRecoveryCodes(account string, now int64) ([]string, error) {
	batch := mustCredID()
	out := make([]string, 0, recoveryCodeN)
	for range recoveryCodeN {
		code, err := randToken(15) // 120 bits ≥ 112
		if err != nil {
			return nil, err
		}
		if err := s.store.PutCredential(meta.Credential{ID: mustCredID(), Account: account, Type: credRecoveryCode, Role: "recovery", Tier: int(authz.TierOwner), Material: hashSecret(code), BatchID: batch, AddedAt: now}); err != nil {
			return nil, err
		}
		out = append(out, code)
	}
	return out, nil
}

// --- Attach ----------------------------------------------------------------

// AttachResult carries the account a device joined.
type AttachResult struct {
	Principal string
	Created   bool
}

// MintAttachCode issues a one-time code that lets another device join `account`.
// The caller must already be an owner (enforced at the HTTP layer).
func (s *Service) MintAttachCode(account string) (string, error) {
	now := time.Now()
	s.store.GCOTP(now.Unix())
	if s.cfg.MaxAttachCodes > 0 {
		if n, err := s.store.CountActiveOTP(account, "attach", now.Unix()); err != nil {
			return "", err
		} else if n >= s.cfg.MaxAttachCodes {
			return "", ErrTooManyCodes
		}
	}
	tok, err := randToken(15)
	if err != nil {
		return "", err
	}
	code := "ac_" + tok
	if err := s.store.PutOTP(hashSecret(code), account, "attach", now.Unix(), now.Add(s.cfg.CodeTTL).Unix()); err != nil {
		return "", err
	}
	return code, nil
}

// Attach adds a device key to the account named by a one-time attach code. It is
// attach-or-fail: an invalid/expired code errors (never falls through to Register),
// and a key already bound to a DIFFERENT account is rejected.
func (s *Service) Attach(ctx context.Context, canon string, pub ed25519.PublicKey, attachCode string) (AttachResult, error) {
	codeHash := hashSecret(attachCode)
	account, ok, err := s.store.ConsumeOTP(codeHash, "attach", time.Now().Unix())
	if err != nil {
		return AttachResult{}, err
	}
	if !ok {
		return AttachResult{}, ErrInvalidCode
	}
	// Serialize on the account AND on the presented key — a concurrent Register(K)
	// holds "key:"+canon, so taking it here (consistent order account→key, never the
	// reverse) prevents a register/attach race from splitting the keyring vs the DB.
	unlockA := s.lock(account)
	defer unlockA()
	unlockK := s.lock("key:" + canon)
	defer unlockK()

	if cred, exists, err := s.store.CredentialByMaterial(credEd25519, canon); err != nil {
		return AttachResult{}, err
	} else if exists {
		s.store.ReleaseOTP(codeHash) // nothing was added — don't burn the code
		if cred.Account != account {
			return AttachResult{}, ErrKeyOnAnotherAccount
		}
		s.authn.AddKeyring(canon, pub, account) // already ours — idempotent
		return AttachResult{Principal: account, Created: false}, nil
	}
	if creds, err := s.store.CredentialsByAccount(account); err != nil {
		return AttachResult{}, err
	} else if len(creds) >= s.cfg.MaxCredentials {
		s.store.ReleaseOTP(codeHash)
		return AttachResult{}, ErrTooManyCredentials
	}
	now := time.Now().Unix()
	if err := s.store.PutCredential(meta.Credential{ID: mustCredID(), Account: account, Type: credEd25519, Role: "primary", Tier: int(authz.TierOwner), Material: canon, Label: "device", AddedAt: now}); err != nil {
		s.store.ReleaseOTP(codeHash)
		return AttachResult{}, err
	}
	s.authn.AddKeyring(canon, pub, account)
	s.store.Audit(account, "account.attach", "", "")
	s.notifyEvent(ctx, account, notify.EventCredentialAdded, "A new device was added to your account")
	return AttachResult{Principal: account, Created: true}, nil
}

// --- Detach ----------------------------------------------------------------

// Detach removes one credential, enforcing the never-remove-last invariant (the
// account must keep ≥1 usable primary AND ≥1 usable recovery) under the per-account
// lock, then evicts its key and revokes the account's sessions (excluding the acting
// one). actingSID is the caller's own session, kept alive.
func (s *Service) Detach(ctx context.Context, account, credID, actingSID string) error {
	unlock := s.lock(account)
	defer unlock()

	creds, err := s.store.CredentialsByAccount(account)
	if err != nil {
		return err
	}
	var target *meta.Credential
	for i := range creds {
		if creds[i].ID == credID && creds[i].Account == account {
			target = &creds[i]
			break
		}
	}
	if target == nil {
		return ErrNoSuchCredential
	}
	now := time.Now().Unix()
	if p, r := usableExcluding(creds, credID, now); p < 1 || r < 1 {
		return ErrLastCredential
	}
	removed, ok, err := s.store.DeleteCredential(credID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoSuchCredential
	}
	if removed.Type == credEd25519 {
		s.authn.RemoveKeyringKey(removed.Material)
	}
	_ = s.authn.RevokeCredentialSessions(credID)
	// Device sessions carry no cred_id, so the targeted revoke above can't reach the
	// detached device's live token — revoke the account's OTHER sessions too (the
	// acting session is excluded so the owner isn't logged out mid-action).
	_ = s.authn.RevokeAccountSessions(account, actingSID)
	s.store.Audit(account, "account.detach", "", credID)
	s.notifyEvent(ctx, account, notify.EventCredentialRemoved, "A sign-in method was removed from your account")
	return nil
}

// usableExcluding counts an account's usable primary and recovery credentials,
// excluding one (a prospective removal). "Usable" = active, not expired, not a
// second-factor. A consumed recovery-code row is already gone, so recovery naturally
// drops to zero when the last code + the recovery key are removed.
func usableExcluding(creds []meta.Credential, excludeID string, now int64) (primary, recovery int) {
	for _, c := range creds {
		if c.ID == excludeID || c.Status != "active" {
			continue
		}
		if c.ExpiresAt != 0 && c.ExpiresAt < now {
			continue
		}
		switch c.Role {
		case "primary":
			primary++
		case "recovery":
			recovery++
		}
	}
	return primary, recovery
}

// --- Recover ---------------------------------------------------------------

// RecoverResult carries the session minted from a redeemed recovery secret.
type RecoverResult struct {
	Principal string
	Token     string
	ExpiresAt time.Time
	Root      bool // true for the recovery key (full scope); false for a one-time code (reduced)
}

// Recover redeems a recovery key or code into a session. The recovery KEY yields a
// full-scope owner session (root). A one-time CODE is consumed and yields a
// REDUCED-scope owner session with a destructive-action hold — it may register a new
// strong credential but not detach others / reach root until the hold passes
// (accounts §21-A2).
func (s *Service) Recover(ctx context.Context, secret string) (RecoverResult, error) {
	h := hashSecret(secret)

	if cred, ok, err := s.store.CredentialByMaterial(credRecoveryKey, h); err != nil {
		return RecoverResult{}, err
	} else if ok {
		tok, exp, _, err := s.authn.MintSessionAs(cred.Account, authz.TierOwner, authz.FactorRecovery, authz.ScopeFull, cred.ID, time.Time{})
		if err != nil {
			return RecoverResult{}, err
		}
		s.store.Audit(cred.Account, "account.recover", "", "key")
		s.notifyEvent(ctx, cred.Account, notify.EventRecoveryUsed, "Your recovery key was used to sign in")
		return RecoverResult{Principal: cred.Account, Token: tok, ExpiresAt: exp, Root: true}, nil
	}

	if cred, ok, err := s.store.CredentialByMaterial(credRecoveryCode, h); err != nil {
		return RecoverResult{}, err
	} else if ok {
		unlock := s.lock(cred.Account)
		defer unlock()
		if _, removed, err := s.store.DeleteCredential(cred.ID); err != nil {
			return RecoverResult{}, err
		} else if !removed {
			return RecoverResult{}, ErrInvalidRecovery // raced/consumed
		}
		notBefore := time.Now().Add(s.cfg.RecoveryHold)
		tok, exp, _, err := s.authn.MintSessionAs(cred.Account, authz.TierOwner, authz.FactorRecovery, authz.ScopeReduced, cred.ID, notBefore)
		if err != nil {
			return RecoverResult{}, err
		}
		s.store.Audit(cred.Account, "account.recover", "", "code")
		s.notifyEvent(ctx, cred.Account, notify.EventRecoveryUsed, "A recovery code was used to sign in")
		return RecoverResult{Principal: cred.Account, Token: tok, ExpiresAt: exp, Root: false}, nil
	}

	return RecoverResult{}, ErrInvalidRecovery
}

// --- Delete + reads --------------------------------------------------------

// Delete removes an account everywhere: its database (per provision.on_revoke), its
// credentials/aliases/otp/sessions, its keyring keys, grants, and sessions.
func (s *Service) Delete(account string) (bool, error) {
	unlock := s.lock(account)
	defer unlock()
	if s.cfg.Provision.OnRevoke == "drop" {
		if err := s.prov.Drop(s.provisionName(account), true); err != nil && !errors.Is(err, registry.ErrUnknownDB) {
			return false, err
		}
	}
	creds, _ := s.store.CredentialsByAccount(account)
	for _, c := range creds {
		if c.Type == credEd25519 {
			s.authn.RemoveKeyringKey(c.Material)
		}
	}
	existed, err := s.store.DeleteAccountCascade(account)
	if err != nil || !existed {
		return existed, err
	}
	s.authn.RemoveKeyringName(account)
	s.policy.RevokePrincipal(account)
	_ = s.authn.RevokeAccountSessions(account, "")
	s.store.Audit(account, "account.delete", "", "")
	return true, nil
}

// LoadExisting re-admits every account's device keys into the authenticator and
// re-applies its grant, at startup before listeners serve. Returns the account count.
func (s *Service) LoadExisting() (int, error) {
	accts, err := s.store.AccountList()
	if err != nil {
		return 0, err
	}
	for _, a := range accts {
		creds, err := s.store.CredentialsByAccount(a.Principal)
		if err != nil {
			return 0, err
		}
		for _, c := range creds {
			if c.Type != credEd25519 {
				continue
			}
			pub, perr := auth.ParseEd25519PublicKey(c.Material)
			if perr != nil {
				s.log.Warn("quicsql/account: skipping undecodable device key", "account", a.Principal, "err", perr)
				continue
			}
			s.authn.AddKeyring(c.Material, pub, a.Principal)
		}
		s.applyGrant(a.Principal)
	}
	return len(accts), nil
}

// List returns every account (for /_admin/principals).
func (s *Service) List() ([]meta.Account, error) { return s.store.AccountList() }

// Credentials lists one account's credentials (secrets are hashed/opaque).
func (s *Service) Credentials(account string) ([]meta.Credential, error) {
	return s.store.CredentialsByAccount(account)
}

// Sessions lists one account's live sessions (the device list).
func (s *Service) Sessions(account string) ([]meta.Session, error) {
	return s.store.ListSessions(account)
}

// RevokeSessions revokes the account's sessions — all (except the acting one, so the
// caller isn't logged out) or a single sid that must belong to the account — and
// records the security event.
func (s *Service) RevokeSessions(ctx context.Context, account, actingSID, sid string, all bool) error {
	switch {
	case all:
		if err := s.authn.RevokeAccountSessions(account, actingSID); err != nil {
			return err
		}
	case sid != "":
		sess, err := s.store.ListSessions(account)
		if err != nil {
			return err
		}
		owned := false
		for _, x := range sess {
			if x.SID == sid {
				owned = true
				break
			}
		}
		if !owned {
			return ErrNoSuchSession
		}
		s.authn.RevokeSessionID(sid)
	default:
		return ErrNoSuchSession
	}
	s.store.Audit(account, "account.sessions_revoked", "", "")
	s.notifyEvent(ctx, account, notify.EventSessionsRevoked, "Sessions were revoked on your account")
	return nil
}

// --- provisioning + grants (mirrors the enroll template) -------------------

func (s *Service) provisionName(principal string) string {
	return strings.ReplaceAll(s.cfg.Provision.NameTemplate, "{principal}", principal)
}

func (s *Service) provisionSpec(principal string) (config.Database, error) {
	p := s.cfg.Provision
	name := s.provisionName(principal)
	if !config.ValidDBName(name) {
		return config.Database{}, fmt.Errorf("account: provisioned db name %q is invalid", name)
	}
	db := config.Database{Name: name, Backend: p.Backend, PragmasPreset: p.PragmasPreset, Vault: p.Vault,
		Grants: []config.Grant{{Principal: principal, Level: p.Level}}}
	if config.UsesPath(p.Backend) {
		ext := ".db"
		if p.Backend == "vault" {
			ext = ".vault"
		}
		db.Path = name + ext
		db.Mode = "rwc"
	}
	if len(p.Pragmas) > 0 || p.MaxBytes > 0 {
		db.Pragmas = make(map[string]any, len(p.Pragmas)+1)
		maps.Copy(db.Pragmas, p.Pragmas)
		if p.MaxBytes > 0 {
			db.Pragmas["max_page_count"] = p.MaxBytes / config.ProvisionPageSize
		}
	}
	return db, nil
}

func (s *Service) provisionFor(ctx context.Context, principal string) error {
	spec, err := s.provisionSpec(principal)
	if err != nil {
		return err
	}
	if err := s.prov.Create(ctx, spec); err != nil && !errors.Is(err, registry.ErrExists) {
		return err
	}
	s.applyGrant(principal)
	return nil
}

func (s *Service) applyGrant(principal string) {
	if lvl, ok := authz.ParseLevel(s.cfg.Provision.Level); ok {
		s.policy.Grant(s.provisionName(principal), principal, lvl)
	}
}

func (s *Service) rollback(principal string) {
	_, _ = s.store.DeleteAccountCascade(principal)
	_ = s.prov.Drop(s.provisionName(principal), true)
	s.policy.RevokePrincipal(principal)
	s.authn.RemoveKeyringName(principal)
}

// notifyEvent always writes the in-app/audit record (the channel-less-safe path) and
// best-effort fires the out-of-band notifier.
func (s *Service) notifyEvent(ctx context.Context, account, event, subject string) {
	s.store.Audit(account, "notify."+event, "", subject)
	_ = s.notify.Notify(ctx, notify.Message{Account: account, Event: event, Subject: subject})
}

// --- crypto helpers --------------------------------------------------------

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(b32.EncodeToString(b)), nil
}

func newAccountID() (string, error) {
	t, err := randToken(10) // 80 bits → 16 base32 chars
	if err != nil {
		return "", err
	}
	return "u_" + t, nil
}

func mustCredID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newRecoveryKey() (plain, hash string, err error) {
	t, err := randToken(16) // 128 bits
	if err != nil {
		return "", "", err
	}
	plain = "rk_" + t
	return plain, hashSecret(plain), nil
}

func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
