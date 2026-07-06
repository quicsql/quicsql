package account

// Password set/change + login (accounts design Phase 2.1). SetPassword writes the
// DATA-ONLY password credential (the HTTP layer gates it on owner/step-up assurance);
// Login resolves an identifier to an account, verifies the password, and mints a
// data-only session. Both paths are enumeration- and timing-uniform (§14.4): the
// no-account / no-password branch still performs one Argon2id verify.

import (
	"context"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"quicsql.net/authz"
	"quicsql.net/meta"
	"quicsql.net/notify"
)

// SetPassword sets or replaces the account's password (one per account). It enforces the
// NIST policy + breach screen; ctxTerms are account-context strings (handle, email
// local-part) that a password must not contain. The caller must already be an owner with
// fresh assurance (enforced at the HTTP layer).
func (s *Service) SetPassword(ctx context.Context, account, newPassword string, ctxTerms []string) error {
	if !s.cfg.Password.Enabled {
		return ErrPasswordDisabled
	}
	if err := checkPasswordPolicy(newPassword, s.cfg.Password.MinLength); err != nil {
		return err
	}
	if err := screenBreach(newPassword, append(ctxTerms, "quicsql")); err != nil {
		return err
	}
	enc, err := hashPassword(newPassword, s.cfg.Password.Pepper)
	if err != nil {
		return err
	}

	unlock := s.lock(account)
	defer unlock()
	existing, err := s.store.CredentialsByAccountType(account, credPassword)
	if err != nil {
		return err
	}
	changed := len(existing) > 0
	if changed {
		if err := s.store.UpdateCredentialMaterial(existing[0].ID, enc, "", "active"); err != nil {
			return err
		}
	} else {
		if err := s.store.PutCredential(meta.Credential{
			ID: mustCredID(), Account: account, Type: credPassword, Role: "primary",
			Tier: int(authz.TierDataOnly), Material: enc, Label: "password", AddedAt: time.Now().Unix(),
		}); err != nil {
			return err
		}
	}
	action, subject := "account.password_set", "A password was set on your account"
	if changed {
		action, subject = "account.password_changed", "Your account password was changed"
	}
	s.store.Audit(account, action, "", "")
	s.notifyEvent(ctx, account, notify.EventCredentialAdded, subject)
	return nil
}

// LoginResult carries the session minted from a successful password login.
type LoginResult struct {
	Principal string
	Token     string
	ExpiresAt time.Time
}

// Login verifies identifier+password and mints a DATA-ONLY session. Failures are
// uniform (ErrBadCredentials) with equalized timing — the no-account and no-password
// paths both run one Argon2id verify so existence can't be inferred.
func (s *Service) Login(ctx context.Context, identifier, password string) (LoginResult, error) {
	if !s.cfg.Password.Enabled {
		return LoginResult{}, ErrPasswordDisabled
	}
	account, ok := s.resolveIdentifier(identifier)
	if !ok {
		dummyVerify(password)
		return LoginResult{}, ErrBadCredentials
	}
	creds, err := s.store.CredentialsByAccountType(account, credPassword)
	if err != nil {
		return LoginResult{}, err
	}
	if len(creds) == 0 || creds[0].Status != "active" {
		dummyVerify(password)
		return LoginResult{}, ErrBadCredentials
	}
	cred := creds[0]
	if !verifyPassword(cred.Material, password, s.cfg.Password.Pepper) {
		return LoginResult{}, ErrBadCredentials
	}
	tok, exp, _, err := s.authn.MintSessionAs(account, authz.TierDataOnly, authz.FactorPassword, authz.ScopeFull, cred.ID, time.Time{})
	if err != nil {
		return LoginResult{}, err
	}
	s.applyGrant(account) // ensure the DB grant is live (e.g. first login after a restart)
	_ = s.store.TouchCredential(cred.ID, time.Now().Unix())
	s.store.Audit(account, "account.login", "", "password")
	return LoginResult{Principal: account, Token: tok, ExpiresAt: exp}, nil
}

// resolveIdentifier maps a login identifier to an account: a verified alias
// (handle/email — Phase 2.3) or a literal u_ principal that has credentials.
func (s *Service) resolveIdentifier(identifier string) (string, bool) {
	id := strings.TrimSpace(identifier)
	if id == "" {
		return "", false
	}
	if acct, ok, err := s.store.AliasAccount(normalizeAliasLookup(id)); err == nil && ok {
		return acct, true
	}
	if strings.HasPrefix(id, accountPrefix) {
		if creds, err := s.store.CredentialsByAccount(id); err == nil && len(creds) > 0 {
			return id, true
		}
	}
	return "", false
}

// normalizeAliasLookup is the base normalization for alias LOOKUPS — NFKC + case-fold +
// trim. The alias WRITE path (Phase 2.3) adds handle-specific confusable/script checks
// on top; the lookup key derived here must match what it stores.
func normalizeAliasLookup(s string) string {
	return norm.NFKC.String(strings.ToLower(strings.TrimSpace(s)))
}
