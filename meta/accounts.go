package meta

import (
	"database/sql"
	"errors"
	"fmt"
)

// This file is the accounts-model persistence (accounts design Phase 1.1): accounts,
// their credentials, one-time attach/recovery codes, and the durable session
// registry. It sits alongside the older enrolled/enroll_codes tables until serverd
// is switched over. FKs are not enforced (foreign_keys stays off) — cascades and the
// "≥1 usable credential" invariant are the account service's job, under a
// per-account lock.

// Account is a stable principal owning a provisioned database.
type Account struct {
	Principal string
	CreatedAt int64
	LastSeen  int64
	Status    string
}

// Credential is one authenticator resolving to an account.
type Credential struct {
	ID        string
	Account   string
	Type      string // ed25519 | recovery_key | recovery_code | …
	Role      string // primary | factor | recovery
	Tier      int    // authz.Tier a session minted from this credential carries
	Material  string
	Meta      string
	BatchID   string
	Label     string
	Status    string // active | pending
	AddedAt   int64
	LastUsed  int64
	ExpiresAt int64
}

// Session is one durable session-registry row (for the device list).
type Session struct {
	SID       string
	Account   string
	CredID    string
	CreatedAt int64
	Exp       int64
	HardExp   int64
}

// --- accounts --------------------------------------------------------------

// PutAccount inserts a new account row.
func (s *Store) PutAccount(principal string, createdAt int64) error {
	if _, err := s.db.Exec(`INSERT INTO accounts(principal, created_at, status) VALUES(?,?,'active')`,
		principal, createdAt); err != nil {
		return fmt.Errorf("meta: put account %q: %w", principal, err)
	}
	return nil
}

// AccountList returns all accounts, oldest first.
func (s *Store) AccountList() ([]Account, error) {
	rows, err := s.db.Query(`SELECT principal, created_at, COALESCE(last_seen, created_at), status FROM accounts ORDER BY created_at, principal`)
	if err != nil {
		return nil, fmt.Errorf("meta: list accounts: %w", err)
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.Principal, &a.CreatedAt, &a.LastSeen, &a.Status); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// TouchAccounts moves last_seen forward for the given accounts (idle-GC bookkeeping),
// mirroring TouchEnrolled — never backward, and only for accounts that exist.
func (s *Store) TouchAccounts(seen map[string]int64) error {
	if len(seen) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`UPDATE accounts SET last_seen = ? WHERE principal = ? AND (last_seen IS NULL OR last_seen < ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for name, at := range seen {
		if _, err := stmt.Exec(at, name, at); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return err
		}
	}
	_ = stmt.Close()
	return tx.Commit()
}

// IdleAccounts lists accounts whose last activity (last_seen, or created_at if never
// seen) predates cutoff — the idle-GC candidates.
func (s *Store) IdleAccounts(cutoff int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT principal FROM accounts WHERE COALESCE(last_seen, created_at) < ?`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("meta: idle accounts: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// DeleteAccountCascade removes an account and everything keyed to it (credentials,
// aliases, otp tokens, sessions). Reports whether the account existed.
func (s *Store) DeleteAccountCascade(principal string) (bool, error) {
	for _, q := range []string{
		`DELETE FROM credentials WHERE account = ?`,
		`DELETE FROM aliases WHERE account = ?`,
		`DELETE FROM otp_tokens WHERE account = ?`,
		`DELETE FROM sessions WHERE account = ?`,
	} {
		if _, err := s.db.Exec(q, principal); err != nil {
			return false, fmt.Errorf("meta: cascade delete %q: %w", principal, err)
		}
	}
	res, err := s.db.Exec(`DELETE FROM accounts WHERE principal = ?`, principal)
	if err != nil {
		return false, fmt.Errorf("meta: delete account %q: %w", principal, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// --- credentials -----------------------------------------------------------

// PutCredential inserts a credential. A UNIQUE(type, material) conflict surfaces as
// an error — the caller's idempotency pre-check (CredentialByMaterial) plus a
// per-account lock keep it from racing in practice.
func (s *Store) PutCredential(c Credential) error {
	_, err := s.db.Exec(`INSERT INTO credentials(cred_id, account, type, role, tier, material, meta, batch_id, label, status, added_at, expires_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Account, c.Type, c.Role, c.Tier, c.Material, nullify(c.Meta), nullify(c.BatchID), nullify(c.Label),
		orDefault(c.Status, "active"), c.AddedAt, nullifyInt(c.ExpiresAt))
	if err != nil {
		return fmt.Errorf("meta: put credential: %w", err)
	}
	return nil
}

// CredentialByMaterial resolves a (type, material) — e.g. an ed25519 key line — to
// its credential, for register/attach idempotency.
func (s *Store) CredentialByMaterial(typ, material string) (Credential, bool, error) {
	c, err := s.scanCredential(s.db.QueryRow(credCols+` WHERE type = ? AND material = ?`, typ, material))
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, err
	}
	return c, true, nil
}

// CredentialByID fetches one credential.
func (s *Store) CredentialByID(id string) (Credential, bool, error) {
	c, err := s.scanCredential(s.db.QueryRow(credCols+` WHERE cred_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, err
	}
	return c, true, nil
}

// CredentialsByAccount lists an account's credentials (for the credential list and
// the never-remove-last invariant).
func (s *Store) CredentialsByAccount(account string) ([]Credential, error) {
	rows, err := s.db.Query(credCols+` WHERE account = ? ORDER BY added_at`, account)
	if err != nil {
		return nil, fmt.Errorf("meta: credentials by account: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := s.scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CredentialsByAccountType lists an account's credentials of one type (e.g. all
// "totp" factors, or the single "password"). Ordered by added_at.
func (s *Store) CredentialsByAccountType(account, typ string) ([]Credential, error) {
	rows, err := s.db.Query(credCols+` WHERE account = ? AND type = ? ORDER BY added_at`, account, typ)
	if err != nil {
		return nil, fmt.Errorf("meta: credentials by account+type: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := s.scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateCredentialMaterial replaces a credential's material (+ meta, + status), for a
// password change or a TOTP replay-step/activation update. status "" leaves it as-is.
func (s *Store) UpdateCredentialMaterial(id, material, meta, status string) error {
	var err error
	if status == "" {
		_, err = s.db.Exec(`UPDATE credentials SET material = ?, meta = ? WHERE cred_id = ?`, material, nullify(meta), id)
	} else {
		_, err = s.db.Exec(`UPDATE credentials SET material = ?, meta = ?, status = ? WHERE cred_id = ?`, material, nullify(meta), status, id)
	}
	if err != nil {
		return fmt.Errorf("meta: update credential material: %w", err)
	}
	return nil
}

// AliasAccount resolves a normalized handle/email alias to its account. Only VERIFIED
// aliases resolve (an unverified email is not yet a usable lookup key). Returns
// (account, true) or ("", false); populated by the alias flows (Phase 2.3).
func (s *Store) AliasAccount(alias string) (string, bool, error) {
	var account string
	err := s.db.QueryRow(`SELECT account FROM aliases WHERE alias = ? AND verified = 1`, alias).Scan(&account)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("meta: alias lookup: %w", err)
	}
	return account, true, nil
}

// TouchCredential stamps a credential's last_used (device/passkey/password auth), for
// the "last used" column in the credential list.
func (s *Store) TouchCredential(id string, ts int64) error {
	if _, err := s.db.Exec(`UPDATE credentials SET last_used = ? WHERE cred_id = ?`, ts, id); err != nil {
		return fmt.Errorf("meta: touch credential: %w", err)
	}
	return nil
}

// DeleteCredential removes one credential, returning it (for keyring/session
// revocation) and whether it existed.
func (s *Store) DeleteCredential(id string) (Credential, bool, error) {
	c, ok, err := s.CredentialByID(id)
	if err != nil || !ok {
		return Credential{}, ok, err
	}
	if _, err := s.db.Exec(`DELETE FROM credentials WHERE cred_id = ?`, id); err != nil {
		return Credential{}, false, fmt.Errorf("meta: delete credential: %w", err)
	}
	return c, true, nil
}

const credCols = `SELECT cred_id, account, type, role, tier, material, COALESCE(meta,''), COALESCE(batch_id,''), COALESCE(label,''), status, added_at, COALESCE(last_used,0), COALESCE(expires_at,0) FROM credentials`

type rowScanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanCredential(r rowScanner) (Credential, error) {
	var c Credential
	err := r.Scan(&c.ID, &c.Account, &c.Type, &c.Role, &c.Tier, &c.Material, &c.Meta, &c.BatchID, &c.Label,
		&c.Status, &c.AddedAt, &c.LastUsed, &c.ExpiresAt)
	return c, err
}

// --- one-time tokens (attach / recovery), same used-at CAS as enroll codes -----

// PutOTP records a minted one-time token by hash, bound to an account and purpose.
func (s *Store) PutOTP(hash, account, purpose string, createdAt, expiresAt int64) error {
	if _, err := s.db.Exec(`INSERT INTO otp_tokens(token_hash, account, purpose, created_at, expires_at) VALUES(?,?,?,?,?)`,
		hash, nullify(account), purpose, createdAt, expiresAt); err != nil {
		return fmt.Errorf("meta: put otp: %w", err)
	}
	return nil
}

// ConsumeOTP atomically marks an unused, unexpired token of the given purpose used
// and returns its bound account. ok=false (a concurrent second attempt updates zero
// rows) means it was already used, expired, or unknown.
func (s *Store) ConsumeOTP(hash, purpose string, now int64) (account string, ok bool, err error) {
	res, err := s.db.Exec(`UPDATE otp_tokens SET used_at = ? WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?`,
		now, hash, purpose, now)
	if err != nil {
		return "", false, fmt.Errorf("meta: consume otp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", false, nil
	}
	err = s.db.QueryRow(`SELECT COALESCE(account,'') FROM otp_tokens WHERE token_hash = ?`, hash).Scan(&account)
	return account, true, err
}

// ReleaseOTP un-consumes a token (used_at = NULL) after an attach that consumed it
// but then rejected the caller downstream (key on another account, cap reached), so a
// legitimate retry isn't blocked. Best-effort.
func (s *Store) ReleaseOTP(hash string) {
	if _, err := s.db.Exec(`UPDATE otp_tokens SET used_at = NULL WHERE token_hash = ?`, hash); err != nil {
		s.log.Error("quicsql/meta: release otp", "err", err)
	}
}

// GCOTP deletes used or expired one-time tokens. Best-effort.
func (s *Store) GCOTP(now int64) {
	if _, err := s.db.Exec(`DELETE FROM otp_tokens WHERE used_at IS NOT NULL OR expires_at <= ?`, now); err != nil {
		s.log.Error("quicsql/meta: gc otp", "err", err)
	}
}

// CountActiveOTP counts an account's live (unused, unexpired) tokens of a purpose —
// for the per-account attach-code cap.
func (s *Store) CountActiveOTP(account, purpose string, now int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM otp_tokens WHERE account = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?`,
		account, purpose, now).Scan(&n)
	return n, err
}

// --- SessionStore (auth.SessionStore): durable session registry ------------

// PutSession records a live session for the device list + targeted revocation.
func (s *Store) PutSession(sid, account, credID string, createdAt, exp, hardExp int64) error {
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO sessions(sid, account, cred_id, created_at, exp, hard_exp) VALUES(?,?,?,?,?,?)`,
		sid, account, nullify(credID), createdAt, exp, nullifyInt(hardExp)); err != nil {
		return fmt.Errorf("meta: put session: %w", err)
	}
	return nil
}

// SessionsByAccount returns hex(sid) → outer deadline (max of exp/hard_exp, unix
// nanos) for every live session of an account.
func (s *Store) SessionsByAccount(account string) (map[string]int64, error) {
	return s.sessionDeadlines(`WHERE account = ?`, account)
}

// SessionsByCredential returns the same for every session minted by a credential.
func (s *Store) SessionsByCredential(credID string) (map[string]int64, error) {
	return s.sessionDeadlines(`WHERE cred_id = ?`, credID)
}

func (s *Store) sessionDeadlines(where, arg string) (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT sid, MAX(COALESCE(exp,0), COALESCE(hard_exp,0)) FROM sessions `+where, arg)
	if err != nil {
		return nil, fmt.Errorf("meta: session deadlines: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var sid string
		var deadline int64
		if err := rows.Scan(&sid, &deadline); err != nil {
			return nil, err
		}
		out[sid] = deadline
	}
	return out, rows.Err()
}

// DeleteSessions removes the given session rows (on revoke).
func (s *Store) DeleteSessions(sids ...string) error {
	for _, sid := range sids {
		if _, err := s.db.Exec(`DELETE FROM sessions WHERE sid = ?`, sid); err != nil {
			return fmt.Errorf("meta: delete session: %w", err)
		}
	}
	return nil
}

// ListSessions returns an account's live sessions for the device list.
func (s *Store) ListSessions(account string) ([]Session, error) {
	rows, err := s.db.Query(`SELECT sid, account, COALESCE(cred_id,''), COALESCE(created_at,0), COALESCE(exp,0), COALESCE(hard_exp,0) FROM sessions WHERE account = ? ORDER BY created_at DESC`, account)
	if err != nil {
		return nil, fmt.Errorf("meta: list sessions: %w", err)
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.SID, &s.Account, &s.CredID, &s.CreatedAt, &s.Exp, &s.HardExp); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ClearSessions drops all session rows. Called at startup: the minter's fresh
// per-process key already invalidated every pre-restart token, so the registry
// would otherwise list dead sessions.
func (s *Store) ClearSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions`)
	return err
}

// GCSessions removes sessions past their outer deadline (unix nanos). Best-effort.
func (s *Store) GCSessions(nowNanos int64) {
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE MAX(COALESCE(exp,0), COALESCE(hard_exp,0)) < ?`, nowNanos); err != nil {
		s.log.Error("quicsql/meta: gc sessions", "err", err)
	}
}

// --- small helpers ---------------------------------------------------------

// nullify stores "" as SQL NULL so COALESCE reads and UNIQUE/optional semantics work.
func nullify(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullifyInt(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
