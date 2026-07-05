// Package meta is the server-owned meta store: a small SQLite database (a vault
// container by default, so it can be encrypted at rest) under data_dir that
// records runtime state the YAML config cannot — the databases created through
// the control plane, and the admin audit log. At startup the daemon reconciles
// config ∪ meta store: the file seeds, the meta store is the running truth for
// anything created at runtime (meta wins on a name conflict for entries it
// created).
package meta

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gosqlite.org"
	"quicsql.net/backend"
	"quicsql.net/config"
	"quicsql.net/secret"
)

const schema = `
CREATE TABLE IF NOT EXISTS databases (
	name       TEXT PRIMARY KEY,
	spec       TEXT NOT NULL,   -- JSON-encoded config.Database
	created_at INTEGER NOT NULL -- unix seconds
);
CREATE TABLE IF NOT EXISTS audit (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	at        INTEGER NOT NULL, -- unix seconds
	principal TEXT NOT NULL,
	action    TEXT NOT NULL,
	db        TEXT NOT NULL,
	detail    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrolled (
	name       TEXT PRIMARY KEY,    -- server-assigned principal name (u_…)
	key        TEXT NOT NULL UNIQUE, -- canonical ssh-ed25519 authorized-keys line
	created_at INTEGER NOT NULL,     -- unix seconds
	last_seen  INTEGER               -- unix seconds of last successful auth (NULL until first seen)
);
CREATE TABLE IF NOT EXISTS enroll_codes (
	hash       TEXT PRIMARY KEY,   -- hex(sha256(single-use enrollment code))
	created_at INTEGER NOT NULL,   -- unix seconds
	expires_at INTEGER NOT NULL,   -- unix seconds
	used_at    INTEGER             -- unix seconds; NULL until consumed
);`

// Store is the open meta store handle.
type Store struct {
	db  *sqlite.DB
	log *slog.Logger
}

// Open opens (creating if absent) the meta store described by cfg. The vault
// backend without a key is a plain container and is warned about — encryption
// at rest needs meta_store.key.
func Open(cfg config.MetaStore, sec secret.Resolver, dataDir string, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	spec := config.Database{
		Name:    "_meta",
		Backend: cfg.Backend,
		Path:    cfg.Path,
		Mode:    "rwc",
	}
	if cfg.Backend == "vault" {
		if cfg.Key != "" {
			spec.Vault = &config.VaultConfig{Key: cfg.Key}
		} else {
			log.Warn("quicsql/meta: meta store has no key (server.meta_store.key) — it is NOT encrypted at rest")
		}
	}
	be, err := backend.For(spec, sec, dataDir)
	if err != nil {
		return nil, fmt.Errorf("meta: %w", err)
	}
	// Bound the open so a wedged backend (e.g. a vault waiting on a slow KMS, or a
	// file lock held by another process) fails startup instead of hanging it forever.
	openCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := be.Open(openCtx)
	if err != nil {
		return nil, fmt.Errorf("meta: open %s: %w", cfg.Path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("meta: schema: %w", err)
	}
	// Migration: stores created before idle GC lack enrolled.last_seen. Detect the
	// column with the pragma_table_info() table-valued function rather than matching a
	// driver's "duplicate column name" error string — that string can change between
	// SQLite builds and would then turn a benign re-run into a startup failure. Add
	// the column only when it is genuinely absent.
	var hasLastSeen int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('enrolled') WHERE name = 'last_seen'`).Scan(&hasLastSeen); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("meta: inspect enrolled columns: %w", err)
	}
	if hasLastSeen == 0 {
		if _, err := db.Exec(`ALTER TABLE enrolled ADD COLUMN last_seen INTEGER`); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("meta: migrate enrolled.last_seen: %w", err)
		}
	}
	return &Store{db: db, log: log}, nil
}

// Close closes the meta store handle.
func (s *Store) Close() error { return s.db.Close() }

// Databases returns the runtime-created database specs, for startup
// reconciliation. An entry whose spec no longer decodes is skipped with a loud
// warning rather than failing startup.
func (s *Store) Databases() ([]config.Database, error) {
	rows, err := s.db.Query(`SELECT name, spec FROM databases ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("meta: list databases: %w", err)
	}
	defer rows.Close()
	var out []config.Database
	for rows.Next() {
		var name, spec string
		if err := rows.Scan(&name, &spec); err != nil {
			return nil, fmt.Errorf("meta: scan: %w", err)
		}
		var db config.Database
		if err := json.Unmarshal([]byte(spec), &db); err != nil || db.Name != name {
			s.log.Warn("quicsql/meta: skipping undecodable database entry", "name", name, "err", err)
			continue
		}
		out = append(out, db)
	}
	return out, rows.Err()
}

// Put records (or replaces) a runtime-created database spec.
func (s *Store) Put(db config.Database) error {
	spec, err := json.Marshal(db)
	if err != nil {
		return fmt.Errorf("meta: encode spec: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO databases(name, spec, created_at) VALUES(?,?,?)
		ON CONFLICT(name) DO UPDATE SET spec=excluded.spec`,
		db.Name, string(spec), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("meta: put %q: %w", db.Name, err)
	}
	return nil
}

// Delete forgets a runtime-created database spec. Deleting a name the meta
// store never recorded is a no-op.
func (s *Store) Delete(name string) error {
	if _, err := s.db.Exec(`DELETE FROM databases WHERE name = ?`, name); err != nil {
		return fmt.Errorf("meta: delete %q: %w", name, err)
	}
	return nil
}

// Enrolled is one runtime-enrolled principal: a server-assigned name bound to
// an ed25519 public key.
type Enrolled struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen"` // last successful auth (== created_at if never seen)
}

// EnrolledList returns every enrolled principal, oldest first.
func (s *Store) EnrolledList() ([]Enrolled, error) {
	rows, err := s.db.Query(`SELECT name, key, created_at, COALESCE(last_seen, created_at) FROM enrolled ORDER BY created_at, name`)
	if err != nil {
		return nil, fmt.Errorf("meta: list enrolled: %w", err)
	}
	defer rows.Close()
	var out []Enrolled
	for rows.Next() {
		var e Enrolled
		if err := rows.Scan(&e.Name, &e.Key, &e.CreatedAt, &e.LastSeen); err != nil {
			return nil, fmt.Errorf("meta: scan enrolled: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// TouchEnrolled records the last-seen time for enrolled principals (idle-GC
// bookkeeping), moving last_seen forward only. Names that aren't enrolled (e.g.
// static keyring identities) match no row and are ignored.
func (s *Store) TouchEnrolled(seen map[string]int64) error {
	if len(seen) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("meta: touch enrolled: %w", err)
	}
	stmt, err := tx.Prepare(`UPDATE enrolled SET last_seen = ? WHERE name = ? AND (last_seen IS NULL OR last_seen < ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("meta: touch enrolled: %w", err)
	}
	defer stmt.Close()
	for name, at := range seen {
		if _, err := stmt.Exec(at, name, at); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("meta: touch enrolled %q: %w", name, err)
		}
	}
	return tx.Commit()
}

// IdleEnrolled returns the names of enrolled principals whose last activity
// (last_seen, or created_at if never seen) predates cutoff — the idle-GC victims.
func (s *Store) IdleEnrolled(cutoff int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM enrolled WHERE COALESCE(last_seen, created_at) < ?`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("meta: idle enrolled: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("meta: scan idle enrolled: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// EnrolledByKey returns the principal name bound to a canonical key and whether it
// exists — the indexed idempotency lookup (enrolled.key is UNIQUE), so the enroll
// path need not scan the whole table.
func (s *Store) EnrolledByKey(key string) (name string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT name FROM enrolled WHERE key = ?`, key).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("meta: enrolled by key: %w", err)
	}
	return name, true, nil
}

// PutEnrolled records one enrolled principal. The name and key are both unique;
// re-enrolling an existing key is the caller's idempotency path, not an upsert.
func (s *Store) PutEnrolled(name, key string) error {
	if _, err := s.db.Exec(`INSERT INTO enrolled(name, key, created_at) VALUES(?,?,?)`,
		name, key, time.Now().Unix()); err != nil {
		return fmt.Errorf("meta: enroll %q: %w", name, err)
	}
	return nil
}

// DeleteEnrolled forgets an enrolled principal, reporting whether it existed.
func (s *Store) DeleteEnrolled(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM enrolled WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("meta: delete enrolled %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PutEnrollCode records a minted single-use enrollment code by its hash.
func (s *Store) PutEnrollCode(hash string, createdAt, expiresAt int64) error {
	if _, err := s.db.Exec(`INSERT INTO enroll_codes(hash, created_at, expires_at) VALUES(?,?,?)`,
		hash, createdAt, expiresAt); err != nil {
		return fmt.Errorf("meta: put enroll code: %w", err)
	}
	return nil
}

// EnrollCodeValid reports whether a code (by hash) exists, is unused, and is not
// yet expired — a read-only pre-check before the enrollment's other gates run.
func (s *Store) EnrollCodeValid(hash string, now int64) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM enroll_codes WHERE hash = ? AND used_at IS NULL AND expires_at > ?`,
		hash, now).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ConsumeEnrollCode atomically marks an unused, unexpired code used and reports
// whether it won — the single-use guarantee: a concurrent second attempt updates
// zero rows and reports false.
func (s *Store) ConsumeEnrollCode(hash string, now int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE enroll_codes SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ?`,
		now, hash, now)
	if err != nil {
		return false, fmt.Errorf("meta: consume enroll code: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ReleaseEnrollCode un-consumes a code (used_at = NULL), restoring it after an
// enrollment that consumed it but then rolled back — so a transient provisioning
// failure never burns a user's one-time code. Best-effort.
func (s *Store) ReleaseEnrollCode(hash string) {
	if _, err := s.db.Exec(`UPDATE enroll_codes SET used_at = NULL WHERE hash = ?`, hash); err != nil {
		s.log.Error("quicsql/meta: release enroll code", "err", err)
	}
}

// GCEnrollCodes deletes used or expired codes, bounding the table. Best-effort.
func (s *Store) GCEnrollCodes(now int64) {
	if _, err := s.db.Exec(`DELETE FROM enroll_codes WHERE used_at IS NOT NULL OR expires_at <= ?`, now); err != nil {
		s.log.Error("quicsql/meta: gc enroll codes", "err", err)
	}
}

// Audit appends one admin-action record. Best-effort: a failure is logged, not
// propagated, so auditing can't take the admin op down with it. Nil-safe: a
// stateless deployment (no meta store) simply drops the record, so callers can
// audit unconditionally — including denied/failed attempts.
func (s *Store) Audit(principal, action, db, detail string) {
	if s == nil {
		return
	}
	_, err := s.db.Exec(`INSERT INTO audit(at, principal, action, db, detail) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), principal, action, db, detail)
	if err != nil {
		s.log.Error("quicsql/meta: audit write failed", "action", action, "db", db, "err", err)
	}
}

// AuditEntry is one row of the admin audit log.
type AuditEntry struct {
	At        int64
	Principal string
	Action    string
	DB        string
	Detail    string
}

// AuditEntries returns the most recent audit records, newest first (up to limit).
// Nil-safe: a stateless deployment (no meta store) has no audit log, so it returns
// nil. It backs the offline audit reader and lets tests assert that denied/failed
// control-plane attempts are recorded, not only successes.
func (s *Store) AuditEntries(limit int) ([]AuditEntry, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT at, principal, action, db, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.At, &e.Principal, &e.Action, &e.DB, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
