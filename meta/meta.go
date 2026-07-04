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
	"encoding/json"
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
// nil. It backs the /_admin audit view and lets tests assert that denied/failed
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
