-- Meta store schema (embedded via //go:embed in meta.go — never inline SQL/DDL in
-- Go sources). The meta store records runtime state the YAML config cannot: the
-- databases created through the control plane, the admin audit log, and the
-- accounts model. Applied idempotently at Open with CREATE ... IF NOT EXISTS.

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
-- Backs the per-account "recent security activity" feed (AuditEntriesByPrincipal):
-- (principal, id DESC) turns the newest-first scan-per-request into an index range.
CREATE INDEX IF NOT EXISTS audit_by_principal ON audit(principal, id DESC);

CREATE TABLE IF NOT EXISTS enrolled (
	name       TEXT PRIMARY KEY,     -- server-assigned principal name (u_…)
	key        TEXT NOT NULL UNIQUE, -- canonical ssh-ed25519 authorized-keys line
	created_at INTEGER NOT NULL,     -- unix seconds
	last_seen  INTEGER               -- unix seconds of last successful auth (NULL until first seen)
);

CREATE TABLE IF NOT EXISTS enroll_codes (
	hash       TEXT PRIMARY KEY,   -- hex(sha256(single-use enrollment code))
	created_at INTEGER NOT NULL,   -- unix seconds
	expires_at INTEGER NOT NULL,   -- unix seconds
	used_at    INTEGER             -- unix seconds; NULL until consumed
);
