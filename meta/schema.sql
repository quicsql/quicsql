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

-- Accounts model (accounts design). An account is a stable principal (u_<random>)
-- owning a provisioned database; many credentials resolve to it; sessions/otp are
-- keyed to it. FKs are documentation only (foreign_keys stays off) — invariants and
-- cascades are enforced in app logic under a per-account lock.
CREATE TABLE IF NOT EXISTS accounts (
	principal  TEXT PRIMARY KEY,    -- u_<random>: immutable authz subject AND provisioned DB name
	created_at INTEGER NOT NULL,    -- unix seconds
	last_seen  INTEGER,             -- unix seconds of last successful auth (idle GC)
	status     TEXT NOT NULL DEFAULT 'active'  -- active | locked | pending_deletion
);

CREATE TABLE IF NOT EXISTS credentials (
	cred_id    TEXT PRIMARY KEY,    -- random id
	account    TEXT NOT NULL,
	type       TEXT NOT NULL,       -- ed25519 | recovery_key | recovery_code (passkey/totp/password later)
	role       TEXT NOT NULL,       -- primary | factor | recovery
	tier       INTEGER NOT NULL,    -- authz.Tier a session minted from this credential carries
	material   TEXT NOT NULL,       -- ed25519 canonical key line / hashed recovery secret
	meta       TEXT,                -- JSON (BE/BS, sign_count, alg, … — later phases)
	batch_id   TEXT,                -- groups a recovery-code batch (regenerate-invalidates-all)
	label      TEXT,
	status     TEXT NOT NULL DEFAULT 'active',  -- active | pending
	added_at   INTEGER NOT NULL,
	last_used  INTEGER,
	expires_at INTEGER,             -- pending-credential TTL
	UNIQUE(type, material)          -- ed25519 idempotency + recovery-hash uniqueness
);
CREATE INDEX IF NOT EXISTS credentials_by_account ON credentials(account);

CREATE TABLE IF NOT EXISTS aliases (            -- populated in Phase 2 (handle/email)
	alias    TEXT PRIMARY KEY,      -- normalized handle or email
	kind     TEXT NOT NULL,         -- handle | email
	account  TEXT NOT NULL,
	verified INTEGER NOT NULL DEFAULT 0,
	added_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS otp_tokens (
	token_hash TEXT PRIMARY KEY,    -- hex(sha256(code))
	account    TEXT,                -- bound account (attach/recovery are account-scoped)
	purpose    TEXT NOT NULL,       -- attach | recovery
	attempts   INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at    INTEGER              -- single-use; NULL until consumed
);

CREATE TABLE IF NOT EXISTS sessions (
	sid        TEXT PRIMARY KEY,    -- hex(session id)
	account    TEXT NOT NULL,
	cred_id    TEXT,                -- credential that minted it (targeted revocation)
	created_at INTEGER,
	exp        INTEGER,
	hard_exp   INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_by_account ON sessions(account);
CREATE INDEX IF NOT EXISTS sessions_by_cred ON sessions(cred_id);
