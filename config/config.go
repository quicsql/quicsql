// Package config is the typed, YAML-backed configuration surface for the
// quicSQL server. It is declarative desired-state: it seeds the database
// registry and expresses defaults. Secret references are plain "source:name"
// strings resolved eagerly at load (the `!secret` YAML tag sugar is a Phase 5
// refinement over these fields).
package config

import "time"

// Config is the whole server configuration. Every section is wired to behavior
// (see load.go's knownTopLevel) except `wire_compression` and `observability`,
// which are parsed but inert (they warn on use) so the schema stays stable.
type Config struct {
	Server       Server                `yaml:"server" json:"server"`
	Secrets      []SecretSource        `yaml:"secrets" json:"secrets"`
	Routing      Routing               `yaml:"routing" json:"routing"`
	TLS          map[string]TLSProfile `yaml:"tls" json:"tls"`
	Listeners    []Listener            `yaml:"listeners" json:"listeners"`
	Auth         Auth                  `yaml:"auth" json:"auth"`
	Databases    []Database            `yaml:"databases" json:"databases"`
	ControlPlane ControlPlane          `yaml:"control_plane" json:"control_plane"`
	Limits       Limits                `yaml:"limits" json:"limits"`
	Logging      Logging               `yaml:"logging" json:"logging"`
	CORS         CORS                  `yaml:"cors" json:"cors"`
	ChangeFeed   ChangeFeed            `yaml:"changefeed" json:"changefeed"`

	warnings []string // config sections present but not yet consumed (logged at startup)
}

// ControlPlane enables the runtime admin API under /_admin: create/detach
// databases and vault maintenance. Admins names the server-admin principals —
// the only ones (besides open mode) allowed to create/detach and to run
// maintenance on any database; a principal holding an `admin` grant on one
// database may run maintenance on that database only.
type ControlPlane struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Admins  []string `yaml:"admins" json:"admins"`
}

// Warnings returns human-readable notes about config that parsed but has no
// effect yet (recognized-but-future sections, unknown keys), for the daemon to
// log so a silently-inert section isn't mistaken for a working one.
func (c *Config) Warnings() []string { return c.warnings }

// Server holds server-wide settings: the data directory and the meta store.
type Server struct {
	DataDir   string    `yaml:"data_dir" json:"data_dir"`
	MetaStore MetaStore `yaml:"meta_store" json:"meta_store"`
}

// MetaStore is the server-owned runtime registry + audit + idempotency state.
// It is a vault by default; set Key (a secret reference) to encrypt it at rest —
// the key must come from a non-meta secret source (chicken-and-egg — see the
// plan). A vault meta store without a key is a plain (unencrypted) container,
// warned at startup.
type MetaStore struct {
	Backend string `yaml:"backend" json:"backend"` // vault (default) | file
	Path    string `yaml:"path" json:"path"`
	Key     string `yaml:"key" json:"key"` // secret ref for the vault backend (raw cipher key)
}

// SecretSource declares one place key material can be read from. Every source
// is unattended (env/file/kms) — there is deliberately no interactive unlock, so
// the daemon starts without human interaction.
type SecretSource struct {
	Name     string `yaml:"name" json:"name"`
	Type     string `yaml:"type" json:"type"` // env | file | kms
	Dir      string `yaml:"dir" json:"dir"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	// Command is the argv a `kms` source execs to resolve a reference: it wraps a
	// real KMS (AWS KMS, GCP KMS, Vault Transit, age, …), receives the secret name
	// in $QUICSQL_SECRET_NAME, and writes the key bytes to stdout (verbatim — no
	// trimming). Trusted operator config; run with no shell.
	Command []string `yaml:"command" json:"command"`
}

// Routing selects how a request's target database is resolved — by URL path, by
// Host subdomain, or a configured default.
type Routing struct {
	ByPath     bool   `yaml:"by_path" json:"by_path"`
	ByHost     bool   `yaml:"by_host" json:"by_host"`
	HostSuffix string `yaml:"host_suffix" json:"host_suffix"`
	DefaultDB  string `yaml:"default_db" json:"default_db"`
}

// Listener is one bound network endpoint: its transport, address, TLS profile, and
// the auth methods it accepts.
type Listener struct {
	Name       string   `yaml:"name" json:"name"`
	Transport  string   `yaml:"transport" json:"transport"` // h1 | h2 | h2c | h3 | unix
	Address    string   `yaml:"address" json:"address"`
	TLS        string   `yaml:"tls" json:"tls"` // name of a tls profile (required for h2/h3)
	Auth       []string `yaml:"auth" json:"auth"`
	SocketMode string   `yaml:"socket_mode" json:"socket_mode"`
	// Advertise (h3 only) opts this HTTP/3 endpoint into Alt-Svc advertising: the
	// TCP transports (h1/h2/h2c) then emit `Alt-Svc: h3=":<port>"` so a client that
	// connected over TCP can discover and upgrade to h3 (as browsers do with :443).
	// Off by default — h3 is served regardless; this only advertises it.
	Advertise bool `yaml:"advertise" json:"advertise"`
}

// TLSProfile describes how to obtain the TLS certificate for a listener.
type TLSProfile struct {
	Mode       string        `yaml:"mode" json:"mode"`               // files | self_signed | qip
	Cert       string        `yaml:"cert" json:"cert"`               // files
	Key        string        `yaml:"key" json:"key"`                 // files
	ClientCA   string        `yaml:"client_ca" json:"client_ca"`     // mTLS (Phase 4)
	MinVersion string        `yaml:"min_version" json:"min_version"` // "1.2" | "1.3"
	Hosts      []string      `yaml:"hosts" json:"hosts"`             // self_signed SANs
	Subdomain  string        `yaml:"subdomain" json:"subdomain"`     // qip
	Refresh    time.Duration `yaml:"refresh" json:"refresh"`         // qip reload interval
}

// Auth is the authentication configuration: the named principals and their
// credential methods, the server-wide SQL policy, and the optional session-token
// service.
type Auth struct {
	AuthorizedKeys string        `yaml:"authorized_keys" json:"authorized_keys"`
	Principals     []Principal   `yaml:"principals" json:"principals"`
	SQLPolicy      SQLPolicy     `yaml:"sql_policy" json:"sql_policy"`
	Session        SessionTokens `yaml:"session" json:"session"`
	Enroll         Enroll        `yaml:"enroll" json:"enroll"`
	Accounts       Accounts      `yaml:"accounts" json:"accounts"`
}

// Accounts enables the multi-credential account model (accounts design): device
// keys, an attach flow, and recovery replace single-key enrollment. Like Enroll it
// requires the control plane + explicit auth, and provisions a per-account database.
type Accounts struct {
	Enabled        bool            `yaml:"enabled" json:"enabled"`
	Provision      Provision       `yaml:"provision" json:"provision"`
	CodeTTL        time.Duration   `yaml:"code_ttl" json:"code_ttl"`           // attach/recovery code lifetime (default 24h)
	RecoveryHold   time.Duration   `yaml:"recovery_hold" json:"recovery_hold"` // reduced-scope destructive hold after a recovery-code redeem
	IdleTTL        time.Duration   `yaml:"idle_ttl" json:"idle_ttl"`           // 0 ⇒ keep forever
	RatePerIP      float64         `yaml:"rate_per_ip" json:"rate_per_ip"`     // per-IP join/recover rate
	MaxCredentials int             `yaml:"max_credentials" json:"max_credentials"`
	MaxAttachCodes int             `yaml:"max_attach_codes" json:"max_attach_codes"`
	Session        AccountSession  `yaml:"session" json:"session"`
	Assurance      AssuranceCfg    `yaml:"assurance" json:"assurance"`
	Password       AccountPassword `yaml:"password" json:"password"`
}

// AccountPassword enables password login (accounts design Phase 2.1). A password is a
// DATA-ONLY credential — a phished password can read/write the database but never
// manages other credentials or reaches root. Pepper is REQUIRED when enabled: it keys
// every Argon2id hash with material held OUTSIDE the SQLite file (a secret reference),
// so a stolen store is not crackable.
type AccountPassword struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Pepper    string `yaml:"pepper" json:"pepper"`         // secret ref (source:name); required when enabled
	MinLength int    `yaml:"min_length" json:"min_length"` // sole-factor floor (default 15; NIST 800-63B-4)
}

// AccountSession selects how session tokens travel. Secure default: header-bearer
// (CSRF-moot). cookie/both auto-enable CSRF defenses (accounts design §21-G1).
type AccountSession struct {
	Transport string `yaml:"transport" json:"transport"` // header (default) | cookie | both
}

// AssuranceCfg is the operator-tunable step-up policy. Defaults are the secure
// phishing-resistant gate; loosening credential_mgmt/destructive to "strong" (accept
// TOTP) warns at startup (accounts design §21-A1/G2).
type AssuranceCfg struct {
	CredentialMgmt string        `yaml:"credential_mgmt" json:"credential_mgmt"` // phishing_resistant (default) | strong
	Destructive    string        `yaml:"destructive" json:"destructive"`
	StepUpWindow   time.Duration `yaml:"step_up_window" json:"step_up_window"` // default 10m
}

// Enroll enables self-service device enrollment at POST /_auth/enroll (served
// on keyring-accepting listeners): a caller proves possession of an ed25519
// private key by signing a fresh challenge, and the server registers the public
// key as a NEW principal with a server-assigned name (u_<key-hash>) and exactly
// the Grants template — never client-chosen names, never more than the
// template. Enrollment requires the control plane (the enrolled set lives in
// the meta store, and /_admin/principals is the oversight surface) and refuses
// to run on an open-mode server: registering the first dynamic principal must
// never be the event that flips enforcement semantics mid-flight.
type Enroll struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Policy gates who may enroll: "open" admits any key holder (dev/demo — the
	// quotas below are the only brake) and "token" additionally demands a valid
	// enrollment token in the request body.
	Policy string `yaml:"policy" json:"policy"` // open | token
	// Tokens are the accepted enrollment tokens for policy "token", each a
	// hex(sha256(token)) or a secret reference — the same never-store-plaintext
	// discipline as bearer credentials. Static and shared (rotate by config change);
	// for one-time per-user invites use Codes (single-use minted codes) instead.
	Tokens []string `yaml:"tokens" json:"tokens"`
	// MaxPrincipals hard-caps the enrolled set (default 1000) — the backstop
	// that bounds meta-store growth and policy size under abuse.
	MaxPrincipals int `yaml:"max_principals" json:"max_principals"`
	// RatePerIP is the sustained enrollment rate allowed per remote IP in
	// requests/second (token bucket, burst 3; default 0.1 ≈ six per minute).
	RatePerIP float64 `yaml:"rate_per_ip" json:"rate_per_ip"`
	// Grants is the template applied to every enrollee — deliberately the ONLY
	// grants an enrolled principal can hold, re-applied from config at startup
	// (the template, not the meta store, is the authorization truth).
	Grants []EnrollGrant `yaml:"grants" json:"grants"`
	// IdleTTL, when > 0, auto-removes an enrolled principal that has not
	// authenticated in this long (idle GC) — freeing its identity and, per
	// Provision.OnRevoke, its per-user database. 0 disables it.
	IdleTTL time.Duration `yaml:"idle_ttl" json:"idle_ttl"`
	// Provision optionally gives each enrollee their OWN database (database-per-user
	// containment) created at enroll time. Off by default.
	Provision Provision `yaml:"provision" json:"provision"`
	// Codes enables server-minted, single-use enrollment codes (POST
	// /_admin/enroll/codes) — a one-time alternative to (or complement of) the
	// static Tokens: an admin mints a code, hands it to a user, and it works once.
	Codes EnrollCodes `yaml:"codes" json:"codes"`
}

// ProvisionPageSize is the page size assumed when translating
// Provision.MaxBytes into a PRAGMA max_page_count cap (SQLite's default page).
const ProvisionPageSize = 4096

// EnrollCodes configures server-minted single-use enrollment codes. When enabled,
// POST /_admin/enroll/codes (server-admin) mints a fresh code, and a caller may
// present it under policy: token exactly once.
type EnrollCodes struct {
	Enabled bool          `yaml:"enabled" json:"enabled"`
	TTL     time.Duration `yaml:"ttl" json:"ttl"` // code lifetime (default 24h)
}

// EnrollGrant is one templated grant: a database name and a capability level.
type EnrollGrant struct {
	DB    string `yaml:"db" json:"db"`
	Level string `yaml:"level" json:"level"` // read-only | read-write
}

// Provision configures the per-enrollee database created at enroll time
// (database-per-user). It is off by default, and every policy that varies by
// use-case is a knob with a safe default — nothing here destroys data unless the
// operator sets on_revoke: drop.
type Provision struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// NameTemplate is the provisioned database's name; the token "{principal}"
	// expands to the enrollee's server-assigned name (u_<hash>). It MUST contain
	// "{principal}" so users don't collide on one database. Default "{principal}".
	NameTemplate string `yaml:"name_template" json:"name_template"`
	// Backend is the per-user database's backend — file | vault | memory-shared |
	// mvcc | memdb. Default "vault" (encrypted + compressed at rest). On-disk
	// backends get a path derived from the name, under data_dir.
	Backend string `yaml:"backend" json:"backend"`
	// Vault templates the per-user vault (key ref, compression, cipher) when
	// Backend is "vault". The key ref is shared across all per-user vaults — this
	// is encryption at rest; per-user isolation is by grant, not by key.
	Vault *VaultConfig `yaml:"vault" json:"vault"`
	// PragmasPreset and Pragmas template the per-user database's pragmas, exactly
	// like a seed database.
	PragmasPreset string         `yaml:"pragmas_preset" json:"pragmas_preset"`
	Pragmas       map[string]any `yaml:"pragmas" json:"pragmas"`
	// Level is the grant the enrollee receives on their OWN database — read-only or
	// read-write (never admin). Default "read-write".
	Level string `yaml:"level" json:"level"`
	// MaxBytes caps a per-user database's size, enforced via PRAGMA max_page_count
	// (a 4 KiB page is assumed). 0 = no size cap.
	MaxBytes int64 `yaml:"max_bytes" json:"max_bytes"`
	// OnRevoke decides the database's fate when the enrollee is deleted: "keep"
	// (default — leave it in place, data preserved and re-grantable) or "drop"
	// (detach it AND delete the file). Data is never destroyed unless "drop".
	OnRevoke string `yaml:"on_revoke" json:"on_revoke"`
}

// SessionTokens enables minting short-lived bearer tokens at POST /_auth/session:
// a request authenticated by any other credential method exchanges it for a
// bounded token (verified by the `session` listener auth method), so a client
// that can't hold a long-lived secret — a browser, a short-lived job — carries a
// revocable, expiring credential instead. Tokens are signed with a random
// per-process key (like challenges and batons): a restart invalidates them and
// clients simply re-mint.
//
// Two timers shape a token's life. IdleTTL is the sliding window: each issued
// token is valid this long. When MaxTTL is 0 (the default) tokens are strictly
// non-renewable — they die at IdleTTL, and a leaked one can't outlive it. When
// MaxTTL > 0 tokens become renewable ("extend on use"): an active session slides
// forward — transparently, via an `X-Quicsql-Session` response header the client
// adopts, or explicitly via PUT /_auth/session — but never past MaxTTL from the
// first mint, so a renewable token's whole chain is still bounded. Pick MaxTTL to
// bound a leaked token's blast radius; revocation (DELETE) still cuts it instantly.
type SessionTokens struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// IdleTTL bounds a single issued token's life and is the amount each renewal
	// grants (default 15m). Keep it short — an idle session lapses after this.
	IdleTTL time.Duration `yaml:"idle_ttl" json:"idle_ttl"`
	// MaxTTL is the absolute ceiling from the first mint. 0 = non-renewable (a
	// token dies at IdleTTL). > 0 = renewable up to this. Must be ≥ IdleTTL.
	MaxTTL time.Duration `yaml:"max_ttl" json:"max_ttl"`
}

// CORS configures cross-origin resource sharing for browser-based clients. Off
// by default: without it a browser page from another origin cannot call the
// server at all. Enabling it answers preflight (OPTIONS) requests before
// authentication — a preflight carries no credential by design — and stamps the
// approval headers on actual responses. Origins lists the allowed page origins
// ("https://app.example.com"); the "*" wildcard allows any origin, which is safe
// for header-credential auth (bearer/session/keyring — none of them are browser
// "credentials" in the cookie sense) but should be narrowed when possible.
type CORS struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Origins []string `yaml:"origins" json:"origins"` // page origins, or "*" (default when empty)
	// AllowHeaders extends the built-in allowed request headers (Authorization,
	// Content-Type, and the X-Quicsql-* keyring trio) for custom proxies/clients.
	AllowHeaders []string `yaml:"allow_headers" json:"allow_headers"`
	// ExposeHeaders names response headers browser scripts may read beyond the
	// CORS-safelisted set.
	ExposeHeaders []string `yaml:"expose_headers" json:"expose_headers"`
	// MaxAge is how long a browser may cache a preflight approval (default 2h,
	// Chrome's cap).
	MaxAge time.Duration `yaml:"max_age" json:"max_age"`
}

// Principal is one named identity and the credential methods (one map per method)
// it may authenticate with.
type Principal struct {
	Name    string           `yaml:"name" json:"name"`
	Methods []map[string]any `yaml:"methods" json:"methods"`
}

// SQLPolicy holds the server-global SQL-surface controls. Only allow_attach is
// wired: it is a DEV-ONLY switch that permits ATTACH/DETACH — and even then only on
// a pinned Hrana session opened by a server-admin (see the admin/attach docs). Off,
// ATTACH/DETACH are denied unconditionally. load_extension stays disabled with no
// knob (loading an arbitrary shared library over the network is remote code
// execution); the extension set is fixed at compile time by quicsql.net/extensions.
type SQLPolicy struct {
	AllowAttach bool `yaml:"allow_attach" json:"allow_attach"`
}

// Database is one registry entry: a logical name mapped to a physical open.
type Database struct {
	Name string `yaml:"name" json:"name"`
	// Backend selects storage: file | memory | memory-shared | mvcc | memdb | vault.
	Backend string `yaml:"backend" json:"backend"`
	Path    string `yaml:"path" json:"path"`
	Mode    string `yaml:"mode" json:"mode"` // rw | ro | rwc
	Pool    Pool   `yaml:"pool" json:"pool"`
	// PragmasPreset opts this database into a named pragma baseline the server
	// applies when it opens connections: "" (default) is bare SQLite; "recommended"
	// seeds the production preset (WAL + busy_timeout + foreign_keys). Explicit
	// Pragmas keys override the preset. It is a server-side setting — a client
	// cannot change a connection's configuration over the wire.
	PragmasPreset string         `yaml:"pragmas_preset" json:"pragmas_preset"`
	Pragmas       map[string]any `yaml:"pragmas" json:"pragmas"`
	Vault         *VaultConfig   `yaml:"vault" json:"vault"`
	Grants        []Grant        `yaml:"grants" json:"grants"`
}

// Pool holds a database's connection-pool settings (max open conns, tx lock mode,
// busy timeout).
type Pool struct {
	MaxOpen     int           `yaml:"max_open" json:"max_open"`
	TxLock      string        `yaml:"tx_lock" json:"tx_lock"` // deferred | immediate | exclusive
	BusyTimeout time.Duration `yaml:"busy_timeout" json:"busy_timeout"`
}

// VaultConfig splits the vault.Options surface into OPEN-time (runtime) fields
// and the create-only provisioning block, mirroring the API's own split.
type VaultConfig struct {
	Compression  string       `yaml:"compression" json:"compression"` // none | fastest | fast | default | better | best
	Cipher       string       `yaml:"cipher" json:"cipher"`           // adiantum | aes-xts
	Key          string       `yaml:"key" json:"key"`                 // secret ref (raw-key mode)
	Identities   []string     `yaml:"identities" json:"identities"`   // secret refs (recipient mode; first match wins)
	WriteAs      string       `yaml:"write_as" json:"write_as"`       // secret ref; omit ⇒ read-only at rest
	Masters      []string     `yaml:"masters" json:"masters"`         // trust anchors at open
	Authenticate bool         `yaml:"authenticate" json:"authenticate"`
	Anchor       *Anchor      `yaml:"anchor" json:"anchor"`
	Create       *VaultCreate `yaml:"create" json:"create"` // honored only when provisioning a new container
}

// Anchor configures the optional rollback-resistance anchor (an external
// monotonic counter). Only the file type is wired; tpm/kms are seams.
type Anchor struct {
	Type string `yaml:"type" json:"type"` // file | tpm | kms
	Path string `yaml:"path" json:"path"`
}

// VaultCreate is the create-only provisioning block, honored only when a new
// container is minted: it defines the initial keyslot membership (recipients,
// masters, writers, the signing master) and the on-disk geometry.
type VaultCreate struct {
	Recipients      []string `yaml:"recipients" json:"recipients"`
	Masters         []string `yaml:"masters" json:"masters"`
	SignWith        string   `yaml:"sign_with" json:"sign_with"`
	Writers         []string `yaml:"writers" json:"writers"`
	PageSize        int      `yaml:"page_size" json:"page_size"`
	BlockSize       int      `yaml:"block_size" json:"block_size"`
	DirSegmentPages int      `yaml:"dir_segment_pages" json:"dir_segment_pages"`
}

// ChangeFeed enables the committed-change notification stream at
// GET /<db>/changes (Server-Sent Events). Events carry table, operation, and
// rowid — never column values — and are published only at COMMIT, so a rolled
// back write is never seen. Requires databases with a stable on-disk path
// (file, vault); private in-memory backends are skipped with a warning.
type ChangeFeed struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Buffer is the per-database replay ring (default 1024 events): a subscriber
	// that reconnects within this window resumes by sequence; older horizons get
	// a `reset` event telling them to refetch.
	Buffer int `yaml:"buffer" json:"buffer"`
	// MaxSubscribers caps concurrent streams per database (default 128).
	MaxSubscribers int `yaml:"max_subscribers" json:"max_subscribers"`
}

// Grant maps a principal (or the "*" wildcard) to a capability level on a database.
type Grant struct {
	Principal string `yaml:"principal" json:"principal"`
	Level     string `yaml:"level" json:"level"` // none | read-only | read-write | admin
}

// Limits holds the server-wide resource limits: result/body/blob sizes, statement
// and transaction timeouts, per-database session and concurrency caps, idle-handle
// eviction, and per-principal rate limiting.
type Limits struct {
	MaxRows            int           `yaml:"max_rows" json:"max_rows"`
	MaxResultBytes     int64         `yaml:"max_result_bytes" json:"max_result_bytes"`
	MaxRequestBytes    int64         `yaml:"max_request_bytes" json:"max_request_bytes"`
	MaxBlobBytes       int64         `yaml:"max_blob_bytes" json:"max_blob_bytes"`       // cap for a single streamed large object (0 = default)
	MaxExportBytes     int64         `yaml:"max_export_bytes" json:"max_export_bytes"`   // cap for a full-database /export image, materialized whole in RAM (0 = default 1 GiB)
	MaxRestoreBytes    int64         `yaml:"max_restore_bytes" json:"max_restore_bytes"` // cap for a /_admin/restore upload, streamed to disk (0 = default 4 GiB; <0 = unlimited)
	StatementTimeout   time.Duration `yaml:"statement_timeout" json:"statement_timeout"`
	TxIdleTimeout      time.Duration `yaml:"tx_idle_timeout" json:"tx_idle_timeout"`
	MaxTxLifetime      time.Duration `yaml:"max_tx_lifetime" json:"max_tx_lifetime"`
	MaxSessionsPerDB   int           `yaml:"max_sessions_per_db" json:"max_sessions_per_db"`     // cap on concurrent pinned Hrana sessions per db (reads + writes)
	MaxConcurrentPerDB int           `yaml:"max_concurrent_per_db" json:"max_concurrent_per_db"` // admission cap per db (0 = unlimited)
	// IdleHandleTimeout, if > 0, closes a database's open handle after it has been
	// idle (no active users) this long; the next request reopens it. Bounds handle
	// growth for churned control-plane-created databases. 0 keeps handles open.
	IdleHandleTimeout time.Duration `yaml:"idle_handle_timeout" json:"idle_handle_timeout"`
	Rate              Rate          `yaml:"rate" json:"rate"`
}

// Rate configures per-principal request rate limiting.
type Rate struct {
	PerPrincipalRPS float64 `yaml:"per_principal_rps" json:"per_principal_rps"` // token-bucket refill rate (0 = unlimited)
}

// Logging configures log output: the format and the slow-query log (with its
// param-redaction default).
type Logging struct {
	Format string `yaml:"format" json:"format"` // json | text
	// ExpandParams opts INTO logging bound-parameter values (expanded SQL). The
	// zero value redacts — params are logged as `?` placeholders — so redaction is
	// the safe default even when the section is omitted.
	ExpandParams  bool          `yaml:"expand_params" json:"expand_params"`
	SlowThreshold time.Duration `yaml:"slow_threshold" json:"slow_threshold"` // >0 enables the slow-query log at this duration
}
