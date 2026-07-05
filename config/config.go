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
// credential methods, plus the server-wide SQL policy.
type Auth struct {
	AuthorizedKeys string      `yaml:"authorized_keys" json:"authorized_keys"`
	Principals     []Principal `yaml:"principals" json:"principals"`
	SQLPolicy      SQLPolicy   `yaml:"sql_policy" json:"sql_policy"`
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
	MaxBlobBytes       int64         `yaml:"max_blob_bytes" json:"max_blob_bytes"`     // cap for a single streamed large object (0 = default)
	MaxExportBytes     int64         `yaml:"max_export_bytes" json:"max_export_bytes"` // cap for a full-database /export image, materialized whole in RAM (0 = default 1 GiB)
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
