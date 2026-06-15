// Package config is the typed, YAML-backed configuration surface for the
// quicSQL server. It is declarative desired-state: it seeds the database
// registry and expresses defaults. Secret references are plain "source:name"
// strings resolved eagerly at load (the `!secret` YAML tag sugar is a Phase 5
// refinement over these fields).
package config

import "time"

// Config is the whole server configuration. Only the Phase 0 subset is wired to
// behavior today; the remaining sections are parsed so the schema is stable.
type Config struct {
	Server       Server                `yaml:"server"`
	Secrets      []SecretSource        `yaml:"secrets"`
	Routing      Routing               `yaml:"routing"`
	TLS          map[string]TLSProfile `yaml:"tls"`
	Listeners    []Listener            `yaml:"listeners"`
	Auth         Auth                  `yaml:"auth"`
	Databases    []Database            `yaml:"databases"`
	ControlPlane ControlPlane          `yaml:"control_plane"`
	Limits       Limits                `yaml:"limits"`
	Logging      Logging               `yaml:"logging"`

	warnings []string // config sections present but not yet consumed (logged at startup)
}

// ControlPlane enables the runtime admin API under /_admin: create/detach
// databases and vault maintenance. Admins names the server-admin principals —
// the only ones (besides open mode) allowed to create/detach and to run
// maintenance on any database; a principal holding an `admin` grant on one
// database may run maintenance on that database only.
type ControlPlane struct {
	Enabled bool     `yaml:"enabled"`
	Admins  []string `yaml:"admins"`
}

// Warnings returns human-readable notes about config that parsed but has no
// effect yet (recognized-but-future sections, unknown keys), for the daemon to
// log so a silently-inert section isn't mistaken for a working one.
func (c *Config) Warnings() []string { return c.warnings }

type Server struct {
	DataDir   string    `yaml:"data_dir"`
	MetaStore MetaStore `yaml:"meta_store"`
}

// MetaStore is the server-owned runtime registry + audit + idempotency state.
// It is a vault by default; set Key (a secret reference) to encrypt it at rest —
// the key must come from a non-meta secret source (chicken-and-egg — see the
// plan). A vault meta store without a key is a plain (unencrypted) container,
// warned at startup.
type MetaStore struct {
	Backend string `yaml:"backend"` // vault (default) | file
	Path    string `yaml:"path"`
	Key     string `yaml:"key"` // secret ref for the vault backend (raw cipher key)
}

// SecretSource declares one place key material can be read from. Every source
// is unattended (env/file/kms) — there is deliberately no interactive unlock, so
// the daemon starts without human interaction.
type SecretSource struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"` // env | file | kms
	Dir      string `yaml:"dir"`
	Endpoint string `yaml:"endpoint"`
}

type Routing struct {
	ByPath     bool   `yaml:"by_path"`
	ByHost     bool   `yaml:"by_host"`
	HostSuffix string `yaml:"host_suffix"`
	DefaultDB  string `yaml:"default_db"`
}

type Listener struct {
	Name       string   `yaml:"name"`
	Transport  string   `yaml:"transport"` // h1 | h2 | h2c | h3 | unix
	Address    string   `yaml:"address"`
	TLS        string   `yaml:"tls"` // name of a tls profile (required for h2/h3)
	Auth       []string `yaml:"auth"`
	SocketMode string   `yaml:"socket_mode"`
}

// TLSProfile describes how to obtain the TLS certificate for a listener.
type TLSProfile struct {
	Mode       string        `yaml:"mode"`        // files | self_signed | qip
	Cert       string        `yaml:"cert"`        // files
	Key        string        `yaml:"key"`         // files
	ClientCA   string        `yaml:"client_ca"`   // mTLS (Phase 4)
	MinVersion string        `yaml:"min_version"` // "1.2" | "1.3"
	Hosts      []string      `yaml:"hosts"`       // self_signed SANs
	Subdomain  string        `yaml:"subdomain"`   // qip
	Refresh    time.Duration `yaml:"refresh"`     // qip reload interval
}

type Auth struct {
	AuthorizedKeys string      `yaml:"authorized_keys"`
	Principals     []Principal `yaml:"principals"`
	SQLPolicy      SQLPolicy   `yaml:"sql_policy"`
}

type Principal struct {
	Name    string           `yaml:"name"`
	Methods []map[string]any `yaml:"methods"`
}

type SQLPolicy struct {
	AllowAttach        bool     `yaml:"allow_attach"`
	AllowLoadExtension bool     `yaml:"allow_load_extension"`
	EnabledExtensions  []string `yaml:"enabled_extensions"`
}

// Database is one registry entry: a logical name mapped to a physical open.
type Database struct {
	Name    string         `yaml:"name"`
	Backend string         `yaml:"backend"` // file | memory | memory-shared | mvcc | memdb | vault
	Path    string         `yaml:"path"`
	Mode    string         `yaml:"mode"` // rw | ro | rwc
	Pool    Pool           `yaml:"pool"`
	Pragmas map[string]any `yaml:"pragmas"`
	Vault   *VaultConfig   `yaml:"vault"`
	Grants  []Grant        `yaml:"grants"`
}

type Pool struct {
	MaxOpen     int           `yaml:"max_open"`
	TxLock      string        `yaml:"tx_lock"` // deferred | immediate | exclusive
	BusyTimeout time.Duration `yaml:"busy_timeout"`
}

// VaultConfig splits the vault.Options surface into OPEN-time (runtime) fields
// and the create-only provisioning block, mirroring the API's own split.
type VaultConfig struct {
	Compression  string       `yaml:"compression"` // none | fastest | fast | default | better | best
	Cipher       string       `yaml:"cipher"`      // adiantum | aes-xts
	Key          string       `yaml:"key"`         // secret ref (raw-key mode)
	Identities   []string     `yaml:"identities"`  // secret refs (recipient mode; first match wins)
	WriteAs      string       `yaml:"write_as"`    // secret ref; omit ⇒ read-only at rest
	Masters      []string     `yaml:"masters"`     // trust anchors at open
	Authenticate bool         `yaml:"authenticate"`
	Anchor       *Anchor      `yaml:"anchor"`
	Create       *VaultCreate `yaml:"create"` // honored only when provisioning a new container
}

// Anchor configures the optional rollback-resistance anchor (an external
// monotonic counter). Only the file type is wired; tpm/kms are seams.
type Anchor struct {
	Type string `yaml:"type"` // file | tpm | kms
	Path string `yaml:"path"`
}

// VaultCreate is the create-only provisioning block, honored only when a new
// container is minted: it defines the initial keyslot membership (recipients,
// masters, writers, the signing master) and the on-disk geometry.
type VaultCreate struct {
	Recipients      []string `yaml:"recipients"`
	Masters         []string `yaml:"masters"`
	SignWith        string   `yaml:"sign_with"`
	Writers         []string `yaml:"writers"`
	PageSize        int      `yaml:"page_size"`
	BlockSize       int      `yaml:"block_size"`
	DirSegmentPages int      `yaml:"dir_segment_pages"`
}

type Grant struct {
	Principal string `yaml:"principal"`
	Level     string `yaml:"level"` // none | read-only | read-write | admin
}

type Limits struct {
	MaxRows               int           `yaml:"max_rows"`
	MaxResultBytes        int64         `yaml:"max_result_bytes"`
	MaxRequestBytes       int64         `yaml:"max_request_bytes"`
	StatementTimeout      time.Duration `yaml:"statement_timeout"`
	TxIdleTimeout         time.Duration `yaml:"tx_idle_timeout"`
	MaxTxLifetime         time.Duration `yaml:"max_tx_lifetime"`
	MaxWriteSessionsPerDB int           `yaml:"max_write_sessions_per_db"`
	MaxConcurrentPerDB    int           `yaml:"max_concurrent_per_db"` // admission cap per db (0 = unlimited)
	Rate                  Rate          `yaml:"rate"`
}

// Rate configures per-principal request rate limiting.
type Rate struct {
	PerPrincipalRPS float64 `yaml:"per_principal_rps"` // token-bucket refill rate (0 = unlimited)
}

type Logging struct {
	Format string `yaml:"format"` // json | text
	// ExpandParams opts INTO logging bound-parameter values (expanded SQL). The
	// zero value redacts — params are logged as `?` placeholders — so redaction is
	// the safe default even when the section is omitted.
	ExpandParams  bool          `yaml:"expand_params"`
	SlowThreshold time.Duration `yaml:"slow_threshold"` // >0 enables the slow-query log at this duration
}
