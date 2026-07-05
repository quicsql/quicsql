package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Reserved is the set of server-scoped names that resolve before database
// routing; a user database may not collide with any of them. Every entry (and
// any name with a leading underscore) is off-limits.
var Reserved = map[string]bool{
	"_server":  true,
	"_meta":    true,
	"_admin":   true,
	"_auth":    true,
	"_health":  true,
	"_metrics": true,
}

// EndpointTokens are the leading path segments that name an endpoint rather than
// a database. A user database may not take one of these names (it would be
// unreachable via URL-path routing). The HTTP router uses the same set.
var EndpointTokens = map[string]bool{
	"query":     true,
	"v2":        true,
	"v3":        true,
	"export":    true,
	"backup":    true, // /<db>/backup — streaming online backup (SQLite file)
	"changeset": true, // /<db>/changeset/{apply,invert,concat}
	"blob":      true, // /<db>/blob/{create,write,read,size,delete}
	"changes":   true, // /<db>/changes — the SSE change feed
}

// KnownBackends is the single source of truth for valid `backend:` values,
// consulted by Validate (backend construction switches over the same set).
var KnownBackends = map[string]bool{
	"file": true, "memory": true, "memory-shared": true, "mvcc": true, "memdb": true, "vault": true,
}

// pathBackends are the backends that open an on-disk file addressed by db.Path,
// so their path must be containment-checked (WithinDir). In-memory backends
// ignore Path.
var pathBackends = map[string]bool{"file": true, "vault": true}

// UsesPath reports whether a backend opens an on-disk file addressed by db.Path.
// Single-sourced here so the control-plane create check and the startup reconcile
// agree on which backends need path containment.
func UsesPath(backend string) bool { return pathBackends[backend] }

// ListenerAuthMethods are the method names a listener may accept. `none` admits
// unauthenticated requests as the anonymous principal; the rest each require a
// matching principal credential. KnownAuthMethods drops `none` — it is the set a
// principal may define a credential for.
var (
	ListenerAuthMethods = map[string]bool{
		"none": true, "peercred": true, "bearer": true, "password": true, "mtls": true, "keyring": true, "session": true,
	}
	KnownAuthMethods = map[string]bool{
		"peercred": true, "bearer": true, "password": true, "mtls": true, "keyring": true,
	}
)

// AuthConfigured reports whether the operator has configured any authentication
// or authorization at all — a principal, or a grant on any database. When false,
// the server runs in open mode (every request is an anonymous read-write
// principal), preserving the pre-auth bind-to-localhost behavior; the first
// principal or grant flips enforcement on.
func (c *Config) AuthConfigured() bool {
	return len(c.Auth.Principals) > 0 || AnyGrants(c.Databases)
}

// AnyGrants reports whether any database in the set carries a grant. It is the
// shared predicate behind open-mode detection — the daemon evaluates it over the
// reconciled (config ∪ meta-store) set, config.AuthConfigured over the config
// seeds — so the two agree on what "auth is configured" means.
func AnyGrants(dbs []Database) bool {
	for _, db := range dbs {
		if len(db.Grants) > 0 {
			return true
		}
	}
	return false
}

// ValidDBName reports whether s is a usable database name: a plain identifier
// (ASCII letters, digits, and `-`/`.`/`_`, first char not `_`), non-empty, not
// reserved or an endpoint token, not `.`/`..`. The identifier charset (no path
// separators, quotes, whitespace, or control characters) keeps a name safe to use
// unquoted as a URL segment, a metrics label, and a path component. Used by both
// config validation and the HTTP router (defense in depth), so the two can't
// diverge.
func ValidDBName(s string) bool {
	switch {
	case s == "" || s == "." || s == "..":
		return false
	case strings.HasPrefix(s, "_") || Reserved[s]:
		return false
	case EndpointTokens[s]:
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
		default:
			return false
		}
	}
	return true
}

// WithinDir resolves p against dir and returns the cleaned absolute path if it
// stays within dir; ok=false for an escape (an absolute path outside dir, or a
// `..` traversal) or when dir/p is empty. It is the single guard for every
// operator/meta-store-supplied on-disk path (control-plane create's db.Path,
// snapshot dest, and the startup reconcile of meta-store specs), so a tampered
// store or request can't make the daemon open a file at an arbitrary location.
func WithinDir(dir, p string) (string, bool) {
	if dir == "" || p == "" {
		return "", false
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(dir, abs)
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(dir, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return abs, true
}

// knownTopLevel are the config sections wired into behavior. inertTopLevel are
// sections the plan defines but nothing consumes yet — their presence warns.
var knownTopLevel = map[string]bool{
	"server": true, "secrets": true, "routing": true, "tls": true, "listeners": true,
	"auth": true, "databases": true, "control_plane": true, "limits": true, "logging": true,
	"cors": true, "changefeed": true,
}

var inertTopLevel = map[string]string{
	"wire_compression": "over-the-wire compression (Phase 3.5)",
	"observability":    "metrics / introspection (Phase 7)",
}

// Load reads, parses, defaults, and validates a YAML config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	// A second raw decode flags sections that parse but nothing consumes yet, so
	// a silently-inert block isn't mistaken for a working one.
	var raw map[string]any
	if yaml.Unmarshal(b, &raw) == nil {
		keys := make([]string, 0, len(raw))
		for k := range raw {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch {
			case inertTopLevel[k] != "":
				c.warnings = append(c.warnings, fmt.Sprintf("config: %q is present but not active yet — %s", k, inertTopLevel[k]))
			case !knownTopLevel[k]:
				c.warnings = append(c.warnings, fmt.Sprintf("config: unknown top-level key %q (ignored)", k))
			}
		}
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Server.MetaStore.Backend == "" {
		c.Server.MetaStore.Backend = "vault"
	}
	if c.Server.MetaStore.Path == "" {
		c.Server.MetaStore.Path = "_meta.vault"
	}
	for i := range c.Databases {
		if c.Databases[i].Mode == "" {
			c.Databases[i].Mode = "rwc"
		}
	}
	if c.Auth.Session.Enabled && c.Auth.Session.IdleTTL == 0 {
		c.Auth.Session.IdleTTL = 15 * time.Minute
	}
	if c.Auth.Enroll.Enabled {
		if c.Auth.Enroll.Policy == "" {
			c.Auth.Enroll.Policy = "token" // fail-safe default: open enrollment is opt-in
		}
		if c.Auth.Enroll.MaxPrincipals == 0 {
			c.Auth.Enroll.MaxPrincipals = 1000
		}
		if c.Auth.Enroll.RatePerIP == 0 {
			c.Auth.Enroll.RatePerIP = 0.1
		}
	}
	if c.CORS.Enabled {
		if len(c.CORS.Origins) == 0 {
			c.CORS.Origins = []string{"*"}
		}
		if c.CORS.MaxAge == 0 {
			c.CORS.MaxAge = 2 * time.Hour
		}
	}
	if c.ChangeFeed.Enabled {
		if c.ChangeFeed.Buffer == 0 {
			c.ChangeFeed.Buffer = 1024
		}
		if c.ChangeFeed.MaxSubscribers == 0 {
			c.ChangeFeed.MaxSubscribers = 128
		}
	}
}

// Validate catches the invariants Phase 0 depends on: unique, non-reserved
// database names with a known backend.
func (c *Config) Validate() error {
	switch c.Server.MetaStore.Backend {
	case "", "vault", "file": // "" defaults to vault in applyDefaults
	default:
		return fmt.Errorf("config: meta_store backend %q invalid (want vault|file)", c.Server.MetaStore.Backend)
	}
	seen := map[string]bool{}
	for _, db := range c.Databases {
		if err := ValidateDatabase(db); err != nil {
			return err
		}
		if seen[db.Name] {
			return fmt.Errorf("config: duplicate database name %q", db.Name)
		}
		seen[db.Name] = true
	}
	if err := c.validateTransports(); err != nil {
		return err
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := c.validateCORS(); err != nil {
		return err
	}
	if c.ChangeFeed.Buffer < 0 || c.ChangeFeed.MaxSubscribers < 0 {
		return fmt.Errorf("config: changefeed buffer and max_subscribers must not be negative")
	}
	switch c.Logging.Format {
	case "", "text", "json":
	default:
		return fmt.Errorf("config: logging.format %q invalid (want text|json)", c.Logging.Format)
	}
	return nil
}

// validateCORS checks the cors block: each origin is "*" or a scheme://host[:port]
// origin (no path, no wildcard subdomains — exact match is the only safe compare),
// and max_age is not negative. "null" is rejected outright: sandboxed-iframe and
// file:// pages serialize their origin as the literal string "null", so allowing
// it admits any of them.
func (c *Config) validateCORS() error {
	if !c.CORS.Enabled {
		return nil
	}
	// A wildcard origin echoes Access-Control-Allow-Origin: * on every response,
	// which is only safe when reading the data itself requires a credential the
	// attacker's page can't hold. In open mode (no auth configured) the anonymous
	// principal is read-write, so `*` would let ANY website read and write this
	// server's databases cross-origin. Refuse the combination — the operator must
	// either configure auth or list explicit origins. (applyDefaults turns an
	// empty origins list into ["*"], so this also catches `cors: {enabled: true}`
	// with nothing else.)
	for _, o := range c.CORS.Origins {
		if o == "*" && !c.AuthConfigured() {
			return fmt.Errorf(`config: cors.origins "*" (the default when origins is empty) with no authentication configured would let any website read and write this server — configure auth (a principal or grant) or list explicit origins`)
		}
	}
	for _, o := range c.CORS.Origins {
		if o == "*" {
			continue
		}
		if o == "null" {
			return fmt.Errorf("config: cors.origins may not contain %q (it would match any sandboxed or file:// page)", o)
		}
		rest, ok := strings.CutPrefix(o, "https://")
		if !ok {
			rest, ok = strings.CutPrefix(o, "http://")
		}
		if !ok || rest == "" || strings.ContainsAny(rest, "/ \t*") {
			return fmt.Errorf("config: cors.origins entry %q invalid (want \"*\" or scheme://host[:port], no path)", o)
		}
	}
	if c.CORS.MaxAge < 0 {
		return fmt.Errorf("config: cors.max_age must not be negative")
	}
	return nil
}

// ValidateDatabase checks a single database spec's invariants — the checks a YAML
// seed and a control-plane create must agree on: a valid, non-reserved name, a known
// backend, and valid mode / tx_lock / pragmas_preset / vault vocabulary. It is the
// single per-database validator shared by Config.Validate (seeds), the admin create
// route, and the startup reconcile, so a runtime-created (or meta-persisted) database
// can't bypass a check a seed is held to — e.g. a typo'd mode that backend.accessMode
// would otherwise silently coerce to read-write-create, downgrading a read-only intent.
func ValidateDatabase(db Database) error {
	if db.Name == "" {
		return fmt.Errorf("config: database with empty name")
	}
	// ValidDBName is the SAME predicate the HTTP router enforces, so a config seed
	// and a runtime request agree on what names are usable. It rejects reserved /
	// endpoint names, path separators, and any name that isn't a plain identifier —
	// a name that passes here is reachable over the wire.
	if !ValidDBName(db.Name) {
		return fmt.Errorf("config: database %q has an invalid or reserved name (use letters, digits, and -._; not leading _, not a reserved or endpoint name)", db.Name)
	}
	if db.Backend == "" {
		return fmt.Errorf("config: database %q missing backend", db.Name)
	}
	if !KnownBackends[db.Backend] {
		return fmt.Errorf("config: database %q unknown backend %q", db.Name, db.Backend)
	}
	switch db.Mode {
	case "", "rw", "ro", "rwc":
	default:
		return fmt.Errorf("config: database %q invalid mode %q (want rw|ro|rwc)", db.Name, db.Mode)
	}
	switch db.Pool.TxLock {
	case "", "deferred", "immediate", "exclusive":
	default:
		return fmt.Errorf("config: database %q invalid tx_lock %q (want deferred|immediate|exclusive)", db.Name, db.Pool.TxLock)
	}
	switch db.PragmasPreset {
	case "", "recommended":
	default:
		return fmt.Errorf("config: database %q invalid pragmas_preset %q (want recommended)", db.Name, db.PragmasPreset)
	}
	return validateVault(db)
}

// grantLevels is the set of valid `grants[].level` strings, kept beside the other
// config vocabularies; package authz compiles the same strings into its Level.
var grantLevels = map[string]bool{"none": true, "read-only": true, "read-write": true, "admin": true}

var (
	vaultCompression = map[string]bool{"": true, "none": true, "fastest": true, "fast": true, "default": true, "better": true, "best": true}
	vaultCiphers     = map[string]bool{"": true, "adiantum": true, "aes-xts": true}
	vaultAnchors     = map[string]bool{"": true, "file": true, "tpm": true, "kms": true}
)

// validateVault checks a database's vault block: the compression/cipher/anchor
// vocabularies, that raw-key and recipient modes aren't mixed, and that a vault
// block isn't attached to a non-vault backend. Secret resolution and the
// create-vs-open decision happen later in package backend.
func validateVault(db Database) error {
	if db.Vault == nil {
		return nil
	}
	if db.Backend != "vault" {
		return fmt.Errorf("config: database %q has a vault block but backend is %q", db.Name, db.Backend)
	}
	vc := db.Vault
	if !vaultCompression[vc.Compression] {
		return fmt.Errorf("config: database %q invalid vault.compression %q", db.Name, vc.Compression)
	}
	if !vaultCiphers[vc.Cipher] {
		return fmt.Errorf("config: database %q invalid vault.cipher %q (want adiantum|aes-xts)", db.Name, vc.Cipher)
	}
	if vc.Anchor != nil && !vaultAnchors[vc.Anchor.Type] {
		return fmt.Errorf("config: database %q invalid vault.anchor.type %q", db.Name, vc.Anchor.Type)
	}
	if vc.Key != "" && len(vc.Identities) > 0 {
		return fmt.Errorf("config: database %q vault sets both key (raw-key mode) and identities (recipient mode)", db.Name)
	}
	return nil
}

// validateAuth checks the principal/capability wiring: known listener methods
// (with transport constraints), unique named principals with known credential
// methods, and grants that name a real principal (or the wildcard) with a valid
// level. Deep credential-parameter checks (parsing a key, resolving a secret)
// happen in package auth at load; here we catch the structural mistakes.
func (c *Config) validateAuth() error {
	for _, lc := range c.Listeners {
		for _, m := range lc.Auth {
			if !ListenerAuthMethods[m] {
				return fmt.Errorf("config: listener %q unknown auth method %q", lc.Name, m)
			}
			if m == "peercred" && lc.Transport != "unix" {
				return fmt.Errorf("config: listener %q: peercred auth is only valid on a unix socket", lc.Name)
			}
			if m == "mtls" && lc.TLS == "" {
				return fmt.Errorf("config: listener %q: mtls auth requires a tls profile (with client_ca)", lc.Name)
			}
			if m == "session" && !c.Auth.Session.Enabled {
				return fmt.Errorf("config: listener %q accepts session auth but auth.session.enabled is false", lc.Name)
			}
		}
	}
	if c.Auth.Session.IdleTTL < 0 || c.Auth.Session.MaxTTL < 0 {
		return fmt.Errorf("config: auth.session idle_ttl and max_ttl must not be negative")
	}
	if c.Auth.Session.MaxTTL > 0 && c.Auth.Session.MaxTTL < c.Auth.Session.IdleTTL {
		return fmt.Errorf("config: auth.session.max_ttl (%s) must be ≥ idle_ttl (%s)", c.Auth.Session.MaxTTL, c.Auth.Session.IdleTTL)
	}
	if c.Auth.Session.Enabled && c.Auth.Session.IdleTTL > 24*time.Hour {
		c.warnings = append(c.warnings, "config: auth.session.idle_ttl exceeds 24h — the idle window is meant to be short (use max_ttl for a long-lived sliding session); prefer minutes to hours")
	}
	if err := c.validateEnroll(); err != nil {
		return err
	}

	principals := map[string]bool{}
	for _, p := range c.Auth.Principals {
		if p.Name == "" {
			return fmt.Errorf("config: auth principal with empty name")
		}
		if principals[p.Name] {
			return fmt.Errorf("config: duplicate auth principal %q", p.Name)
		}
		principals[p.Name] = true
		for _, method := range p.Methods {
			if len(method) != 1 {
				return fmt.Errorf("config: principal %q: each method entry needs exactly one method name", p.Name)
			}
			for name := range method {
				if !KnownAuthMethods[name] {
					return fmt.Errorf("config: principal %q: unknown credential method %q", p.Name, name)
				}
			}
		}
	}

	for _, db := range c.Databases {
		for _, g := range db.Grants {
			if !grantLevels[g.Level] {
				return fmt.Errorf("config: database %q grant has invalid level %q", db.Name, g.Level)
			}
			if g.Principal != "*" && !principals[g.Principal] {
				return fmt.Errorf("config: database %q grants to unknown principal %q", db.Name, g.Principal)
			}
		}
	}
	if c.ControlPlane.Enabled && len(c.ControlPlane.Admins) == 0 {
		// The control plane's capabilities are too powerful to expose without a
		// named admin — refuse to enable it wide open (there is no open-mode
		// fallback for /_admin).
		return fmt.Errorf("config: control_plane.enabled requires at least one control_plane.admins entry")
	}
	for _, a := range c.ControlPlane.Admins {
		if !principals[a] {
			return fmt.Errorf("config: control_plane admin %q is not a configured principal", a)
		}
	}
	return nil
}

// validateEnroll checks the auth.enroll block. Enrollment is refused outright on
// a server without explicit auth or without the control plane: the first dynamic
// principal must never flip an open server into enforcement mid-flight, and an
// enrolled set with no /_admin oversight (and no meta store to live in) would be
// unmanageable by construction.
func (c *Config) validateEnroll() error {
	e := c.Auth.Enroll
	if !e.Enabled {
		return nil
	}
	if !c.AuthConfigured() {
		return fmt.Errorf("config: auth.enroll.enabled requires explicit auth (at least one principal or grant) — enrollment must not flip an open-mode server")
	}
	if !c.ControlPlane.Enabled {
		return fmt.Errorf("config: auth.enroll.enabled requires control_plane.enabled (the meta store holds the enrolled set; /_admin/principals manages it)")
	}
	switch e.Policy {
	case "open", "token":
	default:
		return fmt.Errorf("config: auth.enroll.policy %q invalid (want open|token)", e.Policy)
	}
	if e.Policy == "token" && len(e.Tokens) == 0 {
		return fmt.Errorf("config: auth.enroll.policy token requires at least one auth.enroll.tokens entry")
	}
	if e.MaxPrincipals < 0 || e.RatePerIP < 0 {
		return fmt.Errorf("config: auth.enroll quotas must not be negative")
	}
	if len(e.Grants) == 0 {
		c.warnings = append(c.warnings, "config: auth.enroll.grants is empty — enrolled principals will authenticate but hold no access")
	}
	for _, g := range e.Grants {
		if !ValidDBName(g.DB) {
			return fmt.Errorf("config: auth.enroll.grants names invalid database %q", g.DB)
		}
		if g.Level != "read-only" && g.Level != "read-write" {
			return fmt.Errorf("config: auth.enroll.grants level %q invalid (want read-only|read-write — never admin for self-enrolled principals)", g.Level)
		}
	}
	return nil
}

// transportFamily is the socket family a transport binds — the axis a bind
// conflict is scoped to. h1/h2/h2c are TCP, h3 is UDP (QUIC), unix is a socket
// path; a TCP and a UDP listener may share a port number, same-family ones can't.
func transportFamily(transport string) string {
	switch transport {
	case "h3":
		return "udp"
	case "unix":
		return "unix"
	default:
		return "tcp"
	}
}

// validateTransports fails fast on listener/TLS wiring errors at load rather than
// deferring them to server startup.
func (c *Config) validateTransports() error {
	// Track the (protocol-family, address) each listener binds so two can't clash.
	// h1/h2/h2c bind TCP, h3 binds UDP, unix binds a socket path — so h2 (TCP) and
	// h3 (UDP) may SHARE a port (as :443 does), but two TCP listeners on one address
	// (or two h3, or two unix on one path) would collide at bind time.
	bound := map[string]string{} // "family\x00address" → listener name
	for _, lc := range c.Listeners {
		switch lc.Transport {
		case "h1", "h2", "h2c", "h3", "unix":
		case "":
			return fmt.Errorf("config: listener %q missing transport", lc.Name)
		default:
			return fmt.Errorf("config: listener %q unknown transport %q", lc.Name, lc.Transport)
		}
		if (lc.Transport == "h2" || lc.Transport == "h3") && lc.TLS == "" {
			return fmt.Errorf("config: listener %q (%s) requires a tls profile", lc.Name, lc.Transport)
		}
		if lc.TLS != "" {
			if _, ok := c.TLS[lc.TLS]; !ok {
				return fmt.Errorf("config: listener %q references unknown tls profile %q", lc.Name, lc.TLS)
			}
		}
		if lc.Advertise && lc.Transport != "h3" {
			return fmt.Errorf("config: listener %q: advertise is only valid on an h3 listener", lc.Name)
		}
		if lc.Address != "" {
			key := transportFamily(lc.Transport) + "\x00" + lc.Address
			if other, dup := bound[key]; dup {
				return fmt.Errorf("config: listeners %q and %q both bind %s %q (h2/h3 may share a port, but same-family listeners may not)", other, lc.Name, transportFamily(lc.Transport), lc.Address)
			}
			bound[key] = lc.Name
		}
	}
	for name, p := range c.TLS {
		switch p.Mode {
		case "self_signed":
		case "qip":
			if !validQIPZone(p.Subdomain) {
				return fmt.Errorf("config: tls profile %q qip subdomain %q must be a DNS zone name (letters, digits, '.', '-')", name, p.Subdomain)
			}
		case "files":
			if p.Cert == "" || p.Key == "" {
				return fmt.Errorf("config: tls profile %q (files) needs cert and key", name)
			}
		case "":
			return fmt.Errorf("config: tls profile %q missing mode (files|self_signed)", name)
		default:
			return fmt.Errorf("config: tls profile %q unknown mode %q", name, p.Mode)
		}
		switch p.MinVersion {
		case "", "1.2", "1.3":
		default:
			return fmt.Errorf("config: tls profile %q invalid min_version %q (want 1.2 or 1.3)", name, p.MinVersion)
		}
	}
	return nil
}

// validQIPZone reports whether a qip subdomain is a safe DNS zone name. Empty is OK
// (it defaults to i.qip.sh); otherwise only DNS-label characters are allowed, so a
// stray path segment or URL can't be spliced into the qip.sh cert-fetch URL.
func validQIPZone(zone string) bool {
	if zone == "" {
		return true
	}
	for _, r := range zone {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}
