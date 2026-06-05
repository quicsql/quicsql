package config

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Reserved is the set of server-scoped names that resolve before database
// routing; a user database may not collide with any of them. Every entry (and
// any name with a leading underscore) is off-limits.
var Reserved = map[string]bool{
	"_server":  true,
	"_meta":    true,
	"_admin":   true,
	"_health":  true,
	"_metrics": true,
}

// EndpointTokens are the leading path segments that name an endpoint rather than
// a database. A user database may not take one of these names (it would be
// unreachable via URL-path routing). The HTTP router uses the same set.
var EndpointTokens = map[string]bool{
	"query": true,
	"v2":    true,
	"v3":    true,
}

// KnownBackends is the single source of truth for valid `backend:` values,
// consulted by Validate (backend construction switches over the same set).
var KnownBackends = map[string]bool{
	"file": true, "memory": true, "memory-shared": true, "mvcc": true, "memdb": true, "vault": true,
}

// ValidDBName reports whether s is a usable database name: non-empty, not
// reserved or an endpoint token, not path-shaped. Used by both config
// validation and the HTTP router (defense in depth), so the two can't diverge.
func ValidDBName(s string) bool {
	switch {
	case s == "" || s == "." || s == "..":
		return false
	case strings.HasPrefix(s, "_") || Reserved[s]:
		return false
	case EndpointTokens[s]:
		return false
	case strings.ContainsAny(s, `/\`):
		return false
	default:
		return true
	}
}

// knownTopLevel are the config sections wired into behavior. inertTopLevel are
// sections the plan defines but nothing consumes yet — their presence warns.
var knownTopLevel = map[string]bool{
	"server": true, "secrets": true, "routing": true, "tls": true, "listeners": true,
	"auth": true, "databases": true, "limits": true, "logging": true,
}

var inertTopLevel = map[string]string{
	"control_plane":    "runtime control plane (Phase 6)",
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
		if db.Name == "" {
			return fmt.Errorf("config: database with empty name")
		}
		if strings.HasPrefix(db.Name, "_") || Reserved[db.Name] {
			return fmt.Errorf("config: database %q uses a reserved name", db.Name)
		}
		if EndpointTokens[db.Name] {
			return fmt.Errorf("config: database %q collides with a reserved endpoint name", db.Name)
		}
		if strings.ContainsAny(db.Name, `/\`) {
			return fmt.Errorf("config: database %q must not contain a path separator", db.Name)
		}
		if seen[db.Name] {
			return fmt.Errorf("config: duplicate database name %q", db.Name)
		}
		seen[db.Name] = true
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
	}
	if err := c.validateTransports(); err != nil {
		return err
	}
	return nil
}

// validateTransports fails fast on listener/TLS wiring errors at load rather than
// deferring them to server startup.
func (c *Config) validateTransports() error {
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
	}
	for name, p := range c.TLS {
		switch p.Mode {
		case "self_signed", "qip":
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
