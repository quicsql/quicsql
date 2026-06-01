package config

import (
	"fmt"
	"os"
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
	seen := map[string]bool{}
	for _, db := range c.Databases {
		if db.Name == "" {
			return fmt.Errorf("config: database with empty name")
		}
		if strings.HasPrefix(db.Name, "_") || Reserved[db.Name] {
			return fmt.Errorf("config: database %q uses a reserved name", db.Name)
		}
		if seen[db.Name] {
			return fmt.Errorf("config: duplicate database name %q", db.Name)
		}
		seen[db.Name] = true
		switch db.Backend {
		case "file", "memory", "memory-shared", "mvcc", "memdb", "vault":
		case "":
			return fmt.Errorf("config: database %q missing backend", db.Name)
		default:
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
	return nil
}
