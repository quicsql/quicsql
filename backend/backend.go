// Package backend maps a configured database to a concrete open: each backend
// knows how to build a sqlite.Config (and, for vault, vault.Options) and open
// the single shared handle the registry fans clients through.
package backend

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gosqlite.org"
	"gosqlite.org/server/config"
	"gosqlite.org/server/secret"
)

// Backend opens exactly one *sqlite.DB for a logical database. Open is called
// once per process by the registry; a single Close on the returned handle tears
// down the pool and any VFS the open registered.
type Backend interface {
	Open(ctx context.Context) (*sqlite.DB, error)
	Kind() string
	ReadOnly() bool
}

// For selects and constructs the backend for one database entry.
func For(db config.Database, sec secret.Resolver, dataDir string) (Backend, error) {
	switch db.Backend {
	case "file", "":
		return &fileBackend{cfg: baseConfig(db, dataDir), ro: db.Mode == "ro"}, nil
	case "memory":
		return &memoryBackend{name: db.Name, shared: false}, nil
	case "memory-shared":
		return &memoryBackend{name: db.Name, shared: true}, nil
	case "vault":
		return newVault(db, sec, dataDir)
	case "mvcc", "memdb":
		// Registered-VFS in-memory modes — wired in Phase 5.
		return nil, fmt.Errorf("backend: %q not wired until Phase 5", db.Backend)
	default:
		return nil, fmt.Errorf("backend: unknown backend %q", db.Backend)
	}
}

// All builds the name→Backend map for the whole config.
func All(cfg *config.Config, sec secret.Resolver) (map[string]Backend, error) {
	m := make(map[string]Backend, len(cfg.Databases))
	for _, db := range cfg.Databases {
		be, err := For(db, sec, cfg.Server.DataDir)
		if err != nil {
			return nil, fmt.Errorf("backend: database %q: %w", db.Name, err)
		}
		m[db.Name] = be
	}
	return m, nil
}

// baseConfig renders the sqlite.Config shared by the file and vault backends.
func baseConfig(db config.Database, dataDir string) sqlite.Config {
	cfg := sqlite.Config{
		Path:         resolvePath(db.Path, dataDir),
		Mode:         accessMode(db.Mode),
		MaxOpenConns: db.Pool.MaxOpen,
		TxLock:       db.Pool.TxLock,
		Pragmas:      pragmas(db),
	}
	return cfg
}

func resolvePath(path, dataDir string) string {
	if path == "" || filepath.IsAbs(path) || dataDir == "" {
		return path
	}
	return filepath.Join(dataDir, path)
}

func accessMode(mode string) sqlite.AccessMode {
	switch mode {
	case "ro":
		return sqlite.ModeReadOnly
	case "rw":
		return sqlite.ModeReadWrite
	default:
		return sqlite.ModeReadWriteCreate
	}
}

// pragmas maps the pool busy-timeout and the free-form pragmas map onto
// sqlite.Pragmas. Known keys MUST land in their typed fields, not Extra: vault's
// Open inspects the typed Pragmas.JournalMode to opt into WAL and to order
// page_size/auto_vacuum/journal_mode correctly — a journal_mode dropped into
// Extra would both miss vault's WAL path and lock the wrong page size. Unknown
// keys fall through to Extra.
func pragmas(db config.Database) sqlite.Pragmas {
	p := sqlite.Pragmas{}
	if db.Pool.BusyTimeout > 0 {
		p.BusyTimeout = db.Pool.BusyTimeout
	}
	for k, v := range db.Pragmas {
		s := fmt.Sprint(v)
		switch k {
		case "journal_mode":
			p.JournalMode = sqlite.JournalMode(strings.ToUpper(s))
		case "synchronous":
			p.Synchronous = sqlite.Synchronous(strings.ToUpper(s))
		case "auto_vacuum":
			p.AutoVacuum = sqlite.AutoVacuumMode(strings.ToUpper(s))
		case "temp_store":
			p.TempStore = sqlite.TempStore(strings.ToUpper(s))
		case "foreign_keys":
			p.ForeignKeys = truthy(s)
		case "cache_size":
			if n, err := strconv.Atoi(s); err == nil {
				p.CacheSize = n
			}
		case "busy_timeout":
			if ms, err := strconv.Atoi(s); err == nil {
				p.BusyTimeout = time.Duration(ms) * time.Millisecond
			}
		default:
			if p.Extra == nil {
				p.Extra = map[string]string{}
			}
			p.Extra[k] = s
		}
	}
	return p
}

func truthy(s string) bool {
	switch strings.ToLower(s) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}
