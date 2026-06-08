// Package backend maps a configured database to a concrete open: each backend
// knows how to build a sqlite.Config (and, for vault, vault.Options) and open
// the single shared handle the registry fans clients through.
package backend

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gosqlite.org"
	"gosqlite.org/server/config"
	"gosqlite.org/server/secret"
)

// securityOnce guards the process-global authorizer registration.
var securityOnce sync.Once

// installSecurity registers a connection authorizer that denies ATTACH/DETACH on
// every connection the driver opens. Unlike a leading-keyword check it fires at
// statement-compile time, so it also catches ATTACH buried inside a
// multi-statement `sequence`/script — closing the filesystem-escape the keyword
// guard alone misses. Interim default-deny ahead of the Phase-4 per-principal
// authorizer; ATTACH/DETACH are never needed by the server itself.
func installSecurity() {
	securityOnce.Do(func() {
		sqlite.RegisterAutoHook(func(c *sqlite.Conn) error {
			c.RegisterAuthorizer(denyAttachDetach)
			return nil
		})
	})
}

func denyAttachDetach(op int, _, _, _, _ string) int {
	switch op {
	case sqlite.SQLITE_ATTACH, sqlite.SQLITE_DETACH:
		return sqlite.SQLITE_DENY
	default:
		return sqlite.SQLITE_OK
	}
}

// writeActions are the authorizer action codes for statements that modify the
// database. A read-only principal's connection denies these at statement-compile
// time — the enforcement layer that catches a write buried in a multi-statement
// script (which a leading-keyword classifier misses), exactly as the ATTACH deny
// does. Read/select/function/transaction/savepoint/pragma/recursive are absent,
// so ordinary reads still compile.
var writeActions = map[int]bool{
	sqlite.SQLITE_INSERT: true, sqlite.SQLITE_UPDATE: true, sqlite.SQLITE_DELETE: true,
	sqlite.SQLITE_CREATE_INDEX: true, sqlite.SQLITE_CREATE_TABLE: true, sqlite.SQLITE_CREATE_TRIGGER: true,
	sqlite.SQLITE_CREATE_VIEW: true, sqlite.SQLITE_CREATE_VTABLE: true,
	sqlite.SQLITE_CREATE_TEMP_INDEX: true, sqlite.SQLITE_CREATE_TEMP_TABLE: true,
	sqlite.SQLITE_CREATE_TEMP_TRIGGER: true, sqlite.SQLITE_CREATE_TEMP_VIEW: true,
	sqlite.SQLITE_DROP_INDEX: true, sqlite.SQLITE_DROP_TABLE: true, sqlite.SQLITE_DROP_TRIGGER: true,
	sqlite.SQLITE_DROP_VIEW: true, sqlite.SQLITE_DROP_VTABLE: true,
	sqlite.SQLITE_DROP_TEMP_INDEX: true, sqlite.SQLITE_DROP_TEMP_TABLE: true,
	sqlite.SQLITE_DROP_TEMP_TRIGGER: true, sqlite.SQLITE_DROP_TEMP_VIEW: true,
	sqlite.SQLITE_ALTER_TABLE: true, sqlite.SQLITE_REINDEX: true, sqlite.SQLITE_ANALYZE: true,
}

// denyWrites is the read-only authorizer: it denies ATTACH/DETACH (like the base
// authorizer) and every write action, so a read-only connection rejects writes
// at compile time with SQLITE_AUTH.
func denyWrites(op int, _, _, _, _ string) int {
	switch {
	case op == sqlite.SQLITE_ATTACH || op == sqlite.SQLITE_DETACH:
		return sqlite.SQLITE_DENY
	case writeActions[op]:
		return sqlite.SQLITE_DENY
	default:
		return sqlite.SQLITE_OK
	}
}

// SetConnMode puts the sqlite connection underlying sc into read-only mode (or
// restores the base mode). It is the connection-level layer of read-only
// enforcement, beneath the capability check in the handler; the caller MUST
// restore the base mode (SetConnMode(ctx, sc, false)) before the connection
// returns to the pool, or a later borrower would inherit read-only state.
//
// Two mechanisms, together comprehensive: the denyWrites authorizer rejects
// DML/DDL at statement-compile time (a clean SQLITE_AUTH, so a write hidden in a
// multi-statement script is caught), and PRAGMA query_only blocks every write to
// the database file at run time — including a header-writing PRAGMA like
// user_version that the action-code authorizer never sees — so enforcement does
// not depend on enumerating every write action.
func SetConnMode(ctx context.Context, sc *sql.Conn, readOnly bool) error {
	if err := sc.Raw(func(dc any) error {
		c, ok := dc.(*sqlite.Conn)
		if !ok {
			return fmt.Errorf("backend: connection is not a *sqlite.Conn (%T)", dc)
		}
		if readOnly {
			c.RegisterAuthorizer(denyWrites)
		} else {
			c.RegisterAuthorizer(denyAttachDetach)
		}
		return nil
	}); err != nil {
		return err
	}
	pragma := "PRAGMA query_only = OFF"
	if readOnly {
		pragma = "PRAGMA query_only = ON"
	}
	_, err := sc.ExecContext(ctx, pragma)
	return err
}

// Backend opens exactly one *sqlite.DB for a logical database. Open is called
// once per process by the registry; a single Close on the returned handle tears
// down the pool and any VFS the open registered.
//
// ctx is reserved: the upstream sqlite/vault Open calls are context-free, so it
// cannot cancel the open itself today — the registry uses ctx to bound the wait
// for a concurrent open (see registry.Get). It stays in the signature for a
// future context-aware upstream open.
type Backend interface {
	Open(ctx context.Context) (*sqlite.DB, error)
	Kind() string
	ReadOnly() bool
}

// For selects and constructs the backend for one database entry.
func For(db config.Database, sec secret.Resolver, dataDir string) (Backend, error) {
	installSecurity() // register the ATTACH/DETACH deny before any connection opens
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
	// pool.busy_timeout is the typed, authoritative surface: it wins over a
	// busy_timeout in the free-form pragmas map (avoids a silent unit-mismatched
	// override between the two config surfaces).
	if db.Pool.BusyTimeout > 0 {
		p.BusyTimeout = db.Pool.BusyTimeout
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
