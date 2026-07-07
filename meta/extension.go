package meta

import (
	"sync"

	"gosqlite.org"
)

// Optional feature modules (compiled into a product binary, not core `cmd/quicsql`)
// keep their OWN tables in the meta store — a feature module's own tables, separate
// from the core ones. They register idempotent DDL with RegisterMigration
// (CREATE TABLE IF NOT EXISTS …) from an init(); Open applies it right after the core
// schema, on the SAME connection.
//
// Vault safety: that connection is the backend handle opened by Open (a `*sqlite.DB`
// already fronted by the vault encrypt+compress VFS when server.meta_store.backend is
// "vault"). Feature migrations and queries MUST run on this shared handle — via
// RegisterMigration and Store.DB — never on a second connection opened straight to the
// file, which would read encrypted/compressed bytes as if they were plaintext. Because
// it is one connection, access is serialized exactly as the core meta methods already
// are (feature code shared this handle even before the split).

var (
	migrationMu sync.Mutex
	migrations  []string
)

// RegisterMigration adds idempotent DDL applied to the meta store at Open, after the
// core schema. Call it from a feature package's init(); a product binary compiles the
// feature in with a blank import. Core registers none.
func RegisterMigration(ddl string) {
	migrationMu.Lock()
	defer migrationMu.Unlock()
	migrations = append(migrations, ddl)
}

func registeredMigrations() []string {
	migrationMu.Lock()
	defer migrationMu.Unlock()
	return append([]string(nil), migrations...)
}

// DB returns the meta store's open connection — the SAME vault-backed handle Open
// created. A feature module runs its own tables' queries on this handle so encryption
// and compression stay transparent; it must NOT Close it (Store.Close owns that) or
// open a second connection to the meta file.
func (s *Store) DB() *sqlite.DB { return s.db }
