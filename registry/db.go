package registry

import "gosqlite.org"

// DB is one open, shared database handle plus its metadata. Handle is the
// process-wide singleton pool that every client session fans through; a single
// Close (driven by the registry) tears it down.
type DB struct {
	Name     string
	Kind     string // file | memory | memory-shared | mvcc | memdb | vault
	ReadOnly bool
	Handle   *sqlite.DB
}

// DBInfo is a point-in-time snapshot for the _server introspection interface.
type DBInfo struct {
	Name string
	Kind string
	Open bool
	Refs int
}
