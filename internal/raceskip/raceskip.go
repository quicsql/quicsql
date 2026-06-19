// Package raceskip exposes a single Enabled bool constant whose value reflects
// whether the build was produced with -race. Tests use it to skip cases that
// touch modernc-transpiled native C paths Go's checkptr analyzer rejects (tight
// pointer arithmetic on transpiled C) — the BLOB API, VFS handles, SESSION and
// Serialize. It mirrors gosqlite's own internal raceskip: quicSQL is a separate
// module and cannot import gosqlite's internal packages, so it keeps its own.
package raceskip
