package engine

import (
	"errors"

	"gosqlite.org"
	"quicsql.net/internal/wire"
)

// Error is the typed server error, carrying SQLite's primary and extended
// result codes so each protocol layer can map them (Hrana error, native JSON
// error) without re-parsing message strings.
type Error struct {
	Code     int // primary SQLite result code
	Extended int // extended result code
	Msg      string
}

func (e *Error) Error() string { return e.Msg }

// sqliteAuth is SQLITE_AUTH — the code SQLite returns when an authorizer denies a
// statement at compile time.
const sqliteAuth = 23

// IsNotAuthorized reports whether err is a statement rejected by the connection
// authorizer (SQLITE_AUTH) — a read-only principal attempting a write, or an
// ATTACH/DETACH buried in a script. Callers map it to a policy denial (403)
// rather than a plain SQL error envelope.
func IsNotAuthorized(err error) bool {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code == sqliteAuth
	}
	return false
}

// ExtendedCodeName maps an extended SQLite result code to its symbolic name for
// the Hrana error `code` field, preserving the constraint subtype (UNIQUE vs
// FOREIGNKEY vs NOTNULL vs CHECK) that the primary code alone collapses to a bare
// SQLITE_CONSTRAINT. The table lives in package wire so the client's inverse lookup
// (wire.CodeForName) can't drift from it.
func ExtendedCodeName(extended int) string { return wire.ExtendedCodeName(extended) }

// CodeName maps a primary SQLite result code to its symbolic name (single-sourced
// in package wire); unknown codes fall back to SQLITE_ERROR.
func CodeName(primary int) string { return wire.CodeName(primary) }

// wrap converts a driver error into an *Error when it carries SQLite codes,
// leaving other errors (context cancel, io) untouched.
func wrap(err error) error {
	if err == nil {
		return nil
	}
	if se, ok := errors.AsType[*sqlite.Error](err); ok {
		return &Error{Code: se.Code(), Extended: se.ExtendedCode(), Msg: se.Error()}
	}
	return err
}
