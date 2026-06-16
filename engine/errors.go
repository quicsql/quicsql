package engine

import (
	"errors"

	"gosqlite.org"
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
// SQLITE_CONSTRAINT. A client (e.g. an ORM error-mapper) needs the subtype to
// classify a violation, so the tx path must carry it. Codes outside the
// semantically-meaningful set fall back to the primary code's name.
func ExtendedCodeName(extended int) string {
	switch extended {
	case 2067:
		return "SQLITE_CONSTRAINT_UNIQUE"
	case 1555:
		return "SQLITE_CONSTRAINT_PRIMARYKEY"
	case 787:
		return "SQLITE_CONSTRAINT_FOREIGNKEY"
	case 1299:
		return "SQLITE_CONSTRAINT_NOTNULL"
	case 275:
		return "SQLITE_CONSTRAINT_CHECK"
	}
	return CodeName(extended & 0xff)
}

// CodeName maps a primary SQLite result code to its symbolic name, for the Hrana
// error `code` field (clients match on e.g. SQLITE_CONSTRAINT). Unknown codes
// fall back to SQLITE_ERROR.
func CodeName(primary int) string {
	switch primary {
	case 1:
		return "SQLITE_ERROR"
	case 5:
		return "SQLITE_BUSY"
	case 6:
		return "SQLITE_LOCKED"
	case 8:
		return "SQLITE_READONLY"
	case 9:
		return "SQLITE_INTERRUPT"
	case 11:
		return "SQLITE_CORRUPT"
	case 19:
		return "SQLITE_CONSTRAINT"
	case 20:
		return "SQLITE_MISMATCH"
	case 23:
		return "SQLITE_AUTH"
	default:
		return "SQLITE_ERROR"
	}
}

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
