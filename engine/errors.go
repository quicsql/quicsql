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
	var se *sqlite.Error
	if errors.As(err, &se) {
		return &Error{Code: se.Code(), Extended: se.ExtendedCode(), Msg: se.Error()}
	}
	return err
}
