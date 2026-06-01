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
