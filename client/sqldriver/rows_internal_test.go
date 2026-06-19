package sqldriver

import (
	"database/sql/driver"
	"errors"
	"io"
	"testing"

	"quicsql.net/client"
)

// TestRowsNextTruncated locks in the H5 fix: when the server capped the result
// set, the driver surfaces errTruncated (via rows.Err) instead of a plain io.EOF,
// so a caller iterating the rows can't mistake a partial answer for a complete
// one. A non-truncated result still ends with io.EOF.
func TestRowsNextTruncated(t *testing.T) {
	dest := make([]driver.Value, 1)

	truncated := &rows{res: &client.Result{Columns: []string{"x"}, Rows: [][]any{{int64(1)}}, Truncated: true}}
	if err := truncated.Next(dest); err != nil {
		t.Fatalf("first row: %v", err)
	}
	if err := truncated.Next(dest); !errors.Is(err, errTruncated) {
		t.Fatalf("exhausted truncated rows: err = %v, want errTruncated", err)
	}

	complete := &rows{res: &client.Result{Columns: []string{"x"}, Rows: [][]any{{int64(1)}}}}
	if err := complete.Next(dest); err != nil {
		t.Fatalf("first row: %v", err)
	}
	if err := complete.Next(dest); !errors.Is(err, io.EOF) {
		t.Fatalf("exhausted complete rows: err = %v, want io.EOF", err)
	}
}
