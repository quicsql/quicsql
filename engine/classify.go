package engine

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrDenied marks a statement rejected by server policy (not a SQL error).
var ErrDenied = errors.New("statement not permitted by server policy")

// Run picks Query for a row-returning statement and Exec otherwise, so a caller
// with a single statement of unknown shape gets rows for reads (and for
// `... RETURNING ...`) and affected/last-insert for plain writes. It first
// denies ATTACH/DETACH — those reach the host filesystem and bypass the registry
// / single-owner vault invariant. This is the interim default-deny ahead of the
// full per-principal authorizer (Phase 4).
//
// The read/write split is a Phase-1 heuristic: the leading keyword plus a
// RETURNING probe. It is cheap and covers the thin native endpoint; the Hrana
// path (Phase 2) uses the driver's (*Stmt).Readonly instead. A misclassified
// writing-CTE without RETURNING still EXECUTES correctly (QueryContext runs it);
// only its rows_affected metadata goes unreported.
func (e *Engine) Run(ctx context.Context, q Queryer, s Statement) (*Result, error) {
	switch strings.ToUpper(firstToken(s.SQL)) {
	case "ATTACH", "DETACH":
		return nil, fmt.Errorf("%w: ATTACH/DETACH is disabled", ErrDenied)
	}
	if isReadOnly(s.SQL) || hasReturning(s.SQL) {
		return e.Query(ctx, q, s)
	}
	return e.Exec(ctx, q, s)
}

func isReadOnly(sql string) bool {
	switch strings.ToUpper(firstToken(sql)) {
	case "SELECT", "WITH", "EXPLAIN", "VALUES", "PRAGMA":
		return true
	default:
		return false
	}
}

var returningRe = regexp.MustCompile(`(?i)\bRETURNING\b`)

// hasReturning reports whether the statement has a RETURNING clause, so an
// INSERT/UPDATE/DELETE … RETURNING routes through Query and its rows survive.
// A false positive from the word appearing inside a string literal only costs
// rows_affected metadata (Query still executes the write) — data-safe.
func hasReturning(sql string) bool { return returningRe.MatchString(sql) }

// bom is the UTF-8 byte-order mark (U+FEFF) some clients prepend; written as
// bytes so no literal BOM appears in this source file.
const bom = "\xef\xbb\xbf"

// firstToken returns the leading keyword, after skipping a UTF-8 BOM and any
// leading whitespace and `--`/`/* */` comments — so a commented or BOM-prefixed
// SELECT is not misread as a write. It stops at whitespace or '(' so "SELECT("
// and "select 1" both yield the keyword.
func firstToken(sql string) string {
	sql = strings.TrimPrefix(sql, bom)
	for {
		sql = strings.TrimLeft(sql, " \t\r\n\f")
		switch {
		case strings.HasPrefix(sql, "--"):
			if i := strings.IndexByte(sql, '\n'); i >= 0 {
				sql = sql[i+1:]
			} else {
				sql = ""
			}
		case strings.HasPrefix(sql, "/*"):
			if i := strings.Index(sql, "*/"); i >= 0 {
				sql = sql[i+2:]
			} else {
				sql = ""
			}
		default:
			i := 0
			for i < len(sql) {
				c := sql[i]
				if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '(' {
					break
				}
				i++
			}
			return sql[:i]
		}
	}
}
