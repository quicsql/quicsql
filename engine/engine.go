// Package engine runs statements against a database handle and encodes results
// into the transport-agnostic Value/Result shape shared by every protocol. It
// is deliberately conn-source-neutral: Query/Exec take a Queryer satisfied by a
// pooled *sql.Conn, a session-pinned conn, or the *sql.DB pool itself, so the
// same code serves autocommit and interactive-transaction paths.
package engine

import (
	"context"
	"database/sql"
	"fmt"
)

// DefaultMaxRows and DefaultMaxResultBytes bound a single result so a large
// SELECT can't OOM the process. A zero/negative configured limit falls back to
// these — a network-exposed result set is never unbounded.
const (
	DefaultMaxRows        = 100_000
	DefaultMaxResultBytes = 64 << 20
)

// BatchError wraps the error from a failing batch statement with its index, so
// the caller can tell the client which statement rolled the batch back.
type BatchError struct {
	Index int
	Err   error
}

func (e *BatchError) Error() string { return fmt.Sprintf("batch statement %d: %v", e.Index, e.Err) }
func (e *BatchError) Unwrap() error { return e.Err }

// Queryer is the database/sql surface the engine needs; *sql.DB, *sql.Conn, and
// *sql.Tx all satisfy it.
type Queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// TxBeginner is the subset of database/sql that starts a transaction; both
// *sql.DB and *sql.Conn satisfy it, so a batch can run on the shared pool or on
// a single guarded (read-only) connection.
type TxBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// Engine holds the result caps. Phase 7 adds the slow-log (driver TraceProfile)
// and the richer limits/cancellation wiring around these calls.
type Engine struct {
	maxRows  int
	maxBytes int64
}

// New builds an Engine. A non-positive limit falls back to the safe default, so
// a result is always bounded.
func New(maxRows int, maxResultBytes int64) *Engine {
	if maxRows <= 0 {
		maxRows = DefaultMaxRows
	}
	if maxResultBytes <= 0 {
		maxResultBytes = DefaultMaxResultBytes
	}
	return &Engine{maxRows: maxRows, maxBytes: maxResultBytes}
}

// bindArgs builds the database/sql argument list — sql.Named for named args,
// positional otherwise.
func (s Statement) bindArgs() []any {
	if len(s.Named) > 0 {
		a := make([]any, len(s.Named))
		for i, n := range s.Named {
			a[i] = sql.Named(n.Name, n.Value.arg())
		}
		return a
	}
	return toArgs(s.Args)
}

// Query runs a row-returning statement and scans the rows into a Result,
// honoring the max-rows cap (setting Truncated when hit).
func (e *Engine) Query(ctx context.Context, q Queryer, s Statement) (*Result, error) {
	rows, err := q.QueryContext(ctx, s.SQL, s.bindArgs()...)
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, wrap(err)
	}
	res := &Result{Columns: make([]Column, len(cols))}
	for i, c := range cols {
		res.Columns[i] = Column{Name: c}
	}
	// Scan buffers are allocated once and reused: Scan overwrites dest each row and
	// fromAny copies each value out (database/sql clones a []byte into *any), so the
	// retained `row` never aliases dest. Avoids two slice allocations per row.
	dest := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range dest {
		ptrs[i] = &dest[i]
	}
	var bytes int64
	for rows.Next() {
		if len(res.Rows) >= e.maxRows {
			res.Truncated = true
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, wrap(err)
		}
		row := make([]Value, len(cols))
		for i, v := range dest {
			row[i] = fromAny(v)
			bytes += row[i].size()
			// A single oversized cell is already materialized by Scan (bounded by
			// SQLite's own SQLITE_MAX_LENGTH); stop as soon as the running total
			// trips the cap so a wide row of big cells can't accumulate further.
			if bytes >= e.maxBytes {
				res.Truncated = true
			}
		}
		res.Rows = append(res.Rows, row)
		if res.Truncated {
			break
		}
	}
	return res, wrap(rows.Err())
}

// Exec runs a mutation/DDL statement and reports affected rows + last insert id.
func (e *Engine) Exec(ctx context.Context, q Queryer, s Statement) (*Result, error) {
	r, err := q.ExecContext(ctx, s.SQL, s.bindArgs()...)
	if err != nil {
		return nil, wrap(err)
	}
	res := &Result{}
	res.RowsAffected, _ = r.RowsAffected()
	res.LastInsertID, _ = r.LastInsertId()
	return res, nil
}

// Batch runs a set of statements in ONE explicit transaction (BeginTx/Commit),
// all-or-nothing. Each statement dispatches via Run, so reads return rows and
// writes return affected/last-insert. A failure rolls the whole batch back and
// returns a *BatchError carrying the failing index. Hrana batch step-conditions
// and the interactive (pinned-conn) transactions arrive in Phase 2.
func (e *Engine) Batch(ctx context.Context, db TxBeginner, stmts []Statement) ([]*Result, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, wrap(err)
	}
	out := make([]*Result, 0, len(stmts))
	for i, s := range stmts {
		res, err := e.Run(ctx, tx, s)
		if err != nil {
			_ = tx.Rollback()
			return nil, &BatchError{Index: i, Err: err}
		}
		out = append(out, res)
	}
	if err := tx.Commit(); err != nil {
		return nil, wrap(err)
	}
	return out, nil
}
