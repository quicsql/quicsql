// Package engine runs statements against a database handle and encodes results
// into the transport-agnostic Value/Result shape shared by every protocol. It
// is deliberately conn-source-neutral: Query/Exec take a Queryer satisfied by a
// pooled *sql.Conn, a session-pinned conn, or the *sql.DB pool itself, so the
// same code serves autocommit and interactive-transaction paths.
package engine

import (
	"context"
	"database/sql"
	"log/slog"
)

// Queryer is the database/sql surface the engine needs; *sql.DB, *sql.Conn, and
// *sql.Tx all satisfy it.
type Queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Engine holds the row/byte caps and the log seam. Phase 7 adds the slow-log
// (driver TraceProfile), limits, and cancellation wiring around these calls.
type Engine struct {
	maxRows int
	log     *slog.Logger
}

// New builds an Engine. maxRows <= 0 means unbounded (Phase 0 default).
func New(maxRows int, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{maxRows: maxRows, log: log}
}

// Query runs a row-returning statement and scans the rows into a Result,
// honoring the max-rows cap (setting Truncated when hit).
func (e *Engine) Query(ctx context.Context, q Queryer, s Statement) (*Result, error) {
	rows, err := q.QueryContext(ctx, s.SQL, toArgs(s.Args)...)
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
	for rows.Next() {
		if e.maxRows > 0 && len(res.Rows) >= e.maxRows {
			res.Truncated = true
			break
		}
		dest := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range dest {
			ptrs[i] = &dest[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, wrap(err)
		}
		row := make([]Value, len(cols))
		for i, v := range dest {
			row[i] = fromAny(v)
		}
		res.Rows = append(res.Rows, row)
	}
	return res, wrap(rows.Err())
}

// Exec runs a mutation/DDL statement and reports affected rows + last insert id.
func (e *Engine) Exec(ctx context.Context, q Queryer, s Statement) (*Result, error) {
	r, err := q.ExecContext(ctx, s.SQL, toArgs(s.Args)...)
	if err != nil {
		return nil, wrap(err)
	}
	res := &Result{}
	res.RowsAffected, _ = r.RowsAffected()
	res.LastInsertID, _ = r.LastInsertId()
	return res, nil
}

// Batch runs a set of mutation statements in a single transaction — the
// autocommit-batch primitive. Interactive transactions (BEGIN…COMMIT spanning
// requests on a pinned conn) arrive in Phase 2. A read-mixed batch and the
// Hrana batch step-conditions are also Phase 2.
func (e *Engine) Batch(ctx context.Context, db *sql.DB, stmts []Statement) ([]*Result, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, wrap(err)
	}
	out := make([]*Result, 0, len(stmts))
	for _, s := range stmts {
		res, err := e.Exec(ctx, tx, s)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		out = append(out, res)
	}
	if err := tx.Commit(); err != nil {
		return nil, wrap(err)
	}
	return out, nil
}
