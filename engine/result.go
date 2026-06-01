package engine

// Statement is one SQL statement with its positional bind arguments.
type Statement struct {
	SQL  string
	Args []Value
}

// Column describes one result column.
type Column struct {
	Name string
}

// Result is the transport-agnostic outcome of a statement: rows for a query,
// affected/last-insert for a mutation. Truncated + Cursor support the streaming
// / keyset-pagination story (Phase 1/2).
type Result struct {
	Columns      []Column
	Rows         [][]Value
	RowsAffected int64
	LastInsertID int64
	Truncated    bool
	Cursor       string
}
