package engine

// Statement is one SQL statement with its bind arguments — positional (Args) or
// named (Named), not both.
type Statement struct {
	SQL   string
	Args  []Value
	Named []NamedArg
	// AllowAttach lifts Run's textual ATTACH/DETACH denial for THIS statement,
	// deferring to the connection's authorizer instead. Set only by the Hrana path
	// for a DEV-ONLY attach-enabled session (server-admin); that connection carries
	// the permitAttach authorizer. The native/autocommit path never sets it.
	AllowAttach bool
}

// NamedArg binds a value to a named SQLite parameter (:name / @name / $name).
type NamedArg struct {
	Name  string
	Value Value
}

// Column describes one result column.
type Column struct {
	Name string
}

// Result is the transport-agnostic outcome of a statement: rows for a query,
// affected/last-insert for a mutation. Truncated + Cursor support the streaming
// / keyset-pagination story.
type Result struct {
	Columns      []Column
	Rows         [][]Value
	RowsAffected int64
	LastInsertID int64
	Truncated    bool
	Cursor       string
}
