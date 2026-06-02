package engine

import (
	"fmt"
	"time"
)

// Kind enumerates SQLite's five dynamic storage classes. The wire codecs
// (Hrana, protobuf, native JSON) all encode from this single internal union.
type Kind uint8

const (
	KindNull Kind = iota
	KindInt
	KindFloat
	KindText
	KindBlob
)

// Value is one cell: exactly one field is meaningful, selected by Kind.
type Value struct {
	Kind  Kind
	Int   int64
	Float float64
	Text  string
	Blob  []byte
}

// Constructors — convenience for callers and tests.

func Null() Value           { return Value{Kind: KindNull} }
func Int(n int64) Value     { return Value{Kind: KindInt, Int: n} }
func Float(f float64) Value { return Value{Kind: KindFloat, Float: f} }
func Text(s string) Value   { return Value{Kind: KindText, Text: s} }
func Blob(b []byte) Value   { return Value{Kind: KindBlob, Blob: b} }

// arg converts a Value into a database/sql bind argument.
func (v Value) arg() any {
	switch v.Kind {
	case KindInt:
		return v.Int
	case KindFloat:
		return v.Float
	case KindText:
		return v.Text
	case KindBlob:
		return v.Blob
	default:
		return nil
	}
}

// fromAny maps a scanned database/sql value back into the union.
func fromAny(x any) Value {
	switch t := x.(type) {
	case nil:
		return Value{Kind: KindNull}
	case int64:
		return Value{Kind: KindInt, Int: t}
	case float64:
		return Value{Kind: KindFloat, Float: t}
	case string:
		return Value{Kind: KindText, Text: t}
	case []byte:
		return Value{Kind: KindBlob, Blob: t}
	case time.Time:
		// The driver auto-parses DATE/DATETIME/TIMESTAMP columns into time.Time;
		// render a canonical, round-trippable text form (not time.Time.String,
		// which appends " +0000 UTC").
		return Value{Kind: KindText, Text: t.Format(time.RFC3339Nano)}
	case bool:
		if t {
			return Value{Kind: KindInt, Int: 1}
		}
		return Value{Kind: KindInt}
	default:
		return Value{Kind: KindText, Text: fmt.Sprint(t)}
	}
}

func toArgs(vs []Value) []any {
	a := make([]any, len(vs))
	for i, v := range vs {
		a[i] = v.arg()
	}
	return a
}

// size is an approximate serialized byte cost of a cell, used to bound a result
// so a large read can't exhaust memory. Numbers count as 8.
func (v Value) size() int64 {
	switch v.Kind {
	case KindText:
		return int64(len(v.Text))
	case KindBlob:
		return int64(len(v.Blob))
	default:
		return 8
	}
}
