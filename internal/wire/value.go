// Package wire is the single source of truth for quicSQL's on-the-wire value
// representation and result-code vocabulary, shared by the server (engine,
// httpapi) and the client so the native-JSON and Hrana protocols cannot drift.
//
// Everything encodes from ONE canonical Value (SQLite's five storage classes)
// produced by ONE Go→Value normalizer (FromGo), so a given Go argument lands as
// the identical stored type whether it travels the stateless native endpoint or a
// Hrana transaction. It is a leaf package (stdlib only — no engine, no gosqlite),
// so the thin client does not pull the server in, and it is internal, so the
// codec types stay off the public API.
package wire

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Kind enumerates SQLite's five dynamic storage classes. Every wire codec encodes
// from this single internal union.
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

// FromGo maps a Go value into the canonical union. It is the SINGLE normalizer for
// both directions that matter: the server scanning a database/sql result row, and
// the client binding a statement argument. Because both protocols then encode from
// the resulting Value, an integral float64 (say 100.0) is Kind=Float on both — it
// can never become INTEGER on one path and REAL on the other.
func FromGo(x any) Value {
	switch t := x.(type) {
	case nil:
		return Null()
	case bool:
		if t {
			return Int(1)
		}
		return Int(0)
	case int:
		return Int(int64(t))
	case int8:
		return Int(int64(t))
	case int16:
		return Int(int64(t))
	case int32:
		return Int(int64(t))
	case int64:
		return Int(t)
	case uint8:
		return Int(int64(t))
	case uint16:
		return Int(int64(t))
	case uint32:
		return Int(int64(t))
	case uint:
		return uintValue(uint64(t))
	case uint64:
		return uintValue(t)
	case uintptr:
		return uintValue(uint64(t))
	case float32:
		return Float(float64(t))
	case float64:
		return Float(t)
	case string:
		return Text(t)
	case []byte:
		return Blob(t)
	case time.Time:
		// The driver auto-parses DATE/DATETIME/TIMESTAMP columns into time.Time;
		// render a canonical, round-trippable text form (SQLite has no native time
		// type and its date functions parse RFC3339). NOT time.Time.String, which
		// appends " +0000 UTC".
		return Text(t.Format(time.RFC3339Nano))
	case json.Number:
		return numberValue(t)
	default:
		return Text(fmt.Sprint(t))
	}
}

// uintValue stores a 64-bit unsigned as an integer when it fits, else losslessly
// as text rather than wrapping to a negative int64. (database/sql never delivers
// these; only the raw client API can.)
func uintValue(u uint64) Value {
	if u <= math.MaxInt64 {
		return Int(int64(u))
	}
	return Text(strconv.FormatUint(u, 10))
}

// numberValue decides int vs float for a json.Number: a fractional/exponent form
// is Float, an integer literal is Int (precision-safe past 2^53), and an
// out-of-int64-range integer falls back to Float rather than being rejected.
func numberValue(n json.Number) Value {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		if f, err := n.Float64(); err == nil {
			return Float(f)
		}
		return Text(s)
	}
	if i, err := n.Int64(); err == nil {
		return Int(i)
	}
	if f, err := n.Float64(); err == nil {
		return Float(f)
	}
	return Text(s)
}

// Go converts a Value to a Go value for a client result cell. All returns are
// valid database/sql driver.Values, so the driver passes them through unchanged:
// null→nil, int→int64, float→float64, text→string, blob→[]byte.
func (v Value) Go() any {
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

// Arg converts a Value into a database/sql bind argument (server side).
func (v Value) Arg() any { return v.Go() }

// Size is an approximate serialized byte cost of a cell, used to bound a result so
// a large read can't exhaust memory. Numbers count as 8.
func (v Value) Size() int64 {
	switch v.Kind {
	case KindText:
		return int64(len(v.Text))
	case KindBlob:
		return int64(len(v.Blob))
	default:
		return 8
	}
}
