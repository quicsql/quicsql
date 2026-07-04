package engine

import "quicsql.net/internal/wire"

// Value/Kind and their constructors are the canonical wire union, defined once in
// package wire so the server and client codecs cannot drift. engine re-exports them
// (as aliases) because the engine and the protocol layers built on it are written
// against engine.Value; the single source of truth lives in wire.
type (
	Value = wire.Value
	Kind  = wire.Kind
)

const (
	KindNull  = wire.KindNull
	KindInt   = wire.KindInt
	KindFloat = wire.KindFloat
	KindText  = wire.KindText
	KindBlob  = wire.KindBlob
)

func Null() Value           { return wire.Null() }
func Int(n int64) Value     { return wire.Int(n) }
func Float(f float64) Value { return wire.Float(f) }
func Text(s string) Value   { return wire.Text(s) }
func Blob(b []byte) Value   { return wire.Blob(b) }

// fromAny maps a scanned database/sql value into the union — the same normalizer
// the client uses for bind arguments, so a value stores identically whichever path
// it took.
func fromAny(x any) Value { return wire.FromGo(x) }

func toArgs(vs []Value) []any {
	a := make([]any, len(vs))
	for i, v := range vs {
		a[i] = v.Arg()
	}
	return a
}
