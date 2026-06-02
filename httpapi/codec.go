package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"gosqlite.org/server/engine"
)

// encodeValue maps a cell to its native-JSON form: null/number/string bare, and
// a blob boxed as {"base64": "..."} so it can't be confused with text. A
// non-finite REAL (±Inf/NaN — which JSON numbers cannot represent) is emitted as
// the string "Infinity"/"-Infinity"/"NaN" so the response stays encodable.
func encodeValue(v engine.Value) any {
	switch v.Kind {
	case engine.KindInt:
		return v.Int
	case engine.KindFloat:
		if math.IsInf(v.Float, 0) || math.IsNaN(v.Float) {
			return nonFiniteString(v.Float)
		}
		return v.Float
	case engine.KindText:
		return v.Text
	case engine.KindBlob:
		return map[string]string{"base64": base64.StdEncoding.EncodeToString(v.Blob)}
	default:
		return nil
	}
}

func nonFiniteString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case f > 0:
		return "Infinity"
	default:
		return "-Infinity"
	}
}

func decodeArgs(raw []json.RawMessage) ([]engine.Value, error) {
	out := make([]engine.Value, len(raw))
	for i, r := range raw {
		v, err := decodeArg(r)
		if err != nil {
			return nil, fmt.Errorf("arg %d: %w", i, err)
		}
		out[i] = v
	}
	return out, nil
}

// decodeArg maps a JSON argument to a typed Value. Numbers are decoded with
// json.Number so an integer literal binds as an int64 (not a lossy float64); a
// blob is passed as {"base64": "..."}.
func decodeArg(raw json.RawMessage) (engine.Value, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return engine.Value{}, err
	}
	switch t := x.(type) {
	case nil:
		return engine.Null(), nil
	case bool:
		if t {
			return engine.Int(1), nil
		}
		return engine.Int(0), nil
	case string:
		return engine.Text(t), nil
	case json.Number:
		if strings.ContainsAny(t.String(), ".eE") {
			f, err := t.Float64()
			if err != nil {
				return engine.Value{}, err
			}
			return engine.Float(f), nil
		}
		n, err := t.Int64()
		if err != nil {
			// Out of int64 range — fall back to float rather than reject.
			f, ferr := t.Float64()
			if ferr != nil {
				return engine.Value{}, err
			}
			return engine.Float(f), nil
		}
		return engine.Int(n), nil
	case map[string]any:
		b, ok := t["base64"]
		if !ok || len(t) != 1 {
			return engine.Value{}, errors.New(`unsupported object arg (only {"base64": "..."} is allowed)`)
		}
		s, ok := b.(string)
		if !ok {
			return engine.Value{}, errors.New("base64 arg must be a string")
		}
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return engine.Value{}, fmt.Errorf("invalid base64: %w", err)
		}
		return engine.Blob(data), nil
	default:
		return engine.Value{}, fmt.Errorf("unsupported arg type %T", x)
	}
}
