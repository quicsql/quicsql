package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// NativeValue adapts a Value to the native bare-JSON form used by the stateless
// /<db>/query endpoint: null/number/string bare, a blob boxed as {"base64":"..."}
// so it can't be confused with text. It is used by BOTH sides — server result
// cells and client bind args — so the two never diverge.
type NativeValue struct{ V Value }

// MarshalJSON emits the bare form. A KindFloat is written with a forced decimal
// point (100 -> "100.0") so the decoder's ".eE" rule reads it back as a float and
// not an integer — the crux that keeps an integral float REAL across both the
// native and Hrana paths. A non-finite float (±Inf/NaN, unrepresentable in JSON)
// becomes null, matching the Hrana form.
func (n NativeValue) MarshalJSON() ([]byte, error) {
	v := n.V
	switch v.Kind {
	case KindInt:
		return strconv.AppendInt(nil, v.Int, 10), nil
	case KindFloat:
		return floatNativeJSON(v.Float), nil
	case KindText:
		return json.Marshal(v.Text)
	case KindBlob:
		return json.Marshal(map[string]string{"base64": base64.StdEncoding.EncodeToString(v.Blob)})
	default:
		return []byte("null"), nil
	}
}

// UnmarshalJSON decodes one native argument/cell into a Value. Numbers use
// json.Number so an integer literal binds as int64 (not a lossy float64); a blob
// arrives as {"base64":"..."}.
func (n *NativeValue) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return err
	}
	v, err := fromNativeAny(x)
	if err != nil {
		return err
	}
	n.V = v
	return nil
}

func fromNativeAny(x any) (Value, error) {
	switch t := x.(type) {
	case nil:
		return Null(), nil
	case bool:
		if t {
			return Int(1), nil
		}
		return Int(0), nil
	case string:
		return Text(t), nil
	case json.Number:
		return numberValue(t), nil
	case map[string]any:
		b, ok := t["base64"]
		if !ok || len(t) != 1 {
			return Value{}, errors.New(`unsupported object arg (only {"base64": "..."} is allowed)`)
		}
		s, ok := b.(string)
		if !ok {
			return Value{}, errors.New("base64 arg must be a string")
		}
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return Value{}, fmt.Errorf("invalid base64: %w", err)
		}
		return Blob(data), nil
	default:
		return Value{}, fmt.Errorf("unsupported arg type %T", x)
	}
}

// floatNativeJSON renders a float as a JSON number that always round-trips back to
// a float: a non-integer already contains "." or an exponent; an integral value
// gets ".0" appended so the decoder does not read it as an integer.
func floatNativeJSON(f float64) []byte {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return []byte("null")
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return []byte(s)
}

// DecodeNativeArgs decodes a native arg array into Values.
func DecodeNativeArgs(raw []json.RawMessage) ([]Value, error) {
	out := make([]Value, len(raw))
	for i, r := range raw {
		var nv NativeValue
		if err := nv.UnmarshalJSON(r); err != nil {
			return nil, fmt.Errorf("arg %d: %w", i, err)
		}
		out[i] = nv.V
	}
	return out, nil
}

// HranaValue adapts a Value to Hrana's tagged form: integers are carried as
// decimal STRINGS (precision-safe past 2^53), blobs as base64. Used by both sides.
type HranaValue struct{ V Value }

func (h HranaValue) MarshalJSON() ([]byte, error) {
	v := h.V
	switch v.Kind {
	case KindInt:
		return json.Marshal(map[string]string{"type": "integer", "value": strconv.FormatInt(v.Int, 10)})
	case KindFloat:
		if math.IsInf(v.Float, 0) || math.IsNaN(v.Float) {
			return []byte(`{"type":"null"}`), nil // JSON floats can't carry ±Inf/NaN
		}
		return json.Marshal(struct {
			Type  string  `json:"type"`
			Value float64 `json:"value"`
		}{"float", v.Float})
	case KindText:
		return json.Marshal(map[string]string{"type": "text", "value": v.Text})
	case KindBlob:
		return json.Marshal(map[string]string{"type": "blob", "base64": base64.StdEncoding.EncodeToString(v.Blob)})
	default:
		return []byte(`{"type":"null"}`), nil
	}
}

func (h *HranaValue) UnmarshalJSON(b []byte) error {
	var raw struct {
		Type   string          `json:"type"`
		Value  json.RawMessage `json:"value"`
		Base64 string          `json:"base64"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch raw.Type {
	case "null", "":
		// An empty/absent type decodes as null on both sides (lenient, and matches
		// the client's historical behavior) — the two decoders agree by construction.
		h.V = Null()
	case "integer":
		var s string
		if err := json.Unmarshal(raw.Value, &s); err != nil {
			return err
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("hrana: bad integer value: %w", err)
		}
		h.V = Int(i)
	case "float":
		var f float64
		if err := json.Unmarshal(raw.Value, &f); err != nil {
			return err
		}
		h.V = Float(f)
	case "text":
		var s string
		if err := json.Unmarshal(raw.Value, &s); err != nil {
			return err
		}
		h.V = Text(s)
	case "blob":
		data, err := base64.StdEncoding.DecodeString(raw.Base64)
		if err != nil {
			return fmt.Errorf("hrana: bad blob base64: %w", err)
		}
		h.V = Blob(data)
	default:
		return fmt.Errorf("hrana: unknown value type %q", raw.Type)
	}
	return nil
}
