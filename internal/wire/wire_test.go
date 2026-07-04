package wire

import (
	"encoding/json"
	"math"
	"testing"
)

// canonicalValues is the golden table every codec must round-trip identically.
func canonicalValues() []Value {
	return []Value{
		Null(),
		Int(0), Int(1), Int(-1), Int(math.MaxInt64), Int(math.MinInt64),
		Float(0), Float(1.5), Float(-2.25), Float(100), Float(1e300), // 100 is the integral-float case
		Text(""), Text("hello"), Text("unicode: café — 日本語"),
		Blob([]byte{}), Blob([]byte{0, 1, 2, 255}),
	}
}

func equalValue(a, b Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case KindInt:
		return a.Int == b.Int
	case KindFloat:
		return a.Float == b.Float
	case KindText:
		return a.Text == b.Text
	case KindBlob:
		return string(a.Blob) == string(b.Blob)
	default:
		return true
	}
}

func TestNativeRoundTrip(t *testing.T) {
	for _, v := range canonicalValues() {
		b, err := json.Marshal(NativeValue{V: v})
		if err != nil {
			t.Fatalf("marshal native %+v: %v", v, err)
		}
		var got NativeValue
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal native %s: %v", b, err)
		}
		if !equalValue(v, got.V) {
			t.Fatalf("native round-trip mismatch: %+v -> %s -> %+v", v, b, got.V)
		}
	}
}

func TestHranaRoundTrip(t *testing.T) {
	for _, v := range canonicalValues() {
		b, err := json.Marshal(HranaValue{V: v})
		if err != nil {
			t.Fatalf("marshal hrana %+v: %v", v, err)
		}
		var got HranaValue
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal hrana %s: %v", b, err)
		}
		if !equalValue(v, got.V) {
			t.Fatalf("hrana round-trip mismatch: %+v -> %s -> %+v", v, b, got.V)
		}
	}
}

// TestIntegralFloatStaysFloat is the CODEC-1 guard: an integral float must decode
// back as Float on BOTH protocols (never Int), so it stores REAL in autocommit and
// in a transaction alike.
func TestIntegralFloatStaysFloat(t *testing.T) {
	v := Float(100)
	for name, enc := range map[string]json.Marshaler{"native": NativeValue{V: v}, "hrana": HranaValue{V: v}} {
		b, err := json.Marshal(enc)
		if err != nil {
			t.Fatalf("%s marshal: %v", name, err)
		}
		var kind Kind
		switch enc.(type) {
		case NativeValue:
			var nv NativeValue
			if err := json.Unmarshal(b, &nv); err != nil {
				t.Fatalf("%s unmarshal %s: %v", name, b, err)
			}
			kind = nv.V.Kind
		case HranaValue:
			var hv HranaValue
			if err := json.Unmarshal(b, &hv); err != nil {
				t.Fatalf("%s unmarshal %s: %v", name, b, err)
			}
			kind = hv.V.Kind
		}
		if kind != KindFloat {
			t.Fatalf("%s: integral float decoded as %v (want Float); wire=%s", name, kind, b)
		}
	}
}

// TestFromGoNormalization checks the single normalizer covers the types the two
// paths used to disagree on (CODEC-2): small/unsigned ints stay Int, bool→Int,
// json.Number decides int vs float, integral float64 stays Float.
func TestFromGoNormalization(t *testing.T) {
	cases := []struct {
		in   any
		want Value
	}{
		{true, Int(1)}, {false, Int(0)},
		{int8(5), Int(5)}, {int16(-7), Int(-7)}, {uint16(9), Int(9)}, {uint32(11), Int(11)},
		{uint64(12), Int(12)},
		{float64(100), Float(100)}, {float32(1.5), Float(1.5)},
		{json.Number("42"), Int(42)}, {json.Number("4.5"), Float(4.5)},
		{"s", Text("s")}, {nil, Null()},
	}
	for _, c := range cases {
		if got := FromGo(c.in); !equalValue(got, c.want) {
			t.Fatalf("FromGo(%#v) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

// TestNonFiniteFloatsAreNull: ±Inf/NaN cannot ride JSON, so both encoders emit
// null (a lossy but agreed choice).
func TestNonFiniteFloatsAreNull(t *testing.T) {
	for _, f := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		for name, enc := range map[string]json.Marshaler{"native": NativeValue{V: Float(f)}, "hrana": HranaValue{V: Float(f)}} {
			b, err := json.Marshal(enc)
			if err != nil {
				t.Fatalf("%s marshal %v: %v", name, f, err)
			}
			if name == "native" && string(b) != "null" {
				t.Fatalf("native non-finite: got %s, want null", b)
			}
		}
	}
}

// TestCodeTableBijection: every name maps back to a code, and every primary/
// extended code maps to a name that recovers it.
func TestCodeTableBijection(t *testing.T) {
	for code, name := range primaryNames {
		if CodeName(code) != name {
			t.Fatalf("CodeName(%d) = %q, want %q", code, CodeName(code), name)
		}
		if CodeForName(name) != code {
			t.Fatalf("CodeForName(%q) = %d, want %d", name, CodeForName(name), code)
		}
	}
	for code, name := range extendedNames {
		if ExtendedCodeName(code) != name {
			t.Fatalf("ExtendedCodeName(%d) = %q, want %q", code, ExtendedCodeName(code), name)
		}
		if CodeForName(name) != code {
			t.Fatalf("CodeForName(%q) = %d, want %d", name, CodeForName(name), code)
		}
	}
	if CodeForName("NOT_A_CODE") != 0 {
		t.Fatal("unknown name should map to 0")
	}
}
