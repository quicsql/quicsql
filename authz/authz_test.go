package authz

import "testing"

func TestParseLevel(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Level
		ok   bool
	}{
		{"none", None, true},
		{"read-only", ReadOnly, true},
		{"read-write", ReadWrite, true},
		{"admin", Admin, true},
		{"nonsense", None, false},
	} {
		got, ok := ParseLevel(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseLevel(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestLevelCapabilities(t *testing.T) {
	if None.CanRead() || None.CanWrite() {
		t.Error("None must grant nothing")
	}
	if !ReadOnly.CanRead() || ReadOnly.CanWrite() {
		t.Error("ReadOnly reads but does not write")
	}
	if !ReadWrite.CanWrite() || ReadWrite.CanAdmin() {
		t.Error("ReadWrite writes but is not admin")
	}
	if !Admin.CanAdmin() {
		t.Error("Admin must be admin")
	}
}

func TestPolicyOpenMode(t *testing.T) {
	p := NewPolicy(true)
	// Every principal, including anonymous, is read-write on any database.
	if got := p.Level(Anonymous, "anything"); got != ReadWrite {
		t.Fatalf("open mode: got %v, want read-write", got)
	}
	if got := p.Level(&Principal{Name: "x"}, "anything"); got != ReadWrite {
		t.Fatalf("open mode named: got %v, want read-write", got)
	}
}

func TestPolicyGrantsAndWildcard(t *testing.T) {
	p := NewPolicy(false)
	p.Grant("sales", "app", ReadWrite)
	p.Grant("sales", "analyst", ReadOnly)
	p.Grant("cache", Wildcard, ReadWrite)

	app := &Principal{Name: "app"}
	analyst := &Principal{Name: "analyst"}
	stranger := &Principal{Name: "stranger"}

	if got := p.Level(app, "sales"); got != ReadWrite {
		t.Errorf("app@sales = %v, want read-write", got)
	}
	if got := p.Level(analyst, "sales"); got != ReadOnly {
		t.Errorf("analyst@sales = %v, want read-only", got)
	}
	if got := p.Level(stranger, "sales"); got != None {
		t.Errorf("stranger@sales = %v, want none (no grant)", got)
	}
	// Wildcard applies to everyone, including the anonymous principal.
	if got := p.Level(Anonymous, "cache"); got != ReadWrite {
		t.Errorf("anon@cache = %v, want read-write (wildcard)", got)
	}
	if got := p.Level(app, "cache"); got != ReadWrite {
		t.Errorf("app@cache = %v, want read-write (wildcard)", got)
	}
	// An unknown database has no grants → no access.
	if got := p.Level(app, "unknown"); got != None {
		t.Errorf("app@unknown = %v, want none", got)
	}
}

func TestPolicyNamedBeatsWildcard(t *testing.T) {
	p := NewPolicy(false)
	p.Grant("db", Wildcard, ReadOnly)
	p.Grant("db", "app", ReadWrite)
	if got := p.Level(&Principal{Name: "app"}, "db"); got != ReadWrite {
		t.Errorf("named grant should raise above wildcard: got %v", got)
	}
	if got := p.Level(&Principal{Name: "other"}, "db"); got != ReadOnly {
		t.Errorf("wildcard floor for others: got %v", got)
	}
}
