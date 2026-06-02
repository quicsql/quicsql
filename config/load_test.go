package config

import "testing"

func TestValidateRejectsBadDatabaseNames(t *testing.T) {
	bad := []string{"query", "v2", "v3", "_meta", "_server", "a/b", `a\b`, ""}
	for _, name := range bad {
		c := &Config{Databases: []Database{{Name: name, Backend: "file"}}}
		if err := c.Validate(); err == nil {
			t.Errorf("Validate accepted bad database name %q", name)
		}
	}
	good := &Config{Databases: []Database{{Name: "sales", Backend: "vault", Mode: "rw"}}}
	if err := good.Validate(); err != nil {
		t.Errorf("Validate rejected a good config: %v", err)
	}
}

func TestValidateRejectsBadModeAndTxLock(t *testing.T) {
	c := &Config{Databases: []Database{{Name: "d", Backend: "file", Mode: "read-wryte"}}}
	if err := c.Validate(); err == nil {
		t.Error("Validate accepted an invalid mode")
	}
	c = &Config{Databases: []Database{{Name: "d", Backend: "file", Pool: Pool{TxLock: "wonky"}}}}
	if err := c.Validate(); err == nil {
		t.Error("Validate accepted an invalid tx_lock")
	}
}
