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

func TestValidateTransportsAndTLS(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"h2 without tls", &Config{Listeners: []Listener{{Name: "x", Transport: "h2"}}}, true},
		{"h3 without tls", &Config{Listeners: []Listener{{Name: "x", Transport: "h3"}}}, true},
		{"unknown transport", &Config{Listeners: []Listener{{Name: "x", Transport: "ws"}}}, true},
		{"tls name missing", &Config{Listeners: []Listener{{Name: "x", Transport: "h2", TLS: "nope"}}}, true},
		{"bad tls mode", &Config{TLS: map[string]TLSProfile{"p": {Mode: "weird"}}}, true},
		{"bad min_version", &Config{TLS: map[string]TLSProfile{"p": {Mode: "self_signed", MinVersion: "1.4"}}}, true},
		{"files without cert", &Config{TLS: map[string]TLSProfile{"p": {Mode: "files"}}}, true},
		{"good", &Config{
			TLS:       map[string]TLSProfile{"p": {Mode: "self_signed", MinVersion: "1.3"}},
			Listeners: []Listener{{Name: "x", Transport: "h2", TLS: "p"}, {Name: "u", Transport: "unix"}},
		}, false},
	}
	for _, c := range cases {
		if err := c.cfg.Validate(); (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
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
