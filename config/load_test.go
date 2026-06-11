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

func TestValidateAuth(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"unknown listener method", &Config{Listeners: []Listener{{Name: "l", Transport: "h1", Auth: []string{"magic"}}}}, true},
		{"peercred off unix", &Config{Listeners: []Listener{{Name: "l", Transport: "h1", Auth: []string{"peercred"}}}}, true},
		{"mtls without tls", &Config{Listeners: []Listener{{Name: "l", Transport: "h1", Auth: []string{"mtls"}}}}, true},
		{"duplicate principal", &Config{Auth: Auth{Principals: []Principal{{Name: "a"}, {Name: "a"}}}}, true},
		{"empty principal name", &Config{Auth: Auth{Principals: []Principal{{Name: ""}}}}, true},
		{"unknown credential method", &Config{Auth: Auth{Principals: []Principal{
			{Name: "a", Methods: []map[string]any{{"none": map[string]any{}}}}}}}, true},
		{"multi-key method", &Config{Auth: Auth{Principals: []Principal{
			{Name: "a", Methods: []map[string]any{{"bearer": nil, "mtls": nil}}}}}}, true},
		{"grant to unknown principal", &Config{Databases: []Database{
			{Name: "d", Backend: "file", Grants: []Grant{{Principal: "ghost", Level: "read-only"}}}}}, true},
		{"grant bad level", &Config{
			Auth:      Auth{Principals: []Principal{{Name: "a"}}},
			Databases: []Database{{Name: "d", Backend: "file", Grants: []Grant{{Principal: "a", Level: "root"}}}}}, true},
		{"good", &Config{
			Auth: Auth{Principals: []Principal{{Name: "app", Methods: []map[string]any{{"bearer": map[string]any{"token_hash": "abc"}}}}}},
			Databases: []Database{{Name: "d", Backend: "file", Mode: "rw",
				Grants: []Grant{{Principal: "app", Level: "read-write"}, {Principal: "*", Level: "read-only"}}}},
			Listeners: []Listener{{Name: "l", Transport: "unix", Auth: []string{"peercred", "none"}}},
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cfg.Validate(); (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestValidateVault(t *testing.T) {
	vdb := func(v *VaultConfig) *Config {
		return &Config{Databases: []Database{{Name: "d", Backend: "vault", Mode: "rwc", Vault: v}}}
	}
	cases := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"bad compression", vdb(&VaultConfig{Compression: "turbo"}), true},
		{"bad cipher", vdb(&VaultConfig{Cipher: "rot13"}), true},
		{"bad anchor", vdb(&VaultConfig{Anchor: &Anchor{Type: "magic"}}), true},
		{"key and identities", vdb(&VaultConfig{Key: "f:k", Identities: []string{"f:id"}}), true},
		{"vault block on non-vault backend", &Config{Databases: []Database{
			{Name: "d", Backend: "file", Vault: &VaultConfig{}}}}, true},
		{"good raw key", vdb(&VaultConfig{Cipher: "aes-xts", Compression: "best", Key: "f:k"}), false},
		{"good recipient", vdb(&VaultConfig{Identities: []string{"f:id"}, Anchor: &Anchor{Type: "file", Path: "a"}}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cfg.Validate(); (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestAuthConfigured(t *testing.T) {
	if (&Config{}).AuthConfigured() {
		t.Error("empty config should be unconfigured (open mode)")
	}
	if !(&Config{Auth: Auth{Principals: []Principal{{Name: "a"}}}}).AuthConfigured() {
		t.Error("a principal means auth configured")
	}
	if !(&Config{Databases: []Database{{Name: "d", Grants: []Grant{{Principal: "*", Level: "read-only"}}}}}).AuthConfigured() {
		t.Error("a grant means auth configured")
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
