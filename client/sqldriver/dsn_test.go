package sqldriver_test

import (
	"strings"
	"testing"

	"quicsql.net/client/sqldriver"
)

// TestDSNParseErrorRedactsSecret proves a malformed, secret-bearing DSN does not
// leak the token into the parse error (follow-up item 1). database/sql opens are
// lazy, so this error surfaces on first use where a consumer's logger may record
// it verbatim.
func TestDSNParseErrorRedactsSecret(t *testing.T) {
	// A DEL (0x7f) control character makes url.Parse fail while the raw string —
	// including the token — is still present, exercising the redact path.
	const secret = "SUPERSECRETTOKEN"
	_, err := sqldriver.OpenConnector("quicsql://h\x7fost/db?token=" + secret)
	if err == nil {
		t.Fatal("expected a parse error for a malformed DSN")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("parse error leaked the token: %q", err.Error())
	}
}

// TestDSNRejectsUserinfo proves a DSN carrying URL userinfo is rejected (the
// driver reads credentials only from query params, so userinfo would otherwise be
// silently dropped and bypass the credential-transport guard).
func TestDSNRejectsUserinfo(t *testing.T) {
	_, err := sqldriver.OpenConnector("quicsql://alice:secret@h/db?transport=h2")
	if err == nil {
		t.Fatal("expected a DSN with userinfo to be rejected")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("rejection leaked the userinfo password: %q", err.Error())
	}
}

// TestDSNRefusesCredentialOverInsecureTransport proves the driver fails closed
// when a credential would ride a cleartext or unverified channel (follow-up
// item 2), while still allowing verified TLS, unix sockets, credential-free DSNs,
// and the explicit override.
func TestDSNRefusesCredentialOverInsecureTransport(t *testing.T) {
	reject := []struct {
		name, dsn string
	}{
		{"h1 default plaintext", "quicsql://h/db?token=SECRET"},
		{"h2c plaintext", "quicsql://h/db?transport=h2c&token=SECRET"},
		{"user/password plaintext", "quicsql://h/db?transport=h1&user=u&password=p"},
		{"h2 insecure TLS", "quicsql://h/db?transport=h2&insecure=1&token=SECRET"},
		{"h3 insecure TLS", "quicsql://h/db?transport=h3&insecure=true&token=SECRET"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			_, err := sqldriver.OpenConnector(tc.dsn)
			if err == nil {
				t.Fatalf("expected refusal for %q", tc.dsn)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("refusal error leaked the credential: %q", err.Error())
			}
		})
	}

	allow := []struct {
		name, dsn string
	}{
		{"h2 verified TLS", "quicsql://h/db?transport=h2&token=SECRET"},
		{"h3 verified TLS", "quicsql://h/db?transport=h3&token=SECRET"},
		{"unix socket", "quicsql:///db?transport=unix&socket=/tmp/q.sock&token=SECRET"},
		{"no credential", "quicsql://h/db?transport=h1"},
		{"explicit override", "quicsql://h/db?transport=h1&token=SECRET&allow_insecure_auth=1"},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if _, err := sqldriver.OpenConnector(tc.dsn); err != nil {
				t.Fatalf("unexpected refusal for %q: %v", tc.dsn, err)
			}
		})
	}
}
