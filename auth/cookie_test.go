package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"quicsql.net/config"
	"quicsql.net/secret"
)

// buildCookieSession compiles an Authenticator with cookie session transport on
// over one bearer principal. Cookie mode is activated by SetCookieMode (the seam an
// optional feature like the accounts product uses), not by core config.
func buildCookieSession(t *testing.T) *Middleware {
	t.Helper()
	sum := sha256.Sum256([]byte("s3cr3t"))
	sec, _ := secret.New(nil)
	cfg := &config.Config{
		Auth: config.Auth{
			Principals: []config.Principal{principal("app", "bearer", map[string]any{"token_hash": hex.EncodeToString(sum[:])})},
			Session:    config.SessionTokens{Enabled: true, IdleTTL: time.Minute},
		},
	}
	a, err := New(cfg, sec, nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	a.SetCookieMode(true)
	return a.Middleware(config.Listener{Name: "l", Auth: []string{"bearer", "session", "none"}}, nil)
}

// sessionCookieFrom digs the session cookie out of a recorded response.
func sessionCookieFrom(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == defaultSessionCookie {
			return c
		}
	}
	t.Fatalf("no %s cookie in response (Set-Cookie: %v)", defaultSessionCookie, w.Header().Values("Set-Cookie"))
	return nil
}

func TestCookieTransportMintSetsCookie(t *testing.T) {
	m := buildCookieSession(t)
	w := mintToken(t, m, "Bearer s3cr3t")
	if w.Code != http.StatusOK {
		t.Fatalf("mint status = %d (%s)", w.Code, w.Body.String())
	}
	tok := tokenFrom(t, w) // JSON body still carries the token for header clients
	c := sessionCookieFrom(t, w)
	if c.Value != tok || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cookie attrs: %+v", c)
	}
}

func TestCookieAuthenticatesAndCSRFGates(t *testing.T) {
	m := buildCookieSession(t)
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))

	req := func(method, sfs string) *http.Request {
		r := httptest.NewRequest(method, "/app/query", nil)
		r.AddCookie(&http.Cookie{Name: defaultSessionCookie, Value: tok})
		if sfs != "" {
			r.Header.Set("Sec-Fetch-Site", sfs)
		}
		return r
	}

	// A cookie-borne session authenticates a read regardless of fetch site.
	if p, err := m.authenticate(req(http.MethodGet, "cross-site")); err != nil || p.Name != "app" || p.Method != "session" {
		t.Fatalf("cookie GET: p=%+v err=%v", p, err)
	}
	// Same-origin, direct-navigation, and non-browser writes pass.
	for _, sfs := range []string{"same-origin", "none", ""} {
		if p, err := m.authenticate(req(http.MethodPost, sfs)); err != nil || p.Name != "app" {
			t.Fatalf("cookie POST %q: p=%+v err=%v", sfs, p, err)
		}
	}
	// A forged cross-site (or same-site subdomain) write is decisively refused.
	for _, sfs := range []string{"cross-site", "same-site"} {
		if _, err := m.authenticate(req(http.MethodPost, sfs)); err == nil {
			t.Fatalf("cookie POST %q must fail CSRF", sfs)
		}
	}
}

func TestCookieIgnoredWhenTransportHeader(t *testing.T) {
	m := buildSession(t, time.Minute) // default transport (no accounts/cookie config)
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))

	// With cookie transport off, a valid session token in a cookie must NOT
	// authenticate — the request falls through to `none` → anonymous.
	r := httptest.NewRequest(http.MethodGet, "/app/query", nil)
	r.AddCookie(&http.Cookie{Name: defaultSessionCookie, Value: tok})
	p, err := m.authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !p.IsAnonymous() {
		t.Fatalf("cookie must be ignored with header transport: p=%+v", p)
	}
}

func TestCookieLogoutClearsCookie(t *testing.T) {
	m := buildCookieSession(t)
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))

	h := m.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("session delete must be handled by the middleware")
	}))
	r := httptest.NewRequest(http.MethodDelete, "/_auth/session", nil)
	r.AddCookie(&http.Cookie{Name: defaultSessionCookie, Value: tok})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("cookie logout status = %d (%s)", w.Code, w.Body.String())
	}
	if c := sessionCookieFrom(t, w); c.MaxAge >= 0 || c.Value != "" {
		t.Fatalf("logout must expire the cookie: %+v", c)
	}
	// The revoked token no longer authenticates (by cookie or header).
	r2 := httptest.NewRequest(http.MethodGet, "/app/query", nil)
	r2.AddCookie(&http.Cookie{Name: defaultSessionCookie, Value: tok})
	if p, err := m.authenticate(r2); err == nil && p != nil && p.Method == "session" {
		t.Fatal("revoked cookie session must not authenticate")
	}
}
