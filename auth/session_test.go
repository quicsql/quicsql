package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"quicsql.net/authz"
	"quicsql.net/config"
	"quicsql.net/internal/wire"
	"quicsql.net/secret"
)

// buildSession compiles an Authenticator with non-renewable session tokens
// (idle window = ttl) over one bearer principal, and returns a Middleware
// accepting bearer+session+none.
func buildSession(t *testing.T, ttl time.Duration) *Middleware {
	t.Helper()
	return buildSessionTTL(t, ttl, 0)
}

// buildSessionTTL is buildSession with an explicit max_ttl (0 = non-renewable).
func buildSessionTTL(t *testing.T, idle, max time.Duration) *Middleware {
	t.Helper()
	sum := sha256.Sum256([]byte("s3cr3t"))
	sec, _ := secret.New(nil)
	cfg := &config.Config{Auth: config.Auth{
		Principals: []config.Principal{principal("app", "bearer", map[string]any{"token_hash": hex.EncodeToString(sum[:])})},
		Session:    config.SessionTokens{Enabled: true, IdleTTL: idle, MaxTTL: max},
	}}
	a, err := New(cfg, sec, nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a.Middleware(config.Listener{Name: "l", Auth: []string{"bearer", "session", "none"}}, nil)
}

// mintToken POSTs /_auth/session with the given Authorization value and returns
// the response.
func mintToken(t *testing.T, m *Middleware, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("mint request must be handled by the middleware, not the inner handler")
	}))
	r := httptest.NewRequest(http.MethodPost, "/_auth/session", nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func tokenFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
		Principal string `json:"principal"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("mint response: %v (%s)", err, w.Body.String())
	}
	if resp.Principal != "app" || !strings.HasPrefix(resp.Token, sessionPrefix) {
		t.Fatalf("mint response = %+v", resp)
	}
	return resp.Token
}

func TestSessionMintAndUse(t *testing.T) {
	m := buildSession(t, time.Minute)
	w := mintToken(t, m, "Bearer s3cr3t")
	if w.Code != http.StatusOK {
		t.Fatalf("mint status = %d (%s)", w.Code, w.Body.String())
	}
	tok := tokenFrom(t, w)

	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	p, err := m.authenticate(r)
	if err != nil || p.Name != "app" || p.Method != "session" {
		t.Fatalf("session token auth: p=%+v err=%v", p, err)
	}
}

func TestSessionMintRequiresRealCredential(t *testing.T) {
	m := buildSession(t, time.Minute)

	// No credential: the listener accepts `none`, but anonymous has no identity a
	// token could represent.
	if w := mintToken(t, m, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous mint status = %d, want 401", w.Code)
	}
	// A wrong credential is decisive.
	if w := mintToken(t, m, "Bearer wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad-credential mint status = %d, want 401", w.Code)
	}
}

func TestSessionTokenCannotMintSuccessor(t *testing.T) {
	m := buildSession(t, time.Minute)
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))

	// A valid session token must NOT buy a fresh one — that would extend a leak
	// indefinitely through self-renewal.
	if w := mintToken(t, m, "Bearer "+tok); w.Code != http.StatusUnauthorized {
		t.Fatalf("session-token mint status = %d, want 401", w.Code)
	}
}

func TestSessionExpiry(t *testing.T) {
	m := buildSession(t, time.Millisecond)
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))
	time.Sleep(5 * time.Millisecond)

	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if _, err := m.authenticate(r); err == nil {
		t.Fatal("expired session token must be rejected")
	}
}

func TestSessionRevocation(t *testing.T) {
	m := buildSession(t, time.Minute)
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("revoke must be handled by the middleware")
	}))

	del := httptest.NewRequest(http.MethodDelete, "/_auth/session", nil)
	del.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, del)
	if w.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want 204", w.Code)
	}

	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if _, err := m.authenticate(r); err == nil {
		t.Fatal("revoked session token must be rejected")
	}
}

func TestSessionTamperedTokenRejected(t *testing.T) {
	m := buildSession(t, time.Minute)
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))

	tampered := tok[:len(tok)-2] + "AA"
	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer "+tampered)
	if _, err := m.authenticate(r); err == nil {
		t.Fatal("tampered session token must be rejected")
	}
}

// A non-st_ bearer value on a session-enabled listener must still reach the
// static bearer method — the prefix routes, it doesn't monopolize the header.
func TestSessionCoexistsWithStaticBearer(t *testing.T) {
	m := buildSession(t, time.Minute)
	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer s3cr3t")
	p, err := m.authenticate(r)
	if err != nil || p.Name != "app" || p.Method != "bearer" {
		t.Fatalf("static bearer beside session: p=%+v err=%v", p, err)
	}
}

// The mint endpoint must not exist on a listener that doesn't accept session
// tokens, and session tokens must not authenticate there.
func TestSessionNotAcceptedOnOtherListeners(t *testing.T) {
	sum := sha256.Sum256([]byte("s3cr3t"))
	sec, _ := secret.New(nil)
	cfg := &config.Config{Auth: config.Auth{
		Principals: []config.Principal{principal("app", "bearer", map[string]any{"token_hash": hex.EncodeToString(sum[:])})},
		Session:    config.SessionTokens{Enabled: true, IdleTTL: time.Minute},
	}}
	a, err := New(cfg, sec, nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	withSession := a.Middleware(config.Listener{Name: "s", Auth: []string{"bearer", "session"}}, nil)
	tok := tokenFrom(t, mintToken(t, withSession, "Bearer s3cr3t"))

	bearerOnly := a.Middleware(config.Listener{Name: "b", Auth: []string{"bearer"}}, nil)
	seen := false
	h := bearerOnly.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = true
		if p := authz.FromContext(r.Context()); p.Method == "session" {
			t.Fatalf("session principal on a bearer-only listener: %+v", p)
		}
	}))

	// The mint path falls through to normal auth (no credential → 401), and the
	// inner handler never sees it.
	mint := httptest.NewRequest(http.MethodPost, "/_auth/session", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, mint)
	if w.Code != http.StatusUnauthorized || seen {
		t.Fatalf("mint on bearer-only listener: status=%d seen=%v, want 401 unseen", w.Code, seen)
	}

	// A session token presented as a bearer credential doesn't match any static
	// hash → 401 (present ⇒ decisive, no anonymous downgrade).
	use := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	use.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, use)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("session token on bearer-only listener: status=%d, want 401", w.Code)
	}
}

// renewToken PUTs /_auth/session presenting the given token.
func renewToken(t *testing.T, m *Middleware, token string) *httptest.ResponseRecorder {
	t.Helper()
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("renew request must be handled by the middleware")
	}))
	r := httptest.NewRequest(http.MethodPut, "/_auth/session", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSessionNonRenewableRejectsPut(t *testing.T) {
	m := buildSession(t, time.Minute) // max_ttl = 0 → non-renewable
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))
	if w := renewToken(t, m, tok); w.Code != http.StatusConflict {
		t.Fatalf("renew of a non-renewable token: status = %d, want 409", w.Code)
	}
}

func TestSessionRenewExtendsWithinMax(t *testing.T) {
	m := buildSessionTTL(t, time.Minute, time.Hour) // renewable
	mint := mintToken(t, m, "Bearer s3cr3t")
	var minted struct {
		Token, ExpiresAt, MaxExpiresAt string `json:"-"`
	}
	_ = json.Unmarshal(mint.Body.Bytes(), &struct {
		Token        *string `json:"token"`
		ExpiresAt    *string `json:"expires_at"`
		MaxExpiresAt *string `json:"max_expires_at"`
	}{&minted.Token, &minted.ExpiresAt, &minted.MaxExpiresAt})
	if minted.MaxExpiresAt == "" {
		t.Fatalf("renewable mint should carry max_expires_at: %s", mint.Body.String())
	}

	w := renewToken(t, m, minted.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("renew status = %d (%s)", w.Code, w.Body.String())
	}
	var renewed struct {
		Token        string `json:"token"`
		MaxExpiresAt string `json:"max_expires_at"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &renewed)
	if !strings.HasPrefix(renewed.Token, sessionPrefix) || renewed.Token == minted.Token {
		t.Fatalf("renew should return a NEW token, got %q", renewed.Token)
	}
	// The hard deadline is carried forward unchanged (the chain is still bounded).
	if renewed.MaxExpiresAt != minted.MaxExpiresAt {
		t.Fatalf("renew moved the hard deadline: %s → %s", minted.MaxExpiresAt, renewed.MaxExpiresAt)
	}
	// The renewed token authenticates.
	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer "+renewed.Token)
	if p, err := m.authenticate(r); err != nil || p.Name != "app" {
		t.Fatalf("renewed token auth: p=%+v err=%v", p, err)
	}
}

func TestSessionTransparentRefreshHeader(t *testing.T) {
	// Idle window 100ms, hard cap 1h: after 60ms a request is well past the
	// halfway point (50ms) and well before expiry (100ms), so the middleware hands
	// back a refreshed token in the header. The wide margin keeps the timing
	// robust under parallel test load.
	m := buildSessionTTL(t, 100*time.Millisecond, time.Hour)
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))

	var seen bool
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = true }))
	time.Sleep(60 * time.Millisecond)
	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !seen || w.Code != http.StatusOK {
		t.Fatalf("request should succeed: seen=%v code=%d", seen, w.Code)
	}
	refreshed := w.Header().Get(wire.HeaderSessionToken)
	if refreshed == "" || refreshed == tok {
		t.Fatalf("expected a refreshed session header distinct from the presented token, got %q", refreshed)
	}
	if w.Header().Get(wire.HeaderSessionExpires) == "" {
		t.Fatal("refresh should also carry X-Session-Expires")
	}
}

func TestSessionNoRefreshHeaderWhenNonRenewable(t *testing.T) {
	m := buildSession(t, 4*time.Millisecond) // non-renewable
	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	time.Sleep(3 * time.Millisecond)
	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get(wire.HeaderSessionToken) != "" {
		t.Fatal("a non-renewable session must never emit a refresh header")
	}
}

// TestSessionAuthCountsAsSeen: a session-authenticated request fires the seen-hook
// with the minting principal, so an enrolled device riding a session token stays
// "active" for idle GC (regression for the idle-GC vs session-token contradiction).
func TestSessionAuthCountsAsSeen(t *testing.T) {
	sum := sha256.Sum256([]byte("s3cr3t"))
	sec, _ := secret.New(nil)
	cfg := &config.Config{Auth: config.Auth{
		Principals: []config.Principal{principal("app", "bearer", map[string]any{"token_hash": hex.EncodeToString(sum[:])})},
		Session:    config.SessionTokens{Enabled: true, IdleTTL: time.Minute},
	}}
	a, err := New(cfg, sec, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var seen []string
	a.SetSeenHook(func(name string) { seen = append(seen, name) })
	m := a.Middleware(config.Listener{Name: "l", Auth: []string{"bearer", "session"}}, nil)

	tok := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t")) // minted via bearer (does NOT fire the hook)
	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if _, err := m.authenticate(r); err != nil {
		t.Fatalf("session auth: %v", err)
	}
	if len(seen) != 1 || seen[0] != "app" {
		t.Fatalf("session auth must fire the seen-hook with the principal, got %v", seen)
	}
}

// revokeToken DELETEs /_auth/session presenting the given token.
func revokeToken(t *testing.T, m *Middleware, token string) *httptest.ResponseRecorder {
	t.Helper()
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("revoke request must be handled by the middleware")
	}))
	r := httptest.NewRequest(http.MethodDelete, "/_auth/session", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// tokenField extracts just the token from a mint/renew response.
func tokenField(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v (%s)", err, w.Body.String())
	}
	return resp.Token
}

// authOK reports whether the token authenticates on m.
func authOK(t *testing.T, m *Middleware, token string) bool {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	_, err := m.authenticate(r)
	return err == nil
}

// A sliding session is ONE identity: a DELETE on any token in the renewal chain
// revokes the whole chain — the presented token and every sibling an earlier
// renewal issued (they share the session id). A leaked early token cannot outlive
// the logout that presents a renewed one.
func TestSessionRevokeRevokesWholeChain(t *testing.T) {
	// Security-critical direction: revoking the NEWER token (a logout with the
	// token in hand) must also invalidate an EARLIER, possibly-leaked one.
	m := buildSessionTTL(t, time.Minute, time.Hour) // renewable
	old := tokenFrom(t, mintToken(t, m, "Bearer s3cr3t"))
	renewed := tokenField(t, renewToken(t, m, old))
	if renewed == old || !strings.HasPrefix(renewed, sessionPrefix) {
		t.Fatalf("renew should return a new token, got %q", renewed)
	}
	if !authOK(t, m, old) || !authOK(t, m, renewed) {
		t.Fatal("both tokens should authenticate before revocation")
	}
	if w := revokeToken(t, m, renewed); w.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want 204", w.Code)
	}
	if authOK(t, m, renewed) {
		t.Fatal("the revoked token must be rejected")
	}
	if authOK(t, m, old) {
		t.Fatal("the earlier token in the chain must ALSO be revoked")
	}

	// The reverse direction, on a fresh session: revoking the OLDER token kills
	// the renewed sibling too.
	m2 := buildSessionTTL(t, time.Minute, time.Hour)
	first := tokenFrom(t, mintToken(t, m2, "Bearer s3cr3t"))
	second := tokenField(t, renewToken(t, m2, first))
	if w := revokeToken(t, m2, first); w.Code != http.StatusNoContent {
		t.Fatalf("revoke(first) status = %d, want 204", w.Code)
	}
	if authOK(t, m2, second) {
		t.Fatal("revoking an earlier token must revoke the renewed sibling too")
	}
}
