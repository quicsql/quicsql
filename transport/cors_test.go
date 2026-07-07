package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"quicsql.net/config"
	"quicsql.net/internal/wire"
)

func corsCfg(origins ...string) config.CORS {
	return config.CORS{Enabled: true, Origins: origins, MaxAge: 2 * time.Hour}
}

// denyAll stands in for the auth middleware: every request that reaches it is
// rejected, so a preflight that passes through would come back 401.
var denyAll = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
})

func preflight(origin string) *http.Request {
	r := httptest.NewRequest(http.MethodOptions, "/app/query", nil)
	r.Header.Set("Origin", origin)
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	return r
}

func TestCORSPreflightBypassesAuth(t *testing.T) {
	h := withCORS(corsCfg("*"), denyAll)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preflight("https://app.example.com"))

	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204 (must not reach auth)", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Allow-Origin = %q, want *", got)
	}
	allow := w.Header().Get("Access-Control-Allow-Headers")
	for _, want := range []string{"Authorization", "Content-Type", wire.HeaderKeyringSignature} {
		if !strings.Contains(allow, want) {
			t.Errorf("Allow-Headers %q missing %q", allow, want)
		}
	}
	if got := w.Header().Get("Access-Control-Max-Age"); got != "7200" {
		t.Errorf("Max-Age = %q, want 7200", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Errorf("Allow-Methods = %q, want POST included", got)
	}
}

func TestCORSEchoesAllowedOriginWithVary(t *testing.T) {
	h := withCORS(corsCfg("https://app.example.com"), denyAll)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preflight("https://app.example.com"))

	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("Allow-Origin = %q, want the echoed origin", got)
	}
	if got := w.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Errorf("Vary = %q, want Origin", got)
	}
}

func TestCORSDisallowedOriginPassesThroughWithoutHeaders(t *testing.T) {
	h := withCORS(corsCfg("https://app.example.com"), denyAll)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preflight("https://evil.example.com"))

	// The request reaches the inner handler (auth still guards it) but gets no
	// CORS approval — the browser enforces the block.
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 passthrough", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q, want none", got)
	}
}

func TestCORSNonBrowserRequestUntouched(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := withCORS(corsCfg("*"), inner)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/app/query", nil)) // no Origin

	if w.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want passthrough to inner handler", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q, want none without an Origin header", got)
	}
}

func TestCORSActualRequestGetsOriginAndExposeHeaders(t *testing.T) {
	c := corsCfg("*")
	c.ExposeHeaders = []string{"X-Custom"}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := withCORS(c, inner)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/app/query", nil)
	r.Header.Set("Origin", "https://app.example.com")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Allow-Origin = %q, want *", got)
	}
	if got := w.Header().Get("Access-Control-Expose-Headers"); !strings.Contains(got, "X-Custom") || !strings.Contains(got, wire.HeaderSessionToken) {
		t.Fatalf("Expose-Headers = %q, want the base session headers plus X-Custom", got)
	}
}

// A bare OPTIONS without Access-Control-Request-Method is not a preflight and
// must reach the inner handler.
func TestCORSPlainOptionsIsNotPreflight(t *testing.T) {
	h := withCORS(corsCfg("*"), denyAll)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/app/query", nil)
	r.Header.Set("Origin", "https://app.example.com")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 passthrough for a non-preflight OPTIONS", w.Code)
	}
}
