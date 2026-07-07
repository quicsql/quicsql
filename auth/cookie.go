package auth

// Cookie session transport. The default transport is the Authorization header
// (CSRF-moot: no ambient credential). A feature can turn on cookie transport, which makes
// the session token ALSO travel as an HttpOnly cookie — needed for flows where the app
// can't attach a header (some browser autofill flows, plain links). Because a cookie is an
// ambient credential, enabling it auto-enables the CSRF defenses here: SameSite=Strict,
// HttpOnly, Secure (on TLS), and a Sec-Fetch-Site check on every state-changing request
// whose session arrived by cookie. Config additionally refuses wildcard CORS with
// cookie transport (load.go).

import (
	"net/http"
	"strings"
	"time"
)

// defaultSessionCookie is the brand-neutral default name for the session cookie. The
// `__Host-` prefix is a browser-enforced hardening (the cookie must be Secure, Path=/,
// and carry no Domain — all of which this transport already sets), not a brand. An
// operator/feature may override it with SetSessionCookieName for white-label deployments.
const defaultSessionCookie = "__Host-session"

// cookieTransport reports whether cookie transport is enabled (transport cookie|both).
func (a *Authenticator) cookieTransport() bool { return a.cookieMode }

// SetCookieMode turns cookie session transport on/off. A feature sets it during server
// setup — core auth implements the HttpOnly cookie + CSRF gate but doesn't decide when
// it's used.
func (a *Authenticator) SetCookieMode(on bool) { a.cookieMode = on }

// SetSessionCookieName overrides the session cookie name (white-label). An empty name
// keeps the brand-neutral default. Set it before serving. A `__Host-`-prefixed name is
// recommended (it requires Secure + Path=/ + no Domain, which this transport satisfies).
func (a *Authenticator) SetSessionCookieName(name string) {
	if name != "" {
		a.cookieName = name
	}
}

// WriteSessionTransport applies the configured transport to a freshly minted/renewed
// session token: with cookie transport on, it sets the session cookie (the JSON body
// still carries the token either way — header clients ignore the cookie). The account
// handler calls this from login/recovery mints; serveSession calls it for /_auth/session.
func (a *Authenticator) WriteSessionTransport(w http.ResponseWriter, r *http.Request, tok string, exp time.Time) {
	if !a.cookieTransport() {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    tok,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		// Cookie transport presupposes production TLS; set Secure unconditionally so a
		// TLS-terminating proxy (r.TLS == nil at this hop) can't cause the session cookie
		// to be issued without it and leak over a plaintext segment.
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionTransport expires the session cookie (logout).
func (a *Authenticator) ClearSessionTransport(w http.ResponseWriter, r *http.Request) {
	if !a.cookieTransport() {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		// Cookie transport presupposes production TLS; set Secure unconditionally so a
		// TLS-terminating proxy (r.TLS == nil at this hop) can't cause the session cookie
		// to be issued without it and leak over a plaintext segment.
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// sessionTokenFrom extracts the request's st_ session token from the Authorization
// header, falling back to the session cookie when cookie transport is on. fromCookie
// tells the caller whether the CSRF gate applies (only ambient credentials need it).
func (a *Authenticator) sessionTokenFrom(r *http.Request) (tok string, fromCookie, ok bool) {
	if t, has := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); has {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(t, sessionPrefix) {
			return t, false, true
		}
		return "", false, false // some other bearer credential — not ours
	}
	if !a.cookieTransport() {
		return "", false, false
	}
	c, err := r.Cookie(a.cookieName)
	if err != nil || !strings.HasPrefix(c.Value, sessionPrefix) {
		return "", false, false
	}
	return c.Value, true, true
}

// csrfSafe gates state-changing requests whose session arrived as a cookie. Reads are
// exempt (cross-origin reads are stopped by CORS; there are no state-changing
// GETs). Browsers send Sec-Fetch-Site on every request: same-origin and none (direct
// navigation) pass; same-site and cross-site are forged/embedded contexts and fail.
// An absent header means a non-browser client, which carries no ambient cookie jar an
// attacker can ride — allowed.
func csrfSafe(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	default:
		return false
	}
}
