package transport

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"quicsql.net/config"
)

// corsBaseHeaders are the request headers every quicSQL client may legitimately
// send, pre-approved for browsers. They must be listed explicitly: the CORS `*`
// wildcard never covers Authorization, and an explicit list also lets browsers
// cache the preflight approval reliably. X-Libsql-Client-Version is what the
// libSQL JS SDKs stamp on every request.
var corsBaseHeaders = []string{
	"Authorization",
	"Content-Type",
	"X-Quicsql-Key",
	"X-Quicsql-Challenge",
	"X-Quicsql-Signature",
	"X-Libsql-Client-Version",
}

// corsAllowMethods is every method the API surface answers (plus OPTIONS itself).
// PUT is here for /_auth/session renewal.
const corsAllowMethods = "GET, POST, PUT, DELETE, OPTIONS"

// corsBaseExpose are response headers a browser script must be able to read
// without the operator listing them: the sliding-session renewal headers, which
// the SDK adopts to extend a session on use.
var corsBaseExpose = []string{"X-Quicsql-Session", "X-Quicsql-Session-Expires"}

// withCORS wraps next with cross-origin approval for browser callers. It is
// applied OUTSIDE the auth middleware: a preflight (OPTIONS +
// Access-Control-Request-Method) deliberately carries no credential, so it must
// be answered before authentication or every cross-origin call from a locked
// listener dies on a 401 preflight. Requests without an Origin header — every
// non-browser client — pass through untouched. A disallowed origin also passes
// through, just without approval headers: the browser enforces the block; the
// server's own auth still guards the data either way.
func withCORS(c config.CORS, next http.Handler) http.Handler {
	allowAll := slices.Contains(c.Origins, "*")
	allowed := make(map[string]bool, len(c.Origins))
	for _, o := range c.Origins {
		allowed[o] = true
	}
	allowHeaders := strings.Join(append(slices.Clone(corsBaseHeaders), c.AllowHeaders...), ", ")
	exposeHeaders := strings.Join(append(slices.Clone(corsBaseExpose), c.ExposeHeaders...), ", ")
	maxAge := strconv.FormatInt(int64(c.MaxAge/time.Second), 10)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || (!allowAll && !allowed[origin]) {
			// The response varies by Origin even when we DON'T approve it (a
			// disallowed or absent origin gets no CORS headers), so a shared cache
			// must not serve this to an allowed origin. Only meaningful for the
			// non-wildcard case, but harmless (and correct) to always send.
			if !allowAll {
				w.Header().Add("Vary", "Origin")
			}
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		if allowAll {
			h.Set("Access-Control-Allow-Origin", "*")
		} else {
			// Echoing a specific origin makes the response origin-dependent; Vary keeps
			// shared caches from serving one origin's approval to another.
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", corsAllowMethods)
			h.Set("Access-Control-Allow-Headers", allowHeaders)
			h.Set("Access-Control-Max-Age", maxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if exposeHeaders != "" {
			h.Set("Access-Control-Expose-Headers", exposeHeaders)
		}
		next.ServeHTTP(w, r)
	})
}
