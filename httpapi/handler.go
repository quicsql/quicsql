// Package httpapi is the transport-neutral HTTP surface for quicSQL. Phase 1
// serves the thin native-JSON endpoint (POST /<db>/query) over an ordinary
// http.Handler, so it runs identically on every transport a later phase adds
// (HTTP/1.1, h2/h2c, HTTP/3, WebSocket, UDS). Routing resolves the target
// database from the URL path (default) or the Host subdomain, with server-scoped
// reserved paths (`/_health`, and `/_*` reserved) resolved first.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gosqlite.org/server/config"
	"gosqlite.org/server/engine"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/session"
)

const defaultMaxBody = 8 << 20 // 8 MiB request-body cap

// Handler is the quicSQL HTTP handler. Auth is a Phase 4 seam; Phase 1/2 serve
// every request (bind to localhost/UDS).
type Handler struct {
	reg      *registry.Registry
	eng      *engine.Engine
	route    config.Routing
	maxBody  int64
	stmtTO   time.Duration // per-request statement timeout (0 = none)
	log      *slog.Logger
	sessions *session.Store // Hrana interactive-transaction streams (nil = disabled)
}

// Option customizes a Handler.
type Option func(*Handler)

// WithMaxBody caps the request body size (bytes). Non-positive keeps the default.
func WithMaxBody(n int64) Option {
	return func(h *Handler) {
		if n > 0 {
			h.maxBody = n
		}
	}
}

// WithStatementTimeout bounds each request's execution via the request context.
func WithStatementTimeout(d time.Duration) Option {
	return func(h *Handler) { h.stmtTO = d }
}

// WithLogger sets the handler's logger (server-side error logging).
func WithLogger(l *slog.Logger) Option {
	return func(h *Handler) {
		if l != nil {
			h.log = l
		}
	}
}

// WithSessions enables the Hrana pipeline endpoints, backed by the given store.
func WithSessions(s *session.Store) Option {
	return func(h *Handler) { h.sessions = s }
}

// New builds the handler. When neither path nor host routing is configured, path
// routing is enabled by default.
func New(reg *registry.Registry, eng *engine.Engine, route config.Routing, opts ...Option) *Handler {
	h := &Handler{reg: reg, eng: eng, route: route, maxBody: defaultMaxBody, log: slog.Default()}
	if !h.route.ByPath && !h.route.ByHost {
		h.route.ByPath = true
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Server-scoped reserved routes resolve before any database addressing.
	switch {
	case r.URL.Path == "/_health":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	case strings.HasPrefix(r.URL.Path, "/_"):
		// _metrics / _admin / _server arrive in later phases.
		writeErr(w, http.StatusNotFound, "reserved path not available in this phase")
		return
	}

	db, endpoint, err := h.resolve(r)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	switch endpoint {
	case "/query":
		h.handleQuery(w, r, db)
	case "/v2/pipeline", "/v3/pipeline":
		h.handlePipeline(w, r, db)
	case "/v2", "/v3":
		w.WriteHeader(http.StatusOK) // Hrana version-support probe
	case "/v2/cursor", "/v3/cursor":
		writeErr(w, http.StatusNotImplemented, "cursor requests are not implemented yet")
	default:
		writeErr(w, http.StatusNotFound, "unknown endpoint "+endpoint)
	}
}

var errNoDatabase = errors.New("no database in request (name it in the path, host, or set a default)")

// resolve derives the target database and the endpoint sub-path. The path
// carries the database (`/<db>/<endpoint>`) unless its first segment is a known
// endpoint token, in which case host routing (or the default) supplies it — so
// when both a path db-prefix and a host subdomain are present, the path wins.
func (h *Handler) resolve(r *http.Request) (db, endpoint string, err error) {
	segs := splitPath(r.URL.Path)
	if h.route.ByPath && len(segs) >= 1 && !isEndpointToken(segs[0]) {
		return validated(segs[0], "/"+strings.Join(segs[1:], "/"))
	}
	if h.route.ByHost && h.route.HostSuffix != "" {
		if base, ok := strings.CutSuffix(hostname(r.Host), h.route.HostSuffix); ok {
			if d := strings.TrimSuffix(base, "."); d != "" {
				return validated(d, r.URL.Path)
			}
		}
	}
	if h.route.DefaultDB != "" {
		return validated(h.route.DefaultDB, r.URL.Path)
	}
	return "", "", errNoDatabase
}

var errInvalidDB = errors.New("invalid or reserved database name")

// validated rejects a resolved database name that is reserved, an endpoint
// token, or path-shaped — via config.ValidDBName, the SAME predicate config
// validation uses. The guard applies to path-, host-, and default-derived names
// alike, so a reserved name reached via a Host subdomain can't slip past the
// path-prefix check.
func validated(db, endpoint string) (string, string, error) {
	if !config.ValidDBName(db) {
		return "", "", errInvalidDB
	}
	return db, endpoint, nil
}

// isEndpointToken reports whether a leading path segment is an endpoint name
// (so it is NOT a database). Source of truth is config.EndpointTokens, which is
// also what config validation forbids as a database name.
func isEndpointToken(s string) bool { return config.EndpointTokens[s] }

func splitPath(p string) []string {
	var out []string
	for s := range strings.SplitSeq(strings.Trim(p, "/"), "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func hostname(h string) string {
	host, _, _ := strings.Cut(h, ":")
	return host
}

// writeJSON marshals into a buffer BEFORE writing the status line, so a marshal
// failure becomes a clean 500 error envelope instead of a committed 200 with a
// truncated/empty body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"internal: response encoding failed"}}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(buf, '\n'))
}

const bodyReadDeadline = 30 * time.Second

// boundBodyRead sets a per-request read deadline so a slow-trickle body can't
// hold a stream open indefinitely. This covers the h2/h2c/h3 case where a
// connection-level ReadTimeout can't be used (it would kill legitimate
// multiplexed streams); on h1 it complements the server ReadTimeout.
func boundBodyRead(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyReadDeadline))
}

// readBody reads the request body under the configured size cap.
func (h *Handler) readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, h.maxBody))
}

// withTimeout applies the per-statement timeout (if configured) to ctx.
func (h *Handler) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if h.stmtTO > 0 {
		return context.WithTimeout(ctx, h.stmtTO)
	}
	return ctx, func() {}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeAPIError(w, status, apiError{Message: msg})
}

// writeAPIError is the single error-envelope writer; every error response goes
// through here so the schema is defined once.
func writeAPIError(w http.ResponseWriter, status int, e apiError) {
	writeJSON(w, status, errorEnvelope{Error: e})
}

// writeGetError maps a registry open failure to a status, logging internal
// detail server-side rather than leaking a path/driver string to the client.
func (h *Handler) writeGetError(w http.ResponseWriter, db string, err error) {
	switch {
	case errors.Is(err, registry.ErrUnknownDB):
		writeErr(w, http.StatusNotFound, "unknown database")
	case errors.Is(err, registry.ErrReserved), errors.Is(err, registry.ErrBusy):
		writeErr(w, http.StatusServiceUnavailable, "database temporarily unavailable")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeErr(w, http.StatusGatewayTimeout, "request timed out")
	default:
		h.log.Error("quicsql/http: open database", "db", db, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

// writeRunError maps a statement execution error: policy denials → 403, timeouts
// → 504, SQL faults → 200 with the safe error envelope.
func (h *Handler) writeRunError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, engine.ErrDenied):
		writeErr(w, http.StatusForbidden, err.Error())
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeErr(w, http.StatusGatewayTimeout, "statement timed out")
	default:
		writeAPIError(w, http.StatusOK, toAPIError(err))
	}
}
