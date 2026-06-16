// Package httpapi is the transport-neutral HTTP surface for quicSQL. Phase 1
// serves the thin native-JSON endpoint (POST /<db>/query) over an ordinary
// http.Handler, so it runs identically on every transport a later phase adds
// (HTTP/1.1, h2/h2c, HTTP/3, WebSocket, UDS). Routing resolves the target
// database from the URL path (default) or the Host subdomain, with server-scoped
// reserved paths (`/_health`, and `/_*` reserved) resolved first.
package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"gosqlite.org/server/authz"
	"gosqlite.org/server/config"
	"gosqlite.org/server/engine"
	"gosqlite.org/server/internal/httpjson"
	"gosqlite.org/server/limits"
	"gosqlite.org/server/obs"
	"gosqlite.org/server/registry"
	"gosqlite.org/server/session"
)

const (
	defaultMaxBody = 8 << 20 // 8 MiB request-body cap (query/pipeline/changeset)
	defaultMaxBlob = 1 << 30 // 1 GiB cap for a single streamed large object
)

// Handler is the quicSQL HTTP handler. The auth middleware (package auth) has
// already attached the request's principal to the context by the time a request
// reaches here; the handler enforces the per-database capability via policy.
type Handler struct {
	reg      *registry.Registry
	eng      *engine.Engine
	route    config.Routing
	policy   *authz.Policy
	admin    http.Handler // control plane at /_admin (nil = disabled)
	metrics  obs.Metrics  // request counters/latency (nil = disabled)
	limiter  *limits.Limiter
	maxBody  int64
	maxBlob  int64         // cap for a single streamed large object (blob write)
	stmtTO   time.Duration // per-request statement timeout (0 = none)
	log      *slog.Logger
	sessions *session.Store // Hrana interactive-transaction streams (nil = disabled)
	// blobStores caches an opened *blobstore.Store per (db handle, name) so blob
	// ops don't re-open (and re-run the idempotent CREATE TABLE) per request, and
	// so a provisioned store's options survive across ops. Keyed like the local
	// lob cache (by db handle), so a reopened database gets a fresh entry.
	blobStores sync.Map
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

// WithMaxBlob caps a single streamed large object (blob write). Non-positive
// keeps the default. Unlike WithMaxBody this bounds a streamed body, not a
// buffered one, so it can be large without a matching memory cost.
func WithMaxBlob(n int64) Option {
	return func(h *Handler) {
		if n > 0 {
			h.maxBlob = n
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

// WithPolicy sets the authorization policy. Without it the handler defaults to
// open mode (every principal is read-write on every database), preserving the
// pre-auth behavior for tests and no-auth deployments.
func WithPolicy(p *authz.Policy) Option {
	return func(h *Handler) {
		if p != nil {
			h.policy = p
		}
	}
}

// WithAdmin mounts the control-plane handler at /_admin. Nil (the default)
// leaves the control plane disabled — /_admin then 404s like any reserved path.
func WithAdmin(a http.Handler) Option {
	return func(h *Handler) { h.admin = a }
}

// WithMetrics sets the metrics sink; when it also implements obs.Exposer, the
// /_metrics endpoint renders it.
func WithMetrics(m obs.Metrics) Option {
	return func(h *Handler) { h.metrics = m }
}

// WithLimiter sets the admission-control limiter (per-principal rate + per-db
// concurrency). Nil admits every request.
func WithLimiter(l *limits.Limiter) Option {
	return func(h *Handler) { h.limiter = l }
}

// New builds the handler. When neither path nor host routing is configured, path
// routing is enabled by default.
func New(reg *registry.Registry, eng *engine.Engine, route config.Routing, opts ...Option) *Handler {
	h := &Handler{reg: reg, eng: eng, route: route, policy: authz.NewPolicy(true), maxBody: defaultMaxBody, maxBlob: defaultMaxBlob, log: slog.Default()}
	if !h.route.ByPath && !h.route.ByHost {
		h.route.ByPath = true
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// handleMetrics renders the metrics registry in OpenMetrics/Prometheus text. It
// exposes only aggregate counts (and database names as labels), no secrets.
// Unlike /_health it is NOT whitelisted by the auth middleware, so it is subject
// to the listener's auth — scrape it on a none/localhost listener, and keep it
// off a public listener if database names are sensitive.
func (h *Handler) handleMetrics(w http.ResponseWriter) {
	e, ok := h.metrics.(obs.Exposer)
	if !ok {
		writeErr(w, http.StatusNotFound, "metrics not enabled")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	e.WriteOpenMetrics(w)
}

// meter applies the admission limiter and, for an admitted request, counts it and
// times it. It returns a release func (always deferred by the caller) and
// ok=false after writing a rejection (429 rate / 503 concurrency). A rejected
// request is NOT counted or timed — quicsql_requests_total is served requests,
// not arrivals. It runs after authorize, so only admitted-by-capability requests
// are metered.
func (h *Handler) meter(w http.ResponseWriter, r *http.Request, db string) (func(), bool) {
	p := authz.FromContext(r.Context())
	var release func()
	if h.limiter != nil {
		var ok bool
		var reason string
		release, ok, reason = h.limiter.Allow(p.Name, db)
		if !ok {
			if reason == "rate" {
				writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
			} else {
				writeErr(w, http.StatusServiceUnavailable, "database busy: too many concurrent requests")
			}
			return nil, false
		}
	}
	if h.metrics != nil {
		h.metrics.IncRequests(db, p.Name)
	}
	start := time.Now()
	return func() {
		if release != nil {
			release()
		}
		if h.metrics != nil {
			h.metrics.ObserveLatency(db, time.Since(start))
		}
	}, true
}

// authorize resolves the caller's capability on db. It returns the level and
// true when the principal may at least read; otherwise it writes a 403 and
// returns false. A caller that needs write capability checks level.CanWrite.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, db string) (authz.Level, bool) {
	p := authz.FromContext(r.Context())
	lvl := h.policy.Level(p, db)
	if !lvl.CanRead() {
		writeErr(w, http.StatusForbidden, "forbidden: no access to this database")
		return authz.None, false
	}
	return lvl, true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Server-scoped reserved routes resolve before any database addressing.
	switch {
	case r.URL.Path == "/_health":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	case r.URL.Path == "/_metrics":
		h.handleMetrics(w)
		return
	case r.URL.Path == "/_admin" || strings.HasPrefix(r.URL.Path, "/_admin/"):
		if h.admin == nil {
			writeErr(w, http.StatusNotFound, "control plane not enabled")
			return
		}
		h.admin.ServeHTTP(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/_"):
		// _health, _metrics, _admin, and _auth are handled above; the queryable
		// _server introspection database is a later phase.
		writeErr(w, http.StatusNotFound, "reserved path not available")
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
	case "/export":
		h.handleExport(w, r, db)
	case "/changeset/apply":
		h.handleChangesetApply(w, r, db)
	case "/changeset/invert":
		h.handleChangesetInvert(w, r, db)
	case "/changeset/concat":
		h.handleChangesetConcat(w, r, db)
	case "/blob/provision", "/blob/create", "/blob/write", "/blob/read", "/blob/size", "/blob/delete":
		h.handleBlob(w, r, db, endpoint)
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

// writeJSON marshals into a buffer BEFORE writing the status line (via the shared
// httpjson helper), so a marshal failure becomes a clean 500 error envelope
// instead of a committed 200 with a truncated/empty body.
func writeJSON(w http.ResponseWriter, status int, v any) { httpjson.Write(w, status, v) }

const bodyReadDeadline = 30 * time.Second

// boundBodyRead sets a per-request read deadline so a slow-trickle body can't
// hold a stream open indefinitely. This covers the h2/h2c/h3 case where a
// connection-level ReadTimeout can't be used (it would kill legitimate
// multiplexed streams); on h1 it complements the server ReadTimeout.
func boundBodyRead(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyReadDeadline))
}

// errBodyTooLarge is returned by readBody when the request body exceeds the
// configured cap. Handlers surface it as 413, rather than silently truncating.
var errBodyTooLarge = errors.New("request body exceeds the maximum allowed size")

// readBody reads the request body under the configured size cap. It reads one
// byte past the cap so an over-cap body is rejected (errBodyTooLarge) instead of
// silently truncated — otherwise a blob write or changeset larger than the cap
// would be stored/applied truncated and reported as success.
func (h *Handler) readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, h.maxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > h.maxBody {
		return nil, errBodyTooLarge
	}
	return b, nil
}

// writeReadBodyErr maps a readBody error to a status: 413 for an over-cap body,
// 400 otherwise. Used by the endpoints that accept large payloads.
func writeReadBodyErr(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyTooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, "request body exceeds the maximum allowed size")
		return
	}
	writeErr(w, http.StatusBadRequest, "read body")
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
	case engine.IsNotAuthorized(err):
		writeErr(w, http.StatusForbidden, "forbidden: read-only (write not permitted)")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeErr(w, http.StatusGatewayTimeout, "statement timed out")
	default:
		writeAPIError(w, http.StatusOK, toAPIError(err))
	}
}
