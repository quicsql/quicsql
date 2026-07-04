// Package sqldriver registers a database/sql driver named "quicsql" that
// speaks to a quicSQL server, so ordinary database/sql code connects to a remote
// database the same way it opens a local one:
//
//	import _ "quicsql.net/client/sqldriver"
//	db, _ := sql.Open("quicsql", "quicsql://127.0.0.1:7775/users?transport=h1")
//	db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n)
//
// Importing this package also teaches gosqlite.org's built-in "sqlite" driver to
// dispatch the same DSN, so callers that already use gosqlite for local files can
// point at a server by DSN alone:
//
//	import _ "quicsql.net/client/sqldriver"
//	db, _ := sql.Open("sqlite", "quicsql://127.0.0.1:7775/users?transport=h1")
//
// DSN: one scheme, transport as a parameter.
//
//	quicsql://host:port/db?transport=h1              # cleartext HTTP/1.1 (default)
//	quicsql://host:port/db?transport=h2c             # cleartext HTTP/2
//	quicsql://host:port/db?transport=h2&insecure=1   # HTTP/2 over TLS (dev cert)
//	quicsql://host:port/db?transport=h3&insecure=1   # HTTP/3 over QUIC
//	quicsql:///db?transport=unix&socket=/run/quicsql/sql.sock
//
// Credentials via query params: ?token=<bearer> or ?user=<u>&password=<p>. mTLS
// client certs and the ed25519 challenge/response are not expressible in a DSN —
// build a *client.Client directly (WithClientCert / WithEd25519) and pass it to
// OpenConnectorClient for those.
//
// A DSN that carries a credential is refused on a channel that would expose it:
// the plaintext transports (h1, h2c) or h2/h3 with insecure=1 (unverified TLS).
// Use verified TLS or a unix socket, or set allow_insecure_auth=1 to override on a
// trusted local/dev link.
//
// Transactions are supported: BeginTx opens a session-pinned Hrana stream so that
// every statement in the transaction (and SAVEPOINT nesting) runs on the same
// server-side connection. Autocommit statements use the faster stateless endpoint.
package sqldriver

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	sqlite "gosqlite.org"
	"quicsql.net/client"
)

func init() {
	sql.Register("quicsql", drv{})
	// Teach gosqlite's built-in driver to open quicsql:// DSNs by forwarding.
	sqlite.RegisterRemoteScheme("quicsql", openConn)
}

type drv struct{}

// Open satisfies driver.Driver (the path used by the gosqlite dispatch hook).
func (drv) Open(dsn string) (driver.Conn, error) { return openConn(dsn) }

// OpenConnector satisfies driver.DriverContext, parsing the DSN once.
func (drv) OpenConnector(dsn string) (driver.Connector, error) { return OpenConnector(dsn) }

// openConn builds a connector for the DSN and hands out a connection. It is the
// path database/sql uses when the driver has no DriverContext (e.g. via the
// gosqlite dispatch hook, sql.Open("sqlite", "quicsql://…")). Each call parses the
// DSN and lazily builds a client; database/sql pools the resulting conns, so this
// is called rarely. (The recommended sql.Open("quicsql", …) path uses
// OpenConnector, which builds one connector — and shares one client — per *sql.DB.)
func openConn(dsn string) (driver.Conn, error) {
	c, err := OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return c.Connect(context.Background())
}

// OpenConnector builds a connector from a quicsql DSN.
func OpenConnector(dsn string) (driver.Connector, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		// Both the %q arg and url.Parse's own *url.Error embed the raw DSN, which
		// may carry ?token=/password. Redact the arg and unwrap to the inner reason
		// (which omits the URL) so a mistyped secret-bearing DSN never reaches a log.
		reason := err
		if ue, ok := errors.AsType[*url.Error](err); ok {
			reason = ue.Err
		}
		return nil, fmt.Errorf("quicsql: bad DSN %q: %w", redactDSN(dsn), reason)
	}
	if u.Scheme != "quicsql" {
		return nil, fmt.Errorf("quicsql: DSN scheme must be \"quicsql\", got %q", u.Scheme)
	}
	// The driver takes credentials from query params, not URL userinfo. A DSN like
	// quicsql://user:pw@host/db would otherwise send NO credential (silently
	// unauthenticated) AND slip past the credential-transport guard below — reject it
	// so the mistake is loud, not silent.
	if u.User != nil {
		return nil, errors.New("quicsql: put credentials in query params (?token= or ?user=&password=), not the URL userinfo (user:pw@host)")
	}
	q := u.Query()
	insecure := q.Get("insecure") == "1" || q.Get("insecure") == "true"
	hasCredential := q.Get("token") != "" || q.Get("user") != ""
	var opts []client.Option
	if t := q.Get("token"); t != "" {
		opts = append(opts, client.WithBearer(t))
	}
	if usr := q.Get("user"); usr != "" {
		opts = append(opts, client.WithBasicAuth(usr, q.Get("password")))
	}

	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		return nil, errors.New("quicsql: DSN is missing the database name (quicsql://host/DB?…)")
	}

	transport := q.Get("transport")
	if transport == "" {
		transport = "h1"
	}

	// Fail closed if a credential would ride an unverified or cleartext channel: a
	// bearer token / password sent over h1 or h2c (plaintext), or over h2/h3 with
	// insecure=1 (unverified TLS, so MITM-readable), is exposed on the wire. A DSN
	// is often one opaque string to the caller (e.g. liteorm's sqlite.Open(dsn)),
	// so we refuse rather than silently leak. allow_insecure_auth=1 is the explicit
	// opt-out for trusted local/dev links. (unix sockets are local and exempt.)
	allowInsecureAuth := q.Get("allow_insecure_auth") == "1" || q.Get("allow_insecure_auth") == "true"
	if hasCredential && !allowInsecureAuth {
		switch {
		case transport == "h1" || transport == "h2c":
			return nil, fmt.Errorf("quicsql: refusing to send a credential over cleartext transport=%q; use h2/h3 over verified TLS or a unix socket, or set allow_insecure_auth=1 to override", transport)
		case (transport == "h2" || transport == "h3") && insecure:
			return nil, fmt.Errorf("quicsql: refusing to send a credential over transport=%q with insecure=1 (unverified TLS); use a verified certificate (WithRootCA) or set allow_insecure_auth=1 to override", transport)
		}
	}
	var mk func() *client.Client
	switch transport {
	case "h1":
		mk = func() *client.Client { return client.H1(u.Host, opts...) }
	case "h2c":
		mk = func() *client.Client { return client.H2C(u.Host, opts...) }
	case "h2":
		mk = func() *client.Client { return client.H2TLS(u.Host, insecure, opts...) }
	case "h3":
		mk = func() *client.Client { return client.H3(u.Host, insecure, opts...) }
	case "unix":
		socket := q.Get("socket")
		if socket == "" {
			return nil, errors.New("quicsql: unix transport needs ?socket=<path>")
		}
		mk = func() *client.Client { return client.Unix(socket, opts...) }
	default:
		return nil, fmt.Errorf("quicsql: unknown transport %q (want h1|h2c|h2|h3|unix)", transport)
	}
	return &connector{db: db, mk: mk, ownClient: true}, nil
}

// redactDSN strips secrets from a DSN before it is embedded in an error message:
// URL userinfo (password) and the sensitive query params (token/password/key/
// secret). database/sql opens are lazy, so a malformed secret-bearing DSN surfaces
// as an error on first use that a consumer's statement logger may record verbatim —
// this keeps the bearer token out of that log. An unparseable DSN (which may still
// contain a token) collapses to a placeholder rather than being echoed.
func redactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "<redacted DSN>"
	}
	if u.User != nil {
		u.User = url.User(u.User.Username()) // drop any password
	}
	q := u.Query()
	for _, k := range []string{"token", "password", "key", "secret"} {
		if q.Has(k) {
			q.Set(k, "REDACTED")
		}
	}
	u.RawQuery = q.Encode()
	return u.Redacted() // also masks a userinfo password
}

// OpenConnectorClient wraps a pre-built *client.Client (for auth a DSN cannot
// express — mTLS client certs, ed25519) as a connector for db. Use it with
// sql.OpenDB.
func OpenConnectorClient(cl *client.Client, db string) driver.Connector {
	c := &connector{db: db, mk: func() *client.Client { return cl }}
	c.once.Do(func() { c.cl = cl })
	return c
}

// connector lazily builds one shared client for every database/sql connection it
// hands out; the client's HTTP transport pools connections underneath. ownClient
// marks a client this connector built from a DSN (so sql.DB.Close should close
// it) versus one supplied by the caller via OpenConnectorClient (whose lifetime
// the caller owns).
type connector struct {
	db        string
	mk        func() *client.Client
	once      sync.Once
	cl        *client.Client
	ownClient bool
}

func (c *connector) Connect(context.Context) (driver.Conn, error) {
	c.once.Do(func() { c.cl = c.mk() })
	return &conn{db: c.db, cl: c.cl}, nil
}
func (c *connector) Driver() driver.Driver { return drv{} }

// Close satisfies io.Closer so sql.DB.Close() releases the underlying client's
// transport (notably HTTP/3's background goroutines and UDP socket) instead of
// leaking it. Only a DSN-built client is closed here; a caller-supplied client
// (OpenConnectorClient) is left for the caller to close. database/sql calls this
// after the conn pool has drained, so reading c.cl needs no extra sync.
func (c *connector) Close() error {
	if c.ownClient && c.cl != nil {
		return c.cl.Close()
	}
	return nil
}

// conn is one database/sql connection. While tx is non-nil the connection is
// inside a transaction: every statement routes to the session-pinned Hrana
// stream so it lands on the same server-side connection. While capture is
// non-nil, a changeset capture is open on a pinned stream (see StartCapture); the
// connection's statements route there so the server-side SESSION records them.
type conn struct {
	db      string
	cl      *client.Client
	tx      *client.Stream
	capture *client.Stream
}

func (c *conn) Prepare(query string) (driver.Stmt, error) { return &stmt{c: c, query: query}, nil }

// ResetSession runs before database/sql reuses a pooled conn. If a transaction or
// changeset capture was left open (a caller that reached StartCapture via
// sql.Conn.Raw and skipped EndCapture, or a panic), the conn is dirty — its
// statements would route onto the leftover pinned stream. Discard it so the pool
// never re-hands a conn whose statements would land on someone else's stream.
func (c *conn) ResetSession(context.Context) error {
	if c.tx != nil || c.capture != nil {
		return driver.ErrBadConn // Close() (called on discard) tears down the stream
	}
	return nil
}

func (c *conn) Close() error {
	if c.tx != nil {
		s := c.tx
		c.tx = nil
		_ = s.Close(context.Background())
	}
	if c.capture != nil {
		s := c.capture
		c.capture = nil
		_ = s.Close(context.Background())
	}
	return nil
}

func (c *conn) Begin() (driver.Tx, error) { return c.begin(context.Background()) }

// BeginTx satisfies driver.ConnBeginTx. SQLite runs serializable, so the
// isolation level and read-only hint carry no extra meaning here; the server
// enforces writability from the caller's grant.
func (c *conn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	return c.begin(ctx)
}

func (c *conn) begin(ctx context.Context) (driver.Tx, error) {
	if c.tx != nil || c.capture != nil {
		return nil, errors.New("quicsql: connection is busy (transaction or capture in progress)")
	}
	s := c.cl.OpenStream(c.db)
	if _, err := s.Exec(ctx, "BEGIN", nil); err != nil {
		_ = s.Close(ctx)
		return nil, err
	}
	c.tx = s
	return &tx{c: c}, nil
}

func (c *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	vals, err := values(args)
	if err != nil {
		return nil, err
	}
	res, err := c.run(ctx, query, vals)
	if err != nil {
		return nil, err
	}
	return &rows{res: res}, nil
}

func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	vals, err := values(args)
	if err != nil {
		return nil, err
	}
	res, err := c.run(ctx, query, vals)
	if err != nil {
		return nil, err
	}
	return result{res}, nil
}

// run dispatches a statement: to the pinned stream inside a transaction, else to
// the stateless autocommit endpoint. The native endpoint auto-detects read vs
// write, and a Hrana execute returns rows too, so one path serves Query and Exec.
func (c *conn) run(ctx context.Context, query string, vals []any) (*client.Result, error) {
	switch {
	case c.capture != nil:
		return c.capture.Exec(ctx, query, vals)
	case c.tx != nil:
		return c.tx.Exec(ctx, query, vals)
	default:
		return c.cl.Query(ctx, c.db, query, vals...)
	}
}

// --- native-op methods, reached from database/sql via sql.Conn.Raw ---
//
// These let an out-of-tree package (e.g. LiteORM's changeset backend) drive the
// server's changeset wire protocol without importing this package: it type-
// asserts the driver conn to a structural interface with these methods.

// ApplyChangeset applies a changeset to this conn's database.
func (c *conn) ApplyChangeset(ctx context.Context, cs []byte) error {
	return c.cl.ApplyChangeset(ctx, c.db, cs)
}

// InvertChangeset returns the inverse of cs.
func (c *conn) InvertChangeset(ctx context.Context, cs []byte) ([]byte, error) {
	return c.cl.InvertChangeset(ctx, c.db, cs)
}

// ConcatChangesets returns the concatenation of a then b.
func (c *conn) ConcatChangesets(ctx context.Context, a, b []byte) ([]byte, error) {
	return c.cl.ConcatChangesets(ctx, c.db, a, b)
}

// StartCapture opens a pinned stream, begins a SESSION capture over it, and
// routes this connection's subsequent statements to that stream so they are
// recorded. Pair with CaptureChangeset then EndCapture.
func (c *conn) StartCapture(ctx context.Context, tables []string) error {
	if c.capture != nil || c.tx != nil {
		return errors.New("quicsql: connection is busy (transaction or capture in progress)")
	}
	s := c.cl.OpenStream(c.db)
	if err := s.SessionStart(ctx, tables); err != nil {
		_ = s.Close(ctx)
		return err
	}
	c.capture = s
	return nil
}

// CaptureChangeset returns the changeset recorded since StartCapture.
func (c *conn) CaptureChangeset(ctx context.Context) ([]byte, error) {
	if c.capture == nil {
		return nil, errors.New("quicsql: no capture in progress")
	}
	return c.capture.SessionChangeset(ctx)
}

// EndCapture closes the capture stream, releasing the pinned server connection.
func (c *conn) EndCapture(ctx context.Context) error {
	if c.capture == nil {
		return nil
	}
	s := c.capture
	c.capture = nil
	return s.Close(ctx)
}

// Blob* delegate to the client's whole-object blobstore ops (reached via
// sql.Conn.Raw by LiteORM's lob backend).
func (c *conn) BlobProvision(ctx context.Context, store string, chunk int, compress string, dedup bool) error {
	return c.cl.BlobProvision(ctx, c.db, store, chunk, compress, dedup)
}
func (c *conn) BlobCreate(ctx context.Context, store string) (int64, error) {
	return c.cl.BlobCreate(ctx, c.db, store)
}
func (c *conn) BlobWrite(ctx context.Context, store string, id int64, r io.Reader) (int64, error) {
	return c.cl.BlobWrite(ctx, c.db, store, id, r)
}
func (c *conn) BlobRead(ctx context.Context, store string, id int64) ([]byte, error) {
	return c.cl.BlobRead(ctx, c.db, store, id)
}
func (c *conn) BlobSize(ctx context.Context, store string, id int64) (int64, error) {
	return c.cl.BlobSize(ctx, c.db, store, id)
}
func (c *conn) BlobDelete(ctx context.Context, store string, id int64) error {
	return c.cl.BlobDelete(ctx, c.db, store, id)
}

// values flattens driver args to []any. The wire endpoints bind positionally, so
// a named parameter is rejected rather than silently coerced to its ordinal — a
// silent coercion would mis-bind a statement that mixes ordering (e.g. reuses one
// name across several placeholders) and corrupt the result.
func values(args []driver.NamedValue) ([]any, error) {
	out := make([]any, len(args))
	for i, a := range args {
		if a.Name != "" {
			return nil, fmt.Errorf("quicsql: named parameter %q is not supported; use positional (?) parameters", a.Name)
		}
		out[i] = a.Value
	}
	return out, nil
}

type tx struct{ c *conn }

func (t *tx) Commit() error   { return t.finish("COMMIT") }
func (t *tx) Rollback() error { return t.finish("ROLLBACK") }

func (t *tx) finish(sql string) error {
	c := t.c
	if c.tx == nil {
		return errors.New("quicsql: transaction already finished")
	}
	s := c.tx
	c.tx = nil
	ctx := context.Background()
	_, execErr := s.Exec(ctx, sql, nil)
	closeErr := s.Close(ctx)
	if execErr != nil {
		return execErr
	}
	return closeErr
}

type result struct{ r *client.Result }

func (r result) LastInsertId() (int64, error) { return r.r.LastInsertID, nil }
func (r result) RowsAffected() (int64, error) { return r.r.RowsAffected, nil }

type rows struct {
	res *client.Result
	i   int
}

// ErrTruncated is surfaced through rows.Err() when the server capped the result
// set (row or byte limit): the delivered rows are a prefix of the real result, so
// reporting a plain io.EOF would let the caller mistake a partial answer for a
// complete one. It is exported so a consumer can classify a capped result with
// errors.Is rather than string-matching.
var ErrTruncated = errors.New("quicsql: result truncated by the server's row/byte cap; the returned rows are incomplete")

func (r *rows) Columns() []string { return r.res.Columns }
func (r *rows) Close() error      { return nil }
func (r *rows) Next(dest []driver.Value) error {
	if r.i >= len(r.res.Rows) {
		if r.res.Truncated {
			return ErrTruncated
		}
		return io.EOF
	}
	row := r.res.Rows[r.i]
	r.i++
	for j := range dest {
		if j >= len(row) {
			dest[j] = nil
			continue
		}
		dest[j] = toDriverValue(row[j])
	}
	return nil
}

// toDriverValue maps a client cell to a driver.Value. Both wire paths now decode
// through the shared wire codec, yielding int64/float64/string/[]byte/nil, which
// pass through unchanged. The json.Number branch is retained only as a defensive
// fallback (older/alternate decoders) and is dead for the current codec.
func toDriverValue(v any) driver.Value {
	switch t := v.(type) {
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	default:
		return t
	}
}

type stmt struct {
	c     *conn
	query string
}

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return -1 } // unknown; the server validates arity
func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.c.ExecContext(context.Background(), s.query, named(args))
}
func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.c.QueryContext(context.Background(), s.query, named(args))
}
func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.c.ExecContext(ctx, s.query, args)
}
func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.c.QueryContext(ctx, s.query, args)
}

func named(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, v := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return out
}

// interface assertions
var (
	_ driver.DriverContext   = drv{}
	_ driver.Connector       = (*connector)(nil)
	_ driver.QueryerContext  = (*conn)(nil)
	_ driver.ExecerContext   = (*conn)(nil)
	_ driver.ConnBeginTx     = (*conn)(nil)
	_ driver.SessionResetter = (*conn)(nil)
)
