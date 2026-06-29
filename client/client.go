// Package client is a small Go client for the quicSQL native-JSON API
// (POST /<db>/query). One constructor per transport — H1, H2C, H2TLS, H3, Unix —
// returns a *Client that speaks that wire; the SQL surface (Query/Exec) is
// identical across them, which is what the cross-protocol benchmark relies on.
//
// It is intentionally thin (no connection pooling knobs, no Hrana). For
// interactive transactions use the Hrana pipeline endpoint directly, or a libSQL
// client library.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Client talks to one quicSQL server over one transport, presenting at most one
// credential (bearer / basic / mTLS client cert / ed25519 challenge-response).
type Client struct {
	base   string
	hc     *http.Client
	closer func() error

	token     string // bearer
	user, pw  string // HTTP basic
	edPubLine string // ed25519 authorized_keys line
	edPriv    ed25519.PrivateKey

	// Keyring challenge cache. The server's challenge is stateless and NOT
	// single-use — it validates by HMAC + a short TTL, with no consumed-nonce
	// tracking — so one fetched challenge may sign many requests within its
	// lifetime. Caching it turns the keyring method's per-request GET
	// /_auth/challenge into one fetch per window, collapsing the 2× round-trip
	// penalty on a burst of statements.
	chalMu  sync.Mutex
	chalStr string
	chalExp time.Time // client-side reuse deadline (kept below the server TTL)
}

// challengeReuseWindow bounds how long a fetched keyring challenge is reused
// before refetching. It is deliberately well under the server's fixed challenge
// TTL so a reused challenge still validates after transit and modest clock skew;
// past this window the client fetches a fresh one.
const challengeReuseWindow = 45 * time.Second

// Option customizes a Client. Auth options set the single credential the client
// presents; mutual-TLS is set via WithClientCert on a TLS transport.
type Option func(*clientOpts)

type clientOpts struct {
	token     string
	user, pw  string
	edPubLine string
	edPriv    ed25519.PrivateKey
	cert      *tls.Certificate
	rootCA    *x509.CertPool
}

// WithBearer sends "Authorization: Bearer <token>" on every request.
func WithBearer(token string) Option { return func(o *clientOpts) { o.token = token } }

// WithBasicAuth sends HTTP basic credentials on every request.
func WithBasicAuth(user, password string) Option {
	return func(o *clientOpts) { o.user, o.pw = user, password }
}

// WithClientCert presents a client certificate for mTLS. It applies only to the
// TLS transports (H2TLS, H3); it is ignored on H1/H2C/Unix.
func WithClientCert(cert tls.Certificate) Option {
	return func(o *clientOpts) { o.cert = &cert }
}

// WithRootCA verifies the server's TLS certificate against pool instead of the
// system roots — for a private/dev CA, so the TLS transports (H2TLS, H3) can be
// used verified rather than with insecure=true. Composes with WithClientCert.
func WithRootCA(pool *x509.CertPool) Option {
	return func(o *clientOpts) { o.rootCA = pool }
}

// WithEd25519 authenticates via the keyring challenge/response: the client
// fetches a challenge from /_auth/challenge and signs it with priv, caching and
// reusing the challenge within its window so a burst of requests does not fetch
// one each. pubLine is the matching ssh-ed25519 authorized_keys line.
func WithEd25519(pubLine string, priv ed25519.PrivateKey) Option {
	return func(o *clientOpts) { o.edPubLine, o.edPriv = pubLine, priv }
}

const dialTimeout = 5 * time.Second

// H1 talks plain HTTP/1.1 to addr (host:port).
func H1(addr string, opts ...Option) *Client {
	return finish("http://"+addr, &http.Client{Timeout: 30 * time.Second}, nil, opts)
}

// H2C talks cleartext HTTP/2 (prior knowledge) to addr (host:port).
func H2C(addr string, opts ...Option) *Client {
	t := &http.Transport{}
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	t.Protocols = &p
	return finish("http://"+addr, &http.Client{Transport: t, Timeout: 30 * time.Second}, noErr(t.CloseIdleConnections), opts)
}

// H2TLS talks HTTP/2 over TLS to addr; insecure skips certificate verification
// (for the dev self-signed cert). WithClientCert enables mTLS.
func H2TLS(addr string, insecure bool, opts ...Option) *Client {
	o := apply(opts)
	t := &http.Transport{
		TLSClientConfig:   tlsConfig(insecure, []string{"h2", "http/1.1"}, o),
		ForceAttemptHTTP2: true,
	}
	return bind("https://"+addr, &http.Client{Transport: t, Timeout: 30 * time.Second}, noErr(t.CloseIdleConnections), o)
}

// H3 talks HTTP/3 over QUIC to addr; insecure skips certificate verification.
// WithClientCert enables mTLS.
func H3(addr string, insecure bool, opts ...Option) *Client {
	o := apply(opts)
	t := &http3.Transport{TLSClientConfig: tlsConfig(insecure, []string{"h3"}, o)}
	return bind("https://"+addr, &http.Client{Transport: t, Timeout: 30 * time.Second}, t.Close, o)
}

// Unix talks HTTP/1.1 over a Unix-domain socket.
func Unix(socketPath string, opts ...Option) *Client {
	d := &net.Dialer{Timeout: dialTimeout}
	t := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return finish("http://unix", &http.Client{Transport: t, Timeout: 30 * time.Second}, noErr(t.CloseIdleConnections), opts)
}

func tlsConfig(insecure bool, nextProtos []string, o *clientOpts) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure, NextProtos: nextProtos, RootCAs: o.rootCA}
	if o.cert != nil {
		cfg.Certificates = []tls.Certificate{*o.cert}
	}
	return cfg
}

// noErr adapts a no-error close func to the func() error the Client stores.
func noErr(f func()) func() error {
	return func() error { f(); return nil }
}

func apply(opts []Option) *clientOpts {
	o := &clientOpts{}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// finish applies options and binds them to a Client (for the non-TLS transports,
// where options can't affect the transport).
func finish(base string, hc *http.Client, closeFn func() error, opts []Option) *Client {
	return bind(base, hc, closeFn, apply(opts))
}

func bind(base string, hc *http.Client, closeFn func() error, o *clientOpts) *Client {
	c := &Client{base: base, hc: hc, closer: closeFn}
	c.token, c.user, c.pw = o.token, o.user, o.pw
	c.edPubLine, c.edPriv = o.edPubLine, o.edPriv
	return c
}

// Close releases the client's transport resources (idle connections, QUIC
// sessions). It is safe to call more than once.
func (c *Client) Close() error {
	if c.closer != nil {
		return c.closer()
	}
	return nil
}

// Result is one statement's outcome. Rows holds decoded cells: JSON numbers as
// json.Number, text as string, NULL as nil, a blob as []byte (decoded from the
// {"base64":…} box).
type Result struct {
	Columns      []string
	Rows         [][]any
	RowsAffected int64
	LastInsertID int64
	Truncated    bool
}

// Query runs sql (a read) against db and returns the result.
func (c *Client) Query(ctx context.Context, db, sql string, args ...any) (*Result, error) {
	return c.do(ctx, db, sql, args)
}

// Exec runs sql (a write/DDL) against db. The native endpoint auto-dispatches
// read vs write, so Exec and Query are interchangeable; both are provided for
// call-site clarity.
func (c *Client) Exec(ctx context.Context, db, sql string, args ...any) (*Result, error) {
	return c.do(ctx, db, sql, args)
}

// Export downloads the entire database as a SQLite serialization — the byte image
// a backup contains, which sqlite.Deserialize (or the sqlite3 CLI) can open. It
// requires read access on the server.
func (c *Client) Export(ctx context.Context, db string) ([]byte, error) {
	return c.request(ctx, http.MethodGet, "/"+db+"/export", "", nil)
}

// ApplyChangeset applies a SQLite changeset (as produced by Stream.SessionChangeset)
// to db. It requires write access on the server.
func (c *Client) ApplyChangeset(ctx context.Context, db string, changeset []byte) error {
	_, err := c.request(ctx, http.MethodPost, "/"+db+"/changeset/apply", "application/octet-stream", bytes.NewReader(changeset))
	return err
}

// InvertChangeset returns the inverse (undo) of a changeset. Read access.
func (c *Client) InvertChangeset(ctx context.Context, db string, changeset []byte) ([]byte, error) {
	return c.request(ctx, http.MethodPost, "/"+db+"/changeset/invert", "application/octet-stream", bytes.NewReader(changeset))
}

// ConcatChangesets returns the concatenation of a then b. Read access.
func (c *Client) ConcatChangesets(ctx context.Context, db string, a, b []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"a": base64.StdEncoding.EncodeToString(a),
		"b": base64.StdEncoding.EncodeToString(b),
	})
	if err != nil {
		return nil, err
	}
	return c.request(ctx, http.MethodPost, "/"+db+"/changeset/concat", "application/json", bytes.NewReader(body))
}

// request builds, authenticates, and sends an HTTP request and returns the raw
// response body. A non-200 status becomes an error carrying the server's message.
// It is the single round-trip primitive the endpoint methods share.
func (c *Client) request(ctx context.Context, method, path, contentType string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if err := c.authenticate(ctx, req); err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quicsql: %s %s: %s: %s", method, path, resp.Status, firstMessage(raw))
	}
	return raw, nil
}

// BlobProvision provisions (idempotently) the named store with the given options,
// so objects created in it thereafter honor them. chunk<=0 / compress=="" /
// dedup=false keep server defaults. Requires write access.
func (c *Client) BlobProvision(ctx context.Context, db, store string, chunk int, compress string, dedup bool) error {
	q := url.Values{"store": {store}}
	if chunk > 0 {
		q.Set("chunk", strconv.Itoa(chunk))
	}
	if compress != "" {
		q.Set("compress", compress)
	}
	if dedup {
		q.Set("dedup", "1")
	}
	_, err := c.request(ctx, http.MethodPost, "/"+db+"/blob/provision?"+q.Encode(), "", nil)
	return err
}

// BlobCreate allocates a new large object in the named blobstore and returns its
// id. Store and load its bytes with BlobWrite / BlobRead. Requires write access.
func (c *Client) BlobCreate(ctx context.Context, db, store string) (int64, error) {
	raw, err := c.request(ctx, http.MethodPost, "/"+db+"/blob/create?store="+url.QueryEscape(store), "", nil)
	if err != nil {
		return 0, err
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, err
	}
	return out.ID, nil
}

// BlobWrite streams r as the whole content of object id in store and returns the
// number of bytes written. The body is streamed (bounded memory), so an object
// can be large. Requires write access.
func (c *Client) BlobWrite(ctx context.Context, db, store string, id int64, r io.Reader) (int64, error) {
	raw, err := c.request(ctx, http.MethodPost, blobPath(db, "write", store, id), "application/octet-stream", r)
	if err != nil {
		return 0, err
	}
	var out struct {
		Size int64 `json:"size"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, err
	}
	return out.Size, nil
}

// BlobRead returns the whole content of object id in store (read access).
func (c *Client) BlobRead(ctx context.Context, db, store string, id int64) ([]byte, error) {
	return c.request(ctx, http.MethodGet, blobPath(db, "read", store, id), "", nil)
}

// BlobDelete removes object id from store (write access).
func (c *Client) BlobDelete(ctx context.Context, db, store string, id int64) error {
	_, err := c.request(ctx, http.MethodPost, blobPath(db, "delete", store, id), "", nil)
	return err
}

// BlobSize returns the byte length of object id in store (read access).
func (c *Client) BlobSize(ctx context.Context, db, store string, id int64) (int64, error) {
	raw, err := c.request(ctx, http.MethodGet, blobPath(db, "size", store, id), "", nil)
	if err != nil {
		return 0, err
	}
	var out struct {
		Size int64 `json:"size"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, err
	}
	return out.Size, nil
}

func blobPath(db, op, store string, id int64) string {
	return "/" + db + "/blob/" + op + "?store=" + url.QueryEscape(store) + "&id=" + strconv.FormatInt(id, 10)
}

type wireError struct {
	Message      string `json:"message"`
	Code         int    `json:"code"`
	ExtendedCode int    `json:"extended_code"`
}

// Error is a SQL execution error returned by the server. It carries SQLite's
// primary and extended result codes so callers — notably an ORM's error
// normalization — can classify constraint violations (unique / foreign-key /
// not-null / check) and busy/locked contention. It satisfies the
// Code() int / ExtendedCode() int interfaces those callers assert on.
type Error struct {
	Message string
	code    int
	ext     int
}

func (e *Error) Error() string     { return e.Message }
func (e *Error) Code() int         { return e.code }
func (e *Error) ExtendedCode() int { return e.ext }

func (c *Client) do(ctx context.Context, db, sql string, args []any) (*Result, error) {
	reqBody, err := encodeRequest(sql, args)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/"+db+"/query", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.authenticate(ctx, req); err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quicsql: %s: %s", resp.Status, firstMessage(body))
	}
	var raw struct {
		Columns      []string            `json:"columns"`
		Rows         [][]json.RawMessage `json:"rows"`
		RowsAffected int64               `json:"rows_affected"`
		LastInsertID int64               `json:"last_insert_id"`
		Truncated    bool                `json:"truncated"`
		Error        *wireError          `json:"error"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("quicsql: decode response: %w", err)
	}
	if raw.Error != nil {
		return nil, &Error{Message: raw.Error.Message, code: raw.Error.Code, ext: raw.Error.ExtendedCode}
	}
	res := &Result{Columns: raw.Columns, RowsAffected: raw.RowsAffected, LastInsertID: raw.LastInsertID, Truncated: raw.Truncated}
	res.Rows = make([][]any, len(raw.Rows))
	for i, row := range raw.Rows {
		cells := make([]any, len(row))
		for j, cell := range row {
			cells[j], err = decodeCell(cell)
			if err != nil {
				return nil, fmt.Errorf("quicsql: decode cell: %w", err)
			}
		}
		res.Rows[i] = cells
	}
	return res, nil
}

// authenticate attaches the client's single credential to req. For the ed25519
// challenge/response the challenge is cached and reused within its window (so a
// burst does not pay a fetch each), but the signature is computed per request
// over the challenge BOUND to the request's method and path — so a captured
// signature can't be replayed onto a different request (see keyringSigningInput
// and auth.tryKeyring, which must build the identical bytes).
func (c *Client) authenticate(ctx context.Context, req *http.Request) error {
	switch {
	case c.edPriv != nil:
		chal, err := c.challenge(ctx)
		if err != nil {
			return err
		}
		sig := ed25519.Sign(c.edPriv, keyringSigningInput(chal, req.Method, req.URL.Path))
		req.Header.Set("X-Quicsql-Key", c.edPubLine)
		req.Header.Set("X-Quicsql-Challenge", chal)
		req.Header.Set("X-Quicsql-Signature", base64.StdEncoding.EncodeToString(sig))
	case c.user != "":
		req.SetBasicAuth(c.user, c.pw)
	case c.token != "":
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return nil
}

// keyringSigningInput is the exact byte string the ed25519 challenge/response
// signs: the server's challenge bound to this request's method and path. The
// server reconstructs and verifies the identical bytes in auth.tryKeyring — the
// two MUST stay in sync.
func keyringSigningInput(challenge, method, path string) []byte {
	return []byte(challenge + "\n" + method + "\n" + path)
}

// challenge returns a keyring challenge to sign: the cached one if it is still
// within its reuse window, otherwise a freshly fetched one. The fetch happens
// outside the lock so concurrent callers don't serialize on the network; a rare
// cold-start race just fetches twice, which is harmless.
func (c *Client) challenge(ctx context.Context) (string, error) {
	c.chalMu.Lock()
	if c.chalStr != "" && time.Now().Before(c.chalExp) {
		s := c.chalStr
		c.chalMu.Unlock()
		return s, nil
	}
	c.chalMu.Unlock()

	s, err := c.fetchChallenge(ctx)
	if err != nil {
		return "", err
	}
	c.chalMu.Lock()
	c.chalStr, c.chalExp = s, time.Now().Add(challengeReuseWindow)
	c.chalMu.Unlock()
	return s, nil
}

// fetchChallenge GETs a fresh challenge from the server's /_auth/challenge.
func (c *Client) fetchChallenge(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/_auth/challenge", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("quicsql: fetch challenge: %s", resp.Status)
	}
	var out struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Challenge == "" {
		return "", fmt.Errorf("quicsql: bad challenge response")
	}
	return out.Challenge, nil
}

// encodeRequest builds the {sql, args} body, boxing []byte args as {"base64":…}.
// time.Time is rendered as RFC3339Nano text explicitly (rather than relying on
// json.Marshal's implicit time encoding) so it matches the Hrana path's
// encodeHValue exactly — the same value stores identically in autocommit and in a
// transaction. Keep the two in sync.
func encodeRequest(sql string, args []any) ([]byte, error) {
	out := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case []byte:
			out[i] = map[string]string{"base64": base64.StdEncoding.EncodeToString(v)}
		case time.Time:
			out[i] = v.Format(time.RFC3339Nano)
		default:
			out[i] = a
		}
	}
	req := map[string]any{"sql": sql}
	if len(out) > 0 {
		req["args"] = out
	}
	return json.Marshal(req)
}

// decodeCell maps one response cell to a Go value.
func decodeCell(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if m, ok := v.(map[string]any); ok {
		if b64, ok := m["base64"].(string); ok && len(m) == 1 {
			return base64.StdEncoding.DecodeString(b64)
		}
	}
	return v, nil
}

func firstMessage(body []byte) string {
	var env struct {
		Error *wireError `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error != nil {
		return env.Error.Message
	}
	if len(body) > 200 {
		body = body[:200]
	}
	return string(bytes.TrimSpace(body))
}
