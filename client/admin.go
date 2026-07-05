package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// This file is the typed surface of the `/_admin` control plane and the
// server-scoped `/_health` probe. Every admin call requires a named,
// authenticated caller: a server-admin (config `control_plane.admins`) for the
// server-wide operations, or a principal holding an `admin` grant on a
// database for the per-database views. Open mode never applies here — an
// unauthenticated client gets a 403 no matter how permissive the data plane is.

// Health probes the server-scoped `/_health` endpoint (public, unauthenticated
// on every transport). A nil error means the server answered "ok".
func (c *Client) Health(ctx context.Context) error {
	raw, err := c.request(ctx, http.MethodGet, "/_health", "", nil)
	if err != nil {
		return err
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("quicsql: malformed /_health response: %w", err)
	}
	if body.Status != "ok" {
		return fmt.Errorf("quicsql: server health is %q", body.Status)
	}
	return nil
}

// AdminDatabase is one entry from the control plane's database listing.
type AdminDatabase struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Open bool   `json:"open"`
	Refs int    `json:"refs"`
}

// AdminDatabases lists the databases the caller may administer: all of them
// for a server-admin, otherwise the ones the caller holds an `admin` grant on.
func (c *Client) AdminDatabases(ctx context.Context) ([]AdminDatabase, error) {
	raw, err := c.request(ctx, http.MethodGet, "/_admin/databases", "", nil)
	if err != nil {
		return nil, err
	}
	var body struct {
		Databases []AdminDatabase `json:"databases"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("quicsql: malformed /_admin/databases response: %w", err)
	}
	return body.Databases, nil
}

// AdminInfo is the server-wide runtime snapshot (server-admin only).
type AdminInfo struct {
	UptimeSeconds  int64  `json:"uptime_seconds"`
	Goroutines     int    `json:"goroutines"`
	HeapBytes      uint64 `json:"heap_bytes"`
	Databases      int    `json:"databases"`
	OpenDatabases  int    `json:"open_databases"`
	ActiveSessions int    `json:"active_sessions"`
}

// AdminInfo fetches `/_admin/info` (server-admin only).
func (c *Client) AdminInfo(ctx context.Context) (*AdminInfo, error) {
	raw, err := c.request(ctx, http.MethodGet, "/_admin/info", "", nil)
	if err != nil {
		return nil, err
	}
	info := new(AdminInfo)
	if err := json.Unmarshal(raw, info); err != nil {
		return nil, fmt.Errorf("quicsql: malformed /_admin/info response: %w", err)
	}
	return info, nil
}

// AdminSession is one live interactive-transaction session.
type AdminSession struct {
	ID          string `json:"id"`
	Database    string `json:"database"`
	Principal   string `json:"principal"`
	ReadOnly    bool   `json:"read_only"`
	InFlight    bool   `json:"in_flight"`
	AgeSeconds  int64  `json:"age_seconds"`
	IdleSeconds int64  `json:"idle_seconds"`
}

// AdminSessions lists live sessions, filtered to the databases the caller may
// administer.
func (c *Client) AdminSessions(ctx context.Context) ([]AdminSession, error) {
	raw, err := c.request(ctx, http.MethodGet, "/_admin/sessions", "", nil)
	if err != nil {
		return nil, err
	}
	var body struct {
		Sessions []AdminSession `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("quicsql: malformed /_admin/sessions response: %w", err)
	}
	return body.Sessions, nil
}

// AdminPrincipal is one runtime-enrolled principal (GET /_admin/principals).
type AdminPrincipal struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen"`
}

// AdminPrincipals lists the runtime-enrolled principals (server-admin only).
func (c *Client) AdminPrincipals(ctx context.Context) ([]AdminPrincipal, error) {
	raw, err := c.request(ctx, http.MethodGet, "/_admin/principals", "", nil)
	if err != nil {
		return nil, err
	}
	var body struct {
		Principals []AdminPrincipal `json:"principals"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("quicsql: malformed /_admin/principals response: %w", err)
	}
	return body.Principals, nil
}

// AdminDeletePrincipal revokes one runtime-enrolled principal — its key, grants,
// and (per auth.enroll.provision.on_revoke) its per-user database — together
// (server-admin only). A busy per-user database is refused with 409.
func (c *Client) AdminDeletePrincipal(ctx context.Context, name string) error {
	return c.adminPost(ctx, "/_admin/principals/delete", map[string]any{"name": name})
}

// AdminMintEnrollCode mints a single-use enrollment code (server-admin only;
// requires auth.enroll.codes.enabled). The returned code is shown only here —
// hand it to one user, who enrolls with it exactly once before expiresAt (unix).
func (c *Client) AdminMintEnrollCode(ctx context.Context) (code string, expiresAt int64, err error) {
	raw, err := c.request(ctx, http.MethodPost, "/_admin/enroll/codes", "", nil)
	if err != nil {
		return "", 0, err
	}
	var body struct {
		Code      string `json:"code"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", 0, fmt.Errorf("quicsql: malformed /_admin/enroll/codes response: %w", err)
	}
	return body.Code, body.ExpiresAt, nil
}

// AdminKill force-closes the session with the given id (server-admin only).
// A session with a request in flight is refused with a 409.
func (c *Client) AdminKill(ctx context.Context, session string) error {
	return c.adminPost(ctx, "/_admin/kill", map[string]any{"session": session})
}

// AdminDetach detaches the named database from the registry (server-admin
// only). The underlying file is left in place.
func (c *Client) AdminDetach(ctx context.Context, database string) error {
	return c.adminPost(ctx, "/_admin/detach", map[string]any{"database": database})
}

// AdminCreate provisions a new database at runtime (server-admin only). The
// request is marshaled verbatim as the `/_admin/create` body, whose shape is
//
//	{"database": {<config.Database fields>}, "grants": [{"principal": …, "level": …}]}
//
// It is typed `any` so callers assemble the spec (a map, or their own structs)
// without this package depending on the server's config types.
func (c *Client) AdminCreate(ctx context.Context, request any) error {
	return c.adminPost(ctx, "/_admin/create", request)
}

// AdminMaintenance runs a maintenance op on a database and returns the server's
// raw JSON status for display. Ops:
//   - "compact" (offline, vault) · "compact_online"/"trim" (online, vault;
//     maxBytes caps a reclaim) · "compact_logical" (online, vault: rewrite to the
//     logical footprint) · "reclaimable" (online, vault: report bytes a logical
//     compaction would free)
//   - "checkpoint" (any WAL database; mode is passive|full|restart|truncate)
//   - "snapshot" (any backend; dest is a server-side path inside data_dir)
//
// Pass "" for maxBytes/dest/mode fields an op doesn't use.
func (c *Client) AdminMaintenance(ctx context.Context, database, op string, maxBytes int64, dest, mode string) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{
		"database": database, "op": op, "max_bytes": maxBytes, "dest": dest, "mode": mode,
	})
	if err != nil {
		return nil, err
	}
	return c.request(ctx, http.MethodPost, "/_admin/maintenance", "application/json", bytes.NewReader(body))
}

// AdminRestore replaces a file database's contents with the SQLite image read
// from src (as produced by BackupTo/Export or the sqlite3 CLI). It streams the
// upload, and the server validates the image and swaps it in atomically under a
// reservation — refused with a busy error if the database has active users.
// Server-admin only; file backends only. Back up first: the previous contents
// are discarded.
func (c *Client) AdminRestore(ctx context.Context, database string, src io.Reader) error {
	q := url.Values{"database": {database}}
	_, err := c.request(ctx, http.MethodPost, "/_admin/restore?"+q.Encode(), "application/octet-stream", src)
	return err
}

// adminPost marshals v and POSTs it to path, discarding the response body.
func (c *Client) adminPost(ctx context.Context, path string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.request(ctx, http.MethodPost, path, "application/json", bytes.NewReader(body))
	return err
}
