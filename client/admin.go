package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// AdminMaintenance runs a maintenance op on a database: "compact" (offline,
// vault), "compact_online"/"trim" (online, vault; maxBytes caps a reclaim), or
// "snapshot" (any backend; dest is a server-side path inside data_dir). It
// returns the server's raw JSON status for display.
func (c *Client) AdminMaintenance(ctx context.Context, database, op string, maxBytes int64, dest string) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{
		"database": database, "op": op, "max_bytes": maxBytes, "dest": dest,
	})
	if err != nil {
		return nil, err
	}
	return c.request(ctx, http.MethodPost, "/_admin/maintenance", "application/json", bytes.NewReader(body))
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
