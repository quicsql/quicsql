package httpapi

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	sqlite "gosqlite.org"
	"gosqlite.org/blobstore"
	"quicsql.net/config"
)

// handleBlob serves the large-object endpoints backed by gosqlite's blobstore
// (chunked, optionally compressed/deduplicated objects). The engine runs on the
// server; write/read stream so a single object is bounded by the (large) blob cap
// (WithMaxBlob), not the small request-body cap:
//
//	POST /<db>/blob/provision?store=<s>[&chunk=&compress=&dedup=1]   (write) — options
//	POST /<db>/blob/create?store=<s>                → {"id": <n>}    (write)
//	POST /<db>/blob/write?store=<s>&id=<n>  body=bytes → {"size":<n>}(write, streamed)
//	GET  /<db>/blob/read?store=<s>&id=<n>           → bytes          (read, streamed)
//	GET  /<db>/blob/size?store=<s>&id=<n>           → {"size": <n>}  (read)
//	POST /<db>/blob/delete?store=<s>&id=<n>                          (write)
func (h *Handler) handleBlob(w http.ResponseWriter, r *http.Request, db, endpoint string) {
	lvl, ok := h.authorize(w, r, db)
	if !ok {
		return
	}
	write := endpoint == "/blob/provision" || endpoint == "/blob/create" || endpoint == "/blob/write" || endpoint == "/blob/delete"
	if write && !lvl.CanWrite() {
		writeErr(w, http.StatusForbidden, "forbidden: read-only (write not permitted)")
		return
	}
	if write && r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !write && r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	done, ok := h.meter(w, r, db)
	if !ok {
		return
	}
	defer done()

	q := r.URL.Query()
	store := q.Get("store")
	if !config.ValidDBName(store) { // blobstore validates+quotes too; this is the first gate
		writeErr(w, http.StatusBadRequest, "invalid or missing ?store=")
		return
	}
	dbh, release, err := h.reg.Get(r.Context(), db)
	if err != nil {
		h.writeGetError(w, db, err)
		return
	}
	defer release()
	ctx := r.Context()

	// provision opens (and caches) the store WITH the field's options so every
	// object created in it thereafter honors them (blobstore options are per-open).
	if endpoint == "/blob/provision" {
		if _, err := h.provisionBlobStore(dbh.Handle, store, blobOpts(q)); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "provision: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	// Resolve the store: writable ops reuse the cached (options-provisioned) store;
	// reads use the cache or a read-only handle. A never-provisioned store is 404.
	var st *blobstore.Store
	if write {
		st, err = h.blobStore(dbh.Handle, store)
	} else {
		st, err = h.readBlobStore(dbh.Handle, store)
	}
	if err != nil {
		if !write {
			writeErr(w, http.StatusNotFound, "store not found")
			return
		}
		writeErr(w, http.StatusUnprocessableEntity, "open blobstore: "+err.Error())
		return
	}

	switch endpoint {
	case "/blob/create":
		id, err := st.Create(ctx)
		if err != nil {
			blobFail(w, "create", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"id": id})

	case "/blob/write":
		id, ok := blobID(w, q)
		if !ok {
			return
		}
		boundBodyRead(w)
		wtr, err := st.Writer(ctx, id)
		if err != nil {
			blobFail(w, "open writer", err)
			return
		}
		n, werr := copyToWriterAt(wtr, io.LimitReader(r.Body, h.maxBlob+1))
		_ = wtr.Close()
		if werr != nil {
			blobFail(w, "write", werr)
			return
		}
		if n > h.maxBlob {
			_ = st.Truncate(ctx, id, 0) // reclaim the partial oversized object
			writeErr(w, http.StatusRequestEntityTooLarge, "object exceeds the maximum blob size")
			return
		}
		// Truncate to the streamed length so a rewrite that shrinks the object is exact.
		if err := st.Truncate(ctx, id, n); err != nil {
			blobFail(w, "truncate", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"size": n})

	case "/blob/read":
		id, ok := blobID(w, q)
		if !ok {
			return
		}
		size, err := st.Size(ctx, id)
		if err != nil {
			blobFail(w, "size", err)
			return
		}
		rd, err := st.Reader(ctx, id)
		if err != nil {
			blobFail(w, "open reader", err)
			return
		}
		defer func() { _ = rd.Close() }()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		_ = copyFromReaderAt(w, rd, size) // stream; a mid-stream error just ends the body

	case "/blob/size":
		id, ok := blobID(w, q)
		if !ok {
			return
		}
		size, err := st.Size(ctx, id)
		if err != nil {
			blobFail(w, "size", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"size": size})

	case "/blob/delete":
		id, ok := blobID(w, q)
		if !ok {
			return
		}
		if err := st.Delete(ctx, id); err != nil {
			blobFail(w, "delete", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// blobKey identifies a cached Store by its database handle and name (mirrors the
// local lob storeCache, which keys by *gosqlite.DB so a reopened db gets a fresh
// entry).
type blobKey struct {
	db   *sqlite.DB
	name string
}

// blobStore returns a cached writable Store, opening it once (with defaults) and
// reusing it — avoiding a re-open (and its idempotent CREATE TABLE) per request.
func (h *Handler) blobStore(dbHandle *sqlite.DB, name string) (*blobstore.Store, error) {
	key := blobKey{db: dbHandle, name: name}
	if v, ok := h.blobStores.Load(key); ok {
		return v.(*blobstore.Store), nil
	}
	st, err := blobstore.Open(dbHandle, name)
	if err != nil {
		return nil, err
	}
	actual, _ := h.blobStores.LoadOrStore(key, st)
	return actual.(*blobstore.Store), nil
}

// provisionBlobStore opens the store WITH options and caches it (overwriting any
// default-opened entry), so subsequent objects honor the options.
func (h *Handler) provisionBlobStore(dbHandle *sqlite.DB, name string, opts []blobstore.Option) (*blobstore.Store, error) {
	st, err := blobstore.Open(dbHandle, name, opts...)
	if err != nil {
		return nil, err
	}
	h.blobStores.Store(blobKey{db: dbHandle, name: name}, st)
	return st, nil
}

// readBlobStore returns the cached store or, if none, a read-only handle (which
// errors for a never-provisioned store → the caller returns 404).
func (h *Handler) readBlobStore(dbHandle *sqlite.DB, name string) (*blobstore.Store, error) {
	if v, ok := h.blobStores.Load(blobKey{db: dbHandle, name: name}); ok {
		return v.(*blobstore.Store), nil
	}
	return blobstore.OpenReadOnly(dbHandle, name)
}

// blobOpts builds blobstore options from the provision query params.
func blobOpts(q url.Values) []blobstore.Option {
	var opts []blobstore.Option
	if n, err := strconv.Atoi(q.Get("chunk")); err == nil && n > 0 {
		opts = append(opts, blobstore.WithChunkSize(n))
	}
	switch q.Get("compress") {
	case "fastest":
		opts = append(opts, blobstore.WithCompression(blobstore.CompressionFastest))
	case "fast":
		opts = append(opts, blobstore.WithCompression(blobstore.CompressionFast))
	case "default":
		opts = append(opts, blobstore.WithCompression(blobstore.CompressionDefault))
	case "better":
		opts = append(opts, blobstore.WithCompression(blobstore.CompressionBetter))
	case "best":
		opts = append(opts, blobstore.WithCompression(blobstore.CompressionBest))
	}
	if q.Get("dedup") == "1" {
		opts = append(opts, blobstore.WithDedup())
	}
	return opts
}

// blobFail maps a blobstore op error to a status: 404 for a missing object,
// 422 otherwise.
func blobFail(w http.ResponseWriter, prefix string, err error) {
	if errors.Is(err, blobstore.ErrNotFound) {
		writeErr(w, http.StatusNotFound, prefix+": not found")
		return
	}
	writeErr(w, http.StatusUnprocessableEntity, prefix+": "+err.Error())
}

// copyToWriterAt streams r into an io.WriterAt at increasing offsets, returning
// the total bytes written (bounded memory — no whole-object buffer).
func copyToWriterAt(w io.WriterAt, r io.Reader) (int64, error) {
	buf := make([]byte, 64<<10)
	var off int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.WriteAt(buf[:n], off); werr != nil {
				return off, werr
			}
			off += int64(n)
		}
		if err == io.EOF {
			return off, nil
		}
		if err != nil {
			return off, err
		}
	}
}

// copyFromReaderAt streams size bytes from an io.ReaderAt to w in chunks.
func copyFromReaderAt(w io.Writer, r io.ReaderAt, size int64) error {
	buf := make([]byte, 64<<10)
	var off int64
	for off < size {
		n, err := r.ReadAt(buf, off)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			off += int64(n)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func blobID(w http.ResponseWriter, q url.Values) (int64, bool) {
	vals := q["id"]
	if len(vals) == 0 {
		writeErr(w, http.StatusBadRequest, "missing ?id=")
		return 0, false
	}
	id, err := strconv.ParseInt(vals[0], 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid ?id=")
		return 0, false
	}
	return id, true
}
