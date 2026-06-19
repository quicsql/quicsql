package httpapi

import (
	"encoding/json"
	"net/http"
)

// handleCursor serves Hrana's POST /v2|/v3/cursor: it executes one batch on a
// stream — resolved from the baton exactly like handlePipeline — and streams
// the result as newline-separated JSON per the Hrana 3 spec ("Execute a batch
// using a cursor"): the first line is the prelude (baton + base_url), each
// following line one cursor entry (step_begin / row / step_end / step_error).
// The cursor endpoint exists in Hrana 3; the /v2 route accepts it too as a
// harmless superset (Turso's serverless driver posts to /v3/cursor).
//
// Execution is buffered per STEP, not per row: each step runs through the same
// bounded machinery as the pipeline `batch` request (the engine's row/byte
// caps), and its entries are then written and flushed. Memory stays bounded
// exactly as on the pipeline path while results still arrive incrementally
// across steps.
func (h *Handler) handleCursor(w http.ResponseWriter, r *http.Request, dbName string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if h.sessions == nil {
		writeErr(w, http.StatusNotImplemented, "sessions not enabled")
		return
	}
	level, ok := h.authorize(w, r, dbName)
	if !ok {
		return
	}
	done, ok := h.meter(w, r, dbName)
	if !ok {
		return
	}
	defer done()
	ctx := r.Context() // per-statement timeouts are applied in execStmt
	boundBodyRead(w)
	body, err := h.readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	var req cursorReq
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Batch == nil {
		writeErr(w, http.StatusBadRequest, "cursor requires a batch")
		return
	}

	sess, err := h.stream(ctx, dbName, req.Baton, level)
	if err != nil {
		h.writeStreamError(w, dbName, err)
		return
	}
	// A cursor request cannot close its stream (a batch has no close step), so
	// the prelude always carries a baton. It is minted BEFORE the batch runs —
	// the prelude is the stream's first line — and the session stays busy until
	// the deferred Baton call: the reaper/Kill won't touch the pinned connection
	// mid-stream, and Resume refuses the peeked baton until this request is done.
	baton := h.sessions.PeekBaton(sess)
	defer h.sessions.Baton(sess) // marks the request finished; the baton stays current

	// Every failure past this point is in-stream (a step_error entry): the
	// status line and the prelude are already committed. The spec's terminal
	// batch-level `error` entry is never produced here — with per-step
	// execution, every failure a batch can hit is a step failure, and everything
	// else fails before streaming starts, with the normal error envelope.
	//
	// The media type matches the reference implementation (sqld serves the JSON
	// cursor stream as text/plain); the spec does not name one.
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w) // Encode appends the entry-separating newline
	rc := http.NewResponseController(w)
	write := func(entry any) bool {
		return enc.Encode(entry) == nil // a failed write = client gone: stop executing
	}
	if !write(cursorPrelude{Baton: &baton}) {
		return
	}
	_ = rc.Flush() // the client sees the prelude (its next baton) before the batch runs

	h.runHranaBatch(ctx, sess, *req.Batch, func(step int, res *hStmtResult, herr *hError) bool {
		defer func() { _ = rc.Flush() }() // deliver each step's entries promptly
		if herr != nil {
			return write(cursorStepError{Type: "step_error", Step: uint32(step), Error: herr})
		}
		if !write(cursorStepBegin{Type: "step_begin", Step: uint32(step), Cols: res.Cols}) {
			return false
		}
		for _, row := range res.Rows {
			if !write(cursorRow{Type: "row", Row: row}) {
				return false
			}
		}
		return write(cursorStepEnd{
			Type:             "step_end",
			AffectedRowCount: res.AffectedRowCount,
			LastInsertRowid:  res.LastInsertRowid,
			Truncated:        res.Truncated,
		})
	})
}
