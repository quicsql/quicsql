package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"quicsql.net/engine"
)

// hValue marshals an engine.Value in Hrana's tagged form and back. Integers are
// carried as JSON STRINGS (precision-safe past 2^53); blobs are base64.
//
// Counterpart: encodeValue/decodeArg (codec.go) is the native bare-JSON form.
// Both switch on engine.Kind and must be updated together if a Kind is added.
type hValue struct{ v engine.Value }

func (h hValue) MarshalJSON() ([]byte, error) {
	switch v := h.v; v.Kind {
	case engine.KindInt:
		return json.Marshal(map[string]string{"type": "integer", "value": strconv.FormatInt(v.Int, 10)})
	case engine.KindFloat:
		if math.IsInf(v.Float, 0) || math.IsNaN(v.Float) {
			return []byte(`{"type":"null"}`), nil // JSON floats can't carry ±Inf/NaN
		}
		return json.Marshal(struct {
			Type  string  `json:"type"`
			Value float64 `json:"value"`
		}{"float", v.Float})
	case engine.KindText:
		return json.Marshal(map[string]string{"type": "text", "value": v.Text})
	case engine.KindBlob:
		return json.Marshal(map[string]string{"type": "blob", "base64": base64.StdEncoding.EncodeToString(v.Blob)})
	default:
		return []byte(`{"type":"null"}`), nil
	}
}

func (h *hValue) UnmarshalJSON(b []byte) error {
	var raw struct {
		Type   string          `json:"type"`
		Value  json.RawMessage `json:"value"`
		Base64 string          `json:"base64"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch raw.Type {
	case "null":
		h.v = engine.Null()
	case "integer":
		var s string
		if err := json.Unmarshal(raw.Value, &s); err != nil {
			return err
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("hrana: bad integer value: %w", err)
		}
		h.v = engine.Int(n)
	case "float":
		var f float64
		if err := json.Unmarshal(raw.Value, &f); err != nil {
			return err
		}
		h.v = engine.Float(f)
	case "text":
		var s string
		if err := json.Unmarshal(raw.Value, &s); err != nil {
			return err
		}
		h.v = engine.Text(s)
	case "blob":
		data, err := base64.StdEncoding.DecodeString(raw.Base64)
		if err != nil {
			return fmt.Errorf("hrana: bad blob base64: %w", err)
		}
		h.v = engine.Blob(data)
	default:
		return fmt.Errorf("hrana: unknown value type %q", raw.Type)
	}
	return nil
}

// --- request / response envelopes ---

type pipelineReq struct {
	Baton    *string         `json:"baton"`
	Requests []streamRequest `json:"requests"`
}

// streamRequest is the union of every request kind, discriminated by Type. The
// session_start / session_changeset kinds are quicSQL extensions (not libSQL
// Hrana): they capture a SQLite SESSION changeset on the stream's pinned
// connection — see runStreamRequest.
type streamRequest struct {
	Type   string   `json:"type"`
	Stmt   *hStmt   `json:"stmt"`
	Batch  *hBatch  `json:"batch"`
	SQL    *string  `json:"sql"`
	SQLID  *int32   `json:"sql_id"`
	Tables []string `json:"tables"` // session_start: tables to track (empty = all)
}

// changesetResp carries a captured changeset (base64) for a session_changeset
// request.
type changesetResp struct {
	Type      string `json:"type"`
	Changeset string `json:"changeset"`
}

type pipelineResp struct {
	Baton   *string        `json:"baton"`
	BaseURL *string        `json:"base_url"`
	Results []streamResult `json:"results"`
}

// streamResult is {"type":"ok","response":…} or {"type":"error","error":…}.
type streamResult struct {
	Type     string  `json:"type"`
	Response any     `json:"response,omitempty"`
	Error    *hError `json:"error,omitempty"`
}

// Per-kind responses (each carries its own "result" shape, so they are distinct
// types rather than one struct with clashing json:"result" fields).
type executeResp struct {
	Type   string       `json:"type"`
	Result *hStmtResult `json:"result"`
}
type batchResp struct {
	Type   string        `json:"type"`
	Result *hBatchResult `json:"result"`
}
type describeResp struct {
	Type   string           `json:"type"`
	Result *hDescribeResult `json:"result"`
}
type getAutocommitResp struct {
	Type         string `json:"type"`
	IsAutocommit bool   `json:"is_autocommit"`
}
type simpleResp struct {
	Type string `json:"type"`
}

// --- statement / result ---

type hStmt struct {
	SQL       *string     `json:"sql"`
	SQLID     *int32      `json:"sql_id"`
	Args      []hValue    `json:"args"`
	NamedArgs []hNamedArg `json:"named_args"`
	WantRows  *bool       `json:"want_rows"`
}

type hNamedArg struct {
	Name  string `json:"name"`
	Value hValue `json:"value"`
}

type hCol struct {
	Name     *string `json:"name"`
	Decltype *string `json:"decltype"`
}

type hStmtResult struct {
	Cols             []hCol     `json:"cols"`
	Rows             [][]hValue `json:"rows"`
	AffectedRowCount uint64     `json:"affected_row_count"`
	LastInsertRowid  *string    `json:"last_insert_rowid"`
	// Truncated reports that the row set was capped by the max-rows limit. It is a
	// quicSQL extension to the Hrana result (the spec has no such field).
	Truncated bool `json:"truncated,omitempty"`
}

// --- batch ---

type hBatch struct {
	Steps []hBatchStep `json:"steps"`
}

type hBatchStep struct {
	Condition *hBatchCond `json:"condition"`
	Stmt      hStmt       `json:"stmt"`
}

type hBatchCond struct {
	Type  string       `json:"type"` // ok | error | not | and | or | is_autocommit
	Step  *int32       `json:"step"`
	Cond  *hBatchCond  `json:"cond"`
	Conds []hBatchCond `json:"conds"`
}

type hBatchResult struct {
	StepResults []*hStmtResult `json:"step_results"`
	StepErrors  []*hError      `json:"step_errors"`
}

// --- cursor (POST /v2|/v3/cursor) ---

// cursorReq is the Hrana CursorReqBody: one batch to execute on the stream
// identified by baton (null opens a new stream), with the result streamed back.
type cursorReq struct {
	Baton *string `json:"baton"`
	Batch *hBatch `json:"batch"`
}

// cursorPrelude is the Hrana CursorRespBody — the first newline-separated JSON
// line of a cursor response; the entry lines follow it.
type cursorPrelude struct {
	Baton   *string `json:"baton"`
	BaseURL *string `json:"base_url"`
}

// Cursor entries: one JSON line each, together encoding the same information as
// an hBatchResult but delivered incrementally. A step index refers to the
// batch's steps array; a skipped step (condition false) produces no entries.
type cursorStepBegin struct {
	Type string `json:"type"` // "step_begin"
	Step uint32 `json:"step"`
	Cols []hCol `json:"cols"`
}

type cursorRow struct {
	Type string   `json:"type"` // "row"
	Row  []hValue `json:"row"`
}

type cursorStepEnd struct {
	Type             string  `json:"type"` // "step_end"
	AffectedRowCount uint64  `json:"affected_row_count"`
	LastInsertRowid  *string `json:"last_insert_rowid"`
	// Truncated is the quicSQL extension mirrored from hStmtResult: the step's
	// row set was capped by the max-rows limit.
	Truncated bool `json:"truncated,omitempty"`
}

type cursorStepError struct {
	Type  string  `json:"type"` // "step_error"
	Step  uint32  `json:"step"`
	Error *hError `json:"error"`
}

// --- describe / error ---

type hDescribeResult struct {
	Params     []hDescribeParam `json:"params"`
	Cols       []hCol           `json:"cols"`
	IsExplain  bool             `json:"is_explain"`
	IsReadonly bool             `json:"is_readonly"`
}

type hDescribeParam struct {
	Name *string `json:"name"`
}

type hError struct {
	Message string  `json:"message"`
	Code    *string `json:"code"`
}
