// Package httpjson writes the server's uniform JSON responses and error
// envelopes. It marshals into a buffer BEFORE writing the status line, so an
// encoding failure becomes a clean 500 rather than a committed 200 with a
// truncated body. Every HTTP surface (native, Hrana, auth middleware, admin)
// routes its responses through here so the wire shape is defined once.
package httpjson

import (
	"encoding/json"
	"net/http"
)

// Write marshals v and writes it with the given status. A marshal failure is
// reported as a 500 with a fixed error envelope.
func Write(w http.ResponseWriter, status int, v any) {
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

// Error writes the standard {"error":{"message":…}} envelope with the given
// status.
func Error(w http.ResponseWriter, status int, msg string) {
	Write(w, status, map[string]any{"error": map[string]string{"message": msg}})
}
