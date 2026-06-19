package client_test

import (
	"testing"

	"quicsql.net/internal/raceskip"
)

// skipUnderRace skips tests that drive modernc-transpiled native C paths
// (Serialize/Deserialize, the SESSION extension, and blobstore's incremental
// BLOB I/O). Those do pointer arithmetic that Go's checkptr analyzer — which
// -race enables — rejects, even though the C is correct. The same operations are
// covered under a plain `go test`; this only skips them under -race, matching the
// convention in the root module (see quicsql.net/internal/raceskip).
func skipUnderRace(t *testing.T) {
	t.Helper()
	if raceskip.Enabled {
		t.Skip("modernc native C paths (serialize/session/blobstore) trip checkptr under -race")
	}
}
