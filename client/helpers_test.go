package client_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"quicsql.net/config"
	"quicsql.net/serverd"
)

// runServer starts an in-process quicSQL server from cfg (logs discarded) and
// registers its shutdown as test cleanup. (freeTCP lives in client_test.go.)
func runServer(t *testing.T, cfg *config.Config) {
	t.Helper()
	srv, err := serverd.Run(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("serverd.Run: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
}
