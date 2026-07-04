package client_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"quicsql.net/client"
	"quicsql.net/config"
)

// TestMaxResponseCap proves the client bounds a server-supplied response body
// (follow-up item 3): a BlobRead whose payload exceeds the configured cap errors
// instead of allocating unboundedly, while a generous cap reads it in full.
func TestMaxResponseCap(t *testing.T) {
	skipUnderRace(t)
	addr := freeTCP(t)
	runServer(t, &config.Config{
		Databases: []config.Database{{Name: "app", Backend: "memory-shared"}},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	})
	ctx := context.Background()

	// Seed a ~200 KB object with a default client.
	seed := client.H1(addr)
	defer seed.Close()
	id, err := seed.BlobCreate(ctx, "app", "files")
	if err != nil {
		t.Fatalf("BlobCreate: %v", err)
	}
	payload := bytes.Repeat([]byte("x"), 200<<10)
	if _, err := seed.BlobWrite(ctx, "app", "files", id, bytes.NewReader(payload)); err != nil {
		t.Fatalf("BlobWrite: %v", err)
	}

	// A tiny cap rejects the oversized read.
	capped := client.H1(addr, client.WithMaxResponse(4096))
	defer capped.Close()
	if _, err := capped.BlobRead(ctx, "app", "files", id); err == nil {
		t.Fatal("BlobRead should exceed the 4 KiB response cap")
	} else if !strings.Contains(err.Error(), "client cap") {
		t.Fatalf("expected a cap error, got: %v", err)
	}

	// A generous cap reads the whole object.
	roomy := client.H1(addr, client.WithMaxResponse(1<<20))
	defer roomy.Close()
	got, err := roomy.BlobRead(ctx, "app", "files", id)
	if err != nil {
		t.Fatalf("BlobRead under a roomy cap: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("blob mismatch: read %d bytes, wrote %d", len(got), len(payload))
	}
}
