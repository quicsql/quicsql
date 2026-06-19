package client_test

import (
	"bytes"
	"context"
	"testing"

	"quicsql.net/client"
	"quicsql.net/config"
)

// TestBlobRoundTrip proves the whole-object blob wire protocol: create an object,
// write a multi-chunk payload, read it back byte-for-byte, then delete it.
func TestBlobRoundTrip(t *testing.T) {
	skipUnderRace(t)
	addr := freeTCP(t)
	runServer(t, &config.Config{
		Databases: []config.Database{{Name: "app", Backend: "memory-shared"}},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	})
	ctx := context.Background()

	cl := client.H1(addr)
	defer cl.Close()

	id, err := cl.BlobCreate(ctx, "app", "files")
	if err != nil {
		t.Fatalf("BlobCreate: %v", err)
	}

	payload := bytes.Repeat([]byte("quicsql blob payload — "), 5000) // ~115 KB, many chunks
	if n, err := cl.BlobWrite(ctx, "app", "files", id, bytes.NewReader(payload)); err != nil || n != int64(len(payload)) {
		t.Fatalf("BlobWrite: n=%d err=%v (want %d)", n, err, len(payload))
	}

	got, err := cl.BlobRead(ctx, "app", "files", id)
	if err != nil {
		t.Fatalf("BlobRead: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("blob mismatch: read %d bytes, wrote %d", len(got), len(payload))
	}

	if err := cl.BlobDelete(ctx, "app", "files", id); err != nil {
		t.Fatalf("BlobDelete: %v", err)
	}
	if _, err := cl.BlobRead(ctx, "app", "files", id); err == nil {
		t.Fatal("BlobRead after delete should error")
	}
}

// TestBlobStreamingLarge proves the streamed write/read path handles an object
// larger than the 8 MiB request-body cap (which the old buffered path bounded),
// and that BlobProvision options are accepted.
func TestBlobStreamingLarge(t *testing.T) {
	skipUnderRace(t)
	addr := freeTCP(t)
	runServer(t, &config.Config{
		Databases: []config.Database{{Name: "app", Backend: "memory-shared"}},
		Listeners: []config.Listener{{Name: "h1", Transport: "h1", Address: addr}},
	})
	ctx := context.Background()
	cl := client.H1(addr)
	defer cl.Close()

	if err := cl.BlobProvision(ctx, "app", "big", 0, "best", false); err != nil {
		t.Fatalf("BlobProvision: %v", err)
	}
	id, err := cl.BlobCreate(ctx, "app", "big")
	if err != nil {
		t.Fatalf("BlobCreate: %v", err)
	}
	const size = 20 << 20 // 20 MiB, well over the 8 MiB request-body cap
	payload := bytes.Repeat([]byte("quicsql streams large objects — "), size/32)
	n, err := cl.BlobWrite(ctx, "app", "big", id, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("BlobWrite: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("BlobWrite wrote %d bytes, want %d", n, len(payload))
	}
	got, err := cl.BlobRead(ctx, "app", "big", id)
	if err != nil {
		t.Fatalf("BlobRead: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("blob mismatch: read %d bytes, wrote %d", len(got), len(payload))
	}
}
