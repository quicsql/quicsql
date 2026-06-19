package secret

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"gosqlite.org/crypto/keyring"
	"quicsql.net/config"
)

func fileResolver(t *testing.T, files map[string][]byte) Resolver {
	t.Helper()
	dir := t.TempDir()
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := New([]config.SecretSource{{Name: "f", Type: "file", Dir: dir}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sshKeypair(t *testing.T) (privPEM, pubLine []byte) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(sk, "")
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(blk), ssh.MarshalAuthorizedKey(sp)
}

// TestSSHIdentityRecipientRoundTrip proves the resolver infers a matching
// recipient (from the public line) and identity (from the private PEM): a data
// key wrapped to the recipient unwraps with the identity.
func TestSSHIdentityRecipientRoundTrip(t *testing.T) {
	priv, pub := sshKeypair(t)
	r := fileResolver(t, map[string][]byte{"id.key": priv, "id.pub": pub})

	rec, err := r.Recipient("f:id.pub")
	if err != nil {
		t.Fatalf("Recipient: %v", err)
	}
	id, err := r.Identity("f:id.key")
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	data := []byte("0123456789abcdef0123456789abcdef")
	blob, err := keyring.Wrap(data, rec)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := keyring.Unwrap(blob, id)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("round-trip mismatch: inferred recipient/identity do not match")
	}
}

// TestPassphraseRoundTrip proves a non-key secret resolves to a passphrase
// recipient/identity pair.
func TestPassphraseRoundTrip(t *testing.T) {
	r := fileResolver(t, map[string][]byte{"pw": []byte("correct horse battery staple")})
	rec, err := r.Recipient("f:pw")
	if err != nil {
		t.Fatalf("Recipient: %v", err)
	}
	id, err := r.Identity("f:pw")
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	data := []byte("fedcba9876543210fedcba9876543210")
	blob, err := keyring.Wrap(data, rec)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := keyring.Unwrap(blob, id)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("passphrase round-trip mismatch")
	}
}

// TestMasterResolvers proves the ed25519 master/writer variants parse.
func TestMasterResolvers(t *testing.T) {
	priv, pub := sshKeypair(t)
	r := fileResolver(t, map[string][]byte{"m.key": priv, "m.pub": pub})
	if _, err := r.MasterIdentity("f:m.key"); err != nil {
		t.Fatalf("MasterIdentity: %v", err)
	}
	if _, err := r.MasterRecipient("f:m.pub"); err != nil {
		t.Fatalf("MasterRecipient: %v", err)
	}
}

func TestResolverPropagatesMissingSecret(t *testing.T) {
	r := fileResolver(t, nil)
	if _, err := r.Identity("f:absent.key"); err == nil {
		t.Fatal("a missing file must error, not silently succeed")
	}
}
