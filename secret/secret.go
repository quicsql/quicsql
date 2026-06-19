// Package secret resolves "source:name" references to key material. All sources
// are unattended and resolved eagerly at config-load — there is no interactive
// unlock, so the daemon starts without human interaction.
//
// A reference resolves to raw bytes (env value or file contents); the keyring
// resolvers interpret those bytes by shape: a PEM private key (leading
// "-----BEGIN") becomes an SSH identity, an authorized_keys line (leading
// "ssh-", "ecdsa-", or "sk-") an SSH recipient, and anything else a passphrase
// identity/recipient. The master/writer variants require an ed25519 SSH key (the
// only keyring signer). A misclassified value fails to parse (fail closed) — it
// never opens the wrong door. The kms source is a later seam.
package secret

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gosqlite.org/crypto/keyring"
	"quicsql.net/config"
)

// ErrNotImplemented marks a resolver path a later phase fills in.
var ErrNotImplemented = errors.New("secret: not implemented in this phase")

// ErrMalformedRef and ErrUnknownSource let a caller tell "this string is not a
// secret reference" (so it can fall back to treating it as a literal value) from
// "this reference names a source that does not exist / could not be read".
var (
	ErrMalformedRef  = errors.New("secret: malformed reference (want source:name)")
	ErrUnknownSource = errors.New("secret: unknown source")
)

// Resolver turns a "source:name" reference into concrete key material.
type Resolver interface {
	// Bytes returns raw key bytes (e.g. a vault raw cipher key).
	Bytes(ref string) ([]byte, error)
	// Identity returns a keyring identity for recipient-mode vault opens (an SSH
	// private key, else a passphrase).
	Identity(ref string) (keyring.Identity, error)
	// Recipient returns a keyring recipient for create-time provisioning (an SSH
	// authorized_keys line, else a passphrase).
	Recipient(ref string) (keyring.Recipient, error)
	// MasterIdentity returns an ed25519 master/writer identity (SignWith / WriteAs).
	MasterIdentity(ref string) (keyring.MasterIdentity, error)
	// MasterRecipient returns an ed25519 master/writer recipient (Masters / Writers).
	MasterRecipient(ref string) (keyring.MasterRecipient, error)
}

type mapResolver struct {
	sources map[string]config.SecretSource
}

// New builds a Resolver from the declared sources.
func New(sources []config.SecretSource) (Resolver, error) {
	m := make(map[string]config.SecretSource, len(sources))
	for _, s := range sources {
		if s.Name == "" {
			return nil, fmt.Errorf("secret: source with empty name")
		}
		m[s.Name] = s
	}
	return &mapResolver{sources: m}, nil
}

func (r *mapResolver) Bytes(ref string) ([]byte, error) {
	src, name, err := r.lookup(ref)
	if err != nil {
		return nil, err
	}
	switch src.Type {
	case "env":
		v, ok := os.LookupEnv(name)
		if !ok {
			return nil, fmt.Errorf("secret: env %q not set", name)
		}
		return []byte(v), nil
	case "file":
		// Scope the read to src.Dir: reject a name that escapes it via `..`.
		full := filepath.Join(src.Dir, name)
		if rel, err := filepath.Rel(src.Dir, full); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("secret: file ref %q escapes source dir %q", name, src.Dir)
		}
		return os.ReadFile(full)
	case "kms":
		return nil, fmt.Errorf("secret: kms source %q: %w", src.Name, ErrNotImplemented)
	default:
		return nil, fmt.Errorf("secret: source %q unknown type %q", src.Name, src.Type)
	}
}

// Identity interprets the referenced bytes as an SSH private key (OpenSSH PEM),
// falling back to a passphrase identity.
func (r *mapResolver) Identity(ref string) (keyring.Identity, error) {
	b, err := r.Bytes(ref)
	if err != nil {
		return nil, err
	}
	if isPrivateKeyPEM(b) {
		return keyring.SSHIdentity(b, nil)
	}
	return keyring.PassphraseIdentity(bytes.TrimSpace(b))
}

// Recipient interprets the referenced bytes as an SSH authorized_keys line,
// falling back to a passphrase recipient.
func (r *mapResolver) Recipient(ref string) (keyring.Recipient, error) {
	b, err := r.Bytes(ref)
	if err != nil {
		return nil, err
	}
	if isAuthorizedKeyLine(b) {
		return keyring.SSHRecipient(b)
	}
	return keyring.PassphraseRecipient(bytes.TrimSpace(b))
}

// MasterIdentity interprets the referenced bytes as an ed25519 SSH private key —
// the only signer keyring accepts as a master or writer.
func (r *mapResolver) MasterIdentity(ref string) (keyring.MasterIdentity, error) {
	b, err := r.Bytes(ref)
	if err != nil {
		return nil, err
	}
	return keyring.SSHMasterIdentity(b, nil)
}

// MasterRecipient interprets the referenced bytes as an ssh-ed25519
// authorized_keys line — a master or writer public key.
func (r *mapResolver) MasterRecipient(ref string) (keyring.MasterRecipient, error) {
	b, err := r.Bytes(ref)
	if err != nil {
		return nil, err
	}
	return keyring.SSHMasterRecipient(b)
}

// isPrivateKeyPEM reports whether b is a PEM block (a private key), matched on
// the "-----BEGIN" armor rather than a substring so a passphrase that merely
// contains "PRIVATE KEY" isn't misrouted.
func isPrivateKeyPEM(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN"))
}

// isAuthorizedKeyLine reports whether b looks like an authorized_keys public-key
// line (its leading key-type token).
func isAuthorizedKeyLine(b []byte) bool {
	t := bytes.TrimSpace(b)
	return bytes.HasPrefix(t, []byte("ssh-")) || bytes.HasPrefix(t, []byte("ecdsa-")) || bytes.HasPrefix(t, []byte("sk-"))
}

// lookup splits a "source:name" ref and finds its declared source. A ref with no
// colon is ErrMalformedRef and an undeclared source is ErrUnknownSource, so a
// caller can distinguish "not a reference" from "a broken reference".
func (r *mapResolver) lookup(ref string) (config.SecretSource, string, error) {
	src, name, ok := strings.Cut(ref, ":")
	if !ok {
		return config.SecretSource{}, "", fmt.Errorf("%w: %q", ErrMalformedRef, ref)
	}
	s, ok := r.sources[src]
	if !ok {
		return config.SecretSource{}, "", fmt.Errorf("%w %q in ref %q", ErrUnknownSource, src, ref)
	}
	return s, name, nil
}
