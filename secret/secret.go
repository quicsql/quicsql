// Package secret resolves "source:name" references to key material. All sources
// are unattended and resolved eagerly at config-load — there is no interactive
// unlock, so the daemon starts without human interaction.
//
// Phase 0 wires the env and file sources for raw key bytes; the kms source and
// the keyring Identity/Recipient resolvers are seams filled in Phase 4/5.
package secret

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gosqlite.org/crypto/keyring"
	"gosqlite.org/server/config"
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
	// Identity returns a keyring identity for recipient-mode vault opens.
	Identity(ref string) (keyring.Identity, error)
	// Recipient returns a keyring recipient for create-time provisioning.
	Recipient(ref string) (keyring.Recipient, error)
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

func (r *mapResolver) Identity(ref string) (keyring.Identity, error) {
	return nil, fmt.Errorf("secret: Identity(%q): %w", ref, ErrNotImplemented)
}

func (r *mapResolver) Recipient(ref string) (keyring.Recipient, error) {
	return nil, fmt.Errorf("secret: Recipient(%q): %w", ref, ErrNotImplemented)
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
