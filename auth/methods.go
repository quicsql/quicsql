package auth

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"quicsql.net/secret"
)

// errInvalidCredential marks a credential that was presented but did not verify
// (bad token, unmapped cert, forged signature). errUnauthenticated marks a
// request that presented no credential to a listener that requires one. Both map
// to HTTP 401.
var (
	errInvalidCredential = errors.New("auth: invalid credential")
	errUnauthenticated   = errors.New("auth: authentication required")
)

// keyringCred and passwordCred are the compiled credentials keyed in the
// Authenticator's per-method maps; each remembers which principal it grants.
type (
	keyringCred struct {
		pub  ed25519.PublicKey
		name string
	}
	passwordCred struct {
		hash []byte // bcrypt hash
		name string
	}
)

// resolve turns a method-parameter value into its concrete string. A value that
// is a secret reference ("source:name" naming a declared source) is resolved
// through sec; anything else is taken literally. A reference that names a real
// source but fails to read (env unset, file missing) is a hard error — only a
// non-reference falls back to the literal.
func resolve(sec secret.Resolver, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	b, err := sec.Bytes(v)
	switch {
	case err == nil:
		return strings.TrimSpace(string(b)), nil
	case errors.Is(err, secret.ErrMalformedRef), errors.Is(err, secret.ErrUnknownSource):
		return v, nil // not a secret reference — a literal value
	default:
		return "", err
	}
}

// toStrMap flattens a YAML-decoded method-parameter block to string values
// (scalars only), so an int like a uid renders as "1000".
func toStrMap(raw any) map[string]string {
	out := map[string]string{}
	if m, ok := raw.(map[string]any); ok {
		for k, v := range m {
			out[k] = strings.TrimSpace(fmt.Sprint(v))
		}
	}
	return out
}

// parseEd25519AuthorizedKey parses one ssh-ed25519 authorized_keys line into its
// canonical (comment-free) key string — the stable identifier the roster is
// indexed by — plus the ed25519 public key and the line's comment. A non-ed25519
// key is rejected: only ed25519 is a keyring signer (see crypto/keyring).
func parseEd25519AuthorizedKey(line []byte) (canonical string, pub ed25519.PublicKey, comment string, err error) {
	sshPub, comment, _, _, perr := ssh.ParseAuthorizedKey(line)
	if perr != nil {
		return "", nil, "", fmt.Errorf("auth: parse authorized key: %w", perr)
	}
	cpk, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		return "", nil, "", errors.New("auth: unsupported SSH key")
	}
	edpub, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return "", nil, "", errors.New("auth: keyring credential must be an ssh-ed25519 key")
	}
	canonical = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	return canonical, edpub, comment, nil
}

// ResolveParam resolves a config parameter that may be a secret reference,
// with resolve's exact semantics — exported for sibling packages (the
// enrollment service) that follow the same credential discipline.
func ResolveParam(sec secret.Resolver, v string) (string, error) { return resolve(sec, v) }

// ParseEd25519PublicKey parses an ssh-ed25519 authorized-keys line into its
// public key — exported for the enrollment service, which persists canonical
// key lines and re-admits them at startup.
func ParseEd25519PublicKey(line string) (ed25519.PublicKey, error) {
	_, pub, _, err := parseEd25519AuthorizedKey([]byte(line))
	return pub, err
}
