package backend

import (
	"context"
	"fmt"

	"gosqlite.org"
	"gosqlite.org/server/config"
	"gosqlite.org/server/secret"
	"gosqlite.org/vfs/crypto"
	"gosqlite.org/vfs/vault"
)

// vaultBackend opens a vfs/vault container (compression and/or encryption).
// The server is the single owner of the file (in-process advisory locks only,
// no cross-process sharing), which is the whole reason this daemon exists.
type vaultBackend struct {
	cfg  sqlite.Config
	opts vault.Options
	ro   bool
}

func (b *vaultBackend) Open(ctx context.Context) (*sqlite.DB, error) {
	return vault.Open(b.cfg, b.opts)
}
func (b *vaultBackend) Kind() string   { return "vault" }
func (b *vaultBackend) ReadOnly() bool { return b.ro }

// newVault resolves the OPEN-time options (compression, cipher, raw key,
// identities, authenticate, anchor). Write-signing (write_as/masters) and the
// create-only provisioning block are seams filled in Phase 5.
func newVault(db config.Database, sec secret.Resolver, dataDir string) (Backend, error) {
	be := &vaultBackend{cfg: baseConfig(db, dataDir), ro: db.Mode == "ro"}
	vc := db.Vault
	if vc == nil {
		return be, nil // plain container (no compression, no encryption)
	}

	lvl, err := compressionLevel(vc.Compression)
	if err != nil {
		return nil, err
	}
	be.opts.Level = lvl
	be.opts.Cipher = cipher(vc.Cipher)

	if vc.Key != "" {
		if be.opts.Key, err = sec.Bytes(vc.Key); err != nil {
			return nil, fmt.Errorf("vault %q key: %w", db.Name, err)
		}
	}
	for _, ref := range vc.Identities {
		id, err := sec.Identity(ref)
		if err != nil {
			return nil, fmt.Errorf("vault %q identity: %w", db.Name, err)
		}
		be.opts.Identities = append(be.opts.Identities, id)
	}
	be.opts.Authenticate = vc.Authenticate
	if vc.Anchor != nil {
		switch vc.Anchor.Type {
		case "file":
			be.opts.Anchor = vault.FileAnchor(resolvePath(vc.Anchor.Path, dataDir))
		case "tpm", "kms":
			return nil, fmt.Errorf("vault %q anchor %q: wired in Phase 5", db.Name, vc.Anchor.Type)
		default:
			return nil, fmt.Errorf("vault %q unknown anchor type %q", db.Name, vc.Anchor.Type)
		}
	}
	return be, nil
}

// compressionLevel maps the config tier to vault.Compression. The names ARE the
// tiers (none=off, fastest/fast=LZ4/LZ4-HC, default/better/best=zstd).
func compressionLevel(s string) (vault.Compression, error) {
	switch s {
	case "", "none":
		return vault.CompressionNone, nil
	case "fastest":
		return vault.CompressionFastest, nil
	case "fast":
		return vault.CompressionFast, nil
	case "default":
		return vault.CompressionDefault, nil
	case "better":
		return vault.CompressionBetter, nil
	case "best":
		return vault.CompressionBest, nil
	default:
		return vault.CompressionNone, fmt.Errorf("vault: unknown compression %q", s)
	}
}

func cipher(s string) crypto.Cipher {
	if s == "aes-xts" {
		return crypto.AESXTS
	}
	return crypto.Adiantum
}
