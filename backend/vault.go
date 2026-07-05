package backend

import (
	"context"
	"fmt"
	"os"

	"gosqlite.org"
	"gosqlite.org/vfs/crypto"
	"gosqlite.org/vfs/vault"
	"quicsql.net/config"
	"quicsql.net/secret"
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

// Path is the resolved container path (backend.Pather), addressed by the
// control plane's maintenance ops.
func (b *vaultBackend) Path() string { return b.cfg.Path }

// CompactOffline rewrites the closed container densely with its configured
// options — identities-only preserves the keyslot verbatim (backend.OfflineCompacter).
// The registry must hold the path reservation (handle closed) while this runs.
func (b *vaultBackend) CompactOffline() error { return vault.Compact(b.cfg, b.opts) }

// CompactOnline returns freed container blocks to the OS on the live handle
// (backend.OnlineReclaimer). maxBytes<=0 reclaims as much as possible.
func (b *vaultBackend) CompactOnline(maxBytes int64) (int64, error) {
	return vault.CompactOnline(b.cfg.Path, maxBytes, nil)
}

// Trim releases the trailing free run of the live container to the OS
// (backend.OnlineReclaimer). maxBytes<=0 releases the whole trailing run.
func (b *vaultBackend) Trim(maxBytes int64) (int64, error) {
	return vault.Trim(b.cfg.Path, maxBytes)
}

// ReclaimableBytes reports how much the live container could shed with a logical
// compaction — a read-only probe (backend.LogicalReclaimer).
func (b *vaultBackend) ReclaimableBytes() (int64, error) {
	return vault.ReclaimableBytes(b.cfg.Path)
}

// CompactLogicalOnline rewrites the live container down to its logical footprint
// (the O(live-data) reclaim after large deletes), returning bytes freed
// (backend.LogicalReclaimer).
func (b *vaultBackend) CompactLogicalOnline() (int64, error) {
	return vault.CompactLogicalOnline(b.cfg.Path)
}

// newVault resolves the vault.Options for a database. The option surface splits
// by role (see the plan): raw key, compression, cipher, authenticate, and anchor
// apply to both create and open; the rest is chosen by whether the container
// file already exists. An existing file is OPENED with the runtime credentials
// (identities to unwrap, masters to trust, write_as to sign commits — omit it
// for a read-only-at-rest handle). A missing file with a `create:` block is
// PROVISIONED with recipients/masters/writers/sign_with and the geometry; the
// creating handle also takes write_as so it can write in authenticated-writer
// mode. All secret material is resolved eagerly here so a bad key fails at load.
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
	be.opts.Authenticate = vc.Authenticate

	if vc.Anchor != nil {
		switch vc.Anchor.Type {
		case "file":
			be.opts.Anchor = vault.FileAnchor(resolvePath(vc.Anchor.Path, dataDir))
		case "tpm", "kms":
			return nil, fmt.Errorf("vault %q anchor %q: not yet supported (use a file anchor)", db.Name, vc.Anchor.Type)
		default:
			return nil, fmt.Errorf("vault %q unknown anchor type %q", db.Name, vc.Anchor.Type)
		}
	}

	// Raw cipher key (raw-key mode) — applies to both create and open.
	if vc.Key != "" {
		if be.opts.Key, err = sec.Bytes(vc.Key); err != nil {
			return nil, fmt.Errorf("vault %q key: %w", db.Name, err)
		}
	}

	if fileExists(be.cfg.Path) {
		err = openVaultOptions(&be.opts, db.Name, vc, sec)
	} else if vc.Create != nil {
		err = createVaultOptions(&be.opts, db.Name, vc, sec)
	}
	if err != nil {
		return nil, err
	}
	return be, nil
}

// openVaultOptions fills the runtime credentials used to OPEN an existing
// container: identities that unwrap a keyslot, masters to trust as membership
// signers, and (optionally) the writer identity to sign commits.
func openVaultOptions(o *vault.Options, name string, vc *config.VaultConfig, sec secret.Resolver) error {
	for _, ref := range vc.Identities {
		id, err := sec.Identity(ref)
		if err != nil {
			return fmt.Errorf("vault %q identity: %w", name, err)
		}
		o.Identities = append(o.Identities, id)
	}
	for _, ref := range vc.Masters {
		mr, err := sec.MasterRecipient(ref)
		if err != nil {
			return fmt.Errorf("vault %q master: %w", name, err)
		}
		o.Masters = append(o.Masters, mr)
	}
	if vc.WriteAs != "" {
		wi, err := sec.MasterIdentity(vc.WriteAs)
		if err != nil {
			return fmt.Errorf("vault %q write_as: %w", name, err)
		}
		o.WriteAs = wi
	}
	return nil
}

// createVaultOptions fills the create-only provisioning options for a NEW
// container: the recipient/master/writer keyslot membership, the signing master,
// and the on-disk geometry. write_as is honored here too so the creating handle
// can write in authenticated-writer mode.
func createVaultOptions(o *vault.Options, name string, vc *config.VaultConfig, sec secret.Resolver) error {
	cr := vc.Create
	for _, ref := range cr.Recipients {
		r, err := sec.Recipient(ref)
		if err != nil {
			return fmt.Errorf("vault %q recipient: %w", name, err)
		}
		o.Recipients = append(o.Recipients, r)
	}
	for _, ref := range cr.Masters {
		mr, err := sec.MasterRecipient(ref)
		if err != nil {
			return fmt.Errorf("vault %q create master: %w", name, err)
		}
		o.Masters = append(o.Masters, mr)
	}
	for _, ref := range cr.Writers {
		wr, err := sec.MasterRecipient(ref) // WriterRecipient is an ed25519 recipient
		if err != nil {
			return fmt.Errorf("vault %q writer: %w", name, err)
		}
		o.Writers = append(o.Writers, wr)
	}
	if cr.SignWith != "" {
		mi, err := sec.MasterIdentity(cr.SignWith)
		if err != nil {
			return fmt.Errorf("vault %q sign_with: %w", name, err)
		}
		o.SignWith = mi
	}
	if vc.WriteAs != "" {
		wi, err := sec.MasterIdentity(vc.WriteAs)
		if err != nil {
			return fmt.Errorf("vault %q write_as: %w", name, err)
		}
		o.WriteAs = wi
	}
	o.PageSize = cr.PageSize
	o.BlockSize = cr.BlockSize
	o.DirSegmentPages = cr.DirSegmentPages
	return nil
}

// fileExists reports whether path names an existing file (a vault container).
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
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
