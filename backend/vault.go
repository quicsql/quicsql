package backend

import (
	"context"
	"errors"
	"fmt"
	"os"

	"gosqlite.org"
	"gosqlite.org/crypto/keyring"
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

	// sec, vc, and name let the key-management ops (rekey/rewrap/members) re-resolve
	// the configured create-time membership on demand. vc may be nil (plain container).
	sec  secret.Resolver
	vc   *config.VaultConfig
	name string
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

// SnapshotEncrypted writes a densely-packed, re-sealed copy of the closed
// container to dst (backend.EncryptedSnapshotter): an encrypted vault stays
// encrypted — re-sealed with the SAME runtime options, so no plaintext touches
// disk — while a compression-only vault yields a compressed plaintext copy. The
// registry must hold the path reservation (handle closed) while this runs.
//
// Raw-key vaults re-seal cleanly (the key opens and re-seals). A recipient/
// identity-mode vault opened at runtime carries no create-time recipients, so it
// cannot be re-sealed in-band — vault.Snapshot refuses rather than write plaintext;
// snapshot such a vault out of band.
func (b *vaultBackend) SnapshotEncrypted(dst string) error {
	return vault.Snapshot(dst, b.cfg.Path, b.opts, b.opts)
}

// keyMgmtArgs re-resolves the configured create-time membership into the arguments
// the vault key-management ops take: the master identity that authorizes the
// change (create.sign_with), the writer that signs the commit (write_as), and the
// target membership (create.recipients/masters/writers). These ops manage the
// keyslot of a recipient-mode, master-protected vault; a raw-key or create-less
// vault has no membership to manage.
func (b *vaultBackend) keyMgmtArgs() (by keyring.Identity, writeAs keyring.WriterIdentity, m keyring.Membership, err error) {
	if b.vc == nil || b.vc.Create == nil {
		return nil, nil, keyring.Membership{}, errors.New("vault key management requires a recipient-mode vault with a create: membership in config")
	}
	var o vault.Options
	if err := createVaultOptions(&o, b.name, b.vc, b.sec); err != nil {
		return nil, nil, keyring.Membership{}, err
	}
	if o.SignWith == nil {
		return nil, nil, keyring.Membership{}, errors.New("vault key management requires create.sign_with (a master identity)")
	}
	return o.SignWith, o.WriteAs, keyring.Membership{Masters: o.Masters, Writers: o.Writers, Members: o.Recipients}, nil
}

// masterIdentity resolves ONLY the create.sign_with master identity — the single
// credential the read-only VaultMembers enumeration needs to unwrap the keyslot.
// Unlike keyMgmtArgs it deliberately does NOT resolve the recipient/writer/write_as
// secrets a mutating rewrap/rekey requires, so merely listing membership never
// re-execs a KMS command for creds it will not use.
func (b *vaultBackend) masterIdentity() (keyring.Identity, error) {
	if b.vc == nil || b.vc.Create == nil {
		return nil, errors.New("vault key management requires a recipient-mode vault with a create: membership in config")
	}
	if b.vc.Create.SignWith == "" {
		return nil, errors.New("vault key management requires create.sign_with (a master identity)")
	}
	mi, err := b.sec.MasterIdentity(b.vc.Create.SignWith)
	if err != nil {
		return nil, fmt.Errorf("vault %q sign_with: %w", b.name, err)
	}
	return mi, nil
}

// VaultMembers enumerates the keyslot membership (masters, writers, read-only
// members) of a recipient-mode vault (backend.VaultKeyManager). The container must
// be closed (the registry must hold the path reservation).
func (b *vaultBackend) VaultMembers() ([]VaultMember, error) {
	by, err := b.masterIdentity()
	if err != nil {
		return nil, err
	}
	ms, err := vault.Members(b.cfg.Path, by)
	if err != nil {
		return nil, err
	}
	out := make([]VaultMember, len(ms))
	for i, mem := range ms {
		out[i] = VaultMember{Role: mem.Role, Key: mem.Key, Label: mem.Label}
	}
	return out, nil
}

// Rewrap re-wraps the vault's data key to the configured membership WITHOUT
// re-encrypting data — O(1) access-list management (backend.VaultKeyManager).
// The container must be closed (path reservation held).
func (b *vaultBackend) Rewrap() error {
	by, writeAs, m, err := b.keyMgmtArgs()
	if err != nil {
		return err
	}
	return vault.Rewrap(b.cfg.Path, by, writeAs, m)
}

// Rekey re-encrypts the vault under a fresh data key wrapped to the configured
// membership — O(database size), true cryptographic revocation
// (backend.VaultKeyManager). The container must be closed (path reservation held).
func (b *vaultBackend) Rekey() error {
	by, writeAs, m, err := b.keyMgmtArgs()
	if err != nil {
		return err
	}
	return vault.Rekey(b.cfg.Path, by, writeAs, m)
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
	be := &vaultBackend{cfg: baseConfig(db, dataDir), ro: db.Mode == "ro", sec: sec, vc: db.Vault, name: db.Name}
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
