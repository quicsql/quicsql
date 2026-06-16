package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDocExamplesParse validates that the YAML snippets shown in
// docs/databases.md actually parse and pass Validate() with no unknown-key
// warnings — so the guide's copy-pasteable configs stay honest. (Throwaway
// verification helper; delete if the doc is retired.)
func TestDocExamplesParse(t *testing.T) {
	examples := map[string]string{
		"file": `
databases:
  - name: app
    backend: file
    path: app.db
    mode: rwc
    pragmas_preset: recommended
    pragmas: { synchronous: NORMAL, cache_size: -20000, foreign_keys: true }
    pool: { max_open: 8, tx_lock: immediate, busy_timeout: 5s }
`,
		"memory-family": `
databases:
  - { name: scratch, backend: memory }
  - { name: cache,   backend: memory-shared }
  - { name: work,    backend: mvcc }
  - { name: temp,    backend: memdb }
`,
		"vault-rawkey": `
secrets:
  - { name: keys, type: file, dir: ./secrets }
databases:
  - name: catalog
    backend: vault
    path: catalog.vault
    vault: { compression: best, cipher: adiantum, key: keys:catalog }
`,
		"vault-recipient": `
secrets:
  - { name: keys, type: file, dir: ./secrets }
databases:
  - name: catalog
    backend: vault
    path: catalog.vault
    vault:
      compression: best
      cipher: adiantum
      identities: [ keys:catalog_a ]
      create:
        recipients: [ keys:catalog_a.pub ]
`,
		"vault-authenticated": `
secrets:
  - { name: keys, type: file, dir: ./secrets }
databases:
  - name: catalog
    backend: vault
    path: catalog.vault
    vault:
      cipher: adiantum
      authenticate: true
      identities: [ keys:catalog_a ]
      write_as: keys:writer
      masters: [ keys:master.pub ]
      create:
        recipients: [ keys:catalog_a.pub ]
        masters: [ keys:master.pub ]
        sign_with: keys:master
        writers: [ keys:writer.pub ]
`,
		"vault-geometry": `
secrets:
  - { name: keys, type: file, dir: ./secrets }
databases:
  - name: catalog
    backend: vault
    path: catalog.vault
    vault: { key: keys:catalog, create: { page_size: 8192, block_size: 65536, dir_segment_pages: 64 } }
`,
		"multi-backend": `
secrets:
  - { name: keys, type: file, dir: /etc/quicsql/secrets }
server:
  data_dir: /var/lib/quicsql
auth:
  principals:
    - { name: analyst, methods: [ { bearer: { token_hash: "<sha256-of-token>" } } ] }
    - { name: app,     methods: [ { bearer: { token_hash: "<sha256-of-token>" } } ] }
databases:
  - name: catalog
    backend: vault
    path: catalog.vault
    mode: rwc
    vault: { compression: best, cipher: adiantum, key: keys:catalog }
    grants: [ { principal: analyst, level: read-only } ]
  - name: app
    backend: file
    path: app.db
    mode: rwc
    pragmas_preset: recommended
    pool: { max_open: 8, tx_lock: immediate, busy_timeout: 5s }
    grants: [ { principal: app, level: read-write } ]
  - name: cache
    backend: memory-shared
    grants: [ { principal: "*", level: read-only } ]
`,
	}

	for name, yaml := range examples {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cfg.yaml")
			if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			for _, w := range c.Warnings() {
				t.Errorf("unexpected config warning (likely a wrong key in the doc): %s", w)
			}
		})
	}
}
