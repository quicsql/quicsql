module quicsql.net

go 1.26.0

require (
	github.com/quic-go/quic-go v0.60.0
	go.yaml.in/yaml/v3 v3.0.4
	golang.org/x/crypto v0.53.0
	golang.org/x/net v0.55.0
	golang.org/x/sys v0.46.0
	gosqlite.org v0.12.0
	gosqlite.org/blobstore v0.0.0-00010101000000-000000000000
	gosqlite.org/crypto/keyring v0.12.0
	gosqlite.org/vfs/crypto v0.12.0
	gosqlite.org/vfs/vault v0.12.0
)

require (
	filippo.io/age v1.3.1 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	filippo.io/hpke v0.4.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-again/az v0.4.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/text v0.38.0 // indirect
	lukechampine.com/adiantum v1.1.1 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.52.0 // indirect
)

// Dev convenience so quicSQL builds against the sibling gosqlite checkout during
// co-development. The path holds whether resolved via the .quicsql symlink in the
// gosqlite repo or the real checkout — both sit two levels under the shared
// parent, so ../../sqlite reaches gosqlite either way. Consumers override these
// with their own replaces; a real release drops them for published versions.
replace gosqlite.org => ../../sqlite

replace gosqlite.org/vfs/vault => ../../sqlite/vfs/vault

replace gosqlite.org/vfs/crypto => ../../sqlite/vfs/crypto

replace gosqlite.org/crypto/keyring => ../../sqlite/crypto/keyring

replace gosqlite.org/blobstore => ../../sqlite/blobstore
