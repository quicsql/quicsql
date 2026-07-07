// Command quicsql is the quicSQL server daemon (the core). It serves the
// native-JSON and Hrana endpoints over every transport (HTTP/1.1, cleartext h2c,
// HTTP/2 over TLS, HTTP/3 over QUIC, and Unix sockets).
//
// It is a single brand-named binary (not `-d`-suffixed) so later revisions can add
// subcommands (`quicsql serve`, `quicsql query`, `quicsql admin`) without a rename.
// The launcher lives in package cli (reusable by downstream products that compile in
// optional feature modules); this main only picks the core's module set (the curated
// extensions bundle) and its brand.
package main

import (
	"quicsql.net/cli"
	_ "quicsql.net/extensions" // curated, network-safe extension bundle (regexp, vec0, fts5, …)
)

// version is the build version, stamped at release time via
// -ldflags "-X main.version=<tag>" (see .goreleaser.yaml); "dev" otherwise.
var version = "dev"

func main() {
	cli.Main(cli.Options{Program: "quicsql", Version: version})
}
