// Package extensions is the quicSQL server's standard extension bundle. Blank-
// importing it registers a curated, network-safe set of gosqlite extensions on
// every connection the server opens, so clients can use them through ordinary
// SQL — REGEXP, FTS5 (built into the engine), vec0 vector search, spellfix1,
// r-tree, and a spread of pure-compute functions.
//
//	import _ "gosqlite.org/server/extensions"
//
// The default quicsql daemon imports this. An in-process embedder that wants the
// same batteries imports it too; one that wants a different set imports the
// specific gosqlite.org/ext/<name>/auto packages (and gosqlite.org/vec) it needs
// before calling serverd.Run. Either way this is a SERVER-SIDE decision: the
// engine is composed by the binary, and clients inherit whatever it registered —
// a client cannot add or change extensions over the wire.
//
// # What is bundled
//
// Pure-computation functions and self-contained virtual tables only: regexp,
// spellfix1, r-tree, bloom filters, statistical/aggregate/text/time/unicode/
// hashing/uuid/decimal/money/fuzzy functions, generate_series, pivot, z-order,
// base/hex encoding, IP-address helpers, the transitive-closure graph vtab, and
// vec0 vector search. FTS5 is compiled into the engine, so it needs no import.
//
// # What is deliberately EXCLUDED (opt in via a custom server build)
//
// Anything that touches the host filesystem or evaluates arbitrary SQL is unsafe
// to expose by default on a network server, so it is not bundled here: fileio,
// csv, lines, blobio (filesystem), and eval / statement (arbitrary evaluation).
// A deployment that genuinely needs one builds its own binary that imports the
// specific ext/<name>/auto package and calls serverd.Run.
package extensions

import (
	// vec0 vector search (sqlite-vec) — registered on every connection.
	_ "gosqlite.org/vec"

	// Pure-compute / data-structure extensions, each auto-registered on open.
	_ "gosqlite.org/ext/array/auto"
	_ "gosqlite.org/ext/bloom/auto"
	_ "gosqlite.org/ext/closure/auto"
	_ "gosqlite.org/ext/decimal/auto"
	_ "gosqlite.org/ext/encode/auto"
	_ "gosqlite.org/ext/fuzzy/auto"
	_ "gosqlite.org/ext/hash/auto"
	_ "gosqlite.org/ext/ipaddr/auto"
	_ "gosqlite.org/ext/money/auto"
	_ "gosqlite.org/ext/pivot/auto"
	_ "gosqlite.org/ext/regexp/auto"
	_ "gosqlite.org/ext/rtree/auto"
	_ "gosqlite.org/ext/series/auto"
	_ "gosqlite.org/ext/spellfix1/auto"
	_ "gosqlite.org/ext/stats/auto"
	_ "gosqlite.org/ext/text/auto"
	_ "gosqlite.org/ext/time/auto"
	_ "gosqlite.org/ext/unicode/auto"
	_ "gosqlite.org/ext/uuid/auto"
	_ "gosqlite.org/ext/zorder/auto"
)
