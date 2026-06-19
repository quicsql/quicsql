//go:build unix

package main

import "syscall"

// hardenUmask restricts the process file-creation mask so the daemon's
// databases, WAL sidecars, meta store, and snapshots are created owner-only
// (0600) rather than world-readable (0644 under the common umask 022) — these
// files can hold plaintext data and the audit log. Set only in the standalone
// daemon, never in serverd.Run, so in-process embedders keep control of their
// own umask.
func hardenUmask() { syscall.Umask(0o077) }
