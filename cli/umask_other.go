//go:build !unix

package cli

// hardenUmask is a no-op off Unix (Windows has no umask; file access there is
// governed by NTFS ACLs, not a creation mask).
func hardenUmask() {}
