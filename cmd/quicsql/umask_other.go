//go:build !unix

package main

// hardenUmask is a no-op off Unix (Windows has no umask; file access there is
// governed by NTFS ACLs, not a creation mask).
func hardenUmask() {}
