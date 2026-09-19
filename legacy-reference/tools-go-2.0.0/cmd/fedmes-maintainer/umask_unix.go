//go:build !windows

package main

import "syscall"

func init() {
	// Ensure files created by the root maintainer are private unless explicitly relaxed.
	syscall.Umask(0o077)
}
