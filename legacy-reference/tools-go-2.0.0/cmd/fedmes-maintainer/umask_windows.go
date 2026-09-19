//go:build windows

package main

// Windows has no process umask. Each file is created with explicit permissions
// and sensitive material is additionally protected by the Windows security model.
