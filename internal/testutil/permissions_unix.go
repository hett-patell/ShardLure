//go:build unix

package testutil

import "syscall"

func privatePermissions() func() {
	previous := syscall.Umask(0077)
	return func() { syscall.Umask(previous) }
}
