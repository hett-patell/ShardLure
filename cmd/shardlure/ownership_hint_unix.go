//go:build unix

package main

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// databaseOwnerHint returns a hint for a refused database, or "" when the
// owner cannot be read (the store's own error still stands on its own).
func databaseOwnerHint(dbPath string) string {
	info, err := os.Lstat(dbPath)
	if err != nil {
		return ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	lookup := func(uid uint32) (string, bool) {
		u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
		if err != nil {
			return "", false
		}
		return u.Username, true
	}
	return ownershipHint(st.Uid, uint32(os.Geteuid()), lookup, os.Args)
}
