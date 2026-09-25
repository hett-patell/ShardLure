package main

import (
	"fmt"
	"regexp"
	"strings"
)

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:=@%+,-]+$`)

func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ownershipHint tells an operator which account owns the database and the
// exact command to rerun as that account. store.ErrDatabaseOwner alone named
// neither, so "shardlure dashboard" from a login shell ended in a dead end.
func ownershipHint(owner, euid uint32, lookup func(uint32) (string, bool), args []string) string {
	name, known := lookup(owner)
	who, as := fmt.Sprintf("uid %d", owner), fmt.Sprintf("'#%d'", owner)
	if known {
		who, as = name, shellQuote(name)
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	prefix := "sudo -u " + as + " "
	if owner == 0 {
		prefix = "sudo "
	}
	return fmt.Sprintf("the database is owned by %s; run: %s%s", who, prefix, strings.Join(quoted, " "))
}
