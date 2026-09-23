// fsprobe is a disposable-guest diagnostic, never a release asset or daemon.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/networkshard/shardlure/internal/safefile"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	path := os.Args[1]
	fmt.Printf("guest probe uid=%d gid=%d\n", os.Geteuid(), os.Getegid())
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			fmt.Printf("guest path %q unavailable\n", p)
		} else if s, ok := info.Sys().(*syscall.Stat_t); ok {
			fmt.Printf("guest path %q uid=%d gid=%d mode=%o\n", p, s.Uid, s.Gid, info.Mode().Perm())
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	r, err := safefile.EnsureDirectory(path)
	if err != nil {
		fmt.Printf("guest EnsureDirectory category: %v\n", err)
		os.Exit(1)
	}
	r.Close()
	fmt.Println("guest EnsureDirectory passed")
}
