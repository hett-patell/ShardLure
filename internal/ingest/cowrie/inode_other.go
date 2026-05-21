//go:build !unix

package cowrie

import "os"

func fileInode(fi os.FileInfo) uint64 { return 0 }
