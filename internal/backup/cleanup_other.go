//go:build !linux

package backup

import (
	"errors"
	"io/fs"
)

// removeOwnStaging is Linux-only (it needs descriptor-relative unlinkat); on
// other platforms a failed create keeps its staging directory and the CLI
// reports where it is.
func removeOwnStaging(string, fs.FileInfo, fs.FileInfo, string) error {
	return errors.ErrUnsupported
}
