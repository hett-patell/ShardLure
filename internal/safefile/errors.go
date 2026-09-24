// Package safefile provides descriptor-confined access to untrusted evidence
// and recovery bundles. Errors contain fixed categories, never supplied paths.
package safefile

import (
	"errors"
	"io/fs"
)

var (
	ErrUnsafePath  = errors.New("safefile: unsafe path")
	ErrNotRegular  = errors.New("safefile: regular single-link file required")
	ErrChanged     = errors.New("safefile: file identity changed")
	ErrUnsupported = errors.New("safefile: unsupported platform or filesystem")
	ErrInvalidMode = errors.New("safefile: owner-only non-executable mode required")
	ErrIO          = errors.New("safefile: I/O failed")
	ErrSync        = errors.New("safefile: durable publication failed")
	ErrNoSpace     = errors.New("safefile: insufficient filesystem space")
	ErrExists      = fs.ErrExist
	ErrNotExist    = fs.ErrNotExist
	ErrPermission  = fs.ErrPermission
	ErrClosed      = fs.ErrClosed
)

// Category returns a fixed, non-sensitive sentinel name for the first
// safefile error that matches err, or "unknown" if none match.  It is
// safe to log because the sentinels are compile-time constants that
// never contain paths, hostnames, or other caller-supplied data.
func Category(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, ErrUnsafePath):
		return "ErrUnsafePath"
	case errors.Is(err, ErrNotRegular):
		return "ErrNotRegular"
	case errors.Is(err, ErrChanged):
		return "ErrChanged"
	case errors.Is(err, ErrUnsupported):
		return "ErrUnsupported"
	case errors.Is(err, ErrInvalidMode):
		return "ErrInvalidMode"
	case errors.Is(err, ErrIO):
		return "ErrIO"
	case errors.Is(err, ErrSync):
		return "ErrSync"
	case errors.Is(err, ErrNoSpace):
		return "ErrNoSpace"
	case errors.Is(err, ErrExists):
		return "ErrExists"
	case errors.Is(err, ErrNotExist):
		return "ErrNotExist"
	case errors.Is(err, ErrPermission):
		return "ErrPermission"
	case errors.Is(err, ErrClosed):
		return "ErrClosed"
	default:
		return "unknown"
	}
}
