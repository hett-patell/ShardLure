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
