package store

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var (
	ErrDatabaseOwner       = errors.New("database ownership mismatch: run as the owning service account")
	ErrDatabaseUnsafe      = errors.New("unsafe database path: use a private directory owned by the service account")
	ErrDatabaseAccess      = errors.New("database filesystem access could not be verified")
	ErrDatabaseUnsupported = errors.New("database ownership checks are unsupported on this platform")
)

// A configured database is a filename, not a caller-supplied SQLite DSN.
// Encoding both path and options keeps ?, #, %, spaces and Unicode literal.
func sqliteFileURI(path string, options url.Values) (string, error) {
	if path == "" || strings.ContainsRune(path, 0) || !utf8.ValidString(path) {
		return "", ErrDatabaseUnsafe
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", ErrDatabaseUnsafe
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: options.Encode()}
	return u.String(), nil
}
