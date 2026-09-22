//go:build !unix

package store

func CheckDatabaseOwner(string) error { return ErrDatabaseUnsupported }
