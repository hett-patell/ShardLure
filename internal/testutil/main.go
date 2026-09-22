// Package testutil contains shared test-only setup and fixtures.
package testutil

import (
	"os"
	"testing"
)

// Main makes temporary database/evidence fixtures private regardless of the
// invoking developer's umask. Permission-rejection tests set unsafe modes
// explicitly; the process's original mask is restored when tests finish.
func Main(m *testing.M) {
	restore := privatePermissions()
	code := m.Run()
	restore()
	os.Exit(code)
}
