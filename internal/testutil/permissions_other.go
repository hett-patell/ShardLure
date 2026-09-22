//go:build !unix

package testutil

func privatePermissions() func() { return func() {} }
