//go:build !unix

package main

func databaseOwnerHint(string) string { return "" }
