// Package intelutil holds tiny helpers shared by sibling intel
// packages (ioc, deobf, …) that are too small to justify their own
// home but too widely needed to copy-paste safely.
package intelutil

// Truncate returns s shortened to at most n bytes with a trailing
// ellipsis when truncation occurs. The ellipsis is one rune (3 UTF-8
// bytes) and does not count against n - this matches the existing
// callers' expectations (they only care about display width).
//
// Truncate is byte-oriented; if s contains multi-byte runes whose
// boundary falls inside the [0:n] slice the output will contain a
// broken rune. None of the current callers feed it non-ASCII so we
// keep it simple.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
