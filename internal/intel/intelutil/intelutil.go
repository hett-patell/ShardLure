// Package intelutil holds tiny helpers shared by sibling intel
// packages (ioc, deobf, …) that are too small to justify their own
// home but too widely needed to copy-paste safely.
package intelutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// WaitForProviderAttempt enforces a minimum gap after the previous request
// completed while allowing shutdown or request cancellation to interrupt it.
func WaitForProviderAttempt(ctx context.Context, last time.Time, gap time.Duration) error {
	if last.IsZero() || gap <= 0 {
		return nil
	}
	wait := gap - time.Since(last)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ReadBoundedResponse reads at most limit bytes and rejects a body that has
// even one byte beyond the cap. io.LimitReader(limit) alone cannot distinguish
// an exact-limit body from a truncated oversized response.
func ReadBoundedResponse(service string, body io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, SafeRequestError(service, "read response", err)
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s: response too large", service)
	}
	return raw, nil
}

// SafeRequestError returns a bounded provider error without carrying the
// request URL or transport's diagnostic text. http.Client errors commonly
// include the complete URL; configured endpoints may contain credentials in
// query parameters, and proxy errors may echo request details. Cancellation
// identity is preserved so callers can stop cleanly during shutdown.
func SafeRequestError(service, operation string, err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %s: %w", service, operation, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %s: %w", service, operation, context.DeadlineExceeded)
	}
	return fmt.Errorf("%s: %s failed", service, operation)
}

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

// SanitiseAbuseChTags normalises a tag list for the abuse.ch APIs.
//
// abuse.ch's tag validator accepts only [A-Za-z0-9.- ], and it rejects the
// WHOLE submission over one stray character — a slash in an attacker-supplied
// filename is enough. Disallowed characters are dropped rather than
// substituted, so a tag can never smuggle punctuation upstream.
//
// This lives here because MalwareBazaar and URLhaus share the rule (one
// abuse.ch account, one validator) and previously each carried its own copy:
// a rune switch in bazaar and a regex in urlhaus, which had already drifted
// (only one of them de-duplicated deterministically). One upstream rule should
// have exactly one implementation.
//
// The result is de-duplicated and sorted so repeated submissions produce
// byte-identical payloads, which makes them diffable in logs.
func SanitiseAbuseChTags(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		var b strings.Builder
		b.Grow(len(t))
		for _, r := range t {
			switch {
			case r >= 'A' && r <= 'Z',
				r >= 'a' && r <= 'z',
				r >= '0' && r <= '9',
				r == '.', r == '-', r == ' ':
				b.WriteRune(r)
			}
		}
		s := strings.TrimSpace(b.String())
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
