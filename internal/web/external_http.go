package web

import (
	"context"
	"errors"
	"net"
	"strings"
)

// externalHTTPError discards URLs and nested error text: both may contain
// credentials in query parameters, userinfo, or upstream response bodies.
func externalHTTPError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "request canceled"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return "request timed out"
	}
	return "transport error"
}

// These prefixes wrap untrusted provider text; never echo their suffixes.
func safeSettingsTestMessage(msg string) string {
	switch {
	case strings.HasPrefix(msg, "unreachable:"):
		return "unreachable: transport error"
	case strings.HasPrefix(msg, "provider error:"):
		return "provider returned an error"
	default:
		return msg
	}
}
