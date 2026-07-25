// Package hostsvc reads liveness facts about sibling systemd units.
//
// ShardLure and Cowrie run as SEPARATE systemd units with no IPC — the only
// data contract between them is the JSON log file on disk. That boundary is
// deliberate, so this package is intentionally tiny and read-only: it asks
// systemd when a unit last started, and nothing else. It never starts, stops,
// or reconfigures anything.
package hostsvc

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// StartedAt returns when the given systemd unit entered the active state.
//
// Returns ok=false (no error) when the unit is inactive, unknown, or when the
// host has no systemd at all — callers treat that as "unknown", not a failure,
// because a missing systemctl is a normal condition on a dev laptop or in a
// container and must not degrade the dashboard.
func StartedAt(ctx context.Context, unit string) (t time.Time, ok bool) {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return time.Time{}, false
	}
	// Short timeout: this sits behind a cached dashboard endpoint, and a hung
	// systemctl must never stall the 5s poll path.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx,
		"systemctl", "show", unit, "-p", "ActiveEnterTimestamp", "--value").Output()
	if err != nil {
		return time.Time{}, false
	}
	return parseActiveEnter(string(out))
}

// parseActiveEnter parses systemd's ActiveEnterTimestamp value, e.g.
//
//	"Wed 2026-07-22 05:48:43 UTC"
//
// An empty value means the unit has never been active (systemd prints nothing),
// which is a legitimate "unknown" rather than a parse failure. Split out from
// StartedAt so the format handling is testable without a live systemd.
func parseActiveEnter(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	// systemd's default output carries a leading weekday and a trailing zone.
	// Try the documented layouts in order; tolerate a missing weekday.
	layouts := []string{
		"Mon 2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05 MST",
		"Mon 2006-01-02 15:04:05",
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Uptime returns how long the unit has been continuously active.
func Uptime(ctx context.Context, unit string, now time.Time) (d time.Duration, ok bool) {
	t, ok := StartedAt(ctx, unit)
	if !ok {
		return 0, false
	}
	if d = now.Sub(t); d < 0 {
		// Clock skew between systemd's timestamp zone and ours; report unknown
		// rather than a negative uptime.
		return 0, false
	}
	return d, true
}
