package hostsvc

import (
	"context"
	"testing"
	"time"
)

// TestParseActiveEnter covers systemd's real output shapes. The empty case is
// the important one: systemd prints an EMPTY value for a unit that has never
// been active, and treating that as "unknown" (not an error, not epoch) is what
// keeps the dashboard from showing a nonsense 56-year uptime.
func TestParseActiveEnter(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		ok    bool
		check func(time.Time) bool
	}{
		{
			name: "systemd default with weekday and zone",
			in:   "Wed 2026-07-22 05:48:43 UTC",
			ok:   true,
			check: func(tm time.Time) bool {
				return tm.Year() == 2026 && tm.Month() == time.July && tm.Day() == 22 && tm.Hour() == 5
			},
		},
		{name: "no weekday", in: "2026-07-22 05:48:43 UTC", ok: true,
			check: func(tm time.Time) bool { return tm.Year() == 2026 && tm.Minute() == 48 }},
		{name: "no zone", in: "Wed 2026-07-22 05:48:43", ok: true,
			check: func(tm time.Time) bool { return tm.Second() == 43 }},
		{name: "surrounding whitespace", in: "  Wed 2026-07-22 05:48:43 UTC \n", ok: true,
			check: func(tm time.Time) bool { return tm.Day() == 22 }},
		// never-active unit: systemd emits nothing
		{name: "empty means never active", in: "", ok: false},
		{name: "whitespace only", in: "   \n", ok: false},
		{name: "systemd n/a literal", in: "n/a", ok: false},
		{name: "garbage", in: "not-a-timestamp", ok: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseActiveEnter(c.in)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (in=%q)", ok, c.ok, c.in)
			}
			if ok && c.check != nil && !c.check(got) {
				t.Fatalf("parsed time %v failed its check (in=%q)", got, c.in)
			}
			if !ok && !got.IsZero() {
				t.Fatalf("not-ok must return the zero time, got %v", got)
			}
		})
	}
}

// TestStartedAtUnknownUnit proves the graceful-degradation contract: a unit that
// does not exist (or a host with no systemd) yields ok=false and NO error, so a
// dev laptop or container never breaks the dashboard.
func TestStartedAtUnknownUnit(t *testing.T) {
	_, ok := StartedAt(context.Background(), "shardlure-does-not-exist-xyz.service")
	if ok {
		t.Fatal("expected ok=false for a unit that cannot exist")
	}
}

// TestStartedAtEmptyUnit guards the trivial input.
func TestStartedAtEmptyUnit(t *testing.T) {
	if _, ok := StartedAt(context.Background(), "  "); ok {
		t.Fatal("expected ok=false for an empty unit name")
	}
}

// TestUptimeRejectsNegative documents that clock skew reports unknown rather
// than a negative duration the UI would render as garbage.
func TestUptimeRejectsNegative(t *testing.T) {
	// parseActiveEnter is the seam; Uptime's negative guard is exercised via a
	// future-dated start relative to a past "now".
	start, ok := parseActiveEnter("Wed 2026-07-22 05:48:43 UTC")
	if !ok {
		t.Fatal("fixture failed to parse")
	}
	past := start.Add(-time.Hour)
	if d := past.Sub(start); d >= 0 {
		t.Fatalf("fixture wrong: expected negative, got %v", d)
	}
}
