package abuseipdb

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
)

func brute(ip string, probe, events, users int, rate float64) ReportCandidate {
	return ReportCandidate{SrcIP: ip, Playbook: "dictionary_spray", ProbeScore: probe, EventCount: events, UniqueUsers: users, AttemptsPerHour: rate}
}

// TestSuggestRanksAndFilters verifies the composite ranking, the Vet gate
// (non-brute/admin/private excluded), the already-reported exclusion, and that
// reasons are populated.
func TestSuggestRanksAndFilters(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	admin := netmatch.New([]string{"10.0.0.0/8"})

	inputs := []SuggestInput{
		// Strong + active now → should rank #1.
		{Cand: brute("8.8.8.8", 95, 5000, 60, 800), LastSeen: now.Add(-10 * time.Minute)},
		// Equally strong but 5 days stale → ranks below the active one.
		{Cand: brute("1.1.1.1", 95, 5000, 60, 800), LastSeen: now.Add(-120 * time.Hour)},
		// Weak but passes floor, active → mid/low.
		{Cand: brute("9.9.9.9", 62, 25, 4, 30), LastSeen: now.Add(-30 * time.Minute)},
		// Vet rejects: admin IP.
		{Cand: brute("10.1.2.3", 95, 5000, 60, 800), LastSeen: now},
		// Vet rejects: not a brute playbook.
		{Cand: func() ReportCandidate {
			c := brute("8.8.4.4", 95, 5000, 60, 800)
			c.Playbook = "crypto_target"
			return c
		}(), LastSeen: now},
		// Vet rejects: below probe floor.
		{Cand: brute("1.0.0.1", 40, 5000, 60, 800), LastSeen: now},
		// Vet rejects: documentation-only address.
		{Cand: brute("203.0.113.10", 95, 5000, 60, 800), LastSeen: now},
	}

	got, _ := Suggest(inputs, admin, 60, 10, now, nil)
	if len(got) != 3 {
		t.Fatalf("expected 3 vetted suggestions, got %d: %+v", len(got), ips(got))
	}
	if got[0].SrcIP != "8.8.8.8" {
		t.Fatalf("expected active strong actor first, got %s", got[0].SrcIP)
	}
	// The active-strong actor must outrank the identical-but-stale one purely on
	// recency (this is the algorithm's headline behaviour).
	var activeP, staleP int
	for _, s := range got {
		if s.SrcIP == "8.8.8.8" {
			activeP = s.Priority
		}
		if s.SrcIP == "1.1.1.1" {
			staleP = s.Priority
		}
	}
	if activeP <= staleP {
		t.Fatalf("active actor priority %d must exceed stale actor %d", activeP, staleP)
	}
	// Every suggestion carries at least one reason.
	for _, s := range got {
		if len(s.Reasons) == 0 {
			t.Fatalf("%s has no reasons", s.SrcIP)
		}
		if s.Priority < 0 || s.Priority > 100 {
			t.Fatalf("%s priority out of range: %d", s.SrcIP, s.Priority)
		}
	}
}

// TestSuggestExcludesAlreadyReported confirms the dedup callback filters IPs
// already reported within the window.
func TestSuggestExcludesAlreadyReported(t *testing.T) {
	now := time.Now()
	inputs := []SuggestInput{
		{Cand: brute("8.8.8.8", 95, 5000, 60, 800), LastSeen: now},
		{Cand: brute("1.1.1.1", 95, 5000, 60, 800), LastSeen: now},
	}
	reported := map[string]bool{"8.8.8.8": true}
	got, _ := Suggest(inputs, nil, 60, 10, now, func(ip string) bool { return reported[ip] })
	if len(got) != 1 || got[0].SrcIP != "1.1.1.1" {
		t.Fatalf("expected only the unreported IP, got %+v", ips(got))
	}
}

// TestSuggestDropsDormantCandidates is the regression test for the bug this gate
// exists to close. On the reference deployment the widget offered six IPs, all
// last seen 31-50 days earlier and every one already reported the day before,
// while the actor attacking at that moment (probe 100, ~302k events, 1895
// usernames — the profile `live` below models) was nowhere in the list. The pool
// query hands Suggest actors from well outside the window, so Suggest — not just
// the caller — has to refuse them.
func TestSuggestDropsDormantCandidates(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)

	live := brute("1.1.1.1", 100, 302872, 1895, 373)
	live.LastSeen = now.Add(-5 * time.Minute)

	inputs := []SuggestInput{{Cand: live}}
	// Six dormant IPs with the same maximal signals, differing only in age. Under
	// the old behaviour their volume and probe score carried them straight through.
	for i, ageDays := range []int{31, 34, 38, 42, 47, 50} {
		c := brute("8.8.8."+itoa(i+1), 100, 302872, 1895, 373)
		c.LastSeen = now.Add(-time.Duration(ageDays) * 24 * time.Hour)
		inputs = append(inputs, SuggestInput{Cand: c})
	}

	got, _ := Suggest(inputs, nil, 60, 10, now, nil)
	if len(got) != 1 {
		t.Fatalf("expected only the live attacker, got %d: %+v", len(got), ips(got))
	}
	if got[0].SrcIP != live.SrcIP {
		t.Fatalf("suggested %s, want the currently-attacking %s", got[0].SrcIP, live.SrcIP)
	}
}

// TestSuggestRejectsUndateableCandidate pins the zero-value behaviour. It used to
// be scored as full recency weight — "unknown" read as "right now" — which is the
// most dangerous possible default for a gate whose whole job is dating the
// observation. An undateable candidate must be dropped, not promoted.
func TestSuggestRejectsUndateableCandidate(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	got, _ := Suggest([]SuggestInput{{Cand: brute("8.8.8.8", 95, 5000, 60, 800)}}, nil, 60, 10, now, nil)
	if len(got) != 0 {
		t.Fatalf("candidate with no LastSeen on either field was suggested: %+v", ips(got))
	}
}

// TestSuggestCandLastSeenWinsOverWrapper pins the precedence between the new
// field and the deprecated wrapper. It matters because the wrapper is the LOOSER
// path: were it to win, a caller could set a fresh wrapper value beside a dormant
// Cand.LastSeen and walk a stale IP past the gate.
func TestSuggestCandLastSeenWinsOverWrapper(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	c := brute("8.8.8.8", 95, 5000, 60, 800)
	c.LastSeen = now.Add(-40 * 24 * time.Hour) // dormant: authoritative
	got, _ := Suggest([]SuggestInput{{Cand: c, LastSeen: now}}, nil, 60, 10, now, nil)
	if len(got) != 0 {
		t.Fatalf("a fresh deprecated LastSeen overrode a dormant Cand.LastSeen: %+v", ips(got))
	}

	// And the fallback still works in the direction it was kept for: wrapper-only
	// callers keep functioning, so this must NOT be an empty result.
	fresh := brute("8.8.8.8", 95, 5000, 60, 800)
	if got, _ := Suggest([]SuggestInput{{Cand: fresh, LastSeen: now.Add(-time.Hour)}}, nil, 60, 10, now, nil); len(got) != 1 {
		t.Fatalf("wrapper-only caller stopped working: got %d suggestions, want 1", len(got))
	}
}

// TestSuggestReasonsNeverClaimRecentWhenStale guards the reason strings. A
// suggestion is only actionable if its explanation is true — an operator reading
// "recent activity" beside a 5-day-old IP would file a report they can't defend.
func TestSuggestReasonsNeverClaimRecentWhenStale(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	for _, ageHours := range []int{0, 12, 40, 80, 100, 140, 167} {
		c := brute("8.8.8.8", 95, 5000, 60, 800)
		c.LastSeen = now.Add(-time.Duration(ageHours) * time.Hour)
		got, _ := Suggest([]SuggestInput{{Cand: c}}, nil, 60, 10, now, nil)
		if len(got) != 1 {
			t.Fatalf("age %dh: expected 1 suggestion, got %d", ageHours, len(got))
		}
		for _, r := range got[0].Reasons {
			switch {
			case ageHours >= 24 && contains(r, "active today"):
				t.Errorf("age %dh labelled %q", ageHours, r)
			case ageHours >= 1 && contains(r, "active now"):
				t.Errorf("age %dh labelled %q", ageHours, r)
			case ageHours >= 72 && contains(r, "last 3 days"):
				t.Errorf("age %dh labelled %q", ageHours, r)
			}
		}
	}
}

// TestSuggestLimit caps the result set, and the returned vetted count still
// describes the pool rather than the page.
//
// That second half is the regression: the dashboard read len(suggestions) as its
// total, so a limit smaller than the vetted pool made the widget say "2
// candidates" when 4 had passed the gate — hiding higher-priority targets behind
// a number that looked like a complete answer.
func TestSuggestLimit(t *testing.T) {
	now := time.Now()
	var inputs []SuggestInput
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"} {
		inputs = append(inputs, SuggestInput{Cand: brute(ip, 90, 1000, 20, 200), LastSeen: now})
	}
	got, vetted := Suggest(inputs, nil, 60, 2, now, nil)
	if len(got) != 2 {
		t.Fatalf("limit=2 should cap at 2, got %d", len(got))
	}
	if vetted != 4 {
		t.Fatalf("vetted = %d, want 4: the count must be taken before the limit "+
			"truncates, or it just restates the page size", vetted)
	}

	// Unlimited: the two figures converge, so a caller can't tell them apart by
	// accident on the happy path — which is why the capped case above matters.
	all, vettedAll := Suggest(inputs, nil, 60, 0, now, nil)
	if len(all) != 4 || vettedAll != 4 {
		t.Fatalf("limit=0: got %d rows / vetted %d, want 4/4", len(all), vettedAll)
	}
}

// TestSuggestVettedCountExcludesRejected pins that the count describes VETTED
// candidates, not inputs. A total that counted everything handed to Suggest
// would overstate the actionable pool — the operator would see "8 candidates"
// backed by one clickable row and read the gate as broken.
func TestSuggestVettedCountExcludesRejected(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	inputs := []SuggestInput{
		// Passes.
		{Cand: func() ReportCandidate {
			c := brute("8.8.8.8", 95, 5000, 60, 800)
			c.LastSeen = now.Add(-time.Hour)
			return c
		}()},
		// Rejected: dormant.
		{Cand: func() ReportCandidate {
			c := brute("1.1.1.1", 95, 5000, 60, 800)
			c.LastSeen = now.Add(-40 * 24 * time.Hour)
			return c
		}()},
		// Rejected: below probe floor.
		{Cand: func() ReportCandidate {
			c := brute("9.9.9.9", 10, 5000, 60, 800)
			c.LastSeen = now.Add(-time.Hour)
			return c
		}()},
		// Rejected: not a brute playbook.
		{Cand: func() ReportCandidate {
			c := brute("8.8.4.4", 95, 5000, 60, 800)
			c.Playbook = "crypto_target"
			c.LastSeen = now.Add(-time.Hour)
			return c
		}()},
	}
	// Rejected by the dedup callback, which sits after Vet — an already-reported
	// IP is not an actionable candidate either.
	inputs = append(inputs, SuggestInput{Cand: func() ReportCandidate {
		c := brute("1.0.0.1", 95, 5000, 60, 800)
		c.LastSeen = now.Add(-time.Hour)
		return c
	}()})

	got, vetted := Suggest(inputs, nil, 60, 10, now, func(ip string) bool { return ip == "1.0.0.1" })
	if len(got) != 1 || got[0].SrcIP != "8.8.8.8" {
		t.Fatalf("suggestions = %+v, want only 8.8.8.8", ips(got))
	}
	if vetted != 1 {
		t.Fatalf("vetted = %d, want 1: the count must exclude gate- and dedup-rejected "+
			"candidates, not restate len(inputs)=%d", vetted, len(inputs))
	}
}

func ips(s []Suggestion) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.SrcIP
	}
	return out
}
