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
		{Cand: brute("203.0.113.10", 95, 5000, 60, 800), LastSeen: now.Add(-10 * time.Minute)},
		// Equally strong but 5 days stale → ranks below the active one.
		{Cand: brute("203.0.113.11", 95, 5000, 60, 800), LastSeen: now.Add(-120 * time.Hour)},
		// Weak but passes floor, active → mid/low.
		{Cand: brute("203.0.113.12", 62, 25, 4, 30), LastSeen: now.Add(-30 * time.Minute)},
		// Vet rejects: admin IP.
		{Cand: brute("10.1.2.3", 95, 5000, 60, 800), LastSeen: now},
		// Vet rejects: not a brute playbook.
		{Cand: func() ReportCandidate {
			c := brute("203.0.113.13", 95, 5000, 60, 800)
			c.Playbook = "crypto_target"
			return c
		}(), LastSeen: now},
		// Vet rejects: below probe floor.
		{Cand: brute("203.0.113.14", 40, 5000, 60, 800), LastSeen: now},
	}

	got := Suggest(inputs, admin, 60, 10, now, nil)
	if len(got) != 3 {
		t.Fatalf("expected 3 vetted suggestions, got %d: %+v", len(got), ips(got))
	}
	if got[0].SrcIP != "203.0.113.10" {
		t.Fatalf("expected active strong actor first, got %s", got[0].SrcIP)
	}
	// The active-strong actor must outrank the identical-but-stale one purely on
	// recency (this is the algorithm's headline behaviour).
	var activeP, staleP int
	for _, s := range got {
		if s.SrcIP == "203.0.113.10" {
			activeP = s.Priority
		}
		if s.SrcIP == "203.0.113.11" {
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
		{Cand: brute("203.0.113.10", 95, 5000, 60, 800), LastSeen: now},
		{Cand: brute("203.0.113.11", 95, 5000, 60, 800), LastSeen: now},
	}
	reported := map[string]bool{"203.0.113.10": true}
	got := Suggest(inputs, nil, 60, 10, now, func(ip string) bool { return reported[ip] })
	if len(got) != 1 || got[0].SrcIP != "203.0.113.11" {
		t.Fatalf("expected only the unreported IP, got %+v", ips(got))
	}
}

// TestSuggestLimit caps the result set.
func TestSuggestLimit(t *testing.T) {
	now := time.Now()
	var inputs []SuggestInput
	for _, ip := range []string{"203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"} {
		inputs = append(inputs, SuggestInput{Cand: brute(ip, 90, 1000, 20, 200), LastSeen: now})
	}
	got := Suggest(inputs, nil, 60, 2, now, nil)
	if len(got) != 2 {
		t.Fatalf("limit=2 should cap at 2, got %d", len(got))
	}
}

func ips(s []Suggestion) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.SrcIP
	}
	return out
}
