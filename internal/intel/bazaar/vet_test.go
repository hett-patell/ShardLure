package bazaar

import (
	"testing"
	"time"
)

func TestVet(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-2 * 24 * time.Hour)  // 2 days ago: within policy
	stale := now.Add(-65 * 24 * time.Hour) // 65 days ago: the archive case

	cases := []struct {
		name    string
		cand    Candidate
		cls     Classification
		wantOK  bool
		wantSub string // substring expected in the reject reason (when !wantOK)
	}{
		{
			name:   "fresh ELF binary accepts (structural)",
			cand:   Candidate{SizeBytes: 1_500_000, Origin: "cowrie_download", ObservedAt: fresh},
			cls:    Classification{FileKind: "ELF", Tags: []string{"elf", "aarch64", "linux"}},
			wantOK: true,
		},
		{
			name:   "fresh known-family script accepts (signature)",
			cand:   Candidate{SizeBytes: 4096, Origin: "cowrie_download", ObservedAt: fresh},
			cls:    Classification{FileKind: "Shell script", Family: "RedTail", Tags: []string{"miner", "redtail", "dropper", "linux"}},
			wantOK: true,
		},
		{
			name:   "fresh NOVEL script fetched in session accepts (behavioural)",
			cand:   Candidate{SizeBytes: 2048, Origin: "cowrie_download", ObservedAt: fresh},
			cls:    Classification{FileKind: "Shell script", Tags: []string{"bash", "script", "linux"}}, // no family, no malware tag
			wantOK: true,
		},
		{
			name:    "stale ELF rejects (10-day policy) — the archive case",
			cand:    Candidate{SizeBytes: 1_500_000, Origin: "cowrie_download", ObservedAt: stale},
			cls:     Classification{FileKind: "ELF", Tags: []string{"elf", "x86-64"}},
			wantOK:  false,
			wantSub: "stale",
		},
		{
			name:    "SSH public key rejects (benign) — 389B archive pubkey",
			cand:    Candidate{SizeBytes: 389, Origin: "cowrie_download", ObservedAt: fresh},
			cls:     Classification{FileKind: "SSH key", Tags: []string{"ssh-key"}},
			wantOK:  false,
			wantSub: "benign",
		},
		{
			name:    "1-byte junk rejects (too small)",
			cand:    Candidate{SizeBytes: 1, Origin: "cowrie_download", ObservedAt: fresh},
			cls:     Classification{FileKind: "unknown", Tags: []string{"unknown"}},
			wantOK:  false,
			wantSub: "small",
		},
		{
			name:    "tty transcript rejects (not a sample)",
			cand:    Candidate{SizeBytes: 5000, Origin: "cowrie_tty", ObservedAt: fresh},
			cls:     Classification{FileKind: "unknown"},
			wantOK:  false,
			wantSub: "tty",
		},
		{
			name:    "fresh unknown NOT fetched rejects (unconfirmed)",
			cand:    Candidate{SizeBytes: 5000, Origin: "manual", ObservedAt: fresh},
			cls:     Classification{FileKind: "unknown", Tags: []string{"unknown", "linux"}},
			wantOK:  false,
			wantSub: "unconfirmed",
		},
		{
			name:    "unknown ObservedAt treated as stale (fail-safe)",
			cand:    Candidate{SizeBytes: 1_500_000, Origin: "cowrie_download"}, // zero ObservedAt
			cls:     Classification{FileKind: "ELF", Tags: []string{"elf"}},
			wantOK:  false,
			wantSub: "stale",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := Vet(c.cand, c.cls, now)
			if ok != c.wantOK {
				t.Fatalf("Vet ok=%v want %v (reason=%q)", ok, c.wantOK, reason)
			}
			if !ok && c.wantSub != "" && !contains(reason, c.wantSub) {
				t.Errorf("reject reason %q does not contain %q", reason, c.wantSub)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
