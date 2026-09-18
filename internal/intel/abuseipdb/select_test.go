package abuseipdb

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
)

func TestSelectCandidatesVetsBeforeSourceRanking(t *testing.T) {
	now := time.Now()
	volume := ReportCandidate{SrcIP: "8.8.8.8", Playbook: "dictionary_spray",
		ProbeScore: 70, EventCount: 5000, UniqueUsers: 50, AttemptsPerHour: 500, LastSeen: now}
	strict := ReportCandidate{SrcIP: "8.8.8.8", Playbook: "service_account_enum",
		ProbeScore: 90, EventCount: 20, UniqueUsers: 3, LastSeen: now}
	for _, tc := range []struct {
		name    string
		floor   int
		admin   *netmatch.Set
		want    ReportCandidate
		allowed bool
	}{
		{"higher priority", 60, nil, volume, true},
		{"strict floor", 80, nil, strict, true},
		{"refusal retained", 100, nil, volume, false},
		{"admin exclusion", 60, netmatch.New([]string{"8.8.8.8"}), volume, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range [][]ReportCandidate{{volume, strict}, {strict, volume}} {
				got := SelectCandidates(input, tc.admin, tc.floor, now)
				if len(got) != 1 || got[0] != tc.want {
					t.Fatalf("source selection: %+v, want %+v", got, tc.want)
				}
				if ok, _ := Vet(got[0], tc.admin, tc.floor, now); ok != tc.allowed {
					t.Fatalf("selected candidate bypassed policy: %+v", got[0])
				}
			}
		})
	}
}
