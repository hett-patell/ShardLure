package abuseipdb

import (
	"sort"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// SelectCandidates picks one independent source's evidence per IP and orders
// targets by the same priority as Suggest. Counts are never combined. If no
// source passes Vet, keep the largest evidence set so Report can explain the
// refusal. Selection is not authorization: Report always re-runs Vet.
func SelectCandidates(candidates []ReportCandidate, admin *netmatch.Set, minProbe int, now time.Time) []ReportCandidate {
	type selection struct {
		candidate ReportCandidate
		priority  int // -1 means refused by Vet
	}
	byIP := make(map[string]selection)
	for _, cand := range candidates {
		priority := -1
		if ok, _ := Vet(cand, admin, minProbe, now); ok {
			priority, _ = scoreOne(SuggestInput{Cand: cand}, now)
		}
		old, exists := byIP[cand.SrcIP]
		better := !exists || priority > old.priority
		if exists && priority == old.priority {
			if priority < 0 && cand.EventCount != old.candidate.EventCount {
				better = cand.EventCount > old.candidate.EventCount
			} else {
				better = cand.LastSeen.After(old.candidate.LastSeen)
			}
		}
		if better {
			byIP[cand.SrcIP] = selection{candidate: cand, priority: priority}
		}
	}
	out := make([]ReportCandidate, 0, len(byIP))
	for _, selected := range byIP {
		out = append(out, selected.candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		pi, pj := byIP[out[i].SrcIP].priority, byIP[out[j].SrcIP].priority
		if pi != pj {
			return pi > pj
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].SrcIP < out[j].SrcIP
	})
	return out
}
