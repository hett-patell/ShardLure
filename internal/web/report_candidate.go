package web

import (
	"time"

	"github.com/networkshard/shardlure/internal/intel/abuseipdb"
	"github.com/networkshard/shardlure/pkg/models"
)

// newReportCandidate builds the AbuseIPDB vetting candidate for an actor.
//
// It exists so the four call sites cannot each decide which rate to pass. They
// all used actor.AttemptsPerHour, which is a LIFETIME average and therefore the
// wrong quantity for a report about current behaviour: it understated actively
// escalating attackers by 2-3x and flattered ones that had gone quiet.
//
// recentPerHour is the windowed rate, 0 when the actor has no activity in the
// window. Zero is the honest answer there and is safe: Vet does not gate on the
// rate at all (so a dormant actor cannot become unreportable because of this),
// it only lowers suggest priority, which is the desired outcome for a stale IP.
func newReportCandidate(a *models.Actor, recentPerHour float64) abuseipdb.ReportCandidate {
	return abuseipdb.ReportCandidate{
		SrcIP:           a.PrimaryIP,
		Playbook:        a.Playbook,
		ProbeScore:      a.ProbeScore,
		EventCount:      a.EventCount,
		UniqueUsers:     a.UniqueUsers,
		AttemptsPerHour: recentPerHour,
	}
}

// recentRatesCached memoizes the per-actor windowed rates on the same 10s TTL as
// the other poll-path aggregates: /api/intel builds candidates for up to 80
// actors per poll, and re-running the GROUP BY for each would turn one indexed
// scan into eighty.
func (s *Server) recentRatesCached() map[string]float64 {
	s.ratesMu.Lock()
	defer s.ratesMu.Unlock()
	if s.ratesCached != nil && time.Since(s.ratesAt) < statsTTL {
		return s.ratesCached
	}
	m, err := s.st.RecentRatesByActor(time.Now().Add(-recentRateWindow))
	if err != nil {
		// Serve the previous map rather than an empty one: dropping every rate to
		// zero would silently de-prioritise every suggestion.
		return s.ratesCached
	}
	s.ratesCached = m
	s.ratesAt = time.Now()
	return s.ratesCached
}
