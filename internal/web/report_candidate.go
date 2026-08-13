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
// rate (a quiet hour must not make a live attacker unreportable), it only lowers
// suggest priority. Staleness is gated on a direct last-seen observation
// instead, which a short lull cannot zero out.
//
// ipLastSeen is when the actor's PRIMARY IP was last observed — NOT
// actor.LastSeen. The actor figure is the max across a HASSH cluster, and the
// report names one address: feeding the cluster max into the staleness gate let
// a fresh cluster-mate vouch for a dormant address (a live 22-IP actor kept a
// 17.7-day-silent primary IP reportable off a 4-day-old sibling). Callers pass
// store.PrimaryIPLastSeen()'s answer; an actor missing from that map yields the
// zero time, which Vet hard-rejects — so the failure mode of missing data is a
// refused report, never a wrongful one. Taking it as a parameter rather than
// reading a.LastSeen HERE is what makes the wrong source unreachable: the field
// this function must not use is no longer mentioned in it.
func newReportCandidate(a *models.Actor, recentPerHour float64, ipLastSeen time.Time) abuseipdb.ReportCandidate {
	return abuseipdb.ReportCandidate{
		SrcIP:           a.PrimaryIP,
		Playbook:        a.Playbook,
		ProbeScore:      a.ProbeScore,
		EventCount:      a.EventCount,
		UniqueUsers:     a.UniqueUsers,
		AttemptsPerHour: recentPerHour,
		LastSeen:        ipLastSeen,
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

// primaryIPSeenCached memoizes actor→primary-IP-last-seen on the same TTL and
// for the same reason as recentRatesCached. On a miss it returns the PREVIOUS
// map rather than nil: under a transient DB error a stale answer keeps honest
// candidates reportable, while any actor genuinely absent still gets the zero
// time and is refused by Vet.
func (s *Server) primaryIPSeenCached() map[string]time.Time {
	s.ipSeenMu.Lock()
	defer s.ipSeenMu.Unlock()
	if s.ipSeenCached != nil && time.Since(s.ipSeenAt) < statsTTL {
		return s.ipSeenCached
	}
	m, err := s.st.PrimaryIPLastSeen()
	if err != nil {
		return s.ipSeenCached
	}
	s.ipSeenCached = m
	s.ipSeenAt = time.Now()
	return s.ipSeenCached
}
