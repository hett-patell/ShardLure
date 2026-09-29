package web

import (
	"context"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/intel/abuseipdb"
	"github.com/networkshard/shardlure/pkg/models"
)

// newReportCandidate maps target-IP/source evidence, never cluster aggregates.
// recentPerHour describes the fixed 24h window (including an honest zero);
// ipLastSeen is a direct observation of this IP. Classification/counts cover
// the seven-day reporting window. Missing evidence stays zero and Vet refuses it.
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

// reportCandidateForIP evaluates each source independently. A cluster score
// cannot choose the source: the same IP may have a handshake-only Cowrie
// observation and confirmed journal brute-force evidence (or the reverse).
// Suggest applies the shared Vet and priority rules; rejected evidence is
// retained as a fallback so Report can explain its refusal. Counts are never
// summed across sources.
func (s *Server) reportCandidateForIP(ctx context.Context, ip string) (abuseipdb.ReportCandidate, error) {
	now := time.Now()
	cands, err := s.loadReportEvidence(ctx, ip, now)
	if err != nil {
		return abuseipdb.ReportCandidate{}, err
	}
	return s.chooseReportCandidate(ip, cands, now), nil
}

func (s *Server) loadReportEvidence(ctx context.Context, ip string, now time.Time) ([2]abuseipdb.ReportCandidate, error) {
	var cands [2]abuseipdb.ReportCandidate
	for i, source := range []models.Source{models.SourceJournal, models.SourceCowrie} {
		evidence, err := actor.ReportEvidenceForIPContext(ctx, s.st, &models.Actor{Source: source, PrimaryIP: ip}, now)
		if err != nil {
			return [2]abuseipdb.ReportCandidate{}, err
		}
		cands[i] = newReportCandidate(evidence, evidence.AttemptsPerHour, evidence.LastSeen)
	}
	return cands, nil
}

func (s *Server) chooseReportCandidate(ip string, cands [2]abuseipdb.ReportCandidate, now time.Time) abuseipdb.ReportCandidate {
	selected := abuseipdb.SelectCandidates(cands[:], s.abuseAdmin, s.abuseMinProbeLive(), now)
	for _, cand := range selected {
		if cand.SrcIP == ip {
			return cand
		}
	}
	return abuseipdb.ReportCandidate{SrcIP: ip}
}

// recentCounts is the cached per-actor event count over recentRateWindow and
// the rates derived from it. Both the report candidates (rates) and the
// Brute-Force Radar (ranked counts) read it, so one /api/intel poll counts the
// window at most once per statsTTL instead of once per consumer: the radar
// used to call TopActorsByRecentRate, uncached, on every poll.
type recentCounts struct {
	counts map[string]int
	rates  map[string]float64
	hours  float64
}

// recentCountsCached memoizes the per-actor windowed counts on the same 10s TTL
// as the other poll-path aggregates: /api/intel builds candidates for up to 80
// actors per poll, and re-running the GROUP BY for each would turn one indexed
// scan into eighty. Stale-while-revalidate like the summary tiers (swrCache).
// A failed refresh serves the previous value rather than an empty one:
// dropping every rate to zero would silently de-prioritise every suggestion.
func (s *Server) recentCountsCached() *recentCounts {
	c, _ := s.ratesCache.get(&s.bg, statsTTL, func() (*recentCounts, time.Time, error) {
		counts, err := s.st.RecentEventCountsByActor(context.Background(), time.Now().Add(-recentRateWindow))
		if err != nil {
			return nil, time.Time{}, err
		}
		hours := recentRateWindow.Hours()
		rates := make(map[string]float64, len(counts))
		for id, n := range counts {
			rates[id] = float64(n) / hours
		}
		return &recentCounts{counts: counts, rates: rates, hours: hours}, time.Now(), nil
	})
	return c
}

// recentRatesCached is the rate view of recentCountsCached (nil before the
// first successful count).
func (s *Server) recentRatesCached() map[string]float64 {
	if c := s.recentCountsCached(); c != nil {
		return c.rates
	}
	return nil
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
