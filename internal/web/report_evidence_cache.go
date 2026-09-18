package web

import (
	"context"
	"errors"
	"time"

	"github.com/networkshard/shardlure/internal/intel/abuseipdb"
)

const (
	maxReportEvidenceEntries = 1024
	reportEvidenceErrorTTL   = 2 * time.Second
)

type reportEvidenceEntry struct {
	candidates [2]abuseipdb.ReportCandidate
	at, used   time.Time
	err        error
}

func (s *Server) trimReportEvidenceCacheLocked(now time.Time, incoming string) {
	for key, entry := range s.reportEvidenceCache {
		ttl := statsTTL
		if entry.err != nil {
			ttl = reportEvidenceErrorTTL
		}
		if now.Sub(entry.at) >= ttl {
			delete(s.reportEvidenceCache, key)
		}
	}
	if _, exists := s.reportEvidenceCache[incoming]; exists || len(s.reportEvidenceCache) < maxReportEvidenceEntries {
		return
	}
	oldestKey := ""
	var oldest time.Time
	for key, entry := range s.reportEvidenceCache {
		if oldest.IsZero() || entry.used.Before(oldest) {
			oldestKey, oldest = key, entry.used
		}
	}
	delete(s.reportEvidenceCache, oldestKey)
}

// reportCandidateForIPCached is advisory-only. POST paths always load fresh
// evidence. Cache raw source candidates, not a policy decision: settings,
// admin exclusions and staleness are checked again on every read.
func (s *Server) reportCandidateForIPCached(ctx context.Context, ip string) (abuseipdb.ReportCandidate, error) {
	for {
		if err := ctx.Err(); err != nil {
			return abuseipdb.ReportCandidate{}, err
		}
		now := time.Now()
		s.reportEvidenceMu.Lock()
		if entry, ok := s.reportEvidenceCache[ip]; ok {
			ttl := statsTTL
			if entry.err != nil {
				ttl = reportEvidenceErrorTTL
			}
			if now.Sub(entry.at) < ttl {
				entry.used = now
				s.reportEvidenceCache[ip] = entry
				s.reportEvidenceMu.Unlock()
				if entry.err != nil {
					return abuseipdb.ReportCandidate{}, entry.err
				}
				return s.chooseReportCandidate(ip, entry.candidates, now), nil
			}
		}
		// One in-flight scan process-wide bounds database pressure during a
		// poll storm. Never hold the mutex over I/O or an uncancellable wait.
		if flight := s.reportEvidenceFlight; flight != nil {
			s.reportEvidenceMu.Unlock()
			select {
			case <-ctx.Done():
				return abuseipdb.ReportCandidate{}, ctx.Err()
			case <-flight:
				continue
			}
		}
		flight := make(chan struct{})
		s.reportEvidenceFlight = flight
		s.reportEvidenceMu.Unlock()

		cands, err := s.loadReportEvidence(ctx, ip, now)
		s.reportEvidenceMu.Lock()
		completedAt := time.Now()
		if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			delete(s.reportEvidenceCache, ip)
		} else if err != nil {
			// No last-good fallback for eligibility: a failed evidence refresh
			// must not keep showing an actionable report button. Remember the
			// failure briefly so a polling storm cannot immediately repeat the
			// same expensive scan.
			if s.reportEvidenceCache == nil {
				s.reportEvidenceCache = make(map[string]reportEvidenceEntry)
			}
			s.trimReportEvidenceCacheLocked(completedAt, ip)
			s.reportEvidenceCache[ip] = reportEvidenceEntry{at: completedAt, used: completedAt, err: err}
		} else {
			if s.reportEvidenceCache == nil {
				s.reportEvidenceCache = make(map[string]reportEvidenceEntry)
			}
			s.trimReportEvidenceCacheLocked(completedAt, ip)
			s.reportEvidenceCache[ip] = reportEvidenceEntry{candidates: cands, at: completedAt, used: completedAt}
		}
		s.reportEvidenceFlight = nil
		close(flight)
		s.reportEvidenceMu.Unlock()
		if err != nil {
			return abuseipdb.ReportCandidate{}, err
		}
		return s.chooseReportCandidate(ip, cands, time.Now()), nil
	}
}
