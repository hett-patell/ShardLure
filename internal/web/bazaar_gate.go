package web

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/store"
)

// The MalwareBazaar panel used to report the SharePolicy PRE-FILTER as its
// backlog. After every real sample had been uploaded, prod still showed
// "pending: 3": two SSH-key files and a 257-byte unconfirmed blob, all of which
// bazaar.Vet refuses. The payload library's `shareable` flag was the same
// pre-filter, so its Upload buttons offered those files too and the server
// turned each one down. This file runs the real gate over the real pool so the
// dashboard shows Vet's decision (and its reason), the way the URLhaus and
// ThreatFox panels already do. The upload handler still re-runs Vet: the panel
// is advisory, the server is authoritative.

const (
	// maxBazaarCandidates bounds how many samples one refresh classifies.
	// Classification reads up to 256 KiB per file, and the pool is normally
	// dozens; a larger pool is truncated and disclosed via candidatesTotal.
	maxBazaarCandidates = 200
	// bazaarCandidatesTTL: the pool only moves when the capture runner fetches
	// something or a sample is uploaded (which invalidates the cache), so a
	// short TTL keeps file reads off the 30 s Red-tab poll.
	bazaarCandidatesTTL = 30 * time.Second
)

// bazaarCandidateRow is one pool sample with the gate's decision, shaped for
// the panel.
type bazaarCandidateRow struct {
	SHA256      string   `json:"sha256"`
	SizeBytes   int64    `json:"sizeBytes"`
	FileKind    string   `json:"fileKind,omitempty"`
	Family      string   `json:"family,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Origin      string   `json:"origin,omitempty"`
	LastFetchAt string   `json:"lastFetchAt,omitempty"`
	Eligible    bool     `json:"eligible"`
	Reason      string   `json:"reason,omitempty"`
}

// bazaarCandidateSet is one evaluation of the whole pool.
type bazaarCandidateSet struct {
	Rows []bazaarCandidateRow // newest first, at most maxBazaarCandidates
	// Total is the pool size before truncation (unshared samples only).
	Total int
	// Eligible is the Vet-approved subset of Rows, keyed by sha256.
	Eligible map[string]bool
}

func (s *Server) bazaarSharePolicy() store.SharePolicy {
	return store.SharePolicy{MinBytes: bazaar.MinSampleBytes, Origins: bazaar.ShareableOrigins()}
}

// bazaarFreshnessDaysEffective normalises the live knob the same way Vet does
// (1..9 tightens; anything else is MalwareBazaar's hard 10 days), so the pool
// window and the gate can never disagree about what "fresh" means.
func (s *Server) bazaarFreshnessDaysEffective() int {
	if d := s.bazaarFreshnessDaysLive(); d > 0 && d < 10 {
		return d
	}
	return 10
}

// bazaarShareCandidate builds the bazaar.Candidate for one sha256 exactly as
// the upload handler submits it: the freshest successful payload row chosen by
// GetArtifactForShareBySHA under the bazaar SharePolicy. handleBazaarUpload and
// the panel both call this, so they judge the same row.
func (s *Server) bazaarShareCandidate(sha string) (bazaar.Candidate, error) {
	art, err := s.st.GetArtifactForShareBySHA(sha, s.bazaarSharePolicy())
	if err != nil {
		return bazaar.Candidate{}, err
	}
	if art == nil {
		return bazaar.Candidate{}, errors.New("artifact not found")
	}
	return bazaar.Candidate{
		SHA256: art.SHA256, LocalPath: art.LocalPath, SizeBytes: art.SizeBytes,
		URL: art.URL, CreatedAt: art.CreatedAt,
		// Freshness is measured from the last successful fetch, as in the CLI's
		// artifactToCandidate: CreatedAt is registration time, which is "now"
		// for a re-imported archive and would wrongly look fresh.
		Origin: art.Origin, ObservedAt: art.LastSuccessfulFetchAt,
	}, nil
}

// bazaarVet is the local decision bazaar.Share makes for one candidate, in
// Share's order: size bounds, file present, Classify, then Vet with the live
// freshness knob. Dedup is the caller's job (the pool already excludes the
// ledger). Classify only reads (a bounded head plus the ELF header); nothing is
// executed. Reasons for the pre-flight steps match Share's text; Vet's reason
// is returned verbatim, which is what the upload handler reports for a skip.
func (s *Server) bazaarVet(c bazaar.Candidate, now time.Time) (bazaar.Classification, bool, string) {
	maxBytes := s.bazaarMaxBytesLive()
	if maxBytes == 0 {
		maxBytes = 32 << 20 // bazaar.Share's default for a zero MaxBytes
	}
	if c.SizeBytes <= 0 || c.SizeBytes > maxBytes {
		return bazaar.Classification{}, false, fmt.Sprintf("size %d outside (0, %d]", c.SizeBytes, maxBytes)
	}
	if _, err := os.Stat(c.LocalPath); err != nil {
		return bazaar.Classification{}, false, "file gone"
	}
	cls, err := bazaar.Classify(c.LocalPath)
	if err != nil {
		return bazaar.Classification{}, false, "file unreadable"
	}
	ok, reason := bazaar.Vet(c, cls, now, bazaar.VetOptions{FreshnessDays: s.bazaarFreshnessDaysLive()})
	return cls, ok, reason
}

// computeBazaarCandidates evaluates the pool `share bazaar` iterates:
// ArtifactsForShare over the freshness window, one entry per sha256, minus
// hashes already in bazaar_uploads. Each sample is rebuilt through
// bazaarShareCandidate so its decision is the one the upload button gets.
func (s *Server) computeBazaarCandidates(ctx context.Context) (*bazaarCandidateSet, time.Time, error) {
	now := time.Now()
	since := now.Add(-time.Duration(s.bazaarFreshnessDaysEffective()) * 24 * time.Hour)
	pool, err := s.st.ArtifactsForShare(since, s.bazaarSharePolicy())
	if err != nil {
		return nil, time.Time{}, err
	}
	out := &bazaarCandidateSet{Eligible: map[string]bool{}}
	for _, a := range pool { // already one row per sha256
		if ctx.Err() != nil {
			return nil, time.Time{}, ctx.Err()
		}
		shared, err := s.st.BazaarUploadRecorded(a.SHA256)
		if err != nil {
			return nil, time.Time{}, err
		}
		if shared {
			continue
		}
		out.Total++
		if len(out.Rows) >= maxBazaarCandidates {
			continue // counted in Total, disclosed as truncation
		}
		c, err := s.bazaarShareCandidate(a.SHA256)
		if err != nil {
			return nil, time.Time{}, err
		}
		cls, ok, reason := s.bazaarVet(c, now)
		row := bazaarCandidateRow{
			SHA256: c.SHA256, SizeBytes: c.SizeBytes, Origin: c.Origin,
			FileKind: cls.FileKind, Family: cls.Family, Tags: cls.Tags,
			Eligible: ok, Reason: reason,
		}
		if !c.ObservedAt.IsZero() {
			row.LastFetchAt = c.ObservedAt.UTC().Format(time.RFC3339)
		}
		out.Rows = append(out.Rows, row)
		if ok {
			out.Eligible[c.SHA256] = true
		}
	}
	// The pool is ordered by the selection row's fetch time; the judged row can
	// differ (GetArtifactForShareBySHA picks across the whole sha group), so
	// re-sort on what is displayed.
	sort.SliceStable(out.Rows, func(i, j int) bool { return out.Rows[i].LastFetchAt > out.Rows[j].LastFetchAt })
	return out, now, nil
}

// bazaarCandidatesCached serves the pool evaluation stale-while-revalidate.
// Keyed on nothing user-controlled: every caller gets the same evaluation.
func (s *Server) bazaarCandidatesCached() (*bazaarCandidateSet, error) {
	return s.bazaarCands.get(&s.bg, bazaarCandidatesTTL, s.computeBazaarCandidates)
}
