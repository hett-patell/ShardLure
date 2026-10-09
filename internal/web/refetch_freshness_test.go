package web

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

// C1: a sample captured 16 days ago and re-fetched with the same hash is not
// offered to MalwareBazaar and not counted pending. Before the fix the
// re-fetch moved last_successful_fetch_at, which the pool and Vet read.
func TestRefetchedOldSampleIsNotBazaarPending(t *testing.T) {
	s := newIntelTestServer(t, nil)
	dir := t.TempDir()
	now := time.Now().UTC()
	body := append(minimalFamilyELF(), 'o')
	path, sha := writeFixture(t, dir, "old-xmr", body)
	u := "http://203.0.113.60/bins/xmr"
	if err := s.st.RecordArtifact(store.Artifact{
		URL: u, TS: now.Add(-16 * 24 * time.Hour), SHA256: sha, LocalPath: path,
		SizeBytes: int64(len(body)), Origin: "quarantine_fetch", Status: "fetched",
	}); err != nil {
		t.Fatal(err)
	}
	if out := getBazaar(t, s); out.Stats.Pending != 0 || len(out.Candidates) != 0 {
		t.Fatalf("before the re-fetch: pending=%d candidates=%d", out.Stats.Pending, len(out.Candidates))
	}
	// A schedule row whose window covers the next hour; the re-fetch returns
	// the same bytes.
	if err := s.st.SeedRefetch(u, now.Add(-2*time.Hour), sha); err != nil {
		t.Fatal(err)
	}
	at := now.Add(61 * time.Minute)
	job, err := s.st.ClaimRefetch(at, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim: %+v %v", job, err)
	}
	if np, err := s.st.CompleteRefetch(*job, at, store.RefetchOutcome{OK: true, SHA256: sha, LocalPath: path, Size: int64(len(body))}); err != nil || np {
		t.Fatalf("complete: %v %v", np, err)
	}
	s.bazaarCands.invalidate()
	out := getBazaar(t, s)
	if out.Stats.Pending != 0 || len(out.Candidates) != 0 {
		t.Fatalf("a 16-day-old sample re-fetched now is offered: pending=%d candidates=%+v", out.Stats.Pending, out.Candidates)
	}
}
