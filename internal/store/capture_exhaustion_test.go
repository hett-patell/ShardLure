package store

import (
	"testing"
	"time"
)

func TestExpiredFinalCaptureClaimBecomesTerminal(t *testing.T) {
	s := captureIntegrityStore(t)
	const u = "https://example.com/exhausted"
	if err := s.RecordArtifact(Artifact{URL: u, Origin: "quarantine_fetch", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.ClaimArtifactCapture(u, now.Add(-time.Minute), now.Add(-time.Second), 0, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DueArtifactCaptures(now, 10, 1); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListRecentArtifacts(10)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Status != "failed_permanently" {
		t.Fatalf("status=%s, want terminal exhaustion", rows[0].Status)
	}
}

func TestBazaarRedeliveryDoesNotRefreshEvidence(t *testing.T) {
	s := captureIntegrityStore(t)
	const u = "https://example.com/old-bazaar"
	old := time.Now().Add(-30 * 24 * time.Hour)
	if err := s.RecordArtifact(Artifact{TS: old, URL: u, Origin: "quarantine_fetch", Status: "fetched",
		SHA256: "abc", LocalPath: "/evidence/abc", SizeBytes: 128}); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchArtifactTS(u, time.Now()); err != nil {
		t.Fatal(err)
	}
	pol := SharePolicy{MinBytes: 64, Origins: []string{"quarantine_fetch"}}
	rows, err := s.ArtifactsForShare(time.Now().Add(-10*24*time.Hour), pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("stale payload selected for sharing: %+v", rows)
	}
	stats, err := s.BazaarUploadStats(time.Now().Add(-10*24*time.Hour), pol)
	if err != nil || stats.Pending != 0 {
		t.Fatalf("pending=%d error=%v", stats.Pending, err)
	}
}
