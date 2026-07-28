package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDueArtifactCapturesEmpty(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "retry-empty.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	urls, err := s.DueArtifactCaptures(time.Now(), 10, 5)
	if err != nil {
		t.Fatalf("DueArtifactCaptures: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected 0 due, got %d", len(urls))
	}
}

func TestDueArtifactCapturesPicksUpFailed(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "retry-fail.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.UpsertArtifact(Artifact{
		URL:    "http://example.com/payload",
		Origin: "quarantine_fetch",
		Status: "failed",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	urls, err := s.DueArtifactCaptures(time.Now(), 10, 5)
	if err != nil {
		t.Fatalf("DueArtifactCaptures: %v", err)
	}
	if len(urls) != 1 || urls[0] != "http://example.com/payload" {
		t.Errorf("expected 1 due URL, got %v", urls)
	}
}

func TestDueArtifactCapturesSkipsTerminal(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "retry-term.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Fetched (terminal) should be skipped — migration v17 backfills attempt_count=1.
	if err := s.UpsertArtifact(Artifact{
		URL:    "http://example.com/done",
		Origin: "quarantine_fetch",
		Status: "fetched",
	}); err != nil {
		t.Fatalf("upsert fetched: %v", err)
	}
	if err := s.UpsertArtifact(Artifact{
		URL:    "http://example.com/blocked",
		Origin: "quarantine_fetch",
		Status: "blocked",
	}); err != nil {
		t.Fatalf("upsert blocked: %v", err)
	}

	urls, err := s.DueArtifactCaptures(time.Now(), 10, 5)
	if err != nil {
		t.Fatalf("DueArtifactCaptures: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected 0 due (terminal rows), got %d: %v", len(urls), urls)
	}
}

func TestClaimAndCompleteSuccess(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "retry-ok.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.UpsertArtifact(Artifact{
		URL:    "http://example.com/go",
		Origin: "quarantine_fetch",
		Status: "capturing",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	now := time.Now().UTC()
	lease := now.Add(2 * time.Minute)
	if err := s.ClaimArtifactCapture("http://example.com/go", now, lease, 0); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := s.CompleteArtifactCapture("http://example.com/go", 1, "fetched", "ok", "/tmp/f", "abc123", 42, nil); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Should now be terminal and not due.
	urls, err := s.DueArtifactCaptures(time.Now(), 10, 5)
	if err != nil {
		t.Fatalf("DueArtifactCaptures: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected 0 due after success, got %d", len(urls))
	}
}

func TestClaimStale(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "retry-stale.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.UpsertArtifact(Artifact{
		URL:    "http://example.com/stale",
		Origin: "quarantine_fetch",
		Status: "capturing",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	now := time.Now().UTC()
	lease := now.Add(2 * time.Minute)
	// Claim at attempt 0 succeeds.
	if err := s.ClaimArtifactCapture("http://example.com/stale", now, lease, 0); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Claim again at attempt 0 should be stale (row moved to attempt 1 after complete).
	if err := s.CompleteArtifactCapture("http://example.com/stale", 1, "failed", "err", "", "", 0, &now); err != nil {
		t.Fatalf("complete: %v", err)
	}
	// Now attempt_count=1, claiming at 0 should fail.
	if err := s.ClaimArtifactCapture("http://example.com/stale", now, lease, 0); err != ErrClaimStale {
		t.Errorf("expected ErrClaimStale, got %v", err)
	}
}

func TestCompleteSchedulesRetry(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "retry-sched.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.UpsertArtifact(Artifact{
		URL:    "http://example.com/retry",
		Origin: "quarantine_fetch",
		Status: "capturing",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	now := time.Now().UTC()
	lease := now.Add(2 * time.Minute)
	if err := s.ClaimArtifactCapture("http://example.com/retry", now, lease, 0); err != nil {
		t.Fatalf("claim: %v", err)
	}

	nextTime := now.Add(30 * time.Second)
	if err := s.CompleteArtifactCapture("http://example.com/retry", 1, "failed", "timeout", "", "", 0, &nextTime); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Not yet due (next_attempt_at is in the future).
	urls, err := s.DueArtifactCaptures(now, 10, 5)
	if err != nil {
		t.Fatalf("DueArtifactCaptures: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected 0 due before next_attempt_at, got %d", len(urls))
	}

	// After next_attempt_at, it should be due.
	urls, err = s.DueArtifactCaptures(now.Add(31*time.Second), 10, 5)
	if err != nil {
		t.Fatalf("DueArtifactCaptures future: %v", err)
	}
	if len(urls) != 1 {
		t.Errorf("expected 1 due after next_attempt_at, got %d", len(urls))
	}
}

func TestArtifactAttemptCount(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "retry-count.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.UpsertArtifact(Artifact{
		URL:    "http://example.com/cnt",
		Origin: "quarantine_fetch",
		Status: "failed",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	var n int
	if err := s.ArtifactAttemptCount("http://example.com/cnt", &n); err != nil {
		t.Fatalf("attempt count: %v", err)
	}
	if n != 0 {
		t.Errorf("expected attempt_count=0, got %d", n)
	}
}
