package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func captureIntegrityStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCaptureClaimHasSingleOwner(t *testing.T) {
	s := captureIntegrityStore(t)
	u := "https://example.com/payload"
	if err := s.UpsertArtifact(Artifact{URL: u, Origin: "quarantine_fetch", Status: "failed"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.ClaimArtifactCapture(u, now, now.Add(time.Minute), 0) }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrClaimStale) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("claim winners = %d; want exactly one", wins)
	}
}

func TestCaptureTerminalCompletionStaysTerminal(t *testing.T) {
	for _, status := range []string{"empty", "blocked", "invalid", "failed_permanently"} {
		t.Run(status, func(t *testing.T) {
			s := captureIntegrityStore(t)
			u := "https://example.com/payload"
			if err := s.UpsertArtifact(Artifact{URL: u, Origin: "quarantine_fetch", Status: "capturing"}); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if err := s.ClaimArtifactCapture(u, now, now.Add(time.Minute), 0); err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteArtifactCapture(u, 1, status, "terminal", "", "", 0, nil); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := s.db.QueryRow("SELECT status FROM artifacts WHERE url=?", u).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != status {
				t.Errorf("status = %q, want %q", got, status)
			}
			due, err := s.DueArtifactCaptures(now.Add(time.Hour), 10, 5)
			if err != nil {
				t.Fatal(err)
			}
			if len(due) != 0 {
				t.Errorf("terminal artifact is due: %v", due)
			}
		})
	}
}

func TestArtifactRedeliveryDoesNotRefreshFetchEvidence(t *testing.T) {
	s := captureIntegrityStore(t)
	u := "https://example.com/payload"
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if err := s.UpsertArtifact(Artifact{URL: u, TS: old, Origin: "quarantine_fetch", Status: "fetched", SHA256: "abc", SizeBytes: 128}); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchArtifactTS(u, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	candidates, err := s.URLhausCandidates(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("redelivery made %d stale fetches fresh", len(candidates))
	}
	fox, err := s.ThreatFoxCandidates(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fox) != 0 {
		t.Fatalf("redelivery made %d stale ThreatFox fetches fresh", len(fox))
	}
}

func TestCaptureReclaimFencesOldCompletionAndChargesBudget(t *testing.T) {
	s := captureIntegrityStore(t)
	u := "https://example.com/reclaim"
	if err := s.UpsertArtifact(Artifact{URL: u, Origin: "quarantine_fetch", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.ClaimArtifactCapture(u, now.Add(-2*time.Minute), now.Add(-time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimArtifactCapture(u, now, now.Add(time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteArtifactCapture(u, 1, "fetched", "stale", "/old", "old", 100, nil); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("old completion: %v", err)
	}
	if err := s.CompleteArtifactCapture(u, 2, "fetched", "current", "/new", "new", 200, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimArtifactCapture(u, now.Add(2*time.Minute), now.Add(3*time.Minute), 2); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("terminal claim: %v", err)
	}
}

func TestCaptureClaimEnforcesBudgetWithoutPolling(t *testing.T) {
	s := captureIntegrityStore(t)
	u := "https://example.com/budget"
	if err := s.UpsertArtifact(Artifact{URL: u, Origin: "quarantine_fetch", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for attempt := 0; attempt < 5; attempt++ {
		start := now.Add(time.Duration(attempt) * time.Minute)
		if err := s.ClaimArtifactCapture(u, start, start.Add(30*time.Second), attempt); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ClaimArtifactCapture(u, now.Add(10*time.Minute), now.Add(11*time.Minute), 5); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("exhausted claim: %v", err)
	}
}

func TestArtifactUpsertCannotOverwriteCaptureState(t *testing.T) {
	for _, status := range []string{"capturing", "fetched", "failed_permanently", "blocked"} {
		t.Run(status, func(t *testing.T) {
			s := captureIntegrityStore(t)
			now := time.Now().UTC()
			u := "https://example.com/immutable"
			if err := s.RecordArtifact(Artifact{URL: u, TS: now.Add(-time.Hour), Origin: "quarantine_fetch", Status: "pending", SrcIP: "8.8.8.8"}); err != nil {
				t.Fatal(err)
			}
			if err := s.ClaimArtifactCapture(u, now, now.Add(time.Minute), 0); err != nil {
				t.Fatal(err)
			}
			if status != "capturing" {
				if err := s.CompleteArtifactCapture(u, 1, status, "original detail", "/evidence/original", "original-hash", 123, nil); err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.ListRecentArtifacts(1)
			if err != nil {
				t.Fatal(err)
			}
			for _, incoming := range []Artifact{
				{URL: u, TS: now, Origin: "quarantine_fetch", Status: "pending"},
				{URL: u, TS: now.Add(time.Nanosecond), Origin: "cowrie_download", Status: "fetched", LocalPath: "/evidence/replacement", SHA256: "replacement", SizeBytes: 321},
			} {
				if err := s.UpsertArtifact(incoming); err != nil {
					t.Fatal(err)
				}
			}
			rows, err := s.ListRecentArtifacts(1)
			if err != nil || len(rows) != 1 {
				t.Fatalf("rows=%+v err=%v", rows, err)
			}
			got, want := rows[0], before[0]
			if got.Status != want.Status || got.SHA256 != want.SHA256 || got.LocalPath != want.LocalPath || got.Detail != want.Detail || got.Origin != want.Origin || got.SrcIP != want.SrcIP || got.SizeBytes != want.SizeBytes || !got.LastSuccessfulFetchAt.Equal(want.LastSuccessfulFetchAt) || !got.LastFetchAttemptAt.Equal(want.LastFetchAttemptAt) || !got.FirstObservedAt.Equal(want.FirstObservedAt) {
				t.Fatalf("upsert overwrote state: got=%+v before=%+v", got, want)
			}
			if !got.LastSeenAt.Equal(now.Add(time.Nanosecond)) {
				t.Fatalf("observation lost precision: %s", got.LastSeenAt)
			}
			if status == "capturing" {
				if err := s.CompleteArtifactCapture(u, 1, "empty", "owner completed", "", "", 0, nil); err != nil {
					t.Fatalf("upsert invalidated lease: %v", err)
				}
			}
		})
	}
}
