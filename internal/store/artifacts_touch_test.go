package store

import (
	"path/filepath"
	"testing"
	"time"
)

// artifactTS reads the raw ts column for a url so tests can assert on the
// exact stored value.
func artifactTS(t *testing.T, s *Store, url string) time.Time {
	t.Helper()
	var raw string
	if err := s.db.QueryRow(`SELECT ts FROM artifacts WHERE url=?`, url).Scan(&raw); err != nil {
		t.Fatalf("read ts: %v", err)
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("parse ts %q: %v", raw, err)
	}
	return ts
}

func TestTouchArtifactTSAdvancesOnNewerRedelivery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "touch.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.RecordArtifact(Artifact{
		TS: old, URL: "cowrie-download:abc", SHA256: "deadbeef",
		Origin: "cowrie_download", Status: "fetched",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	newer := old.Add(48 * time.Hour)
	if err := s.TouchArtifactTS("cowrie-download:abc", newer); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if got := artifactTS(t, s, "cowrie-download:abc"); !got.Equal(newer) {
		t.Errorf("ts not advanced: got %v want %v", got, newer)
	}
}

func TestTouchArtifactTSNeverRewinds(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "touch-rewind.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	cur := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := s.RecordArtifact(Artifact{
		TS: cur, URL: "u", SHA256: "aa", Origin: "cowrie_download", Status: "fetched",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	// An older event (e.g. a backfilled rotated log) must not rewind the row.
	if err := s.TouchArtifactTS("u", cur.Add(-24*time.Hour)); err != nil {
		t.Fatalf("touch older: %v", err)
	}
	if got := artifactTS(t, s, "u"); !got.Equal(cur) {
		t.Errorf("ts rewound: got %v want %v", got, cur)
	}

	// Equal timestamp is a no-op too (the steady-state 5s tick path).
	if err := s.TouchArtifactTS("u", cur); err != nil {
		t.Fatalf("touch equal: %v", err)
	}
	if got := artifactTS(t, s, "u"); !got.Equal(cur) {
		t.Errorf("ts changed on equal touch: got %v want %v", got, cur)
	}
}

func TestTouchArtifactTSMissingRowAndZeroInputsAreNoops(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "touch-noop.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.TouchArtifactTS("never-recorded", time.Now()); err != nil {
		t.Errorf("missing row should be a silent no-op, got %v", err)
	}
	if err := s.TouchArtifactTS("", time.Now()); err != nil {
		t.Errorf("empty url should be a no-op, got %v", err)
	}
	if err := s.TouchArtifactTS("never-recorded", time.Time{}); err != nil {
		t.Errorf("zero ts should be a no-op, got %v", err)
	}
}

// The whole point of the fix: a redelivered payload must stay inside the
// dashboard payload window used by CountDistinctPayloadsSince.
func TestTouchArtifactTSKeepsRedeliveredPayloadInWindow(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "touch-window.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	firstSeen := time.Now().UTC().Add(-30 * 24 * time.Hour) // outside a 7d window
	if err := s.RecordArtifact(Artifact{
		TS: firstSeen, URL: "cowrie-download:sha", SHA256: "cafe",
		Origin: "cowrie_download", Status: "fetched",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	window := time.Now().UTC().Add(-7 * 24 * time.Hour)
	n, err := s.CountDistinctPayloadsSince(window)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("stale payload unexpectedly in window before touch: %d", n)
	}

	// Attacker drops the same file again today.
	if err := s.TouchArtifactTS("cowrie-download:sha", time.Now().UTC()); err != nil {
		t.Fatalf("touch: %v", err)
	}
	n, err = s.CountDistinctPayloadsSince(window)
	if err != nil {
		t.Fatalf("count after touch: %v", err)
	}
	if n != 1 {
		t.Errorf("redelivered payload missing from window after touch: got %d want 1", n)
	}
}
