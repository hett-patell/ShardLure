package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// A failing refetch_schedule purge is scheduling state only: it must not
// skip event retention or the orphan-actor sweep, and its error must still
// reach the caller (joined, as campaign-derived retention errors are).
func TestRefetchSchedulePurgeFailureDoesNotSkipEventRetention(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "purge-refetch-err.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	old := time.Now().UTC().Add(-60 * 24 * time.Hour)
	if err := s.InsertEvent(&models.Event{
		TS: old, Source: models.SourceCowrie, Kind: models.KindFailedPass,
		SrcIP: "10.9.9.9", Username: "root", ActorID: "cowrie:old",
	}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}
	seedActor(t, s, "cowrie:orphan", old, "", "")
	// Make the schedule purge fail.
	if _, err := s.db.Exec(`DROP TABLE refetch_schedule`); err != nil {
		t.Fatal(err)
	}

	err = s.MaintenancePurge(30)
	if err == nil || !strings.Contains(err.Error(), "refetch-schedule retention") {
		t.Fatalf("MaintenancePurge error = %v, want the joined refetch-schedule error", err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM events`); n != 0 {
		t.Fatalf("expired events kept after a schedule-purge failure: %d", n)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM actors WHERE id='cowrie:orphan'`); n != 0 {
		t.Fatal("orphan-actor sweep skipped after a schedule-purge failure")
	}
}
