package store

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestWindowActivitySinceBoundsTheWindow is the point of the whole type: events
// outside the window must not be counted. The threat gauge previously scored
// cumulative totals and consequently never moved.
func TestWindowActivitySinceBoundsTheWindow(t *testing.T) {
	st := newTestStore(t, "window.db")
	now := time.Now().UTC()

	// Inside the window.
	in := []*models.Event{
		{TS: now.Add(-1 * time.Hour), Source: models.SourceCowrie, Kind: "accepted", SrcIP: "1.1.1.1", ActorID: "a1"},
		{TS: now.Add(-2 * time.Hour), Source: models.SourceCowrie, Kind: "command", SrcIP: "1.1.1.1", ActorID: "a1"},
		{TS: now.Add(-3 * time.Hour), Source: models.SourceCowrie, Kind: "file_download", SrcIP: "2.2.2.2", ActorID: "a2"},
		{TS: now.Add(-4 * time.Hour), Source: models.SourceCowrie, Kind: "file_upload", SrcIP: "2.2.2.2", ActorID: "a2"},
		{TS: now.Add(-5 * time.Hour), Source: models.SourceJournal, Kind: "failed_password", SrcIP: "3.3.3.3", ActorID: "a3"},
	}
	// Outside: must be invisible to the gauge.
	out := []*models.Event{
		{TS: now.Add(-48 * time.Hour), Source: models.SourceCowrie, Kind: "accepted", SrcIP: "9.9.9.9", ActorID: "a9"},
		{TS: now.Add(-72 * time.Hour), Source: models.SourceCowrie, Kind: "command", SrcIP: "8.8.8.8", ActorID: "a8"},
	}
	for _, e := range append(append([]*models.Event{}, in...), out...) {
		if err := st.InsertEvent(e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	got, err := st.WindowActivitySince(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("WindowActivitySince: %v", err)
	}
	if got.Events != len(in) {
		t.Errorf("Events = %d, want %d (older events must be excluded)", got.Events, len(in))
	}
	if got.UniqueIPs != 3 {
		t.Errorf("UniqueIPs = %d, want 3", got.UniqueIPs)
	}
	if got.Accepted != 1 {
		t.Errorf("Accepted = %d, want 1", got.Accepted)
	}
	if got.Commands != 1 {
		t.Errorf("Commands = %d, want 1", got.Commands)
	}
	if got.Downloads != 2 {
		t.Errorf("Downloads = %d, want 2 (file_download + file_upload)", got.Downloads)
	}
}

// TestWindowActivitySinceEmpty covers a fresh install and a dead honeypot: the
// conditional SUMs return NULL, which must default to 0 rather than error and
// blank the gauge.
func TestWindowActivitySinceEmpty(t *testing.T) {
	st := newTestStore(t, "window.db")
	got, err := st.WindowActivitySince(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("empty window must not error (NULL SUMs): %v", err)
	}
	if got.Events != 0 || got.UniqueIPs != 0 || got.Accepted != 0 || got.Commands != 0 || got.Downloads != 0 {
		t.Errorf("empty window returned %+v, want all zero", got)
	}
}
