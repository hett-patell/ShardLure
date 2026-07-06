package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestSessionMetaRoundTrip verifies duration/arch persist independently for the
// same session (closed and params events arrive separately), that empty/zero
// values don't clobber a real one, and that ListSessions stamps them.
func TestSessionMetaRoundTrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// arch recorded first (params), then duration (closed) — the two upserts
	// must not erase each other.
	if err := st.RecordSessionArch("sessA", "linux-x64-lsb"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordSessionDuration("sessA", 2267); err != nil {
		t.Fatal(err)
	}
	// zero/empty must be ignored.
	if err := st.RecordSessionDuration("sessA", 0); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordSessionArch("sessA", ""); err != nil {
		t.Fatal(err)
	}

	meta, err := st.SessionMetaForSessions([]string{"sessA", "sessMissing"})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := meta["sessA"]
	if !ok {
		t.Fatal("sessA not in meta map")
	}
	if m.DurationMs != 2267 || m.Arch != "linux-x64-lsb" {
		t.Fatalf("meta = %d / %q (want 2267 / linux-x64-lsb)", m.DurationMs, m.Arch)
	}
	if _, ok := meta["sessMissing"]; ok {
		t.Fatal("missing session should not appear in map")
	}

	// End-to-end: a session's events plus its meta binding → ListSessions stamps
	// DurationMs/Arch onto the summary.
	now := time.Now().UTC()
	ev := []*models.Event{
		{TS: now.Add(-2 * time.Minute), Source: models.SourceCowrie, Kind: models.KindConnect, SrcIP: "5.5.5.5", SessionID: "sessA"},
		{TS: now.Add(-1 * time.Minute), Source: models.SourceCowrie, Kind: models.KindCommand, SrcIP: "5.5.5.5", SessionID: "sessA", Command: "id"},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(ev, nil); err != nil {
		t.Fatal(err)
	}
	sums, err := st.ListSessions(now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, s := range sums {
		if s.ID == "sessA" {
			found = true
			if s.DurationMs != 2267 || s.Arch != "linux-x64-lsb" {
				t.Fatalf("ListSessions stamp = %d / %q", s.DurationMs, s.Arch)
			}
		}
	}
	if !found {
		t.Fatal("sessA not returned by ListSessions")
	}
}
