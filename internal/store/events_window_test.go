package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestEventsSinceCappedBoundsAndTotal verifies the HIGH perf fix: the windowed
// fetch caps how many rows it materializes but still reports the TRUE window
// total, so callers can disclose "analyzed N of M" instead of silently
// truncating (the failure mode of the old fixed-cap EventsSince).
func TestEventsSinceCappedBoundsAndTotal(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "win.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	const n = 50
	ev := make([]*models.Event, 0, n)
	for i := 0; i < n; i++ {
		ev = append(ev, &models.Event{
			TS: now.Add(-time.Duration(i) * time.Minute), Source: models.SourceCowrie,
			Kind: models.KindCommand, SrcIP: "9.9.9.9", SessionID: "s1",
			Command: "cmd", ActorID: "a1",
		})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(ev, nil); err != nil {
		t.Fatal(err)
	}

	since := now.Add(-24 * time.Hour)

	// Cap below the population: events are bounded, total is the full count.
	events, total, err := st.EventsSinceCapped(since, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 10 {
		t.Fatalf("capped events = %d, want 10", len(events))
	}
	if total != n {
		t.Fatalf("total = %d, want %d (true window population regardless of cap)", total, n)
	}

	// Newest-first: the first returned event must be the most recent.
	if len(events) >= 2 && events[0].TS.Before(events[1].TS) {
		t.Fatalf("events not newest-first: %v before %v", events[0].TS, events[1].TS)
	}

	// Cap above the population: returns everything, total unchanged.
	all, total2, err := st.EventsSinceCapped(since, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != n || total2 != n {
		t.Fatalf("uncapped: got len=%d total=%d, want %d/%d", len(all), total2, n, n)
	}
}

// TestRecordSessionBindingsMatchesSingular verifies the batched side-channel
// writer persists hassh/duration/arch/tty exactly like the per-item methods it
// replaces on the ingest hot path.
func TestRecordSessionBindingsMatchesSingular(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "bind.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ts := time.Now().UTC()
	batch := []SessionBinding{
		{SessionID: "s1", HASSH: "aa:bb", Arch: "linux-x64-lsb", DurationMs: 4200},
		{SessionID: "s2", HASSH: "cc:dd"},
		{SessionID: "s1", TTYSHA: "DEADBEEF", TTYTS: ts}, // tty keyed separately
	}
	if err := st.RecordSessionBindings(batch); err != nil {
		t.Fatal(err)
	}

	hasshes, err := st.HASSHForSessions([]string{"s1", "s2"})
	if err != nil {
		t.Fatal(err)
	}
	if hasshes["s1"] != "aa:bb" || hasshes["s2"] != "cc:dd" {
		t.Fatalf("hassh map = %v, want s1=aa:bb s2=cc:dd", hasshes)
	}

	meta, err := st.SessionMetaForSessions([]string{"s1"})
	if err != nil {
		t.Fatal(err)
	}
	if meta["s1"].DurationMs != 4200 {
		t.Fatalf("s1 duration = %d, want 4200", meta["s1"].DurationMs)
	}
	if meta["s1"].Arch != "linux-x64-lsb" {
		t.Fatalf("s1 arch = %q, want linux-x64-lsb", meta["s1"].Arch)
	}

	// tty sha is normalized to lowercase (matches RecordCowrieTTYBinding).
	sess, err := st.SessionIDForCowrieTTYShasum("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if sess != "s1" {
		t.Fatalf("tty sha -> session = %q, want s1", sess)
	}

	// Empty batch is a no-op, not an error.
	if err := st.RecordSessionBindings(nil); err != nil {
		t.Fatalf("empty batch returned error: %v", err)
	}
}
