package campaign

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// keyCommand writes a syntactically valid ed25519 key whose 32 key bytes are
// derived from seed, so two seeds give two distinct linking values.
func keyCommand(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	var blob []byte
	blob = binary.BigEndian.AppendUint32(blob, uint32(len("ssh-ed25519")))
	blob = append(blob, "ssh-ed25519"...)
	blob = binary.BigEndian.AppendUint32(blob, 32)
	blob = append(blob, sum[:]...)
	return fmt.Sprintf(`mkdir -p ~/.ssh; echo "ssh-ed25519 %s op" >> ~/.ssh/authorized_keys`, base64.StdEncoding.EncodeToString(blob))
}

// twoKeyCampaigns inserts two key campaigns (K1 by a and b, K2 by c and d,
// K2 the later one) and returns the events for a --replace.
func twoKeyCampaigns(t *testing.T, st *store.Store) []*models.Event {
	t.Helper()
	var events []*models.Event
	for i, actor := range []string{"cowrie:a", "cowrie:b", "cowrie:c", "cowrie:d"} {
		key, age := "K1", -2*time.Hour
		if i >= 2 {
			key, age = "K2", -time.Hour
		}
		e := &models.Event{TS: time.Now().UTC().Add(age), Source: models.SourceCowrie, Kind: models.KindCommand,
			SessionID: fmt.Sprintf("s%d", i), ActorID: actor, SrcIP: "198.51.100.1", Command: keyCommand(key)}
		if err := st.InsertEvent(e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	return events
}

// I-2: a regroup while the recorder still has a backlog sees only the
// evidence recorded so far, and SaveGrouping replaces campaign_ids with what
// Group returned, so every campaign whose evidence is not yet re-recorded
// loses its assignment; when the evidence arrives it is minted under a new
// ID (the old one is reserved by the edit) and the name stays on an empty
// shell. The audit reached it through `ingest cowrie --replace` (clears the
// evidence, parks the cursor, re-inserts the rows above it) followed by a
// restart: editsSeen starts at 0, so the first tick saw "a new edit" and
// regrouped at once. The same happens in one process when the operator
// edits during a backfill (Wake). Neither may regroup until the tick ends
// drained; the drain already owes a regroup.
func TestRestartDuringBacklogKeepsRenamedCampaign(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	events := twoKeyCampaigns(t, st)
	w := NewWorker(st, 90, t.TempDir())
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 2 {
		t.Fatalf("campaigns %+v %v", list, err)
	}
	later := list[0]
	for _, c := range list {
		if c.LastSeen.After(later.LastSeen) {
			later = c
		}
	}
	if err := st.AppendCampaignEdit(ctx, later.ID, "rename", "Operator Name", "cli"); err != nil {
		t.Fatal(err)
	}
	w.Wake()
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	w.Close() // the process stops; the lease is released
	// `ingest cowrie --replace` with the same events.
	if err := st.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, events, nil); err != nil {
		t.Fatal(err)
	}
	// A new process whose backlog spans several ticks (window 1 event).
	w2 := NewWorker(st, 90, t.TempDir())
	t.Cleanup(w2.Close)
	w2.window, w2.maxWindows = 1, 1
	for i := 0; i < 20 && !w2.drained; i++ {
		if err := w2.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !w2.drained {
		t.Fatal("backlog never drained")
	}
	list, err = st.ListCampaigns(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range list {
		got = append(got, fmt.Sprintf("%s name=%q actors=%d", c.ID, c.Name, c.Actors))
	}
	if len(list) != 2 {
		t.Fatalf("want the two campaigns after the drain, got %v", got)
	}
	for _, c := range list {
		if c.ID == later.ID && (c.Name != "Operator Name" || c.Actors != 2) {
			t.Fatalf("renamed campaign lost its members: %v", got)
		}
		if c.ID != later.ID && (c.Name != "" || c.Actors != 2) {
			t.Fatalf("unexpected campaign: %v", got)
		}
	}
}

// The single-process shape of I-2: a Wake (an operator edit) during a
// backlog is deferred, not consumed, and the regroup the drain owes applies
// it. Before, a Wake regrouped at once and dropped the assignments of every
// campaign whose evidence was still queued.
func TestWakeDuringBacklogIsDeferredUntilDrained(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	twoKeyCampaigns(t, st)
	w := NewWorker(st, 90, t.TempDir())
	t.Cleanup(w.Close)
	w.window, w.maxWindows = 1, 1
	if err := w.Tick(ctx); err != nil { // one event recorded of four
		t.Fatal(err)
	}
	if w.drained {
		t.Fatal("precondition: the backlog must outlive the tick")
	}
	w.Wake()
	grouped := w.lastGroup
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.lastGroup.Equal(grouped) {
		t.Fatal("a Wake regrouped during a backlog")
	}
	if !w.wake.Load() {
		t.Fatal("the Wake was consumed during a backlog instead of deferred")
	}
	w.window, w.maxWindows = recordWindow, maxWindowsPerTick
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.drained || w.pending || w.wake.Load() || !w.lastGroup.After(grouped) {
		t.Fatalf("the drain did not run the owed regroup: drained=%v pending=%v wake=%v", w.drained, w.pending, w.wake.Load())
	}
	list, err := st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 2 {
		t.Fatalf("campaigns %+v %v", list, err)
	}
}
