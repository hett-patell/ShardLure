package campaign

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// scriptCampaignStore opens a store at a known path (so the test can read
// campaign_ids directly), inserts one script-only session per actor and
// returns the store, the events (for a --replace) and a raw-SQL scalar reader.
func scriptCampaignStore(t *testing.T, actors ...string) (*store.Store, []*models.Event, func(q string, args ...any) string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "replace.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var events []*models.Event
	for i, a := range actors {
		e := &models.Event{TS: time.Now().UTC().Add(-time.Hour), Source: models.SourceCowrie, Kind: models.KindCommand,
			SessionID: fmt.Sprintf("s%d", i), ActorID: a, SrcIP: "198.51.100.1", Command: scriptOnlyCmd}
		if err := st.InsertEvent(e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	one := func(q string, args ...any) string {
		t.Helper()
		var v string
		if err := raw.QueryRow(q, args...).Scan(&v); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return v
	}
	return st, events, one
}

// renamedScriptCampaign ticks w until the script-only campaign exists,
// renames it "Keep" and returns its ID.
func renamedScriptCampaign(t *testing.T, st *store.Store, w *Worker) string {
	t.Helper()
	ctx := context.Background()
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 1 || list[0].Actors != 2 {
		t.Fatalf("script-only campaign %+v %v", list, err)
	}
	if err := st.AppendCampaignEdit(ctx, list[0].ID, "rename", "Keep", "cli"); err != nil {
		t.Fatal(err)
	}
	w.Wake()
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	return list[0].ID
}

// showCampaigns lists the campaigns with a one-line rendering for failures.
func showCampaigns(t *testing.T, st *store.Store) (list []store.CampaignSummary, shown []string) {
	t.Helper()
	list, err := st.ListCampaigns(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		shown = append(shown, fmt.Sprintf("%s name=%q actors=%d", c.ID, c.Name, c.Actors))
	}
	return list, shown
}

func expectKept(t *testing.T, st *store.Store, id string) {
	t.Helper()
	list, shown := showCampaigns(t, st)
	if len(list) != 1 || list[0].ID != id || list[0].Name != "Keep" || list[0].Actors != 2 {
		t.Fatalf("after the hold released: %v (want only %s named Keep with 2 actors)", shown, id)
	}
}

// Store pipeline audit I1, worker side. A Cowrie --replace re-records every
// session with a fresh updated_at, so for ten minutes no script is settled
// anywhere; the store now arms the script rebuild hold on every replace so
// the drain's regroup waits for that settle. The worker must see the hold
// on its next tick whichever process ran the replace. It used to cache "no
// hold" once read (holdClear) and re-read only after a restart or a lease
// takeover, so a running worker regrouped straight through a hold the CLI
// had just armed: the regroup dropped the script row from campaign_ids and
// the settled sessions came back under a fresh ID with "Keep" on an empty
// shell.
func TestReplaceHoldIsSeenWithoutRestart(t *testing.T) {
	st, events, one := scriptCampaignStore(t, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	w := NewWorker(st, 90, t.TempDir())
	t.Cleanup(w.Close)
	w.idle = -time.Minute
	id := renamedScriptCampaign(t, st, w)
	fp := one(`SELECT value FROM campaign_ids WHERE kind='script'`)

	// The CLI runs `ingest cowrie --replace` with the same sessions while w
	// keeps ticking; the re-recorded sessions are fresh, so with the real
	// idle nothing settles yet. The replaced rows drain inside one tick, so
	// the tick itself owes no regroup; what regroups in the settle window
	// is the 10-minute schedule or an operator edit, here a Wake.
	if err := st.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, events, nil); err != nil {
		t.Fatal(err)
	}
	w.idle = settleIdle
	w.Wake()
	grouped := w.lastGroup
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.drained {
		t.Fatal("precondition: the replaced rows drained in one tick")
	}
	if !w.lastGroup.Equal(grouped) || !w.wake.Load() || one(`SELECT COUNT(*) FROM campaign_ids WHERE kind='script' AND value=?`, fp) != "1" {
		t.Fatalf("regrouped through the hold the replace armed: regrouped=%v wake kept=%v script rows=%s",
			!w.lastGroup.Equal(grouped), w.wake.Load(), one(`SELECT COUNT(*) FROM campaign_ids WHERE kind='script'`))
	}
	// The sessions settle, the hold releases and the owed regroup runs.
	w.idle = -time.Minute
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	expectKept(t, st, id)
}

// The auditor's Probe A: the same replace with no prior hold, followed by a
// restart, ticked through the process. The first tick of the new process
// drains and, with the real idle, must be held; once the sessions settle the
// hold releases (carrying nothing: the fingerprints did not change) and the
// campaign keeps its ID and name.
func TestReplaceWithoutPriorHoldKeepsRenamedScriptCampaignAcrossRestart(t *testing.T) {
	st, events, one := scriptCampaignStore(t, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	w := NewWorker(st, 90, t.TempDir())
	w.idle = -time.Minute
	id := renamedScriptCampaign(t, st, w)
	w.Close() // the process stops; the lease is released; no hold exists
	if got := one(`SELECT COUNT(*) FROM ingest_state WHERE source='script_version' AND path<>'normaliser'`); got != "0" {
		t.Fatalf("precondition: a hold exists before the replace (%s rows)", got)
	}
	if err := st.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, events, nil); err != nil {
		t.Fatal(err)
	}
	w2 := NewWorker(st, 90, t.TempDir()) // the real settleIdle
	t.Cleanup(w2.Close)
	for i := 0; i < 20 && !w2.drained; i++ {
		if err := w2.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !w2.drained {
		t.Fatal("backlog never drained")
	}
	if !w2.lastGroup.IsZero() || one(`SELECT COUNT(*) FROM campaign_ids WHERE kind='script'`) != "1" {
		t.Fatalf("regrouped before the re-recorded sessions settled: regrouped=%v script rows=%s",
			!w2.lastGroup.IsZero(), one(`SELECT COUNT(*) FROM campaign_ids WHERE kind='script'`))
	}
	w2.idle = -time.Minute
	if err := w2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := one(`SELECT COUNT(*) FROM ingest_state WHERE source='script_version' AND path<>'normaliser'`); got != "0" {
		t.Fatalf("hold not released (%s rows)", got)
	}
	expectKept(t, st, id)
}

// Final re-review, store/campaign open item. The hold check and the
// regroup's reads are separate statements with no shared snapshot: a CLI
// --replace committing after this tick's hold check read "no hold" but
// before the regroup read the evidence left the regroup looking at empty
// evidence and scripts beside the kept campaign_ids. Group dropped every
// assignment, and the save was accepted (its fence checked only the lease
// and the edit log, and a replace moves neither), so "Keep" was left on an
// empty shell and the sessions came back under a fresh ID. The save must
// refuse (ErrStaleGrouping, retried on the next tick, which sees the hold
// the replace armed) and the campaign must survive once the hold releases.
func TestReplaceBetweenHoldCheckAndRegroupReadsKeepsCampaign(t *testing.T) {
	st, events, one := scriptCampaignStore(t, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	w := NewWorker(st, 90, t.TempDir())
	t.Cleanup(w.Close)
	w.idle = -time.Minute
	id := renamedScriptCampaign(t, st, w)

	replaced := false
	regroupStart = func() {
		regroupStart = nil
		replaced = true
		if err := st.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, events, nil); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { regroupStart = nil })
	w.idle = settleIdle // the re-recorded sessions are fresh: nothing settles yet
	w.Wake()
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatal("precondition: the tick never reached regroup")
	}
	// The refused save leaves the pre-replace grouping in place: the named
	// campaign still owns the script row. Its members and counts went with
	// the replace (which zeroes the counts of the campaigns it keeps, so they
	// never sit beside an empty member list); a save would have dropped the
	// script row instead.
	if list, shown := showCampaigns(t, st); len(list) != 1 || list[0].ID != id || list[0].Name != "Keep" || list[0].Actors != 0 ||
		one(`SELECT COUNT(*) FROM campaign_ids WHERE kind='script' AND campaign_id=?`, id) != "1" {
		t.Fatalf("the regroup saved over a replace that landed after its hold check: %v (script rows=%s)",
			shown, one(`SELECT COUNT(*) FROM campaign_ids WHERE kind='script'`))
	}
	if !w.wake.Load() {
		t.Fatal("the refused save was not kept owed (wake cleared)")
	}
	// The next tick sees the hold; once the sessions settle it releases and
	// the owed regroup keeps the campaign.
	w.idle = -time.Minute
	for i := 0; i < 3; i++ {
		if err := w.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	expectKept(t, st, id)
}
