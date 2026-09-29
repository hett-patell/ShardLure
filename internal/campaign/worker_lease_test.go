package campaign

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/script"
)

// captureLog routes the worker's log lines into a buffer for the test.
func captureLog(t *testing.T) *strings.Builder {
	t.Helper()
	var b strings.Builder
	prev := logf
	logf = func(format string, args ...any) { b.WriteString(fmt.Sprintf(format, args...) + "\n") }
	t.Cleanup(func() { logf = prev })
	return &b
}

// Two workers on one database stand for `shardlure live` and a separately
// started `shardlure web`: only the lease holder runs the pipeline. The other
// ticks quietly (nil, no state, no backoff) and says so once.
func TestOnlyTheLeaseHolderRunsThePipeline(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	logs := captureLog(t)
	w1 := NewWorker(st, 90, t.TempDir())
	w2 := NewWorker(st, 90, t.TempDir())
	if err := w1.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w1.leaseOwner {
		t.Fatalf("lease holder %q, want w1 %q", owner, w1.leaseOwner)
	}
	for i := 0; i < 3; i++ {
		if err := w2.Tick(ctx); err != nil {
			t.Fatalf("a worker without the lease must skip quietly, got %v", err)
		}
	}
	if w2.versionChecked || !w2.leaseUntil.IsZero() || w2.failures != 0 || !w2.retryAt.IsZero() {
		t.Fatalf("w2 ran or backed off without the lease: %+v", w2)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w1.leaseOwner {
		t.Fatalf("lease holder %q after w2's ticks, want w1", owner)
	}
	if n := strings.Count(logs.String(), "holds the campaign worker lease"); n != 1 {
		t.Fatalf("the other holder was logged %d times over 3 skipped ticks, want once:\n%s", n, logs.String())
	}
	if err := w2.Regroup(ctx); err != ErrLeaseHeldElsewhere {
		t.Fatalf("Regroup without the lease = %v, want ErrLeaseHeldElsewhere", err)
	}
	// The holder alone built the campaign: a standalone web against an
	// offline-ingested database is exactly a single worker.
	list, err := st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 1 || list[0].Actors != 2 {
		t.Fatalf("campaigns %+v %v", list, err)
	}
}

// A crashed owner never releases; its lease expires and the next worker takes
// over, after which the old owner's ticks skip.
func TestLeaseExpiryHandsThePipelineOver(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b") // script lines, so a forced rebuild below has something to hold for
	ctx := context.Background()
	logs := captureLog(t)
	// A shared fake clock: the lease is decided on the time the worker passes
	// to the store, so the test advances time instead of sleeping (a real
	// 40 ms TTL lapsed before the second tick under a loaded test host).
	now := time.Now()
	clock := func() time.Time { return now }
	w1 := NewWorker(st, 90, t.TempDir())
	w1.clock = clock
	w2 := NewWorker(st, 90, t.TempDir())
	w2.clock = clock
	if err := w1.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	if err := w2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w1.leaseOwner {
		t.Fatalf("w2 took a live lease: holder %q", owner)
	}
	now = now.Add(campaignLeaseTTL) // w1 "crashed": no renewal, the lease has expired
	if err := w2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w2.leaseOwner {
		t.Fatalf("expired lease not taken over: holder %q, want w2 %q", owner, w2.leaseOwner)
	}
	if !strings.Contains(logs.String(), "now holds the campaign worker lease") {
		t.Fatalf("takeover not logged:\n%s", logs.String())
	}
	// w1 comes back: its in-memory expiry has passed, the renewal is refused.
	now = now.Add(time.Second)
	if err := w1.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w2.leaseOwner || !w1.leaseUntil.IsZero() {
		t.Fatalf("evicted owner kept running: holder %q, w1 until %v", owner, w1.leaseUntil)
	}
	// Regaining the lease re-reads the hold from the store: a script rebuild
	// started meanwhile (here forced directly on the store) holds regroups,
	// and w1, which believed the hold clear, must not regroup through it.
	w2.Close()
	if err := st.ForceScriptRebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if reset, err := st.ResetScriptsForVersion(ctx, script.Version); err != nil || !reset {
		t.Fatalf("reset=%v err=%v, want a reset that sets the hold", reset, err)
	}
	w1.holdClear = true
	w1.Wake()
	grouped := w1.lastGroup
	now = now.Add(time.Second)
	if err := w1.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w1.leaseOwner {
		t.Fatalf("w1 did not reacquire after w2's release: holder %q", owner)
	}
	if w1.holdClear || !w1.lastGroup.Equal(grouped) || !w1.wake.Load() {
		t.Fatalf("regained lease did not re-read the hold: holdClear=%v regrouped=%v wake=%v", w1.holdClear, !w1.lastGroup.Equal(grouped), w1.wake.Load())
	}
}

// M-1: a holder whose lease lapsed on its own clock (a phase stalled past
// the TTL) never saw another holder, so leaseUntil stays non-zero. Another
// process takes the lapsed lease, starts a script rebuild (store hold) and
// releases; the first process's next acquire must count as regaining, or its
// stale holdClear lets it regroup through the hold.
func TestLapsedHolderRereadsHoldOnReacquire(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	now := time.Now()
	clock := func() time.Time { return now }
	a := NewWorker(st, 90, t.TempDir())
	a.clock = clock
	if err := a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !a.holdClear || a.leaseUntil.IsZero() {
		t.Fatalf("precondition: a holds with the hold clear: holdClear=%v until=%v", a.holdClear, a.leaseUntil)
	}
	grouped := a.lastGroup
	now = now.Add(campaignLeaseTTL + time.Second) // a stalled; its lease lapsed unseen
	if err := st.ForceScriptRebuild(ctx); err != nil {
		t.Fatal(err)
	}
	b := NewWorker(st, 90, t.TempDir())
	b.clock = clock
	if err := b.Tick(ctx); err != nil { // takes the lapsed lease, resets, holds
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != b.leaseOwner {
		t.Fatalf("b did not take the lapsed lease: holder %q", owner)
	}
	if held, err := st.ScriptRebuildHold(ctx, now); err != nil || !held {
		t.Fatalf("precondition: b's reset must hold regroups: held=%v err=%v", held, err)
	}
	b.Close()
	now = now.Add(time.Second)
	a.Wake()
	if err := a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != a.leaseOwner {
		t.Fatalf("a did not reacquire: holder %q", owner)
	}
	if a.holdClear || !a.lastGroup.Equal(grouped) {
		t.Fatalf("a regrouped through the store hold after its lease lapsed: holdClear=%v regrouped=%v", a.holdClear, !a.lastGroup.Equal(grouped))
	}
}

// A takeover re-runs the normaliser version check (cmd audit M2): worker B
// held once and checked; A took over; a `scripts --rebuild` deleted the
// version row while A held; when B takes the lease back it must run the
// reset, not trust its earlier check.
func TestLeaseTakeoverRerunsVersionCheck(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	logs := captureLog(t)
	now := time.Now()
	clock := func() time.Time { return now }
	a, b := NewWorker(st, 90, t.TempDir()), NewWorker(st, 90, t.TempDir())
	a.clock, b.clock = clock, clock
	if err := b.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !b.versionChecked {
		t.Fatal("precondition: b checked the version while holding")
	}
	now = now.Add(campaignLeaseTTL + time.Second)
	if err := a.Tick(ctx); err != nil { // a takes b's expired lease
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != a.leaseOwner {
		t.Fatalf("a did not take over: holder %q", owner)
	}
	if err := st.ForceScriptRebuild(ctx); err != nil { // `scripts --rebuild` while a holds
		t.Fatal(err)
	}
	a.Close()
	now = now.Add(time.Second)
	if err := b.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != b.leaseOwner {
		t.Fatalf("b did not take the released lease: holder %q", owner)
	}
	if !strings.Contains(logs.String(), "rebuilding script lines") {
		t.Fatalf("b took the lease without re-running the version check:\n%s", logs.String())
	}
	if held, err := st.ScriptRebuildHold(ctx, now); err != nil || !held {
		t.Fatalf("the reset must hold regroups: held=%v err=%v", held, err)
	}
}

// M-2: the lease is a fence for the save. A regroup whose lease lapsed on
// the process's own clock, or whose row another process took under a wall
// clock this process has not seen advance, must not reach SaveGrouping; the
// next tick retakes the lease and regroups again.
func TestSaveIsFencedByTheLease(t *testing.T) {
	for _, mode := range []string{"lapsed clock", "row taken"} {
		t.Run(mode, func(t *testing.T) {
			st := openStore(t)
			insertSharedKey(t, st, "cowrie:a", "cowrie:b")
			ctx := context.Background()
			now := time.Now()
			w := NewWorker(st, 90, t.TempDir())
			w.clock = func() time.Time { return now }
			if err := w.Tick(ctx); err != nil {
				t.Fatal(err)
			}
			list, err := st.ListCampaigns(ctx, 10)
			if err != nil || len(list) != 1 {
				t.Fatalf("campaigns %+v %v", list, err)
			}
			if err := st.AppendCampaignEdit(ctx, list[0].ID, "rename", "Fenced", "cli"); err != nil {
				t.Fatal(err)
			}
			beforeSave = func() {
				beforeSave = nil
				switch mode {
				case "lapsed clock":
					now = now.Add(campaignLeaseTTL + time.Second)
				case "row taken":
					// Another process, whose wall clock is past this lease's
					// stored expiry, takes the row; this process's clock has
					// not moved.
					if held, err := st.AcquireCampaignLease(ctx, "other", now.Add(campaignLeaseTTL+time.Second), campaignLeaseTTL); err != nil || !held {
						t.Errorf("other process could not take the expired row: held=%v err=%v", held, err)
					}
				}
			}
			t.Cleanup(func() { beforeSave = nil })
			w.Wake()
			if err := w.Tick(ctx); !errors.Is(err, ErrLeaseLapsed) {
				t.Fatalf("Tick = %v, want ErrLeaseLapsed", err)
			}
			if list, _ := st.ListCampaigns(ctx, 10); len(list) != 1 || list[0].Name != "" {
				t.Fatalf("the save went through a lapsed lease: %+v", list)
			}
			if !w.pending {
				t.Fatal("the refused regroup is not owed")
			}
			if mode == "row taken" {
				if err := st.ReleaseCampaignLease(ctx, "other"); err != nil {
					t.Fatal(err)
				}
			}
			now = now.Add(campaignLeaseTTL + 2*time.Second)
			w.retryAt = time.Time{} // past the backoff
			if err := w.Tick(ctx); err != nil {
				t.Fatal(err)
			}
			if list, _ := st.ListCampaigns(ctx, 10); len(list) != 1 || list[0].Name != "Fenced" {
				t.Fatalf("the next tick did not retake the lease and regroup: %+v", list)
			}
		})
	}
}

// Close releases the lease so a restart hands over at once, without waiting
// out the TTL; a worker that never held it has nothing to release.
func TestCloseReleasesTheLease(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	w1 := NewWorker(st, 90, t.TempDir())
	w2 := NewWorker(st, 90, t.TempDir())
	if err := w1.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	w2.Close() // never held: must not evict w1
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w1.leaseOwner {
		t.Fatalf("Close of a non-holder evicted the holder: %q", owner)
	}
	w1.Close()
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != "" {
		t.Fatalf("lease still held after Close: %q", owner)
	}
	if err := w2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w2.leaseOwner {
		t.Fatalf("released lease not taken: holder %q", owner)
	}
}

// With the lease, only one process regroups, but edits are POSTed to whichever
// process serves the dashboard: an edit recorded straight into the store (as a
// `shardlure web` beside the `live` daemon would, with its own Wake going to
// the wrong process) must still be applied by the holder on its next tick, not
// at the next 10-minute scheduled regroup.
func TestEditRecordedByAnotherProcessRegroupsOnNextTick(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	w := NewWorker(st, 90, t.TempDir())
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("campaigns %+v %v", list, err)
	}
	if err := st.AppendCampaignEdit(ctx, list[0].ID, "rename", "From The Other Process", "web"); err != nil {
		t.Fatal(err)
	}
	// No Wake: the other process called its own. The holder's tick must see
	// the new edit ID and regroup now.
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, err = st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 1 || list[0].Name != "From The Other Process" {
		t.Fatalf("edit from another process not applied on the next tick: %+v %v", list, err)
	}
	// And an idle tick with nothing new does not regroup (lastGroup unchanged).
	before := w.lastGroup
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.lastGroup.Equal(before) {
		t.Fatal("an idle tick regrouped although no edit arrived")
	}
}
