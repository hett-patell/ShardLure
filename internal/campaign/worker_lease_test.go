package campaign

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
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
	// Regaining the lease re-reads the hold from the store (holdClear reset).
	w2.Close()
	w1.holdClear = true
	now = now.Add(time.Second)
	if err := w1.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w1.leaseOwner {
		t.Fatalf("w1 did not reacquire after w2's release: holder %q", owner)
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
