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
	w1 := NewWorker(st, 90, t.TempDir())
	w1.leaseTTL = 40 * time.Millisecond
	w2 := NewWorker(st, 90, t.TempDir())
	w2.leaseTTL = 40 * time.Millisecond
	if err := w1.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w1.leaseOwner {
		t.Fatalf("w2 took a live lease: holder %q", owner)
	}
	time.Sleep(60 * time.Millisecond) // w1 "crashed": no renewal
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
	if err := w1.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != w2.leaseOwner || !w1.leaseUntil.IsZero() {
		t.Fatalf("evicted owner kept running: holder %q, w1 until %v", owner, w1.leaseUntil)
	}
	// Regaining the lease re-reads the hold from the store (holdClear reset).
	w2.Close()
	w1.holdClear = true
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
