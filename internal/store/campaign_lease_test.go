package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// One process holds the campaign worker lease at a time: a second owner is
// refused while the lease is live, renews are owner-only, an expired lease is
// taken over, and a release hands it on immediately.
func TestCampaignLeaseSingleHolder(t *testing.T) {
	st := newTestStore(t, "lease.db")
	ctx := context.Background()
	t0 := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

	if held, err := st.AcquireCampaignLease(ctx, "a", t0, time.Minute); err != nil || !held {
		t.Fatalf("first acquire = %v, %v", held, err)
	}
	if held, err := st.AcquireCampaignLease(ctx, "b", t0.Add(10*time.Second), time.Minute); err != nil || held {
		t.Fatalf("second owner took a live lease: %v, %v", held, err)
	}
	if owner, until, err := st.CampaignLeaseHolder(ctx); err != nil || owner != "a" || !until.Equal(t0.Add(time.Minute)) {
		t.Fatalf("holder = %q until %v, %v", owner, until, err)
	}
	// Renewal by the owner extends the expiry; the loser's attempt did not.
	if held, err := st.AcquireCampaignLease(ctx, "a", t0.Add(30*time.Second), time.Minute); err != nil || !held {
		t.Fatalf("renew = %v, %v", held, err)
	}
	if _, until, _ := st.CampaignLeaseHolder(ctx); !until.Equal(t0.Add(90 * time.Second)) {
		t.Fatalf("renewal did not extend: until %v", until)
	}
	// Still live at the old expiry, so b waits.
	if held, _ := st.AcquireCampaignLease(ctx, "b", t0.Add(89*time.Second), time.Minute); held {
		t.Fatal("b took the lease before it expired")
	}
	// Expired: the crashed owner is replaced.
	if held, err := st.AcquireCampaignLease(ctx, "b", t0.Add(90*time.Second), time.Minute); err != nil || !held {
		t.Fatalf("takeover of an expired lease = %v, %v", held, err)
	}
	// The old owner's renewal now fails, and its release is a no-op.
	if held, _ := st.AcquireCampaignLease(ctx, "a", t0.Add(91*time.Second), time.Minute); held {
		t.Fatal("evicted owner renewed over the new holder")
	}
	if err := st.ReleaseCampaignLease(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != "b" {
		t.Fatalf("release by a non-holder evicted %q", owner)
	}
	// Release by the holder hands the lease on at once.
	if err := st.ReleaseCampaignLease(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != "" {
		t.Fatalf("lease still held by %q after release", owner)
	}
	if held, err := st.AcquireCampaignLease(ctx, "a", t0.Add(92*time.Second), time.Minute); err != nil || !held {
		t.Fatalf("acquire after release = %v, %v", held, err)
	}
	for _, bad := range []struct {
		owner string
		ttl   time.Duration
	}{{"", time.Minute}, {"x", 0}, {"x", 2 * time.Hour}} {
		if _, err := st.AcquireCampaignLease(ctx, bad.owner, t0, bad.ttl); err != ErrCampaignLeaseInvalid {
			t.Fatalf("owner %q ttl %v: err %v", bad.owner, bad.ttl, err)
		}
	}
}

// A Cowrie --replace clears the campaign-derived rows but must not evict the
// lease: the row shares ingest_state's source='campaign' with the cursor.
func TestCampaignLeaseSurvivesReplace(t *testing.T) {
	st := newTestStore(t, "lease_replace.db")
	ctx := context.Background()
	now := time.Now()
	if held, err := st.AcquireCampaignLease(ctx, "a", now, time.Minute); err != nil || !held {
		t.Fatalf("acquire = %v, %v", held, err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error { return clearCampaignDerivedTx(tx) }); err != nil {
		t.Fatal(err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != "a" {
		t.Fatalf("replace evicted the lease holder: %q", owner)
	}
}

// RenewCampaignLease extends only an unexpired lease held by the caller: it
// never inserts a missing row, never renews for another owner and never
// takes over an expired one (that is AcquireCampaignLease's job, at the
// start of a tick).
func TestRenewCampaignLeaseNeverTakesOver(t *testing.T) {
	st := newTestStore(t, "renew.db")
	ctx := context.Background()
	t0 := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	if held, err := st.RenewCampaignLease(ctx, "a", t0, time.Minute); err != nil || held {
		t.Fatalf("renew with no row = %v, %v; want refused", held, err)
	}
	if owner, _, _ := st.CampaignLeaseHolder(ctx); owner != "" {
		t.Fatalf("renew inserted a row for %q", owner)
	}
	if held, err := st.AcquireCampaignLease(ctx, "a", t0, time.Minute); err != nil || !held {
		t.Fatalf("acquire = %v, %v", held, err)
	}
	if held, err := st.RenewCampaignLease(ctx, "b", t0.Add(time.Second), time.Minute); err != nil || held {
		t.Fatalf("renew by another owner = %v, %v; want refused", held, err)
	}
	if held, err := st.RenewCampaignLease(ctx, "a", t0.Add(30*time.Second), time.Minute); err != nil || !held {
		t.Fatalf("renew by the holder = %v, %v", held, err)
	}
	if _, until, _ := st.CampaignLeaseHolder(ctx); !until.Equal(t0.Add(90 * time.Second)) {
		t.Fatalf("renewal did not extend: until %v", until)
	}
	// Expired at the caller's clock: not renewed, row untouched.
	if held, err := st.RenewCampaignLease(ctx, "a", t0.Add(90*time.Second), time.Minute); err != nil || held {
		t.Fatalf("renew of an expired lease = %v, %v; want refused", held, err)
	}
	if owner, until, _ := st.CampaignLeaseHolder(ctx); owner != "a" || !until.Equal(t0.Add(90*time.Second)) {
		t.Fatalf("refused renewal changed the row: %q until %v", owner, until)
	}
	if _, err := st.RenewCampaignLease(ctx, "", t0, time.Minute); err != ErrCampaignLeaseInvalid {
		t.Fatalf("empty owner = %v, want ErrCampaignLeaseInvalid", err)
	}
}

// SaveGroupingAsLeaseHolder writes only while the lease row names the
// caller as an unexpired holder at the caller's clock; a missing row, another
// owner's row or an expired own row refuse with ErrCampaignLeaseLost and
// leave the previous grouping in place. The predicate runs in the save's own
// transaction.
func TestSaveGroupingAsLeaseHolderRequiresLiveOwnLease(t *testing.T) {
	st := newTestStore(t, "fenced.db")
	ctx := context.Background()
	t0 := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	row := func(id string) []CampaignRow { return []CampaignRow{{ID: id, AnchorKind: "ssh_key", AnchorValue: "K"}} }
	count := func() int {
		list, err := st.ListCampaigns(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	if err := st.SaveGroupingAsLeaseHolder(ctx, "a", t0, 0, row("c-1"), nil, nil, 0); !errors.Is(err, ErrCampaignLeaseLost) || count() != 0 {
		t.Fatalf("save with no lease row = %v (campaigns %d), want ErrCampaignLeaseLost and nothing written", err, count())
	}
	if held, err := st.AcquireCampaignLease(ctx, "b", t0, time.Minute); err != nil || !held {
		t.Fatalf("acquire = %v, %v", held, err)
	}
	if err := st.SaveGroupingAsLeaseHolder(ctx, "a", t0.Add(time.Second), 0, row("c-1"), nil, nil, 0); !errors.Is(err, ErrCampaignLeaseLost) || count() != 0 {
		t.Fatalf("save under another owner's lease = %v (campaigns %d), want ErrCampaignLeaseLost", err, count())
	}
	if held, err := st.AcquireCampaignLease(ctx, "a", t0.Add(time.Minute), time.Minute); err != nil || !held {
		t.Fatalf("takeover = %v, %v", held, err)
	}
	if err := st.SaveGroupingAsLeaseHolder(ctx, "a", t0.Add(2*time.Minute), 0, row("c-1"), nil, nil, 0); !errors.Is(err, ErrCampaignLeaseLost) || count() != 0 {
		t.Fatalf("save on an own lease expired at the caller's clock = %v (campaigns %d), want ErrCampaignLeaseLost", err, count())
	}
	if err := st.SaveGroupingAsLeaseHolder(ctx, "a", t0.Add(90*time.Second), 0, row("c-1"), nil, nil, 0); err != nil || count() != 1 {
		t.Fatalf("save under a live own lease = %v (campaigns %d)", err, count())
	}
	if err := st.SaveGroupingAsLeaseHolder(ctx, "", t0, 0, row("c-2"), nil, nil, 0); err != ErrCampaignLeaseInvalid {
		t.Fatalf("empty owner = %v, want ErrCampaignLeaseInvalid (never an unfenced save)", err)
	}
	if err := st.SaveGrouping(ctx, row("c-3"), nil, nil, 0); err != nil {
		t.Fatalf("unfenced SaveGrouping (fixtures) = %v", err)
	}
}

// A process that does not hold the lease must not take SQLite's write lock
// to find that out (pipeline audit M2). The conditional upsert's WHERE was
// false for it, but the statement still waited for the lock: behind a long
// writer in the holder's process (a CLI --replace is one multi-minute
// transaction on prod) it waited busy_timeout and failed with SQLITE_BUSY,
// which Tick counted as a failure (backoff, worker_error=1, a logged error)
// on a process that had nothing to do. The acquire now reads the row first
// and writes only when the lease is absent, its own or expired.
func TestNonHolderAcquireDoesNotWaitForTheWriteLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "busy.db")
	holder, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	ctx := context.Background()
	now := time.Now()
	if held, err := holder.AcquireCampaignLease(ctx, "holder", now, time.Minute); err != nil || !held {
		t.Fatalf("holder acquire %v %v", held, err)
	}
	// The holder's process keeps a write transaction open, with the SQLite
	// write lock taken, until the other process's acquire has returned.
	locked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- holder.WithTx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO app_settings(key,value,updated_at) VALUES('probe','x','x')`); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	start := time.Now()
	held, err := other.AcquireCampaignLease(ctx, "other", now.Add(time.Second), time.Minute)
	waited := time.Since(start)
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if err != nil || held {
		t.Fatalf("non-holder acquire behind a live lease and a long writer: held=%v err=%v after %v; want quietly refused", held, err, waited.Round(time.Millisecond))
	}
	if waited > time.Second {
		t.Fatalf("non-holder acquire waited %v on the write lock", waited.Round(time.Millisecond))
	}
	// The write path still decides the contested cases: the lease has expired,
	// so the other process takes it over (and the old owner is then refused).
	if held, err := other.AcquireCampaignLease(ctx, "other", now.Add(2*time.Minute), time.Minute); err != nil || !held {
		t.Fatalf("takeover of an expired lease = %v, %v", held, err)
	}
	if held, err := holder.AcquireCampaignLease(ctx, "holder", now.Add(2*time.Minute), time.Minute); err != nil || held {
		t.Fatalf("evicted owner re-acquired: %v, %v", held, err)
	}
}

// The worker save is also fenced by the recorder reset epoch it read before
// its hold check: a Cowrie --replace committing after that read (another
// process, the CLI) bumps the epoch, and the save must refuse with
// ErrStaleGrouping, leaving the previous grouping in place, instead of
// replacing campaign_ids with a grouping read over the emptied evidence
// (final re-review, store/campaign open item).
func TestSaveGroupingAsLeaseHolderRefusesMovedResetEpoch(t *testing.T) {
	st := newTestStore(t, "fenced-epoch.db")
	ctx := context.Background()
	t0 := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	// Named, so the replace (which drops unnamed campaigns) keeps it.
	row := func(id string) []CampaignRow {
		return []CampaignRow{{ID: id, Name: "Keep", AnchorKind: "ssh_key", AnchorValue: "K"}}
	}
	if held, err := st.AcquireCampaignLease(ctx, "a", t0, time.Minute); err != nil || !held {
		t.Fatalf("acquire = %v, %v", held, err)
	}
	before, err := st.EvidenceResetEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveGroupingAsLeaseHolder(ctx, "a", t0, before, row("c-1"), nil, nil, 0); err != nil {
		t.Fatalf("save under an unchanged epoch = %v", err)
	}
	if err := st.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, nil, nil); err != nil {
		t.Fatal(err)
	}
	after, err := st.EvidenceResetEpoch(ctx)
	if err != nil || after == before {
		t.Fatalf("precondition: a replace moves the epoch (%d -> %d, %v)", before, after, err)
	}
	if err := st.SaveGroupingAsLeaseHolder(ctx, "a", t0, before, row("c-2"), nil, nil, 0); !errors.Is(err, ErrStaleGrouping) {
		t.Fatalf("save under a moved epoch = %v, want ErrStaleGrouping", err)
	}
	list, err := st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 1 || list[0].ID != "c-1" {
		t.Fatalf("the refused save wrote: %+v %v", list, err)
	}
	if err := st.SaveGroupingAsLeaseHolder(ctx, "a", t0, after, row("c-2"), nil, nil, 0); err != nil {
		t.Fatalf("save under the re-read epoch = %v", err)
	}
}
