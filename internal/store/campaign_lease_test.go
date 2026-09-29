package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
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
