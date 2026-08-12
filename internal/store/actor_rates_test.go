package store

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// seedRateFixture builds two actors with the SAME lifetime event count but very
// different recent behaviour: `escalating` has been observed for weeks and is
// attacking now; `stale` was loud once, long ago, and has stopped. Their lifetime
// averages are similar, which is exactly why that metric cannot separate them.
//
// It also seeds `paused` (returned via pausedActorID, not the tuple, to leave the
// three existing callers untouched): a high lifetime-rate actor last seen 2 days
// ago, i.e. outside the 24h window but INSIDE ReportPoolMaxAge. It separates the
// two reasons an actor can be absent from the window — briefly quiet versus long
// dormant — which a fixture holding only `stale` (30 days) cannot do.
const pausedActorID = "journal:4.4.4.4"

func seedRateFixture(t *testing.T, st *Store) (escalating, moderate, stale string) {
	t.Helper()
	now := time.Now().UTC()
	escalating, moderate, stale = "journal:1.1.1.1", "journal:3.3.3.3", "journal:2.2.2.2"

	var evs []*models.Event
	// escalating: 60 events, ALL inside the last 24h
	for i := 0; i < 60; i++ {
		evs = append(evs, &models.Event{
			TS: now.Add(-time.Duration(i) * 20 * time.Minute), Source: models.SourceJournal,
			Kind: "failed_password", SrcIP: "1.1.1.1", ActorID: escalating,
		})
	}
	// moderate: also active in the window but at a LOWER volume, so ordering
	// within the window is actually exercised. Without a second in-window actor
	// an ORDER BY regression cannot be detected - verified by mutation.
	for i := 0; i < 20; i++ {
		evs = append(evs, &models.Event{
			TS: now.Add(-time.Duration(i) * 30 * time.Minute), Source: models.SourceJournal,
			Kind: "failed_password", SrcIP: "3.3.3.3", ActorID: moderate,
		})
	}
	// stale: 60 events, ALL ~30 days ago
	for i := 0; i < 60; i++ {
		evs = append(evs, &models.Event{
			TS:     now.Add(-30 * 24 * time.Hour).Add(-time.Duration(i) * 20 * time.Minute),
			Source: models.SourceJournal, Kind: "failed_password", SrcIP: "2.2.2.2", ActorID: stale,
		})
	}
	// paused: loud, but last seen 2 days ago — outside the 24h window, well
	// inside ReportPoolMaxAge. Still a legitimate report target.
	for i := 0; i < 60; i++ {
		evs = append(evs, &models.Event{
			TS:     now.Add(-48 * time.Hour).Add(-time.Duration(i) * 20 * time.Minute),
			Source: models.SourceJournal, Kind: "failed_password", SrcIP: "4.4.4.4", ActorID: pausedActorID,
		})
	}
	for _, e := range evs {
		if err := st.InsertEvent(e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	for _, a := range []*models.Actor{
		{ID: escalating, Source: models.SourceJournal, PrimaryIP: "1.1.1.1", EventCount: 60,
			UniqueUsers: 5, AttemptsPerHour: 2.0, ProbeScore: 70, Playbook: "fast_dictionary_spray",
			FirstSeen: now.Add(-30 * 24 * time.Hour), LastSeen: now},
		{ID: moderate, Source: models.SourceJournal, PrimaryIP: "3.3.3.3", EventCount: 20,
			UniqueUsers: 4, AttemptsPerHour: 1.0, ProbeScore: 70, Playbook: "fast_dictionary_spray",
			FirstSeen: now.Add(-20 * 24 * time.Hour), LastSeen: now},
		{ID: stale, Source: models.SourceJournal, PrimaryIP: "2.2.2.2", EventCount: 60,
			UniqueUsers: 5, AttemptsPerHour: 900.0, ProbeScore: 70, Playbook: "fast_dictionary_spray",
			FirstSeen: now.Add(-30 * 24 * time.Hour), LastSeen: now.Add(-30 * 24 * time.Hour)},
		// Highest lifetime rate of all, so it heads the lifetime-ranked half and
		// its exclusion (or retention) is unambiguous.
		{ID: pausedActorID, Source: models.SourceJournal, PrimaryIP: "4.4.4.4", EventCount: 60,
			UniqueUsers: 5, AttemptsPerHour: 950.0, ProbeScore: 70, Playbook: "fast_dictionary_spray",
			FirstSeen: now.Add(-10 * 24 * time.Hour), LastSeen: now.Add(-48 * time.Hour)},
	} {
		if err := st.UpsertActor(a); err != nil {
			t.Fatalf("upsert actor: %v", err)
		}
	}
	return escalating, moderate, stale
}

// TestRecentRatesByActorSeesCurrentActivity is the core of the fix: the stored
// lifetime average says the stale actor is 450x more aggressive; the windowed
// rate says the opposite, which is the truth.
func TestRecentRatesByActorSeesCurrentActivity(t *testing.T) {
	st := newTestStore(t, "rates.db")
	esc, _, stale := seedRateFixture(t, st)

	rates, err := st.RecentRatesByActor(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("RecentRatesByActor: %v", err)
	}
	if rates[esc] <= 0 {
		t.Errorf("actively attacking actor has recent rate %.2f, want > 0", rates[esc])
	}
	if _, ok := rates[stale]; ok {
		t.Errorf("actor with no events in the window appears in the map (%.2f); absent "+
			"and zero must stay distinguishable", rates[stale])
	}
	// The whole point: recent ranking must invert the lifetime ranking here.
	if rates[esc] <= rates[stale] {
		t.Errorf("recent rate ranks the stale actor at or above the active one (%.2f vs %.2f)",
			rates[stale], rates[esc])
	}
}

// TestTopActorsByRecentRateRanksByWindow pins the Brute-Force Radar fix: it must
// order by current activity, not by the stored lifetime average.
func TestTopActorsByRecentRateRanksByWindow(t *testing.T) {
	st := newTestStore(t, "toprate.db")
	esc, mod, stale := seedRateFixture(t, st)

	got, err := st.TopActorsByRecentRate(time.Now().Add(-24*time.Hour), 8)
	if err != nil {
		t.Fatalf("TopActorsByRecentRate: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no actors ranked")
	}
	// Ordering inside the window must follow recent volume: 60 events beats 20.
	var idx = map[string]int{}
	for i, r := range got {
		idx[r.Actor.ID] = i
	}
	if pe, pm := idx[esc], idx[mod]; pe > pm {
		t.Errorf("higher-volume actor ranked below the lower-volume one (%d vs %d): "+
			"the radar is not ordering by recent activity", pe, pm)
	}
	if got[0].Actor.ID != esc {
		t.Errorf("top actor is %q, want the actively attacking %q (the stale actor has a "+
			"900/h LIFETIME average, which is what the old ORDER BY used)", got[0].Actor.ID, esc)
	}
	for _, r := range got {
		if r.Actor.ID == stale {
			t.Error("an actor with no events in the window appears in the radar")
		}
		if r.PerHour <= 0 {
			t.Errorf("%s ranked with a non-positive rate %.2f", r.Actor.ID, r.PerHour)
		}
		// The reported rate must be the WINDOWED one, not the stored column.
		if r.PerHour == r.Actor.AttemptsPerHour {
			t.Errorf("%s reports its stored lifetime average (%.2f) as the recent rate",
				r.Actor.ID, r.PerHour)
		}
	}
}

// TestActorsForReportingIncludesActiveActors pins the biggest practical part of
// the bug: the old pool was the top-N by lifetime rate, which on real data
// excluded 229 of 245 currently-active actors, half of them otherwise
// reportable. A low lifetime average must not hide an actor attacking right now.
func TestActorsForReportingIncludesActiveActors(t *testing.T) {
	st := newTestStore(t, "pool.db")
	esc, _, _ := seedRateFixture(t, st)

	// limit=1 makes the lifetime half of the union as narrow as possible: only
	// the stale actor (900/h average) qualifies that way. The active actor can
	// therefore only appear via the window half.
	pool, err := st.ActorsForReporting(time.Now().Add(-24*time.Hour), 1)
	if err != nil {
		t.Fatalf("ActorsForReporting: %v", err)
	}
	var haveEsc, havePaused bool
	for _, a := range pool {
		switch a.ID {
		case esc:
			haveEsc = true
		case pausedActorID:
			havePaused = true
		}
	}
	if !haveEsc {
		t.Error("actor attacking inside the window is missing from the reporting pool; " +
			"its low lifetime average must not hide it (this is the 229-of-245 bug)")
	}
	// The lifetime half must still widen the window half — but only over actors
	// that could still be reported. `paused` (2d, and the top lifetime rate, so
	// it is the one actor limit=1 can admit that way) distinguishes "the union
	// still works" from "the union collapsed into the 24h window".
	if !havePaused {
		t.Error("high lifetime-rate actor last seen 2 days ago dropped out of the pool: " +
			"ReportPoolMaxAge is meant to exclude DORMANT actors, not to collapse the " +
			"union into the 24h window (that would restore the 229-of-245 bug for " +
			"anyone reporting on a weekly cadence)")
	}
	// `stale` is deliberately NOT asserted here: at limit=1 the lifetime half can
	// only admit one row and `paused` outranks it, so it would be absent with or
	// without the age bound. See TestActorsForReportingExcludesDormantActors.
}

// TestActorsForReportingExcludesDormantActors pins the other half of the pool
// contract. The lifetime-ranked branch ignores `since` by design, which left it
// unbounded: measured on the reference deployment, 868 of the top 1000 by
// lifetime rate had been silent over a week, and every one of the 6 IPs the
// suggestions widget offered was 31-50 days stale — all already reported the day
// before — while the actor attacking at that moment had never been reported.
//
// The limit here is deliberately wide. At limit=1 the assertion is vacuous (only
// the single highest lifetime rate gets in either way); the bound is only
// observable once the lifetime half is broad enough to reach a dormant row.
func TestActorsForReportingExcludesDormantActors(t *testing.T) {
	st := newTestStore(t, "pool_dormant.db")
	_, _, stale := seedRateFixture(t, st)

	pool, err := st.ActorsForReporting(time.Now().Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatalf("ActorsForReporting: %v", err)
	}
	var haveStale, havePaused bool
	for _, a := range pool {
		switch a.ID {
		case stale:
			haveStale = true
		case pausedActorID:
			havePaused = true
		}
	}
	if haveStale {
		t.Error("actor dormant for 30 days is in the reporting pool: without an age " +
			"bound the lifetime-ranked half re-admits attackers that stopped months " +
			"ago, and they outrank live ones because the ranking is a lifetime average")
	}
	// Same widened limit must still admit the 2-day-old actor, so a failure above
	// means "the bound is wrong", not "the bound is missing".
	if !havePaused {
		t.Error("the age bound also excluded an actor last seen 2 days ago; " +
			"ReportPoolMaxAge is a week precisely so a paused campaign stays reportable")
	}
}
