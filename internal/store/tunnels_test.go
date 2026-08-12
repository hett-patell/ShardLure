package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestTopTunnelTargets verifies the proxy-target aggregate groups by
// dst_ip:dst_port, counts hits and distinct actors, drops non-tunnel and
// empty-dst rows, and honours the since window.
func TestTopTunnelTargets(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "tun.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	mk := func(kind models.EventKind, ts time.Time, actor, dstIP string, dstPort int) *models.Event {
		return &models.Event{
			TS: ts, Source: models.SourceCowrie, Kind: kind,
			SrcIP: "9.9.9.9", ActorID: actor, DstIP: dstIP, DstPort: dstPort,
		}
	}
	events := []*models.Event{
		// 1.1.1.1:53 — two actors, three hits (one outside the 24h window).
		mk(models.KindTunnel, now.Add(-1*time.Hour), "cowrie:a", "1.1.1.1", 53),
		mk(models.KindTunnel, now.Add(-2*time.Hour), "cowrie:b", "1.1.1.1", 53),
		mk(models.KindTunnel, now.Add(-48*time.Hour), "cowrie:a", "1.1.1.1", 53),
		// 62.210.131.144:2535 — single hit.
		mk(models.KindTunnel, now.Add(-3*time.Hour), "cowrie:a", "62.210.131.144", 2535),
		// A tunnel event with no dst must be excluded (no bogus ":0" bucket).
		mk(models.KindTunnel, now.Add(-1*time.Hour), "cowrie:a", "", 0),
		// A non-tunnel event carrying a dst must be excluded.
		mk(models.KindCommand, now.Add(-1*time.Hour), "cowrie:a", "8.8.8.8", 53),
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatalf("append: %v", err)
	}

	// 24h window: 1.1.1.1:53 has 2 hits / 2 actors, plus 62.210…:2535 (1/1).
	got, err := st.TopTunnelTargets(now.Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatalf("TopTunnelTargets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 targets in 24h window, got %d: %+v", len(got), got)
	}
	top := got[0]
	if top.DstIP != "1.1.1.1" || top.DstPort != 53 {
		t.Fatalf("top target = %q:%d", top.DstIP, top.DstPort)
	}
	if top.Hits != 2 {
		t.Fatalf("expected 2 hits in window, got %d", top.Hits)
	}
	if top.UniqueActors != 2 {
		t.Fatalf("expected 2 distinct actors, got %d", top.UniqueActors)
	}

	// All-time (zero since): 1.1.1.1:53 now has all 3 hits.
	all, err := st.TopTunnelTargets(time.Time{}, 10)
	if err != nil {
		t.Fatalf("TopTunnelTargets all-time: %v", err)
	}
	if len(all) != 2 || all[0].Hits != 3 {
		t.Fatalf("expected top target 3 hits all-time, got %+v", all)
	}
}

// TestCountTunnelTargetsSinceIgnoresPageLimit pins the disclosure fix: the
// count must describe the whole window regardless of what limit the page used.
// The widget's total was len(targets), so requesting 1 destination reported
// "1 destination" while more existed — six were hidden on live data with
// nothing on screen to suggest it.
//
// It also pins that distinctness is over (dst_ip, dst_port), not dst_ip: a
// single host swept on several ports is several destinations, which is exactly
// the shape this widget exists to show.
func TestCountTunnelTargetsSinceIgnoresPageLimit(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "tuncount.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	mk := func(kind models.EventKind, ts time.Time, dstIP string, dstPort int) *models.Event {
		return &models.Event{
			TS: ts, Source: models.SourceCowrie, Kind: kind,
			SrcIP: "9.9.9.9", ActorID: "cowrie:a", DstIP: dstIP, DstPort: dstPort,
		}
	}
	events := []*models.Event{
		// One host, three ports = three distinct destinations. The first is hit
		// twice so hits and destination count can't be confused.
		mk(models.KindTunnel, now.Add(-1*time.Hour), "1.1.1.1", 22),
		mk(models.KindTunnel, now.Add(-1*time.Hour), "1.1.1.1", 22),
		mk(models.KindTunnel, now.Add(-2*time.Hour), "1.1.1.1", 80),
		mk(models.KindTunnel, now.Add(-3*time.Hour), "1.1.1.1", 443),
		// A fourth destination on another host.
		mk(models.KindTunnel, now.Add(-4*time.Hour), "2.2.2.2", 53),
		// Outside the window — counted all-time, not in 24h.
		mk(models.KindTunnel, now.Add(-48*time.Hour), "3.3.3.3", 8080),
		// Excluded by the shared WHERE, exactly as in the page query.
		mk(models.KindTunnel, now.Add(-1*time.Hour), "", 0),
		mk(models.KindCommand, now.Add(-1*time.Hour), "8.8.8.8", 53),
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatalf("append: %v", err)
	}

	since := now.Add(-24 * time.Hour)
	total, err := st.CountTunnelTargetsSince(since)
	if err != nil {
		t.Fatalf("CountTunnelTargetsSince: %v", err)
	}
	if total != 4 {
		t.Fatalf("count = %d, want 4 distinct (dst_ip,dst_port) in the 24h window: "+
			"3 ports on 1.1.1.1 plus 2.2.2.2:53, excluding the empty-dst and "+
			"non-tunnel rows and the 48h-old one", total)
	}

	// The whole point: a tighter page limit must not move the total.
	for _, limit := range []int{1, 2, 10} {
		page, err := st.TopTunnelTargets(since, limit)
		if err != nil {
			t.Fatalf("TopTunnelTargets(limit=%d): %v", limit, err)
		}
		want := limit
		if want > 4 {
			want = 4
		}
		if len(page) != want {
			t.Fatalf("limit=%d returned %d rows, want %d", limit, len(page), want)
		}
		again, err := st.CountTunnelTargetsSince(since)
		if err != nil {
			t.Fatalf("CountTunnelTargetsSince(limit=%d): %v", limit, err)
		}
		if again != 4 {
			t.Fatalf("count = %d with page limit %d, want 4: the total describes the "+
				"window, not the page", again, limit)
		}
	}

	// All-time (zero since) picks up the 48h-old destination.
	allTime, err := st.CountTunnelTargetsSince(time.Time{})
	if err != nil {
		t.Fatalf("CountTunnelTargetsSince all-time: %v", err)
	}
	if allTime != 5 {
		t.Fatalf("all-time count = %d, want 5 (adds 3.3.3.3:8080)", allTime)
	}
}
