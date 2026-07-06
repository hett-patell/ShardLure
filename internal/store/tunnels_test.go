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
